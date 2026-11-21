"""Synthetic Git histories prove lineage and source approval cannot be rehashed away."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from test_training_sources import commit
from test_training_sources import reviewed as reviewed
from test_training_sources_hardening import handoff as handoff

from ml import training_sources as old
from ml.stream_sources import derivation_certificate, verify_stream_manifest

ROOT = Path(__file__).resolve().parents[1]


def hashfile(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def derived(handoff):
    (root, raw, evidence, ids, rows, parent_policy, _), _, parent, _ = handoff
    for i, row in enumerate(rows):
        row["incident"] = dict(
            incident_id=row["incident_id"],
            asset_id="unit",
            feature_schema_version="features-v3",
            family_hint="account",
            start_time="2026-01-01T00:00:00Z",
            end_time="2026-01-01T00:00:10Z",
            features=deepcopy(row["features"]),
            evidence_sources=["wazuh"],
            base_severity=0,
            raw_refs=["sealed-raw"],
            indicator=None,
        )
        key = old.run_key(row["run_id"])
        parent_policy["approved_runs"][key]["record_sha256"] = old.digest(old.canonical_record(row))
        parent_policy["partitions"][old.PARTITIONS[i]] = old.partition_commitment([row])
    parent_policy["dataset_hash_sha256"] = old.canonical_dataset_hash(rows)
    path = root / old.POLICY_RELATIVE
    path.write_text(json.dumps(parent_policy))
    parent_commit = commit(root)
    parent_policy_bytes = path.read_bytes()
    cert = old._certificate(
        parent_policy, hashfile(path), parent_commit, parent_policy["processing_runtimes"][0]
    )
    parent = deepcopy(parent)
    parent["provenance"].update(
        builder_git_commit=parent_commit, source_compatibility_sha256=old.digest(cert)
    )
    parent["collection_audit"]["source_compatibility"] = cert
    parent["source_partitions"] = deepcopy(parent_policy["partitions"])
    parent["partitions"] = {
        k: {"sha256": v["sha256"], "record_count": v["record_count"]}
        for k, v in parent_policy["partitions"].items()
    }
    parent["dataset_hash_sha256"] = parent_policy["dataset_hash_sha256"]
    parent["locked_test_sha256"] = parent_policy["partitions"]["locked_test"]["sha256"]
    old.verify_training_manifest(parent, root=root, expected_commit=parent_commit)

    (root / "ml/feature_schema_stream.json").write_bytes(
        (ROOT / "ml/feature_schema_stream.json").read_bytes()
    )
    (root / "ml/training_stream_config.yaml").write_text("unit-profile: stream\n")
    review_path = root / "config/stream-training-source-compatibility.json"
    review_path.write_text("{}")
    commit(root)
    processing = old.processing_hash(root)
    parent_policy["processing_sha256"] = processing
    parent_policy["approved_training_manifests"] = {
        old.digest(parent): {
            "builder_commit": parent_commit,
            "policy_sha256": hashlib.sha256(parent_policy_bytes).hexdigest(),
            "processing_sha256": old.processing_hash(root, parent_commit),
        }
    }
    path.write_text(json.dumps(parent_policy))
    builder = commit(root)
    schema = json.loads((root / "ml/feature_schema_stream.json").read_text())
    parts = {}
    for role, row in zip(old.PARTITIONS, rows, strict=True):
        source = deepcopy(row["incident"])
        features = {**dict.fromkeys(schema["required"], 0.0), **row["features"]}
        projected = {
            **old.canonical_record(row),
            "source_incident": source,
            "features": features,
            "incident": {
                **source,
                "feature_schema_version": "features-v4-stream-v1",
                "features": features,
                "indicator_attribution": None,
            },
        }
        parts[role] = [projected]
    commitments = {k: old.partition_commitment(v) for k, v in parts.items()}
    manifest = {
        "manifest_version": "dataset-manifest-v4-stream-v1",
        "feature_schema_version": schema["version"],
        "feature_schema_sha256": hashfile(root / "ml/feature_schema_stream.json"),
        "parent_manifest": parent,
        "parent_manifest_sha256": old.digest(parent),
        "group_key": "cohort_id",
        "locked_test_status": "UNOPENED",
        "record_counts": {k: len(v) for k, v in parts.items()},
        "partitions": commitments,
        "locked_test_sha256": commitments["locked_test"]["sha256"],
        "dataset_hash_sha256": old.canonical_dataset_hash([r for p in parts.values() for r in p]),
        "row_commitments": {
            old.run_key(r["run_id"]): old.digest(r) for p in parts.values() for r in p
        },
        "split_assignment_commitment_sha256": parent["split_assignment_commitment_sha256"],
        "provenance": {
            "builder_git_commit": builder,
            "processing_sha256": processing,
            "processing_runtime": deepcopy(parent_policy["processing_runtimes"][0]),
            "builder_config_sha256": hashfile(root / "ml/training_stream_config.yaml"),
        },
    }
    raw_cert = old._certificate(
        parent_policy, hashfile(path), builder, parent_policy["processing_runtimes"][0]
    )
    derived_cert = derivation_certificate(parent, raw_cert)
    manifest["collection_audit"] = {
        "status": "DERIVED_VERIFIED",
        "source_compatibility": derived_cert,
    }
    manifest["provenance"]["source_compatibility_sha256"] = old.digest(derived_cert)
    review = {
        "version": "reviewed-stream-training-v1",
        "status": "READY",
        "approved_manifest_sha256": old.digest(manifest),
        "processing_sha256": processing,
        "parent_manifest_sha256": old.digest(parent),
        "feature_schema_sha256": manifest["feature_schema_sha256"],
        "builder_config_sha256": manifest["provenance"]["builder_config_sha256"],
    }
    review_path.write_text(json.dumps(review))
    trainer = commit(root)
    return root, manifest, parts, review, trainer


def test_exact_reviewed_stream_dataset_keeps_parent_identity_and_split(derived):
    root, manifest, parts, _, trainer = derived
    verify_stream_manifest(
        manifest, {k: parts[k] for k in ("train", "validation")}, root=root, expected_commit=trainer
    )


@pytest.mark.parametrize("change", ["manifest", "row", "source", "wrong-trainer", "pending"])
def test_unreviewed_stream_data_or_executing_source_cannot_train(derived, change):
    root, manifest, parts, review, trainer = derived
    if change == "manifest":
        manifest["locked_test_status"] = "OPENED"
    elif change == "row":
        parts["train"][0]["features"]["tcp_connection_count"] = 999
    elif change == "source":
        (root / "module.py").write_text("unreviewed = True\n")
    elif change == "wrong-trainer":
        trainer = manifest["provenance"]["builder_git_commit"]
    else:
        review["status"] = "BUILD_PENDING"
        (root / "config/stream-training-source-compatibility.json").write_text(json.dumps(review))
        trainer = commit(root)
    with pytest.raises(ValueError):
        verify_stream_manifest(
            manifest,
            {k: parts[k] for k in ("train", "validation")},
            root=root,
            expected_commit=trainer,
        )


@pytest.mark.parametrize(
    "change",
    [
        "label",
        "cohort",
        "retained-feature",
        "split",
        "bounds",
        "runtime",
        "dataset-hash",
        "missing-certificate",
        "forged-certificate",
    ],
)
def test_even_reapproved_derived_hash_cannot_rewrite_parent_contract(derived, change):
    root, manifest, parts, review, _ = derived
    row = parts["train"][0]
    if change == "label":
        row["label"] = 1 - row["label"]
    elif change == "cohort":
        row["cohort_id"] = "different-cohort"
    elif change == "retained-feature":
        row["features"]["failed_login_count"] = 999
        row["incident"]["features"] = deepcopy(row["features"])
    elif change == "bounds":
        row["features"]["dns_observation_fraction"] = 2
    elif change == "runtime":
        manifest["provenance"]["processing_runtime"] = {"unreviewed": True}
    elif change == "dataset-hash":
        manifest["dataset_hash_sha256"] = "invalid"
    elif change == "missing-certificate":
        manifest.pop("collection_audit", None)
    elif change == "forged-certificate":
        manifest["collection_audit"] = {"status": "DERIVED_VERIFIED", "source_compatibility": {}}
    else:
        parts["train"], parts["validation"] = parts["validation"], parts["train"]
    manifest["partitions"] = {k: old.partition_commitment(v) for k, v in parts.items()}
    manifest["row_commitments"] = {
        old.run_key(r["run_id"]): old.digest(r) for p in parts.values() for r in p
    }
    review["approved_manifest_sha256"] = old.digest(manifest)
    (root / "config/stream-training-source-compatibility.json").write_text(json.dumps(review))
    trainer = commit(root)
    with pytest.raises(ValueError):
        verify_stream_manifest(
            manifest,
            {k: parts[k] for k in ("train", "validation")},
            root=root,
            expected_commit=trainer,
        )


def test_training_verifier_refuses_a_locked_partition_argument(derived):
    root, manifest, parts, _, trainer = derived
    with pytest.raises(ValueError, match="locked|train/validation"):
        verify_stream_manifest(manifest, parts, root=root, expected_commit=trainer)


def test_stream_loader_validates_files_before_training_without_opening_locked(derived, monkeypatch):
    from ml.stream_sources import load_stream_partitions

    root, manifest, parts, _, trainer = derived
    output = root.parent / "processed-stream-v1"
    output.mkdir(parents=True)
    (output / "dataset_manifest.json").write_text(json.dumps(manifest))
    for name in ("train", "validation"):
        (output / f"{name}.jsonl").write_bytes(old.partition_bytes(parts[name]))
    real_read = Path.read_bytes

    def guarded_read(path):
        assert path.name not in {"locked_test.jsonl", "test.txt"}
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    train, validation, accepted = load_stream_partitions(
        output,
        root / "ml/feature_schema_stream.json",
        config_path=root / "ml/training_stream_config.yaml",
        root=root,
        expected_commit=trainer,
    )
    assert train == parts["train"] and validation == parts["validation"] and accepted == manifest
    (output / "train.jsonl").write_bytes(old.partition_bytes(parts["validation"]))
    with pytest.raises(ValueError, match="integrity"):
        load_stream_partitions(
            output,
            root / "ml/feature_schema_stream.json",
            config_path=root / "ml/training_stream_config.yaml",
            root=root,
            expected_commit=trainer,
        )


def test_staging_rechecks_bytes_after_loading_and_never_exports_a_partial_set(derived, monkeypatch):
    from ml import stream_dataset
    from ml.stream_sources import load_stream_partitions

    root, manifest, parts, _, _ = derived
    processed = root.parent / 'stage-input'
    processed.mkdir()
    (processed / 'dataset_manifest.json').write_text(json.dumps(manifest))
    for name in ('train', 'validation'):
        (processed / f'{name}.jsonl').write_bytes(old.partition_bytes(parts[name]))
    monkeypatch.setattr(stream_dataset, 'ROOT', root)
    real_load = load_stream_partitions

    def mutate_after_load(*args, **kwargs):
        result = real_load(*args, root=root, **kwargs)
        (processed / 'train.jsonl').write_bytes(b'{}\n')
        return result

    monkeypatch.setattr(stream_dataset, 'load_stream_partitions', mutate_after_load)
    output = root.parent / 'safe-upload'
    with pytest.raises(ValueError, match='changed|integrity'):
        stream_dataset.stage_stream_dataset(processed, output)
    assert not output.exists()
