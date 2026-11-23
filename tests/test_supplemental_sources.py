"""Prospective training requires committed exact review, not a self-rehashed bundle."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from test_supplemental_plan import registration
from test_training_sources import commit, git

from ml import supplemental_sources as s
from ml.supplemental_design import load_design, make_plan, resolve_plan_run
from ml.training_sources import (
    canonical_dataset_hash,
    digest,
    partition_bytes,
    partition_commitment,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def prospective(tmp_path):
    """Invented integrity-only rows, never observational training evidence."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "core.autocrlf", "false")
    (root / ".gitignore").write_bytes(b"data/\noperator-logs/\nml/model-package*/\n")
    (root / "ml").mkdir()
    (root / "config").mkdir()
    (root / s.SCHEMA_RELATIVE).write_bytes((ROOT / s.SCHEMA_RELATIVE).read_bytes())
    config = yaml.safe_load((ROOT / s.CONFIG_RELATIVE).read_bytes())
    config["data"].update(processed_dir="data/processed-unit", collection_design=None)
    config["package_dir"] = "ml/model-package-unit"
    config["models"]["random_forest"]["n_estimators"] = 5
    config["models"]["xgboost"]["n_estimators"] = 5
    config["selection"].update(bootstrap_iterations=10, latency_repeats=2)
    (root / s.CONFIG_RELATIVE).write_bytes(yaml.safe_dump(config).encode("utf-8"))
    (root / "module.py").write_bytes(b"literal_synthetic_source = 1\n")
    review_path = root / s.POLICY_RELATIVE
    review_path.write_text("{}")
    builder = commit(root)
    design = load_design(ROOT / "config/supplemental-design.yaml")
    plan = make_plan(design, registration(design), seed=42)
    tag = design["candidate_tag"]
    git(
        root,
        "-c",
        "user.name=Unit",
        "-c",
        "user.email=unit@example.invalid",
        "tag",
        "-a",
        tag,
        "-m",
        "synthetic integrity fixture",
    )
    from ml.training_sources import source_tree_hash

    candidate = dict(
        version="collection-candidate-v1",
        tag=tag,
        commit=builder,
        tag_object=git(root, "rev-parse", "refs/tags/" + tag),
        origin="https://github.com/lethinhlord/Repo.git",
        tracked_files_sha256=source_tree_hash(root, builder),
    )
    runtime = dict(python_version="synthetic", installed_packages_sha256="b" * 64)
    schema = json.loads((root / s.SCHEMA_RELATIVE).read_bytes())
    parts = {k: [] for k in s.ROLES}
    for unit in plan["runs"]:
        planned = resolve_plan_run(plan, unit["run_id"])
        f = dict.fromkeys(schema["required"], 0.0)
        if unit["family"] == "c2":
            f.update(
                http_evidence_available=1.0, flow_evidence_available=1.0, dominant_tcp_unique=1.0
            )
        incident = dict(
            incident_id=unit["run_id"] + "-INC",
            family_hint=unit["family"],
            asset_id="WIN11-TARGET",
            feature_schema_version=s.SCHEMA_VERSION,
            features=f,
            observation_quality="COMPLETE",
            context_status="AVAILABLE",
            context_revision="synthetic-enrollment",
            review_reasons=[],
            start_time=unit["context"]["collection_date"] + "T00:00:00Z",
            end_time=unit["context"]["collection_date"] + "T00:00:01Z",
            evidence_sources=["synthetic-only"],
            raw_refs=["synthetic-only"],
            base_severity=0,
            indicator=None,
            indicator_attribution=None,
        )
        source = {
            **deepcopy(incident),
            "feature_schema_version": "features-v3",
            "features": {k: f[k] for k in schema["x-retained-legacy-features"]},
        }
        source.pop("indicator_attribution")
        row = dict(
            incident_id=incident["incident_id"],
            scenario_id=unit["scenario_id"],
            run_id=unit["run_id"],
            family=unit["family"],
            label=int(unit["label"] == "malicious"),
            features=f,
            source_file=f"data/raw/{unit['run_id']}/incidents.jsonl",
            purpose="trainable",
            cohort_id=unit["cohort_id"],
            incident=incident,
            source_incident=source,
            evaluation_group_id=unit["context"]["evaluation_group_id"],
            template_id=unit["template_id"],
            planned_run_id=unit["run_id"],
            attempt_number=planned["attempt_number"],
            campaign_plan_sha256=digest(plan),
            collection_context=unit["context"],
        )
        parts[unit["partition"]].append(row)
    cert = dict(
        version="supplemental-source-compatibility-v1",
        candidate=candidate,
        processing_sha256=s.processing_hash(root),
        processing_runtime=runtime,
        plan_sha256=digest(plan),
        design_sha256=digest(design),
        acceptance_sha256="a" * 64,
        input_inventory_sha256="c" * 64,
    )
    rows = [r for values in parts.values() for r in values]
    manifest = dict(
        manifest_version=s.MANIFEST_VERSION,
        feature_schema_version=s.SCHEMA_VERSION,
        feature_schema_sha256=hashlib.sha256((root / s.SCHEMA_RELATIVE).read_bytes()).hexdigest(),
        group_key="evaluation_group_id",
        evaluation_protocol=s.PROTOCOL,
        design=design,
        plan=plan,
        design_sha256=digest(design),
        plan_sha256=digest(plan),
        locked_test_status="UNOPENED",
        record_counts=s.COUNTS,
        partitions={k: partition_commitment(v) for k, v in parts.items()},
        locked_test_sha256=partition_commitment(parts["locked_test"])["sha256"],
        dataset_hash_sha256=canonical_dataset_hash(rows),
        row_commitments={s.run_key(r["run_id"]): digest(r) for r in rows},
        run_partitions={s.run_key(r["run_id"]): k for k, v in parts.items() for r in v},
        unit_membership={s.run_key(r["planned_run_id"]): s.run_key(r["run_id"]) for r in rows},
        provenance=dict(
            builder_git_commit=builder,
            processing_sha256=s.processing_hash(root),
            processing_runtime=runtime,
            source_compatibility_sha256=digest(cert),
            builder_config_sha256=hashlib.sha256(
                (root / s.CONFIG_RELATIVE).read_bytes()
            ).hexdigest(),
        ),
        collection_audit=dict(
            status="SUPPLEMENTAL_COLLECTION_AUDIT_PASS", source_compatibility=cert
        ),
    )
    review = dict(
        version="reviewed-supplemental-training-v1",
        status="READY",
        collection_candidate_tag=tag,
        processing_sha256=s.processing_hash(root),
        processing_runtimes=[runtime],
        approved_manifest_sha256=digest(manifest),
    )
    review_path.write_text(json.dumps(review))
    trainer = commit(root)
    return root, manifest, parts, review, trainer


def test_exact_committed_prospective_review_and_two_visible_files(
    prospective, tmp_path, monkeypatch
):
    root, manifest, parts, _, trainer = prospective
    s.verify_manifest(
        manifest, {k: parts[k] for k in ("train", "validation")}, root=root, expected_commit=trainer
    )
    processed = tmp_path / "processed"
    processed.mkdir()
    for role in ("train", "validation"):
        (processed / f"{role}.jsonl").write_bytes(partition_bytes(parts[role]))
    (processed / "dataset_manifest.json").write_text(json.dumps(manifest))
    # The loader must work even when locked_test.jsonl does not exist here.
    monkeypatch.setattr(s, "ROOT", root)
    loaded = s.load_partitions(
        processed,
        root / s.SCHEMA_RELATIVE,
        config_path=root / s.CONFIG_RELATIVE,
        expected_commit=trainer,
    )
    assert loaded == (parts["train"], parts["validation"], manifest)


@pytest.mark.parametrize("mutation", ["role", "row", "context", "profile", "source"])
def test_self_rehash_cannot_override_exact_prospective_review(prospective, mutation):
    root, manifest, parts, _, trainer = prospective
    manifest, parts = deepcopy(manifest), deepcopy(parts)
    if mutation == "source":
        (root / "module.py").write_text("changed = True\n")
    elif mutation == "role":
        first = next(iter(manifest["run_partitions"]))
        manifest["run_partitions"][first] = "locked_test"
    elif mutation == "row":
        parts["train"][0]["features"]["failed_login_count"] = 99
        manifest["row_commitments"][s.run_key(parts["train"][0]["run_id"])] = digest(
            parts["train"][0]
        )
        manifest["partitions"]["train"] = partition_commitment(parts["train"])
    elif mutation == "context":
        parts["train"][0]["evaluation_group_id"] = "fake-independent-ID"
    else:
        manifest["feature_schema_version"] = "features-v4-stream-v1"
    with pytest.raises(ValueError):
        s.verify_manifest(
            manifest,
            {k: parts[k] for k in ("train", "validation")},
            root=root,
            expected_commit=trainer,
        )


def test_even_committed_review_cannot_make_related_host_days_independent(prospective):
    root, manifest, parts, review, _ = prospective
    bad = deepcopy(manifest)
    context = bad["plan"]["registration"]["contexts"][10]
    context["collection_date"] = bad["plan"]["registration"]["contexts"][0]["collection_date"]
    bad["plan"]["plan_sha256"] = digest(
        {k: v for k, v in bad["plan"].items() if k != "plan_sha256"}
    )
    bad["plan_sha256"] = digest(bad["plan"])
    review["approved_manifest_sha256"] = digest(bad)
    (root / s.POLICY_RELATIVE).write_text(json.dumps(review))
    trainer = commit(root)
    with pytest.raises(ValueError):
        s.verify_manifest(bad, root=root, expected_commit=trainer)


def test_new_review_exemption_cannot_hide_collector_or_notebook_changes(monkeypatch):
    from ml import supplemental_sources as s

    files = {
        s.POLICY_RELATIVE: b"pending",
        "ml/scenario_collection.py": b"original",
        "notebooks/supplemental_train_colab.ipynb": b"original notebook",
    }
    monkeypatch.setattr(s, "_files", lambda *a: files.copy())
    before = s.processing_hash(Path("unused"))
    files[s.POLICY_RELATIVE] = b"ready"
    assert s.processing_hash(Path("unused")) == before
    files["ml/scenario_collection.py"] = b"changed"
    assert s.processing_hash(Path("unused")) != before
    files["ml/scenario_collection.py"] = b"original"
    files["notebooks/supplemental_train_colab.ipynb"] = b"changed notebook"
    assert s.processing_hash(Path("unused")) != before


def test_current_campaign_has_no_fabricated_dataset_approval():
    from ml.supplemental_sources import ROOT, policy

    document = json.loads((ROOT / s.POLICY_RELATIVE).read_bytes())
    if document["status"] == "READY":
        # A future exact owner review is allowed; source conformance still applies.
        approved, _ = policy(ROOT, require_ready=True)
        assert len(approved["approved_manifest_sha256"]) == 64
    else:
        assert document["approved_manifest_sha256"] is None
        with pytest.raises(ValueError):
            policy(ROOT, require_ready=True)
