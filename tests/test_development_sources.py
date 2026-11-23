"""Synthetic integrity fixtures, never real48-run data or lab acceptance."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from test_development_plan import development_registration
from test_training_sources import commit, git

from ml import development_sources as s
from ml.supplemental_design import load_design, make_plan
from ml.training_sources import partition_bytes, source_tree_hash

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def development_data(tmp_path):
    from ml.development_dataset import assemble_manifest

    root = tmp_path / "source"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "core.autocrlf", "false")
    (root / "config").mkdir()
    (root / "ml").mkdir()
    (root / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
    for relative in (s.SCHEMA_RELATIVE, s.CONFIG_RELATIVE, "config/development-design.yaml"):
        (root / relative).write_bytes((ROOT / relative).read_bytes())
    config = yaml.safe_load((root / s.CONFIG_RELATIVE).read_bytes())
    config["models"]["random_forest"]["n_estimators"] = 5
    config["models"]["xgboost"]["n_estimators"] = 5
    config["selection"].update(bootstrap_iterations=10, latency_repeats=2)
    (root / s.CONFIG_RELATIVE).write_text(yaml.safe_dump(config), encoding="utf-8")
    (root / s.POLICY_RELATIVE).write_text("{}")
    builder = commit(root)
    design = load_design(ROOT / "config/development-design.yaml")
    plan = make_plan(design, development_registration(design), seed=42)
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
        "SYNTHETIC integrity fixture",
    )
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
    rows = []
    for unit in plan["runs"]:
        f = dict.fromkeys(schema["required"], 0.0)
        if unit["family"] == "c2":
            f.update(
                http_evidence_available=1.0, flow_evidence_available=1.0, dominant_tcp_unique=1.0
            )
            f["http_method_switch_fraction"] = 0.1 + 0.7 * int(unit["label"] == "malicious")
        else:
            f["failed_login_count"] = (
                1 + 4 * int(unit["label"] == "malicious") + int(unit["cohort_id"][-2:]) % 3
            )
        incident = dict(
            incident_id=unit["run_id"] + "-INC",
            asset_id="WIN11-TARGET",
            family_hint=unit["family"],
            feature_schema_version=s.SCHEMA_VERSION,
            features=f,
            observation_quality="COMPLETE",
            context_status="AVAILABLE",
            context_revision="SYNTHETIC-enrollment",
            review_reasons=[],
            start_time=unit["context"]["collection_date"] + "T00:00:00Z",
            end_time=unit["context"]["collection_date"] + "T00:00:01Z",
            raw_refs=["SYNTHETIC-only"],
            evidence_sources=["SYNTHETIC-only"],
            base_severity=0,
            indicator=None,
            indicator_attribution=None,
        )
        original = {
            **deepcopy(incident),
            "feature_schema_version": "features-v3",
            "features": {k: f[k] for k in schema["x-retained-legacy-features"]},
        }
        original.pop("indicator_attribution")
        rows.append(
            dict(
                incident_id=incident["incident_id"],
                run_id=unit["run_id"],
                scenario_id=unit["scenario_id"],
                family=unit["family"],
                label=int(unit["label"] == "malicious"),
                features=f,
                source_file=f"data/raw/{unit['run_id']}/incidents.jsonl",
                purpose="trainable",
                cohort_id=unit["cohort_id"],
                incident=incident,
                source_incident=original,
                evaluation_group_id=unit["context"]["evaluation_group_id"],
                template_id=unit["template_id"],
                planned_run_id=unit["run_id"],
                attempt_number=1,
                campaign_plan_sha256=s.digest(plan),
                collection_context=unit["context"],
            )
        )
    review = dict(
        version="reviewed-development-training-v1",
        status="COLLECTION_READY",
        collection_candidate_tag=tag,
        processing_sha256=s.processing_hash(root),
        processing_runtimes=[runtime],
        approved_manifest_sha256=None,
    )
    report = dict(
        status="SUPPLEMENTAL_COLLECTION_AUDIT_PASS",
        counts={"train": 48},
        input_inventory_sha256="c" * 64,
        issues=[],
    )
    audited = (report, {"train": rows}, candidate, {"SYNTHETIC": True}, design, plan)
    manifest = assemble_manifest(audited, review, builder, runtime, root)
    review.update(status="READY", approved_manifest_sha256=s.digest(manifest))
    (root / s.POLICY_RELATIVE).write_text(json.dumps(review))
    trainer = commit(root)
    return root, manifest, rows, review, trainer, audited


def test_exact_review_loads_only_development_train(development_data, tmp_path, monkeypatch):
    root, manifest, rows, _, trainer, _ = development_data
    s.verify_manifest(manifest, rows, root=root, expected_commit=trainer)
    processed = tmp_path / "processed"
    processed.mkdir()
    (processed / "train.jsonl").write_bytes(partition_bytes(rows))
    (processed / "dataset_manifest.json").write_text(json.dumps(manifest))
    before = Path.read_bytes

    def visible_only(path):
        if path.name in {"validation.jsonl", "locked_test.jsonl"}:
            raise AssertionError("development loading must not open external data")
        return before(path)

    monkeypatch.setattr(Path, "read_bytes", visible_only)
    loaded, m = s.load_training_data(processed, root=root, expected_commit=trainer)
    assert loaded == rows and m == manifest and len(loaded) == 48
    assert (
        manifest["external_validation_status"] == manifest["locked_test_status"] == "NOT_COLLECTED"
    )


@pytest.mark.parametrize("mutation", ["external-status", "fake-groups", "missing", "row"])
def test_self_rehash_cannot_override_development_contract(development_data, mutation):
    root, manifest, rows, review, _, _ = development_data
    manifest, rows = deepcopy(manifest), deepcopy(rows)
    if mutation == "external-status":
        manifest["external_validation_status"] = "PASSED"
    elif mutation == "fake-groups":
        rows[0]["evaluation_group_id"] = "f" * 64
    elif mutation == "missing":
        rows.pop()
    else:
        rows[0]["features"]["http_post_fraction"] = 2
    if mutation != "external-status":
        from ml.training_sources import canonical_dataset_hash, partition_commitment, run_key

        manifest["row_commitments"] = {run_key(r["run_id"]): s.digest(r) for r in rows}
        manifest["partitions"]["train"] = partition_commitment(rows)
        manifest["dataset_hash_sha256"] = canonical_dataset_hash(rows)
    review["approved_manifest_sha256"] = s.digest(manifest)
    (root / s.POLICY_RELATIVE).write_text(json.dumps(review))
    trainer = commit(root)
    with pytest.raises(ValueError):
        s.verify_manifest(manifest, rows, root=root, expected_commit=trainer)
