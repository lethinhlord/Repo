"""Statistical dependency guards, independent of generated classifier accuracy."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from test_supplemental_sources import prospective as prospective
from test_training_sources import commit

from ml.training import _matrix, leakage_audit
from ml.training_sources import (
    canonical_dataset_hash,
    digest,
    partition_bytes,
    partition_commitment,
)


def test_cv_groups_are_actual_host_days_not_template_or_run_names(prospective):
    _, _, parts, _, _ = prospective
    rows = parts["train"]
    _, _, groups = _matrix(rows, "account", ["failed_login_count"])
    expected = [r["evaluation_group_id"] for r in rows if r["family"] == "account"]
    assert groups.tolist() == expected
    assert groups[0] != next(r["cohort_id"] for r in rows if r["family"] == "account")


def test_missing_dependency_group_never_falls_back_to_cohort_for_new_profile(prospective):
    _, _, parts, _, _ = prospective
    rows = deepcopy(parts["train"])
    rows[0].pop("evaluation_group_id")
    with pytest.raises(ValueError, match="dependency"):
        _matrix(rows, "account", ["failed_login_count"])


def test_group_leakage_and_template_overlap_have_distinct_meaning(prospective):
    _, _, parts, _, _ = prospective
    train, validation = deepcopy(parts["train"]), deepcopy(parts["validation"])
    audit = leakage_audit(train, validation)
    assert audit["passed"]
    assert audit["protocol"] == "known-template-new-host-day"
    assert audit["template_overlap_diagnostic"]
    validation[0]["evaluation_group_id"] = train[0]["evaluation_group_id"]
    audit = leakage_audit(train, validation)
    assert not audit["passed"]
    assert audit["checks"]["evaluation_group_overlap"]


def test_real_fit_export_freeze_and_inference_keep_research_scope(prospective, monkeypatch):
    """Software fit on INVENTED integrity fixtures; no model-quality claim."""
    from test_ml_package import SIGNING_KEY

    from api.app.contracts import HttpIncidentRequest
    from ml import supplemental_sources as source
    from ml.freeze_model import freeze
    from ml.inference import ModelRuntime
    from ml.training import train

    root, manifest, parts, review, _ = prospective
    for group in parts.values():
        for row in group:
            if row["family"] == "account":
                row["features"]["failed_login_count"] = float(2 + 20 * row["label"])
                row["source_incident"]["features"]["failed_login_count"] = row["features"][
                    "failed_login_count"
                ]
            else:
                row["features"]["flow_upload_fraction"] = 0.1 + 0.7 * row["label"]
            row["incident"]["features"] = row["features"]
    rows = [r for group in parts.values() for r in group]
    manifest["partitions"] = {k: partition_commitment(v) for k, v in parts.items()}
    manifest["row_commitments"] = {source.run_key(r["run_id"]): digest(r) for r in rows}
    manifest["dataset_hash_sha256"] = canonical_dataset_hash(rows)
    manifest["locked_test_sha256"] = manifest["partitions"]["locked_test"]["sha256"]
    review["approved_manifest_sha256"] = digest(manifest)
    (root / source.POLICY_RELATIVE).write_text(json.dumps(review))
    trainer = commit(root)
    processed = root / "data/processed-unit"
    processed.mkdir(parents=True)
    for role in ("train", "validation"):
        (processed / f"{role}.jsonl").write_bytes(partition_bytes(parts[role]))
    (processed / "dataset_manifest.json").write_text(json.dumps(manifest))
    (processed / "locked_test.jsonl").write_bytes(b"MUST NEVER BE READ BY TRAINING\n")
    monkeypatch.setattr(source, "ROOT", root)
    monkeypatch.chdir(root)
    original = Path.read_bytes

    def reject_locked(path):
        if path.name == "locked_test.jsonl":
            raise AssertionError("training opened locked data")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", reject_locked)
    config_path = root / source.CONFIG_RELATIVE
    metadata = train(config_path)
    assert metadata["git_commit"] == trainer
    assert metadata["dependency_group_key"] == "evaluation_group_id"
    assert metadata["feature_schema_version"] == "features-v5-http-v1"
    package = root / "ml/model-package-unit"
    thresholds = json.loads((package / "thresholds.json").read_bytes())
    assert all(
        v["automation_eligible"] is False and "scope_research_only" in v["gate_failures"]
        for v in thresholds["families"].values()
    )
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", SIGNING_KEY)
    freeze(package)
    runtime = ModelRuntime(package)
    value = runtime.predict(HttpIncidentRequest.model_validate(parts["validation"][0]["incident"]))
    assert value.review_required and not value.automation_eligible
    assert "model:prospective_lab_profile_research_only" in value.review_reasons
    assert metadata["locked_test_status"] == "UNOPENED"
