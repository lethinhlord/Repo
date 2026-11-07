import hashlib
import json

import joblib
import pytest
import yaml
from test_ml_package import SIGNING_KEY, account_features, create_package

from api.app.contracts import IncidentRequest
from ml.freeze_model import freeze


def fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", SIGNING_KEY)
    from ml.evaluate_challenge import runtime_policy_hash

    package = tmp_path / "package"
    create_package(package)
    rows = []
    expectations = []
    for index, (label, context) in enumerate([(0, "MISSING"), (1, "AVAILABLE")]):
        scenario = f"challenge-{index}"
        incident = IncidentRequest(
            incident_id=f"INC-{index}",
            asset_id="UNIT",
            family_hint="account",
            start_time="2026-10-11T00:00:00Z",
            end_time="2026-10-11T00:01:00Z",
            features=account_features(20, 1),
            evidence_sources=["synthetic-unit"],
            base_severity=12,
            context_status=context,
            context_revision="synthetic-context" if context == "AVAILABLE" else None,
            observation_quality="COMPLETE",
        )
        rows.append(
            {
                "scenario_id": scenario,
                "cohort_id": "pair",
                "run_id": scenario,
                "incident_id": incident.incident_id,
                "family": "account",
                "label": label,
                "purpose": "challenge",
                "features": incident.features,
                "incident": incident.model_dump(mode="json"),
            }
        )
        expectations.append(
            {
                "scenario_id": scenario,
                "cohort_id": "pair",
                "expected_decision": "REVIEW",
                "training_eligible": False,
            }
        )
    challenge = tmp_path / "challenge.jsonl"
    challenge.write_text("".join(json.dumps(row) + "\n" for row in rows))
    design = tmp_path / "design.yaml"
    design.write_text(
        yaml.safe_dump(
            {
                "challenge_expectations": expectations,
                "challenge_evaluation": {
                    "post_freeze_only": True,
                    "threshold_tuning_allowed": False,
                },
            }
        )
    )
    manifest = {
        "challenge": {
            "sha256": hashlib.sha256(challenge.read_bytes()).hexdigest(),
            "record_count": len(rows),
            "training_eligible": False,
        }
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    metadata = json.loads((package / "metadata.json").read_text())
    metadata.update(
        dataset_manifest_payload_sha256=hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        dataset_provenance={
            "collection_design_sha256": hashlib.sha256(design.read_bytes()).hexdigest()
        },
        runtime_policy_sha256=runtime_policy_hash(),
    )
    (package / "metadata.json").write_text(json.dumps(metadata))
    bundle = joblib.load(package / "model.joblib")
    bundle["metadata"] = metadata
    joblib.dump(bundle, package / "model.joblib")
    return package, challenge, manifest_path, design


def test_challenge_replays_context_and_reports_confident_failure(tmp_path, monkeypatch):
    from ml.evaluate_challenge import evaluate_challenge

    package, challenge, manifest, design = fixture(tmp_path, monkeypatch)
    with pytest.raises((RuntimeError, PermissionError), match="frozen|incomplete"):
        evaluate_challenge(package, challenge, manifest, design, evidence_dir=tmp_path / "evidence")
    freeze(package)
    original = {p.name: p.read_bytes() for p in package.iterdir()}
    result = evaluate_challenge(
        package, challenge, manifest, design, evidence_dir=tmp_path / "evidence"
    )
    assert result["status"] == "FAIL"
    assert result["review_rate"] == 0.5
    assert result["confident_malicious_rate"] == 0.5
    assert result["coverage"] == 1.0
    assert result["pair_agreement"] == 0.0
    assert result["records"][0]["review_required"] is True
    assert result["records"][1]["review_required"] is False
    assert original == {p.name: p.read_bytes() for p in package.iterdir()}
    assert not list((tmp_path / "evidence").rglob("LOCKED_TEST_RESERVED"))
    with pytest.raises(PermissionError, match="already"):
        evaluate_challenge(package, challenge, manifest, design, evidence_dir=tmp_path / "evidence")


def test_challenge_policy_mismatch_rejected_before_read_and_reservation(tmp_path, monkeypatch):
    from ml.evaluate_challenge import evaluate_challenge

    package, challenge, manifest, design = fixture(tmp_path, monkeypatch)
    freeze(package)
    design.write_text("changed: true")
    challenge.unlink()
    with pytest.raises(ValueError, match="design"):
        evaluate_challenge(package, challenge, manifest, design, evidence_dir=tmp_path / "evidence")
    assert not (tmp_path / "evidence").exists()
