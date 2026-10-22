from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.linear_model import LogisticRegression

from api.app.contracts import IncidentRequest
from api.app.main import app, load_model_runtime
from ml.evaluate import evaluate_locked_test
from ml.freeze_model import freeze
from ml.inference import ModelPackageError, ModelRuntime


def create_package(path: Path, *, automation_eligible: bool = True) -> None:
    estimator = LogisticRegression(random_state=42).fit(
        np.asarray([[0.0, 0.0], [1.0, 0.0], [10.0, 1.0], [20.0, 1.0]]),
        np.asarray([0, 0, 1, 1]),
    )
    metadata = {
        "model_version": "test-model-v1",
        "feature_schema_version": "features-v1",
        "locked_test_status": "UNOPENED",
        "locked_test_sha256": hashlib.sha256(b"").hexdigest(),
    }
    path.mkdir()
    joblib.dump(
        {
            "metadata": metadata,
            "families": {
                "account": {
                    "estimator": estimator,
                    "feature_order": ["failed_login_count", "success_after_fail"],
                    "threshold": 0.5,
                    "model_name": "logistic_regression",
                }
            },
        },
        path / "model.joblib",
    )
    (path / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (path / "thresholds.json").write_text(
        json.dumps(
            {
                "revision": "test-threshold-v1",
                "families": {
                    "account": {
                        "threshold": 0.5,
                        "automation_eligible": automation_eligible,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (path / "metrics_validation.json").write_text("{}", encoding="utf-8")
    (path / "eda_train.json").write_text("{}", encoding="utf-8")
    (path / "leakage_audit.json").write_text("{}", encoding="utf-8")
    (path / "feature_schema.json").write_text(
        json.dumps(
            {
                "version": "features-v1",
                "x-family-features": {
                    "account": ["failed_login_count", "success_after_fail"]
                },
            }
        ),
        encoding="utf-8",
    )


def test_runtime_preserves_feature_order_and_package_versions(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    freeze(package)
    runtime = ModelRuntime(package)
    incident = IncidentRequest(
        incident_id="INC-1",
        asset_id="HOST-1",
        start_time="2026-10-11T00:00:00Z",
        end_time="2026-10-11T00:01:00Z",
        family_hint="account",
        features={"success_after_fail": 1.0, "failed_login_count": 20.0},
        evidence_sources=["fixture"],
        base_severity=12,
    )

    result = runtime.predict(incident)

    assert result.predicted_class == "malicious"
    assert result.model_version == "test-model-v1"
    assert result.threshold_revision == "test-threshold-v1"
    assert result.automation_eligible is True
    assert result.review_required is False


def test_locked_test_cannot_open_before_explicit_freeze_gate(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    locked = tmp_path / "locked.jsonl"
    locked.write_text("{}\n", encoding="utf-8")

    with pytest.raises(PermissionError, match="access denied"):
        evaluate_locked_test(package, locked, unlock_locked_test=False)
    with pytest.raises(PermissionError, match="must be frozen"):
        evaluate_locked_test(package, locked, unlock_locked_test=True)

    result = freeze(package)
    assert result["model_version"] == "test-model-v1"


def test_fastapi_loads_trained_package_and_rejects_missing_features(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "package"
    create_package(package)
    freeze(package)
    monkeypatch.setenv("MODEL_PACKAGE_DIR", str(package))
    load_model_runtime.cache_clear()
    client = TestClient(app)
    payload = {
        "incident_id": "INC-API-1",
        "asset_id": "HOST-1",
        "start_time": "2026-10-11T00:00:00Z",
        "end_time": "2026-10-11T00:01:00Z",
        "family_hint": "account",
        "features": {"failed_login_count": 20.0, "success_after_fail": 1.0},
        "evidence_sources": ["fixture"],
        "base_severity": 12,
    }

    readiness = client.get("/model/ready")
    prediction = client.post("/predict", json=payload)
    payload["features"].pop("success_after_fail")
    invalid = client.post("/predict", json=payload)

    assert readiness.json()["mode"] == "trained"
    assert prediction.status_code == 200
    assert prediction.json()["model_version"] == "test-model-v1"
    assert invalid.status_code == 422


def test_runtime_rejects_tampered_frozen_artifact_before_loading(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    freeze(package)
    (package / "thresholds.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ModelPackageError, match="integrity"):
        ModelRuntime(package)


def test_runtime_rejects_threshold_mismatch_between_bundle_and_document(
    tmp_path: Path,
) -> None:
    package = tmp_path / "package"
    create_package(package)
    thresholds = json.loads((package / "thresholds.json").read_text(encoding="utf-8"))
    thresholds["families"]["account"]["threshold"] = 0.9
    (package / "thresholds.json").write_text(json.dumps(thresholds), encoding="utf-8")
    freeze(package)

    with pytest.raises(ModelPackageError, match="threshold"):
        ModelRuntime(package)


def test_ineligible_model_forces_review_instead_of_automatic_binary_decision(
    tmp_path: Path,
) -> None:
    package = tmp_path / "package"
    create_package(package, automation_eligible=False)
    freeze(package)
    runtime = ModelRuntime(package)
    incident = IncidentRequest(
        incident_id="INC-REVIEW",
        asset_id="HOST-1",
        start_time="2026-10-11T00:00:00Z",
        end_time="2026-10-11T00:01:00Z",
        family_hint="account",
        features={"failed_login_count": 20.0, "success_after_fail": 1.0},
        evidence_sources=["fixture"],
        base_severity=12,
    )

    result = runtime.predict(incident)

    assert result.predicted_class == "malicious"
    assert result.automation_eligible is False
    assert result.review_required is True


def test_locked_test_hash_is_verified_and_opening_is_recorded(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    locked = tmp_path / "locked.jsonl"
    row = {
        "family": "account",
        "label": 0,
        "features": {"failed_login_count": 0.0, "success_after_fail": 0.0},
    }
    malicious_row = {
        **row,
        "label": 1,
        "features": {"failed_login_count": 20.0, "success_after_fail": 1.0},
    }
    locked.write_text(
        json.dumps(row) + "\n" + json.dumps(malicious_row) + "\n",
        encoding="utf-8",
    )
    metadata = json.loads((package / "metadata.json").read_text(encoding="utf-8"))
    metadata["locked_test_sha256"] = hashlib.sha256(locked.read_bytes()).hexdigest()
    (package / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    bundle = joblib.load(package / "model.joblib")
    bundle["metadata"] = metadata
    joblib.dump(bundle, package / "model.joblib")
    freeze(package)

    wrong = tmp_path / "wrong.jsonl"
    wrong.write_text(json.dumps({**row, "label": 1}) + "\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="locked test integrity"):
        evaluate_locked_test(package, wrong, unlock_locked_test=True)

    result = evaluate_locked_test(package, locked, unlock_locked_test=True)

    assert result["locked_test_status"] == "EVALUATED"
    assert (package / "LOCKED_TEST_OPENED.json").is_file()
    runtime = ModelRuntime(package)
    assert runtime.locked_test_status == "EVALUATED"
