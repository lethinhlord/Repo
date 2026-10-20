from __future__ import annotations

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
from ml.inference import ModelRuntime


def create_package(path: Path) -> None:
    estimator = LogisticRegression(random_state=42).fit(
        np.asarray([[0.0, 0.0], [1.0, 0.0], [10.0, 1.0], [20.0, 1.0]]),
        np.asarray([0, 0, 1, 1]),
    )
    metadata = {
        "model_version": "test-model-v1",
        "feature_schema_version": "features-v1",
        "locked_test_status": "UNOPENED",
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
        json.dumps({"revision": "test-threshold-v1"}), encoding="utf-8"
    )
    (path / "metrics_validation.json").write_text("{}", encoding="utf-8")


def test_runtime_preserves_feature_order_and_package_versions(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
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
