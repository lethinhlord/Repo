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

ROOT = Path(__file__).resolve().parents[1]
SIGNING_KEY = "test-model-signing-key-that-is-at-least-32-bytes"


@pytest.fixture(autouse=True)
def configure_signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", SIGNING_KEY)


def account_features(failed: float, success_after_fail: float) -> dict[str, float]:
    return {
        "failed_login_count": failed,
        "successful_login_count": success_after_fail,
        "success_after_fail": success_after_fail,
        "unique_target_account_count": 1.0,
        "unique_source_count": 1.0,
        "remote_logon_ratio": 1.0,
        "failure_window_seconds": failed,
        "attempt_rate_per_minute": failed + success_after_fail,
    }


def create_package(path: Path, *, automation_eligible: bool = True) -> None:
    feature_order = list(account_features(0.0, 0.0))
    estimator = LogisticRegression(random_state=42).fit(
        np.asarray(
            [
                list(account_features(0.0, 0.0).values()),
                list(account_features(1.0, 0.0).values()),
                list(account_features(10.0, 1.0).values()),
                list(account_features(20.0, 1.0).values()),
            ]
        ),
        np.asarray([0, 0, 1, 1]),
    )
    metadata = {
        "model_version": "test-model-v1",
        "feature_schema_version": "features-v2",
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
                    "feature_order": feature_order,
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
    (path / "calibration_validation.json").write_text("{}", encoding="utf-8")
    (path / "feature_profile.json").write_text(
        json.dumps(
            {
                "revision": "feature-profile-v1",
                "families": {
                    "account": {
                        "records": 4,
                        "features": {
                            name: {"ood_lower": -1.0, "ood_upper": 30.0}
                            for name in feature_order
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (path / "feature_schema.json").write_text(
        (ROOT / "ml/feature_schema.json").read_text(encoding="utf-8"),
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
        features=account_features(20.0, 1.0),
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
        "features": account_features(20.0, 1.0),
        "evidence_sources": ["fixture"],
        "base_severity": 12,
    }

    readiness = client.get("/model/ready")
    prediction = client.post("/predict", json=payload)
    metrics = client.get("/model/metrics")
    payload["features"].pop("success_after_fail")
    invalid = client.post("/predict", json=payload)

    assert readiness.json()["mode"] == "trained"
    assert prediction.status_code == 200
    assert prediction.json()["model_version"] == "test-model-v1"
    assert metrics.status_code == 200
    assert metrics.json()["predictions_total"] == 1
    assert invalid.status_code == 422


def test_runtime_rejects_tampered_frozen_artifact_before_loading(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    freeze(package)
    (package / "thresholds.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ModelPackageError, match="integrity"):
        ModelRuntime(package)


def test_runtime_rejects_rewritten_unsigned_freeze_manifest(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    freeze(package)
    document = json.loads((package / "FROZEN.json").read_text(encoding="utf-8"))
    document["model_version"] = "attacker-rewrite"
    (package / "FROZEN.json").write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ModelPackageError, match="signature"):
        ModelRuntime(package)


def test_runtime_rejects_package_with_non_active_schema(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    schema = json.loads((package / "feature_schema.json").read_text(encoding="utf-8"))
    schema["description"] = "tampered but internally versioned"
    (package / "feature_schema.json").write_text(json.dumps(schema), encoding="utf-8")
    freeze(package)

    with pytest.raises(ModelPackageError, match="active runtime schema"):
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
        features=account_features(20.0, 1.0),
        evidence_sources=["fixture"],
        base_severity=12,
    )

    result = runtime.predict(incident)

    assert result.predicted_class == "malicious"
    assert result.automation_eligible is False
    assert result.review_required is True


def test_out_of_distribution_input_abstains_and_updates_metrics(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    freeze(package)
    runtime = ModelRuntime(package)
    features = account_features(100.0, 1.0)
    incident = IncidentRequest(
        incident_id="INC-OOD",
        asset_id="HOST-1",
        start_time="2026-10-11T00:00:00Z",
        end_time="2026-10-11T00:01:00Z",
        family_hint="account",
        features=features,
        evidence_sources=["fixture"],
        base_severity=12,
    )

    result = runtime.predict(incident)
    metrics = runtime.metrics_snapshot()

    assert result.ood_detected is True
    assert "failed_login_count" in result.ood_features
    assert result.automation_eligible is False
    assert result.review_required is True
    assert metrics.predictions_total == 1
    assert metrics.ood_total == 1
    assert metrics.ood_by_family == {"account": 1}
    assert metrics.monitoring_alerts == []
    assert metrics.review_required_total == 1


def test_sustained_ood_rate_raises_monitoring_alert(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    freeze(package)
    runtime = ModelRuntime(package)
    incident = IncidentRequest(
        incident_id="INC-OOD-ALERT",
        asset_id="HOST-1",
        start_time="2026-10-11T00:00:00Z",
        end_time="2026-10-11T00:01:00Z",
        family_hint="account",
        features=account_features(100.0, 1.0),
        evidence_sources=["fixture"],
        base_severity=12,
    )

    for _ in range(ModelRuntime.OOD_ALERT_MINIMUM_SAMPLES):
        runtime.predict(incident)

    assert runtime.metrics_snapshot().monitoring_alerts == ["OOD_RATE_HIGH:account"]


def test_locked_test_hash_is_verified_and_opening_is_recorded(tmp_path: Path) -> None:
    package = tmp_path / "package"
    create_package(package)
    locked = tmp_path / "locked.jsonl"
    row = {
        "family": "account",
        "label": 0,
        "features": account_features(0.0, 0.0),
    }
    malicious_row = {
        **row,
        "label": 1,
        "features": account_features(20.0, 1.0),
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
