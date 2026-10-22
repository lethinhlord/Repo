import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.app.main import app

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app)


def fixture(name: str) -> dict:
    return json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))


def test_feature_endpoint_normalizes_raw_wazuh_alert() -> None:
    response = client.post("/features/wazuh", json=fixture("wazuh-alert-c2.json"))

    assert response.status_code == 200
    body = response.json()
    assert body["feature_schema_version"] == "features-v1"
    assert body["incident"]["family_hint"] == "c2"
    assert body["incident"]["features"]["periodicity_score"] == 0.87


def test_batch_feature_endpoint_reports_duplicate_count() -> None:
    alert = fixture("wazuh-alert-account.json")
    response = client.post(
        "/features/wazuh/batch",
        json={"alerts": [alert, alert], "window_minutes": 5},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["input_alert_count"] == 2
    assert body["unique_alert_count"] == 1
    assert body["duplicate_alert_count"] == 1
    assert len(body["incidents"]) == 1


def test_readiness_exposes_week2_revisions_and_safe_gate(monkeypatch) -> None:
    monkeypatch.setenv("VT_MODE", "mock")
    monkeypatch.delenv("MODEL_PACKAGE_DIR", raising=False)
    monkeypatch.setenv("ALLOW_MOCK_INFERENCE", "false")

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "degraded",
        "service": "datn-ai-soar-api",
        "api_version": "3.1.0",
        "feature_schema_version": "features-v1",
        "asset_context_revision": "asset-context-v1",
        "risk_policy_revision": "risk-week2-v1",
        "ti_policy_revision": "ti-week2-v1",
        "ti_mode": "mock",
        "model_status": "not_configured",
        "inference_mode": "unconfigured",
        "strong_actions_enabled": False,
    }


def test_predict_fails_closed_when_model_is_missing(monkeypatch) -> None:
    monkeypatch.delenv("MODEL_PACKAGE_DIR", raising=False)
    monkeypatch.setenv("ALLOW_MOCK_INFERENCE", "false")

    response = client.post(
        "/predict",
        json={
            "incident_id": "INC-NO-MODEL",
            "asset_id": "WIN11-TARGET",
            "start_time": "2026-10-11T00:00:00Z",
            "end_time": "2026-10-11T00:01:00Z",
            "family_hint": "account",
            "features": {"failed_login_count": 1.0, "success_after_fail": 1.0},
            "evidence_sources": ["fixture"],
            "base_severity": 5,
        },
    )

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_asset_endpoint_returns_inventory_and_safe_default() -> None:
    known = client.get("/assets/WIN11-02")
    unknown = client.get("/assets/not-registered")

    assert known.status_code == 200
    assert known.json()["source"] == "inventory"
    assert known.json()["risk_score"] == 0.6
    assert unknown.status_code == 200
    assert unknown.json()["protected"] is True
    assert unknown.json()["risk_score"] is None
    assert unknown.json()["review_required"] is True


def test_ti_endpoint_uses_deterministic_mock_without_secret(monkeypatch) -> None:
    monkeypatch.setenv("VT_MODE", "mock")
    monkeypatch.delenv("VT_API_KEY", raising=False)

    response = client.post("/ti/lookup", json={"indicator": "203.0.113.66"})

    assert response.status_code == 200
    assert response.json()["provider"] == "mock-ti-v2"
    assert response.json()["status"] == "MALICIOUS"


def test_ti_endpoint_rejects_extra_input_fields() -> None:
    response = client.post(
        "/ti/lookup",
        json={"indicator": "8.8.8.8", "api_key": "must-never-be-accepted"},
    )

    assert response.status_code == 422


def test_risk_endpoint_renormalizes_missing_context_and_requires_review() -> None:
    response = client.post(
        "/risk/evaluate",
        json={
            "ai_probability": 0.8,
            "observed_evidence": 0.5,
            "threat_intelligence_score": None,
            "asset_score": None,
            "severity_score": 0.8,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["policy_revision"] == "risk-week2-v1"
    assert body["review_required"] is True
    assert set(body["missing_signals"]) == {"threat_intelligence", "asset"}
    assert body["available_weight"] == 0.7
    assert body["internal"] == 0.714286
    assert body["display"] == 7.1
