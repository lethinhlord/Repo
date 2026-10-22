from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from api.app.main import app

client = TestClient(app)


def incident_payload() -> dict:
    started = datetime(2026, 10, 5, 8, 0, tzinfo=UTC)
    return {
        "incident_id": "INC-W1-0001",
        "asset_id": "WIN11-01",
        "start_time": started.isoformat(),
        "end_time": (started + timedelta(minutes=2)).isoformat(),
        "family_hint": "account",
        "features": {"failed_login_count": 12.0, "success_after_fail": 1.0},
        "evidence_sources": ["Wazuh", "Sysmon"],
        "base_severity": 12,
        "raw_refs": ["wazuh-alert-0001"],
        "indicator": "203.0.113.66",
    }


def test_health_exposes_service_liveness_identity() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "datn-ai-soar-api",
        "api_version": "3.1.0",
    }


def test_explicit_lab_mock_returns_deterministic_contract(monkeypatch) -> None:
    monkeypatch.delenv("MODEL_PACKAGE_DIR", raising=False)
    monkeypatch.setenv("ALLOW_MOCK_INFERENCE", "true")
    first = client.post("/predict", json=incident_payload())
    second = client.post("/predict", json=incident_payload())

    assert first.status_code == 200
    assert first.json() == second.json()
    assert first.json()["predicted_class"] == "malicious"
    assert first.json()["malicious_probability"] == 0.95
    assert first.json()["family"] == "account"
    assert first.json()["threshold_revision"] == "mock-thr-v1"
    assert first.json()["automation_eligible"] is False
    assert first.json()["review_required"] is True


def test_predict_rejects_end_before_start() -> None:
    payload = incident_payload()
    payload["end_time"] = "2026-10-05T07:59:00+00:00"

    response = client.post("/predict", json=payload)

    assert response.status_code == 422


def test_orchestrate_returns_shadow_decision_and_audit_record() -> None:
    response = client.post("/orchestrate/mock", json=incident_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["automation_state"] == "SHADOW"
    assert body["selected_playbook"] == "create_update_incident_notify"
    assert body["strong_action_allowed"] is False
    assert body["ti_context"]["status"] == "MALICIOUS"
    assert body["risk"]["display"] == 8.9
    assert body["audit"]["incident_id"] == "INC-W1-0001"
    assert body["audit"]["workflow_revision"] == "week1-mock-v1"


def test_unknown_indicator_degrades_to_unknown_ti_without_failure() -> None:
    payload = incident_payload()
    payload["indicator"] = "unknown.example"

    response = client.post("/orchestrate/mock", json=payload)

    assert response.status_code == 200
    assert response.json()["ti_context"]["status"] == "UNKNOWN"
