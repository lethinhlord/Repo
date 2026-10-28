import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from api.app.main import (
    app,
    load_feature_state_store,
    load_feedback_store,
    load_incident_store,
    load_webhook_authenticator,
)
from api.app.webhook_auth import sign_payload

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app)


def fixture(name: str) -> dict:
    return json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))


def test_feature_endpoint_normalizes_raw_wazuh_alert() -> None:
    response = client.post("/features/wazuh", json=fixture("wazuh-alert-c2.json"))

    assert response.status_code == 200
    body = response.json()
    assert body["feature_schema_version"] == "features-v3"
    assert body["incident"]["family_hint"] == "c2"
    assert body["incident"]["features"]["periodicity_score"] == 0.87
    assert 0.0 <= body["evidence_quality"] <= 1.0
    assert body["evidence_quality_reasons"]


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


def test_stateful_feature_endpoint_persists_and_deduplicates(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FEATURE_STATE_DB", str(tmp_path / "state.sqlite3"))
    load_feature_state_store.cache_clear()
    alert = fixture("wazuh-alert-account.json")

    first = client.post("/features/wazuh/stateful", json=alert)
    replay = client.post("/features/wazuh/stateful", json=alert)

    assert first.status_code == 200
    assert first.json()["ingest_status"] == "new"
    assert replay.status_code == 200
    assert replay.json()["ingest_status"] == "duplicate"


def test_stateful_feature_endpoint_rejects_conflicting_replay(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FEATURE_STATE_DB", str(tmp_path / "state.sqlite3"))
    load_feature_state_store.cache_clear()
    first = fixture("wazuh-alert-account.json")
    conflicting = fixture("wazuh-alert-account.json")
    conflicting["timestamp"] = "2026-10-05T12:00:01Z"

    assert client.post("/features/wazuh/stateful", json=first).status_code == 200
    response = client.post("/features/wazuh/stateful", json=conflicting)

    assert response.status_code == 409


def test_incident_record_endpoint_is_idempotent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("INCIDENT_DB", str(tmp_path / "incidents.sqlite3"))
    load_incident_store.cache_clear()
    payload = {
        "incident_id": "INC-API-1",
        "source_event_id": "EVENT-API-1",
        "route": "review",
        "review_required": True,
        "notification": "manual review required",
        "decision": {"risk": {"display": 6.2}},
    }

    first = client.post("/incidents/record", json=payload)
    replay = client.post("/incidents/record", json=payload)

    assert first.status_code == 200
    assert first.json()["disposition"] == "created"
    assert first.json()["notification_status"] == "QUEUED"
    assert replay.status_code == 200
    assert replay.json()["disposition"] == "duplicate"

    monkeypatch.setenv("NOTIFICATION_MODE", "log")
    delivery = client.post(
        "/notifications/dispatch", json={"incident_id": "INC-API-1"}
    )
    delivery_replay = client.post(
        "/notifications/dispatch", json={"incident_id": "INC-API-1"}
    )
    assert delivery.status_code == 200
    assert delivery.json()["notification_status"] == "SENT"
    assert delivery.json()["channel"] == "audit-log"
    assert delivery_replay.status_code == 200
    assert delivery_replay.json()["notification_status"] == "ALREADY_SENT"


def test_failed_notification_delivery_remains_retryable(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("INCIDENT_DB", str(tmp_path / "incidents.sqlite3"))
    monkeypatch.setenv("NOTIFICATION_MODE", "disabled")
    load_incident_store.cache_clear()
    payload = {
        "incident_id": "INC-RETRY-1",
        "source_event_id": "EVENT-RETRY-1",
        "route": "review",
        "review_required": True,
        "notification": "manual review required",
        "decision": {"risk": {"display": 6.2}},
    }
    assert client.post("/incidents/record", json=payload).status_code == 200

    failed = client.post(
        "/notifications/dispatch", json={"incident_id": "INC-RETRY-1"}
    )
    monkeypatch.setenv("NOTIFICATION_MODE", "log")
    retried = client.post(
        "/notifications/dispatch", json={"incident_id": "INC-RETRY-1"}
    )

    assert failed.status_code == 503
    assert retried.status_code == 200
    assert retried.json()["notification_status"] == "SENT"


def test_model_feedback_is_traceable_and_idempotent(monkeypatch, tmp_path: Path) -> None:
    incident_path = tmp_path / "incidents.sqlite3"
    monkeypatch.setenv("INCIDENT_DB", str(incident_path))
    monkeypatch.setenv("MODEL_FEEDBACK_DB", str(tmp_path / "feedback.sqlite3"))
    load_incident_store.cache_clear()
    load_feedback_store.cache_clear()
    incident = {
        "incident_id": "INC-API-1",
        "source_event_id": "EVENT-FEEDBACK-1",
        "route": "review",
        "review_required": True,
        "notification": "manual review required",
        "decision": {"prediction": {
            "model_version": "week3-test-v1", "predicted_class": "malicious"
        }},
    }
    assert client.post("/incidents/record", json=incident).status_code == 200
    payload = {
        "incident_id": "INC-API-1",
        "model_version": "week3-test-v1",
        "analyst_id": "analyst-01",
        "analyst_label": "benign",
        "disposition": "false_positive",
        "notes": "Interactive administration confirmed by ticket.",
    }

    first = client.post("/model/feedback", json=payload)
    replay = client.post("/model/feedback", json=payload)

    assert first.status_code == 200
    assert first.json()["disposition"] == "created"
    assert len(first.json()["feedback_id"]) == 64
    assert replay.status_code == 200
    assert replay.json()["disposition"] == "duplicate"


def test_model_feedback_rejects_semantic_contradiction() -> None:
    response = client.post(
        "/model/feedback",
        json={
            "incident_id": "INC-API-2",
            "model_version": "week3-test-v1",
            "analyst_id": "analyst-02",
            "analyst_label": "malicious",
            "disposition": "false_positive",
        },
    )

    assert response.status_code == 422


def test_model_feedback_rejects_unknown_incident(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("INCIDENT_DB", str(tmp_path / "incidents.sqlite3"))
    monkeypatch.setenv("MODEL_FEEDBACK_DB", str(tmp_path / "feedback.sqlite3"))
    load_incident_store.cache_clear()
    load_incident_store(str(tmp_path / "incidents.sqlite3"))
    load_feedback_store.cache_clear()

    response = client.post(
        "/model/feedback",
        json={
            "incident_id": "INC-UNKNOWN",
            "model_version": "week3-test-v1",
            "analyst_id": "analyst-02",
            "analyst_label": "malicious",
            "disposition": "false_negative",
        },
    )

    assert response.status_code == 409
    assert "unknown incident" in response.json()["detail"]


def test_signed_ingress_endpoint_authenticates_and_blocks_replay(
    monkeypatch, tmp_path: Path
) -> None:
    secret = "api-test-webhook-secret-that-is-at-least-32-bytes"
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("INGRESS_NONCE_DB", str(tmp_path / "nonces.sqlite3"))
    load_webhook_authenticator.cache_clear()
    payload = fixture("wazuh-alert-account.json")
    timestamp = int(time.time())
    nonce = "api-nonce-0000000001"
    request = {
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": sign_payload(
            secret,
            timestamp=timestamp,
            nonce=nonce,
            payload=payload,
        ),
        "payload": payload,
    }

    first = client.post("/ingress/wazuh/verify", json=request)
    replay = client.post("/ingress/wazuh/verify", json=request)

    assert first.status_code == 200
    assert first.json()["verified"] is True
    assert replay.status_code == 401


def test_readiness_exposes_week2_revisions_and_safe_gate(monkeypatch) -> None:
    monkeypatch.setenv("VT_MODE", "mock")
    monkeypatch.delenv("MODEL_PACKAGE_DIR", raising=False)
    monkeypatch.setenv("ALLOW_MOCK_INFERENCE", "false")

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "degraded",
        "service": "datn-ai-soar-api",
        "api_version": "4.0.0",
        "feature_schema_version": "features-v3",
        "asset_context_revision": "asset-context-v1",
        "risk_policy_revision": "risk-week2-v2",
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


def test_risk_endpoint_penalizes_missing_context_and_requires_review() -> None:
    response = client.post(
        "/risk/evaluate",
        json={
            "ai_probability": 0.8,
            "observed_evidence": 0.5,
            "threat_intelligence_score": None,
            "asset_score": None,
            "severity_score": 0.8,
            "feature_quality": "COMPLETE",
            "model_automation_eligible": True,
            "model_review_required": False,
            "threat_intelligence_status": "UNKNOWN",
            "asset_review_required": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["policy_revision"] == "risk-week2-v2"
    assert body["review_required"] is True
    assert set(body["missing_signals"]) == {"threat_intelligence", "asset"}
    assert body["available_weight"] == 0.7
    assert body["internal"] == 0.5
    assert body["display"] == 5.0
    assert "asset:review_required" in body["review_reasons"]
