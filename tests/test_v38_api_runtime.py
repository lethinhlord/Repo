import json
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_feature_state import raw_account_alert
from test_incident_store import request
from test_threat_intelligence import make_transport
from test_webhook_auth import SECRET, signed_request

from api.app.contracts import IncidentRecordRequest
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from api.app.incident_store import IncidentStore
from api.app.threat_intelligence import VirusTotalClient
from api.app.webhook_auth import WebhookAuthenticationError, WebhookAuthenticator

BUCKET = datetime(2026, 10, 27, tzinfo=UTC).timestamp()


@pytest.mark.parametrize("retention,prune_at", [(300, 361), (86400, 86461)])
def test_evicted_window_cannot_be_certified_complete(tmp_path, monkeypatch, retention, prune_at):
    store = FeatureStateStore(tmp_path / "state.sqlite3", retention_seconds=retention)
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 10)
    store.ingest(raw_account_alert("FAIL", "2026-10-27T00:00:05Z", 4625))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 290)
    store.ingest(raw_account_alert("SUCCESS", "2026-10-27T00:04:45Z", 4624))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + prune_at)
    store.ingest(raw_account_alert("OTHER", "2026-10-27T00:06:00Z", 4624))
    with pytest.raises(FeatureStateConflictError, match="retention|evict"):
        store.finalize_window("SUCCESS")


def test_snapshot_revisions_are_durable_ordered_and_immutable_on_replay(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 20)
    first_alert = raw_account_alert("FIRST", "2026-10-27T00:00:05Z", 4625)
    first = FeatureStateStore(path).ingest(first_alert)
    second = FeatureStateStore(path).ingest(
        raw_account_alert("SECOND", "2026-10-27T00:00:15Z", 4624)
    )
    assert first.snapshot_revision > 0
    assert second.snapshot_revision > first.snapshot_revision
    assert FeatureStateStore(path).ingest(first_alert).snapshot_revision == first.snapshot_revision
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 400)
    closed = FeatureStateStore(path).finalize_window("FIRST")
    assert closed.snapshot_revision > second.snapshot_revision
    assert (
        FeatureStateStore(path).finalize_window("SECOND").snapshot_revision
        == closed.snapshot_revision
    )


@pytest.mark.parametrize("older_revision", [1, None])
def test_stale_completion_preserves_current_incident_and_escalation(tmp_path, older_revision):
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    newer = request("NEW", notification="malicious risk 9").model_copy(
        update={"snapshot_revision": 2}
    )
    recorded = store.record(newer)
    older = request("OLD", notification="benign risk 2").model_copy(
        update={"snapshot_revision": older_revision}
    )
    stale = store.record(older)
    with sqlite3.connect(store.path) as connection:
        current = json.loads(connection.execute("SELECT payload_json FROM incidents").fetchone()[0])
        statuses = connection.execute("SELECT status FROM notification_revisions").fetchall()
    assert current["source_event_id"] == "NEW"
    assert statuses == [("QUEUED",)]
    assert stale.disposition == "stale"
    assert stale.notification_revision == recorded.notification_revision
    assert store.record(older).disposition == "duplicate"
    assert (
        store.dispatch_notification(
            newer.incident_id,
            lambda *_: "audit-log",
            notification_revision=recorded.notification_revision,
        ).notification_status
        == "SENT"
    )


def test_feature_failure_is_durable_retryable_without_consuming_event(tmp_path):
    path = tmp_path / "incidents.sqlite3"
    failure = IncidentRecordRequest.model_validate(
        {
            **request("RETRY").model_dump(),
            "processing_status": "retryable",
            "source_payload_sha256": "a" * 64,
            "decision": {"raw_payload": {"id": "RETRY"}, "feature_error": {"statusCode": 503}},
        }
    )
    store = IncidentStore(path)
    assert store.record(failure).disposition == "retryable"
    assert IncidentStore(path).get_event_outcome("RETRY", payload_sha256="a" * 64) is None
    with sqlite3.connect(path) as connection:
        saved = json.loads(
            connection.execute("SELECT payload_json FROM retryable_events").fetchone()[0]
        )
        assert saved["decision"]["raw_payload"] == {"id": "RETRY"}
        assert saved["decision"]["feature_error"]["statusCode"] == 503
        assert connection.execute("SELECT COUNT(*) FROM processed_events").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM notification_revisions").fetchone()[0] == 0
    recovered = request("RETRY").model_copy(update={"source_payload_sha256": "a" * 64})
    assert IncidentStore(path).record(recovered).disposition == "created"
    assert (
        IncidentStore(path).get_event_outcome("RETRY", payload_sha256="a" * 64).disposition
        == "duplicate"
    )


@pytest.mark.parametrize("votes", [{"harmless": 10}, {"malicious": 10}])
def test_future_ti_report_is_unknown(votes):
    now = datetime(2026, 11, 4, tzinfo=UTC)
    payload = {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "last_analysis_date": int(now.timestamp()) + 1,
                "last_analysis_stats": votes,
            },
        }
    }
    result = VirusTotalClient(
        api_key="unit-test-key", clock=lambda: now, transport=make_transport(200, payload)
    ).lookup("8.8.8.8")
    assert result.status == "UNKNOWN"
    assert result.available is False
    assert result.score is None
    assert result.reason_code == "FUTURE_REPORT"


@pytest.mark.parametrize("elapsed", [301, 600])
def test_future_signed_timestamp_nonce_survives_entire_validity_interval(
    tmp_path, monkeypatch, elapsed
):
    now = 1800000000
    monkeypatch.setattr("api.app.webhook_auth.time.time", lambda: now)
    auth = WebhookAuthenticator(tmp_path / "auth.sqlite3", SECRET)
    signed = signed_request(offset=300)
    auth.verify(signed)
    monkeypatch.setattr("api.app.webhook_auth.time.time", lambda: now + elapsed)
    with pytest.raises(WebhookAuthenticationError, match="already used"):
        WebhookAuthenticator(auth.path, SECRET).verify(signed)


def _workflow_nodes():
    path = Path(__file__).resolve().parents[1] / "n8n/workflows/week2-feature-ti-asset-shadow.json"
    document = json.loads(path.read_text())
    return document, {n["name"]: n for n in document["nodes"]}


def _run_code(code, nodes, current=None):
    source = (
        'const f = new Function("$node", "$json", '
        + json.dumps(code)
        + "); process.stdout.write(JSON.stringify(f("
        + json.dumps(nodes)
        + ","
        + json.dumps(current or {})
        + ")));"
    )
    return json.loads(
        subprocess.run(["node", "-e", source], check=True, capture_output=True, text=True).stdout
    )[0]["json"]


def test_workflow_feature_failure_preserves_evidence_returns_503_and_bypasses_terminal_branch(
    tmp_path,
):
    document, nodes = _workflow_nodes()
    connections = document["connections"]
    assert (
        connections["Extract Incident Features"]["main"][0][0]["node"]
        == "Feature Snapshot Available?"
    )
    assert connections["Feature Snapshot Available?"]["main"][0][0]["node"] == "Call AI Model"
    assert (
        connections["Feature Snapshot Available?"]["main"][1][0]["node"]
        == "Build Retryable Feature Failure"
    )
    data = {
        "Wazuh Alert Webhook v2": {"json": {"body": {"id": "RETRY", "data": {"raw": "preserved"}}}},
        "Verify Signed Ingress": {
            "json": {"verified": True, "source_event_id": "RETRY", "payload_sha256": "b" * 64}
        },
        "Extract Incident Features": {
            "json": {"error": {"message": "temporary feature 503", "statusCode": 503}}
        },
    }
    failure = _run_code(nodes["Build Retryable Feature Failure"]["parameters"]["jsCode"], data)
    assert failure["decision"]["raw_payload"] == data["Wazuh Alert Webhook v2"]["json"]["body"]
    assert failure["decision"]["feature_error"] == data["Extract Incident Features"]["json"]
    store = IncidentStore(tmp_path / "workflow.sqlite3")
    persisted = store.record(IncidentRecordRequest.model_validate(failure))
    response = _run_code(
        nodes["Build Feature Retry Response"]["parameters"]["jsCode"],
        {},
        persisted.model_dump(mode="json"),
    )
    assert response["response_code"] == 503
    assert response["status"] == "feature_retryable"
    assert response["strong_action_allowed"] is False
    assert store.get_event_outcome("RETRY", payload_sha256="b" * 64) is None
    assert (
        connections["Persist Retryable Feature Failure"]["main"][0][0]["node"]
        == "Build Feature Retry Response"
    )
    assert connections["Build Feature Retry Response"]["main"][0][0]["node"] == "Respond to Webhook"


def test_equal_snapshot_revision_conflicting_decision_fails_without_mutation(tmp_path):
    store = IncidentStore(tmp_path / "equal.sqlite3")
    store.record(request("NEW").model_copy(update={"snapshot_revision": 7}))
    with pytest.raises(ValueError, match="snapshot revision.*conflict"):
        store.record(
            request("CONFLICT", notification="conflicting").model_copy(
                update={"snapshot_revision": 7}
            )
        )
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM notification_revisions").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM processed_events").fetchone()[0] == 1


def test_eviction_tombstone_survives_restart_when_event_clock_is_ahead(tmp_path, monkeypatch):
    path = tmp_path / "eviction.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET - 86410)
    FeatureStateStore(path).ingest(raw_account_alert("EARLY", "2026-10-27T00:00:05Z", 4625))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 20)
    FeatureStateStore(path).ingest(raw_account_alert("ANCHOR", "2026-10-27T00:00:15Z", 4624))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 400)
    with pytest.raises(FeatureStateConflictError, match="evicted"):
        FeatureStateStore(path).finalize_window("ANCHOR")


def test_retryable_replays_preserve_original_raw_error_and_reject_changed_raw(tmp_path):
    store = IncidentStore(tmp_path / "pending.sqlite3")
    failure = request("PENDING").model_copy(
        update={
            "processing_status": "retryable",
            "source_payload_sha256": "c" * 64,
            "decision": {"raw_payload": {"id": "PENDING"}, "feature_error": {"error": "first 503"}},
        }
    )
    store.record(failure)
    store.record(
        failure.model_copy(
            update={
                "decision": {
                    "raw_payload": {"id": "PENDING"},
                    "feature_error": {"error": "later timeout"},
                }
            }
        )
    )
    with sqlite3.connect(store.path) as connection:
        saved = json.loads(
            connection.execute("SELECT payload_json FROM retryable_events").fetchone()[0]
        )
        assert saved["decision"]["feature_error"] == {"error": "first 503"}
    with pytest.raises(ValueError, match="different raw payload"):
        store.record(failure.model_copy(update={"source_payload_sha256": "d" * 64}))
    with pytest.raises(ValueError, match="different raw payload"):
        store.record(request("PENDING").model_copy(update={"source_payload_sha256": "d" * 64}))


def test_workflow_passes_durable_snapshot_revision_to_persistence():
    _, nodes = _workflow_nodes()
    data = {
        "Extract Incident Features": {
            "json": {
                "snapshot_revision": 42,
                "feature": {
                    "incident": {"incident_id": "INC-SNAPSHOT", "review_reasons": []},
                    "quality_status": "PARTIAL",
                },
            }
        },
        "Call AI Model": {"json": {}},
        "Lookup Threat Intelligence": {"json": {}},
        "Load Asset Context": {"json": {}},
        "Evaluate Risk": {"json": {}},
        "Verify Signed Ingress": {
            "json": {
                "verified": True,
                "source_event_id": "SNAPSHOT",
                "payload_sha256": "e" * 64,
            }
        },
    }
    gate = _run_code(nodes["Enforce Shadow Gate"]["parameters"]["jsCode"], data)
    assert gate["snapshot_revision"] == 42
    for name in ("Build Review Decision", "Build Shadow Decision"):
        persisted = _run_code(nodes[name]["parameters"]["jsCode"], {}, gate)
        assert persisted["snapshot_revision"] == 42


def test_concurrent_snapshot_transactions_allocate_distinct_durable_revisions(
    tmp_path, monkeypatch
):
    path = tmp_path / "concurrent-features.sqlite3"
    stores = [FeatureStateStore(path), FeatureStateStore(path)]
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 20)
    alerts = [raw_account_alert(f"THREAD-{i}", "2026-10-27T00:00:05Z", 4625) for i in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda pair: pair[0].ingest(pair[1]), zip(stores, alerts, strict=True))
        )
    assert sorted(result.snapshot_revision for result in results) == [1, 2]
    assert sorted(result.stored_event_count for result in results) == [1, 2]
    for alert, result in zip(alerts, results, strict=True):
        assert FeatureStateStore(path).ingest(alert).snapshot_revision == result.snapshot_revision


def test_concurrent_completions_keep_highest_snapshot_and_its_notification(tmp_path):
    store = IncidentStore(tmp_path / "concurrent-incidents.sqlite3")
    decisions = [
        request(f"THREAD-{i}", notification=f"risk {i}").model_copy(update={"snapshot_revision": i})
        for i in (1, 2)
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(store.record, decisions))
    with sqlite3.connect(store.path) as connection:
        current = json.loads(connection.execute("SELECT payload_json FROM incidents").fetchone()[0])
        notifications = connection.execute(
            "SELECT notification FROM notification_revisions WHERE status='QUEUED'"
        ).fetchall()
        assert current["snapshot_revision"] == 2
        assert notifications == [("risk 2",)]
        assert connection.execute("SELECT COUNT(*) FROM incident_decisions").fetchone()[0] == 2


def test_legacy_cached_snapshot_recovers_with_current_facts_and_keeps_original_evidence(
    tmp_path, monkeypatch
):
    path = tmp_path / "legacy.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 20)
    first_alert = raw_account_alert("LEGACY-FIRST", "2026-10-27T00:00:05Z", 4625)
    store = FeatureStateStore(path)
    historical = store.ingest(first_alert).model_dump(mode="json")
    historical.pop("snapshot_revision")
    newer = store.ingest(raw_account_alert("LEGACY-SECOND", "2026-10-27T00:00:15Z", 4624))
    legacy_json = json.dumps(historical)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE wazuh_alerts SET feature_response_json=? WHERE alert_id=?",
            (legacy_json, first_alert.id),
        )
    recovered = FeatureStateStore(path).ingest(first_alert)
    assert recovered.snapshot_revision is not None
    assert recovered.snapshot_revision > newer.snapshot_revision
    assert recovered.stored_event_count == 2
    assert recovered.feature.incident.features["successful_login_count"] == 1
    assert recovered.feature.quality_status == "PARTIAL"
    assert "window:legacy_rebuilt" in recovered.feature.incident.review_reasons
    assert FeatureStateStore(path).ingest(first_alert) == recovered
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT legacy_feature_response_json FROM wazuh_alerts WHERE alert_id=?",
                (first_alert.id,),
            ).fetchone()[0]
            == legacy_json
        )


def test_legacy_closed_snapshot_recovers_current_revision_preserving_close_evidence(
    tmp_path, monkeypatch
):
    path = tmp_path / "legacy-close.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 20)
    alert = raw_account_alert("LEGACY-CLOSE", "2026-10-27T00:00:05Z", 4625)
    store = FeatureStateStore(path)
    ingested = store.ingest(alert)
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 400)
    closed = store.finalize_window(alert.id)
    legacy = closed.model_dump(mode="json")
    legacy.pop("snapshot_revision")
    legacy_json = json.dumps(legacy)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE closed_feature_windows SET response_json=?", (legacy_json,))
    recovered = FeatureStateStore(path).finalize_window(alert.id)
    assert recovered.snapshot_revision is not None
    assert recovered.snapshot_revision > closed.snapshot_revision > ingested.snapshot_revision
    assert recovered.feature == closed.feature
    assert FeatureStateStore(path).finalize_window(alert.id) == recovered
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT legacy_response_json FROM closed_feature_windows"
            ).fetchone()[0]
            == legacy_json
        )


def test_out_of_range_future_ti_timestamp_fails_closed_without_exception():
    payload = {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {"last_analysis_date": 10**30, "last_analysis_stats": {"harmless": 10}},
        }
    }
    result = VirusTotalClient(
        api_key="unit-test-key", transport=make_transport(200, payload)
    ).lookup("8.8.8.8")
    assert result.status == "UNKNOWN"
    assert result.available is False
    assert result.reason_code == "INVALID_RESPONSE"
