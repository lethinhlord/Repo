import json
import sqlite3
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from api.app.contracts import IncidentRecordRequest
from api.app.incident_store import IncidentStore
from api.app.main import app, load_incident_store
from api.app.notification import deliver_notification


def decision(event_id: str, *, review: bool, notification: str) -> IncidentRecordRequest:
    return IncidentRecordRequest(
        incident_id="INC-ESCALATION",
        source_event_id=event_id,
        route="review" if review else "shadow",
        review_required=review,
        notification=notification,
        decision={
            "prediction": {
                "model_version": "test-model-v1",
                "predicted_class": "malicious" if review else "benign",
            }
        },
    )


def test_escalation_after_delivery_sends_a_new_revision_once(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    sent = []

    def sender(incident_id, message, *key):
        sent.append((incident_id, message, key))
        return "webhook"

    store.record(decision("E1", review=False, notification="initial low risk"))
    store.dispatch_notification("INC-ESCALATION", sender)
    store.record(decision("E2", review=True, notification="escalated malicious"))
    store.dispatch_notification("INC-ESCALATION", sender)
    replay = store.dispatch_notification("INC-ESCALATION", sender)

    assert [item[1] for item in sent] == ["initial low risk", "escalated malicious"]
    assert sent[0][2] != sent[1][2]
    assert replay.notification_status == "ALREADY_SENT"


def test_queued_update_dispatches_current_text_and_keeps_history(tmp_path: Path) -> None:
    path = tmp_path / "incidents.sqlite3"
    store = IncidentStore(path)
    sent = []
    store.record(decision("E1", review=False, notification="initial low risk"))
    store.record(decision("E2", review=True, notification="escalated malicious"))
    store.dispatch_notification(
        "INC-ESCALATION", lambda _, message, *_key: sent.append(message) or "webhook"
    )

    assert sent == ["escalated malicious"]
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT notification, status FROM notification_revisions "
            "WHERE incident_id = ? ORDER BY revision", ("INC-ESCALATION",)
        ).fetchall()
    assert rows == [("initial low risk", "SUPERSEDED"), ("escalated malicious", "SENT")]


def test_inflight_delivery_cannot_mark_new_revision_sent(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    store.record(decision("E1", review=False, notification="initial"))

    def sender(_incident_id, _message, *_key):
        store.record(decision("E2", review=True, notification="escalated"))
        return "webhook"

    store.dispatch_notification("INC-ESCALATION", sender)
    sent = []
    current = store.dispatch_notification(
        "INC-ESCALATION", lambda _, message, *_key: sent.append(message) or "webhook"
    )

    assert current.notification_status == "SENT"
    assert sent == ["escalated"]


def test_legacy_sent_outbox_is_migrated_without_resending(tmp_path: Path) -> None:
    path = tmp_path / "incidents.sqlite3"
    store = IncidentStore(path)
    old = decision("E1", review=False, notification="legacy sent")
    store.record(old)
    # Construct the old persisted shape, independently of the new outbox code.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE IF EXISTS notification_revisions")
        stamp = datetime(2026, 10, 27, tzinfo=UTC).isoformat()
        connection.execute(
            "INSERT OR REPLACE INTO notification_outbox "
            "(incident_id,notification,status,created_at,delivered_at,channel) "
            "VALUES (?,?, 'SENT',?,?,'webhook')",
            (old.incident_id, old.notification, stamp, stamp),
        )
    migrated = IncidentStore(path)
    sent = []
    replay = migrated.dispatch_notification(
        "INC-ESCALATION", lambda _, message, *_key: sent.append(message) or "webhook"
    )
    assert replay.notification_status == "ALREADY_SENT"
    assert sent == []
    migrated.record(decision("E2", review=True, notification="new escalation"))
    migrated.dispatch_notification(
        "INC-ESCALATION", lambda _, message, *_key: sent.append(message) or "webhook"
    )
    assert sent == ["new escalation"]


def test_receiver_idempotency_key_versions_notification_without_changing_incident(
    monkeypatch,
) -> None:
    captured = []

    def open_request(request, *, timeout):
        captured.append((json.loads(request.data), request.get_header("Idempotency-key")))
        return nullcontext(SimpleNamespace(status=200))

    monkeypatch.setattr("api.app.notification.urllib.request.urlopen", open_request)
    for revision in (1, 2):
        deliver_notification(
            "INC-ESCALATION", f"revision {revision}", mode="webhook",
            webhook_url="http://127.0.0.1/notify", timeout_seconds=1,
            notification_key=f"INC-ESCALATION:notification:{revision}",
        )
    assert {row[0]["incident_id"] for row in captured} == {"INC-ESCALATION"}
    assert captured[0][1] != captured[1][1]


def test_verified_raw_replay_returns_the_original_outcome_after_context_changes(
    tmp_path: Path,
) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    original = decision("E1", review=False, notification="original").model_copy(
        update={"source_payload_sha256": "a" * 64}
    )
    first = store.record(original)
    changed = decision("E1", review=True, notification="new derived context").model_copy(
        update={"source_payload_sha256": "a" * 64}
    )
    replay = store.record(changed)
    cached = store.get_event_outcome("E1", payload_sha256="a" * 64)
    assert replay.disposition == cached.disposition == "duplicate"
    assert replay.route == cached.route == first.route == "shadow"
    assert replay.notification_revision == cached.notification_revision == 1
    assert replay.recorded_at == cached.recorded_at == first.recorded_at
    with pytest.raises(ValueError, match="different raw payload"):
        store.get_event_outcome("E1", payload_sha256="b" * 64)
    with pytest.raises(ValueError, match="different raw payload"):
        store.record(changed.model_copy(update={"source_payload_sha256": "b" * 64}))


@pytest.mark.parametrize("event_id", ["E1", "E/1"])
def test_event_outcome_endpoint_distinguishes_absent_verified_and_conflicting_events(
    monkeypatch, tmp_path: Path, event_id: str,
) -> None:
    path = tmp_path / "incidents.sqlite3"
    monkeypatch.setenv("INCIDENT_DB", str(path))
    load_incident_store.cache_clear()
    client = TestClient(app)
    assert client.get(
        f"/incidents/events/{event_id}", params={"payload_sha256": "a"*64}
    ).status_code == 404
    request = decision(event_id, review=False, notification="original").model_copy(
        update={"source_payload_sha256": "a" * 64}
    )
    assert client.post("/incidents/record", json=request.model_dump()).status_code == 200
    cached = client.get(f"/incidents/events/{event_id}", params={"payload_sha256": "a"*64})
    conflict = client.get(f"/incidents/events/{event_id}", params={"payload_sha256": "b"*64})
    assert cached.status_code == 200
    assert cached.json()["disposition"] == "duplicate"
    assert cached.json()["notification_revision"] == 1
    assert conflict.status_code == 409


def test_retry_of_superseded_revision_does_not_send_stale_text(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    first = store.record(decision("E1", review=False, notification="old"))
    current = store.record(decision("E2", review=True, notification="escalated"))
    sent = []
    result = store.dispatch_notification(
        "INC-ESCALATION", lambda _, message, *_key: sent.append(message) or "webhook",
        notification_revision=first.notification_revision,
    )
    assert result.notification_status == "SUPERSEDED"
    assert result.superseded_by_revision == current.notification_revision
    assert result.channel is None
    assert result.delivered_at is None
    assert sent == []


def test_failed_inflight_revision_is_superseded_if_a_new_decision_arrived(
    tmp_path: Path,
) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    first = store.record(decision("E1", review=False, notification="old"))

    def interrupted(_incident, _message, _key):
        store.record(decision("E2", review=True, notification="escalated"))
        raise OSError("simulated delivery failure")

    with pytest.raises(OSError):
        store.dispatch_notification("INC-ESCALATION", interrupted)
    result = store.dispatch_notification(
        "INC-ESCALATION", lambda *_args: "webhook",
        notification_revision=first.notification_revision,
    )
    assert result.notification_status == "SUPERSEDED"
    assert result.superseded_by_revision == 2
