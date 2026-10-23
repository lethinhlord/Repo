from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.app.contracts import IncidentRecordRequest
from api.app.incident_store import IncidentStore


def request(event_id: str, *, notification: str = "review") -> IncidentRecordRequest:
    return IncidentRecordRequest(
        incident_id="INC-STABLE-1",
        source_event_id=event_id,
        route="review",
        review_required=True,
        notification=notification,
        decision={"risk": {"display": 7.2}},
    )


def test_incident_store_creates_updates_and_queues_once(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")

    created = store.record(request("EVENT-1"))
    updated = store.record(request("EVENT-2", notification="new text"))
    duplicate = store.record(request("EVENT-2", notification="new text"))

    assert created.disposition == "created"
    assert created.notification_status == "QUEUED"
    assert updated.disposition == "updated"
    assert updated.notification_status == "ALREADY_QUEUED"
    assert duplicate.disposition == "duplicate"
    assert duplicate.notification_status == "ALREADY_QUEUED"


def test_incident_store_rejects_event_id_reuse_with_changed_decision(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    store.record(request("EVENT-1"))

    with pytest.raises(ValueError, match="different decision"):
        store.record(request("EVENT-1", notification="changed"))


def test_stale_notification_lease_is_recovered_after_process_interruption(
    tmp_path: Path,
) -> None:
    store = IncidentStore(tmp_path / "incidents.sqlite3")
    store.record(request("EVENT-1"))
    started = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)

    def interrupted_sender(_incident_id: str, _notification: str) -> str:
        raise SystemExit("simulated process interruption")

    with pytest.raises(SystemExit, match="process interruption"):
        store.dispatch_notification(
            "INC-STABLE-1",
            interrupted_sender,
            now=started,
            lease_seconds=60,
        )

    with pytest.raises(ValueError, match="already in progress"):
        store.dispatch_notification(
            "INC-STABLE-1",
            lambda _incident_id, _notification: "audit-log",
            now=started + timedelta(seconds=59),
            lease_seconds=60,
        )

    calls: list[str] = []

    def recovered_sender(incident_id: str, _notification: str) -> str:
        calls.append(incident_id)
        return "webhook"

    recovered = store.dispatch_notification(
        "INC-STABLE-1",
        recovered_sender,
        now=started + timedelta(seconds=60),
        lease_seconds=60,
    )
    replay = store.dispatch_notification(
        "INC-STABLE-1",
        recovered_sender,
        now=started + timedelta(seconds=61),
        lease_seconds=60,
    )

    assert recovered.notification_status == "SENT"
    assert recovered.channel == "webhook"
    assert replay.notification_status == "ALREADY_SENT"
    assert calls == ["INC-STABLE-1"]
