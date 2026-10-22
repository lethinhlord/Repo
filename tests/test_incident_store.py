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
