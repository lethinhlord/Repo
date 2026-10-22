from __future__ import annotations

from pathlib import Path

import pytest

from api.app.contracts import WazuhAlert
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore


def raw_account_alert(alert_id: str, timestamp: str, event_id: int) -> WazuhAlert:
    return WazuhAlert.model_validate(
        {
            "id": alert_id,
            "timestamp": timestamp,
            "rule": {"id": "60100", "level": 7},
            "agent": {"id": "001", "name": "WIN11-TARGET"},
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "win": {
                    "system": {"eventID": str(event_id)},
                    "eventdata": {
                        "targetUserName": "labuser",
                        "ipAddress": "10.40.0.10",
                        "logonType": "3",
                    },
                }
            },
            "location": "Security",
        }
    )


def test_state_store_correlates_sequential_webhook_events(tmp_path: Path) -> None:
    store = FeatureStateStore(tmp_path / "feature-state.sqlite3")

    first = store.ingest(raw_account_alert("A-1", "2026-10-05T12:00:00Z", 4625))
    second = store.ingest(raw_account_alert("A-2", "2026-10-05T12:00:10Z", 4625))
    result = store.ingest(raw_account_alert("A-3", "2026-10-05T12:00:20Z", 4624))

    assert first.feature.quality_status == "COMPLETE"
    assert second.stored_event_count == 2
    assert result.stored_event_count == 3
    assert result.feature.incident.features["failed_login_count"] == 2.0
    assert result.feature.incident.features["successful_login_count"] == 1.0
    assert result.feature.incident.features["success_after_fail"] == 1.0


def test_state_store_is_idempotent_across_process_restart(tmp_path: Path) -> None:
    path = tmp_path / "feature-state.sqlite3"
    alert = raw_account_alert("A-1", "2026-10-05T12:00:00Z", 4625)

    assert FeatureStateStore(path).ingest(alert).ingest_status == "new"
    replay = FeatureStateStore(path).ingest(alert)

    assert replay.ingest_status == "duplicate"
    assert replay.stored_event_count == 1


def test_state_store_rejects_conflicting_replay(tmp_path: Path) -> None:
    store = FeatureStateStore(tmp_path / "feature-state.sqlite3")
    store.ingest(raw_account_alert("A-1", "2026-10-05T12:00:00Z", 4625))

    with pytest.raises(FeatureStateConflictError, match="conflicting payload"):
        store.ingest(raw_account_alert("A-1", "2026-10-05T12:00:01Z", 4625))
