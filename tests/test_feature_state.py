from __future__ import annotations

import sqlite3
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
                    "system": {"eventID": str(event_id), "systemTime": timestamp},
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
    assert first.feature.incident.incident_id == result.feature.incident.incident_id


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


def test_replay_returns_original_feature_after_window_has_changed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = FeatureStateStore(path)
    first_event = raw_account_alert("REPLAY-1", "2026-10-05T12:00:00Z", 4625)
    original = store.ingest(first_event)
    store.ingest(raw_account_alert("REPLAY-2", "2026-10-05T12:00:10Z", 4624))
    replay = FeatureStateStore(path).ingest(first_event)
    assert replay.ingest_status == "duplicate"
    assert replay.feature == original.feature
    assert replay.stored_event_count == original.stored_event_count


def test_state_store_uses_fixed_event_time_window_and_keeps_late_identity(tmp_path: Path) -> None:
    store = FeatureStateStore(tmp_path / "state.sqlite3")
    first = store.ingest(raw_account_alert("W1", "2026-10-05T12:04:50Z", 4625))
    second = store.ingest(raw_account_alert("W2", "2026-10-05T12:05:10Z", 4625))
    third = store.ingest(raw_account_alert("W3", "2026-10-05T12:10:00Z", 4624))
    assert (
        len(
            {
                first.feature.incident.incident_id,
                second.feature.incident.incident_id,
                third.feature.incident.incident_id,
            }
        )
        == 3
    )
    late = store.ingest(raw_account_alert("W0", "2026-10-05T12:00:01Z", 4625))
    assert late.feature.incident.incident_id == first.feature.incident.incident_id


def test_v1_sqlite_rows_are_retained_but_legacy_replay_is_not_recomputed(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    alert = raw_account_alert("LEGACY", "2026-10-05T12:00:00Z", 4625)
    payload, digest = FeatureStateStore._serialize(alert)
    import time

    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE wazuh_alerts (alert_id TEXT PRIMARY KEY, "
            "payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL, "
            "event_timestamp REAL NOT NULL, received_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO wazuh_alerts VALUES (?, ?, ?, ?, ?)",
            (alert.id, digest, payload, alert.timestamp.timestamp(), time.time()),
        )
    store = FeatureStateStore(path)
    with pytest.raises(FeatureStateConflictError, match="legacy event"):
        store.ingest(alert)
    fresh = store.ingest(raw_account_alert("FRESH", "2026-10-05T12:00:10Z", 4624))
    assert fresh.stored_event_count == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM wazuh_alerts").fetchone()[0] == 2
