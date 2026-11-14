"""A grouping change must not reuse or reinterpret source6 cached decisions."""

import sqlite3
from datetime import UTC, datetime

import pytest

from api.app.contracts import WazuhAlert
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from ml import feature_pipeline

BUCKET = datetime(2026, 11, 14, 6, 50, tzinfo=UTC).timestamp()


def sensor_event():
    return WazuhAlert.model_validate({
        "id": "SENSOR-SSH-UPGRADE", "timestamp": "2026-11-14T06:50:12Z",
        "agent": {"name": "NET-SENSOR"}, "rule": {"id": "test", "level": 0},
        "decoder": {"name": "sshd"}, "data": {},
    })


def source6_cache(path, monkeypatch, closed):
    # Exact source6 mapping for this input. No dependency on Git history or VMs.
    with monkeypatch.context() as old:
        old.setattr(feature_pipeline, "_asset_id", lambda alert, config=None: "WIN11-TARGET")
        old.setattr("api.app.feature_state.time.time", lambda: BUCKET + 30)
        store = FeatureStateStore(path)
        result = store.ingest(sensor_event())
        assert result.feature.incident.asset_id == "WIN11-TARGET"
        if closed:
            old.setattr("api.app.feature_state.time.time", lambda: BUCKET + 361)
            store.finalize_window(sensor_event().id)
    # Source6 has the native clock policy, but no grouping policy table.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE IF EXISTS feature_grouping_policy")
        assert connection.execute("SELECT version FROM feature_time_policy").fetchone() == (
            "sysmon-native-lifecycle-v1",
        )


@pytest.mark.parametrize("closed", [False, True])
def test_source6_cache_is_refused_before_mutation_or_second_incident(tmp_path, monkeypatch, closed):
    path = tmp_path / "source6.sqlite3"
    source6_cache(path, monkeypatch, closed)
    original = path.read_bytes()
    with sqlite3.connect(path) as connection:
        rows = list(connection.iterdump())
    with pytest.raises(FeatureStateConflictError, match="grouping.*fresh"):
        FeatureStateStore(path)
    assert path.read_bytes() == original
    with sqlite3.connect(path) as connection:
        assert list(connection.iterdump()) == rows


def test_fresh_grouping_policy_keeps_restart_duplicate_and_close_consistent(tmp_path, monkeypatch):
    path = tmp_path / "current.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 30)
    first = FeatureStateStore(path).ingest(sensor_event())
    duplicate = FeatureStateStore(path).ingest(sensor_event())
    assert first.feature.incident.asset_id == duplicate.feature.incident.asset_id == "NET-SENSOR"
    assert duplicate.ingest_status == "duplicate"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: BUCKET + 361)
    closed = FeatureStateStore(path).finalize_window(sensor_event().id)
    repeated = FeatureStateStore(path).finalize_window(sensor_event().id)
    assert repeated.feature == closed.feature
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM closed_feature_windows").fetchone()[0] == 1
        assert connection.execute("SELECT version FROM feature_grouping_policy").fetchone() == (
            feature_pipeline.FEATURE_GROUPING_POLICY_VERSION,
        )


def test_unknown_grouping_policy_is_never_silently_upgraded(tmp_path):
    path = tmp_path / "future.sqlite3"
    FeatureStateStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS feature_grouping_policy "
                           "(singleton INTEGER PRIMARY KEY,version TEXT NOT NULL)")
        connection.execute("DELETE FROM feature_grouping_policy")
        connection.execute("INSERT INTO feature_grouping_policy VALUES (1,'unknown-policy')")
    original = path.read_bytes()
    with pytest.raises(FeatureStateConflictError, match="grouping.*fresh"):
        FeatureStateStore(path)
    assert path.read_bytes() == original
