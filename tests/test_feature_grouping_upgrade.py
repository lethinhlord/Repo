"""A grouping change must not reuse or reinterpret source6 cached decisions."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from test_context_feature_contract import baseline
from test_flow_accounting import START, flow

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


def clock_cache_events():
    """The five synthetic inputs that expose the 100-ms/300-ms cache mismatch."""
    events = []
    for event_id, native, published, extra in [
        (1, 8.25, 8.28, {"commandLine": "curl.exe https://service.local/status"}),
        (3, 8, 9.3, {
            "initiated": "true", "sourceIp": "10.20.0.10", "sourcePort": "50001",
            "protocol": "tcp", "destinationIp": "10.40.0.10", "destinationPort": "8081",
        }),
        (5, 12, 12.1, {}),
    ]:
        timestamp = (START + timedelta(seconds=published)).isoformat()
        events.append(WazuhAlert.model_validate({
            "id": f"clock-cache-{event_id}", "timestamp": timestamp,
            "agent": {"name": "WIN11-TARGET"}, "rule": {"id": "fixture", "level": 1},
            "data": {"win": {
                "system": {
                    "eventID": str(event_id), "systemTime": timestamp,
                    "providerName": "Microsoft-Windows-Sysmon",
                },
                "eventdata": {
                    "utcTime": (START + timedelta(seconds=native)).strftime(
                        "%Y-%m-%d %H:%M:%S.%f",
                    ),
                    "processGuid": "{CACHE-COMPATIBILITY}", "processId": "100",
                    "user": r"UNIT\fixture", "image": "curl.exe", **extra,
                },
            }},
        }))
    for name, payload in [
        ("http", flow(event_type="http", emitted=8, sent=60, received=30)),
        ("flow", flow(emitted=70)),
    ]:
        events.append(WazuhAlert.model_validate({
            "id": f"clock-cache-{name}", "timestamp": payload["timestamp"],
            "agent": {"name": "NET-SENSOR"}, "rule": {"id": "fixture", "level": 0},
            "full_log": json.dumps(payload),
        }))
    return events


def prepare_clock_cache(path, monkeypatch, *, closed):
    snapshot = path.with_suffix(".json")
    snapshot.write_text(baseline().model_dump_json(), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_BASELINE_PATH", str(snapshot))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 80)
    store = FeatureStateStore(path)
    events = clock_cache_events()
    responses = [store.ingest(event) for event in events]
    if closed:
        monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 400)
        return store.finalize_window(events[1].id)
    return responses[1]


@pytest.mark.parametrize("closed", [False, True])
def test_prior_100ms_derivation_cache_is_refused_without_mutation(tmp_path, monkeypatch, closed):
    path = tmp_path / "old-clock.sqlite3"
    with monkeypatch.context() as old:
        old.setattr(feature_pipeline, "_SYSMON_EVENT3_CREATION_TOLERANCE",
                    timedelta(milliseconds=100))
        old.setattr("api.app.feature_state.FEATURE_GROUPING_POLICY_VERSION",
                    "sensor-asset-origin-v1")
        historical = prepare_clock_cache(path, old, closed=closed)
        assert historical.feature.quality_status == "PARTIAL"
        assert historical.feature.incident.features["outbound_connection_count"] == 0
        assert historical.feature.incident.features["flow_total_bytes_log1p"] == 0
    original = path.read_bytes()
    with sqlite3.connect(path) as connection:
        rows = list(connection.iterdump())
    with pytest.raises(FeatureStateConflictError, match="grouping.*fresh"):
        FeatureStateStore(path)
    assert path.read_bytes() == original
    with sqlite3.connect(path) as connection:
        assert list(connection.iterdump()) == rows


def test_fresh_300ms_derivation_replays_and_closes_consistently(tmp_path, monkeypatch):
    path = tmp_path / "new-clock.sqlite3"
    result = prepare_clock_cache(path, monkeypatch, closed=True)
    assert result.feature.quality_status == "COMPLETE"
    assert result.feature.incident.features["outbound_connection_count"] == 1
    assert result.feature.incident.features["flow_total_bytes_log1p"] == pytest.approx(5.70711)
    replay = FeatureStateStore(path).finalize_window(clock_cache_events()[1].id)
    assert replay.ingest_status == "duplicate"
    assert replay.feature == result.feature
    assert replay.snapshot_revision == result.snapshot_revision
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT version FROM feature_grouping_policy").fetchone() == (
            "sensor-origin-clock300-v2",
        )
        assert connection.execute("SELECT version FROM feature_time_policy").fetchone() == (
            "sysmon-native-lifecycle-v1",
        )
