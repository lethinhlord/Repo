"""Native lifecycle chronology must prove attribution without a post-exit grace."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from api.app.contracts import WazuhAlert
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from ml.feature_pipeline import aggregate_wazuh_alerts
from ml.telemetry import event_time, sysmon_clock_issues

START = datetime(2026, 11, 13, 11, 45, tzinfo=UTC)


def event(identifier, kind, system_seconds, native_seconds, *, native_key="utcTime", **fields):
    system_time = (START + timedelta(seconds=system_seconds)).isoformat()
    native_time = (START + timedelta(seconds=native_seconds)).strftime("%Y-%m-%d %H:%M:%S.%f")
    return WazuhAlert.model_validate({
        "id": identifier,
        "timestamp": system_time,
        "rule": {"id": "chronology-unit", "level": 5},
        "agent": {"name": "WIN11-TARGET"},
        "data": {"win": {
            "system": {"eventID": str(kind), "systemTime": system_time,
                       "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {"image": "curl.exe", "processGuid": "{CHRONOLOGY}",
                          "processId": "7776", "user": "WIN11-TARGET\\socuser",
                          native_key: native_time, **fields},
        }},
    })


def network(system_seconds=20, native_seconds=18, **fields):
    return event("NETWORK", 3, system_seconds, native_seconds,
                 initiated="true", sourceIp="10.20.0.10", sourcePort="51464",
                 destinationIp="10.40.0.10", destinationPort="8081", **fields)


def result(events):
    batch = aggregate_wazuh_alerts(events)
    return next(item for item in batch.incidents
                if "wazuh-alert:NETWORK" in item.incident.raw_refs)


@pytest.mark.parametrize("native_key", ["utcTime", "UtcTime", "UTCTIME"])
def test_delayed_publication_uses_valid_native_connection_before_exit(native_key):
    observed = result([
        event("CREATE", 1, 14.7, 14.685),
        network(native_key=native_key),
        event("EXIT", 5, 18.734303, 18.732),
    ])
    assert observed.incident.features["outbound_connection_count"] == 1
    assert "suspicious_process" not in observed.missing_required_features


def test_delayed_creation_publication_does_not_hide_native_lifetime_start():
    observed = result([
        event("CREATE", 1, 18.020, 18.000),
        network(system_seconds=20, native_seconds=18.010),
        event("EXIT", 5, 18.040, 18.030),
    ])
    assert observed.incident.features["outbound_connection_count"] == 1


def test_delayed_exit_publication_does_not_admit_native_post_exit_connection():
    observed = result([
        event("CREATE", 1, 14.7, 14.685),
        network(system_seconds=20, native_seconds=18.733),
        event("EXIT", 5, 18.734303, 18.732),
    ])
    assert observed.incident.features["outbound_connection_count"] == 0
    assert "suspicious_process" in observed.missing_required_features


def test_pilot_native_post_exit_shape_remains_unattributed():
    # Exact first observed pilot clock values, reduced to non-sensitive fields.
    # Both Event 3 clocks are after exit: this is not delayed publication of a
    # native pre-exit connection, and must not be rescued by a two-second grace.
    observed = result([
        event("CREATE", 1, 14.705218, 14.685),
        network(system_seconds=19.864772, native_seconds=20.319),
        event("EXIT", 5, 18.734303, 18.732),
    ])
    assert observed.incident.features["outbound_connection_count"] == 0
    assert "suspicious_process" in observed.missing_required_features


@pytest.mark.parametrize("fields", [
    {"processId": "9999"}, {"user": "WIN11-TARGET\\another-user"},
    {"processGuid": "{OTHER}"}, {"image": "powershell.exe"},
])
def test_pre_exit_connection_still_requires_matching_identity(fields):
    observed = result([
        event("CREATE", 1, 14.7, 14.685), network(**fields),
        event("EXIT", 5, 18.734303, 18.732),
    ])
    assert observed.incident.features["outbound_connection_count"] == 0
    assert "suspicious_process" in observed.missing_required_features


@pytest.mark.parametrize("kind", [1, 3, 5])
def test_native_clock_does_not_reinterpret_another_provider_namespace(kind):
    other = event("OTHER-PROVIDER", kind, 20, 18).model_dump(mode="json")
    other["data"]["win"]["system"]["providerName"] = "Other-Provider"
    assert event_time(other) == START + timedelta(seconds=20)


@pytest.mark.parametrize("kind", [1, 3, 5])
def test_invalid_native_lifecycle_clock_keeps_clock_failure_visible(kind):
    invalid = event("INVALID", kind, 20, 10).model_dump(mode="json")
    assert "clock:sysmon_timestamp_mismatch" in sysmon_clock_issues(invalid)
    assert event_time(invalid) == START + timedelta(seconds=20)


def test_restarted_store_retains_native_creation_before_bucket_boundary(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 301)
    # Publication falls after the new bucket's connection, but native creation
    # is in the prior bucket and is valid process context for that connection.
    FeatureStateStore(path).ingest(event("CREATE", 1, 300.020, 299.990))
    observed = FeatureStateStore(path).ingest(
        network(system_seconds=302, native_seconds=300.010),
    )
    assert observed.feature.incident.features["outbound_connection_count"] == 1


@pytest.mark.parametrize("kind", [1, 3, 5])
def test_conflicting_native_aliases_cannot_choose_a_lifetime_by_dictionary_order(kind):
    raw = event("CONFLICT", kind, 20, 18).model_dump(mode="json")
    raw["data"]["win"]["eventdata"]["UtcTime"] = "2026-11-13 11:45:19.000"
    assert "clock:conflicting_sysmon_utc_time" in sysmon_clock_issues(raw)
    assert event_time(raw) == START + timedelta(seconds=20)


@pytest.mark.parametrize("kind", [22, 4624, 4625])
def test_dns_and_account_timestamp_semantics_are_unchanged(kind):
    raw = event("OTHER", kind, 20, 18).model_dump(mode="json")
    assert event_time(raw) == START + timedelta(seconds=20)


@pytest.mark.parametrize("table", [
    "wazuh_alerts", "process_identity_events", "closed_feature_windows",
    "evicted_feature_windows",
])
def test_prepolicy_nonempty_store_is_refused_before_any_mutation(tmp_path, table):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(f"CREATE TABLE {table} (evidence TEXT)")
        connection.execute(f"INSERT INTO {table} VALUES (?)", ("preserve original",))
    original = path.read_bytes()
    with pytest.raises(FeatureStateConflictError, match="chronology.*fresh"):
        FeatureStateStore(path)
    assert path.read_bytes() == original
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()


def test_changed_policy_store_cannot_replay_cached_features(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 21)
    FeatureStateStore(path).ingest(event("CREATE", 1, 14.7, 14.685))
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE feature_time_policy SET version='unknown-policy'")
    with pytest.raises(FeatureStateConflictError, match="chronology.*fresh"):
        FeatureStateStore(path)


def test_prepolicy_current_cache_is_preserved_without_recomputation(tmp_path, monkeypatch):
    path = tmp_path / "current.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 21)
    store = FeatureStateStore(path)
    store.ingest(event("CREATE", 1, 14.7, 14.685))
    store.ingest(network())
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 361)
    store.finalize_window("NETWORK")
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE feature_time_policy")
        snapshot = list(connection.iterdump())
    with pytest.raises(FeatureStateConflictError, match="chronology.*fresh"):
        FeatureStateStore(path)
    with sqlite3.connect(path) as connection:
        assert list(connection.iterdump()) == snapshot


def test_empty_prepolicy_database_can_initialize_and_restart(tmp_path):
    path = tmp_path / "empty.sqlite3"
    sqlite3.connect(path).close()
    FeatureStateStore(path)
    FeatureStateStore(path)


def test_native_clock_store_close_and_restart_match_batch(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 21)
    events = [event("CREATE", 1, 18.020, 18.000),
              network(system_seconds=20, native_seconds=18.010),
              event("EXIT", 5, 18.040, 18.030)]
    store = FeatureStateStore(path)
    for item in events:
        store.ingest(item)
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 361)
    closed = store.finalize_window("NETWORK")
    assert closed.feature.incident.features == result(events).incident.features
    assert FeatureStateStore(path).finalize_window("NETWORK").feature == closed.feature
