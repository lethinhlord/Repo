"""Runtime process proof survives bucket boundaries without importing behavior."""
from datetime import UTC, datetime, timedelta

import pytest

from api.app.contracts import WazuhAlert
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from ml.feature_pipeline import aggregate_wazuh_alerts

START = datetime(2026, 11, 7, tzinfo=UTC)


def event(identifier, event_id, seconds, **fields):
    timestamp = (START + timedelta(seconds=seconds)).isoformat()
    return WazuhAlert.model_validate({
        "id": identifier, "timestamp": timestamp, "rule": {"id": "runtime-unit", "level": 5},
        "agent": {"name": "WIN11-TARGET"},
        "data": {"win": {"system": {"eventID": str(event_id), "systemTime": timestamp},
                         "eventdata": {"image": "curl.exe", "processGuid": "{LIFETIME}",
                                       **fields}}},
    })


def connection(identifier="NETWORK", seconds=301, **fields):
    return event(identifier, 3, seconds, initiated="true", sourceIp="10.20.0.10",
                 destinationIp="10.40.0.10", destinationPort="8081", **fields)


def target(batch, identifier="NETWORK"):
    return next(
        item for item in batch.incidents if f"wazuh-alert:{identifier}" in item.incident.raw_refs
    )


def test_batch_prior_bucket_creation_proves_only_current_bucket_connections():
    creation = event("PROCESS", 1, 299, commandLine="curl https://service.local/")
    old_network = connection("OLD-NETWORK", 299.5)
    result = target(aggregate_wazuh_alerts([creation, old_network, connection()]))
    assert result.incident.features["outbound_connection_count"] == 1
    assert "suspicious_process" not in result.missing_required_features
    assert "wazuh-alert:OLD-NETWORK" not in result.incident.raw_refs
    assert "wazuh-alert:PROCESS" not in result.incident.raw_refs
    assert result.incident.start_time == START + timedelta(seconds=301)
    assert result.incident.base_severity == 5


@pytest.mark.parametrize("variant", ["future", "agent", "guid", "terminated", "conflict"])
def test_process_proof_is_as_of_and_scoped(variant):
    creation = event("PROCESS", 1, 299)
    events = [creation, connection()]
    if variant == "future":
        events[0] = event("PROCESS", 1, 302)
    elif variant == "agent":
        events[0] = creation.model_copy(update={
            "agent": creation.agent.model_copy(update={"name": "OTHER"}),
        })
    elif variant == "guid":
        events[0] = event("PROCESS", 1, 299, processGuid="{OTHER}")
    elif variant == "terminated":
        events.append(event("EXIT", 5, 300))
    elif variant == "conflict":
        events.append(event("REUSED", 1, 300, image="powershell.exe"))
    result = target(aggregate_wazuh_alerts(events))
    assert result.incident.features["outbound_connection_count"] == 0
    assert "suspicious_process" in result.missing_required_features


def test_later_termination_does_not_remove_pre_exit_observations():
    result = target(aggregate_wazuh_alerts([
        event("PROCESS", 1, 299), connection(), event("EXIT", 5, 302), connection("AFTER", 303),
    ]))
    assert result.incident.features["outbound_connection_count"] == 1


def test_prior_bucket_process_clock_mismatch_cannot_validate_network():
    result = target(aggregate_wazuh_alerts([
        event("PROCESS", 1, 299, utcTime="2026-11-07T00:03:00Z"), connection(),
    ]))
    assert result.incident.features["outbound_connection_count"] == 0
    assert "suspicious_process" in result.missing_required_features


def test_prior_bucket_creation_supports_unknown_network_image_and_dns():
    batch = aggregate_wazuh_alerts([
        event("PROCESS", 1, 299), connection(image="<unknown process>"),
        event("DNS", 22, 302, queryName="service.local"),
    ])
    result = target(batch)
    assert result.incident.features["outbound_connection_count"] == 2
    assert result.incident.features["unique_destination_count"] == 2


def test_state_restart_retains_identity_and_close_replays_without_old_counts(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 299.9)
    FeatureStateStore(path).ingest(event("PROCESS", 1, 299))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 302)
    store = FeatureStateStore(path)
    provisional = store.ingest(connection())
    assert provisional.feature.incident.features["outbound_connection_count"] == 1
    assert provisional.stored_event_count == 1
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 661)
    closed = store.finalize_window("NETWORK")
    assert closed.feature.incident.features["outbound_connection_count"] == 1
    assert closed.stored_event_count == 1
    assert FeatureStateStore(path).finalize_window("NETWORK").feature == closed.feature
    assert FeatureStateStore(path).ingest(connection()).feature == provisional.feature


def test_active_identity_survives_raw_ttl_and_conflicting_replay_fails(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 1)
    FeatureStateStore(path, retention_seconds=600).ingest(event("PROCESS", 1, 0))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 902)
    store = FeatureStateStore(path, retention_seconds=600)
    result = store.ingest(connection(seconds=901))
    assert result.feature.incident.features["outbound_connection_count"] == 1
    with pytest.raises(FeatureStateConflictError, match="conflicting payload"):
        store.ingest(event("PROCESS", 1, 0, image="powershell.exe"))


def test_late_process_identity_invalidates_closed_window(tmp_path, monkeypatch):
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 302)
    store = FeatureStateStore(tmp_path / "state.sqlite3")
    store.ingest(connection())
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 661)
    store.finalize_window("NETWORK")
    store.ingest(event("PROCESS", 1, 299))
    with pytest.raises(FeatureStateConflictError, match="late|changed"):
        store.finalize_window("NETWORK")


def test_future_exit_does_not_change_an_already_closed_pre_exit_window(tmp_path, monkeypatch):
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 302)
    store = FeatureStateStore(tmp_path / "state.sqlite3")
    store.ingest(event("PROCESS", 1, 299))
    store.ingest(connection())
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 661)
    closed = store.finalize_window("NETWORK")
    store.ingest(event("EXIT", 5, 302))
    assert store.finalize_window("NETWORK").feature == closed.feature


def test_out_of_order_terminated_identity_expires_without_resurrection(tmp_path, monkeypatch):
    import sqlite3

    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 302)
    store = FeatureStateStore(path, retention_seconds=600)
    store.ingest(event("EXIT", 5, 300))
    store.ingest(event("PROCESS", 1, 299))
    # Receipt expiry uses a strict cutoff, matching retained raw-event semantics.
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 903)
    result = store.ingest(connection(seconds=901))
    assert result.feature.incident.features["outbound_connection_count"] == 0
    with sqlite3.connect(path) as connection_db:
        rows = connection_db.execute("SELECT COUNT(*) FROM process_identity_events").fetchone()[0]
        assert rows == 0


def test_expired_creation_cannot_reactivate_an_expired_terminated_process(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 302)
    store = FeatureStateStore(path, retention_seconds=600)
    store.ingest(event("EXIT", 5, 300))
    store.ingest(event("PROCESS", 1, 299))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 903)
    store.ingest(connection(seconds=901))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 904)
    with pytest.raises(FeatureStateConflictError, match="stale|expired"):
        store.ingest(event("PROCESS", 1, 299))


def test_retained_identity_rejects_its_id_reused_as_network_after_raw_expiry(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 1)
    store = FeatureStateStore(tmp_path / "state.sqlite3", retention_seconds=600)
    store.ingest(event("SAME", 1, 0))
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: START.timestamp() + 902)
    with pytest.raises(FeatureStateConflictError, match="conflicting payload"):
        store.ingest(connection("SAME", 901))


def test_batch_rejects_id_collision_between_context_and_current_alert():
    with pytest.raises(ValueError, match="conflicting payload"):
        aggregate_wazuh_alerts(
            [connection("SAME")], process_context=[event("SAME", 1, 299)],
        )


def test_process_termination_native_clock_is_validated():
    from ml.telemetry import sysmon_clock_issues

    terminated = event("EXIT", 5, 300, utcTime="2026-11-07T00:00:00Z").model_dump(mode="json")
    terminated["data"]["win"]["system"]["providerName"] = "Microsoft-Windows-Sysmon"
    assert sysmon_clock_issues(terminated)
