"""Sysmon's Event 3 image sentinel must never supply process identity."""

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from api.app.contracts import WazuhAlert
from ml.feature_pipeline import aggregate_wazuh_alerts
from ml.scenario_collection import CollectionError, RunDraft, SourceConfig, _derive_c2

ROOT = Path(__file__).resolve().parents[1]
NONCE = "unknownimage001"


def evidence():
    at = datetime(2026, 10, 27, tzinfo=UTC)

    def event(event_id, fields, second):
        timestamp = (at + timedelta(seconds=second)).isoformat()
        return {
            "id": f"UNKNOWN-{event_id}", "timestamp": timestamp,
            "rule": {"id": "61600", "level": 5},
            "agent": {"name": "WIN11-TARGET"},
            "data": {"win": {"system": {"eventID": str(event_id),
                                           "systemTime": timestamp},
                              "eventdata": fields}},
        }

    identity = {"processGuid": "proven-guid", "processId": "1234", "user": "LAB\\operator"}
    process = event(1, {**identity, "image": "C:\\Windows\\System32\\curl.exe",
                        "commandLine": f"curl.exe http://10.40.0.10:8081/beacon?run={NONCE}"}, 0)
    network = event(3, {**identity, "image": "&lt;unknown process&gt;", "initiated": "true",
                        "sourceIp": "10.20.0.10", "sourcePort": "50001", "protocol": "tcp",
                        "destinationIp": "10.40.0.10", "destinationPort": "8081"}, 1)
    eve = {
        "id": "UNKNOWN-EVE", "timestamp": network["timestamp"],
        "rule": {"id": "86601", "level": 5}, "agent": {"name": "NET-SENSOR"},
        "data": {"event_type": "http", "timestamp": network["timestamp"], "flow_id": 123,
                 "src_ip": "10.20.0.10", "src_port": 50001, "proto": "TCP",
                 "dest_ip": "10.40.0.10", "dest_port": 8081,
                 "http": {"url": f"/beacon?run={NONCE}", "status": 200}},
    }
    clock = {name: at.isoformat() for name in (
        "captured_at", "controller_utc", "target_utc", "wazuh_utc", "sensor_utc", "attacker_utc")}
    clock["maximum_skew_seconds"] = 10
    draft = RunDraft.model_validate({
        "scenario_id": "UNKNOWN-IMAGE", "run_id": "UNKNOWN-IMAGE-1", "family": "c2",
        "label": "malicious", "host": "WIN11-TARGET", "operator": "test",
        "expected_behavior": "Controlled HTTP attribution regression.", "collection_seed": 42,
        "attribution": {"process_names": ["curl.exe"], "command_contains_any": ["/beacon"],
                        "source_ips": ["10.20.0.10"], "destination_ips": ["10.40.0.10"],
                        "destination_ports": [8081]},
        "quality_gates": {"min_process_events": 1, "min_network_events": 1,
                          "min_suricata_events": 1},
        "scenario_parameters": {"run_nonce": NONCE, "expected_action_count": 1},
        "expected_observables": ["Attributable HTTP transaction"], "clock_preflight": clock,
    })
    config = yaml.safe_load((ROOT / "config/collection-sources.yaml").read_text(encoding="utf-8"))
    # Unit evidence has no final flow; production's final-flow gate remains mandatory.
    config["require_flow_counters"] = False
    source = SourceConfig.model_validate(config)
    taxonomy = yaml.safe_load((ROOT / "config/suspicious-process-taxonomy.yaml").read_text())
    return [process, network, eve], draft, source, taxonomy


def online(events, source, taxonomy):
    return next(item for item in aggregate_wazuh_alerts(
        [WazuhAlert.model_validate(item) for item in events],
        source_config=source.model_dump(mode="json"), taxonomy=taxonomy,
        use_runtime_baseline=False,
    ).incidents if item.incident.asset_id == source.windows_agent_name)


@pytest.mark.parametrize("image", ["<unknown process>", "&lt;unknown process&gt;", "curl.exe"])
def test_http_unknown_image_preserves_online_offline_parity_and_raw_evidence(image):
    events, draft, source, taxonomy = evidence()
    events[1]["data"]["win"]["eventdata"]["image"] = image
    before = copy.deepcopy(events)
    features, windows, suricata, _ = _derive_c2(events, draft, source, taxonomy)
    result = online(events, source, taxonomy)
    assert result.incident.features == features
    assert features["outbound_connection_count"] == 1
    assert features["suspicious_process"] == 1
    assert windows == events[:2]
    assert suricata
    assert events == before


@pytest.mark.parametrize("fault", [
    "missing-creation", "missing-guid", "wrong-guid", "other-agent", "creation-other-agent",
    "known-wrong-image", "missing-image", "empty-image", "unknown-path", "unknown-creation",
    "unknown-creation-path",
    "inbound", "wrong-source", "wrong-destination", "wrong-port", "before-creation",
    "pid-mismatch", "user-mismatch", "conflicting-creation", "conflicting-command",
    "conflicting-time", "unknown-dns",
])
def test_http_unknown_image_fails_closed_without_consistent_process_and_tuple(fault):
    events, draft, source, taxonomy = evidence()
    process, network = events[:2]
    fields = network["data"]["win"]["eventdata"]
    process_fields = process["data"]["win"]["eventdata"]
    if fault == "missing-creation":
        events.remove(process)
    elif fault == "missing-guid":
        fields.pop("processGuid")
    elif fault == "wrong-guid":
        fields["processGuid"] = "unproven-guid"
    elif fault in {"other-agent", "creation-other-agent"}:
        (network if fault == "other-agent" else process)["agent"]["name"] = "OTHER-HOST"
    elif fault in {"known-wrong-image", "empty-image", "unknown-path"}:
        fields["image"] = {"known-wrong-image": "other.exe", "empty-image": "",
                           "unknown-path": "C:\\temp\\<unknown process>"}[fault]
    elif fault == "missing-image":
        fields.pop("image")
    elif fault in {"unknown-creation", "unknown-creation-path"}:
        process_fields["image"] = (
            "<unknown process>" if fault == "unknown-creation" else "C:\\temp\\<unknown process>"
        )
    elif fault in {"inbound", "wrong-source", "wrong-destination", "wrong-port"}:
        field, value = {"inbound": ("initiated", "false"),
                        "wrong-source": ("sourceIp", "10.20.0.99"),
                        "wrong-destination": ("destinationIp", "10.40.0.99"),
                        "wrong-port": ("destinationPort", "8082")}[fault]
        fields[field] = value
    elif fault == "before-creation":
        process["timestamp"] = process["data"]["win"]["system"]["systemTime"] = (
            "2026-10-27T00:00:02+00:00")
    elif fault in {"pid-mismatch", "user-mismatch"}:
        fields["processId" if fault == "pid-mismatch" else "user"] = "conflicting-identity"
    elif fault.startswith("conflicting-"):
        duplicate = copy.deepcopy(process)
        duplicate["id"] = "CONFLICTING-CREATION"
        duplicate_fields = duplicate["data"]["win"]["eventdata"]
        if fault == "conflicting-creation":
            duplicate_fields["image"] = "other.exe"
        elif fault == "conflicting-command":
            duplicate_fields["commandLine"] = "unrelated command"
        else:
            duplicate["timestamp"] = duplicate["data"]["win"]["system"]["systemTime"] = (
                "2026-10-27T00:00:01+00:00")
        events.append(duplicate)
    elif fault == "unknown-dns":
        network["data"]["win"]["system"]["eventID"] = "22"
        fields["queryName"] = f"{NONCE}.beacon.datn.test"
        draft = draft.model_copy(update={"attribution": draft.attribution.model_copy(
            update={"dns_suffixes": ["beacon.datn.test"]})})
    before = copy.deepcopy(events)
    with pytest.raises(CollectionError):
        _derive_c2(events, draft, source, taxonomy)
    result = online(events, source, taxonomy)
    # Runtime is scenario-independent, but the mismatched EVE tuple must remain uncorrelated.
    if fault not in {"wrong-destination", "wrong-port"}:
        assert result.incident.features["outbound_connection_count"] == 0
    else:
        assert "suricata_alert_count" in result.missing_required_features
    assert events == before


@pytest.mark.parametrize("fault", ["before-creation", "processId", "user", "duplicate-guid"])
def test_known_image_also_rejects_inconsistent_process_evidence(fault):
    events, draft, source, taxonomy = evidence()
    process, network = events[:2]
    network["data"]["win"]["eventdata"]["image"] = "curl.exe"
    if fault == "before-creation":
        process["timestamp"] = process["data"]["win"]["system"]["systemTime"] = (
            "2026-10-27T00:00:02+00:00")
    elif fault == "duplicate-guid":
        duplicate = copy.deepcopy(process)
        duplicate["id"] = "CONFLICTING-CREATION"
        duplicate["data"]["win"]["eventdata"]["commandLine"] = "unrelated command"
        events.append(duplicate)
    else:
        network["data"]["win"]["eventdata"][fault] = "conflicting-identity"
    with pytest.raises(CollectionError):
        _derive_c2(events, draft, source, taxonomy)
    assert online(events, source, taxonomy).incident.features["outbound_connection_count"] == 0


@pytest.mark.parametrize("duplicate", [False, True])
def test_process_proof_is_order_independent_and_identical_creation_replays_are_safe(duplicate):
    events, draft, source, taxonomy = evidence()
    if duplicate:
        replay = copy.deepcopy(events[0])
        replay["id"] = "REPLAY-CREATION"
        events.append(replay)
    features = _derive_c2(list(reversed(events)), draft, source, taxonomy)[0]
    assert features["outbound_connection_count"] == 1
    assert online(events, source, taxonomy).incident.features == features
