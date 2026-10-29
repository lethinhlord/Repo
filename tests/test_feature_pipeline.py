import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from api.app.contracts import WazuhAlert
from ml.feature_pipeline import (
    FEATURE_ORDER,
    aggregate_wazuh_alerts,
    extract_wazuh_features,
)

ROOT = Path(__file__).resolve().parents[1]


def raw_c2_alert(alert_id: str, event_id: int, data: dict, seconds: int) -> WazuhAlert:
    timestamp = f"2026-10-27T00:00:{seconds:02d}Z"
    return WazuhAlert.model_validate(
        {
            "id": alert_id,
            "timestamp": timestamp,
            "rule": {"id": "61600", "level": 5},
            "agent": {"name": "WIN11-TARGET", "id": "001"},
            "data": {
                "win": {
                    "system": {"eventID": str(event_id), "systemTime": timestamp},
                    "eventdata": data,
                }
            },
        }
    )


def test_raw_c2_uses_canonical_taxonomy_and_correlates_only_outbound_process() -> None:
    alerts = [
        raw_c2_alert(
            "PROCESS",
            1,
            {
                "image": "curl.exe",
                "processGuid": "guid-one",
                "commandLine": "curl.exe http://10.40.0.10:8081/beacon",
            },
            0,
        ),
        raw_c2_alert(
            "NETWORK",
            3,
            {
                "image": "curl.exe",
                "processGuid": "guid-one",
                "initiated": "true",
                "sourceIp": "10.20.0.10",
                "destinationIp": "10.40.0.10",
                "destinationPort": "8081",
            },
            1,
        ),
        raw_c2_alert(
            "INBOUND",
            3,
            {
                "image": "curl.exe",
                "processGuid": "guid-one",
                "initiated": "false",
                "sourceIp": "10.20.0.10",
                "destinationIp": "10.40.0.10",
                "destinationPort": "8081",
            },
            2,
        ),
        raw_c2_alert(
            "WRONG-PROCESS",
            3,
            {
                "image": "other.exe",
                "processGuid": "unproven",
                "initiated": "true",
                "sourceIp": "10.20.0.10",
                "destinationIp": "10.40.0.10",
                "destinationPort": "8081",
            },
            3,
        ),
        raw_c2_alert(
            "INVALID-DESTINATION",
            3,
            {
                "image": "curl.exe",
                "processGuid": "guid-one",
                "initiated": "true",
                "sourceIp": "10.20.0.10",
                "destinationIp": "not-an-ip",
                "destinationPort": "8081",
            },
            4,
        ),
    ]
    result = aggregate_wazuh_alerts(alerts).incidents[0]
    assert result.incident.features["suspicious_process"] == 1.0
    assert result.incident.features["outbound_connection_count"] == 1.0
    assert result.quality_status == "PARTIAL"


def test_mapped_ipv6_and_source_event_time_have_same_account_semantics() -> None:
    def account(i: str, success: bool, source: str, event_seconds: int) -> WazuhAlert:
        timestamp = f"2026-10-27T00:00:{event_seconds:02d}Z"
        return WazuhAlert.model_validate(
            {
                "id": i,
                "timestamp": "2026-10-27T00:02:00Z",
                "rule": {"id": "60100", "level": 5},
                "agent": {"name": "WIN11-TARGET"},
                "data": {
                    "win": {
                        "system": {
                            "eventID": "4624" if success else "4625",
                            "systemTime": timestamp,
                        },
                        "eventdata": {
                            "targetUserName": "labuser",
                            "ipAddress": source,
                            "logonType": "3",
                        },
                    }
                },
            }
        )

    batch = aggregate_wazuh_alerts(
        [
            account("FAILURE", False, "::ffff:10.40.0.10", 0),
            account("SUCCESS", True, "10.40.0.10", 10),
        ]
    )
    assert len(batch.incidents) == 1
    incident = batch.incidents[0].incident
    assert incident.features["success_after_fail"] == 1.0
    assert incident.features["unique_source_count"] == 1.0
    assert incident.start_time == datetime(2026, 10, 27, tzinfo=UTC)
    assert incident.end_time.second == 10


def test_unrelated_suricata_does_not_make_c2_complete() -> None:
    network = raw_c2_alert(
        "NET-ONLY",
        3,
        {
            "image": "curl.exe",
            "processGuid": "unproven",
            "initiated": "true",
            "sourceIp": "10.20.0.10",
            "destinationIp": "10.40.0.10",
            "destinationPort": "8081",
        },
        1,
    )
    eve = WazuhAlert.model_validate(
        {
            "id": "EVE-UNRELATED",
            "timestamp": "2026-10-27T00:00:01Z",
            "rule": {"id": "86601", "level": 5},
            "agent": {"name": "NET-SENSOR"},
            "full_log": json.dumps(
                {
                    "event_type": "alert",
                    "timestamp": "2026-10-27T00:00:01Z",
                    "src_ip": "10.20.0.99",
                    "dest_ip": "198.51.100.8",
                    "dest_port": 80,
                    "alert": {"signature_id": 1, "severity": 1},
                }
            ),
        }
    )
    result = aggregate_wazuh_alerts([network, eve]).incidents[0]
    assert result.quality_status == "PARTIAL"
    assert result.incident.features["outbound_connection_count"] == 0.0
    assert result.incident.features["suricata_alert_count"] == 0.0


def test_fixed_windows_do_not_reassign_events_when_earliest_event_expires() -> None:
    first = load_fixture("wazuh-alert-account.json")
    second = load_fixture("wazuh-alert-account.json")
    first.update(id="BUCKET-1", timestamp="2026-10-27T00:04:50Z")
    second.update(id="BUCKET-2", timestamp="2026-10-27T00:05:10Z")
    batch = aggregate_wazuh_alerts(
        [WazuhAlert.model_validate(first), WazuhAlert.model_validate(second)]
    )
    assert len(batch.incidents) == 2


def test_data_only_eve_is_preserved_at_wazuh_boundary_and_correlated() -> None:
    process = raw_c2_alert(
        "DATA-PROCESS",
        1,
        {
            "image": "curl.exe",
            "processGuid": "g1",
            "commandLine": "curl.exe http://10.40.0.10:8081/beacon",
        },
        0,
    )
    network = raw_c2_alert(
        "DATA-NETWORK",
        3,
        {
            "image": "curl.exe",
            "processGuid": "g1",
            "initiated": "true",
            "sourceIp": "10.20.0.10",
            "sourcePort": "50001",
            "protocol": "tcp",
            "destinationIp": "10.40.0.10",
            "destinationPort": "8081",
        },
        1,
    )
    eve = WazuhAlert.model_validate(
        {
            "id": "DATA-EVE",
            "timestamp": "2026-10-27T00:02:00Z",
            "rule": {"id": "86601", "level": 5},
            "agent": {"name": "NET-SENSOR"},
            "data": {
                "event_type": "alert",
                "timestamp": "2026-10-27T00:00:01Z",
                "src_ip": "10.20.0.10",
                "src_port": 50001,
                "proto": "TCP",
                "sensor_instance": "sensor-boot-qa-001",
                "flow_id": 123,
                "dest_ip": "10.40.0.10",
                "dest_port": 8081,
                "alert": {"signature_id": 900001, "severity": 3},
            },
        }
    )
    eve = WazuhAlert.model_validate(eve.model_dump(mode="json", exclude_none=True))
    assert eve.data.proto == "TCP"
    assert eve.data.sensor_instance == "sensor-boot-qa-001"
    result = aggregate_wazuh_alerts([process, network, eve]).incidents[0]
    assert result.quality_status == "PARTIAL"
    assert result.incident.context_status == "MISSING"
    assert result.incident.features["suricata_alert_count"] == 1.0
    assert result.incident.end_time.second == 1


def test_dns_requires_process_and_client_correlated_eve(monkeypatch) -> None:
    monkeypatch.setattr(
        "ml.feature_pipeline._collection_config",
        lambda: {
            "windows_agent_name": "WIN11-TARGET",
            "suricata_agent_name": "NET-SENSOR",
            "taxonomy_path": "config/suspicious-process-taxonomy.yaml",
            "windows_source_ips": ["10.20.0.10"],
        },
    )
    process = raw_c2_alert(
        "DNS-PROCESS",
        1,
        {
            "image": "powershell.exe",
            "processGuid": "dns-guid",
            "commandLine": "powershell.exe Resolve-DnsName auditnonce1.beacon.datn.test",
        },
        0,
    )
    query = raw_c2_alert(
        "DNS-QUERY",
        22,
        {
            "image": "powershell.exe",
            "processGuid": "dns-guid",
            "queryName": "auditnonce1.beacon.datn.test",
        },
        1,
    )
    payload = {
        "event_type": "dns",
        "timestamp": "2026-10-27T00:00:01Z",
        "src_ip": "10.40.0.10",
        "dest_ip": "10.20.0.10",
        "src_port": 53,
        "dns": {"type": "answer", "queries": [{"rrname": "auditnonce1.beacon.datn.test"}]},
    }
    envelope = {
        "id": "DNS-ANSWER",
        "timestamp": "2026-10-27T00:00:03Z",
        "rule": {"id": "86601", "level": 3},
        "agent": {"name": "NET-SENSOR"},
    }
    eve = WazuhAlert.model_validate({**envelope, "full_log": json.dumps(payload)})
    result = aggregate_wazuh_alerts([process, query, eve]).incidents[0]
    assert result.quality_status == "PARTIAL"
    assert result.incident.context_status == "MISSING"
    assert result.incident.features["dns_query_count"] == 1.0
    assert result.incident.features["suspicious_process"] == 1.0

    wrong_client = WazuhAlert.model_validate(
        {**envelope, "full_log": json.dumps({**payload, "dest_ip": "10.20.0.99"})}
    )
    unrelated = aggregate_wazuh_alerts([process, query, wrong_client]).incidents[0]
    assert unrelated.quality_status == "PARTIAL"
    assert "suricata_alert_count" in unrelated.missing_required_features
    missing_process = aggregate_wazuh_alerts([query, eve]).incidents[0]
    assert missing_process.quality_status == "PARTIAL"
    assert missing_process.incident.features["dns_query_count"] == 0.0


@pytest.mark.parametrize("dns", [False, True])
@pytest.mark.parametrize("mapped_ip", [False, True])
@pytest.mark.parametrize("eve_second", [1, 16])
def test_offline_and_online_derive_the_same_c2_vector_for_same_raw_window(
    dns: bool, mapped_ip: bool, eve_second: int,
) -> None:
    import yaml

    from ml.scenario_collection import CollectionError, RunDraft, SourceConfig, _derive_c2

    nonce = "testnonce001"
    query = f"{nonce}.beacon.datn.test"
    command = (
        f"powershell.exe Resolve-DnsName {query}"
        if dns
        else f"curl.exe http://10.40.0.10:8081/beacon?run={nonce}"
    )
    image = "powershell.exe" if dns else "curl.exe"
    process = raw_c2_alert(
        "PARITY-PROCESS",
        1,
        {
            "image": image,
            "processGuid": "parity-guid",
            "commandLine": command,
        },
        0,
    )
    details = {"image": image, "processGuid": "parity-guid"}
    details.update(
        {"queryName": query}
        if dns
        else {
            "initiated": "true",
            "sourceIp": "::ffff:10.20.0.10" if mapped_ip else "10.20.0.10",
            "destinationIp": "::ffff:10.40.0.10" if mapped_ip else "10.40.0.10",
            "destinationPort": "8081",
            "sourcePort": "50001",
            "protocol": "tcp",
        }
    )
    network = raw_c2_alert("PARITY-NETWORK", 22 if dns else 3, details, 1)
    eve_data = {
        "event_type": "alert",
        "timestamp": f"2026-10-27T00:00:{eve_second:02d}Z",
        "src_ip": "::ffff:10.20.0.10" if mapped_ip else "10.20.0.10",
        "dest_ip": "::ffff:10.40.0.10" if mapped_ip else "10.40.0.10",
        "dest_port": 53 if dns else 8081,
        "flow_id": 123,
        "src_port": 50001,
        "proto": "UDP" if dns else "TCP",
        "alert": {"signature_id": 900002 if dns else 900001, "severity": 3},
    }
    if dns:
        eve_data["dns"] = {"type": "query", "queries": [{"rrname": query}]}
    else:
        eve_data["http"] = {"url": f"/beacon?run={nonce}"}
    eve = WazuhAlert.model_validate(
        {
            "id": "PARITY-EVE",
            "timestamp": "2026-10-27T00:02:00Z",
            "rule": {"id": "86601", "level": 5},
            "agent": {"name": "NET-SENSOR"},
            "data": eve_data,
        }
    )
    clock = {
        name: "2026-10-27T00:00:00Z"
        for name in (
            "captured_at",
            "controller_utc",
            "target_utc",
            "wazuh_utc",
            "sensor_utc",
            "attacker_utc",
        )
    }
    clock["maximum_skew_seconds"] = 10
    attribution = {
        "process_names": [image],
        "source_ips": ["10.20.0.10"],
        "command_contains_any": ["beacon.datn.test" if dns else "/beacon"],
    }
    attribution.update(
        {"dns_suffixes": ["beacon.datn.test"]}
        if dns
        else {"destination_ips": ["10.40.0.10"], "destination_ports": [8081]}
    )
    draft = RunDraft.model_validate(
        {
            "scenario_id": "PARITY",
            "run_id": "PARITY-1",
            "family": "c2",
            "label": "malicious",
            "host": "WIN11-TARGET",
            "expected_behavior": "Controlled raw telemetry parity check.",
            "operator": "test",
            "attribution": attribution,
            "quality_gates": {
                "min_process_events": 1,
                "min_dns_events" if dns else "min_network_events": 1,
                "min_suricata_events": 1,
            },
            "collection_seed": 42,
            "scenario_parameters": {
                "run_nonce": nonce,
                "expected_action_count": 1,
                "expected_intervals_seconds": "",
            },
            "expected_observables": ["correlated process, network and EVE"],
            "clock_preflight": clock,
        }
    )
    source = SourceConfig.model_validate(
        yaml.safe_load((ROOT / "config/collection-sources.yaml").read_text(encoding="utf-8"))
    )
    # This component fixture deliberately has no final-flow counter record.
    # Full collection requires it; both feature results must remain PARTIAL here.
    source = source.model_copy(update={"require_flow_counters": False})
    taxonomy = yaml.safe_load((ROOT / "config/suspicious-process-taxonomy.yaml").read_text())
    alerts = [process, network, eve]
    if eve_second == 16:
        with pytest.raises(CollectionError, match="Suricata"):
            _derive_c2(
                [alert.model_dump(mode="json") for alert in alerts], draft, source, taxonomy
            )
        assert aggregate_wazuh_alerts(alerts).incidents[0].quality_status == "PARTIAL"
        return
    offline = _derive_c2(
        [alert.model_dump(mode="json") for alert in alerts], draft, source, taxonomy
    )[0]
    online = aggregate_wazuh_alerts(alerts).incidents[0]
    assert online.quality_status == "PARTIAL"
    assert online.incident.context_status == "MISSING"
    assert online.incident.features == offline


def load_fixture(name: str) -> dict:
    return json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))


def test_account_fixture_produces_versioned_deterministic_features() -> None:
    alert = WazuhAlert.model_validate(load_fixture("wazuh-alert-account.json"))

    first = extract_wazuh_features(alert)
    second = extract_wazuh_features(alert)

    assert first == second
    assert first.feature_schema_version == "features-v3"
    assert first.feature_order == list(FEATURE_ORDER)
    assert first.incident.incident_id.startswith("INC-FV3-")
    assert first.incident.family_hint == "account"
    assert first.incident.asset_id == "linux-endpoint-01"
    assert first.incident.features["failed_login_count"] == 12.0
    assert first.incident.features["success_after_fail"] == 1.0
    assert first.incident.indicator == "203.0.113.66"
    assert first.incident.evidence_sources == ["wazuh"]
    assert first.evidence_quality < 1.0
    assert first.evidence_quality_reasons
    assert "source-log:auth.log" in first.incident.raw_refs
    assert (first.incident.end_time - first.incident.start_time).total_seconds() == 0


def test_c2_fixture_produces_only_observed_behavioral_features() -> None:
    alert = WazuhAlert.model_validate(load_fixture("wazuh-alert-c2.json"))

    result = extract_wazuh_features(alert)

    assert result.incident.family_hint == "c2"
    assert result.incident.features["suspicious_process"] == 1.0
    assert result.incident.features["periodicity_score"] == 0.87
    assert result.incident.features["suricata_alert_count"] == 2.0
    assert result.incident.features["outbound_connection_count"] == 15.0
    assert result.incident.features["destination_port_count"] == 1.0
    assert result.quality_status == "PARTIAL"
    assert result.evidence_quality < 1.0
    forbidden = {"label", "ground_truth", "asset_criticality", "ti_score"}
    assert forbidden.isdisjoint(result.incident.features)


def test_missing_optional_measurements_default_safely_without_failure() -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["data"] = {"srcip": "unknown.example"}
    alert = WazuhAlert.model_validate(payload)

    result = extract_wazuh_features(alert)

    assert all(value == 0.0 for value in result.incident.features.values())
    assert set(result.missing_required_features) == set(FEATURE_ORDER[:10])
    assert set(result.structural_zero_features) == set(FEATURE_ORDER[10:])
    assert result.quality_status == "PARTIAL"


def test_feature_pipeline_does_not_copy_fixture_normalized_incident() -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["normalized_incident"]["features"]["failed_login_count"] = 9999

    result = extract_wazuh_features(WazuhAlert.model_validate(payload))

    assert result.incident.features["failed_login_count"] == 12.0


def test_feature_schema_and_implementation_have_identical_order() -> None:
    schema = json.loads((ROOT / "ml/feature_schema.json").read_text(encoding="utf-8"))

    assert schema["version"] == "features-v3"
    assert schema["x-feature-order"] == list(FEATURE_ORDER)
    assert list(schema["properties"]) == list(FEATURE_ORDER)


def test_batch_pipeline_deduplicates_and_aggregates_within_window() -> None:
    first = load_fixture("wazuh-alert-account.json")
    second = load_fixture("wazuh-alert-account.json")
    second["id"] = "WAZUH-W2-ACCOUNT-0002"
    second["timestamp"] = "2026-10-05T12:03:00Z"
    second["data"]["failed_login_count"] = 3
    alerts = [
        WazuhAlert.model_validate(first),
        WazuhAlert.model_validate(first),
        WazuhAlert.model_validate(second),
    ]

    batch = aggregate_wazuh_alerts(alerts, window_minutes=5)

    assert batch.input_alert_count == 3
    assert batch.unique_alert_count == 2
    assert batch.duplicate_alert_count == 1
    assert len(batch.incidents) == 1
    incident = batch.incidents[0].incident
    assert incident.features["failed_login_count"] == 12.0
    assert batch.incidents[0].quality_status == "PARTIAL"
    assert (incident.end_time - incident.start_time).total_seconds() == 180
    assert incident.evidence_sources == ["wazuh"]


def test_batch_pipeline_uses_half_open_five_minute_window() -> None:
    first = load_fixture("wazuh-alert-account.json")
    second = load_fixture("wazuh-alert-account.json")
    second["id"] = "WAZUH-W2-ACCOUNT-0003"
    second["timestamp"] = "2026-10-05T12:05:00Z"

    batch = aggregate_wazuh_alerts(
        [WazuhAlert.model_validate(first), WazuhAlert.model_validate(second)],
        window_minutes=5,
    )

    assert len(batch.incidents) == 2


def test_batch_pipeline_rejects_conflicting_duplicate_id() -> None:
    first = load_fixture("wazuh-alert-account.json")
    conflicting = load_fixture("wazuh-alert-account.json")
    conflicting["data"]["failed_login_count"] = 99

    try:
        aggregate_wazuh_alerts(
            [WazuhAlert.model_validate(first), WazuhAlert.model_validate(conflicting)]
        )
    except ValueError as error:
        assert "conflicting payload" in str(error)
    else:
        raise AssertionError("conflicting duplicate must be rejected")


def test_naive_timestamp_is_rejected_at_boundary() -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["timestamp"] = "2026-10-05T12:00:00"

    with pytest.raises(ValidationError, match="timezone"):
        WazuhAlert.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("failed_login_count", -1),
        ("failed_login_count", 1_000_001),
        ("success_after_fail", 2),
        ("periodicity_score", 1.1),
        ("destination_port_count", 65_536),
    ],
)
def test_feature_bounds_are_enforced(field: str, value: float) -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["data"][field] = value

    with pytest.raises(ValidationError):
        WazuhAlert.model_validate(payload)


def test_raw_account_events_are_correlated_before_deriving_features() -> None:
    def raw_alert(alert_id: str, timestamp: str, event_id: int) -> WazuhAlert:
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

    alerts = [
        raw_alert("A-1", "2026-10-05T12:00:00Z", 4625),
        raw_alert("A-2", "2026-10-05T12:00:10Z", 4625),
        raw_alert("A-3", "2026-10-05T12:00:20Z", 4624),
    ]

    result = aggregate_wazuh_alerts(alerts).incidents[0]

    assert result.quality_status == "PARTIAL"
    assert result.incident.context_status == "MISSING"
    assert result.evidence_quality == 0.96
    assert "new_source_for_user" in result.missing_required_features
    assert result.incident.features["failed_login_count"] == 2.0
    assert result.incident.features["successful_login_count"] == 1.0
    assert result.incident.features["success_after_fail"] == 1.0
    assert result.incident.features["unique_target_account_count"] == 1.0
    assert result.incident.features["unique_source_count"] == 1.0
    assert result.incident.features["remote_logon_ratio"] == 1.0


def test_password_spray_accounts_from_one_source_share_behavior_window() -> None:
    def failure(alert_id: str, timestamp: str, account: str) -> WazuhAlert:
        return WazuhAlert.model_validate(
            {
                "id": alert_id,
                "timestamp": timestamp,
                "rule": {"id": "60122", "level": 10},
                "agent": {"id": "001", "name": "WIN11-TARGET"},
                "decoder": {"name": "windows_eventchannel"},
                "data": {
                    "win": {
                        "system": {"eventID": "4625", "systemTime": timestamp},
                        "eventdata": {
                            "targetUserName": account,
                            "ipAddress": "10.40.0.10",
                            "logonType": "3",
                        },
                    }
                },
                "location": "Security",
            }
        )

    batch = aggregate_wazuh_alerts(
        [
            failure("SPRAY-1", "2026-10-05T12:00:00Z", "alice"),
            failure("SPRAY-2", "2026-10-05T12:00:10Z", "bob"),
            failure("SPRAY-3", "2026-10-05T12:00:20Z", "carol"),
        ]
    )

    assert len(batch.incidents) == 1
    features = batch.incidents[0].incident.features
    assert features["failed_login_count"] == 3.0
    assert features["unique_target_account_count"] == 3.0
    assert features["unique_source_count"] == 1.0


def test_account_events_from_different_sources_remain_separate() -> None:
    alerts = []
    for index, source in enumerate(("10.40.0.10", "10.40.0.11"), start=1):
        payload = {
            "id": f"SOURCE-{index}",
            "timestamp": f"2026-10-05T12:00:0{index}Z",
            "rule": {"id": "60122", "level": 7},
            "agent": {"id": "001", "name": "WIN11-TARGET"},
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "win": {
                    "system": {"eventID": "4625", "systemTime": f"2026-10-05T12:00:0{index}Z"},
                    "eventdata": {
                        "targetUserName": "labuser",
                        "ipAddress": source,
                        "logonType": "3",
                    },
                }
            },
            "location": "Security",
        }
        alerts.append(WazuhAlert.model_validate(payload))

    assert len(aggregate_wazuh_alerts(alerts).incidents) == 2


@pytest.mark.parametrize(
    ("logon_type", "expected_ratio"),
    [("2", 0.0), ("7", 0.0), ("11", 0.0), ("3", 1.0), ("10", 1.0)],
)
def test_windows_logon_type_is_classified_by_remote_semantics(
    logon_type: str, expected_ratio: float
) -> None:
    payload = {
        "id": f"LOGON-{logon_type}",
        "timestamp": "2026-10-05T12:00:00Z",
        "rule": {"id": "60122", "level": 7},
        "agent": {"id": "001", "name": "WIN11-TARGET"},
        "decoder": {"name": "windows_eventchannel"},
        "data": {
            "win": {
                "system": {"eventID": "4624", "systemTime": "2026-10-05T12:00:00Z"},
                "eventdata": {
                    "targetUserName": "labuser",
                    "ipAddress": "10.40.0.10",
                    "logonType": logon_type,
                },
            }
        },
        "location": "Security",
    }

    result = extract_wazuh_features(WazuhAlert.model_validate(payload))

    assert result.incident.features["remote_logon_ratio"] == expected_ratio
