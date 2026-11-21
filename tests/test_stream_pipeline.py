import json
from datetime import UTC, datetime, timedelta

import yaml

from api.app.contracts import WazuhAlert
from ml.context import BaselineSnapshot
from ml.feature_pipeline import aggregate_wazuh_alerts, derive_c2_network_evidence
from ml.scenario_collection import SourceConfig, _verify_full_capture_parity
from ml.stream_pipeline import aggregate_stream_alerts

AT = datetime(2026, 1, 1, 1, tzinfo=UTC)
CONFIG = {"windows_agent_name": "WIN11-TARGET", "suricata_agent_name": "NET-SENSOR",
          "windows_source_ips": ["10.20.0.10"], "correlation_window_seconds": 10,
          "require_flow_counters": False}


def event(ident, kind, seconds, fields):
    at = AT+timedelta(seconds=seconds)
    return WazuhAlert.model_validate({
        "id": ident, "timestamp": at, "agent": {"name": "WIN11-TARGET"},
        "rule": {"id": "raw", "level": 0},
        "data": {"win": {"system": {"eventID": str(kind), "systemTime": at.isoformat()},
                         "eventdata": fields}},
    })


def events():
    result = []
    for i in range(3):
        process = {"processGuid": f"curl-{i}", "image": "curl.exe",
                   "processId": str(i+100), "user": "labuser"}
        result.append(event(f"create-{i}", 1, i*2, process))
        result.append(event(f"net-{i}", 3, i*2+1, {
            **process, "initiated": "true", "sourceIp": "10.20.0.10",
            "destinationIp": "10.40.0.10", "destinationPort": "8081", "protocol": "tcp",
        }))
    result.extend([
        event("dns-create", 1, 1, {"processGuid": "os-dns", "image": "svchost.exe"}),
        event("dns", 22, 40, {"processGuid": "os-dns", "image": "svchost.exe",
                              "queryName": "background.example"}),
        event("unproven", 3, 10, {"processGuid": "no-start", "image": "bad.exe",
            "initiated": "true", "sourceIp": "10.20.0.10", "destinationIp": "192.0.2.99",
            "destinationPort": "443", "protocol": "tcp"}),
    ])
    return result


def baseline():
    return BaselineSnapshot.model_validate({
        "version": "context-baseline-v1", "revision": "independent-enrollment",
        "captured_at": AT-timedelta(hours=1), "observed_through": AT-timedelta(hours=2),
        "valid_until": AT+timedelta(hours=1), "source_capture_sha256": "a"*64,
        "accounts": [], "destinations": [{"asset_id": "WIN11-TARGET",
            "destination": "10.40.0.10", "port": 8081, "process_images": ["curl.exe"]}],
    })


def test_stream_layer_uses_only_already_verified_network_observations():
    proof = derive_c2_network_evidence(events(), CONFIG, {})
    assert len(proof.observations) == len(proof.streams) == 4
    assert {x.process_image for x in proof.streams} == {"curl.exe", "svchost.exe"}
    assert "bad.exe" not in {x.process_image for x in proof.streams}


def test_enrichment_preserves_all_legacy_values_and_quality():
    old = aggregate_wazuh_alerts(events(), baseline=baseline(), source_config=CONFIG,
                                 taxonomy={}, use_runtime_baseline=False).incidents[0]
    new = aggregate_stream_alerts(events(), baseline=baseline(), source_config=CONFIG,
                                  taxonomy={}, use_runtime_baseline=False).incidents[0]
    assert old.feature_schema_version == "features-v3"
    assert new.feature_schema_version == "features-v4-stream-v1"
    assert new.incident.feature_schema_version == "features-v4-stream-v1"
    assert "indicator_attribution" not in old.incident.model_dump()
    assert len(new.incident.features) == 44
    assert {k:new.incident.features[k] for k in old.incident.features} == old.incident.features
    assert new.quality_status == old.quality_status
    assert new.incident.observation_quality == old.incident.observation_quality
    assert new.incident.features["new_destination"] == 1
    assert new.incident.features["dominant_tcp_new_destination"] == 0
    assert new.incident.features["dominant_tcp_context_known"] == 1
    assert new.incident.features["dominant_tcp_periodicity_score"] == 1
    assert new.incident.features["tcp_connection_count"] == 3
    attribution = new.incident.indicator_attribution
    assert attribution.destination == new.incident.indicator == "10.40.0.10"
    assert attribution.history_known and attribution.new_destination is False
    assert attribution.response_authorized is False
    assert set(attribution.evidence_refs) == {"wazuh-alert:net-0", "wazuh-alert:net-1",
                                            "wazuh-alert:net-2"}


def test_transport_event_id_renaming_cannot_change_stream_features():
    alerts = events()
    original = aggregate_stream_alerts(alerts, source_config=CONFIG, taxonomy={},
                                       use_runtime_baseline=False).incidents[0].incident.features
    renamed = [a.model_copy(update={"id": f"other-{i}"}) for i, a in enumerate(reversed(alerts))]
    again = aggregate_stream_alerts(renamed, source_config=CONFIG, taxonomy={},
                                    use_runtime_baseline=False).incidents[0].incident.features
    assert again == original


def test_sealed_raw_replay_and_online_stream_batch_have_identical_features(tmp_path):
    (tmp_path/'context-baseline.json').write_text(baseline().model_dump_json())
    (tmp_path/'suspicious-process-taxonomy.yaml').write_text(yaml.safe_dump({
        'revision':'synthetic-taxonomy', 'rules': [],
    }))
    (tmp_path/'execution_receipt.json').write_text(json.dumps({
        'action_started_at':(AT+timedelta(seconds=1)).isoformat(),
        'aggregation_window_start':AT.isoformat(),
        'aggregation_window_end':(AT+timedelta(minutes=5)).isoformat(),
    }))
    source = SourceConfig.model_validate({
        **CONFIG, 'wazuh_archives_path':'/unused/archives.json',
        'version':'collection-sources-v1', 'taxonomy_path':'unused',
        'scenario_catalog_path':'unused',
    })
    old = aggregate_wazuh_alerts(events(), baseline=baseline(), source_config=CONFIG,
                                 taxonomy={}, use_runtime_baseline=False).incidents[0].incident
    captured = [a.model_dump(mode='json') for a in events()]
    legacy = _verify_full_capture_parity(captured, old, source, tmp_path)
    projected = _verify_full_capture_parity(captured, old, source, tmp_path,
        compare=False, feature_profile='features-v4-stream-v1')
    online = aggregate_stream_alerts(events(), baseline=baseline(), source_config=CONFIG,
                                     taxonomy={}, use_runtime_baseline=False).incidents[0].incident
    assert projected.features == online.features
    assert {k:projected.features[k] for k in legacy.features} == legacy.features
