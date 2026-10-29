"""Fresh synthetic QA for account scope and online flow attribution; never lab evidence."""

from __future__ import annotations

import json
import math

import pytest
import test_collection_acceptance as acceptance
import yaml
from test_context_feature_contract import baseline, windows_event
from test_flow_accounting import flow

from api.app.contracts import WazuhAlert
from api.app.feature_state import FeatureStateStore
from ml.context import load_baseline
from ml.feature_pipeline import aggregate_wazuh_alerts


def _eve(identifier, payload):
    return WazuhAlert.model_validate(
        {
            "id": identifier,
            "timestamp": payload["timestamp"],
            "rule": {"id": "synthetic-qa", "level": 0},
            "agent": {"name": "NET-SENSOR"},
            "full_log": json.dumps(payload),
        }
    )


@pytest.mark.parametrize(
    "case,expected",
    [
        ("valid", "COMPLETE"),
        ("source-port-mismatch", "PARTIAL"),
        ("protocol-mismatch", "PARTIAL"),
        ("final-without-transaction", "PARTIAL"),
    ],
)
def test_online_c2_requires_attributable_transaction_and_full_tuple(
    tmp_path, monkeypatch, case, expected
):
    bucket = acceptance.COLLECTION_BASE.timestamp() - 5
    monkeypatch.setattr(
        "api.app.feature_state.aggregate_wazuh_alerts",
        lambda alerts, **kw: aggregate_wazuh_alerts(alerts, baseline=baseline(), **kw),
    )
    store = FeatureStateStore(tmp_path / "online.sqlite3")
    guid = "{FRESH-QA-FLOW}"
    process = windows_event(
        1,
        {
            "image": "curl.exe",
            "processGuid": guid,
            "commandLine": "curl.exe http://10.40.0.10:8081/beacon?run=fresh-qa",
        },
        5,
    )
    network = windows_event(
        3,
        {
            "image": "curl.exe",
            "processGuid": guid,
            "initiated": "true",
            "sourceIp": "10.20.0.10",
            "sourcePort": "50001",
            "protocol": "tcp",
            "destinationIp": "10.40.0.10",
            "destinationPort": "8081",
        },
        8,
    )
    transaction = flow(event_type="http", emitted=8, sent=60, received=30)
    transaction["http"] = {"url": "/beacon?run=fresh-qa"}
    final = flow(emitted=70)
    for payload in (transaction, final):
        if case == "source-port-mismatch":
            payload["src_port"] = 50002
        elif case == "protocol-mismatch":
            payload["proto"] = "UDP"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: bucket + 120)
    for alert in (
        [process, network]
        + ([] if case == "final-without-transaction" else [_eve("QA-TX", transaction)])
        + [_eve("QA-FINAL", final)]
    ):
        store.ingest(alert)
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: bucket + 400)
    closed = store.finalize_window(process.id)
    assert closed.feature.quality_status == expected
    if expected == "COMPLETE":
        assert closed.feature.incident.features["flow_total_bytes_log1p"] == round(
            math.log1p(300), 6
        )
    else:
        assert closed.feature.incident.features["flow_total_bytes_log1p"] == 0


def test_dns_missing_transport_tuple_stays_partial_without_guessing(tmp_path):
    archive, sources, catalog = acceptance._prepare_collection_root(tmp_path)
    snapshot = load_baseline(tmp_path / "evidence/context-baseline.json")
    domain = next(
        s for s in catalog.scenarios if s.scenario_id == "C2-BENIGN-DNS"
    ).attribution.dns_suffixes[0]
    guid = "{FRESH-QA-DNS}"
    process = windows_event(
        1,
        {
            "image": "powershell.exe",
            "processGuid": guid,
            "commandLine": f"powershell Resolve-DnsName {domain}",
        },
        5,
    )
    dns = windows_event(
        22, {"image": "powershell.exe", "processGuid": guid, "queryName": domain}, 8
    )
    transaction = flow(event_type="dns", emitted=8)
    transaction.update(dest_port=53, dns={"type": "query", "rrname": domain})
    final = flow(emitted=70)
    final["dest_port"] = 53
    for payload in (transaction, final):
        payload.pop("src_port")
        payload.pop("proto")
    result = aggregate_wazuh_alerts(
        [process, dns, _eve("DNS-TX", transaction), _eve("DNS-FINAL", final)],
        baseline=snapshot,
        source_config=yaml.safe_load(sources.read_text()),
        use_runtime_baseline=False,
    )
    assert len(result.incidents) == 1
    assert result.incidents[0].quality_status == "PARTIAL"
    assert result.incidents[0].incident.features["flow_total_bytes_log1p"] == 0


def test_dns_transactions_with_competing_socket_tuples_are_ambiguous():
    from datetime import UTC, datetime

    from ml.telemetry import unambiguous_transactions

    at = datetime(2026, 10, 24, tzinfo=UTC)
    first = flow(event_type="dns")
    first["dns"] = {"type": "query", "rrname": "fresh.example"}
    second = {**first, "src_port": 50002, "flow_id": 10}
    assert unambiguous_transactions([(first, at), (second, at)], 10) == []


def test_reverse_dns_response_preserves_connection_identity():
    from datetime import UTC, datetime

    from ml.behavior_features import NetworkObservation
    from ml.telemetry import linked_flow, suricata_correlates

    at = datetime(2026, 10, 24, tzinfo=UTC)
    response = flow(event_type="dns")
    response.update(
        src_ip="10.40.0.10",
        src_port=53,
        dest_ip="10.20.0.10",
        dest_port=50001,
        dns={"type": "answer", "rrname": "fresh.example"},
    )
    observation = NetworkObservation(at, "fresh.example", 53, "fresh.example")
    assert suricata_correlates(response, at, [observation], 10, source_ips=["10.20.0.10"])
    final = flow()
    final["dest_port"] = 53
    final["flow"]["start"] = at.isoformat()
    final["flow"]["end"] = at.isoformat()
    assert linked_flow(final, [(response, at)], 10)
