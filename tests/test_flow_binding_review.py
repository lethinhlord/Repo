"""Independent checks of flow identity validation."""

import pytest
from test_flow_accounting import flow

from ml.telemetry import flow_connection_key


@pytest.mark.parametrize("field", ["src_ip", "dest_ip"])
def test_invalid_ip_cannot_form_flow_identity(field):
    payload = flow(event_type="dns")
    payload[field] = "not-an-ip-address"
    assert flow_connection_key(payload) is None


@pytest.mark.parametrize("change", [{"src_port": 50002}, {"proto": "UDP"}, {"flow_id": 10}])
def test_nonce_inheritance_requires_full_tuple(change):
    from datetime import UTC, datetime

    from ml.telemetry import linked_transaction

    at = datetime(2026, 10, 24, tzinfo=UTC)
    transaction = flow(event_type="http")
    alert = {**transaction, "event_type": "alert", **change}
    assert not linked_transaction(alert, at, [(transaction, at)], 10)


def test_nonce_inheritance_uses_retained_unambiguous_transactions_and_time():
    from datetime import UTC, datetime, timedelta

    from ml.telemetry import linked_transaction, unambiguous_transactions

    at = datetime(2026, 10, 24, tzinfo=UTC)
    transaction = flow(event_type="dns")
    transaction["dns"] = {"type": "query", "rrname": "nonce.example"}
    other = {**transaction, "src_port": 50002}
    references = unambiguous_transactions([(transaction, at), (other, at)], 10)
    alert = {**transaction, "event_type": "alert"}
    assert not linked_transaction(alert, at, references, 10)
    assert not linked_transaction(alert, at + timedelta(seconds=11), [(transaction, at)], 10)
    assert linked_transaction(alert, at, [(transaction, at)], 10)


def test_collector_rejects_reused_flow_id_on_unrelated_socket(tmp_path, monkeypatch):
    import copy
    import json

    import test_collection_acceptance as acceptance
    import yaml

    from ml.scenario_collection import SourceConfig, _derive_c2

    archive, source_path, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == "C2-BENIGN-HEALTH-POLL")
    source = SourceConfig.model_validate(yaml.safe_load(source_path.read_text()))
    taxonomy = yaml.safe_load((tmp_path / source.taxonomy_path).read_text())
    original = acceptance._c2_events
    checked = []

    def check(run_id, selected_scenario, draft, first_event_at):
        events, ended = original(run_id, selected_scenario, draft, first_event_at)
        transactions = [
            event
            for event in events
            if event.get("full_log") and json.loads(event["full_log"]).get("event_type") == "http"
        ]
        assert len(transactions) >= 2
        first, second = [json.loads(event["full_log"]) for event in transactions[:2]]
        unrelated = copy.deepcopy(transactions[1])
        payload = {
            **second,
            "event_type": "alert",
            "flow_id": first["flow_id"],
            "alert": {"signature_id": 987654321, "severity": 1},
        }
        payload.pop("http", None)
        unrelated["full_log"] = json.dumps(payload)
        clean = _derive_c2(events, draft, source, taxonomy)
        actual = _derive_c2(events + [unrelated], draft, source, taxonomy)
        assert actual[0] == clean[0]
        assert unrelated not in actual[2]
        assert all("987654321" not in json.dumps(row) for row in actual[2])
        checked.append(True)
        return events, ended

    monkeypatch.setattr(acceptance, "_c2_events", check)
    acceptance._collect_run(tmp_path, archive, source_path, scenario, sequence=0, repeat=0)
    assert checked
