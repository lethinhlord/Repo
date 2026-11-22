"""Label-free transaction enrichment from native evidence, not actor parameters."""

import json
from copy import deepcopy

import pytest
from test_supplemental_capture_binding import http_events

from api.app.contracts import WazuhAlert


def alerts_for(events):
    return [
        WazuhAlert.model_validate(
            {"rule": {"id": "archive-raw", "level": 0}, **r, "id": f"evidence-{i}"}
        )
        for i, r in enumerate(events)
    ]


def enrich(tmp_path, events=None, window_minutes=5):
    from ml.feature_pipeline import derive_c2_network_evidence
    from ml.http_features import derive_http_features

    _, source, generated = http_events(tmp_path)
    alerts = alerts_for(generated if events is None else events)
    proof = derive_c2_network_evidence(alerts, source.model_dump(), taxonomy={"rules": []})
    return derive_http_features(alerts, proof, source.model_dump(), window_minutes=window_minutes)


def test_http_features_use_actual_method_order_sizes_and_masks(tmp_path):
    values = enrich(tmp_path)
    assert values["http_transaction_count"] == 8
    assert values["http_post_fraction"] == 0.5
    assert values["http_method_switch_fraction"] == 1
    assert values["http_evidence_available"] == values["flow_evidence_available"] == 1
    assert values["verified_parent_fraction"] == values["reported_parent_fraction"] == 0
    assert 0 < values["flow_upload_fraction"] < 1
    assert values["http_response_bytes_log1p"] > 0


def test_missing_transactions_are_unknown_and_duplicate_envelopes_do_not_inflate(tmp_path):
    _, _, events = http_events(tmp_path)
    expected = enrich(tmp_path, events)
    assert enrich(tmp_path, events + deepcopy(events)) == expected
    without_http = [
        r
        for r in events
        if not ("full_log" in r and json.loads(r["full_log"])["event_type"] == "http")
    ]
    result = enrich(tmp_path, without_http)
    assert result["http_evidence_available"] == 0
    assert result["flow_evidence_available"] == 0
    assert result["http_transaction_count"] == 0


def test_parent_claim_is_distinct_from_independent_parent_proof(tmp_path):
    _, _, events = http_events(tmp_path)
    for r in events:
        win = r.get("data", {}).get("win")
        if win and win["system"]["eventID"] == "1":
            win["eventdata"].update(
                parentProcessGuid="{PARENT}", parentImage="powershell.exe", parentProcessId="77"
            )
    claimed = enrich(tmp_path, events)
    assert claimed["reported_parent_fraction"] == 1
    assert claimed["verified_parent_fraction"] == 0
    parent = deepcopy(next(r for r in events if r.get("data", {}).get("win")))
    parent["data"]["win"]["system"]["systemTime"] = "2027-01-01T00:00:00+00:00"
    parent["data"]["win"]["eventdata"] = dict(
        processGuid="{PARENT}",
        image="powershell.exe",
        processId="77",
        utcTime="2027-01-01T00:00:00+00:00",
        commandLine="powershell.exe -NoProfile",
    )
    verified = enrich(tmp_path, [parent, *events])
    assert verified["verified_parent_fraction"] == verified["verified_shell_parent_fraction"] == 1
    foreign = deepcopy(parent)
    foreign["data"]["win"]["system"]["providerName"] = "Microsoft-Windows-Security-Auditing"
    assert enrich(tmp_path, [foreign, *events])["verified_parent_fraction"] == 0
    parent["data"]["win"]["eventdata"]["processId"] = "88"
    with pytest.raises(ValueError, match="parent"):
        enrich(tmp_path, [parent, *events])


def test_batch_retains_all44_and_closed56_schema(tmp_path):
    from ml.feature_profiles import registered_schema, validate_stream_values
    from ml.http_pipeline import aggregate_http_alerts
    from ml.stream_pipeline import aggregate_stream_alerts

    _, source, events = http_events(tmp_path)
    alerts = alerts_for(events)
    options = dict(
        source_config=source.model_dump(), taxonomy={"rules": []}, use_runtime_baseline=False
    )
    old = aggregate_stream_alerts(alerts, **options).incidents[0].incident
    rich = aggregate_http_alerts(alerts, **options).incidents[0]
    assert len(rich.incident.features) == 56
    assert {k: rich.incident.features[k] for k in old.features} == old.features
    assert rich.incident.features["http_evidence_available"] == 1
    assert rich.feature_schema_version == "features-v5-http-v1"
    schema = registered_schema(rich.feature_schema_version)
    assert schema["x-feature-order"] == rich.feature_order
    assert "http" in schema["$id"]
    validate_stream_values(rich.incident.features, schema)
    with pytest.raises(ValueError):
        validate_stream_values({**rich.incident.features, "label": 1}, schema)


def test_http_stateful_contract_is_separate_and_keeps_unknown_evidence(tmp_path, monkeypatch):
    from test_stream_feature_state import clock
    from test_stream_pipeline import CONFIG, events

    from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
    from ml.http_pipeline import aggregate_http_alerts

    clock(monkeypatch, 50)
    monkeypatch.setattr("ml.http_pipeline._collection_config", lambda: CONFIG)
    path = tmp_path / "http.sqlite"
    store = FeatureStateStore(path, feature_profile="features-v5-http-v1")
    for alert in events():
        value = store.ingest(alert)
    assert value.feature.feature_schema_version == "features-v5-http-v1"
    clock(monkeypatch, 361)
    finalized = store.finalize_window("net-2")
    batch = aggregate_http_alerts(
        events(), source_config=CONFIG, taxonomy={}, use_runtime_baseline=False
    ).incidents[0]
    assert finalized.feature.incident.features == batch.incident.features
    assert finalized.feature.incident.observation_quality == "PARTIAL"
    assert "http_evidence_available" in finalized.feature.missing_required_features
    with pytest.raises(FeatureStateConflictError, match="grouping"):
        FeatureStateStore(path, feature_profile="features-v4-stream-v1")


def test_http_routes_are_typed_and_never_silently_use_mock(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from api.app.main import app

    _, source, events = http_events(tmp_path)
    config = source.model_dump()
    monkeypatch.setattr("ml.http_pipeline._collection_config", lambda: config)
    monkeypatch.delenv("CONTEXT_BASELINE_PATH", raising=False)
    monkeypatch.delenv("MODEL_PACKAGE_DIR", raising=False)
    monkeypatch.setenv("ALLOW_MOCK_INFERENCE", "true")
    client = TestClient(app)
    response = client.post(
        "/features/wazuh/http/batch",
        json={
            "alerts": [a.model_dump(mode="json") for a in alerts_for(events)],
        },
    )
    assert response.status_code == 200, response.text
    incident = response.json()["incidents"][0]["incident"]
    assert incident["feature_schema_version"] == "features-v5-http-v1"
    assert client.post("/predict/http", json=incident).status_code == 503
    assert client.post("/predict/stream", json=incident).status_code == 422
    incident["feature_schema_version"] = "features-v3"
    assert client.post("/predict/http", json=incident).status_code == 422


def test_prior_bucket_child_identity_is_equal_with_or_without_explicit_cache(tmp_path):
    from ml.http_pipeline import aggregate_http_alerts

    _, source, events = http_events(tmp_path)
    for event in events:
        win = event.get("data", {}).get("win")
        if win and win["system"]["eventID"] == "1":
            event["timestamp"] = win["system"]["systemTime"] = "2026-12-31T23:59:59+00:00"
            win["eventdata"]["utcTime"] = event["timestamp"]
    alerts = alerts_for(events)
    options = dict(source_config=source.model_dump(), taxonomy={}, use_runtime_baseline=False)
    starts = [a for a in alerts if a.data.win and a.data.win["system"]["eventID"] == "1"]
    plain = aggregate_http_alerts(alerts, **options)
    cached = aggregate_http_alerts(alerts, process_context=starts, **options)
    before = next(
        i.incident for i in plain.incidents if i.incident.features["tcp_connection_count"]
    )
    after = next(
        i.incident for i in cached.incidents if i.incident.features["tcp_connection_count"]
    )
    assert before.features == after.features
    assert before.features["http_evidence_available"] == 1


def test_reversed_flow_tuple_cannot_prove_directional_upload(tmp_path):
    _, _, events = http_events(tmp_path)
    for row in events:
        if "full_log" not in row:
            continue
        p = json.loads(row["full_log"])
        if p["event_type"] == "flow":
            p["src_ip"], p["dest_ip"] = p["dest_ip"], p["src_ip"]
            p["src_port"], p["dest_port"] = p["dest_port"], p["src_port"]
        row["full_log"] = json.dumps(p)
    value = enrich(tmp_path, events)
    assert value["http_evidence_available"] == 1
    assert value["flow_evidence_available"] == value["flow_upload_fraction"] == 0


@pytest.mark.parametrize("mutation", ["zero-counters", "one-minute"])
def test_flow_mask_never_certifies_impossible_bytes_or_wrong_bucket(tmp_path, mutation):
    _, _, events = http_events(tmp_path)
    for row in events:
        if "full_log" not in row:
            continue
        p = json.loads(row["full_log"])
        if p["event_type"] == "flow" and mutation == "zero-counters":
            p["flow"].update(bytes_toserver=0, bytes_toclient=0)
        row["full_log"] = json.dumps(p)
    value = enrich(tmp_path, events, window_minutes=1 if mutation == "one-minute" else 5)
    assert value["http_evidence_available"] == 1
    assert value["flow_evidence_available"] == 0


def test_method_order_uses_native_connection_order_not_response_latency(tmp_path):
    from datetime import datetime, timedelta

    _, _, events = http_events(tmp_path, "C2-SUP-03")
    original = enrich(tmp_path, events)
    count = 0
    for row in events:
        if "full_log" not in row:
            continue
        p = json.loads(row["full_log"])
        if p["event_type"] == "http" and count == 0:
            at = datetime.fromisoformat(row["timestamp"]) + timedelta(seconds=7)
            row["timestamp"] = p["timestamp"] = at.isoformat()
            count += 1
        if p["event_type"] == "flow":
            p["flow"]["end"] = (
                datetime.fromisoformat(p["flow"]["start"]) + timedelta(seconds=8)
            ).isoformat()
        row["full_log"] = json.dumps(p)
    assert enrich(tmp_path, events) == original
