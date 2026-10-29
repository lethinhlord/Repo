"""Only an explicit watermark may turn a provisional window into a final observation."""
from datetime import UTC, datetime

import pytest
from test_context_feature_contract import baseline
from test_feature_state import raw_account_alert

from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from ml.feature_pipeline import aggregate_wazuh_alerts

BUCKET = datetime(2026, 10, 27, tzinfo=UTC).timestamp()


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr('api.app.feature_state.aggregate_wazuh_alerts',
        lambda alerts, **kw: aggregate_wazuh_alerts(alerts, baseline=baseline(), **kw))
    return FeatureStateStore(tmp_path/'state.sqlite3')


def test_close_waits_for_watermark_then_reproduces_all_events_and_caches(store, monkeypatch):
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 20)
    first = raw_account_alert('FIRST', '2026-10-27T00:00:05Z', 4625)
    store.ingest(first)
    second = raw_account_alert('SECOND', '2026-10-27T00:00:15Z', 4624)
    store.ingest(second)
    with pytest.raises(FeatureStateConflictError, match='close|watermark'):
        store.finalize_window(first.id)
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 400)
    result = store.finalize_window(first.id)
    assert result.feature.incident.observation_quality == 'COMPLETE'
    assert result.feature.incident.features['failed_login_count'] == 1
    assert result.feature.incident.features['successful_login_count'] == 1
    assert not any(x.startswith('window:') for x in result.feature.incident.review_reasons)
    assert result.stored_event_count == 2
    replay = store.finalize_window(second.id)
    assert replay.ingest_status == 'duplicate'
    assert replay.feature == result.feature


def test_late_arrival_does_not_silently_rewrite_a_closed_window(store, monkeypatch):
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 20)
    first = raw_account_alert('FIRST', '2026-10-27T00:00:05Z', 4625)
    store.ingest(first)
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 400)
    store.finalize_window(first.id)
    late = raw_account_alert('LATE', '2026-10-27T00:00:10Z', 4625)
    assert 'window:late_arrival' in store.ingest(late).feature.incident.review_reasons
    with pytest.raises(FeatureStateConflictError, match='late|changed'):
        store.finalize_window(first.id)


def test_closing_never_upgrades_missing_history_to_complete(tmp_path, monkeypatch):
    store = FeatureStateStore(tmp_path/'no-context.sqlite3')
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 20)
    first = raw_account_alert('FIRST', '2026-10-27T00:00:05Z', 4624)
    store.ingest(first)
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 400)
    result = store.finalize_window(first.id)
    assert result.feature.incident.observation_quality == 'PARTIAL'
    assert result.feature.incident.context_status == 'MISSING'


def test_api_exposes_explicit_window_closure_with_conflict_before_watermark(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from api.app.main import app
    monkeypatch.setenv('FEATURE_STATE_DB', str(tmp_path/'api-state.sqlite3'))
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 20)
    client = TestClient(app)
    alert = raw_account_alert('API-CLOSE', '2026-10-27T00:00:05Z', 4624)
    ingested = client.post('/features/wazuh/stateful', json=alert.model_dump(mode='json'))
    assert ingested.status_code == 200
    request = {'alert_id': alert.id, 'window_minutes': 5}
    assert client.post('/features/wazuh/finalize-window', json=request).status_code == 409
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 400)
    response = client.post('/features/wazuh/finalize-window', json=request)
    assert response.status_code == 200
    assert response.json()['feature']['incident']['context_status'] == 'MISSING'
    assert response.json()['feature']['quality_status'] == 'PARTIAL'


def test_late_final_eve_flow_updates_original_window_before_watermark(store, monkeypatch):
    import json
    import math

    from test_context_feature_contract import windows_event
    from test_flow_accounting import flow

    from api.app.contracts import WazuhAlert
    guid = '{FLOW-CLOSE-UNIT}'
    process = windows_event(1, {'image':'curl.exe', 'processGuid':guid,
                               'commandLine':'curl.exe https://service.local/status'}, 5)
    network = windows_event(3, {'image':'curl.exe', 'processGuid':guid, 'initiated':'true',
        'sourceIp':'10.20.0.10', 'sourcePort':'50001', 'protocol':'tcp',
        'destinationIp':'10.40.0.10', 'destinationPort':'8081'}, 8)

    def eve(identifier, payload):
        return WazuhAlert.model_validate({
            'id':identifier, 'timestamp':payload['timestamp'],
            'rule':{'id':'unit-eve', 'level':0}, 'agent':{'name':'NET-SENSOR'},
            'full_log':json.dumps(payload),
        })

    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 20)
    store.ingest(process)
    store.ingest(network)
    store.ingest(eve('HTTP-TRANSACTION', flow(event_type='http', emitted=8, sent=60, received=30)))
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 340)
    provisional = store.ingest(eve('FINAL-FLOW', flow(emitted=340)))
    assert provisional.feature.incident.start_time.timestamp() < BUCKET + 300
    monkeypatch.setattr('api.app.feature_state.time.time', lambda: BUCKET + 400)
    closed = store.finalize_window(process.id)
    assert closed.feature.quality_status == 'COMPLETE'
    assert closed.feature.incident.features['flow_total_bytes_log1p'] == round(math.log1p(300), 6)
    assert closed.stored_event_count == 4
