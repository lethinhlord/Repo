import hashlib

import pytest
from fastapi.testclient import TestClient
from test_stream_pipeline import AT, CONFIG, events

from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from api.app.main import app, load_feature_state_store
from ml.stream_features import STREAM_SCHEMA_VERSION


def clock(monkeypatch, seconds):
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: AT.timestamp()+seconds)
    monkeypatch.setattr("ml.feature_pipeline._collection_config", lambda: CONFIG)
    monkeypatch.setattr("ml.stream_pipeline._collection_config", lambda: CONFIG)
    monkeypatch.setattr("ml.feature_pipeline._process_taxonomy", lambda: {})


def test_stream_cache_ingest_finalize_and_repeat_keep_stream_contract(tmp_path, monkeypatch):
    clock(monkeypatch, 50)
    store = FeatureStateStore(tmp_path/'stream.sqlite', feature_profile=STREAM_SCHEMA_VERSION)
    for item in events():
        value = store.ingest(item)
        assert value.feature.feature_schema_version == STREAM_SCHEMA_VERSION
    clock(monkeypatch, 361)
    closed = store.finalize_window("net-2")
    assert closed.feature.incident.features['tcp_connection_count'] == 3
    assert closed.feature.incident.features['dominant_tcp_periodicity_score'] == 1
    assert closed.feature.incident.indicator_attribution.response_authorized is False
    repeated = store.finalize_window("net-2")
    assert repeated.ingest_status == "duplicate"
    assert repeated.feature.model_dump() == closed.feature.model_dump()


def test_stream_cache_cannot_reinterpret_legacy_database(tmp_path, monkeypatch):
    clock(monkeypatch, 50)
    path = tmp_path/'legacy.sqlite'
    FeatureStateStore(path).ingest(events()[0])
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(FeatureStateConflictError, match="grouping"):
        FeatureStateStore(path, feature_profile=STREAM_SCHEMA_VERSION)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_unknown_cache_profile_is_rejected_before_creating_database(tmp_path):
    path = tmp_path/'never-created.sqlite'
    with pytest.raises(ValueError, match="profile"):
        FeatureStateStore(path, feature_profile="unreviewed")
    assert not path.exists()


def test_online_stream_endpoints_preserve_version_through_window_close(tmp_path, monkeypatch):
    clock(monkeypatch, 50)
    monkeypatch.setenv("FEATURE_STREAM_STATE_DB", str(tmp_path/'online-stream.sqlite'))
    load_feature_state_store.cache_clear()
    client = TestClient(app)
    response = client.post('/features/wazuh/stream/batch', json={
        'alerts': [x.model_dump(mode='json') for x in events()],
    })
    assert response.status_code == 200
    assert response.json()['feature_schema_version'] == STREAM_SCHEMA_VERSION
    for item in events():
        response = client.post('/features/wazuh/stream/stateful', json=item.model_dump(mode='json'))
        assert response.status_code == 200
        assert response.json()['feature']['feature_schema_version'] == STREAM_SCHEMA_VERSION
    clock(monkeypatch, 361)
    response = client.post('/features/wazuh/stream/finalize-window', json={'alert_id':'net-2'})
    assert response.status_code == 200
    assert response.json()['feature']['incident']['features']['tcp_connection_count'] == 3
