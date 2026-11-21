import json
from pathlib import Path

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.linear_model import LogisticRegression
from test_ml_package import SIGNING_KEY, create_package

from api.app.contracts import IncidentRequest, StreamIncidentRequest
from api.app.main import app
from ml.feature_profiles import registered_schema
from ml.freeze_model import freeze
from ml.inference import InferenceInputError, ModelRuntime

ROOT = Path(__file__).resolve().parents[1]


def request(version="features-v4-stream-v1"):
    schema = registered_schema(version)
    features = dict.fromkeys(schema['required'], 0.0)
    features['destination_history_known'] = 1
    if version == "features-v4-stream-v1":
        features.update(tcp_connection_count=3, dominant_tcp_observation_count=3,
                        dominant_tcp_unique=1, dominant_tcp_context_known=1)
    data = dict(incident_id="stream-test", asset_id="WIN11-TARGET",
        start_time="2026-01-01T00:00:00Z", end_time="2026-01-01T00:00:10Z",
        family_hint="c2", features=features, evidence_sources=["wazuh"], base_severity=0,
        context_status="AVAILABLE", context_revision="independent-enrollment",
        observation_quality="COMPLETE", indicator="192.0.2.10")
    if version == "features-v3":
        return IncidentRequest(**data)
    return StreamIncidentRequest(**data, indicator_attribution=dict(
        destination="192.0.2.10", destination_port=443, observation_count=3,
        history_known=True, new_destination=False, evidence_refs=["wazuh-alert:observed"],
    ))


def package(path, monkeypatch, *, stream=False):
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", SIGNING_KEY)
    create_package(path)
    if stream:
        schema = registered_schema("features-v4-stream-v1")
        bundle = joblib.load(path/'model.joblib')
        bundle['metadata']['feature_schema_version'] = schema['version']
        order = schema['x-family-features']['c2']
        estimator = LogisticRegression().fit(np.array([
            [0]*len(order), [.1]*len(order), [.8]*len(order), [1]*len(order),
        ]), np.array([0, 0, 1, 1]))
        bundle['families']['c2'].update(estimator=estimator, feature_order=order)
        joblib.dump(bundle, path/'model.joblib')
        (path/'metadata.json').write_text(json.dumps(bundle['metadata']))
        (path/'feature_schema.json').write_text(json.dumps(schema))
        profile = json.loads((path/'feature_profile.json').read_text())
        profile['families']['c2']['features'] = {
            n: {'ood_lower': -1, 'ood_upper': 30} for n in order
        }
        (path/'feature_profile.json').write_text(json.dumps(profile))
    freeze(path)
    return ModelRuntime(path)


def test_legacy_runtime_cannot_consume_stream_request_even_with_all_legacy_features(
    tmp_path, monkeypatch,
):
    runtime = package(tmp_path/'old', monkeypatch)
    with pytest.raises(InferenceInputError, match="profile"):
        runtime.predict(request())


def test_stream_runtime_cannot_consume_legacy_request(tmp_path, monkeypatch):
    runtime = package(tmp_path/'new', monkeypatch, stream=True)
    with pytest.raises(InferenceInputError, match="profile"):
        runtime.predict(request("features-v3"))


def test_dns_only_stream_requires_review_even_when_package_threshold_is_eligible(
    tmp_path, monkeypatch,
):
    runtime = package(tmp_path/'new', monkeypatch, stream=True)
    value = request()
    value.features.update(tcp_connection_count=0, dominant_tcp_unique=0,
                          dominant_tcp_context_known=0, dns_only_window=1)
    value.indicator = None
    value.indicator_attribution = None
    result = runtime.predict(value)
    assert result.review_required and not result.automation_eligible
    assert "model:unsupported_non_tcp_c2" in result.review_reasons


def test_target_attribution_must_agree_with_stream_features(tmp_path, monkeypatch):
    runtime = package(tmp_path/'new', monkeypatch, stream=True)
    value = request()
    value.features['dominant_tcp_new_destination'] = 1
    with pytest.raises(InferenceInputError, match="attribution"):
        runtime.predict(value)


@pytest.mark.parametrize("change", ["missing", "unknown", "out-of-bounds"])
def test_stream_contract_validates_retained_values_not_only_compact_model_inputs(
    tmp_path, monkeypatch, change,
):
    runtime = package(tmp_path/'new', monkeypatch, stream=True)
    value = request()
    if change == "missing":
        del value.features['flow_total_bytes_log1p']
    elif change == "unknown":
        value.features['scenario_label'] = 1
    else:
        value.features['dns_observation_fraction'] = 2
    with pytest.raises(InferenceInputError, match="schema"):
        runtime.predict(value)


def test_stream_route_does_not_fall_back_to_legacy_mock(monkeypatch):
    monkeypatch.delenv("MODEL_PACKAGE_DIR", raising=False)
    monkeypatch.setenv("ALLOW_MOCK_INFERENCE", "true")
    response = TestClient(app).post('/predict/stream', json=request().model_dump(mode="json"))
    assert response.status_code == 503


def test_readiness_advertises_the_actual_loaded_stream_profile(tmp_path, monkeypatch):
    package(tmp_path/'new', monkeypatch, stream=True)
    monkeypatch.setenv("MODEL_PACKAGE_DIR", str(tmp_path/'new'))
    monkeypatch.setenv("MODEL_MONITORING_DB", str(tmp_path/'monitor.sqlite'))
    monkeypatch.setenv("VT_MODE", "mock")
    response = TestClient(app).get('/ready')
    assert response.status_code == 200
    assert response.json()['status'] == 'ready'
    assert response.json()['feature_schema_version'] == 'features-v4-stream-v1'
    assert response.json()['strong_actions_enabled'] is False
