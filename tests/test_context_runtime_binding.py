"""Collector and container consume the same read-only baseline file by default."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_api_container_reads_the_collector_baseline_without_bundling_raw_evidence():
    api = yaml.safe_load((ROOT/'compose.yaml').read_text())['services']['api']
    source = yaml.safe_load((ROOT/'config/collection-sources.yaml').read_text())
    target = api['environment']['CONTEXT_BASELINE_PATH']
    bind = next(item for item in api['volumes'] if isinstance(item, dict)
                and item.get('target') == target)
    assert bind['source'] == '${CONTEXT_BASELINE_HOST_FILE:-./evidence/context-baseline.json}'
    assert source['context_baseline_path'] == 'evidence/context-baseline.json'
    assert bind['type'] == 'bind'
    assert bind['read_only'] is True
    assert bind['bind']['create_host_path'] is False


def test_online_window_grace_matches_the_collection_configuration(tmp_path, monkeypatch):
    from api.app.main import load_feature_state_store
    monkeypatch.setattr('ml.feature_pipeline._collection_config',
                        lambda: {'late_arrival_grace_seconds':120})
    store = load_feature_state_store(str(tmp_path/'state.sqlite3'), 86400)
    assert store.late_arrival_grace_seconds == 120


@pytest.mark.parametrize('invalid', [True, '120', -1, 601])
def test_invalid_window_grace_does_not_create_a_serving_store(tmp_path, monkeypatch, invalid):
    from api.app.main import load_feature_state_store
    monkeypatch.setattr('ml.feature_pipeline._collection_config',
                        lambda: {'late_arrival_grace_seconds':invalid})
    with pytest.raises(ValueError, match='grace'):
        load_feature_state_store(str(tmp_path/'state.sqlite3'), 86400)
