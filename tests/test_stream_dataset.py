from copy import deepcopy

import pytest
from test_stream_pipeline import CONFIG, baseline, events

from ml.feature_pipeline import aggregate_wazuh_alerts
from ml.stream_pipeline import aggregate_stream_alerts
from ml.stream_sources import restore_parent_record


def test_projection_keeps_original_identity_and_every_parent_value():
    from ml.stream_dataset import project_record

    kwargs = dict(source_config=CONFIG,taxonomy={},baseline=baseline(),use_runtime_baseline=False)
    old = aggregate_wazuh_alerts(events(),**kwargs).incidents[0].incident
    stream = aggregate_stream_alerts(events(),**kwargs).incidents[0].incident
    parent = dict(incident_id='sealed-original-id',run_id='unit',scenario_id='unit',
                  family='c2',label=1,cohort_id='paired',purpose='trainable',
                  features=old.features,source_file='data/raw/unit/incidents.jsonl',
                  incident={**old.model_dump(mode='json'),'incident_id':'sealed-original-id'})
    before = deepcopy(parent)
    result = project_record(parent,stream)
    assert restore_parent_record(result) == before == parent
    assert len(result['features']) == 44
    assert result['incident']['incident_id'] == 'sealed-original-id'
    assert result['incident']['indicator_attribution']['response_authorized'] is False
    stream.features['failed_login_count'] += 1
    with pytest.raises(ValueError,match='retained'):
        project_record(parent,stream)
