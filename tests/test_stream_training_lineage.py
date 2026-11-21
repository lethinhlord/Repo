from copy import deepcopy

import pytest

from ml.stream_sources import restore_parent_record


def records():
    incident = {'incident_id':'original', 'features':{'failed_login_count':2.0},
                'feature_schema_version':'features-v3', 'indicator':'old.example',
                'start_time':'2026-01-01T00:00:00Z', 'raw_refs':['sealed-capture']}
    parent = {'run_id':'one', 'incident_id':'original', 'family':'account', 'label':0,
              'cohort_id':'same-cohort', 'scenario_id':'same-scenario', 'purpose':'trainable',
              'source_file':'data/raw/one/incidents.jsonl', 'features':incident['features'],
              'incident':incident}
    features = {**incident['features'], 'tcp_connection_count':0.0}
    derived = {**deepcopy(parent), 'source_incident':deepcopy(incident), 'features':features,
               'incident':{**deepcopy(incident), 'feature_schema_version':'features-v4-stream-v1',
                           'features':features, 'indicator':None, 'indicator_attribution':None}}
    return parent, derived


def test_derived_record_reconstructs_the_exact_original_record():
    parent, derived = records()
    before = deepcopy(derived)
    assert restore_parent_record(derived) == parent
    assert derived == before


@pytest.mark.parametrize('change', ['retained-feature','incident-features','time','refs','version'])
def test_derivation_cannot_rewrite_the_observation_contract(change):
    _, derived = records()
    if change == 'retained-feature':
        derived['features']['failed_login_count'] = 999
    elif change == 'incident-features':
        derived['incident']['features'] = {'different':1}
    elif change == 'time':
        derived['incident']['start_time'] = '2026-01-02T00:00:00Z'
    elif change == 'refs':
        derived['incident']['raw_refs'] = ['replacement-capture']
    else:
        derived['incident']['feature_schema_version'] = 'features-v3'
    with pytest.raises(ValueError):
        restore_parent_record(derived)
