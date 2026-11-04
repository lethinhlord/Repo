"""Native archive rule/ID collisions; synthetic evidence only."""

import copy
import hashlib
import json
from datetime import timedelta

import pytest
import test_archive_replay_identity as old
import test_collection_acceptance as acceptance
import test_scenario_collection as fixtures
import yaml

from api.app.contracts import WazuhAlert
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from ml import scenario_collection as collector
from ml.feature_pipeline import aggregate_wazuh_alerts

NATIVE_ID = '1793764571.1226030'


def _ruled(row, firedtimes):
    result = copy.deepcopy(row)
    result['id'] = NATIVE_ID
    result['rule'] = {
        'id': '67023', 'level': 3, 'description': 'synthetic', 'firedtimes': firedtimes,
    }
    return result


def _independent_envelopes(rows, ordinals):
    """An independently normalized oracle; do not call the archive adapter."""
    envelopes = []
    for ordinal in ordinals:
        row = rows[ordinal]
        canonical = json.dumps(row, sort_keys=True, separators=(',', ':'))
        envelope = copy.deepcopy(row)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        envelope['id'] = f'archive-occurrence-v2-{ordinal:012d}-{digest}'
        envelopes.append(WazuhAlert.model_validate(envelope))
    return envelopes


def _independent_incident(rows, ordinals, evidence, family):
    alerts = _independent_envelopes(rows, ordinals)
    baseline = collector.load_baseline(evidence / 'context-baseline.json')
    source = yaml.safe_load((evidence / 'collection-sources.yaml').read_text(encoding='utf-8'))
    taxonomy = yaml.safe_load(
        (evidence / 'suspicious-process-taxonomy.yaml').read_text(encoding='utf-8')
    )
    batch = aggregate_wazuh_alerts(
        alerts, baseline=baseline, source_config=source, taxonomy=taxonomy,
        use_runtime_baseline=False,
    )
    matches = [entry.incident for entry in batch.incidents if entry.incident.family_hint == family]
    assert len(matches) == 1
    return matches[0]


def _spy_parity(monkeypatch):
    observed = []
    aggregate = collector.aggregate_wazuh_alerts

    def spy(alerts, **kwargs):
        observed.append([alert.model_dump(mode='json') for alert in alerts])
        return aggregate(alerts, **kwargs)

    monkeypatch.setattr(collector, 'aggregate_wazuh_alerts', spy)
    return observed


def test_ruled_archive_account_same_id_different_occurrences_and_background(tmp_path, monkeypatch):
    first = _ruled(old._account(5), 8)
    second = _ruled(old._account(5.002), 9)
    duplicate = copy.deepcopy(first)
    background = _ruled(fixtures.suricata_event(
        old.BASE + timedelta(seconds=7), {'event_type': 'stats', 'stats': {'uptime': 1}}
    ), 10)
    outside = _ruled(old._account(-1), 1)
    foreign = _ruled(old._account(8), 1)
    foreign['agent']['name'] = 'OTHER-AGENT'
    rows = [outside, first, foreign, second, duplicate, background]
    old._prepare(tmp_path, rows, successes=3)
    original = copy.deepcopy(rows)
    archive = tmp_path / 'archives.json'
    archive_bytes = archive.read_bytes()
    expected_capture = archive_bytes[
        collector.run_status(old.RUN_ID, tmp_path)['archive_cursor']['size']:
    ]
    observed = _spy_parity(monkeypatch)
    result = collector.finalize_run(old.RUN_ID, tmp_path, now=old.BASE + timedelta(seconds=360))
    assert result['status'] == 'FINALIZED'
    evidence = tmp_path / 'evidence/scenario-runs' / old.RUN_ID
    assert (evidence / 'archive_capture.jsonl').read_bytes() == expected_capture
    assert archive.read_bytes() == archive_bytes
    assert rows == original
    selected = old._rows(evidence / 'windows_events.jsonl')
    assert selected == [first, second, duplicate]
    incident = json.loads((tmp_path / 'data/raw' / old.RUN_ID / 'incidents.jsonl').read_text())
    assert incident['features']['successful_login_count'] == 3
    assert incident['context_status'] == 'AVAILABLE'
    independent = _independent_incident(rows, [1, 3, 4, 5], evidence, 'account')
    assert independent.features == incident['features']
    assert independent.context_status == incident['context_status']
    assert independent.observation_quality == incident['observation_quality']
    expected = [a.model_dump(mode='json') for a in _independent_envelopes(rows, [1, 3, 4, 5])]
    assert observed and observed[-1] == expected
    assert len({alert['id'] for alert in expected}) == 4
    assert [x['rule']['id'] for x in expected] == ['67023'] * 4
    archive.unlink()
    assert collector.validate_run(old.RUN_ID, tmp_path)['status'] == 'VALID'
    assert (evidence / 'archive_capture.jsonl').read_bytes() == expected_capture
    assert all(entry == expected for entry in observed)


def test_unadapted_api_conflicting_genuine_ids_still_rejected():
    first = _ruled(old._account(5), 8)
    second = _ruled(old._account(5.002), 9)
    alerts = [WazuhAlert.model_validate(row) for row in (first, second)]
    with pytest.raises(ValueError, match='duplicate alert id has conflicting payload'):
        aggregate_wazuh_alerts(alerts, use_runtime_baseline=False)


def test_unadapted_state_store_conflicting_genuine_ids_still_rejected(tmp_path):
    first = WazuhAlert.model_validate(_ruled(old._account(5), 8))
    second = WazuhAlert.model_validate(_ruled(old._account(5.002), 9))
    store = FeatureStateStore(tmp_path / 'state.sqlite3')
    assert store.ingest(first).ingest_status == 'new'
    with pytest.raises(FeatureStateConflictError, match='conflicting payload'):
        store.ingest(second)


@pytest.mark.parametrize('scenario_id', ['C2-MALICIOUS-HTTP-BEACON', 'C2-MALICIOUS-DNS-BEACON'])
def test_ruled_archive_cross_agent_c2_same_id_validates_offline(tmp_path, monkeypatch, scenario_id):
    archive, source, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(row for row in catalog.scenarios if row.scenario_id == scenario_id)
    run_id = f'RULED-{scenario_id}'
    action_start = acceptance.COLLECTION_BASE + timedelta(seconds=5)
    collection_start = acceptance.COLLECTION_BASE - timedelta(seconds=10)
    draft_path = tmp_path / 'run-drafts' / f'{run_id}.yaml'
    collector.create_run_draft(
        tmp_path / 'config/scenario-catalog.yaml', scenario_id, run_id, 'synthetic',
        draft_path, collection_seed=20_261_027,
        clock_preflight=acceptance._clock_preflight(collection_start),
    )
    draft = collector.RunDraft.model_validate(yaml.safe_load(draft_path.read_text()))
    collector.start_run(draft_path, source, tmp_path, now=collection_start)
    collector.begin_action(run_id, tmp_path, now=action_start)
    first_event = action_start + timedelta(
        seconds=float(draft.scenario_parameters['pre_action_delay_seconds'])
    )
    generated, last_event = acceptance._c2_events(run_id, scenario, draft, first_event)
    rows = [_ruled(row, index + 1) for index, row in enumerate(generated)]
    fixtures.append_jsonl(archive, rows)
    archive_bytes = archive.read_bytes()
    cursor = collector.run_status(run_id, tmp_path)['archive_cursor']['size']
    expected_capture = archive_bytes[cursor:]
    collector.complete_action(run_id, tmp_path, now=last_event + timedelta(seconds=2))
    observed = _spy_parity(monkeypatch)
    assert collector.finalize_run(
        run_id, tmp_path, now=acceptance.COLLECTION_BASE + timedelta(seconds=355)
    )['status'] == 'FINALIZED'
    evidence = tmp_path / 'evidence/scenario-runs' / run_id
    assert archive.read_bytes() == archive_bytes
    assert (evidence / 'archive_capture.jsonl').read_bytes() == expected_capture
    expected = [a.model_dump(mode='json') for a in _independent_envelopes(rows, range(len(rows)))]
    assert observed and observed[-1] == expected
    assert len({alert['id'] for alert in expected}) == len(rows)
    incident = json.loads((tmp_path / 'data/raw' / run_id / 'incidents.jsonl').read_text())
    feature = (
        'dns_query_count' if scenario.quality_gates.min_dns_events else 'outbound_connection_count'
    )
    assert incident['features'][feature] == 8
    assert incident['features']['suricata_alert_count'] == 8
    independent = _independent_incident(rows, range(len(rows)), evidence, 'c2')
    assert independent.features == incident['features']
    assert independent.context_status == incident['context_status']
    assert independent.observation_quality == incident['observation_quality']
    archive.unlink()
    assert collector.validate_run(run_id, tmp_path)['status'] == 'VALID'
    assert (evidence / 'archive_capture.jsonl').read_bytes() == expected_capture
    assert all(entry == expected for entry in observed)
