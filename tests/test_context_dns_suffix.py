"""A capture nonce must not manufacture destination novelty for every DNS run."""
from datetime import UTC, datetime, timedelta

import pytest

import ml.context as context
from ml.behavior_features import NetworkObservation
from ml.context import assess_context, build_baseline

NOW = datetime(2026,10,28,tzinfo=UTC)


def observed_baseline():
    return build_baseline([{'agent':{'name':'WIN11-TARGET'},'timestamp':NOW.isoformat(),
        'data':{'win':{'system':{'eventID':'22','systemTime':NOW.isoformat()},
            'eventdata':{'image':'powershell.exe','queryName':'enrollment.www.datn.test'}}}}],
        revision='unit-before-runs',captured_at=NOW,valid_until=NOW+timedelta(days=1),
        source_capture_sha256='a'*64)


def test_approved_observed_suffix_is_stable_when_only_the_run_nonce_changes():
    snapshot = context.with_dns_suffix_history(observed_baseline(), ['datn.test'])
    assert snapshot.destinations[0].match == 'dns_suffix'
    assert snapshot.destinations[0].destination == 'datn.test'
    at = NOW+timedelta(minutes=1)
    for name, novelty in [('new-nonce.www.datn.test',0),('unrelated.example.test',1),
                          ('notdatn.test',1)]:
        result = assess_context(snapshot, at=at, asset_id='WIN11-TARGET',
            network=[NetworkObservation(at,name,53,name)])
        assert result.status == 'AVAILABLE'
        assert result.features['destination_history_known'] == 1
        assert result.features['new_destination'] == novelty
    assert snapshot.source_capture_sha256 == 'a'*64


@pytest.mark.parametrize('suffixes', [
    ['test'],['*.datn.test'],['http://datn.test'],['10.40.0.10'],['unknown.test'],
    ['datn.test','www.datn.test'],['datn.test','datn.test'],
])
def test_suffixes_require_specific_nonoverlapping_observed_inventory(suffixes):
    with pytest.raises(ValueError):
        context.with_dns_suffix_history(observed_baseline(), suffixes)


def test_enrollment_cli_exposes_suffix_inventory_without_editing_snapshot(tmp_path, monkeypatch):
    import json
    import sys

    from scripts import enroll_context_baseline
    capture = tmp_path/'approved.jsonl'
    capture.write_text(json.dumps({'agent':{'name':'WIN11-TARGET'},'timestamp':NOW.isoformat(),
        'data':{'win':{'system':{'eventID':'22','systemTime':NOW.isoformat()},
            'eventdata':{'image':'powershell.exe','queryName':'enroll.datn.test'}}}})+'\n')
    output = tmp_path/'context-baseline.json'
    monkeypatch.setattr(sys,'argv',['enroll','--capture',str(capture),'--revision','unit-cli',
        '--output',str(output),'--approved-enrollment','--dns-suffix','datn.test'])
    assert enroll_context_baseline.main() == 0
    baseline = context.load_baseline(output)
    assert baseline.destinations[0].destination == 'datn.test'
    assert baseline.destinations[0].match == 'dns_suffix'
