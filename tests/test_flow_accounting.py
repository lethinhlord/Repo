"""Flow counter quality is independent of transaction arrival order."""
from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

from ml.telemetry import event_time, flow_counter_issues, linked_flow, suricata_observations

START = datetime(2026, 10, 27, tzinfo=UTC)
END = START + timedelta(minutes=5)


def flow(*, event_type='flow', start=5, end=10, sent=100, received=200, emitted=70):
    return {
        'timestamp': (START + timedelta(seconds=emitted)).isoformat(),
        'event_type': event_type, 'flow_id': 9, 'proto': 'TCP',
        'src_ip': '10.20.0.10', 'src_port': 50001,
        'dest_ip': '10.40.0.10', 'dest_port': 8081,
        'flow': {'start': (START + timedelta(seconds=start)).isoformat(),
                 'end': (START + timedelta(seconds=end)).isoformat(),
                 'bytes_toserver': sent, 'bytes_toclient': received},
    }


@pytest.mark.parametrize('reverse', [False, True])
def test_cumulative_transactions_and_replays_count_final_flow_once(reverse) -> None:
    rows = [flow(event_type='http', sent=60, received=30), flow(), copy.deepcopy(flow())]
    if reverse:
        rows.reverse()
    assert sum(x.total_bytes for x in suricata_observations(rows)) == 300
    assert flow_counter_issues(rows, window_start=START, window_end=END) == []


@pytest.mark.parametrize('updates,reason', [
    ({'event_type':'http'}, 'flow:missing_final_counters'),
    ({'start':-1}, 'flow:cross_window_or_invalid_interval'),
    ({'end':301}, 'flow:cross_window_or_invalid_interval'),
    ({'sent':-1}, 'flow:invalid_counter'),
    ({'sent':True}, 'flow:invalid_counter'),
])
def test_unreliable_flow_never_has_complete_quality(updates, reason) -> None:
    assert reason in flow_counter_issues([flow(**updates)], window_start=START, window_end=END)


def test_reused_id_and_reset_counters_are_reported() -> None:
    rows = [flow(start=5), flow(start=20), flow(event_type='http', sent=500)]
    reasons = flow_counter_issues(rows, window_start=START, window_end=END)
    assert 'flow:ambiguous_reused_id' in reasons
    assert 'flow:counter_reset_or_conflict' in reasons


def test_late_final_flow_anchors_original_bucket_and_requires_matching_tuple() -> None:
    final = flow(emitted=340)
    reference = flow(event_type='http')
    at = START + timedelta(seconds=8)
    assert event_time({'full_log': __import__('json').dumps(final)}) == START + timedelta(seconds=5)
    assert linked_flow(final, [(reference, at)], 2)
    reference['src_port'] = 50002
    assert not linked_flow(final, [(reference, at)], 2)


@pytest.mark.parametrize('invalid', [None, [], 'broken', 12])
def test_malformed_final_flow_is_a_quality_failure_instead_of_a_server_crash(invalid) -> None:
    payload = flow()
    payload['flow'] = invalid
    reasons = flow_counter_issues([payload], window_start=START, window_end=END)
    assert 'flow:cross_window_or_invalid_interval' in reasons
    assert 'flow:invalid_counter' in reasons
