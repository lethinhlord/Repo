"""Reproduce native Sysmon Event 3 preceding Event 1."""

from datetime import UTC, datetime, timedelta

import pytest

from ml.feature_pipeline import (
    _process_creation_index,
    _process_observation_matches,
)
from ml.telemetry import event_time, windows_fields


BASE = datetime(2026, 11, 19, 5, 15, 7, tzinfo=UTC)


def make_event(event_id, native_ms, *, pid="204", guid="{CLOCK-LAB}"):
    native = BASE + timedelta(milliseconds=native_ms)
    publication = native + timedelta(
        seconds=3 if event_id == 3 else 0.02
    )
    return {
        "agent": {"name": "WIN11-TARGET"},
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                    "providerName": "Microsoft-Windows-Sysmon",
                    "systemTime": publication.isoformat(),
                },
                "eventdata": {
                    "image": r"C:\Windows\System32\curl.exe",
                    "processGuid": guid,
                    "processId": pid,
                    "user": r"WIN11-TARGET\datn_clock",
                    "utcTime": native.strftime("%Y-%m-%d %H:%M:%S.%f"),
                },
            },
        },
    }


@pytest.mark.parametrize("delta_ms", [-15, -57])
def test_small_native_inversion_requires_review(delta_ms):
    creation = make_event(1, 0)
    network = make_event(3, delta_ms)
    exit_event = make_event(5, 4000)

    network_time = event_time(network)
    _, _, network_fields = windows_fields(network)

    indexed = _process_creation_index(
        [creation, exit_event],
        "WIN11-TARGET",
        as_of=network_time,
    )

    matched = _process_observation_matches(
        "3", network_fields, network_time, creation
    )

    # Baseline: strict lookup without an explicit tolerance still rejects.
    # The bounded policy must be requested explicitly by the caller.
    assert indexed == {}
    assert matched is True


def test_normal_chronology_is_accepted():
    creation = make_event(1, 0)
    network = make_event(3, 15)
    network_time = event_time(network)
    _, _, network_fields = windows_fields(network)

    indexed = _process_creation_index(
        [creation],
        "WIN11-TARGET",
        as_of=network_time,
    )

    assert "{clock-lab}" in indexed

    assert _process_observation_matches(
        "3", network_fields, network_time, creation
    )


def test_large_inversion_remains_rejected():
    creation = make_event(1, 0)
    network = make_event(3, -500)
    network_time = event_time(network)
    _, _, network_fields = windows_fields(network)

    assert not _process_observation_matches(
        "3", network_fields, network_time, creation
    )


@pytest.mark.parametrize("delta_ms", [-15, -57])
def test_small_inversion_should_support_verified_process(delta_ms):
    creation = make_event(1, 0)
    network = make_event(3, delta_ms)
    exit_event = make_event(5, 4000)

    network_time = event_time(network)
    _, _, fields = windows_fields(network)

    # Proposed behavior: retain the matching process identity.
    indexed = _process_creation_index(
        [creation, exit_event],
        "WIN11-TARGET",
        as_of=network_time,
        creation_tolerance=timedelta(milliseconds=100),
    )

    assert "{clock-lab}" in indexed
    assert _process_observation_matches(
        "3", fields, network_time, creation
    )


@pytest.mark.parametrize("delta_ms", [-1, -15, -57, -100])
def test_bounded_inversion_accepts_only_full_identity(delta_ms):
    creation = make_event(1, 0)
    network = make_event(3, delta_ms)
    network_time = event_time(network)
    _, _, fields = windows_fields(network)
    index = _process_creation_index(
        [creation], "WIN11-TARGET", as_of=network_time,
        creation_tolerance=timedelta(milliseconds=100),
    )
    assert "{clock-lab}" in index
    assert _process_observation_matches("3", fields, network_time, index["{clock-lab}"])


@pytest.mark.parametrize("delta_ms", [-301, -500])
def test_inversion_over_boundary_rejected_at_both_gates(delta_ms):
    creation = make_event(1, 0)
    network = make_event(3, delta_ms)
    time = event_time(network)
    _, _, fields = windows_fields(network)
    index = _process_creation_index(
        [creation], "WIN11-TARGET", as_of=time,
        creation_tolerance=timedelta(milliseconds=100),
    )
    assert index == {}
    assert not _process_observation_matches("3", fields, time, creation)


@pytest.mark.parametrize("field,value", [
    ("processGuid", "{OTHER}"),
    ("processId", "9999"),
    ("user", r"WIN11-TARGET\other"),
    ("image", r"C:\Windows\System32\powershell.exe"),
    ("processId", ""),
    ("user", ""),
    ("image", ""),
])
def test_early_event3_requires_complete_matching_identity(field, value):
    creation = make_event(1, 0)
    network = make_event(3, -57)
    network["data"]["win"]["eventdata"][field] = value
    _, _, fields = windows_fields(network)
    assert not _process_observation_matches(
        "3", fields, event_time(network), creation,
    )


def test_clock_exception_not_applied_to_dns_event22():
    creation = make_event(1, 0)
    dns = make_event(22, -57)
    _, _, fields = windows_fields(dns)
    assert not _process_observation_matches("22", fields, event_time(dns), creation)


def test_termination_event_not_lost_when_tolerating_future_creation():
    creation = make_event(1, 0)
    network = make_event(3, -57)
    # Exit recorded before network event: must reject the process.
    exit_event = make_event(5, -100)
    indexed = _process_creation_index(
        [creation, exit_event], "WIN11-TARGET", as_of=event_time(network),
        creation_tolerance=timedelta(milliseconds=100),
    )
    assert indexed == {}


def test_default_lookup_remains_strict():
    creation = make_event(1, 0)
    network = make_event(3, -57)
    assert _process_creation_index(
        [creation], "WIN11-TARGET", as_of=event_time(network),
    ) == {}
