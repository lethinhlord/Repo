"""Regression: Sysmon Event 3 may be emitted after process exit."""

from datetime import UTC, datetime

from ml.telemetry import event_time, sysmon_clock_issues


def make_event(event_id, system_time, native_time):
    return {
        "agent": {"name": "WIN11-TARGET"},
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                    "providerName": "Microsoft-Windows-Sysmon",
                    "systemTime": system_time,
                },
                "eventdata": {
                    "processGuid": "{PILOT4-TEST}",
                    "image": "C:\\Windows\\System32\\curl.exe",
                    "utcTime": native_time,
                },
            }
        },
    }


def test_delayed_network_event_uses_native_connection_time():
    created = make_event(
        1,
        "2026-11-11T04:25:11.938596Z",
        "2026-11-11 04:25:11.922",
    )
    network = make_event(
        3,
        "2026-11-11T04:25:14.053834Z",
        "2026-11-11 04:25:11.951",
    )
    exited = make_event(
        5,
        "2026-11-11T04:25:11.955078Z",
        "2026-11-11 04:25:11.954",
    )

    assert all(
        sysmon_clock_issues(e) == []
        for e in (created, network, exited)
    )

    assert (
        event_time(created)
        <= event_time(network)
        <= event_time(exited)
    )


def test_genuinely_late_connection_remains_after_exit():
    network = make_event(
        3,
        "2026-11-11T04:25:15.000000Z",
        "2026-11-11 04:25:15.000",
    )
    exited = make_event(
        5,
        "2026-11-11T04:25:11.955078Z",
        "2026-11-11 04:25:11.954",
    )

    assert event_time(network) > event_time(exited)


def test_invalid_native_clock_is_not_trusted():
    network = make_event(
        3,
        "2026-11-11T04:25:20.000000Z",
        "2026-11-11 04:25:11.951",
    )

    assert sysmon_clock_issues(network)
    assert event_time(network) == datetime(
        2026, 11, 11, 4, 25, 20, tzinfo=UTC
    )
