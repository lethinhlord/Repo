"""Synthetic regressions preserving uncertain authentication and native clocks."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest
from test_context_feature_contract import baseline, windows_event

from ml.context import build_baseline
from ml.feature_pipeline import _family, aggregate_wazuh_alerts
from ml.scenario_collection import CollectionError, _validate_attributed_clock
from ml.telemetry import account_source


def test_missing_logon_type_contaminates_account_source_window():
    good = windows_event(
        4625, {"targetUserName": "labuser", "logonType": "3", "ipAddress": "10.40.0.10"}, 1
    )
    bad = windows_event(4625, {"targetUserName": "labuser", "ipAddress": "10.40.0.10"}, 2)
    batch = aggregate_wazuh_alerts([good, bad], baseline=baseline(), use_runtime_baseline=False)
    accounts = [i for i in batch.incidents if i.incident.family_hint == "account"]
    assert len(accounts) == 1
    assert accounts[0].quality_status == "PARTIAL"
    assert "telemetry:missing_or_invalid_logon_type" in accounts[0].incident.review_reasons
    assert accounts[0].incident.features["failed_login_count"] == 1
    assert "wazuh-alert:" + bad.id in accounts[0].incident.raw_refs


@pytest.mark.parametrize("source", [None, "", "-", "  -  "])
def test_remote_missing_source_is_unknown_even_with_local_history(source):
    fields = {"targetUserName": "labuser", "logonType": "3"}
    if source is not None:
        fields["ipAddress"] = source
    event = windows_event(4624, fields, 1)
    result = aggregate_wazuh_alerts(
        [event],
        baseline=baseline(
            accounts=[
                {
                    "asset_id": "WIN11-TARGET",
                    "account": "labuser",
                    "known_sources": ["local-console"],
                }
            ]
        ),
        use_runtime_baseline=False,
    ).incidents[0]
    assert result.quality_status == "PARTIAL"
    assert result.incident.features["source_history_known"] == 0
    assert result.incident.features["new_source_for_user"] == 0
    assert account_source(fields) == "unknown-source"


def test_background_windows_does_not_fall_through_decoder_to_account():
    event = windows_event(5, {}, 1)
    event.decoder.name = "windows_eventchannel"
    assert _family(event) == "unknown"


def sysmon_event(native="2026-10-27 00:00:01.000", message=None):
    event = windows_event(
        3,
        {
            "image": "curl.exe",
            "initiated": "true",
            "sourceIp": "10.20.0.10",
            "destinationIp": "10.40.0.10",
            "destinationPort": "8081",
        },
        1,
    ).model_dump(mode="json")
    event["data"]["win"]["system"]["providerName"] = "Microsoft-Windows-Sysmon"
    if native is not None:
        event["data"]["win"]["eventdata"]["utcTime"] = native
    if message is not None:
        event["data"]["win"]["system"]["message"] = message
    return event


@pytest.mark.parametrize(
    "native,message",
    [
        (None, None),
        ("invalid", None),
        ("2026-10-26 08:00:01.000", None),
        (
            "2026-10-27 00:00:01.000",
            "Network connection detected:\r\nUtcTime: 2026-10-26 08:00:01.000\r\nImage: curl.exe",
        ),
    ],
)
def test_bad_sysmon_clock_rejected_by_raw_and_baseline(native, message):
    event = sysmon_event(native, message)
    with pytest.raises(CollectionError, match="clock"):
        _validate_attributed_clock(event)
    with pytest.raises(ValueError, match="clock"):
        build_baseline(
            [event],
            revision="test",
            captured_at=datetime(2026, 10, 27, 1, tzinfo=UTC),
            valid_until=datetime(2026, 10, 28, tzinfo=UTC),
            source_capture_sha256="a" * 64,
        )


def test_native_clock_helper_preserves_input_and_five_second_boundary():
    from ml.telemetry import sysmon_clock_issues

    event = sysmon_event("2026-10-27 00:00:06.000")
    original = deepcopy(event)
    assert sysmon_clock_issues(event) == []
    assert event == original
    event["data"]["win"]["eventdata"]["utcTime"] = "2026-10-27 00:00:06.000001"
    assert sysmon_clock_issues(event)


def test_sysmon_100ns_past_clock_boundary_is_not_truncated():
    from ml.telemetry import sysmon_clock_issues

    assert sysmon_clock_issues(sysmon_event("2026-10-27 00:00:06.0000001"))


@pytest.mark.parametrize("native", ["2026-10-27", "2026-10-27T00:00:01+07:00", 123, ""])
def test_malformed_native_clock_cannot_be_a_valid_sysmon_time(native):
    from ml.telemetry import sysmon_clock_issues

    assert sysmon_clock_issues(sysmon_event(native))


def test_explicit_other_provider_event_id_does_not_trigger_sysmon_clock_contract():
    from ml.telemetry import sysmon_clock_issues

    event = sysmon_event(None)
    event["data"]["win"]["system"]["providerName"] = "Microsoft-Windows-Security-Auditing"
    assert sysmon_clock_issues(event) == []


def test_online_bad_sysmon_clock_remains_partial_with_raw_reference():
    from api.app.contracts import WazuhAlert

    event = sysmon_event("2026-10-26 08:00:01.000")
    result = aggregate_wazuh_alerts(
        [WazuhAlert.model_validate(event)], baseline=baseline(), use_runtime_baseline=False
    ).incidents[0]
    assert result.quality_status == "PARTIAL"
    assert "clock:sysmon_timestamp_mismatch" in result.incident.review_reasons
    assert "wazuh-alert:" + event["id"] in result.incident.raw_refs


@pytest.mark.parametrize("type_value", [None, "invalid", True, 1.5])
def test_uncertain_logon_type_remains_account_evidence(type_value):
    event = windows_event(4625, {"targetUserName": "labuser", "logonType": type_value}, 1)
    assert _family(event) == "account"


@pytest.mark.parametrize("type_value", ["4", "5", "7", "8", "9", "11", "12", "13"])
def test_proven_excluded_logon_type_remains_background(type_value):
    event = windows_event(4625, {"targetUserName": "labuser", "logonType": type_value}, 1)
    event.decoder.name = "windows_eventchannel"
    assert _family(event) == "unknown"


def test_unknown_source_does_not_make_neighboring_source_window_complete():
    good = windows_event(
        4625, {"targetUserName": "labuser", "logonType": "3", "ipAddress": "10.40.0.10"}, 1
    )
    bad = windows_event(4624, {"targetUserName": "labuser", "logonType": "3"}, 2)
    results = aggregate_wazuh_alerts(
        [good, bad], baseline=baseline(), use_runtime_baseline=False
    ).incidents
    assert all(item.quality_status == "PARTIAL" for item in results)
    known = next(item for item in results if "wazuh-alert:" + good.id in item.incident.raw_refs)
    assert known.incident.features["successful_login_count"] == 0


@pytest.mark.parametrize("family", ["account", "c2"])
def test_collection_rejects_used_c2_clock_but_keeps_unrelated_account_background(
    tmp_path,
    monkeypatch,
    family,
):
    import json

    import test_collection_acceptance as acceptance

    from ml import scenario_collection as collector

    archive, source, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(row for row in catalog.scenarios if row.family == family)

    def finalize_with_bad_clock(run_id, root, *, now):
        original_lines = archive.read_text().splitlines(keepends=True)
        rows = [json.loads(line) for line in original_lines]
        if family == "account":
            native = sysmon_event("2000-01-01 00:00:00.000")
            native["data"]["win"]["system"]["systemTime"] = rows[-1]["data"]["win"]["system"][
                "systemTime"
            ]
            with archive.open("a") as handle:
                handle.write(json.dumps(native) + "\n")
        else:
            for row in rows:
                win = row.get("data", {}).get("win", {})
                if str(win.get("system", {}).get("eventID")) in {"3", "22"}:
                    win["system"]["providerName"] = "Microsoft-Windows-Sysmon"
                    win["eventdata"]["utcTime"] = "2000-01-01 00:00:00.000"
            archive.write_text(
                original_lines[0] + "".join(json.dumps(row) + "\n" for row in rows[1:])
            )
        return collector.finalize_run(run_id, root, now=now)

    monkeypatch.setattr(acceptance, "finalize_run", finalize_with_bad_clock)
    if family == "account":
        run_id = acceptance._collect_run(tmp_path, archive, source, scenario, sequence=0, repeat=0)
        assert collector.validate_run(run_id, tmp_path)["status"] == "VALID"
        capture = tmp_path / "evidence/scenario-runs" / run_id / "archive_capture.jsonl"
        assert "2000-01-01 00:00:00.000" in capture.read_text()
    else:
        with pytest.raises(CollectionError, match="clock"):
            acceptance._collect_run(tmp_path, archive, source, scenario, sequence=0, repeat=0)
        assert not list((tmp_path / "data/raw").glob("*/incidents.jsonl"))
