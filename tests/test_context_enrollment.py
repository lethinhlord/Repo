"""Enroll history from approved raw telemetry without importing scenario truth."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta

import pytest

CAPTURED = datetime(2026, 10, 28, 0, 0, tzinfo=UTC)
DIGEST = "b" * 64


def _event(event_id: int, seconds: int, data: dict, *, agent: str = "WIN11-TARGET") -> dict:
    at = CAPTURED + timedelta(seconds=seconds)
    return {
        "timestamp": at.isoformat(),
        "agent": {"id": "001", "name": agent},
        "data": {"win": {
            "system": {"eventID": str(event_id), "systemTime": at.isoformat()},
            "eventdata": data,
        }},
    }


def _logon(*, user: str = "LabUser", source: str = "10.40.0.10", event_id: int = 4624,
           logon_type: str = "3", seconds: int = -10, agent: str = "WIN11-TARGET") -> dict:
    return _event(event_id, seconds, {
        "targetUserName": user, "ipAddress": source, "logonType": logon_type,
    }, agent=agent)


def _network(*, destination: str = "10.40.0.10", port="8081", image: str = "curl.exe",
             seconds: int = -8, initiated: str = "true") -> dict:
    return _event(3, seconds, {
        "image": image, "processGuid": "{APPROVED-ENROLLMENT-PROCESS}",
        "sourceIp": "10.20.0.10", "destinationIp": destination,
        "destinationPort": port, "initiated": initiated,
    })


def _build(events: list[dict]):
    return importlib.import_module("ml.context").build_baseline(
        events, revision="approved-enrollment-v1", captured_at=CAPTURED,
        valid_until=CAPTURED + timedelta(days=1), source_capture_sha256=DIGEST,
        windows_agent_name="WIN11-TARGET",
    )


def test_enrollment_derives_account_network_and_dns_history_from_raw_fields() -> None:
    events = [
        _logon(),
        _network(),
        _event(22, -6, {
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "queryName": "APPROVED.DATN.TEST",
        }),
    ]

    snapshot = _build(events)

    assert snapshot.version == "context-baseline-v1"
    assert snapshot.revision == "approved-enrollment-v1"
    assert snapshot.source_capture_sha256 == DIGEST
    assert snapshot.observed_through == CAPTURED - timedelta(seconds=6)
    assert len(snapshot.accounts) == 1
    account = snapshot.accounts[0]
    assert (account.asset_id, account.account, account.known_sources) == (
        "win11-target", "labuser", ["10.40.0.10"],
    )
    destinations = {(row.destination, row.port): row for row in snapshot.destinations}
    assert set(destinations) == {("10.40.0.10", 8081), ("approved.datn.test", 53)}
    assert destinations[("10.40.0.10", 8081)].process_images == ["curl.exe"]
    assert destinations[("approved.datn.test", 53)].process_images == ["powershell.exe"]


def test_enrollment_normalizes_and_deduplicates_identity_ip_and_process_images() -> None:
    events = [
        _logon(user="LabUser", source="::ffff:10.40.0.10"),
        _logon(user="LABUSER", source="10.40.0.10"),
        _network(destination="::ffff:10.40.0.10", image=r"C:\Windows\System32\CURL.EXE"),
        _network(image="curl.exe"),
        _network(image=r"C:\Program Files\PowerShell\pwsh.exe"),
    ]

    snapshot = _build(events)

    assert len(snapshot.accounts) == 1
    assert snapshot.accounts[0].account == "labuser"
    assert snapshot.accounts[0].known_sources == ["10.40.0.10"]
    assert len(snapshot.destinations) == 1
    assert snapshot.destinations[0].destination == "10.40.0.10"
    assert sorted(snapshot.destinations[0].process_images) == ["curl.exe", "pwsh.exe"]


def test_failed_service_and_other_agents_events_cannot_enroll_a_known_account() -> None:
    events = [
        _logon(),
        _logon(user="failed-user", event_id=4625, seconds=-2),
        _logon(user="service-user", logon_type="5", seconds=-1),
        _logon(user="other-agent-user", agent="UNTRUSTED-TARGET", seconds=-1),
        _network(initiated="false", seconds=-1),
    ]

    snapshot = _build(events)

    assert [row.account for row in snapshot.accounts] == ["labuser"]
    assert snapshot.destinations == []
    assert snapshot.observed_through == CAPTURED - timedelta(seconds=10)


@pytest.mark.parametrize("logon_type", ["2", "3", "10"])
def test_supported_successful_logon_types_can_enroll_history(logon_type: str) -> None:
    source = "" if logon_type == "2" else "10.40.0.10"
    snapshot = _build([_logon(logon_type=logon_type, source=source)])

    assert snapshot.accounts[0].known_sources == [source or "local-console"]


def test_enrollment_rejects_original_event_time_after_capture() -> None:
    future = _logon(seconds=1)
    future["timestamp"] = (CAPTURED - timedelta(seconds=5)).isoformat()

    with pytest.raises(ValueError):
        _build([future])


def test_enrollment_rejects_a_capture_without_usable_successful_telemetry() -> None:
    with pytest.raises(ValueError):
        _build([_logon(event_id=4625), _network(initiated="false")])


@pytest.mark.parametrize("port", [0, 65536, "invalid-port"])
def test_enrollment_does_not_create_history_from_invalid_network_ports(port) -> None:
    with pytest.raises(ValueError):
        _build([_network(port=port)])


def test_raw_scenario_labels_and_approval_metadata_are_never_snapshot_fields() -> None:
    raw = _logon()
    raw.update(label="malicious", ground_truth={"label": "malicious"}, approved=True)
    raw["data"]["win"]["eventdata"].update(
        scenario_id="BENIGN-LABEL-ORACLE", authorized=True,
    )

    snapshot = _build([raw])
    payload = snapshot.model_dump(mode="json")

    assert set(payload) == {
        "version", "revision", "captured_at", "observed_through", "valid_until",
        "source_capture_sha256", "accounts", "destinations",
    }
    serialized = snapshot.model_dump_json()
    assert "malicious" not in serialized
    assert "BENIGN-LABEL-ORACLE" not in serialized
    assert "authorized" not in serialized


def test_enrollment_cli_preserves_the_bytes_it_actually_hashed(tmp_path, monkeypatch) -> None:
    import hashlib
    import json
    import sys

    from scripts import enroll_context_baseline as command
    event = _logon()
    raw = (json.dumps(event) + '\n').encode()
    capture = tmp_path/'enrollment.jsonl'
    capture.write_bytes(raw)
    output = tmp_path/'context-baseline.json'
    original = command.build_baseline

    def concurrent_source_change(*args, **kwargs):
        snapshot = original(*args, **kwargs)
        capture.write_text('source changed while enrollment was running', encoding='utf-8')
        return snapshot

    monkeypatch.setattr(command, 'build_baseline', concurrent_source_change)
    monkeypatch.setattr(sys, 'argv', ['enroll', '--capture', str(capture),
        '--output', str(output), '--revision', 'unit-enrollment', '--approved-enrollment'])
    assert command.main() == 0
    saved = tmp_path/'context-captures'/f'{hashlib.sha256(raw).hexdigest()}.jsonl'
    assert saved.read_bytes() == raw
