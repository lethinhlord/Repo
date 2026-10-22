from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from ml.scenario_collection import (
    Attribution,
    CollectionError,
    _matches_suricata,
    abort_run,
    finalize_run,
    quarantine_run,
    start_run,
    validate_run,
)


def append_jsonl(path: Path, payloads: list[dict]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for payload in payloads:
            handle.write(json.dumps(payload) + "\n")


def source_config(tmp_path: Path) -> Path:
    archive = tmp_path / "archives.json"
    archive.write_text('{"baseline":true}\n', encoding="utf-8")
    taxonomy = tmp_path / "taxonomy.yaml"
    taxonomy.write_text(
        yaml.safe_dump(
            {
                "revision": "test-taxonomy-v1",
                "rules": [
                    {
                        "name": "scripted-beacon",
                        "image_suffix": "powershell.exe",
                        "command_contains_any": ["/beacon"],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config = tmp_path / "sources.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "version": "collection-sources-v1",
                "wazuh_archives_path": str(archive),
                "windows_agent_name": "WIN11-TARGET",
                "suricata_agent_name": "NET-SENSOR",
                "taxonomy_path": str(taxonomy),
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return config


def write_draft(
    tmp_path: Path,
    *,
    run_id: str,
    family: str,
    label: str,
    attribution: dict,
    quality_gates: dict | None = None,
) -> Path:
    draft = tmp_path / f"{run_id}.yaml"
    draft.write_text(
        yaml.safe_dump(
            {
                "scenario_id": f"SCENARIO-{family}-{label}",
                "run_id": run_id,
                "family": family,
                "label": label,
                "host": "WIN11-TARGET",
                "expected_behavior": "Controlled lab behavior.",
                "operator": "Kien",
                "attribution": attribution,
                "quality_gates": quality_gates
                or {
                    "min_account_failures": 0,
                    "min_account_successes": 0,
                    "min_process_events": 0,
                    "min_network_events": 0,
                    "min_dns_events": 0,
                    "min_suricata_events": 0,
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return draft


def windows_event(
    event_id: int,
    when: datetime,
    eventdata: dict,
) -> dict:
    eventdata = dict(eventdata)
    if event_id in {4624, 4625}:
        eventdata.setdefault("logonType", "2")
    return {
        "timestamp": when.isoformat(),
        "agent": {"name": "WIN11-TARGET"},
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                    "systemTime": when.isoformat().replace("+00:00", "Z"),
                    "eventRecordID": str(int(when.timestamp() * 1000)),
                },
                "eventdata": eventdata,
            }
        },
    }


def suricata_event(when: datetime, payload: dict) -> dict:
    eve = {"timestamp": when.isoformat(), **payload}
    return {
        "timestamp": when.isoformat(),
        "agent": {"name": "NET-SENSOR"},
        "full_log": json.dumps(eve),
    }


def test_account_run_creates_strict_manifest_incident_and_checksums(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-MALICIOUS-001",
        family="account",
        label="malicious",
        attribution={"account_names": ["testuser"]},
    )
    started = datetime(2026, 10, 16, 1, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    archive = tmp_path / "archives.json"
    append_jsonl(
        archive,
        [
            windows_event(4625, started + timedelta(seconds=5), {"targetUserName": "testuser"}),
            windows_event(4625, started + timedelta(seconds=10), {"targetUserName": "testuser"}),
            windows_event(4624, started + timedelta(seconds=15), {"targetUserName": "testuser"}),
            windows_event(4625, started + timedelta(seconds=20), {"targetUserName": "other"}),
        ],
    )

    result = finalize_run(
        "ACCOUNT-MALICIOUS-001",
        tmp_path,
        now=started + timedelta(seconds=30),
    )

    run_dir = tmp_path / "data/raw/ACCOUNT-MALICIOUS-001"
    incident = json.loads((run_dir / "incidents.jsonl").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "scenario_manifest.json").read_text(encoding="utf-8"))
    assert result["status"] == "FINALIZED"
    assert set(manifest) == {
        "scenario_id",
        "run_id",
        "family",
        "label",
        "host",
        "start_time",
        "end_time",
        "expected_behavior",
    }
    assert incident["asset_id"] == "WIN11-TARGET"
    assert incident["features"]["failed_login_count"] == 2.0
    assert incident["features"]["success_after_fail"] == 1.0
    assert incident["features"]["suricata_alert_count"] == 0.0
    assert incident["evidence_sources"] == ["wazuh-archives"]
    validation = validate_run("ACCOUNT-MALICIOUS-001", tmp_path)
    assert validation["status"] == "VALID"


def test_account_run_ignores_noninteractive_logons_for_declared_user(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-INTERACTIVE-001",
        family="account",
        label="benign",
        attribution={"account_names": ["testuser"]},
        quality_gates={
            "min_account_failures": 0,
            "max_account_failures": 0,
            "min_account_successes": 1,
            "max_account_successes": 1,
            "require_success_after_failure": False,
        },
    )
    started = datetime(2026, 10, 16, 1, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    missing_logon_type = windows_event(
        4624,
        started + timedelta(seconds=3),
        {"targetUserName": "testuser"},
    )
    del missing_logon_type["data"]["win"]["eventdata"]["logonType"]
    append_jsonl(
        tmp_path / "archives.json",
        [
            missing_logon_type,
            windows_event(
                4624,
                started + timedelta(seconds=5),
                {"targetUserName": "testuser", "logonType": "3"},
            ),
            windows_event(
                4624,
                started + timedelta(seconds=10),
                {"targetUserName": "testuser", "logonType": "2"},
            ),
        ],
    )

    result = finalize_run(
        "ACCOUNT-BENIGN-INTERACTIVE-001",
        tmp_path,
        now=started + timedelta(seconds=30),
    )

    assert result["status"] == "FINALIZED"
    evidence = [
        json.loads(line)
        for line in (
            tmp_path
            / "evidence/scenario-runs/ACCOUNT-BENIGN-INTERACTIVE-001/windows_events.jsonl"
        ).read_text(encoding="utf-8").splitlines()
    ]
    assert len(evidence) == 1
    assert evidence[0]["data"]["win"]["eventdata"]["logonType"] == "2"


def test_c2_run_requires_correlated_sysmon_and_suricata_and_calculates_features(
    tmp_path: Path,
) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="C2-MALICIOUS-001",
        family="c2",
        label="malicious",
        attribution={
            "process_names": ["powershell.exe"],
            "destination_ips": ["10.40.0.10"],
            "destination_ports": [8081],
            "dns_suffixes": [],
        },
    )
    started = datetime(2026, 10, 16, 2, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    archive = tmp_path / "archives.json"
    events = [
        windows_event(
            1,
            started + timedelta(seconds=1),
            {
                "image": (
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                ),
                "commandLine": "GET /beacon",
            },
        )
    ]
    for offset in (5, 15, 25):
        events.append(
            windows_event(
                3,
                started + timedelta(seconds=offset),
                {
                    "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "initiated": "true",
                    "destinationIp": "10.40.0.10",
                    "destinationPort": "8081",
                },
            )
        )
    events.extend(
        [
            suricata_event(
                started + timedelta(seconds=6),
                {
                    "event_type": "flow",
                    "src_ip": "10.20.0.10",
                    "dest_ip": "10.40.0.10",
                    "dest_port": 8081,
                    "flow_id": 1001,
                },
            ),
            suricata_event(
                started + timedelta(seconds=16),
                {
                    "event_type": "alert",
                    "src_ip": "10.20.0.10",
                    "dest_ip": "10.40.0.10",
                    "dest_port": 8081,
                    "flow_id": 1002,
                    "alert": {"signature_id": 900001, "severity": 2},
                },
            ),
        ]
    )
    append_jsonl(archive, events)

    finalize_run("C2-MALICIOUS-001", tmp_path, now=started + timedelta(seconds=40))

    incident_path = tmp_path / "data/raw/C2-MALICIOUS-001/incidents.jsonl"
    incident = json.loads(incident_path.read_text(encoding="utf-8"))
    assert incident["features"] == {
        "failed_login_count": 0.0,
        "successful_login_count": 0.0,
        "success_after_fail": 0.0,
        "unique_target_account_count": 0.0,
        "unique_source_count": 0.0,
        "remote_logon_ratio": 0.0,
        "failure_window_seconds": 0.0,
        "attempt_rate_per_minute": 0.0,
        "suspicious_process": 1.0,
        "periodicity_score": 1.0,
        "connection_interval_cv": 0.0,
        "mean_interval_seconds": 10.0,
        "suricata_alert_count": 1.0,
        "suricata_severity_score": 0.666667,
        "outbound_connection_count": 3.0,
        "unique_destination_count": 1.0,
        "destination_port_count": 1.0,
        "dns_query_count": 0.0,
        "dns_unique_query_ratio": 0.0,
        "flow_total_bytes_log1p": 0.0,
    }
    assert incident["evidence_sources"] == ["wazuh-archives", "suricata-eve"]


def test_c2_finalize_fails_closed_without_suricata_evidence(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="C2-BENIGN-001",
        family="c2",
        label="benign",
        attribution={
            "process_names": ["curl.exe"],
            "destination_ips": ["10.20.0.20"],
            "destination_ports": [8000],
        },
    )
    started = datetime(2026, 10, 16, 3, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [
            windows_event(
                3,
                started + timedelta(seconds=5),
                {
                    "image": r"C:\Windows\System32\curl.exe",
                    "initiated": "true",
                    "destinationIp": "10.20.0.20",
                    "destinationPort": "8000",
                },
            )
        ],
    )

    with pytest.raises(CollectionError, match="Suricata"):
        finalize_run("C2-BENIGN-001", tmp_path, now=started + timedelta(seconds=20))

    assert not (tmp_path / "data/raw/C2-BENIGN-001").exists()


def test_finalize_rejects_source_truncation_after_start(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    start_run(
        draft,
        config,
        tmp_path,
        now=datetime(2026, 10, 16, 4, 0, tzinfo=UTC),
    )
    (tmp_path / "archives.json").write_text("", encoding="utf-8")

    with pytest.raises(CollectionError, match="rotated or truncated"):
        finalize_run(
            "ACCOUNT-BENIGN-001",
            tmp_path,
            now=datetime(2026, 10, 16, 4, 1, tzinfo=UTC),
        )


def test_validate_detects_evidence_tampering(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-002",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    started = datetime(2026, 10, 16, 5, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [windows_event(4624, started + timedelta(seconds=5), {"targetUserName": "labuser"})],
    )
    finalize_run("ACCOUNT-BENIGN-002", tmp_path, now=started + timedelta(seconds=10))
    evidence = tmp_path / "evidence/scenario-runs/ACCOUNT-BENIGN-002/wazuh_archives.jsonl"
    evidence.write_text(evidence.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")

    with pytest.raises(CollectionError, match="checksum"):
        validate_run("ACCOUNT-BENIGN-002", tmp_path)


def test_dns_only_attribution_rejects_unrelated_non_dns_suricata_events() -> None:
    attribution = Attribution(dns_suffixes=["beacon.datn.test"])

    assert not _matches_suricata(
        {
            "event_type": "flow",
            "src_ip": "10.20.0.10",
            "dest_ip": "1.1.1.1",
            "dest_port": 443,
        },
        attribution,
    )
    assert _matches_suricata(
        {
            "event_type": "dns",
            "dns": {"rrname": "a.beacon.datn.test"},
        },
        attribution,
    )

def test_suricata8_dns_queries_attribution() -> None:
    attribution = Attribution(dns_suffixes=["beacon.datn.test"])

    assert _matches_suricata(
        {
            "event_type": "dns",
            "dns": {
                "queries": [
                    {"rrname": "a.beacon.datn.test"}
                ]
            },
        },
        attribution,
    )

    assert not _matches_suricata(
        {
            "event_type": "dns",
            "dns": {
                "queries": [
                    {"rrname": "unrelated.example.com"}
                ]
            },
        },
        attribution,
    )


def test_suricata8_dns_alert_attribution() -> None:
    attribution = Attribution(
        source_ips=["10.20.0.10"],
        dns_suffixes=["beacon.datn.test"],
    )

    assert _matches_suricata(
        {
            "event_type": "alert",
            "src_ip": "10.20.0.10",
            "dest_ip": "10.40.0.10",
            "dns": {
                "version": 3,
                "type": "request",
                "queries": [{"rrname": "r01.beacon.datn.test"}],
            },
            "alert": {"signature_id": 900002},
        },
        attribution,
    )


def test_suricata8_dns_response_matches_target_as_destination() -> None:
    attribution = Attribution(
        source_ips=["10.20.0.10"],
        dns_suffixes=["beacon.datn.test"],
    )

    assert _matches_suricata(
        {
            "event_type": "dns",
            "src_ip": "10.40.0.10",
            "dest_ip": "10.20.0.10",
            "dns": {
                "version": 3,
                "type": "response",
                "queries": [{"rrname": "r01.beacon.datn.test"}],
            },
        },
        attribution,
    )


def test_suricata8_dns_response_reverses_all_attributed_endpoints() -> None:
    attribution = Attribution(
        source_ips=["10.20.0.10"],
        destination_ips=["10.40.0.10"],
        destination_ports=[53],
        dns_suffixes=["beacon.datn.test"],
    )

    assert _matches_suricata(
        {
            "event_type": "dns",
            "src_ip": "10.40.0.10",
            "src_port": 53,
            "dest_ip": "10.20.0.10",
            "dest_port": 53000,
            "dns": {
                "version": 3,
                "type": "response",
                "queries": [{"rrname": "r01.beacon.datn.test"}],
            },
        },
        attribution,
    )


@pytest.mark.parametrize(
    "dns",
    [
        {
            "query": [
                {
                    "type": "query",
                    "rrname": "r01.beacon.datn.test",
                }
            ]
        },
        {
            "answer": {
                "type": "answer",
                "rrname": "r01.beacon.datn.test",
            }
        },
    ],
)
def test_suricata_legacy_dns_alert_formats_remain_attributable(dns: dict) -> None:
    attribution = Attribution(dns_suffixes=["beacon.datn.test"])

    assert _matches_suricata(
        {"event_type": "alert", "dns": dns},
        attribution,
    )


def test_suricata_dns_attribution_tolerates_malformed_query_collections() -> None:
    attribution = Attribution(dns_suffixes=["beacon.datn.test"])

    assert not _matches_suricata(
        {"event_type": "dns", "dns": {"queries": None}},
        attribution,
    )


@pytest.mark.parametrize(
    ("label", "run_id", "suffix", "query", "signature_id"),
    [
        (
            "malicious",
            "C2-MALICIOUS-DNS-001",
            "beacon.datn.test",
            "r01.beacon.datn.test",
            900002,
        ),
        (
            "benign",
            "C2-BENIGN-DNS-001",
            "www.datn.test",
            "b01.www.datn.test",
            900004,
        ),
    ],
)
def test_dns_c2_finalize_accepts_suricata8_request_response_and_alert(
    tmp_path: Path,
    label: str,
    run_id: str,
    suffix: str,
    query: str,
    signature_id: int,
) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id=run_id,
        family="c2",
        label=label,
        attribution={
            "process_names": ["powershell.exe"],
            "source_ips": ["10.20.0.10"],
            "dns_suffixes": [suffix],
        },
        quality_gates={
            "min_dns_events": 1,
            "min_suricata_events": 3,
            "required_suricata_signature_ids": [signature_id],
        },
    )
    started = datetime(2026, 10, 20, 4, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    dns = {
        "version": 3,
        "queries": [{"rrname": query, "rrtype": "A"}],
    }
    append_jsonl(
        tmp_path / "archives.json",
        [
            windows_event(
                22,
                started + timedelta(seconds=1),
                {
                    "image": (
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    ),
                    "queryName": query,
                },
            ),
            suricata_event(
                started + timedelta(seconds=2),
                {
                    "event_type": "dns",
                    "src_ip": "10.20.0.10",
                    "dest_ip": "10.40.0.10",
                    "dns": {**dns, "type": "request"},
                },
            ),
            suricata_event(
                started + timedelta(seconds=3),
                {
                    "event_type": "dns",
                    "src_ip": "10.40.0.10",
                    "dest_ip": "10.20.0.10",
                    "dns": {**dns, "type": "response"},
                },
            ),
            suricata_event(
                started + timedelta(seconds=4),
                {
                    "event_type": "alert",
                    "src_ip": "10.20.0.10",
                    "dest_ip": "10.40.0.10",
                    "dns": {**dns, "type": "request"},
                    "alert": {"signature_id": signature_id},
                },
            ),
        ],
    )

    result = finalize_run(
        run_id,
        tmp_path,
        now=started + timedelta(seconds=10),
    )

    assert result["status"] == "FINALIZED"
    incident = json.loads(
        (tmp_path / f"data/raw/{run_id}/incidents.jsonl").read_text(
            encoding="utf-8"
        )
    )
    assert incident["features"]["suricata_alert_count"] == 1.0
    assert incident["features"]["dns_query_count"] == 1.0
    assert incident["features"]["outbound_connection_count"] == 1.0
    assert incident["features"]["destination_port_count"] == 1.0
    suricata_rows = (
        tmp_path
        / f"evidence/scenario-runs/{run_id}/suricata_eve.jsonl"
    ).read_text(encoding="utf-8").splitlines()
    assert len(suricata_rows) == 3


def test_finalize_fails_if_declared_execution_log_is_missing(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-ATOMIC-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    payload = yaml.safe_load(draft.read_text(encoding="utf-8"))
    payload["execution_log_path"] = "operator-logs/missing.csv"
    draft.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    started = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [windows_event(4624, started + timedelta(seconds=5), {"targetUserName": "labuser"})],
    )

    with pytest.raises(CollectionError, match="execution log"):
        finalize_run(
            "ACCOUNT-BENIGN-ATOMIC-001",
            tmp_path,
            now=started + timedelta(seconds=20),
        )


def test_account_finalize_rejects_run_below_declared_event_counts(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-MALICIOUS-QUALITY-001",
        family="account",
        label="malicious",
        attribution={"account_names": ["testuser"]},
        quality_gates={
            "min_account_failures": 6,
            "max_account_failures": 6,
            "min_account_successes": 0,
            "max_account_successes": 0,
        },
    )
    started = datetime(2026, 10, 16, 7, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [windows_event(4625, started + timedelta(seconds=5), {"targetUserName": "testuser"})],
    )

    with pytest.raises(CollectionError, match="account failure count"):
        finalize_run(
            "ACCOUNT-MALICIOUS-QUALITY-001",
            tmp_path,
            now=started + timedelta(seconds=20),
        )


def test_account_finalize_requires_every_declared_spray_account(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-MALICIOUS-SPRAY-QUALITY-001",
        family="account",
        label="malicious",
        attribution={"account_names": ["spray01", "spray02", "spray03"]},
        quality_gates={
            "min_account_failures": 3,
            "max_account_failures": 3,
            "min_account_successes": 0,
            "max_account_successes": 0,
            "require_all_accounts_observed": True,
        },
    )
    started = datetime(2026, 10, 16, 8, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [
            windows_event(4625, started + timedelta(seconds=5), {"targetUserName": "spray01"}),
            windows_event(4625, started + timedelta(seconds=6), {"targetUserName": "spray01"}),
            windows_event(4625, started + timedelta(seconds=7), {"targetUserName": "spray02"}),
        ],
    )

    with pytest.raises(CollectionError, match="missing declared accounts"):
        finalize_run(
            "ACCOUNT-MALICIOUS-SPRAY-QUALITY-001",
            tmp_path,
            now=started + timedelta(seconds=20),
        )


def test_c2_finalize_rejects_run_below_declared_network_count(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="C2-MALICIOUS-QUALITY-001",
        family="c2",
        label="malicious",
        attribution={
            "process_names": ["curl.exe"],
            "destination_ips": ["10.40.0.10"],
            "destination_ports": [8081],
        },
        quality_gates={
            "min_network_events": 8,
            "min_suricata_events": 8,
            "required_suricata_signature_ids": [900001],
        },
    )
    started = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [
            windows_event(
                3,
                started + timedelta(seconds=5),
                {
                    "image": r"C:\Windows\System32\curl.exe",
                    "initiated": "true",
                    "destinationIp": "10.40.0.10",
                    "destinationPort": "8081",
                },
            ),
            suricata_event(
                started + timedelta(seconds=6),
                {
                    "event_type": "alert",
                    "src_ip": "10.20.0.10",
                    "dest_ip": "10.40.0.10",
                    "dest_port": 8081,
                    "alert": {"signature_id": 900001},
                },
            ),
        ],
    )

    with pytest.raises(CollectionError, match="network event count"):
        finalize_run(
            "C2-MALICIOUS-QUALITY-001",
            tmp_path,
            now=started + timedelta(seconds=20),
        )


def test_start_rejects_archive_cursor_that_is_not_on_a_line_boundary(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    (tmp_path / "archives.json").write_text('{"partial":true}', encoding="utf-8")
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-CURSOR-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )

    with pytest.raises(CollectionError, match="complete newline"):
        start_run(
            draft,
            config,
            tmp_path,
            now=datetime(2026, 10, 16, 10, 0, tzinfo=UTC),
        )

    evidence_dir = tmp_path / "evidence/scenario-runs/ACCOUNT-BENIGN-CURSOR-001"
    assert not evidence_dir.exists()

    (tmp_path / "archives.json").write_text('{"baseline":true}\n', encoding="utf-8")
    result = start_run(
        draft,
        config,
        tmp_path,
        now=datetime(2026, 10, 16, 10, 1, tzinfo=UTC),
    )
    assert result["status"] == "STARTED"


def test_start_rejects_legacy_or_incomplete_raw_dataset_layout(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="C2-MALICIOUS-LEGACY-GATE-001",
        family="c2",
        label="malicious",
        attribution={
            "source_ips": ["10.20.0.10"],
            "destination_ips": ["10.40.0.10"],
            "destination_ports": [8081],
        },
    )
    legacy_run = tmp_path / "data/raw/C2/HTTP_Beacon_run01"
    legacy_run.mkdir(parents=True)
    (legacy_run / "metadata.json").write_text("{}\n", encoding="utf-8")
    (legacy_run / "events_raw.jsonl").write_text("{}\n", encoding="utf-8")

    with pytest.raises(CollectionError, match="incompatible raw dataset layout"):
        start_run(draft, config, tmp_path)

    assert not (tmp_path / "evidence/scenario-runs/.active-run.json").exists()
    assert not (
        tmp_path
        / "evidence/scenario-runs/C2-MALICIOUS-LEGACY-GATE-001"
    ).exists()


def test_start_rejects_orphan_current_schema_raw_run(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-ORPHAN-GATE-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    orphan = tmp_path / "data/raw/ACCOUNT-BENIGN-ORPHAN-000"
    orphan.mkdir(parents=True)
    (orphan / "scenario_manifest.json").write_text("{}\n", encoding="utf-8")
    (orphan / "incidents.jsonl").write_text("{}\n", encoding="utf-8")

    with pytest.raises(CollectionError, match="incompatible raw dataset layout"):
        start_run(draft, config, tmp_path)

    assert not (tmp_path / "evidence/scenario-runs/.active-run.json").exists()


def test_start_accepts_collection_root_with_prior_valid_run(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    first = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-VALID-ROOT-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
        quality_gates={
            "min_account_successes": 1,
            "max_account_successes": 1,
        },
    )
    started = datetime(2026, 10, 16, 14, 0, tzinfo=UTC)
    start_run(first, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [windows_event(4624, started + timedelta(seconds=5), {"targetUserName": "labuser"})],
    )
    finalize_run(
        "ACCOUNT-BENIGN-VALID-ROOT-001",
        tmp_path,
        now=started + timedelta(seconds=10),
    )
    second = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-VALID-ROOT-002",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )

    result = start_run(
        second,
        config,
        tmp_path,
        now=started + timedelta(seconds=20),
    )

    assert result["status"] == "STARTED"


def test_finalize_rejects_incomplete_archive_tail_and_allows_retry(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-CURSOR-002",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    started = datetime(2026, 10, 16, 11, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    event = windows_event(
        4624,
        started + timedelta(seconds=5),
        {"targetUserName": "labuser"},
    )
    encoded = json.dumps(event)
    split = len(encoded) // 2
    archive = tmp_path / "archives.json"
    with archive.open("a", encoding="utf-8") as handle:
        handle.write(encoded[:split])

    with pytest.raises(CollectionError, match="incomplete final JSON line"):
        finalize_run(
            "ACCOUNT-BENIGN-CURSOR-002",
            tmp_path,
            now=started + timedelta(seconds=10),
        )

    with archive.open("a", encoding="utf-8") as handle:
        handle.write(encoded[split:] + "\n")
    result = finalize_run(
        "ACCOUNT-BENIGN-CURSOR-002",
        tmp_path,
        now=started + timedelta(seconds=20),
    )
    assert result["status"] == "FINALIZED"


def test_start_rejects_a_second_concurrent_run_and_abort_releases_lock(
    tmp_path: Path,
) -> None:
    config = source_config(tmp_path)
    first = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-CONCURRENT-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    second = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-CONCURRENT-002",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )

    start_run(first, config, tmp_path)
    with pytest.raises(CollectionError, match="active run"):
        start_run(second, config, tmp_path)

    abort_run("ACCOUNT-BENIGN-CONCURRENT-001", tmp_path, "test cleanup")
    result = start_run(second, config, tmp_path)
    assert result["status"] == "STARTED"


def test_finalize_rejects_modified_start_snapshot(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-SNAPSHOT-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    started = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    ground_truth = (
        tmp_path
        / "evidence/scenario-runs/ACCOUNT-BENIGN-SNAPSHOT-001/ground_truth.json"
    )
    payload = json.loads(ground_truth.read_text(encoding="utf-8"))
    payload["label"] = "malicious"
    ground_truth.write_text(json.dumps(payload), encoding="utf-8")
    append_jsonl(
        tmp_path / "archives.json",
        [windows_event(4624, started + timedelta(seconds=5), {"targetUserName": "labuser"})],
    )

    with pytest.raises(CollectionError, match="start snapshot"):
        finalize_run(
            "ACCOUNT-BENIGN-SNAPSHOT-001",
            tmp_path,
            now=started + timedelta(seconds=10),
        )


def test_suricata_attribution_requires_the_declared_windows_source_ip() -> None:
    attribution = Attribution(
        source_ips=["10.20.0.10"],
        destination_ips=["10.40.0.10"],
        destination_ports=[8081],
    )
    unrelated = {
        "event_type": "http",
        "src_ip": "10.20.0.99",
        "dest_ip": "10.40.0.10",
        "dest_port": 8081,
    }
    expected = {**unrelated, "src_ip": "10.20.0.10"}

    assert not _matches_suricata(unrelated, attribution)
    assert _matches_suricata(expected, attribution)


def test_validate_rejects_empty_or_incomplete_checksum_manifest(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-CHECKSUM-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    started = datetime(2026, 10, 16, 13, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [windows_event(4624, started + timedelta(seconds=5), {"targetUserName": "labuser"})],
    )
    finalize_run(
        "ACCOUNT-BENIGN-CHECKSUM-001",
        tmp_path,
        now=started + timedelta(seconds=10),
    )
    checksum_path = (
        tmp_path
        / "evidence/scenario-runs/ACCOUNT-BENIGN-CHECKSUM-001/checksums.sha256"
    )
    checksum_path.write_text("", encoding="utf-8")

    with pytest.raises(CollectionError, match="checksum manifest"):
        validate_run("ACCOUNT-BENIGN-CHECKSUM-001", tmp_path)


def test_start_rejects_draft_identity_that_disagrees_with_catalog(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text(
        yaml.safe_dump(
            {
                "version": "scenario-catalog-v1",
                "lab_only": True,
                "scenarios": [
                    {
                        "scenario_id": "SCENARIO-account-benign",
                        "family": "account",
                        "label": "benign",
                        "expected_behavior": "Controlled lab behavior.",
                        "attribution": {"account_names": ["labuser"]},
                        "quality_gates": {},
                        "preconditions": ["test"],
                        "execution_steps": ["test"],
                        "expected_observables": ["test"],
                        "cleanup_steps": ["test"],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config_payload = yaml.safe_load(config.read_text(encoding="utf-8"))
    config_payload["scenario_catalog_path"] = str(catalog)
    config.write_text(yaml.safe_dump(config_payload, sort_keys=False), encoding="utf-8")
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-MISMATCH-001",
        family="account",
        label="malicious",
        attribution={"account_names": ["labuser"]},
    )

    with pytest.raises(CollectionError, match="does not match scenario catalog"):
        start_run(draft, config, tmp_path)


def test_invalid_finalized_run_can_be_quarantined_without_deletion(tmp_path: Path) -> None:
    config = source_config(tmp_path)
    draft = write_draft(
        tmp_path,
        run_id="ACCOUNT-BENIGN-QUARANTINE-001",
        family="account",
        label="benign",
        attribution={"account_names": ["labuser"]},
    )
    started = datetime(2026, 10, 16, 14, 0, tzinfo=UTC)
    start_run(draft, config, tmp_path, now=started)
    append_jsonl(
        tmp_path / "archives.json",
        [windows_event(4624, started + timedelta(seconds=5), {"targetUserName": "labuser"})],
    )
    finalize_run(
        "ACCOUNT-BENIGN-QUARANTINE-001",
        tmp_path,
        now=started + timedelta(seconds=10),
    )
    incident = tmp_path / "data/raw/ACCOUNT-BENIGN-QUARANTINE-001/incidents.jsonl"
    incident.write_text("tampered\n", encoding="utf-8")

    result = quarantine_run(
        "ACCOUNT-BENIGN-QUARANTINE-001", tmp_path, "checksum mismatch"
    )

    assert result["status"] == "QUARANTINED"
    assert not (tmp_path / "data/raw/ACCOUNT-BENIGN-QUARANTINE-001").exists()
    assert not (tmp_path / "evidence/scenario-runs/ACCOUNT-BENIGN-QUARANTINE-001").exists()
    assert (tmp_path / "data/quarantine/ACCOUNT-BENIGN-QUARANTINE-001").is_dir()
    evidence = tmp_path / "evidence/quarantine/ACCOUNT-BENIGN-QUARANTINE-001"
    assert evidence.is_dir()
    assert json.loads((evidence / "quarantine.json").read_text(encoding="utf-8"))[
        "reason"
    ] == "checksum mismatch"
