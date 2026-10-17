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
        "success_after_fail": 0.0,
        "suspicious_process": 1.0,
        "periodicity_score": 1.0,
        "suricata_alert_count": 1.0,
        "outbound_connection_count": 3.0,
        "destination_port_count": 1.0,
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
