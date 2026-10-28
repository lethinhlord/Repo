"""End-to-end acceptance coverage for the checked-in collection catalog."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from ml.context import build_baseline
from ml.dataset_audit import STRATA, audit_dataset
from ml.scenario_collection import (
    ClockPreflight,
    RunDraft,
    ScenarioCatalog,
    ScenarioDefinition,
    begin_action,
    complete_action,
    create_run_draft,
    finalize_run,
    start_run,
    validate_run,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COLLECTION_BASE = datetime(2026, 10, 27, 0, 0, 5, tzinfo=UTC)
RUN_SPACING = timedelta(minutes=10)


def _json_line(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True) + "\n"


def _windows_event(
    run_id: str,
    when: datetime,
    event_id: int,
    eventdata: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{index}",
        "timestamp": when.isoformat(),
        "agent": {"id": "001", "name": "WIN11-TARGET"},
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                    "eventRecordID": f"{run_id}-{index}",
                    "systemTime": when.isoformat(),
                },
                "eventdata": eventdata,
            }
        },
    }


def _suricata_event(when: datetime, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent": {"id": "002", "name": "NET-SENSOR"},
        "timestamp": when.isoformat(),
        "full_log": json.dumps({"timestamp": when.isoformat(), **payload}),
    }


def _clock_preflight(at: datetime) -> ClockPreflight:
    return ClockPreflight.model_validate(
        {
            name: at
            for name in (
                "captured_at",
                "controller_utc",
                "target_utc",
                "wazuh_utc",
                "sensor_utc",
                "attacker_utc",
            )
        }
    )


def _prepare_collection_root(tmp_path: Path) -> tuple[Path, Path, ScenarioCatalog]:
    (tmp_path / "config").mkdir()
    (tmp_path / "ml").mkdir()
    catalog_path = tmp_path / "config/scenario-catalog.yaml"
    taxonomy_path = tmp_path / "config/suspicious-process-taxonomy.yaml"
    schema_path = tmp_path / "ml/feature_schema.json"
    shutil.copyfile(PROJECT_ROOT / "config/scenario-catalog.yaml", catalog_path)
    shutil.copyfile(
        PROJECT_ROOT / "config/suspicious-process-taxonomy.yaml", taxonomy_path
    )
    shutil.copyfile(PROJECT_ROOT / "ml/feature_schema.json", schema_path)

    archive_path = tmp_path / "archives.json"
    archive_path.write_text('{"baseline":true}\n', encoding="utf-8")
    source_payload = yaml.safe_load(
        (PROJECT_ROOT / "config/collection-sources.yaml").read_text(encoding="utf-8")
    )
    source_payload["wazuh_archives_path"] = str(archive_path)
    source_path = tmp_path / "config/collection-sources.yaml"
    source_path.write_text(
        yaml.safe_dump(source_payload, sort_keys=False), encoding="utf-8"
    )
    catalog = ScenarioCatalog.model_validate(
        yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    )
    # Separate synthetic enrollment, completed before every labeled test run.
    # It proves context contracts only and is never real training evidence.
    observed_at = COLLECTION_BASE - timedelta(days=1)
    enrollment = []
    users = {name for row in catalog.scenarios for name in row.attribution.account_names}
    for user in sorted(users):
        for source in ("local-console", "-", "10.40.0.10"):
            enrollment.append(_windows_event("ENROLLMENT", observed_at, 4624, {
                "targetUserName": user, "logonType": "3", "ipAddress": source,
            }, len(enrollment)))
    for row in catalog.scenarios:
        for destination in row.attribution.destination_ips:
            for port in row.attribution.destination_ports:
                enrollment.append(_windows_event("ENROLLMENT", observed_at, 3, {
                    "image":"curl.exe", "initiated":"true", "sourceIp":"10.20.0.10",
                    "destinationIp":destination, "destinationPort":str(port),
                },len(enrollment)))
        for domain in row.attribution.dns_suffixes:
            enrollment.append(_windows_event("ENROLLMENT", observed_at, 22, {
                "image":"powershell.exe", "queryName":domain,
            },len(enrollment)))
    captured = "".join(_json_line(row) for row in enrollment).encode()
    digest = hashlib.sha256(captured).hexdigest()
    baseline = build_baseline(
        enrollment, revision="SYNTHETIC-ACCEPTANCE-ENROLLMENT", captured_at=observed_at,
        valid_until=COLLECTION_BASE + timedelta(days=7), source_capture_sha256=digest,
    )
    for destination in baseline.destinations:
        if destination.port == 53:
            destination.match = "dns_suffix"
    context_path = tmp_path/"evidence/context-baseline.json"
    capture_dir = context_path.parent/"context-captures"
    capture_dir.mkdir(parents=True)
    (capture_dir/f"{digest}.jsonl").write_bytes(captured)
    context_path.write_text(baseline.model_dump_json(indent=2),encoding="utf-8")
    return archive_path, source_path, catalog


def _account_events(
    run_id: str,
    scenario: ScenarioDefinition,
    draft: RunDraft,
    first_event_at: datetime,
) -> tuple[list[dict[str, Any]], datetime]:
    gates = scenario.quality_gates
    accounts = scenario.attribution.account_names
    logon_type = str(scenario.attribution.logon_types[0])
    source_ip = scenario.attribution.source_ips[0] if scenario.attribution.source_ips else "-"
    interval = float(draft.scenario_parameters.get("attempt_delay_seconds", 2.0))
    events: list[dict[str, Any]] = []
    event_at = first_event_at
    index = 0

    for number in range(gates.min_account_failures):
        events.append(
            _windows_event(
                run_id,
                event_at,
                4625,
                {
                    "targetUserName": accounts[number % len(accounts)],
                    "ipAddress": source_ip,
                    "logonType": logon_type,
                },
                index,
            )
        )
        event_at += timedelta(seconds=interval)
        index += 1
    for number in range(gates.min_account_successes):
        events.append(
            _windows_event(
                run_id,
                event_at,
                4624,
                {
                    "targetUserName": accounts[-1],
                    "ipAddress": source_ip,
                    "logonType": logon_type,
                },
                index + number,
            )
        )
        event_at += timedelta(seconds=interval)
    return events, event_at


def _c2_events(
    run_id: str,
    scenario: ScenarioDefinition,
    draft: RunDraft,
    first_event_at: datetime,
) -> tuple[list[dict[str, Any]], datetime]:
    nonce = str(draft.scenario_parameters["run_nonce"])
    gaps = [
        float(value)
        for value in str(draft.scenario_parameters["expected_intervals_seconds"]).split(",")
        if value
    ]
    action_count = int(draft.scenario_parameters["expected_action_count"])
    events: list[dict[str, Any]] = []
    event_at = first_event_at
    event_index = 0

    if scenario.quality_gates.min_dns_events:
        suffix = scenario.attribution.dns_suffixes[0]
        process_guid = f"{{SYNTHETIC-{run_id}-DNS}}"
        events.append(
            _windows_event(
                run_id,
                event_at - timedelta(milliseconds=100),
                1,
                {
                    "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "commandLine": (
                        "powershell.exe -NoProfile -Command "
                        f"Resolve-DnsName {nonce}-0.{suffix}"
                    ),
                    "processGuid": process_guid,
                },
                event_index,
            )
        )
        event_index += 1
        for number in range(action_count):
            query = f"{nonce}-{number}.{suffix}"
            events.append(
                _windows_event(
                    run_id,
                    event_at,
                    22,
                    {
                        "image": "powershell.exe",
                        "queryName": query,
                        "processGuid": process_guid,
                    },
                    event_index,
                )
            )
            event_index += 1
            payload: dict[str, Any] = {
                "event_type": "dns",
                "src_ip": "10.20.0.10",
                "dest_ip": "10.40.0.10",
                "dest_port": 53,
                "flow_id": f"{run_id}-{number}",
                "dns": {"type": "query", "rrname": query},
            }
            events.append(_suricata_event(event_at, payload))
            signature = scenario.quality_gates.required_suricata_signature_ids[0]
            events.append(
                _suricata_event(
                    event_at,
                    {
                        **payload,
                        "event_type": "alert",
                        "alert": {"signature_id": signature, "severity": 3},
                    },
                )
            )
            events.append(_suricata_event(event_at + timedelta(seconds=60), {
                "event_type":"flow", "src_ip":"10.20.0.10", "dest_ip":"10.40.0.10",
                "dest_port":53, "flow_id":f"{run_id}-{number}",
                "flow":{"start":event_at.isoformat(),
                        "end":(event_at + timedelta(milliseconds=10)).isoformat(),
                        "bytes_toserver":40,"bytes_toclient":60},
            }))
            if number < len(gaps):
                event_at += timedelta(seconds=gaps[number])
        return events, event_at

    port = scenario.attribution.destination_ports[0]
    command_term = scenario.attribution.command_contains_any[0]
    for number in range(action_count):
        process_guid = f"{{SYNTHETIC-{run_id}-{number}}}"
        uri = f"{command_term}?run={nonce}&n={number}"
        events.extend(
            [
                _windows_event(
                    run_id,
                    event_at - timedelta(milliseconds=100),
                    1,
                    {
                        "image": r"C:\Windows\System32\curl.exe",
                        "commandLine": f"curl.exe http://10.40.0.10:{port}{uri}",
                        "processGuid": process_guid,
                    },
                    event_index,
                ),
                _windows_event(
                    run_id,
                    event_at,
                    3,
                    {
                        "image": r"C:\Windows\System32\curl.exe",
                        "processGuid": process_guid,
                        "sourceIp": "10.20.0.10",
                        "destinationIp": "10.40.0.10",
                        "destinationPort": str(port),
                        "initiated": "true",
                    },
                    event_index + 1,
                ),
            ]
        )
        event_index += 2
        payload = {
            "event_type": "http",
            "src_ip": "10.20.0.10",
            "dest_ip": "10.40.0.10",
            "dest_port": port,
            "flow_id": f"{run_id}-{number}",
            "http": {"url": uri},
        }
        events.append(_suricata_event(event_at, payload))
        if scenario.quality_gates.required_suricata_signature_ids:
            events.append(
                _suricata_event(
                    event_at,
                    {
                        **payload,
                        "event_type": "alert",
                        "alert": {
                            "signature_id": (
                                scenario.quality_gates.required_suricata_signature_ids[0]
                            ),
                            "severity": 3,
                        },
                    },
                )
            )
        events.append(_suricata_event(event_at + timedelta(seconds=60), {
            "event_type":"flow", "src_ip":"10.20.0.10", "dest_ip":"10.40.0.10",
            "dest_port":port, "flow_id":f"{run_id}-{number}",
            "flow":{"start":event_at.isoformat(),
                    "end":(event_at + timedelta(milliseconds=10)).isoformat(),
                    "bytes_toserver":40,"bytes_toclient":60},
        }))
        if number < len(gaps):
            event_at += timedelta(seconds=gaps[number])
    return events, event_at


def _collect_run(
    root: Path,
    archive_path: Path,
    source_path: Path,
    scenario: ScenarioDefinition,
    *,
    sequence: int,
    repeat: int,
) -> str:
    run_id = f"ACCEPT-{scenario.scenario_id}-R{repeat + 1}"
    action_started_at = COLLECTION_BASE + sequence * RUN_SPACING + timedelta(seconds=5)
    collection_started_at = COLLECTION_BASE + sequence * RUN_SPACING - timedelta(seconds=10)
    draft_path = root / "run-drafts" / f"{run_id}.yaml"
    create_run_draft(
        root / "config/scenario-catalog.yaml",
        scenario.scenario_id,
        run_id,
        "synthetic-acceptance",
        draft_path,
        collection_seed=20_261_027 + sequence,
        clock_preflight=_clock_preflight(collection_started_at),
    )
    draft = RunDraft.model_validate(
        yaml.safe_load(draft_path.read_text(encoding="utf-8"))
    )
    started = start_run(draft_path, source_path, root, now=collection_started_at)
    receipt = begin_action(run_id, root, now=action_started_at)
    first_event_at = action_started_at + timedelta(
        seconds=float(draft.scenario_parameters["pre_action_delay_seconds"])
    )
    if scenario.family == "account":
        events, last_event_at = _account_events(
            run_id, scenario, draft, first_event_at
        )
    else:
        events, last_event_at = _c2_events(run_id, scenario, draft, first_event_at)
    with archive_path.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(_json_line(event))

    action_ended_at = last_event_at + timedelta(seconds=2)
    assert action_ended_at - action_started_at < timedelta(minutes=5)
    complete_action(run_id, root, now=action_ended_at)
    metadata = finalize_run(
        run_id, root, now=datetime.fromtimestamp(
            (int(action_started_at.timestamp()) // 300 + 1) * 300, UTC,
        ) + timedelta(seconds=60)
    )
    validation = validate_run(run_id, root)

    assert started["frozen_parameters_sha256"] == receipt["frozen_parameters_sha256"]
    assert metadata["status"] == "FINALIZED"
    assert validation == {
        "status": "VALID",
        "run_id": run_id,
        "family": scenario.family,
        "label": scenario.label,
    }
    _assert_run_integrity(root, run_id, draft)
    return run_id


def _assert_run_integrity(root: Path, run_id: str, draft: RunDraft) -> None:
    evidence_dir = root / "evidence/scenario-runs" / run_id
    state = json.loads((evidence_dir / ".collection_state.json").read_text(encoding="utf-8"))
    receipt = json.loads((evidence_dir / "execution_receipt.json").read_text(encoding="utf-8"))
    markers = [
        json.loads(line)
        for line in (evidence_dir / "run_markers.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    windows_rows = [
        json.loads(line)
        for line in (evidence_dir / "windows_events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert state["status"] == "FINALIZED"
    assert receipt["status"] == "COMPLETED"
    assert [marker["event"] for marker in markers] == ["START", "END"]
    assert all(row["id"].startswith(f"synthetic-{run_id}-") for row in windows_rows)
    assert len(state["collection_contract_sha256"]) == 64
    assert len(state["start_contract_sha256"]) == 64
    if draft.family == "c2":
        process_rows = [
            row
            for row in windows_rows
            if row["data"]["win"]["system"]["eventID"] == "1"
        ]
        assert len(process_rows) >= draft.quality_gates.min_process_events
        nonce = str(draft.scenario_parameters["run_nonce"])
        assert all(
            nonce in row["data"]["win"]["eventdata"]["commandLine"]
            for row in process_rows
        )


def _audit(root: Path, source_path: Path) -> dict[str, Any]:
    return audit_dataset(
        root / "data/raw",
        root / "evidence/scenario-runs",
        scenario_catalog_path=root / "config/scenario-catalog.yaml",
        source_config_path=source_path,
        taxonomy_path=root / "config/suspicious-process-taxonomy.yaml",
    )


def _assert_balanced_report(
    report: dict[str, Any],
    *,
    expected_status: str,
    expected_runs_per_stratum: int,
    expected_scenario_counts: list[int],
) -> None:
    assert report["status"] == expected_status, report["issues"]
    assert report["invalid_run_count"] == 0
    assert report["error_count"] == 0
    assert report["total_valid_runs"] == expected_runs_per_stratum * len(STRATA)
    assert len(report["collection_contract_sha256"]) == 64
    for stratum in STRATA:
        row = report["strata"][stratum]
        assert row["valid_runs"] == expected_runs_per_stratum
        assert row["distinct_scenarios"] == 5
        assert sorted(row["scenario_counts"].values()) == expected_scenario_counts


def test_checked_in_catalog_reaches_ready_and_target_with_fresh_balanced_runs(
    tmp_path: Path,
) -> None:
    archive_path, source_path, catalog = _prepare_collection_root(tmp_path)
    scenarios_by_stratum: dict[str, list[ScenarioDefinition]] = defaultdict(list)
    for scenario in catalog.scenarios:
        scenarios_by_stratum[f"{scenario.family}:{scenario.label}"].append(scenario)

    assert set(scenarios_by_stratum) == set(STRATA)
    assert all(len(scenarios) == 5 for scenarios in scenarios_by_stratum.values())
    assert len(catalog.scenarios) == 20
    health_poll = next(
        scenario
        for scenario in catalog.scenarios
        if scenario.scenario_id == "C2-BENIGN-HEALTH-POLL"
    )
    assert health_poll.quality_gates.min_process_events == 8
    assert health_poll.quality_gates.min_network_events == 8
    for scenario_id in ("C2-BENIGN-DNS", "C2-MALICIOUS-DNS-BEACON"):
        scenario = next(
            item for item in catalog.scenarios if item.scenario_id == scenario_id
        )
        assert scenario.quality_gates.min_process_events == 1

    run_ids: list[str] = []
    sequence = 0
    for repeat in range(2):
        for scenario in catalog.scenarios:
            run_ids.append(
                _collect_run(
                    tmp_path,
                    archive_path,
                    source_path,
                    scenario,
                    sequence=sequence,
                    repeat=repeat,
                )
            )
            sequence += 1

    assert len(run_ids) == 40
    assert len(set(run_ids)) == 40
    ready_report = _audit(tmp_path, source_path)
    _assert_balanced_report(
        ready_report,
        expected_status="READY",
        expected_runs_per_stratum=10,
        expected_scenario_counts=[2, 2, 2, 2, 2],
    )

    third_repeats = [
        scenario
        for stratum in STRATA
        for scenario in scenarios_by_stratum[stratum][:2]
    ]
    assert Counter(
        f"{scenario.family}:{scenario.label}" for scenario in third_repeats
    ) == Counter({stratum: 2 for stratum in STRATA})
    for scenario in third_repeats:
        run_ids.append(
            _collect_run(
                tmp_path,
                archive_path,
                source_path,
                scenario,
                sequence=sequence,
                repeat=2,
            )
        )
        sequence += 1

    assert len(run_ids) == 48
    assert len(set(run_ids)) == 48
    target_report = _audit(tmp_path, source_path)
    _assert_balanced_report(
        target_report,
        expected_status="TARGET_MET",
        expected_runs_per_stratum=12,
        expected_scenario_counts=[2, 2, 2, 3, 3],
    )
    assert target_report["collection_contract_sha256"] == ready_report[
        "collection_contract_sha256"
    ]
    catalog_sha256 = hashlib.sha256(
        (tmp_path / "config/scenario-catalog.yaml").read_bytes()
    ).hexdigest()
    assert {
        json.loads(
            (
                tmp_path
                / "data/raw"
                / run_id
                / "scenario_manifest.json"
            ).read_text(encoding="utf-8")
        )["scenario_catalog_sha256"]
        for run_id in run_ids
    } == {catalog_sha256}
