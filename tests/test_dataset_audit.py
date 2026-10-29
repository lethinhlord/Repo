from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from ml.dataset_audit import audit_dataset
from ml.scenario_collection import (
    RunDraft,
    ScenarioCatalog,
    SourceConfig,
    _derive_account,
    _derive_c2,
)

FEATURES = {
    "failed_login_count": 0.0,
    "successful_login_count": 0.0,
    "success_after_fail": 0.0,
    "unique_target_account_count": 0.0,
    "unique_source_count": 0.0,
    "remote_logon_ratio": 0.0,
    "failure_window_seconds": 0.0,
    "attempt_rate_per_minute": 0.0,
    "suspicious_process": 0.0,
    "periodicity_score": 0.0,
    "connection_interval_cv": 0.0,
    "mean_interval_seconds": 0.0,
    "suricata_alert_count": 0.0,
    "suricata_severity_score": 0.0,
    "outbound_connection_count": 1.0,
    "unique_destination_count": 1.0,
    "destination_port_count": 1.0,
    "dns_query_count": 0.0,
    "dns_unique_query_ratio": 0.0,
    "flow_total_bytes_log1p": 0.0,
}


def checksums(directory: Path) -> None:
    rows = []
    files = (
        path
        for path in directory.iterdir()
        if path.is_file()
        and path.name not in {"checksums.sha256", ".collection_state.json"}
    )
    for path in sorted(files):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.name}\n")
    (directory / "checksums.sha256").write_text("".join(rows), encoding="utf-8")


def write_run(
    root: Path,
    *,
    family: str,
    label: str,
    index: int,
    scenario_slot: int,
    incident_id: str | None = None,
    include_suricata: bool = True,
    c2_offsets: list[float] | None = None,
    account_successes: int = 1,
    remote: bool = False,
    timing_offset: float | None = None,
    time_slot: int | None = None,
) -> None:
    run_id = f"{family.upper()}-{label.upper()}-{index:02d}"
    slot = time_slot if time_slot is not None else (
        index + 20 * ((family == "c2") * 2 + (label == "malicious"))
    )
    started = datetime(2026, 10, 16, 1, 0, 5, tzinfo=UTC) + timedelta(minutes=10 * slot)
    ended = started + timedelta(seconds=30)
    run_dir = root / "data/raw" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    scenario_parameters = {"variant_index": index, "timing_jitter_percent": 10 + index}
    if family == "c2":
        scenario_parameters["run_nonce"] = hashlib.sha256(run_id.encode()).hexdigest()[:16]
    catalog_path = root / "scenario-catalog.yaml"
    parsed_catalog = ScenarioCatalog.model_validate(
        yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    )
    scenario = next(
        item
        for item in parsed_catalog.scenarios
        if item.scenario_id == f"{family.upper()}-{label.upper()}-S{scenario_slot}"
    )
    clock_preflight = {
        "captured_at": started.isoformat(),
        "controller_utc": started.isoformat(),
        "target_utc": started.isoformat(),
        "wazuh_utc": started.isoformat(),
        "sensor_utc": started.isoformat(),
        "attacker_utc": started.isoformat(),
        "maximum_skew_seconds": 2.0,
    }
    ground_truth = {
        "scenario_id": f"{family.upper()}-{label.upper()}-S{scenario_slot}",
        "run_id": run_id,
        "family": family,
        "label": label,
        "host": "WIN11-TARGET",
        "expected_behavior": scenario.expected_behavior,
        "operator": "Kien",
        "attribution": scenario.attribution.model_dump(mode="json"),
        "quality_gates": scenario.quality_gates.model_dump(mode="json"),
        "execution_log_path": None,
        "collection_seed": index,
        "scenario_parameters": scenario_parameters,
        "expected_observables": ["test"],
        "clock_preflight": clock_preflight,
    }
    ground_truth = RunDraft.model_validate(ground_truth).model_dump(mode="json")
    provenance_sha256 = hashlib.sha256(
        json.dumps(ground_truth, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    evidence_dir = root / "evidence/scenario-runs" / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    source_snapshot = evidence_dir / "collection-sources.yaml"
    source_snapshot.write_bytes((root / "collection-sources.yaml").read_bytes())
    taxonomy_snapshot = evidence_dir / "suspicious-process-taxonomy.yaml"
    taxonomy_snapshot.write_bytes(
        (root / "suspicious-process-taxonomy.yaml").read_bytes()
    )
    catalog_snapshot = evidence_dir / "scenario-catalog.yaml"
    catalog_snapshot.write_bytes(catalog_path.read_bytes())
    schema_source = Path(__file__).parents[1] / "ml/feature_schema.json"
    schema_snapshot = evidence_dir / "feature-schema.json"
    schema_snapshot.write_bytes(schema_source.read_bytes())
    contract_hashes = {
        "source_config_sha256": hashlib.sha256(source_snapshot.read_bytes()).hexdigest(),
        "taxonomy_sha256": hashlib.sha256(taxonomy_snapshot.read_bytes()).hexdigest(),
        "scenario_catalog_sha256": hashlib.sha256(catalog_snapshot.read_bytes()).hexdigest(),
        "feature_schema_sha256": hashlib.sha256(schema_snapshot.read_bytes()).hexdigest(),
    }
    collection_contract_sha256 = hashlib.sha256(
        json.dumps(contract_hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    source_payload = yaml.safe_load(source_snapshot.read_text(encoding="utf-8"))
    archive_cursor = {
        "path": source_payload["wazuh_archives_path"],
        "size": 0,
        "device": 0,
        "inode": 0,
    }
    frozen_parameters = {
        "run_id": run_id,
        "scenario_id": scenario.scenario_id,
        "family": family,
        "label": label,
        "scenario_parameters": scenario_parameters,
    }
    frozen_parameters_sha256 = hashlib.sha256(
        json.dumps(frozen_parameters, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    start_contract = {
        "version": "collection-start-contract-v1",
        "run_id": run_id,
        "started_at": started.isoformat(),
        "draft_sha256": provenance_sha256,
        "draft_snapshot_sha256": provenance_sha256,
        **contract_hashes,
        "collection_contract_sha256": collection_contract_sha256,
        "frozen_parameters_sha256": frozen_parameters_sha256,
        "source": source_payload,
        "archive_cursor": archive_cursor,
    }
    start_contract_path = evidence_dir / "start-contract.json"
    start_contract_path.write_text(json.dumps(start_contract), encoding="utf-8")
    start_contract_sha256 = hashlib.sha256(
        json.dumps(start_contract, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = {
        "version": "execution-receipt-v1",
        "status": "COMPLETED",
        "run_id": run_id,
        "scenario_id": scenario.scenario_id,
        "operator": "Kien",
        "frozen_parameters_sha256": frozen_parameters_sha256,
        "action_started_at": started.isoformat(),
        "action_ended_at": ended.isoformat(),
        "aggregation_window_start": (started - timedelta(seconds=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        "aggregation_window_end": (started + timedelta(seconds=295)).isoformat().replace(
            "+00:00", "Z"
        ),
        "action_deadline": (started + timedelta(seconds=293)).isoformat().replace(
            "+00:00", "Z"
        ),
        "reserved_action_seconds": 60.0,
    }
    (evidence_dir / "execution-parameters.json").write_text(
        json.dumps(frozen_parameters), encoding="utf-8"
    )
    receipt_path = evidence_dir / "execution_receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    manifest = {
        "scenario_id": f"{family.upper()}-{label.upper()}-S{scenario_slot}",
        "run_id": run_id,
        "family": family,
        "label": label,
        "host": "WIN11-TARGET",
        "start_time": started.isoformat(),
        "end_time": ended.isoformat(),
        "expected_behavior": scenario.expected_behavior,
        "collection_seed": index,
        "scenario_parameters": scenario_parameters,
        "provenance_sha256": provenance_sha256,
        **contract_hashes,
        "collection_contract_sha256": collection_contract_sha256,
    }
    (run_dir / "scenario_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    evidence_sources = ["wazuh-archives"]
    if family == "c2":
        evidence_sources.append("suricata-eve")
    incident = {
        "incident_id": incident_id or f"INC-{run_id}",
        "asset_id": "WIN11-TARGET",
        "start_time": started.isoformat(),
        "end_time": ended.isoformat(),
        "family_hint": family,
        "features": dict(FEATURES),
        "evidence_sources": evidence_sources,
        "base_severity": 0,
        "raw_refs": [f"evidence:{run_id}"],
        "indicator": "10.40.0.10" if family == "c2" else None,
    }
    offset = timing_offset if timing_offset is not None else (0.0 if label == "benign" else .01)
    step = 1.0 + index * .05 + offset
    raw_windows = []
    raw_suricata = []

    def win(event_id: int, seconds: float, fields: dict) -> dict:
        timestamp = (started + timedelta(seconds=seconds)).isoformat()
        return {"timestamp": timestamp, "agent": {"name": "WIN11-TARGET"},
                "data": {"win": {"system": {"eventID": str(event_id),
                    "systemTime": timestamp}, "eventdata": fields}}}

    if family == "account":
        fields = {"targetUserName": "labuser", "ipAddress": "10.40.0.10",
                  "logonType": "3" if remote else "2"}
        for number in range(index + 1):
            raw_windows.append(win(4625, 1 + number * step, fields))
        for number in range(account_successes):
            raw_windows.append(win(4624, 1 + (index + 1 + number) * step, fields))
        features, raw_windows, _ = _derive_account(
            raw_windows, RunDraft.model_validate(ground_truth), "WIN11-TARGET"
        )
    else:
        nonce = scenario_parameters["run_nonce"]
        raw_windows.append(win(1, .5, {"image": "curl.exe", "processGuid": "fixture-guid",
            "commandLine": f"curl.exe http://10.40.0.10:8080/status?run={nonce}"}))
        offsets = c2_offsets if c2_offsets is not None else [1+i*step for i in range(index+2)]
        for connection, seconds in enumerate(offsets):
            raw_windows.append(win(3, seconds, {"image": "curl.exe", "processGuid": "fixture-guid",
                "initiated": "true", "sourceIp": "10.20.0.10",
                "sourcePort": str(50000 + connection), "protocol": "tcp",
                "destinationIp": "10.40.0.10", "destinationPort": "8080"}))
            timestamp = (started + timedelta(seconds=seconds)).isoformat()
            payload = {"timestamp": timestamp, "event_type": "http", "src_ip": "10.20.0.10",
                "src_port": 50000 + connection, "proto": "TCP",
                "flow_id": f"{run_id}-{connection}",
                "dest_ip": "10.40.0.10", "dest_port": 8080, "http": {"url": f"/status?run={nonce}"}}
            raw_suricata.append({"timestamp": timestamp, "agent": {"name": "NET-SENSOR"},
                                 "full_log": json.dumps(payload)})
        features, raw_windows, _, _ = _derive_c2(
            raw_windows+raw_suricata, RunDraft.model_validate(ground_truth),
            SourceConfig.model_validate(source_payload), {"revision": "test-v1", "rules": []},
        )
    incident["features"] = features
    (run_dir / "incidents.jsonl").write_text(json.dumps(incident) + "\n", encoding="utf-8")

    (evidence_dir / "ground_truth.json").write_text(
        json.dumps(ground_truth),
        encoding="utf-8",
    )
    manifest_hash = hashlib.sha256((run_dir / "scenario_manifest.json").read_bytes()).hexdigest()
    incidents_hash = hashlib.sha256((run_dir / "incidents.jsonl").read_bytes()).hexdigest()
    (evidence_dir / "collection_metadata.json").write_text(
        json.dumps(
            {
                "status": "FINALIZED",
                "run_id": run_id,
                "scenario_manifest_sha256": manifest_hash,
                "incidents_sha256": incidents_hash,
                "collection_seed": index,
                "scenario_parameters": scenario_parameters,
                "run_marker_count": 2,
                "start_contract_sha256": start_contract_sha256,
                **contract_hashes,
                "collection_contract_sha256": collection_contract_sha256,
                "frozen_parameters_sha256": frozen_parameters_sha256,
                "execution_receipt_sha256": hashlib.sha256(
                    receipt_path.read_bytes()
                ).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "wazuh_archives.jsonl").write_text(
        "".join(json.dumps(row)+"\n" for row in raw_windows+raw_suricata), encoding="utf-8")
    (evidence_dir / "windows_events.jsonl").write_text(
        "".join(json.dumps(row)+"\n" for row in raw_windows), encoding="utf-8")
    (evidence_dir / "run_markers.jsonl").write_text(
        json.dumps(
            {
                "event": "START",
                "run_id": run_id,
                "timestamp": started.isoformat(),
                "start_contract_sha256": start_contract_sha256,
            }
        )
        + "\n"
        + json.dumps(
            {
                "event": "END",
                "run_id": run_id,
                "timestamp": ended.isoformat(),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    if family == "c2" and include_suricata:
        from ml.telemetry import suricata_payload

        (evidence_dir / "suricata_eve.jsonl").write_text(
            "".join(json.dumps(suricata_payload(row))+"\n" for row in raw_suricata),
            encoding="utf-8",
        )
    elif family == "account":
        (evidence_dir / "suricata_eve.jsonl").write_text("", encoding="utf-8")
    (evidence_dir / ".collection_state.json").write_text(
        json.dumps(
            {
                "status": "FINALIZED",
                "run_id": run_id,
                "started_at": started.isoformat(),
                "draft": ground_truth,
                "source": source_payload,
                "archive_cursor": archive_cursor,
                "draft_sha256": provenance_sha256,
                "draft_snapshot_sha256": provenance_sha256,
                **contract_hashes,
                "collection_contract_sha256": collection_contract_sha256,
                "frozen_parameters_sha256": frozen_parameters_sha256,
                "start_contract_sha256": start_contract_sha256,
                "execution_receipt": receipt,
            }
        ),
        encoding="utf-8",
    )
    checksums(evidence_dir)


def write_catalog(root: Path) -> Path:
    scenarios = []
    for family in ("account", "c2"):
        for label in ("benign", "malicious"):
            for slot in range(1, 6):
                attribution = (
                    {"account_names": ["labuser"], "logon_types": [2, 3]}
                    if family == "account"
                    else {
                        "source_ips": ["10.20.0.10"],
                        "destination_ips": ["10.40.0.10"],
                    }
                )
                scenarios.append(
                    {
                        "scenario_id": f"{family.upper()}-{label.upper()}-S{slot}",
                        "family": family,
                        "label": label,
                        "expected_behavior": "Controlled test behavior.",
                        "attribution": attribution,
                        "quality_gates": {},
                        "preconditions": ["test"],
                        "execution_steps": ["test"],
                        "expected_observables": ["test"],
                        "cleanup_steps": ["test"],
                    }
                )
    path = root / "scenario-catalog.yaml"
    path.write_text(
        yaml.safe_dump(
            {"version": "scenario-catalog-v1", "lab_only": True, "scenarios": scenarios},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (root / "collection-sources.yaml").write_text(
        "\n".join(
            (
                "version: collection-sources-v1",
                "wazuh_archives_path: /var/ossec/logs/archives/archives.json",
                "windows_agent_name: WIN11-TARGET",
                "suricata_agent_name: NET-SENSOR",
                "taxonomy_path: config/suspicious-process-taxonomy.yaml",
                "scenario_catalog_path: config/scenario-catalog.yaml",
                "",
            )
        ),
        encoding="utf-8",
    )
    (root / "suspicious-process-taxonomy.yaml").write_text(
        "revision: test-v1\nrules: []\n", encoding="utf-8"
    )
    return path


def run_audit(root: Path, **kwargs) -> dict:
    catalog_path = root / "scenario-catalog.yaml"
    if not catalog_path.is_file():
        catalog_path = write_catalog(root)
    return audit_dataset(
        root / "data/raw",
        root / "evidence/scenario-runs",
        scenario_catalog_path=catalog_path,
        source_config_path=root / "collection-sources.yaml",
        taxonomy_path=root / "suspicious-process-taxonomy.yaml",
        minimum_runs=10,
        target_runs=12,
        **kwargs,
    )


def populate(root: Path, count: int = 10) -> None:
    write_catalog(root)
    for family in ("account", "c2"):
        for label in ("benign", "malicious"):
            for index in range(count):
                write_run(
                    root,
                    family=family,
                    label=label,
                    index=index,
                    scenario_slot=(index % 5) + 1,
                )


def test_audit_reports_ready_at_ten_independent_runs_per_stratum(tmp_path: Path) -> None:
    populate(tmp_path, count=10)

    report = run_audit(tmp_path)

    assert report["status"] == "READY"
    assert report["error_count"] == 0
    assert report["total_valid_runs"] == 40
    assert report["strata"]["c2:benign"]["valid_runs"] == 10
    assert report["strata"]["c2:benign"]["shortage_to_target"] == 2


def test_auditor_blocks_individually_valid_runs_that_reuse_a_bucket(tmp_path: Path) -> None:
    write_catalog(tmp_path)
    for label in ("benign", "malicious"):
        write_run(tmp_path, family="account", label=label, index=0, scenario_slot=1, time_slot=0)
    report = run_audit(tmp_path)
    assert report["status"] == "NOT_READY"
    assert report["invalid_run_count"] == 2
    assert any(item["code"] == "BUCKET_REUSE" for item in report["issues"])


def test_auditor_rejects_nonempty_but_meaningless_raw_evidence(tmp_path: Path) -> None:
    write_catalog(tmp_path)
    write_run(tmp_path, family="c2", label="benign", index=0, scenario_slot=1)
    evidence = tmp_path / "evidence/scenario-runs/C2-BENIGN-00"
    (evidence / "windows_events.jsonl").write_text("{}\n", encoding="utf-8")
    (evidence / "wazuh_archives.jsonl").write_text("{}\n", encoding="utf-8")
    checksums(evidence)

    report = run_audit(tmp_path)

    assert report["invalid_run_count"] == 1
    assert any(item["code"] == "FEATURE_PROVENANCE_INVALID" for item in report["issues"])


@pytest.mark.parametrize("filename", [
    "start-contract.json", ".collection_state.json", "ground_truth.json",
    "collection_metadata.json", "execution-parameters.json", "execution_receipt.json",
    "run_markers.jsonl",
])
def test_auditor_reports_wrong_json_document_type_without_crashing(
    tmp_path: Path, filename: str,
) -> None:
    write_catalog(tmp_path)
    write_run(tmp_path, family="account", label="benign", index=0, scenario_slot=1)
    evidence = tmp_path / "evidence/scenario-runs/ACCOUNT-BENIGN-00"
    (evidence / filename).write_text("[]", encoding="utf-8")
    checksums(evidence)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert report["invalid_run_count"] == 1
    assert report["error_count"] > 0


def test_auditor_rejects_a_consistently_rehashed_invalid_bucket(tmp_path: Path) -> None:
    write_catalog(tmp_path)
    write_run(tmp_path, family="account", label="benign", index=0, scenario_slot=1)
    evidence = tmp_path / "evidence/scenario-runs/ACCOUNT-BENIGN-00"
    receipt_path = evidence / "execution_receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["aggregation_window_end"] = "2026-10-16T01:10:00Z"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    state_path = evidence / ".collection_state.json"
    state = json.loads(state_path.read_text())
    state["execution_receipt"] = receipt
    state_path.write_text(json.dumps(state), encoding="utf-8")
    metadata_path = evidence / "collection_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["execution_receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    checksums(evidence)

    report = run_audit(tmp_path)

    assert report["invalid_run_count"] == 1
    assert any(item["code"] == "FEATURE_PROVENANCE_INVALID" for item in report["issues"])


@pytest.mark.parametrize("corruption", ["agent", "eve_alert"])
def test_auditor_reports_malformed_nested_raw_event_without_crashing(
    tmp_path: Path, corruption: str,
) -> None:
    write_catalog(tmp_path)
    write_run(tmp_path, family="c2", label="benign", index=0, scenario_slot=1)
    evidence = tmp_path / "evidence/scenario-runs/C2-BENIGN-00"
    path = evidence / "wazuh_archives.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if corruption == "agent":
        rows[0]["agent"] = "not-an-object"
    else:
        index = next(i for i, row in enumerate(rows) if "full_log" in row)
        payload = json.loads(rows[index]["full_log"])
        payload.update(event_type="alert", alert=["not-an-object"])
        rows[index]["full_log"] = json.dumps(payload)
    path.write_text("".join(json.dumps(row)+"\n" for row in rows), encoding="utf-8")
    checksums(evidence)

    report = run_audit(tmp_path)

    assert report["invalid_run_count"] == 1
    assert any(item["code"] == "FEATURE_PROVENANCE_INVALID" for item in report["issues"])


@pytest.mark.parametrize(
    ("snapshot_name", "hash_field", "old_value", "new_value"),
    [
        (
            "collection-sources.yaml",
            "source_config_sha256",
            "windows_agent_name: WIN11-TARGET",
            "windows_agent_name: UNTRUSTED-AGENT",
        ),
        (
            "suspicious-process-taxonomy.yaml",
            "taxonomy_sha256",
            "revision: test-v1",
            "revision: untrusted-v2",
        ),
    ],
)
def test_audit_rejects_a_run_with_a_different_canonical_contract(
    tmp_path: Path,
    snapshot_name: str,
    hash_field: str,
    old_value: str,
    new_value: str,
) -> None:
    populate(tmp_path, count=10)
    run_id = "ACCOUNT-BENIGN-00"
    run_dir = tmp_path / "data/raw" / run_id
    evidence_dir = tmp_path / "evidence/scenario-runs" / run_id
    contract_snapshot = evidence_dir / snapshot_name
    contract_snapshot.write_text(
        contract_snapshot.read_text(encoding="utf-8").replace(old_value, new_value),
        encoding="utf-8",
    )
    manifest_path = run_dir / "scenario_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[hash_field] = hashlib.sha256(contract_snapshot.read_bytes()).hexdigest()
    contract_hashes = {
        name: manifest[name]
        for name in (
            "source_config_sha256",
            "taxonomy_sha256",
            "scenario_catalog_sha256",
            "feature_schema_sha256",
        )
    }
    manifest["collection_contract_sha256"] = hashlib.sha256(
        json.dumps(contract_hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    start_contract_path = evidence_dir / "start-contract.json"
    start_contract = json.loads(start_contract_path.read_text(encoding="utf-8"))
    start_contract.update(contract_hashes)
    start_contract["collection_contract_sha256"] = manifest[
        "collection_contract_sha256"
    ]
    if hash_field == "source_config_sha256":
        start_contract["source"]["windows_agent_name"] = "UNTRUSTED-AGENT"
    start_contract_path.write_text(json.dumps(start_contract), encoding="utf-8")
    start_contract_sha256 = hashlib.sha256(
        json.dumps(start_contract, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for filename in (".collection_state.json", "collection_metadata.json"):
        path = evidence_dir / filename
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload.update(contract_hashes)
        payload["collection_contract_sha256"] = manifest[
            "collection_contract_sha256"
        ]
        payload["start_contract_sha256"] = start_contract_sha256
        if filename == "collection_metadata.json":
            payload["scenario_manifest_sha256"] = hashlib.sha256(
                manifest_path.read_bytes()
            ).hexdigest()
        elif hash_field == "source_config_sha256":
            payload["source"]["windows_agent_name"] = "UNTRUSTED-AGENT"
        path.write_text(json.dumps(payload), encoding="utf-8")
    marker_path = evidence_dir / "run_markers.jsonl"
    markers = [json.loads(line) for line in marker_path.read_text().splitlines()]
    markers[0]["start_contract_sha256"] = start_contract_sha256
    marker_path.write_text(
        "".join(json.dumps(marker) + "\n" for marker in markers), encoding="utf-8"
    )
    checksums(evidence_dir)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any(
        issue["code"] == "COLLECTION_CONTRACT_INVALID"
        and issue["run_id"] == run_id
        for issue in report["issues"]
    )


def test_audit_reports_exact_shortage_for_sparse_c2_benign(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    sparse = tmp_path / "data/raw/C2-BENIGN-09"
    for path in sparse.iterdir():
        path.unlink()
    sparse.rmdir()
    evidence = tmp_path / "evidence/scenario-runs/C2-BENIGN-09"
    for path in evidence.iterdir():
        path.unlink()
    evidence.rmdir()

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert report["strata"]["c2:benign"]["valid_runs"] == 9
    assert report["strata"]["c2:benign"]["shortage_to_minimum"] == 1


def test_audit_rejects_c2_run_without_suricata_evidence(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    evidence = tmp_path / "evidence/scenario-runs/C2-MALICIOUS-00"
    (evidence / "suricata_eve.jsonl").unlink()
    checksums(evidence)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert report["strata"]["c2:malicious"]["valid_runs"] == 9
    assert any("Suricata" in issue["message"] for issue in report["issues"])


def test_audit_rejects_scenario_concentration_above_thirty_percent(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    for index in range(6):
        manifest_path = tmp_path / f"data/raw/C2-BENIGN-{index:02d}/scenario_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["scenario_id"] = "C2-BENIGN-S1"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        evidence_dir = tmp_path / f"evidence/scenario-runs/C2-BENIGN-{index:02d}"
        metadata_path = evidence_dir / "collection_metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["scenario_manifest_sha256"] = hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        checksums(evidence_dir)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any("maximum is 30.0%" in issue["message"] for issue in report["issues"])


def test_audit_rejects_duplicate_incident_ids_across_runs(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    duplicate = "DUPLICATE-INCIDENT"
    for run_id in ("ACCOUNT-BENIGN-00", "ACCOUNT-BENIGN-01"):
        incident_path = tmp_path / f"data/raw/{run_id}/incidents.jsonl"
        incident = json.loads(incident_path.read_text(encoding="utf-8"))
        incident["incident_id"] = duplicate
        incident_path.write_text(json.dumps(incident) + "\n", encoding="utf-8")

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any("duplicate incident_id" in issue["message"] for issue in report["issues"])


def test_audit_rejects_hidden_incomplete_raw_run(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    incomplete = tmp_path / "data/raw/INCOMPLETE-RUN"
    incomplete.mkdir(parents=True)
    (incomplete / "incidents.jsonl").write_text("{}\n", encoding="utf-8")

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any(issue["code"] == "RAW_RUN_INCOMPLETE" for issue in report["issues"])


def test_audit_rejects_stale_started_collection(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    evidence = tmp_path / "evidence/scenario-runs/STALE-RUN"
    evidence.mkdir(parents=True)
    (evidence / ".collection_state.json").write_text(
        json.dumps({"status": "STARTED", "run_id": "STALE-RUN"}),
        encoding="utf-8",
    )

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any(issue["code"] == "STALE_STARTED_RUN" for issue in report["issues"])


def test_audit_rejects_any_model_feature_that_perfectly_separates_labels(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    for label in ("benign", "malicious"):
        for index in range(10):
            offsets = [1., 1.1, 1.2, 25.] if label == "benign" else [1., 6., 11., 16.]
            write_run(tmp_path, family="c2", label=label, index=index,
                      scenario_slot=index % 5 + 1, c2_offsets=offsets)
    report = run_audit(tmp_path)
    assert report["status"] == "NOT_READY"
    assert any(item["code"] == "FEATURE_LABEL_SEPARATION"
               and "periodicity_score" in item["message"] for item in report["issues"])
    assert not any(item["code"] == "FEATURE_PROVENANCE_INVALID" for item in report["issues"])


def test_audit_rejects_empty_checksum_manifest(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    checksum_path = tmp_path / "evidence/scenario-runs/ACCOUNT-BENIGN-00/checksums.sha256"
    checksum_path.write_text("", encoding="utf-8")

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any("checksum manifest" in issue["message"] for issue in report["issues"])


def test_audit_rejects_catalog_mismatch_and_started_raw_candidate(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    run_id = "ACCOUNT-BENIGN-00"
    manifest_path = tmp_path / f"data/raw/{run_id}/scenario_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["scenario_id"] = "INVENTED-SCENARIO"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    evidence = tmp_path / f"evidence/scenario-runs/{run_id}"
    metadata_path = evidence / "collection_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["scenario_manifest_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    state_path = evidence / ".collection_state.json"
    state_path.write_text(
        json.dumps({"status": "STARTED", "run_id": run_id}), encoding="utf-8"
    )
    checksums(evidence)

    report = run_audit(tmp_path)

    codes = {issue["code"] for issue in report["issues"]}
    assert "SCENARIO_CATALOG_MISMATCH" in codes
    assert "RUN_STATE_INVALID" in codes


def test_audit_requires_even_distribution_at_ten_runs(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    manifest_path = tmp_path / "data/raw/C2-BENIGN-09/scenario_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["scenario_id"] = "C2-BENIGN-S1"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    evidence = tmp_path / "evidence/scenario-runs/C2-BENIGN-09"
    ground_truth_path = evidence / "ground_truth.json"
    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    ground_truth["scenario_id"] = "C2-BENIGN-S1"
    ground_truth_path.write_text(json.dumps(ground_truth), encoding="utf-8")
    manifest["provenance_sha256"] = hashlib.sha256(
        json.dumps(ground_truth, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    metadata_path = evidence / "collection_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["scenario_manifest_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    parameters_path = evidence / "execution-parameters.json"
    parameters = json.loads(parameters_path.read_text(encoding="utf-8"))
    parameters["scenario_id"] = "C2-BENIGN-S1"
    parameters_path.write_text(json.dumps(parameters), encoding="utf-8")
    frozen_digest = hashlib.sha256(
        json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    state_path = evidence / ".collection_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["draft"] = ground_truth
    state["draft_snapshot_sha256"] = manifest["provenance_sha256"]
    state["frozen_parameters_sha256"] = frozen_digest
    state["execution_receipt"]["scenario_id"] = "C2-BENIGN-S1"
    state["execution_receipt"]["frozen_parameters_sha256"] = frozen_digest
    start_contract_path = evidence / "start-contract.json"
    start_contract = json.loads(start_contract_path.read_text(encoding="utf-8"))
    start_contract["draft_snapshot_sha256"] = manifest["provenance_sha256"]
    start_contract["frozen_parameters_sha256"] = frozen_digest
    start_contract_path.write_text(json.dumps(start_contract), encoding="utf-8")
    start_contract_sha256 = hashlib.sha256(
        json.dumps(start_contract, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    state["start_contract_sha256"] = start_contract_sha256
    receipt_path = evidence / "execution_receipt.json"
    receipt_path.write_text(json.dumps(state["execution_receipt"]), encoding="utf-8")
    state_path.write_text(json.dumps(state), encoding="utf-8")
    metadata["frozen_parameters_sha256"] = frozen_digest
    metadata["start_contract_sha256"] = start_contract_sha256
    metadata["execution_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    marker_path = evidence / "run_markers.jsonl"
    markers = [json.loads(line) for line in marker_path.read_text().splitlines()]
    markers[0]["start_contract_sha256"] = start_contract_sha256
    marker_path.write_text(
        "".join(json.dumps(marker) + "\n" for marker in markers), encoding="utf-8"
    )
    checksums(evidence)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any(issue["code"] == "SCENARIO_IMBALANCE" for issue in report["issues"])


def test_audit_rejects_more_than_target_runs(tmp_path: Path) -> None:
    populate(tmp_path, count=13)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any(issue["code"] == "STRATUM_EXCESS" for issue in report["issues"])


def test_audit_detects_low_cardinality_joint_label_separation(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    for label in ("benign", "malicious"):
        for index in range(10):
            success = index % 2
            remote = bool(success if label == "benign" else 1-success)
            write_run(tmp_path, family="account", label=label, index=index,
                      scenario_slot=index % 5 + 1, account_successes=success, remote=remote)
    report = run_audit(tmp_path)
    assert report["status"] == "NOT_READY"
    assert any(item["code"] == "JOINT_FEATURE_LABEL_SEPARATION" for item in report["issues"])
    assert not any(item["code"] == "FEATURE_PROVENANCE_INVALID" for item in report["issues"])


def test_audit_rejects_cross_label_full_vector_collision(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    write_run(tmp_path, family="account", label="malicious", index=0,
              scenario_slot=1, timing_offset=0.)
    report = run_audit(tmp_path)
    assert report["status"] == "NOT_READY"
    collisions = [item for item in report["issues"] if item["code"] == "CROSS_LABEL_COLLISION"]
    assert len(collisions) == 1
    assert "ACCOUNT-BENIGN-00" in collisions[0]["message"]
    assert "ACCOUNT-MALICIOUS-00" in collisions[0]["message"]
    assert not any(item["code"] == "FEATURE_PROVENANCE_INVALID" for item in report["issues"])
