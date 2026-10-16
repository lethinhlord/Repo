from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ml.dataset_audit import audit_dataset

FEATURES = {
    "failed_login_count": 0.0,
    "success_after_fail": 0.0,
    "suspicious_process": 0.0,
    "periodicity_score": 0.0,
    "suricata_alert_count": 0.0,
    "outbound_connection_count": 1.0,
    "destination_port_count": 1.0,
}


def checksums(directory: Path) -> None:
    rows = []
    files = (
        path
        for path in directory.iterdir()
        if path.is_file() and path.name != "checksums.sha256"
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
) -> None:
    run_id = f"{family.upper()}-{label.upper()}-{index:02d}"
    started = datetime(2026, 10, 16, 1, 0, tzinfo=UTC) + timedelta(minutes=index)
    ended = started + timedelta(seconds=30)
    run_dir = root / "data/raw" / run_id
    run_dir.mkdir(parents=True)
    manifest = {
        "scenario_id": f"{family.upper()}-{label.upper()}-S{scenario_slot}",
        "run_id": run_id,
        "family": family,
        "label": label,
        "host": "WIN11-TARGET",
        "start_time": started.isoformat(),
        "end_time": ended.isoformat(),
        "expected_behavior": "Controlled lab activity.",
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
    (run_dir / "incidents.jsonl").write_text(json.dumps(incident) + "\n", encoding="utf-8")

    evidence_dir = root / "evidence/scenario-runs" / run_id
    evidence_dir.mkdir(parents=True)
    manifest_hash = hashlib.sha256((run_dir / "scenario_manifest.json").read_bytes()).hexdigest()
    incidents_hash = hashlib.sha256((run_dir / "incidents.jsonl").read_bytes()).hexdigest()
    (evidence_dir / "collection_metadata.json").write_text(
        json.dumps(
            {
                "status": "FINALIZED",
                "run_id": run_id,
                "scenario_manifest_sha256": manifest_hash,
                "incidents_sha256": incidents_hash,
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "wazuh_archives.jsonl").write_text("{}\n", encoding="utf-8")
    (evidence_dir / "windows_events.jsonl").write_text("{}\n", encoding="utf-8")
    if family == "c2" and include_suricata:
        (evidence_dir / "suricata_eve.jsonl").write_text("{}\n", encoding="utf-8")
    checksums(evidence_dir)


def populate(root: Path, count: int = 10) -> None:
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

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

    assert report["status"] == "READY"
    assert report["error_count"] == 0
    assert report["total_valid_runs"] == 40
    assert report["strata"]["c2:benign"]["valid_runs"] == 10
    assert report["strata"]["c2:benign"]["shortage_to_target"] == 2


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

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

    assert report["status"] == "NOT_READY"
    assert report["strata"]["c2:benign"]["valid_runs"] == 9
    assert report["strata"]["c2:benign"]["shortage_to_minimum"] == 1


def test_audit_rejects_c2_run_without_suricata_evidence(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    evidence = tmp_path / "evidence/scenario-runs/C2-MALICIOUS-00"
    (evidence / "suricata_eve.jsonl").unlink()
    checksums(evidence)

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

    assert report["status"] == "NOT_READY"
    assert report["strata"]["c2:malicious"]["valid_runs"] == 9
    assert any("Suricata" in issue["message"] for issue in report["issues"])


def test_audit_rejects_scenario_concentration_above_thirty_percent(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    for index in range(6):
        manifest_path = tmp_path / f"data/raw/C2-BENIGN-{index:02d}/scenario_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["scenario_id"] = "C2-BENIGN-DOMINANT"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        evidence_dir = tmp_path / f"evidence/scenario-runs/C2-BENIGN-{index:02d}"
        metadata_path = evidence_dir / "collection_metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["scenario_manifest_sha256"] = hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        checksums(evidence_dir)

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

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

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

    assert report["status"] == "NOT_READY"
    assert any("duplicate incident_id" in issue["message"] for issue in report["issues"])


def test_audit_rejects_hidden_incomplete_raw_run(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    incomplete = tmp_path / "data/raw/INCOMPLETE-RUN"
    incomplete.mkdir(parents=True)
    (incomplete / "incidents.jsonl").write_text("{}\n", encoding="utf-8")

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

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

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

    assert report["status"] == "NOT_READY"
    assert any(issue["code"] == "STALE_STARTED_RUN" for issue in report["issues"])


def test_audit_rejects_suricata_alert_feature_that_perfectly_separates_labels(
    tmp_path: Path,
) -> None:
    populate(tmp_path, count=10)
    for label in ("benign", "malicious"):
        for index in range(10):
            run_id = f"C2-{label.upper()}-{index:02d}"
            incident_path = tmp_path / f"data/raw/{run_id}/incidents.jsonl"
            incident = json.loads(incident_path.read_text(encoding="utf-8"))
            incident["features"]["suricata_alert_count"] = float(label == "malicious")
            incident_path.write_text(json.dumps(incident) + "\n", encoding="utf-8")
            evidence_dir = tmp_path / f"evidence/scenario-runs/{run_id}"
            metadata_path = evidence_dir / "collection_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["incidents_sha256"] = hashlib.sha256(
                incident_path.read_bytes()
            ).hexdigest()
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            checksums(evidence_dir)

    report = audit_dataset(
        tmp_path / "data/raw",
        tmp_path / "evidence/scenario-runs",
        minimum_runs=10,
        target_runs=12,
    )

    assert report["status"] == "NOT_READY"
    assert any(
        issue["code"] == "FEATURE_LABEL_SEPARATION" for issue in report["issues"]
    )
