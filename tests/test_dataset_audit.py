from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

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
    offset = 0.1 if label == "benign" else 0.2
    if family == "account":
        incident["features"]["failed_login_count"] = index + offset
        incident["features"]["success_after_fail"] = float(index % 2)
    else:
        incident["features"]["periodicity_score"] = (index + offset) / 12.0
        incident["features"]["outbound_connection_count"] = float(index + 1)
    (run_dir / "incidents.jsonl").write_text(json.dumps(incident) + "\n", encoding="utf-8")

    evidence_dir = root / "evidence/scenario-runs" / run_id
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "ground_truth.json").write_text(
        json.dumps(
            {
                "scenario_id": manifest["scenario_id"],
                "run_id": run_id,
                "family": family,
                "label": label,
                "host": manifest["host"],
                "expected_behavior": manifest["expected_behavior"],
            }
        ),
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
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "wazuh_archives.jsonl").write_text("{}\n", encoding="utf-8")
    (evidence_dir / "windows_events.jsonl").write_text("{}\n", encoding="utf-8")
    if family == "c2" and include_suricata:
        (evidence_dir / "suricata_eve.jsonl").write_text("{}\n", encoding="utf-8")
    (evidence_dir / ".collection_state.json").write_text(
        json.dumps({"status": "FINALIZED", "run_id": run_id}),
        encoding="utf-8",
    )
    checksums(evidence_dir)


def write_catalog(root: Path) -> Path:
    scenarios = []
    for family in ("account", "c2"):
        for label in ("benign", "malicious"):
            for slot in range(1, 6):
                attribution = (
                    {"account_names": ["labuser"]}
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
    return path


def run_audit(root: Path, **kwargs) -> dict:
    return audit_dataset(
        root / "data/raw",
        root / "evidence/scenario-runs",
        scenario_catalog_path=write_catalog(root),
        minimum_runs=10,
        target_runs=12,
        **kwargs,
    )


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

    report = run_audit(tmp_path)

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


def test_audit_rejects_any_model_feature_that_perfectly_separates_labels(
    tmp_path: Path,
) -> None:
    populate(tmp_path, count=10)
    for label in ("benign", "malicious"):
        for index in range(10):
            run_id = f"C2-{label.upper()}-{index:02d}"
            incident_path = tmp_path / f"data/raw/{run_id}/incidents.jsonl"
            incident = json.loads(incident_path.read_text(encoding="utf-8"))
            incident["features"]["periodicity_score"] = float(label == "malicious")
            incident_path.write_text(json.dumps(incident) + "\n", encoding="utf-8")
            evidence_dir = tmp_path / f"evidence/scenario-runs/{run_id}"
            metadata_path = evidence_dir / "collection_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["incidents_sha256"] = hashlib.sha256(
                incident_path.read_bytes()
            ).hexdigest()
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            checksums(evidence_dir)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    separation = [
        issue for issue in report["issues"] if issue["code"] == "FEATURE_LABEL_SEPARATION"
    ]
    assert len(separation) == 1
    assert "periodicity_score" in separation[0]["message"]


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
    metadata_path = evidence / "collection_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["scenario_manifest_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
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
            run_id = f"ACCOUNT-{label.upper()}-{index:02d}"
            incident_path = tmp_path / f"data/raw/{run_id}/incidents.jsonl"
            incident = json.loads(incident_path.read_text(encoding="utf-8"))
            if label == "benign":
                values = ((0.0, 0.0), (1.0, 1.0))[index % 2]
            else:
                values = ((0.0, 1.0), (1.0, 0.0))[index % 2]
            incident["features"]["failed_login_count"] = values[0]
            incident["features"]["success_after_fail"] = values[1]
            incident_path.write_text(json.dumps(incident) + "\n", encoding="utf-8")
            evidence = tmp_path / f"evidence/scenario-runs/{run_id}"
            metadata_path = evidence / "collection_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["incidents_sha256"] = hashlib.sha256(
                incident_path.read_bytes()
            ).hexdigest()
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            checksums(evidence)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    assert any(issue["code"] == "JOINT_FEATURE_LABEL_SEPARATION" for issue in report["issues"])


def test_audit_rejects_cross_label_full_vector_collision(tmp_path: Path) -> None:
    populate(tmp_path, count=10)
    benign_path = tmp_path / "data/raw/ACCOUNT-BENIGN-00/incidents.jsonl"
    malicious_path = tmp_path / "data/raw/ACCOUNT-MALICIOUS-00/incidents.jsonl"
    benign = json.loads(benign_path.read_text(encoding="utf-8"))
    malicious = json.loads(malicious_path.read_text(encoding="utf-8"))
    malicious["features"] = benign["features"]
    malicious_path.write_text(json.dumps(malicious) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence/scenario-runs/ACCOUNT-MALICIOUS-00"
    metadata_path = evidence / "collection_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["incidents_sha256"] = hashlib.sha256(malicious_path.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    checksums(evidence)

    report = run_audit(tmp_path)

    assert report["status"] == "NOT_READY"
    collisions = [
        issue for issue in report["issues"] if issue["code"] == "CROSS_LABEL_COLLISION"
    ]
    assert len(collisions) == 1
    assert "ACCOUNT-BENIGN-00" in collisions[0]["message"]
    assert "ACCOUNT-MALICIOUS-00" in collisions[0]["message"]
