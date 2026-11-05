from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from test_collection_acceptance import _collect_run, _prepare_collection_root

from ml.scenario_collection import CollectionError


def verifier():
    path = Path(__file__).resolve().parents[1] / "scripts/verify_run_evidence.py"
    assert path.is_file()
    spec = importlib.util.spec_from_file_location("supplementary_verifier", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_supplementary_checks_accept_complete_synthetic_run_without_mutating(tmp_path: Path):
    module = verifier()
    archive, source, catalog = _prepare_collection_root(tmp_path)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == "ACCOUNT-BENIGN-NORMAL-LOGON")
    run_id = _collect_run(tmp_path, archive, source, scenario, sequence=0, repeat=0)
    before = {p: p.read_bytes() for p in (tmp_path / "evidence/scenario-runs" / run_id).iterdir()}
    report = module.verify_run_evidence(run_id, tmp_path)
    assert report["status"] == "RUN_EVIDENCE_CHECK_PASS"
    assert report["collector_validation"]["status"] == "VALID"
    assert report["enrollment_clock_issue_count"] == 0
    assert all(p.read_bytes() == raw for p, raw in before.items())


def test_supplementary_checks_require_original_dataset_files(tmp_path: Path):
    module = verifier()
    archive, source, catalog = _prepare_collection_root(tmp_path)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == "ACCOUNT-BENIGN-NORMAL-LOGON")
    run_id = _collect_run(tmp_path, archive, source, scenario, sequence=0, repeat=0)
    (tmp_path / "data/raw" / run_id / "incidents.jsonl").unlink()
    with pytest.raises(CollectionError, match="checksum mismatch for dataset file"):
        module.verify_run_evidence(run_id, tmp_path)


def test_legacy_bad_destination_history_prevents_whole_pilot_acceptance(tmp_path: Path):
    module = verifier()
    archive, source, catalog = _prepare_collection_root(tmp_path)
    baseline_path = tmp_path / "evidence/context-baseline.json"
    baseline = json.loads(baseline_path.read_text())
    capture_dir = tmp_path / "evidence/context-captures"
    capture = capture_dir / (baseline["source_capture_sha256"] + ".jsonl")
    rows = [json.loads(line) for line in capture.read_text().splitlines()]
    network = next(row for row in rows if row["data"]["win"]["system"]["eventID"] == "3")
    network["data"]["win"]["system"]["providerName"] = "Microsoft-Windows-Sysmon"
    network["data"]["win"]["eventdata"]["utcTime"] = "2020-01-01 00:00:00.000"
    raw = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    # Emulate a byte-consistent legacy baseline, before starting the new synthetic
    # account run. Do not relax source checks or edit any finalized evidence.
    (capture_dir / f"{digest}.jsonl").write_bytes(raw)
    baseline["source_capture_sha256"] = digest
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    scenario = next(s for s in catalog.scenarios if s.scenario_id == "ACCOUNT-BENIGN-NORMAL-LOGON")
    run_id = _collect_run(tmp_path, archive, source, scenario, sequence=0, repeat=0)
    report = module.verify_run_evidence(run_id, tmp_path)
    assert report["collector_validation"]["status"] == "VALID"
    assert report["status"] == "RUN_EVIDENCE_CHECK_REVIEW"
    assert report["enrollment_clock_issue_count"] == 1
    assert report["enrollment_clock_issue_examples"][0]["reasons"] == [
        "clock:sysmon_timestamp_mismatch",
    ]
