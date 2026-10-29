"""Progress audits must not confuse expected quota shortage with corrupt evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from ml.dataset_audit import audit_dataset
from scripts import audit_dataset as audit_cli

ROOT = Path(__file__).resolve().parents[1]


def _acceptance_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "progress_audit_acceptance", ROOT / "tests/test_collection_acceptance.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def collection(tmp_path: Path) -> tuple[Path, Path, str, ModuleType, object]:
    helper = _acceptance_helper()
    archive, source, catalog = helper._prepare_collection_root(tmp_path)
    scenario = next(
        row for row in catalog.scenarios if row.family == "account" and row.label == "benign"
    )
    run_id = helper._collect_run(
        tmp_path, archive, source, scenario, sequence=0, repeat=0
    )
    return archive, source, run_id, helper, catalog


def _audit(root: Path, source: Path, **kwargs):
    return audit_dataset(
        root / "data/raw",
        root / "evidence/scenario-runs",
        scenario_catalog_path=root / "config/scenario-catalog.yaml",
        source_config_path=source,
        taxonomy_path=root / "config/suspicious-process-taxonomy.yaml",
        **kwargs,
    )


def test_progress_allows_collecting_after_one_valid_run(tmp_path: Path, collection) -> None:
    _, source, _, _, _ = collection

    report = _audit(tmp_path, source, mode="progress")

    assert report["status"] == "COLLECTING"
    assert report["total_valid_runs"] == 1
    assert report["invalid_run_count"] == 0
    assert report["error_count"] == 0
    assert "STRATUM_SHORTAGE" in {row["code"] for row in report["pending_issues"]}


def test_final_gate_still_rejects_the_same_incomplete_collection(
    tmp_path: Path, collection
) -> None:
    _, source, _, _, _ = collection

    report = _audit(tmp_path, source)

    assert report["status"] == "NOT_READY"
    assert report["error_count"] > 0
    assert "STRATUM_SHORTAGE" in {row["code"] for row in report["issues"]}


@pytest.mark.parametrize("mode", ["progress", "final"])
def test_corrupt_evidence_blocks_both_modes(tmp_path: Path, collection, mode: str) -> None:
    _, source, run_id, _, _ = collection
    evidence = tmp_path / "evidence/scenario-runs" / run_id / "windows_events.jsonl"
    evidence.write_text("{}\n", encoding="utf-8")

    report = _audit(tmp_path, source, mode=mode)

    assert report["status"] == "NOT_READY"
    assert report["error_count"] > 0
    assert report["invalid_run_count"] == 1
    assert any(row["code"] == "RUN_INVALID" for row in report["issues"])


def test_separation_is_pending_until_scenario_coverage_is_collected(
    tmp_path: Path, collection
) -> None:
    archive, source, _, helper, catalog = collection
    malicious = next(
        row for row in catalog.scenarios
        if row.family == "account" and row.label == "malicious"
        and row.quality_gates.min_account_failures >= 1
    )
    helper._collect_run(tmp_path, archive, source, malicious, sequence=1, repeat=0)

    progress = _audit(tmp_path, source, mode="progress")
    final = _audit(tmp_path, source, mode="final")

    assert progress["status"] == "COLLECTING"
    assert progress["error_count"] == 0
    assert "FEATURE_LABEL_SEPARATION" in {
        row["code"] for row in progress["pending_issues"]
    }
    assert final["status"] == "NOT_READY"
    assert "FEATURE_LABEL_SEPARATION" in {row["code"] for row in final["issues"]}


def test_progress_cli_returns_success_without_hiding_shortage(
    tmp_path: Path, collection, monkeypatch
) -> None:
    _, source, _, _, _ = collection
    output = tmp_path / "progress-report.json"
    monkeypatch.setattr(sys, "argv", [
        "audit_dataset",
        "--mode", "progress",
        "--raw-dir", str(tmp_path / "data/raw"),
        "--evidence-dir", str(tmp_path / "evidence/scenario-runs"),
        "--scenario-catalog", str(tmp_path / "config/scenario-catalog.yaml"),
        "--source-config", str(source),
        "--taxonomy", str(tmp_path / "config/suspicious-process-taxonomy.yaml"),
        "--output", str(output),
    ])

    assert audit_cli.main() == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "COLLECTING"
    assert report["strata"]["account:benign"]["shortage_to_minimum"] == 9
