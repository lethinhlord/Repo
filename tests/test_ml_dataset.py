from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ml.build_dataset import build_dataset
from ml.dataset import DatasetError, DatasetRecord, assign_grouped_folds
from ml.training import leakage_audit
from scripts.generate_smoke_dataset import generate

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def record(
    run_id: str,
    family: str,
    label: int,
    index: int = 0,
    *,
    scenario_id: str | None = None,
) -> DatasetRecord:
    return DatasetRecord(
        incident_id=f"{run_id}-{index}",
        scenario_id=scenario_id or f"scenario-{family}-{label}",
        run_id=run_id,
        family=family,
        label=label,
        features={"failed_login_count": float(index), "success_after_fail": float(label)},
        source_file="fixture.jsonl",
    )


def test_grouped_split_keeps_runs_together_and_is_deterministic() -> None:
    rows = [
        record(f"{family}-{label}-{run}", family, label, incident)
        for family in ("account", "c2")
        for label in (0, 1)
        for run in range(5)
        for incident in range(3)
    ]

    first = assign_grouped_folds(
        rows, number_of_folds=5, random_seed=42, group_key="run_id"
    )
    second = assign_grouped_folds(
        rows, number_of_folds=5, random_seed=42, group_key="run_id"
    )

    assert first == second
    assert set(first.values()) == {0, 1, 2, 3, 4}
    assert len(first) == 20


def test_grouped_split_rejects_too_few_independent_runs() -> None:
    rows = [
        record(f"{family}-{label}-{run}", family, label)
        for family in ("account", "c2")
        for label in (0, 1)
        for run in range(4)
    ]

    with pytest.raises(DatasetError, match="at least 5 independent run_id groups"):
        assign_grouped_folds(
            rows, number_of_folds=5, random_seed=42, group_key="run_id"
        )


def test_scenario_grouped_split_keeps_every_scenario_in_one_fold() -> None:
    rows = [
        record(
            f"{family}-{label}-S{scenario}-R{run}",
            family,
            label,
            scenario_id=f"{family}-{label}-S{scenario}",
        )
        for family in ("account", "c2")
        for label in (0, 1)
        for scenario in range(5)
        for run in range(2)
    ]

    folds = assign_grouped_folds(
        rows,
        number_of_folds=5,
        random_seed=42,
        group_key="scenario_id",
    )

    fold_by_scenario: dict[str, set[int]] = {}
    for row in rows:
        fold_by_scenario.setdefault(row.scenario_id, set()).add(folds[row.run_id])
    assert all(len(values) == 1 for values in fold_by_scenario.values())
    assert set(folds.values()) == {0, 1, 2, 3, 4}


def test_scenario_grouped_split_rejects_fewer_scenarios_than_folds() -> None:
    rows = [
        record(
            f"{family}-{label}-S{scenario}-R01",
            family,
            label,
            scenario_id=f"{family}-{label}-S{scenario}",
        )
        for family in ("account", "c2")
        for label in (0, 1)
        for scenario in range(4)
    ]

    with pytest.raises(DatasetError, match="independent scenario_id groups"):
        assign_grouped_folds(
            rows,
            number_of_folds=5,
            random_seed=42,
            group_key="scenario_id",
        )


def test_grouped_split_rejects_unknown_group_key() -> None:
    rows = [record("account-0-0", "account", 0)]

    with pytest.raises(DatasetError, match="group_key must be run_id or scenario_id"):
        assign_grouped_folds(rows, number_of_folds=5, random_seed=42, group_key="host")


def test_leakage_audit_rejects_run_overlap() -> None:
    train = [record("same-run", "account", 0).as_dict()]
    validation = [record("same-run", "account", 0, 1).as_dict()]

    result = leakage_audit(train, validation)

    assert result["passed"] is False
    assert result["checks"]["run_overlap"] == ["same-run"]


def test_leakage_audit_rejects_scenario_overlap_across_distinct_runs() -> None:
    train = [
        record(
            "train-run",
            "account",
            0,
            scenario_id="ACCOUNT-BENIGN-NORMAL-LOGON",
        ).as_dict()
    ]
    validation = [
        record(
            "validation-run",
            "account",
            0,
            scenario_id="ACCOUNT-BENIGN-NORMAL-LOGON",
        ).as_dict()
    ]

    result = leakage_audit(train, validation)

    assert result["passed"] is False
    assert result["checks"]["run_overlap"] == []
    assert result["checks"]["scenario_overlap"] == [
        "ACCOUNT-BENIGN-NORMAL-LOGON"
    ]


def test_build_stops_before_reading_raw_data_when_collection_audit_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = yaml.safe_load(
        (PROJECT_ROOT / "config/training-smoke.yaml").read_text(encoding="utf-8")
    )
    config["feature_schema"] = str(PROJECT_ROOT / "ml/feature_schema.json")
    config["data"].update(
        {
            "raw_dir": str(tmp_path / "missing-raw"),
            "processed_dir": str(tmp_path / "processed"),
            "splits_dir": str(tmp_path / "splits"),
            "require_collection_audit": True,
            "evidence_dir": str(tmp_path / "evidence"),
            "scenario_catalog": str(PROJECT_ROOT / "config/scenario-catalog.yaml"),
            "audit_report": str(tmp_path / "dataset-audit.json"),
            "minimum_runs": 10,
            "target_runs": 12,
        }
    )
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setattr(
        "ml.build_dataset.audit_dataset",
        lambda *args, **kwargs: {"status": "NOT_READY", "error_count": 1},
        raising=False,
    )

    with pytest.raises(ValueError, match="collection audit is not ready"):
        build_dataset(config_path)


def test_public_dataset_manifest_does_not_expose_locked_fold_membership(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    generate(raw_dir)
    config = yaml.safe_load(
        (PROJECT_ROOT / "config/training-smoke.yaml").read_text(encoding="utf-8")
    )
    config["feature_schema"] = str(PROJECT_ROOT / "ml/feature_schema.json")
    config["data"].update(
        {
            "raw_dir": str(raw_dir),
            "processed_dir": str(tmp_path / "processed"),
            "splits_dir": str(tmp_path / "splits"),
            "require_collection_audit": False,
        }
    )
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    manifest = build_dataset(config_path)

    assert "fold_by_run" not in manifest
    assert "split_assignment_commitment_sha256" in manifest
