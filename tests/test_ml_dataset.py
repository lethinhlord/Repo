from __future__ import annotations

import pytest

from ml.dataset import DatasetError, DatasetRecord, assign_grouped_folds
from ml.training import leakage_audit


def record(run_id: str, family: str, label: int, index: int = 0) -> DatasetRecord:
    return DatasetRecord(
        incident_id=f"{run_id}-{index}",
        scenario_id=f"scenario-{family}-{label}",
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

    first = assign_grouped_folds(rows, number_of_folds=5, random_seed=42)
    second = assign_grouped_folds(rows, number_of_folds=5, random_seed=42)

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

    with pytest.raises(DatasetError, match="at least 5 independent runs"):
        assign_grouped_folds(rows, number_of_folds=5, random_seed=42)


def test_leakage_audit_rejects_run_overlap() -> None:
    train = [record("same-run", "account", 0).as_dict()]
    validation = [record("same-run", "account", 0, 1).as_dict()]

    result = leakage_audit(train, validation)

    assert result["passed"] is False
    assert result["checks"]["run_overlap"] == ["same-run"]
