from __future__ import annotations

import pytest

from ml.dataset import DatasetError, DatasetRecord, assign_grouped_folds
from ml.training import leakage_audit


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
