from __future__ import annotations

import numpy as np

from ml.metrics import classification_metrics, grouped_bootstrap_intervals, select_threshold


def test_threshold_selection_prioritizes_precision_constraint_then_recall() -> None:
    labels = np.asarray([0, 0, 0, 1, 1, 1])
    probabilities = np.asarray([0.1, 0.2, 0.65, 0.7, 0.8, 0.9])

    result = select_threshold(labels, probabilities, minimum_precision=1.0)

    assert result["automation_eligible"] is True
    assert result["threshold"] == 0.7
    assert result["recall"] == 1.0


def test_threshold_falls_back_to_assisted_when_target_is_impossible() -> None:
    labels = np.asarray([0, 0, 1, 1])
    probabilities = np.asarray([0.9, 0.8, 0.7, 0.6])

    result = select_threshold(labels, probabilities, minimum_precision=1.01)

    assert result["automation_eligible"] is False
    assert result["selection_reason"] == "precision_target_not_met"


def test_metrics_include_false_positive_rate_and_group_uncertainty() -> None:
    labels = np.asarray([0, 0, 1, 1, 0, 1])
    probabilities = np.asarray([0.1, 0.2, 0.8, 0.9, 0.3, 0.7])
    groups = np.asarray(["a", "a", "b", "b", "c", "c"])

    metrics = classification_metrics(labels, probabilities, 0.5)
    intervals = grouped_bootstrap_intervals(
        labels,
        probabilities,
        groups,
        0.5,
        iterations=30,
        confidence=0.95,
        random_seed=42,
    )

    assert metrics["fpr"] == 0.0
    assert metrics["confusion_matrix"] == {"tn": 3, "fp": 0, "fn": 0, "tp": 3}
    assert set(intervals) == {"precision", "recall", "f1", "pr_auc", "fpr", "brier"}
