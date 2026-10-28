from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def select_threshold(
    labels: np.ndarray,
    probabilities: np.ndarray,
    *,
    minimum_precision: float,
) -> dict[str, Any]:
    candidates = sorted({0.0, 1.0, *map(float, probabilities)})
    rows = []
    for threshold in candidates:
        predictions = (probabilities >= threshold).astype(int)
        rows.append(
            {
                "threshold": threshold,
                "precision": precision_score(labels, predictions, zero_division=0),
                "recall": recall_score(labels, predictions, zero_division=0),
                "f1": f1_score(labels, predictions, zero_division=0),
            }
        )
    eligible = [row for row in rows if row["precision"] >= minimum_precision]
    if eligible:
        selected = max(
            eligible,
            key=lambda row: (row["recall"], row["f1"], row["precision"], row["threshold"]),
        )
        automation_eligible = True
        reason = "precision_target_met"
    else:
        selected = max(rows, key=lambda row: (row["f1"], row["precision"], row["recall"]))
        automation_eligible = False
        reason = "precision_target_not_met"
    return {
        **selected,
        "minimum_precision": minimum_precision,
        "automation_eligible": automation_eligible,
        "selection_reason": reason,
    }


def classification_metrics(
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
        "f1": f1_score(labels, predictions, zero_division=0),
        "pr_auc": average_precision_score(labels, probabilities),
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "brier": brier_score_loss(labels, probabilities),
        "ece": expected_calibration_error(labels, probabilities),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def reliability_curve(
    labels: np.ndarray, probabilities: np.ndarray, *, bins: int = 10
) -> list[dict[str, float | int]]:
    if bins < 2:
        raise ValueError("reliability curve requires at least two bins")
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows: list[dict[str, float | int]] = []
    for index in range(bins):
        lower = float(edges[index])
        upper = float(edges[index + 1])
        mask = (probabilities >= lower) & (
            probabilities <= upper if index == bins - 1 else probabilities < upper
        )
        count = int(np.sum(mask))
        if count == 0:
            continue
        rows.append(
            {
                "lower": lower,
                "upper": upper,
                "count": count,
                "mean_probability": float(np.mean(probabilities[mask])),
                "observed_frequency": float(np.mean(labels[mask])),
            }
        )
    return rows


def expected_calibration_error(
    labels: np.ndarray, probabilities: np.ndarray, *, bins: int = 10
) -> float:
    curve = reliability_curve(labels, probabilities, bins=bins)
    total = max(len(labels), 1)
    return float(
        sum(
            row["count"]
            / total
            * abs(row["observed_frequency"] - row["mean_probability"])
            for row in curve
        )
    )


def grouped_bootstrap_intervals(
    labels: np.ndarray,
    probabilities: np.ndarray,
    groups: np.ndarray,
    threshold: float,
    *,
    iterations: int,
    confidence: float,
    random_seed: int,
) -> dict[str, dict[str, float | None]]:
    samples: dict[str, list[float]] = {
        name: []
        for name in ("precision", "recall", "f1", "pr_auc", "fpr", "brier", "ece")
    }
    if grouped_uncertainty_status(labels, groups)["status"] != "ESTIMATED":
        return {name: {"low": None, "high": None} for name in samples}
    unique_groups = np.unique(groups)
    rng = np.random.default_rng(random_seed)
    for _ in range(iterations):
        selected_groups = rng.choice(unique_groups, size=len(unique_groups), replace=True)
        selected_indices = np.concatenate(
            [np.flatnonzero(groups == group) for group in selected_groups]
        )
        sample_labels = labels[selected_indices]
        if len(np.unique(sample_labels)) < 2:
            continue
        result = classification_metrics(
            sample_labels,
            probabilities[selected_indices],
            threshold,
        )
        for name in samples:
            samples[name].append(float(result[name]))
    alpha = (1.0 - confidence) / 2.0
    intervals: dict[str, dict[str, float | None]] = {}
    for name, values in samples.items():
        if not values:
            intervals[name] = {"low": None, "high": None}
        else:
            intervals[name] = {
                "low": float(np.quantile(values, alpha)),
                "high": float(np.quantile(values, 1.0 - alpha)),
            }
    return intervals


def grouped_uncertainty_status(labels: np.ndarray, groups: np.ndarray) -> dict[str, Any]:
    """Do not turn repeated runs of two templates into false precision."""
    minimum = 3
    counts = {
        str(label): int(len(np.unique(groups[labels == label]))) for label in (0, 1)
    }
    enough = all(count >= minimum for count in counts.values())
    return {
        "status": "ESTIMATED" if enough else "INSUFFICIENT_INDEPENDENT_GROUPS",
        "minimum_groups_per_label": minimum,
        "observed_groups_per_label": counts,
        "reason": (
            "group_bootstrap" if enough
            else "at least three independent validation scenarios per label are required"
        ),
    }


def measure_latency_ms(
    predict_probability: Callable[[], np.ndarray], *, repeats: int
) -> dict[str, float]:
    durations = []
    for _ in range(repeats):
        started = time.perf_counter_ns()
        probabilities = predict_probability()
        elapsed = time.perf_counter_ns() - started
        durations.append(elapsed / max(len(probabilities), 1) / 1_000_000)
    return {
        "median_per_record_ms": float(np.median(durations)),
        "p95_per_record_ms": float(np.quantile(durations, 0.95)),
        "repeats": repeats,
    }
