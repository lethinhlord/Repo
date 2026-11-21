"""Quality decisions must retain every independent failed acceptance condition."""

import numpy as np

from ml.metrics import quality_gate_failures, training_prior_baseline


def metrics(**changes):
    return {
        "precision": 1.0, "brier": 0.1, "ece": 0.1,
        "uncertainty": {"status": "ESTIMATED"}, **changes,
    }


def gates(result, *, delta=0.0):
    return quality_gate_failures(
        result, minimum_precision=0.9, maximum_brier=0.2,
        maximum_ece=0.15, threshold_delta=delta, maximum_threshold_delta=0.25,
    )


def test_missed_precision_is_retained_even_when_other_quality_gates_fail():
    assert gates(metrics(
        precision=0.5, brier=0.262, ece=0.205,
        uncertainty={"status": "INSUFFICIENT_INDEPENDENT_GROUPS"},
    )) == [
        "minimum_precision_not_met", "insufficient_validation_groups",
        "maximum_brier_exceeded", "maximum_ece_exceeded",
    ]


def test_precision_can_fail_independently_of_calibration_and_stability():
    assert gates(metrics(precision=0.89)) == ["minimum_precision_not_met"]


def test_exact_acceptance_boundaries_are_preserved():
    assert gates(metrics(precision=0.9, brier=0.2, ece=0.15), delta=0.25) == []


def test_stability_gate_remains_independent():
    assert gates(metrics(), delta=0.251) == ["threshold_instability"]


def test_prior_baseline_probability_comes_only_from_training_labels():
    result = training_prior_baseline(
        np.array([0, 0, 0, 1]), np.array([0, 1]), threshold=0.5,
    )
    assert result["fit_partition"] == "train"
    assert result["malicious_probability"] == 0.25
    assert result["metrics"]["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 1, "tp": 0}


def test_f1_for_constant_positive_baseline_exposes_the_c2_failure_mode():
    result = training_prior_baseline(
        np.array([0, 1, 0, 1]), np.array([0, 0, 1, 1]), threshold=0.0,
    )
    assert result["metrics"]["f1"] == 2 / 3
    assert result["metrics"]["fpr"] == 1
    assert result["metrics"]["pr_auc"] == 0.5


def test_written_precision_only_failure_keeps_its_actual_selection_reason(tmp_path, monkeypatch):
    import json

    import yaml
    from sklearn.dummy import DummyClassifier
    from test_training_integrity import prepare_dataset

    import ml.training as training
    from ml.build_dataset import build_dataset

    config_path, _ = prepare_dataset(tmp_path)
    config = yaml.safe_load(config_path.read_text())
    # Isolate precision reporting in this synthetic fixture, not a lab approval.
    config["selection"]["maximum_brier"] = 0.3
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    build_dataset(config_path)
    monkeypatch.setattr(training, "build_candidates", lambda *a, **k: {
        "constant_prior": DummyClassifier(strategy="prior"),
    })
    monkeypatch.setattr(training, "grouped_uncertainty_status", lambda *a: {
        "status": "ESTIMATED",
    })
    training.train(config_path)
    written = json.loads((tmp_path / "ml/model-package/thresholds.json").read_text())
    for family in written["families"].values():
        assert family["gate_failures"] == ["minimum_precision_not_met"]
        assert family["automation_eligible"] is False
        assert family["threshold_selection_reason"] == "precision_target_not_met"
        assert family["selection_reason"] == "precision_target_not_met"
