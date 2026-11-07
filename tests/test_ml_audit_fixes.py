import hashlib
import json

import joblib
import numpy as np
import pytest
from test_ml_package import SIGNING_KEY, account_features, c2_features, create_package
from test_training_integrity import prepare_dataset

from ml.evaluate import evaluate_locked_test
from ml.freeze_model import freeze
from ml.inference import ModelRuntime
from ml.metrics import classification_metrics, expected_calibration_error
from ml.training import train


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", SIGNING_KEY)


@pytest.mark.parametrize(
    "field,value", [("builder_git_commit", "a" * 40), ("builder_config_sha256", "0" * 64)]
)
def test_training_provenance_rejected_before_partition_read(tmp_path, field, value):
    config, _ = prepare_dataset(tmp_path)
    path = tmp_path / "processed/dataset_manifest.json"
    manifest = json.loads(path.read_text())
    manifest["provenance"][field] = value
    path.write_text(json.dumps(manifest))
    (tmp_path / "processed/train.jsonl").unlink()
    with pytest.raises(ValueError, match="builder.*(commit|config)"):
        train(config)


def test_ece_uses_configured_bin_policy():
    labels = np.array([0, 1, 0, 1, 1, 0])
    probabilities = np.array([0.11, 0.19, 0.31, 0.39, 0.51, 0.59])
    result = classification_metrics(labels, probabilities, 0.5, calibration_bins=5)
    assert result["ece"] == expected_calibration_error(labels, probabilities, bins=5)
    assert result["calibration_bins"] == 5


def test_freeze_is_idempotent_and_never_resigns_changed_artifacts(tmp_path):
    package = tmp_path / "package"
    create_package(package)
    first = freeze(package)
    before = (package / "FROZEN.json").read_bytes()
    assert freeze(package) == first
    assert (package / "FROZEN.json").read_bytes() == before
    (package / "metrics_validation.json").write_text('{"changed":true}')
    with pytest.raises(ValueError, match="integrity"):
        freeze(package)
    assert (package / "FROZEN.json").read_bytes() == before


@pytest.mark.parametrize("fault", ["threshold", "family", "version", "nan"])
def test_evaluation_preflight_precedes_reservation_and_test_read(tmp_path, fault):
    package = tmp_path / "package"
    create_package(package)
    bundle = joblib.load(package / "model.joblib")
    if fault == "threshold":
        bundle["families"]["account"]["threshold"] = 0.7
    elif fault == "family":
        del bundle["families"]["c2"]
    elif fault == "nan":
        bundle["families"]["account"]["threshold"] = float("nan")
    else:
        bundle["metadata"]["model_version"] = "different"
    joblib.dump(bundle, package / "model.joblib")
    freeze(package)
    with pytest.raises(
        (ValueError, RuntimeError, PermissionError), match="threshold|families|versions"
    ):
        evaluate_locked_test(package, tmp_path / "DOES_NOT_EXIST", unlock_locked_test=True)
    assert not (package / "LOCKED_TEST_RESERVED").exists()


def prepared_locked(tmp_path):
    package = tmp_path / "package"
    create_package(package)
    locked = tmp_path / "locked.jsonl"
    rows = [
        {"family": "account", "label": 0, "features": account_features(0, 0)},
        {"family": "account", "label": 1, "features": account_features(20, 1)},
        {"family": "c2", "label": 0, "features": c2_features(0)},
        {"family": "c2", "label": 1, "features": c2_features(1)},
    ]
    locked.write_text("".join(json.dumps(row) + "\n" for row in rows))
    metadata = json.loads((package / "metadata.json").read_text())
    metadata["locked_test_sha256"] = hashlib.sha256(locked.read_bytes()).hexdigest()
    (package / "metadata.json").write_text(json.dumps(metadata))
    bundle = joblib.load(package / "model.joblib")
    bundle["metadata"] = metadata
    joblib.dump(bundle, package / "model.joblib")
    freeze(package)
    return package, locked


def test_external_evidence_preserves_release_and_is_write_once(tmp_path):
    package, locked = prepared_locked(tmp_path)
    original = {p.name: p.read_bytes() for p in package.iterdir()}
    evidence = tmp_path / "evidence"
    result = evaluate_locked_test(package, locked, unlock_locked_test=True, evidence_dir=evidence)
    assert result["locked_test_status"] == "EVALUATED"
    assert {p.name: p.read_bytes() for p in package.iterdir()} == original
    assert ModelRuntime(package, evidence_dir=evidence).locked_test_status == "EVALUATED"
    with pytest.raises(PermissionError, match="already"):
        evaluate_locked_test(package, locked, unlock_locked_test=True, evidence_dir=evidence)
    freeze_before = (package / "FROZEN.json").read_bytes()
    freeze(package)
    assert (package / "FROZEN.json").read_bytes() == freeze_before
    assert ModelRuntime(package, evidence_dir=evidence).locked_test_status == "EVALUATED"
    opened = next(evidence.rglob("LOCKED_TEST_OPENED.json"))
    document = json.loads(opened.read_text())
    document["evaluated_at_utc"] = "tampered"
    opened.write_text(json.dumps(document))
    with pytest.raises(RuntimeError, match="signature|integrity"):
        ModelRuntime(package, evidence_dir=evidence)


def test_key_rotation_retains_original_manifest_and_opening(tmp_path, monkeypatch):
    package, locked = prepared_locked(tmp_path)
    evaluate_locked_test(package, locked, unlock_locked_test=True)
    original = (package / "FROZEN.json").read_bytes()
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", "new-key-for-next-packages-at-least-32-bytes")
    monkeypatch.setenv("MODEL_PACKAGE_VERIFICATION_KEYS", json.dumps([SIGNING_KEY]))
    freeze(package)
    assert (package / "FROZEN.json").read_bytes() == original
    assert ModelRuntime(package).locked_test_status == "EVALUATED"


def test_nested_threshold_probabilities_are_calibrated_without_outer_group_leakage():
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.linear_model import LogisticRegression

    import ml.training as training

    groups = np.repeat(np.arange(12), 4)
    labels = np.repeat(np.arange(12) % 2, 4)
    x = np.column_stack([labels * 3 + np.tile([-0.2, -0.1, 0.1, 0.2], 12), groups / 100])
    estimator = LogisticRegression(C=0.001)
    outer = training._inner_splits(labels, groups, folds=3, random_seed=42)
    actual, audit = training.grouped_calibrated_probabilities(
        estimator,
        x,
        labels,
        groups,
        outer_splits=outer,
        folds=3,
        method="sigmoid",
        random_seed=42,
    )
    expected = np.empty(len(labels))
    for fitted, heldout in outer:
        inner = training._inner_splits(labels[fitted], groups[fitted], folds=3, random_seed=42)
        model = CalibratedClassifierCV(
            estimator=estimator, method="sigmoid", cv=inner, ensemble=False
        )
        model.fit(x[fitted], labels[fitted])
        expected[heldout] = model.predict_proba(x[heldout])[:, 1]
    np.testing.assert_allclose(actual, expected)
    assert audit["probability_scale"] == "calibrated_probability"
    for fold in audit["folds"]:
        assert not set(fold["fit_groups"]) & set(fold["assessment_groups"])
        for inner in fold["calibration_folds"]:
            assert not set(inner["fit_groups"]) & set(inner["assessment_groups"])
            assert set(inner["fit_groups"] + inner["assessment_groups"]) <= set(fold["fit_groups"])


@pytest.mark.parametrize("fault", ["calibration_bins", "profile_bounds"])
def test_invalid_metric_and_ood_policy_rejected_before_test_open(tmp_path, fault):
    package = tmp_path / "package"
    create_package(package)
    if fault == "calibration_bins":
        path = package / "metadata.json"
        document = json.loads(path.read_text())
        document["calibration_bins"] = 1
    else:
        path = package / "feature_profile.json"
        document = json.loads(path.read_text())
        document["families"]["account"]["features"]["failed_login_count"]["ood_lower"] = float(
            "nan"
        )
    path.write_text(json.dumps(document))
    freeze(package)
    with pytest.raises(RuntimeError, match="calibration|profile"):
        evaluate_locked_test(package, tmp_path / "ABSENT", unlock_locked_test=True)
    assert not (package / "LOCKED_TEST_RESERVED").exists()
