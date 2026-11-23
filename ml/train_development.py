"""Fit an offline development artifact from48 runs and three real host/day groups."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import sklearn
import xgboost
import yaml
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_predict

from ml import development_sources as source
from ml.metrics import classification_metrics, select_threshold
from ml.training import (
    _inner_splits,
    _matrix,
    build_candidates,
    exploratory_summary,
    grouped_calibrated_probabilities,
)
from ml.training_sources import digest


def train(*, root: Path | None = None, expected_commit: str | None = None) -> dict:
    root = source.ROOT if root is None else root.resolve()
    review, head = guard = source.policy(root, require_ready=True)
    config_path = root / source.CONFIG_RELATIVE
    config = yaml.safe_load(config_path.read_bytes())
    processed = root / config["data"]["processed_dir"]
    rows, manifest = source.load_training_data(
        processed, root=root, expected_commit=expected_commit
    )
    schema = json.loads((root / source.SCHEMA_RELATIVE).read_bytes())
    output = (root / config["package_dir"]).resolve()
    if output.exists() or output != root / "ml/development-model-v1":
        raise ValueError("use a fresh development-model-v1 artifact directory")
    models, results = {}, {}
    seed = int(config["random_seed"])
    for family, order in schema["x-family-features"].items():
        x, y, groups = _matrix(rows, family, order)
        if len(x) != 24 or len(set(groups)) != 3 or not np.any(np.ptp(x, axis=0) > 0):
            raise ValueError(
                "development training requires24 nonconstant rows and3 real days/family"
            )
        outer = _inner_splits(y, groups, folds=3, random_seed=seed)
        candidates = build_candidates(config, random_seed=seed)
        candidate_results = {}
        print(f"[development] {family}:3-day grouped selection and nested calibration", flush=True)
        for name, estimator in candidates.items():
            probabilities = cross_val_predict(
                estimator,
                x,
                y,
                cv=outer,
                method="predict_proba",
                n_jobs=1,
            )[:, 1]
            selected = select_threshold(y, probabilities, minimum_precision=0.9)
            candidate_results[name] = dict(
                partition="TRAIN_GROUPED_CV_SELECTION",
                threshold=selected,
                metrics=classification_metrics(y, probabilities, selected["threshold"]),
            )
        selected_name = max(
            candidate_results,
            key=lambda name: (
                candidate_results[name]["metrics"]["pr_auc"],
                candidate_results[name]["metrics"]["f1"],
                -candidate_results[name]["metrics"]["brier"],
            ),
        )
        # Each outer assessment day is excluded from both selection and sigmoid
        # fitting. This estimates a procedure, whose chosen model can vary by fold.
        oof, folds = grouped_calibrated_probabilities(
            candidates,
            x,
            y,
            groups,
            outer_splits=outer,
            folds=3,
            method="sigmoid",
            random_seed=seed,
            minimum_precision=0.9,
            calibration_bins=int(config["selection"]["calibration_bins"]),
        )
        threshold = select_threshold(y, oof, minimum_precision=0.9)
        diagnostic = classification_metrics(
            y,
            oof,
            threshold["threshold"],
            calibration_bins=int(config["selection"]["calibration_bins"]),
        )
        final = CalibratedClassifierCV(
            estimator=clone(candidates[selected_name]),
            method="sigmoid",
            cv=outer,
            ensemble=False,
        )
        final.fit(x, y)
        models[family] = dict(
            estimator=final,
            feature_order=order,
            model_name=selected_name,
            development_threshold=threshold["threshold"],
        )
        results[family] = dict(
            final_model_selected_on="TRAIN_GROUPED_CV",
            selected_model=selected_name,
            independent_host_days=3,
            records=24,
            candidates=candidate_results,
            nested_grouped_cv=folds,
            procedure_oof_probabilities=oof.tolist(),
            procedure_metrics_at_selected_threshold=diagnostic,
            threshold_selection=dict(partition="POOLED_TRAIN_OOF_SELECTION", **threshold),
            interpretation=(
                "Out-of-day development procedure; not external or forward-time assessment"
            ),
            final_model_external_metrics=None,
            confidence_intervals=None,
            uncertainty_status="INSUFFICIENT_EXTERNAL_ASSESSMENT",
            numerical_diagnostics_only=dict(
                precision_at_least_090=diagnostic["precision"] >= 0.9,
                brier_at_most_020=diagnostic["brier"] <= 0.2,
                ece_at_most_015=diagnostic["ece"] <= 0.15,
            ),
            prior_baseline=classification_metrics(y, np.full(len(y), 0.5), 0.5),
            automation_eligible=False,
        )
    if source.policy(root, require_ready=True) != guard:
        raise ValueError("development processing source changed during fitting")
    _, verified_manifest = source.load_training_data(processed, root=root, expected_commit=head)
    if verified_manifest != manifest:
        raise ValueError("development training data changed during fitting")
    stamp = datetime.now(UTC)
    metadata = dict(
        artifact_kind="development-model-v1",
        model_version=stamp.strftime("development-%Y%m%dT%H%M%SZ"),
        trained_at_utc=stamp.isoformat(),
        feature_schema_version=source.SCHEMA_VERSION,
        dataset_hash_sha256=manifest["dataset_hash_sha256"],
        dataset_manifest_payload_sha256=digest(manifest),
        dataset_provenance=manifest["provenance"],
        git_commit=head,
        processing_sha256=review["processing_sha256"],
        training_config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest(),
        random_seed=seed,
        evaluation_protocol=source.PROTOCOL,
        dependency_group_key="evaluation_group_id",
        record_count=48,
        external_validation_status="NOT_COLLECTED",
        locked_test_status="NOT_COLLECTED",
        deployment_eligible=False,
        automation_eligible=False,
        uncertainty_status="INSUFFICIENT_EXTERNAL_ASSESSMENT",
        training_environment=dict(
            python=platform.python_version(),
            sklearn=sklearn.__version__,
            xgboost=xgboost.__version__,
            numpy=np.__version__,
        ),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tmp-development-model-", dir=output.parent) as temp:
        pending = Path(temp) / "complete"
        pending.mkdir()
        joblib.dump(
            dict(artifact_kind="development-model-v1", metadata=metadata, families=models),
            pending / "development_model.joblib",
        )
        for name, document in (
            ("metadata.json", metadata),
            ("metrics_development.json", dict(families=results)),
            ("feature_schema.json", schema),
            ("eda_train.json", exploratory_summary(rows, schema)),
        ):
            (pending / name).write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        if source.policy(root, require_ready=True) != guard:
            raise ValueError("development source changed while exporting")
        pending.rename(output)
    return dict(
        status="DEVELOPMENT_MODEL_TRAINED_REQUIRES_EXTERNAL_ASSESSMENT",
        model_version=metadata["model_version"],
        output=str(output),
        automation_eligible=False,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(train(expected_commit=args.expected_commit), indent=2))


if __name__ == "__main__":
    main()
