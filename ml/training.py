from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
import xgboost

from ml.dataset import load_config, load_feature_schema, write_json
from ml.metrics import (
    classification_metrics,
    grouped_bootstrap_intervals,
    measure_latency_ms,
    select_threshold,
)
from ml.models import build_candidates


def _read_partition(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"partition does not exist: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _partition_hash(rows: list[dict[str, Any]]) -> set[str]:
    return {
        hashlib.sha256(json.dumps(row, sort_keys=True).encode("utf-8")).hexdigest() for row in rows
    }


def leakage_audit(
    train_rows: list[dict[str, Any]], validation_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    train_runs = {row["run_id"] for row in train_rows}
    validation_runs = {row["run_id"] for row in validation_rows}
    train_incidents = {row["incident_id"] for row in train_rows}
    validation_incidents = {row["incident_id"] for row in validation_rows}
    checks = {
        "run_overlap": sorted(train_runs & validation_runs),
        "incident_overlap": sorted(train_incidents & validation_incidents),
        "exact_row_overlap": sorted(_partition_hash(train_rows) & _partition_hash(validation_rows)),
        "forbidden_training_fields": sorted(
            {key for row in train_rows for key in row["features"]}
            & {"asset_criticality", "asset_score", "ground_truth", "label", "ti_score"}
        ),
    }
    passed = not any(checks.values())
    return {"passed": passed, "checks": checks}


def exploratory_summary(rows: list[dict[str, Any]], schema: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {"records": len(rows), "families": {}}
    for family, feature_order in schema["x-family-features"].items():
        subset = [row for row in rows if row["family"] == family]
        labels = [int(row["label"]) for row in subset]
        feature_stats = {}
        for feature in feature_order:
            values = np.asarray([row["features"][feature] for row in subset], dtype=float)
            q1 = float(np.quantile(values, 0.25))
            q3 = float(np.quantile(values, 0.75))
            iqr = q3 - q1
            feature_stats[feature] = {
                "minimum": float(np.min(values)),
                "q1": q1,
                "median": float(np.median(values)),
                "q3": q3,
                "maximum": float(np.max(values)),
                "missing": 0,
                "distinct": int(len(np.unique(values))),
                "iqr_outlier_count": int(
                    np.sum((values < q1 - 1.5 * iqr) | (values > q3 + 1.5 * iqr))
                ),
            }
        output["families"][family] = {
            "records": len(subset),
            "independent_runs": len({row["run_id"] for row in subset}),
            "benign": labels.count(0),
            "malicious": labels.count(1),
            "features": feature_stats,
        }
    return output


def _matrix(rows: list[dict[str, Any]], family: str, feature_order: list[str]):
    subset = [row for row in rows if row["family"] == family]
    x = np.asarray([[row["features"][name] for name in feature_order] for row in subset])
    y = np.asarray([row["label"] for row in subset], dtype=int)
    groups = np.asarray([row["run_id"] for row in subset])
    if len(np.unique(y)) != 2:
        raise ValueError(f"{family} partition must contain benign and malicious records")
    return x, y, groups


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def train(config_path: Path) -> dict[str, Any]:
    config = load_config(config_path)
    schema = load_feature_schema(Path(config["feature_schema"]))
    processed_dir = Path(config["data"]["processed_dir"])
    package_dir = Path(config["package_dir"])
    if (package_dir / "FROZEN.json").exists():
        raise PermissionError("refusing to overwrite a frozen model package")
    train_rows = _read_partition(processed_dir / "train.jsonl")
    validation_rows = _read_partition(processed_dir / "validation.jsonl")
    audit = leakage_audit(train_rows, validation_rows)
    if not audit["passed"]:
        raise ValueError(f"leakage audit failed: {audit['checks']}")
    eda = exploratory_summary(train_rows, schema)

    artifacts: dict[str, Any] = {}
    all_metrics: dict[str, Any] = {"families": {}}
    threshold_document: dict[str, Any] = {
        "revision": "week3-validation-v1",
        "selection_partition": "validation",
        "families": {},
    }
    for family, feature_order in schema["x-family-features"].items():
        x_train, y_train, _ = _matrix(train_rows, family, feature_order)
        if not np.any(np.ptp(x_train, axis=0) > 0):
            raise ValueError(f"{family} training features are all constant")
        x_validation, y_validation, validation_groups = _matrix(
            validation_rows, family, feature_order
        )
        family_results: dict[str, Any] = {}
        fitted: dict[str, Any] = {}
        for model_name, estimator in build_candidates(
            config, random_seed=int(config["random_seed"])
        ).items():
            if model_name == "xgboost":
                positives = int(np.sum(y_train == 1))
                negatives = int(np.sum(y_train == 0))
                estimator.set_params(scale_pos_weight=negatives / positives)
            estimator.fit(x_train, y_train)
            probabilities = estimator.predict_proba(x_validation)[:, 1]
            threshold = select_threshold(
                y_validation,
                probabilities,
                minimum_precision=float(config["selection"]["minimum_precision"]),
            )
            metrics = classification_metrics(y_validation, probabilities, threshold["threshold"])
            metrics["confidence_intervals"] = grouped_bootstrap_intervals(
                y_validation,
                probabilities,
                validation_groups,
                threshold["threshold"],
                iterations=int(config["selection"]["bootstrap_iterations"]),
                confidence=float(config["selection"]["bootstrap_confidence"]),
                random_seed=int(config["random_seed"]),
            )
            metrics["latency"] = measure_latency_ms(
                lambda estimator=estimator, matrix=x_validation: estimator.predict_proba(matrix)[
                    :, 1
                ],
                repeats=int(config["selection"]["latency_repeats"]),
            )
            family_results[model_name] = {"threshold": threshold, "metrics": metrics}
            fitted[model_name] = estimator
        selected_name = max(
            family_results,
            key=lambda name: (
                family_results[name]["threshold"]["automation_eligible"],
                family_results[name]["metrics"]["pr_auc"],
                family_results[name]["metrics"]["f1"],
                -family_results[name]["metrics"]["fpr"],
                -family_results[name]["metrics"]["latency"]["p95_per_record_ms"],
            ),
        )
        selected_threshold = family_results[selected_name]["threshold"]
        artifacts[family] = {
            "estimator": fitted[selected_name],
            "feature_order": feature_order,
            "threshold": selected_threshold["threshold"],
            "model_name": selected_name,
        }
        threshold_document["families"][family] = {
            "model_name": selected_name,
            **selected_threshold,
        }
        all_metrics["families"][family] = {
            "selected_model": selected_name,
            "candidates": family_results,
        }

    manifest = json.loads((processed_dir / "dataset_manifest.json").read_text(encoding="utf-8"))
    trained_at = datetime.now(UTC)
    metadata = {
        "model_version": f"week3-{trained_at.strftime('%Y%m%dT%H%M%SZ')}",
        "feature_schema_version": schema["version"],
        "training_timestamp_utc": trained_at.isoformat(),
        "dataset_hash_sha256": manifest["dataset_hash_sha256"],
        "training_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "random_seed": int(config["random_seed"]),
        "git_commit": _git_commit(),
        "locked_test_status": "UNOPENED",
        "selection_partition": "validation",
        "partition_record_counts": manifest["record_counts"],
        "libraries": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "numpy": np.__version__,
        },
    }
    package_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"metadata": metadata, "families": artifacts}, package_dir / "model.joblib")
    write_json(package_dir / "thresholds.json", threshold_document)
    write_json(package_dir / "metadata.json", metadata)
    write_json(package_dir / "metrics_validation.json", all_metrics)
    write_json(package_dir / "eda_train.json", eda)
    write_json(package_dir / "leakage_audit.json", audit)
    return metadata
