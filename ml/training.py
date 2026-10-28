from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
import xgboost
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict

from ml.dataset import (
    DatasetRecord,
    load_config,
    load_feature_schema,
    validate_feature_contract,
    write_json,
)
from ml.metrics import (
    classification_metrics,
    grouped_bootstrap_intervals,
    grouped_uncertainty_status,
    measure_latency_ms,
    reliability_curve,
    select_threshold,
)
from ml.models import build_candidates


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_training_partitions(
    processed_dir: Path,
    schema_path: Path,
    *,
    require_collection_audit: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Validate the builder's contract without reading the locked-test partition."""
    manifest = json.loads((processed_dir / "dataset_manifest.json").read_text(encoding="utf-8"))
    schema_bytes = schema_path.read_bytes()
    schema = json.loads(schema_bytes)
    if not isinstance(manifest, dict) or not isinstance(schema, dict):
        raise ValueError("dataset manifest and feature schema must be mappings")
    if (
        manifest.get("manifest_version") != "dataset-manifest-v2"
        or manifest.get("group_key") != "scenario_id"
        or manifest.get("locked_test_status") != "UNOPENED"
        or manifest.get("feature_schema_version") != schema.get("version")
        or manifest.get("feature_schema_sha256") != hashlib.sha256(schema_bytes).hexdigest()
        or not _is_sha256(manifest.get("dataset_hash_sha256"))
        or not _is_sha256(manifest.get("locked_test_sha256"))
    ):
        raise ValueError(
            "dataset manifest integrity/schema contract is invalid; rebuild partitions"
        )
    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict) or not _is_sha256(
        provenance.get("builder_config_sha256")
    ) or not provenance.get("builder_git_commit"):
        raise ValueError("dataset builder provenance is missing or invalid")
    collection = manifest.get("collection_audit", {})
    if require_collection_audit and (
        not isinstance(collection, dict)
        or collection.get("status") not in {"READY", "TARGET_MET"}
        or not _is_sha256(collection.get("report_sha256"))
        or provenance.get("collection_mode") != "REAL_LAB"
        or not _is_sha256(provenance.get("collection_contract_sha256"))
        or collection.get("collection_contract_sha256")
        != provenance.get("collection_contract_sha256")
    ):
        raise ValueError("dataset collection audit provenance is missing or not ready")
    verified: dict[str, list[dict[str, Any]]] = {}
    partitions = manifest.get("partitions")
    record_counts = manifest.get("record_counts")
    if not isinstance(partitions, dict) or not isinstance(record_counts, dict):
        raise ValueError("partition integrity contract is missing")
    locked_contract = partitions.get("locked_test")
    if not isinstance(locked_contract, dict) or locked_contract.get("sha256") != manifest.get(
        "locked_test_sha256"
    ):
        raise ValueError("locked-test commitment is inconsistent; do not open the test")
    for name in ("train", "validation"):
        contract = partitions.get(name)
        payload = (processed_dir / f"{name}.jsonl").read_bytes()
        if not isinstance(contract, dict) or hashlib.sha256(payload).hexdigest() != contract.get(
            "sha256"
        ):
            raise ValueError(f"{name} partition integrity check failed")
        rows = [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]
        if not rows or len(rows) != contract.get("record_count") or len(rows) != record_counts.get(
            name
        ):
            raise ValueError(f"{name} partition record count integrity check failed")
        try:
            records = [DatasetRecord(**row) for row in rows]
            if any(
                record.family not in schema["x-family-features"]
                or type(record.label) is not int
                or record.label not in {0, 1}
                or any(not math.isfinite(float(value)) for value in record.features.values())
                for record in records
            ):
                raise ValueError("invalid family/label/non-finite feature")
            validate_feature_contract(records, schema)
        except (TypeError, KeyError, ValueError) as exc:
            raise ValueError(f"{name} partition feature contract is invalid: {exc}") from exc
        verified[name] = rows
    return verified["train"], verified["validation"], manifest


def _partition_hash(rows: list[dict[str, Any]]) -> set[str]:
    return {
        hashlib.sha256(json.dumps(row, sort_keys=True).encode("utf-8")).hexdigest() for row in rows
    }


def leakage_audit(
    train_rows: list[dict[str, Any]], validation_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    train_runs = {row["run_id"] for row in train_rows}
    validation_runs = {row["run_id"] for row in validation_rows}
    train_scenarios = {row["scenario_id"] for row in train_rows}
    validation_scenarios = {row["scenario_id"] for row in validation_rows}
    train_incidents = {row["incident_id"] for row in train_rows}
    validation_incidents = {row["incident_id"] for row in validation_rows}
    checks = {
        "run_overlap": sorted(train_runs & validation_runs),
        "scenario_overlap": sorted(train_scenarios & validation_scenarios),
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


def feature_profile(rows: list[dict[str, Any]], schema: dict[str, Any]) -> dict[str, Any]:
    document: dict[str, Any] = {"revision": "feature-profile-v1", "families": {}}
    for family, feature_order in schema["x-family-features"].items():
        subset = [row for row in rows if row["family"] == family]
        profiles: dict[str, dict[str, float]] = {}
        for feature in feature_order:
            values = np.asarray([row["features"][feature] for row in subset], dtype=float)
            q1 = float(np.quantile(values, 0.25))
            q3 = float(np.quantile(values, 0.75))
            iqr = q3 - q1
            margin = max(3.0 * iqr, 1e-9)
            profiles[feature] = {
                "minimum": float(np.min(values)),
                "maximum": float(np.max(values)),
                "mean": float(np.mean(values)),
                "standard_deviation": float(np.std(values)),
                "ood_lower": q1 - margin,
                "ood_upper": q3 + margin,
            }
        document["families"][family] = {
            "records": len(subset),
            "features": profiles,
        }
    return document


def _matrix(rows: list[dict[str, Any]], family: str, feature_order: list[str]):
    subset = [row for row in rows if row["family"] == family]
    x = np.asarray([[row["features"][name] for name in feature_order] for row in subset])
    y = np.asarray([row["label"] for row in subset], dtype=int)
    groups = np.asarray([row["scenario_id"] for row in subset])
    if len(np.unique(y)) != 2:
        raise ValueError(f"{family} partition must contain benign and malicious records")
    return x, y, groups


def _inner_splits(
    labels: np.ndarray,
    groups: np.ndarray,
    *,
    folds: int,
    random_seed: int,
) -> list[tuple[np.ndarray, np.ndarray]]:
    for label in (0, 1):
        label_groups = len(np.unique(groups[labels == label]))
        if label_groups < folds:
            raise ValueError(
                f"inner grouped CV requires at least {folds} scenarios for label {label}; "
                f"observed {label_groups}"
            )
    splitter = StratifiedGroupKFold(
        n_splits=folds,
        shuffle=True,
        random_state=random_seed,
    )
    splits = list(splitter.split(np.zeros(len(labels)), labels, groups))
    if any(set(labels[test].tolist()) != {0, 1} for _, test in splits):
        raise ValueError("inner grouped CV produced a fold without both labels")
    return splits


def _scenario_diagnostics(
    rows: list[dict[str, Any]],
    family: str,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, dict[str, float | int]]:
    subset = [row for row in rows if row["family"] == family]
    output: dict[str, dict[str, float | int]] = {}
    for scenario_id in sorted({row["scenario_id"] for row in subset}):
        indices = [
            index for index, row in enumerate(subset) if row["scenario_id"] == scenario_id
        ]
        labels = np.asarray([subset[index]["label"] for index in indices], dtype=int)
        scenario_probabilities = probabilities[indices]
        predictions = (scenario_probabilities >= threshold).astype(int)
        output[scenario_id] = {
            "records": len(indices),
            "label": int(labels[0]),
            "mean_probability": float(np.mean(scenario_probabilities)),
            "predicted_malicious_rate": float(np.mean(predictions)),
            "error_rate": float(np.mean(predictions != labels)),
        }
    return output


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
    train_rows, validation_rows, manifest = verify_training_partitions(
        processed_dir,
        Path(config["feature_schema"]),
        require_collection_audit=bool(config["data"].get("require_collection_audit", True)),
    )
    audit = leakage_audit(train_rows, validation_rows)
    if not audit["passed"]:
        raise ValueError(f"leakage audit failed: {audit['checks']}")
    eda = exploratory_summary(train_rows, schema)
    profile = feature_profile(train_rows, schema)

    artifacts: dict[str, Any] = {}
    all_metrics: dict[str, Any] = {"families": {}}
    threshold_document: dict[str, Any] = {
        "revision": "week3-validation-v2",
        "selection_partition": "validation",
        "families": {},
    }
    calibration_document: dict[str, Any] = {
        "revision": "week3-calibration-v1",
        "fit_partition": "train_grouped_cv",
        "assessment_partition": "validation",
        "families": {},
    }
    for family, feature_order in schema["x-family-features"].items():
        x_train, y_train, train_groups = _matrix(train_rows, family, feature_order)
        if not np.any(np.ptp(x_train, axis=0) > 0):
            raise ValueError(f"{family} training features are all constant")
        x_validation, y_validation, validation_groups = _matrix(
            validation_rows, family, feature_order
        )
        family_results: dict[str, Any] = {}
        candidates = build_candidates(
            config, random_seed=int(config["random_seed"])
        )
        inner_splits = _inner_splits(
            y_train,
            train_groups,
            folds=int(config["selection"]["inner_cv_folds"]),
            random_seed=int(config["random_seed"]),
        )
        for model_name, estimator in candidates.items():
            if model_name == "xgboost":
                positives = int(np.sum(y_train == 1))
                negatives = int(np.sum(y_train == 0))
                estimator.set_params(scale_pos_weight=negatives / positives)
            inner_probabilities = cross_val_predict(
                estimator,
                x_train,
                y_train,
                cv=inner_splits,
                method="predict_proba",
                n_jobs=1,
            )[:, 1]
            inner_threshold = select_threshold(
                y_train,
                inner_probabilities,
                minimum_precision=float(config["selection"]["minimum_precision"]),
            )
            family_results[model_name] = {
                "inner_cv_threshold": inner_threshold,
                "inner_cv_metrics": classification_metrics(
                    y_train,
                    inner_probabilities,
                    inner_threshold["threshold"],
                ),
            }
        selected_name = max(
            family_results,
            key=lambda name: (
                family_results[name]["inner_cv_metrics"]["pr_auc"],
                family_results[name]["inner_cv_metrics"]["f1"],
                -family_results[name]["inner_cv_metrics"]["brier"],
            ),
        )
        calibrated = CalibratedClassifierCV(
            estimator=clone(candidates[selected_name]),
            method=str(config["selection"]["calibration_method"]),
            cv=inner_splits,
            ensemble=False,
        )
        calibrated.fit(x_train, y_train)
        probabilities = calibrated.predict_proba(x_validation)[:, 1]
        selected_threshold = select_threshold(
            y_validation,
            probabilities,
            minimum_precision=float(config["selection"]["minimum_precision"]),
        )
        metrics = classification_metrics(
            y_validation,
            probabilities,
            selected_threshold["threshold"],
        )
        metrics["confidence_intervals"] = grouped_bootstrap_intervals(
            y_validation,
            probabilities,
            validation_groups,
            selected_threshold["threshold"],
            iterations=int(config["selection"]["bootstrap_iterations"]),
            confidence=float(config["selection"]["bootstrap_confidence"]),
            random_seed=int(config["random_seed"]),
        )
        metrics["uncertainty"] = grouped_uncertainty_status(y_validation, validation_groups)
        metrics["latency"] = measure_latency_ms(
            lambda estimator=calibrated, matrix=x_validation: estimator.predict_proba(matrix)[
                :, 1
            ],
            repeats=int(config["selection"]["latency_repeats"]),
        )
        metrics["scenario_diagnostics"] = _scenario_diagnostics(
            validation_rows,
            family,
            probabilities,
            selected_threshold["threshold"],
        )
        inner_threshold = family_results[selected_name]["inner_cv_threshold"]
        threshold_delta = abs(
            float(selected_threshold["threshold"]) - float(inner_threshold["threshold"])
        )
        gate_failures = []
        if metrics["uncertainty"]["status"] != "ESTIMATED":
            gate_failures.append("insufficient_validation_groups")
        if metrics["brier"] > float(config["selection"]["maximum_brier"]):
            gate_failures.append("maximum_brier_exceeded")
        if metrics["ece"] > float(config["selection"]["maximum_ece"]):
            gate_failures.append("maximum_ece_exceeded")
        if threshold_delta > float(config["selection"]["maximum_threshold_delta"]):
            gate_failures.append("threshold_instability")
        if gate_failures:
            selected_threshold["automation_eligible"] = False
            selected_threshold["selection_reason"] = "calibration_or_stability_gate_failed"
        selected_threshold["gate_failures"] = gate_failures
        selected_threshold["uncertainty_status"] = metrics["uncertainty"]["status"]
        selected_threshold["inner_cv_threshold"] = inner_threshold["threshold"]
        selected_threshold["threshold_delta"] = threshold_delta
        family_results[selected_name]["validation"] = metrics
        artifacts[family] = {
            "estimator": calibrated,
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
        calibration_document["families"][family] = {
            "method": config["selection"]["calibration_method"],
            "bins": reliability_curve(
                y_validation,
                probabilities,
                bins=int(config["selection"]["calibration_bins"]),
            ),
            "brier": metrics["brier"],
            "ece": metrics["ece"],
            "maximum_brier": float(config["selection"]["maximum_brier"]),
            "maximum_ece": float(config["selection"]["maximum_ece"]),
            "gate_failures": gate_failures,
        }

    trained_at = datetime.now(UTC)
    metadata = {
        "model_version": f"week3-{trained_at.strftime('%Y%m%dT%H%M%SZ')}",
        "feature_schema_version": schema["version"],
        "training_timestamp_utc": trained_at.isoformat(),
        "dataset_hash_sha256": manifest["dataset_hash_sha256"],
        "dataset_provenance": manifest["provenance"],
        "training_partition_sha256": {
            name: manifest["partitions"][name]["sha256"] for name in ("train", "validation")
        },
        "dataset_manifest_payload_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "training_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "random_seed": int(config["random_seed"]),
        "git_commit": _git_commit(),
        "locked_test_status": "UNOPENED",
        "locked_test_sha256": manifest["locked_test_sha256"],
        "selection_partition": "validation",
        "model_selection_partition": "train_grouped_cv",
        "calibration_partition": "train_grouped_cv",
        "calibration_revision": calibration_document["revision"],
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
    write_json(package_dir / "calibration_validation.json", calibration_document)
    write_json(package_dir / "feature_profile.json", profile)
    shutil.copy2(Path(config["feature_schema"]), package_dir / "feature_schema.json")
    return metadata
