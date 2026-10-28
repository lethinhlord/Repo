from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from api.app.contracts import IncidentRequest, ModelMetricsResponse, PredictionResponse
from ml.behavior_features import FEATURE_SCHEMA_VERSION
from ml.freeze_model import PACKAGE_FILES, verify_frozen_manifest
from ml.model_monitoring import ModelMonitoringStore


class ModelPackageError(RuntimeError):
    pass


class InferenceInputError(ValueError):
    pass


class ModelRuntime:
    OOD_ALERT_MINIMUM_SAMPLES = 200
    OOD_ALERT_RATE = 0.05

    def __init__(self, package_dir: Path, *, monitoring_path: Path | None = None):
        self.package_dir = package_dir
        required = (*PACKAGE_FILES, "FROZEN.json")
        missing = [name for name in required if not (package_dir / name).is_file()]
        if missing:
            raise ModelPackageError(f"incomplete model package; missing: {missing}")
        try:
            freeze = verify_frozen_manifest(package_dir)
            self.metadata = json.loads(
                (package_dir / "metadata.json").read_text(encoding="utf-8")
            )
            self.thresholds = json.loads(
                (package_dir / "thresholds.json").read_text(encoding="utf-8")
            )
            schema = json.loads(
                (package_dir / "feature_schema.json").read_text(encoding="utf-8")
            )
            self.feature_profile = json.loads(
                (package_dir / "feature_profile.json").read_text(encoding="utf-8")
            )
        except (KeyError, json.JSONDecodeError, TypeError) as exc:
            raise ModelPackageError("invalid frozen model package manifest") from exc
        except ValueError as exc:
            raise ModelPackageError(str(exc)) from exc
        if any(not isinstance(document, dict) for document in (
            self.metadata, self.thresholds, schema, self.feature_profile,
        )):
            raise ModelPackageError("model package documents must be mappings")
        if freeze.get("model_version") != self.metadata.get("model_version"):
            raise ModelPackageError("freeze and metadata versions do not match")
        if schema.get("version") != self.metadata.get("feature_schema_version"):
            raise ModelPackageError("feature schema and metadata versions do not match")
        active_schema = json.loads(
            Path(__file__).with_name("feature_schema.json").read_text(encoding="utf-8")
        )
        if schema.get("version") != FEATURE_SCHEMA_VERSION or schema != active_schema:
            raise ModelPackageError("model package schema is not the active runtime schema")
        if self.feature_profile.get("revision") != "feature-profile-v1":
            raise ModelPackageError("unsupported or missing feature profile")
        schema_families = schema.get("x-family-features", {})
        required_families = set(schema_families)
        threshold_families = self.thresholds.get("families")
        profile_families = self.feature_profile.get("families")
        if (
            not isinstance(threshold_families, dict)
            or not isinstance(profile_families, dict)
            or set(threshold_families) != required_families
            or set(profile_families) != required_families
        ):
            raise ModelPackageError("model package does not contain all required families")
        for family, feature_order in schema_families.items():
            profile = self.feature_profile["families"][family]
            features = profile.get("features") if isinstance(profile, dict) else None
            if not isinstance(features, dict) or set(features) != set(feature_order):
                raise ModelPackageError(f"{family} required feature profile is incomplete")
        self.schema = schema

        # joblib is executable deserialization. It is loaded only after every immutable
        # artifact has passed the signed-package boundary represented by FROZEN.json.
        self.bundle = joblib.load(package_dir / "model.joblib")
        if not isinstance(self.bundle, dict):
            raise ModelPackageError("model bundle must be a mapping")
        if self.bundle.get("metadata", {}).get("model_version") != self.metadata.get(
            "model_version"
        ):
            raise ModelPackageError("model and metadata versions do not match")
        if self.metadata.get("locked_test_status") != "UNOPENED":
            raise ModelPackageError("runtime package does not have the expected locked-test state")
        bundle_families = self.bundle.get("families")
        if not isinstance(bundle_families, dict) or set(bundle_families) != required_families:
            raise ModelPackageError("model bundle does not contain all required families")
        for family, artifact in self.bundle["families"].items():
            threshold = self.thresholds["families"][family]
            if not isinstance(artifact, dict) or not isinstance(threshold, dict):
                raise ModelPackageError(f"{family} model and threshold must be mappings")
            if float(artifact["threshold"]) != float(threshold.get("threshold")):
                raise ModelPackageError(f"{family} model and document threshold mismatch")
            if artifact.get("feature_order") != schema_families.get(family):
                raise ModelPackageError(f"{family} feature schema mismatch")
            if not isinstance(threshold.get("automation_eligible"), bool):
                raise ModelPackageError(f"{family} automation eligibility is missing")
            estimator = artifact.get("estimator")
            if (
                not callable(getattr(estimator, "predict_proba", None))
                or list(getattr(estimator, "classes_", [])) != [0, 1]
                or getattr(estimator, "n_features_in_", None) != len(artifact["feature_order"])
            ):
                raise ModelPackageError(f"{family} binary estimator capability is invalid")

        self.locked_test_status = "UNOPENED"
        opened_path = package_dir / "LOCKED_TEST_OPENED.json"
        if opened_path.exists():
            try:
                opened = json.loads(opened_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ModelPackageError("invalid locked-test opening record") from exc
            freeze_sha256 = hashlib.sha256(
                (package_dir / "FROZEN.json").read_bytes()
            ).hexdigest()
            if (
                opened.get("model_version") != self.metadata.get("model_version")
                or opened.get("freeze_sha256") != freeze_sha256
                or opened.get("locked_test_sha256")
                != self.metadata.get("locked_test_sha256")
            ):
                raise ModelPackageError("locked-test opening record integrity failed")
            self.locked_test_status = "EVALUATED"
        self.monitoring = ModelMonitoringStore(monitoring_path)

    def predict(self, incident: IncidentRequest) -> PredictionResponse:
        family = incident.family_hint
        if family not in self.bundle["families"]:
            raise InferenceInputError(f"unsupported model family: {family}")
        artifact: dict[str, Any] = self.bundle["families"][family]
        feature_order = artifact["feature_order"]
        missing = [name for name in feature_order if name not in incident.features]
        if missing:
            raise InferenceInputError(f"missing required {family} features: {missing}")
        ood_features = []
        family_profile = self.feature_profile["families"][family]["features"]
        for name in feature_order:
            value = float(incident.features[name])
            property_schema = self.schema["properties"][name]
            if not math.isfinite(value):
                raise InferenceInputError(f"{name} must be finite")
            if value < float(property_schema["minimum"]) or value > float(
                property_schema["maximum"]
            ):
                raise InferenceInputError(f"{name} is outside the feature schema bounds")
            profile = family_profile[name]
            if value < float(profile["ood_lower"]) or value > float(profile["ood_upper"]):
                ood_features.append(name)
        vector = np.asarray([[incident.features[name] for name in feature_order]], dtype=float)
        probability = float(artifact["estimator"].predict_proba(vector)[0, 1])
        threshold = float(artifact["threshold"])
        package_eligible = bool(
            self.thresholds["families"][family]["automation_eligible"]
        )
        reasons = list(incident.review_reasons)
        history_mask = (
            "source_history_known" if family == "account" else "destination_history_known"
        )
        if incident.context_status != "AVAILABLE" or not incident.context_revision:
            reasons.append(f"context:{incident.context_status.lower()}")
        if incident.features.get(history_mask) != 1.0:
            reasons.append("context:history_not_known")
        if incident.observation_quality != "COMPLETE":
            reasons.append("telemetry:partial")
        if ood_features:
            reasons.append("model:out_of_distribution")
        if not package_eligible:
            reasons.append("model:automation_ineligible")
        automation_eligible = not reasons
        result = PredictionResponse(
            model_version=self.metadata["model_version"],
            predicted_class="malicious" if probability >= threshold else "benign",
            malicious_probability=probability,
            family=family,
            threshold_revision=self.thresholds["revision"],
            automation_eligible=automation_eligible,
            review_required=not automation_eligible,
            inference_mode="trained",
            ood_detected=bool(ood_features),
            ood_features=ood_features,
            review_reasons=sorted(set(reasons)),
        )
        self.monitoring.record_prediction(
            model_version=self.metadata["model_version"],
            family=family,
            review_required=result.review_required,
            ood_features=ood_features,
        )
        return result

    def metrics_snapshot(self) -> ModelMetricsResponse:
        snapshot = self.monitoring.snapshot(
            self.metadata["model_version"], list(self.bundle["families"])
        )
        predictions_by_family = snapshot["predictions_by_family"]
        ood_by_family = snapshot["ood_by_family"]
        ood_by_feature = snapshot["ood_by_feature"]
        alerts = []
        for family, total in predictions_by_family.items():
            if total < self.OOD_ALERT_MINIMUM_SAMPLES:
                continue
            if ood_by_family[family] / total > self.OOD_ALERT_RATE:
                alerts.append(f"OOD_RATE_HIGH:{family}")
            family_features = self.bundle["families"][family]["feature_order"]
            for name in family_features:
                if ood_by_feature.get(name, 0) / total > self.OOD_ALERT_RATE:
                    alerts.append(f"FEATURE_OOD_RATE_HIGH:{family}:{name}")
        return ModelMetricsResponse(
            model_version=self.metadata["model_version"],
            monitoring_alerts=alerts,
            **snapshot,
        )
