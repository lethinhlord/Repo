from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from api.app.contracts import IncidentRequest, PredictionResponse
from ml.freeze_model import PACKAGE_FILES, file_hash


class ModelPackageError(RuntimeError):
    pass


class InferenceInputError(ValueError):
    pass


class ModelRuntime:
    def __init__(self, package_dir: Path):
        self.package_dir = package_dir
        required = (*PACKAGE_FILES, "FROZEN.json")
        missing = [name for name in required if not (package_dir / name).is_file()]
        if missing:
            raise ModelPackageError(f"incomplete model package; missing: {missing}")
        freeze_path = package_dir / "FROZEN.json"
        try:
            freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
            if freeze.get("format_version") != "model-package-v2":
                raise ModelPackageError("unsupported frozen model package format")
            expected_hashes = freeze["files_sha256"]
            for name in PACKAGE_FILES:
                if expected_hashes.get(name) != file_hash(package_dir / name):
                    raise ModelPackageError(
                        f"model package integrity verification failed: {name}"
                    )
            self.metadata = json.loads(
                (package_dir / "metadata.json").read_text(encoding="utf-8")
            )
            self.thresholds = json.loads(
                (package_dir / "thresholds.json").read_text(encoding="utf-8")
            )
            schema = json.loads(
                (package_dir / "feature_schema.json").read_text(encoding="utf-8")
            )
        except (KeyError, json.JSONDecodeError, TypeError) as exc:
            raise ModelPackageError("invalid frozen model package manifest") from exc
        if freeze.get("model_version") != self.metadata.get("model_version"):
            raise ModelPackageError("freeze and metadata versions do not match")
        if schema.get("version") != self.metadata.get("feature_schema_version"):
            raise ModelPackageError("feature schema and metadata versions do not match")

        # joblib is executable deserialization. It is loaded only after every immutable
        # artifact has passed the signed-package boundary represented by FROZEN.json.
        self.bundle = joblib.load(package_dir / "model.joblib")
        if self.bundle.get("metadata", {}).get("model_version") != self.metadata.get(
            "model_version"
        ):
            raise ModelPackageError("model and metadata versions do not match")
        if self.metadata.get("locked_test_status") != "UNOPENED":
            raise ModelPackageError("runtime package does not have the expected locked-test state")
        if set(self.bundle.get("families", {})) != set(
            self.thresholds.get("families", {})
        ):
            raise ModelPackageError("model and threshold families do not match")
        schema_families = schema.get("x-family-features", {})
        for family, artifact in self.bundle["families"].items():
            threshold = self.thresholds["families"][family]
            if float(artifact["threshold"]) != float(threshold.get("threshold")):
                raise ModelPackageError(f"{family} model and document threshold mismatch")
            if artifact.get("feature_order") != schema_families.get(family):
                raise ModelPackageError(f"{family} feature schema mismatch")
            if not isinstance(threshold.get("automation_eligible"), bool):
                raise ModelPackageError(f"{family} automation eligibility is missing")

        self.locked_test_status = "UNOPENED"
        opened_path = package_dir / "LOCKED_TEST_OPENED.json"
        if opened_path.exists():
            try:
                opened = json.loads(opened_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ModelPackageError("invalid locked-test opening record") from exc
            freeze_sha256 = hashlib.sha256(freeze_path.read_bytes()).hexdigest()
            if (
                opened.get("model_version") != self.metadata.get("model_version")
                or opened.get("freeze_sha256") != freeze_sha256
                or opened.get("locked_test_sha256")
                != self.metadata.get("locked_test_sha256")
            ):
                raise ModelPackageError("locked-test opening record integrity failed")
            self.locked_test_status = "EVALUATED"

    def predict(self, incident: IncidentRequest) -> PredictionResponse:
        family = incident.family_hint
        if family not in self.bundle["families"]:
            raise InferenceInputError(f"unsupported model family: {family}")
        artifact: dict[str, Any] = self.bundle["families"][family]
        feature_order = artifact["feature_order"]
        missing = [name for name in feature_order if name not in incident.features]
        if missing:
            raise InferenceInputError(f"missing required {family} features: {missing}")
        vector = np.asarray([[incident.features[name] for name in feature_order]], dtype=float)
        probability = float(artifact["estimator"].predict_proba(vector)[0, 1])
        threshold = float(artifact["threshold"])
        automation_eligible = bool(
            self.thresholds["families"][family]["automation_eligible"]
        )
        return PredictionResponse(
            model_version=self.metadata["model_version"],
            predicted_class="malicious" if probability >= threshold else "benign",
            malicious_probability=probability,
            family=family,
            threshold_revision=self.thresholds["revision"],
            automation_eligible=automation_eligible,
            review_required=not automation_eligible,
            inference_mode="trained",
        )
