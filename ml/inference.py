from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from api.app.contracts import IncidentRequest, PredictionResponse


class ModelPackageError(RuntimeError):
    pass


class InferenceInputError(ValueError):
    pass


class ModelRuntime:
    def __init__(self, package_dir: Path):
        self.package_dir = package_dir
        required = ("model.joblib", "metadata.json", "thresholds.json")
        missing = [name for name in required if not (package_dir / name).is_file()]
        if missing:
            raise ModelPackageError(f"incomplete model package; missing: {missing}")
        self.metadata = json.loads((package_dir / "metadata.json").read_text(encoding="utf-8"))
        self.thresholds = json.loads((package_dir / "thresholds.json").read_text(encoding="utf-8"))
        self.bundle = joblib.load(package_dir / "model.joblib")
        if self.bundle.get("metadata", {}).get("model_version") != self.metadata.get(
            "model_version"
        ):
            raise ModelPackageError("model and metadata versions do not match")
        if self.metadata.get("locked_test_status") != "UNOPENED":
            raise ModelPackageError("runtime package does not have the expected locked-test state")

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
        return PredictionResponse(
            model_version=self.metadata["model_version"],
            predicted_class="malicious" if probability >= threshold else "benign",
            malicious_probability=probability,
            family=family,
            threshold_revision=self.thresholds["revision"],
        )
