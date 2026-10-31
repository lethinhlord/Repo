#!/usr/bin/env python3
"""Load a signed smoke package and exercise one malicious account prediction."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from api.app.contracts import IncidentRequest
from ml.behavior_features import ACCOUNT_FEATURES
from ml.inference import ModelRuntime


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-dir", type=Path, required=True)
    arguments = parser.parse_args()
    runtime = ModelRuntime(arguments.package_dir)
    now = datetime.now(UTC)
    incident = IncidentRequest(
        # Synthetic independent enrollment; this smoke is not model-quality evidence.
        context_status="AVAILABLE",
        context_revision="synthetic-smoke-enrollment-v1",
        observation_quality="COMPLETE",
        incident_id="SMOKE-INFERENCE-01",
        asset_id="SMOKE-ACCOUNT-HOST",
        start_time=now,
        end_time=now,
        family_hint="account",
        features={
            "failed_login_count": 18.0,
            "successful_login_count": 1.0,
            "success_after_fail": 1.0,
            "unique_target_account_count": 2.0,
            "unique_source_count": 2.0,
            "remote_logon_ratio": 0.75,
            "failure_window_seconds": 180.0,
            "attempt_rate_per_minute": 12.0,
            "source_history_known": 1.0,
            "new_source_for_user": 0.0,
        },
        evidence_sources=["smoke-verification"],
        base_severity=12,
    )
    if set(incident.features) != set(ACCOUNT_FEATURES):
        raise RuntimeError("synthetic smoke fixture differs from active account schema")
    result = runtime.predict(incident)
    if result.predicted_class != "malicious":
        raise RuntimeError("smoke model did not classify the malicious account fixture")
    metadata = json.loads(
        (arguments.package_dir / "metadata.json").read_text(encoding="utf-8")
    )
    if metadata.get("locked_test_status") != "UNOPENED":
        raise RuntimeError("smoke package unexpectedly opened the locked test")
    print(f"Inference verified: {result.model_version} -> {result.predicted_class}")
    print("PASS: LR/RF/XGBoost benchmark, package, and inference smoke test")


if __name__ == "__main__":
    main()
