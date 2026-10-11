#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON_BIN="${PYTHON_BIN:-.venv-ml/bin/python}"
if [ ! -x "$PYTHON_BIN" ]; then
  echo "ERROR: $PYTHON_BIN is unavailable; run scripts/bootstrap_ml.sh first." >&2
  exit 1
fi

"$PYTHON_BIN" scripts/generate_smoke_dataset.py
"$PYTHON_BIN" -m ml.build_dataset --config config/training-smoke.yaml
"$PYTHON_BIN" -m ml.train --config config/training-smoke.yaml
"$PYTHON_BIN" - <<'PY'
import json
from datetime import UTC, datetime
from pathlib import Path

from api.app.contracts import IncidentRequest
from ml.inference import ModelRuntime

runtime = ModelRuntime(Path("artifacts/runtime/smoke-model-package"))
incident = IncidentRequest(
    incident_id="SMOKE-INFERENCE-01",
    asset_id="SMOKE-ACCOUNT-HOST",
    start_time=datetime.now(UTC),
    end_time=datetime.now(UTC),
    family_hint="account",
    features={"failed_login_count": 20.0, "success_after_fail": 1.0},
    evidence_sources=["smoke-verification"],
    base_severity=12,
)
result = runtime.predict(incident)
assert result.predicted_class == "malicious"
metadata = json.loads(
    Path("artifacts/runtime/smoke-model-package/metadata.json").read_text()
)
assert metadata["locked_test_status"] == "UNOPENED"
print(f"Inference verified: {result.model_version} -> {result.predicted_class}")
print("PASS: LR/RF/XGBoost benchmark, package, and inference smoke test")
PY
