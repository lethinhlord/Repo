#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

PYTHON_BIN="${PYTHON_BIN:-.venv-ml/bin/python}"
export PYTHONPATH="${PYTHONPATH:-.}"
if [ ! -x "$PYTHON_BIN" ]; then
  echo "ERROR: $PYTHON_BIN is unavailable; run scripts/bootstrap_ml.sh first." >&2
  exit 1
fi

SMOKE_PACKAGE="artifacts/runtime/smoke-model-package"
rm -f \
  "$SMOKE_PACKAGE/FROZEN.json" \
  "$SMOKE_PACKAGE/model.joblib" \
  "$SMOKE_PACKAGE/thresholds.json" \
  "$SMOKE_PACKAGE/metadata.json" \
  "$SMOKE_PACKAGE/metrics_validation.json" \
  "$SMOKE_PACKAGE/eda_train.json" \
  "$SMOKE_PACKAGE/leakage_audit.json" \
  "$SMOKE_PACKAGE/calibration_validation.json" \
  "$SMOKE_PACKAGE/feature_profile.json" \
  "$SMOKE_PACKAGE/feature_schema.json"

"$PYTHON_BIN" scripts/generate_smoke_dataset.py
"$PYTHON_BIN" -m ml.build_dataset --config config/training-smoke.yaml
"$PYTHON_BIN" -m ml.train --config config/training-smoke.yaml
export MODEL_PACKAGE_SIGNING_KEY="${MODEL_PACKAGE_SIGNING_KEY:-smoke-only-signing-key-not-for-production-0001}"
"$PYTHON_BIN" -m ml.freeze_model --package-dir artifacts/runtime/smoke-model-package
"$PYTHON_BIN" -m scripts.verify_model_package \
  --package-dir artifacts/runtime/smoke-model-package
