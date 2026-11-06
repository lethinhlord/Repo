#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-.venv-ml/bin/python}"
RUFF="${RUFF:-.venv-ml/bin/ruff}"

"$PYTHON" -m pytest -q \
  tests/test_scenario_collection.py \
  tests/test_dataset_audit.py \
  tests/test_collection_configuration.py \
  tests/test_collection_windows.py \
  tests/test_bucket_reservations.py \
  tests/test_handoff_regressions.py \
  tests/test_progress_audit.py \
  tests/test_export_run_parameters.py \
  tests/test_collection_release.py \
  tests/test_official_collection_acceptance.py \
  tests/test_collection_training_design.py \
  tests/test_execution_profiles.py \
  tests/test_collection_plan.py \
  tests/test_enrollment_rebuild.py \
  tests/test_preflight_report_binding.py \
  tests/test_unknown_process_image.py \
  tests/test_ml_dataset.py
"$RUFF" check \
  ml/scenario_collection.py \
  ml/dataset_audit.py \
  scripts/create_run_draft.py \
  scripts/export_run_parameters.py \
  scripts/scenario_session.py \
  scripts/audit_dataset.py
"$RUFF" check ml/collection_release.py ml/collection_backup.py ml/collection_design.py \
  ml/execution_profile.py ml/preflight.py scripts/collection_release.py \
  scripts/make_collection_plan.py scripts/run_training_account_remote.py

if [ "${REQUIRE_TARGET:-0}" = "1" ]; then
  exec "$PYTHON" -m scripts.audit_dataset \
    --minimum-runs 10 \
    --target-runs 12 \
    --minimum-scenarios 5 \
    --maximum-scenario-share 0.30 \
    --require-target \
    --output evidence/dataset-audit.json
fi

exec "$PYTHON" -m scripts.audit_dataset \
  --minimum-runs 10 \
  --target-runs 12 \
  --minimum-scenarios 5 \
  --maximum-scenario-share 0.30 \
  --output evidence/dataset-audit.json
