# Model package output

This directory is intentionally committed without a binary model. Run the Week 3
training gate with real, reviewed scenario data to produce:

- `model.joblib`
- `thresholds.json`
- `metadata.json`
- `metrics_validation.json`
- `eda_train.json`
- `leakage_audit.json`

Synthetic smoke-test artifacts are written under `artifacts/runtime/` and must not
be used as scientific evidence. Do not open the locked test until the Week 6 freeze
gate has been approved and `FROZEN.json` exists.
