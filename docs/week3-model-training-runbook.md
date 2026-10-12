# Week 3 model training runbook

## Outcome

This pipeline benchmarks Logistic Regression, Random Forest, and XGBoost independently
for `account` and `c2`. It selects on VALIDATION using PR-AUC, F1, FPR, and latency;
chooses a threshold that targets at least 0.90 precision; writes uncertainty intervals
using grouped bootstrap; and produces a versioned inference package. Accuracy is not a
selection metric.

The committed smoke generator exists only to prove that the software path works. Its
metrics must never be presented as model quality.

## 1. Verify the environment

Run in the Ubuntu VM from `/home/lethinh/datn-ai-soar`:

```bash
cd /home/lethinh/datn-ai-soar
python3 --version
.venv-ml/bin/python -c "import sklearn, xgboost; print(sklearn.__version__, xgboost.__version__)"
git status --short
```

Expected project versions are scikit-learn 1.9.1 and XGBoost 3.4.1. If the environment
does not exist:

```bash
bash scripts/bootstrap_ml.sh
```

## 2. Run the non-scientific pipeline smoke test

```bash
cd /home/lethinh/datn-ai-soar
bash scripts/verify_week3_model.sh | tee evidence/week3-model-smoke.log
```

Expected final line:

```text
PASS: LR/RF/XGBoost benchmark, package, and inference smoke test
```

Artifacts are written under `artifacts/runtime/` and are ignored by Git.

## 3. Collect and review real scenario data

Follow [week3-data-contract.md](week3-data-contract.md). Store each execution under
`data/raw/<run_id>/`. Review manifests and incident lines before building partitions.

Useful checks:

```bash
find data/raw -mindepth 2 -maxdepth 2 -name scenario_manifest.json | sort
find data/raw -mindepth 2 -maxdepth 2 -name incidents.jsonl | sort
grep -R '"label"\|"ground_truth"\|"ti_score"\|"asset_score"' data/raw/*/incidents.jsonl
```

The final command should produce no feature leakage matches. A manifest `label` is
expected; an incident feature `label` is forbidden.

## 4. Build immutable grouped partitions

```bash
.venv-ml/bin/python -m ml.build_dataset --config ml/training_config.yaml \
  | tee evidence/week3-dataset-build.log
cat data/processed/dataset_manifest.json
printf '%s\n' 'TRAIN runs:' && cat ml/splits/train.txt
printf '%s\n' 'VALIDATION runs:' && cat ml/splits/validation.txt
printf '%s\n' 'LOCKED TEST runs (IDs only):' && cat ml/splits/test.txt
```

Do not inspect `data/processed/locked_test.jsonl`. The manifest must show
`locked_test_status: UNOPENED`, zero overlap by construction, and a stable SHA-256 hash.

## 5. Train and select candidates

### Option A: Google Colab (recommended when local resources are limited)

Build the grouped partitions on the trusted Ubuntu VM first. Create a Colab staging
folder in Google Drive:

```text
MyDrive/DATN/week3-data/processed/
├── train.jsonl
├── validation.jsonl
└── dataset_manifest.json
```

Do not place `locked_test.jsonl`, raw telemetry, `.env`, credentials, or API keys in the
staging folder. Open `notebooks/week3_train_colab.ipynb` from GitHub on branch
`feature/week3-model-training`, then run the cells in order. The notebook performs EDA,
checks split independence, runs Ruff and pytest, executes the trusted training module,
and writes `model-package-week3.tar.gz` to:

```text
MyDrive/DATN/week3-results/
```

The notebook deliberately stops if a locked-test file is visible in either the Drive
staging folder or the Colab checkout. Runtime, ML and notebook dependencies are pinned
in `requirements.lock`, `requirements-ml.lock` and `requirements-notebook.lock`.

### Option B: Ubuntu VM

```bash
.venv-ml/bin/python -m ml.train --config ml/training_config.yaml \
  | tee evidence/week3-training.log
python3 -m json.tool ml/model-package/metadata.json
python3 -m json.tool ml/model-package/metrics_validation.json
python3 -m json.tool ml/model-package/thresholds.json
python3 -m json.tool ml/model-package/leakage_audit.json
```

Training writes:

```text
ml/model-package/
├── model.joblib
├── thresholds.json
├── metadata.json
├── metrics_validation.json
├── eda_train.json
└── leakage_audit.json
```

Accept the package only if leakage audit passes, both families contain both classes,
confidence intervals are reported, and the selected thresholds meet the intended safety
target. `automation_eligible=false` means the system must remain ASSISTED/SHADOW.
Only load a package produced locally by this trusted pipeline: `joblib` artifacts must
never be accepted from an untrusted source.

## 6. Activate trained inference in SHADOW mode

Use the in-container package path:

```bash
export MODEL_PACKAGE_DIR=/app/ml/model-package
docker compose up -d --build api n8n
curl -s http://127.0.0.1:8000/model/ready | python3 -m json.tool
curl -s http://127.0.0.1:8000/ready | python3 -m json.tool
```

`/model/ready` must report `mode: trained`, the package model version, and
`locked_test_status: UNOPENED`. Strong response actions remain disabled by the Week 2
SHADOW gate.

## 7. Freeze later; do not evaluate locked test in Week 3

The following commands are documented for the Week 6 gate only:

```bash
.venv-ml/bin/python -m ml.freeze_model --package-dir ml/model-package
.venv-ml/bin/python -m ml.evaluate \
  --package-dir ml/model-package \
  --locked-test data/processed/locked_test.jsonl \
  --unlock-locked-test
```

Before `FROZEN.json` exists, the evaluator refuses locked-test access. After freezing,
any package modification invalidates the SHA-256 integrity check.

## Evidence capture checklist

Capture the full 1920×1200 laptop screen with VMware Workstation chrome visible. Keep the
Ubuntu terminal or Firefox/PyCharm inside the VM maximized, but do not crop out the host
taskbar or VMware frame.

1. PyCharm project tree showing `ml/`, training configuration, tests, and documentation.
2. Ubuntu terminal showing Python and pinned library versions.
3. Dataset build terminal showing the dataset hash and `UNOPENED` status.
4. `dataset_manifest.json` in PyCharm, including group and partition counts.
5. Training terminal showing successful package creation.
6. `metrics_validation.json` showing all three candidates and validation metrics.
7. `thresholds.json` showing the selected threshold and automation eligibility.
8. `leakage_audit.json` showing `passed: true`.
9. Firefox at `/model/ready` showing trained mode.
10. n8n SHADOW workflow and one successful execution using `/predict`.

Do not capture passwords, SSH private keys, API keys, `.env`, or raw personal data.
