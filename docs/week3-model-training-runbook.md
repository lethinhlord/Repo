# Week 3 model training runbook

## Outcome

This pipeline benchmarks Logistic Regression, Random Forest, and XGBoost independently
for `account` and `c2`. It selects candidates on grouped inner cross-validation of TRAIN,
then reports independent VALIDATION diagnostics and selects the final threshold there.
The precision target is at least 0.90. Grouped bootstrap uncertainty is estimated only
with at least three independent validation cohorts per label; otherwise intervals
are null, `uncertainty.status` is `INSUFFICIENT_INDEPENDENT_GROUPS`, and the package is
ineligible for automation. Accuracy is not a selection metric.

The committed smoke generator exists only to prove that the software path works. Its
metrics must never be presented as model quality.

## 1. Verify the environment

Run in the Ubuntu VM from the checked-out repository (example
`$HOME/datn-ai-soar-v4`):

```bash
cd "$HOME/datn-ai-soar-v4"
python3 --version
.venv-ml/bin/python -c "import sklearn, xgboost; print(sklearn.__version__, xgboost.__version__)"
git status --short
```

Expected project versions are scikit-learn 1.9.1 and the CPU build of XGBoost 3.4.1.
The CPU distribution still imports as `xgboost` and avoids adding unused CUDA/NCCL
libraries to the inference image. If the environment
does not exist:

```bash
bash scripts/bootstrap_ml.sh
```

## 2. Run the non-scientific pipeline smoke test

```bash
cd "$HOME/datn-ai-soar-v4"
mkdir -p evidence
set -o pipefail
bash scripts/verify_week3_model.sh | tee evidence/week3-model-smoke.log
```

Expected final line:

```text
PASS: LR/RF/XGBoost benchmark, package, and inference smoke test
```

Artifacts are written under `artifacts/runtime/` and are ignored by Git.

## 3. Collect and review real scenario data

The collection candidate implements the paired design and defaults to cohort_id.
Follow [the four-VM runbook](scenario-collection-runbook.md) for source pinning,
enrollment, four new pilots, preflight replay, real backup restore and per-lab acceptance.
Only that evidence-bound acceptance opens official collection. Synthetic/pilot runs
never count toward the40–48quota. The target is controlled lab activity profiles,
not unobservable intent. Five cohorts per family leave one validation cohort per label,
so uncertainty remains insufficient and automation ineligible.

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
# Locked-test mapping remains blinded until the approved Week 6 gate.
```

Do not open or display `ml/splits/test.txt` or `data/processed/locked_test.jsonl` before
the approved Week 6 gate. Check only manifest integrity/counts; do not print test mapping. The manifest must show
`locked_test_status: UNOPENED`, zero overlap by construction, and a stable SHA-256 hash.

Rebuild partitions using the current builder before the first training run after this
upgrade. `dataset-manifest-v2` binds each partition's SHA-256 and row count, the active
feature schema, collection-contract hash, builder commit, training configuration and predeclared collection-design hash.
The trainer verifies TRAIN and VALIDATION against these bindings before fitting; it
does not open the locked-test file. Older manifests or edited partition files are
rejected. Correct the source/build process and rebuild; do not edit hashes by hand.

## 5. Train and select candidates

### Option A: Google Colab (recommended when local resources are limited)

Build the grouped partitions on the trusted Ubuntu VM first. Create a Colab staging
folder in Google Drive:

```text
MyDrive/DATN/week3-data/processed/
├── train.jsonl
├── validation.jsonl
├── dataset_manifest.json
└── colab-upload.sha256
```

On the trusted Ubuntu VM, generate the checksum file before uploading the four files:

```bash
(cd data/processed && sha256sum train.jsonl validation.jsonl dataset_manifest.json > colab-upload.sha256)
```

Do not place `locked_test.jsonl`, split mapping, raw telemetry, `.env`, credentials,
or API keys in the staging folder. Open the released notebook from `main` at the
owner-approved source revision. Set its `EXPECTED_TRAINING_COMMIT` field to the exact
40-character SHA approved by the owner and recorded as
`dataset_manifest.json.provenance.builder_git_commit` by the trusted build. Do not
substitute a branch name, current HEAD, or copy an unapproved SHA from an upload.
The approved SHA and manifest builder SHA must agree. Build with that approved clean
checkout and its committed `ml/training_config.yaml`; changing the config requires a
new approved source revision and rebuild. No notebook code patch is needed.

Use a fresh Colab runtime with no existing project directory, then run cells in order.
Before installing repository dependencies or running EDA, the notebook checks all three
data hashes, UNOPENED status, approved/builder SHA equality, checks out that exact SHA
in detached mode, and verifies the config SHA against the manifest. A stale project,
missing checksum, source mismatch or config mismatch stops the run. The notebook performs EDA,
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
├── leakage_audit.json
├── calibration_validation.json
├── feature_profile.json
└── feature_schema.json
```

For software and SHADOW evaluation, require a passed leakage audit, verified input
provenance, both families and classes, and an explicit uncertainty status. The normal
40–48-run schedule has only one validation scenario per label after a 3/1/1 scenario
split; it is a pilot dataset, so null confidence intervals and
`insufficient_validation_groups` are expected. Repeating the same templates does not
add independent scenarios. Do not rename runs to bypass this gate. Additional varied
scenarios and a predeclared split are needed before claiming statistical readiness.
Automation eligibility additionally requires estimated confidence intervals and all
threshold, calibration and stability gates. `automation_eligible=false` means the
system must remain ASSISTED/SHADOW.
Only load a package produced locally by this trusted pipeline: `joblib` artifacts must
never be accepted from an untrusted source.

## 6. Activate trained inference in SHADOW mode

For the Colab archive, follow the final handoff cell of the notebook: it checks the
trusted archive hash, extracts only allowed regular files into fresh staging, compares
model and dataset provenance, and signs a new versioned directory under
`artifacts/runtime/model-releases/`. It prints the verified absolute host path. Do not
use the smoke verifier as acceptance of the Colab archive. A failed handoff must not be
activated. For the Ubuntu-local training option, the trusted output is
`ml/model-package`; create and freeze its immutable release using section 2 of
[the model operations runbook](model-operations-runbook.md) before continuing. That
procedure uses UID 0 for the registry, matching the shipped Docker image, and persists
both package and registry host paths.

Load the protected environment, then set `MODEL_PACKAGE_HOST_DIR` to the **verified
absolute host path** of the selected package (for Colab, the path printed by its
successful handoff; for local training, the versioned release path). Also select
`MODEL_EVALUATION_REGISTRY_HOST_DIR` from the same handoff/freeze. Compose mounts
that exact host directory at the container path `/app/ml/model-package`. Verify the
actual host package before building and starting SHADOW:

```bash
set -eu
: "${MODEL_PACKAGE_HOST_DIR:?Set the verified absolute host package path}"
: "${EXPECTED_MODEL_VERSION:?Set the model version recorded from trusted training}"
: "${MODEL_EVALUATION_REGISTRY_HOST_DIR:?Set the retained registry initialized for this release}"
DATN_SELECTED_PACKAGE_HOST_DIR=$(realpath -e -- "$MODEL_PACKAGE_HOST_DIR")
DATN_SELECTED_REGISTRY_HOST_DIR=$(realpath -e -- "$MODEL_EVALUATION_REGISTRY_HOST_DIR")
DATN_EXPECTED_ACTIVATION_VERSION="$EXPECTED_MODEL_VERSION"
readonly DATN_SELECTED_PACKAGE_HOST_DIR DATN_SELECTED_REGISTRY_HOST_DIR DATN_EXPECTED_ACTIVATION_VERSION
set -a
. ./.env
set +a
export MODEL_PACKAGE_HOST_DIR="$DATN_SELECTED_PACKAGE_HOST_DIR"
export MODEL_EVALUATION_REGISTRY_HOST_DIR="$DATN_SELECTED_REGISTRY_HOST_DIR"
export MODEL_EVALUATION_REGISTRY_DIR="$DATN_SELECTED_REGISTRY_HOST_DIR"
.venv-ml/bin/python - "$MODEL_PACKAGE_HOST_DIR" "$DATN_EXPECTED_ACTIVATION_VERSION" <<'PY'
import json, pathlib, sys
metadata = json.loads((pathlib.Path(sys.argv[1]) / "metadata.json").read_text())
if metadata.get("model_version") != sys.argv[2]:
    raise SystemExit("Selected package identity differs from trusted training version")
PY
sudo --preserve-env=MODEL_PACKAGE_SIGNING_KEY,MODEL_PACKAGE_VERIFICATION_KEYS,MODEL_EVALUATION_REGISTRY_DIR \
  .venv-ml/bin/python -m ml.freeze_model --verify-only --package-dir "$MODEL_PACKAGE_HOST_DIR"
python3 - "$MODEL_PACKAGE_HOST_DIR" "$MODEL_EVALUATION_REGISTRY_HOST_DIR" <<'PY'
from pathlib import Path
import sys
path = Path(".env")
keys = ("MODEL_PACKAGE_HOST_DIR", "MODEL_EVALUATION_REGISTRY_HOST_DIR")
lines = [line for line in path.read_text().splitlines() if not any(line.startswith(key + "=") for key in keys)]
lines.extend(key + "=" + value for key, value in zip(keys, sys.argv[1:], strict=True))
path.write_text("\n".join(lines) + "\n")
PY
export MODEL_PACKAGE_DIR=/app/ml/model-package
./scripts/build_reproducible_image.sh datn-ai-soar-api:week3
docker compose up -d api n8n
curl -fsS http://127.0.0.1:8000/model/ready | python3 -c \
 'import json,sys; d=json.load(sys.stdin); assert d["mode"]=="trained" and d["model_version"]==sys.argv[1] and d["locked_test_status"]=="UNOPENED"; print(json.dumps(d,indent=2))' \
 "$DATN_EXPECTED_ACTIVATION_VERSION"
curl -fsS http://127.0.0.1:8000/ready | python3 -m json.tool
```

The selected package/registry host paths and expected version are captured before loading `.env`;
an older `.env` selection cannot silently activate another frozen package.

`/model/ready` must report `mode: trained`, the package model version, and
`locked_test_status: UNOPENED`. The HMAC signing key is read only from the protected
environment file; never paste it into a notebook, command line or screenshot. Strong
response actions remain disabled by the Week 2 SHADOW gate.
Use [model-operations-runbook.md](model-operations-runbook.md) for immutable release
directories, monitoring, analyst feedback, retraining and rollback.

## 7. Freeze before deployment; evaluate locked test only at the Week 6 gate

Freezing signs the selected package and does not read the locked test. The Colab
handoff freezes its selected release on the trusted Ubuntu VM, not in Colab. Locally
trained output follows the same UID 0 freeze/registry procedure in the model operations
runbook before activation. The following evaluator command is for
the approved Week 6 gate only:

```bash
docker compose run --rm --no-deps \
  -v "$PWD/data/processed:/evaluation-input:ro" api \
  python -m ml.evaluate --package-dir /app/ml/model-package \
  --locked-test /evaluation-input/locked_test.jsonl --unlock-locked-test
```

Before `FROZEN.json` exists, both runtime and evaluator refuse the package. After
freezing, any package modification or manifest rewrite invalidates the HMAC/hash gate.

An interrupted opening reports `OPENED_INCOMPLETE`, not `UNOPENED`. Preserve the
reservation, metrics (including incomplete output), opening record and error log;
do not delete the reservation or rerun evaluation to hide the attempt. Stop test-based
tuning and have the evaluation owner audit what was exposed before planning any
further evaluation. A fresh holdout is required if the original holdout is no longer
independent; rerunning the same package is not evidence that it was never opened.

`EVIDENCE_INTEGRITY_ERROR` means the recorded evaluation evidence cannot be trusted.
Preserve/quarantine the package and compare a complete original backup against its
independently retained hashes. Restore original records only with that provenance;
never recompute an opening hash or remove markers to turn the status into UNOPENED.
Neither state authorizes automation or a model accuracy claim.

## Evidence capture checklist

Capture the full 1920×1200 laptop screen with VMware Workstation chrome visible. Keep the
Ubuntu terminal or Firefox/PyCharm inside the VM maximized, but do not crop out the host
taskbar or VMware frame.

1. PyCharm project tree showing `ml/`, training configuration, tests, and documentation.
2. Ubuntu terminal showing Python and pinned library versions.
3. Dataset build terminal showing the dataset hash and `UNOPENED` status.
4. `dataset_manifest.json` in PyCharm, including group and partition counts.
5. Training terminal showing successful package creation.
6. `metrics_validation.json` showing grouped inner-CV candidate selection,
   per-scenario validation diagnostics and confidence intervals.
7. `calibration_validation.json` showing sigmoid calibration, reliability bins,
   Brier score, ECE and gate results.
8. `thresholds.json` showing the validation-only threshold, inner-CV threshold,
   stability delta and automation eligibility.
9. `leakage_audit.json` showing `passed: true`.
10. Firefox at `/model/ready` showing trained mode.
11. n8n SHADOW workflow and one successful execution using `/predict`.
12. `/model/metrics` showing prediction, review and OOD counters for the active model
    version without raw features or incident identifiers.

Do not capture passwords, SSH private keys, API keys, `.env`, or raw personal data.


## Audit corrections: provenance, calibration and challenge replay

Local training and the Colab partition gate use the same builder provenance validator.
The builder commit must equal the executing training commit, and the byte hash of the
training configuration must equal the builder configuration hash, before train or
validation is read. Rebuild under an approved source/configuration if they differ; do
not edit manifest hashes to bypass this gate. The Colab pre-install owner approval and
detached source checkout checks remain in force.

`selection.calibration_bins` now defines validation ECE, reliability curves, bootstrap
ECE intervals and the calibration gate consistently. Its value is frozen in metadata
and used again for locked-test metrics. Threshold stability compares validation
probabilities with calibrated out-of-fold training probabilities. Each outer held-out
group is excluded from candidate ranking, estimator fitting and inner grouped calibration; the
chosen stability threshold, each fold's selected candidate, selection metrics and group
inventory are retained in validation metrics. Each outer fit partition independently
ranks all candidates using only its inner grouped CV labels; the globally selected
final model is not reused to select the outer-fold estimator.
Candidate ranking retains its original uncalibrated inner-CV metrics. Nested calibration
requires at least two fitting groups per label in every outer fold; it fails closed
when the dataset cannot support this. Existing calibration limits and insufficient
independent validation group safeguards remain unchanged.

For an immutable release, use the shared writable evidence volume described in
`model-operations-runbook.md`. Both evaluation commands use Compose so they share the
deployment registry and writable evidence volume; no undefined host evidence-root
variable or separate host history is used. Never make the release writable for evaluation.

Challenge evaluation is a separate, post-freeze, write-once replay and does not open
locked-test data or change thresholds. Newly trained metadata binds the dataset
manifest, collection design and runtime decision code; the preserved `incident`
payload supplies original context, observation quality and review reasons to
`ModelRuntime.predict`. The evaluator never injects the expected REVIEW decision.

```bash
docker compose run --rm --no-deps \
  -v "$PWD/data/processed:/evaluation-input:ro" \
  -v "$PWD/config/collection-design.yaml:/evaluation-design.yaml:ro" api \
  python -m ml.evaluate_challenge --package-dir /app/ml/model-package \
  --challenge /evaluation-input/challenge.jsonl \
  --manifest /evaluation-input/dataset_manifest.json \
  --design /evaluation-design.yaml
```

The signed report contains per-scenario expected/actual decisions, review and confident
benign/malicious rates, scenario coverage, missing scenarios and pair agreement
(equal decision distributions across observed scenarios in a cohort). A confident
binary decision against a REVIEW expectation is reported as FAIL, not rewritten as
REVIEW. Incomplete coverage also fails. Preserve `CHALLENGE_RESERVED` and the report
in the release evidence namespace, including interrupted or failing attempts. Do not
use the challenge result for tuning this release. Legacy packages without the runtime
policy commitment or datasets without preserved incident context cannot be replayed;
prepare a new reviewed dataset/package before challenge evaluation. Synthetic replay
tests establish tooling behavior only, not four-VM acceptance or real model quality.


Every release now also requires its pre-existing durable evaluation registry. Freeze
creates the signed registry binding; runtime and evaluators only open existing storage.
Copy/mount the registry and retained evidence with the package, following
`model-operations-runbook.md`. Deleting a challenge or locked-test result directory
does not reset the registry's consumed state. Legacy releases require explicit,
provenance-backed migration; missing files do not establish UNOPENED status.
