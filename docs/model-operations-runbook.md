# Model operations runbook

## Purpose and safety boundary

This runbook governs model activation, observation, analyst feedback, retraining and
rollback. The n8n policy remains `SHADOW`; none of these steps enable host isolation,
account disablement, process termination or network blocking.

Every deployed package must:

- use the active `features-v3` schema;
- contain all nine files listed by `ml.freeze_model.PACKAGE_FILES`: `model.joblib`,
  `thresholds.json`, `metadata.json`, `metrics_validation.json`, `eda_train.json`,
  `leakage_audit.json`, `calibration_validation.json`, `feature_profile.json`, and
  `feature_schema.json`, plus the signed `FROZEN.json`;
- have `locked_test_status: UNOPENED` at the pre-deployment gate;
- have a valid HMAC-signed `FROZEN.json` and unchanged SHA-256 file hashes;
- pass calibration, stability and OOD safeguards before automation eligibility can be
  considered. SHADOW mode remains mandatory even when eligibility is true.

## 1. Prepare secrets before freezing a package

Create `.env` on the Ubuntu SOAR-AI VM before training/freeze. Never commit or capture
the secret values in evidence screenshots.

```bash
cd "$HOME/datn-ai-soar"
umask 077
test -f .env || cp .env.example .env
python3 - <<'PY'
from pathlib import Path
import secrets

path = Path('.env')
values = {}
for line in path.read_text().splitlines():
    if line and not line.startswith('#') and '=' in line:
        key, value = line.split('=', 1)
        values[key] = value
for key in ('N8N_ENCRYPTION_KEY', 'WAZUH_WEBHOOK_SECRET', 'MODEL_PACKAGE_SIGNING_KEY'):
    if not values.get(key) or values[key].startswith('replace-with-'):
        values[key] = secrets.token_hex(32)
path.write_text('\n'.join(f'{key}={value}' for key, value in values.items()) + '\n')
PY
chmod 600 .env
```

The signing key must remain available for every package that may be rolled back. Key
rotation requires re-freezing a verified candidate; never edit `FROZEN.json` manually.

## 2. Create an immutable release directory

Train into `ml/model-package`, inspect the validation evidence, then copy the unfrozen
candidate to a versioned release directory. Replace `MODEL_VERSION` with the exact value
from `metadata.json`.

```bash
MODEL_VERSION="$(python3 -c 'import json; print(json.load(open("ml/model-package/metadata.json"))["model_version"])')"
RELEASE_ROOT="$HOME/datn-model-releases"
RELEASE_DIR="$RELEASE_ROOT/$MODEL_VERSION"
mkdir -p "$RELEASE_ROOT"
test ! -e "$RELEASE_DIR"
cp -a ml/model-package "$RELEASE_DIR"
set -a; . ./.env; set +a
.venv-ml/bin/python -m ml.freeze_model --package-dir "$RELEASE_DIR"
.venv-ml/bin/python -m ml.freeze_model --verify-only --package-dir "$RELEASE_DIR"
chmod -R a-w "$RELEASE_DIR"
sha256sum "$RELEASE_DIR/FROZEN.json" | tee "evidence/$MODEL_VERSION.freeze.sha256"
```

Set the host mount to the immutable directory without changing the in-container path:

```bash
python3 - "$RELEASE_DIR" <<'PY'
from pathlib import Path
import sys

path = Path('.env')
release = sys.argv[1]
lines = path.read_text().splitlines()
key = 'MODEL_PACKAGE_HOST_DIR='
lines = [line for line in lines if not line.startswith(key)]
lines.append(f'{key}{release}')
path.write_text('\n'.join(lines) + '\n')
PY
```

## 3. Pre-deployment gate and activation

```bash
docker compose config --quiet
./scripts/deploy_week2.sh | tee "evidence/$MODEL_VERSION.deploy.log"
curl -fsS http://127.0.0.1:8000/model/ready | python3 -m json.tool
curl -fsS http://127.0.0.1:8000/ready | python3 -m json.tool
```

Stop if either endpoint is degraded, the reported version differs from
`MODEL_VERSION`, the schema is not `features-v3`, or signed-package verification fails.
The API container healthcheck intentionally fails in those states, so n8n cannot start
against an absent or invalid model.

## 4. Runtime monitoring

Collect the counters at least daily and after every deployment:

```bash
mkdir -p evidence/model-monitoring
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
curl -fsS http://127.0.0.1:8000/model/metrics \
  | tee "evidence/model-monitoring/$STAMP.json" | python3 -m json.tool
```

Open an investigation and keep all decisions in manual review when any condition is
met:

- OOD rate exceeds 5% over at least 200 predictions for either family;
- review-required rate increases by 20 percentage points from the accepted baseline;
- a required feature begins failing schema validation or becomes structurally absent;
- model-package integrity/readiness changes from `ready`;
- at least 50 adjudicated malicious or benign examples show false-negative rate above
  5% or false-positive rate above 10%, respectively;
- data or feature distribution changes after a sensor, Sysmon, Suricata or Wazuh rule
  update.

Prediction counters, family/feature OOD counts and last-prediction time are aggregated
without raw feature values in `/app/state/model-monitoring.sqlite3`; they survive API
and host restarts. Analyst feedback is durable in
`/app/state/model-feedback.sqlite3`. `/model/metrics` combines both stores and emits
`OOD_RATE_HIGH`, `FEATURE_OOD_RATE_HIGH`, `FALSE_POSITIVE_RATE_HIGH` or
`FALSE_NEGATIVE_RATE_HIGH` only after the documented minimum sample count. Evidence
files must still be time-stamped and retained for review and version comparison.

## 5. Record analyst feedback

Use a stable, non-personal analyst identifier. Supply the `source_event_id` returned
by the workflow to bind the review to that immutable prediction, including when a
later event has updated the incident. Without it the API selects the most recent
decision for that model. A repeated submission is idempotent; changed verdicts for the
same incident, prediction fingerprint and analyst are rejected and retained for review.

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{
    "incident_id":"INC-EXAMPLE-001",
    "source_event_id":"REPLACE_WITH_REVIEWED_EVENT_ID",
    "model_version":"REPLACE_WITH_DEPLOYED_VERSION",
    "analyst_id":"soc-analyst-01",
    "analyst_label":"benign",
    "disposition":"false_positive",
    "notes":"Change ticket and interactive logon confirmed"
  }' \
  http://127.0.0.1:8000/model/feedback | python3 -m json.tool
```

`true_positive` and `false_negative` require `analyst_label=malicious`;
`true_negative` and `false_positive` require `analyst_label=benign`; unresolved cases
use `needs_investigation` plus `analyst_label=uncertain`. Do not put credentials or raw
telemetry in `notes`.

The API also checks the stored prediction: false positives require a malicious
prediction, and false negatives require a benign prediction. Multiple analysts do not
create independent samples. Monitoring counts one adjudicated incident per model;
conflicting verdicts become unresolved and are excluded from FPR/FNR denominators.
Old reviews remain in the append-only ledger. Reviews migrated without a verifiable
prediction are marked `FEEDBACK_LEGACY_UNVERIFIED` and cannot establish error rates.

## 6. Retraining gate

Retraining is allowed only after feedback and new scenario runs have been independently
reviewed. Never append production predictions directly to TRAIN.

1. Export accepted feedback and map it back to immutable raw evidence by incident ID.
2. Correct ground truth only through a new, reviewed scenario manifest revision.
3. Run `scripts/verify_collection_dataset.sh` and require no blocking audit findings.
4. Require the G7-approved cohort/challenge design and frozen split contract before
   official collection or retraining. Use `cohort_id` only with that approved design;
   the current `scenario_id` default is pilot configuration. Preserve the approved
   grouping/partition policy; do not reshuffle or rename runs to improve results.
5. Run inner grouped cross-validation, calibration and validation threshold selection.
6. Compare calibration, PR-AUC, FPR/FNR, threshold stability and OOD profiles against
   the active version. Accuracy alone is never an acceptance criterion.
7. Create a new versioned release; never modify the active release directory.

## 7. Rollback

Rollback changes only the read-only package mount and restarts the API/n8n. Use the last
known-good directory whose signed manifest was retained.

```bash
PREVIOUS_RELEASE="$HOME/datn-model-releases/REPLACE_WITH_PREVIOUS_VERSION"
test -r "$PREVIOUS_RELEASE/FROZEN.json"
set -a; . ./.env; set +a
.venv-ml/bin/python -m ml.freeze_model --verify-only --package-dir "$PREVIOUS_RELEASE"
python3 - "$PREVIOUS_RELEASE" <<'PY'
from pathlib import Path
import sys

path = Path('.env')
key = 'MODEL_PACKAGE_HOST_DIR='
lines = [line for line in path.read_text().splitlines() if not line.startswith(key)]
lines.append(f'{key}{sys.argv[1]}')
path.write_text('\n'.join(lines) + '\n')
PY
./scripts/deploy_week2.sh | tee "evidence/rollback-$(date -u +%Y%m%dT%H%M%SZ).log"
curl -fsS http://127.0.0.1:8000/model/ready | python3 -m json.tool
```

Record the reason, previous/new version, operator, UTC time and readiness response in the
incident record. Preserve the failed release for forensic review; do not delete or edit
it.

Before first production-like use of every candidate, perform this procedure once in the
isolated lab: activate the candidate, send one signed benign fixture, restore the previous
release, and verify `/model/ready` reports the previous exact version. A release is not
accepted until both signed packages pass `ml.freeze_model --verify-only` and the rollback
check succeeds. Monitoring rows are keyed by model version, so candidate observations do
not contaminate the restored model's counters.
