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

The signing key must remain available for every package that may be rolled back.
Freeze is write-once: repeating it verifies and returns the original manifest byte for
byte; changed artifacts cannot be re-signed in place. Never edit or remove `FROZEN.json`.
For key rotation, set `MODEL_PACKAGE_SIGNING_KEY` to the new signing key and retain
previous keys in `MODEL_PACKAGE_VERIFICATION_KEYS`, a secret JSON array of strings.
Mount/pass this same keyring to all verifiers and runtime containers. Existing releases
and evaluation records retain their original signatures and opening provenance; only
new releases use the new key. Removing an old key makes its releases and records
unverifiable, so retain it through the rollback/evidence retention window.

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
export MODEL_EVALUATION_REGISTRY_DIR="$RELEASE_ROOT/.model-evaluation-registry"
sudo --preserve-env=MODEL_PACKAGE_SIGNING_KEY,MODEL_PACKAGE_VERIFICATION_KEYS,MODEL_EVALUATION_REGISTRY_DIR \
  .venv-ml/bin/python -m ml.freeze_model --package-dir "$RELEASE_DIR"
sudo --preserve-env=MODEL_PACKAGE_SIGNING_KEY,MODEL_PACKAGE_VERIFICATION_KEYS,MODEL_EVALUATION_REGISTRY_DIR \
  .venv-ml/bin/python -m ml.freeze_model --verify-only --package-dir "$RELEASE_DIR"
sudo chmod -R a+rX,a-w "$RELEASE_DIR"
sudo chmod 700 "$MODEL_EVALUATION_REGISTRY_DIR"
sha256sum "$RELEASE_DIR/FROZEN.json" | tee "evidence/$MODEL_VERSION.freeze.sha256"
```

Set the host mount to the immutable directory without changing the in-container path:

```bash
python3 - "$RELEASE_DIR" "$MODEL_EVALUATION_REGISTRY_DIR" <<'PY'
from pathlib import Path
import sys

path = Path('.env')
release = sys.argv[1]
lines = path.read_text().splitlines()
key = 'MODEL_PACKAGE_HOST_DIR='
lines = [line for line in lines if not line.startswith(key)]
lines.append(f'{key}{release}')
registry_key = 'MODEL_EVALUATION_REGISTRY_HOST_DIR='
lines = [line for line in lines if not line.startswith(registry_key)]
lines.append(f'{registry_key}{sys.argv[2]}')
path.write_text('\n'.join(lines) + '\n')
PY
export MODEL_PACKAGE_HOST_DIR="$RELEASE_DIR"
export MODEL_EVALUATION_REGISTRY_HOST_DIR="$MODEL_EVALUATION_REGISTRY_DIR"
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
   official collection or retraining. The official design defaults to `cohort_id`;
   `scenario_id` applies only to legacy/pilot configurations. Preserve the approved
   grouping/partition policy; do not reshuffle or rename runs to improve results.
5. Run inner grouped cross-validation, calibration and validation threshold selection.
6. Compare calibration, PR-AUC, FPR/FNR, threshold stability and OOD profiles against
   the active version. Accuracy alone is never an acceptance criterion.
7. Create a new versioned release; never modify the active release directory.

## 7. Rollback

Rollback changes only the read-only package mount and restarts the API/n8n. Use the last
known-good directory whose signed manifest and registry were retained. Select the
registry that was initialized for that release; retain the same evaluation evidence volume.

```bash
PREVIOUS_RELEASE="$HOME/datn-model-releases/REPLACE_WITH_PREVIOUS_VERSION"
PREVIOUS_REGISTRY="$HOME/datn-model-releases/.model-evaluation-registry"
test -r "$PREVIOUS_RELEASE/FROZEN.json"
set -a; . ./.env; set +a
export MODEL_EVALUATION_REGISTRY_DIR="$PREVIOUS_REGISTRY"
sudo --preserve-env=MODEL_PACKAGE_SIGNING_KEY,MODEL_PACKAGE_VERIFICATION_KEYS,MODEL_EVALUATION_REGISTRY_DIR \
  .venv-ml/bin/python -m ml.freeze_model --verify-only --package-dir "$PREVIOUS_RELEASE"
python3 - "$PREVIOUS_RELEASE" "$PREVIOUS_REGISTRY" <<'PY'
from pathlib import Path
import sys

path = Path('.env')
key = 'MODEL_PACKAGE_HOST_DIR='
lines = [line for line in path.read_text().splitlines() if not line.startswith(key)]
lines.append(f'{key}{sys.argv[1]}')
registry_key = 'MODEL_EVALUATION_REGISTRY_HOST_DIR='
lines = [line for line in lines if not line.startswith(registry_key)]
lines.append(f'{registry_key}{sys.argv[2]}')
path.write_text('\n'.join(lines) + '\n')
PY
export MODEL_PACKAGE_HOST_DIR="$PREVIOUS_RELEASE"
export MODEL_EVALUATION_REGISTRY_HOST_DIR="$PREVIOUS_REGISTRY"
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


## Immutable release evaluation evidence

Keep the release read-only. Evaluators accept `--evidence-dir` or
`MODEL_EVALUATION_EVIDENCE_DIR` as the separate writable evidence root. An explicit
argument must agree with the configured deployment root. Each release stores evidence
under `<root>/<SHA256-of-FROZEN.json>/`; paths must not traverse symlinks or junctions.
The API uses `/app/state/model-evaluations` in its existing persistent state volume.
Run evaluators in that same Compose service/volume, not against a new host directory:

```bash
# At the approved Week 6 gate only. The processed directory is mounted read-only.
docker compose run --rm --no-deps \
  -v "$PWD/data/processed:/evaluation-input:ro" api \
  python -m ml.evaluate --package-dir /app/ml/model-package \
  --locked-test /evaluation-input/locked_test.jsonl --unlock-locked-test
```

Public predeclared manifest/design commitments may be checked during preflight; they
are already training inputs, not hidden challenge observations. Challenge feature bytes
and locked-test bytes are accessed only after their durable consumption reservation.
The shared runtime semantic validator runs before reservation or any locked-test read.
Reservation is durable and exclusive; failure after reservation consumes the attempt.
Metrics and signed opening records are published exclusively, never replaced. The
opening signature binds model version, frozen manifest, test hash and metrics hash.
Runtime reads the same evidence store and still detects legacy package-local markers.
Only unbound legacy releases retain package-local fallback. A newly bound release
without an explicit evidence root defaults to the sibling
`<release-parent>/.model-evaluation-evidence/<freeze-digest>/`, so even the local CLI
preserves the immutable package. Docker deployment uses its configured external root. Back up the whole persistent evidence volume;
changing roots, removing markers or restoring incomplete evidence does not authorize
a new evaluation. A new deployment must retain the same evidence store for rollback.


## Durable evaluation consumption registry

New freezes bind `evaluation_registry_id` into the signed immutable manifest and
initialize an independent registry before the package is usable. The local default
registry directory is `<release-parent>/.model-evaluation-registry`; override it with
`MODEL_EVALUATION_REGISTRY_DIR` before freezing. Compose mounts the host directory
configured by `MODEL_EVALUATION_REGISTRY_HOST_DIR` at `/app/model-evaluation-registry`.
Set the host value to the directory actually initialized by freeze, as in section 2.
Docker must not create an empty directory in place of a missing registry.

The shipped API image runs as UID 0 with `cap_drop: ALL`; it does not run as UID
10001 and cannot use DAC override to read another owner's private files. For this
Ubuntu deployment, freeze, migration and host verification therefore use `sudo` with
only the three named signing/registry environment variables preserved. Registry files
and replacement signed heads remain owned by UID 0, matching the container. Keep the
registry private and outside the read-only model release. The model-only release
receives read/traverse permission before write permission is removed, so host-owned
training artifacts and root-created `FROZEN.json` are readable without DAC override.
This permission step never targets `.env`, the registry or signing keys. The examples never pass
secret values on the command line. A deployment with a different UID must provision
freeze, registry, evidence ownership and verifier access consistently for that UID;
do not add capabilities or make storage world-writable. Local library/tests may still
run entirely as one ordinary user; that is separate from the shipped Docker identity.
A restored or previously ordinary-user-owned registry must retain its verified bytes
and be provisioned for UID 0 before activation: after retaining a verified backup,
change ownership only with `sudo chown -R 0:0 "$MODEL_EVALUATION_REGISTRY_DIR"` and
keep the directory private. Verify again using the narrow sudo command. Do not
re-freeze or regenerate any ledger to correct an ownership mismatch.

Each release has a SQLite append-only signed event chain, a separately signed head,
and an interprocess lock. Registration commits both locked-test and challenge states.
The evaluators durably commit RESERVED before reading the relevant dataset and append
COMPLETE with hashes of the reservation and output files. Missing namespace/output
files cannot reset consumed state. Missing database/head/lock, truncated or conflicting
records, or mismatched output hashes fail closed; startup never creates missing
registry storage. A crash between ledger commit and head publication is also an
integrity failure requiring provenance review, never permission to retry.

Retain the entire registry alongside the entire evidence store when moving, backing up
or rolling back releases. Copying only a model release is insufficient. Restore exact
registry and evidence from an independently verified complete backup; never delete or
reinitialize a registry to clear an incomplete attempt. SQLite constraints reject
updates/deletes to event records, and signed chaining plus the separate head detects
partial truncation. This is not protection against a trusted administrator erasing or
rolling back *all* ledger, head, evidence and independent backup storage. Retain an
independent custody/audit trail to detect that administrative action.

### Explicit migration of an unbound legacy release

An older manifest without `evaluation_registry_id` is not automatically trusted as
unopened. The administrator must review independently retained original freeze receipts,
opening logs and backups and produce a signed `evaluation-registry-migration-v1` JSON
receipt with `freeze_sha256`, `approved_by`, `statuses` for both `locked_test` and
`challenge` (`UNOPENED` or `CONSUMED`), and a nonempty `source_receipts` mapping of
archived basenames to SHA-256 hashes, including the original frozen manifest. Any
UNOPENED declaration additionally requires `affirmative_unopened_attestation: true`.
Sign the reviewed receipt using the trusted package signing key via
`ml.freeze_model.sign_evidence`; the evaluator does not manufacture this approval.
Absence of output files is insufficient evidence for that attestation. If provenance
cannot establish unopened status, declare CONSUMED and retain the failure for review.

```bash
export MODEL_EVALUATION_REGISTRY_DIR="/path/to/retained-registry"
sudo --preserve-env=MODEL_PACKAGE_SIGNING_KEY,MODEL_PACKAGE_VERIFICATION_KEYS,MODEL_EVALUATION_REGISTRY_DIR \
  .venv-ml/bin/python -m ml.freeze_model --package-dir "$RELEASE_DIR" \
  --migrate-legacy-registry /path/to/approved-signed-migration.json \
  --receipt-archive /path/to/immutable-source-receipts
sudo --preserve-env=MODEL_PACKAGE_SIGNING_KEY,MODEL_PACKAGE_VERIFICATION_KEYS,MODEL_EVALUATION_REGISTRY_DIR \
  .venv-ml/bin/python -m ml.freeze_model --verify-only --package-dir "$RELEASE_DIR"
sudo chmod 700 "$MODEL_EVALUATION_REGISTRY_DIR"
export MODEL_EVALUATION_REGISTRY_HOST_DIR="$MODEL_EVALUATION_REGISTRY_DIR"
```

Before activation, use the section 2 host-mount persistence block with this
`RELEASE_DIR` and registry path to save both selections in `.env`. Runtime and later
Compose evaluation must mount this same retained registry.

The migration verifies signatures and archived hashes, rejects unopened declarations
contradicted by existing evidence, and initializes exclusively. It cannot repair or
reinitialize a release that already has a signed registry binding. Declaring CONSUMED preserves the consumed state and never creates a new evaluation
allowance. A complete historical evaluation can remain available by also supplying
`evaluation_files_sha256` keyed by evaluation kind, committing every reservation and
result/opening file. Each digest must occur in `source_receipts` and match the retained
files at the configured evidence location. The migration preserves that exact evidence
and recognizes it as complete; missing or partial consumed evidence stays fail-closed. Preserve the signed migration receipt and its source archive.
