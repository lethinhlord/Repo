# Week 2 Runbook — Thịnh (AI/SOAR)

> Historical Week 2 snapshot. Its original PASS claims apply only to that
> revision and evidence; they are not acceptance of the current release. For the
> active `features-v3` contract and pilot gates, use the collection runbook and
> model operations runbook. `dataset-manifest-v2` is a separate manifest version.

## Scope and boundary

Week 2 completes the feature pipeline on controlled Wazuh fixtures, the
VirusTotal v3 adapter, versioned asset context, the Risk v2 service and the n8n
SHADOW workflow. It does **not** claim a trained model or accuracy result; model
training starts in Week 3. The existing Week 1 endpoints and schemas remain
available for regression.

## 1. Inspect the repository on Ubuntu

Run these commands in the VMware Ubuntu terminal. Capture the complete VMware
window after each numbered checkpoint; do not expose `.env` or API keys.

```bash
cd ~/datn-ai-soar
git status --short --branch
git log --oneline --decorate -5
find api ml config fixtures n8n schemas scripts tests -maxdepth 2 -type f | sort
```

Checkpoint W2-01: the terminal must show the Week 2 branch/commit and the real
repository tree, including `ml/feature_pipeline.py`, `config/asset-context.yaml`,
`config/ti-policy.yaml` and the Week 2 n8n workflow.

The future Week 3 training toolchain is version-pinned separately so the Week 2
API image remains small. To prove the planned tools are installable without
claiming any training result:

```bash
./scripts/bootstrap_ml.sh
```

This verifies scikit-learn 1.9.1 and XGBoost 3.4.1 in `.venv-ml`.

## 2. Configure safe mock mode

The default is deterministic and makes no external TI request:

```bash
cp -n .env.example .env
chmod 600 .env
grep -E '^(VT_MODE|VT_TIMEOUT_SECONDS)=' .env
```

Expected values are `VT_MODE=mock` and `VT_TIMEOUT_SECONDS=5`. Do not print
`N8N_ENCRYPTION_KEY` or `VT_API_KEY` in screenshots.

## 3. Deploy the services

```bash
chmod +x scripts/*.sh
./scripts/deploy_week2.sh
docker compose ps
docker compose images
```

Checkpoint W2-02: `api` is healthy, `n8n` is running, the API image is
`datn-ai-soar-api:week2`, and the workflow is published only after readiness
checks. FastAPI is bound to host loopback; n8n reaches it through the Docker
network.

## 4. Prove API and versioned contracts

```bash
curl -sS http://127.0.0.1:8000/health | python3 -m json.tool
curl -sS http://127.0.0.1:8000/ready | python3 -m json.tool
curl -sS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account.json \
  http://127.0.0.1:8000/features/wazuh | python3 -m json.tool
curl -sS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account.json \
  http://127.0.0.1:8000/features/wazuh/stateful | python3 -m json.tool
```

Checkpoint W2-03: `/health` proves Week 1 compatibility. `/ready` proves the
Week 2 policy revisions, feature schema, mock TI mode and disabled strong
actions. The feature response must show `features-v3`, conservative `PARTIAL` for the fixture, one Wazuh
evidence source and no TI/asset/label field inside the ML vector. Repeating the
stateful request must report `duplicate`; changing a payload while retaining the
same alert ID must return HTTP 409.

## 5. Prove asset and TI failure-safe behavior

```bash
curl -sS http://127.0.0.1:8000/assets/WIN11-01 | python3 -m json.tool
curl -sS http://127.0.0.1:8000/assets/UNREGISTERED-HOST | python3 -m json.tool
curl -sS -H 'Content-Type: application/json' \
  -d '{"indicator":"203.0.113.66"}' \
  http://127.0.0.1:8000/ti/lookup | python3 -m json.tool
```

Checkpoint W2-04: the known workstation has criticality 3; an unknown asset is
`UNKNOWN`, protected, unscored and `review_required=true`. Mock TI is explicitly
identified as `mock-ti-v2`; it is not presented as a live VirusTotal result.

## 6. Verify the n8n workflow in the browser

Open `http://192.168.149.128:5678` inside the Ubuntu browser and select
**Week 2 - Feature TI Asset Risk (SHADOW)**. Confirm the visible chain:

1. Wazuh Alert Webhook v2
2. Verify Signed Ingress
3. Ingress Verified?
4. Find Persisted Outcome; a duplicate bypasses feature/model/TI calls
5. Outcome Missing?; only HTTP 404 enters fresh processing, other failures stop
6. Extract Incident Features (stateful)
7. Call AI Model
8. Lookup Threat Intelligence
9. Load Asset Context
10. Evaluate Risk
11. Enforce Shadow Gate
12. Decision Ready?
13. Build SHADOW or review decision
14. Persist Incident And Queue
15. Select Recorded Outcome → Dispatch Notification (exact notification revision)
16. Finalize Response
17. Respond to Webhook

Checkpoint W2-05: capture the complete VMware screen with the entire workflow.
No isolation, IP blocking, process termination or account-disabling node may
exist.

## 7. Execute the end-to-end fixture

Never paste or display the webhook secret. Load it from the root-owned `.env`
and use the canonical signing client:

The client and API use RFC 8785 JSON Canonicalization Scheme (JCS), so the HMAC
remains valid when n8n/JavaScript normalizes values such as `12.0` to `12`.

```bash
set -a
. ./.env
set +a
python3 scripts/send_signed_webhook.py fixtures/wazuh-alert-account.json \
  --url http://127.0.0.1:5678/webhook/wazuh-alert-week2 \
  --output evidence/week2-e2e-response.json
python3 -m json.tool evidence/week2-e2e-response.json
```

Checkpoint W2-06: capture the terminal result and the matching n8n execution.
The response must be `shadow_notified` or `review_notified`, `SHADOW`,
`strong_action_allowed=false`, and contain a durable persistence disposition plus a
`SENT`/`ALREADY_SENT` notification receipt. A delivery failure returns
`notification_pending` and leaves the outbox retryable.
An interrupted dispatch remains leased for `NOTIFICATION_LEASE_SECONDS` (300 seconds
by default), then becomes retryable with the same revision's `Idempotency-Key`; webhook
receivers must deduplicate that key because delivery is at-least-once. Meaningful
decision changes create a new notification revision and key while preserving the
incident ID. A queued older revision becomes `SUPERSEDED`. Retrying it returns
`decision_superseded` with `superseded_by_revision`, without claiming stale delivery.

After signature verification the workflow checks the durable event outcome before
calling features, ML or TI. Retries must keep exactly the same event ID and payload,
and use a new signing nonce. An accepted replay returns the original route, timestamp
and `notification_revision`; a raw-content conflict returns HTTP 409. Lookup failures
return 503 instead of recomputing a possibly different decision.

Online windows are fixed UTC intervals `[floor(timestamp/300)*300, +300)`. Raw Sysmon
and EVE timestamps are used. Event membership and cached replay responses survive
restart. At the first upgrade to this window implementation, retain the state volume
and drain a complete five-minute bucket before collecting new acceptance evidence;
legacy uncached feature rows do not enter new buckets. Keep each collection action
within its declared bucket using the collection runbook's deadline checks. Replay
parity compares the same selected raw set; cumulative early snapshots need not equal
the completed run vector until all relevant events have arrived.
An invalid/expired/replayed signature is HTTP 401 and is never processed. A
structurally invalid signed payload is also rejected before feature extraction.
missing service, partial feature, ineligible model, malicious/unknown TI,
protected asset or missing context must route to the review queue, never to an
action.

## 8. Run the complete verification gate

```bash
./scripts/verify_week2.sh
./scripts/verify_supply_chain.sh
git status --short
```

Checkpoint W2-07: capture the full terminal showing all Pytest tests passing,
Ruff passing, Compose validation passing and the E2E assertion succeeding.
The scripts write JSON evidence, the CycloneDX runtime SBOM and the Python vulnerability
audit under `evidence/`. Install the audit tool in the operator environment with
`.venv-ml/bin/python -m pip install pip-audit==2.10.0`; it is deliberately excluded from
the production image. The supply-chain gate also performs two clean OCI builds with the
Git commit timestamp and requires identical manifest digests; this step downloads and
installs the locked wheels twice and can take several minutes.

## Optional live VirusTotal check

Live mode is not required for deterministic Week 2 acceptance. Before enabling
it, obtain authorization to disclose the exact public indicator to VirusTotal.
Never submit private, reserved, internal, confidential or personal data.

```bash
chmod 600 .env
# Edit locally without showing the key on screen:
# VT_MODE=live
# VT_API_KEY=<secret>
docker compose up -d --force-recreate api
curl -sS http://127.0.0.1:8000/ready | python3 -m json.tool
```

The adapter accepts only public IP addresses or public domains. Timeout, stale
reports, authentication errors, rate limits, missing data and malformed replies
all become `UNKNOWN` with a typed reason code and no score.

## Screenshot storage and naming

Save full 16-inch-screen captures to:
`D:\Tài liệu\Đồ án\Ảnh báo cáo\Tuan_2_Thinh`.

Use ordered names such as `W2-01_repo.png` through `W2-07_verify.png`. Keep the
VMware title bar, Ubuntu desktop/panel, application title and relevant output in
frame. Never include passwords, tokens, `.env` contents or browser credential
dialogs.
