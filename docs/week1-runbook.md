# Week 1 Runbook

## Delivered scope

- Git repository and reproducible pinned Python container.
- Strict FastAPI request/response contract and exported schemas.
- Deterministic mock inference, mock TI and Risk v1.
- n8n workflow: Wazuh webhook → normalize → mock AI → SHADOW notification.
- Docker Compose deployment on the Ubuntu VM.
- Automated unit, contract, lint, Compose and end-to-end checks.

## Deploy on Ubuntu

```bash
cd ~/datn-ai-soar
chmod +x scripts/*.sh
./scripts/deploy_week1.sh
./scripts/verify_week1.sh
```

Use a clean committed checkout: the reproducible image builder rejects changed
runtime inputs. Install Docker with Compose/Buildx, OpenSSL, Git and curl first.
No trained model package or enrolled context baseline is needed for this slice.

The first deploy creates `.env.week1` with random n8n encryption, webhook and
package-signing keys and mode `0600`; subsequent deploys retain nonempty keys.
Never commit that file. Keep it with the Week 1 n8n volume when backing up.
Scripts select `compose.week1.yaml` and project `datn-week1` explicitly, leaving
the trained deployment's `.env`, volumes and Compose definition separate. Stop
any other service using local ports 8000/5678 before starting this slice.

- FastAPI: `http://127.0.0.1:8000/docs`
- n8n: `http://127.0.0.1:5678`
- production webhook: `POST http://127.0.0.1:5678/webhook/wazuh-alert`

For a remote VM, forward the loopback ports over SSH, for example
`ssh -L 8000:127.0.0.1:8000 -L 5678:127.0.0.1:5678 user@vm`.
The Week 1 webhook accepts fixture data without the later signed-ingress flow;
keep this sample slice on loopback. Its workflow builds a SHADOW notification
in the returned execution data and does not send a real external notification.

The API uses the reproducible `datn-ai-soar-api:week1` tag. Verification derives
`datn-ai-soar-api:week1-qa` from that tag and installs Git plus the pinned QA
requirements (including pytest/Ruff) there; the runtime image continues to
contain runtime dependencies only.
The verifier runs tests/lint in the QA image, validates the selected Compose
file, retries webhook registration, and stores the API and end-to-end responses
under `evidence/week1-*.json`.

## Acceptance criteria

1. `docker compose ps` shows the API healthy and n8n running.
2. All Pytest tests and Ruff checks pass.
3. `/health` identifies API 4.0.0. `/ready` reports `inference_mode=mock`,
   `model_status=not_configured` and `ti_mode=mock`. Its overall `degraded` status
   is expected: this endpoint retains the trained-deployment readiness contract.
   The Week 1 container healthcheck uses `/health` instead.
4. The Wazuh fixture returns `status=notified`, `automation_state=SHADOW`,
   `strong_action_allowed=false`, risk 8.9 and audit outcome `NOTIFIED`.
5. n8n retains the successful execution for audit review.

To stop only this slice, run:

```bash
docker compose -p datn-week1 -f compose.week1.yaml --env-file .env.week1 down
```

Do not add `--volumes` unless intentionally deleting its execution history.

## Week 1 boundary

This is a controlled sample-data vertical slice. Real Wazuh/Suricata ingestion,
dataset construction, feature extraction, model training/evaluation and any
strong response action belong to later milestones. No claim of model quality is
made from mock inference.
