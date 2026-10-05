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

The first deploy creates `.env` with a random n8n encryption key and mode
`0600`. Never commit that file. Services are then available at:

- FastAPI: `http://192.168.149.128:8000/docs`
- n8n: `http://192.168.149.128:5678`
- production webhook: `POST http://192.168.149.128:5678/webhook/wazuh-alert`

## Acceptance criteria

1. `docker compose ps` shows the API healthy and n8n running.
2. All Pytest tests and Ruff checks pass.
3. `/health` identifies API 1.0.0 and mock-v1.
4. The Wazuh fixture returns `status=notified`, `automation_state=SHADOW`,
   `strong_action_allowed=false`, risk 8.9 and audit outcome `NOTIFIED`.
5. n8n retains the successful execution for audit review.

## Week 1 boundary

This is a controlled sample-data vertical slice. Real Wazuh/Suricata ingestion,
dataset construction, feature extraction, model training/evaluation and any
strong response action belong to later milestones. No claim of model quality is
made from mock inference.
