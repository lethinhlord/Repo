# DATN AI SOAR

Repository for the AI and SOAR workstream of the graduation project.

Week 1 establishes a reproducible development environment, Interface Contract v1,
a mock FastAPI inference service, an n8n orchestration workflow, deterministic
Threat Intelligence and Risk mocks, and end-to-end verification evidence.

Start with `docs/week1-runbook.md`. The frozen request/response rules are in
`docs/interface-contract-v1.md`; machine-readable schemas are under `schemas/`.

On the Ubuntu VM, deployment and verification are reproducible with:

```bash
./scripts/deploy_week1.sh
./scripts/verify_week1.sh
```
