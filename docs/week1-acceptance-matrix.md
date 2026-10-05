# Week 1 Acceptance Matrix — Thịnh (AI/SOAR)

This matrix reconciles the Week 1 assignment in the approved project outline
with the P1 acceptance items in the implementation plan.

| Planned item | Delivered evidence | Status |
|---|---|---|
| ML repository foundation | Git repository at `D:\Repo`, pinned runtime and atomic commits | PASS |
| FastAPI skeleton | `/health`, `/predict`, `/orchestrate/mock`, OpenAPI and JSON Schemas | PASS |
| n8n foundation | n8n 2.41.7 container with persistent storage and imported published workflow | PASS |
| Risk schema | Strict input/output models, Risk v1 policy, boundary tests | PASS |
| Mock inference | Deterministic `mock-v1` response with versioned threshold | PASS |
| Mock Threat Intelligence | Deterministic `mock-ti-v1` malicious/clean/unknown results | PASS |
| Wazuh → n8n → mock AI → notify | Production webhook tested with `WAZUH-W1-0001` fixture | PASS |
| Audit record | Workflow response and retained n8n execution contain `NOTIFIED` audit outcome | PASS |
| Interface Contract v1 | Markdown contract plus machine-readable schemas and OpenAPI | PASS |
| Safety boundary | `SHADOW`, notification-only playbook, strong action disabled | PASS |
| Reproducibility | Deploy and verification scripts; 10 tests and Ruff checks pass | PASS |

## Deliberately not claimed in Week 1

No real ML training, accuracy metric, production dataset or strong automated
response is claimed. Those require later data preparation, leakage-safe
evaluation and explicit promotion gates. Week 1 proves the contract and the
end-to-end orchestration path using controlled fixtures.
