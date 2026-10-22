# Week 2 Acceptance Matrix — Thịnh (AI/SOAR)

| Planned item | Acceptance evidence | Status |
|---|---|---|
| Feature pipeline on fixture | Shared online/offline `features-v2` derivation, versioned JSON Schema, account/C2 fixtures | PASS |
| Incident window and dedup | Deterministic 1–5 minute half-open grouping, duplicate suppression and conflict rejection tests | PASS |
| Leakage control | Vector contains observed behavior only; TI, asset, labels and ground truth are excluded | PASS |
| Stable feature contract | Ordered vector, family applicability, range/finite-value validation and generated API schemas | PASS |
| VirusTotal adapter | Fixed HTTPS v3 endpoints, environment-only key, strict response validation and typed failure reasons | PASS |
| Safe TI degradation | Reserved/private input is not sent; timeout/429/404/5xx/stale/malformed/missing data becomes `UNKNOWN` | PASS |
| Asset context | Versioned inventory for WIN11-01/02, SOC-CORE and SOAR-AI; unknown assets are protected and require review | PASS |
| Risk v2 | YAML is loaded and validated; missing TI/asset is excluded and forces review | PASS |
| n8n mock workflow | Feature → mock AI → TI → asset → Risk → SHADOW guard → notification/degraded response | PASS |
| Safety boundary | Strong actions are structurally disabled; only create/update/notify is allowed | PASS |
| Week 1 regression | Original health and orchestration contracts remain supported; prediction fails closed without a verified package | PASS |
| Reproducibility | Pinned images/dependencies, deploy/verify scripts, OpenAPI and JSON Schemas | PASS |
| Audit evidence | API readiness, feature response and E2E JSON are written under `evidence/`; n8n retains executions | PASS after VM verification |

## Deliberately not claimed

Week 2 does not claim trained LR/RF/boosting models, accuracy/F1/ROC-AUC,
production-quality labels, a live VirusTotal quota, or autonomous containment.
Those claims require the Week 3+ training and safety promotion gates.
