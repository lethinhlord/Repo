# Capability Map: Training Data Collection

| Module id | Responsibility | Depends on |
|---|---|---|
| `run-contract` | Freeze run metadata, attribution, evidence and incident contracts | — |
| `scenario-collector` | Start/finalize/validate one run from Wazuh Archives and forwarded Suricata EVE | `run-contract` |
| `dataset-auditor` | Validate all runs, count four strata and enforce leakage/diversity gates | `run-contract` |
| `operator-runbook` | Reproducible four-VM installation, scenario execution and evidence workflow | `scenario-collector`, `dataset-auditor` |

Build order: `run-contract` → `scenario-collector`, `dataset-auditor` → `operator-runbook`.
