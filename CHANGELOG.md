# Changelog

## Unreleased

### Added

- Initial repository for the Week 1 AI and SOAR foundation.
- Week 2 behavioral feature schema and deterministic Wazuh incident aggregation.
- Fail-safe VirusTotal v3 adapter with strict validation and typed degradation.
- Versioned asset context and YAML-backed Risk v2 evaluation.
- n8n Week 2 SHADOW workflow with a degraded manual-review branch.
- Week 2 contract exports, runbook, acceptance matrix and verification scripts.
- Separately pinned scikit-learn 1.9.1 and XGBoost 3.4.1 for Week 3 preparation.
- Fail-closed four-VM scenario collector with immutable run ground truth, attributed
  Wazuh/Sysmon/Suricata evidence and SHA-256 integrity checks.
- Dataset readiness auditor enforcing 10-run minimum, 12-run target, scenario diversity,
  grouped-run boundaries and mandatory C2 Suricata evidence.
- Versioned 20-scenario catalog (five per stratum) and complete Vietnamese collection runbook.
- Durable per-model prediction/OOD counters, feature-level drift alerts and
  analyst-feedback quality thresholds for post-deployment monitoring.
- Timestamp-normalized OCI builds with bytecode-free dependency installation and a
  two-build digest verification gate.

### Security

- Bind FastAPI to host loopback and drop Linux capabilities in Compose.
- Keep VirusTotal credentials environment-only and reject non-public indicators.
- Represent missing TI/asset scores as null and force manual review.
