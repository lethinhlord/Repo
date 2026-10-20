# Implementation Plan: Four-VM Training Data Collection

## Overview

Build a tested collector and dataset readiness auditor, then write a new executable
Vietnamese runbook whose commands are traced to those tools and the existing ML contract.

## Architecture Decisions

- Forward NET-SENSOR Suricata EVE through its Wazuh Agent so SOC-AI has one durable source.
- Capture append-only Wazuh Archive bytes using size/device/inode cursors; fail on rotation.
- Use a separate attribution document so ground truth never becomes a model feature.
- Generate one aggregate incident per run; split only by `run_id`.
- Readiness is fail-closed at 10 valid runs per stratum; 12 is the preferred target.

## Task List

### Phase 1: Contract and collector
- [x] Task 1: Add failing collector tests for account, C2 and source-integrity gates.
- [x] Task 2: Implement scenario collection module and CLI until focused tests pass.

### Checkpoint: Collector
- [x] Account and C2 fixtures produce strict IncidentRequest records.
- [x] Missing/rotated telemetry fails without partial final output.

### Phase 2: Dataset readiness
- [x] Task 3: Add failing auditor tests for counts, diversity, evidence and leakage.
- [x] Task 4: Implement auditor module and CLI until focused tests pass.

### Checkpoint: Auditor
- [x] Four-stratum report shows actual/required/shortage and stable exit status.
- [x] Ten-run readiness and twelve-run target policies are tested.

### Phase 3: Operator delivery
- [x] Task 5: Add pinned source/taxonomy/catalog configuration.
- [x] Task 6: Write complete runbook and replace the standalone Kiên guide.
- [x] Task 7: Run focused tests, full pytest, Ruff and a generated 40-run audit smoke.

### Checkpoint: Complete
- [x] All success criteria in `SPEC-data-collection.md` pass.
- [x] Commands in the guide correspond to files that exist in the repository.
- [x] No secret, raw dataset or locked-test content is introduced.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Wazuh rotates during a run | Missing/corrupt evidence | Detect inode/size changes and reject the run |
| Background Windows events contaminate C2 | Label noise | Require explicit process/IP/port/domain attribution |
| Suricata is invisible | False zero feature | Require attributable non-alert EVE evidence for every C2 run |
| Raw rows leak across splits | Inflated metrics | One sample/run and grouped split by `run_id` |
| Operator edits generated files | Unreproducible data | Checksums and validate command; rerun instead of repair |

## Open Questions

None. Runtime VM-specific values are supplied through versioned configuration and run drafts.
