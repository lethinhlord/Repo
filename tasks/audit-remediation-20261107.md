# Audit remediation ledger — 7–8 November 2026

Baseline: 7a967c5. Target: collection-v4.0.0-candidate.2.
All original training data and historical evidence remain unchanged.
No safety feature is removed to obtain a passing test.

| Finding | Implemented contract | Regression evidence |
|---|---|---|
| F01 | Per-action Sysmon/transaction/final-flow coverage | test_collection_audit_regressions |
| F02 | HTTP result; frozen DNS resolver, standard QUERY/A response, real wire identity | test_collection_audit_regressions; test_suricata_protocol_wire |
| F03 | Bidirectional FINALIZED/ABORTED source and restored inventory | test_collection_audit_regressions; test_release_backup |
| F04 | Complete nonempty host checksum/archive/source receipt | test_host_backup_verifier on PS5/PS7 |
| F05 | Immutable quota/repetitions and designated target cohorts | test_audit_completion_contracts; official 40/48 run integration |
| F06 | Seed uniqueness includes every valid purpose | test_audit_completion_contracts |
| F07 | Shared local/Colab builder source/config binding | test_ml_audit_fixes; notebook/handoff regressions |
| F08 | Configured ECE bins throughout curves/metrics/evaluation | test_ml_audit_fixes |
| F09 | Outer selection and calibration exclude assessment labels | test_evaluation_registry; test_ml_audit_fixes |
| F10 | Verified idempotent freeze, unchanged existing signatures/keyring | test_ml_audit_fixes |
| F11 | Runtime semantic validation before test reservation/read | test_ml_audit_fixes |
| F12 | Read-only release, external outputs and signed consumption registry | test_evaluation_registry; non-root Linux probe |
| F13 | Reject superseded expired notification claims | test_incident_store |
| F14 | Private/special-use root and child TI filtering | test_threat_intelligence |
| F15 | Actual model-free bootstrap plus source/dependency/image attestation | test_week1_bootstrap; test_runtime_artifact; separate real n8n smoke |
| C01 | Scoped lifecycle across buckets, expiry/replay, termination forwarding/clock | test_process_lifetime; test_collection_configuration |
| C02 | Selected running image must match the reviewed runtime and QA source/dependencies | test_runtime_artifact; actual image attestation and disposable deployment |
| C03 | Post-freeze context-faithful challenge evaluator | test_challenge_evaluation; test_evaluation_registry |

Cross-model reviews found additional edge cases inside these findings:
output deletion resetting evaluation, model-choice leakage, default package-local
evidence, DNS endpoint/outcome/type/opcode, incorrect equality of Suricata engine
tx_id, cross-purpose seed reuse, target cohort allocation, stale process resurrection,
retained-ID collisions and checkout mounts masking the tested runtime image.
Each actionable case was reconciled into code and regression tests. Public
manifest/design preflight was clarified as allowed public provenance, not secret
challenge observation; it was not changed to consume an evaluation unnecessarily.

## Verification gate

Implementation, focused red/green checks and cross-model review are complete.
Native Windows: 1099 passed, 1 unavailable-symlink skip. Linux: 1036 passed and
57 native-PowerShell skips after the documented 15-case affected-module rerun;
the original failed invocation is retained. Official synthetic 40/48-run cases,
source/image/dependency attestation, real disposable n8n execution, read-only
evaluation under both runtime identities, document parsing and Ruff passed.
See the verification document for evidence and limits. Publication uses the
annotated candidate tag; an external receipt records its full merged commit.

## Scope that remains actual lab work

- G7 on Kiên's four VMs; fresh raw evidence, enrollment, canary and pilots.
- New 40 minimum/48 preferred trainable runs and separate challenge data.
- Real model quality, independent-cohort uncertainty and Week 6 locked test.
- Final response executor/rollback/verify and A/B/C project benchmarks.

Those are explicit milestones, not silently waived checks. The exploratory
five-cohort design does not establish AUTO readiness; preserve SHADOW/ASSISTED.
C04 is retained as this statistical limitation. C05 is the pending real-lab/data
and later project deliverables, not a claim that synthetic tests completed them.
C06 is recorded by the user-approved four-VM inventory and role boundaries in the
current collection runbook; the original thesis Word files remain unchanged.
