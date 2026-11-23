# Supplemental collection v1 — authorized implementation, 22 November 2026

## Outcome and scope

Deliver a reproducible prospective collection/training path for Kien's existing
four-VM isolated lab. Preserve original40 raw/evidence, old partitions, model
packages and immutable collection/training tags. Existing releases retain their
own pinned trainer source; no old hash or approval is rewritten to authorize new
observations. No real lab acceptance or improvement in model accuracy is claimed
from synthetic tests. This computer has no operating four-VM SOC; actual source
enrollment and G7 remain operations Kien must execute using the new runbook.

The first supplemental target is controlled account behavior and HTTP/TCP
activity profiles. DNS plumbing/canary and ambiguous-intent challenge coverage
remain; a TCP model is never described as general DNS-C2 detection. No arbitrary
remote commands, exploitation, credentials or public targets are needed by the
new HTTP simulator. All response execution remains disabled.

## Capability map / build order

| Module | Responsibility | Depends on |
|---|---|---|
| campaign-design | Versioned templates, registered contexts, fixed roles and quotas | existing frozen profile contracts |
| campaign-capture | Native action workflows and sealed plan/run binding | campaign-design, existing collector |
| evidence-profile | Label-independent verified parent/network/transaction features | shared identity/chronology proof |
| campaign-dataset | Fresh input audit, deterministic transform, provenance and role commitments | capture, profile |
| campaign-training | Grouped CV, calibration and distinct visible/locked loading | dataset |
| operator-handoff | Github-only setup, acceptance, execution, validation, backup and Colab guide | all above |

The user's eight-point implementation instruction authorizes these boundaries
and the progression below; no extra approval gate is introduced.

## Fixed scientific and operational contract

- Predeclare18 paired context slots per family:10TRAIN/4VALIDATION/4LOCKED,
  three independent action executions per label/slot (108/family,216 total).
  This is a starting research budget, not a promised sample-size sufficiency.
- Template IDs identify behavior. Scenario-instance IDs identify their planned
  context. Context registration must record actual environment/session/time
  boundaries, not merely new labels or seeds. Related sessions/environment
  blocks cannot cross partitions. Same-template new-context assessment and
  unseen-template diagnostics must be named separately.
- No training from pilot/challenge runs. Ambiguous observations are challenge
  REVIEW expectations, never made separable by a label/nonce/IP/filename token.
- Predeclared variation shared across labels includes tool, endpoint/port,
  parent environment and schedule ranges. New request/response/flow patterns
  are observable transactions, not special class labels inserted in payloads.
- Keep native process identity/lifetime/clock validation, original timestamp
  semantics, full-window raw replay, late-arrival checks and complete flow
  closure. Additional process/HTTP evidence has explicit availability masks.
- Keep the original24 and stream20 values. A separately registered feature
  profile may append proven transaction/flow/process-context values. No mutation
  of features-v3 or features-v4-stream-v1; no extra-field/schema wildcard.
- A fresh prospective manifest binds source/runtime/config/design/plan,
  registration, raw inventory, audited records and fixed membership. Unreviewed
  sources, incomplete or duplicate runs, changed roles and mixed releases fail.
- Export only train.jsonl, validation.jsonl, dataset_manifest.json and a checksum
  for Colab. Locked data stays on the trusted lab; model selection/feature
  design/calibration fit remains TRAIN-only. Current observed validation is
  historical development evidence, not fresh proof for the next experiment.
- Retain precision>=.90, Brier<=.20, ECE<=.15, threshold stability and independent
  group checks. Report uncertainty and actual coverage. Research-only source
  scope and model gates do not authorize strong automatic response.

## Implementation / verification slices

1. RED/GREEN campaign design, registration, frozen plan, role and template
   semantics; fixed inventory, metadata and leakage guards.
2. Native HTTP workflow and telemetry contract; execution receipt and selected
   design/catalog release binding; meaningful real-protocol/native-runner tests.
3. Shared verified-observation enrichment; batch/stateful/offline equality and
   schema/runtime mismatch tests. No label or execution nonce used as features.
4. Prospective raw/evidence audit, deterministic builder, exact source/role/row
   commitments, atomic four-file staging and hostile mutation tests.
5. Trainer/notebook integration; synthetic E2E from capture through partition
   verification and real fitting, never presenting generated telemetry as a real
   dataset. Complete legacy regression and independent cross-review.
6. Github publication with immutable new candidate and complete Kien.txt. Leave
   real acceptance pending until Kien supplies actual raw pilots/preflight and
   verified restore under that exact source/runtime. No fictitious G7 receipt.

Commands use D:/Repo/.venv-codex/Scripts/python.exe -B -X utf8 for development,
pytest for focused RED/GREEN and full regression, and ruff check . for lint.
No new dependencies or package changes to the approved local processing env.

## State

Software and handoff completed on 23 November 2026; PR25 merged at
70ac35d6a2b028189512879fb37e13747ffdf202. Annotated collection tag:
supplemental-collection-v1.0.0-candidate.1. Source approval is COLLECTION_READY;
there is no future dataset READY approval. See
[release verification](../docs/supplemental-source-verification.md) and the
[complete operator guide](../docs/supplemental-collection-runbook.md).

Remaining real operations: Kiên executes four fresh transport pilots and G7 v3
once on that tag, collects the preregistered 216 units on actual host/UTC-day
blocks, and hands off sealed evidence. Thịnh audits/builds the new data and commits
its exact manifest review before Colab training. These are not certified by
software tests and have not been performed on this computer.
