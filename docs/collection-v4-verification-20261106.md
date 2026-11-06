# Collection candidate verification — 6 November 2026

Candidate: collection-v4.0.0-candidate.1. This record concerns software and the
operator procedure; onsite acceptance on Kiên's four VMs remains required.

## Result and scope

- Linux final full suite: **784 passed, 50 Windows-only skips**, zero failures.
- Windows: **833 unique cases passed, one symlink privilege skip**, combining the
  full suite with the final changed-scope rerun, taking the latest result per case.
  The first full run found one obsolete notebook test fixture missing the newly
  required design file/hash. The fixture was updated, three rejection cases added,
  and the exact notebook cell passed against a real local detached Git checkout.
  The gate was retained. The former failing case also passed a final standalone run.
- Final Windows provenance/integration run: **24 passed**, including all 28 action
  profiles, four-pilot/preflight/backup/acceptance flow and 40 fresh synthetic
  trainable executions through READY audit and a cohort split without pilot leakage.
- Ruff passed. Runbook commands parsed: **70 Bash blocks, 26 PowerShell blocks,
  five Python heredocs**; 12 pure Python notebook cells parsed. The delivered
  enrollment checker also executes against a rebuilt synthetic baseline.
- All four real input pilots replay **VALID / RUN_EVIDENCE_CHECK_PASS** on a copy.
  All **432 original input files** were rehashed without changes. Their purpose
  remains pilot; neither their source receipt nor their quota is backdated.
- The official Wazuh assistant at
  [8739c47527bf18563eba44140db9a5e36568cee0](https://github.com/wazuh/wazuh-installation-assistant/tree/8739c47527bf18563eba44140db9a5e36568cee0)
  built a 4.14.9 installer in Linux. Bash syntax and exact pinned dist-detect body
  checks passed. No installer was executed. The rolling 4.14 URL had advanced to
  4.14.10, so the active guide now uses immutable assistant source.

The three initial independent model reviews covered HTTP attribution, experimental
design and release gates. Root integration and the final Windows/Linux checks
followed those reviews. Additional model turns were unavailable due to usage limits;
no additional independent final approval is asserted.

## Preserved contracts

The candidate retains features-v3/24 fields, full raw capture, finite intake cutoff,
60-second grace, source continuity, native clocks, final-flow counters, frozen
context, online/offline parity and the locked-test boundary. HTTP Event3's two
literal unknown-image sentinels require consistent Event1/GUID/PID/user/chronology
proof; DNS and conflicting creation evidence remain strict.

Official profiles use neutral shared actors/endpoints and deterministic frozen
schedules. Trainable collection requires actual candidate-bound pilot/preflight/
restore evidence. Audit rejects mixed frozen source/runtime identities even when
configuration hashes match; builder recaptures the accepted source/runtime. Training
and Colab bind the predeclared design hash and cohort grouping. Historical protocol
fixtures remain isolated under fixtures/legacy for regression testing.

## What remains an onsite action

Kiên must obtain the exact GitHub candidate, install and inventory the actual four
VMs, run fresh canary/enrollment and all four transport pilots, then create the
evidence-bound acceptance. Only then may the 40–48 trainable runs start. Follow
[the complete runbook](scenario-collection-runbook.md). These steps do not require
an offline code bundle or a manually written PASS.

Synthetic tests certify plumbing, not telemetry or model quality. This release does
not claim real four-VM acceptance, real model training, locked-test evaluation,
production deployment or automatic response authorization. Five paired cohorts per
family support an exploratory activity-profile benchmark; they leave insufficient
validation groups for automation uncertainty. Preserve SHADOW/ASSISTED.

## Local evidence

The detailed logs, JUnit reports, initial model reviews, immutable-input inventory,
real-pilot replay and checksum receipt are under:

    D:\DataCodex\2026-10-05\c\outputs\training-release-20261106

Key files: linux-final-full.xml, windows-full.xml, final-provenance.xml,
windows-cleared-last-failure.xml, windows-reconciled.json,
document-command-check.json, real-pilot-replay.json and verification-files.sha256.
Publication/tag/guide-copy hashes are recorded separately in publication-receipt.json
after GitHub verification, avoiding a source commit containing its own hash.
