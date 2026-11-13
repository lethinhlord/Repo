# Native lifecycle / jitter retest remediation

Input: `D:/PILOT-C2-MALICIOUS-JITTER-BEACON-20261113T114033Z-SYSMON-RETEST`,
nested same-name run directory; 16 original files, preserved read-only.
Archive SHA256: `ba571e0cd2d10afa68848b13b2148ef8cfc5468b577eb456afd62dc072f711dd`.
Frozen source: candidate.5 / `a0d3f71a137e9331e306a98e411da2065b491ccd`.

## Verified cause

- 261 raw records. Eight attributed curl processes each have Events1/3/5, HTTP
  and final EVE flow. Native3 is 1.586–1.591s AFTER native5 for every process.
- Same-tuple EVE starts are 9.613–15.966ms after native5 on another sensor clock.
  Measured clock uncertainty does not establish a strict pre-exit ordering.
- Frozen start contract and sealed checkpoint verify offline. Live archive tail
  cannot be audited here. No data loss claim is inferred from feature attribution.
- Old scoped collection counts8 while full-window online counts0/PARTIAL.
  The raw final flows exist; they lose attribution after process proof fails.
- Independent model reproduced five other chronology defects: native casing,
  delayed creation publication, delayed exit false acceptance and SQLite restart.

## Changes and boundaries

- Verified native UTC for1/3/5, contradictory aliases rejected;22 and Security
  timestamps unchanged. No post-exit grace, no identity/clock guard weakened.
- SQLite processing policy explicit; incompatible current caches refused before
  upgrade, old rows/files preserved. New Compose/API defaults use a fresh path.
- HTTP sends first, then two local transfers at rate1/2s. Same curl survives
  at least2s after response; same one-request actor and frozen cadence remain.
- Hold is bounded, not a guarantee of future sensor latency. Failed historical
  retest remains incomplete and excluded from trainable quotas.
- Reviewed source transition policy refreshed; candidate.5 receipt is not
  transplanted to candidate.6. Old candidate.4 four-pilot evidence stays frozen.

## Verification / handoff state

- Original chronology repro:5 FAILED/10 PASSED before patch; all green after.
- Independent model:148 focused tests and Ruff passed.
- Root:78 chronology/state/Compose focused tests passed;8 native HTTP tests passed,
  including real loopback curl with immediate/slow200 and500 failure.
- All7 sealed historical pilots replay VALID/RUN_EVIDENCE_CHECK_PASS unchanged.
- Full regression suite running with per-batch JUnit in external audit output.
- Actual remote jitter retest and new G7 authorization require Kiên's four VMs.
  No remote-lab PASS or model-training readiness is asserted from localhost tests.

Detailed operator procedure: `docs/sysmon-jitter-retest-20261113.md`.
External audit output: `D:/DataCodex/2026-10-05/c/outputs/sysmon-chronology-20261113`.
