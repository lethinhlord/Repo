# PR21 integration fixes — 14/11/2026

User authorized fixing the two independently reproduced merge blockers.
Original PR21 head:d6e2c50; base/current candidate.6:42dab78.

## Verified evidence

- Handoff001–003:62 original files,61 external hashes and36 inner hashes match.
-001/002 are VALID trainable source6 under both base and PR; retain unchanged.
-003 has499 raw rows,9 intended failed and3 successful authentications. A native
  sensor SSH event creates an extra Windows account group under the old mapping.
  The asset fix alone restores COMPLETE component replay. Original remains STARTED.
- Frozen source6 Git LF tree0bb8ae... matches the published commit. Current and
  frozen runtime/source identity must remain distinct from laptop test runtime.

## Implemented

- Separate feature_grouping_policy=sensor-asset-origin-v1, retaining native time
  policy. Source6 caches lack grouping metadata and are refused before mutation.
  Legacy v1/v2 audit-only handling retained. Fresh DB defaults keep old files intact.
- Four failing grouping upgrade tests before patch;61 related tests pass after.
- Real aggregate and START/action/finalize/validate test replaces mocked parity.
  Independent negative controls prove old asset grouping fails the lifecycle case.
- Actual repository source transition test reproduces stale G7 policy, rather than
  only checking a synthetic fixture. Policy and candidate.7 binding refreshed after review.
- Dedicated source7 collection checkout keeps source6 trainable runs unchanged and
  preserves the single-candidate audit/build rule. No automatic dataset-source migration.

## Verification and release work

- Real evidence001/002 remains VALID/PASS;003 component replay is COMPLETE9/3.
- All7 historical pilots validate with current code. Original62 handoff files unchanged.
- Actual4pilot/preflight/backup replay rejects different laptop runtime and passes
  an explicitly labeled simulation of the unchanged SOC runtime. No lab receipt issued.
- 84 Bash blocks and 26 Windows PowerShell 5.1 blocks parse; local doc links resolve.
- Final independent GPT-6 Astra review finds no additional blocker. Duplicate plan
  ambiguity fixed; upgrade and G7 steps now lead to one plan, without4pilot reruns.
- 13 core integration/release tests and Ruff pass. Full regression completed:
  1167 unique cases in102 files;1166PASS,0failures/errors,1Windows symlink skip.
  All8 native HTTP/Windows actor cases pass. All test input hashes unchanged.
- Production tree unchanged since4b20b4c; subsequent commits clarify docs and
  verification only. Release target:immutable collection-v4.0.0-candidate.7.
- Local full JUnit, core RED/GREEN, immutable evidence replay, command syntax,
  G7 simulation and final release/guide hashes retained under
  D:/DataCodex/2026-10-05/c/outputs/pr21-fix-20261114/.

No original dataset/state or old tag is rewritten.
New G7 acceptance must be issued on Kiên's actual SOC runtime with fresh context;
offline tests and runtime-field simulations are never production authorization.
