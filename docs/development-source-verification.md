# Three-day development release verification — 23 November 2026

Source: annotated `development-collection-v1.0.0-candidate.1` from
https://github.com/lethinhlord/Repo.git. Use the immutable tag, not a changing main
branch, for collector setup. The complete operating procedure is
[the four-VM runbook](development-three-day-runbook.md).

The explicit development protocol collects48 verified runs over three real
consecutive UTC dates,12 per stratum,16 per date. Nine paired templates cover
five Account and four HTTP/TCP profiles, including difficult benign counterparts.
All native/raw24/HTTP56 identity, process lifetime, clock, full capture/parity,
flow, context, source/G7, retry and backup/restore checks remain in force.

At source revision `a71c35491ffe453114db8f9493114cde92fc6319`, full regression
completed with1420 Windows passes/2 skips and1354 Linux passes/61 skips.
Linux used isolated CPython3.12.15 with the deployment runtime hash lock and
constrained quality dependencies. Windows used the unchanged approved builder
inventory. Ruff passed. Earlier synthetic dual-protocol G7/restore/acceptance
and native feature projection passed for both formal216 and development48.

The final addition is an early read-only `ml.development_dataset review-progress`
wrapper around the same complete native auditor. It retains all issues in the
full report; current/future uncollected plan units are pending, overdue units and
all other defects block. It never approves a dataset, even when replay is complete.
Focused regression covers pending/overdue/raw corruption/ambiguity, CLI exit,
complete-but-not-READY, exact source/data, grouping, real model fitting and notebook
export. Cross-model review found and verified the fix for a nested threshold
eligibility reporting defect. Precision target attainment is now recorded only
as a numerical diagnostic; automation remains false throughout development output.

The guide's71 Bash and30 PowerShell blocks plus six embedded Python blocks parse.
Its template inventory is checked against the deterministic plan. It preserves
full native actor output and checksum transfer after bucket/grace closes, before
finalization. All code comes from GitHub; native scripts transferred from SOC-AI
originate in that exact tagged checkout.

`config/development-training-review.json` authorizes COLLECTION_READY software
only. Its approved future manifest is null. The separate formal216 policy and
old40-run source/adoption policies remain unchanged. After actual collection,
raw replay/build and an exact committed READY manifest review are mandatory.
Safe staging produces three files, never fake validation/test partitions.

The resulting model is an offline development artifact. Its three host/day groups
support grouped exploratory selection/calibration, not independent final-model
assessment. External validation/test are NOT_COLLECTED, external CIs are null and
deployment/automation are false. Production ModelRuntime refuses the artifact.
No remote VM, real G7, new48-run data, Google Colab service execution or detection
quality is certified by these synthetic and local software checks.

The coordinating release record retains exact commits, tag object, processing
hash, canonical tracked-tree hash and test reports outside the repository. Final
publication checks use a fresh GitHub clone, real candidate capture, annotated
remote tag comparison and the development source verifier. This avoids treating
an old checkout's CRLF byte inventory as the canonical tagged source tree.
