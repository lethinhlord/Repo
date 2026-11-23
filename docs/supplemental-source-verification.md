# Supplemental source release — 23 November 2026

Code and operator handoff were merged in [PR25](https://github.com/lethinhlord/Repo/pull/25).
The immutable annotated collection tag is
[supplemental-collection-v1.0.0-candidate.1](https://github.com/lethinhlord/Repo/tree/supplemental-collection-v1.0.0-candidate.1).
The collector must use that tag; later documentation commits on main do not
replace the candidate identity.

| Binding | Value |
|---|---|
| Collection commit | `70ac35d6a2b028189512879fb37e13747ffdf202` |
| Annotated tag object | `d39486d20b2bba01661c0ce1bbbb10b5f5915a29` |
| Processing SHA-256 | `58c4cf68e676b690268aafc2f719e9449b186f4827cc9a982fc20e2ef8f80399` |
| Candidate tracked-tree SHA-256 | `0a7c4d85faaf528261a8f9ee1febf705e123b51ee00d013dc6bf696199040a98` |
| Source policy | `COLLECTION_READY`; approved future manifest is null |

The candidate fingerprint above was captured from a fresh checkout of the
published GitHub tag, checked against the remote annotated tag and accepted by
the prospective source verifier. An older Windows worktree retained CRLF bytes
in eight files despite Git reporting it clean. Its byte fingerprint was correctly
rejected by the verifier. Those local line endings were restored to the tracked
LF bytes without changing file contents or the published tag. Use the fresh
tagged checkout required by the operator guide; a clean status alone is not a
substitute for the candidate fingerprint check.

Validation completed:

- Windows: 1,400 passed and 2 skipped across the full suite and affected-test
  reruns. Counts are a union of test identities, using the later result for a
  repeated case; this is not described as one all-green full-suite invocation.
- Linux x86_64, CPython3.12.15: complete suite, 1,334 passed and 61 platform skips.
  Runtime packages were installed from the hash lock; quality/notebook packages
  were constrained to the same deployment versions. Dependency consistency and
  Ruff passed. Node workflow regression tests executed JavaScript.
- Final source approval/conformance: 12 passed after the policy was committed.
  The pre-install source verifier imports using the standard library alone.
- Native Windows PowerShell/curl exchanged bounded GET/POST payloads against a
  loopback HTTP server. Synthetic native-event/EVE fixtures exercised G7/restore,
  raw replay, HTTP enrichment, grouped fitting, export, freeze and inference.
  These are software tests, not observational SOC data or real lab acceptance.
- Two independent model reviews covered lineage, operator sequencing, source
  guards and notebook behavior. Confirmed defects were reproduced and corrected.
  The final independent focused review ran 19 tests successfully and found no
  additional reproducible blocker within its inspected scope.
- The final guide's 100 Bash/PowerShell blocks and 6 embedded Python blocks parse.
  The local Kiên.txt is byte-identical to the canonical guide, SHA-256
  `ef93c438e5937302d39a89f34cdd6b531bade84b1798311e506b43847c8d386c`.

The measured approved Windows builder uses CPython3.12.14 and installed-package
inventory SHA-256
`2cd678155bd2f54087487703e1a74f008e88b926dc197eb8e9ea9697fa2976e8`.
No packages were changed in that environment. Collector runtime inventory is
recorded separately by real G7; an arbitrary system Python is not automatically
approved to build the dataset.

Local verification logs, XML reports, review notes, source-approval proof and
published-candidate metadata are retained under
`D:\DataCodex\2026-10-05\c\outputs\supplemental-collection-v1-20261122`.
Historical raw data, partitions, packages, policies and annotated tags were
preserved; no old locked-test file was opened for this work.

Use the [complete four-VM guide](supplemental-collection-runbook.md) for setup,
registration, collection, recovery and handoff. Kiên still needs four new pilots
and G7 v3 once, followed by the registered 216 execution units. There is no new
observational supplemental dataset, exact-manifest READY approval, hosted Colab
run or model-quality approval yet. The
[new notebook](../notebooks/supplemental_train_colab.ipynb) intentionally blocks
training until the real dataset receives that exact committed review. New
packages remain research/ASSISTED/SHADOW; no automatic response is authorized.
