# Collection candidate verification — 8 November 2026

Candidate: collection-v4.0.0-candidate.2.
Baseline audited: 7a967c5. See the remediation ledger for every original finding
and the additional edge cases discovered during independent model review.

## Implemented scope and evidence

- Per-action protocol/flow proof, backup inventory, native host transfer checks,
  frozen audit quotas/seed/cohort allocation, training provenance/calibration,
  durable immutable evaluation, challenge replay and runtime lifecycle safety.
- Real disposable n8n/API Week 1 execution passed with mock inference, SHADOW and
  no strong action. It used separate project/ports/volume, not the existing stack.
- The actual runtime image evaluated only synthetic locked tests under UID0 and
  UID65534 with all Linux capabilities dropped and model volumes mounted read-only.
  Artifact hashes stayed unchanged and repeat opening failed for both identities.
- Suricata 8.0.7 processed a two-packet harmless DNS PCAP offline with network none.
  The committed protocol fixture records actual output, including distinct request
  and response engine tx_id values and their shared DNS wire id.
- Independent Terra, Astra and Sol workstreams and cross-model review were used.
  A reviewer attempt that hit a usage limit is not counted as a completed review.

## Final integration results

The source tag is not a certificate of remote lab acceptance.

| Environment | Passed | Skipped | Final unresolved failures |
|---|---:|---:|---:|
| Native Windows full suite | 1099 | 1 | 0 |
| Linux runtime-derived QA, full suite plus affected-module rerun | 1036 | 57 | 0 |
| Final affected-module rerun, each OS | 15 | 0 | 0 |

Windows collected 1100 cases and exited 0; its one skipped case requires symlink
creation unavailable to that runner. Linux collected 1093 cases. Its 57 skipped
cases require native PowerShell. The strict Linux full invocation had 1035 passes
and one schema-export failure from the test module collected before correction.
The current three affected modules then passed all 15 cases on both operating
systems. The Linux totals above use the latest result for each unique test ID;
they do not describe a single all-green full invocation. The original failing log
and exact reconciliation are retained in linux-final-full.xml and
linux-reconciled-results.json. The official 40-run and preferred 48-run protocol
integration cases passed on both operating systems with synthetic data.

Additional checks complete:

- Runtime attestation: all 60 API/ML/config files and all 32 runtime distributions
  match between checkout, unmounted runtime image and derived QA image. QA adds
  only pytest/Ruff and their testing dependencies, plus Git/Node.js tooling.
- The first Linux integration run exposed CRLF in a locally edited shell script
  and a schema-export test writing into a read-only source mount. The shell uses
  LF, and the exporter now accepts an external output directory. Fifteen related
  tests passed on both Windows and Linux after those corrections; all 19 exported
  Week 2 contracts are compared against their committed JSON schemas.
- Guide syntax: 70 Bash blocks, 26 PowerShell blocks, 5 embedded Python programs
  and 12 pure-Python notebook cells parsed successfully. This is a syntax check,
  not execution of remote lab instructions.
- The 432 original pilot files and all three original thesis Word documents
  retain their recorded hashes. Kiên.txt will be replaced only after publication
  with the exact published runbook, retaining its previous version outside Git.

Detailed local logs/reproductions:
D:/DataCodex/2026-10-05/c/outputs/fix-audit-20261107

## Preserved boundaries

No real raw data or original thesis document was modified. No real-data model was
trained and no real locked-test dataset was opened. The old pilot outcomes remain
historical and cannot be relabelled into the new trainable quota. The actual lab still needs fresh candidate
acceptance. Forty to forty-eight runs are exploratory activity-profile data;
five paired cohorts do not establish general malicious intent detection or AUTO.
No deploy of the existing old features-v2 local stack is implied by the smoke.
