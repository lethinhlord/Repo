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
- Unprivileged Linux UID65534 evaluated only a synthetic locked test using a
  0555 model directory; artifact hashes stayed unchanged and repeat opening failed.
- Suricata 8.0.7 processed a two-packet harmless DNS PCAP offline with network none.
  The committed protocol fixture records actual output, including distinct request
  and response engine tx_id values and their shared DNS wire id.
- Independent Terra, Astra and Sol workstreams and cross-model review were used.
  A reviewer attempt that hit a usage limit is not counted as a completed review.

## Final integration results

Final full-suite and artifact verification results are being collected before
publication. The source tag is not a certificate of remote lab acceptance.

Detailed local logs/reproductions:
D:/DataCodex/2026-10-05/c/outputs/fix-audit-20261107

## Preserved boundaries

No real raw data, original thesis Word documents, real trained package or locked
test was modified/opened. The old pilot outcomes remain historical and cannot be
relabelled into the new trainable quota. The actual lab still needs fresh candidate
acceptance. Forty to forty-eight runs are exploratory activity-profile data;
five paired cohorts do not establish general malicious intent detection or AUTO.
No deploy of the existing old features-v2 local stack is implied by the smoke.
