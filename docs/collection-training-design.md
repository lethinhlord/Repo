# Paired training collection design

Status: design implemented; actual four-VM collection acceptance remains pending. This document does not open G7, certify telemetry, or authorize automation.

## What this experiment can establish

The 24-feature classifiers benchmark predeclared lab activity profiles. Labels describe controlled benign and simulated abusive/C2-like executions. Counts, cadence, account spread and authentication outcomes are observable; the operator's intent is not. A successful classifier here is not evidence of general C2 detection. A legitimate process can generate every listed network pattern. Such matched intent-only streams belong in the challenge set and require REVIEW rather than a confidently inferred intention.

The topology remains four VMs: Kali; WIN11-TARGET; combined SOCAI/Wazuh; NET-SENSOR router/Suricata. No extra VM, IP alias, production target, executable payload, or external endpoint is required. All HTTP actions request the same harmless body from `http://10.40.0.10:8081/beacon`; all DNS actions use the same `www.datn.test` suffix and resolver `10.40.0.10`. All account identities are shared disposable `datn_lab01`, `datn_lab02`, `datn_lab03` accounts. HTTP uses curl.exe; both DNS labels use the same PowerShell runner and nonce-qualified unique-query format. The taxonomy remains unchanged: its marker is deliberately shared across labels, never a label oracle.

## Frozen scenario/cohort mapping

The executable source of each schedule is `execution_profile` in `config/scenario-catalog.yaml`. The following gaps are seconds between action starts, before the independently seeded common 10–30 percent multiplicative jitter. An empty list means one action. The same jitter distribution applies to both labels. Parameter randomization adds repetitions, not independent cohorts.

F and S mean failed and successful authentication. The exact account order is in `attempts_csv`; console is logon type 2 and SMB is type 3. Close remote sessions between attempts to avoid cached authentication. Extra or missing events invalidate the execution rather than being trimmed from raw evidence.

| Cohort | Scenario | Label | Actions | Base gaps |
| --- | --- | --- | --- | --- |
| ACCOUNT-PAIR-01 | ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS | benign | u01:F,u01:F,u01:S | 20,20 |
| ACCOUNT-PAIR-01 | ACCOUNT-MALICIOUS-BURST-THEN-SUCCESS | malicious | u01:F,u01:F,u01:F,u01:F,u01:F,u01:F,u01:F,u01:F,u01:S | 2,2,2,2,2,2,2,2 |
| ACCOUNT-PAIR-02 | ACCOUNT-BENIGN-REMOTE-SESSIONS | benign | u01:S,u01:S,u01:S,u01:S,u01:S,u01:S | 2,3,7,11,17 |
| ACCOUNT-PAIR-02 | ACCOUNT-MALICIOUS-REPEATED-FAILURES-6 | malicious | u01:F,u01:F,u01:F,u01:F,u01:F,u01:F | 2,3,7,11,17 |
| ACCOUNT-PAIR-03 | ACCOUNT-BENIGN-MULTIACCOUNT-MAINTENANCE | benign | u01:S,u02:S,u03:S | 15,15 |
| ACCOUNT-PAIR-03 | ACCOUNT-MALICIOUS-PASSWORD-SPRAY | malicious | u01:F,u02:F,u03:F,u03:S | 4,4,4 |
| ACCOUNT-PAIR-04 | ACCOUNT-BENIGN-STALE-CREDENTIAL | benign | u01:F,u01:F,u01:F,u01:F,u01:F,u01:F | 30,30,30,30,30 |
| ACCOUNT-PAIR-04 | ACCOUNT-MALICIOUS-RAPID-GUESSING | malicious | u01:F,u01:F,u01:F,u01:F,u01:F,u01:F | 2,2,2,2,2 |
| ACCOUNT-PAIR-05 | ACCOUNT-BENIGN-MULTIACCOUNT-RECOVERY | benign | u01:F,u01:S,u02:F,u02:S,u03:F,u03:S | 8,8,8,8,8 |
| ACCOUNT-PAIR-05 | ACCOUNT-MALICIOUS-MULTIACCOUNT-GUESSING | malicious | u01:F,u02:F,u03:F,u01:F,u02:F,u03:F,u01:F,u02:F,u03:F,u01:S,u02:S,u03:S | 3,3,3,3,3,3,3,3,3,3,3 |
| C2-PAIR-01 | C2-BENIGN-HEALTH-POLL | benign | 8 http | 25,25,25,25,25,25,25 |
| C2-PAIR-01 | C2-MALICIOUS-HTTP-BEACON | malicious | 8 http | 15,15,15,15,15,15,15 |
| C2-PAIR-02 | C2-BENIGN-SINGLE-DOWNLOAD | benign | 1 http | none |
| C2-PAIR-02 | C2-MALICIOUS-STAGED-TRANSFER | malicious | 8 http | 2,2,2,2,2,2,2 |
| C2-PAIR-03 | C2-BENIGN-DNS | benign | 4 dns | 7,19,11 |
| C2-PAIR-03 | C2-MALICIOUS-DNS-BEACON | malicious | 8 dns | 15,15,15,15,15,15,15 |
| C2-PAIR-04 | C2-BENIGN-IRREGULAR-API | benign | 4 http | 10,35,20 |
| C2-PAIR-04 | C2-MALICIOUS-JITTER-BEACON | malicious | 8 http | 8,21,13,30,11,24,17 |
| C2-PAIR-05 | C2-BENIGN-API-BURST | benign | 6 http | 2,2,2,2,2 |
| C2-PAIR-05 | C2-MALICIOUS-STAGED-TRANSFER-RETRY | malicious | 3 http | 20,20 |

The five account workflows are console recovery, remote sessions, multiaccount maintenance/spray, stale credential retries/rapid guessing, and multiaccount recovery/guessing. Each paired workflow uses identical identities and transport. A six-failure benign retry case prevents a universal failure-count cutoff from being treated as the model's target. Both local and remote activity occur under both labels.

The five network workflows are polling cadence, single versus repeated transfer requests, DNS query cadence/count, irregular API versus jittered requests, and burst versus spaced retries. “Staged transfer” IDs are retained for compatibility but execute harmless requests to the shared endpoint. They do not prove execution, persistence, payload delivery, exfiltration, or attacker control. C2 observations do not encode URI meaning, process intent or data direction. These are related workflow templates in one environment; the ten cohort IDs are partition boundaries, not proof of ten independent environments or causal mechanisms.

## Collection and split contract

Collect two fresh executions per trainable scenario: 10 runs per family/label and 40 total. The optional target adds a third execution to both scenarios in PAIR-01 and PAIR-02 of each family: 12 per stratum and 48 total. Scenario counts are then 3/3/2/2/2, never more than a one-run difference; maximum share is 25 percent. Preserve the existing minimum 10 runs, five scenarios and five groups per stratum.

Use group_key=cohort_id. Every paired benign/malicious template stays together; a scenario never changes cohort. There are five paired cohorts per family, so every outer fold has both labels from each family. Folds 0/1/2 provide three training cohorts per family/label for grouped inner CV; fold 3 has one validation cohort per family/label; fold 4 is locked. Actual assignments come from the deterministic splitter, not manual placement based on outcomes. A challenge sharing a training template keeps that cohort ID but is exported separately and is never assigned a training fold.

The single validation cohort per label cannot support the required three-group uncertainty estimates. Intervals must remain null/insufficient and automation_eligible=false. These are exploratory training data, not robust performance or precision evidence. Repeating each scenario ten times would not solve this limitation.

Before every paired execution, use an AVAILABLE as-of baseline frozen before the actions, with matched history-known/novelty conditions. Do not enroll an entity after observing its run to make it look known. Randomize which label runs first; close sessions and preserve the same frozen baseline condition, using a new seed, nonce, bucket and run ID for each execution. Do not revert VM snapshots or clear event logs between runs: that can reset clocks, native identities and source continuity. Existing clock failures or invalid pilot artifacts remain invalid. Never relabel a failed run after seeing its features or reuse raw data under another ID.

HEALTH-POLL uses seven 25-second base gaps: at the largest factor its action span is 227.5 seconds. Startup delay, cleanup/reserve and capture rules still need the collector's real bucket budget check. Any miss must abort before crossing the frozen action window. Late-arrival grace is not extra action time.

## Predeclared challenge set

Each row below expands into two scenarios ending BENIGN and MALICIOUS. Both members have identical execution profiles and share their related cohort boundary. Their expected decision is REVIEW in both cases. No threshold, model, feature or split selection may use these results. Evaluate after freezing the exploratory package and report actual review, confident benign/malicious, coverage and paired agreement rates.

| Pair prefix | Cohort | Identical actions | Expected |
| --- | --- | --- | --- |
| ACCOUNT-CHALLENGE-LOW-NOISE | ACCOUNT-PAIR-01 | SMB, same user, one failure then success, 3-second gap | REVIEW |
| ACCOUNT-CHALLENGE-FAST-RETRIES | ACCOUNT-PAIR-04 | Same user/source, six SMB failures, 2-second gaps | REVIEW |
| C2-CHALLENGE-POLL-INTENT | C2-PAIR-01 | Eight identical HTTP polls, 15-second gaps | REVIEW |
| C2-CHALLENGE-DOWNLOAD-INTENT | C2-PAIR-02 | One identical harmless HTTP download | REVIEW |

Expected REVIEW is a test requirement, not a claim that the current runtime forces it. A runtime gate must depend only on observable evidence and policy, never scenario_id, purpose, expected_decision or ground-truth label. If the model is confident on these indistinguishable profiles, report the challenge failure and retain ASSISTED/SHADOW; do not hide or retroactively relabel it. Some challenge profiles deliberately match trainable patterns: this exposes the bounded scope of the benchmark, rather than providing an unseen generalization test. Challenge records are excluded from the 40–48-run quota and from training/validation/locked-test partitions.

## Leakage and audit policy

The old auditor blocks any low-cardinality two-feature combination separating labels. That policy confuses legitimate behavioral signal with a shortcut. The design declares feature roles before collection. Keep forbidden inputs and exact cross-label vector collisions as errors. Keep nuisance marginal and nuisance-pair separation blocking. Preserve behavioral separation findings as visible warnings and diagnostics rather than making a learnable target intrinsically fail. Legacy datasets lacking the frozen design retain the original strict policy.

Account nuisance features are remote_logon_ratio, source_history_known and new_source_for_user. C2 nuisance features are suspicious_process, destination_port_count, destination_history_known, new_destination and suricata_severity_score. Remaining family features are declared behavioral. Suricata alert count can track action count because both labels exercise the same canary; an alert's name, SID meaning or a label-specific severity is not a legitimate distinction. Nuisance-versus-behavior interactions still require review; role assignment does not prove absence of every shortcut.

Check actual feature distributions, context and canary outcomes after collection. Shared design intent cannot replace observed parity. The design file must be bound to the release, catalog and dataset provenance. Changing its roles after seeing a failure requires a new reviewed collection design, not an undocumented exemption.

## Acceptance work still required on the actual four VMs

Repository tests can establish catalog validation, shared entities, cohort coverage and runner contracts. They cannot certify Sysmon clocks, reachability, Suricata rule behavior, source authenticity, lockout policy, actual counts or full-bucket parity. Before official collection, verify the pinned source and helper hashes on all relevant VMs, document the service/listener setup, establish AVAILABLE as-of context, prove native clocks within the existing tolerance, and execute fresh valid pilot runs of every distinct action transport/profile shape. Preserve raw evidence and observed failures.

No manual owner waiver substitutes for an unfinished runner, missing schedule parser, unbound design or unsupported action receipt. Implement and test those release components before requesting lab acceptance. After real acceptance, freeze the dataset design and collect; G7 remains governed by its existing release and lab evidence gates.
