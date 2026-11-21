# Improve trained C2 pipeline — 20/11/2026

## User scope

Check and improve the pipeline using the existing immutable 40-run handoff.
Preserve the Colab model export as the baseline. No recollection, label editing,
row deletion, locked-test reads, weaker gates or promotion to AUTO.

## Baseline

- Source16b19887, candidate8. Model week3-20261120T140751Z.
- Archive SHA f8997667c6a310a4ef7e552d884ba9e60eefc0643bf0492090ec4746b51ef443.
- Account validation4/4 correct but ECE.343; C2 precision.5/FPR1, AP.5.
- One paired validation cohort/family; minimum3/label not met, all CIs null.
- Full inspection at outputs/model-package-review-20261120; original12 files intact.

## Work slices and verification

1. Audit only TRAIN raw/features, preserving attribution and feature schema24.
   No claim of collector bug without a reproducer; no edits of original evidence.
2. Predeclare bounded TRAIN-only grouped nested-CV experiments. Keep validation
   out of model/hyperparameter selection and locked test inaccessible. Record
   negative as well as positive results; no promise that tuning solves missing
   semantic information or missing independent validation cohorts.
3. Improve gate reporting: preserve failed precision separately, all gates still
   block AUTO. Add meaningful RED/GREEN tests.
4. Improve streaming/retained quality and train logs; retain full pytest gate.
   Pin/verify the actual training runtime against deployment libraries and
   Python3.12, without mutating collection runtime or original artifacts.
5. Permit training-only code evolution against exactly the already reviewed
   candidate8 manifest. Keep original builder identity/certificate unchanged.
   Current executing code/policy must remain Git-pinned and clean; historical
   acceptance requires explicit exact-manifest/source review, never arbitrary
   mixed source or an expected-commit bypass. v2/default strict path preserved.
6. Incorporate model recipe only if TRAIN-only evidence justifies it. Preserve
   original LR/RF/XGBoost and schema; no validation-driven switch to a favored
   estimator. Separate builder config from any reviewed experiment recipe.
7. Cross-review changes, focused and full regression, true original-manifest
   integration and local notebook flow, original hashes unchanged. Publish a
   reviewable commit/PR under the existing authorization, merge only when checks
   complete. No new G7 or deployment acceptance inferred from training changes.

## Ownership

Root: TRAIN forensic audit/experiment, strict historical-manifest transition,
training/metrics reporting, policies, integration and release.
Independent model agent: notebook/runtime/logging slice and tests; no commits or
policy edits until root coordinates shared production hashes.

## State

Implemented on fix/c2-training-reliability, core e0c777c, notebook ef5bf5f,
precision-only report correction b5e677e. Both source policies refreshed without
reading any locked rows. Actual unchanged40 manifest accepted on the new source;
independent nine-case mutation review passed with zero locked-file reads.

All12 C2 TRAIN evidence runs replayed PASS in isolated16b1988 worktree containing
only those12 directories. Predeclared10-candidate nested TRAIN-only experiment
did not establish defensible classifier improvement; keep production LR/RF/XGB,
the24 features, original config/partitions and AUTO gates unchanged.

RED/GREEN evidence covers gate completeness, precision-only written record,
training metadata, historical source transition and live subprocess logs.
Actual pinned Linux3.12.15 bootstrap/dependency checks and POSIX interruption tests
passed independently. Full Windows regression interrupted after14/23 groups
overnight; 21November resume preserves passed reports and reruns missing groups.
Final actual-notebook backend run in pinned Linux and release checks are pending.

Evidence directory: outputs/c2-training-improvement-20261120. The initial Colab
package remains immutable at D:/model-package-week3; no new lab G7 issued.
