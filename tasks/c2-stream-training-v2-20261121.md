# C2 stream representation and train-ready handoff — 21 November 2026

## Authorized outcome

Fix the observed representation/attribution problems and deliver an immediately
runnable, verified training path from the existing immutable forty runs. No
recollection, relabeling, deleted observations, reshuffling cohorts, weakened
quality gates or fake AUTO approval. Existing v3 artifacts remain usable.

## Scientific boundaries

- Design against the already audited twelve C2 TRAIN runs and counterexamples.
- Record representation and bounded ablations before fitting or regenerating
  held-out data. Choose configurations on TRAIN grouped CV only.
- Deterministic trusted reprocessing may transform the sealed held-out raw
  inputs after the transform is fixed. Do not inspect their features or labels
  for design/model selection. Preserve exact partition membership.
- Keep the locked partition off Colab and out of development/evaluation reads.
- Dataset validity and executable training do not prove DNS C2 coverage or AUTO
  readiness; report any remaining evidence limits explicitly.

## Implementation slices

1. Add a pure, versioned stream descriptor function and meaningful RED/GREEN
   counterexamples: background DNS, multiple processes/peers, transient curl
   GUIDs, missing timing support and interval-order loss. Retain legacy24 values.
2. Reuse the existing identity/chronology/correlation proof for online/offline
   stream observations. Introduce an explicit additive v4 profile/schema;
   preserve v3 defaults and old source evidence. Bind representative target
   context explicitly without claiming whole-window scores authorize actions.
3. Add strict versioned raw-to-derived provenance, feature/config/source and
   partition commitments. New derived bytes get new identities; never rewrite
   original manifest/checksums. Verify raw and old vectors before enrichment.
4. Predeclare compact stream vs legacy/combined TRAIN-only comparison. Keep
   LR/RF/XGBoost, grouped splitting, calibration and all quality gates. Record
   negative results and scope unsupported modalities explicitly.
5. Generate the derived partitions in a sealed worker; four-file Colab staging
   excludes locked test. Test rejection of mutations, changed split, unexpected
   source and schema mismatch. Exercise actual fitting/export from new source.
6. Provide the corresponding pinned Colab notebook, guide, checksums and model
   evidence. Run focused and full regression plus independent review before
   publishing under standing GitHub authorization.

## Fixed descriptor proposal (before fits)

Observation grouping uses verified process image + destination + port +
protocol, with DNS separate. Process GUID proves observation identity and
contributes an instance count, but is not itself a model input or the sole
conversation key: curl can start a new process on every request.

Append explicit TCP count, DNS fraction, process/conversation counts, dominant
conversation share/count, timing/periodicity/order availability masks, per-stream
mean/CV/periodicity/duration/order alternation, destination history/novelty and
DNS-only mode. No exact identities, URLs, nonce, scenario/label, TI/asset/risk
inputs. Equal maximum stream counts remain ambiguous: no representative target or dominant timing is asserted.

Retain full-window legacy behavior alongside decomposition. Availability masks
represent insufficient sample support; zero must not silently mean measured
perfect regularity. Unknown context remains unknown/review. Per-indicator
attribution stays separate from strong-response authorization, which remains
false.

## State

Branch feature/c2-stream-training-v2, starting source e8f970f3. Prior audit is
saved in D:/C2_TRAIN_SIGNAL_AUDIT_20261121. Core implementation, exact raw-verified derivation and four-file staging are complete. Full Windows regression and pinned Linux notebook fitting/export checks are running; no release or automation approval is claimed yet.

Builder:57d815d83ace89e8db8c1859ad7b8122bb2e7493. Exact review commit:f2a9438129fced35520af2bc1ea9f73d3db5c401. Derived manifest:f552c36d391bcf097af77eba3894d2a852f870a85d453b249499962dae2c23d9. Original889 files, original v3 staging and original12-file model remain unchanged. Independent core/source/notebook and guide reviews are retained under outputs/c2-stream-training-v2-20261121.

The compact12 representation was predeclared before TRAIN fits. Nested TRAIN comparison did not establish broad performance or automation readiness (three independent C2 cohorts only). Held-out processing was a deterministic blind transform after code was committed; no locked-test partition was opened for feature/model selection. The full44 includes structural zeros and unsupported DNS-only observations, with explicit REVIEW behavior instead of silently dropping them.
