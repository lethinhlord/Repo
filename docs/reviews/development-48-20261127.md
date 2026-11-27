# Exact review: 48-run development dataset, 2026-11-27

This review authorizes only the reconstructed and independently checked 48-row TRAIN artifact below for the registered `development-three-day-grouped-cv` experiment. It does not approve deployment or automated response.

## Exact artifact commitments

| Commitment | SHA-256 |
| --- | --- |
| Canonical manifest digest (`approved_manifest_sha256`) | `4052c9b8de492304c28532f6c1138abb826d4993e35776f83c2268ee08e8c0a7` |
| Physical `dataset_manifest.json` file | `920cf5f4aeca337d3ba9b9e42c48abce1087ea4fc0e30858ec48fd63a16eb92d` |
| `train.jsonl` file | `ab793526d1fb902bed8f2caa23a5ee479a9ff3632b9f38928667213dc67495b1` |
| Canonical dataset | `99ce1da900b75cecabe7ec99ddf4a8a53e66d5bf5617701938cd2f2b40d749db` |
| Restored native input inventory | `18472838c96d4d832119c4e013d085e75490d2825b903a757fd8bd9ef600f72e` |
| Registered plan | `e8c9386221503ef860b142e64fa74e8cf3a1c52cebbb1e32eb781420863cf633` |

The canonical manifest digest is the policy commitment; it intentionally differs from the file checksum. The builder is `f6060b33324978be2568ae97ebaf34ff63de752c`, using the already approved Windows CPython 3.12.14 runtime and package inventory. Collection remains pinned to immutable tag `development-collection-v1.0.0-candidate.1`; collection and processing runtime identities remain separately recorded.

## Restored source evidence

All 24 transferred components passed the handoff SHA-256 inventory. The original G7 archive matches its pre-existing receipt (`bb95c78d4f4a29319784521f0cd9beb3861c5316334996d8b969a11ccbe66015`); its source metadata, four pilot commitments and restored pilot validations pass. Original preflight capture/report hashes match the accepted receipt, and canonical recomputation from native log reproduces the original canary result.

The final selective archive (`9835ca220d8958f049c400b6490a90e3fb2b66e70724c5e25b12b062dd0a03ff`) contains 1,145 files, all byte-identical to the previously audited daily handoffs. It has no standalone canonical restore report and omits the pilot evidence and registered plan. It is explicitly **not** accepted as a standalone canonical final backup.

The reviewed input was physically restored and composed from that selective archive, the original G7 archive, and the byte-identical original subsequent G7 acceptance receipt already present in the earlier handoff. The composition retains 52 FINALIZED runs (48 TRAIN and four pilots) and eight ABORTED attempts (two official retries and six historical pilots). Original archives, captures, states and receipts were not edited; no replacement PASS receipt was synthesized. A per-file origin map is retained with the local review evidence.

## Validation and independent review

- Canonical restored native audit: 48/48 verified, `issues=[]`, twelve rows in each account/C2 benign/malicious stratum.
- Three actual UTC dates, 2026-11-25 through 2026-11-27, with sixteen TRAIN rows per date and three host/date groups; all nine registered templates are covered.
- The processed 48 rows exactly reproduce the previous canonical native replay. All 56 derived features are finite and all rows have COMPLETE observation quality. No exact opposite-label collision exists in the selected model inputs.
- Native build and a subsequent fresh `propose-review` replay reproduce the exact manifest and TRAIN bytes. Raw input mutation and uncommitted source checks remain enforced.
- Independent cross-model review recomputes row, unit, partition, schema, plan, design, runtime, source-compatibility and native-input commitments; no failed checks or row errors remain.
- Existing dataset/source/notebook guard regression tests: 17 passed. These synthetic guard tests supplement the real native replay; they do not replace it.

No features, algorithms, splits, thresholds, raw evidence or quality gates were changed to obtain approval. The policy update changes only readiness and the exact approved manifest digest; this document records the basis for that decision. Detailed native replay, transport, restore, origin-map and independent-review artifacts are retained offline in the 2026-11-27 final-backup review output.

## Training boundary

Only TRAIN exists in this development protocol. External validation and locked test remain `NOT_COLLECTED`, and `automation_eligible=false`. The three dates come from one controlled lab host; no independent environment, external performance, confidence interval or production-readiness claim follows from collection completion. No model was trained during this review.

After this exact review is committed and merged, stage with `ml.development_dataset stage`. Upload only `train.jsonl`, `dataset_manifest.json`, and `colab-upload.sha256` to the development Drive directory, and use `notebooks/development_train_colab.ipynb` pinned to the merged READY-review commit. Keep raw archives and credentials offline.
