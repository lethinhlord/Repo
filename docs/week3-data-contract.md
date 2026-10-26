# Week 3 ML data contract

## Scope

The model learns only from observed behavioral telemetry. Threat-intelligence output,
asset criticality, scenario labels, Wazuh-derived labels, and Risk scores are prohibited
as input features. Ground truth comes only from the scenario manifest created before a
run. Account and C2 are trained as separate binary classifiers.

## Raw layout

Create one directory for every independent scenario execution:

```text
data/raw/
└── <run_id>/
    ├── scenario_manifest.json
    └── incidents.jsonl
```

`run_id` is the atomic collection boundary: every real execution gets a new run ID and
cannot contain mixed families, labels or scenarios. `scenario_id` is the partition
boundary: all repeated executions of the same scenario stay in exactly one of TRAIN,
VALIDATION or LOCKED TEST. This prevents the model from validating on a near-identical
scenario template it already saw during training.

Example `scenario_manifest.json`:

```json
{
  "scenario_id": "ACC-BRUTE-FORCE-01",
  "run_id": "ACC-BRUTE-FORCE-01-RUN-001",
  "family": "account",
  "label": "malicious",
  "host": "WIN11-01",
  "start_time": "2026-10-12T08:00:00+07:00",
  "end_time": "2026-10-12T08:05:00+07:00",
  "expected_behavior": "Repeated failed logins followed by a successful login.",
  "collection_seed": 123456,
  "scenario_parameters": {"attempt_delay_seconds": 2.5},
  "provenance_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "source_config_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "taxonomy_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "scenario_catalog_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "feature_schema_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "collection_contract_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Các chuỗi zero chỉ minh họa kiểu dữ liệu. Collector thật tự tính hash từ snapshot
`collection-sources`, taxonomy, catalog và feature schema; không tự điền hoặc sửa hash.

`incidents.jsonl` contains one normalized `IncidentRequest` per line, either directly or
under an `incident` key. The `family_hint` must match the manifest. Features must conform
to [feature_schema.json](../ml/feature_schema.json).

Each raw run has a matching `evidence/scenario-runs/<run_id>/` directory. The collector
creates `start-contract.json` at `start`; it binds the normalized runtime source and
archive cursor to the source config, taxonomy, scenario catalog, feature schema, frozen
parameters and start time. `begin-action`, `complete-action`, `finalize`, `validate` and
the dataset auditor all reject a state whose source or cursor differs from that contract.
The completed `execution_receipt.json` must identify the same run/scenario, parameter
digest and action window as the finalized manifest.

The dataset auditor compares every run's source-config and taxonomy hashes, as well as
its catalog and feature-schema hashes, with the canonical files in the checked-out
collection commit. A dataset assembled from mixed collection contracts is not ready.

## Collection minimum

The grouped splitter has a technical floor of five groups, but this project does not
declare the dataset ready until it has at least ten independent valid runs for each of
the four strata. Twelve is the preferred target:

| Family | Label | Ready | Preferred target |
|---|---:|---:|---:|
| account | benign | 10 | 12 |
| account | malicious | 10 | 12 |
| c2 | benign | 10 | 12 |
| c2 | malicious | 10 | 12 |

Use all five scenario IDs in every stratum and keep the largest scenario at or below
30%. At 10 runs the intended distribution is 2-2-2-2-2; at 12 it is 3-3-2-2-2.
Vary collection times while preserving each scenario's declared behavior. Do not
duplicate rows to satisfy the minimum. Enforce this policy with
`scripts/audit_dataset.py` before building partitions.

## Split and locked-test policy

`python -m ml.build_dataset` applies deterministic stratified grouped folds with seed 42:

- folds 0–2: TRAIN (60%);
- fold 3: VALIDATION (20%);
- fold 4: LOCKED TEST (20%).

The split is grouped by `scenario_id`, never by event or individual run. Every run still
remains atomic within its assigned scenario partition. Training reads only TRAIN and
VALIDATION. The locked test remains unopened until Week 6 and can only be evaluated
after a package is frozen with `python -m ml.freeze_model`.

## Leakage checklist

- Ground truth is authored before the run and stored only in the manifest.
- No Wazuh rule ID, Wazuh severity, TI result, asset criticality, or Risk score is a model
  feature.
- The same incident ID, run ID and scenario ID may occur in only one partition.
- Preprocessing is inside each estimator pipeline and fitted on TRAIN only.
- Threshold and model selection use VALIDATION only.
- LOCKED TEST never participates in model or threshold selection.
