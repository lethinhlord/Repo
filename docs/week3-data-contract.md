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

`run_id` is the leakage boundary. Retries or minor variations derived from the same
execution must retain the same `run_id`. A run cannot contain mixed families or labels.

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
  "expected_behavior": "Repeated failed logins followed by a successful login."
}
```

`incidents.jsonl` contains one normalized `IncidentRequest` per line, either directly or
under an `incident` key. The `family_hint` must match the manifest. Features must conform
to [feature_schema.json](../ml/feature_schema.json).

## Collection minimum

Before the first serious benchmark, collect at least five independent runs for each of
the four strata:

| Family | Label | Minimum independent runs |
|---|---:|---:|
| account | benign | 5 |
| account | malicious | 5 |
| c2 | benign | 5 |
| c2 | malicious | 5 |

This is only the technical minimum for a valid 5-fold grouped partition. More diverse
runs are strongly preferred. Vary hosts, times, rates, destinations, and benign lookalike
activity. Do not duplicate rows to satisfy the minimum.

## Split and locked-test policy

`python -m ml.build_dataset` applies deterministic stratified grouped folds with seed 42:

- folds 0–2: TRAIN (60%);
- fold 3: VALIDATION (20%);
- fold 4: LOCKED TEST (20%).

The split is by `run_id`, never by event. Training reads only TRAIN and VALIDATION. The
locked test remains unopened until Week 6 and can only be evaluated after a package is
frozen with `python -m ml.freeze_model`.

## Leakage checklist

- Ground truth is authored before the run and stored only in the manifest.
- No Wazuh rule ID, Wazuh severity, TI result, asset criticality, or Risk score is a model
  feature.
- The same incident ID and run ID may occur in only one partition.
- Preprocessing is inside each estimator pipeline and fitted on TRAIN only.
- Threshold and model selection use VALIDATION only.
- LOCKED TEST never participates in model or threshold selection.
