# Spec: Four-VM Training Data Collection

## Objective

Provide an executable, fail-closed workflow that lets Kiên collect independent real-lab
runs for `account:benign`, `account:malicious`, `c2:benign` and `c2:malicious`. A dataset
is ready at 10 valid runs per stratum and reaches the preferred target at 12. The workflow
must preserve raw evidence, derive features without using the label, prevent row-level
leakage and produce input accepted by the existing Week 3 grouped-split pipeline.

## Assumptions

1. Exactly four VMs are used: Kali, Windows 11, SOC-AI and NET-SENSOR.
2. The collector runs on SOC-AI where Wazuh Archives are local.
3. NET-SENSOR runs a Wazuh Agent that forwards Suricata EVE JSON to SOC-AI.
4. Each run produces one aggregated incident and one immutable ground-truth label.
5. `run_id` is the grouping/leakage boundary; raw event rows are never independent samples.
6. The collector fails rather than silently converting a missing source to observed zero.
7. The locked test remains unopened; the collector and auditor operate only on `data/raw`.

## Tech Stack

- Python 3.12, Pydantic 2.13.5, PyYAML 6.0.3.
- pytest 9.1.1 and Ruff 0.16.10.
- Wazuh Archives JSON, Sysmon/Security Event Channel and Suricata EVE JSON.
- Existing `ml.dataset`, `ml.feature_schema.json` and `api.app.contracts.IncidentRequest`.

## Commands

```bash
# Focused tests
.venv-ml/bin/python -m pytest -q tests/test_scenario_collection.py tests/test_dataset_audit.py

# Start, bind the action to frozen parameters, finalize and validate a run
.venv-ml/bin/python -m scripts.scenario_session start --draft run-draft.yaml
.venv-ml/bin/python -m scripts.export_run_parameters --run-id RUN_ID --format powershell
.venv-ml/bin/python -m scripts.scenario_session begin-action --run-id RUN_ID
# Execute exactly one catalog action here.
.venv-ml/bin/python -m scripts.scenario_session complete-action --run-id RUN_ID
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id RUN_ID
.venv-ml/bin/python -m scripts.scenario_session validate --run-id RUN_ID

# Audit all four strata
.venv-ml/bin/python -m scripts.audit_dataset --raw-dir data/raw \
  --evidence-dir evidence/scenario-runs --minimum-runs 10 --target-runs 12 \
  --output evidence/dataset-audit.json

# Existing grouped build after audit is READY
.venv-ml/bin/python -m ml.build_dataset --config ml/training_config.yaml
```

## Project Structure

```text
config/collection-sources.yaml          Source paths and agent identities
config/suspicious-process-taxonomy.yaml Versioned process/command taxonomy
config/scenario-catalog.yaml             Five safe scenarios per stratum
config/sysmon-datn.xml                   Required Sysmon event families
config/suricata-datn.rules               Deterministic lab-only signatures
ml/scenario_collection.py               Collector and feature derivation
ml/dataset_audit.py                      Dataset readiness validator
scripts/create_run_draft.py              Validated draft generator
scripts/export_run_parameters.py         Export collector-frozen run parameters
scripts/scenario_session.py              Collector CLI
scripts/audit_dataset.py                 Auditor CLI
scripts/verify_collection_dataset.sh     One-command test/lint/readiness gate
tests/test_scenario_collection.py        Collector tests
tests/test_dataset_audit.py              Auditor tests
docs/scenario-collection-runbook.md      Operator runbook
```

## Code Style

Use typed pure functions for parsing and feature calculation; isolate filesystem state in
small orchestration functions. Reject ambiguity with a descriptive exception.

```python
def periodicity_score(timestamps: list[datetime]) -> float:
    if len(timestamps) < 3:
        return 0.0
    intervals = [...]
    return max(0.0, min(1.0, 1.0 - pstdev(intervals) / mean(intervals)))
```

## Testing Strategy

- Unit tests: event attribution, feature derivation, catalog/configuration and stratum
  counting.
- Filesystem integration tests: start/finalize/validate using temporary Wazuh JSONL files.
- Negative tests: missing Suricata evidence, truncated source, duplicate incident ID,
  sparse stratum, excessive scenario concentration and forbidden feature leakage.
- Full regression: repository pytest and Ruff.

## Boundaries

- Always: declare label before execution; preserve raw evidence; verify timestamps and
  checksums; aggregate by run; require Suricata visibility for C2.
- Ask first: change the frozen feature schema, lower readiness below 10 runs/stratum,
  change locked-test policy or execute a destructive Atomic test.
- Never: infer ground truth from Wazuh/Suricata alerts; label every raw row; edit generated
  incidents manually; treat missing telemetry as a successful observation; upload the
  locked test, secrets or raw personal telemetry to Colab.

## Success Criteria

1. Collector start writes immutable ground truth, source cursors and collection-contract
   snapshots before activity; `start-contract.json` binds the normalized runtime source
   and cursor to those snapshots, and a completed action receipt is mandatory.
2. Finalize produces a strict `ScenarioManifest`, strict `IncidentRequest`, raw evidence,
   metadata and SHA-256 checksums atomically.
3. C2 finalization fails without a matching nonce, ProcessGuid, action count/timing,
   attributable Sysmon telemetry and time-correlated Suricata application/flow telemetry.
4. Auditor rejects mixed source, taxonomy, catalog or feature-schema contracts, reports
   counts and shortage for all four strata, and exits non-zero until every stratum has at
   least 10 valid independent runs.
5. Auditor enforces all five catalog scenarios per stratum and no scenario above 30%.
6. Output passes the existing `ml.build_dataset` contract and grouped split.
7. The Vietnamese runbook contains complete installation, pilot, per-run, recovery,
   screenshot and Colab handoff procedures.

## Open Questions

None block implementation. VM interface names and IP addresses are installation-time
values and are recorded explicitly by the operator rather than guessed by the software.
