# DATN AI SOAR

Repository for the AI and SOAR workstream of the graduation project.

Week 1 establishes a reproducible development environment, Interface Contract v1,
a mock FastAPI inference service and the first n8n vertical slice. Week 2 adds a
versioned fixture feature pipeline, incident-window aggregation, a fail-safe
VirusTotal adapter, asset context, Risk v2 and a guarded n8n SHADOW workflow.
Week 3 adds a leakage-safe, per-family training pipeline that benchmarks Logistic
Regression, Random Forest and XGBoost, selects thresholds on validation data, and
packages trained inference artifacts without opening the locked test.

Start ML work with `docs/week3-model-training-runbook.md` and
`docs/week3-data-contract.md`. The Colab entry point is
`notebooks/week3_train_colab.ipynb`; it intentionally accepts only TRAIN,
VALIDATION and the dataset manifest. The frozen Week 1 request/response rules are
in `docs/interface-contract-v1.md`; machine-readable Week 1 and Week 2 schemas
are under `schemas/`.

Real-lab collection uses the fail-closed four-VM workflow in
`docs/scenario-collection-runbook.md`. Create a run draft from the controlled catalog,
capture one independent run, validate its evidence, then audit all four strata:

```bash
.venv-ml/bin/python -m scripts.create_run_draft --scenario SCENARIO_ID \
  --run-id UNIQUE_RUN_ID --operator OPERATOR
.venv-ml/bin/python -m scripts.scenario_session start \
  --draft run-drafts/UNIQUE_RUN_ID.yaml
.venv-ml/bin/python -m scripts.scenario_session finalize --run-id UNIQUE_RUN_ID
.venv-ml/bin/python -m scripts.scenario_session validate --run-id UNIQUE_RUN_ID
.venv-ml/bin/python -m scripts.audit_dataset --minimum-runs 10 --target-runs 12
```

For the complete test, lint and readiness gate, run
`./scripts/verify_collection_dataset.sh`; set `REQUIRE_TARGET=1` to require all 12 runs
per stratum.

On the Ubuntu VM, deployment and verification are reproducible with:

```bash
./scripts/deploy_week2.sh
./scripts/verify_week2.sh
```

Threat Intelligence defaults to deterministic `mock` mode. Live VirusTotal is
optional and must never be used with private, reserved or confidential values.
All strong response actions remain disabled.
