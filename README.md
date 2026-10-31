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
`docs/week3-data-contract.md`. Production monitoring, feedback, retraining and
rollback are defined in `docs/model-operations-runbook.md`. The Colab entry point is
`notebooks/week3_train_colab.ipynb`; it intentionally accepts only TRAIN,
VALIDATION, the dataset manifest and its upload checksum. The frozen Week 1 request/response rules are
in `docs/interface-contract-v1.md`; machine-readable Week 1 and Week 2 schemas
are under `schemas/`.

Real-lab collection uses the four-VM procedure in
[the collection runbook](docs/scenario-collection-runbook.md). Follow its setup,
measured clock preflight, context enrollment and pilot gates in order. Run drafts
require `--clock-preflight` from that measured preflight; an abbreviated command
cannot replace it. G7 remains closed until cohort/challenge/taxonomy release and
real-lab acceptance are complete. A merged software fix is not a collection baseline.

Use `main` as the maintained entry point and the exact approved source SHA for
collection, dataset building and training. The Colab notebook accepts
`train.jsonl`, `validation.jsonl`, `dataset_manifest.json` and `colab-upload.sha256`,
and checks the approved SHA against the manifest before installing or running code.
Historical validation records are under [docs/history](docs/history/README.md);
they are not current operating instructions or proof of real-lab acceptance.

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
