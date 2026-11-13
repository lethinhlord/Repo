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
cannot replace it. The current candidate is
[collection-v4.0.0-candidate.6](https://github.com/lethinhlord/Repo/tree/collection-v4.0.0-candidate.6).
It implements the paired cohort design, neutral actor runners and evidence-bound
per-lab acceptance. Pilot → preflight replay → backup restore → acceptance must
succeed on the actual four VMs before trainable collection opens. Repository tests
do not certify the remote lab or a trained model.

See [current status](docs/current-status.md) and the
[collection design and limits](docs/collection-training-design.md). The four
candidate.4 pilots in the November 11 handoff replay VALID/PASS. Follow
[G7 with existing pilots](docs/g7-existing-candidate4-pilots.md) to reuse their
immutable evidence through the reviewed candidate.6 adoption policy. G7 v2 binds
the exact active source for draft, START, audit and builder. Renew expired
enrollment; do not rewrite or recollect pilots merely to change the candidate.
The November 13 Sysmon retest exposed native post-exit network timestamps.
Follow [the chronology fix and lab retest](docs/sysmon-jitter-retest-20261113.md)
before resuming collection. Native lifecycle clocks now agree across Events 1/3/5;
HTTP keeps curl alive after its request. Existing feature-state caches are retained
under their old path, not silently reinterpreted. Fast HTTP cadence limitations
remain documented; no profile or quality gate is removed.

Use `main` as the maintained entry point and the exact approved source SHA for
collection, dataset building and training. The Colab notebook accepts
`train.jsonl`, `validation.jsonl`, `dataset_manifest.json` and `colab-upload.sha256`,
and checks the approved SHA against the manifest before installing or running code.
Historical validation records are under [docs/history](docs/history/README.md);
they are not current operating instructions or proof of real-lab acceptance.

For the complete test, lint and readiness gate, run
`./scripts/verify_collection_dataset.sh`; set `REQUIRE_TARGET=1` to require all 12 runs
per stratum. It selects `operator-logs/collection-sources-active.yaml` when present;
set `COLLECTION_SOURCE_CONFIG` explicitly to use another accepted source file.

On the Ubuntu VM, deployment and verification are reproducible with:

```bash
./scripts/deploy_week2.sh
./scripts/verify_week2.sh
```

Threat Intelligence defaults to deterministic `mock` mode. Live VirusTotal is
optional and must never be used with private, reserved or confidential values.
All strong response actions remain disabled.
