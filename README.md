# DATN AI SOAR

Repository for the AI and SOAR workstream of the graduation project.

Week 1 establishes a reproducible development environment, Interface Contract v1,
a mock FastAPI inference service and the first n8n vertical slice. Week 2 adds a
versioned fixture feature pipeline, incident-window aggregation, a fail-safe
VirusTotal adapter, asset context, Risk v2 and a guarded n8n SHADOW workflow.
Week 3 adds a leakage-safe, per-family training pipeline that benchmarks Logistic
Regression, Random Forest and XGBoost, selects thresholds on validation data, and
packages trained inference artifacts without opening the locked test.

For the reviewed existing 40-run handoff, start with the Vietnamese guide
[training from the existing 40 runs](docs/training-existing-40-runs.md).
It preserves all inputs and describes the explicit, reviewed two-origin mode;
no recollection is required for offline processing. General ML procedures remain in
[the training runbook](docs/week3-model-training-runbook.md) and
[the data contract](docs/week3-data-contract.md). Production monitoring, feedback, retraining and
rollback are defined in `docs/model-operations-runbook.md`. The Colab entry point is
`notebooks/week3_train_colab.ipynb`; it intentionally accepts only TRAIN,
VALIDATION, the dataset manifest and its upload checksum. The frozen Week 1 request/response rules are
in `docs/interface-contract-v1.md`; machine-readable Week 1 and Week 2 schemas
are under `schemas/`.

Real-lab collection uses the four-VM procedure in
[the collection runbook](docs/scenario-collection-runbook.md). Follow its setup,
measured clock preflight, context enrollment and pilot gates in order. Run drafts
require `--clock-preflight` from that measured preflight; an abbreviated command
cannot replace it. The candidate prepared for the reviewed training pipeline is
`collection-v4.0.0-candidate.8`; use
[its release source](https://github.com/lethinhlord/Repo/tree/collection-v4.0.0-candidate.8)
only after the tag is published and its exact SHA is owner-approved. This entry
does not assert publication or a new G7 acceptance. It retains the paired cohort
design, neutral actor runners and evidence-bound per-lab acceptance. Any future
collection on the new candidate requires actual four-VM G7 approval before runs
open. Offline processing of the existing frozen 40-run handoff does not require
new enrollment, pilots or G7. Repository tests do not certify the remote lab or a
trained model.

See [current status](docs/current-status.md) and the
[collection design and limits](docs/collection-training-design.md). Historical
operating records include [G7 with candidate.4 pilots](docs/g7-existing-candidate4-pilots.md)
and [the candidate.7 upgrade](docs/collector-upgrade-candidate7.md). Their commands
and approvals describe those releases; they are not current candidate.8 G7
approval or instructions to recollect the existing 40 runs.

The default audit/build path remains strict for a single collection source.
The explicit `--compatibility-policy config/training-source-compatibility.json`
path authorizes only the reviewed 23-run and 17-run origins and exact immutable
inputs, records and split commitments. It produces `dataset-manifest-v3` and retains
the original collection identities separately from the processing commit. It does
not authorize arbitrary source mixing or metadata relabeling. Legacy single-source
and smoke datasets retain the v2 path. Clock, grouping and lifecycle guards remain
active; fast-cadence limits remain documented.

Use the exact approved source SHA for each activity. For the existing 40 runs,
use the candidate.8 processing/training SHA and unchanged source-active file as
described in the dedicated guide; keep the two original collection SHAs intact.
The Colab notebook accepts
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
