# Interface Contract v1

## Scope

Week 1 uses deterministic mock inference and deterministic mock Threat
Intelligence. It validates the interface and orchestration path; it does not
claim production detection accuracy.

## Input: normalized incident

`POST /predict` and `POST /orchestrate/mock` accept the same strict payload:

| Field | Type | Rule |
|---|---|---|
| `incident_id` | string | Required, 1–128 characters |
| `asset_id` | string | Required, 1–128 characters |
| `start_time`, `end_time` | ISO-8601 datetime | End cannot precede start |
| `family_hint` | `account`, `c2`, `unknown` | Defaults to `unknown` |
| `features` | object of numeric values | Mock model inputs |
| `evidence_sources` | string array | At least one source |
| `base_severity` | integer | 0–15 |
| `raw_refs` | string array | References only; no raw secret material |
| `indicator` | string or null | IP/domain for mock TI lookup |

Unknown fields are rejected. JSON Schemas are frozen under `schemas/`.

## Output and safety state

The orchestration result contains prediction metadata, TI context, risk,
playbook selection, rationale and an audit record. Week 1 is always `SHADOW`.
Only `create_update_incident_notify` is selected and
`strong_action_allowed` is always `false`.

Risk v1 is:

```text
risk = 0.40*AI + 0.20*observed_evidence + 0.15*TI
     + 0.15*asset + 0.10*severity
```

Inputs are clamped to 0–1. Internal risk is stored on 0–1; display risk is
0–10 and rounded with ROUND_HALF_UP. The sample fixture produces 0.885 / 8.9.

## Version fields

- API: `1.0.0`
- Mock model: `mock-v1`
- Threshold: `mock-thr-v1`
- Risk policy: `risk-week1-v1`
- Workflow: `week1-mock-v1`
- Mock TI provider: `mock-ti-v1`
