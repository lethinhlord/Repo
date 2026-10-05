from datetime import UTC, datetime

from fastapi import FastAPI

from api.app.contracts import (
    AuditRecord,
    DecisionRecord,
    HealthResponse,
    IncidentRequest,
    PredictionResponse,
)
from api.app.mock_services import lookup_ti_mock, predict_mock
from api.app.risk import calculate_risk

app = FastAPI(
    title="DATN AI SOAR Mock API",
    summary="Week 1 contract-first mock inference and orchestration API",
    version="1.0.0",
)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse()


@app.post("/predict", response_model=PredictionResponse)
def predict(incident: IncidentRequest) -> PredictionResponse:
    return predict_mock(incident)


@app.post("/orchestrate/mock", response_model=DecisionRecord)
def orchestrate_mock(incident: IncidentRequest) -> DecisionRecord:
    prediction = predict_mock(incident)
    ti_context = lookup_ti_mock(incident.indicator)
    observed_evidence = min(len(set(incident.evidence_sources)) / 2.0, 1.0)
    asset_score = 1.0 if incident.asset_id in {"SOC-CORE", "SOAR-AI"} else 0.6
    risk = calculate_risk(
        ai_probability=prediction.malicious_probability,
        observed_evidence=observed_evidence,
        ti_score=ti_context.score,
        asset_score=asset_score,
        severity_score=incident.base_severity / 15.0,
    )
    return DecisionRecord(
        incident_id=incident.incident_id,
        prediction=prediction,
        ti_context=ti_context,
        risk=risk,
        rationale=[
            "Week 1 uses deterministic mock inference and Threat Intelligence.",
            "Automation remains SHADOW; strong response actions are disabled.",
            "The create/update incident and notification playbook is always permitted.",
        ],
        audit=AuditRecord(
            incident_id=incident.incident_id,
            recorded_at=datetime.now(UTC),
        ),
    )
