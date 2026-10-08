import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI
from fastapi import Path as ApiPath

from api.app.asset_context import AssetContextRepository
from api.app.contracts import (
    AssetContext,
    AuditRecord,
    DecisionRecord,
    FeatureBatchResponse,
    FeaturePipelineResponse,
    HealthResponse,
    IncidentRequest,
    PredictionResponse,
    ReadinessResponse,
    RiskEvaluation,
    RiskEvaluationRequest,
    ThreatIntelligenceResult,
    ThreatLookupRequest,
    WazuhAlert,
    WazuhAlertBatch,
)
from api.app.mock_services import lookup_ti_mock, predict_mock
from api.app.risk import calculate_risk
from api.app.risk_policy import RiskPolicyRepository
from api.app.threat_intelligence import (
    ThreatIntelligencePolicy,
    lookup_threat_intelligence,
)
from ml.feature_pipeline import aggregate_wazuh_alerts, extract_wazuh_features

app = FastAPI(
    title="DATN AI SOAR API",
    summary="Week 1 compatibility API plus Week 2 feature and context services",
    version="2.0.0-week2",
)

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
ASSET_CONTEXT_PATH = CONFIG_DIR / "asset-context.yaml"
asset_context_repository = AssetContextRepository(ASSET_CONTEXT_PATH)
risk_policy_repository = RiskPolicyRepository(CONFIG_DIR / "risk-policy-week2.yaml")
ti_policy = ThreatIntelligencePolicy.load(CONFIG_DIR / "ti-policy.yaml")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse()


@app.get("/ready", response_model=ReadinessResponse)
def readiness() -> ReadinessResponse:
    raw_mode = os.getenv("VT_MODE", "mock").strip().lower()
    mode = raw_mode if raw_mode in {"mock", "live", "disabled"} else "invalid"
    degraded = mode == "invalid" or (mode == "live" and not os.getenv("VT_API_KEY"))
    return ReadinessResponse(
        status="degraded" if degraded else "ready",
        ti_mode=mode,
    )


@app.post("/predict", response_model=PredictionResponse)
def predict(incident: IncidentRequest) -> PredictionResponse:
    return predict_mock(incident)


@app.post("/features/wazuh", response_model=FeaturePipelineResponse)
def features_from_wazuh(alert: WazuhAlert) -> FeaturePipelineResponse:
    return extract_wazuh_features(alert)


@app.post("/features/wazuh/batch", response_model=FeatureBatchResponse)
def features_from_wazuh_batch(batch: WazuhAlertBatch) -> FeatureBatchResponse:
    return aggregate_wazuh_alerts(
        batch.alerts,
        window_minutes=batch.window_minutes,
    )


@app.get("/assets/{asset_id}", response_model=AssetContext)
def asset_context(
    asset_id: Annotated[str, ApiPath(min_length=1, max_length=128)],
) -> AssetContext:
    return asset_context_repository.get(asset_id)


@app.post("/ti/lookup", response_model=ThreatIntelligenceResult)
def threat_intelligence(request: ThreatLookupRequest) -> ThreatIntelligenceResult:
    settings = ti_policy.virustotal
    timeout_value = os.getenv("VT_TIMEOUT_SECONDS", str(settings.timeout_seconds))
    try:
        timeout_seconds = float(timeout_value)
    except ValueError:
        timeout_seconds = settings.timeout_seconds
    return lookup_threat_intelligence(
        request.indicator,
        mode=os.getenv("VT_MODE", "mock"),
        api_key=os.getenv("VT_API_KEY"),
        timeout_seconds=timeout_seconds,
        minimum_engines=settings.minimum_engines,
        max_report_age_days=settings.max_report_age_days,
    )


@app.post("/risk/evaluate", response_model=RiskEvaluation)
def evaluate_risk(request: RiskEvaluationRequest) -> RiskEvaluation:
    return risk_policy_repository.evaluate(**request.model_dump())


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
