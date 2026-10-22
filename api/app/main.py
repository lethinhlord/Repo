import os
import sqlite3
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException
from fastapi import Path as ApiPath

from api.app.asset_context import AssetContextRepository
from api.app.contracts import (
    AssetContext,
    AuditRecord,
    DecisionRecord,
    FeatureBatchResponse,
    FeaturePipelineResponse,
    FeatureStateResponse,
    HealthResponse,
    IncidentRequest,
    ModelReadinessResponse,
    PredictionResponse,
    ReadinessResponse,
    RiskEvaluation,
    RiskEvaluationRequest,
    ThreatIntelligenceResult,
    ThreatLookupRequest,
    WazuhAlert,
    WazuhAlertBatch,
)
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from api.app.mock_services import lookup_ti_mock, predict_mock
from api.app.risk import calculate_risk
from api.app.risk_policy import RiskPolicyRepository
from api.app.threat_intelligence import (
    ThreatIntelligencePolicy,
    lookup_threat_intelligence,
)
from ml.feature_pipeline import aggregate_wazuh_alerts, extract_wazuh_features
from ml.inference import InferenceInputError, ModelPackageError, ModelRuntime

app = FastAPI(
    title="DATN AI SOAR API",
    summary="Week 1/2 compatibility services plus Week 3 trained-model inference",
    version="3.0.0-week3",
)

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
ASSET_CONTEXT_PATH = CONFIG_DIR / "asset-context.yaml"
asset_context_repository = AssetContextRepository(ASSET_CONTEXT_PATH)
risk_policy_repository = RiskPolicyRepository(CONFIG_DIR / "risk-policy-week2.yaml")
ti_policy = ThreatIntelligencePolicy.load(CONFIG_DIR / "ti-policy.yaml")


@lru_cache(maxsize=4)
def load_model_runtime(package_dir: str) -> ModelRuntime:
    """Load once per configured path; deployments restart when a package changes."""

    return ModelRuntime(Path(package_dir))


@lru_cache(maxsize=4)
def load_feature_state_store(path: str, retention_seconds: int) -> FeatureStateStore:
    return FeatureStateStore(Path(path), retention_seconds=retention_seconds)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse()


def _allow_mock_inference() -> bool:
    return os.getenv("ALLOW_MOCK_INFERENCE", "false").strip().lower() == "true"


def _model_state() -> tuple[str, str]:
    package_dir = os.getenv("MODEL_PACKAGE_DIR", "").strip()
    if not package_dir:
        return ("not_configured", "mock" if _allow_mock_inference() else "unconfigured")
    try:
        load_model_runtime(package_dir)
    except (ModelPackageError, OSError, ValueError):
        return ("invalid", "unconfigured")
    return ("ready", "trained")


@app.get("/ready", response_model=ReadinessResponse)
def readiness() -> ReadinessResponse:
    raw_mode = os.getenv("VT_MODE", "mock").strip().lower()
    mode = raw_mode if raw_mode in {"mock", "live", "disabled"} else "invalid"
    model_status, inference_mode = _model_state()
    degraded = (
        mode == "invalid"
        or (mode == "live" and not os.getenv("VT_API_KEY"))
        or model_status != "ready"
    )
    return ReadinessResponse(
        status="degraded" if degraded else "ready",
        ti_mode=mode,
        model_status=model_status,
        inference_mode=inference_mode,
    )


@app.post("/predict", response_model=PredictionResponse)
def predict(incident: IncidentRequest) -> PredictionResponse:
    package_dir = os.getenv("MODEL_PACKAGE_DIR", "").strip()
    if package_dir:
        try:
            return load_model_runtime(package_dir).predict(incident)
        except InferenceInputError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (ModelPackageError, OSError, ValueError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    if _allow_mock_inference():
        return predict_mock(incident)
    raise HTTPException(
        status_code=503,
        detail="trained model is not configured; mock inference is disabled",
    )


@app.get("/model/ready", response_model=ModelReadinessResponse)
def model_readiness() -> ModelReadinessResponse:
    package_dir = os.getenv("MODEL_PACKAGE_DIR", "").strip()
    if not package_dir:
        return ModelReadinessResponse(
            status="not_configured",
            mode="mock" if _allow_mock_inference() else "unconfigured",
            model_version="mock-v1",
            feature_schema_version="features-v2",
            locked_test_status="UNOPENED",
            detail=(
                "MODEL_PACKAGE_DIR is not configured; explicit lab mock inference is active."
                if _allow_mock_inference()
                else "MODEL_PACKAGE_DIR is not configured; inference is unavailable."
            ),
        )
    try:
        runtime = load_model_runtime(package_dir)
    except (ModelPackageError, OSError, ValueError) as exc:
        return ModelReadinessResponse(
            status="invalid",
            mode="unconfigured",
            model_version="unavailable",
            feature_schema_version="features-v2",
            locked_test_status="UNKNOWN",
            detail=str(exc),
        )
    return ModelReadinessResponse(
        status="ready",
        mode="trained",
        model_version=runtime.metadata["model_version"],
        feature_schema_version=runtime.metadata["feature_schema_version"],
        locked_test_status=runtime.locked_test_status,
        detail="Validated trained model package is active.",
    )


@app.post("/features/wazuh", response_model=FeaturePipelineResponse)
def features_from_wazuh(alert: WazuhAlert) -> FeaturePipelineResponse:
    return extract_wazuh_features(alert)


@app.post("/features/wazuh/batch", response_model=FeatureBatchResponse)
def features_from_wazuh_batch(batch: WazuhAlertBatch) -> FeatureBatchResponse:
    return aggregate_wazuh_alerts(
        batch.alerts,
        window_minutes=batch.window_minutes,
    )


@app.post("/features/wazuh/stateful", response_model=FeatureStateResponse)
def features_from_wazuh_stateful(alert: WazuhAlert) -> FeatureStateResponse:
    path = os.getenv("FEATURE_STATE_DB", "/tmp/datn-feature-state.sqlite3").strip()
    try:
        retention_seconds = int(os.getenv("FEATURE_STATE_RETENTION_SECONDS", "86400"))
        return load_feature_state_store(path, retention_seconds).ingest(alert)
    except FeatureStateConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"feature state unavailable: {exc}") from exc


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
