import logging
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
    AnalystFeedbackRequest,
    AnalystFeedbackResponse,
    AssetContext,
    AuditRecord,
    DecisionRecord,
    FeatureBatchResponse,
    FeaturePipelineResponse,
    FeatureStateResponse,
    HealthResponse,
    IncidentRecordRequest,
    IncidentRecordResponse,
    IncidentRequest,
    ModelMetricsResponse,
    ModelReadinessResponse,
    NotificationDispatchRequest,
    NotificationDispatchResponse,
    PredictionResponse,
    ReadinessResponse,
    RiskEvaluation,
    RiskEvaluationRequest,
    SignedWazuhIngestRequest,
    SignedWazuhIngestResponse,
    ThreatIntelligenceResult,
    ThreatLookupRequest,
    WazuhAlert,
    WazuhAlertBatch,
)
from api.app.feature_state import FeatureStateConflictError, FeatureStateStore
from api.app.feedback_store import AnalystFeedbackStore
from api.app.incident_store import IncidentStore
from api.app.mock_services import lookup_ti_mock, predict_mock
from api.app.notification import NotificationDeliveryError, deliver_notification
from api.app.risk import calculate_risk
from api.app.risk_policy import RiskPolicyRepository
from api.app.threat_intelligence import (
    ThreatIntelligencePolicy,
    lookup_threat_intelligence,
)
from api.app.webhook_auth import WebhookAuthenticationError, WebhookAuthenticator
from ml.feature_pipeline import aggregate_wazuh_alerts, extract_wazuh_features
from ml.inference import InferenceInputError, ModelPackageError, ModelRuntime

logger = logging.getLogger(__name__)

app = FastAPI(
    title="DATN AI SOAR API",
    summary="Week 1/2 compatibility services plus Week 3 trained-model inference",
    version="3.1.0",
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


@lru_cache(maxsize=4)
def load_incident_store(path: str) -> IncidentStore:
    return IncidentStore(Path(path))


@lru_cache(maxsize=4)
def load_feedback_store(path: str, incident_path: str) -> AnalystFeedbackStore:
    return AnalystFeedbackStore(Path(path), Path(incident_path))


@lru_cache(maxsize=4)
def load_webhook_authenticator(
    path: str, secret: str, max_skew_seconds: int, max_requests_per_minute: int
) -> WebhookAuthenticator:
    return WebhookAuthenticator(
        Path(path),
        secret,
        max_skew_seconds=max_skew_seconds,
        max_requests_per_minute=max_requests_per_minute,
    )


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


@app.get("/model/metrics", response_model=ModelMetricsResponse)
def model_metrics() -> ModelMetricsResponse:
    package_dir = os.getenv("MODEL_PACKAGE_DIR", "").strip()
    if not package_dir:
        raise HTTPException(status_code=503, detail="trained model is not configured")
    try:
        return load_model_runtime(package_dir).metrics_snapshot()
    except (ModelPackageError, OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/model/feedback", response_model=AnalystFeedbackResponse)
def model_feedback(request: AnalystFeedbackRequest) -> AnalystFeedbackResponse:
    path = os.getenv("MODEL_FEEDBACK_DB", "/tmp/datn-model-feedback.sqlite3").strip()
    incident_path = os.getenv("INCIDENT_DB", "/tmp/datn-incidents.sqlite3").strip()
    try:
        return load_feedback_store(path, incident_path).record(request)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(status_code=503, detail=f"feedback store unavailable: {exc}") from exc


@app.post("/features/wazuh", response_model=FeaturePipelineResponse)
def features_from_wazuh(alert: WazuhAlert) -> FeaturePipelineResponse:
    return extract_wazuh_features(alert)


@app.post("/ingress/wazuh/verify", response_model=SignedWazuhIngestResponse)
def verify_wazuh_ingress(request: SignedWazuhIngestRequest) -> SignedWazuhIngestResponse:
    path = os.getenv("INGRESS_NONCE_DB", "/tmp/datn-ingress-nonces.sqlite3").strip()
    secret = os.getenv("WAZUH_WEBHOOK_SECRET", "")
    try:
        max_skew = int(os.getenv("WAZUH_WEBHOOK_MAX_SKEW_SECONDS", "300"))
        max_requests = int(os.getenv("WAZUH_WEBHOOK_MAX_REQUESTS_PER_MINUTE", "300"))
        return load_webhook_authenticator(path, secret, max_skew, max_requests).verify(request)
    except WebhookAuthenticationError as exc:
        logger.warning("Wazuh ingress rejected: %s", exc)
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"webhook verifier unavailable: {exc}") from exc


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


@app.post("/incidents/record", response_model=IncidentRecordResponse)
def record_incident(request: IncidentRecordRequest) -> IncidentRecordResponse:
    path = os.getenv("INCIDENT_DB", "/tmp/datn-incidents.sqlite3").strip()
    try:
        return load_incident_store(path).record(request)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(status_code=503, detail=f"incident store unavailable: {exc}") from exc


@app.post("/notifications/dispatch", response_model=NotificationDispatchResponse)
def dispatch_notification(
    request: NotificationDispatchRequest,
) -> NotificationDispatchResponse:
    path = os.getenv("INCIDENT_DB", "/tmp/datn-incidents.sqlite3").strip()
    mode = os.getenv("NOTIFICATION_MODE", "log")
    webhook_url = os.getenv("NOTIFICATION_WEBHOOK_URL")
    try:
        timeout_seconds = float(os.getenv("NOTIFICATION_TIMEOUT_SECONDS", "5"))
        if not 0 < timeout_seconds <= 30:
            raise ValueError("notification timeout must be between 0 and 30 seconds")
        return load_incident_store(path).dispatch_notification(
            request.incident_id,
            lambda incident_id, message: deliver_notification(
                incident_id,
                message,
                mode=mode,
                webhook_url=webhook_url,
                timeout_seconds=timeout_seconds,
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (NotificationDeliveryError, OSError, sqlite3.Error) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


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
