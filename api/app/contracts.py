from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FamilyHint = Literal["account", "c2", "unknown"]
ThreatStatus = Literal["MALICIOUS", "CLEAN", "UNKNOWN"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ExternalModel(BaseModel):
    """Tolerant boundary model for the evolving Wazuh event envelope."""

    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    service: Literal["datn-ai-soar-api"] = "datn-ai-soar-api"
    api_version: Literal["4.0.0"] = "4.0.0"


class IncidentRequest(StrictModel):
    feature_schema_version: Literal["features-v3"] = "features-v3"
    context_status: Literal["AVAILABLE", "MISSING", "STALE", "FUTURE", "UNKNOWN"] = "MISSING"
    context_revision: str | None = None
    review_reasons: list[str] = Field(default_factory=list)
    observation_quality: Literal["COMPLETE", "PARTIAL"] = "PARTIAL"
    incident_id: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=128)
    start_time: datetime
    end_time: datetime
    family_hint: FamilyHint = "unknown"
    features: dict[str, float] = Field(default_factory=dict)
    evidence_sources: list[str] = Field(min_length=1)
    base_severity: int = Field(ge=0, le=15)
    raw_refs: list[str] = Field(default_factory=list)
    indicator: str | None = Field(default=None, max_length=512)

    @field_validator("start_time", "end_time")
    @classmethod
    def normalize_incident_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("incident timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_time_window(self) -> "IncidentRequest":
        if self.end_time < self.start_time:
            raise ValueError("end_time must not be earlier than start_time")
        if any(not source.strip() for source in self.evidence_sources):
            raise ValueError("evidence_sources must contain nonblank values")
        if len(set(self.evidence_sources)) != len(self.evidence_sources):
            raise ValueError("evidence_sources must be unique")
        return self


class WazuhRule(ExternalModel):
    id: str | int
    level: int = Field(ge=0, le=15)
    description: str = ""


class WazuhAgent(ExternalModel):
    id: str | int = "unknown"
    name: str = Field(default="unknown-asset", min_length=1, max_length=128)


class WazuhDecoder(ExternalModel):
    name: str = Field(default="unknown", max_length=128)


class WazuhAlertData(ExternalModel):
    srcip: str | None = Field(default=None, max_length=512)
    destination_ip: str | None = Field(default=None, max_length=512)
    destination_domain: str | None = Field(default=None, max_length=512)
    dstuser: str | None = Field(default=None, max_length=256)
    failed_login_count: float | None = Field(default=None, ge=0, le=1_000_000)
    success_after_fail: float | None = Field(default=None, ge=0, le=1)
    suspicious_process: float | None = Field(default=None, ge=0, le=1)
    periodicity_score: float | None = Field(default=None, ge=0, le=1)
    suricata_alert_count: float | None = Field(default=None, ge=0, le=1_000_000)
    outbound_connection_count: float | None = Field(default=None, ge=0, le=1_000_000)
    destination_port_count: float | None = Field(default=None, ge=0, le=65_535)
    win: dict[str, object] | None = None
    event_type: str | None = Field(default=None, max_length=32)
    timestamp: str | None = Field(default=None, max_length=64)
    src_ip: str | None = Field(default=None, max_length=64)
    dest_ip: str | None = Field(default=None, max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    flow_id: int | str | None = None
    proto: str | None = Field(default=None, max_length=32)
    sensor_instance: str | None = Field(default=None, max_length=128)
    dns: dict[str, object] | None = None
    http: dict[str, object] | None = None
    tls: dict[str, object] | None = None
    flow: dict[str, object] | None = None
    alert: dict[str, object] | None = None


class WazuhAlert(ExternalModel):
    id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    rule: WazuhRule
    agent: WazuhAgent
    decoder: WazuhDecoder = Field(default_factory=WazuhDecoder)
    data: WazuhAlertData = Field(default_factory=WazuhAlertData)
    location: str = Field(default="unknown-log", max_length=1024)
    full_log: str | None = Field(default=None, max_length=2_000_000)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Wazuh timestamp must include a timezone")
        return value.astimezone(UTC)


class SignedWazuhIngestRequest(StrictModel):
    timestamp: int = Field(gt=0)
    nonce: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    signature: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    payload: dict[str, object]

    @field_validator("payload")
    @classmethod
    def bound_payload(cls, value: dict[str, object]) -> dict[str, object]:
        import json

        if len(json.dumps(value, default=str).encode()) > 2_000_000:
            raise ValueError("Wazuh payload exceeds 2 MB")
        return value


class SignedWazuhIngestResponse(StrictModel):
    verified: Literal[True] = True
    source_event_id: str
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_at: datetime


class FeaturePipelineResponse(StrictModel):
    feature_schema_version: Literal["features-v3"] = "features-v3"
    feature_order: list[str]
    ordered_vector: list[float]
    quality_status: Literal["COMPLETE", "PARTIAL"]
    missing_required_features: list[str]
    structural_zero_features: list[str]
    evidence_quality: float = Field(ge=0.0, le=1.0)
    evidence_quality_reasons: list[str] = Field(min_length=1)
    incident: IncidentRequest


class WazuhAlertBatch(StrictModel):
    alerts: list[WazuhAlert] = Field(min_length=1, max_length=1000)
    window_minutes: int = Field(default=5, ge=1, le=5)


class FeatureBatchResponse(StrictModel):
    feature_schema_version: Literal["features-v3"] = "features-v3"
    input_alert_count: int = Field(ge=1)
    unique_alert_count: int = Field(ge=1)
    duplicate_alert_count: int = Field(ge=0)
    incidents: list[FeaturePipelineResponse] = Field(min_length=1)


class FeatureStateResponse(StrictModel):
    ingest_status: Literal["new", "duplicate"]
    stored_event_count: int = Field(ge=1)
    window_minutes: int = Field(ge=1, le=5)
    feature: FeaturePipelineResponse


class FeatureWindowFinalizeRequest(StrictModel):
    alert_id: str = Field(min_length=1, max_length=128)
    window_minutes: int = Field(default=5, ge=1, le=5)


class PredictionResponse(StrictModel):
    review_reasons: list[str] = Field(default_factory=list)
    model_version: str = Field(default="mock-v1", min_length=1, max_length=128)
    predicted_class: Literal["malicious", "benign"]
    malicious_probability: float = Field(ge=0.0, le=1.0)
    family: FamilyHint
    threshold_revision: str = Field(default="mock-thr-v1", min_length=1, max_length=128)
    automation_eligible: bool = False
    review_required: bool = True
    inference_mode: Literal["trained", "mock"] = "mock"
    ood_detected: bool = False
    ood_features: list[str] = Field(default_factory=list)
    monitoring_revision: Literal["model-monitor-v2"] = "model-monitor-v2"


class ModelMetricsResponse(StrictModel):
    monitoring_revision: Literal["model-monitor-v2"] = "model-monitor-v2"
    model_version: str
    monitoring_storage: Literal["memory", "sqlite"]
    predictions_total: int = Field(ge=0)
    predictions_by_family: dict[str, int]
    review_required_total: int = Field(ge=0)
    ood_total: int = Field(ge=0)
    ood_by_family: dict[str, int]
    ood_by_feature: dict[str, int]
    feedback_total: int = Field(default=0, ge=0)
    feedback_by_disposition: dict[str, int] = Field(default_factory=dict)
    false_positive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    false_negative_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    monitoring_alerts: list[str]
    last_prediction_at: datetime | None


class AnalystFeedbackRequest(StrictModel):
    incident_id: str = Field(min_length=1, max_length=128)
    source_event_id: str | None = Field(default=None, min_length=1, max_length=128)
    model_version: str = Field(min_length=1, max_length=128)
    analyst_id: str = Field(min_length=1, max_length=128)
    analyst_label: Literal["benign", "malicious", "uncertain"]
    disposition: Literal[
        "true_positive",
        "false_positive",
        "true_negative",
        "false_negative",
        "needs_investigation",
    ]
    notes: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def validate_feedback_semantics(self) -> "AnalystFeedbackRequest":
        expected = {
            "true_positive": "malicious",
            "false_positive": "benign",
            "true_negative": "benign",
            "false_negative": "malicious",
            "needs_investigation": "uncertain",
        }
        if expected[self.disposition] != self.analyst_label:
            raise ValueError("analyst_label contradicts disposition")
        return self


class AnalystFeedbackResponse(StrictModel):
    feedback_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    incident_id: str
    model_version: str
    disposition: Literal["created", "duplicate"]
    recorded_at: datetime


class ModelReadinessResponse(StrictModel):
    status: Literal["ready", "not_configured", "invalid"]
    mode: Literal["trained", "mock", "unconfigured"]
    model_version: str
    feature_schema_version: str
    locked_test_status: str
    detail: str


class ThreatIntelligenceContext(StrictModel):
    provider: Literal["mock-ti-v1"] = "mock-ti-v1"
    indicator: str | None
    status: ThreatStatus
    score: float = Field(ge=0.0, le=1.0)
    rationale: str


class ThreatLookupRequest(StrictModel):
    indicator: str | None = Field(default=None, max_length=512)


ThreatReasonCode = Literal[
    "DETECTED",
    "NO_DETECTIONS",
    "INSUFFICIENT_DATA",
    "NO_INDICATOR",
    "NON_PUBLIC_INDICATOR",
    "RATE_LIMITED",
    "AUTH_ERROR",
    "NOT_FOUND",
    "PROVIDER_UNAVAILABLE",
    "INVALID_RESPONSE",
    "STALE_REPORT",
    "TIMEOUT",
    "NOT_CONFIGURED",
    "DISABLED",
    "INVALID_MODE",
]


class ThreatIntelligenceResult(StrictModel):
    provider: Literal["mock-ti-v2", "virustotal-v3", "disabled"]
    indicator: str | None
    status: Literal["MALICIOUS", "BENIGN", "UNKNOWN"]
    available: bool
    score: float | None = Field(default=None, ge=0.0, le=1.0)
    reason_code: ThreatReasonCode
    rationale: str
    detections: int | None = Field(default=None, ge=0)
    total_votes: int | None = Field(default=None, ge=0)
    last_analysis_at: datetime | None = None
    policy_revision: Literal["ti-week2-v1"] = "ti-week2-v1"

    @model_validator(mode="after")
    def validate_availability(self) -> "ThreatIntelligenceResult":
        if self.status == "UNKNOWN" and (self.available or self.score is not None):
            raise ValueError("UNKNOWN threat intelligence must be unavailable with no score")
        if self.status != "UNKNOWN" and (not self.available or self.score is None):
            raise ValueError("known threat intelligence must be available with a score")
        return self


class AssetContext(StrictModel):
    asset_id: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=128)
    criticality: int | None = Field(default=None, ge=1, le=5)
    protected: bool
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    source: Literal["inventory", "default"]
    status: Literal["FOUND", "UNKNOWN"]
    review_required: bool
    context_revision: Literal["asset-context-v1"] = "asset-context-v1"

    @model_validator(mode="after")
    def validate_context_state(self) -> "AssetContext":
        if self.status == "UNKNOWN" and (
            self.criticality is not None
            or self.risk_score is not None
            or not self.review_required
            or not self.protected
            or self.source != "default"
        ):
            raise ValueError("UNKNOWN assets must be protected, unscored, and require review")
        if self.status == "FOUND" and (
            self.criticality is None
            or self.risk_score is None
            or self.review_required != self.protected
        ):
            raise ValueError(
                "FOUND assets require a score; protected assets alone require review"
            )
        return self


class RiskEvaluationRequest(StrictModel):
    ai_probability: float = Field(ge=0.0, le=1.0)
    observed_evidence: float = Field(ge=0.0, le=1.0)
    threat_intelligence_score: float | None = Field(default=None, ge=0.0, le=1.0)
    asset_score: float | None = Field(default=None, ge=0.0, le=1.0)
    severity_score: float = Field(ge=0.0, le=1.0)
    feature_quality: Literal["COMPLETE", "PARTIAL"]
    model_automation_eligible: bool
    model_review_required: bool
    threat_intelligence_status: Literal["MALICIOUS", "BENIGN", "UNKNOWN"]
    asset_review_required: bool

    @model_validator(mode="after")
    def validate_context_statuses(self) -> "RiskEvaluationRequest":
        if (self.threat_intelligence_status == "UNKNOWN") != (
            self.threat_intelligence_score is None
        ):
            raise ValueError("UNKNOWN TI requires a null score and known TI requires a score")
        if self.asset_score is None and not self.asset_review_required:
            raise ValueError("missing asset context must require review")
        return self


class RiskEvaluation(StrictModel):
    policy_revision: Literal["risk-week2-v2"] = "risk-week2-v2"
    internal: float = Field(ge=0.0, le=1.0)
    display: float = Field(ge=0.0, le=10.0)
    available_weight: float = Field(gt=0.0, le=1.0)
    missing_signals: list[Literal["threat_intelligence", "asset"]]
    contributions: dict[str, float]
    review_required: bool
    review_reasons: list[str]


class IncidentRecordRequest(StrictModel):
    incident_id: str = Field(min_length=1, max_length=128)
    source_event_id: str = Field(min_length=1, max_length=128)
    source_payload_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    route: Literal["shadow", "review"]
    review_required: bool
    notification: str = Field(min_length=1, max_length=4096)
    decision: dict[str, object]

    @field_validator("decision")
    @classmethod
    def bound_decision_document(cls, value: dict[str, object]) -> dict[str, object]:
        import json

        if len(json.dumps(value, default=str).encode()) > 1_000_000:
            raise ValueError("decision document exceeds 1 MB")
        return value


class IncidentRecordResponse(StrictModel):
    incident_id: str
    source_event_id: str
    disposition: Literal["created", "updated", "duplicate"]
    notification_status: Literal["QUEUED", "ALREADY_QUEUED"]
    notification_revision: int = Field(default=1, ge=1)
    route: Literal["shadow", "review"]
    review_required: bool
    recorded_at: datetime


class NotificationDispatchRequest(StrictModel):
    incident_id: str = Field(min_length=1, max_length=128)
    notification_revision: int | None = Field(default=None, ge=1)


class NotificationDispatchResponse(StrictModel):
    incident_id: str
    notification_revision: int = Field(default=1, ge=1)
    notification_status: Literal["SENT", "ALREADY_SENT", "SUPERSEDED"]
    channel: Literal["audit-log", "webhook"] | None = None
    delivered_at: datetime | None = None
    superseded_by_revision: int | None = Field(default=None, ge=1)


class ReadinessResponse(StrictModel):
    status: Literal["ready", "degraded"]
    service: Literal["datn-ai-soar-api"] = "datn-ai-soar-api"
    api_version: Literal["4.0.0"] = "4.0.0"
    feature_schema_version: Literal["features-v3"] = "features-v3"
    asset_context_revision: Literal["asset-context-v1"] = "asset-context-v1"
    risk_policy_revision: Literal["risk-week2-v2"] = "risk-week2-v2"
    ti_policy_revision: Literal["ti-week2-v1"] = "ti-week2-v1"
    ti_mode: Literal["mock", "live", "disabled", "invalid"]
    model_status: Literal["ready", "not_configured", "invalid"]
    inference_mode: Literal["trained", "mock", "unconfigured"]
    strong_actions_enabled: Literal[False] = False


class RiskResult(StrictModel):
    policy_revision: Literal["risk-week1-v1"] = "risk-week1-v1"
    internal: float = Field(ge=0.0, le=1.0)
    display: float = Field(ge=0.0, le=10.0)


class AuditRecord(StrictModel):
    incident_id: str
    recorded_at: datetime
    workflow_revision: Literal["week1-mock-v1"] = "week1-mock-v1"
    outcome: Literal["NOTIFIED"] = "NOTIFIED"


class DecisionRecord(StrictModel):
    incident_id: str
    prediction: PredictionResponse
    ti_context: ThreatIntelligenceContext
    risk: RiskResult
    automation_state: Literal["SHADOW"] = "SHADOW"
    selected_playbook: Literal["create_update_incident_notify"] = (
        "create_update_incident_notify"
    )
    strong_action_allowed: Literal[False] = False
    rationale: list[str]
    audit: AuditRecord
