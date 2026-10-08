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
    mode: Literal["mock"] = "mock"
    api_version: Literal["1.0.0"] = "1.0.0"
    model_version: Literal["mock-v1"] = "mock-v1"


class IncidentRequest(StrictModel):
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


class WazuhAlert(ExternalModel):
    id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    rule: WazuhRule
    agent: WazuhAgent
    decoder: WazuhDecoder = Field(default_factory=WazuhDecoder)
    data: WazuhAlertData = Field(default_factory=WazuhAlertData)
    location: str = Field(default="unknown-log", max_length=1024)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Wazuh timestamp must include a timezone")
        return value.astimezone(UTC)


class FeaturePipelineResponse(StrictModel):
    feature_schema_version: Literal["features-v1"] = "features-v1"
    feature_order: list[str]
    ordered_vector: list[float]
    quality_status: Literal["COMPLETE", "PARTIAL"]
    missing_required_features: list[str]
    structural_zero_features: list[str]
    incident: IncidentRequest


class WazuhAlertBatch(StrictModel):
    alerts: list[WazuhAlert] = Field(min_length=1, max_length=1000)
    window_minutes: int = Field(default=5, ge=1, le=5)


class FeatureBatchResponse(StrictModel):
    feature_schema_version: Literal["features-v1"] = "features-v1"
    input_alert_count: int = Field(ge=1)
    unique_alert_count: int = Field(ge=1)
    duplicate_alert_count: int = Field(ge=0)
    incidents: list[FeaturePipelineResponse] = Field(min_length=1)


class PredictionResponse(StrictModel):
    model_version: Literal["mock-v1"] = "mock-v1"
    predicted_class: Literal["malicious", "benign"]
    malicious_probability: float = Field(ge=0.0, le=1.0)
    family: FamilyHint
    threshold_revision: Literal["mock-thr-v1"] = "mock-thr-v1"


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
            self.criticality is None or self.risk_score is None or self.review_required
        ):
            raise ValueError("FOUND assets require a score and must not force review")
        return self


class RiskEvaluationRequest(StrictModel):
    ai_probability: float = Field(ge=0.0, le=1.0)
    observed_evidence: float = Field(ge=0.0, le=1.0)
    threat_intelligence_score: float | None = Field(default=None, ge=0.0, le=1.0)
    asset_score: float | None = Field(default=None, ge=0.0, le=1.0)
    severity_score: float = Field(ge=0.0, le=1.0)


class RiskEvaluation(StrictModel):
    policy_revision: Literal["risk-week2-v1"] = "risk-week2-v1"
    internal: float = Field(ge=0.0, le=1.0)
    display: float = Field(ge=0.0, le=10.0)
    available_weight: float = Field(gt=0.0, le=1.0)
    missing_signals: list[Literal["threat_intelligence", "asset"]]
    contributions: dict[str, float]
    review_required: bool


class ReadinessResponse(StrictModel):
    status: Literal["ready", "degraded"]
    service: Literal["datn-ai-soar-api"] = "datn-ai-soar-api"
    api_version: Literal["2.0.0-week2"] = "2.0.0-week2"
    feature_schema_version: Literal["features-v1"] = "features-v1"
    asset_context_revision: Literal["asset-context-v1"] = "asset-context-v1"
    risk_policy_revision: Literal["risk-week2-v1"] = "risk-week2-v1"
    ti_policy_revision: Literal["ti-week2-v1"] = "ti-week2-v1"
    ti_mode: Literal["mock", "live", "disabled", "invalid"]
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
