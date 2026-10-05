from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FamilyHint = Literal["account", "c2", "unknown"]
ThreatStatus = Literal["MALICIOUS", "CLEAN", "UNKNOWN"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


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

    @model_validator(mode="after")
    def validate_time_window(self) -> "IncidentRequest":
        if self.end_time < self.start_time:
            raise ValueError("end_time must not be earlier than start_time")
        return self


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
