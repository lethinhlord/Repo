from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from api.app.contracts import RiskEvaluation

SIGNAL_NAMES = (
    "ai",
    "observed_evidence",
    "threat_intelligence",
    "asset",
    "severity",
)


class _RiskPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: Literal["risk-week2-v2"]
    weights: dict[str, float]
    automation_state: Literal["SHADOW"]
    strong_actions_enabled: Literal[False]
    allowed_playbooks: list[Literal["create_update_incident_notify"]]
    missing_signal_strategy: Literal["zero_contribution_review"]
    malicious_ti_strategy: Literal["review"]
    partial_feature_strategy: Literal["review"]
    ineligible_model_strategy: Literal["review"]

    @model_validator(mode="after")
    def validate_weights(self) -> "_RiskPolicy":
        if set(self.weights) != set(SIGNAL_NAMES):
            raise ValueError("risk policy must define exactly the five canonical signals")
        if any(weight < 0 or weight > 1 for weight in self.weights.values()):
            raise ValueError("risk policy weights must be between 0 and 1")
        if abs(sum(self.weights.values()) - 1.0) > 1e-9:
            raise ValueError("risk policy weights must sum to 1")
        if self.allowed_playbooks != ["create_update_incident_notify"]:
            raise ValueError("Week 2 permits only the notify-only playbook")
        return self


class RiskPolicyRepository:
    def __init__(self, policy_path: Path) -> None:
        document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        self._policy = _RiskPolicy.model_validate(document)

    def evaluate(
        self,
        *,
        ai_probability: float,
        observed_evidence: float,
        threat_intelligence_score: float | None,
        asset_score: float | None,
        severity_score: float,
        feature_quality: Literal["COMPLETE", "PARTIAL"],
        model_automation_eligible: bool,
        model_review_required: bool,
        threat_intelligence_status: Literal["MALICIOUS", "BENIGN", "UNKNOWN"],
        asset_review_required: bool,
    ) -> RiskEvaluation:
        values: dict[str, float | None] = {
            "ai": ai_probability,
            "observed_evidence": observed_evidence,
            "threat_intelligence": threat_intelligence_score,
            "asset": asset_score,
            "severity": severity_score,
        }
        for name, value in values.items():
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")

        missing = [
            name
            for name in ("threat_intelligence", "asset")
            if values[name] is None
        ]
        contributions = {
            name: round(self._policy.weights[name] * value, 6)
            for name, value in values.items()
            if value is not None
        }
        available_weight = round(
            sum(
                self._policy.weights[name]
                for name, value in values.items()
                if value is not None
            ),
            6,
        )
        internal = round(sum(contributions.values()), 6)
        display = float(
            Decimal(str(10 * internal)).quantize(
                Decimal("0.1"), rounding=ROUND_HALF_UP
            )
        )
        review_reasons = [f"missing_signal:{name}" for name in missing]
        if feature_quality == "PARTIAL":
            review_reasons.append("feature_quality:PARTIAL")
        if not model_automation_eligible:
            review_reasons.append("model:automation_ineligible")
        if model_review_required:
            review_reasons.append("model:review_required")
        if threat_intelligence_status == "MALICIOUS":
            review_reasons.append("threat_intelligence:MALICIOUS")
        if threat_intelligence_status == "UNKNOWN" and "threat_intelligence" not in missing:
            review_reasons.append("threat_intelligence:UNKNOWN")
        if asset_review_required:
            review_reasons.append("asset:review_required")
        return RiskEvaluation(
            internal=internal,
            display=display,
            available_weight=available_weight,
            missing_signals=missing,
            contributions=contributions,
            review_required=bool(review_reasons),
            review_reasons=review_reasons,
        )
