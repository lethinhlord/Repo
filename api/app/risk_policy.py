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

    revision: Literal["risk-week2-v1"]
    weights: dict[str, float]
    automation_state: Literal["SHADOW"]
    strong_actions_enabled: Literal[False]
    allowed_playbooks: list[Literal["create_update_incident_notify"]]

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
        numerator = sum(contributions.values())
        internal = round(numerator / available_weight, 6)
        display = float(
            Decimal(str(10 * internal)).quantize(
                Decimal("0.1"), rounding=ROUND_HALF_UP
            )
        )
        return RiskEvaluation(
            internal=internal,
            display=display,
            available_weight=available_weight,
            missing_signals=missing,
            contributions=contributions,
            review_required=bool(missing),
        )
