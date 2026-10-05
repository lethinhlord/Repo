from decimal import ROUND_HALF_UP, Decimal

from api.app.contracts import RiskResult

WEIGHTS = {
    "ai": 0.40,
    "observed_evidence": 0.20,
    "threat_intelligence": 0.15,
    "asset": 0.15,
    "severity": 0.10,
}


def _unit(value: float) -> float:
    return min(1.0, max(0.0, value))


def calculate_risk(
    *,
    ai_probability: float,
    observed_evidence: float,
    ti_score: float,
    asset_score: float,
    severity_score: float,
) -> RiskResult:
    internal = round(
        WEIGHTS["ai"] * _unit(ai_probability)
        + WEIGHTS["observed_evidence"] * _unit(observed_evidence)
        + WEIGHTS["threat_intelligence"] * _unit(ti_score)
        + WEIGHTS["asset"] * _unit(asset_score)
        + WEIGHTS["severity"] * _unit(severity_score),
        6,
    )
    display = float(
        Decimal(str(10 * internal)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    )
    return RiskResult(internal=internal, display=display)
