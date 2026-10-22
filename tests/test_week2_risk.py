from pathlib import Path

import pytest

from api.app.risk_policy import RiskPolicyRepository

ROOT = Path(__file__).resolve().parents[1]


def repository() -> RiskPolicyRepository:
    return RiskPolicyRepository(ROOT / "config" / "risk-policy-week2.yaml")


def test_complete_context_uses_frozen_week2_weights() -> None:
    result = repository().evaluate(
        ai_probability=0.95,
        observed_evidence=1.0,
        threat_intelligence_score=0.9,
        asset_score=0.6,
        severity_score=0.8,
        feature_quality="COMPLETE",
        model_automation_eligible=True,
        model_review_required=False,
        threat_intelligence_status="BENIGN",
        asset_review_required=False,
    )

    assert result.internal == 0.885
    assert result.display == 8.9
    assert result.available_weight == 1.0
    assert result.missing_signals == []
    assert result.review_required is False
    assert sum(result.contributions.values()) == pytest.approx(0.885)


def test_unknown_context_keeps_policy_denominator_and_requires_review() -> None:
    result = repository().evaluate(
        ai_probability=0.8,
        observed_evidence=0.5,
        threat_intelligence_score=None,
        asset_score=None,
        severity_score=0.8,
        feature_quality="COMPLETE",
        model_automation_eligible=True,
        model_review_required=False,
        threat_intelligence_status="UNKNOWN",
        asset_review_required=True,
    )

    assert result.internal == 0.5
    assert result.available_weight == 0.7
    assert result.missing_signals == ["threat_intelligence", "asset"]
    assert result.review_required is True
    assert result.review_reasons == [
        "missing_signal:threat_intelligence",
        "missing_signal:asset",
        "asset:review_required",
    ]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"feature_quality": "PARTIAL"}, "feature_quality:PARTIAL"),
        ({"model_automation_eligible": False}, "model:automation_ineligible"),
        ({"model_review_required": True}, "model:review_required"),
        (
            {"threat_intelligence_status": "MALICIOUS"},
            "threat_intelligence:MALICIOUS",
        ),
        ({"asset_review_required": True}, "asset:review_required"),
    ],
)
def test_review_gate_covers_every_fail_closed_signal(overrides: dict, reason: str) -> None:
    values = {
        "ai_probability": 0.4,
        "observed_evidence": 1.0,
        "threat_intelligence_score": 0.5,
        "asset_score": 0.6,
        "severity_score": 0.4,
        "feature_quality": "COMPLETE",
        "model_automation_eligible": True,
        "model_review_required": False,
        "threat_intelligence_status": "BENIGN",
        "asset_review_required": False,
    }
    values.update(overrides)

    result = repository().evaluate(**values)

    assert result.review_required is True
    assert reason in result.review_reasons


def test_invalid_policy_weight_sum_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "risk.yaml"
    path.write_text(
        """revision: risk-week2-v2
weights:
  ai: 0.4
  observed_evidence: 0.2
  threat_intelligence: 0.1
  asset: 0.1
  severity: 0.1
automation_state: SHADOW
strong_actions_enabled: false
allowed_playbooks: [persist_incident_queue_review]
missing_signal_strategy: zero_contribution_review
malicious_ti_strategy: review
partial_feature_strategy: review
ineligible_model_strategy: review
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sum to 1"):
        RiskPolicyRepository(path)
