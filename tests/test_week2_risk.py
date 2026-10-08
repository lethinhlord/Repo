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
    )

    assert result.internal == 0.885
    assert result.display == 8.9
    assert result.available_weight == 1.0
    assert result.missing_signals == []
    assert result.review_required is False
    assert sum(result.contributions.values()) == pytest.approx(0.885)


def test_unknown_context_is_excluded_instead_of_treated_as_benign() -> None:
    result = repository().evaluate(
        ai_probability=0.8,
        observed_evidence=0.5,
        threat_intelligence_score=None,
        asset_score=None,
        severity_score=0.8,
    )

    assert result.internal == 0.714286
    assert result.available_weight == 0.7
    assert result.missing_signals == ["threat_intelligence", "asset"]
    assert result.review_required is True


def test_invalid_policy_weight_sum_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "risk.yaml"
    path.write_text(
        """revision: risk-week2-v1
weights:
  ai: 0.4
  observed_evidence: 0.2
  threat_intelligence: 0.1
  asset: 0.1
  severity: 0.1
automation_state: SHADOW
strong_actions_enabled: false
allowed_playbooks: [create_update_incident_notify]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sum to 1"):
        RiskPolicyRepository(path)
