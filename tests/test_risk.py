from api.app.risk import calculate_risk


def test_risk_formula_matches_frozen_week1_policy() -> None:
    result = calculate_risk(
        ai_probability=0.95,
        observed_evidence=1.0,
        ti_score=0.9,
        asset_score=0.6,
        severity_score=0.8,
    )

    assert result.internal == 0.885
    assert result.display == 8.9


def test_risk_inputs_are_clamped_to_unit_interval() -> None:
    result = calculate_risk(
        ai_probability=2.0,
        observed_evidence=-1.0,
        ti_score=0.0,
        asset_score=0.0,
        severity_score=0.0,
    )

    assert result.internal == 0.4
    assert result.display == 4.0
