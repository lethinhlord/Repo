import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from api.app.contracts import WazuhAlert
from ml.feature_pipeline import (
    FEATURE_ORDER,
    aggregate_wazuh_alerts,
    extract_wazuh_features,
)

ROOT = Path(__file__).resolve().parents[1]


def load_fixture(name: str) -> dict:
    return json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))


def test_account_fixture_produces_versioned_deterministic_features() -> None:
    alert = WazuhAlert.model_validate(load_fixture("wazuh-alert-account.json"))

    first = extract_wazuh_features(alert)
    second = extract_wazuh_features(alert)

    assert first == second
    assert first.feature_schema_version == "features-v1"
    assert first.feature_order == list(FEATURE_ORDER)
    assert first.incident.incident_id == "WAZUH-W1-0001"
    assert first.incident.family_hint == "account"
    assert first.incident.asset_id == "linux-endpoint-01"
    assert first.incident.features["failed_login_count"] == 12.0
    assert first.incident.features["success_after_fail"] == 1.0
    assert first.incident.indicator == "203.0.113.66"
    assert first.incident.evidence_sources == ["wazuh"]
    assert "source-log:auth.log" in first.incident.raw_refs
    assert (first.incident.end_time - first.incident.start_time).total_seconds() == 0


def test_c2_fixture_produces_only_observed_behavioral_features() -> None:
    alert = WazuhAlert.model_validate(load_fixture("wazuh-alert-c2.json"))

    result = extract_wazuh_features(alert)

    assert result.incident.family_hint == "c2"
    assert result.incident.features == {
        "failed_login_count": 0.0,
        "success_after_fail": 0.0,
        "suspicious_process": 1.0,
        "periodicity_score": 0.87,
        "suricata_alert_count": 2.0,
        "outbound_connection_count": 15.0,
        "destination_port_count": 1.0,
    }
    forbidden = {"label", "ground_truth", "asset_criticality", "ti_score"}
    assert forbidden.isdisjoint(result.incident.features)


def test_missing_optional_measurements_default_safely_without_failure() -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["data"] = {"srcip": "unknown.example"}
    alert = WazuhAlert.model_validate(payload)

    result = extract_wazuh_features(alert)

    assert all(value == 0.0 for value in result.incident.features.values())
    assert set(result.missing_required_features) == {
        "failed_login_count",
        "success_after_fail",
    }
    assert set(result.structural_zero_features) == set(FEATURE_ORDER[2:])
    assert result.quality_status == "PARTIAL"


def test_feature_pipeline_does_not_copy_fixture_normalized_incident() -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["normalized_incident"]["features"]["failed_login_count"] = 9999

    result = extract_wazuh_features(WazuhAlert.model_validate(payload))

    assert result.incident.features["failed_login_count"] == 12.0


def test_feature_schema_and_implementation_have_identical_order() -> None:
    schema = json.loads((ROOT / "ml/feature_schema.json").read_text(encoding="utf-8"))

    assert schema["version"] == "features-v1"
    assert schema["x-feature-order"] == list(FEATURE_ORDER)
    assert list(schema["properties"]) == list(FEATURE_ORDER)


def test_batch_pipeline_deduplicates_and_aggregates_within_window() -> None:
    first = load_fixture("wazuh-alert-account.json")
    second = load_fixture("wazuh-alert-account.json")
    second["id"] = "WAZUH-W2-ACCOUNT-0002"
    second["timestamp"] = "2026-10-05T12:03:00Z"
    second["data"]["failed_login_count"] = 3
    alerts = [
        WazuhAlert.model_validate(first),
        WazuhAlert.model_validate(first),
        WazuhAlert.model_validate(second),
    ]

    batch = aggregate_wazuh_alerts(alerts, window_minutes=5)

    assert batch.input_alert_count == 3
    assert batch.unique_alert_count == 2
    assert batch.duplicate_alert_count == 1
    assert len(batch.incidents) == 1
    incident = batch.incidents[0].incident
    assert incident.features["failed_login_count"] == 15.0
    assert (incident.end_time - incident.start_time).total_seconds() == 180
    assert incident.evidence_sources == ["wazuh"]


def test_batch_pipeline_uses_half_open_five_minute_window() -> None:
    first = load_fixture("wazuh-alert-account.json")
    second = load_fixture("wazuh-alert-account.json")
    second["id"] = "WAZUH-W2-ACCOUNT-0003"
    second["timestamp"] = "2026-10-05T12:05:00Z"

    batch = aggregate_wazuh_alerts(
        [WazuhAlert.model_validate(first), WazuhAlert.model_validate(second)],
        window_minutes=5,
    )

    assert len(batch.incidents) == 2


def test_batch_pipeline_rejects_conflicting_duplicate_id() -> None:
    first = load_fixture("wazuh-alert-account.json")
    conflicting = load_fixture("wazuh-alert-account.json")
    conflicting["data"]["failed_login_count"] = 99

    try:
        aggregate_wazuh_alerts(
            [WazuhAlert.model_validate(first), WazuhAlert.model_validate(conflicting)]
        )
    except ValueError as error:
        assert "conflicting payload" in str(error)
    else:
        raise AssertionError("conflicting duplicate must be rejected")


def test_naive_timestamp_is_rejected_at_boundary() -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["timestamp"] = "2026-10-05T12:00:00"

    with pytest.raises(ValidationError, match="timezone"):
        WazuhAlert.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("failed_login_count", -1),
        ("failed_login_count", 1_000_001),
        ("success_after_fail", 2),
        ("periodicity_score", 1.1),
        ("destination_port_count", 65_536),
    ],
)
def test_feature_bounds_are_enforced(field: str, value: float) -> None:
    payload = load_fixture("wazuh-alert-account.json")
    payload["data"][field] = value

    with pytest.raises(ValidationError):
        WazuhAlert.model_validate(payload)
