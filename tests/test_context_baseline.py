"""Context history is independent, as-of, and explicit about unavailable history."""

from __future__ import annotations

import importlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from ml.behavior_features import AccountObservation, NetworkObservation

CAPTURED = datetime(2026, 10, 28, 0, 0, tzinfo=UTC)
AT = CAPTURED + timedelta(hours=1)
FEATURE_NAMES = {
    "source_history_known",
    "new_source_for_user",
    "destination_history_known",
    "new_destination",
}


def _module():
    return importlib.import_module("ml.context")


def _payload() -> dict:
    return {
        "version": "context-baseline-v1",
        "revision": "enrollment-20261028-v1",
        "captured_at": CAPTURED.isoformat(),
        "observed_through": (CAPTURED - timedelta(seconds=1)).isoformat(),
        "valid_until": (CAPTURED + timedelta(days=1)).isoformat(),
        "source_capture_sha256": "a" * 64,
        "accounts": [{
            "asset_id": "WIN11-TARGET",
            "account": "labuser",
            "known_sources": ["10.40.0.10"],
        }],
        "destinations": [{
            "asset_id": "WIN11-TARGET",
            "destination": "10.40.0.10",
            "port": 8081,
            "process_images": ["curl.exe"],
        }],
    }


def _snapshot(payload: dict | None = None):
    return _module().BaselineSnapshot.model_validate(payload or _payload())


def _account(source: str = "10.40.0.10", user: str = "labuser") -> AccountObservation:
    return AccountObservation(AT, user, source, "3", True)


def _network(destination: str = "10.40.0.10", port: int = 8081) -> NetworkObservation:
    return NetworkObservation(AT, destination, port)


def _assess(snapshot, **kwargs):
    return _module().assess_context(
        snapshot, at=kwargs.pop("at", AT), asset_id=kwargs.pop("asset_id", "WIN11-TARGET"),
        **kwargs,
    )


def test_known_history_is_available_without_leaking_identity_into_features() -> None:
    assessment = _assess(_snapshot(), accounts=[_account()], network=[_network()])

    assert assessment.status == "AVAILABLE"
    assert assessment.revision == "enrollment-20261028-v1"
    assert set(assessment.features) == FEATURE_NAMES
    assert assessment.features == {
        "source_history_known": 1.0,
        "new_source_for_user": 0.0,
        "destination_history_known": 1.0,
        "new_destination": 0.0,
    }
    assert assessment.review_reasons == []


def test_known_user_with_new_source_has_valid_history_and_new_source_flag() -> None:
    assessment = _assess(_snapshot(), accounts=[_account(source="10.40.0.99")])

    assert assessment.features["source_history_known"] == 1.0
    assert assessment.features["new_source_for_user"] == 1.0
    assert assessment.features["destination_history_known"] == 0.0
    assert assessment.features["new_destination"] == 0.0


def test_known_destination_history_marks_a_new_destination() -> None:
    assessment = _assess(_snapshot(), network=[_network(destination="10.40.0.99")])

    assert assessment.features["destination_history_known"] == 1.0
    assert assessment.features["new_destination"] == 1.0


def test_destination_port_is_part_of_the_history_identity() -> None:
    assessment = _assess(_snapshot(), network=[_network(port=443)])

    assert assessment.features["destination_history_known"] == 1.0
    assert assessment.features["new_destination"] == 1.0


def test_mapped_ipv6_sources_and_destinations_match_ipv4_history() -> None:
    regular = _assess(_snapshot(), accounts=[_account()], network=[_network()])
    mapped = _assess(
        _snapshot(), accounts=[_account(source="::ffff:10.40.0.10")],
        network=[_network(destination="::ffff:10.40.0.10")],
    )

    assert mapped.status == regular.status == "AVAILABLE"
    assert mapped.features == regular.features
    assert mapped.review_reasons == regular.review_reasons == []


def test_missing_snapshot_does_not_mean_sources_and_destinations_are_new() -> None:
    assessment = _assess(None, accounts=[_account()], network=[_network()])

    assert assessment.status == "MISSING"
    assert assessment.revision is None
    assert assessment.features == dict.fromkeys(FEATURE_NAMES, 0.0)
    assert assessment.review_reasons


def test_unknown_account_keeps_history_mask_false_and_does_not_invent_novelty() -> None:
    assessment = _assess(_snapshot(), accounts=[_account(user="not-enrolled")])

    assert assessment.status == "UNKNOWN"
    assert assessment.features["source_history_known"] == 0.0
    assert assessment.features["new_source_for_user"] == 0.0
    assert assessment.review_reasons


def test_unknown_asset_does_not_borrow_another_assets_history() -> None:
    assessment = _assess(
        _snapshot(), asset_id="UNENROLLED-TARGET", accounts=[_account()], network=[_network()]
    )

    assert assessment.status == "UNKNOWN"
    assert assessment.features == dict.fromkeys(FEATURE_NAMES, 0.0)
    assert assessment.review_reasons


def test_account_observations_do_not_require_unrelated_network_history() -> None:
    payload = _payload()
    payload["destinations"] = []

    assessment = _assess(_snapshot(payload), accounts=[_account()])

    assert assessment.status == "AVAILABLE"
    assert assessment.features["destination_history_known"] == 0.0
    assert assessment.features["new_destination"] == 0.0
    assert assessment.review_reasons == []


def test_network_observations_do_not_require_unrelated_account_history() -> None:
    payload = _payload()
    payload["accounts"] = []

    assessment = _assess(_snapshot(payload), network=[_network()])

    assert assessment.status == "AVAILABLE"
    assert assessment.features["source_history_known"] == 0.0
    assert assessment.features["new_source_for_user"] == 0.0
    assert assessment.review_reasons == []


def test_snapshot_not_yet_captured_cannot_supply_future_context() -> None:
    before_capture = CAPTURED - timedelta(microseconds=1)
    observation = AccountObservation(before_capture, "labuser", "10.40.0.10", "3", True)
    assessment = _assess(
        _snapshot(), at=before_capture, accounts=[observation]
    )

    assert assessment.status == "FUTURE"
    assert assessment.features == dict.fromkeys(FEATURE_NAMES, 0.0)
    assert assessment.review_reasons


def test_snapshot_captured_during_the_window_cannot_describe_its_earlier_events() -> None:
    observations = [
        AccountObservation(CAPTURED - timedelta(minutes=1), "labuser", "10.40.0.10", "3", False),
        _account(),
    ]

    assessment = _assess(_snapshot(), at=AT, accounts=observations)

    assert assessment.status == "FUTURE"
    assert assessment.features == dict.fromkeys(FEATURE_NAMES, 0.0)
    assert assessment.review_reasons


@pytest.mark.parametrize("family", ["account", "network"])
def test_assessment_rejects_observations_after_the_decision_time(family: str) -> None:
    later = AT + timedelta(microseconds=1)
    observations = (
        {"accounts": [AccountObservation(later, "labuser", "10.40.0.10", "3", True)]}
        if family == "account" else
        {"network": [NetworkObservation(later, "10.40.0.10", 8081)]}
    )

    with pytest.raises(ValueError):
        _assess(_snapshot(), at=AT, **observations)


def test_snapshot_is_stale_at_the_expiration_boundary() -> None:
    assessment = _assess(
        _snapshot(), at=CAPTURED + timedelta(days=1), accounts=[_account()], network=[_network()]
    )

    assert assessment.status == "STALE"
    assert assessment.features == dict.fromkeys(FEATURE_NAMES, 0.0)
    assert assessment.review_reasons


@pytest.mark.parametrize("field", ["captured_at", "observed_through", "valid_until"])
def test_snapshot_rejects_timezone_ambiguous_timestamps(field: str) -> None:
    payload = _payload()
    payload[field] = "2026-10-28T00:00:00"

    with pytest.raises(ValueError):
        _snapshot(payload)


@pytest.mark.parametrize("field,value", [
    ("observed_through", CAPTURED + timedelta(seconds=1)),
    ("valid_until", CAPTURED),
    ("valid_until", CAPTURED - timedelta(seconds=1)),
])
def test_snapshot_rejects_invalid_observation_or_validity_order(field: str, value) -> None:
    payload = _payload()
    payload[field] = value.isoformat()

    with pytest.raises(ValueError):
        _snapshot(payload)


@pytest.mark.parametrize("scope", ["snapshot", "account", "destination"])
@pytest.mark.parametrize("field", ["label", "ground_truth"])
def test_snapshot_rejects_target_information_at_every_schema_boundary(
    scope: str, field: str
) -> None:
    payload = deepcopy(_payload())
    target = (
        payload if scope == "snapshot" else
        payload["accounts"][0] if scope == "account" else payload["destinations"][0]
    )
    target[field] = "malicious"

    with pytest.raises(ValueError):
        _snapshot(payload)


@pytest.mark.parametrize("digest", ["a" * 63, "g" * 64, ""])
def test_snapshot_requires_a_real_capture_digest(digest: str) -> None:
    payload = _payload()
    payload["source_capture_sha256"] = digest

    with pytest.raises(ValueError):
        _snapshot(payload)


def test_assessment_rejects_an_ambiguous_as_of_timestamp() -> None:
    with pytest.raises(ValueError):
        _assess(_snapshot(), at=datetime(2026, 10, 28, 1), accounts=[_account()])
