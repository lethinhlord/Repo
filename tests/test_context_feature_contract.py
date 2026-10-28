"""Feature/context contract: unknown history is not a known-normal observation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from api.app.contracts import WazuhAlert
from ml.context import BaselineSnapshot
from ml.feature_pipeline import aggregate_wazuh_alerts

ASSET = "WIN11-TARGET"
REVISION = "context-test-enrollment-20261026"


def baseline(**overrides: Any) -> BaselineSnapshot:
    document = {
        "version": "context-baseline-v1",
        "revision": REVISION,
        "captured_at": "2026-10-26T18:00:00Z",
        "observed_through": "2026-10-26T17:59:00Z",
        "valid_until": "2026-10-28T00:00:00Z",
        "source_capture_sha256": "a" * 64,
        "accounts": [
            {"asset_id": ASSET, "account": "labuser", "known_sources": ["10.40.0.10"]},
        ],
        "destinations": [
            {
                "asset_id": ASSET,
                "destination": "10.40.0.10",
                "port": 8081,
                "process_images": ["curl.exe"],
            },
        ],
    }
    return BaselineSnapshot.model_validate({**document, **overrides})


def windows_event(event_id: int, data: dict[str, Any], seconds: int) -> WazuhAlert:
    timestamp = datetime(2026, 10, 27, 0, 0, seconds, tzinfo=UTC).isoformat()
    return WazuhAlert.model_validate(
        {
            "id": f"CONTEXT-{event_id}-{seconds}",
            # Envelope arrival is later than the original Windows event time.
            "timestamp": "2026-10-27T00:02:00Z",
            "rule": {"id": "context-test", "level": 3},
            "agent": {"id": "001", "name": ASSET},
            "data": {
                "win": {
                    "system": {"eventID": str(event_id), "systemTime": timestamp},
                    "eventdata": data,
                },
            },
        }
    )


def account_alerts(
    *, account: str = "labuser", source: str = "::ffff:10.40.0.10",
) -> list[WazuhAlert]:
    data = {"targetUserName": account, "ipAddress": source, "logonType": "3"}
    return [windows_event(4625, data, 0), windows_event(4624, data, 10)]


def account_feature(snapshot: BaselineSnapshot | None, **kwargs: str):
    batch = aggregate_wazuh_alerts(account_alerts(**kwargs), baseline=snapshot)
    assert len(batch.incidents) == 1
    return batch.incidents[0]


def test_known_mapped_source_has_v3_history_mask_without_new_source() -> None:
    result = account_feature(baseline())

    assert result.feature_schema_version == result.incident.feature_schema_version == "features-v3"
    assert result.incident.context_status == "AVAILABLE"
    assert result.incident.context_revision == REVISION
    assert result.quality_status == "COMPLETE"
    assert result.incident.features["source_history_known"] == 1.0
    assert result.incident.features["new_source_for_user"] == 0.0
    assert result.incident.features["destination_history_known"] == 0.0
    assert result.incident.features["new_destination"] == 0.0
    assert result.incident.features["success_after_fail"] == 1.0
    assert "source_history_known" in result.feature_order
    assert result.ordered_vector == [
        result.incident.features[name] for name in result.feature_order
    ]


def test_known_user_from_a_new_source_is_observed_novelty_not_missing_history() -> None:
    result = account_feature(baseline(), source="10.40.0.99")

    assert result.incident.context_status == "AVAILABLE"
    assert result.incident.features["source_history_known"] == 1.0
    assert result.incident.features["new_source_for_user"] == 1.0


def test_unknown_user_has_zero_mask_and_requires_review() -> None:
    result = account_feature(baseline(), account="not-enrolled-user")

    assert result.incident.context_status == "UNKNOWN"
    assert result.incident.features["source_history_known"] == 0.0
    assert result.incident.features["new_source_for_user"] == 0.0
    assert result.quality_status == "PARTIAL"
    assert any(reason.startswith("context:") for reason in result.incident.review_reasons)


@pytest.mark.parametrize("unavailable", ["MISSING", "STALE", "FUTURE"])
def test_unavailable_context_never_makes_account_complete(unavailable: str) -> None:
    if unavailable == "MISSING":
        snapshot = None
    elif unavailable == "STALE":
        snapshot = baseline(valid_until="2026-10-27T00:00:05Z")
    else:
        # Baseline is captured after the first event but before the last event.
        # It must not become eligible because the envelope arrived two minutes later.
        snapshot = baseline(
            observed_through="2026-10-27T00:00:04Z",
            captured_at="2026-10-27T00:00:05Z",
        )
    result = account_feature(snapshot)

    assert result.incident.context_status == unavailable
    assert result.quality_status == "PARTIAL"
    assert result.incident.features["source_history_known"] == 0.0
    assert result.incident.features["new_source_for_user"] == 0.0
    assert any(reason.startswith("context:") for reason in result.incident.review_reasons)
    if snapshot is None:
        assert result.incident.context_revision is None


def test_omitting_baseline_defaults_to_missing_context() -> None:
    result = aggregate_wazuh_alerts(account_alerts()).incidents[0]

    assert result.incident.context_status == "MISSING"
    assert result.quality_status == "PARTIAL"
    assert result.incident.features["source_history_known"] == 0.0
    assert any(reason.startswith("context:") for reason in result.incident.review_reasons)


@pytest.mark.parametrize(
    ("destination", "novelty"), [("::ffff:10.40.0.10", 0.0), ("10.40.0.99", 1.0)],
)
def test_c2_context_is_destination_specific_and_other_family_masks_are_zero(
    destination: str, novelty: float,
) -> None:
    process = windows_event(
        1, {"image": "curl.exe", "processGuid": "context-process", "commandLine": "curl.exe"}, 0,
    )
    network = windows_event(
        3,
        {
            "image": "curl.exe",
            "processGuid": "context-process",
            "initiated": "true",
            "sourceIp": "10.20.0.10",
            "destinationIp": destination,
            "destinationPort": "8081",
        },
        1,
    )
    result = aggregate_wazuh_alerts([process, network], baseline=baseline()).incidents[0]

    assert result.incident.context_status == "AVAILABLE"
    assert result.incident.features["destination_history_known"] == 1.0
    assert result.incident.features["new_destination"] == novelty
    assert result.incident.features["source_history_known"] == 0.0
    assert result.incident.features["new_source_for_user"] == 0.0
    # Context is known, but no Suricata evidence was supplied by this unit test.
    assert result.quality_status == "PARTIAL"
