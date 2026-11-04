"""Synthetic regressions for incomplete account and flow telemetry."""

from __future__ import annotations

import json
import math
from copy import deepcopy

import pytest
from test_context_feature_contract import baseline, windows_event

from api.app.contracts import WazuhAlert
from ml.behavior_features import ACCOUNT_FEATURES
from ml.feature_pipeline import aggregate_wazuh_alerts


def _account(event_id: int, second: int, fields: dict) -> WazuhAlert:
    return windows_event(event_id, {"ipAddress": "10.40.0.10", "logonType": "3", **fields}, second)


def _sensor(identifier: str, payload: dict) -> WazuhAlert:
    return WazuhAlert.model_validate({
        "id": identifier,
        "timestamp": payload["timestamp"],
        "rule": {"id": "synthetic-integrity", "level": 3},
        "agent": {"name": "NET-SENSOR"},
        "full_log": json.dumps(payload),
    })


@pytest.mark.parametrize("event_id", [4624, 4625])
def test_subject_is_not_substituted_for_missing_windows_target(event_id: int) -> None:
    snapshot = baseline(accounts=[{
        "asset_id": "WIN11-TARGET", "account": "system",
        "known_sources": ["10.40.0.10"],
    }])
    result = aggregate_wazuh_alerts(
        [_account(event_id, 5, {"subjectUserName": "SYSTEM"})],
        baseline=snapshot, use_runtime_baseline=False,
    ).incidents[0]

    assert result.quality_status == "PARTIAL"
    assert result.incident.features["unique_target_account_count"] == 0
    assert result.incident.features["failed_login_count"] == 0
    assert result.incident.features["successful_login_count"] == 0
    assert "unique_target_account_count" in result.missing_required_features


def test_missing_target_cannot_be_hidden_by_valid_event_in_same_source_window() -> None:
    valid = _account(4625, 5, {"targetUserName": "labuser"})
    missing = _account(4624, 6, {"subjectUserName": "SYSTEM"})
    result = aggregate_wazuh_alerts(
        [valid, missing], baseline=baseline(), use_runtime_baseline=False,
    )

    account = [item for item in result.incidents if item.incident.family_hint == "account"]
    assert len(account) == 1
    assert account[0].quality_status == "PARTIAL"
    assert set(ACCOUNT_FEATURES) <= set(account[0].missing_required_features)
    assert account[0].incident.features["failed_login_count"] == 1
    assert account[0].incident.features["successful_login_count"] == 0


def test_explicit_dstuser_target_remains_a_valid_legacy_mapping() -> None:
    result = aggregate_wazuh_alerts(
        [_account(4624, 5, {"dstuser": "labuser", "subjectUserName": "SYSTEM"})],
        baseline=baseline(), use_runtime_baseline=False,
    ).incidents[0]
    assert result.quality_status == "COMPLETE"
    assert result.incident.features["successful_login_count"] == 1
    assert result.incident.features["unique_target_account_count"] == 1


@pytest.mark.parametrize("variant", ["mixed_proto_case", "missing_interim_start"])
def test_final_flow_counter_is_byte_oracle_for_complete_online_feature(variant: str) -> None:
    process = windows_event(1, {
        "image": "curl.exe", "processGuid": "{INTEGRITY-FLOW}",
        "commandLine": "curl.exe http://10.40.0.10:8081/beacon",
    }, 0)
    network = windows_event(3, {
        "image": "curl.exe", "processGuid": "{INTEGRITY-FLOW}", "initiated": "true",
        "sourceIp": "10.20.0.10", "sourcePort": "50001", "protocol": "TCP",
        "destinationIp": "10.40.0.10", "destinationPort": "8081",
    }, 1)
    identity = {
        "flow_id": 77, "src_ip": "10.20.0.10", "src_port": 50001,
        "dest_ip": "10.40.0.10", "dest_port": 8081,
    }
    interim = {
        **identity, "timestamp": "2026-10-27T00:00:02Z",
        "event_type": "http", "proto": "TCP", "http": {"url": "/beacon"},
        "flow": {"start": "2026-10-27T00:00:01Z",
                 "bytes_toserver": 40, "bytes_toclient": 20},
    }
    final = {
        **identity, "timestamp": "2026-10-27T00:00:04Z",
        "event_type": "flow", "proto": "TCP",
        "flow": {"start": "2026-10-27T00:00:01Z",
                 "end": "2026-10-27T00:00:03Z",
                 "bytes_toserver": 50, "bytes_toclient": 30},
    }
    if variant == "mixed_proto_case":
        final["proto"] = "tcp"
    else:
        interim = deepcopy(interim)
        del interim["flow"]["start"]
    alert = {
        **identity, "timestamp": "2026-10-27T00:00:02Z",
        "event_type": "alert", "proto": "TCP", "http": {"url": "/beacon"},
        "alert": {"signature_id": 900001, "severity": 2},
    }
    result = aggregate_wazuh_alerts(
        [process, network, _sensor("TX", interim), _sensor("ALERT", alert),
         _sensor("FINAL", final)],
        baseline=baseline(), use_runtime_baseline=False,
    ).incidents[0]

    assert result.quality_status == "COMPLETE"
    assert result.incident.features["suricata_alert_count"] == 1
    assert result.incident.features["suricata_severity_score"] > 0
    assert result.incident.features["flow_total_bytes_log1p"] == round(math.log1p(50 + 30), 6)
