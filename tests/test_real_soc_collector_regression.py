"""Synthetic collector regressions; private lab evidence is never a test fixture."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
import test_scenario_collection as fixtures
import yaml

from api.app.contracts import IncidentRequest, WazuhAlert
from ml import feature_pipeline as fp
from ml import scenario_collection as sc
from ml.context import build_baseline

SESSION_START = datetime(2026, 11, 14, 6, 47, 35, tzinfo=UTC)
ACTION_START = datetime(2026, 11, 14, 6, 50, 5, tzinfo=UTC)
RUN_ID = "SYNTHETIC-SENSOR-ASSET"


def make_alert(agent, timestamp, data, decoder=None):
    payload = {
        "id": f"test-{agent}-{timestamp}",
        "timestamp": timestamp,
        "agent": {"name": agent},
        "rule": {"id": "100", "level": 0},
        "data": data,
    }
    if decoder:
        payload["decoder"] = {"name": decoder}
    return WazuhAlert.model_validate(payload)


def test_sensor_os_log_remains_sensor_asset():
    config = {
        "windows_agent_name": "WIN11-TARGET",
        "suricata_agent_name": "NET-SENSOR",
    }
    ssh = make_alert(
        "NET-SENSOR", "2026-11-14T06:51:32Z", {}, decoder="sshd",
    )
    assert fp._aggregation_key(ssh, config) == (
        "net-sensor", "account", "unknown-source"
    )
    eve = make_alert(
        "NET-SENSOR",
        "2026-11-14T06:51:33Z",
        {
            "event_type": "http",
            "src_ip": "10.20.0.10",
            "dest_ip": "10.40.0.10",
            "dest_port": 8081,
            "http": {"url": "/beacon"},
        },
    )
    assert fp._asset_id(eve, config) == "WIN11-TARGET"


@pytest.fixture
def account_run(tmp_path):
    source_path = fixtures.source_config(tmp_path)
    accounts = ["synthetic01", "synthetic02", "synthetic03"]

    def account_event(kind, when, account):
        return fixtures.windows_event(kind, when, {
            "targetUserName": account, "ipAddress": "10.40.0.10", "logonType": "3",
        })

    draft = fixtures.write_draft(
        tmp_path, run_id=RUN_ID, family="account", label="malicious",
        attribution={
            "account_names": accounts, "source_ips": ["10.40.0.10"], "logon_types": [3],
        },
        quality_gates={
            "min_account_failures": 9, "max_account_failures": 9,
            "min_account_successes": 3, "max_account_successes": 3,
            "require_all_accounts_observed": True, "require_success_after_failure": True,
        },
    )
    enrolled_at = SESSION_START - timedelta(minutes=1)
    enrollment = [account_event(4624, enrolled_at, account) for account in accounts]
    enrollment_bytes = "".join(json.dumps(row) + "\n" for row in enrollment).encode()
    digest = hashlib.sha256(enrollment_bytes).hexdigest()
    baseline = build_baseline(
        enrollment, revision="SYNTHETIC-SENSOR-REGRESSION", captured_at=enrolled_at,
        valid_until=ACTION_START + timedelta(hours=1), source_capture_sha256=digest,
    )
    baseline_path = tmp_path / "context.json"
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")
    captures = tmp_path / "context-captures"
    captures.mkdir()
    (captures / f"{digest}.jsonl").write_bytes(enrollment_bytes)
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    source.update(
        context_baseline_path=str(baseline_path), require_online_parity=True,
        require_clean_bucket=True, feature_scope="full-window",
    )
    source_path.write_text(yaml.safe_dump(source), encoding="utf-8")
    fixtures.start_run(draft, source_path, tmp_path, now=SESSION_START)
    sc.begin_action(RUN_ID, tmp_path, now=ACTION_START)
    sc.complete_action(RUN_ID, tmp_path, now=ACTION_START + timedelta(seconds=80))

    previous_bucket = account_event(4625, SESSION_START + timedelta(seconds=10), accounts[0])
    authentication = [
        account_event(
            4625 if index < 9 else 4624,
            ACTION_START + timedelta(seconds=7 + index * 4), accounts[index % 3],
        )
        for index in range(12)
    ]
    sensor_os = make_alert(
        "NET-SENSOR", "2026-11-14T06:51:32Z", {}, decoder="sshd",
    ).model_dump(mode="json", exclude_none=True)
    sensor_os.update(
        location="journald", full_log="sshd[123]: Received signal 15; terminating.",
    )
    rows = [previous_bucket, *authentication, sensor_os]
    fixtures.append_jsonl(tmp_path / "archives.json", rows)
    return rows, sc.SourceConfig.model_validate(source)


@pytest.mark.parametrize("incident_start", [SESSION_START, ACTION_START])
def test_receipt_replay_selects_action_bucket_with_real_aggregation(
    tmp_path, account_run, incident_start,
):
    rows, source = account_run
    # The helper can receive a historical/session-anchored incident. The normal
    # finalizer already supplies action time; the lifecycle test covers that path.
    incident = IncidentRequest(
        incident_id="SYNTHETIC-PARITY", asset_id="WIN11-TARGET", family_hint="account",
        start_time=incident_start, end_time=ACTION_START + timedelta(seconds=80),
        evidence_sources=["wazuh-archives"], base_severity=0,
    )
    evidence = tmp_path / "evidence/scenario-runs" / RUN_ID
    result = sc._verify_full_capture_parity(rows, incident, source, evidence, compare=False)
    assert result.asset_id == "WIN11-TARGET"
    assert result.observation_quality == "COMPLETE"
    assert result.review_reasons == []
    assert result.features["failed_login_count"] == 9.0
    assert result.features["successful_login_count"] == 3.0
    assert result.features["unique_target_account_count"] == 3.0
    assert result.start_time == ACTION_START + timedelta(seconds=7)
    assert result.end_time == ACTION_START + timedelta(seconds=51)
    assert len([ref for ref in result.raw_refs if ref.startswith("wazuh-alert:")]) == 12
    assert "source-log:journald" not in result.raw_refs


def test_cross_bucket_collection_finalizes_and_validates_with_sensor_os_noise(
    tmp_path, account_run,
):
    rows, _ = account_run
    archive = tmp_path / "archives.json"
    original_archive = archive.read_bytes()
    evidence = tmp_path / "evidence/scenario-runs" / RUN_ID
    original_receipt = (evidence / "execution_receipt.json").read_bytes()
    result = sc.finalize_run(
        RUN_ID, tmp_path, now=datetime(2026, 11, 14, 6, 56, tzinfo=UTC),
    )
    assert result["status"] == "FINALIZED"
    incident = IncidentRequest.model_validate_json(
        (tmp_path / "data/raw" / RUN_ID / "incidents.jsonl").read_text(encoding="utf-8")
    )
    assert incident.start_time == ACTION_START
    assert incident.observation_quality == "COMPLETE"
    assert incident.context_status == "AVAILABLE"
    assert incident.review_reasons == []
    assert incident.features["failed_login_count"] == 9.0
    assert incident.features["successful_login_count"] == 3.0
    assert incident.features["source_history_known"] == 1.0
    assert archive.read_bytes() == original_archive
    assert (evidence / "execution_receipt.json").read_bytes() == original_receipt
    assert [json.loads(line) for line in (evidence / "archive_capture.jsonl").read_text(
        encoding="utf-8",
    ).splitlines()] == rows
    # Validation must depend on sealed evidence, including the unfiltered noise,
    # without needing the live archive or rewriting the action/session times.
    archive.unlink()
    assert sc.validate_run(RUN_ID, tmp_path)["status"] == "VALID"
