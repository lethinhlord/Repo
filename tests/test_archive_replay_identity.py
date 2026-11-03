"""Synthetic archive identity regressions; no private lab records or training evidence."""

import copy
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import test_collection_acceptance as acceptance
import test_scenario_collection as fixtures
import yaml

from ml import scenario_collection as collector
from ml.context import build_baseline

BASE = datetime(2026, 10, 16, 1, 0, tzinfo=UTC)
RUN_ID = "ARCHIVE-IDENTITY"


def _account(second=5, *, native_id="shared-native-id"):
    row = fixtures.windows_event(
        4624, BASE + timedelta(seconds=second), {"targetUserName": "testuser"}
    )
    if native_id is not None:
        row["id"] = native_id
    return row


def _prepare(root, rows, *, successes=1):
    source_path = fixtures.source_config(root)
    draft = fixtures.write_draft(
        root,
        run_id=RUN_ID,
        family="account",
        label="benign",
        attribution={"account_names": ["testuser"]},
        quality_gates={
            "min_account_successes": successes,
            "max_account_successes": successes,
            "min_account_failures": 0,
            "max_account_failures": 0,
        },
    )
    enrollment = [_account(-10, native_id=None)]
    raw = (json.dumps(enrollment[0]) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    baseline = build_baseline(
        enrollment,
        revision="SYNTHETIC-ARCHIVE-IDENTITY",
        captured_at=BASE - timedelta(seconds=10),
        valid_until=BASE + timedelta(hours=1),
        source_capture_sha256=digest,
    )
    baseline_path = root / "context.json"
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")
    captures = root / "context-captures"
    captures.mkdir()
    (captures / f"{digest}.jsonl").write_bytes(raw)
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    source.update(context_baseline_path=str(baseline_path), require_online_parity=True)
    source_path.write_text(yaml.safe_dump(source), encoding="utf-8")
    fixtures.start_run(draft, source_path, root, now=BASE)
    collector.begin_action(RUN_ID, root, now=BASE + timedelta(seconds=3))
    collector.complete_action(RUN_ID, root, now=BASE + timedelta(seconds=20))
    fixtures.append_jsonl(root / "archives.json", rows)


def _rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _canonical_rows(rows):
    return sorted(json.dumps(row, sort_keys=True) for row in rows)


def _finalize_and_replay(root, rows, *, successes=1):
    """Exercise intake, real aggregation, persisted raw evidence and offline replay."""
    archive = root / "archives.json"
    source_bytes = archive.read_bytes()
    result = collector.finalize_run(RUN_ID, root, now=BASE + timedelta(seconds=360))
    assert result["status"] == "FINALIZED"
    evidence = root / "evidence/scenario-runs" / RUN_ID
    assert archive.read_bytes() == source_bytes
    assert _rows(evidence / "archive_capture.jsonl") == rows
    incident = json.loads((root / "data/raw" / RUN_ID / "incidents.jsonl").read_text())
    assert incident["features"]["successful_login_count"] == float(successes)
    assert incident["context_status"] == "AVAILABLE"
    archive.unlink()
    assert collector.validate_run(RUN_ID, root)["status"] == "VALID"
    assert _rows(evidence / "archive_capture.jsonl") == rows


def test_distinct_raw_records_with_same_agent_and_native_id_replay(tmp_path):
    rows = [_account(5), _account(6)]
    original = copy.deepcopy(rows)
    _prepare(tmp_path, rows, successes=2)
    _finalize_and_replay(tmp_path, rows, successes=2)
    assert rows == original


def test_cross_agent_background_raw_id_collision_replays(tmp_path):
    background = fixtures.suricata_event(
        BASE + timedelta(seconds=7), {"event_type": "stats", "stats": {"uptime": 1}}
    )
    background["id"] = "shared-native-id"
    rows = [_account(), background]
    _prepare(tmp_path, rows)
    _finalize_and_replay(tmp_path, rows)


@pytest.mark.parametrize("native_id", ["shared-native-id", None])
def test_identical_raw_occurrences_keep_multiplicity(tmp_path, native_id):
    row = _account(native_id=native_id)
    rows = [row, copy.deepcopy(row)]
    _prepare(tmp_path, rows, successes=2)
    _finalize_and_replay(tmp_path, rows, successes=2)
    evidence = tmp_path / "evidence/scenario-runs" / RUN_ID
    assert _rows(evidence / "windows_events.jsonl") == rows
    assert _rows(evidence / "wazuh_archives.jsonl") == rows


def test_replay_identity_uses_original_row_and_full_capture_ordinal(tmp_path, monkeypatch):
    foreign = _account()
    foreign["agent"]["name"] = "UNRELATED-AGENT"
    outside_bucket = _account(-1)
    raw = _account(native_id=None)
    raw["unmodeled_archive_metadata"] = {"note": "must participate in identity"}
    same_raw_with_native_id = {**copy.deepcopy(raw), "id": "native-id-is-hashed"}
    genuine = _account(8, native_id="genuine-alert-id")
    genuine["rule"] = {"id": "100001", "level": 3}
    rows = [foreign, outside_bucket, raw, same_raw_with_native_id, genuine]
    _prepare(tmp_path, rows, successes=3)
    observed_ids = []
    aggregate = collector.aggregate_wazuh_alerts

    def observe(alerts, **kwargs):
        observed_ids.append([alert.id for alert in alerts])
        return aggregate(alerts, **kwargs)

    monkeypatch.setattr(collector, "aggregate_wazuh_alerts", observe)
    _finalize_and_replay(tmp_path, rows, successes=3)
    expected = []
    for ordinal in (2, 3):
        canonical = json.dumps(rows[ordinal], sort_keys=True, separators=(",", ":"))
        expected.append(f"archive-raw-v1-{ordinal}-{hashlib.sha256(canonical.encode()).hexdigest()}")
    expected.append("genuine-alert-id")
    assert len(observed_ids) >= 2  # Finalization and source-independent validation.
    assert all(ids == expected for ids in observed_ids)


def test_conflicting_genuine_alert_identity_still_fails_as_collection_error(tmp_path):
    rows = [_account(5), _account(6)]
    for row in rows:
        row["rule"] = {"id": "100001", "level": 3}
    _prepare(tmp_path, rows, successes=2)
    with pytest.raises(collector.CollectionError, match="conflicting payload"):
        collector.finalize_run(RUN_ID, tmp_path, now=BASE + timedelta(seconds=360))
    assert not (tmp_path / "data/raw" / RUN_ID).exists()


@pytest.mark.parametrize("rule", [None, "invalid-rule", {}, {"id": "100001"}])
def test_present_but_malformed_rule_is_not_treated_as_raw(tmp_path, rule):
    row = _account()
    row["rule"] = rule
    _prepare(tmp_path, [row])
    with pytest.raises(collector.CollectionError, match="envelope is invalid"):
        collector.finalize_run(RUN_ID, tmp_path, now=BASE + timedelta(seconds=360))
    assert not (tmp_path / "data/raw" / RUN_ID).exists()


@pytest.mark.parametrize("scenario_id", ["C2-MALICIOUS-HTTP-BEACON", "C2-MALICIOUS-DNS-BEACON"])
def test_c2_raw_id_collision_preserves_correlated_records_offline(tmp_path, scenario_id):
    archive, source, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(row for row in catalog.scenarios if row.scenario_id == scenario_id)
    run_id = f"IDENTITY-{scenario_id}"
    action_start = acceptance.COLLECTION_BASE + timedelta(seconds=5)
    collection_start = acceptance.COLLECTION_BASE - timedelta(seconds=10)
    draft_path = tmp_path / "run-drafts" / f"{run_id}.yaml"
    collector.create_run_draft(
        tmp_path / "config/scenario-catalog.yaml",
        scenario_id,
        run_id,
        "synthetic-archive-identity",
        draft_path,
        collection_seed=20_261_027,
        clock_preflight=acceptance._clock_preflight(collection_start),
    )
    draft = collector.RunDraft.model_validate(yaml.safe_load(draft_path.read_text()))
    collector.start_run(draft_path, source, tmp_path, now=collection_start)
    collector.begin_action(run_id, tmp_path, now=action_start)
    first_event = action_start + timedelta(
        seconds=float(draft.scenario_parameters["pre_action_delay_seconds"])
    )
    events, last_event = acceptance._c2_events(run_id, scenario, draft, first_event)
    for row in events:
        row["id"] = "same-native-id-for-every-c2-record"
    fixtures.append_jsonl(archive, events)
    source_bytes = archive.read_bytes()
    collector.complete_action(run_id, tmp_path, now=last_event + timedelta(seconds=2))
    result = collector.finalize_run(
        run_id, tmp_path, now=acceptance.COLLECTION_BASE + timedelta(seconds=355)
    )
    assert result["status"] == "FINALIZED"
    evidence = tmp_path / "evidence/scenario-runs" / run_id
    assert archive.read_bytes() == source_bytes
    assert _rows(evidence / "archive_capture.jsonl") == events
    windows = _rows(evidence / "windows_events.jsonl")
    expected_windows = [row for row in events if row["agent"]["name"] == "WIN11-TARGET"]
    assert _canonical_rows(windows) == _canonical_rows(expected_windows)
    suricata = _rows(evidence / "suricata_eve.jsonl")
    expected_suricata = [json.loads(row["full_log"]) for row in events if "full_log" in row]
    assert _canonical_rows(suricata) == _canonical_rows(expected_suricata)
    assert {"flow", "alert", "dns" if scenario.quality_gates.min_dns_events else "http"} <= {
        row["event_type"] for row in suricata
    }
    incident = json.loads((tmp_path / "data/raw" / run_id / "incidents.jsonl").read_text())
    count_feature = "dns_query_count" if scenario.quality_gates.min_dns_events else (
        "outbound_connection_count"
    )
    assert incident["features"][count_feature] == 8.0
    assert incident["features"]["suricata_alert_count"] == 8.0
    archive.unlink()
    assert collector.validate_run(run_id, tmp_path)["status"] == "VALID"
    assert _rows(evidence / "archive_capture.jsonl") == events


def test_cli_genuine_conflicting_alert_returns_structured_error(tmp_path):
    rows = [_account(5), _account(6)]
    for row in rows:
        row["rule"] = {"id": "100001", "level": 3}
    _prepare(tmp_path, rows, successes=2)
    # Seal the synthetic historical intake before retrying with the CLI's live clock.
    with pytest.raises(collector.CollectionError, match="conflicting payload"):
        collector.finalize_run(RUN_ID, tmp_path, now=BASE + timedelta(seconds=360))
    result = subprocess.run(
        [sys.executable, "-m", "scripts.scenario_session", "--project-root", str(tmp_path),
         "finalize", "--run-id", RUN_ID],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 1
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["status"] == "ERROR"
    assert "conflicting payload" in payload["detail"]
    assert not (tmp_path / "data/raw" / RUN_ID).exists()
