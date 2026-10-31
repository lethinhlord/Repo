"""Synthetic clock/context integration; never training or lab evidence."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
import test_scenario_collection as fixtures
import yaml

from ml import scenario_collection as collector
from ml.context import build_baseline

BASE = datetime(2026, 10, 16, 1, 0, tzinfo=UTC)


def prepare(
    root,
    *,
    event_second=11,
    expiry=1000,
    capture=-10,
    parity=False,
    collection_second=0,
    action_delay=3,
):
    source = fixtures.source_config(root)
    draft = fixtures.write_draft(
        root,
        run_id="CLOCK",
        family="account",
        label="benign",
        attribution={"account_names": ["testuser"]},
    )
    enrollment = [
        fixtures.windows_event(
            4624, BASE + timedelta(seconds=capture), {"targetUserName": "testuser"}
        )
    ]
    raw = (json.dumps(enrollment[0]) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    baseline = build_baseline(
        enrollment,
        revision="SYNTHETIC-CLOCK",
        captured_at=BASE + timedelta(seconds=capture),
        valid_until=BASE + timedelta(seconds=expiry),
        source_capture_sha256=digest,
    )
    baseline_path = root / "context.json"
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")
    (root / "context-captures").mkdir()
    (root / "context-captures" / f"{digest}.jsonl").write_bytes(raw)
    config = yaml.safe_load(source.read_text())
    config.update(context_baseline_path=str(baseline_path), require_online_parity=parity)
    source.write_text(yaml.safe_dump(config), encoding="utf-8")
    fixtures.start_run(draft, source, root, now=BASE + timedelta(seconds=collection_second))
    collector.begin_action(
        "CLOCK", root, now=BASE + timedelta(seconds=collection_second + action_delay)
    )
    collector.complete_action("CLOCK", root, now=BASE + timedelta(seconds=10))
    event = fixtures.windows_event(
        4624, BASE + timedelta(seconds=event_second), {"targetUserName": "testuser"}
    )
    fixtures.append_jsonl(root / "archives.json", [event])
    return event


@pytest.mark.parametrize("parity", [False, True])
@pytest.mark.parametrize("second", [8, 10, 11, 12])
def test_allowed_skew_replays_with_active_context(tmp_path, second, parity):
    event = prepare(tmp_path, event_second=second, parity=parity)
    collector.finalize_run("CLOCK", tmp_path, now=BASE + timedelta(seconds=360 if parity else 20))
    incident = json.loads((tmp_path / "data/raw/CLOCK/incidents.jsonl").read_text())
    assert incident["context_status"] == "AVAILABLE"
    evidence = tmp_path / "evidence/scenario-runs/CLOCK"
    assert json.loads((evidence / "windows_events.jsonl").read_text()) == event
    (tmp_path / "archives.json").unlink()
    assert collector.validate_run("CLOCK", tmp_path)["status"] == "VALID"


@pytest.mark.parametrize("parity", [False, True])
@pytest.mark.parametrize("expiry,status", [(10, "STALE"), (11, "STALE"), (12, "AVAILABLE")])
def test_context_ttl_uses_observation_time(tmp_path, expiry, status, parity):
    prepare(tmp_path, expiry=expiry, parity=parity)
    collector.finalize_run("CLOCK", tmp_path, now=BASE + timedelta(seconds=360 if parity else 20))
    incident = json.loads((tmp_path / "data/raw/CLOCK/incidents.jsonl").read_text())
    assert incident["context_status"] == status
    assert collector.validate_run("CLOCK", tmp_path)["status"] == "VALID"


def test_source_after_controller_decision_fails_closed(tmp_path):
    prepare(tmp_path, event_second=12)
    with pytest.raises(collector.CollectionError, match="controller"):
        collector.finalize_run("CLOCK", tmp_path, now=BASE + timedelta(seconds=11))


def test_beyond_allowed_skew_fails_closed(tmp_path):
    prepare(tmp_path, event_second=13)
    with pytest.raises(collector.CollectionError, match="run window"):
        collector.finalize_run("CLOCK", tmp_path, now=BASE + timedelta(seconds=20))


def test_replay_rejects_changed_context_policy_and_time(tmp_path):
    prepare(tmp_path)
    collector.finalize_run("CLOCK", tmp_path, now=BASE + timedelta(seconds=20))
    evidence = tmp_path / "evidence/scenario-runs/CLOCK"
    path = evidence / "collection_metadata.json"
    original = json.loads(path.read_text())
    for change in (
        {"context_time_policy": "legacy"},
        {"context_observation_as_of": BASE.isoformat()},
        {"finalized_at": (BASE + timedelta(seconds=10)).isoformat()},
    ):
        path.write_text(json.dumps({**original, **change}))
        collector._write_checksums(evidence)
        with pytest.raises(collector.CollectionError, match="context"):
            collector.validate_run("CLOCK", tmp_path)


def test_unrelated_online_row_does_not_change_context_ttl(tmp_path):
    from api.app.contracts import WazuhAlert
    from ml.context import load_baseline
    from ml.feature_pipeline import aggregate_wazuh_alerts

    event = prepare(tmp_path, expiry=12)
    noise = fixtures.windows_event(
        4624, BASE + timedelta(seconds=15), {"targetUserName": "noise", "logonType": "5"}
    )
    alerts = [
        WazuhAlert.model_validate({**row, "id": str(index), "rule": {"id": "test", "level": 0}})
        for index, row in enumerate([event, noise])
    ]
    batch = aggregate_wazuh_alerts(
        alerts,
        baseline=load_baseline(tmp_path / "context.json"),
        source_config=yaml.safe_load((tmp_path / "sources.yaml").read_text()),
        use_runtime_baseline=False,
    )
    assert batch.incidents[0].incident.context_status == "AVAILABLE"


@pytest.mark.parametrize("parity", [False, True])
def test_negative_skew_cannot_use_history_captured_after_event(tmp_path, parity):
    prepare(tmp_path, event_second=4, capture=5, collection_second=5, action_delay=1, parity=parity)
    collector.finalize_run("CLOCK", tmp_path, now=BASE + timedelta(seconds=360 if parity else 20))
    incident = json.loads((tmp_path / "data/raw/CLOCK/incidents.jsonl").read_text())
    assert incident["context_status"] == "FUTURE"
    assert incident["features"]["source_history_known"] == 0.0
    assert collector.validate_run("CLOCK", tmp_path)["status"] == "VALID"


def test_full_bucket_parity_still_rejects_extra_relevant_account(tmp_path):
    prepare(tmp_path, parity=True)
    fixtures.append_jsonl(
        tmp_path / "archives.json",
        [
            fixtures.windows_event(
                4625, BASE + timedelta(seconds=9), {"targetUserName": "other-account"}
            )
        ],
    )
    with pytest.raises(collector.CollectionError, match="full-capture parity failed"):
        collector.finalize_run("CLOCK", tmp_path, now=BASE + timedelta(seconds=360))


def test_c2_positive_skew_replays_full_bucket_with_active_context(tmp_path, monkeypatch):
    import test_collection_acceptance as acceptance

    archive, source, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(row for row in catalog.scenarios if row.family == "c2")

    def finish_before_last_source(run_id, root, *, now):
        return collector.complete_action(run_id, root, now=now - timedelta(seconds=3))

    monkeypatch.setattr(acceptance, "complete_action", finish_before_last_source)
    run_id = acceptance._collect_run(tmp_path, archive, source, scenario, sequence=0, repeat=0)
    evidence = tmp_path / "evidence/scenario-runs" / run_id
    metadata = json.loads((evidence / "collection_metadata.json").read_text())
    assert metadata["context_observation_as_of"] > metadata["ended_at"]
    incident = json.loads((tmp_path / "data/raw" / run_id / "incidents.jsonl").read_text())
    assert incident["context_status"] == "AVAILABLE"
