from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from ml.scenario_collection import (
    CollectionError,
    RunDraft,
    _validate_action_window,
    abort_run,
    begin_action,
    complete_action,
    finalize_run,
    start_run,
)
from scripts.scenario_session import parser


def started_run(
    root: Path,
    started_at: datetime,
    *,
    family: str = "account",
    intervals: str = "",
    count: int = 1,
    skew: float = 5.0,
    pre_delay: float = 2.0,
) -> str:
    run_id = "WINDOW-CHECK-001"
    archive = root / "archives.json"
    archive.write_text("{}\n", encoding="utf-8")
    taxonomy = root / "taxonomy.yaml"
    taxonomy.write_text("revision: window-test-v1\nrules: []\n", encoding="utf-8")
    catalog_path = root / "catalog.yaml"
    attribution = (
        {"account_names": ["labuser"]}
        if family == "account"
        else {
            "process_names": ["curl.exe"],
            "source_ips": ["10.20.0.10"],
            "destination_ips": ["10.40.0.10"],
            "destination_ports": [8081],
        }
    )
    scenario = {
        "scenario_id": "WINDOW-CHECK",
        "family": family,
        "label": "benign",
        "expected_behavior": "Execute a controlled action inside one aggregation window.",
        "attribution": attribution,
        "quality_gates": {"min_account_successes": 1},
        "expected_observables": ["timestamped events inside the receipt bucket"],
        "preconditions": ["isolated test"],
        "execution_steps": ["test"],
        "cleanup_steps": ["test"],
    }
    catalog_path.write_text(
        yaml.safe_dump(
            {"version": "scenario-catalog-v1", "lab_only": True, "scenarios": [scenario]}
        ),
        encoding="utf-8",
    )
    sources = root / "sources.yaml"
    sources.write_text(
        yaml.safe_dump(
            {
                "version": "collection-sources-v1",
                "wazuh_archives_path": str(archive),
                "taxonomy_path": str(taxonomy),
                "scenario_catalog_path": str(catalog_path),
                "windows_agent_name": "WIN11-TARGET",
                "suricata_agent_name": "NET-SENSOR",
            }
        ),
        encoding="utf-8",
    )
    parameters = {"pre_action_delay_seconds": pre_delay, "run_nonce": "windowtestnonce1"}
    if family == "c2":
        parameters.update(expected_action_count=count, expected_intervals_seconds=intervals)
    draft = {
        **{
            key: value
            for key, value in scenario.items()
            if key not in {"preconditions", "execution_steps", "cleanup_steps"}
        },
        "run_id": run_id,
        "host": "WIN11-TARGET",
        "operator": "test",
        "collection_seed": 42,
        "scenario_parameters": parameters,
        "clock_preflight": {
            **{
                key: started_at.isoformat()
                for key in (
                    "captured_at",
                    "controller_utc",
                    "target_utc",
                    "wazuh_utc",
                    "sensor_utc",
                    "attacker_utc",
                )
            },
            "maximum_skew_seconds": skew,
        },
    }
    draft_path = root / "draft.yaml"
    draft_path.write_text(yaml.safe_dump(draft), encoding="utf-8")
    start_run(draft_path, sources, root, now=started_at)
    return run_id


def test_begin_refuses_frozen_schedule_that_cannot_fit_current_window(tmp_path: Path) -> None:
    started = datetime(2026, 10, 27, 0, 4, tzinfo=UTC)
    run_id = started_run(tmp_path, started, family="c2", count=8, intervals=",".join(["30"] * 7))
    with pytest.raises(CollectionError, match="aggregation window"):
        begin_action(run_id, tmp_path, now=started + timedelta(seconds=1))


def test_wait_for_window_waits_before_creating_receipt(tmp_path: Path, monkeypatch) -> None:
    started = datetime(2026, 10, 27, 0, 4, tzinfo=UTC)
    run_id = started_run(tmp_path, started, family="c2", count=8, intervals=",".join(["30"] * 7))
    clock = {"current": started + timedelta(seconds=1)}
    sleeps = []

    def sleep(seconds: float) -> None:
        state = json.loads(
            (tmp_path / "evidence/scenario-runs" / run_id / ".collection_state.json").read_text()
        )
        assert state["execution_receipt"] is None
        sleeps.append(seconds)
        clock["current"] += timedelta(seconds=seconds)

    monkeypatch.setattr("ml.scenario_collection._utc", lambda value: value or clock["current"])
    monkeypatch.setattr("ml.scenario_collection.time.sleep", sleep)
    receipt = begin_action(run_id, tmp_path, wait_for_window=True)

    assert sleeps and max(sleeps) <= 30
    assert receipt["aggregation_window_start"] == "2026-10-27T00:05:00Z"
    assert receipt["aggregation_window_end"] == "2026-10-27T00:10:00Z"
    assert receipt["action_started_at"] == "2026-10-27T00:05:05Z"
    assert receipt["action_deadline"] == "2026-10-27T00:09:55Z"


def test_worst_health_schedule_fits_with_five_second_clock_guard(tmp_path: Path) -> None:
    started = datetime(2026, 10, 27, tzinfo=UTC)
    run_id = started_run(
        tmp_path, started, family="c2", count=8, intervals=",".join(["39"] * 7), pre_delay=5.0
    )
    receipt = begin_action(run_id, tmp_path, now=started + timedelta(seconds=5))
    assert receipt["reserved_action_seconds"] == 288.0
    assert receipt["action_deadline"] == "2026-10-27T00:04:55Z"


def test_schedule_that_cannot_fit_any_guarded_window_is_rejected(tmp_path: Path) -> None:
    started = datetime(2026, 10, 27, tzinfo=UTC)
    run_id = started_run(
        tmp_path,
        started,
        family="c2",
        count=8,
        skew=10.0,
        intervals=",".join(["39"] * 7),
        pre_delay=5.0,
    )
    with pytest.raises(CollectionError, match="cannot fit"):
        begin_action(run_id, tmp_path, now=started + timedelta(seconds=10))


@pytest.mark.parametrize("end_seconds", [295, 300, 301])
def test_complete_rejects_deadline_and_cross_bucket_action(
    tmp_path: Path, end_seconds: int
) -> None:
    started = datetime(2026, 10, 27, tzinfo=UTC)
    run_id = started_run(tmp_path, started)
    begin_action(run_id, tmp_path, now=started + timedelta(seconds=1))
    with pytest.raises(CollectionError, match="aggregation window"):
        complete_action(run_id, tmp_path, now=started + timedelta(seconds=end_seconds))
    saved = json.loads(
        (tmp_path / "evidence/scenario-runs" / run_id / "execution_receipt.json").read_text()
    )
    assert saved["status"] == "STARTED"
    assert saved["action_ended_at"] is None


def test_finalize_rejects_clock_tolerated_event_in_previous_bucket(tmp_path: Path) -> None:
    started = datetime(2026, 10, 27, tzinfo=UTC)
    run_id = started_run(tmp_path, started)
    begin_action(run_id, tmp_path, now=started + timedelta(seconds=1))
    event = {
        "timestamp": started.isoformat(),
        "agent": {"name": "WIN11-TARGET"},
        "data": {
            "win": {
                "system": {
                    "eventID": "4624",
                    "systemTime": (started - timedelta(seconds=1)).isoformat(),
                },
                "eventdata": {"targetUserName": "labuser", "logonType": "2"},
            }
        },
    }
    with (tmp_path / "archives.json").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    complete_action(run_id, tmp_path, now=started + timedelta(seconds=10))
    with pytest.raises(CollectionError, match="aggregation window"):
        finalize_run(run_id, tmp_path, now=started + timedelta(seconds=30))


@pytest.mark.parametrize("intervals", ["-1", "nan", "inf"])
def test_begin_rejects_invalid_frozen_schedule(tmp_path: Path, intervals: str) -> None:
    started = datetime(2026, 10, 27, tzinfo=UTC)
    run_id = started_run(tmp_path, started, family="c2", count=2, intervals=intervals)
    with pytest.raises(CollectionError, match="schedule"):
        begin_action(run_id, tmp_path, now=started + timedelta(seconds=5))


def test_begin_cli_exposes_wait_for_window() -> None:
    args = parser().parse_args(
        ["begin-action", "--run-id", "WINDOW-CHECK-001", "--wait-for-window"]
    )
    assert args.wait_for_window is True


def test_aborting_run_during_wait_does_not_resurrect_action(tmp_path: Path, monkeypatch) -> None:
    started = datetime(2026, 10, 27, 0, 4, tzinfo=UTC)
    run_id = started_run(tmp_path, started, family="c2", count=8, intervals=",".join(["30"] * 7))
    clock = {"current": started + timedelta(seconds=1)}
    aborted = []

    def sleep(seconds: float) -> None:
        if not aborted:
            abort_run(run_id, tmp_path, "operator cancelled during window wait")
            aborted.append(True)
        clock["current"] += timedelta(seconds=seconds)

    monkeypatch.setattr("ml.scenario_collection._utc", lambda value=None: value or clock["current"])
    monkeypatch.setattr("ml.scenario_collection.time.sleep", sleep)
    with pytest.raises(CollectionError, match="run state changed"):
        begin_action(run_id, tmp_path, wait_for_window=True)
    saved = json.loads(
        (tmp_path / "evidence/scenario-runs" / run_id / ".collection_state.json").read_text()
    )
    assert saved["status"] == "ABORTED"
    assert saved["execution_receipt"] is None
    assert not (tmp_path / "evidence/scenario-runs" / run_id / "execution_receipt.json").exists()


def test_legacy_receipt_without_fixed_window_contract_is_rejected(tmp_path: Path) -> None:
    started = datetime(2026, 10, 27, tzinfo=UTC)
    run_id = started_run(tmp_path, started)
    receipt = begin_action(run_id, tmp_path, now=started + timedelta(seconds=5))
    del receipt["aggregation_window_start"]
    draft = RunDraft.model_validate(
        json.loads((tmp_path / "evidence/scenario-runs" / run_id / "ground_truth.json").read_text())
    )
    with pytest.raises(CollectionError, match="aggregation window contract"):
        _validate_action_window(receipt, draft)
