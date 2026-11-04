"""Synthetic lifecycle regressions; no live archives, containers or lab evidence."""

from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest
import test_collection_acceptance as acceptance

from ml import scenario_collection as collector


class Interrupted(Exception):
    pass


@pytest.fixture
def pending_run(tmp_path, monkeypatch):
    archive, source, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(row for row in catalog.scenarios if row.family == "account")
    pending = {}

    def stop_before_finalize(run_id, root, *, now):
        pending.update(run_id=run_id, root=root, cutoff=now)
        raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(acceptance, "finalize_run", stop_before_finalize)
        with pytest.raises(Interrupted):
            acceptance._collect_run(
                tmp_path, archive, source, scenario, sequence=0, repeat=0,
            )
    run = SimpleNamespace(**pending)
    run.archive = archive
    run.source = source
    run.evidence = tmp_path / "evidence/scenario-runs" / run.run_id
    run.output = tmp_path / "data/raw" / run.run_id
    run.staging = run.output.with_name(f".{run.run_id}.tmp")
    run.active = run.evidence.parent / ".active-run.json"
    run.state = lambda: collector.run_status(run.run_id, run.root)
    run.finalize = lambda: collector.finalize_run(run.run_id, run.root, now=run.cutoff)
    return run


def append_unrelated(run, seconds=1):
    row = {
        "agent": {"name": "WIN11-TARGET"},
        "timestamp": (run.cutoff + timedelta(seconds=seconds)).isoformat(),
    }
    with run.archive.open("ab") as handle:
        handle.write((json.dumps(row) + "\n").encode())


def frozen_capture(run):
    return tuple((run.evidence / name).read_bytes() for name in (
        "archive_capture.jsonl", "intake_checkpoint.json",
    ))


def interrupt_finalizing(run, monkeypatch, *, existing_late=False):
    original_write = collector._write_json
    original_derive = collector._derive_account

    def derive(*args, **kwargs):
        if existing_late:
            append_unrelated(run)
        return original_derive(*args, **kwargs)

    def write(path, payload):
        original_write(path, payload)
        if path.name == ".collection_state.json" and payload.get("status") == "FINALIZING":
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(collector, "_write_json", write)
        patch.setattr(collector, "_derive_account", derive)
        with pytest.raises(Interrupted):
            run.finalize()
    assert run.state()["status"] == "FINALIZING"
    assert run.staging.is_dir()
    assert not run.output.exists()
    assert run.active.exists()
    return frozen_capture(run)


@pytest.mark.parametrize("existing_late", [False, True])
def test_recovery_allows_unrelated_tail_creation_and_growth(
    pending_run, monkeypatch, existing_late,
):
    run = pending_run
    frozen = interrupt_finalizing(run, monkeypatch, existing_late=existing_late)
    certified = {
        path.name: path.read_bytes() for path in run.evidence.iterdir()
        if path.is_file() and path.name != ".collection_state.json"
    }
    append_unrelated(run, seconds=2)

    assert run.finalize()["status"] == "FINALIZED"
    assert collector.validate_run(run.run_id, run.root)["status"] == "VALID"
    assert frozen_capture(run) == frozen
    assert {
        path.name: path.read_bytes() for path in run.evidence.iterdir()
        if path.is_file() and path.name != ".collection_state.json"
    } == certified
    assert not run.active.exists()


@pytest.mark.parametrize("tamper", ["evidence", "staging", "late-original"])
def test_recovery_rejects_invalid_evidence_before_publication(pending_run, monkeypatch, tamper):
    run = pending_run
    frozen = interrupt_finalizing(run, monkeypatch)
    if tamper == "evidence":
        with (run.evidence / "windows_events.jsonl").open("ab") as handle:
            handle.write(b"{}\n")
    elif tamper == "staging":
        with (run.staging / "incidents.jsonl").open("ab") as handle:
            handle.write(b"{}\n")
    else:
        with run.archive.open("ab") as handle:
            handle.write(frozen[0])

    with pytest.raises(collector.CollectionError):
        run.finalize()
    assert run.state()["status"] == "FINALIZING"
    assert run.active.exists()
    if tamper != "staging":
        assert not run.output.exists()
    assert run.staging.is_dir() or run.output.is_dir()
    assert frozen_capture(run) == frozen


def test_recovery_validation_failure_remains_retryable(pending_run, monkeypatch):
    run = pending_run
    frozen = interrupt_finalizing(run, monkeypatch)

    def unavailable(*args, **kwargs):
        raise collector.CollectionError("injected validation unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(collector, "verify_feature_provenance", unavailable)
        with pytest.raises(collector.CollectionError, match="validation unavailable"):
            run.finalize()
    assert run.state()["status"] == "FINALIZING"
    assert run.active.exists()
    assert run.finalize()["status"] == "FINALIZED"
    assert collector.validate_run(run.run_id, run.root)["status"] == "VALID"
    assert frozen_capture(run) == frozen


@pytest.mark.parametrize(
    "operation", ["start", "begin", "complete", "finalize", "abort", "quarantine"],
)
def test_lifecycle_commands_fail_fast_while_finalize_is_active(pending_run, monkeypatch, operation):
    run = pending_run
    entered, release = Event(), Event()
    original = collector._derive_account

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(10), "test barrier was not released"
        return original(*args, **kwargs)

    calls = {
        "start": lambda: collector.start_run(
            run.root / "run-drafts" / f"{run.run_id}.yaml", run.source, run.root,
            now=acceptance.COLLECTION_BASE - timedelta(seconds=10),
        ),
        "begin": lambda: collector.begin_action(run.run_id, run.root),
        "complete": lambda: collector.complete_action(run.run_id, run.root),
        "finalize": run.finalize,
        "abort": lambda: collector.abort_run(run.run_id, run.root, "operator rejects run"),
        "quarantine": lambda: collector.quarantine_run(
            run.run_id, run.root, "operator rejects run",
        ),
    }
    monkeypatch.setattr(collector, "_derive_account", blocked)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(run.finalize)
        try:
            assert entered.wait(10)
            with pytest.raises(collector.CollectionError, match="(?i)busy|in progress|locked"):
                calls[operation]()
        finally:
            release.set()
        assert first.result(timeout=10)["status"] == "FINALIZED"
    assert collector.validate_run(run.run_id, run.root)["status"] == "VALID"


def test_lifecycle_lock_releases_after_operation_exception(pending_run, monkeypatch):
    run = pending_run

    def interrupted(*args, **kwargs):
        raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(collector, "_derive_account", interrupted)
        with pytest.raises(Interrupted):
            run.finalize()
    assert collector.abort_run(run.run_id, run.root, "cancel after failure")["status"] == "ABORTED"
    with pytest.raises(collector.CollectionError):
        run.finalize()
    assert run.state()["status"] == "ABORTED"


def test_lifecycle_lock_excludes_a_second_process(pending_run, monkeypatch):
    run = pending_run
    entered, release = Event(), Event()
    original = collector._derive_account

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(20)
        return original(*args, **kwargs)

    program = """
import sys
from pathlib import Path
from ml import scenario_collection as c
try:
    c.abort_run(sys.argv[1], Path(sys.argv[2]), 'concurrent process abort')
except c.CollectionError as exc:
    print(exc)
    raise SystemExit(7)
"""
    monkeypatch.setattr(collector, "_derive_account", blocked)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(run.finalize)
        try:
            assert entered.wait(10)
            process = subprocess.run(
                [sys.executable, "-B", "-X", "utf8", "-c", program,
                 run.run_id, str(run.root)],
                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=15,
            )
            assert process.returncode == 7, process.stdout + process.stderr
            assert "busy" in process.stdout.casefold()
        finally:
            release.set()
        assert first.result(timeout=10)["status"] == "FINALIZED"
    assert collector.validate_run(run.run_id, run.root)["status"] == "VALID"


def test_lifecycle_lock_releases_after_process_crash(pending_run):
    run = pending_run
    program = """
import os, sys
from pathlib import Path
from datetime import datetime
from ml import scenario_collection as c
c._derive_account = lambda *args, **kwargs: os._exit(42)
c.finalize_run(sys.argv[1], Path(sys.argv[2]), now=datetime.fromisoformat(sys.argv[3]))
"""
    process = subprocess.run(
        [sys.executable, "-B", "-X", "utf8", "-c", program,
         run.run_id, str(run.root), run.cutoff.isoformat()],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30,
    )
    assert process.returncode == 42, process.stdout + process.stderr
    frozen = frozen_capture(run)
    assert run.finalize()["status"] == "FINALIZED"
    assert frozen_capture(run) == frozen
    assert collector.validate_run(run.run_id, run.root)["status"] == "VALID"


@pytest.mark.parametrize("tamper", [False, True])
def test_recovery_after_finalized_commit_finishes_only_verified_ownership(
    pending_run, monkeypatch, tamper,
):
    run = pending_run
    original_write = collector._write_json

    def interrupt_after_commit(path, payload):
        original_write(path, payload)
        if path.name == ".collection_state.json" and payload.get("status") == "FINALIZED":
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(collector, "_write_json", interrupt_after_commit)
        with pytest.raises(Interrupted):
            run.finalize()
    assert run.state()["status"] == "FINALIZED"
    assert run.active.exists()
    assert run.output.is_dir()
    if tamper:
        with (run.evidence / "windows_events.jsonl").open("ab") as handle:
            handle.write(b"{}\n")
        with pytest.raises(collector.CollectionError, match="checksum"):
            run.finalize()
        assert run.active.exists()
    else:
        certified = {
            path.name: path.read_bytes() for path in run.evidence.iterdir() if path.is_file()
        }
        assert run.finalize()["status"] == "FINALIZED"
        assert not run.active.exists()
        assert collector.validate_run(run.run_id, run.root)["status"] == "VALID"
        assert {
            path.name: path.read_bytes() for path in run.evidence.iterdir() if path.is_file()
        } == certified


def test_finalized_retry_never_releases_another_runs_owner(pending_run):
    run = pending_run
    assert run.finalize()["status"] == "FINALIZED"
    owner = b'{"run_id":"ANOTHER-RUN"}\n'
    run.active.write_bytes(owner)
    with pytest.raises(collector.CollectionError, match="belongs to"):
        run.finalize()
    assert run.active.read_bytes() == owner
    assert collector.validate_run(run.run_id, run.root)["status"] == "VALID"
