"""Generated bounded-observation tests; no lab evidence or wall-clock waiting."""

import hashlib
import json
from datetime import UTC, datetime

import pytest

from ml import intake_window as intake
from ml import scenario_collection as collector


def test_start_waits_for_completion_and_keeps_observed_fragment_in_prefix(tmp_path, monkeypatch):
    path = tmp_path / "archives.jsonl"
    partial = b'{"before":true}\n{"partial":'
    path.write_bytes(partial)

    def finish(_):
        with path.open("ab") as handle:
            handle.write(b"true}\n")

    monkeypatch.setattr(collector.time, "sleep", finish)
    cursor = collector._cursor(path)
    assert cursor["size"] == len(partial + b"true}\n")
    assert cursor["prefix_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_start_rejects_mutated_previously_observed_fragment(tmp_path, monkeypatch):
    path = tmp_path / "archives.jsonl"
    path.write_bytes(b'{"before":true}\n{"partial":')

    def change(_):
        path.write_bytes(b'{"before":true}\n{"changed":true}\n')

    monkeypatch.setattr(collector.time, "sleep", change)
    with pytest.raises(collector.CollectionError, match="prefix|changed|provenance"):
        collector._cursor(path)


@pytest.mark.parametrize("late_relevant", [False, True])
def test_completed_late_tail_is_observation_only(tmp_path, monkeypatch, late_relevant):
    path = tmp_path / "archives.jsonl"
    path.write_bytes(b'{"id":"timely"}\n')
    stat = path.stat()
    cursor = {"path": str(path), "size": 0, "device": stat.st_dev, "inode": stat.st_ino}
    capture, checkpoint = tmp_path / "capture.jsonl", tmp_path / "checkpoint.json"
    deadline = datetime(2026, 10, 27, tzinfo=UTC)
    intake.capture_window(cursor, capture, checkpoint, deadline=deadline, clock=lambda: deadline)
    frozen = capture.read_bytes(), checkpoint.read_bytes()
    late = (json.dumps({"relevant": late_relevant}) + "\n").encode()
    with path.open("ab") as handle:
        handle.write(late[:-1])

    def finish(_):
        with path.open("ab") as handle:
            handle.write(b"\n")

    monkeypatch.setattr(intake.time, "sleep", finish)
    if late_relevant:
        with pytest.raises(intake.IntakeError, match="late original-window"):
            intake.verify_capture(
                cursor,
                capture,
                checkpoint,
                deadline=deadline,
                relevant=lambda row: row.get("relevant", False),
            )
    else:
        assert intake.verify_capture(
            cursor,
            capture,
            checkpoint,
            deadline=deadline,
            relevant=lambda row: row.get("relevant", False),
        ) == [{"id": "timely"}]
    assert (capture.read_bytes(), checkpoint.read_bytes()) == frozen


def test_late_completion_must_preserve_observed_partial_bytes(tmp_path, monkeypatch):
    path = tmp_path / "archives.jsonl"
    path.write_bytes(b'{"initial":')
    stat = path.stat()
    cursor = {"path": str(path), "size": 0, "device": stat.st_dev, "inode": stat.st_ino}

    def change(_):
        path.write_bytes(b'{"changed":true}\n')

    monkeypatch.setattr(intake.time, "sleep", change)
    with path.open("rb") as handle, pytest.raises(intake.IntakeError, match="changed|prefix"):
        intake._read_tail_snapshot(handle, cursor, 0)


def test_rejected_late_partial_mutation_cannot_disappear_on_retry(tmp_path, monkeypatch):
    path = tmp_path / "archives.jsonl"
    timely = b'{"id":"timely"}\n'
    partial = b'{"relevant":tr'
    path.write_bytes(timely)
    stat = path.stat()
    cursor = {"path": str(path), "size": 0, "device": stat.st_dev, "inode": stat.st_ino}
    capture, checkpoint = tmp_path / "capture.jsonl", tmp_path / "checkpoint.json"
    deadline = datetime(2026, 10, 27, tzinfo=UTC)
    intake.capture_window(cursor, capture, checkpoint, deadline=deadline, clock=lambda: deadline)
    path.write_bytes(timely + partial)

    def change(_):
        path.write_bytes(timely + b'{"irrelevant":true}\n')

    monkeypatch.setattr(intake.time, "sleep", change)
    with pytest.raises(intake.IntakeError, match="changed|prefix"):
        intake.verify_capture(
            cursor, capture, checkpoint, deadline=deadline, relevant=lambda _: False
        )
    with pytest.raises(intake.IntakeError, match="changed|prefix"):
        intake.verify_capture(
            cursor, capture, checkpoint, deadline=deadline, relevant=lambda _: False
        )
    assert (tmp_path / "capture-late.jsonl").read_bytes() == partial
