"""Synthetic late-tail boundary regressions; these bytes are not R03 evidence."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ml import intake_window as intake

DEADLINE = datetime(2026, 10, 27, 0, 6, tzinfo=UTC)
CHUNK = 1024 * 1024


def line(identifier, *, relevant=False, padding=0):
    return (
        json.dumps({"id": identifier, "original_window": relevant, "padding": "x" * padding})
        + "\n"
    ).encode()


def relevant(row):
    return row.get("original_window", False)


class CrossingClock:
    def __init__(self, *completions):
        self.times = iter((DEADLINE - timedelta(seconds=1), *completions))

    def __call__(self):
        return next(self.times, DEADLINE + timedelta(seconds=1))


@pytest.fixture
def archive(tmp_path):
    source = tmp_path / "archive.jsonl"
    source.write_bytes(b'{"baseline":true}\n')
    stat = source.stat()
    cursor = {
        "path": str(source),
        "size": stat.st_size,
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }
    capture = tmp_path / "capture.jsonl"
    checkpoint = tmp_path / "checkpoint.json"
    late = tmp_path / "capture-late.jsonl"

    class Archive:
        def append(self, payload):
            with source.open("ab") as handle:
                handle.write(payload)

        def run(self, clock=lambda: DEADLINE, *, wait=False):
            return intake.capture_window(
                cursor, capture, checkpoint, deadline=DEADLINE, clock=clock,
                wait=wait, relevant=relevant,
            )

        def verify(self, *, live_source=True, predicate=relevant):
            return intake.verify_capture(
                cursor, capture, checkpoint, deadline=DEADLINE,
                relevant=predicate, live_source=live_source,
            )

        def seal(self):
            self.append(line("timely", relevant=True))
            assert [row["id"] for row in self.run()] == ["timely"]
            return capture.read_bytes(), checkpoint.read_bytes()

        def assert_frozen(self, frozen):
            assert (capture.read_bytes(), checkpoint.read_bytes()) == frozen

    result = Archive()
    result.source, result.cursor = source, cursor
    result.capture, result.checkpoint, result.late = capture, checkpoint, late
    return result


@pytest.mark.parametrize("timely_prefix", [False, True])
def test_complete_unrelated_record_crossing_chunk_cutoff_remains_only_late(archive, timely_prefix):
    timely = line("timely", relevant=True) if timely_prefix else b""
    late = line("next-bucket", padding=2 * CHUNK)
    archive.append(timely + late)
    completions = (
        (DEADLINE, DEADLINE + timedelta(seconds=1))
        if timely_prefix else (DEADLINE + timedelta(seconds=1),)
    )

    rows = archive.run(CrossingClock(*completions), wait=True)

    assert [row["id"] for row in rows] == (["timely"] if timely_prefix else [])
    assert archive.capture.read_bytes() == timely
    assert archive.late.read_bytes() == late
    frozen = archive.capture.read_bytes(), archive.checkpoint.read_bytes()
    archive.verify()
    archive.verify(live_source=False)
    archive.assert_frozen(frozen)


def test_saved_unrelated_partial_can_be_completed_without_changing_sealed_capture(archive):
    frozen = archive.seal()
    late = line("next-bucket")
    archive.append(late[:-1])
    with pytest.raises(intake.IntakeError, match="partial|incomplete|newline"):
        archive.verify()
    assert archive.late.read_bytes() == late[:-1]
    archive.append(b"\n")

    assert [row["id"] for row in archive.verify()] == ["timely"]

    assert archive.late.read_bytes() == late
    archive.verify(live_source=False)
    archive.assert_frozen(frozen)


class ShortTailReader:
    """A regular source handle that returns nonempty short reads in its late region."""

    def __init__(self, handle, late_start):
        self.handle, self.late_start = handle, late_start

    def __getattr__(self, name):
        return getattr(self.handle, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self.handle.__exit__(*args)

    def read(self, size=-1):
        if self.handle.tell() >= self.late_start:
            size = min(size, 7) if size >= 0 else 7
        return self.handle.read(size)


@pytest.mark.parametrize("is_relevant", [False, True])
def test_nonempty_short_reads_do_not_slice_a_complete_saved_late_record(
    archive, monkeypatch, is_relevant,
):
    frozen = archive.seal()
    late_start = archive.source.stat().st_size
    late = line("late-record", relevant=is_relevant)
    archive.append(late)
    original_open = Path.open

    def open_source(path, mode="r", *args, **kwargs):
        handle = original_open(path, mode, *args, **kwargs)
        if path == archive.source and mode == "rb":
            return ShortTailReader(handle, late_start)
        return handle

    monkeypatch.setattr(Path, "open", open_source)

    if is_relevant:
        with pytest.raises(intake.IntakeError, match="late original-window"):
            archive.verify()
    else:
        assert [row["id"] for row in archive.verify()] == ["timely"]

    assert archive.late.read_bytes() == late
    archive.assert_frozen(frozen)


def test_timely_record_prefix_completed_after_cutoff_is_not_admitted(archive):
    timely = line("timely", relevant=True)
    late = line("crosses-cutoff", relevant=True, padding=CHUNK)
    archive.append(timely + late)
    clock = CrossingClock(DEADLINE, DEADLINE + timedelta(seconds=1))

    with pytest.raises(intake.IntakeError, match="after intake deadline|late original-window"):
        archive.run(clock, wait=True)

    assert archive.capture.read_bytes() == timely
    assert archive.late.read_bytes() == late
    assert b"crosses-cutoff" not in archive.capture.read_bytes()


@pytest.mark.parametrize("source_change", ["offline", "truncate", "rewrite"])
def test_saved_relevant_rejection_survives_source_changes(archive, source_change):
    frozen = archive.seal()
    sealed_source = archive.source.read_bytes()
    late = line("late-original", relevant=True)
    archive.append(late)
    with pytest.raises(intake.IntakeError, match="late original-window"):
        archive.verify()
    assert archive.late.read_bytes() == late
    if source_change == "offline":
        archive.source.unlink()
    elif source_change == "truncate":
        archive.source.write_bytes(sealed_source)
    else:
        archive.source.write_bytes(sealed_source + line("unrelated-replacement"))

    with pytest.raises(intake.IntakeError, match="saved late original-window"):
        archive.verify(live_source=source_change != "offline")

    assert archive.late.read_bytes() == late
    archive.assert_frozen(frozen)


def test_saved_relevant_complete_prefix_is_fatal_despite_incomplete_suffix_offline(archive):
    frozen = archive.seal()
    late = line("late-original", relevant=True) + line("unknown-partial")[:-4]
    archive.append(late)
    with pytest.raises(intake.IntakeError, match="late original-window|partial|incomplete"):
        archive.verify()
    assert archive.late.read_bytes() == late
    archive.source.unlink()

    with pytest.raises(intake.IntakeError, match="saved late original-window"):
        archive.verify(live_source=False)

    assert archive.late.read_bytes() == late
    archive.assert_frozen(frozen)


@pytest.mark.parametrize("live_source", [False, True])
def test_genuine_eof_partial_is_preserved_and_refused(archive, live_source):
    frozen = archive.seal()
    partial = line("unknown-unfinished")[:-4]
    archive.append(partial)
    with pytest.raises(intake.IntakeError, match="partial|incomplete|newline"):
        archive.verify()

    with pytest.raises(intake.IntakeError, match="partial|incomplete|newline"):
        archive.verify(live_source=live_source)

    assert archive.late.read_bytes() == partial
    archive.assert_frozen(frozen)


def test_true_partial_at_exact_cutoff_is_never_added_to_capture(archive):
    timely, partial = line("timely", relevant=True), line("unfinished", relevant=True)[:-1]
    archive.append(timely + partial)

    with pytest.raises(intake.IntakeError, match="partial|incomplete|newline"):
        archive.run()

    assert archive.capture.read_bytes() == timely
    assert archive.late.read_bytes() == partial
    assert json.loads(archive.checkpoint.read_text())["status"] == "capturing"


def test_saved_unrelated_prefix_cannot_be_rewritten_during_completion(archive):
    frozen = archive.seal()
    source_prefix = archive.source.read_bytes()
    partial = line("next-bucket")[:-1]
    archive.append(partial)
    with pytest.raises(intake.IntakeError, match="partial|incomplete"):
        archive.verify()
    archive.source.write_bytes(source_prefix + line("replacement"))

    with pytest.raises(intake.IntakeError, match="late tail.*truncated|late tail.*changed"):
        archive.verify()

    assert archive.late.read_bytes() == partial
    archive.assert_frozen(frozen)


def test_missing_timestamp_from_selected_agent_stays_relevant_and_fatal(archive):
    from ml.scenario_collection import SourceConfig, _intake_relevant

    source = SourceConfig(
        version="collection-sources-v1",
        wazuh_archives_path=str(archive.source),
        windows_agent_name="windows",
        suricata_agent_name="suricata",
        taxonomy_path="synthetic-taxonomy.yaml",
        scenario_catalog_path="synthetic-catalog.yaml",
    )
    frozen = archive.seal()
    late = (json.dumps({"agent": {"name": "windows"}, "padding": "x" * CHUNK}) + "\n").encode()
    archive.append(late)

    with pytest.raises(intake.IntakeError, match="late original-window"):
        archive.verify(predicate=_intake_relevant(source, DEADLINE - timedelta(minutes=1)))

    assert archive.late.read_bytes() == late
    archive.assert_frozen(frozen)


@pytest.mark.parametrize("change", ["none", "rotation"])
def test_verification_keeps_empty_tail_stable_and_rejects_rotation(archive, change):
    frozen = archive.seal()
    if change == "rotation":
        raw = archive.source.read_bytes()
        archive.source.rename(archive.source.with_suffix(".old"))
        archive.source.write_bytes(raw)
        with pytest.raises(intake.IntakeError, match="rotated|truncated"):
            archive.verify()
    else:
        assert [row["id"] for row in archive.verify()] == ["timely"]
        assert not archive.late.exists()
    archive.assert_frozen(frozen)


def test_snapshot_shrink_between_identity_and_size_never_uses_unbounded_read(archive, monkeypatch):
    import os

    archive.seal()
    offset = archive.source.stat().st_size
    original_fstat = intake.os.fstat
    calls = 0
    reads = []

    def shrinking_snapshot(fd):
        nonlocal calls
        observed = original_fstat(fd)
        calls += 1
        if calls == 2:
            fields = list(observed)
            fields[6] = offset - 1
            return os.stat_result(fields)
        return observed

    class Reader:
        def __init__(self, handle):
            self.handle = handle

        def __getattr__(self, name):
            return getattr(self.handle, name)

        def read(self, size):
            reads.append(size)
            return self.handle.read(size)

    monkeypatch.setattr(intake.os, "fstat", shrinking_snapshot)
    with archive.source.open("rb") as handle, pytest.raises(intake.IntakeError, match="truncated"):
        intake._read_tail_snapshot(Reader(handle), archive.cursor, offset)
    assert reads == []


def test_late_snapshot_does_not_chase_a_continuously_growing_source(archive):
    archive.seal()
    offset = archive.source.stat().st_size
    original_tail = line("initial-tail")
    archive.append(original_tail)
    sizes = []

    class GrowingReader(ShortTailReader):
        def read(self, size=-1):
            sizes.append(size)
            payload = super().read(size)
            archive.append(line("appended-during-observation"))
            return payload

    with archive.source.open("rb") as handle:
        tail = intake._read_tail_snapshot(GrowingReader(handle, offset), archive.cursor, offset)
    assert tail == original_tail
    assert all(0 < size <= CHUNK for size in sizes)
    assert len(sizes) == (len(original_tail) + 6) // 7
    assert archive.source.stat().st_size > offset + len(original_tail)
