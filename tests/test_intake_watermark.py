"""Deterministic receive-watermark regressions; generated QA bytes, no lab evidence."""

import importlib
import json
from datetime import UTC, datetime, timedelta

import pytest

DEADLINE = datetime(2026, 10, 27, 0, 6, tzinfo=UTC)


def line(identifier, relevant=True):
    return (
        json.dumps(
            {"id": identifier, "original_window": relevant, "timestamp": "2026-10-27T00:00:10Z"}
        )
        + "\n"
    ).encode()


class Clock:
    def __init__(self, seconds=0, on_sleep=None):
        self.now = DEADLINE + timedelta(seconds=seconds)
        self.on_sleep = on_sleep

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += timedelta(seconds=seconds)
        if self.on_sleep:
            callback, self.on_sleep = self.on_sleep, None
            callback()


@pytest.fixture
def intake(tmp_path):
    module = importlib.import_module("ml.intake_window")
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

    def append(payload):
        with source.open("ab") as handle:
            handle.write(payload)

    def run(clock, wait=False):
        return module.capture_window(
            cursor,
            capture,
            checkpoint,
            deadline=DEADLINE,
            clock=clock,
            wait=wait,
            sleep=clock.sleep,
            relevant=lambda row: row.get("original_window", False),
        )

    def verify():
        return module.verify_capture(
            cursor,
            capture,
            checkpoint,
            deadline=DEADLINE,
            relevant=lambda row: row.get("original_window", False),
        )

    return module, source, capture, checkpoint, append, run, verify


def test_exact_deadline_capture_preserves_bytes_and_checkpoint(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    raw = b"  " + line("timely")
    append(raw)
    assert [r["id"] for r in run(Clock())] == ["timely"]
    assert capture.read_bytes() == raw
    assert checkpoint.is_file()
    verify()


def test_foreground_wait_captures_append_before_cutoff(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("first"))
    clock = Clock(-20, lambda: append(line("second")))
    assert [r["id"] for r in run(clock, wait=True)] == ["first", "second"]
    assert capture.read_bytes() == line("first") + line("second")
    verify()


def test_cold_finalize_after_deadline_refuses_even_old_envelope(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("old-envelope-new-arrival"))
    with pytest.raises(
        (ValueError, RuntimeError), match="(?i)cutoff|deadline|checkpoint|watermark|late"
    ):
        run(Clock(1))


def test_retry_never_admits_new_original_window_record(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("timely"))
    run(Clock())
    frozen = capture.read_bytes()
    append(line("late"))
    with pytest.raises((ValueError, RuntimeError), match="(?i)late|cutoff|deadline|watermark"):
        run(Clock(30))
    assert capture.read_bytes() == frozen
    assert any(
        b'"late"' in path.read_bytes() for path in capture.parent.glob("*.jsonl") if path != source
    )
    with pytest.raises((ValueError, RuntimeError)):
        verify()


def test_retry_ignores_later_unrelated_bucket_without_growing_capture(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("timely"))
    run(Clock())
    frozen = capture.read_bytes()
    append(line("next-bucket", relevant=False))
    assert [r["id"] for r in run(Clock(30))] == ["timely"]
    assert capture.read_bytes() == frozen
    verify()


@pytest.mark.parametrize("kind", ["truncate", "rotate", "capture-tamper", "checkpoint-tamper"])
def test_retry_rejects_tampered_or_changed_capture_origin(intake, kind):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("timely"))
    run(Clock())
    if kind == "truncate":
        source.write_bytes(b"")
    elif kind == "rotate":
        raw = source.read_bytes()
        source.rename(source.with_suffix(".old"))
        source.write_bytes(raw)
    elif kind == "capture-tamper":
        capture.write_bytes(line("forged"))
    else:
        checkpoint.write_text("{}")
    with pytest.raises((ValueError, RuntimeError)):
        run(Clock(30))


def test_read_completion_after_deadline_is_not_timely(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("crossed-cutoff"))
    calls = iter([DEADLINE - timedelta(seconds=1), DEADLINE + timedelta(seconds=1)])

    class CrossingClock:
        def __call__(self):
            return next(calls, DEADLINE + timedelta(seconds=1))

        def sleep(self, seconds):
            pass

    with pytest.raises((ValueError, RuntimeError), match="(?i)late|cutoff|deadline|watermark"):
        run(CrossingClock(), wait=True)


def test_clock_rollback_during_wait_fails_closed(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("first"))
    clock = Clock(-10)
    clock.on_sleep = lambda: setattr(clock, "now", DEADLINE - timedelta(seconds=30))
    with pytest.raises((ValueError, RuntimeError), match="(?i)clock|backward|rollback"):
        run(clock, wait=True)


def test_partial_record_completed_after_cutoff_cannot_be_rescued_by_retry(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("timely") + line("partial")[:-1])
    with pytest.raises((ValueError, RuntimeError), match="(?i)partial|incomplete|newline|late"):
        run(Clock())
    append(b"\n")
    with pytest.raises((ValueError, RuntimeError)):
        run(Clock(1))


def test_source_prefix_rewrite_is_detected(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("timely"))
    run(Clock())
    raw = source.read_bytes()
    source.write_bytes(raw.replace(b"true", b"null", 1))
    with pytest.raises(module.IntakeError, match="prefix|provenance"):
        verify()


def test_unterminated_late_tail_is_preserved_and_rejected(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("timely"))
    run(Clock())
    append(line("partial")[:-1])
    with pytest.raises(module.IntakeError, match="partial|incomplete"):
        verify()
    assert capture.with_name("capture-late.jsonl").read_bytes() == line("partial")[:-1]


def test_receipt_cutoff_is_inclusive(intake):
    module = intake[0]
    assert module.receipt_timely(DEADLINE, DEADLINE)
    assert not module.receipt_timely(DEADLINE + timedelta(microseconds=1), DEADLINE)


def test_wait_required_before_cutoff(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    with pytest.raises(module.IntakeError, match="wait"):
        run(Clock(-1))
    assert not checkpoint.exists()


def test_saved_late_rejection_survives_replacement_with_unrelated_tail(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    append(line("timely"))
    run(Clock())
    sealed_source = source.read_bytes()
    append(line("late"))
    with pytest.raises(module.IntakeError, match="late"):
        verify()
    saved_late = capture.with_name("capture-late.jsonl").read_bytes()
    source.write_bytes(sealed_source + line("unrelated", relevant=False))
    with pytest.raises(module.IntakeError, match="late"):
        verify()
    assert capture.with_name("capture-late.jsonl").read_bytes() == saved_late


def test_capture_source_io_failure_is_actionable_intake_error(intake):
    module, source, capture, checkpoint, append, run, verify = intake
    source.unlink()
    with pytest.raises(module.IntakeError, match="I/O"):
        run(Clock())
