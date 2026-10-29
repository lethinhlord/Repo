"""Independent deterministic intake boundary review; generated QA only."""

import json
from datetime import UTC, datetime

from ml.intake_window import capture_window


def test_exact_deadline_drains_complete_records_across_read_chunks(tmp_path):
    deadline = datetime(2026, 10, 27, 0, 6, tzinfo=UTC)
    source = tmp_path / "archive.jsonl"
    raw = (json.dumps({"id": "large-timely", "padding": "x" * (1024 * 1024)}) + "\n").encode()
    source.write_bytes(raw)
    stat = source.stat()
    cursor = {"path": str(source), "size": 0, "device": stat.st_dev, "inode": stat.st_ino}
    rows = capture_window(
        cursor,
        tmp_path / "capture.jsonl",
        tmp_path / "checkpoint.json",
        deadline=deadline,
        clock=lambda: deadline,
    )
    assert [row["id"] for row in rows] == ["large-timely"]
    assert (tmp_path / "capture.jsonl").read_bytes() == raw


def test_previously_rejected_late_input_cannot_be_erased_by_source_truncation(tmp_path):
    import pytest

    from ml.intake_window import IntakeError, verify_capture

    deadline = datetime(2026, 10, 27, 0, 6, tzinfo=UTC)
    source = tmp_path / "archive.jsonl"
    timely = b'{"id":"timely"}\n'
    source.write_bytes(timely)
    stat = source.stat()
    cursor = {"path": str(source), "size": 0, "device": stat.st_dev, "inode": stat.st_ino}
    capture, checkpoint = tmp_path / "capture.jsonl", tmp_path / "checkpoint.json"
    capture_window(cursor, capture, checkpoint, deadline=deadline, clock=lambda: deadline)
    with source.open("ab") as handle:
        handle.write(b'{"id":"late"}\n')
    with pytest.raises(IntakeError, match="late"):
        verify_capture(cursor, capture, checkpoint, deadline=deadline, relevant=lambda row: True)
    # Keep the entire sealed prefix but truncate the tail after its rejection was recorded.
    source.write_bytes(timely)
    with pytest.raises(IntakeError, match="late|truncat"):
        verify_capture(cursor, capture, checkpoint, deadline=deadline, relevant=lambda row: True)
