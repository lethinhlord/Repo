"""Foreground archive intake; collector read completion is the arrival evidence.

A sealed checkpoint never admits new bytes. Hashes detect corruption, not a
malicious operator rewriting the source and every evidence file together.
"""

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path


class IntakeError(ValueError):
    pass


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise IntakeError("intake clock/deadline must be timezone aware")
    return value.astimezone(UTC)


def receipt_timely(received_at, deadline):
    return _utc(received_at) <= _utc(deadline)


def _digest(payload):
    return hashlib.sha256(payload).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _rows(payload):
    if payload and not payload.endswith(b"\n"):
        raise IntakeError("incomplete partial JSON line at intake cutoff")
    try:
        rows = [json.loads(line) for line in payload.splitlines() if line.strip()]
    except (ValueError, UnicodeError) as exc:
        raise IntakeError("invalid intake JSON line") from exc
    if any(not isinstance(row, dict) for row in rows):
        raise IntakeError("intake JSON line must be an object")
    return rows


def _identity(handle, cursor, minimum):
    stat = os.fstat(handle.fileno())
    current = Path(cursor["path"]).stat()
    for observed in (stat, current):
        if (
            observed.st_dev != cursor["device"]
            or observed.st_ino != cursor["inode"]
            or observed.st_size < minimum
        ):
            raise IntakeError("intake source rotated or truncated")


def _hash_prefix(handle, length):
    handle.seek(0)
    digest = hashlib.sha256()
    remaining = length
    while remaining:
        block = handle.read(min(1024 * 1024, remaining))
        if not block:
            raise IntakeError("intake source truncated")
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest()


def verify_capture(cursor, capture_path, checkpoint_path, *, deadline, relevant, live_source=True):
    """Verify frozen evidence; live_source also audits the current archive tail.

    Offline verification cannot attest that no new source bytes arrived later.
    """
    capture_path, checkpoint_path = Path(capture_path), Path(checkpoint_path)
    try:
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        seal = checkpoint.pop("sha256")
        if seal != _digest(_canonical(checkpoint)):
            raise IntakeError("checkpoint provenance hash mismatch")
        if (
            checkpoint["status"] != "sealed"
            or checkpoint["cursor"] != cursor
            or checkpoint["deadline"] != _utc(deadline).isoformat()
        ):
            raise IntakeError("invalid intake checkpoint provenance")
        raw = capture_path.read_bytes()
        offset = checkpoint["admitted_offset"]
        if offset != cursor["size"] + len(raw) or _digest(raw) != checkpoint["raw_sha256"]:
            raise IntakeError("capture hash/offset mismatch")
        if cursor.get("prefix_sha256", checkpoint["prefix_sha256"]) != checkpoint["prefix_sha256"]:
            raise IntakeError("checkpoint prefix differs from start cursor")
        previous = _utc(datetime.fromisoformat(checkpoint["started_at"]))
        if not receipt_timely(previous, deadline):
            raise IntakeError("checkpoint started after deadline")
        consumed = cursor["size"]
        for batch in checkpoint["reads"]:
            observed = _utc(datetime.fromisoformat(batch["completed_at"]))
            if observed < previous or not receipt_timely(observed, deadline):
                raise IntakeError("invalid checkpoint clock/watermark")
            end = batch["end"]
            if not consumed < end <= offset:
                raise IntakeError("invalid checkpoint read offsets")
            consumed, previous = end, observed
        if consumed != offset:
            raise IntakeError("checkpoint lacks read completion evidence")
        late_path = capture_path.with_name(capture_path.stem + "-late.jsonl")
        saved_late = late_path.read_bytes() if late_path.exists() else b""
        if any(relevant(row) for row in _rows(saved_late)):
            raise IntakeError("saved late original-window evidence after cutoff")
        if live_source:
            with Path(cursor["path"]).open("rb") as handle:
                _identity(handle, cursor, offset)
                if _hash_prefix(handle, cursor["size"]) != checkpoint["prefix_sha256"]:
                    raise IntakeError("source prefix provenance mismatch")
                if _hash_prefix(handle, offset) != checkpoint["source_sha256"]:
                    raise IntakeError("source capture provenance mismatch")
                handle.seek(offset)
                late = handle.read()
                _identity(handle, cursor, offset + len(late))
            if not late.startswith(saved_late):
                raise IntakeError("source late tail was truncated or changed")
            if late:
                late_path.write_bytes(late)
                if any(relevant(row) for row in _rows(late)):
                    raise IntakeError("late original-window input after intake cutoff")
        return _rows(raw)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, IntakeError):
            raise
        raise IntakeError(f"invalid intake checkpoint/capture: {exc}") from exc


def capture_window(
    cursor,
    capture_path,
    checkpoint_path,
    *,
    deadline,
    clock=lambda: datetime.now(UTC),
    wait=False,
    sleep=time.sleep,
    relevant=lambda row: True,
):
    try:
        capture_path, checkpoint_path = Path(capture_path), Path(checkpoint_path)
        deadline = _utc(deadline)
        if checkpoint_path.exists():
            return verify_capture(
                cursor, capture_path, checkpoint_path, deadline=deadline, relevant=relevant
            )
        started = _utc(clock())
        if started > deadline:
            raise IntakeError("past intake deadline without verified checkpoint")
        if started < deadline and not wait:
            raise IntakeError("intake deadline is open; use foreground --wait")
        if capture_path.exists():
            raise IntakeError("capture exists without verified checkpoint")
        # Exclusive sentinel prevents a failed/partial capture being silently retried.
        with checkpoint_path.open("x", encoding="utf-8") as marker:
            marker.write('{"status":"capturing"}\n')
        with Path(cursor["path"]).open("rb") as source, capture_path.open("xb") as target:
            offset = cursor["size"]
            _identity(source, cursor, offset)
            prefix = _hash_prefix(source, offset)
            if cursor.get("prefix_sha256", prefix) != prefix:
                raise IntakeError("source prefix differs from start cursor")
            source.seek(offset)
            pending = b""
            reads = []
            previous = started
            while True:
                _identity(source, cursor, source.tell())
                block = source.read(1024 * 1024)
                completed = _utc(clock())
                if completed < previous:
                    raise IntakeError("intake clock rollback/backward movement")
                previous = completed
                pending += block
                if completed > deadline:
                    if pending:
                        capture_path.with_name(capture_path.stem + "-late.jsonl").write_bytes(
                            pending
                        )
                        if any(relevant(row) for row in _rows(pending)):
                            raise IntakeError("read completed after intake deadline/cutoff")
                    break
                boundary = pending.rfind(b"\n") + 1
                if boundary:
                    admitted, pending = pending[:boundary], pending[boundary:]
                    _rows(admitted)
                    target.write(admitted)
                    offset += len(admitted)
                    reads.append({"end": offset, "completed_at": completed.isoformat()})
                if completed == deadline and not block:
                    if pending:
                        capture_path.with_name(capture_path.stem + "-late.jsonl").write_bytes(
                            pending
                        )
                        raise IntakeError("partial incomplete newline at intake cutoff")
                    break
                if not block:
                    sleep(min(0.1, (deadline - completed).total_seconds()))
            target.flush()
            os.fsync(target.fileno())
            _identity(source, cursor, offset)
            if _hash_prefix(source, cursor["size"]) != prefix:
                raise IntakeError("source prefix changed during intake")
            source_hash = _hash_prefix(source, offset)
            source.seek(cursor["size"])
            if _digest(source.read(offset - cursor["size"])) != _digest(capture_path.read_bytes()):
                raise IntakeError("source changed during capture")
        checkpoint = {
            "status": "sealed",
            "cursor": cursor,
            "deadline": deadline.isoformat(),
            "started_at": started.isoformat(),
            "prefix_sha256": prefix,
            "source_sha256": source_hash,
            "admitted_offset": offset,
            "raw_sha256": _digest(capture_path.read_bytes()),
            "reads": reads,
        }
        checkpoint["sha256"] = _digest(_canonical(checkpoint))
        temporary = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(checkpoint, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(checkpoint_path)
        return verify_capture(
            cursor, capture_path, checkpoint_path, deadline=deadline, relevant=relevant
        )
    except OSError as exc:
        raise IntakeError(f"intake source/evidence I/O failure: {exc}") from exc
