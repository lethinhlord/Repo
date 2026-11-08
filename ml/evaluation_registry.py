"""Durable consumption ledger, independent from disposable evaluation output directories.

Opening existing ledgers never creates storage. Signed chained events and a separately
persisted signed head detect deletion/truncation of either ledger or output evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ml.freeze_model import file_hash, sign_evidence, verify_evidence

KINDS = ("locked_test", "challenge")


def _payload_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def registry_paths(package: Path) -> tuple[Path, Path, str, str]:
    freeze_bytes = (package / "FROZEN.json").read_bytes()
    freeze_hash = hashlib.sha256(freeze_bytes).hexdigest()
    document = json.loads(freeze_bytes)
    registry_id = document.get("evaluation_registry_id", "legacy-" + freeze_hash)
    if not isinstance(registry_id, str) or not re.fullmatch(
        r"[a-f0-9]{32}|legacy-[a-f0-9]{64}", registry_id
    ):
        raise ValueError("invalid signed evaluation registry identifier")
    root = Path(
        os.getenv(
            "MODEL_EVALUATION_REGISTRY_DIR", str(package.parent / ".model-evaluation-registry")
        )
    ).absolute()
    if root == package.resolve() or package.resolve() in root.parents:
        raise ValueError("evaluation registry must be outside the immutable package")
    if root.resolve() != root:
        raise ValueError("evaluation registry must not traverse symlinks or junctions")
    ledger = root / f"{registry_id}.sqlite3"
    head = root / f"{registry_id}.head.json"
    if ledger.is_symlink() or head.is_symlink():
        raise ValueError("evaluation registry files must not be symlinks")
    return ledger, head, registry_id, freeze_hash


@contextmanager
def _registry_lock(package: Path):
    ledger, _, _, _ = registry_paths(package)
    path = ledger.with_suffix(".lock")
    if path.is_symlink() or not path.is_file():
        raise ValueError("evaluation registry lock missing; refuse reinitialization")
    with path.open("r+b") as stream:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _sync_directory(path: Path) -> None:
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _publish_head(path: Path, event: dict[str, Any], *, initial: bool = False) -> None:
    value = sign_evidence(
        {
            "registry_id": event["registry_id"],
            "freeze_sha256": event["freeze_sha256"],
            "sequence": event["sequence"],
            "event_sha256": _payload_hash(event),
        }
    )
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".registry-head-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        if initial:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def initialize_registry(package: Path, *, migration: dict[str, Any] | None = None) -> None:
    """Called only for a newly frozen release or an explicit signed legacy migration."""
    ledger, head, registry_id, freeze_hash = registry_paths(package)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    if head.exists():
        raise ValueError("evaluation registry head already exists; never reinitialize")
    # Exclusive creation is deliberate. Missing/broken existing storage is not repaired here.
    fd = os.open(ledger, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with ledger.with_suffix(".lock").open("xb") as stream:
        stream.write(b"0")
        stream.flush()
        os.fsync(stream.fileno())
    event = sign_evidence(
        {
            "registry_id": registry_id,
            "freeze_sha256": freeze_hash,
            "sequence": 0,
            "previous_sha256": None,
            "state": "REGISTERED",
            "initial_statuses": migration["statuses"]
            if migration
            else dict.fromkeys(KINDS, "UNOPENED"),
            "migration_receipt": migration,
            "timestamp_utc": datetime.now(UTC).isoformat(),
        }
    )
    with closing(sqlite3.connect(ledger)) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.executescript("""
            CREATE TABLE events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TRIGGER events_no_update BEFORE UPDATE ON events
            BEGIN SELECT RAISE(ABORT, 'evaluation ledger is append only'); END;
            CREATE TRIGGER events_no_delete BEFORE DELETE ON events
            BEGIN SELECT RAISE(ABORT, 'evaluation ledger is append only'); END;
        """)
        connection.execute(
            "INSERT INTO events VALUES (?, ?)", (0, json.dumps(event, sort_keys=True))
        )
        connection.commit()
    _publish_head(head, event, initial=True)
    _sync_directory(ledger.parent)


def _read(connection: sqlite3.Connection, head_path: Path, registry_id: str, freeze_hash: str):
    rows = connection.execute("SELECT sequence, payload FROM events ORDER BY sequence").fetchall()
    if not rows:
        raise ValueError("evaluation ledger has no signed registration")
    states: dict[str, dict[str, Any]] = {}
    previous = None
    for sequence, payload in rows:
        event = json.loads(payload)
        verify_evidence(event)
        if (
            sequence != event.get("sequence")
            or sequence != (0 if previous is None else previous["sequence"] + 1)
            or event.get("registry_id") != registry_id
            or event.get("freeze_sha256") != freeze_hash
            or event.get("previous_sha256")
            != (None if previous is None else _payload_hash(previous))
        ):
            raise ValueError("evaluation ledger chain integrity failed")
        if sequence == 0:
            statuses = event.get("initial_statuses", {})
            if (
                event.get("state") != "REGISTERED"
                or set(statuses) != set(KINDS)
                or any(value not in {"UNOPENED", "CONSUMED"} for value in statuses.values())
            ):
                raise ValueError("invalid evaluation registry registration")
            states = {kind: {"state": status} for kind, status in statuses.items()}
            migration_files = (event.get("migration_receipt") or {}).get(
                "evaluation_files_sha256",
                {},
            )
            for kind, files in migration_files.items():
                if kind not in states or statuses[kind] != "CONSUMED":
                    raise ValueError("invalid migrated evaluation state")
                states[kind] = {"state": "COMPLETE", "files_sha256": files}
        else:
            kind = event.get("kind")
            if kind not in states or (states[kind]["state"], event.get("state")) not in {
                ("UNOPENED", "RESERVED"),
                ("RESERVED", "COMPLETE"),
            }:
                raise ValueError("invalid evaluation ledger state transition")
            states[kind] = event
        previous = event
    head = json.loads(head_path.read_text(encoding="utf-8"))
    verify_evidence(head)
    if (
        head.get("registry_id") != registry_id
        or head.get("freeze_sha256") != freeze_hash
        or head.get("sequence") != previous["sequence"]
        or head.get("event_sha256") != _payload_hash(previous)
    ):
        raise ValueError("evaluation ledger and signed head disagree")
    return states, previous


def _connect(package: Path):
    ledger, head, registry_id, freeze_hash = registry_paths(package)
    if not ledger.is_file() or not head.is_file():
        raise ValueError("evaluation registry ledger/head missing; refuse reinitialization")
    connection = sqlite3.connect(
        ledger.as_uri() + "?mode=rw", uri=True, timeout=30, isolation_level=None
    )
    connection.execute("PRAGMA synchronous=FULL")
    return connection, head, registry_id, freeze_hash


def registry_status(package: Path) -> dict[str, dict[str, Any]]:
    with _registry_lock(package):
        return _registry_status_locked(package)


def _registry_status_locked(package: Path) -> dict[str, dict[str, Any]]:
    connection = None
    try:
        connection, head, registry_id, freeze_hash = _connect(package)
        return _read(connection, head, registry_id, freeze_hash)[0]
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"evaluation registry integrity failed: {exc}") from exc
    finally:
        if connection is not None:
            connection.close()


def transition(
    package: Path, kind: str, state: str, *, files: dict[str, str] | None = None
) -> None:
    with _registry_lock(package):
        _transition_locked(package, kind, state, files=files)


def _transition_locked(
    package: Path, kind: str, state: str, *, files: dict[str, str] | None = None
) -> None:
    connection = None
    try:
        connection, head, registry_id, freeze_hash = _connect(package)
        connection.execute("BEGIN IMMEDIATE")
        states, previous = _read(connection, head, registry_id, freeze_hash)
        expected = "UNOPENED" if state == "RESERVED" else "RESERVED"
        if (
            kind not in KINDS
            or state not in {"RESERVED", "COMPLETE"}
            or states[kind]["state"] != expected
        ):
            raise PermissionError("evaluation already consumed or reserved in durable registry")
        event = sign_evidence(
            {
                "registry_id": registry_id,
                "freeze_sha256": freeze_hash,
                "sequence": previous["sequence"] + 1,
                "previous_sha256": _payload_hash(previous),
                "kind": kind,
                "state": state,
                "files_sha256": files or {},
                "timestamp_utc": datetime.now(UTC).isoformat(),
            }
        )
        connection.execute(
            "INSERT INTO events VALUES (?, ?)",
            (event["sequence"], json.dumps(event, sort_keys=True)),
        )
        connection.execute("COMMIT")
        # A crash between commit and head publication is an integrity error, never UNOPENED.
        _publish_head(head, event)
    except (OSError, sqlite3.Error, KeyError, TypeError) as exc:
        raise ValueError(f"evaluation registry integrity failed: {exc}") from exc
    finally:
        if connection is not None:
            connection.close()


def check_output_evidence(package: Path, evidence: Path, kind: str) -> str:
    state = registry_status(package)[kind]
    status = state["state"]
    if status == "COMPLETE":
        files = state.get("files_sha256", {})
        expected = (
            {"LOCKED_TEST_RESERVED", "LOCKED_TEST_OPENED.json", "metrics_locked_test.json"}
            if kind == "locked_test"
            else {"CHALLENGE_RESERVED", "challenge_evaluation.json"}
        )
        if set(files) != expected:
            raise ValueError("evaluation ledger output inventory integrity failed")
        for name, digest in files.items():
            path = evidence / name
            if path.is_symlink() or not path.is_file() or file_hash(path) != digest:
                raise ValueError("evaluation registry consumed output evidence integrity failed")
    elif status == "CONSUMED":
        raise ValueError(
            "legacy evaluation registry records consumed evidence; restoration required"
        )
    return status


def migrate_legacy_registry(package: Path, receipt_path: Path, archive: Path) -> None:
    """Explicit administrator migration of an unbound v3 release, never loss recovery.

    A trusted signed attestation and immutable archived source receipts are required.
    Absence of files is never interpreted as evidence that test data was unopened.
    """
    from ml.evaluation_evidence import evidence_directory
    from ml.freeze_model import verify_frozen_manifest

    frozen = verify_frozen_manifest(package)
    if frozen.get("evaluation_registry_id"):
        raise ValueError("bound registry missing/corrupt: migration cannot reinitialize it")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    verify_evidence(receipt)
    statuses = receipt.get("statuses", {})
    if (
        receipt.get("format_version") != "evaluation-registry-migration-v1"
        or receipt.get("freeze_sha256") != file_hash(package / "FROZEN.json")
        or set(statuses) != set(KINDS)
        or any(value not in {"UNOPENED", "CONSUMED"} for value in statuses.values())
        or not isinstance(receipt.get("approved_by"), str)
        or not receipt["approved_by"].strip()
    ):
        raise ValueError("invalid signed evaluation registry migration receipt")
    if (
        "UNOPENED" in statuses.values()
        and receipt.get("affirmative_unopened_attestation") is not True
    ):
        raise ValueError(
            "migration requires affirmative unopened attestation from verified provenance"
        )
    sources = receipt.get("source_receipts")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("migration requires archived immutable source receipts")
    if receipt["freeze_sha256"] not in sources.values():
        raise ValueError("migration source receipts must include the original frozen manifest")
    for name, digest in sources.items():
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or name in {".", ".."}
            or (archive / name).is_symlink()
            or file_hash(archive / name) != digest
        ):
            raise ValueError("migration archived source receipt integrity failed")
    locations = {package, evidence_directory(package)}
    for kind, status in statuses.items():
        names = (
            ("LOCKED_TEST_RESERVED", "LOCKED_TEST_OPENED.json", "metrics_locked_test.json")
            if kind == "locked_test"
            else ("CHALLENGE_RESERVED", "challenge_evaluation.json")
        )
        if status == "UNOPENED" and any(
            (root / name).exists() or (root / name).is_symlink()
            for root in locations
            for name in names
        ):
            raise ValueError(
                "migration unopened attestation contradicts existing exposure evidence"
            )
    restored_files = receipt.get("evaluation_files_sha256", {})
    if not isinstance(restored_files, dict):
        raise ValueError("invalid migration evaluation evidence inventory")
    for kind, files in restored_files.items():
        required = (
            {"LOCKED_TEST_RESERVED", "LOCKED_TEST_OPENED.json", "metrics_locked_test.json"}
            if kind == "locked_test"
            else {"CHALLENGE_RESERVED", "challenge_evaluation.json"}
        )
        if (
            statuses.get(kind) != "CONSUMED"
            or not isinstance(files, dict)
            or set(files) != required
            or not set(files.values()) <= set(sources.values())
        ):
            raise ValueError("migration evaluation evidence must match archived source receipts")
        if not any(
            all(
                (root / name).is_file()
                and not (root / name).is_symlink()
                and file_hash(root / name) == digest
                for name, digest in files.items()
            )
            for root in locations
        ):
            raise ValueError("migration complete evaluation evidence is missing or changed")
    initialize_registry(package, migration=receipt)
