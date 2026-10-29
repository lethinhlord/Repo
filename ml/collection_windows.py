"""Durable, conservative reservations for isolated collection windows."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path


def _slot(root: Path, asset: str, started: datetime) -> Path:
    key = hashlib.sha256(asset.strip().casefold().encode()).hexdigest()[:24]
    return root / "evidence/bucket-reservations" / f"{key}-{int(started.timestamp())}.json"


def _safe_path(root: Path, path: Path) -> None:
    """Reject linked/reparse inputs and paths escaping the evidence root."""
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("recovery evidence escapes project root")
    for part in (path, *path.parents):
        if part == root.parent:
            break
        if part.exists() and (
            part.is_symlink() or getattr(part.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("linked recovery evidence is not permitted")


def _recover_quarantined_receipt(root: Path, directory: Path) -> dict | None:
    """Recover ownership only; never repair or replace the damaged original.

    The finalized checksum manifest, metadata, frozen start contract, state copy
    of the receipt and independent reservation must all agree. There is no
    cached exemption: every source is checked again on every lookup.
    """
    from ml.scenario_collection import CollectionError, _verify_start_snapshot

    _safe_path(root, directory)
    for source_path in directory.iterdir():
        _safe_path(root, source_path)

    def read(name: str) -> dict:
        value = json.loads((directory / name).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"invalid recovery evidence: {name}")
        return value

    state = read(".collection_state.json")
    marker = read("quarantine.json")
    run_id = directory.name
    if any(value.get("run_id") != run_id for value in (state, marker)):
        raise ValueError("recovery run identity mismatch")
    if marker.get("status") != "QUARANTINED":
        raise ValueError("invalid quarantine marker")
    try:
        _verify_start_snapshot(directory, state, root)
    except CollectionError as exc:
        raise ValueError(str(exc)) from exc
    receipt = state.get("execution_receipt")
    receipt_path = directory / "execution_receipt.json"
    # FINALIZING is written only after finalized metadata and checksums exist.
    # This recovers bucket ownership, not the interrupted run's validity.
    finalized = state.get("status") in {"FINALIZING", "FINALIZED"}
    if not finalized:
        if state.get("status") not in {"STARTED", "ABORTED"}:
            raise ValueError("unsupported quarantined collection state")
        if receipt is None:
            if receipt_path.exists() or (directory / "collection_metadata.json").exists():
                raise ValueError("receipt-free state conflicts with evidence")
            for reservation_path in (root / "evidence/bucket-reservations").glob("*.json"):
                _safe_path(root, reservation_path)
                reservation = json.loads(reservation_path.read_text(encoding="utf-8"))
                if reservation.get("run_id") == run_id:
                    raise ValueError("receipt-free state conflicts with reservation")
            return None
    if not isinstance(receipt, dict) or receipt.get("run_id") != run_id:
        raise ValueError("missing frozen receipt ownership")
    if receipt.get("frozen_parameters_sha256") != state.get("frozen_parameters_sha256"):
        raise ValueError("receipt differs from frozen parameters")
    if not receipt_path.is_file():
        raise ValueError("missing required execution receipt; restore verified backup")
    if not finalized:
        if read("execution_receipt.json") != receipt:
            raise ValueError("nonfinal receipt differs from state")
        _verify_reservation(root, state["draft"]["host"], receipt, run_id)
        return receipt
    metadata = read("collection_metadata.json")
    if metadata.get("run_id") != run_id or metadata.get("status") != "FINALIZED":
        raise ValueError("finalized metadata identity mismatch")
    entries = {}
    for line in (directory / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        if (
            name in entries
            or Path(name).name != name
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("invalid recovery checksum manifest")
        entries[name] = digest
        if (
            name != "execution_receipt.json"
            and hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest
        ):
            raise ValueError(f"recovery source hash mismatch: {name}")
    required = {
        "execution_receipt.json",
        "collection_metadata.json",
        "ground_truth.json",
        "start-contract.json",
        "execution-parameters.json",
    }
    if not required <= entries.keys():
        raise ValueError("recovery checksum manifest lacks required evidence")
    expected_files = {path.name for path in directory.iterdir() if path.is_file()} - {
        ".collection_state.json",
        "checksums.sha256",
        "quarantine.json",
        "bucket_recovery.json",
    }
    if set(entries) != expected_files:
        raise ValueError("recovery manifest file inventory differs from evidence")
    serialized = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    candidate_hashes = {
        hashlib.sha256(serialized.replace("\n", newline).encode()).hexdigest()
        for newline in ("\n", "\r\n")
    }
    expected = entries["execution_receipt.json"]
    if expected not in candidate_hashes or metadata.get("execution_receipt_sha256") != expected:
        raise ValueError("frozen receipt hash mismatch")
    for field in ("start_contract_sha256", "frozen_parameters_sha256"):
        if metadata.get(field) != state.get(field):
            raise ValueError("recovery metadata differs from frozen state")
    host = state["draft"]["host"]
    window = datetime.fromisoformat(receipt["aggregation_window_start"].replace("Z", "+00:00"))
    if window.tzinfo is None or window.utcoffset() is None:
        raise ValueError("recovery bucket has no timezone")
    intact = hashlib.sha256(receipt_path.read_bytes()).hexdigest() == expected
    reservation_path = _slot(root, host, window)
    if reservation_path.exists() or not intact or (directory / "bucket_recovery.json").exists():
        _verify_reservation(root, host, receipt, run_id)
    if intact and not (directory / "bucket_recovery.json").exists():
        return receipt
    record = {
        "version": "quarantine-bucket-recovery-v1",
        "run_id": run_id,
        "asset": host,
        "bucket_start": window.isoformat(),
        "expected_receipt_sha256": expected,
        "source_sha256": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in (*entries, "checksums.sha256", ".collection_state.json", "quarantine.json")
        },
        "reservation_sha256": hashlib.sha256(_slot(root, host, window).read_bytes()).hexdigest(),
    }
    record_path = directory / "bucket_recovery.json"
    try:
        descriptor = os.open(record_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if read("bucket_recovery.json") != record:
            raise ValueError("recovery record or source hashes changed") from None
    else:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write((json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
            handle.flush()
            os.fsync(handle.fileno())
    return receipt


def _verify_reservation(root: Path, host: str, receipt: dict, run_id: str) -> None:
    window = datetime.fromisoformat(receipt["aggregation_window_start"].replace("Z", "+00:00"))
    path = _slot(root, host, window)
    _safe_path(root, path)
    reservation = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(reservation, dict)
        or reservation.get("version") != "collection-bucket-v1"
        or reservation.get("run_id") != run_id
        or reservation.get("asset", "").strip().casefold() != host.strip().casefold()
        or datetime.fromisoformat(reservation["bucket_start"]) != window
    ):
        raise ValueError("reservation conflicts with frozen ownership")


def bucket_used(root: Path, asset: str, started: datetime) -> bool:
    if _slot(root, asset, started).exists():
        return True
    # Recover conservatively from receipts if the reservation index was lost or
    # restored from an earlier backup. Aborted/quarantined traffic still exists.
    for relative in ("evidence/scenario-runs", "evidence/quarantine"):
        for directory in (root / relative).glob("*"):
            if not directory.is_dir():
                continue
            receipt_path = directory / "execution_receipt.json"
            if relative == "evidence/scenario-runs" and not receipt_path.exists():
                continue
            try:
                if relative == "evidence/quarantine":
                    receipt = _recover_quarantined_receipt(root, directory)
                    if receipt is None:
                        continue
                else:
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                draft = json.loads(
                    (receipt_path.parent / "ground_truth.json").read_text(encoding="utf-8")
                )
                if (
                    not isinstance(receipt, dict)
                    or not isinstance(draft, dict)
                    or not isinstance(receipt.get("aggregation_window_start"), str)
                    or not isinstance(draft.get("host"), str)
                    or not draft["host"].strip()
                ):
                    raise ValueError("receipt recovery requires a host and timezone-aware bucket")
                window = datetime.fromisoformat(
                    receipt["aggregation_window_start"].replace("Z", "+00:00")
                )
                if window.tzinfo is None or window.utcoffset() is None:
                    raise ValueError("bucket has no timezone")
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise ValueError(
                    f"cannot recover collection bucket: {receipt_path}; preserve evidence and "
                    "restore matching immutable snapshots, finalized metadata and original "
                    "reservation from a verified backup before retrying"
                ) from exc
            if draft["host"].casefold() == asset.casefold() and window == started:
                return True
    return False


def reserve_bucket(root: Path, asset: str, started: datetime, run_id: str) -> None:
    path = _slot(root, asset, started)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            {
                "version": "collection-bucket-v1",
                "asset": asset,
                "bucket_start": started.isoformat(),
                "run_id": run_id,
            },
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("aggregation window already reserved; wait for a new bucket") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
