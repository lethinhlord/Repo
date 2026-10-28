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


def bucket_used(root: Path, asset: str, started: datetime) -> bool:
    if _slot(root, asset, started).exists():
        return True
    # Recover conservatively from receipts if the reservation index was lost or
    # restored from an earlier backup. Aborted/quarantined traffic still exists.
    for relative in ("evidence/scenario-runs", "evidence/quarantine"):
        for receipt_path in (root / relative).glob("*/execution_receipt.json"):
            try:
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                draft = json.loads(
                    (receipt_path.parent / "ground_truth.json").read_text(encoding="utf-8")
                )
                if (
                    not isinstance(receipt, dict) or not isinstance(draft, dict)
                    or not isinstance(receipt.get("aggregation_window_start"), str)
                    or not isinstance(draft.get("host"), str) or not draft["host"].strip()
                ):
                    raise ValueError("receipt recovery requires a host and timezone-aware bucket")
                window = datetime.fromisoformat(
                    receipt["aggregation_window_start"].replace("Z", "+00:00")
                )
                if window.tzinfo is None or window.utcoffset() is None:
                    raise ValueError("bucket has no timezone")
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"cannot recover collection bucket: {receipt_path}") from exc
            if draft["host"].casefold() == asset.casefold() and window == started:
                return True
    return False


def reserve_bucket(root: Path, asset: str, started: datetime, run_id: str) -> None:
    path = _slot(root, asset, started)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({
        "version": "collection-bucket-v1", "asset": asset,
        "bucket_start": started.isoformat(), "run_id": run_id,
    }, sort_keys=True).encode() + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("aggregation window already reserved; wait for a new bucket") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
