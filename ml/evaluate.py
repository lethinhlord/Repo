from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from ml.freeze_model import file_hash, verify_frozen_manifest
from ml.metrics import classification_metrics


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".evaluation-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def evaluate_locked_test(
    package_dir: Path,
    locked_test_path: Path,
    *,
    unlock_locked_test: bool,
) -> dict[str, Any]:
    if not unlock_locked_test:
        raise PermissionError(
            "locked test access denied; pass --unlock-locked-test only after the Week 6 freeze gate"
        )
    freeze_path = package_dir / "FROZEN.json"
    if not freeze_path.is_file():
        raise PermissionError("model package must be frozen before opening the locked test")
    try:
        freeze = verify_frozen_manifest(package_dir)
    except ValueError as exc:
        raise PermissionError(str(exc)) from exc
    opened_path = package_dir / "LOCKED_TEST_OPENED.json"
    reservation_path = package_dir / "LOCKED_TEST_RESERVED"
    if opened_path.exists():
        raise PermissionError("locked test has already been opened for this model package")
    try:
        fd = os.open(reservation_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise PermissionError(
            "locked test has already been opened or reserved for this model package"
        ) from exc
    with os.fdopen(fd, "wb") as reservation:
        reservation.write(b"Locked test opening reserved; do not remove or retry.\n")
        reservation.flush()
        os.fsync(reservation.fileno())
    # Persist the directory entry where supported, before reading the locked test.
    if os.name != "nt":
        directory_fd = os.open(package_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    metadata = json.loads((package_dir / "metadata.json").read_text(encoding="utf-8"))
    actual_test_hash = file_hash(locked_test_path)
    if actual_test_hash != metadata.get("locked_test_sha256"):
        raise PermissionError("locked test integrity check failed")
    bundle = joblib.load(package_dir / "model.joblib")
    rows = [
        json.loads(line)
        for line in locked_test_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    output: dict[str, Any] = {"model_version": freeze["model_version"], "families": {}}
    for family, artifact in bundle["families"].items():
        subset = [row for row in rows if row["family"] == family]
        if not subset:
            raise ValueError(f"locked test has no records for family {family}")
        x = np.asarray(
            [[row["features"][name] for name in artifact["feature_order"]] for row in subset]
        )
        labels = np.asarray([row["label"] for row in subset], dtype=int)
        if set(labels.tolist()) != {0, 1}:
            raise ValueError(f"locked test must contain both labels for family {family}")
        probabilities = artifact["estimator"].predict_proba(x)[:, 1]
        output["families"][family] = classification_metrics(
            labels, probabilities, float(artifact["threshold"])
        )
    output["locked_test_status"] = "EVALUATED"
    path = package_dir / "metrics_locked_test.json"
    _atomic_write(path, output)
    opened = {
        "status": "EVALUATED",
        "model_version": freeze["model_version"],
        "evaluated_at_utc": datetime.now(UTC).isoformat(),
        "locked_test_sha256": actual_test_hash,
        "metrics_locked_test_sha256": file_hash(path),
        "freeze_sha256": hashlib.sha256(freeze_path.read_bytes()).hexdigest(),
    }
    _atomic_write(opened_path, opened)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the immutable model on locked test data")
    parser.add_argument("--package-dir", type=Path, default=Path("ml/model-package"))
    parser.add_argument(
        "--locked-test", type=Path, default=Path("data/processed/locked_test.jsonl")
    )
    parser.add_argument("--unlock-locked-test", action="store_true")
    args = parser.parse_args()
    result = evaluate_locked_test(
        args.package_dir,
        args.locked_test,
        unlock_locked_test=args.unlock_locked_test,
    )
    print(f"Locked-test evaluation complete for {result['model_version']}")


if __name__ == "__main__":
    main()
