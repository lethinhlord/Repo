from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from ml.evaluation_registry import transition
from ml.freeze_model import file_hash, sign_evidence, verify_frozen_manifest
from ml.inference import ModelRuntime
from ml.metrics import classification_metrics


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".evaluation-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(name, path)
        os.unlink(name)
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
    evidence_dir: Path | None = None,
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
    # The exact runtime validator must pass before reservation or any test read.
    runtime = ModelRuntime(package_dir, evidence_dir=evidence_dir)
    if runtime.locked_test_status != "UNOPENED":
        raise PermissionError("locked test has already been opened or evidence is invalid")
    evidence_path = runtime.evidence_dir
    evidence_path.mkdir(parents=True, exist_ok=True)
    opened_path = evidence_path / "LOCKED_TEST_OPENED.json"
    reservation_path = evidence_path / "LOCKED_TEST_RESERVED"
    metrics_path = evidence_path / "metrics_locked_test.json"
    if (opened_path.exists() or opened_path.is_symlink()
            or metrics_path.exists() or metrics_path.is_symlink()):
        raise PermissionError("locked test has already been opened for this model package")
    transition(package_dir, "locked_test", "RESERVED")
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
        directory_fd = os.open(evidence_path, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    metadata = runtime.metadata
    actual_test_hash = file_hash(locked_test_path)
    if actual_test_hash != metadata.get("locked_test_sha256"):
        raise PermissionError("locked test integrity check failed")
    bundle = runtime.bundle
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
            labels, probabilities, float(artifact["threshold"]),
            calibration_bins=int(metadata.get("calibration_bins", 10)),
        )
    output["locked_test_status"] = "EVALUATED"
    path = evidence_path / "metrics_locked_test.json"
    _atomic_write(path, output)
    opened = {
        "status": "EVALUATED",
        "model_version": freeze["model_version"],
        "evaluated_at_utc": datetime.now(UTC).isoformat(),
        "locked_test_sha256": actual_test_hash,
        "metrics_locked_test_sha256": file_hash(path),
        "freeze_sha256": hashlib.sha256(freeze_path.read_bytes()).hexdigest(),
    }
    _atomic_write(opened_path, sign_evidence(opened))
    transition(package_dir, "locked_test", "COMPLETE", files={
        path.name: file_hash(path) for path in (reservation_path, opened_path, metrics_path)
    })
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the immutable model on locked test data")
    parser.add_argument("--package-dir", type=Path, default=Path("ml/model-package"))
    parser.add_argument(
        "--locked-test", type=Path, default=Path("data/processed/locked_test.jsonl")
    )
    parser.add_argument("--unlock-locked-test", action="store_true")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    result = evaluate_locked_test(
        args.package_dir,
        args.locked_test,
        unlock_locked_test=args.unlock_locked_test,
        evidence_dir=args.evidence_dir,
    )
    print(f"Locked-test evaluation complete for {result['model_version']}")


if __name__ == "__main__":
    main()
