"""Trusted evidence root: one write-once namespace per immutable freeze digest."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


def evidence_directory(package_dir: Path, evidence_dir: Path | None = None) -> Path:
    deployment_root = os.getenv("MODEL_EVALUATION_EVIDENCE_DIR")
    if (
        deployment_root
        and evidence_dir
        and Path(deployment_root).resolve() != evidence_dir.resolve()
    ):
        raise ValueError("evidence directory differs from the configured deployment evidence root")
    configured = evidence_dir or deployment_root
    if configured is None:
        return package_dir  # Legacy releases keep their original evidence location.
    root = Path(configured).absolute()
    package = package_dir.resolve()
    if root == package or package in root.parents:
        raise ValueError("evaluation evidence root must be outside the immutable package")
    # Reject aliases, including Windows junctions, so the configured path is the contract.
    if root.resolve() != root:
        raise ValueError("evaluation evidence root must not traverse symlinks or junctions")
    digest = hashlib.sha256((package_dir / "FROZEN.json").read_bytes()).hexdigest()
    target = root / digest
    if target.is_symlink() or target.resolve() != target:
        raise ValueError("evaluation evidence namespace must not be a symlink or junction")
    return target


def runtime_policy_hash() -> str:
    """Bind replay to inference gates and the request contract used during training."""
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for relative in ("ml/inference.py", "api/app/contracts.py"):
        digest.update(relative.encode())
        digest.update((root / relative).read_text(encoding="utf-8").encode())
    return digest.hexdigest()
