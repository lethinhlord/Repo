"""Private raw/evidence backup with a real restore validation under the collector lock."""

from __future__ import annotations

import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from ml import collection_release
from ml.collection_lock import CollectionLockError, collection_operation
from ml.collection_release import (
    ReleaseError,
    _extract_backup,
    _file_hash,
    _read_json,
)


def _run_inventory(root: Path) -> tuple[list[str], list[str]]:
    states = {}
    evidence_root = root / "evidence/scenario-runs"
    for directory in evidence_root.iterdir() if evidence_root.exists() else ():
        if not directory.is_dir():
            continue
        state_path = directory / ".collection_state.json"
        if not state_path.is_file():
            raise ReleaseError(f"run evidence is missing state: {directory.name}")
        state = _read_json(state_path)
        if state.get("run_id") != directory.name:
            raise ReleaseError(f"run state identity mismatch: {directory.name}")
        status = state.get("status")
        if status not in {"FINALIZED", "ABORTED"}:
            raise ReleaseError("backup refused while a collection is active or incomplete")
        states[directory.name] = status
    runs = sorted(rid for rid, status in states.items() if status == "FINALIZED")
    raw_root = root / "data/raw"
    raw_runs = (
        {p.name for p in raw_root.iterdir() if p.is_dir()} if raw_root.exists() else set()
    )
    if raw_runs != set(runs):
        raise ReleaseError("finalized state and raw run inventories disagree")
    for rid in runs:
        if not (raw_root / rid / "scenario_manifest.json").is_file():
            raise ReleaseError(f"finalized run is missing its manifest: {rid}")
    aborted_runs = sorted(rid for rid, status in states.items() if status == "ABORTED")
    return runs, aborted_runs


def create_backup(root: Path, tag: str, output: Path) -> dict:
    from ml.scenario_collection import validate_run

    root, output = Path(root).resolve(), Path(output).resolve()
    if output.is_relative_to(root):
        raise ReleaseError("backup directory must be outside the source checkout")
    if output.exists():
        raise ReleaseError("backup output already exists; choose a fresh directory")
    try:
        with collection_operation(root):
            if (root / "evidence/scenario-runs/.active-run.json").exists():
                raise ReleaseError("close the active run before backup")
            runs, aborted_runs = _run_inventory(root)
            candidate = collection_release.capture_candidate(root, tag)
            if not runs:
                raise ReleaseError("backup requires finalized raw data")
            for rid in runs:
                validate_run(rid, root)
            output.mkdir(parents=True, mode=0o700)
            archive = output / (
                "collection-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".tar.gz"
            )
            with tarfile.open(archive, "x:gz") as tar:
                for rel in (
                    "data/raw",
                    "data/quarantine",
                    "evidence/scenario-runs",
                    "evidence/quarantine",
                    "evidence/bucket-reservations",
                    "evidence/context-captures",
                    "evidence/context-baseline.json",
                    "evidence/collection-acceptance.json",
                    "evidence/collection-candidate.json",
                    "run-drafts",
                    "operator-logs",
                ):
                    path = root / rel
                    if not path.exists():
                        continue
                    entries = [path, *path.rglob("*")] if path.is_dir() else [path]
                    if any(
                        p.is_symlink()
                        or any(
                            n.startswith(".env") or n.endswith((".pem", ".key"))
                            for n in p.relative_to(root).parts
                        )
                        for p in entries
                    ):
                        raise ReleaseError("unsupported link/secret in private backup inputs")
                    tar.add(path, arcname=rel, recursive=True)
            for name, value in {
                "git-commit.txt": candidate["commit"],
                "source-tag.txt": tag,
                "source-tag-object.txt": candidate["tag_object"],
                "source-url.txt": candidate["origin"],
            }.items():
                (output / name).write_text(value + "\n", encoding="utf-8")
            with tempfile.TemporaryDirectory(prefix="datn-backup-restore-") as temp:
                restored = Path(temp)
                _extract_backup(archive, restored)
                if _run_inventory(restored) != (runs, aborted_runs):
                    raise ReleaseError("restored run inventory differs from source")
                for rid in runs:
                    validate_run(rid, restored)
            report = {
                "status": "BACKUP_RESTORED_AND_VALIDATED",
                "directory": str(output),
                "archive": archive.name,
                "archive_sha256": _file_hash(archive),
                "validated_runs": runs,
                "aborted_runs": aborted_runs,
                "candidate": candidate,
            }
            import json

            (output / "restore-report.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (output / "checksums.sha256").write_text(
                "".join(f"{_file_hash(p)}  {p.name}\n" for p in sorted(output.iterdir())),
                encoding="utf-8",
            )
            return report
    except CollectionLockError as exc:
        raise ReleaseError(str(exc)) from exc
