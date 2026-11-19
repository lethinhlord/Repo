"""Explicitly reviewed pilot reuse; frozen pilot source/runtime identities stay intact."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

from ml.collection_release import ReleaseError, digest

POLICY = "config/collection-pilot-adoption.json"
IDENTITY = ("commit", "tag", "tag_object", "origin", "tracked_files_sha256")
RUNTIME = ("python_version", "node_version", "installed_packages_sha256")


def _archive_files(root: Path, commit: str) -> dict[str, bytes]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "archive", commit],
            capture_output=True, check=True, timeout=30,
        )
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            return {
                item.name: archive.extractfile(item).read() for item in archive if item.isfile()
            }
    except (OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        raise ReleaseError("cannot verify pilot source commit tree") from exc


def _collection_changes(before: dict[str, bytes], after: dict[str, bytes]) -> dict:
    """Bind every production change; exclude only the policy itself and documentation/tests."""
    changes = {}
    for name in sorted(before.keys() | after.keys()):
        if name == POLICY or name.startswith(("docs/", "tests/", "tasks/")):
            continue
        if before.get(name) != after.get(name):
            changes[name] = {
                side: hashlib.sha256(files[name]).hexdigest() if name in files else None
                for side, files in (("before", before), ("after", after))
            }
    return changes


def verify_pilot_adoption(root: Path, pilot: dict, current: dict) -> dict:
    """Verify an explicitly scoped, immutable pilot-source transition.

    V1 is kept for already-frozen acceptances. V2 is a new source review,
    not a mutation of a previous review or a waiver of quality gates.
    """
    try:
        raw_policy = (root / POLICY).read_bytes()
        policy = json.loads(raw_policy)
        version = policy.get("version")
        identity = {key: pilot[key] for key in IDENTITY}
        if (
            version not in {"reviewed-pilot-adoption-v1", "reviewed-pilot-adoption-v2"}
            or policy.get("from_candidate") != identity
            or pilot["origin"] != current["origin"]
            or any(not pilot.get(key) or pilot[key] != current.get(key) for key in RUNTIME)
        ):
            raise ReleaseError("pilot adoption requires the reviewed source and same runtime")
        ancestor = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor",
             pilot["commit"], current["commit"]],
            capture_output=True, timeout=30,
        )
        if ancestor.returncode != 0:
            raise ReleaseError("pilot source must be an ancestor of the collection candidate")
        before = _archive_files(root, pilot["commit"])
        after = _archive_files(root, current["commit"])
        tree_hash = digest({
            name: hashlib.sha256(content).hexdigest() for name, content in before.items()
        })
        if tree_hash != pilot["tracked_files_sha256"]:
            raise ReleaseError("pilot source tree differs from its frozen fingerprint")
        changes = _collection_changes(before, after)
        patch_hash = digest(changes)
        if version == "reviewed-pilot-adoption-v2":
            reviewed = policy.get("reviewed_collection_changes")
            scope = policy.get("reviewed_scope")
            if (
                not isinstance(reviewed, dict)
                or scope not in (["ml/feature_pipeline.py"], ["config/collection-design.yaml", "ml/collection_adoption.py", "ml/feature_pipeline.py"])
                or set(reviewed) != set(scope)
                or changes != reviewed
                or patch_hash != policy.get("collection_patch_sha256")
            ):
                raise ReleaseError("unreviewed production change in bounded Sysmon clock transition")
        elif patch_hash != policy.get("collection_patch_sha256"):
            raise ReleaseError("collection code or contract changed outside the reviewed G7 patch")
        return {
            "version": version, "from_candidate": identity,
            "policy_sha256": hashlib.sha256(raw_policy).hexdigest(),
            "collection_patch_sha256": patch_hash,
        }
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        raise ReleaseError(f"pilot adoption verification failed: {exc}") from exc
