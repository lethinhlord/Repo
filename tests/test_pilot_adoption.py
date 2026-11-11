"""Reviewed G7-only migration never silently accepts changed collection code."""

import hashlib
import json
import subprocess

import pytest

from ml.collection_release import ReleaseError, digest


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@pytest.fixture
def migration(tmp_path):
    from ml.collection_adoption import _archive_files, _collection_changes

    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Synthetic fixture")
    git(tmp_path, "config", "user.email", "fixture@example.invalid")
    for rel, content in {
        "ml/feature_pipeline.py": "observations = 24\n",
        "ml/collection_release.py": "gate = 1\n",
        "config/collection-design.yaml": "candidate_tag: old\n",
    }.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "Old collection fixture")
    old_commit = git(tmp_path, "rev-parse", "HEAD")
    old_files = _archive_files(tmp_path, old_commit)
    old = {
        "commit": old_commit, "tag": "old", "tag_object": "b" * 40,
        "origin": "https://github.com/lethinhlord/Repo.git",
        "tracked_files_sha256": digest({
            p: hashlib.sha256(b).hexdigest() for p, b in old_files.items()
        }),
        "python_version": "unit", "node_version": "unit", "installed_packages_sha256": "c" * 64,
    }
    (tmp_path / "ml/collection_release.py").write_text("gate = 2\n")
    (tmp_path / "config/collection-design.yaml").write_text("candidate_tag: new\n")
    current_files = {p: (tmp_path / p).read_bytes() for p in old_files}
    policy = {
        "version": "reviewed-pilot-adoption-v1",
        "from_candidate": {k: old[k] for k in (
            "commit", "tag", "tag_object", "origin", "tracked_files_sha256",
        )},
        "collection_patch_sha256": digest(_collection_changes(old_files, current_files)),
    }
    (tmp_path / "config/collection-pilot-adoption.json").write_text(json.dumps(policy))
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "Reviewed G7 migration fixture")
    current = {**old, "commit": git(tmp_path, "rev-parse", "HEAD"), "tag": "new"}
    return tmp_path, old, current


def test_reviewed_gate_patch_preserves_original_pilot_identity(migration):
    from ml.collection_adoption import verify_pilot_adoption

    root, old, current = migration
    proof = verify_pilot_adoption(root, old, current)
    assert proof["from_candidate"] == {k: old[k] for k in proof["from_candidate"]}
    assert proof["collection_patch_sha256"]


@pytest.mark.parametrize("change", ["runtime", "pilot_tree", "collection_code"])
def test_adoption_rejects_unreviewed_or_incompatible_changes(migration, change):
    from ml.collection_adoption import verify_pilot_adoption

    root, old, current = migration
    if change == "runtime":
        current["python_version"] = "different"
    elif change == "pilot_tree":
        old["tracked_files_sha256"] = "f" * 64
    else:
        (root / "ml/feature_pipeline.py").write_text("observations = 0\n")
        git(root, "add", ".")
        git(root, "commit", "-qm", "Unreviewed observation change")
        current["commit"] = git(root, "rev-parse", "HEAD")
    with pytest.raises(ReleaseError):
        verify_pilot_adoption(root, old, current)
