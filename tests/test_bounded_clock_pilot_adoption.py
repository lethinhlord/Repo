import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ml.collection_adoption import _collection_changes, verify_pilot_adoption
from ml.collection_release import ReleaseError, digest


def test_v2_exact_review_rejects_extra_changes(tmp_path):
    old = b"old feature"
    new = b"new feature"
    before = {"ml/feature_pipeline.py": old}
    after = {"ml/feature_pipeline.py": new}
    identity = {
        "commit": "1" * 40, "tag": "old", "tag_object": "2" * 40,
        "origin": "https://github.com/lethinhlord/Repo.git",
        "tracked_files_sha256": digest({"ml/feature_pipeline.py": hashlib.sha256(old).hexdigest()}),
    }
    runtime = {
        "python_version": "3.14", "node_version": "v22", "installed_packages_sha256": "f" * 64,
    }
    pilot = {**identity, **runtime}
    current = {"commit": "3" * 40, "origin": pilot["origin"], **runtime}
    reviewed = _collection_changes(before, after)
    policy = {
        "version": "reviewed-pilot-adoption-v2",
        "from_candidate": identity, "reviewed_scope": ["ml/feature_pipeline.py"],
        "reviewed_collection_changes": reviewed, "collection_patch_sha256": digest(reviewed),
    }
    p = tmp_path / "config/collection-pilot-adoption.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps(policy))
    with (
        patch("ml.collection_adoption.subprocess.run", return_value=SimpleNamespace(returncode=0)),
        patch("ml.collection_adoption._archive_files", side_effect=[before, after]),
    ):
        result = verify_pilot_adoption(tmp_path, pilot, current)
    assert result["collection_patch_sha256"] == digest(reviewed)
    after["scripts/other.py"] = b"unreviewed"
    with (
        patch("ml.collection_adoption.subprocess.run", return_value=SimpleNamespace(returncode=0)),
        patch("ml.collection_adoption._archive_files", side_effect=[before, after]),
        pytest.raises(ReleaseError, match="unreviewed production change"),
    ):
        verify_pilot_adoption(tmp_path, pilot, current)
    bad_runtime = {**current, "node_version": "different"}
    with pytest.raises(ReleaseError, match="same runtime"):
        verify_pilot_adoption(tmp_path, pilot, bad_runtime)
