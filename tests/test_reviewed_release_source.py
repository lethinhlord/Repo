"""Check the real release tree, not only a synthetic policy fixture."""

import json
import subprocess
from pathlib import Path

from ml.collection_adoption import _collection_changes, verify_pilot_adoption
from ml.collection_release import digest

ROOT = Path(__file__).resolve().parents[1]


def test_stream_review_is_separately_pinned_without_exempting_collector_code():
    path = "config/stream-training-source-compatibility.json"
    before = {path: b"BUILD_PENDING", "ml/stream_dataset.py": b"original"}
    after = {**before, path: b"READY"}
    assert _collection_changes(before, after) == {}
    after["ml/stream_dataset.py"] = b"changed processing"
    assert set(_collection_changes(before, after)) == {"ml/stream_dataset.py"}


def test_repository_production_tree_matches_reviewed_pilot_transition():
    policy = json.loads(
        (ROOT / "config/collection-pilot-adoption.json").read_text(encoding="utf-8"),
    )
    # Equal stand-in runtime values isolate source/patch binding. This test does
    # not approve the real lab's Python/Node/package inventory or issue a receipt.
    runtime = {
        "python_version": "source-conformance-only", "node_version": "source-conformance-only",
        "installed_packages_sha256": "e" * 64,
    }
    pilot = {**policy["from_candidate"], **runtime}
    commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True,
    ).strip()
    current = {"commit": commit, "origin": pilot["origin"], **runtime}
    proof = verify_pilot_adoption(ROOT, pilot, current)
    assert proof["collection_patch_sha256"] == digest(policy["reviewed_collection_changes"])
