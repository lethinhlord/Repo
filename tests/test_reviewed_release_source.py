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
        # This transition authorizes the immutable historical training release.
        # Supplemental collection has a distinct, stricter precollection review;
        # changing the old adoption policy would rewrite historical evidence.
        ["git", "-C", str(ROOT), "rev-parse", "training-v2.0.0^{commit}"], text=True,
    ).strip()
    current = {"commit": commit, "origin": pilot["origin"], **runtime}
    proof = verify_pilot_adoption(ROOT, pilot, current)
    assert proof["collection_patch_sha256"] == digest(policy["reviewed_collection_changes"])


def test_supplemental_source_preserves_historical_policies_and_compiles_exactly():
    import yaml

    from ml.supplemental_catalog import compile_catalog
    from ml.supplemental_design import load_design

    for relative in (
        "config/collection-pilot-adoption.json",
        "config/training-source-compatibility.json",
        "config/stream-training-source-compatibility.json",
    ):
        historical = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", "training-v2.0.0:" + relative],
        )
        # Git text objects are LF, independent of local checkout autocrlf.
        assert (ROOT / relative).read_text(encoding="utf-8") == historical.decode()
    design = load_design(ROOT / "config/supplemental-design.yaml")
    base = yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_bytes())
    actual = yaml.safe_load((ROOT / "config/supplemental-catalog.yaml").read_bytes())
    assert actual == compile_catalog(design, base)
    review = json.loads((ROOT / "config/supplemental-training-review.json").read_bytes())
    assert review["collection_candidate_tag"] == design["candidate_tag"]
    assert review["status"] in {"PREPARATION_IN_PROGRESS", "COLLECTION_READY", "READY"}
    # Future data approval cannot be inferred from preparation/collection approval.
    if review["status"] != "READY":
        assert review["approved_manifest_sha256"] is None


def test_development_scope_preserves_formal_policy_and_compiles_its_own_catalog():
    import yaml

    from ml.supplemental_catalog import compile_catalog
    from ml.supplemental_design import load_design

    historical = subprocess.check_output([
        "git", "-C", str(ROOT), "show",
        "supplemental-collection-v1.0.0-candidate.1:config/supplemental-training-review.json",
    ])
    assert (ROOT / "config/supplemental-training-review.json").read_bytes() == historical
    design = load_design(ROOT / "config/development-design.yaml")
    base = yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_bytes())
    assert yaml.safe_load((ROOT / "config/development-catalog.yaml").read_bytes()) == (
        compile_catalog(design, base)
    )
