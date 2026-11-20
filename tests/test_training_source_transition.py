"""Only an explicitly reviewed immutable manifest may outlive its processor code."""

import copy
import hashlib
import json

import pytest
from test_training_sources import commit, git
from test_training_sources import reviewed as reviewed
from test_training_sources_hardening import handoff as handoff

from ml import training_sources as sources
from ml.training import verify_builder_provenance


@pytest.fixture
def transition(handoff):
    (root, *_), _, manifest, partitions = handoff
    before = git(root, "rev-parse", "HEAD")
    path = root / sources.POLICY_RELATIVE
    old_bytes = path.read_bytes()
    policy = json.loads(old_bytes)
    approval = {
        "builder_commit": before,
        "policy_sha256": hashlib.sha256(old_bytes).hexdigest(),
        "processing_sha256": policy["processing_sha256"],
    }
    (root / "module.py").write_text("version = 3\n", encoding="utf-8")
    commit(root)
    policy["processing_sha256"] = sources.processing_hash(root)
    policy["approved_training_manifests"] = {sources.digest(manifest): approval}
    path.write_text(json.dumps(policy), encoding="utf-8")
    after = commit(root)
    return root, manifest, partitions, before, after


def test_reviewed_training_transition_preserves_original_manifest_and_records(transition):
    root, manifest, partitions, before, after = transition
    original = copy.deepcopy(manifest)
    sources.verify_training_manifest(manifest, partitions, root=root, expected_commit=after)
    assert manifest == original
    assert manifest["provenance"]["builder_git_commit"] == before != after


@pytest.mark.parametrize("mutation", ["audit", "row", "source", "approval", "policy", "data"])
def test_training_transition_rejects_mutated_manifest_rows_or_source(transition, mutation):
    root, manifest, partitions, _, after = transition
    if mutation == "audit":
        manifest["collection_audit"]["report_sha256"] = "0" * 64
    elif mutation == "row":
        partitions["train"][0]["label"] = 1
    elif mutation == "source":
        (root / "module.py").write_text("version = 999\n", encoding="utf-8")
    else:
        path = root / sources.POLICY_RELATIVE
        policy = json.loads(path.read_text())
        if mutation == "approval":
            next(iter(policy["approved_training_manifests"].values()))["policy_sha256"] = "0" * 64
        elif mutation == "policy":
            policy["approved_training_manifests"] = {}
        else:
            next(iter(policy["approved_runs"].values()))["record_sha256"] = "0" * 64
        path.write_text(json.dumps(policy), encoding="utf-8")
        after = commit(root)
    with pytest.raises(ValueError):
        sources.verify_training_manifest(manifest, partitions, root=root, expected_commit=after)


def test_prior_builder_sha_cannot_impersonate_the_executing_trainer(transition):
    root, manifest, partitions, before, _ = transition
    with pytest.raises(ValueError, match="executing|pinned|provenance"):
        sources.verify_training_manifest(manifest, partitions, root=root, expected_commit=before)


def test_public_builder_provenance_delegates_only_to_reviewed_v3(transition, monkeypatch):
    root, manifest, _, _, after = transition
    monkeypatch.setattr(sources, "ROOT", root)
    verify_builder_provenance(manifest, config_path=None, expected_commit=after)
    legacy = copy.deepcopy(manifest)
    legacy["manifest_version"] = "dataset-manifest-v2"
    with pytest.raises(ValueError, match="builder commit differs"):
        verify_builder_provenance(legacy, config_path=None, expected_commit=after)
