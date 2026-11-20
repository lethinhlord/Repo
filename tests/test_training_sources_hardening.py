"""Adversarial checks use a tiny synthetic Git history, never lab collection data."""

from __future__ import annotations

import copy

import pytest
from test_training_sources import git
from test_training_sources import reviewed as reviewed

from ml import training_sources as sources


@pytest.fixture
def handoff(reviewed):
    root, raw, evidence, ids, rows, policy, calls = reviewed
    certificate = sources.verify_training_sources(
        root, raw, evidence, ids, root / sources.POLICY_RELATIVE,
    )
    manifest = {
        "manifest_version": "dataset-manifest-v3",
        "provenance": {
            "builder_git_commit": git(root, "rev-parse", "HEAD"),
            "source_compatibility_sha256": sources.digest(certificate),
            "collection_contract_sha256": policy["collection_contract_sha256"],
            "collection_design_sha256": policy["collection_design_sha256"],
            "builder_config_sha256": policy["builder_config_sha256"],
            "collection_mode": "REAL_LAB",
        },
        "collection_audit": {
            "source_compatibility": copy.deepcopy(certificate),
            "status": "READY",
            "audit_version": "dataset-audit-v2", "report_sha256": "f" * 64,
            "collection_contract_sha256": policy["collection_contract_sha256"],
            "collection_design_sha256": policy["collection_design_sha256"],
        },
        "feature_schema_sha256": policy["feature_schema_sha256"],
        "group_key": "cohort_id",
        "locked_test_status": "UNOPENED",
        "partition_counts": {name: 1 for name in sources.PARTITIONS},
        "record_counts": {name: 1 for name in sources.PARTITIONS},
        "stratum_run_counts": policy["stratum_run_counts"],
        "split_assignment_commitment_sha256": policy["split_assignment_commitment_sha256"],
        "dataset_hash_sha256": policy["dataset_hash_sha256"],
        "locked_test_sha256": policy["partitions"]["locked_test"]["sha256"],
        "source_partitions": copy.deepcopy(policy["partitions"]),
        "partitions": {
            name: {"sha256": item["sha256"], "record_count": item["record_count"]}
            for name, item in policy["partitions"].items()
        },
    }
    partitions = {
        "train": [copy.deepcopy(sources.canonical_record(rows[0]))],
        "validation": [copy.deepcopy(sources.canonical_record(rows[1]))],
    }
    sources.verify_training_manifest(manifest, partitions, root=root)
    calls.clear()
    return reviewed, certificate, manifest, partitions


def rehash_certificate(manifest):
    certificate = manifest["collection_audit"]["source_compatibility"]
    manifest["provenance"]["source_compatibility_sha256"] = sources.digest(certificate)


@pytest.mark.parametrize("strip_certificate", [False, True])
def test_reviewed_v3_cannot_downgrade_even_after_removing_its_certificate(
    handoff, strip_certificate,
):
    (root, *_), _, manifest, partitions = handoff
    manifest["manifest_version"] = "dataset-manifest-v2"
    if strip_certificate:
        del manifest["collection_audit"]["source_compatibility"]
        del manifest["provenance"]["source_compatibility_sha256"]
    with pytest.raises(ValueError, match="v3"):
        sources.verify_training_manifest(manifest, partitions, root=root, expected_commit=None)


def test_whole_cohort_swap_cannot_be_authorized_by_rehashing_the_manifest(handoff):
    (root, *_), _, manifest, partitions = handoff
    partitions["train"], partitions["validation"] = partitions["validation"], partitions["train"]
    certificate = manifest["collection_audit"]["source_compatibility"]
    for name, rows in partitions.items():
        commitment = sources.partition_commitment(rows)
        manifest["source_partitions"][name] = commitment
        certificate["partitions"][name] = copy.deepcopy(commitment)
        manifest["partitions"][name] = {
            "sha256": commitment["sha256"], "record_count": commitment["record_count"],
        }
    rehash_certificate(manifest)
    with pytest.raises(ValueError, match="pinned policy"):
        sources.verify_training_manifest(manifest, partitions, root=root)


@pytest.mark.parametrize("inventory", ["extra", "duplicate"])
def test_audit_rejects_extra_and_duplicate_run_inventory_before_replay(reviewed, inventory):
    root, raw, evidence, ids, _, _, calls = reviewed
    proposed = [*ids, "UNAPPROVED-EXTRA" if inventory == "extra" else ids[0]]
    with pytest.raises(ValueError, match="inventory"):
        sources.verify_training_sources(
            root, raw, evidence, proposed, root / sources.POLICY_RELATIVE,
        )
    assert calls == [], "An unapproved inventory must fail before any run replay"


@pytest.mark.parametrize("inventory", ["extra", "duplicate"])
def test_export_rejects_extra_and_duplicate_records_after_audit(handoff, inventory):
    (root, raw, evidence, _, rows, *_), certificate, _, _ = handoff
    extra = copy.deepcopy(rows[0])
    if inventory == "extra":
        extra["run_id"] = "UNAPPROVED-EXTRA"
    with pytest.raises(ValueError, match="inventory"):
        sources.verify_export_records(
            [*rows, extra], certificate, root=root, raw_dir=raw, evidence_dir=evidence,
        )


@pytest.mark.parametrize("input_kind", ["raw", "evidence"])
def test_export_rechecks_original_input_bytes_after_the_successful_audit(handoff, input_kind):
    (root, raw, evidence, ids, rows, *_), certificate, _, _ = handoff
    path = (raw / ids[0] / "incidents.jsonl" if input_kind == "raw"
            else evidence / ids[0] / ".collection_state.json")
    # JSON semantics and the exported rows stay identical; the approved bytes do not.
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="original input changed after audit"):
        sources.verify_export_records(
            rows, certificate, root=root, raw_dir=raw, evidence_dir=evidence,
        )


def test_untracked_processing_source_cannot_verify_a_reviewed_handoff(handoff):
    (root, *_), _, manifest, partitions = handoff
    (root / "untracked_processor.py").write_text("modified = True\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source is dirty"):
        sources.verify_training_manifest(manifest, partitions, root=root)


def test_assume_unchanged_cannot_hide_modified_executing_source_bytes(handoff):
    (root, *_), _, manifest, partitions = handoff
    git(root, "update-index", "--assume-unchanged", "module.py")
    (root / "module.py").write_text("version = 999\n", encoding="utf-8")
    assert git(root, "status", "--porcelain", "--untracked-files=all") == ""
    with pytest.raises(ValueError, match="executing processing bytes differ"):
        sources.verify_training_manifest(manifest, partitions, root=root)


def test_alternate_policy_path_cannot_replace_the_committed_fixed_path(reviewed):
    root, raw, evidence, ids, *_ = reviewed
    alternate = root / "config/alternate-review.json"
    alternate.write_bytes((root / sources.POLICY_RELATIVE).read_bytes())
    with pytest.raises(ValueError, match="pinned source policy"):
        sources.verify_training_sources(root, raw, evidence, ids, alternate)


@pytest.mark.parametrize("forgery", ["contract", "dataset_hash", "locked_hash"])
def test_forged_commitments_fail_even_when_the_certificate_is_self_rehashed(handoff, forgery):
    (root, *_), _, manifest, _ = handoff
    certificate = manifest["collection_audit"]["source_compatibility"]
    forged_hash = "0" * 64
    if forgery == "contract":
        manifest["collection_audit"]["collection_contract_sha256"] = forged_hash
        manifest["provenance"]["collection_contract_sha256"] = forged_hash
        certificate["collection_contract_sha256"] = forged_hash
    elif forgery == "dataset_hash":
        manifest["dataset_hash_sha256"] = forged_hash
        certificate["dataset_hash_sha256"] = forged_hash
    else:
        manifest["locked_test_sha256"] = forged_hash
        manifest["partitions"]["locked_test"]["sha256"] = forged_hash
        manifest["source_partitions"]["locked_test"]["sha256"] = forged_hash
        certificate["partitions"]["locked_test"]["sha256"] = forged_hash
    rehash_certificate(manifest)
    # The attacker controls all mutually matching metadata, but not the committed policy.
    with pytest.raises(ValueError, match="pinned policy"):
        sources.verify_training_manifest(manifest, root=root)


@pytest.mark.parametrize("with_local_policy", [False, True])
def test_unrelated_v2_loads_without_git_or_processing_policy_verification(
    tmp_path, monkeypatch, with_local_policy,
):
    root = tmp_path / "legacy-without-git"
    root.mkdir()
    if with_local_policy:
        policy = root / sources.POLICY_RELATIVE
        policy.parent.mkdir()
        policy.write_text('{"approved_runs": {}}', encoding="utf-8")

    def unavailable(*args, **kwargs):
        raise FileNotFoundError("Git is unavailable in this legacy environment")

    def no_processing_requirement(*args, **kwargs):
        pytest.fail("An unrelated v2 dataset must not require reviewed processing provenance")

    monkeypatch.setattr(sources, "_files", unavailable)
    monkeypatch.setattr(sources, "_policy", no_processing_requirement)
    sources.verify_training_manifest(
        {"manifest_version": "dataset-manifest-v2"},
        {"train": [{"run_id": "UNRELATED-LEGACY"}], "validation": []},
        root=root, expected_commit=None,
    )


def test_v2_rejects_reviewed_partition_marker_before_loading_any_rows():
    with pytest.raises(ValueError, match="manifest v3"):
        sources.verify_training_manifest({
            "manifest_version": "dataset-manifest-v2", "source_partitions": {},
        })


@pytest.mark.parametrize("field", [
    "audit_status", "collection_candidate", "source_config_override", "stratum_run_counts",
])
def test_reviewed_metadata_rejects_contradictions_before_loading_rows(handoff, field):
    (root, *_), _, manifest, _ = handoff
    if field == "audit_status":
        manifest["collection_audit"]["status"] = "TARGET_MET"
    elif field == "collection_candidate":
        manifest["collection_audit"]["collection_candidate"] = {"commit": "0" * 40}
    elif field == "source_config_override":
        manifest["provenance"]["source_config_override"] = {"sha256": "0" * 64}
    else:
        manifest["stratum_run_counts"] = {"account:0": 999}
    with pytest.raises(ValueError, match="inconsistent|source override hash"):
        sources.verify_training_manifest(manifest, root=root)
