"""Exact source/data approval for48-run development; stdlib-only before pip."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ml import supplemental_sources as base
from ml.development_design import PROTOCOL
from ml.supplemental_design import resolve_plan_run, verify_plan
from ml.training_sources import (
    _files,
    _git,
    canonical_dataset_hash,
    digest,
    partition_commitment,
    run_key,
    source_tree_hash,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_RELATIVE = "config/development-training-review.json"
CONFIG_RELATIVE = "ml/training_development_config.yaml"
CATALOG_RELATIVE = "config/development-catalog.yaml"
ROLES = ("train",)
COUNTS = {"train": 48}
MANIFEST_VERSION = "dataset-manifest-development-3day-v1"
SCHEMA_RELATIVE = base.SCHEMA_RELATIVE
SCHEMA_VERSION = base.SCHEMA_VERSION


def processing_hash(root: Path, commit: str = "HEAD") -> str:
    return digest(
        {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in _files(root, commit).items()
            if name != POLICY_RELATIVE and not name.startswith(("docs/", "tests/", "tasks/"))
        }
    )


def policy(root: Path = ROOT, *, require_ready: bool = False) -> tuple[dict, str]:
    head = _git(root, "rev-parse", "HEAD")
    raw = _files(root, head).get(POLICY_RELATIVE)
    if raw is None or (root / POLICY_RELATIVE).read_bytes() != raw:
        raise ValueError("development review must be committed and unchanged")
    review = json.loads(raw)
    if (
        set(review)
        != {
            "version",
            "status",
            "collection_candidate_tag",
            "processing_sha256",
            "processing_runtimes",
            "approved_manifest_sha256",
        }
        or review["version"] != "reviewed-development-training-v1"
        or review["status"] not in ({"READY"} if require_ready else {"COLLECTION_READY", "READY"})
        or re.fullmatch(r"[0-9a-f]{64}", str(review["processing_sha256"])) is None
        or review["processing_sha256"] != processing_hash(root, head)
        or not isinstance(review["processing_runtimes"], list)
        or not review["processing_runtimes"]
    ):
        raise ValueError("development source/data approval is not ready for this operation")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("development processing requires a clean source checkout")
    return review, head


def require_collection_source(root: Path, tag: str) -> tuple[dict, str]:
    review, head = policy(root)
    if review["collection_candidate_tag"] != tag:
        raise ValueError("development candidate differs from its reviewed source")
    return review, head


def verify_candidate(candidate: dict, review: dict, root: Path = ROOT) -> None:
    tag = "refs/tags/" + review["collection_candidate_tag"]
    if (
        candidate.get("version") != "collection-candidate-v1"
        or candidate.get("tag") != review["collection_candidate_tag"]
        or candidate.get("origin") != "https://github.com/lethinhlord/Repo.git"
        or _git(root, "rev-parse", tag + "^{commit}") != candidate.get("commit")
        or _git(root, "rev-parse", tag) != candidate.get("tag_object")
        or _git(root, "cat-file", "-t", tag) != "tag"
        or source_tree_hash(root, candidate["commit"]) != candidate.get("tracked_files_sha256")
        or processing_hash(root, candidate["commit"]) != review["processing_sha256"]
    ):
        raise ValueError("development collection source differs from its immutable reviewed tag")


def verify_manifest(
    manifest: dict,
    rows: list[dict] | None = None,
    *,
    root: Path = ROOT,
    expected_commit: str | None = None,
) -> None:
    review, head = policy(root, require_ready=True)
    if expected_commit is not None and head != expected_commit:
        raise ValueError("development trainer differs from its owner-pinned source")
    if review["approved_manifest_sha256"] != digest(manifest):
        raise ValueError("development dataset has no exact committed manifest review")
    schema_bytes = (root / SCHEMA_RELATIVE).read_bytes()
    if (
        manifest.get("manifest_version") != MANIFEST_VERSION
        or manifest.get("feature_schema_version") != SCHEMA_VERSION
        or manifest.get("feature_schema_sha256") != hashlib.sha256(schema_bytes).hexdigest()
        or manifest.get("evaluation_protocol") != PROTOCOL
        or manifest.get("group_key") != "evaluation_group_id"
        or manifest.get("external_validation_status") != "NOT_COLLECTED"
        or manifest.get("locked_test_status") != "NOT_COLLECTED"
        or manifest.get("automation_eligible") is not False
        or manifest.get("record_counts") != COUNTS
        or set(manifest.get("partitions", {})) != {"train"}
    ):
        raise ValueError("invalid48-run development scope/schema/data contract")
    design, plan = manifest["design"], manifest["plan"]
    verify_plan(plan, design)
    if (
        design["version"] != "development-design-v1"
        or len(plan["runs"]) != 48
        or manifest["design_sha256"] != digest(design)
        or manifest["plan_sha256"] != digest(plan)
        or manifest["design_config_sha256"]
        != hashlib.sha256(
            (root / "config/development-design.yaml").read_bytes(),
        ).hexdigest()
    ):
        raise ValueError("development plan/design commitment differs")
    members, hashes = manifest["unit_membership"], manifest["row_commitments"]
    if (
        set(members) != {run_key(r["run_id"]) for r in plan["runs"]}
        or len(set(members.values())) != 48
        or set(members.values()) != set(hashes)
        or manifest["partitions"]["train"]["record_count"] != 48
        or manifest["partitions"]["train"]["run_keys_sha256"] != digest(sorted(hashes))
    ):
        raise ValueError("development unit/run inventory differs")
    for unit in plan["runs"]:
        if members[run_key(unit["run_id"])] not in {run_key(a["run_id"]) for a in unit["attempts"]}:
            raise ValueError("development contains an unplanned attempt")
    cert = manifest["collection_audit"]["source_compatibility"]
    provenance = manifest["provenance"]
    if (
        manifest["collection_audit"]["status"] != "SUPPLEMENTAL_COLLECTION_AUDIT_PASS"
        or cert["version"] != "development-source-compatibility-v1"
        or cert["processing_sha256"] != review["processing_sha256"]
        or cert["processing_runtime"] not in review["processing_runtimes"]
        or cert["plan_sha256"] != digest(plan)
        or cert["design_sha256"] != digest(design)
        or provenance["processing_sha256"] != review["processing_sha256"]
        or provenance["processing_runtime"] != cert["processing_runtime"]
        or provenance["source_compatibility_sha256"] != digest(cert)
        or provenance["builder_config_sha256"]
        != hashlib.sha256(
            (root / CONFIG_RELATIVE).read_bytes(),
        ).hexdigest()
        or processing_hash(root, provenance["builder_git_commit"]) != review["processing_sha256"]
    ):
        raise ValueError("development native processing certificate differs")
    verify_candidate(cert["candidate"], review, root)
    _git(root, "merge-base", "--is-ancestor", provenance["builder_git_commit"], head)
    if rows is not None:
        if (
            partition_commitment(rows) != manifest["partitions"]["train"]
            or canonical_dataset_hash(rows) != manifest["dataset_hash_sha256"]
        ):
            raise ValueError("development rows or partition bytes differ")
        schema = json.loads(schema_bytes)
        for row in rows:
            key = run_key(row["run_id"])
            if hashes.get(key) != digest(row):
                raise ValueError("development row differs from its exact commitment")
            planned = resolve_plan_run(plan, row["run_id"])
            base.validate_row(row, planned, schema, plan)


def load_training_data(
    processed: Path,
    *,
    root: Path = ROOT,
    expected_commit: str | None = None,
) -> tuple[list[dict], dict]:
    """Only TRAIN exists in this protocol; never open a validation/test file."""
    manifest = json.loads((processed / "dataset_manifest.json").read_bytes())
    verify_manifest(manifest, root=root, expected_commit=expected_commit)
    raw = (processed / "train.jsonl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["partitions"]["train"]["sha256"]:
        raise ValueError("development training bytes changed")
    rows = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    verify_manifest(manifest, rows, root=root, expected_commit=expected_commit)
    return rows, manifest
