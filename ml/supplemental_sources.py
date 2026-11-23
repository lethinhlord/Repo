"""Prospective source/partition commitments; standard library only before installation."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from ml.feature_profiles import validate_stream_values
from ml.training_sources import (
    _files,
    _git,
    digest,
    partition_commitment,
    run_key,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_RELATIVE = "config/supplemental-training-review.json"
SCHEMA_RELATIVE = "ml/feature_schema_http.json"
CONFIG_RELATIVE = "ml/training_supplemental_config.yaml"
SCHEMA_VERSION = "features-v5-http-v1"
MANIFEST_VERSION = "dataset-manifest-v5-supplemental-v1"
PROTOCOL = "known-template-new-host-day"
ROLES = ("train", "validation", "locked_test")
COUNTS = {"train": 120, "validation": 48, "locked_test": 48}
ROW_FIELDS = {
    "incident_id",
    "scenario_id",
    "run_id",
    "family",
    "label",
    "features",
    "source_file",
    "purpose",
    "cohort_id",
    "incident",
    "source_incident",
    "evaluation_group_id",
    "template_id",
    "planned_run_id",
    "attempt_number",
    "campaign_plan_sha256",
    "collection_context",
}


def processing_hash(root: Path, commit: str = "HEAD") -> str:
    # A separate exact dataset review avoids a circular source hash. Executable
    # code, schema, notebook, runners and legacy policies receive NO exemption.
    return digest(
        {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in _files(root, commit).items()
            if name != POLICY_RELATIVE and not name.startswith(("tests/", "docs/", "tasks/"))
        }
    )


def policy(root: Path = ROOT, *, require_ready: bool = False) -> tuple[dict, str]:
    head = _git(root, "rev-parse", "HEAD")
    files = _files(root, head)
    raw = files.get(POLICY_RELATIVE)
    if raw is None or (root / POLICY_RELATIVE).read_bytes() != raw:
        raise ValueError("prospective review must be committed and unchanged")
    review = json.loads(raw)
    allowed = {"READY"} if require_ready else {"COLLECTION_READY", "READY"}
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
        or review["version"] != "reviewed-supplemental-training-v1"
        or review["status"] not in allowed
        or not re.fullmatch(r"[0-9a-f]{64}", str(review["processing_sha256"]))
        or review["processing_sha256"] != processing_hash(root, head)
        or not isinstance(review["processing_runtimes"], list)
        or not review["processing_runtimes"]
    ):
        raise ValueError("prospective source/review is not approved for this operation")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("prospective processing requires a clean source checkout")
    return review, head


def _planned_row(plan: dict, run_id: str) -> dict:
    matches = [
        {**row, **attempt, "planned_run_id": row["run_id"], "attempt_number": number}
        for row in plan["runs"]
        for number, attempt in enumerate(row["attempts"], 1)
        if attempt["run_id"] == run_id
    ]
    if len(matches) != 1:
        raise ValueError("partition contains an unplanned or duplicate attempt identity")
    return matches[0]


def require_collection_source(root: Path, tag: str) -> tuple[dict, str]:
    """COLLECTION_READY authorizes software collection, never a future dataset."""
    review, head = policy(root)
    if review["collection_candidate_tag"] != tag:
        raise ValueError("collection tag differs from the reviewed supplemental source")
    return review, head


def source_policy_for_design(design: dict):
    """Keep the three-day approval separate from formal216 collection/data review."""
    if design.get("version") == "development-design-v1":
        from ml import development_sources

        return development_sources
    import sys

    return sys.modules[__name__]


def verify_candidate(candidate: dict, review: dict, root: Path = ROOT) -> None:
    from ml.training_sources import source_tree_hash

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
        raise ValueError("collection Git source differs from the reviewed immutable candidate")


def validate_row(row: dict, planned: dict, schema: dict, plan: dict) -> None:
    """Keep metadata out of the matrix and retain the original24 observation values."""
    if (
        not isinstance(row, dict)
        or set(row) != ROW_FIELDS
        or any(
            row[k] != planned[k]
            for k in (
                "run_id",
                "scenario_id",
                "family",
                "cohort_id",
                "template_id",
                "planned_run_id",
                "attempt_number",
            )
        )
        or type(row["label"]) is not int
        or row["label"] != int(planned["label"] == "malicious")
        or row["purpose"] != "trainable"
        or row["campaign_plan_sha256"] != digest(plan)
        or row["collection_context"] != planned["context"]
        or row["evaluation_group_id"] != planned["context"]["evaluation_group_id"]
        or row["source_file"] != f"data/raw/{row['run_id']}/incidents.jsonl"
    ):
        raise ValueError("record differs from its registered plan/context/attempt")
    validate_stream_values(row["features"], schema)
    if row["family"] == "account" and any(
        row["features"][name] != 0
        for name in schema["required"]
        if name not in schema["x-family-features"]["account"]
    ):
        raise ValueError("account record has nonzero structural network features")
    incident, source = row["incident"], row["source_incident"]
    if (
        not isinstance(incident, dict)
        or not isinstance(source, dict)
        or incident.get("feature_schema_version") != SCHEMA_VERSION
        or source.get("feature_schema_version") != "features-v3"
        or set(source.get("features", {})) != set(schema["x-retained-legacy-features"])
        or incident.get("features") != row["features"]
        or incident.get("incident_id") != row["incident_id"]
        or incident.get("family_hint") != row["family"]
        or incident.get("asset_id") != planned["context"]["host"]
        or incident.get("observation_quality") != "COMPLETE"
        or incident.get("context_status") != "AVAILABLE"
        or incident.get("review_reasons")
        or any(row["features"].get(k) != v for k, v in source.get("features", {}).items())
    ):
        raise ValueError("record lacks complete verified context or retained raw24 lineage")
    immutable = {
        "incident_id",
        "asset_id",
        "family_hint",
        "start_time",
        "end_time",
        "raw_refs",
        "evidence_sources",
        "base_severity",
        "context_revision",
        "context_status",
    }
    if any(incident.get(k) != source.get(k) for k in immutable):
        raise ValueError("HTTP projection changed original incident identity/evidence")
    start, end = (datetime.fromisoformat(incident[k]) for k in ("start_time", "end_time"))
    if (
        start.tzinfo is None
        or end.tzinfo is None
        or end < start
        or any(
            at.astimezone(UTC).date().isoformat() != planned["context"]["collection_date"]
            for at in (start, end)
        )
    ):
        raise ValueError("incident timestamps differ from the registered actual UTC day")
    if row["family"] == "c2" and any(
        row["features"].get(k) != 1
        for k in (
            "http_evidence_available",
            "flow_evidence_available",
            "dominant_tcp_unique",
        )
    ):
        raise ValueError("C2 record lacks complete verified HTTP/flow evidence")


def verify_manifest(
    manifest: dict,
    visible: dict[str, list[dict]] | None = None,
    *,
    root: Path = ROOT,
    expected_commit: str | None = None,
) -> None:
    review, head = policy(root, require_ready=True)
    if expected_commit is not None and head != expected_commit:
        raise ValueError("trainer differs from its owner-pinned source commit")
    if review.get("approved_manifest_sha256") != digest(manifest):
        raise ValueError("dataset has no exact committed prospective review")
    schema_bytes = (root / SCHEMA_RELATIVE).read_bytes()
    schema = json.loads(schema_bytes)
    if (
        manifest.get("manifest_version") != MANIFEST_VERSION
        or manifest.get("feature_schema_version") != SCHEMA_VERSION
        or manifest.get("feature_schema_sha256") != hashlib.sha256(schema_bytes).hexdigest()
        or manifest.get("group_key") != "evaluation_group_id"
        or manifest.get("evaluation_protocol") != PROTOCOL
        or manifest.get("locked_test_status") != "UNOPENED"
        or manifest.get("record_counts") != COUNTS
        or set(manifest.get("partitions", {})) != set(ROLES)
    ):
        raise ValueError("invalid prospective manifest/schema/protocol contract")
    design, plan = manifest["design"], manifest["plan"]
    from ml.supplemental_design import verify_plan

    verify_plan(plan, design)
    if (
        manifest["design_sha256"] != digest(design)
        or manifest["plan_sha256"] != digest(plan)
        or plan.get("design_sha256") != digest(design)
        or plan.get("plan_sha256") != digest({k: v for k, v in plan.items() if k != "plan_sha256"})
        or len(plan.get("runs", [])) != 216
    ):
        raise ValueError("manifest registered design/plan commitment differs")
    members, roles, hashes = (
        manifest["unit_membership"],
        manifest["run_partitions"],
        manifest["row_commitments"],
    )
    if (
        set(members) != {run_key(r["run_id"]) for r in plan["runs"]}
        or len(set(members.values())) != 216
        or set(members.values()) != set(roles)
        or set(roles) != set(hashes)
    ):
        raise ValueError("prospective intended-unit/run inventory is incomplete or duplicated")
    for role in ROLES:
        selected = sorted(k for k, r in roles.items() if r == role)
        part = manifest["partitions"][role]
        if (
            part["record_count"] != COUNTS[role]
            or len(selected) != COUNTS[role]
            or part["run_keys_sha256"] != digest(selected)
            or re.fullmatch(r"[0-9a-f]{64}", str(part["sha256"])) is None
        ):
            raise ValueError("prospective role counts/commitments differ")
    for unit in plan["runs"]:
        attempt_key = members[run_key(unit["run_id"])]
        allowed = {run_key(a["run_id"]) for a in unit["attempts"]}
        if attempt_key not in allowed or roles[attempt_key] != unit["partition"]:
            raise ValueError("prospective role changed after its predeclared plan")
    if manifest["locked_test_sha256"] != manifest["partitions"]["locked_test"]["sha256"]:
        raise ValueError("locked commitment changed")
    cert = manifest["collection_audit"]["source_compatibility"]
    provenance = manifest["provenance"]
    if (
        manifest["collection_audit"]["status"] != "SUPPLEMENTAL_COLLECTION_AUDIT_PASS"
        or cert.get("version") != "supplemental-source-compatibility-v1"
        or cert.get("plan_sha256") != digest(plan)
        or cert.get("design_sha256") != digest(design)
        or cert.get("processing_sha256") != review["processing_sha256"]
        or cert.get("processing_runtime") not in review["processing_runtimes"]
        or provenance.get("processing_sha256") != review["processing_sha256"]
        or provenance.get("processing_runtime") != cert["processing_runtime"]
        or provenance.get("source_compatibility_sha256") != digest(cert)
        or provenance.get("builder_config_sha256")
        != hashlib.sha256((root / CONFIG_RELATIVE).read_bytes()).hexdigest()
    ):
        raise ValueError("prospective collection/processing certificate differs")
    candidate = cert["candidate"]
    tag = "refs/tags/" + review["collection_candidate_tag"]
    from ml.training_sources import source_tree_hash

    if (
        candidate.get("version") != "collection-candidate-v1"
        or candidate.get("tag") != review["collection_candidate_tag"]
        or candidate.get("origin") != "https://github.com/lethinhlord/Repo.git"
        or _git(root, "rev-parse", tag + "^{commit}") != candidate.get("commit")
        or _git(root, "rev-parse", tag) != candidate.get("tag_object")
        or _git(root, "cat-file", "-t", tag) != "tag"
        or source_tree_hash(root, candidate["commit"]) != candidate.get("tracked_files_sha256")
        or processing_hash(root, candidate["commit"]) != review["processing_sha256"]
        or processing_hash(root, provenance["builder_git_commit"]) != review["processing_sha256"]
    ):
        raise ValueError("prospective collection/builder Git history is not the reviewed source")
    _git(root, "merge-base", "--is-ancestor", provenance["builder_git_commit"], head)
    if visible is not None:
        if set(visible) != {"train", "validation"}:
            raise ValueError("training verification accepts only visible train/validation data")
        groups = {}
        for role, rows in visible.items():
            if partition_commitment(rows) != manifest["partitions"][role]:
                raise ValueError("visible partition bytes or membership differ")
            for row in rows:
                key = run_key(row["run_id"])
                if roles.get(key) != role or hashes.get(key) != digest(row):
                    raise ValueError("visible row differs from its approved role/commitment")
                planned = _planned_row(plan, row["run_id"])
                validate_row(row, planned, schema, plan)
                if groups.setdefault(row["evaluation_group_id"], role) != role:
                    raise ValueError("related host/day contexts cross visible partitions")


def load_partitions(
    processed_dir: Path,
    schema_path: Path,
    *,
    config_path: Path | None = None,
    expected_commit: str | None = None,
    collection_design_path=None,
):
    """Load two visible files; never stat, open or enumerate the locked partition."""
    if (
        schema_path.resolve() != (ROOT / SCHEMA_RELATIVE).resolve()
        or config_path is None
        or config_path.resolve() != (ROOT / CONFIG_RELATIVE).resolve()
        or (
            collection_design_path is not None
            and Path(collection_design_path).resolve()
            != (ROOT / "config/supplemental-design.yaml").resolve()
        )
    ):
        raise ValueError("prospective training requires its committed schema/config/design")
    manifest = json.loads((processed_dir / "dataset_manifest.json").read_bytes())
    verify_manifest(manifest, root=ROOT, expected_commit=expected_commit)
    visible = {}
    for role in ("train", "validation"):
        payload = (processed_dir / f"{role}.jsonl").read_bytes()
        if hashlib.sha256(payload).hexdigest() != manifest["partitions"][role]["sha256"]:
            raise ValueError("visible partition file changed")
        visible[role] = [json.loads(line) for line in payload.decode().splitlines() if line.strip()]
    verify_manifest(manifest, visible, root=ROOT, expected_commit=expected_commit)
    return visible["train"], visible["validation"], manifest
