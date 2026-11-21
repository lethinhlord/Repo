"""Exact parent and derived-data commitments; safe to import before dependencies."""
from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path

from ml.feature_profiles import validate_stream_values
from ml.training_sources import (
    ROOT,
    _certificate,
    _files,
    _git,
    _policy,
    canonical_record,
    digest,
    partition_commitment,
    processing_hash,
    run_key,
    verify_training_manifest,
)

MANIFEST_VERSION = "dataset-manifest-v4-stream-v1"
POLICY_VERSION = "reviewed-stream-training-v1"
POLICY_RELATIVE = "config/stream-training-source-compatibility.json"
SCHEMA_RELATIVE = "ml/feature_schema_stream.json"
CONFIG_RELATIVE = "ml/training_stream_config.yaml"
SCHEMA_VERSION = "features-v4-stream-v1"


def derivation_certificate(parent: dict, raw_certificate: dict) -> dict:
    """Bind the unchanged parent and the new replay worker, without new G7 claims."""
    return {
        "version": "derived-stream-source-v1",
        "parent_manifest_sha256": digest(parent),
        "parent_processing_commit": parent["provenance"]["builder_git_commit"],
        "stream_processing_commit": raw_certificate["processing_commit"],
        "stream_processing_sha256": raw_certificate["processing_sha256"],
        "raw_verification_certificate": raw_certificate,
    }


def restore_parent_record(row: dict) -> dict:
    """Recover original bytes' canonical object; only explicit fields may evolve."""
    result = deepcopy(row)
    source = result.pop("source_incident", None)
    incident = result.get("incident")
    if (not isinstance(source, dict) or not isinstance(source.get("features"), dict)
            or not isinstance(incident, dict)
            or incident.get("feature_schema_version") != SCHEMA_VERSION
            or incident.get("features") != result.get("features")):
        raise ValueError("derived record requires its unchanged source incident and stream vector")
    for name, value in source["features"].items():
        if result["features"].get(name) != value:
            raise ValueError("stream derivation changed a retained legacy feature")
    mutable = {"features", "feature_schema_version", "indicator", "indicator_attribution"}
    if any(incident.get(k) != v for k, v in source.items() if k not in mutable):
        raise ValueError("stream derivation changed original observation identity or evidence")
    if set(incident)-set(source)-mutable:
        raise ValueError("unexpected derived incident metadata")
    result["features"] = source["features"]
    result["incident"] = source
    return canonical_record(result)


def verify_stream_manifest(
    manifest: dict, rows_by_partition: dict[str, list[dict]] | None = None, *,
    root: Path | None = None, expected_commit: str | None = None,
) -> None:
    """Accept only exact committed review; parent roles and observations stay immutable."""
    root = ROOT if root is None else root
    parent_policy, policy_sha, trainer = _policy(root)
    if expected_commit is not None and expected_commit != trainer:
        raise ValueError("executing stream trainer differs from the pinned expected source")
    files = _files(root, trainer)
    policy_bytes = files.get(POLICY_RELATIVE)
    if policy_bytes is None:
        raise ValueError("missing committed stream training review")
    policy = json.loads(policy_bytes)
    if (policy.get("version") != POLICY_VERSION or policy.get("status") != "READY"
            or policy.get("approved_manifest_sha256") != digest(manifest)):
        raise ValueError("stream manifest is outside the exact committed READY review")
    if (manifest.get("manifest_version") != MANIFEST_VERSION
            or manifest.get("feature_schema_version") != SCHEMA_VERSION
            or manifest.get("locked_test_status") != "UNOPENED"):
        raise ValueError("invalid stream manifest version or locked-test state")
    parent = manifest.get("parent_manifest")
    if not isinstance(parent, dict) or parent.get("manifest_version") != "dataset-manifest-v3":
        raise ValueError("stream derivation requires its original parent manifest")
    verify_training_manifest(parent, root=root)
    if (manifest.get("parent_manifest_sha256") != digest(parent)
            or policy.get("parent_manifest_sha256") != digest(parent)):
        raise ValueError("stream parent differs from the pinned original dataset")
    schema_bytes, config_bytes = files.get(SCHEMA_RELATIVE), files.get(CONFIG_RELATIVE)
    if schema_bytes is None or config_bytes is None:
        raise ValueError("missing committed stream schema/config")
    schema = json.loads(schema_bytes)
    provenance = manifest.get("provenance", {})
    builder = provenance.get("builder_git_commit")
    source_hash = processing_hash(root, trainer)
    if (not isinstance(builder, str) or re.fullmatch(r"[0-9a-f]{40}", builder) is None
            or provenance.get("processing_sha256") != source_hash
            or policy.get("processing_sha256") != source_hash
            or provenance.get("processing_runtime") not in parent_policy["processing_runtimes"]):
        raise ValueError("stream builder/source differs from the committed review")
    _git(root, "merge-base", "--is-ancestor", builder, trainer)
    if processing_hash(root, builder) != source_hash:
        raise ValueError("executing transform differs from the original stream builder")
    certificate = derivation_certificate(parent, _certificate(
        parent_policy, policy_sha, builder, provenance["processing_runtime"],
    ))
    collection = manifest.get("collection_audit", {})
    if (collection.get("status") != "DERIVED_VERIFIED"
            or collection.get("source_compatibility") != certificate
            or provenance.get("source_compatibility_sha256") != digest(certificate)):
        raise ValueError("stream raw replay certificate differs from the reviewed source")
    schema_hash = hashlib.sha256(schema_bytes).hexdigest()
    config_hash = hashlib.sha256(config_bytes).hexdigest()
    if (manifest.get("feature_schema_sha256") != schema_hash
            or schema.get("version") != SCHEMA_VERSION
            or policy.get("feature_schema_sha256") != schema_hash
            or provenance.get("builder_config_sha256") != config_hash
            or policy.get("builder_config_sha256") != config_hash):
        raise ValueError("stream schema/config differs from the reviewed transform")
    roles = {"train", "validation", "locked_test"}
    parts = manifest.get("partitions", {})
    parent_parts = parent.get("source_partitions", {})
    if (set(parts) != roles or set(parent_parts) != roles
            or manifest.get("record_counts") != parent.get("record_counts")
            or manifest.get("group_key") != parent.get("group_key")
            or manifest.get("group_key") != "cohort_id"
            or manifest.get("split_assignment_commitment_sha256")
            != parent.get("split_assignment_commitment_sha256")):
        raise ValueError("stream partition roles/counts differ from original grouped assignment")
    for role in roles:
        if (parts[role].get("record_count") != parent_parts[role]["record_count"]
                or parts[role].get("run_keys_sha256") != parent_parts[role]["run_keys_sha256"]
                or re.fullmatch(r"[0-9a-f]{64}", str(parts[role].get("sha256"))) is None):
            raise ValueError("stream partition membership differs from the original dataset")
    if manifest.get("locked_test_sha256") != parts["locked_test"]["sha256"]:
        raise ValueError("inconsistent stream locked-test commitment")
    if re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("dataset_hash_sha256"))) is None:
        raise ValueError("invalid complete stream dataset commitment")
    parents = parent["collection_audit"]["source_compatibility"]["runs"]
    committed_rows = manifest.get("row_commitments", {})
    if (set(committed_rows) != set(parents)
            or any(re.fullmatch(r"[0-9a-f]{64}", str(v)) is None for v in committed_rows.values())):
        raise ValueError("derived row inventory differs from the exact parent source")
    if rows_by_partition is None:
        return
    if set(rows_by_partition) != {"train", "validation"}:
        raise ValueError("training verifies train/validation only; never open locked rows")
    seen = set()
    for role, rows in rows_by_partition.items():
        if partition_commitment(rows) != parts[role]:
            raise ValueError("stream partition bytes/count/membership changed")
        for row in rows:
            key = run_key(row["run_id"])
            if (key in seen or key not in parents or row != canonical_record(row)
                    or digest(row) != committed_rows[key]):
                raise ValueError("unapproved stream record")
            validate_stream_values(row["features"], schema)
            restored = restore_parent_record(row)
            if digest(restored) != parents[key]["record_sha256"]:
                raise ValueError("derived record rewrote original label/cohort/observation")
            seen.add(key)
    locked = set(parents)-seen
    if (len(locked) != parts["locked_test"]["record_count"]
            or digest(sorted(locked)) != parts["locked_test"]["run_keys_sha256"]):
        raise ValueError("stream locked-test membership changed")


def load_stream_partitions(
    processed_dir: Path, schema_path: Path, *, config_path: Path | None = None,
    collection_design_path: Path | None = None, root: Path | None = None,
    expected_commit: str | None = None,
) -> tuple[list[dict], list[dict], dict]:
    """Read only the two visible roles, after exact source/manifest approval."""
    from api.app.contracts import StreamIncidentRequest
    from ml.dataset import DatasetRecord

    root = ROOT if root is None else root
    manifest = json.loads((processed_dir / "dataset_manifest.json").read_bytes())
    verify_stream_manifest(manifest, root=root, expected_commit=expected_commit)
    if hashlib.sha256(schema_path.read_bytes()).hexdigest() != manifest["feature_schema_sha256"]:
        raise ValueError("executing stream schema differs from the reviewed schema")
    if config_path is not None and hashlib.sha256(config_path.read_bytes()).hexdigest() != (
        manifest["provenance"]["builder_config_sha256"]
    ):
        raise ValueError("executing stream config differs from the reviewed config")
    if collection_design_path is not None and hashlib.sha256(
        collection_design_path.read_bytes(),
    ).hexdigest() != manifest["parent_manifest"]["provenance"]["collection_design_sha256"]:
        raise ValueError("stream collection design differs from the original parent")
    partitions = {}
    for role in ("train", "validation"):
        payload = (processed_dir / f"{role}.jsonl").read_bytes()
        if hashlib.sha256(payload).hexdigest() != manifest["partitions"][role]["sha256"]:
            raise ValueError(f"{role} partition integrity check failed")
        rows = [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]
        for row in rows:
            record = DatasetRecord(**row)
            incident = StreamIncidentRequest.model_validate(record.incident)
            if (record.family not in {"account", "c2"} or type(record.label) is not int
                    or record.label not in {0, 1} or record.purpose != "trainable"
                    or not record.cohort_id or record.incident_id != incident.incident_id
                    or record.family != incident.family_hint
                    or record.features != incident.features):
                raise ValueError("invalid stream training record")
        partitions[role] = rows
    verify_stream_manifest(manifest, partitions, root=root, expected_commit=expected_commit)
    return partitions["train"], partitions["validation"], manifest
