"""Deterministic, blind derivation from the reviewed immutable forty-run parent.

The transform/profile is committed before this command runs. No held-out feature
or label diagnostics are emitted; the locked partition is never opened for
selection, training, or staging. New READY approval remains a separate review.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from copy import deepcopy
from pathlib import Path

from api.app.contracts import IncidentRequest, StreamIncidentRequest
from ml.dataset import discover_records
from ml.feature_profiles import registered_schema, validate_stream_values
from ml.scenario_collection import SourceConfig, _read_evidence_rows, _verify_full_capture_parity
from ml.stream_sources import (
    CONFIG_RELATIVE,
    MANIFEST_VERSION,
    POLICY_RELATIVE,
    SCHEMA_RELATIVE,
    SCHEMA_VERSION,
    derivation_certificate,
    load_stream_partitions,
    restore_parent_record,
)
from ml.training_sources import POLICY_RELATIVE as PARENT_POLICY
from ml.training_sources import (
    ROOT,
    _policy,
    canonical_dataset_hash,
    canonical_record,
    digest,
    partition_bytes,
    partition_commitment,
    run_key,
    verify_export_records,
    verify_training_manifest,
    verify_training_sources,
)


def project_record(parent: dict, stream: StreamIncidentRequest) -> dict:
    """Keep the original observation envelope; extend only the declared profile fields."""
    snapshot = deepcopy(parent["incident"])
    incident = deepcopy(snapshot)
    incident.update(
        features=deepcopy(stream.features), feature_schema_version=SCHEMA_VERSION,
        indicator=stream.indicator,
        indicator_attribution=(stream.indicator_attribution.model_dump(mode="json")
                               if stream.indicator_attribution else None),
    )
    derived = {**canonical_record(deepcopy(parent)), "source_incident": snapshot,
               "features": deepcopy(stream.features), "incident": incident}
    if restore_parent_record(derived) != canonical_record(parent):
        raise ValueError("stream projection changed its original record")
    StreamIncidentRequest.model_validate(incident)
    validate_stream_values(derived["features"], registered_schema(SCHEMA_VERSION))
    return derived


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8", newline="\n")


def build_stream_dataset(parent_dir: Path, input_project: Path, output: Path) -> dict:
    """Reverify all original bytes/replay, then transform with original role memberships."""
    root = ROOT
    output = output.resolve()
    if output.exists() or output.parent != (root / "data").resolve():
        raise ValueError("stream output must be a new directory directly under this repo's data")
    output.parent.mkdir(exist_ok=True)
    policy, _, _ = _policy(root)
    stream_policy = json.loads((root / POLICY_RELATIVE).read_bytes())
    parent = json.loads((parent_dir / "dataset_manifest.json").read_bytes())
    verify_training_manifest(parent, root=root)
    if digest(parent) != stream_policy.get("parent_manifest_sha256"):
        raise ValueError("unreviewed original parent dataset")
    # Preserve the original group assignment; there is no split fitting here.
    # No indirect held-out feature information enters the fixed transform.
    visible = {}
    for role in ("train", "validation"):
        payload = (parent_dir / f"{role}.jsonl").read_bytes()
        if hashlib.sha256(payload).hexdigest() != parent["partitions"][role]["sha256"]:
            raise ValueError("original parent partition bytes changed")
        visible[role] = [json.loads(line) for line in payload.decode().splitlines() if line.strip()]
    verify_training_manifest(parent, visible, root=root)
    raw = input_project / "data/raw"
    evidence = input_project / "evidence/scenario-runs"
    originals = [canonical_record(r.as_dict()) for r in discover_records(
        raw, "scenario_manifest.json", "incidents.jsonl",
    )]
    ids = [r["run_id"] for r in originals]
    print("[stream-build] Verifying original raw, sealed evidence and legacy replay", flush=True)
    raw_certificate = verify_training_sources(root, raw, evidence, ids, root / PARENT_POLICY)
    originals = verify_export_records(originals, raw_certificate, root=root,
                                      raw_dir=raw, evidence_dir=evidence)
    roles = {r["run_id"]: role for role, rows in visible.items() for r in rows}
    partitioned = {role: [] for role in ("train", "validation", "locked_test")}
    print("[stream-build] Applying committed stream transform; held-out diagnostics disabled",
          flush=True)
    for row in originals:
        rid = row["run_id"]
        run_evidence = evidence / rid
        state = json.loads((run_evidence / ".collection_state.json").read_bytes())
        source = SourceConfig.model_validate(state["source"])
        incident = IncidentRequest.model_validate(row["incident"])
        captured = _read_evidence_rows(run_evidence / "archive_capture.jsonl")
        # Never bypass legacy parity to hide a collector inconsistency.
        _verify_full_capture_parity(captured, incident, source, run_evidence)
        stream = _verify_full_capture_parity(captured, incident, source, run_evidence,
            compare=False, feature_profile=SCHEMA_VERSION)
        partitioned[roles.get(rid, "locked_test")].append(project_record(row, stream))
    for role, rows in partitioned.items():
        original_keys = parent["source_partitions"][role]["run_keys_sha256"]
        if digest(sorted(run_key(r["run_id"]) for r in rows)) != original_keys:
            raise ValueError("derived role membership differs from the original parent")
    # Close the replay/transform/write gap: original bytes and source are checked again.
    verify_export_records(originals, raw_certificate, root=root, raw_dir=raw, evidence_dir=evidence)
    if raw_certificate["processing_sha256"] != policy["processing_sha256"]:
        raise ValueError("processing source changed during stream derivation")
    cert = derivation_certificate(parent, raw_certificate)
    commitments = {k: partition_commitment(v) for k, v in partitioned.items()}
    all_rows = [r for rows in partitioned.values() for r in rows]
    manifest = {
        "manifest_version": MANIFEST_VERSION, "feature_schema_version": SCHEMA_VERSION,
        "feature_schema_sha256": hashlib.sha256((root / SCHEMA_RELATIVE).read_bytes()).hexdigest(),
        "parent_manifest": parent, "parent_manifest_sha256": digest(parent),
        "group_key": "cohort_id", "locked_test_status": "UNOPENED",
        "record_counts": {k: len(v) for k, v in partitioned.items()}, "partitions": commitments,
        "locked_test_sha256": commitments["locked_test"]["sha256"],
        "dataset_hash_sha256": canonical_dataset_hash(all_rows),
        "row_commitments": {run_key(r["run_id"]): digest(r) for r in all_rows},
        "split_assignment_commitment_sha256": parent["split_assignment_commitment_sha256"],
        "provenance": {
            "builder_git_commit": raw_certificate["processing_commit"],
            "processing_sha256": raw_certificate["processing_sha256"],
            "processing_runtime": raw_certificate["processing_runtime"],
            "builder_config_sha256": hashlib.sha256(
                (root / CONFIG_RELATIVE).read_bytes(),
            ).hexdigest(),
            "source_compatibility_sha256": digest(cert),
        },
        "collection_audit": {"status": "DERIVED_VERIFIED", "source_compatibility": cert},
    }
    # Rename only a fully written private directory; failed builds leave no partial dataset.
    scratch = root / "operator-logs"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stream-build-", dir=scratch) as name:
        pending = Path(name) / "complete"
        pending.mkdir()
        for role, rows in partitioned.items():
            payload = partition_bytes(rows)
            if hashlib.sha256(payload).hexdigest() != commitments[role]["sha256"]:
                raise ValueError("partition serialization changed")
            (pending / f"{role}.jsonl").write_bytes(payload)
        _write_json(pending / "dataset_manifest.json", manifest)
        _write_json(pending / "build_receipt.json", {
            "status": "BUILT_REQUIRES_EXACT_REVIEW", "manifest_sha256": digest(manifest),
            "record_counts": manifest["record_counts"], "original_partitions_opened": [
                "train", "validation"], "locked_partition_read_for_selection": False,
            "processing_commit": raw_certificate["processing_commit"],
        })
        pending.rename(output)
    print("[stream-build] Complete; exact manifest review is required before training", flush=True)
    return manifest


def stage_stream_dataset(processed: Path, output: Path) -> None:
    """Export exactly four safe files, only after the committed READY review."""
    _, _, manifest = load_stream_partitions(processed, ROOT / SCHEMA_RELATIVE,
                                            config_path=ROOT / CONFIG_RELATIVE)
    if output.exists():
        raise ValueError("staging destination already exists; preserve the previous handoff")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stream-stage-", dir=output.parent) as name:
        pending = Path(name) / "complete"
        pending.mkdir()
        checksums = []
        for member in ("train.jsonl", "validation.jsonl", "dataset_manifest.json"):
            payload = (processed / member).read_bytes()
            if member == "dataset_manifest.json":
                valid = digest(json.loads(payload)) == digest(manifest)
            else:
                role = member.removesuffix(".jsonl")
                valid = (hashlib.sha256(payload).hexdigest()
                         == manifest["partitions"][role]["sha256"])
            if not valid:
                raise ValueError("dataset changed after staging verification")
            (pending / member).write_bytes(payload)
            checksums.append(f"{hashlib.sha256(payload).hexdigest()}  {member}\n")
        (pending / "colab-upload.sha256").write_text("".join(checksums), encoding="utf-8",
                                                    newline="\n")
        pending.rename(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--parent-dir", type=Path, required=True)
    build.add_argument("--input-project", type=Path, required=True)
    build.add_argument("--output", type=Path, default=ROOT / "data/processed-stream-v1")
    stage = commands.add_parser("stage")
    stage.add_argument("--processed", type=Path, default=ROOT / "data/processed-stream-v1")
    stage.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        build_stream_dataset(args.parent_dir, args.input_project, args.output)
    else:
        stage_stream_dataset(args.processed, args.output)


if __name__ == "__main__":
    main()
