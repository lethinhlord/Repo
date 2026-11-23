"""Audit/build48 development runs without inventing external assessment data."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from ml import development_sources as source
from ml import supplemental_dataset as shared
from ml.development_design import PROTOCOL
from ml.training_sources import (
    canonical_dataset_hash,
    digest,
    partition_bytes,
    partition_commitment,
    run_key,
    runtime_identity,
)


def audit_collection(root: Path, plan_path: Path, *, processor_root: Path = source.ROOT):
    return shared.audit_collection(
        root,
        plan_path,
        processor_root=processor_root,
        source_module=source,
        catalog_relative=source.CATALOG_RELATIVE,
    )


def assemble_manifest(audited, review: dict, head: str, runtime: dict, root: Path) -> dict:
    report, parts, candidate, accepted, design, plan = audited
    if (
        report["status"] != "SUPPLEMENTAL_COLLECTION_AUDIT_PASS"
        or report["issues"]
        or report["counts"] != source.COUNTS
        or set(parts) != {"train"}
        or len(parts["train"]) != 48
        or runtime not in review["processing_runtimes"]
        or design["evaluation_protocol"] != PROTOCOL
    ):
        raise ValueError("a complete48-run native audit in an approved runtime is required")
    rows = parts["train"]
    cert = dict(
        version="development-source-compatibility-v1",
        candidate=candidate,
        acceptance_sha256=digest(accepted),
        plan_sha256=digest(plan),
        design_sha256=digest(design),
        input_inventory_sha256=report["input_inventory_sha256"],
        processing_sha256=review["processing_sha256"],
        processing_runtime=runtime,
    )
    return dict(
        manifest_version=source.MANIFEST_VERSION,
        feature_schema_version=source.SCHEMA_VERSION,
        feature_schema_sha256=hashlib.sha256(
            (root / source.SCHEMA_RELATIVE).read_bytes()
        ).hexdigest(),
        group_key="evaluation_group_id",
        evaluation_protocol=PROTOCOL,
        external_validation_status="NOT_COLLECTED",
        locked_test_status="NOT_COLLECTED",
        automation_eligible=False,
        record_counts={"train": 48},
        design=design,
        plan=plan,
        design_sha256=digest(design),
        plan_sha256=digest(plan),
        design_config_sha256=hashlib.sha256(
            (root / "config/development-design.yaml").read_bytes(),
        ).hexdigest(),
        partitions={"train": partition_commitment(rows)},
        dataset_hash_sha256=canonical_dataset_hash(rows),
        row_commitments={run_key(r["run_id"]): digest(r) for r in rows},
        unit_membership={run_key(r["planned_run_id"]): run_key(r["run_id"]) for r in rows},
        provenance=dict(
            builder_git_commit=head,
            processing_sha256=review["processing_sha256"],
            processing_runtime=runtime,
            source_compatibility_sha256=digest(cert),
            builder_config_sha256=hashlib.sha256(
                (root / source.CONFIG_RELATIVE).read_bytes(),
            ).hexdigest(),
        ),
        collection_audit={**report, "source_compatibility": cert},
    )


def _unchanged(root: Path, plan: Path, manifest: dict, authority: tuple, processor: Path):
    if (
        digest(shared.input_inventory(root, plan))
        != manifest["collection_audit"]["input_inventory_sha256"]
        or source.policy(processor) != authority
    ):
        raise ValueError("development raw inputs or approved processing source changed")


def build_dataset(root: Path, plan: Path, output: Path, *, processor_root: Path = source.ROOT):
    import yaml

    review, head = authority = source.policy(processor_root)
    runtime = runtime_identity()
    if runtime not in review["processing_runtimes"]:
        raise ValueError("development builder runtime is not approved")
    config = yaml.safe_load((processor_root / source.CONFIG_RELATIVE).read_bytes())
    output = output.resolve()
    if (
        output.exists()
        or output != (processor_root / config["data"]["processed_dir"]).resolve()
        or output.parent != (processor_root / "data").resolve()
    ):
        raise ValueError("use the fresh development output directory in the pinned config")
    audited = audit_collection(root, plan, processor_root=processor_root)
    manifest = assemble_manifest(audited, review, head, runtime, processor_root)
    _unchanged(root, plan, manifest, authority, processor_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tmp-development-build-", dir=output.parent) as temp:
        pending = Path(temp) / "complete"
        pending.mkdir()
        (pending / "train.jsonl").write_bytes(partition_bytes(audited[1]["train"]))
        (pending / "dataset_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        receipt = dict(
            status="DEVELOPMENT_BUILT_REQUIRES_EXACT_REVIEW",
            manifest_sha256=digest(manifest),
            record_counts={"train": 48},
            external_validation_status="NOT_COLLECTED",
            locked_test_status="NOT_COLLECTED",
        )
        (pending / "build_receipt.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        _unchanged(root, plan, manifest, authority, processor_root)
        pending.rename(output)
    return receipt


def propose_review(root: Path, plan: Path, processed: Path, output: Path):
    from ml.training_sources import _git

    review, head = authority = source.policy(source.ROOT)
    if runtime_identity() not in review["processing_runtimes"]:
        raise ValueError("development review runtime is not approved")
    manifest = shared.read_object(processed / "dataset_manifest.json")
    builder = manifest["provenance"]["builder_git_commit"]
    _git(source.ROOT, "merge-base", "--is-ancestor", builder, head)
    if source.processing_hash(source.ROOT, builder) != review["processing_sha256"]:
        raise ValueError("development builder source differs")
    replayed = assemble_manifest(
        audit_collection(root, plan),
        review,
        builder,
        manifest["provenance"]["processing_runtime"],
        source.ROOT,
    )
    if (
        replayed != manifest
        or hashlib.sha256((processed / "train.jsonl").read_bytes()).hexdigest()
        != (manifest["partitions"]["train"]["sha256"])
    ):
        raise ValueError("development raw replay does not reproduce proposed data exactly")
    _unchanged(root, plan, manifest, authority, source.ROOT)
    proposal = {**review, "status": "READY", "approved_manifest_sha256": digest(manifest)}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(proposal, indent=2, sort_keys=True) + "\n")
    return dict(
        status="DEVELOPMENT_EXACT_REVIEW_PROPOSAL",
        output=str(output),
        source_review_changed=False,
        manifest_sha256=digest(manifest),
    )


def stage_dataset(processed: Path, output: Path):
    _, manifest = source.load_training_data(processed, root=source.ROOT)
    authority = source.policy(source.ROOT, require_ready=True)
    output = output.resolve()
    if output.exists() or output.is_relative_to(source.ROOT.resolve()):
        raise ValueError("development staging must use a fresh path outside the source checkout")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tmp-development-stage-", dir=output.parent) as temp:
        pending = Path(temp) / "complete"
        pending.mkdir()
        sums = []
        for name in ("train.jsonl", "dataset_manifest.json"):
            raw = (processed / name).read_bytes()
            valid = (
                digest(json.loads(raw)) == digest(manifest)
                if name.endswith(".json")
                else hashlib.sha256(raw).hexdigest() == manifest["partitions"]["train"]["sha256"]
            )
            if not valid:
                raise ValueError("development staging input changed")
            (pending / name).write_bytes(raw)
            sums.append(f"{hashlib.sha256(raw).hexdigest()}  {name}\n")
        (pending / "colab-upload.sha256").write_text("".join(sums), encoding="utf-8", newline="\n")
        if source.policy(source.ROOT, require_ready=True) != authority:
            raise ValueError("development source changed during staging")
        pending.rename(output)
    return dict(status="THREE_DEVELOPMENT_FILES_STAGED", output=str(output))


def main(argv=None):
    from ml.scenario_collection import CollectionError

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "build", "propose-review", "stage"):
        item = sub.add_parser(name)
        item.add_argument("--output", type=Path, required=True)
        if name != "stage":
            item.add_argument("--input-project", type=Path, required=True)
            item.add_argument("--plan", type=Path, required=True)
        if name in {"propose-review", "stage"}:
            item.add_argument("--processed", type=Path, required=True)
    a = parser.parse_args(argv)
    try:
        if a.command == "build":
            result = build_dataset(a.input_project, a.plan, a.output)
        elif a.command == "stage":
            result = stage_dataset(a.processed, a.output)
        elif a.command == "propose-review":
            result = propose_review(a.input_project, a.plan, a.processed, a.output)
        else:
            result = audit_collection(a.input_project, a.plan)[0]
            a.output.parent.mkdir(parents=True, exist_ok=True)
            with a.output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
        print(json.dumps(result, indent=2))
        return int(result.get("status") == "SUPPLEMENTAL_COLLECTION_AUDIT_FAIL")
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps(dict(status="ERROR", detail=str(exc))))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
