"""Prospective sealed-evidence audit/build; no original40 input or split reuse."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections import defaultdict
from pathlib import Path

from ml import supplemental_sources as lineage
from ml.supplemental_design import resolve_plan_run, verify_plan
from ml.training_sources import (
    canonical_dataset_hash,
    digest,
    partition_bytes,
    partition_commitment,
    run_key,
    runtime_identity,
)


def read_object(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def select_attempts(plan: dict, root: Path) -> tuple[list[dict], list[dict]]:
    """Select identities only; success here never replaces full native-evidence audit."""
    selected, issues = [], []
    for unit in plan["runs"]:
        states, finalized = [], []
        for number, attempt in enumerate(unit["attempts"], 1):
            folder = root / "evidence/scenario-runs" / attempt["run_id"]
            path = folder / ".collection_state.json"
            if folder.is_symlink() or (folder.exists() and not path.is_file()):
                issues.append(dict(code="INVALID_ATTEMPT_STATE", run_id=attempt["run_id"]))
                states.append("INVALID")
                continue
            try:
                state = read_object(path) if path.exists() else {}
            except (OSError, ValueError, TypeError) as exc:
                issues.append(
                    dict(code="INVALID_ATTEMPT_STATE", run_id=attempt["run_id"], detail=str(exc))
                )
                states.append("INVALID")
                continue
            status = state.get("status", "NOT_STARTED")
            raw = root / "data/raw" / attempt["run_id"]
            if raw.exists() and status == "NOT_STARTED":
                issues.append(dict(code="ORPHAN_RAW_ATTEMPT", run_id=attempt["run_id"]))
                status = "INVALID"
            states.append(status)
            if status == "FINALIZED":
                finalized.append((number, attempt["run_id"]))
            elif status not in {"NOT_STARTED", "ABORTED"}:
                issues.append(dict(code="UNFINISHED_ATTEMPT", run_id=attempt["run_id"]))
        if len(finalized) > 1:
            issues.append(dict(code="DUPLICATE_PLANNED_UNIT", run_id=unit["run_id"]))
            continue
        if not finalized:
            issues.append(dict(code="MISSING_PLANNED_UNIT", run_id=unit["run_id"]))
            continue
        number, rid = finalized[0]
        if any(s != "ABORTED" for s in states[: number - 1]) or any(
            s != "NOT_STARTED" for s in states[number:]
        ):
            issues.append(dict(code="INVALID_ATTEMPT_CHAIN", run_id=rid))
            continue
        selected.append(resolve_plan_run(plan, rid))
    return selected, issues


def representation_audit(train_rows: list[dict], schema: dict) -> dict:
    """Check TRAIN only. No locked feature/label diagnostics influence the experiment.

    Old24 collisions remain a reported limitation of the old representation.
    They cannot substitute for checking the actual predeclared new model inputs.
    """
    selected, old = defaultdict(list), defaultdict(list)
    for row in train_rows:
        selected[
            (
                row["family"],
                tuple(row["features"][k] for k in schema["x-family-features"][row["family"]]),
            )
        ].append(row)
        old[
            (row["family"], tuple(row["features"][k] for k in schema["x-retained-legacy-features"]))
        ].append(row)
    conflicts = [
        sorted(r["run_id"] for r in rows)
        for rows in selected.values()
        if len({r["label"] for r in rows}) > 1
    ]
    return dict(
        partition="train",
        selected_input_collisions=conflicts,
        legacy24_collision_count=sum(len({r["label"] for r in rows}) > 1 for rows in old.values()),
        validation_or_locked_feature_diagnostics=False,
    )


def input_inventory(root: Path, plan_path: Path) -> dict[str, str]:
    files = {"registered-plan": hashlib.sha256(plan_path.read_bytes()).hexdigest()}
    for relative in ("data/raw", "evidence/scenario-runs"):
        folder = root / relative
        if (
            not folder.is_dir()
            or folder.is_symlink()
            or not folder.resolve().is_relative_to(root.resolve())
        ):
            raise ValueError("collection input roots are missing or linked")
        for path in folder.rglob("*"):
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("linked collection inputs are not supported")
            if path.is_file():
                files[path.relative_to(root).as_posix()] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
            elif not path.is_dir():
                raise ValueError("unsupported collection input member")
    return files


def project_run(
    root: Path, planned: dict, plan: dict, catalog, processor_root: Path,
    *, catalog_relative: str = "config/supplemental-catalog.yaml",
) -> dict:
    """Keep all native/raw24 checks before deriving the separate HTTP vector."""
    from ml.dataset_audit import _audit_run
    from ml.scenario_collection import (
        RunDraft,
        SourceConfig,
        _read_evidence_rows,
        _validate_campaign_attempt,
        _verify_full_capture_parity,
    )
    from scripts.verify_run_evidence import verify_run_evidence

    rid = planned["run_id"]
    evidence = root / "evidence/scenario-runs" / rid
    state = json.loads((evidence / ".collection_state.json").read_bytes())
    draft = RunDraft.model_validate(state["draft"])
    source = SourceConfig.model_validate(state["source"])
    if (
        draft.campaign_plan != plan
        or source.feature_scope != "full-window"
        or any(
            getattr(source, k) is not True
            for k in ("require_clean_bucket", "require_flow_counters", "require_online_parity")
        )
    ):
        raise ValueError("run lacks its exact registered plan or required full-capture guards")
    _validate_campaign_attempt(draft, root)
    check = verify_run_evidence(rid, root)
    if check["status"] != "RUN_EVIDENCE_CHECK_PASS":
        raise ValueError("native evidence verification requires review")

    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    raw_schema = json.loads((processor_root / "ml/feature_schema.json").read_bytes())
    manifest, incidents, errors = _audit_run(
        root / "data/raw" / rid / "scenario_manifest.json",
        root / "evidence/scenario-runs",
        raw_schema,
        {s.scenario_id: s for s in catalog.scenarios},
        sha(processor_root / catalog_relative),
        sha(processor_root / "ml/feature_schema.json"),
        sha(evidence / "collection-sources.yaml"),
        sha(processor_root / "config/suspicious-process-taxonomy.yaml"),
        require_context=True,
    )
    if errors or manifest is None or len(incidents) != 1:
        raise ValueError("sealed raw24 run audit failed: " + "; ".join(errors))
    original = incidents[0]
    # _audit_run independently replayed and compared the original24 vector.
    # The new representation never substitutes for that mandatory old check.
    rich = _verify_full_capture_parity(
        _read_evidence_rows(evidence / "archive_capture.jsonl"),
        original,
        source,
        evidence,
        compare=False,
        feature_profile=lineage.SCHEMA_VERSION,
    )
    # Replay has its own group ID. Preserve the sealed original incident envelope
    # and references; only explicitly versioned representation/quality fields evolve.
    from api.app.contracts import HttpIncidentRequest

    projected = original.model_dump(mode="json")
    projected.update(
        feature_schema_version=lineage.SCHEMA_VERSION,
        features=rich.features,
        indicator=rich.indicator,
        indicator_attribution=(
            rich.indicator_attribution.model_dump(mode="json")
            if rich.indicator_attribution
            else None
        ),
        observation_quality=rich.observation_quality,
        review_reasons=rich.review_reasons,
    )
    projected = HttpIncidentRequest.model_validate(projected)
    row = dict(
        incident_id=original.incident_id,
        scenario_id=manifest.scenario_id,
        run_id=rid,
        family=manifest.family,
        label=int(manifest.label == "malicious"),
        features=rich.features,
        source_file=f"data/raw/{rid}/incidents.jsonl",
        purpose=manifest.purpose,
        cohort_id=manifest.cohort_id,
        incident=projected.model_dump(mode="json"),
        source_incident=original.model_dump(mode="json"),
        evaluation_group_id=planned["context"]["evaluation_group_id"],
        template_id=planned["template_id"],
        planned_run_id=planned["planned_run_id"],
        attempt_number=planned["attempt_number"],
        campaign_plan_sha256=digest(plan),
        collection_context=planned["context"],
    )
    schema = json.loads((processor_root / lineage.SCHEMA_RELATIVE).read_bytes())
    lineage.validate_row(row, planned, schema, plan)
    return row


def audit_collection(
    root: Path, plan_path: Path, *, processor_root: Path = lineage.ROOT,
    source_module=None, catalog_relative: str = "config/supplemental-catalog.yaml",
):
    """Return report + private records; callers must never print the locked records."""
    import yaml

    from ml.collection_release import verify_frozen_acceptance
    from ml.scenario_collection import CollectionError, ScenarioCatalog

    authority = lineage if source_module is None else source_module
    review, head = authority.policy(processor_root)
    root, plan_path = root.resolve(), plan_path.resolve()
    catalog = ScenarioCatalog.model_validate(
        yaml.safe_load(
            (processor_root / catalog_relative).read_bytes(),
        )
    )
    design = catalog.campaign_design
    plan = read_object(plan_path)
    verify_plan(plan, design)
    before = input_inventory(root, plan_path)
    selected, issues = select_attempts(plan, root)
    if (root / "evidence/scenario-runs/.active-run.json").exists():
        issues.append(dict(code="ACTIVE_COLLECTION", run_id="CAMPAIGN"))
    parts = {role: [] for role in authority.ROLES}
    candidate = accepted = None
    expected_attempts = {a["run_id"] for r in plan["runs"] for a in r["attempts"]}
    for directory in (root / "data/raw").iterdir():
        if not directory.is_dir():
            issues.append(dict(code="UNEXPECTED_RAW_LAYOUT", run_id=directory.name))
            continue
        state_path = root / "evidence/scenario-runs" / directory.name / ".collection_state.json"
        state = read_object(state_path) if state_path.exists() else {}
        if directory.name not in expected_attempts and state.get("draft", {}).get(
            "purpose"
        ) not in {
            "pilot",
            "challenge",
        }:
            issues.append(dict(code="UNPLANNED_RAW_DATA", run_id=directory.name))
    for planned in selected:
        rid = planned["run_id"]
        try:
            evidence = root / "evidence/scenario-runs" / rid
            state = json.loads((evidence / ".collection_state.json").read_bytes())
            verify_frozen_acceptance(state)
            origin, registration = state["collection_candidate"], state["collection_release"]
            if candidate is None:
                authority.verify_candidate(origin, review, processor_root)
            if (
                registration.get("version") != "collection-acceptance-v3"
                or registration["campaign_registration"]["plan"] != plan
                or candidate is not None
                and origin != candidate
                or accepted is not None
                and registration != accepted
            ):
                raise ValueError(
                    "mixed source/runtime/G7/plan identities in prospective collection"
                )
            candidate, accepted = origin, registration
            parts[planned["partition"]].append(
                project_run(
                    root, planned, plan, catalog, processor_root,
                    catalog_relative=catalog_relative,
                )
            )
        except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
            issues.append(
                dict(code="RAW_EVIDENCE_OR_FEATURES_INVALID", run_id=rid, detail=str(exc))
            )
    if accepted is not None:
        from scripts.verify_run_evidence import verify_run_evidence

        for pilot in accepted["pilots"]:
            try:
                rid = pilot["run_id"]
                for relative, key in (
                    (f"data/raw/{rid}/scenario_manifest.json", "manifest_sha256"),
                    (f"evidence/scenario-runs/{rid}/.collection_state.json", "state_sha256"),
                    (f"evidence/scenario-runs/{rid}/checksums.sha256", "checksums_sha256"),
                ):
                    if hashlib.sha256((root / relative).read_bytes()).hexdigest() != pilot[key]:
                        raise ValueError("G7 pilot bytes differ from the accepted commitments")
                if (
                    verify_run_evidence(pilot["run_id"], root)["status"]
                    != "RUN_EVIDENCE_CHECK_PASS"
                ):
                    raise ValueError("G7 pilot needs review")
            except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
                issues.append(
                    dict(code="G7_PILOT_INVALID", run_id=pilot["run_id"], detail=str(exc))
                )
    schema = json.loads((processor_root / lineage.SCHEMA_RELATIVE).read_bytes())
    representation = representation_audit(parts["train"], schema)
    if representation["selected_input_collisions"]:
        issues.append(dict(code="TRAIN_SELECTED_REPRESENTATION_AMBIGUITY", run_id="CAMPAIGN"))
    if input_inventory(root, plan_path) != before:
        raise ValueError("collection inputs changed during native replay/audit")
    if authority.policy(processor_root) != (review, head):
        raise ValueError("processing code or review changed during collection audit")
    report = dict(
        status="SUPPLEMENTAL_COLLECTION_AUDIT_FAIL"
        if issues
        else "SUPPLEMENTAL_COLLECTION_AUDIT_PASS",
        planned_units=len(plan["runs"]),
        verified_units=sum(len(v) for v in parts.values()),
        issues=issues,
        counts={r: len(v) for r, v in parts.items()},
        strata={
            f"{family}-{label}": sum(
                r["family"] == family and r["label"] == label
                for rows in parts.values()
                for r in rows
            )
            for family in ("account", "c2")
            for label in (0, 1)
        },
        input_inventory_sha256=digest(before),
        plan_sha256=digest(plan),
        training_representation=representation,
        held_out_features_used_for_selection=False,
    )
    return report, parts, candidate, accepted, design, plan


def assemble_manifest(
    audited, review: dict, head: str, runtime: dict, processor_root: Path
) -> dict:
    report, parts, candidate, accepted, design, plan = audited
    if (
        report["status"] != "SUPPLEMENTAL_COLLECTION_AUDIT_PASS"
        or report["counts"] != lineage.COUNTS
        or runtime not in review["processing_runtimes"]
    ):
        raise ValueError("only a complete audited campaign in a reviewed runtime may be built")
    rows = [r for role in lineage.ROLES for r in parts[role]]
    commitments = {role: partition_commitment(parts[role]) for role in lineage.ROLES}
    certificate = dict(
        version="supplemental-source-compatibility-v1",
        candidate=candidate,
        acceptance_sha256=digest(accepted),
        design_sha256=digest(design),
        plan_sha256=digest(plan),
        input_inventory_sha256=report["input_inventory_sha256"],
        processing_sha256=review["processing_sha256"],
        processing_runtime=runtime,
    )
    return dict(
        manifest_version=lineage.MANIFEST_VERSION,
        feature_schema_version=lineage.SCHEMA_VERSION,
        feature_schema_sha256=hashlib.sha256(
            (processor_root / lineage.SCHEMA_RELATIVE).read_bytes()
        ).hexdigest(),
        group_key="evaluation_group_id",
        evaluation_protocol=lineage.PROTOCOL,
        design=design,
        plan=plan,
        design_sha256=digest(design),
        plan_sha256=digest(plan),
        locked_test_status="UNOPENED",
        record_counts={k: len(v) for k, v in parts.items()},
        partitions=commitments,
        locked_test_sha256=commitments["locked_test"]["sha256"],
        dataset_hash_sha256=canonical_dataset_hash(rows),
        row_commitments={run_key(r["run_id"]): digest(r) for r in rows},
        run_partitions={run_key(r["run_id"]): role for role, group in parts.items() for r in group},
        unit_membership={run_key(r["planned_run_id"]): run_key(r["run_id"]) for r in rows},
        provenance=dict(
            builder_git_commit=head,
            processing_sha256=review["processing_sha256"],
            processing_runtime=runtime,
            source_compatibility_sha256=digest(certificate),
            builder_config_sha256=hashlib.sha256(
                (processor_root / lineage.CONFIG_RELATIVE).read_bytes()
            ).hexdigest(),
        ),
        collection_audit={**report, "source_compatibility": certificate},
    )


def build_dataset(
    root: Path, plan_path: Path, output: Path, *, processor_root: Path = lineage.ROOT
):
    import yaml

    review, head = lineage.policy(processor_root)
    runtime = runtime_identity()
    if runtime not in review["processing_runtimes"]:
        raise ValueError("builder runtime is outside the reviewed inventory")
    output = output.resolve()
    config = yaml.safe_load((processor_root / lineage.CONFIG_RELATIVE).read_bytes())
    declared = (processor_root / config["data"]["processed_dir"]).resolve()
    if (
        output.exists()
        or output != declared
        or output.parent != (processor_root / "data").resolve()
    ):
        raise ValueError("build output must be the fresh directory declared by the pinned config")
    audited = audit_collection(root, plan_path, processor_root=processor_root)
    manifest = assemble_manifest(audited, review, head, runtime, processor_root)
    if digest(input_inventory(root, plan_path)) != manifest["collection_audit"][
        "input_inventory_sha256"
    ] or lineage.policy(processor_root) != (review, head):
        raise ValueError("raw inputs or processing source changed after audit")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tmp-supplemental-build-", dir=output.parent) as temp:
        pending = Path(temp) / "complete"
        pending.mkdir()
        for role, rows in audited[1].items():
            raw = partition_bytes(rows)
            if hashlib.sha256(raw).hexdigest() != manifest["partitions"][role]["sha256"]:
                raise ValueError("prospective partition serialization changed")
            (pending / f"{role}.jsonl").write_bytes(raw)
        (pending / "dataset_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        receipt = dict(
            status="BUILT_REQUIRES_EXACT_REVIEW",
            manifest_sha256=digest(manifest),
            record_counts=manifest["record_counts"],
            builder_commit=head,
            locked_features_used_for_selection=False,
        )
        (pending / "build_receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        # Close the replay/write gap as well as the earlier audit/write gap.
        if digest(input_inventory(root, plan_path)) != manifest["collection_audit"][
            "input_inventory_sha256"
        ] or lineage.policy(processor_root) != (review, head):
            raise ValueError("collection/source changed while preparing the atomic dataset")
        pending.rename(output)
    return receipt


def stage_dataset(processed: Path, output: Path):
    output = output.resolve()
    if output.is_relative_to(lineage.ROOT.resolve()):
        raise ValueError("Colab staging output must be outside the source checkout")
    _, _, manifest = lineage.load_partitions(
        processed,
        lineage.ROOT / lineage.SCHEMA_RELATIVE,
        config_path=lineage.ROOT / lineage.CONFIG_RELATIVE,
    )
    review, head = lineage.policy(lineage.ROOT, require_ready=True)
    if output.exists():
        raise ValueError("staging output exists; preserve the previous handoff")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tmp-supplemental-stage-", dir=output.parent) as temp:
        pending = Path(temp) / "complete"
        pending.mkdir()
        checksums = []
        for name in ("train.jsonl", "validation.jsonl", "dataset_manifest.json"):
            raw = (processed / name).read_bytes()
            if name == "dataset_manifest.json":
                valid = digest(json.loads(raw)) == digest(manifest)
            else:
                role = name.removesuffix(".jsonl")
                valid = hashlib.sha256(raw).hexdigest() == manifest["partitions"][role]["sha256"]
            if not valid:
                raise ValueError("visible data changed after staging validation")
            (pending / name).write_bytes(raw)
            checksums.append(f"{hashlib.sha256(raw).hexdigest()}  {name}\n")
        (pending / "colab-upload.sha256").write_text(
            "".join(checksums), encoding="utf-8", newline="\n"
        )
        if lineage.policy(lineage.ROOT, require_ready=True) != (review, head):
            raise ValueError("source/review changed during safe staging")
        pending.rename(output)
    return dict(
        status="FOUR_SAFE_FILES_STAGED", output=str(output), manifest_sha256=digest(manifest)
    )


def propose_review(root: Path, plan_path: Path, processed: Path, output: Path):
    """Replay the raw again; write a proposal, never silently change the source review."""
    review, head = lineage.policy(lineage.ROOT)
    if runtime_identity() not in review["processing_runtimes"]:
        raise ValueError("review replay runtime is outside the approved inventory")
    manifest = read_object(processed / "dataset_manifest.json")
    from ml.training_sources import _git

    builder = manifest["provenance"]["builder_git_commit"]
    if lineage.processing_hash(lineage.ROOT, builder) != review["processing_sha256"]:
        raise ValueError("recorded builder used different processing code")
    _git(lineage.ROOT, "merge-base", "--is-ancestor", builder, head)
    audited = audit_collection(root, plan_path)
    reproduced = assemble_manifest(
        audited,
        review,
        builder,
        manifest["provenance"]["processing_runtime"],
        lineage.ROOT,
    )
    if reproduced != manifest:
        raise ValueError("raw replay does not reproduce the exact proposed manifest")
    for role in lineage.ROLES:
        # Hash the locked bytes only. Its feature values never drive selection/review diagnostics.
        if (
            hashlib.sha256((processed / f"{role}.jsonl").read_bytes()).hexdigest()
            != (manifest["partitions"][role]["sha256"])
        ):
            raise ValueError("a proposed partition file differs from its raw replay")
    if digest(input_inventory(root, plan_path)) != audited[0][
        "input_inventory_sha256"
    ] or lineage.policy(lineage.ROOT) != (review, head):
        raise ValueError("raw or source changed during exact review proposal")
    proposal = {**review, "status": "READY", "approved_manifest_sha256": digest(manifest)}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(proposal, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return dict(
        status="EXACT_REVIEW_PROPOSAL_WRITTEN",
        output=str(output),
        manifest_sha256=digest(manifest),
        source_review_changed=False,
    )


def main(argv=None) -> int:
    from ml.scenario_collection import CollectionError

    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("audit", "build", "propose-review"):
        sub = commands.add_parser(name)
        sub.add_argument("--input-project", type=Path, required=True)
        sub.add_argument("--plan", type=Path, required=True)
        sub.add_argument("--output", type=Path, required=True)
        if name == "propose-review":
            sub.add_argument("--processed", type=Path, required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--processed", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        if a.command == "stage":
            report = stage_dataset(a.processed, a.output)
        elif a.command == "build":
            report = build_dataset(a.input_project, a.plan, a.output)
        elif a.command == "propose-review":
            report = propose_review(a.input_project, a.plan, a.processed, a.output)
        else:
            report = audit_collection(a.input_project, a.plan)[0]
            a.output.parent.mkdir(parents=True, exist_ok=True)
            with a.output.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(report, stream, indent=2, sort_keys=True)
                stream.write("\n")
        print(json.dumps(report, indent=2, sort_keys=True))
        return int(report.get("status") == "SUPPLEMENTAL_COLLECTION_AUDIT_FAIL")
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
