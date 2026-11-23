"""Prospective campaign commands; never creates telemetry or fabricates acceptance."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import yaml

from ml.scenario_collection import ClockPreflight, CollectionError, SourceConfig, create_run_draft
from ml.supplemental_design import (
    load_design,
    make_plan,
    resolve_plan_run,
    slots,
    verify_plan,
    write_plan,
)


def _path(root: Path, value: Path | str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else root / p


def registration_template(design: dict, start: date, operator: str) -> dict:
    contexts = []
    for slot in slots(design):
        ordinal = int(slot["cohort_id"].rsplit("-", 1)[-1]) - 1
        contexts.append(
            dict(
                cohort_id=slot["cohort_id"],
                partition=slot["partition"],
                collection_date=(start + timedelta(days=(
                    ordinal // 4 if design["version"] == "development-design-v1" else ordinal
                ))).isoformat(),
                host=design["windows_host"],
                operator=operator,
                environment_id="TODO record real VM image/configuration",
                application_context="TODO record actual applications and session context",
                reset_reference="TODO record actual reset/snapshot reference",
            )
        )
    return {
        "version": "supplemental-registration-v1",
        "campaign_id": design["campaign_id"],
        "contexts": contexts,
    }


def campaign_progress(plan: dict, root: Path, day: str) -> dict:
    """Scheduling hint only; the full dataset auditor must independently verify bytes."""
    date.fromisoformat(day)
    completed, due, active, exhausted = [], [], [], []
    for unit in plan["runs"]:
        seen = []
        for attempt in unit["attempts"]:
            p = root / "evidence/scenario-runs" / attempt["run_id"] / ".collection_state.json"
            status = json.loads(p.read_bytes()).get("status") if p.exists() else "NOT_STARTED"
            seen.append((attempt["run_id"], status))
        finalized = [rid for rid, status in seen if status == "FINALIZED"]
        if len(finalized) > 1:
            raise ValueError("multiple finalized attempts for one planned unit; stop and audit")
        if finalized:
            completed.append(finalized[0])
        elif any(status not in {"ABORTED", "NOT_STARTED"} for _, status in seen):
            active.extend(rid for rid, status in seen if status not in {"ABORTED", "NOT_STARTED"})
        else:
            available = next((rid for rid, status in seen if status == "NOT_STARTED"), None)
            if available is None:
                exhausted.append(unit["run_id"])
            elif unit["context"]["collection_date"] == day:
                due.append(resolve_plan_run(plan, available))
    return dict(
        status="SCHEDULE_ONLY_REQUIRES_FULL_AUDIT",
        planned_units=len(plan["runs"]),
        finalized_attempts=len(completed),
        due=due,
        active_attempts=active,
        exhausted_units=exhausted,
        utc_date=day,
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project-root", type=Path, default=Path.cwd())
    p.add_argument("--design", type=Path, default=Path("config/supplemental-design.yaml"))
    commands = p.add_subparsers(dest="command", required=True)
    template = commands.add_parser("registration-template")
    template.add_argument("--start-date", type=date.fromisoformat, required=True)
    template.add_argument("--operator", required=True)
    template.add_argument("--output", type=Path, required=True)
    planner = commands.add_parser("plan")
    planner.add_argument("--registration", type=Path, required=True)
    planner.add_argument("--seed", type=int, default=42)
    planner.add_argument("--output", type=Path, required=True)
    for command in ("verify-plan", "progress", "draft"):
        item = commands.add_parser(command)
        item.add_argument("--plan", type=Path, required=True)
        if command == "progress":
            item.add_argument("--date", default=datetime.now(UTC).date().isoformat())
        if command == "draft":
            item.add_argument("--run-id", required=True)
            item.add_argument("--clock-preflight", type=Path, required=True)
            item.add_argument(
                "--source-config", type=Path, default=Path("config/supplemental-sources.yaml")
            )
            item.add_argument("--execution-log", required=True)
            item.add_argument("--output", type=Path, required=True)
    params = commands.add_parser("parameters")
    params.add_argument("--run-id", required=True)
    params.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    root = a.project_root.resolve()
    try:
        design = load_design(_path(root, a.design))
        if a.command == "registration-template":
            write_plan(
                _path(root, a.output), registration_template(design, a.start_date, a.operator)
            )
            result = {"status": "TEMPLATE_REQUIRES_REAL_CONTEXTS", "output": str(a.output)}
        elif a.command == "plan":
            registration = yaml.safe_load(_path(root, a.registration).read_text(encoding="utf-8"))
            plan = make_plan(design, registration, seed=a.seed)
            write_plan(_path(root, a.output), plan)
            result = {
                "status": "PLAN_FROZEN",
                "plan_sha256": plan["plan_sha256"],
                "planned_units": len(plan["runs"]),
            }
        elif a.command == "parameters":
            from scripts.export_run_parameters import load_frozen_parameters

            frozen, sha = load_frozen_parameters(root, a.run_id)
            # Native runners accept a flat, collector-frozen object; no manual copying.
            write_plan(
                _path(root, a.output),
                {**frozen["scenario_parameters"], "frozen_parameters_sha256": sha},
            )
            result = {
                "status": "FROZEN_PARAMETERS_EXPORTED",
                "run_id": a.run_id,
                "output": str(a.output),
                "frozen_parameters_sha256": sha,
            }
        else:
            plan = json.loads(_path(root, a.plan).read_bytes())
            verify_plan(plan, design)
            if a.command == "verify-plan":
                result = {
                    "status": "PLAN_VERIFIED",
                    "plan_sha256": plan["plan_sha256"],
                    "planned_units": len(plan["runs"]),
                }
            elif a.command == "progress":
                result = campaign_progress(plan, root, a.date)
            else:
                source_path = _path(root, a.source_config)
                source = SourceConfig.model_validate(yaml.safe_load(source_path.read_bytes()))
                row = resolve_plan_run(plan, a.run_id)
                result = create_run_draft(
                    _path(root, source.scenario_catalog_path),
                    row["scenario_id"],
                    row["run_id"],
                    row["context"]["operator"],
                    _path(root, a.output),
                    host=row["context"]["host"],
                    collection_seed=row["collection_seed"],
                    execution_log_path=a.execution_log,
                    source_config_path=source_path,
                    campaign_plan=plan,
                    clock_preflight=ClockPreflight.model_validate(
                        yaml.safe_load(
                            _path(root, a.clock_preflight).read_bytes(),
                        )
                    ),
                )
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
