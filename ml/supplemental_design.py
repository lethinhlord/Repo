"""Prospective registrations and immutable plans; never creates telemetry."""

from __future__ import annotations

import json
import random
import re
from collections import defaultdict
from datetime import date
from pathlib import Path

from ml.training_sources import digest

ROLES = ("train", "validation", "locked_test")
FAMILIES = ("account", "c2")
CONTEXT_FIELDS = {
    "cohort_id",
    "collection_date",
    "environment_id",
    "host",
    "application_context",
    "reset_reference",
    "operator",
    "partition",
}


def load_design(path: Path) -> dict:
    import yaml

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    validate_design(value)
    return value


def validate_design(value: dict) -> None:
    if isinstance(value, dict) and value.get("version") == "development-design-v1":
        from ml.development_design import validate_development_design

        validate_development_design(value)
        return
    expected = {
        "version",
        "campaign_id",
        "candidate_tag",
        "scope",
        "evaluation_protocol",
        "raw_feature_schema",
        "derived_feature_schema",
        "automation_eligible",
        "partition_contexts",
        "repetitions_per_label",
        "maximum_attempts_per_run",
        "minimum_host_days_per_partition",
        "dependency_block",
        "http_endpoint",
        "windows_host",
        "templates",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["version"] != "supplemental-design-v1"
        or value["evaluation_protocol"] != "known-template-new-host-day"
        or value["partition_contexts"] != dict(train=10, validation=4, locked_test=4)
        or any(type(v) is not int for v in value["partition_contexts"].values())
        or type(value["repetitions_per_label"]) is not int
        or value["repetitions_per_label"] != 3
        or type(value["maximum_attempts_per_run"]) is not int
        or value["maximum_attempts_per_run"] != 3
        or type(value["minimum_host_days_per_partition"]) is not int
        or value["minimum_host_days_per_partition"] != 3
        or value["automation_eligible"] is not False
        or value["raw_feature_schema"] != "features-v3"
        or value["derived_feature_schema"] != "features-v5-http-v1"
        or value["dependency_block"] != "casefolded-host-and-utc-date"
        or value["http_endpoint"] != "http://10.40.0.10:8081/beacon"
        or value["windows_host"] != "WIN11-TARGET"
    ):
        raise ValueError("invalid supplemental scientific/source contract")
    for name in ("campaign_id", "candidate_tag"):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{3,70}", str(value[name])) is None:
            raise ValueError("invalid campaign/candidate identity")
    if not isinstance(value["scope"], str) or "profiles" not in value["scope"]:
        raise ValueError("supplemental scope must state its lab profiles limitation")
    if set(value["templates"]) != set(FAMILIES):
        raise ValueError("both supplemental families are required")
    for family in FAMILIES:
        rows = value["templates"][family]
        if not isinstance(rows, list) or not 4 <= len(rows) <= 10:
            raise ValueError("insufficient declared behavior template coverage")
        ids = set()
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"id", "benign", "malicious"}
                or not all(isinstance(v, str) and v.strip() for v in row.values())
                or row["id"] in ids
                or row["benign"] == row["malicious"]
            ):
                raise ValueError("invalid paired template identity")
            ids.add(row["id"])


def slots(design: dict) -> list[dict]:
    validate_design(design)
    result = []
    for family in FAMILIES:
        ordinal = 0
        for role in ROLES:
            for _ in range(design["partition_contexts"][role]):
                template = design["templates"][family][ordinal % len(design["templates"][family])]
                ordinal += 1
                result.append(
                    dict(
                        cohort_id=f"{family.upper()}-SUP-{ordinal:02d}",
                        partition=role,
                        family=family,
                        template_id=template["id"],
                    )
                )
    return result


def validate_registration(design: dict, registration: dict) -> dict[str, dict]:
    if (
        not isinstance(registration, dict)
        or set(registration) != {"version", "campaign_id", "contexts"}
        or registration["version"] != "supplemental-registration-v1"
        or registration["campaign_id"] != design["campaign_id"]
        or not isinstance(registration["contexts"], list)
    ):
        raise ValueError("invalid prospective context registration")
    expected = {s["cohort_id"]: s for s in slots(design)}
    contexts, blocks, dates = {}, {}, defaultdict(set)
    for context in registration["contexts"]:
        if (
            not isinstance(context, dict)
            or set(context) != CONTEXT_FIELDS
            or any(not isinstance(v, str) or len(v.strip()) < 3 for v in context.values())
            or any(re.search(r"TODO|PLACEHOLDER|CHANGEME|<|>", v, re.I) for v in context.values())
        ):
            raise ValueError("registration needs real explicit contexts, not placeholders")
        key = context["cohort_id"]
        if key not in expected or key in contexts:
            raise ValueError("duplicate or unknown context slot")
        if (
            context["partition"] != expected[key]["partition"]
            or context["host"].casefold() != design["windows_host"].casefold()
        ):
            raise ValueError("registered host/role differs from the predeclared design")
        at = date.fromisoformat(context["collection_date"])
        if at.isoformat() != context["collection_date"]:
            raise ValueError("registration date must be the canonical UTC calendar date")
        block = digest([context["host"].casefold(), at.isoformat()])
        previous = blocks.setdefault(block, context["partition"])
        if previous != context["partition"]:
            raise ValueError("related host/day contexts cross partitions")
        family = expected[key]["family"]
        dates[(family, context["partition"])].add(at)
        contexts[key] = {**context, "evaluation_group_id": block}
    if set(contexts) != set(expected):
        raise ValueError("prospective registration is incomplete")
    if design["version"] == "development-design-v1":
        from ml.development_design import validate_development_days

        validate_development_days(contexts, expected)
        return contexts
    for family in FAMILIES:
        for role in ROLES:
            if len(dates[(family, role)]) < design["minimum_host_days_per_partition"]:
                raise ValueError("too few actual registered host/day blocks")
        if max(dates[(family, "train")]) >= min(dates[(family, "validation")]) or max(
            dates[(family, "validation")]
        ) >= min(dates[(family, "locked_test")]):
            raise ValueError("prospective roles must be chronological nonoverlapping blocks")
    return contexts


def make_plan(design: dict, registration: dict, *, seed: int) -> dict:
    validate_design(design)
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("plan seed must be a uint32 integer")
    contexts = validate_registration(design, registration)
    rng, used, runs = random.Random(seed), set(), []
    for slot in sorted(
        slots(design),
        key=lambda s: (
            contexts[s["cohort_id"]]["collection_date"],
            s["cohort_id"],
        ),
    ):
        context = contexts[slot["cohort_id"]]
        labels = ["benign", "malicious"] * design["repetitions_per_label"]
        rng.shuffle(labels)
        for repetition, label in enumerate(labels, 1):
            run_id = f"SUP-{design['campaign_id']}-{slot['cohort_id']}-{repetition:02d}"
            if len(run_id) > 124:
                raise ValueError("planned collector identity exceeds its boundary")
            attempts = []
            for attempt in range(1, design["maximum_attempts_per_run"] + 1):
                run_seed = rng.getrandbits(32)
                while run_seed in used:
                    run_seed = rng.getrandbits(32)
                used.add(run_seed)
                attempts.append(
                    {
                        "run_id": run_id if attempt == 1 else f"{run_id}-A{attempt:02d}",
                        "collection_seed": run_seed,
                    }
                )
            runs.append(
                {
                    **slot,
                    "run_id": run_id,
                    "label": label,
                    "scenario_id": f"{slot['cohort_id']}-{label[0].upper()}",
                    "collection_seed": attempts[0]["collection_seed"],
                    "attempts": attempts,
                    "context": context,
                }
            )
    payload = {
        "version": "supplemental-plan-v1",
        "campaign_id": design["campaign_id"],
        "evaluation_protocol": design["evaluation_protocol"],
        "plan_seed": seed,
        "design_sha256": digest(design),
        "registration": registration,
        "registration_sha256": digest(registration),
        "runs": runs,
    }
    return {**payload, "plan_sha256": digest(payload)}


def verify_plan(plan: dict, design: dict) -> None:
    if (
        not isinstance(plan, dict)
        or plan.get("version") != "supplemental-plan-v1"
        or plan != make_plan(design, plan.get("registration"), seed=plan.get("plan_seed"))
    ):
        raise ValueError("plan differs from deterministic design/registration commitments")


def resolve_plan_run(plan: dict, run_id: str) -> dict:
    for row in plan["runs"]:
        for number, attempt in enumerate(row["attempts"], 1):
            if attempt["run_id"] == run_id:
                return {**row, **attempt, "planned_run_id": row["run_id"], "attempt_number": number}
    raise ValueError("run ID is not a predeclared campaign attempt")


def write_plan(path: Path, plan: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(plan, handle, sort_keys=True, indent=2)
        handle.write("\n")
