"""Create predeclared execution metadata; never creates telemetry or training samples."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import secrets
from datetime import UTC, datetime
from pathlib import Path

import yaml

from ml.collection_design import load_collection_design
from ml.scenario_collection import ScenarioCatalog


def make_plan(catalog_path: Path, kind: str, seed: int, stamp: str) -> dict:
    design = load_collection_design(catalog_path)
    if design is None:
        raise ValueError("official collection design required")
    catalog = ScenarioCatalog.model_validate(
        yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    )
    rng = random.Random(seed)
    scenarios = {s.scenario_id: s for s in catalog.scenarios}
    if kind == "pilot":
        selected = [
            scenarios[n]
            for n in (
                "ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS",
                "ACCOUNT-MALICIOUS-REPEATED-FAILURES-6",
                "C2-BENIGN-DNS",
                "C2-MALICIOUS-HTTP-BEACON",
            )
        ]
    elif kind == "challenge":
        selected = [s for s in catalog.scenarios if s.purpose == "challenge"]
    elif kind in {"minimum", "preferred"}:
        counts = {
            x["cohort_id"]: x[
                "target_runs_per_scenario" if kind == "preferred" else "minimum_runs_per_scenario"
            ]
            for x in design["cohorts"]
        }
        selected = [
            s
            for s in catalog.scenarios
            if s.purpose == "trainable"
            for _ in range(counts[s.cohort_id])
        ]
    else:
        raise ValueError("unknown plan kind")
    rng.shuffle(selected)
    seeds = set()
    runs = []
    for number, s in enumerate(selected, 1):
        run_seed = rng.getrandbits(32)
        while run_seed in seeds:
            run_seed = rng.getrandbits(32)
        seeds.add(run_seed)
        purpose = "pilot" if kind == "pilot" else s.purpose
        rid = f"{purpose.upper()}-{s.scenario_id}-{stamp}-{number:03d}"
        if len(rid) > 128:
            raise ValueError("planned run_id too long")
        runs.append(
            {
                "ordinal": number,
                "scenario_id": s.scenario_id,
                "run_id": rid,
                "purpose": purpose,
                "cohort_id": s.cohort_id,
                "collection_seed": run_seed,
            }
        )
    return {
        "version": "collection-plan-v1",
        "kind": kind,
        "plan_seed": seed,
        "catalog_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
        "design_sha256": design["sha256"],
        "runs": runs,
        "telemetry_created": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("config/scenario-catalog.yaml"))
    parser.add_argument(
        "--kind", choices=("pilot", "minimum", "preferred", "challenge"), required=True
    )
    parser.add_argument("--seed", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = make_plan(
        args.catalog,
        args.kind,
        args.seed if args.seed is not None else secrets.randbits(32),
        datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"Plan saved: {args.output}; {len(result['runs'])} planned executions, zero telemetry")


if __name__ == "__main__":
    main()
