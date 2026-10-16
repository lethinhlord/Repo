from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.dataset_audit import audit_dataset, format_audit_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit four-stratum DATN training data")
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument(
        "--evidence-dir", type=Path, default=Path("evidence/scenario-runs")
    )
    parser.add_argument("--minimum-runs", type=int, default=10)
    parser.add_argument("--target-runs", type=int, default=12)
    parser.add_argument("--minimum-scenarios", type=int, default=3)
    parser.add_argument("--maximum-scenario-share", type=float, default=0.40)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-target", action="store_true")
    args = parser.parse_args()

    report = audit_dataset(
        args.raw_dir,
        args.evidence_dir,
        minimum_runs=args.minimum_runs,
        target_runs=args.target_runs,
        minimum_scenarios=args.minimum_scenarios,
        maximum_scenario_share=args.maximum_scenario_share,
    )
    print(format_audit_report(report), end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(f".{args.output.name}.tmp")
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(args.output)
    if report["status"] == "NOT_READY":
        return 1
    if args.require_target and report["status"] != "TARGET_MET":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
