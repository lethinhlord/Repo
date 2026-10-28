from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from ml.scenario_collection import ClockPreflight, CollectionError, create_run_draft


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a validated run draft from the controlled scenario catalog"
    )
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--host", default="WIN11-TARGET")
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("config/scenario-catalog.yaml"),
    )
    parser.add_argument("--execution-log", type=str)
    parser.add_argument("--collection-seed", type=int)
    parser.add_argument("--purpose", choices=("trainable", "challenge", "pilot"))
    parser.add_argument("--clock-preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    output = args.output or Path("run-drafts") / f"{args.run_id}.yaml"
    try:
        payload = create_run_draft(
            catalog_path=args.catalog,
            scenario_id=args.scenario,
            run_id=args.run_id,
            operator=args.operator,
            output_path=output,
            host=args.host,
            execution_log_path=args.execution_log,
            collection_seed=args.collection_seed,
            purpose=args.purpose,
            clock_preflight=ClockPreflight.model_validate(
                yaml.safe_load(args.clock_preflight.read_text(encoding="utf-8"))
            ),
        )
    except (CollectionError, OSError, ValueError, yaml.YAMLError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}, indent=2))
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
