from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.scenario_collection import (
    CollectionError,
    abort_run,
    begin_action,
    complete_action,
    finalize_run,
    quarantine_run,
    run_status,
    start_run,
    validate_run,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Fail-closed DATN scenario collector")
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    subcommands = result.add_subparsers(dest="command", required=True)

    start = subcommands.add_parser("start")
    start.add_argument("--draft", type=Path, required=True)
    start.add_argument(
        "--source-config", type=Path, default=Path("config/collection-sources.yaml")
    )

    for name in ("begin-action", "complete-action", "finalize", "validate", "status"):
        command = subcommands.add_parser(name)
        command.add_argument("--run-id", required=True)

    abort = subcommands.add_parser("abort")
    abort.add_argument("--run-id", required=True)
    abort.add_argument("--reason", required=True)
    quarantine = subcommands.add_parser("quarantine")
    quarantine.add_argument("--run-id", required=True)
    quarantine.add_argument("--reason", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    root = args.project_root.resolve()
    try:
        if args.command == "start":
            payload = start_run(args.draft, args.source_config, root)
        elif args.command == "begin-action":
            payload = begin_action(args.run_id, root)
        elif args.command == "complete-action":
            payload = complete_action(args.run_id, root)
        elif args.command == "finalize":
            payload = finalize_run(args.run_id, root)
        elif args.command == "validate":
            payload = validate_run(args.run_id, root)
        elif args.command == "status":
            payload = run_status(args.run_id, root)
        elif args.command == "abort":
            payload = abort_run(args.run_id, root, args.reason)
        else:
            payload = quarantine_run(args.run_id, root, args.reason)
    except CollectionError as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}, indent=2))
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
