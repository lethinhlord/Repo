"""Verify a candidate and create an evidence-bound collection acceptance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.collection_release import (
    ReleaseError,
    capture_candidate,
    create_acceptance,
    create_backup,
    verify_remote_candidate,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)
    candidate = sub.add_parser("candidate")
    candidate.add_argument("--tag", required=True)
    candidate.add_argument("--check-remote", action="store_true")
    accept = sub.add_parser("accept")
    accept.add_argument("--tag", required=True)
    accept.add_argument("--pilot", action="append", required=True)
    accept.add_argument("--backup-dir", type=Path, required=True)
    accept.add_argument("--preflight-dir", type=Path, required=True)
    accept.add_argument("--output", type=Path, required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("--tag", required=True)
    backup.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "candidate":
            result = capture_candidate(args.project_root, args.tag)
            if args.check_remote:
                verify_remote_candidate(args.project_root, result)
        elif args.command == "backup":
            result = create_backup(args.project_root, args.tag, args.output_directory)
        else:
            result = create_acceptance(
                args.project_root,
                args.tag,
                args.pilot,
                args.backup_dir,
                args.preflight_dir,
                args.output,
            )
    except (ReleaseError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
