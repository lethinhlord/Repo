"""Verify a candidate and create an evidence-bound collection acceptance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.collection_release import (
    ReleaseError,
    assert_collection_authorized,
    capture_candidate,
    create_acceptance,
    create_backup,
    verify_remote_candidate,
)


def _active_source(root: Path, path: Path):
    import yaml

    from ml.scenario_collection import SourceConfig
    from scripts.prepare_collection_source import require_fresh_baseline

    selected = path if path.is_absolute() else root / path
    source = SourceConfig.model_validate(yaml.safe_load(selected.read_text(encoding="utf-8")))
    if not source.context_baseline_path:
        raise ReleaseError("active source requires an enrollment baseline")
    require_fresh_baseline(root, source.context_baseline_path, source.windows_agent_name)
    return selected, source


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
    accept.add_argument("--source-config", type=Path)
    authorize = sub.add_parser("authorize", help="revalidate G7 before creating trainable runs")
    authorize.add_argument("--source-config", type=Path, required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("--tag", required=True)
    backup.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "candidate":
            result = capture_candidate(args.project_root, args.tag)
            if args.check_remote:
                verify_remote_candidate(args.project_root, result)
        elif args.command == "authorize":
            selected, source = _active_source(args.project_root.resolve(), args.source_config)
            record = assert_collection_authorized(source, args.project_root, "trainable", selected)
            result = {"status": "COLLECTION_AUTHORIZED", "candidate": record["candidate"],
                      "record_sha256": record["record_sha256"]}
        elif args.command == "backup":
            result = create_backup(args.project_root, args.tag, args.output_directory)
        else:
            if args.source_config is not None:
                _active_source(args.project_root.resolve(), args.source_config)
            result = create_acceptance(
                args.project_root,
                args.tag,
                args.pilot,
                args.backup_dir,
                args.preflight_dir,
                args.output,
                source_config_path=args.source_config,
            )
    except (ReleaseError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
