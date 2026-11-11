"""Prepare an active source from a verified pilot and a fresh real enrollment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import yaml

from ml.context import BaselineSnapshot, verify_baseline_capture, verify_lab_enrollment
from ml.scenario_collection import SourceConfig
from scripts.verify_run_evidence import verify_run_evidence


def require_fresh_baseline(root, baseline_path, windows_agent_name, *, now=None):
    path = Path(baseline_path)
    if not path.is_absolute():
        path = root / path
    baseline = BaselineSnapshot.model_validate_json(path.read_bytes())
    capture = path.parent / "context-captures" / (baseline.source_capture_sha256 + ".jsonl")
    raw = capture.read_bytes()
    verify_baseline_capture(baseline, raw, windows_agent_name=windows_agent_name)
    verify_lab_enrollment(baseline, raw)
    at = now or datetime.now(UTC)
    if not baseline.captured_at <= at < baseline.valid_until:
        raise ValueError("active enrollment is expired or future; collect a fresh enrollment first")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--pilot", required=True)
    parser.add_argument("--baseline", default="evidence/context-baseline.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        root = args.project_root.resolve()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{3,127}", args.pilot):
            raise ValueError("invalid pilot ID")
        report = verify_run_evidence(args.pilot, root)
        if report.get("status") != "RUN_EVIDENCE_CHECK_PASS":
            raise ValueError("pilot evidence did not pass")
        frozen = root / "evidence/scenario-runs" / args.pilot / "collection-sources.yaml"
        document = yaml.safe_load(frozen.read_text(encoding="utf-8"))
        source = SourceConfig.model_validate(document)
        require_fresh_baseline(root, args.baseline, source.windows_agent_name)
        document["context_baseline_path"] = args.baseline
        output = args.output if args.output.is_absolute() else root / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            yaml.safe_dump(document, stream, sort_keys=False)
        print(json.dumps({"status": "ACTIVE_SOURCE_PREPARED", "path": str(output),
                          "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
