"""Read-only supplementary run/enrollment checks; never replaces collector validation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ml.scenario_collection import CollectionError, validate_run
from ml.telemetry import (
    basename,
    flow_connection_key,
    network_is_outbound,
    sysmon_clock_issues,
    windows_fields,
)


def _rows(path: Path) -> list[dict[str, Any]]:
    result = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
              if line.strip()]
    if any(not isinstance(row, dict) for row in result):
        raise CollectionError(f"expected event objects in {path.name}")
    return result


def verify_run_evidence(run_id: str, project_root: Path) -> dict[str, Any]:
    root = project_root.resolve()
    validation = validate_run(run_id, root)
    evidence = root / "evidence/scenario-runs" / run_id
    manifest = json.loads((root / "data/raw" / run_id / "scenario_manifest.json").read_text())
    state = json.loads((evidence / ".collection_state.json").read_text())
    metadata = json.loads((evidence / "collection_metadata.json").read_text())
    schema = json.loads((evidence / "feature-schema.json").read_text())
    incident = json.loads((root / "data/raw" / run_id / "incidents.jsonl").read_text())
    for name in ("archive_capture.jsonl", "intake_checkpoint.json", "context-baseline.json",
                 "context-capture.jsonl", "execution_receipt.json", "checksums.sha256"):
        if not (evidence / name).is_file() or not (evidence / name).stat().st_size:
            raise CollectionError(f"missing/empty required evidence: {name}")
    if (metadata.get("feature_schema_version") != "features-v3"
            or schema.get("version") != "features-v3"):
        raise CollectionError("wrong feature schema")
    if set(incident["features"]) != set(schema["required"]) or len(schema["required"]) != 24:
        raise CollectionError("wrong feature fields; never fill missing history with zero")
    if (incident.get("context_status") != "AVAILABLE"
            or incident.get("observation_quality") != "COMPLETE"):
        raise CollectionError("missing context or incomplete observation")
    if any(state["source"].get(key) is not True for key in (
        "require_clean_bucket", "require_flow_counters", "require_online_parity",
    )):
        raise CollectionError("run used a relaxed source contract")
    skew = state["draft"]["clock_preflight"]["maximum_skew_seconds"]
    windows = _rows(evidence / "windows_events.jsonl")
    eve = _rows(evidence / "suricata_eve.jsonl")
    checked = 0
    for number, event in enumerate(windows, 1):
        event_id, system, fields = windows_fields(event)
        if event_id in {"1", "3", "22"}:
            checked += 1
            # Preserve the original runbook's strict raw-export gate. Historical
            # provider-less online adapters remain supported by the central
            # helper, but cannot certify missing native fields in a lab export.
            if not any(key.casefold() == "utctime" for key in fields):
                raise CollectionError(f"missing native Sysmon UTC field line={number}")
            provider = str(system.get("providerName", "")).casefold()
            if provider and provider != "microsoft-windows-sysmon":
                raise CollectionError(f"selected C2 record is not native Sysmon line={number}")
            if reasons := sysmon_clock_issues(event, maximum_skew_seconds=skew):
                raise CollectionError(f"Sysmon UTC mismatch line={number}: {','.join(reasons)}")
    connections = {
        flow_connection_key(event) for event in eve
        if event.get("event_type") in {"http", "dns", "tls"}
    }
    finals = {flow_connection_key(event) for event in eve if event.get("event_type") == "flow"}
    if manifest["family"] == "c2" and (
        not checked or not connections or None in connections or not connections <= finals
    ):
        raise CollectionError("missing Sysmon/final-flow coverage for selected C2 transactions")

    # A valid Security/account run does not certify unrelated destination history.
    # Inspect the frozen mixed enrollment separately, preserving all original rows.
    enrollment_issues = []
    for number, event in enumerate(_rows(evidence / "context-capture.jsonl"), 1):
        if (event.get("agent") or {}).get("name") != state["source"]["windows_agent_name"]:
            continue
        event_id, system, fields = windows_fields(event)
        if event_id not in {"3", "22"} or not basename(fields.get("image")):
            continue
        if event_id == "3" and not network_is_outbound(fields):
            continue
        if reasons := sysmon_clock_issues(event):
            enrollment_issues.append({
                "line": number, "event_record_id": system.get("eventRecordID"),
                "reasons": reasons,
            })
    return {
        "status": "RUN_EVIDENCE_CHECK_REVIEW" if enrollment_issues else "RUN_EVIDENCE_CHECK_PASS",
        "collector_validation": validation,
        "run_id": run_id, "family": manifest["family"], "purpose": manifest["purpose"],
        "sysmon_time_rows": checked,
        "transaction_connections": len(connections), "final_connections": len(finals),
        "enrollment_clock_issue_count": len(enrollment_issues),
        "enrollment_clock_issue_examples": enrollment_issues[:10],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        report = verify_run_evidence(args.run_id, args.project_root)
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "run_id": args.run_id, "detail": str(exc)}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(report["status"] != "RUN_EVIDENCE_CHECK_PASS")


if __name__ == "__main__":
    raise SystemExit(main())
