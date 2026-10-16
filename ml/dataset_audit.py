from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from api.app.contracts import IncidentRequest
from ml.dataset import (
    DatasetRecord,
    ScenarioManifest,
    load_feature_schema,
    validate_feature_contract,
)

STRATA = ("account:benign", "account:malicious", "c2:benign", "c2:malicious")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _issue(
    issues: list[dict[str, str]],
    code: str,
    message: str,
    *,
    run_id: str = "DATASET",
    severity: str = "ERROR",
) -> None:
    issues.append(
        {"severity": severity, "code": code, "run_id": run_id, "message": message}
    )


def _verify_evidence_checksums(evidence_dir: Path) -> list[str]:
    errors: list[str] = []
    path = evidence_dir / "checksums.sha256"
    if not path.is_file():
        return ["missing checksums.sha256"]
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            expected, name = line.split("  ", 1)
        except ValueError:
            errors.append(f"invalid checksums.sha256 line {line_number}")
            continue
        target = evidence_dir / name
        if not target.is_file():
            errors.append(f"checksummed evidence file is missing: {name}")
        elif _sha256(target) != expected:
            errors.append(f"checksum mismatch for evidence file: {name}")
    return errors


def _load_incidents(path: Path) -> list[IncidentRequest]:
    incidents: list[IncidentRequest] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            incidents.append(IncidentRequest.model_validate(payload.get("incident", payload)))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"invalid incident line {line_number}: {exc}") from exc
    return incidents


def _audit_run(
    manifest_path: Path,
    evidence_root: Path,
    schema: dict[str, Any],
) -> tuple[ScenarioManifest | None, list[IncidentRequest], list[str]]:
    errors: list[str] = []
    run_dir = manifest_path.parent
    try:
        manifest = ScenarioManifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        return None, [], [f"invalid scenario_manifest.json: {exc}"]
    if run_dir.name != manifest.run_id:
        errors.append(
            f"run directory {run_dir.name} does not match manifest run_id {manifest.run_id}"
        )

    incident_path = run_dir / "incidents.jsonl"
    if not incident_path.is_file():
        return manifest, [], errors + ["missing incidents.jsonl"]
    try:
        incidents = _load_incidents(incident_path)
    except (OSError, ValueError) as exc:
        return manifest, [], errors + [str(exc)]
    if len(incidents) != 1:
        errors.append(
            f"each run must contain exactly one aggregated incident; found {len(incidents)}"
        )
    for incident in incidents:
        if incident.family_hint != manifest.family:
            errors.append(
                f"family mismatch: manifest={manifest.family}, incident={incident.family_hint}"
            )
        if incident.asset_id != manifest.host:
            errors.append(
                f"host mismatch: manifest={manifest.host}, incident={incident.asset_id}"
            )
        if incident.start_time < manifest.start_time or incident.end_time > manifest.end_time:
            errors.append(f"incident {incident.incident_id} is outside scenario window")
        try:
            validate_feature_contract(
                [
                    DatasetRecord(
                        incident_id=incident.incident_id,
                        scenario_id=manifest.scenario_id,
                        run_id=manifest.run_id,
                        family=manifest.family,
                        label=int(manifest.label == "malicious"),
                        features={key: float(value) for key, value in incident.features.items()},
                        source_file=incident_path.as_posix(),
                    )
                ],
                schema,
            )
        except (TypeError, ValueError) as exc:
            errors.append(f"feature contract failed for {incident.incident_id}: {exc}")

    evidence_dir = evidence_root / manifest.run_id
    if not evidence_dir.is_dir():
        return manifest, incidents, errors + ["missing evidence directory"]
    metadata_path = evidence_dir / "collection_metadata.json"
    if not metadata_path.is_file():
        errors.append("missing collection_metadata.json")
        metadata: dict[str, Any] = {}
    else:
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid collection_metadata.json: {exc}")
            metadata = {}
    if metadata.get("status") != "FINALIZED":
        errors.append("collection metadata status is not FINALIZED")
    if metadata.get("run_id") != manifest.run_id:
        errors.append("collection metadata run_id mismatch")
    protected = {
        "scenario_manifest.json": metadata.get("scenario_manifest_sha256"),
        "incidents.jsonl": metadata.get("incidents_sha256"),
    }
    for name, expected in protected.items():
        target = run_dir / name
        if not isinstance(expected, str):
            errors.append(f"metadata is missing SHA-256 for {name}")
        elif not target.is_file() or _sha256(target) != expected:
            errors.append(f"dataset checksum mismatch for {name}")

    errors.extend(_verify_evidence_checksums(evidence_dir))
    wazuh = evidence_dir / "wazuh_archives.jsonl"
    windows = evidence_dir / "windows_events.jsonl"
    if not wazuh.is_file() or not wazuh.read_text(encoding="utf-8").strip():
        errors.append("missing non-empty Wazuh Archives evidence")
    if not windows.is_file() or not windows.read_text(encoding="utf-8").strip():
        errors.append("missing non-empty attributed Windows evidence")
    if manifest.family == "c2":
        suricata = evidence_dir / "suricata_eve.jsonl"
        if not suricata.is_file() or not suricata.read_text(encoding="utf-8").strip():
            errors.append("C2 run is missing non-empty Suricata EVE evidence")
        for incident in incidents:
            if "suricata-eve" not in incident.evidence_sources:
                errors.append(
                    f"C2 incident {incident.incident_id} does not declare suricata-eve evidence"
                )
    return manifest, incidents, errors


def audit_dataset(
    raw_dir: Path,
    evidence_dir: Path,
    *,
    minimum_runs: int = 10,
    target_runs: int = 12,
    minimum_scenarios: int = 3,
    maximum_scenario_share: float = 0.40,
) -> dict[str, Any]:
    if minimum_runs < 5:
        raise ValueError("minimum_runs must be at least 5 for the configured grouped split")
    if target_runs < minimum_runs:
        raise ValueError("target_runs must be greater than or equal to minimum_runs")
    if minimum_scenarios < 1:
        raise ValueError("minimum_scenarios must be positive")
    if not 0 < maximum_scenario_share <= 1:
        raise ValueError("maximum_scenario_share must be in (0, 1]")

    raw_dir = raw_dir.resolve()
    evidence_dir = evidence_dir.resolve()
    schema = load_feature_schema(Path(__file__).with_name("feature_schema.json"))
    issues: list[dict[str, str]] = []
    candidates: dict[str, tuple[ScenarioManifest, list[IncidentRequest]]] = {}
    invalid_runs: set[str] = set()
    excluded_aborted_runs: set[str] = set()

    if not raw_dir.is_dir():
        _issue(issues, "RAW_DIR_MISSING", f"raw dataset directory does not exist: {raw_dir}")
        manifest_paths: list[Path] = []
    else:
        manifest_paths = sorted(raw_dir.glob("*/scenario_manifest.json"))
        for run_dir in sorted(path for path in raw_dir.iterdir() if path.is_dir()):
            if not (run_dir / "scenario_manifest.json").is_file():
                invalid_runs.add(run_dir.name)
                _issue(
                    issues,
                    "RAW_RUN_INCOMPLETE",
                    "raw run directory exists without scenario_manifest.json",
                    run_id=run_dir.name,
                )
    if not manifest_paths:
        _issue(issues, "NO_RUNS", "no scenario_manifest.json files were found")

    for manifest_path in manifest_paths:
        manifest, incidents, errors = _audit_run(manifest_path, evidence_dir, schema)
        run_id = manifest.run_id if manifest is not None else manifest_path.parent.name
        if errors:
            invalid_runs.add(run_id)
            for message in errors:
                code = "SURICATA_MISSING" if "Suricata" in message else "RUN_INVALID"
                _issue(issues, code, message, run_id=run_id)
        if manifest is not None:
            candidates[run_id] = (manifest, incidents)

    if evidence_dir.is_dir():
        for run_dir in sorted(path for path in evidence_dir.iterdir() if path.is_dir()):
            if run_dir.name in candidates:
                continue
            state_path = run_dir / ".collection_state.json"
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                state = {}
            status = state.get("status")
            if status == "ABORTED":
                excluded_aborted_runs.add(run_dir.name)
                _issue(
                    issues,
                    "ABORTED_RUN_EXCLUDED",
                    "aborted collection is excluded from dataset counts",
                    run_id=run_dir.name,
                    severity="WARNING",
                )
            elif status == "STARTED":
                invalid_runs.add(run_dir.name)
                _issue(
                    issues,
                    "STALE_STARTED_RUN",
                    "collection is still STARTED and has no finalized raw run",
                    run_id=run_dir.name,
                )
            else:
                invalid_runs.add(run_dir.name)
                _issue(
                    issues,
                    "ORPHAN_EVIDENCE",
                    "evidence directory has no corresponding finalized raw run",
                    run_id=run_dir.name,
                )

    incident_owners: dict[str, str] = {}
    for run_id, (_, incidents) in candidates.items():
        for incident in incidents:
            owner = incident_owners.get(incident.incident_id)
            if owner is not None and owner != run_id:
                invalid_runs.update({owner, run_id})
                _issue(
                    issues,
                    "DUPLICATE_INCIDENT",
                    f"duplicate incident_id {incident.incident_id} also appears in {owner}",
                    run_id=run_id,
                )
            else:
                incident_owners[incident.incident_id] = run_id

    valid = {
        run_id: value for run_id, value in candidates.items() if run_id not in invalid_runs
    }
    stratum_runs: dict[str, list[ScenarioManifest]] = {name: [] for name in STRATA}
    for manifest, _ in valid.values():
        stratum_runs[f"{manifest.family}:{manifest.label}"].append(manifest)

    strata: dict[str, dict[str, Any]] = {}
    for name in STRATA:
        manifests = stratum_runs[name]
        scenarios = Counter(manifest.scenario_id for manifest in manifests)
        count = len(manifests)
        largest = max(scenarios.values(), default=0)
        largest_share = largest / count if count else 0.0
        strata[name] = {
            "valid_runs": count,
            "minimum_runs": minimum_runs,
            "target_runs": target_runs,
            "shortage_to_minimum": max(0, minimum_runs - count),
            "shortage_to_target": max(0, target_runs - count),
            "distinct_scenarios": len(scenarios),
            "scenario_counts": dict(sorted(scenarios.items())),
            "largest_scenario_share": round(largest_share, 6),
        }
        if count < minimum_runs:
            _issue(
                issues,
                "STRATUM_SHORTAGE",
                f"{name} has {count}/{minimum_runs} required runs",
            )
        if count and len(scenarios) < minimum_scenarios:
            _issue(
                issues,
                "SCENARIO_DIVERSITY",
                f"{name} has {len(scenarios)} scenarios; requires at least {minimum_scenarios}",
            )
        if count and largest_share > maximum_scenario_share + 1e-12:
            _issue(
                issues,
                "SCENARIO_CONCENTRATION",
                f"{name} largest scenario share is {largest_share:.1%}; maximum is 40%",
            )

    error_count = sum(issue["severity"] == "ERROR" for issue in issues)
    minimum_met = all(value["valid_runs"] >= minimum_runs for value in strata.values())
    target_met = all(value["valid_runs"] >= target_runs for value in strata.values())
    if error_count or not minimum_met:
        status = "NOT_READY"
    elif target_met:
        status = "TARGET_MET"
    else:
        status = "READY"
    return {
        "audit_version": "dataset-audit-v1",
        "status": status,
        "minimum_policy": f">={minimum_runs} valid independent runs per family/label",
        "target_policy": f">={target_runs} valid independent runs per family/label",
        "group_key": "run_id",
        "raw_event_rows_are_independent_samples": False,
        "discovered_runs": len(candidates),
        "total_valid_runs": len(valid),
        "invalid_run_count": len(invalid_runs),
        "excluded_aborted_run_count": len(excluded_aborted_runs),
        "error_count": error_count,
        "strata": strata,
        "issues": issues,
    }


def format_audit_report(report: dict[str, Any]) -> str:
    rows = [
        f"DATASET STATUS: {report['status']}",
        "",
        "STRATUM                 VALID  MIN  TARGET  MISS-MIN  MISS-TARGET  SCENARIOS",
    ]
    for name in STRATA:
        value = report["strata"][name]
        rows.append(
            f"{name:<23} {value['valid_runs']:>5}  {value['minimum_runs']:>3}  "
            f"{value['target_runs']:>6}  {value['shortage_to_minimum']:>8}  "
            f"{value['shortage_to_target']:>11}  {value['distinct_scenarios']:>9}"
        )
    rows.extend(
        [
            "",
            f"Discovered runs: {report['discovered_runs']}",
            f"Valid runs:      {report['total_valid_runs']}",
            f"Invalid runs:    {report['invalid_run_count']}",
            f"Aborted excluded:{report['excluded_aborted_run_count']:>6}",
            f"Errors:          {report['error_count']}",
        ]
    )
    if report["issues"]:
        rows.append("")
        rows.append("ISSUES:")
        rows.extend(
            f"- [{item['code']}] {item['run_id']}: {item['message']}"
            for item in report["issues"]
        )
    return "\n".join(rows) + "\n"
