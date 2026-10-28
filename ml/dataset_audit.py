from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml

from api.app.contracts import IncidentRequest
from ml.dataset import (
    DatasetRecord,
    ScenarioManifest,
    load_feature_schema,
    validate_feature_contract,
)
from ml.scenario_collection import (
    ClockPreflight,
    CollectionError,
    ScenarioCatalog,
    ScenarioDefinition,
    _parse_time,
    verify_feature_provenance,
)

STRATA = ("account:benign", "account:malicious", "c2:benign", "c2:malicious")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload_sha256(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read_mapping(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return payload


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
    entries: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            expected, name = line.split("  ", 1)
        except ValueError:
            errors.append(f"invalid checksums.sha256 line {line_number}")
            continue
        if len(expected) != 64 or any(
            character not in "0123456789abcdef" for character in expected
        ):
            errors.append(f"invalid checksum digest on line {line_number}")
            continue
        if name in entries or Path(name).name != name:
            errors.append(f"invalid checksum file name on line {line_number}")
            continue
        entries[name] = expected
        target = evidence_dir / name
        if not target.is_file():
            errors.append(f"checksummed evidence file is missing: {name}")
        elif _sha256(target) != expected:
            errors.append(f"checksum mismatch for evidence file: {name}")
    actual_files = {
        target.name
        for target in evidence_dir.iterdir()
        if target.is_file()
        and target.name not in {"checksums.sha256", ".collection_state.json"}
    }
    if not entries or set(entries) != actual_files:
        errors.append(
            "checksum manifest is incomplete or inconsistent: "
            f"missing={sorted(actual_files - set(entries))}, "
            f"unexpected={sorted(set(entries) - actual_files)}"
        )
    return errors


def _load_incidents(path: Path) -> list[IncidentRequest]:
    incidents: list[IncidentRequest] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("incident must contain a JSON object")
            incidents.append(IncidentRequest.model_validate(payload.get("incident", payload)))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"invalid incident line {line_number}: {exc}") from exc
    return incidents


def _audit_run(
    manifest_path: Path,
    evidence_root: Path,
    schema: dict[str, Any],
    catalog: dict[str, ScenarioDefinition],
    expected_catalog_sha256: str,
    expected_schema_sha256: str,
    expected_source_config_sha256: str,
    expected_taxonomy_sha256: str,
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
    catalog_scenario = catalog.get(manifest.scenario_id)
    if catalog_scenario is None or (
        catalog_scenario.family,
        catalog_scenario.label,
    ) != (manifest.family, manifest.label):
        errors.append(
            "SCENARIO_CATALOG_MISMATCH: scenario_id is missing from the catalog or "
            "does not match its catalog family/label"
        )
    if (
        manifest.collection_seed is None
        or not manifest.scenario_parameters
        or manifest.provenance_sha256 is None
    ):
        errors.append(
            "RUN_PROVENANCE_MISSING: manifest requires collection seed, randomized "
            "parameters and provenance hash"
        )
    if manifest.scenario_catalog_sha256 != expected_catalog_sha256:
        errors.append(
            "COLLECTION_CONTRACT_INVALID: run used a different scenario catalog"
        )
    if manifest.feature_schema_sha256 != expected_schema_sha256:
        errors.append(
            "COLLECTION_CONTRACT_INVALID: run used a different feature schema"
        )
    if manifest.source_config_sha256 != expected_source_config_sha256:
        errors.append(
            "COLLECTION_CONTRACT_INVALID: run used a different source configuration"
        )
    if manifest.taxonomy_sha256 != expected_taxonomy_sha256:
        errors.append("COLLECTION_CONTRACT_INVALID: run used a different taxonomy")

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
    state_path = evidence_dir / ".collection_state.json"
    try:
        state = _read_mapping(state_path)
    except (OSError, ValueError) as exc:
        errors.append(f"RUN_STATE_INVALID: invalid .collection_state.json: {exc}")
        state = {}
    if state.get("status") != "FINALIZED" or state.get("run_id") != manifest.run_id:
        errors.append("RUN_STATE_INVALID: collection state is not FINALIZED for this run")
    ground_truth_path = evidence_dir / "ground_truth.json"
    try:
        ground_truth = _read_mapping(ground_truth_path)
    except (OSError, ValueError) as exc:
        errors.append(f"invalid ground_truth.json: {exc}")
        ground_truth = {}
    manifest_identity = {
        "scenario_id": manifest.scenario_id,
        "run_id": manifest.run_id,
        "family": manifest.family,
        "label": manifest.label,
        "host": manifest.host,
        "expected_behavior": manifest.expected_behavior,
    }
    if any(ground_truth.get(name) != value for name, value in manifest_identity.items()):
        errors.append("ground truth identity does not match finalized scenario manifest")
    if catalog_scenario is not None:
        catalog_contract = {
            "expected_behavior": catalog_scenario.expected_behavior,
            "attribution": catalog_scenario.attribution.model_dump(mode="json"),
            "quality_gates": catalog_scenario.quality_gates.model_dump(mode="json"),
            "expected_observables": catalog_scenario.expected_observables,
        }
        if any(
            ground_truth.get(name) != value
            for name, value in catalog_contract.items()
        ):
            errors.append(
                "SCENARIO_CATALOG_MISMATCH: ground truth does not match the full "
                "catalog scenario contract"
            )
    if manifest.provenance_sha256 is not None:
        actual_provenance = hashlib.sha256(
            json.dumps(ground_truth, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if actual_provenance != manifest.provenance_sha256:
            errors.append("RUN_PROVENANCE_INVALID: ground truth provenance hash mismatch")
    if not isinstance(ground_truth.get("clock_preflight"), dict):
        errors.append("CLOCK_PREFLIGHT_MISSING: ground truth lacks VM clock evidence")
    else:
        try:
            ClockPreflight.model_validate(ground_truth["clock_preflight"])
        except ValueError as exc:
            errors.append(f"CLOCK_PREFLIGHT_INVALID: {exc}")
    if not isinstance(ground_truth.get("expected_observables"), list):
        errors.append("EXPECTED_OBSERVABLES_MISSING: ground truth lacks observable assertions")
    elif catalog_scenario is not None and ground_truth["expected_observables"] != (
        catalog_scenario.expected_observables
    ):
        errors.append(
            "EXPECTED_OBSERVABLES_INVALID: assertions do not match the scenario catalog"
        )
    metadata_path = evidence_dir / "collection_metadata.json"
    if not metadata_path.is_file():
        errors.append("missing collection_metadata.json")
        metadata: dict[str, Any] = {}
    else:
        try:
            metadata = _read_mapping(metadata_path)
        except (OSError, ValueError) as exc:
            errors.append(f"invalid collection_metadata.json: {exc}")
            metadata = {}
    if metadata.get("status") != "FINALIZED":
        errors.append("collection metadata status is not FINALIZED")
    if metadata.get("run_id") != manifest.run_id:
        errors.append("collection metadata run_id mismatch")
    if metadata.get("collection_seed") != manifest.collection_seed:
        errors.append("collection metadata seed does not match manifest")
    if metadata.get("scenario_parameters") != manifest.scenario_parameters:
        errors.append("collection metadata parameters do not match manifest")
    start_contract_path = evidence_dir / "start-contract.json"
    try:
        start_contract = _read_mapping(start_contract_path)
    except (OSError, ValueError) as exc:
        errors.append(f"COLLECTION_CONTRACT_INVALID: invalid start contract: {exc}")
        start_contract = {}
    start_contract_sha256 = (
        _payload_sha256(start_contract) if isinstance(start_contract, dict) else ""
    )
    bound_start_fields = (
        "run_id",
        "started_at",
        "draft_sha256",
        "draft_snapshot_sha256",
        "source_config_sha256",
        "taxonomy_sha256",
        "scenario_catalog_sha256",
        "feature_schema_sha256",
        "collection_contract_sha256",
        "frozen_parameters_sha256",
        "source",
        "archive_cursor",
    )
    if (
        not isinstance(start_contract, dict)
        or start_contract.get("version") != "collection-start-contract-v1"
        or start_contract_sha256 != state.get("start_contract_sha256")
        or start_contract_sha256 != metadata.get("start_contract_sha256")
        or any(start_contract.get(name) != state.get(name) for name in bound_start_fields)
    ):
        errors.append(
            "COLLECTION_CONTRACT_INVALID: runtime source/cursor is not bound to the "
            "immutable start contract"
        )
    cursor = start_contract.get("archive_cursor", {})
    source = start_contract.get("source", {})
    if (
        not isinstance(cursor, dict)
        or not isinstance(source, dict)
        or cursor.get("path") != source.get("wazuh_archives_path")
    ):
        errors.append(
            "COLLECTION_CONTRACT_INVALID: start contract archive cursor/source mismatch"
        )
    try:
        frozen_parameters = _read_mapping(evidence_dir / "execution-parameters.json")
        receipt_path = evidence_dir / "execution_receipt.json"
        receipt = _read_mapping(receipt_path)
    except (OSError, ValueError) as exc:
        errors.append(f"EXECUTION_RECEIPT_INVALID: {exc}")
        frozen_parameters = {}
        receipt = {}
        receipt_path = evidence_dir / "execution_receipt.json"
    frozen_digest = hashlib.sha256(
        json.dumps(frozen_parameters, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if (
        frozen_parameters.get("run_id") != manifest.run_id
        or frozen_parameters.get("scenario_id") != manifest.scenario_id
        or frozen_parameters.get("family") != manifest.family
        or frozen_parameters.get("label") != manifest.label
        or frozen_parameters.get("scenario_parameters") != manifest.scenario_parameters
        or frozen_digest != state.get("frozen_parameters_sha256")
        or frozen_digest != metadata.get("frozen_parameters_sha256")
    ):
        errors.append(
            "EXECUTION_RECEIPT_INVALID: frozen execution parameters are inconsistent"
        )
    if (
        receipt != state.get("execution_receipt")
        or receipt.get("status") != "COMPLETED"
        or receipt.get("run_id") != manifest.run_id
        or receipt.get("scenario_id") != manifest.scenario_id
        or receipt.get("frozen_parameters_sha256") != frozen_digest
        or _parse_time(receipt.get("action_started_at"))
        != manifest.start_time.astimezone(UTC)
        or _parse_time(receipt.get("action_ended_at"))
        != manifest.end_time.astimezone(UTC)
        or not receipt_path.is_file()
        or metadata.get("execution_receipt_sha256") != _sha256(receipt_path)
    ):
        errors.append(
            "EXECUTION_RECEIPT_INVALID: collector-managed action receipt is inconsistent"
        )
    contract_hashes = {
        "source_config_sha256": manifest.source_config_sha256,
        "taxonomy_sha256": manifest.taxonomy_sha256,
        "scenario_catalog_sha256": manifest.scenario_catalog_sha256,
        "feature_schema_sha256": manifest.feature_schema_sha256,
    }
    expected_contract = hashlib.sha256(
        json.dumps(contract_hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if manifest.collection_contract_sha256 != expected_contract:
        errors.append("COLLECTION_CONTRACT_INVALID: manifest contract digest mismatch")
    for name, expected in {
        **contract_hashes,
        "collection_contract_sha256": manifest.collection_contract_sha256,
    }.items():
        if metadata.get(name) != expected or state.get(name) != expected:
            errors.append(
                f"COLLECTION_CONTRACT_INVALID: {name} differs across run artifacts"
            )
    for filename, expected in {
        "collection-sources.yaml": manifest.source_config_sha256,
        "suspicious-process-taxonomy.yaml": manifest.taxonomy_sha256,
        "scenario-catalog.yaml": manifest.scenario_catalog_sha256,
        "feature-schema.json": manifest.feature_schema_sha256,
    }.items():
        snapshot = evidence_dir / filename
        if not snapshot.is_file() or _sha256(snapshot) != expected:
            errors.append(
                f"COLLECTION_CONTRACT_INVALID: snapshot {filename} is missing or changed"
            )
    marker_path = evidence_dir / "run_markers.jsonl"
    try:
        markers = [
            json.loads(line)
            for line in marker_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if any(not isinstance(marker, dict) for marker in markers):
            raise ValueError("run markers must be JSON objects")
    except (OSError, ValueError) as exc:
        errors.append(f"RUN_MARKERS_INVALID: invalid run marker evidence: {exc}")
        markers = []
    if (
        len(markers) != 2
        or markers[0].get("event") != "START"
        or markers[1].get("event") != "END"
        or any(marker.get("run_id") != manifest.run_id for marker in markers)
        or metadata.get("run_marker_count") != 2
    ):
        errors.append("RUN_MARKERS_INVALID: START/END marker pair is incomplete")
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
    for incident in incidents:
        try:
            verify_feature_provenance(evidence_dir, manifest, incident, state)
        except (CollectionError, OSError, ValueError, TypeError) as exc:
            errors.append(f"FEATURE_PROVENANCE_INVALID: {exc}")
    return manifest, incidents, errors


def audit_dataset(
    raw_dir: Path,
    evidence_dir: Path,
    *,
    minimum_runs: int = 10,
    target_runs: int = 12,
    minimum_scenarios: int = 5,
    maximum_scenario_share: float = 0.30,
    scenario_catalog_path: Path = Path("config/scenario-catalog.yaml"),
    source_config_path: Path = Path("config/collection-sources.yaml"),
    taxonomy_path: Path = Path("config/suspicious-process-taxonomy.yaml"),
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
    try:
        payload = yaml.safe_load(scenario_catalog_path.read_text(encoding="utf-8"))
        parsed_catalog = ScenarioCatalog.model_validate(payload)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise ValueError(f"invalid scenario catalog {scenario_catalog_path}: {exc}") from exc
    catalog = {item.scenario_id: item for item in parsed_catalog.scenarios}
    expected_scenarios: dict[str, set[str]] = {name: set() for name in STRATA}
    for item in parsed_catalog.scenarios:
        expected_scenarios[f"{item.family}:{item.label}"].add(item.scenario_id)
    schema = load_feature_schema(Path(__file__).with_name("feature_schema.json"))
    catalog_sha256 = _sha256(scenario_catalog_path)
    schema_sha256 = _sha256(Path(__file__).with_name("feature_schema.json"))
    try:
        source_config_sha256 = _sha256(source_config_path)
        taxonomy_sha256 = _sha256(taxonomy_path)
    except OSError as exc:
        raise ValueError(f"invalid canonical collection contract: {exc}") from exc
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
        manifest, incidents, errors = _audit_run(
            manifest_path,
            evidence_dir,
            schema,
            catalog,
            catalog_sha256,
            schema_sha256,
            source_config_sha256,
            taxonomy_sha256,
        )
        run_id = manifest.run_id if manifest is not None else manifest_path.parent.name
        if errors:
            invalid_runs.add(run_id)
            for message in errors:
                if message.startswith("SCENARIO_CATALOG_MISMATCH:"):
                    code = "SCENARIO_CATALOG_MISMATCH"
                    message = message.split(":", 1)[1].strip()
                elif message.startswith("RUN_STATE_INVALID:"):
                    code = "RUN_STATE_INVALID"
                    message = message.split(":", 1)[1].strip()
                elif any(
                    message.startswith(f"{prefix}:")
                    for prefix in (
                        "RUN_PROVENANCE_MISSING",
                        "RUN_PROVENANCE_INVALID",
                        "CLOCK_PREFLIGHT_MISSING",
                        "CLOCK_PREFLIGHT_INVALID",
                        "EXPECTED_OBSERVABLES_MISSING",
                        "EXPECTED_OBSERVABLES_INVALID",
                        "RUN_MARKERS_INVALID",
                        "COLLECTION_CONTRACT_INVALID",
                        "EXECUTION_RECEIPT_INVALID",
                        "FEATURE_PROVENANCE_INVALID",
                    )
                ):
                    code, message = message.split(":", 1)
                    message = message.strip()
                else:
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
                state = _read_mapping(state_path)
            except (OSError, ValueError):
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
    parameter_rows: dict[str, list[tuple[str, int, dict[str, Any]]]] = {
        name: [] for name in STRATA
    }
    for run_id, (manifest, _) in valid.items():
        if manifest.collection_seed is None:
            continue
        stratum = f"{manifest.family}:{manifest.label}"
        parameter_rows[stratum].append(
            (run_id, manifest.collection_seed, manifest.scenario_parameters)
        )
    for stratum, rows in parameter_rows.items():
        seeds = [seed for _, seed, _ in rows]
        if len(seeds) != len(set(seeds)):
            _issue(
                issues,
                "COLLECTION_SEED_REUSE",
                f"{stratum} reuses a collection seed; each run needs an independent seed",
            )
        parameter_variants = {
            json.dumps(parameters, sort_keys=True, separators=(",", ":"))
            for _, _, parameters in rows
        }
        if len(rows) >= minimum_runs and len(parameter_variants) < 3:
            _issue(
                issues,
                "PARAMETER_VARIATION_MISSING",
                f"{stratum} has only {len(parameter_variants)} randomized parameter variants",
            )
    for family in ("account", "c2"):
        benign = [parameters for _, _, parameters in parameter_rows[f"{family}:benign"]]
        malicious = [
            parameters for _, _, parameters in parameter_rows[f"{family}:malicious"]
        ]
        if not benign or not malicious:
            continue
        shared_numeric = set.intersection(
            {key for row in benign for key, value in row.items() if isinstance(value, int | float)},
            {
                key
                for row in malicious
                for key, value in row.items()
                if isinstance(value, int | float)
            },
        )
        for name in sorted(shared_numeric - {"variant_index"}):
            benign_values = [float(row[name]) for row in benign if name in row]
            malicious_values = [float(row[name]) for row in malicious if name in row]
            if not benign_values or not malicious_values:
                continue
            separated = max(benign_values) < min(malicious_values) or max(
                malicious_values
            ) < min(benign_values)
            if separated:
                _issue(
                    issues,
                    "PARAMETER_LABEL_SEPARATION",
                    f"{family} parameter {name} separates labels; use overlapping ranges",
                )
    family_feature_values: dict[str, dict[str, dict[str, list[float]]]] = {
        family: {
            feature: {"benign": [], "malicious": []}
            for feature in schema["x-family-features"][family]
        }
        for family in ("account", "c2")
    }
    for manifest, incidents in valid.values():
        for incident in incidents:
            for feature, labels in family_feature_values[manifest.family].items():
                value = incident.features.get(feature)
                if value is not None:
                    labels[manifest.label].append(float(value))
    for family, feature_values in family_feature_values.items():
        feature_names = sorted(feature_values)
        vectors: dict[tuple[float, ...], dict[str, list[str]]] = {}
        for run_id, (manifest, incidents) in valid.items():
            if manifest.family != family:
                continue
            for incident in incidents:
                vector = tuple(float(incident.features[name]) for name in feature_names)
                labels = vectors.setdefault(vector, {"benign": [], "malicious": []})
                labels[manifest.label].append(run_id)
        for vector, labels in vectors.items():
            if labels["benign"] and labels["malicious"]:
                _issue(
                    issues,
                    "CROSS_LABEL_COLLISION",
                    f"identical {family} feature vector has conflicting labels; "
                    f"features={dict(zip(feature_names, vector, strict=True))}, "
                    f"benign_runs={sorted(set(labels['benign']))}, "
                    f"malicious_runs={sorted(set(labels['malicious']))}",
                )
        for feature, labels in feature_values.items():
            benign_values = labels["benign"]
            malicious_values = labels["malicious"]
            if not benign_values or not malicious_values:
                continue
            benign_range = (min(benign_values), max(benign_values))
            malicious_range = (min(malicious_values), max(malicious_values))
            separated = (
                benign_range[1] < malicious_range[0]
                or malicious_range[1] < benign_range[0]
            )
            if separated:
                _issue(
                    issues,
                    "FEATURE_LABEL_SEPARATION",
                    f"{feature} perfectly separates {family} labels; collect scenarios "
                    "whose benign and malicious value ranges overlap before training "
                    f"(benign={benign_range}, malicious={malicious_range})",
                )
        family_rows: dict[str, list[dict[str, float]]] = {"benign": [], "malicious": []}
        for manifest, incidents in valid.values():
            if manifest.family != family:
                continue
            family_rows[manifest.label].extend(
                {name: float(incident.features[name]) for name in feature_names}
                for incident in incidents
            )
        for first, second in combinations(feature_names, 2):
            benign_pairs = {
                (row[first], row[second]) for row in family_rows["benign"]
            }
            malicious_pairs = {
                (row[first], row[second]) for row in family_rows["malicious"]
            }
            if (
                benign_pairs
                and malicious_pairs
                and benign_pairs.isdisjoint(malicious_pairs)
                and len(benign_pairs | malicious_pairs) <= 16
            ):
                first_benign = {pair[0] for pair in benign_pairs}
                first_malicious = {pair[0] for pair in malicious_pairs}
                second_benign = {pair[1] for pair in benign_pairs}
                second_malicious = {pair[1] for pair in malicious_pairs}
                if first_benign & first_malicious and second_benign & second_malicious:
                    _issue(
                        issues,
                        "JOINT_FEATURE_LABEL_SEPARATION",
                        f"the low-cardinality pair ({first}, {second}) perfectly "
                        f"separates {family} labels; collect overlapping joint behavior",
                    )
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
        if count > target_runs:
            _issue(
                issues,
                "STRATUM_EXCESS",
                f"{name} has {count} runs; freeze collection at the target of {target_runs}",
            )
        expected = expected_scenarios[name]
        if count >= minimum_runs and set(scenarios) != expected:
            _issue(
                issues,
                "SCENARIO_CATALOG_COVERAGE",
                f"{name} must use exactly the catalog scenarios; "
                f"missing={sorted(expected - set(scenarios))}, "
                f"unexpected={sorted(set(scenarios) - expected)}",
            )
        if count >= minimum_runs and scenarios and max(scenarios.values()) - min(
            scenarios.values()
        ) > 1:
            _issue(
                issues,
                "SCENARIO_IMBALANCE",
                f"{name} scenario counts must differ by at most one: "
                f"{dict(sorted(scenarios.items()))}",
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
                f"{name} largest scenario share is {largest_share:.1%}; "
                f"maximum is {maximum_scenario_share:.1%}",
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
        "audit_version": "dataset-audit-v2",
        "collection_contract_sha256": _payload_sha256({
            "source_config_sha256": source_config_sha256,
            "taxonomy_sha256": taxonomy_sha256,
            "scenario_catalog_sha256": catalog_sha256,
            "feature_schema_sha256": schema_sha256,
        }),
        "status": status,
        "minimum_policy": (
            f"{minimum_runs}..{target_runs} valid independent runs, exactly "
            f"{minimum_scenarios} catalog scenarios, scenario counts differ by at most "
            "one per family/label"
        ),
        "target_policy": f"exactly {target_runs} valid independent runs per family/label",
        "collection_unit": "run_id",
        "split_group_key": "scenario_id",
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
