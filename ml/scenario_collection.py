from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from api.app.contracts import IncidentRequest
from ml.behavior_features import (
    AccountObservation,
    NetworkObservation,
    SuricataObservation,
    derive_account_features,
    derive_c2_features,
    interval_features,
)
from ml.dataset import (
    DatasetRecord,
    ScenarioManifest,
    load_feature_schema,
    validate_feature_contract,
)


class CollectionError(RuntimeError):
    pass


class Attribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_names: list[str] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    destination_ports: list[int] = Field(default_factory=list)
    dns_suffixes: list[str] = Field(default_factory=list)
    command_contains_any: list[str] = Field(default_factory=list)
    logon_types: list[int] = Field(default_factory=lambda: [2])

    @model_validator(mode="after")
    def require_a_filter(self) -> Attribution:
        fields = (
            self.account_names,
            self.process_names,
            self.source_ips,
            self.destination_ips,
            self.destination_ports,
            self.dns_suffixes,
            self.command_contains_any,
        )
        if not any(fields):
            raise ValueError("attribution requires at least one explicit filter")
        if not self.logon_types or any(item not in {2, 3, 10} for item in self.logon_types):
            raise ValueError("logon_types must contain only interactive/network/RDP types")
        if len(set(self.logon_types)) != len(self.logon_types):
            raise ValueError("logon_types must be unique")
        return self


class ClockPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid")

    captured_at: datetime
    controller_utc: datetime
    target_utc: datetime
    wazuh_utc: datetime
    sensor_utc: datetime
    attacker_utc: datetime
    maximum_skew_seconds: float = Field(default=5.0, gt=0, le=10)
    maximum_capture_age_seconds: float = Field(default=120.0, gt=0, le=300)

    @model_validator(mode="after")
    def validate_clock_skew(self) -> ClockPreflight:
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("captured_at must include a timezone")
        values = [
            self.controller_utc,
            self.target_utc,
            self.wazuh_utc,
            self.sensor_utc,
            self.attacker_utc,
        ]
        if any(value.tzinfo is None or value.utcoffset() is None for value in values):
            raise ValueError("clock preflight timestamps must include a timezone")
        span = (max(values) - min(values)).total_seconds()
        if span > self.maximum_skew_seconds:
            raise ValueError(
                f"VM clock skew {span:.3f}s exceeds {self.maximum_skew_seconds:.3f}s"
            )
        measurement_age = (self.captured_at - min(values)).total_seconds()
        if measurement_age < -1 or measurement_age > self.maximum_capture_age_seconds:
            raise ValueError(
                "clock preflight measurements are stale or captured in the future"
            )
        return self


class QualityGates(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_account_failures: int = Field(default=0, ge=0)
    max_account_failures: int | None = Field(default=None, ge=0)
    min_account_successes: int = Field(default=0, ge=0)
    max_account_successes: int | None = Field(default=None, ge=0)
    require_success_after_failure: bool | None = None
    require_all_accounts_observed: bool = False
    min_process_events: int = Field(default=0, ge=0)
    min_network_events: int = Field(default=0, ge=0)
    min_dns_events: int = Field(default=0, ge=0)
    min_suricata_events: int = Field(default=0, ge=0)
    required_suricata_signature_ids: list[int] = Field(default_factory=list)
    forbidden_suricata_signature_ids: list[int] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_ranges_and_signatures(self) -> QualityGates:
        ranges = (
            (
                "account failures",
                self.min_account_failures,
                self.max_account_failures,
            ),
            (
                "account successes",
                self.min_account_successes,
                self.max_account_successes,
            ),
        )
        for name, minimum, maximum in ranges:
            if maximum is not None and maximum < minimum:
                raise ValueError(f"maximum {name} must be greater than or equal to minimum")
        required = set(self.required_suricata_signature_ids)
        forbidden = set(self.forbidden_suricata_signature_ids)
        if required & forbidden:
            raise ValueError("a Suricata signature cannot be both required and forbidden")
        if len(required) != len(self.required_suricata_signature_ids):
            raise ValueError("required Suricata signature IDs must be unique")
        if len(forbidden) != len(self.forbidden_suricata_signature_ids):
            raise ValueError("forbidden Suricata signature IDs must be unique")
        return self


class RunDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    family: Literal["account", "c2"]
    label: Literal["benign", "malicious"]
    host: str = Field(min_length=1, max_length=128)
    expected_behavior: str = Field(min_length=1)
    operator: str = Field(min_length=1, max_length=128)
    attribution: Attribution
    quality_gates: QualityGates
    execution_log_path: str | None = None
    collection_seed: int = Field(ge=0, le=2**32 - 1)
    scenario_parameters: dict[str, int | float | str | bool] = Field(min_length=1)
    expected_observables: list[str] = Field(min_length=1)
    clock_preflight: ClockPreflight

    @model_validator(mode="after")
    def validate_family_attribution(self) -> RunDraft:
        if self.family == "account" and not self.attribution.account_names:
            raise ValueError("account run requires attribution.account_names")
        if self.family == "c2" and not (
            self.attribution.destination_ips
            or self.attribution.destination_ports
            or self.attribution.dns_suffixes
        ):
            raise ValueError("c2 run requires destination IP, port or DNS attribution")
        return self


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["collection-sources-v1"]
    wazuh_archives_path: str
    windows_agent_name: str = Field(min_length=1)
    suricata_agent_name: str = Field(min_length=1)
    taxonomy_path: str
    scenario_catalog_path: str | None = None


class ScenarioDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=128)
    family: Literal["account", "c2"]
    label: Literal["benign", "malicious"]
    expected_behavior: str = Field(min_length=1)
    attribution: Attribution
    quality_gates: QualityGates
    preconditions: list[str] = Field(min_length=1)
    execution_steps: list[str] = Field(min_length=1)
    expected_observables: list[str] = Field(min_length=1)
    cleanup_steps: list[str] = Field(min_length=1)


class ScenarioCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["scenario-catalog-v1"]
    lab_only: Literal[True]
    scenarios: list[ScenarioDefinition] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_ids(self) -> ScenarioCatalog:
        identifiers = [item.scenario_id for item in self.scenarios]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("scenario_id values must be unique")
        return self


def _utc(value: datetime | None = None) -> datetime:
    result = value or datetime.now(UTC)
    if result.tzinfo is None or result.utcoffset() is None:
        raise CollectionError("collector timestamps must include a timezone")
    return result.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = normalized[:-2] + ":" + normalized[-2:]
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CollectionError(f"cannot read YAML {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CollectionError(f"YAML document must be a mapping: {path}")
    return payload


def _resolve(project_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else project_root / path


def _validate_draft_against_catalog(draft: RunDraft, catalog_path: Path) -> None:
    try:
        catalog = ScenarioCatalog.model_validate(_read_yaml(catalog_path))
    except ValueError as exc:
        raise CollectionError(f"invalid scenario catalog: {exc}") from exc
    scenario = next(
        (item for item in catalog.scenarios if item.scenario_id == draft.scenario_id),
        None,
    )
    if scenario is None:
        raise CollectionError(f"draft does not match scenario catalog: {draft.scenario_id}")
    expected = {
        "family": scenario.family,
        "label": scenario.label,
        "expected_behavior": scenario.expected_behavior,
        "attribution": scenario.attribution.model_dump(mode="json"),
        "quality_gates": scenario.quality_gates.model_dump(mode="json"),
        "expected_observables": scenario.expected_observables,
    }
    actual = {
        "family": draft.family,
        "label": draft.label,
        "expected_behavior": draft.expected_behavior,
        "attribution": draft.attribution.model_dump(mode="json"),
        "quality_gates": draft.quality_gates.model_dump(mode="json"),
        "expected_observables": draft.expected_observables,
    }
    if actual != expected:
        raise CollectionError(f"draft does not match scenario catalog: {draft.scenario_id}")


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _write_json(path: Path, payload: Any) -> None:
    _atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_jsonl(path: Path, payloads: list[dict[str, Any]]) -> None:
    _atomic_text(path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in payloads))


def create_run_draft(
    catalog_path: Path,
    scenario_id: str,
    run_id: str,
    operator: str,
    output_path: Path,
    *,
    host: str = "WIN11-TARGET",
    execution_log_path: str | None = None,
    collection_seed: int | None = None,
    clock_preflight: ClockPreflight,
) -> dict[str, str]:
    if output_path.exists():
        raise CollectionError(f"draft output already exists: {output_path}")
    try:
        catalog = ScenarioCatalog.model_validate(_read_yaml(catalog_path))
    except ValueError as exc:
        raise CollectionError(f"invalid scenario catalog: {exc}") from exc
    scenario = next(
        (item for item in catalog.scenarios if item.scenario_id == scenario_id),
        None,
    )
    if scenario is None:
        raise CollectionError(f"unknown scenario_id: {scenario_id}")
    seed = collection_seed
    if seed is None:
        seed = int.from_bytes(hashlib.sha256(run_id.encode()).digest()[:4], "big")
    rng = random.Random(seed)
    if scenario.family == "account":
        parameters: dict[str, int | float | str | bool] = {
            "attempt_delay_seconds": round(rng.uniform(1.0, 5.0), 3),
            "operator_pause_jitter_percent": rng.randint(10, 30),
            "variant_index": rng.randint(0, 999_999),
        }
    else:
        parameters = {
            "interval_jitter_percent": rng.randint(10, 30),
            "payload_size_bytes": rng.randint(256, 2048),
            "variant_index": rng.randint(0, 999_999),
        }
    try:
        draft = RunDraft(
            scenario_id=scenario.scenario_id,
            run_id=run_id,
            family=scenario.family,
            label=scenario.label,
            host=host,
            expected_behavior=scenario.expected_behavior,
            operator=operator,
            attribution=scenario.attribution,
            quality_gates=scenario.quality_gates,
            execution_log_path=execution_log_path,
            collection_seed=seed,
            scenario_parameters=parameters,
            expected_observables=scenario.expected_observables,
            clock_preflight=clock_preflight,
        )
    except ValueError as exc:
        raise CollectionError(f"invalid run draft values: {exc}") from exc
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_text(
        output_path,
        yaml.safe_dump(draft.model_dump(mode="json"), sort_keys=False),
    )
    return {
        "status": "CREATED",
        "scenario_id": scenario_id,
        "run_id": run_id,
        "path": str(output_path),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cursor(path: Path) -> dict[str, int | str]:
    with path.open("rb") as handle:
        size = handle.seek(0, 2)
        if size:
            handle.seek(size - 1)
            if handle.read(1) != b"\n":
                raise CollectionError(
                    "Wazuh Archives does not end with a complete newline; wait for the "
                    "current write to finish and retry start"
                )
        stat = path.stat()
    return {
        "path": str(path),
        "size": size,
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }


def _append_log(evidence_dir: Path, message: str) -> None:
    with (evidence_dir / "collector.log").open("a", encoding="utf-8") as handle:
        handle.write(f"{_iso(datetime.now(UTC))} {message}\n")


def _active_lock_path(evidence_root: Path) -> Path:
    return evidence_root / ".active-run.json"


def _acquire_active_run(evidence_root: Path, run_id: str) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    for state_path in evidence_root.glob("*/.collection_state.json"):
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CollectionError(
                f"cannot verify collection state before start: {state_path}: {exc}"
            ) from exc
        if state.get("status") == "STARTED":
            raise CollectionError(
                f"active run already exists: {state.get('run_id', state_path.parent.name)}"
            )

    lock_path = _active_lock_path(evidence_root)
    payload = json.dumps({"run_id": run_id}, sort_keys=True) + "\n"
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        try:
            owner = json.loads(lock_path.read_text(encoding="utf-8")).get("run_id")
        except (OSError, json.JSONDecodeError):
            owner = "UNKNOWN"
        raise CollectionError(f"active run lock is held by: {owner}") from exc
    try:
        os.write(descriptor, payload.encode("utf-8"))
    finally:
        os.close(descriptor)


def _release_active_run(evidence_root: Path, run_id: str) -> None:
    lock_path = _active_lock_path(evidence_root)
    if not lock_path.exists():
        return
    try:
        owner = json.loads(lock_path.read_text(encoding="utf-8")).get("run_id")
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"cannot verify active run lock: {lock_path}: {exc}") from exc
    if owner != run_id:
        raise CollectionError(f"active run lock belongs to {owner}, not {run_id}")
    lock_path.unlink()


def _assert_raw_dataset_layout(project_root: Path) -> None:
    raw_root = project_root / "data/raw"
    if not raw_root.is_dir():
        return
    issues: set[str] = set()
    for marker_name in ("events_raw.jsonl", "metadata.json"):
        for marker in raw_root.rglob(marker_name):
            issues.add(str(marker.relative_to(project_root)))
    for run_dir in raw_root.iterdir():
        if not run_dir.is_dir():
            continue
        required = (run_dir / "scenario_manifest.json", run_dir / "incidents.jsonl")
        if not all(path.is_file() for path in required):
            issues.add(str(run_dir.relative_to(project_root)))
            continue
        try:
            validate_run(run_dir.name, project_root)
        except CollectionError as exc:
            issues.add(f"{run_dir.relative_to(project_root)} ({exc})")
    if issues:
        details = ", ".join(sorted(issues))
        raise CollectionError(
            "incompatible raw dataset layout; quarantine legacy/incomplete data "
            f"outside data/raw before collection: {details}"
        )


def start_run(
    draft_path: Path,
    source_config_path: Path,
    project_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    try:
        draft = RunDraft.model_validate(_read_yaml(draft_path))
        source = SourceConfig.model_validate(_read_yaml(source_config_path))
    except ValueError as exc:
        raise CollectionError(f"invalid run configuration: {exc}") from exc

    archive_path = _resolve(project_root, source.wazuh_archives_path).resolve()
    taxonomy_path = _resolve(project_root, source.taxonomy_path).resolve()
    if not archive_path.is_file():
        raise CollectionError(f"Wazuh Archives source does not exist: {archive_path}")
    if not taxonomy_path.is_file():
        raise CollectionError(f"taxonomy does not exist: {taxonomy_path}")
    catalog_path: Path | None = None
    if source.scenario_catalog_path:
        catalog_path = _resolve(project_root, source.scenario_catalog_path).resolve()
        if not catalog_path.is_file():
            raise CollectionError(f"scenario catalog does not exist: {catalog_path}")
        _validate_draft_against_catalog(draft, catalog_path)

    _assert_raw_dataset_layout(project_root)

    evidence_dir = project_root / "evidence/scenario-runs" / draft.run_id
    output_dir = project_root / "data/raw" / draft.run_id
    if evidence_dir.exists() or output_dir.exists():
        raise CollectionError(f"run_id already exists: {draft.run_id}")

    started_at = _utc(now)
    draft_snapshot = draft.model_dump(mode="json")
    source_snapshot = source.model_dump(mode="json")
    source_snapshot["wazuh_archives_path"] = str(archive_path)
    source_snapshot["taxonomy_path"] = str(taxonomy_path)
    if catalog_path is not None:
        source_snapshot["scenario_catalog_path"] = str(catalog_path)
    state = {
        "version": "scenario-collection-v1",
        "status": "STARTED",
        "run_id": draft.run_id,
        "started_at": _iso(started_at),
        "draft": draft_snapshot,
        "source": source_snapshot,
        "archive_cursor": _cursor(archive_path),
        "draft_sha256": _sha256(draft_path),
        "source_config_sha256": _sha256(source_config_path),
        "taxonomy_sha256": _sha256(taxonomy_path),
    }
    start_marker = {
        "event": "START",
        "run_id": draft.run_id,
        "timestamp": _iso(started_at),
        "draft_sha256": state["draft_sha256"],
    }
    state["start_marker"] = start_marker
    if catalog_path is not None:
        state["scenario_catalog_sha256"] = _sha256(catalog_path)
    evidence_root = evidence_dir.parent
    _acquire_active_run(evidence_root, draft.run_id)
    try:
        with tempfile.TemporaryDirectory(
            prefix=f".{draft.run_id}.starting-",
            dir=evidence_root,
        ) as temporary:
            staging_dir = Path(temporary)
            _write_json(staging_dir / "ground_truth.json", draft_snapshot)
            shutil.copyfile(source_config_path, staging_dir / "collection-sources.yaml")
            shutil.copyfile(
                taxonomy_path,
                staging_dir / "suspicious-process-taxonomy.yaml",
            )
            if catalog_path is not None:
                shutil.copyfile(catalog_path, staging_dir / "scenario-catalog.yaml")
            _write_jsonl(staging_dir / "run_markers.jsonl", [start_marker])
            _write_json(staging_dir / ".collection_state.json", state)
            _append_log(staging_dir, f"RUN_STARTED run_id={draft.run_id}")
            staging_dir.replace(evidence_dir)
    except OSError as exc:
        _release_active_run(evidence_root, draft.run_id)
        raise CollectionError(f"could not initialize run evidence: {exc}") from exc
    return {"status": "STARTED", "run_id": draft.run_id, "started_at": state["started_at"]}


def _read_appended_jsonl(cursor: dict[str, Any]) -> list[dict[str, Any]]:
    path = Path(cursor["path"])
    stat = path.stat()
    if (
        stat.st_size < int(cursor["size"])
        or stat.st_dev != int(cursor["device"])
        or stat.st_ino != int(cursor["inode"])
    ):
        raise CollectionError(f"source was rotated or truncated after start: {path}")
    with path.open("rb") as handle:
        handle.seek(int(cursor["size"]))
        payload = handle.read()
    if not payload:
        raise CollectionError("no Wazuh Archive bytes were appended during the run")
    if not payload.endswith(b"\n"):
        raise CollectionError(
            "Wazuh Archives has an incomplete final JSON line; wait for the write to "
            "finish and retry finalize"
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectionError(f"appended source is not UTF-8: {exc}") from exc
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CollectionError(f"invalid appended JSON line {line_number}: {exc}") from exc
        if not isinstance(event, dict):
            raise CollectionError(f"appended JSON line {line_number} is not an object")
        events.append(event)
    if not events:
        raise CollectionError("no complete JSON events were appended during the run")
    return events


def _event_time(event: dict[str, Any]) -> datetime | None:
    system = (((event.get("data") or {}).get("win") or {}).get("system") or {})
    return _parse_time(system.get("systemTime")) or _parse_time(event.get("timestamp"))


def _windows_fields(event: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    win = ((event.get("data") or {}).get("win") or {})
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or {}
    return str(system.get("eventID", "")), system, eventdata


def _casefold_set(values: list[str]) -> set[str]:
    return {value.strip().casefold() for value in values if value.strip()}


def _basename(value: Any) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def _account_user(eventdata: dict[str, Any]) -> str:
    for name in ("targetUserName", "TargetUserName", "dstuser", "subjectUserName"):
        value = eventdata.get(name)
        if value:
            return str(value).strip().casefold()
    return ""


def _is_interactive_logon(eventdata: dict[str, Any], attribution: Attribution) -> bool:
    """Keep only the logon types declared by the controlled scenario."""
    raw = eventdata.get("logonType", eventdata.get("LogonType"))
    if raw in (None, ""):
        return False
    with suppress(TypeError, ValueError):
        return int(str(raw).strip()) in set(attribution.logon_types)
    return False


def _matches_network(eventdata: dict[str, Any], attribution: Attribution) -> bool:
    initiated = str(eventdata.get("initiated", "true")).casefold()
    if initiated not in {"true", "1", "yes"}:
        return False
    process_names = _casefold_set(attribution.process_names)
    if process_names and _basename(eventdata.get("image")) not in process_names:
        return False
    destination_ips = _casefold_set(attribution.destination_ips)
    destination_ip = str(eventdata.get("destinationIp", "")).casefold()
    if destination_ips and destination_ip not in destination_ips:
        return False
    if attribution.destination_ports:
        try:
            port = int(eventdata.get("destinationPort"))
        except (TypeError, ValueError):
            return False
        if port not in set(attribution.destination_ports):
            return False
    return True


def _matches_dns(eventdata: dict[str, Any], attribution: Attribution) -> bool:
    query = str(eventdata.get("queryName", "")).strip(".").casefold()
    suffixes = [value.strip(".").casefold() for value in attribution.dns_suffixes]
    suffix_matches = any(
        query == suffix or query.endswith(f".{suffix}") for suffix in suffixes
    )
    if not suffixes or not suffix_matches:
        return False
    process_names = _casefold_set(attribution.process_names)
    return not process_names or _basename(eventdata.get("image")) in process_names


def _suricata_payload(event: dict[str, Any]) -> dict[str, Any] | None:
    full_log = event.get("full_log")
    if isinstance(full_log, str):
        try:
            payload = json.loads(full_log)
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None
    data = event.get("data")
    if isinstance(data, dict) and "event_type" in data:
        return data
    return None


def _suricata_dns_names(dns: object) -> list[str]:
    if not isinstance(dns, dict):
        return []

    raw_names: list[object] = [dns.get("rrname")]
    for field in ("queries", "query"):
        records = dns.get(field)
        if isinstance(records, dict):
            records = [records]
        if isinstance(records, list):
            raw_names.extend(
                record.get("rrname")
                for record in records
                if isinstance(record, dict)
            )

    legacy_answer = dns.get("answer")
    if isinstance(legacy_answer, dict):
        raw_names.append(legacy_answer.get("rrname"))

    normalized = [
        name.strip().strip(".").casefold()
        for name in raw_names
        if isinstance(name, str) and name.strip().strip(".")
    ]
    return list(dict.fromkeys(normalized))


def _suricata_dns_is_response(dns: object) -> bool:
    if not isinstance(dns, dict):
        return False
    message_type = str(dns.get("type", "")).casefold()
    if message_type in {"answer", "response"}:
        return True
    legacy_answer = dns.get("answer")
    return isinstance(legacy_answer, dict) and str(
        legacy_answer.get("type", "")
    ).casefold() in {"answer", "response"}


def _matches_suricata(payload: dict[str, Any], attribution: Attribution) -> bool:
    event_type = payload.get("event_type")
    dns = payload.get("dns")
    dns_response = _suricata_dns_is_response(dns)
    source_ips = _casefold_set(attribution.source_ips)
    source_field = "dest_ip" if dns_response else "src_ip"
    if source_ips and str(payload.get(source_field, "")).casefold() not in source_ips:
        return False
    destination_ips = _casefold_set(attribution.destination_ips)
    destination_field = "src_ip" if dns_response else "dest_ip"
    if (
        destination_ips
        and str(payload.get(destination_field, "")).casefold() not in destination_ips
    ):
        return False
    if attribution.destination_ports:
        port_field = "src_port" if dns_response else "dest_port"
        try:
            port = int(payload.get(port_field))
        except (TypeError, ValueError):
            return False
        if port not in set(attribution.destination_ports):
            return False
    if attribution.dns_suffixes:
        if event_type not in {"dns", "alert"}:
            return False
        queries = _suricata_dns_names(dns)
        suffixes = [
            value.strip(".").casefold()
            for value in attribution.dns_suffixes
            if value.strip(".")
        ]
        if not any(
            query == suffix or query.endswith(f".{suffix}")
            for query in queries
            for suffix in suffixes
        ):
            return False

    return event_type in {"alert", "flow", "dns", "http", "tls"}


def _load_taxonomy(path: Path) -> dict[str, Any]:
    payload = _read_yaml(path)
    if not isinstance(payload.get("revision"), str) or not isinstance(payload.get("rules"), list):
        raise CollectionError("taxonomy requires revision and rules")
    return payload


def _taxonomy_match(eventdata: dict[str, Any], taxonomy: dict[str, Any]) -> bool:
    image = _basename(eventdata.get("image"))
    command = str(eventdata.get("commandLine", "")).casefold()
    for rule in taxonomy["rules"]:
        if not isinstance(rule, dict):
            continue
        suffix = str(rule.get("image_suffix", "")).casefold()
        terms = [str(item).casefold() for item in rule.get("command_contains_any", [])]
        if suffix and image != _basename(suffix):
            continue
        if terms and not any(term in command for term in terms):
            continue
        if suffix or terms:
            return True
    return False


def periodicity_score(timestamps: list[datetime]) -> float:
    return interval_features(timestamps)[0]


def _derive_account(
    events: list[dict[str, Any]], draft: RunDraft, windows_agent: str
) -> tuple[dict[str, float], list[dict[str, Any]], str | None]:
    users = _casefold_set(draft.attribution.account_names)
    selected: list[dict[str, Any]] = []
    observations: list[AccountObservation] = []
    observed_accounts: set[str] = set()
    for event in events:
        if str((event.get("agent") or {}).get("name")) != windows_agent:
            continue
        event_id, _, eventdata = _windows_fields(event)
        if (
            event_id not in {"4624", "4625"}
            or _account_user(eventdata) not in users
            or not _is_interactive_logon(eventdata, draft.attribution)
        ):
            continue
        timestamp = _event_time(event)
        if timestamp is None:
            continue
        selected.append(event)
        observed_accounts.add(_account_user(eventdata))
        account = _account_user(eventdata)
        source = str(
            eventdata.get("ipAddress")
            or eventdata.get("IpAddress")
            or eventdata.get("sourceIp")
            or eventdata.get("workstationName")
            or eventdata.get("WorkstationName")
            or "local-console"
        ).strip().casefold()
        logon_type = str(
            eventdata.get("logonType", eventdata.get("LogonType", "unknown"))
        ).strip()
        observations.append(
            AccountObservation(
                timestamp=timestamp,
                account=account,
                source=source,
                logon_type=logon_type,
                success=event_id == "4624",
            )
        )
    if not selected:
        raise CollectionError("no attributable Windows account events were collected")
    features = derive_account_features(observations)
    failures = int(features["failed_login_count"])
    successes = int(features["successful_login_count"])
    success_after_fail = bool(features["success_after_fail"])
    gates = draft.quality_gates
    if failures < gates.min_account_failures or (
        gates.max_account_failures is not None
        and failures > gates.max_account_failures
    ):
        raise CollectionError(
            "account failure count failed quality gate: "
            f"observed={failures}, expected="
            f"[{gates.min_account_failures}, {gates.max_account_failures}]"
        )
    if successes < gates.min_account_successes or (
        gates.max_account_successes is not None
        and successes > gates.max_account_successes
    ):
        raise CollectionError(
            "account success count failed quality gate: "
            f"observed={successes}, expected="
            f"[{gates.min_account_successes}, {gates.max_account_successes}]"
        )
    if (
        gates.require_success_after_failure is not None
        and success_after_fail != gates.require_success_after_failure
    ):
        raise CollectionError(
            "success-after-failure sequence failed quality gate: "
            f"observed={success_after_fail}, "
            f"expected={gates.require_success_after_failure}"
        )
    if gates.require_all_accounts_observed:
        missing_accounts = sorted(users - observed_accounts)
        if missing_accounts:
            raise CollectionError(
                f"account evidence is missing declared accounts: {missing_accounts}"
            )
    return features, selected, draft.attribution.account_names[0]


def _derive_c2(
    events: list[dict[str, Any]], draft: RunDraft, source: SourceConfig, taxonomy: dict[str, Any]
) -> tuple[dict[str, float], list[dict[str, Any]], list[dict[str, Any]], str | None]:
    windows: list[dict[str, Any]] = []
    network_observations: list[NetworkObservation] = []
    process_events = 0
    dns_events = 0
    suspicious = False
    for event in events:
        if str((event.get("agent") or {}).get("name")) != source.windows_agent_name:
            continue
        event_id, _, eventdata = _windows_fields(event)
        if event_id == "1" and (
            _basename(eventdata.get("image")) in _casefold_set(draft.attribution.process_names)
            or any(
                term.casefold() in str(eventdata.get("commandLine", "")).casefold()
                for term in draft.attribution.command_contains_any
            )
        ):
            windows.append(event)
            process_events += 1
            suspicious = suspicious or _taxonomy_match(eventdata, taxonomy)
        elif event_id == "3" and _matches_network(eventdata, draft.attribution):
            timestamp = _event_time(event)
            if timestamp is None:
                continue
            windows.append(event)
            destination = str(eventdata.get("destinationIp", "")).strip()
            destination_port = None
            with suppress(TypeError, ValueError):
                destination_port = int(eventdata.get("destinationPort"))
            network_observations.append(
                NetworkObservation(timestamp, destination, destination_port)
            )
            suspicious = suspicious or _taxonomy_match(eventdata, taxonomy)
        elif event_id == "22" and _matches_dns(eventdata, draft.attribution):
            timestamp = _event_time(event)
            if timestamp is None:
                continue
            windows.append(event)
            dns_events += 1
            query = str(eventdata.get("queryName", "")).strip(".")
            network_observations.append(
                NetworkObservation(timestamp, query, 53, dns_query=query)
            )
            suspicious = suspicious or _taxonomy_match(eventdata, taxonomy)
    if not network_observations:
        raise CollectionError("no attributable Sysmon network or DNS telemetry was collected")

    suricata: list[dict[str, Any]] = []
    seen: set[str] = set()
    signature_ids: set[int] = set()
    for event in events:
        if str((event.get("agent") or {}).get("name")) != source.suricata_agent_name:
            continue
        payload = _suricata_payload(event)
        if payload is None or not _matches_suricata(payload, draft.attribution):
            continue
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        suricata.append(payload)
        if payload.get("event_type") == "alert":
            with suppress(TypeError, ValueError):
                signature_ids.add(int((payload.get("alert") or {}).get("signature_id")))
    if not suricata:
        raise CollectionError("no attributable Suricata EVE evidence was collected")

    gates = draft.quality_gates
    observed_counts = {
        "process": process_events,
        "network": sum(item.dns_query is None for item in network_observations),
        "DNS": dns_events,
        "Suricata": len(suricata),
    }
    minimum_counts = {
        "process": gates.min_process_events,
        "network": gates.min_network_events,
        "DNS": gates.min_dns_events,
        "Suricata": gates.min_suricata_events,
    }
    for name, minimum in minimum_counts.items():
        if observed_counts[name] < minimum:
            raise CollectionError(
                f"{name} event count failed quality gate: "
                f"observed={observed_counts[name]}, minimum={minimum}"
            )
    missing_signatures = sorted(
        set(gates.required_suricata_signature_ids) - signature_ids
    )
    if missing_signatures:
        raise CollectionError(
            f"required Suricata signatures were not observed: {missing_signatures}"
        )
    forbidden_signatures = sorted(
        set(gates.forbidden_suricata_signature_ids) & signature_ids
    )
    if forbidden_signatures:
        raise CollectionError(
            f"forbidden Suricata signatures were observed: {forbidden_signatures}"
        )

    suricata_observations: list[SuricataObservation] = []
    for payload in suricata:
        flow = payload.get("flow") if isinstance(payload.get("flow"), dict) else {}
        total_bytes = 0
        for field in ("bytes_toserver", "bytes_toclient"):
            with suppress(TypeError, ValueError):
                total_bytes += max(0, int(flow.get(field, 0)))
        severity = None
        if payload.get("event_type") == "alert":
            with suppress(TypeError, ValueError):
                severity = int((payload.get("alert") or {}).get("severity"))
        suricata_observations.append(
            SuricataObservation(
                is_alert=payload.get("event_type") == "alert",
                severity=severity,
                total_bytes=total_bytes,
            )
        )
    features = derive_c2_features(
        network_observations,
        suricata_observations,
        suspicious_process=suspicious,
    )
    indicator = next(iter(draft.attribution.destination_ips), None)
    if indicator is None:
        indicator = next(iter(draft.attribution.dns_suffixes), None)
    return features, windows, suricata, indicator


def _write_checksums(evidence_dir: Path) -> None:
    excluded = {"checksums.sha256", ".collection_state.json"}
    rows = []
    for path in sorted(item for item in evidence_dir.iterdir() if item.is_file()):
        if path.name in excluded:
            continue
        rows.append(f"{_sha256(path)}  {path.name}\n")
    _atomic_text(evidence_dir / "checksums.sha256", "".join(rows))


def _verify_start_snapshot(evidence_dir: Path, state: dict[str, Any]) -> None:
    ground_truth_path = evidence_dir / "ground_truth.json"
    source_snapshot_path = evidence_dir / "collection-sources.yaml"
    taxonomy_snapshot_path = evidence_dir / "suspicious-process-taxonomy.yaml"
    try:
        ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid start snapshot ground_truth.json: {exc}") from exc
    if ground_truth != state.get("draft"):
        raise CollectionError("start snapshot ground_truth.json changed after run start")
    marker_path = evidence_dir / "run_markers.jsonl"
    try:
        markers = [
            json.loads(line)
            for line in marker_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid run marker evidence: {exc}") from exc
    if not markers or markers[0] != state.get("start_marker"):
        raise CollectionError("START marker does not match immutable collection state")
    protected = {
        source_snapshot_path: state.get("source_config_sha256"),
        taxonomy_snapshot_path: state.get("taxonomy_sha256"),
    }
    if state.get("scenario_catalog_sha256") is not None:
        protected[evidence_dir / "scenario-catalog.yaml"] = state.get(
            "scenario_catalog_sha256"
        )
    for path, expected in protected.items():
        if not isinstance(expected, str) or not path.is_file() or _sha256(path) != expected:
            raise CollectionError(f"start snapshot changed after run start: {path.name}")


def finalize_run(
    run_id: str,
    project_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    evidence_dir = project_root / "evidence/scenario-runs" / run_id
    state_path = evidence_dir / ".collection_state.json"
    if not state_path.is_file():
        raise CollectionError(f"run was not started: {run_id}")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("status") != "STARTED":
        raise CollectionError(f"run is not in STARTED state: {run_id}")
    try:
        draft = RunDraft.model_validate(state["draft"])
        source = SourceConfig.model_validate(state["source"])
    except ValueError as exc:
        raise CollectionError(f"stored collection state is invalid: {exc}") from exc
    _verify_start_snapshot(evidence_dir, state)
    ended_at = _utc(now)
    started_at = _parse_time(state["started_at"])
    if started_at is None or ended_at <= started_at:
        raise CollectionError("finalize time must be later than start time")

    events = _read_appended_jsonl(state["archive_cursor"])
    in_window = [
        event
        for event in events
        if (timestamp := _event_time(event)) is not None and started_at <= timestamp <= ended_at
    ]
    if not in_window:
        raise CollectionError("no timestamped events fall inside the run window")
    taxonomy_path = evidence_dir / "suspicious-process-taxonomy.yaml"
    taxonomy = _load_taxonomy(taxonomy_path)
    if _sha256(taxonomy_path) != state["taxonomy_sha256"]:
        raise CollectionError("taxonomy changed after run start")

    if draft.family == "account":
        features, windows_events, indicator = _derive_account(
            in_window, draft, source.windows_agent_name
        )
        suricata_events: list[dict[str, Any]] = []
        evidence_sources = ["wazuh-archives"]
    else:
        features, windows_events, suricata_events, indicator = _derive_c2(
            in_window, draft, source, taxonomy
        )
        evidence_sources = ["wazuh-archives", "suricata-eve"]

    incident_id = f"INC-{hashlib.sha256(run_id.encode()).hexdigest()[:16].upper()}"
    incident = IncidentRequest(
        incident_id=incident_id,
        asset_id=draft.host,
        start_time=started_at,
        end_time=ended_at,
        family_hint=draft.family,
        features=features,
        evidence_sources=evidence_sources,
        base_severity=0,
        raw_refs=[f"run:{run_id}", "evidence:wazuh_archives.jsonl"],
        indicator=indicator,
    )
    manifest = ScenarioManifest(
        scenario_id=draft.scenario_id,
        run_id=draft.run_id,
        family=draft.family,
        label=draft.label,
        host=draft.host,
        start_time=started_at,
        end_time=ended_at,
        expected_behavior=draft.expected_behavior,
        collection_seed=draft.collection_seed,
        scenario_parameters=draft.scenario_parameters,
        provenance_sha256=hashlib.sha256(
            json.dumps(
                draft.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
    )
    schema_path = project_root / "ml/feature_schema.json"
    if not schema_path.is_file():
        schema_path = Path(__file__).with_name("feature_schema.json")
    schema = load_feature_schema(schema_path)
    validate_feature_contract(
        [
            DatasetRecord(
                incident_id=incident.incident_id,
                scenario_id=manifest.scenario_id,
                run_id=run_id,
                family=draft.family,
                label=int(draft.label == "malicious"),
                features=features,
                source_file=f"data/raw/{run_id}/incidents.jsonl",
            )
        ],
        schema,
    )
    execution_log_source: Path | None = None
    if draft.execution_log_path:
        execution_log_source = _resolve(project_root, draft.execution_log_path).resolve()
        if not execution_log_source.is_file():
            raise CollectionError(
                f"declared execution log does not exist: {execution_log_source}"
            )

    final_dir = project_root / "data/raw" / run_id
    if final_dir.exists():
        raise CollectionError(f"final output already exists: {final_dir}")
    temporary_dir = final_dir.with_name(f".{run_id}.tmp")
    if temporary_dir.exists():
        raise CollectionError(f"stale temporary output must be reviewed: {temporary_dir}")
    temporary_dir.mkdir(parents=True)
    _write_json(temporary_dir / "scenario_manifest.json", manifest.model_dump(mode="json"))
    _write_jsonl(temporary_dir / "incidents.jsonl", [incident.model_dump(mode="json")])

    _write_jsonl(evidence_dir / "wazuh_archives.jsonl", in_window)
    _write_jsonl(evidence_dir / "windows_events.jsonl", windows_events)
    _write_jsonl(evidence_dir / "suricata_eve.jsonl", suricata_events)
    marker_path = evidence_dir / "run_markers.jsonl"
    start_marker = state["start_marker"]
    _write_jsonl(
        marker_path,
        [
            start_marker,
            {
                "event": "END",
                "run_id": run_id,
                "timestamp": _iso(ended_at),
                "incident_id": incident_id,
            },
        ],
    )
    if execution_log_source is not None:
        shutil.copyfile(execution_log_source, evidence_dir / "atomic_execution.csv")
    metadata = {
        "version": "scenario-collection-v1",
        "status": "FINALIZED",
        "run_id": run_id,
        "started_at": _iso(started_at),
        "ended_at": _iso(ended_at),
        "archive_events": len(in_window),
        "attributed_windows_events": len(windows_events),
        "attributed_suricata_events": len(suricata_events),
        "taxonomy_revision": taxonomy["revision"],
        "collection_seed": draft.collection_seed,
        "scenario_parameters": draft.scenario_parameters,
        "expected_observables": draft.expected_observables,
        "clock_preflight": draft.clock_preflight.model_dump(mode="json"),
        "run_marker_count": 2,
        "feature_schema_version": schema["version"],
        "scenario_manifest_sha256": _sha256(temporary_dir / "scenario_manifest.json"),
        "incidents_sha256": _sha256(temporary_dir / "incidents.jsonl"),
    }
    _write_json(evidence_dir / "collection_metadata.json", metadata)
    _append_log(evidence_dir, f"RUN_FINALIZED run_id={run_id}")
    _write_checksums(evidence_dir)
    temporary_dir.replace(final_dir)
    state["status"] = "FINALIZED"
    state["ended_at"] = _iso(ended_at)
    _write_json(state_path, state)
    _release_active_run(evidence_dir.parent, run_id)
    return metadata


def _verify_checksums(evidence_dir: Path) -> None:
    checksum_path = evidence_dir / "checksums.sha256"
    if not checksum_path.is_file():
        raise CollectionError("missing evidence checksums.sha256")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(checksum_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            expected, name = line.split("  ", 1)
        except ValueError as exc:
            raise CollectionError(f"invalid checksum line {line_number}") from exc
        if len(expected) != 64 or any(
            character not in "0123456789abcdef" for character in expected
        ):
            raise CollectionError(f"invalid checksum digest on line {line_number}")
        if name in entries or Path(name).name != name:
            raise CollectionError(f"invalid checksum file name on line {line_number}")
        entries[name] = expected
        path = evidence_dir / name
        if not path.is_file() or _sha256(path) != expected:
            raise CollectionError(f"checksum mismatch for evidence file: {name}")
    expected_files = {
        path.name
        for path in evidence_dir.iterdir()
        if path.is_file() and path.name not in {"checksums.sha256", ".collection_state.json"}
    }
    if not entries or set(entries) != expected_files:
        missing = sorted(expected_files - set(entries))
        unexpected = sorted(set(entries) - expected_files)
        raise CollectionError(
            "checksum manifest is incomplete or inconsistent: "
            f"missing={missing}, unexpected={unexpected}"
        )


def validate_run(run_id: str, project_root: Path) -> dict[str, Any]:
    project_root = project_root.resolve()
    evidence_dir = project_root / "evidence/scenario-runs" / run_id
    run_dir = project_root / "data/raw" / run_id
    _verify_checksums(evidence_dir)
    state_path = evidence_dir / ".collection_state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid collection state: {exc}") from exc
    if state.get("status") != "FINALIZED" or state.get("run_id") != run_id:
        raise CollectionError("collection state is not FINALIZED for this run")
    _verify_start_snapshot(evidence_dir, state)
    metadata_path = evidence_dir / "collection_metadata.json"
    if not metadata_path.is_file():
        raise CollectionError("missing collection_metadata.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    markers = [
        json.loads(line)
        for line in (evidence_dir / "run_markers.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if (
        len(markers) != 2
        or markers[0].get("event") != "START"
        or markers[1].get("event") != "END"
        or any(marker.get("run_id") != run_id for marker in markers)
        or metadata.get("run_marker_count") != 2
    ):
        raise CollectionError("run marker evidence is incomplete or inconsistent")
    protected_files = {
        "scenario_manifest.json": metadata.get("scenario_manifest_sha256"),
        "incidents.jsonl": metadata.get("incidents_sha256"),
    }
    for name, expected in protected_files.items():
        path = run_dir / name
        if not isinstance(expected, str) or not path.is_file() or _sha256(path) != expected:
            raise CollectionError(f"checksum mismatch for dataset file: {name}")
    try:
        manifest = ScenarioManifest.model_validate_json(
            (run_dir / "scenario_manifest.json").read_text(encoding="utf-8")
        )
        lines = [
            line
            for line in (run_dir / "incidents.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if len(lines) != 1:
            raise CollectionError("collector run must contain exactly one aggregated incident")
        incident = IncidentRequest.model_validate_json(lines[0])
    except (OSError, ValueError) as exc:
        raise CollectionError(f"invalid finalized run {run_id}: {exc}") from exc
    if manifest.run_id != run_id or incident.family_hint != manifest.family:
        raise CollectionError("finalized run identity/family mismatch")
    if incident.asset_id != manifest.host:
        raise CollectionError("finalized run host mismatch")
    if incident.start_time < manifest.start_time or incident.end_time > manifest.end_time:
        raise CollectionError("incident lies outside scenario window")
    if manifest.family == "c2":
        suricata_path = evidence_dir / "suricata_eve.jsonl"
        if not suricata_path.is_file() or not suricata_path.read_text(encoding="utf-8").strip():
            raise CollectionError("C2 run is missing attributable Suricata evidence")
    return {"status": "VALID", "run_id": run_id, "family": manifest.family, "label": manifest.label}


def run_status(run_id: str, project_root: Path) -> dict[str, Any]:
    state_path = (
        project_root.resolve()
        / "evidence/scenario-runs"
        / run_id
        / ".collection_state.json"
    )
    if not state_path.is_file():
        raise CollectionError(f"unknown run_id: {run_id}")
    return json.loads(state_path.read_text(encoding="utf-8"))


def abort_run(run_id: str, project_root: Path, reason: str) -> dict[str, Any]:
    if not reason.strip():
        raise CollectionError("abort reason must not be blank")
    project_root = project_root.resolve()
    evidence_dir = project_root / "evidence/scenario-runs" / run_id
    state_path = evidence_dir / ".collection_state.json"
    if not state_path.is_file():
        raise CollectionError(f"unknown run_id: {run_id}")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("status") == "FINALIZED":
        raise CollectionError("a finalized run cannot be aborted")
    state["status"] = "ABORTED"
    state["abort_reason"] = reason.strip()
    state["aborted_at"] = _iso(datetime.now(UTC))
    _write_json(state_path, state)
    _append_log(evidence_dir, f"RUN_ABORTED run_id={run_id} reason={reason.strip()}")
    _release_active_run(evidence_dir.parent, run_id)
    return {"status": "ABORTED", "run_id": run_id, "reason": reason.strip()}


def quarantine_run(run_id: str, project_root: Path, reason: str) -> dict[str, Any]:
    if not reason.strip():
        raise CollectionError("quarantine reason must not be blank")
    project_root = project_root.resolve()
    evidence_source = project_root / "evidence/scenario-runs" / run_id
    raw_source = project_root / "data/raw" / run_id
    if not evidence_source.is_dir():
        raise CollectionError(f"unknown run_id: {run_id}")
    evidence_target = project_root / "evidence/quarantine" / run_id
    raw_target = project_root / "data/quarantine" / run_id
    if evidence_target.exists() or raw_target.exists():
        raise CollectionError(f"quarantine target already exists: {run_id}")
    evidence_target.parent.mkdir(parents=True, exist_ok=True)
    raw_target.parent.mkdir(parents=True, exist_ok=True)

    _release_active_run(evidence_source.parent, run_id)
    raw_moved = False
    try:
        if raw_source.exists():
            raw_source.replace(raw_target)
            raw_moved = True
        evidence_source.replace(evidence_target)
    except OSError as exc:
        if raw_moved and raw_target.exists() and not raw_source.exists():
            raw_target.replace(raw_source)
        raise CollectionError(f"could not quarantine run {run_id}: {exc}") from exc

    marker = {
        "status": "QUARANTINED",
        "run_id": run_id,
        "reason": reason.strip(),
        "quarantined_at": _iso(datetime.now(UTC)),
        "raw_preserved": raw_moved,
    }
    _write_json(evidence_target / "quarantine.json", marker)
    return marker
