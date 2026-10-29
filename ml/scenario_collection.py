from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import re
import shutil
import tempfile
import time
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from api.app.contracts import IncidentRequest, WazuhAlert
from ml.behavior_features import (
    AccountObservation,
    NetworkObservation,
    derive_account_features,
    derive_c2_features,
    interval_features,
)
from ml.clock_evidence import ClockPreflight
from ml.collection_windows import bucket_used, reserve_bucket
from ml.context import BaselineSnapshot, context_from_events, load_baseline
from ml.dataset import (
    DatasetRecord,
    ScenarioManifest,
    load_feature_schema,
    validate_feature_contract,
)
from ml.feature_pipeline import aggregate_wazuh_alerts
from ml.telemetry import (
    account_observation_eligible,
    flow_counter_issues,
    linked_flow,
    linked_transaction,
    network_is_outbound,
    normalize_ip,
    suricata_observations,
    unambiguous_transactions,
)
from ml.telemetry import (
    account_source as _account_source,
)
from ml.telemetry import (
    account_user as _account_user,
)
from ml.telemetry import (
    basename as _basename,
)
from ml.telemetry import (
    event_time as _event_time,
)
from ml.telemetry import (
    parse_time as _parse_time,
)
from ml.telemetry import (
    process_guid as _process_guid,
)
from ml.telemetry import (
    suricata_correlates as _suricata_correlates,
)
from ml.telemetry import (
    suricata_dns_is_response as _suricata_dns_is_response,
)
from ml.telemetry import (
    suricata_dns_names as _suricata_dns_names,
)
from ml.telemetry import (
    suricata_payload as _suricata_payload,
)
from ml.telemetry import (
    taxonomy_match as _taxonomy_match,
)
from ml.telemetry import (
    windows_fields as _windows_fields,
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
    purpose: Literal["trainable", "challenge", "pilot"] = "trainable"
    cohort_id: str | None = Field(default=None, min_length=1, max_length=128)
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
        if self.family == "c2":
            nonce = self.scenario_parameters.get("run_nonce")
            if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", nonce):
                raise ValueError("c2 run requires an 8-64 character scenario_parameters.run_nonce")
        return self


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["collection-sources-v1"]
    wazuh_archives_path: str
    windows_agent_name: str = Field(min_length=1)
    suricata_agent_name: str = Field(min_length=1)
    windows_source_ips: list[str] = Field(default_factory=list)
    correlation_window_seconds: float = Field(default=10.0, gt=0, le=30)
    taxonomy_path: str
    scenario_catalog_path: str = Field(min_length=1)
    context_baseline_path: str | None = None
    require_clean_bucket: bool = False
    require_flow_counters: bool = False
    require_online_parity: bool = False
    late_arrival_grace_seconds: int = Field(default=60, ge=0, le=600, strict=True)


class ScenarioDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=128)
    family: Literal["account", "c2"]
    label: Literal["benign", "malicious"]
    purpose: Literal["trainable", "challenge", "pilot"] = "trainable"
    cohort_id: str | None = Field(default=None, min_length=1, max_length=128)
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


def _normalized_source(source: SourceConfig, project_root: Path) -> dict[str, Any]:
    payload = source.model_dump(mode="json")
    payload["wazuh_archives_path"] = str(
        _resolve(project_root, source.wazuh_archives_path).resolve()
    )
    payload["taxonomy_path"] = str(_resolve(project_root, source.taxonomy_path).resolve())
    payload["scenario_catalog_path"] = str(
        _resolve(project_root, source.scenario_catalog_path).resolve()
    )
    if source.context_baseline_path:
        payload["context_baseline_path"] = str(
            _resolve(project_root, source.context_baseline_path).resolve()
        )
    return payload


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
    if draft.purpose not in {scenario.purpose, "pilot"} or draft.cohort_id != scenario.cohort_id:
        raise CollectionError("draft purpose/cohort does not match the frozen scenario catalog")


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
    purpose: Literal["trainable", "challenge", "pilot"] | None = None,
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
    common_parameters: dict[str, int | float | str | bool] = {
        "pre_action_delay_seconds": round(rng.uniform(1.0, 5.0), 3),
    }
    if scenario.family == "account":
        parameters = dict(common_parameters)
        if scenario.scenario_id == "ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS":
            parameters["attempt_delay_seconds"] = round(rng.uniform(1.0, 5.0), 3)
    else:
        base_intervals: dict[str, list[float]] = {
            "C2-BENIGN-HEALTH-POLL": [30.0] * 7,
            "C2-BENIGN-SINGLE-DOWNLOAD": [],
            "C2-BENIGN-IRREGULAR-API": [10.0, 35.0, 20.0],
            "C2-BENIGN-DNS": [7.0, 19.0, 11.0],
            "C2-BENIGN-API-BURST": [2.0] * 5,
            "C2-MALICIOUS-HTTP-BEACON": [15.0] * 7,
            "C2-MALICIOUS-JITTER-BEACON": [8.0, 21.0, 13.0, 30.0, 11.0, 24.0, 17.0],
            "C2-MALICIOUS-DNS-BEACON": [15.0] * 7,
            "C2-MALICIOUS-STAGED-TRANSFER": [],
            "C2-MALICIOUS-STAGED-TRANSFER-RETRY": [20.0] * 2,
        }
        if scenario.scenario_id not in base_intervals:
            raise CollectionError(
                f"missing timing contract for C2 scenario: {scenario.scenario_id}"
            )
        jitter_percent = rng.randint(10, 30)
        jitter_direction = rng.choice((-1, 1))
        factor = 1.0 + jitter_direction * jitter_percent / 100.0
        expected_action_count = max(
            scenario.quality_gates.min_process_events,
            scenario.quality_gates.min_network_events,
            scenario.quality_gates.min_dns_events,
        )
        parameters = {
            **common_parameters,
            "interval_jitter_percent": jitter_percent,
            "interval_jitter_direction": jitter_direction,
            "variant_index": rng.randint(0, 999_999),
            "run_nonce": hashlib.sha256(f"{run_id}:{seed}".encode()).hexdigest()[:16],
            "expected_action_count": expected_action_count,
            "expected_intervals_seconds": ",".join(
                str(round(value * factor, 3)) for value in base_intervals[scenario.scenario_id]
            ),
        }
    try:
        draft = RunDraft(
            scenario_id=scenario.scenario_id,
            run_id=run_id,
            family=scenario.family,
            label=scenario.label,
            purpose=purpose or scenario.purpose,
            cohort_id=scenario.cohort_id,
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
    _validate_draft_against_catalog(draft, catalog_path)
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


def _payload_sha256(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


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
        if state.get("status") in {"STARTED", "FINALIZING"}:
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
    catalog_path = _resolve(project_root, source.scenario_catalog_path).resolve()
    if not catalog_path.is_file():
        raise CollectionError(f"scenario catalog does not exist: {catalog_path}")
    _validate_draft_against_catalog(draft, catalog_path)
    schema_path = project_root / "ml/feature_schema.json"
    if not schema_path.is_file():
        schema_path = Path(__file__).with_name("feature_schema.json")
    if not schema_path.is_file():
        raise CollectionError(f"feature schema does not exist: {schema_path}")
    context_path = (
        _resolve(project_root, source.context_baseline_path)
        if source.context_baseline_path else None
    )
    baseline = None
    context_bytes = None
    capture_bytes = None
    if context_path:
        try:
            context_bytes = context_path.read_bytes()
            baseline = BaselineSnapshot.model_validate_json(context_bytes)
        except (OSError, ValueError) as exc:
            raise CollectionError(
                f"context baseline is required and must be valid; enroll a separate capture: {exc}"
            ) from exc
        context_capture = context_path.parent / "context-captures" / (
            baseline.source_capture_sha256 + ".jsonl"
        )
        try:
            capture_bytes = context_capture.read_bytes()
        except OSError as exc:
            raise CollectionError("context enrollment capture is missing") from exc
        if hashlib.sha256(capture_bytes).hexdigest() != baseline.source_capture_sha256:
            raise CollectionError("context enrollment capture is missing or its hash differs")

    started_at = _utc(now)
    if baseline and not baseline.captured_at <= started_at < baseline.valid_until:
        raise CollectionError("context baseline is stale or unavailable at collection start")
    clock_age = (started_at - _utc(draft.clock_preflight.captured_at)).total_seconds()
    if clock_age < -1 or clock_age > draft.clock_preflight.maximum_capture_age_seconds:
        raise CollectionError(
            f"clock evidence is stale or captured in the future at run start: age={clock_age:.3f}s"
        )

    _assert_raw_dataset_layout(project_root)

    evidence_dir = project_root / "evidence/scenario-runs" / draft.run_id
    output_dir = project_root / "data/raw" / draft.run_id
    if evidence_dir.exists() or output_dir.exists():
        raise CollectionError(f"run_id already exists: {draft.run_id}")

    draft_snapshot = draft.model_dump(mode="json")
    frozen_parameters = {
        "run_id": draft.run_id,
        "scenario_id": draft.scenario_id,
        "family": draft.family,
        "label": draft.label,
        "purpose": draft.purpose,
        "cohort_id": draft.cohort_id,
        "scenario_parameters": draft.scenario_parameters,
    }
    frozen_parameters_sha256 = _payload_sha256(frozen_parameters)
    source_snapshot = _normalized_source(source, project_root)
    archive_cursor = _cursor(archive_path)
    state = {
        "version": "scenario-collection-v1",
        "status": "STARTED",
        "run_id": draft.run_id,
        "started_at": _iso(started_at),
        "draft": draft_snapshot,
        "source": source_snapshot,
        "archive_cursor": archive_cursor,
        "draft_sha256": _sha256(draft_path),
        "draft_snapshot_sha256": _payload_sha256(draft_snapshot),
        "source_config_sha256": _sha256(source_config_path),
        "taxonomy_sha256": _sha256(taxonomy_path),
        "feature_schema_sha256": _sha256(schema_path),
        "frozen_parameters_sha256": frozen_parameters_sha256,
        "execution_receipt": None,
        "origin_project_root": str(project_root),
        "context_baseline_sha256": (
            hashlib.sha256(context_bytes).hexdigest() if context_bytes is not None else None
        ),
        "context_capture_sha256": baseline.source_capture_sha256 if baseline else None,
    }
    state["scenario_catalog_sha256"] = _sha256(catalog_path)
    state["collection_contract_sha256"] = _payload_sha256(
        {
            "source_config_sha256": state["source_config_sha256"],
            "taxonomy_sha256": state["taxonomy_sha256"],
            "scenario_catalog_sha256": state["scenario_catalog_sha256"],
            "feature_schema_sha256": state["feature_schema_sha256"],
        }
    )
    start_contract = {
        "version": "collection-start-contract-v2",
        "origin_project_root": str(project_root),
        "source_document": source.model_dump(mode="json"),
        "context_baseline_sha256": state["context_baseline_sha256"],
        "context_capture_sha256": state["context_capture_sha256"],
        "run_id": draft.run_id,
        "started_at": state["started_at"],
        "draft_sha256": state["draft_sha256"],
        "draft_snapshot_sha256": state["draft_snapshot_sha256"],
        "source_config_sha256": state["source_config_sha256"],
        "taxonomy_sha256": state["taxonomy_sha256"],
        "scenario_catalog_sha256": state["scenario_catalog_sha256"],
        "feature_schema_sha256": state["feature_schema_sha256"],
        "collection_contract_sha256": state["collection_contract_sha256"],
        "frozen_parameters_sha256": state["frozen_parameters_sha256"],
        "source": source_snapshot,
        "archive_cursor": archive_cursor,
    }
    state["start_contract_sha256"] = _payload_sha256(start_contract)
    start_marker = {
        "event": "START",
        "run_id": draft.run_id,
        "timestamp": _iso(started_at),
        "draft_sha256": state["draft_sha256"],
        "start_contract_sha256": state["start_contract_sha256"],
    }
    state["start_marker"] = start_marker
    evidence_root = evidence_dir.parent
    _acquire_active_run(evidence_root, draft.run_id)
    try:
        with tempfile.TemporaryDirectory(
            prefix=f".{draft.run_id}.starting-",
            dir=evidence_root,
        ) as temporary:
            staging_dir = Path(temporary)
            _write_json(staging_dir / "ground_truth.json", draft_snapshot)
            _write_json(staging_dir / "execution-parameters.json", frozen_parameters)
            _write_json(staging_dir / "start-contract.json", start_contract)
            shutil.copyfile(source_config_path, staging_dir / "collection-sources.yaml")
            shutil.copyfile(
                taxonomy_path,
                staging_dir / "suspicious-process-taxonomy.yaml",
            )
            shutil.copyfile(catalog_path, staging_dir / "scenario-catalog.yaml")
            shutil.copyfile(schema_path, staging_dir / "feature-schema.json")
            if context_bytes is not None and capture_bytes is not None:
                (staging_dir / "context-baseline.json").write_bytes(context_bytes)
                (staging_dir / "context-capture.jsonl").write_bytes(capture_bytes)
            _write_jsonl(staging_dir / "run_markers.jsonl", [start_marker])
            _write_json(staging_dir / ".collection_state.json", state)
            _append_log(staging_dir, f"RUN_STARTED run_id={draft.run_id}")
            staging_dir.replace(evidence_dir)
    except OSError as exc:
        _release_active_run(evidence_root, draft.run_id)
        raise CollectionError(f"could not initialize run evidence: {exc}") from exc
    return {
        "status": "STARTED",
        "run_id": draft.run_id,
        "started_at": state["started_at"],
        "frozen_parameters_sha256": frozen_parameters_sha256,
    }


def _read_appended_jsonl(
    cursor: dict[str, Any], capture_path: Path | None = None,
) -> list[dict[str, Any]]:
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
        _validate_raw_event_structure(event)
        events.append(event)
    if not events:
        raise CollectionError("no complete JSON events were appended during the run")
    if capture_path:
        capture_path.write_bytes(payload)
    return events


def _casefold_set(values: list[str]) -> set[str]:
    return {value.strip().casefold() for value in values if value.strip()}


def _is_interactive_logon(eventdata: dict[str, Any], attribution: Attribution) -> bool:
    """Keep only the logon types declared by the controlled scenario."""
    return account_observation_eligible(eventdata, attribution.logon_types)


def _matches_network(eventdata: dict[str, Any], attribution: Attribution) -> bool:
    if not network_is_outbound(eventdata):
        return False
    process_names = _casefold_set(attribution.process_names)
    if process_names and _basename(eventdata.get("image")) not in process_names:
        return False
    source_ips = {normalize_ip(value) for value in attribution.source_ips}
    source_ip = normalize_ip(eventdata.get("sourceIp") or eventdata.get("SourceIp") or "")
    if source_ips and source_ip not in source_ips:
        return False
    destination_ips = {normalize_ip(value) for value in attribution.destination_ips}
    destination_ip = normalize_ip(eventdata.get("destinationIp"))
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
    suffix_matches = any(query == suffix or query.endswith(f".{suffix}") for suffix in suffixes)
    if not suffixes or not suffix_matches:
        return False
    process_names = _casefold_set(attribution.process_names)
    return not process_names or _basename(eventdata.get("image")) in process_names


def _matches_suricata(
    payload: dict[str, Any], attribution: Attribution, *, bound_flow: bool = False
) -> bool:
    event_type = payload.get("event_type")
    dns = payload.get("dns")
    dns_response = _suricata_dns_is_response(dns)
    source_ips = {normalize_ip(value) for value in attribution.source_ips}
    source_field = "dest_ip" if dns_response else "src_ip"
    if source_ips and normalize_ip(payload.get(source_field)) not in source_ips:
        return False
    destination_ips = {normalize_ip(value) for value in attribution.destination_ips}
    destination_field = "src_ip" if dns_response else "dest_ip"
    if destination_ips and normalize_ip(payload.get(destination_field)) not in destination_ips:
        return False
    if attribution.destination_ports:
        port_field = "src_port" if dns_response else "dest_port"
        try:
            port = int(payload.get(port_field))
        except (TypeError, ValueError):
            return False
        if port not in set(attribution.destination_ports):
            return False
    if attribution.dns_suffixes and not (bound_flow and event_type == "flow"):
        if event_type not in {"dns", "alert"}:
            return False
        queries = _suricata_dns_names(dns)
        suffixes = [
            value.strip(".").casefold() for value in attribution.dns_suffixes if value.strip(".")
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


def _suricata_has_nonce(payload: dict[str, Any], nonce: str) -> bool:
    expected = nonce.casefold()
    if any(expected in name for name in _suricata_dns_names(payload.get("dns"))):
        return True
    http = payload.get("http")
    if isinstance(http, dict):
        for field in ("url", "hostname", "http_user_agent"):
            if expected in str(http.get(field, "")).casefold():
                return True
    return False


def periodicity_score(timestamps: list[datetime]) -> float:
    return interval_features(timestamps)[0]


def _derive_account(
    events: list[dict[str, Any]], draft: RunDraft, windows_agent: str
) -> tuple[dict[str, float], list[dict[str, Any]], str | None]:
    users = _casefold_set(draft.attribution.account_names)
    sources = {normalize_ip(value) for value in draft.attribution.source_ips}
    selected: list[dict[str, Any]] = []
    observations: list[AccountObservation] = []
    observed_accounts: set[str] = set()
    for event in events:
        if str((event.get("agent") or {}).get("name")) != windows_agent:
            continue
        event_id, _, eventdata = _windows_fields(event)
        source = _account_source(eventdata)
        if (
            event_id not in {"4624", "4625"}
            or _account_user(eventdata) not in users
            or not _is_interactive_logon(eventdata, draft.attribution)
            or (sources and source not in sources)
        ):
            continue
        timestamp = _event_time(event)
        if timestamp is None:
            continue
        selected.append(event)
        observed_accounts.add(_account_user(eventdata))
        account = _account_user(eventdata)
        logon_type = str(eventdata.get("logonType", eventdata.get("LogonType", "unknown"))).strip()
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
        gates.max_account_failures is not None and failures > gates.max_account_failures
    ):
        raise CollectionError(
            "account failure count failed quality gate: "
            f"observed={failures}, expected="
            f"[{gates.min_account_failures}, {gates.max_account_failures}]"
        )
    if successes < gates.min_account_successes or (
        gates.max_account_successes is not None and successes > gates.max_account_successes
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
    nonce = str(draft.scenario_parameters["run_nonce"]).casefold()
    attributed_process_guids: set[str] = set()
    process_names = _casefold_set(draft.attribution.process_names)
    command_terms = [term.casefold() for term in draft.attribution.command_contains_any]
    for event in events:
        if str((event.get("agent") or {}).get("name")) != source.windows_agent_name:
            continue
        event_id, _, eventdata = _windows_fields(event)
        command_line = str(eventdata.get("commandLine", "")).casefold()
        guid = _process_guid(eventdata)
        if event_id != "1":
            continue
        if (
            (not process_names or _basename(eventdata.get("image")) in process_names)
            and (not command_terms or any(term in command_line for term in command_terms))
            and nonce in command_line
            and guid
        ):
            windows.append(event)
            process_events += 1
            attributed_process_guids.add(guid)
            suspicious = suspicious or _taxonomy_match(eventdata, taxonomy)

    if not attributed_process_guids:
        raise CollectionError("no attributable process creation proves this C2 execution")
    for event in events:
        if str((event.get("agent") or {}).get("name")) != source.windows_agent_name:
            continue
        event_id, _, eventdata = _windows_fields(event)
        guid = _process_guid(eventdata)
        if (
            event_id == "3"
            and _matches_network(eventdata, draft.attribution)
            and guid in attributed_process_guids
        ):
            timestamp = _event_time(event)
            if timestamp is None:
                continue
            windows.append(event)
            destination = normalize_ip(eventdata.get("destinationIp"))
            destination_port = None
            with suppress(TypeError, ValueError):
                destination_port = int(eventdata.get("destinationPort"))
            network_observations.append(
                NetworkObservation(
                    timestamp,
                    destination,
                    destination_port,
                    source=normalize_ip(eventdata.get("sourceIp")),
                    source_port=_transport_port(eventdata.get("sourcePort")),
                    protocol=str(eventdata.get("protocol", "")),
                )
            )
            suspicious = suspicious or _taxonomy_match(eventdata, taxonomy)
        elif (
            event_id == "22"
            and _matches_dns(eventdata, draft.attribution)
            and nonce in str(eventdata.get("queryName", "")).strip(".").casefold()
            and guid in attributed_process_guids
        ):
            timestamp = _event_time(event)
            if timestamp is None:
                continue
            windows.append(event)
            dns_events += 1
            query = str(eventdata.get("queryName", "")).strip(".")
            network_observations.append(NetworkObservation(timestamp, query, 53, dns_query=query))
            suspicious = suspicious or _taxonomy_match(eventdata, taxonomy)
    if not network_observations:
        raise CollectionError("no attributable Sysmon network or DNS telemetry was collected")

    expected_action_count = draft.scenario_parameters.get("expected_action_count")
    expected_intervals_text = draft.scenario_parameters.get("expected_intervals_seconds")
    if isinstance(expected_action_count, int):
        action_observations = (
            [item for item in network_observations if item.dns_query is not None]
            if draft.quality_gates.min_dns_events
            else [item for item in network_observations if item.dns_query is None]
        )
        if len(action_observations) != expected_action_count:
            raise CollectionError(
                "frozen action count does not match attributable telemetry: "
                f"observed={len(action_observations)}, expected={expected_action_count}"
            )
        if isinstance(expected_intervals_text, str) and expected_intervals_text:
            try:
                expected_intervals = [float(value) for value in expected_intervals_text.split(",")]
            except ValueError as exc:
                raise CollectionError("invalid frozen interval contract") from exc
            observed_times = sorted(item.timestamp for item in action_observations)
            observed_intervals = [
                (current - previous).total_seconds()
                for previous, current in zip(observed_times, observed_times[1:], strict=False)
            ]
            if len(observed_intervals) != len(expected_intervals) or any(
                abs(observed - expected) > max(3.0, expected * 0.20)
                for observed, expected in zip(observed_intervals, expected_intervals, strict=True)
            ):
                raise CollectionError(
                    "observed action timing does not match the frozen interval contract: "
                    f"observed={observed_intervals}, expected={expected_intervals}"
                )

    nonce_references: list[tuple[dict[str, Any], datetime]] = []
    maximum_delta = source.correlation_window_seconds
    for event in events:
        if str((event.get("agent") or {}).get("name")) != source.suricata_agent_name:
            continue
        payload = _suricata_payload(event)
        timestamp = _event_time(event)
        if (
            payload is None
            or timestamp is None
            or not _matches_suricata(payload, draft.attribution)
            or not _suricata_correlates(payload, timestamp, network_observations, maximum_delta)
        ):
            continue
        if payload.get("event_type") in {"http", "dns", "tls"} and _suricata_has_nonce(
            payload, nonce
        ):
            nonce_references.append((payload, timestamp))

    nonce_references = unambiguous_transactions(nonce_references, maximum_delta)
    suricata: list[dict[str, Any]] = []
    seen: set[str] = set()
    signature_ids: set[int] = set()
    for event in events:
        if str((event.get("agent") or {}).get("name")) != source.suricata_agent_name:
            continue
        payload = _suricata_payload(event)
        timestamp = _event_time(event)
        bound_flow = bool(payload and linked_flow(payload, nonce_references, maximum_delta))
        if (
            payload is None
            or timestamp is None
            or not _matches_suricata(payload, draft.attribution, bound_flow=bound_flow)
            or (payload.get("event_type") == "flow" and not bound_flow)
            or (
                not bound_flow
                and not _suricata_correlates(
                    payload, timestamp, network_observations, maximum_delta
                )
            )
        ):
            continue
        if not _suricata_has_nonce(payload, nonce) and not (
            bound_flow
            or linked_transaction(payload, timestamp, nonce_references, maximum_delta)
        ):
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
    if source.require_flow_counters:
        start, end = _aggregation_window(min(item.timestamp for item in network_observations))
        flow_issues = flow_counter_issues(suricata, window_start=start, window_end=end)
        if flow_issues:
            raise CollectionError("incomplete flow evidence: " + ",".join(flow_issues))

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
    missing_signatures = sorted(set(gates.required_suricata_signature_ids) - signature_ids)
    if missing_signatures:
        raise CollectionError(
            f"required Suricata signatures were not observed: {missing_signatures}"
        )
    forbidden_signatures = sorted(set(gates.forbidden_suricata_signature_ids) & signature_ids)
    if forbidden_signatures:
        raise CollectionError(
            f"forbidden Suricata signatures were observed: {forbidden_signatures}"
        )

    features = derive_c2_features(
        network_observations,
        suricata_observations(suricata),
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


def _validate_raw_event_structure(event: dict[str, Any]) -> None:
    for field in ("agent", "data"):
        if event.get(field) is not None and not isinstance(event[field], dict):
            raise CollectionError(f"raw event {field} must be an object")
    data = event.get("data") or {}
    win = data.get("win")
    if win is not None:
        if not isinstance(win, dict):
            raise CollectionError("raw event data.win must be an object")
        for field in ("system", "eventdata"):
            if win.get(field) is not None and not isinstance(win[field], dict):
                raise CollectionError(f"raw event data.win.{field} must be an object")
    payload = _suricata_payload(event)
    if payload is not None:
        for field in ("alert", "flow", "dns", "http", "tls"):
            if payload.get(field) is not None and not isinstance(payload[field], dict):
                raise CollectionError(f"raw EVE {field} must be an object")


def _read_evidence_rows(path: Path, *, required: bool = True) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CollectionError(f"cannot read raw evidence {path.name}: {exc}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CollectionError(f"invalid raw evidence {path.name}:{number}") from exc
        if not isinstance(row, dict) or not row:
            raise CollectionError(f"raw evidence must contain event objects: {path.name}:{number}")
        _validate_raw_event_structure(row)
        rows.append(row)
    if required and not rows:
        raise CollectionError(f"missing non-empty raw evidence: {path.name}")
    return rows


def _verify_full_capture_parity(
    captured: list[dict[str, Any]], incident: IncidentRequest, source: SourceConfig,
    evidence_dir: Path,
) -> None:
    """Replay the full asset bucket without label, scenario or nonce filtering."""
    start, end = _aggregation_window(incident.start_time)
    alerts = []
    for row in captured:
        at = _event_time(row)
        agent = row.get("agent")
        if not isinstance(agent, dict) or agent.get("name") not in {
            source.windows_agent_name, source.suricata_agent_name,
        }:
            continue
        if at is None:
            raise CollectionError("full-capture parity requires original event timestamps")
        if not start <= at < end:
            continue
        envelope = dict(row)
        canonical = json.dumps(row, sort_keys=True, separators=(",", ":"))
        envelope.setdefault("id", "archive-" + hashlib.sha256(canonical.encode()).hexdigest())
        envelope.setdefault("timestamp", _iso(at))
        envelope.setdefault("rule", {"id": "archive-raw", "level": 0})
        try:
            alert = WazuhAlert.model_validate(envelope)
        except ValueError as exc:
            raise CollectionError(f"full-capture parity envelope is invalid: {exc}") from exc
        alerts.append(alert)
    if not alerts:
        raise CollectionError("full-capture parity has no replayable records")
    batch = aggregate_wazuh_alerts(
        alerts, baseline=load_baseline(evidence_dir / "context-baseline.json"),
        source_config=source.model_dump(mode="json"),
        taxonomy=_load_taxonomy(evidence_dir / "suspicious-process-taxonomy.yaml"),
        use_runtime_baseline=False,
    )
    candidates = [
        item.incident for item in batch.incidents
        if item.incident.asset_id.casefold() == incident.asset_id.casefold()
        and item.incident.family_hint == incident.family_hint
    ]
    if len(candidates) != 1:
        raise CollectionError("full-capture parity requires exactly one attributable online group")
    online = candidates[0]
    if (
        online.features != incident.features
        or online.context_status != incident.context_status
        or online.context_revision != incident.context_revision
        or online.observation_quality != incident.observation_quality
    ):
        changed = sorted(
            key for key in online.features.keys() | incident.features.keys()
            if online.features.get(key) != incident.features.get(key)
        )
        raise CollectionError(f"full-capture parity failed; feature differences={changed}")


def verify_feature_provenance(
    evidence_dir: Path,
    manifest: ScenarioManifest,
    incident: IncidentRequest,
    state: dict[str, Any],
) -> None:
    """Reproduce the finalized vector from its raw archives without live log access."""
    contract = json.loads((evidence_dir / "start-contract.json").read_text(encoding="utf-8"))
    if not isinstance(contract, dict):
        raise CollectionError("start-contract.json must contain an object")
    if contract.get("version") == "collection-start-contract-v2":
        _verify_start_snapshot(evidence_dir, state, evidence_dir.parents[2])
    try:
        draft = RunDraft.model_validate(
            json.loads((evidence_dir / "ground_truth.json").read_text(encoding="utf-8"))
        )
        source = SourceConfig.model_validate(state.get("source"))
    except (OSError, ValueError, TypeError) as exc:
        raise CollectionError(f"invalid feature provenance configuration: {exc}") from exc
    if _payload_sha256(draft.model_dump(mode="json")) != manifest.provenance_sha256:
        raise CollectionError("raw provenance draft digest does not match manifest")
    tolerance = timedelta(seconds=draft.clock_preflight.maximum_skew_seconds)
    events = _read_evidence_rows(evidence_dir / "wazuh_archives.jsonl")
    receipt = state.get("execution_receipt")
    if not isinstance(receipt, dict):
        raise CollectionError("feature provenance requires a valid execution receipt")
    _validate_action_window(receipt, draft, events=events)
    for event in events:
        timestamp = _event_time(event)
        if timestamp is None or not (
            manifest.start_time - tolerance <= timestamp <= manifest.end_time + tolerance
        ):
            raise CollectionError("raw event has no valid time inside the declared action window")
    if manifest.family == "account":
        features, windows, _ = _derive_account(events, draft, source.windows_agent_name)
        suricata: list[dict[str, Any]] = []
    else:
        features, windows, suricata, _ = _derive_c2(
            events,
            draft,
            source,
            _load_taxonomy(evidence_dir / "suspicious-process-taxonomy.yaml"),
        )
    baseline = load_baseline(evidence_dir / "context-baseline.json")
    context = context_from_events(
        baseline, windows, at=manifest.end_time, asset_id=manifest.host,
    )
    features.update(context.features)
    if contract.get("version") == "collection-start-contract-v2" and (
        incident.context_status != context.status
        or incident.context_revision != context.revision
        or incident.review_reasons != context.review_reasons
    ):
        raise CollectionError("context assessment does not reproduce the finalized incident")
    capture_path = evidence_dir / "archive_capture.jsonl"
    if capture_path.is_file():
        captured = _read_evidence_rows(capture_path)
        selected = {json.dumps(item, sort_keys=True) for item in events}
        if not selected <= {json.dumps(item, sort_keys=True) for item in captured}:
            raise CollectionError("selected evidence is not a subset of the original capture")
        if source.require_online_parity:
            _verify_full_capture_parity(captured, incident, source, evidence_dir)
    elif source.require_online_parity:
        raise CollectionError("full-capture parity evidence is missing")
    if features != incident.features:
        changed = sorted(
            name
            for name in features.keys() | incident.features.keys()
            if features.get(name) != incident.features.get(name)
        )
        raise CollectionError(f"raw evidence does not reproduce finalized features: {changed}")

    def canonical(rows: list[dict[str, Any]]) -> list[str]:
        return sorted(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)

    saved_windows = _read_evidence_rows(evidence_dir / "windows_events.jsonl")
    saved_suricata = _read_evidence_rows(
        evidence_dir / "suricata_eve.jsonl", required=manifest.family == "c2"
    )
    if canonical(saved_windows) != canonical(windows):
        raise CollectionError("Windows evidence differs from attributed archive events")
    if canonical(saved_suricata) != canonical(suricata):
        raise CollectionError("Suricata evidence differs from attributed archive events")


def _verify_start_snapshot(
    evidence_dir: Path,
    state: dict[str, Any],
    project_root: Path,
) -> dict[str, Any]:
    ground_truth_path = evidence_dir / "ground_truth.json"
    source_snapshot_path = evidence_dir / "collection-sources.yaml"
    taxonomy_snapshot_path = evidence_dir / "suspicious-process-taxonomy.yaml"
    try:
        ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid start snapshot ground_truth.json: {exc}") from exc
    if ground_truth != state.get("draft") or _payload_sha256(ground_truth) != state.get(
        "draft_snapshot_sha256"
    ):
        raise CollectionError("start snapshot ground_truth.json changed after run start")
    start_contract_path = evidence_dir / "start-contract.json"
    try:
        start_contract = json.loads(start_contract_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid immutable start contract: {exc}") from exc
    if (
        not isinstance(start_contract, dict)
        or start_contract.get("version") not in {
            "collection-start-contract-v1", "collection-start-contract-v2"
        }
        or _payload_sha256(start_contract) != state.get("start_contract_sha256")
    ):
        raise CollectionError("immutable start contract digest is inconsistent")
    bound_fields = (
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
    if any(start_contract.get(name) != state.get(name) for name in bound_fields):
        raise CollectionError("runtime state differs from the immutable start contract")
    parameters_path = evidence_dir / "execution-parameters.json"
    try:
        parameters = json.loads(parameters_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid frozen execution parameters: {exc}") from exc
    if _payload_sha256(parameters) != state.get("frozen_parameters_sha256"):
        raise CollectionError("frozen execution parameters changed after run start")
    marker_path = evidence_dir / "run_markers.jsonl"
    try:
        markers = [
            json.loads(line)
            for line in marker_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid run marker evidence: {exc}") from exc
    if (
        not markers
        or markers[0] != state.get("start_marker")
        or markers[0].get("start_contract_sha256") != state.get("start_contract_sha256")
    ):
        raise CollectionError("START marker does not match immutable collection state")
    protected = {
        source_snapshot_path: start_contract.get("source_config_sha256"),
        taxonomy_snapshot_path: start_contract.get("taxonomy_sha256"),
        evidence_dir / "feature-schema.json": start_contract.get("feature_schema_sha256"),
    }
    for name in ("context_baseline_sha256", "context_capture_sha256"):
        if start_contract.get(name) != state.get(name):
            raise CollectionError("runtime context differs from the immutable start contract")
    if start_contract.get("context_baseline_sha256"):
        protected[evidence_dir / "context-baseline.json"] = start_contract[
            "context_baseline_sha256"
        ]
        protected[evidence_dir / "context-capture.jsonl"] = start_contract["context_capture_sha256"]
    if start_contract.get("scenario_catalog_sha256") is not None:
        protected[evidence_dir / "scenario-catalog.yaml"] = start_contract.get(
            "scenario_catalog_sha256"
        )
    for path, expected in protected.items():
        if not isinstance(expected, str) or not path.is_file() or _sha256(path) != expected:
            raise CollectionError(f"start snapshot changed after run start: {path.name}")
    if start_contract.get("context_baseline_sha256"):
        try:
            frozen_baseline = load_baseline(evidence_dir / "context-baseline.json")
        except (OSError, ValueError) as exc:
            raise CollectionError("frozen context baseline is invalid") from exc
        captured_start = _parse_time(start_contract.get("started_at"))
        if (
            frozen_baseline is None or captured_start is None
            or frozen_baseline.source_capture_sha256 != start_contract.get("context_capture_sha256")
            or not frozen_baseline.captured_at <= captured_start < frozen_baseline.valid_until
        ):
            raise CollectionError("frozen baseline/capture/as-of contract is inconsistent")
    try:
        snapshot_source = SourceConfig.model_validate(_read_yaml(source_snapshot_path))
    except ValueError as exc:
        raise CollectionError(f"invalid start snapshot source config: {exc}") from exc
    if start_contract["version"] == "collection-start-contract-v2":
        # Runtime paths identify the original capture, not the recovery checkout.
        # Both the parsed document and its original resolved paths are immutable.
        if (
            start_contract.get("source_document") != snapshot_source.model_dump(mode="json")
            or start_contract.get("origin_project_root") != state.get("origin_project_root")
            or not isinstance(start_contract.get("origin_project_root"), str)
        ):
            raise CollectionError("portable source document differs from the start contract")
        normalized_source = start_contract["source"]
        path_fields = {
            "wazuh_archives_path", "taxonomy_path", "scenario_catalog_path", "context_baseline_path"
        }
        if any(
            normalized_source.get(name) != value
            for name, value in snapshot_source.model_dump(mode="json").items()
            if name not in path_fields
        ):
            raise CollectionError("portable source values differ from runtime origin")
    else:
        normalized_source = _normalized_source(snapshot_source, project_root.resolve())
    if normalized_source != start_contract.get("source"):
        raise CollectionError("normalized source differs from the immutable start contract")
    cursor = start_contract.get("archive_cursor")
    if (
        not isinstance(cursor, dict)
        or cursor.get("path") != normalized_source["wazuh_archives_path"]
        or not isinstance(cursor.get("size"), int)
        or not isinstance(cursor.get("device"), int)
        or not isinstance(cursor.get("inode"), int)
        or int(cursor["size"]) < 0
    ):
        raise CollectionError("archive cursor differs from the immutable start contract")
    contract_components = {
        "source_config_sha256": start_contract.get("source_config_sha256"),
        "taxonomy_sha256": start_contract.get("taxonomy_sha256"),
        "scenario_catalog_sha256": start_contract.get("scenario_catalog_sha256"),
        "feature_schema_sha256": start_contract.get("feature_schema_sha256"),
    }
    if _payload_sha256(contract_components) != start_contract.get("collection_contract_sha256"):
        raise CollectionError("immutable start contract components are inconsistent")
    return start_contract


_AGGREGATION_WINDOW_SECONDS = 300
_ACTION_MANUAL_RESERVE_SECONDS = 10.0
_LOGGER = logging.getLogger(__name__)


def _aggregation_window(at: datetime) -> tuple[datetime, datetime]:
    seconds = math.floor(at.timestamp() / _AGGREGATION_WINDOW_SECONDS)
    start = datetime.fromtimestamp(seconds * _AGGREGATION_WINDOW_SECONDS, UTC)
    return start, start + timedelta(seconds=_AGGREGATION_WINDOW_SECONDS)


def _reserved_action_seconds(draft: RunDraft) -> float:
    """Budget frozen waits plus a bounded allowance for issuing/finishing actions."""
    parameters = draft.scenario_parameters

    def seconds(value: Any) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise CollectionError("frozen action schedule contains invalid seconds") from exc
        if isinstance(value, bool) or not math.isfinite(result) or result < 0:
            raise CollectionError("frozen action schedule requires finite nonnegative seconds")
        return result

    pre_delay = seconds(parameters.get("pre_action_delay_seconds", 0.0))
    if draft.family == "account":
        attempt_delay = seconds(parameters.get("attempt_delay_seconds", 0.0))
        attempts = (
            draft.quality_gates.min_account_failures + draft.quality_gates.min_account_successes
        )
        return max(
            60.0,
            pre_delay + max(5.0, attempt_delay) * attempts + 20.0 + _ACTION_MANUAL_RESERVE_SECONDS,
        )
    count = parameters.get("expected_action_count")
    raw_intervals = parameters.get("expected_intervals_seconds")
    if count is None and raw_intervals is None:
        # Custom, unscheduled drafts still face the strict actual receipt deadline.
        return max(60.0, pre_delay + _ACTION_MANUAL_RESERVE_SECONDS)
    try:
        count_value = seconds(count)
        interval_values = (
            [] if raw_intervals == "" else [seconds(item) for item in str(raw_intervals).split(",")]
        )
    except CollectionError as exc:
        raise CollectionError(f"invalid frozen action schedule: {exc}") from exc
    if (
        count_value < 1
        or not count_value.is_integer()
        or len(interval_values) != int(count_value) - 1
        or any(value <= 0 for value in interval_values)
    ):
        raise CollectionError("frozen action schedule count and positive intervals disagree")
    return pre_delay + sum(interval_values) + _ACTION_MANUAL_RESERVE_SECONDS


def _validate_action_window(
    receipt: dict[str, Any],
    draft: RunDraft,
    *,
    events: list[dict[str, Any]] | None = None,
) -> tuple[datetime, datetime]:
    """Require the action and every attributed source event to share a UTC bucket."""
    started = _parse_time(receipt.get("action_started_at"))
    if started is None:
        raise CollectionError("aggregation window is missing its action start")
    start, end = _aggregation_window(started)
    deadline = end - timedelta(seconds=draft.clock_preflight.maximum_skew_seconds)
    reservation = _reserved_action_seconds(draft)
    if (
        receipt.get("aggregation_window_start") != _iso(start)
        or receipt.get("aggregation_window_end") != _iso(end)
        or receipt.get("action_deadline") != _iso(deadline)
        or receipt.get("reserved_action_seconds") != reservation
        or started + timedelta(seconds=reservation) > deadline
    ):
        raise CollectionError("execution receipt has an invalid aggregation window contract")
    ended_value = receipt.get("action_ended_at")
    if ended_value is not None:
        ended = _parse_time(ended_value)
        if ended is None or not started < ended < deadline:
            raise CollectionError("action exceeded its guarded aggregation window deadline")
    for event in events or []:
        timestamp = _event_time(event)
        if timestamp is None or not start <= timestamp < end:
            raise CollectionError("attributed telemetry crosses the action aggregation window")
    return start, end


def begin_action(
    run_id: str,
    project_root: Path,
    *,
    now: datetime | None = None,
    wait_for_window: bool = False,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    evidence_dir = project_root / "evidence/scenario-runs" / run_id
    state_path = evidence_dir / ".collection_state.json"
    if not state_path.is_file():
        raise CollectionError(f"run was not started: {run_id}")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("status") != "STARTED" or state.get("execution_receipt") is not None:
        raise CollectionError("action can begin only once for a STARTED run")
    _verify_start_snapshot(evidence_dir, state, project_root)
    draft = RunDraft.model_validate(state["draft"])
    reservation = _reserved_action_seconds(draft)
    guard = draft.clock_preflight.maximum_skew_seconds
    if reservation > _AGGREGATION_WINDOW_SECONDS - guard * 2:
        raise CollectionError(
            "frozen action schedule cannot fit one guarded aggregation window; "
            "reduce the clock skew or choose a shorter approved timing contract"
        )
    if wait_for_window and now is not None:
        raise CollectionError("wait-for-window requires the live collector clock")
    action_started_at = _utc(now)
    collection_started_at = _parse_time(state.get("started_at"))
    if collection_started_at is None or action_started_at < collection_started_at:
        raise CollectionError("action start cannot precede collection start")
    while True:
        bucket_start, bucket_end = _aggregation_window(action_started_at)
        guarded_start = bucket_start + timedelta(seconds=guard)
        deadline = bucket_end - timedelta(seconds=guard)
        try:
            occupied = bucket_used(project_root, draft.host, bucket_start)
        except ValueError as exc:
            raise CollectionError(str(exc)) from exc
        if wait_for_window and action_started_at < guarded_start:
            ready_at = guarded_start
        elif state["source"].get("require_clean_bucket") and bucket_start < (
            _aggregation_window(collection_started_at)[1]
        ):
            if not wait_for_window:
                raise CollectionError(
                    "aggregation window contains pre-collection activity; wait for a clean bucket"
                )
            ready_at = _aggregation_window(collection_started_at)[1] + timedelta(seconds=guard)
        elif occupied:
            if not wait_for_window:
                raise CollectionError("aggregation window already used; wait for a new bucket")
            ready_at = bucket_end + timedelta(seconds=guard)
        elif action_started_at + timedelta(seconds=reservation) > deadline:
            if not wait_for_window:
                raise CollectionError(
                    "frozen action schedule exceeds the remaining aggregation window; "
                    "retry begin-action with --wait-for-window before executing actions"
                )
            ready_at = bucket_end + timedelta(seconds=guard)
        else:
            break
        delay = min(30.0, (ready_at - action_started_at).total_seconds())
        _LOGGER.info(
            "Waiting for aggregation window: earliest action start %s; reserved %.3fs",
            _iso(ready_at),
            reservation,
        )
        time.sleep(delay)
        action_started_at = _utc(None)
    # An operator may have aborted or quarantined the run while this call waited.
    refreshed = json.loads(state_path.read_text(encoding="utf-8"))
    if refreshed.get("status") != "STARTED" or refreshed.get("execution_receipt") is not None:
        raise CollectionError("run state changed while waiting for its aggregation window")
    _verify_start_snapshot(evidence_dir, refreshed, project_root)
    state = refreshed
    receipt = {
        "version": "execution-receipt-v1",
        "status": "STARTED",
        "run_id": run_id,
        "scenario_id": state["draft"]["scenario_id"],
        "operator": state["draft"]["operator"],
        "frozen_parameters_sha256": state["frozen_parameters_sha256"],
        "action_started_at": _iso(action_started_at),
        "action_ended_at": None,
        "aggregation_window_start": _iso(bucket_start),
        "aggregation_window_end": _iso(bucket_end),
        "action_deadline": _iso(deadline),
        "reserved_action_seconds": reservation,
    }
    _validate_action_window(receipt, draft)
    try:
        reserve_bucket(project_root, draft.host, bucket_start, run_id)
    except ValueError as exc:
        raise CollectionError(str(exc)) from exc
    state["execution_receipt"] = receipt
    _write_json(state_path, state)
    _write_json(evidence_dir / "execution_receipt.json", receipt)
    _append_log(evidence_dir, f"ACTION_STARTED run_id={run_id}")
    return receipt


def complete_action(
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
    receipt = state.get("execution_receipt")
    if state.get("status") != "STARTED" or not isinstance(receipt, dict):
        raise CollectionError("action was not started for this run")
    _verify_start_snapshot(evidence_dir, state, project_root)
    receipt_path = evidence_dir / "execution_receipt.json"
    try:
        receipt_snapshot = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid execution receipt: {exc}") from exc
    if receipt_snapshot != receipt:
        raise CollectionError("execution receipt does not match collection state")
    if receipt.get("status") != "STARTED":
        raise CollectionError("action can be completed only once")
    action_started_at = _parse_time(receipt.get("action_started_at"))
    action_ended_at = _utc(now)
    if action_started_at is None or action_ended_at <= action_started_at:
        raise CollectionError("action end must be later than action start")
    receipt["status"] = "COMPLETED"
    receipt["action_ended_at"] = _iso(action_ended_at)
    _validate_action_window(receipt, RunDraft.model_validate(state["draft"]))
    state["execution_receipt"] = receipt
    _write_json(state_path, state)
    _write_json(receipt_path, receipt)
    _append_log(evidence_dir, f"ACTION_COMPLETED run_id={run_id}")
    return receipt


def finalize_run(
    run_id: str,
    project_root: Path,
    *,
    now: datetime | None = None,
    wait_for_window: bool = False,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    evidence_dir = project_root / "evidence/scenario-runs" / run_id
    state_path = evidence_dir / ".collection_state.json"
    if not state_path.is_file():
        raise CollectionError(f"run was not started: {run_id}")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    final_dir = project_root / "data/raw" / run_id
    temporary_dir = final_dir.with_name(f".{run_id}.tmp")
    if state.get("status") == "FINALIZING":
        if final_dir.exists() and temporary_dir.exists():
            raise CollectionError(
                "finalization recovery found both staged and final output; quarantine the run"
            )
        if temporary_dir.is_dir():
            temporary_dir.replace(final_dir)
        if not final_dir.is_dir():
            raise CollectionError(
                "finalization recovery found neither staged nor final dataset output"
            )
        state["status"] = "FINALIZED"
        state["ended_at"] = state.get("pending_ended_at")
        state.pop("pending_ended_at", None)
        _write_json(state_path, state)
        _release_active_run(evidence_dir.parent, run_id)
        validate_run(run_id, project_root)
        return json.loads((evidence_dir / "collection_metadata.json").read_text(encoding="utf-8"))
    if state.get("status") != "STARTED":
        raise CollectionError(f"run is not in STARTED state: {run_id}")
    try:
        draft = RunDraft.model_validate(state["draft"])
        source = SourceConfig.model_validate(state["source"])
    except ValueError as exc:
        raise CollectionError(f"stored collection state is invalid: {exc}") from exc
    _verify_start_snapshot(evidence_dir, state, project_root)
    receipt = state.get("execution_receipt")
    if not isinstance(receipt, dict) or receipt.get("status") != "COMPLETED":
        raise CollectionError(
            "a completed collector-managed execution receipt is required before finalize"
        )
    receipt_path = evidence_dir / "execution_receipt.json"
    try:
        receipt_snapshot = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid execution receipt: {exc}") from exc
    if receipt_snapshot != receipt:
        raise CollectionError("execution receipt does not match immutable collection state")
    if receipt.get("frozen_parameters_sha256") != state.get("frozen_parameters_sha256"):
        raise CollectionError("execution receipt references the wrong frozen parameters")
    collection_started_at = _parse_time(state["started_at"])
    started_at = _parse_time(receipt.get("action_started_at"))
    ended_at = _parse_time(receipt.get("action_ended_at"))
    finalized_at = _utc(now)
    if (
        collection_started_at is None
        or started_at is None
        or ended_at is None
        or started_at < collection_started_at
        or ended_at <= started_at
        or finalized_at < ended_at
    ):
        raise CollectionError("execution receipt contains an invalid action window")
    _validate_action_window(receipt, draft)

    if source.require_online_parity:
        capture_deadline = _aggregation_window(started_at)[1] + timedelta(
            seconds=source.late_arrival_grace_seconds,
        )
        if wait_for_window and now is None:
            while finalized_at < capture_deadline:
                _LOGGER.info("Waiting for full capture until %s", _iso(capture_deadline))
                time.sleep(min(30.0, (capture_deadline - finalized_at).total_seconds()))
                finalized_at = _utc(None)
            if json.loads(state_path.read_text(encoding="utf-8")) != state:
                raise CollectionError("run state changed while waiting for full capture")
            _verify_start_snapshot(evidence_dir, state, project_root)
        if finalized_at < capture_deadline:
            raise CollectionError(
                "full-capture parity requires a closed bucket plus grace; "
                f"retry after {_iso(capture_deadline)}"
            )
    events = _read_appended_jsonl(state["archive_cursor"], evidence_dir / "archive_capture.jsonl")
    tolerance = timedelta(seconds=draft.clock_preflight.maximum_skew_seconds)
    window_start = started_at - tolerance
    window_end = ended_at + tolerance
    in_window = [
        event
        for event in events
        if (timestamp := _event_time(event)) is not None and window_start <= timestamp <= window_end
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
        scoped_archive_events = list(windows_events)
        evidence_sources = ["wazuh-archives"]
    else:
        features, windows_events, suricata_events, indicator = _derive_c2(
            in_window, draft, source, taxonomy
        )
        selected_suricata = {
            json.dumps(item, sort_keys=True, separators=(",", ":")) for item in suricata_events
        }
        suricata_wrappers = [
            event
            for event in in_window
            if str((event.get("agent") or {}).get("name")) == source.suricata_agent_name
            and (payload := _suricata_payload(event)) is not None
            and json.dumps(payload, sort_keys=True, separators=(",", ":")) in selected_suricata
        ]
        scoped_archive_events = list(windows_events) + suricata_wrappers
        scoped_archive_events.sort(
            key=lambda item: _event_time(item) or datetime.min.replace(tzinfo=UTC)
        )
        evidence_sources = ["wazuh-archives", "suricata-eve"]

    _validate_action_window(receipt, draft, events=scoped_archive_events)
    baseline = load_baseline(evidence_dir / "context-baseline.json")
    context = context_from_events(
        baseline, windows_events, at=ended_at, asset_id=draft.host,
    )
    features.update(context.features)
    incident_id = f"INC-{hashlib.sha256(run_id.encode()).hexdigest()[:16].upper()}"
    incident = IncidentRequest(
        context_status=context.status, context_revision=context.revision,
        review_reasons=context.review_reasons,
        observation_quality="COMPLETE" if context.status == "AVAILABLE" else "PARTIAL",
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
    if source.require_online_parity:
        _verify_full_capture_parity(events, incident, source, evidence_dir)
    manifest = ScenarioManifest(
        scenario_id=draft.scenario_id,
        run_id=draft.run_id,
        family=draft.family,
        label=draft.label,
        purpose=draft.purpose,
        cohort_id=draft.cohort_id,
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
        source_config_sha256=state["source_config_sha256"],
        taxonomy_sha256=state["taxonomy_sha256"],
        scenario_catalog_sha256=state["scenario_catalog_sha256"],
        feature_schema_sha256=state["feature_schema_sha256"],
        collection_contract_sha256=state["collection_contract_sha256"],
    )
    schema_path = evidence_dir / "feature-schema.json"
    if _sha256(schema_path) != state["feature_schema_sha256"]:
        raise CollectionError("feature schema changed after run start")
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
            raise CollectionError(f"declared execution log does not exist: {execution_log_source}")

    if final_dir.exists():
        raise CollectionError(f"final output already exists: {final_dir}")
    if temporary_dir.exists():
        if not temporary_dir.is_dir():
            raise CollectionError(f"stale temporary output is not a directory: {temporary_dir}")
        shutil.rmtree(temporary_dir)
    temporary_dir.mkdir(parents=True)
    _write_json(temporary_dir / "scenario_manifest.json", manifest.model_dump(mode="json"))
    _write_jsonl(temporary_dir / "incidents.jsonl", [incident.model_dump(mode="json")])

    _write_jsonl(evidence_dir / "wazuh_archives.jsonl", scoped_archive_events)
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
        "collection_started_at": _iso(collection_started_at),
        "started_at": _iso(started_at),
        "ended_at": _iso(ended_at),
        "finalized_at": _iso(finalized_at),
        "archive_events": len(scoped_archive_events),
        "attributed_windows_events": len(windows_events),
        "attributed_suricata_events": len(suricata_events),
        "execution_receipt_sha256": _sha256(receipt_path),
        "start_contract_sha256": state["start_contract_sha256"],
        "frozen_parameters_sha256": state["frozen_parameters_sha256"],
        "source_config_sha256": state["source_config_sha256"],
        "taxonomy_sha256": state["taxonomy_sha256"],
        "scenario_catalog_sha256": state["scenario_catalog_sha256"],
        "feature_schema_sha256": state["feature_schema_sha256"],
        "collection_contract_sha256": state["collection_contract_sha256"],
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
    state["status"] = "FINALIZING"
    state["pending_ended_at"] = _iso(ended_at)
    _write_json(state_path, state)
    temporary_dir.replace(final_dir)
    state["status"] = "FINALIZED"
    state["ended_at"] = _iso(ended_at)
    state.pop("pending_ended_at", None)
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
    _verify_start_snapshot(evidence_dir, state, project_root)
    contract_components = {
        "source_config_sha256": state.get("source_config_sha256"),
        "taxonomy_sha256": state.get("taxonomy_sha256"),
        "scenario_catalog_sha256": state.get("scenario_catalog_sha256"),
        "feature_schema_sha256": state.get("feature_schema_sha256"),
    }
    if _payload_sha256(contract_components) != state.get("collection_contract_sha256"):
        raise CollectionError("collection contract digest is inconsistent")
    receipt_path = evidence_dir / "execution_receipt.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid execution receipt: {exc}") from exc
    if (
        receipt != state.get("execution_receipt")
        or receipt.get("status") != "COMPLETED"
        or receipt.get("frozen_parameters_sha256") != state.get("frozen_parameters_sha256")
    ):
        raise CollectionError("execution receipt is incomplete or inconsistent")
    metadata_path = evidence_dir / "collection_metadata.json"
    if not metadata_path.is_file():
        raise CollectionError("missing collection_metadata.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if (
        metadata.get("execution_receipt_sha256") != _sha256(receipt_path)
        or metadata.get("start_contract_sha256") != state.get("start_contract_sha256")
        or metadata.get("frozen_parameters_sha256") != state.get("frozen_parameters_sha256")
    ):
        raise CollectionError("execution receipt metadata is inconsistent")
    markers = [
        json.loads(line)
        for line in (evidence_dir / "run_markers.jsonl").read_text(encoding="utf-8").splitlines()
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
    try:
        frozen_parameters = json.loads(
            (evidence_dir / "execution-parameters.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectionError(f"invalid frozen execution parameters: {exc}") from exc
    frozen_digest = _payload_sha256(frozen_parameters)
    draft = state.get("draft") if isinstance(state.get("draft"), dict) else {}
    if manifest.run_id != run_id or incident.family_hint != manifest.family:
        raise CollectionError("finalized run identity/family mismatch")
    if incident.asset_id != manifest.host:
        raise CollectionError("finalized run host mismatch")
    if any(
        getattr(manifest, name) != value
        for name, value in {
            **contract_components,
            "collection_contract_sha256": state["collection_contract_sha256"],
        }.items()
    ):
        raise CollectionError("manifest collection contract does not match run state")
    if (
        frozen_parameters.get("run_id") != manifest.run_id
        or frozen_parameters.get("purpose", "trainable") != manifest.purpose
        or frozen_parameters.get("cohort_id") != manifest.cohort_id
        or draft.get("purpose", "trainable") != manifest.purpose
        or draft.get("cohort_id") != manifest.cohort_id
        or frozen_parameters.get("scenario_id") != manifest.scenario_id
        or frozen_parameters.get("family") != manifest.family
        or frozen_parameters.get("label") != manifest.label
        or frozen_parameters.get("scenario_parameters") != manifest.scenario_parameters
        or frozen_digest != state.get("frozen_parameters_sha256")
        or draft.get("run_id") != manifest.run_id
        or draft.get("scenario_id") != manifest.scenario_id
        or draft.get("family") != manifest.family
        or draft.get("label") != manifest.label
        or draft.get("scenario_parameters") != manifest.scenario_parameters
    ):
        raise CollectionError("frozen execution parameters do not match the finalized manifest")
    receipt_start = _parse_time(receipt.get("action_started_at"))
    receipt_end = _parse_time(receipt.get("action_ended_at"))
    if (
        receipt.get("run_id") != manifest.run_id
        or receipt.get("scenario_id") != manifest.scenario_id
        or receipt.get("operator") != draft.get("operator")
        or receipt.get("frozen_parameters_sha256") != frozen_digest
        or receipt_start != manifest.start_time.astimezone(UTC)
        or receipt_end != manifest.end_time.astimezone(UTC)
    ):
        raise CollectionError("execution receipt identity/window is inconsistent")
    if incident.start_time < manifest.start_time or incident.end_time > manifest.end_time:
        raise CollectionError("incident lies outside scenario window")
    if manifest.family == "c2":
        suricata_path = evidence_dir / "suricata_eve.jsonl"
        if not suricata_path.is_file() or not suricata_path.read_text(encoding="utf-8").strip():
            raise CollectionError("C2 run is missing attributable Suricata evidence")
    verify_feature_provenance(evidence_dir, manifest, incident, state)
    return {"status": "VALID", "run_id": run_id, "family": manifest.family, "label": manifest.label}


def run_status(run_id: str, project_root: Path) -> dict[str, Any]:
    state_path = (
        project_root.resolve() / "evidence/scenario-runs" / run_id / ".collection_state.json"
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
    if state.get("status") in {"FINALIZING", "FINALIZED"}:
        raise CollectionError(
            "a finalizing or finalized run cannot be aborted; recover finalize or quarantine"
        )
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


def _transport_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None

