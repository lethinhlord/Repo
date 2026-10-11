from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sklearn.model_selection import StratifiedGroupKFold

from api.app.contracts import IncidentRequest

FAMILIES = ("account", "c2")
LABELS = ("benign", "malicious")
FORBIDDEN_FEATURE_NAMES = {
    "asset_criticality",
    "asset_score",
    "ground_truth",
    "label",
    "scenario_label",
    "threat_intelligence",
    "ti_score",
}


class ScenarioManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    family: str
    label: str
    host: str = Field(min_length=1, max_length=128)
    start_time: datetime
    end_time: datetime
    expected_behavior: str = Field(min_length=1)

    @field_validator("family")
    @classmethod
    def validate_family(cls, value: str) -> str:
        if value not in FAMILIES:
            raise ValueError(f"family must be one of {FAMILIES}")
        return value

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str) -> str:
        if value not in LABELS:
            raise ValueError(f"label must be one of {LABELS}")
        return value

    @field_validator("start_time", "end_time")
    @classmethod
    def validate_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scenario timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_time_window(self) -> ScenarioManifest:
        if self.end_time < self.start_time:
            raise ValueError("scenario end_time must not be earlier than start_time")
        return self


class DatasetError(ValueError):
    pass


@dataclass(frozen=True)
class DatasetRecord:
    incident_id: str
    scenario_id: str
    run_id: str
    family: str
    label: int
    features: dict[str, float]
    source_file: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "family": self.family,
            "label": self.label,
            "features": self.features,
            "source_file": self.source_file,
        }


def load_config(path: Path) -> dict[str, Any]:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise DatasetError("training configuration must be a mapping")
    return config


def load_feature_schema(path: Path) -> dict[str, Any]:
    schema = json.loads(path.read_text(encoding="utf-8"))
    required = schema.get("required")
    family_features = schema.get("x-family-features")
    if not isinstance(required, list) or not isinstance(family_features, dict):
        raise DatasetError("feature schema is missing required training metadata")
    return schema


def discover_records(raw_dir: Path, manifest_name: str, records_name: str) -> list[DatasetRecord]:
    records: list[DatasetRecord] = []
    if not raw_dir.exists():
        raise DatasetError(f"raw dataset directory does not exist: {raw_dir}")
    manifest_paths = sorted(raw_dir.glob(f"*/{manifest_name}"))
    if not manifest_paths:
        raise DatasetError(f"no {manifest_name} files found below {raw_dir}")

    seen_run_ids: set[str] = set()
    seen_incident_ids: set[str] = set()
    for manifest_path in manifest_paths:
        manifest = ScenarioManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.parent.name != manifest.run_id:
            raise DatasetError(
                f"run directory {manifest_path.parent.name} does not match "
                f"manifest run_id {manifest.run_id}"
            )
        if manifest.run_id in seen_run_ids:
            raise DatasetError(f"duplicate run_id: {manifest.run_id}")
        seen_run_ids.add(manifest.run_id)
        record_path = manifest_path.with_name(records_name)
        if not record_path.exists():
            raise DatasetError(f"missing records file for {manifest.run_id}: {record_path}")
        run_count = 0
        for line_number, line in enumerate(record_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"invalid JSON at {record_path}:{line_number}: {exc}") from exc
            incident_payload = payload.get("incident", payload)
            try:
                incident = IncidentRequest.model_validate(incident_payload)
            except ValueError as exc:
                raise DatasetError(
                    f"invalid incident at {record_path}:{line_number}: {exc}"
                ) from exc
            incident_id = incident.incident_id
            if incident_id in seen_incident_ids:
                raise DatasetError(f"duplicate incident_id: {incident_id}")
            seen_incident_ids.add(incident_id)
            if incident.family_hint != manifest.family:
                raise DatasetError(
                    f"family mismatch for {incident_id}: manifest={manifest.family}, "
                    f"record={incident.family_hint}"
                )
            if incident.asset_id != manifest.host:
                raise DatasetError(
                    f"host mismatch for {incident_id}: manifest={manifest.host}, "
                    f"record={incident.asset_id}"
                )
            if (
                incident.start_time < manifest.start_time
                or incident.end_time > manifest.end_time
            ):
                raise DatasetError(
                    f"incident {incident_id} is outside the declared scenario window"
                )
            features = incident.features
            forbidden = sorted(set(features).intersection(FORBIDDEN_FEATURE_NAMES))
            if forbidden:
                raise DatasetError(f"label/context leakage in {incident_id}: {forbidden}")
            try:
                numeric_features = {key: float(value) for key, value in features.items()}
            except (TypeError, ValueError) as exc:
                raise DatasetError(f"non-numeric feature in {incident_id}") from exc
            records.append(
                DatasetRecord(
                    incident_id=incident_id,
                    scenario_id=manifest.scenario_id,
                    run_id=manifest.run_id,
                    family=manifest.family,
                    label=int(manifest.label == "malicious"),
                    features=numeric_features,
                    source_file=record_path.as_posix(),
                )
            )
            run_count += 1
        if run_count == 0:
            raise DatasetError(f"no incident records found for run {manifest.run_id}")
    return records


def assign_grouped_folds(
    records: list[DatasetRecord], *, number_of_folds: int, random_seed: int
) -> dict[str, int]:
    group_rows: dict[str, DatasetRecord] = {}
    for record in records:
        existing = group_rows.setdefault(record.run_id, record)
        if (existing.family, existing.label) != (record.family, record.label):
            raise DatasetError(f"run {record.run_id} contains mixed family or labels")
    rows = sorted(group_rows.values(), key=lambda row: row.run_id)
    strata = [f"{row.family}:{row.label}" for row in rows]
    groups = [row.run_id for row in rows]
    counts: dict[str, int] = {}
    for stratum in strata:
        counts[stratum] = counts.get(stratum, 0) + 1
    sparse = {key: value for key, value in counts.items() if value < number_of_folds}
    if sparse:
        raise DatasetError(
            "grouped stratification requires at least "
            f"{number_of_folds} independent runs per family/label; found {sparse}"
        )

    splitter = StratifiedGroupKFold(
        n_splits=number_of_folds,
        shuffle=True,
        random_state=random_seed,
    )
    fold_by_run: dict[str, int] = {}
    dummy_x = [[0.0]] * len(rows)
    for fold, (_, held_out) in enumerate(splitter.split(dummy_x, strata, groups)):
        for index in held_out:
            fold_by_run[rows[index].run_id] = fold
    return fold_by_run


def dataset_hash(records: Iterable[DatasetRecord]) -> str:
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda row: (row.run_id, row.incident_id)):
        canonical = json.dumps(record.as_dict(), sort_keys=True, separators=(",", ":"))
        digest.update(canonical.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def validate_feature_contract(records: list[DatasetRecord], schema: dict[str, Any]) -> None:
    by_family = schema["x-family-features"]
    for record in records:
        expected = set(by_family[record.family])
        actual = set(record.features)
        missing = sorted(expected - actual)
        if missing:
            raise DatasetError(f"{record.incident_id} is missing family features: {missing}")
        unknown = sorted(actual - set(schema["required"]))
        if unknown:
            raise DatasetError(f"{record.incident_id} has unknown features: {unknown}")
        for name, value in record.features.items():
            rules = schema["properties"][name]
            if value < rules["minimum"] or value > rules["maximum"]:
                raise DatasetError(
                    f"{record.incident_id} feature {name}={value} is outside "
                    f"[{rules['minimum']}, {rules['maximum']}]"
                )


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")
