from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

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
    "purpose",
    "cohort_id",
}


class ScenarioManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    family: str
    label: str
    purpose: Literal["trainable", "challenge", "pilot"] = "trainable"
    cohort_id: str | None = Field(default=None, min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=128)
    start_time: datetime
    end_time: datetime
    expected_behavior: str = Field(min_length=1)
    collection_seed: int | None = Field(default=None, ge=0, le=2**32 - 1)
    scenario_parameters: dict[str, int | float | str | bool] = Field(default_factory=dict)
    provenance_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    taxonomy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feature_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collection_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

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
    purpose: str = "trainable"
    cohort_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "family": self.family,
            "label": self.label,
            "features": self.features,
            "source_file": self.source_file,
            "purpose": self.purpose,
            "cohort_id": self.cohort_id,
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


def discover_records(
    raw_dir: Path, manifest_name: str, records_name: str,
    *, include_purposes: tuple[str, ...] = ("trainable",),
) -> list[DatasetRecord]:
    if not include_purposes or set(include_purposes) - {"trainable", "challenge", "pilot"}:
        raise DatasetError("include_purposes must select trainable, challenge or pilot")
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
                    purpose=manifest.purpose,
                    cohort_id=manifest.cohort_id,
                )
            )
            run_count += 1
        if run_count == 0:
            raise DatasetError(f"no incident records found for run {manifest.run_id}")
    # Parse every manifest/record before filtering so excluded corrupt runs cannot hide.
    return [record for record in records if record.purpose in include_purposes]


def assign_grouped_folds(
    records: list[DatasetRecord],
    *,
    number_of_folds: int,
    random_seed: int,
    group_key: str = "run_id",
) -> dict[str, int]:
    if group_key not in {"run_id", "scenario_id", "cohort_id"}:
        raise DatasetError("group_key must be run_id, scenario_id or cohort_id")
    if number_of_folds < 2:
        raise DatasetError("number_of_folds must be at least two")
    if any(record.purpose != "trainable" for record in records):
        raise DatasetError("only trainable records may be assigned training folds")

    run_rows: dict[str, DatasetRecord] = {}
    for record in records:
        existing = run_rows.setdefault(record.run_id, record)
        if (existing.family, existing.label, existing.scenario_id, existing.cohort_id) != (
            record.family,
            record.label,
            record.scenario_id,
            record.cohort_id,
        ):
            raise DatasetError(
                f"run {record.run_id} contains mixed family, labels or scenarios"
            )

    if group_key == "cohort_id":
        return _assign_cohort_folds(run_rows, number_of_folds, random_seed)

    group_rows: dict[str, DatasetRecord] = {}
    for record in run_rows.values():
        group_id = getattr(record, group_key)
        existing = group_rows.setdefault(group_id, record)
        if (existing.family, existing.label) != (record.family, record.label):
            raise DatasetError(
                f"{group_key} group {group_id} contains mixed family or labels"
            )

    rows = sorted(group_rows.values(), key=lambda row: getattr(row, group_key))
    strata = [f"{row.family}:{row.label}" for row in rows]
    groups = [getattr(row, group_key) for row in rows]
    counts: dict[str, int] = {}
    for stratum in strata:
        counts[stratum] = counts.get(stratum, 0) + 1
    sparse = {key: value for key, value in counts.items() if value < number_of_folds}
    if sparse:
        raise DatasetError(
            "grouped stratification requires at least "
            f"{number_of_folds} independent {group_key} groups per family/label; "
            f"found {sparse}"
        )

    if group_key == "scenario_id":
        fold_by_group: dict[str, int] = {}
        groups_by_stratum: dict[str, list[str]] = {}
        for row in rows:
            stratum = f"{row.family}:{row.label}"
            groups_by_stratum.setdefault(stratum, []).append(row.scenario_id)
        for stratum, stratum_groups in sorted(groups_by_stratum.items()):
            seed_bytes = hashlib.sha256(f"{random_seed}:{stratum}".encode()).digest()
            generator = random.Random(int.from_bytes(seed_bytes[:8], "big"))
            ordered = sorted(stratum_groups)
            generator.shuffle(ordered)
            for index, group_id in enumerate(ordered):
                fold_by_group[group_id] = index % number_of_folds
        return {
            run_id: fold_by_group[record.scenario_id]
            for run_id, record in run_rows.items()
        }

    splitter = StratifiedGroupKFold(
        n_splits=number_of_folds,
        shuffle=True,
        random_state=random_seed,
    )
    fold_by_group: dict[str, int] = {}
    dummy_x = [[0.0]] * len(rows)
    for fold, (_, held_out) in enumerate(splitter.split(dummy_x, strata, groups)):
        for index in held_out:
            fold_by_group[rows[index].run_id] = fold
    return {
        run_id: fold_by_group[record.run_id]
        for run_id, record in run_rows.items()
    }


def _assign_cohort_folds(
    run_rows: dict[str, DatasetRecord], number_of_folds: int, random_seed: int,
) -> dict[str, int]:
    """Place matched behavior groups together even when they contain both labels.

    Balance by the strata represented in each cohort, rather than treating a
    mixed-label cohort as its first/last row's label. Refuse an unsupported
    collection design instead of silently returning an empty-label partition.
    """
    members: dict[str, set[tuple[str, int]]] = {}
    scenario_cohorts: dict[str, str] = {}
    for row in run_rows.values():
        if not row.cohort_id or not row.cohort_id.strip():
            raise DatasetError("cohort_id split requires an explicit cohort for every run")
        previous = scenario_cohorts.setdefault(row.scenario_id, row.cohort_id)
        if previous != row.cohort_id:
            raise DatasetError(
                f"scenario {row.scenario_id} appears in multiple cohorts; preserve its boundary"
            )
        members.setdefault(row.cohort_id, set()).add((row.family, row.label))
    strata = {stratum for values in members.values() for stratum in values}
    sparse = {
        stratum: sum(stratum in values for values in members.values())
        for stratum in strata
        if sum(stratum in values for values in members.values()) < number_of_folds
    }
    if not strata or sparse:
        raise DatasetError(
            f"cohort split requires {number_of_folds} independent cohorts per stratum; {sparse}"
        )
    by_pattern: dict[tuple[tuple[str, int], ...], list[str]] = {}
    for group, values in members.items():
        by_pattern.setdefault(tuple(sorted(values)), []).append(group)
    fold_by_group: dict[str, int] = {}
    loads = [0] * number_of_folds
    for pattern, groups in sorted(by_pattern.items()):
        digest = hashlib.sha256(f"{random_seed}:{pattern}".encode()).digest()
        rng = random.Random(int.from_bytes(digest[:8], "big"))
        ordered = sorted(groups)
        rng.shuffle(ordered)
        offset = min(range(number_of_folds), key=lambda fold: (loads[fold], fold))
        for index, group in enumerate(ordered):
            fold = (index + offset) % number_of_folds
            fold_by_group[group] = fold
            loads[fold] += 1
    for fold in range(number_of_folds):
        present = {
            value for group, values in members.items() if fold_by_group[group] == fold
            for value in values
        }
        if present != strata:
            raise DatasetError(
                "cohort design cannot provide every family/label in every fold; "
                "collect balanced matched cohorts before building"
            )
    return {run_id: fold_by_group[row.cohort_id] for run_id, row in run_rows.items()}


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
