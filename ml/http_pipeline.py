"""Opt-in HTTP evidence profile; retain all44 legacy/stream observations."""

import hashlib
import json
import os
from pathlib import Path

import yaml

from api.app.contracts import (
    HttpFeatureBatchResponse,
    HttpFeaturePipelineResponse,
    HttpIncidentRequest,
)
from ml.feature_pipeline import derive_c2_network_evidence
from ml.http_features import HTTP_FEATURES, HTTP_SCHEMA_VERSION, derive_http_features
from ml.stream_pipeline import STREAM_FEATURE_ORDER, aggregate_stream_alerts
from ml.telemetry import event_time, windows_fields

HTTP_FEATURE_ORDER = (*STREAM_FEATURE_ORDER, *HTTP_FEATURES)
ROOT = Path(__file__).resolve().parents[1]
SOURCE_SEMANTIC_FIELDS = (
    "windows_agent_name",
    "suricata_agent_name",
    "windows_source_ips",
    "correlation_window_seconds",
    "late_arrival_grace_seconds",
    "require_clean_bucket",
    "require_flow_counters",
    "require_online_parity",
    "feature_scope",
    "taxonomy_path",
)


def _collection_config() -> dict:
    # This opt-in profile has its own pinned source. Do not inherit the legacy
    # default or cache a mutable file across calls to a durable state store.
    from ml.scenario_collection import SourceConfig

    return SourceConfig.model_validate(
        yaml.safe_load(
            (ROOT / "config/supplemental-sources.yaml").read_text(encoding="utf-8"),
        )
    ).model_dump()


def http_collection_grace_seconds() -> int:
    value = _collection_config().get("late_arrival_grace_seconds", 60)
    if type(value) is not int or not 0 <= value <= 600:
        raise ValueError("HTTP collection grace must be an integer in [0,600]")
    return value


def http_config_fingerprint() -> str:
    config = _collection_config()
    payload = {name: config.get(name) for name in SOURCE_SEMANTIC_FIELDS}
    # A cache must not combine evidence derived with different taxonomy or
    # enrolled context snapshots, including an environment-selected baseline.
    for name in ("taxonomy_path", "context_baseline_path"):
        path = os.getenv("CONTEXT_BASELINE_PATH") if name == "context_baseline_path" else None
        path = path or config.get(name)
        selected = ROOT / path if path else None
        payload[name + "_sha256"] = (
            hashlib.sha256(selected.read_bytes()).hexdigest()
            if selected is not None and selected.is_file()
            else None
        )
        if name == "context_baseline_path":
            payload[name] = str(selected) if selected else None
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def require_http_source_semantics(source: dict, root: Path) -> None:
    """A selected offline collector must match the source used by the HTTP API."""
    from ml.scenario_collection import SourceConfig

    expected = SourceConfig.model_validate(
        yaml.safe_load(
            (root / "config/supplemental-sources.yaml").read_text(encoding="utf-8"),
        )
    ).model_dump()
    if any(source.get(name) != expected[name] for name in SOURCE_SEMANTIC_FIELDS):
        raise ValueError("supplemental source semantics differ from the pinned HTTP API source")


def aggregate_http_alerts(alerts, **kwargs) -> HttpFeatureBatchResponse:
    """Share proof and clocks; optional cached context never invents parent evidence."""
    config = kwargs.get("source_config")
    if config is None:
        config = _collection_config()
    kwargs["source_config"] = config
    if kwargs.get("taxonomy") is None:
        kwargs["taxonomy"] = yaml.safe_load(
            (
                ROOT / config.get("taxonomy_path", "config/suspicious-process-taxonomy.yaml")
            ).read_text(encoding="utf-8"),
        )
    stream = aggregate_stream_alerts(alerts, **kwargs)
    by_id = {a.id: a for a in alerts}
    result = []
    for item in stream.incidents:
        incident = item.incident
        extra = dict.fromkeys(HTTP_FEATURES, 0.0)
        reasons = list(incident.review_reasons)
        missing = list(item.missing_required_features)
        if incident.family_hint == "c2":
            members = [
                by_id[r.removeprefix("wazuh-alert:")]
                for r in incident.raw_refs
                if r.startswith("wazuh-alert:")
            ]
            proof = derive_c2_network_evidence(
                members,
                config,
                kwargs.get("taxonomy"),
                [
                    a
                    for a in [*(kwargs.get("process_context") or []), *alerts]
                    if windows_fields(a.model_dump())[0] in {"1", "5"}
                ],
            )
            start = incident.start_time.replace(second=0, microsecond=0)
            from datetime import timedelta

            start -= timedelta(minutes=start.minute % kwargs.get("window_minutes", 5))
            native = [
                a
                for a in alerts
                if a.agent.name == config["windows_agent_name"]
                and windows_fields(a.model_dump())[0] in {"1", "5"}
                and start
                <= event_time(a.model_dump())
                < start
                + timedelta(
                    minutes=kwargs.get("window_minutes", 5),
                )
            ]
            extra = derive_http_features(
                [*members, *native],
                proof,
                config,
                window_minutes=kwargs.get("window_minutes", 5),
            )
            for name in ("http_evidence_available", "flow_evidence_available"):
                if extra[name] != 1:
                    reasons.append(f"http-profile:{name}:unknown")
                    missing.append(name)
        payload = incident.model_dump()
        features = {**incident.features, **extra}
        payload.update(
            feature_schema_version=HTTP_SCHEMA_VERSION,
            features=features,
            review_reasons=sorted(set(reasons)),
            observation_quality="PARTIAL" if missing else incident.observation_quality,
        )
        values = item.model_dump(exclude={"incident"})
        values.update(
            feature_schema_version=HTTP_SCHEMA_VERSION,
            feature_order=list(HTTP_FEATURE_ORDER),
            ordered_vector=[features[n] for n in HTTP_FEATURE_ORDER],
            missing_required_features=sorted(set(missing)),
            quality_status=payload["observation_quality"],
            evidence_quality=(
                min(item.evidence_quality, 0.5) if missing else item.evidence_quality
            ),
            evidence_quality_reasons=(
                item.evidence_quality_reasons + sorted(set(reasons) - set(incident.review_reasons))
            ),
            structural_zero_features=(
                item.structural_zero_features + list(HTTP_FEATURES)
                if incident.family_hint != "c2"
                else item.structural_zero_features
            ),
            incident=HttpIncidentRequest(**payload),
        )
        result.append(HttpFeaturePipelineResponse(**values))
    return HttpFeatureBatchResponse(
        **{
            **stream.model_dump(exclude={"incidents"}),
            "feature_schema_version": HTTP_SCHEMA_VERSION,
            "incidents": result,
        }
    )
