from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Any

import yaml

from api.app.contracts import (
    FeatureBatchResponse,
    FeaturePipelineResponse,
    IncidentRequest,
    WazuhAlert,
)
from ml.behavior_features import (
    ACCOUNT_FEATURES,
    C2_FEATURES,
    FEATURE_ORDER,
    AccountObservation,
    NetworkObservation,
    SuricataObservation,
    derive_account_features,
    derive_c2_features,
    empty_feature_vector,
)
from ml.context import BaselineSnapshot, context_from_events, load_baseline
from ml.telemetry import (
    account_source,
    account_user,
    basename,
    event_time,
    flow_counter_issues,
    is_interactive_logon,
    linked_flow,
    network_is_outbound,
    normalize_ip,
    process_guid,
    suricata_correlates,
    suricata_observations,
    suricata_payload,
    taxonomy_match,
    windows_fields,
)

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _collection_config() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "config/collection-sources.yaml").read_text(encoding="utf-8"))


def collection_grace_seconds() -> int:
    value = _collection_config().get("late_arrival_grace_seconds", 60)
    if type(value) is not int or not 0 <= value <= 600:
        raise ValueError("collection grace must be an integer in [0,600]")
    return value


def _collection_sources(document: dict[str, Any] | None = None) -> tuple[str, str]:
    document = _collection_config() if document is None else document
    return str(document["windows_agent_name"]), str(document["suricata_agent_name"])


@lru_cache(maxsize=1)
def _process_taxonomy() -> dict[str, Any]:
    return yaml.safe_load(
        (ROOT / str(_collection_config()["taxonomy_path"])).read_text(encoding="utf-8")
    )


def _is_suspicious_process(eventdata: dict[str, Any]) -> bool:
    return taxonomy_match(eventdata, _process_taxonomy())


def _windows_fields(alert: WazuhAlert) -> tuple[str, dict[str, Any]]:
    event_id, _, eventdata = windows_fields(alert.model_dump(mode="json"))
    return event_id, eventdata


def _suricata_payload(alert: WazuhAlert) -> dict[str, Any] | None:
    return suricata_payload(alert.model_dump(mode="json"))


def alert_event_time(alert: WazuhAlert) -> datetime:
    timestamp = event_time(alert.model_dump(mode="json"))
    if timestamp is None:
        raise ValueError(f"raw event {alert.id} has no valid original event timestamp")
    return timestamp


def window_start(alert: WazuhAlert, *, window_minutes: int = 5) -> datetime:
    if not 1 <= window_minutes <= 5:
        raise ValueError("window_minutes must be between 1 and 5")
    seconds = window_minutes * 60
    bucket = int(alert_event_time(alert).timestamp()) // seconds
    return datetime.fromtimestamp(bucket * seconds, UTC)


def _family(alert: WazuhAlert) -> str:
    event_id, _ = _windows_fields(alert)
    if event_id in {"4624", "4625"}:
        return "account"
    if event_id in {"1", "3", "22"} or _suricata_payload(alert) is not None:
        return "c2"
    decoder = alert.decoder.name.strip().lower()
    if decoder in {"suricata", "sysmon-c2"} or any(
        (value or 0) > 0
        for value in (
            alert.data.suspicious_process,
            alert.data.periodicity_score,
            alert.data.suricata_alert_count,
            alert.data.outbound_connection_count,
            alert.data.destination_port_count,
        )
    ):
        return "c2"
    if decoder in {"sshd", "pam", "windows_eventchannel"} or any(
        (value or 0) > 0 for value in (alert.data.failed_login_count, alert.data.success_after_fail)
    ):
        return "account"
    return "unknown"


def _asset_id(alert: WazuhAlert, config: dict[str, Any] | None = None) -> str:
    windows_agent, suricata_agent = _collection_sources(config)
    return windows_agent if alert.agent.name == suricata_agent else alert.agent.name.strip()


def _account_name(alert: WazuhAlert) -> str:
    _, eventdata = _windows_fields(alert)
    return account_user(eventdata) or str(alert.data.dstuser or "unknown-user").strip().casefold()


def _account_source(alert: WazuhAlert) -> str:
    _, eventdata = _windows_fields(alert)
    return account_source(eventdata)


def _aggregation_key(
    alert: WazuhAlert, config: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    family = _family(alert)
    discriminator = _account_source(alert) if family == "account" else "behavior-window"
    if family == "unknown":
        discriminator = alert.id
    return (_asset_id(alert, config).casefold(), family, discriminator)


def _legacy_features(alert: WazuhAlert) -> tuple[dict[str, float], list[str]]:
    features = empty_feature_vector()
    observed = {
        "failed_login_count": alert.data.failed_login_count,
        "success_after_fail": alert.data.success_after_fail,
        "suspicious_process": alert.data.suspicious_process,
        "periodicity_score": alert.data.periodicity_score,
        "suricata_alert_count": alert.data.suricata_alert_count,
        "outbound_connection_count": alert.data.outbound_connection_count,
        "destination_port_count": alert.data.destination_port_count,
    }
    for name, value in observed.items():
        if value is not None:
            features[name] = float(value)
    family = _family(alert)
    applicable = ACCOUNT_FEATURES if family == "account" else C2_FEATURES
    missing = [name for name in applicable if name not in observed or observed[name] is None]
    return features, missing


def _derive_raw_group(
    alerts: list[WazuhAlert], family: str,
    config: dict[str, Any] | None = None, taxonomy: dict[str, Any] | None = None,
) -> tuple[dict[str, float], list[str], list[str], str | None, list[WazuhAlert]]:
    config = _collection_config() if config is None else config
    if family == "account":
        observations: list[AccountObservation] = []
        attributed = []
        for alert in alerts:
            event_id, eventdata = _windows_fields(alert)
            if (
                event_id not in {"4624", "4625"}
                or not account_user(eventdata)
                or not is_interactive_logon(eventdata)
            ):
                continue
            attributed.append(alert)
            observations.append(
                AccountObservation(
                    timestamp=alert_event_time(alert),
                    account=_account_name(alert),
                    source=_account_source(alert),
                    logon_type=str(
                        eventdata.get("logonType", eventdata.get("LogonType", "unknown"))
                    ),
                    success=event_id == "4624",
                )
            )
        if not observations:
            features, missing = _legacy_features(alerts[0])
            return features, missing, list(C2_FEATURES), alerts[0].data.srcip, []
        features = derive_account_features(observations)
        return (
            features,
            [],
            list(C2_FEATURES),
            next((item.source for item in observations if item.source != "local-console"), None),
            attributed,
        )

    if family == "c2":
        network: list[NetworkObservation] = []
        suricata: list[SuricataObservation] = []
        suspicious = False
        indicator: str | None = None
        attributed: list[WazuhAlert] = []
        processes: dict[str, tuple[dict[str, Any], datetime, WazuhAlert]] = {}
        windows_agent, sensor_agent = _collection_sources(config)
        configured_sources = {
            normalize_ip(value) for value in config.get("windows_source_ips", [])
        }
        for alert in alerts:
            if alert.agent.name != windows_agent:
                continue
            event_id, eventdata = _windows_fields(alert)
            guid = process_guid(eventdata)
            if event_id == "1" and guid and basename(eventdata.get("image")):
                processes[guid] = (eventdata, alert_event_time(alert), alert)

        observed_sources: set[str] = set()
        used_processes: set[str] = set()
        for alert in alerts:
            if alert.agent.name != windows_agent:
                continue
            event_id, eventdata = _windows_fields(alert)
            if event_id not in {"3", "22"}:
                continue
            guid = process_guid(eventdata)
            if guid not in processes:
                continue
            process, created_at, _ = processes[guid]
            timestamp = alert_event_time(alert)
            if timestamp < created_at or basename(eventdata.get("image")) != basename(
                process.get("image")
            ):
                continue
            if event_id == "3":
                source = normalize_ip(eventdata.get("sourceIp"))
                if not network_is_outbound(eventdata) or (
                    configured_sources and source not in configured_sources
                ):
                    continue
                destination = normalize_ip(eventdata.get("destinationIp"))
                try:
                    port = int(eventdata.get("destinationPort"))
                except (TypeError, ValueError):
                    continue
                if not destination or not 0 < port <= 65535:
                    continue
                network.append(NetworkObservation(timestamp, destination, port))
                observed_sources.add(source)
                indicator = indicator or destination
            else:
                query = str(eventdata.get("queryName", "")).strip(".").casefold()
                if not query:
                    continue
                network.append(NetworkObservation(timestamp, query, 53, query))
                indicator = indicator or query
            used_processes.add(guid)
            attributed.append(alert)
        for guid in sorted(used_processes):
            process, _, alert = processes[guid]
            attributed.append(alert)
            suspicious = suspicious or taxonomy_match(
                process, _process_taxonomy() if taxonomy is None else taxonomy,
            )

        sources = configured_sources or observed_sources
        seen_eve: set[str] = set()
        eve_payloads: list[dict[str, Any]] = []
        maximum_delta = float(config.get("correlation_window_seconds", 10.0))
        references = []
        for alert in alerts:
            if alert.agent.name != sensor_agent:
                continue
            payload = _suricata_payload(alert)
            if payload is not None and suricata_correlates(
                payload, alert_event_time(alert), network, maximum_delta, source_ips=sources,
            ):
                references.append((payload, alert_event_time(alert)))
        for alert in alerts:
            if alert.agent.name != sensor_agent:
                continue
            payload = _suricata_payload(alert)
            if (
                payload is None
                or not sources
                or not (linked_flow(payload, references, maximum_delta) or suricata_correlates(
                    payload, alert_event_time(alert), network,
                    maximum_delta,
                    source_ips=sources,
                ))
            ):
                continue
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if canonical in seen_eve:
                continue
            seen_eve.add(canonical)
            attributed.append(alert)
            eve_payloads.append(payload)
        suricata = suricata_observations(eve_payloads)
        has_raw = any(
            _windows_fields(alert)[0] in {"1", "3", "22"} or _suricata_payload(alert) is not None
            for alert in alerts
        )
        if not has_raw:
            features, missing = _legacy_features(alerts[0])
            return (
                features,
                missing,
                list(ACCOUNT_FEATURES),
                (alerts[0].data.destination_ip or alerts[0].data.destination_domain),
                [],
            )
        features = derive_c2_features(network, suricata, suspicious_process=suspicious)
        missing = []
        if not network:
            missing.extend(
                [
                    "periodicity_score",
                    "outbound_connection_count",
                    "unique_destination_count",
                ]
            )
        if not suricata:
            missing.extend(
                [
                    "suricata_alert_count",
                    "suricata_severity_score",
                    "flow_total_bytes_log1p",
                ]
            )
        if not used_processes:
            missing.append("suspicious_process")
        return features, sorted(set(missing)), list(ACCOUNT_FEATURES), indicator, attributed

    features, _ = _legacy_features(alerts[0])
    return features, list(FEATURE_ORDER), [], None, []


def _build_response(
    alerts: list[WazuhAlert], *, window_minutes: int = 5,
    baseline: BaselineSnapshot | None = None,
    source_config: dict[str, Any] | None = None, taxonomy: dict[str, Any] | None = None,
) -> FeaturePipelineResponse:
    config = _collection_config() if source_config is None else source_config
    first = alerts[0]
    family = _family(first)
    features, missing, structural, indicator, attributed = _derive_raw_group(
        alerts, family, config, taxonomy,
    )
    ordered_alerts = sorted(alerts, key=lambda item: (alert_event_time(item), item.id))
    context = context_from_events(
        baseline, [item.model_dump(mode="json") for item in attributed],
        at=alert_event_time(ordered_alerts[-1]), asset_id=_asset_id(first, config),
    )
    features.update(context.features)
    if context.status != "AVAILABLE":
        if family == "account":
            missing.append("new_source_for_user")
        elif family == "c2":
            missing.append("new_destination")
    flow_reasons = []
    if family == "c2" and config.get("require_flow_counters"):
        start = window_start(first, window_minutes=window_minutes)
        from datetime import timedelta
        flow_reasons = flow_counter_issues(
            [payload for item in attributed if (payload := _suricata_payload(item)) is not None],
            window_start=start, window_end=start + timedelta(minutes=window_minutes),
        )
        if flow_reasons:
            missing.append("flow_total_bytes_log1p")
    refs = [f"wazuh-alert:{alert.id}" for alert in ordered_alerts]
    location_names = [
        PurePath(alert.location.replace("\\", "/")).name.lower()
        for alert in ordered_alerts
        if PurePath(alert.location.replace("\\", "/")).name
    ]
    refs.extend(f"source-log:{name}" for name in dict.fromkeys(location_names))
    bucket = int(window_start(first, window_minutes=window_minutes).timestamp())
    digest = (
        hashlib.sha256(
            "|".join([*_aggregation_key(first, config), str(window_minutes), str(bucket)]).encode()
        )
        .hexdigest()[:12]
        .upper()
    )
    sources = ["wazuh"]
    if any(_suricata_payload(alert) is not None for alert in attributed):
        sources.append("suricata-eve")
    applicable = ACCOUNT_FEATURES if family == "account" else C2_FEATURES
    completeness = (
        (len(applicable) - len(set(missing) & set(applicable))) / len(applicable)
        if family in {"account", "c2"}
        else 0.0
    )
    if family == "account":
        source_coverage = float("wazuh" in sources)
        relevant_events = sum(_windows_fields(alert)[0] in {"4624", "4625"} for alert in attributed)
        correlation = min(relevant_events / 3.0, 1.0)
    elif family == "c2":
        source_coverage = len(set(sources) & {"wazuh", "suricata-eve"}) / 2.0
        has_network = any(_windows_fields(alert)[0] in {"3", "22"} for alert in attributed)
        has_suricata = any(_suricata_payload(alert) is not None for alert in attributed)
        correlation = (int(has_network) + int(has_suricata)) / 2.0
    else:
        source_coverage = 0.0
        correlation = 0.0
    evidence_quality = round(
        0.4 * completeness + 0.3 * source_coverage + 0.2 * correlation + 0.1,
        6,
    )
    evidence_reasons = [
        f"feature_completeness={completeness:.3f}",
        f"required_source_coverage={source_coverage:.3f}",
        f"correlation_strength={correlation:.3f}",
        "validated_envelope=1.000",
    ]
    incident = IncidentRequest(
        context_status=context.status, context_revision=context.revision,
        review_reasons=[
            *context.review_reasons, *flow_reasons, *(["telemetry:partial"] if missing else [])
        ],
        observation_quality="PARTIAL" if missing or family == "unknown" else "COMPLETE",
        incident_id=f"INC-FV3-{digest}",
        asset_id=_asset_id(first, config),
        start_time=alert_event_time(ordered_alerts[0]),
        end_time=alert_event_time(ordered_alerts[-1]),
        family_hint=family,
        features=features,
        evidence_sources=sources,
        base_severity=max(alert.rule.level for alert in alerts),
        raw_refs=list(dict.fromkeys(refs)),
        indicator=indicator,
    )
    return FeaturePipelineResponse(
        feature_order=list(FEATURE_ORDER),
        ordered_vector=[features[name] for name in FEATURE_ORDER],
        quality_status="PARTIAL" if missing or family == "unknown" else "COMPLETE",
        missing_required_features=missing,
        structural_zero_features=structural,
        evidence_quality=evidence_quality,
        evidence_quality_reasons=evidence_reasons,
        incident=incident,
    )


def extract_wazuh_features(alert: WazuhAlert) -> FeaturePipelineResponse:
    """Derive a conservative feature vector from one event.

    A single raw event is normally PARTIAL. Production uses the stateful/batch
    window so the same derivation functions as offline collection see the full run.
    """

    return _build_response([alert])


def aggregate_wazuh_alerts(
    alerts: list[WazuhAlert], *, window_minutes: int = 5,
    baseline: BaselineSnapshot | None = None,
    source_config: dict[str, Any] | None = None, taxonomy: dict[str, Any] | None = None,
    use_runtime_baseline: bool = True,
) -> FeatureBatchResponse:
    config = _collection_config() if source_config is None else source_config
    if not 1 <= window_minutes <= 5:
        raise ValueError("window_minutes must be between 1 and 5")
    if baseline is None and use_runtime_baseline:
        configured = os.getenv("CONTEXT_BASELINE_PATH") or config.get(
            "context_baseline_path"
        )
        baseline = load_baseline(ROOT / configured) if configured else None
    unique_by_id: dict[str, WazuhAlert] = {}
    for alert in alerts:
        existing = unique_by_id.get(alert.id)
        if existing is not None and existing.model_dump() != alert.model_dump():
            raise ValueError(f"duplicate alert id has conflicting payload: {alert.id}")
        unique_by_id.setdefault(alert.id, alert)
    ordered = sorted(unique_by_id.values(), key=lambda item: (alert_event_time(item), item.id))
    groups: dict[tuple[tuple[str, str, str], datetime], list[WazuhAlert]] = {}
    for alert in ordered:
        key = (_aggregation_key(alert, config), window_start(alert, window_minutes=window_minutes))
        groups.setdefault(key, []).append(alert)
    return FeatureBatchResponse(
        input_alert_count=len(alerts),
        unique_alert_count=len(unique_by_id),
        duplicate_alert_count=len(alerts) - len(unique_by_id),
        incidents=[
            _build_response(
                group, window_minutes=window_minutes, baseline=baseline,
                source_config=config, taxonomy=taxonomy,
            )
            for group in groups.values()
        ],
    )
