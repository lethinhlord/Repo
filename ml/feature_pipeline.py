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
from ml.context import (
    BaselineSnapshot,
    context_from_events,
    context_observation_as_of,
    load_baseline,
)
from ml.telemetry import (
    account_observation_eligible,
    account_observation_issues,
    account_source,
    account_user,
    basename,
    event_time,
    flow_counter_issues,
    linked_flow,
    network_is_outbound,
    normalize_ip,
    process_guid,
    suricata_correlates,
    suricata_observations,
    suricata_payload,
    sysmon_clock_issues,
    taxonomy_match,
    unambiguous_transactions,
    windows_fields,
)

ROOT = Path(__file__).resolve().parents[1]
_UNKNOWN_PROCESS_IMAGES = {"<unknown process>", "&lt;unknown process&gt;"}


def _process_creation_index(
    events: list[dict[str, Any]], windows_agent: str, *, as_of: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Index known Event 1 identities, excluding conflicting reuse of a GUID."""
    creations: dict[str, dict[str, Any]] = {}
    conflicting: set[str] = set()
    terminated: set[str] = set()
    for event in events:
        if str((event.get("agent") or {}).get("name")) != windows_agent:
            continue
        timestamp = event_time(event)
        if timestamp is None or (as_of is not None and timestamp > as_of):
            continue
        event_id, _, fields = windows_fields(event)
        guid = process_guid(fields)
        if as_of is not None and guid and sysmon_clock_issues(event):
            conflicting.add(guid)
            continue
        if as_of is not None and event_id == "5" and guid:
            terminated.add(guid)
        if event_id != "1" or not guid:
            continue
        previous = creations.get(guid)
        if previous is not None and (
            windows_fields(previous)[2] != fields or event_time(previous) != event_time(event)
        ):
            conflicting.add(guid)
        creations.setdefault(guid, event)
    return {
        guid: event for guid, event in creations.items()
        if guid not in conflicting and guid not in terminated
        and event_time(event) is not None
        and basename(windows_fields(event)[2].get("image"))
        and basename(windows_fields(event)[2].get("image")).strip() not in _UNKNOWN_PROCESS_IMAGES
    }


def _process_observation_matches(
    event_id: str, fields: dict[str, Any], timestamp: datetime,
    creation: dict[str, Any],
) -> bool:
    """Allow Event 3's literal sentinel only after independent process proof."""
    process = windows_fields(creation)[2]
    created_at = event_time(creation)
    if created_at is None or timestamp < created_at:
        return False
    image = str(fields.get("image", "")).strip().casefold()
    if basename(image) != basename(process.get("image")) and not (
        event_id == "3" and image in _UNKNOWN_PROCESS_IMAGES
    ):
        return False
    for name in ("processId", "user"):
        observed = str(fields.get(name, "")).strip().casefold()
        expected = str(process.get(name, "")).strip().casefold()
        if observed and expected and observed != expected:
            return False
    return True


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
    event_id, fields = _windows_fields(alert)
    if event_id in {"4624", "4625"}:
        if account_observation_eligible(fields):
            return "account"
        # Keep uncertain authentication in scope so missing target/type/source
        # evidence cannot make neighboring account features appear complete.
        return "account" if account_observation_issues(fields) else "unknown"
    if event_id in {"1", "3", "22"} or _suricata_payload(alert) is not None:
        return "c2"
    if event_id:
        return "unknown"
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
    # Suricata EVE describes traffic monitored for the Windows target.
    # Native sensor OS events (e.g. sshd/journald) belong to NET-SENSOR.
    if alert.agent.name == suricata_agent:
        if _suricata_payload(alert) is not None:
            return windows_agent
        return alert.agent.name.strip()
    return alert.agent.name.strip()


def _account_name(alert: WazuhAlert) -> str:
    _, eventdata = _windows_fields(alert)
    return account_user(eventdata) or str(alert.data.dstuser or "unknown-user").strip().casefold()


def _account_source(alert: WazuhAlert) -> str:
    _, eventdata = _windows_fields(alert)
    return account_source(eventdata)


def _aggregation_key(
    alert: WazuhAlert,
    config: dict[str, Any] | None = None,
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
    alerts: list[WazuhAlert],
    family: str,
    config: dict[str, Any] | None = None,
    taxonomy: dict[str, Any] | None = None,
    process_context: list[WazuhAlert] | None = None,
) -> tuple[dict[str, float], list[str], list[str], str | None, list[WazuhAlert]]:
    config = _collection_config() if config is None else config
    if family == "account":
        observations: list[AccountObservation] = []
        attributed = []
        missing_target = False
        for alert in alerts:
            event_id, eventdata = _windows_fields(alert)
            if event_id in {"4624", "4625"} and not account_user(eventdata):
                missing_target = missing_target or bool(account_observation_issues(eventdata))
            if (
                event_id not in {"4624", "4625"}
                or not account_user(eventdata)
                or not account_observation_eligible(eventdata)
                or _account_source(alert) != _account_source(alerts[0])
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
            if missing_target:
                missing = list(ACCOUNT_FEATURES)
            return features, missing, list(C2_FEATURES), alerts[0].data.srcip, []
        features = derive_account_features(observations)
        return (
            features,
            list(ACCOUNT_FEATURES) if missing_target else [],
            list(C2_FEATURES),
            next((item.source for item in observations if item.source != "local-console"), None),
            attributed,
        )

    if family == "c2":
        from ml.telemetry import linked_transaction
        network: list[NetworkObservation] = []
        suricata: list[SuricataObservation] = []
        suspicious = False
        indicator: str | None = None
        attributed: list[WazuhAlert] = []
        windows_agent, sensor_agent = _collection_sources(config)
        configured_sources = {normalize_ip(value) for value in config.get("windows_source_ips", [])}
        identity_events = {}
        for item in [*(process_context or []), *alerts]:
            payload = item.model_dump(mode="json")
            if item.id in identity_events and identity_events[item.id] != payload:
                raise ValueError(f"duplicate alert id has conflicting payload: {item.id}")
            identity_events[item.id] = payload
        identities_by_guid: dict[str, list[dict[str, Any]]] = {}
        for identity in identity_events.values():
            kind, _, fields = windows_fields(identity)
            if kind in {"1", "5"}:
                identities_by_guid.setdefault(process_guid(fields), []).append(identity)
        alerts_by_id = {alert.id: alert for alert in alerts}

        observed_sources: set[str] = set()
        used_processes: dict[str, dict[str, Any]] = {}
        for alert in alerts:
            if alert.agent.name != windows_agent:
                continue
            event_id, eventdata = _windows_fields(alert)
            if event_id not in {"3", "22"}:
                continue
            guid = process_guid(eventdata)
            timestamp = alert_event_time(alert)
            processes = _process_creation_index(
                identities_by_guid.get(guid, []), windows_agent, as_of=timestamp,
            )
            if guid not in processes:
                continue
            if not _process_observation_matches(event_id, eventdata, timestamp, processes[guid]):
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
                network.append(
                    NetworkObservation(
                        timestamp,
                        destination,
                        port,
                        source=source,
                        source_port=_transport_port(eventdata.get("sourcePort")),
                        protocol=str(eventdata.get("protocol", "")),
                    )
                )
                observed_sources.add(source)
                indicator = indicator or destination
            else:
                query = str(eventdata.get("queryName", "")).strip(".").casefold()
                if not query:
                    continue
                network.append(NetworkObservation(timestamp, query, 53, query))
                indicator = indicator or query
            used_processes[guid] = processes[guid]
            attributed.append(alert)
        for guid in sorted(used_processes):
            creation = used_processes[guid]
            process = windows_fields(creation)[2]
            if creation["id"] in alerts_by_id:
                attributed.append(alerts_by_id[creation["id"]])
            suspicious = suspicious or taxonomy_match(
                process,
                _process_taxonomy() if taxonomy is None else taxonomy,
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
            if (
                payload is not None
                and payload.get("event_type") in {"http", "dns", "tls"}
                and suricata_correlates(
                    payload,
                    alert_event_time(alert),
                    network,
                    maximum_delta,
                    source_ips=sources,
                )
            ):
                references.append((payload, alert_event_time(alert)))
        references = unambiguous_transactions(references, maximum_delta)
        for alert in alerts:
            if alert.agent.name != sensor_agent:
                continue
            payload = _suricata_payload(alert)
            if (
                payload is None
                or not sources
                or not (
                    linked_flow(payload, references, maximum_delta)
                    if payload.get("event_type") == "flow"
                    else (
                        suricata_correlates(
                            payload,
                            alert_event_time(alert),
                            network,
                            maximum_delta,
                            source_ips=sources,
                        )
                        or (
                            payload.get("event_type") == "alert"
                            and linked_transaction(
                                payload,
                                alert_event_time(alert),
                                references,
                                maximum_delta,
                            )
                        )
                    )
                )
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
    alerts: list[WazuhAlert],
    *,
    window_minutes: int = 5,
    baseline: BaselineSnapshot | None = None,
    source_config: dict[str, Any] | None = None,
    taxonomy: dict[str, Any] | None = None,
    process_context: list[WazuhAlert] | None = None,
) -> FeaturePipelineResponse:
    config = _collection_config() if source_config is None else source_config
    first = alerts[0]
    family = _family(first)
    features, missing, structural, indicator, attributed = _derive_raw_group(
        alerts,
        family,
        config,
        taxonomy,
        process_context,
    )
    ordered_alerts = sorted(alerts, key=lambda item: (alert_event_time(item), item.id))
    context_events = [item.model_dump(mode="json") for item in attributed]
    context = context_from_events(
        baseline,
        context_events,
        at=context_observation_as_of(
            context_events, fallback=alert_event_time(ordered_alerts[-1]),
        ),
        asset_id=_asset_id(first, config),
    )
    features.update(context.features)
    telemetry_reasons = sorted({
        reason
        for item in alerts
        for reason in (
            sysmon_clock_issues(item.model_dump(mode="json"))
            + (account_observation_issues(_windows_fields(item)[1])
               if _windows_fields(item)[0] in {"4624", "4625"} else [])
        )
    })
    if telemetry_reasons:
        missing.extend(
            name for name in (ACCOUNT_FEATURES if family == "account" else C2_FEATURES)
            if name not in missing
        )
        if family == "account" and "telemetry:unknown_account_source" in telemetry_reasons:
            features["source_history_known"] = 0.0
            features["new_source_for_user"] = 0.0
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
            window_start=start,
            window_end=start + timedelta(minutes=window_minutes),
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
        context_status=context.status,
        context_revision=context.revision,
        review_reasons=[
            *context.review_reasons,
            *flow_reasons,
            *telemetry_reasons,
            *(["telemetry:partial"] if missing else []),
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
    alerts: list[WazuhAlert],
    *,
    window_minutes: int = 5,
    baseline: BaselineSnapshot | None = None,
    source_config: dict[str, Any] | None = None,
    taxonomy: dict[str, Any] | None = None,
    use_runtime_baseline: bool = True,
    process_context: list[WazuhAlert] | None = None,
) -> FeatureBatchResponse:
    config = _collection_config() if source_config is None else source_config
    if not 1 <= window_minutes <= 5:
        raise ValueError("window_minutes must be between 1 and 5")
    if baseline is None and use_runtime_baseline:
        configured = os.getenv("CONTEXT_BASELINE_PATH") or config.get("context_baseline_path")
        baseline = load_baseline(ROOT / configured) if configured else None
    unique_by_id: dict[str, WazuhAlert] = {}
    for alert in alerts:
        existing = unique_by_id.get(alert.id)
        if existing is not None and existing.model_dump() != alert.model_dump():
            raise ValueError(f"duplicate alert id has conflicting payload: {alert.id}")
        unique_by_id.setdefault(alert.id, alert)
    ordered = sorted(unique_by_id.values(), key=lambda item: (alert_event_time(item), item.id))
    # Identity proof is separate from bucket members: prior starts/exits may
    # validate a current observation, but never contribute prior behavior counts,
    # severity, context observations, timestamps, or incident membership.
    identities = [
        item for item in [*(process_context or []), *ordered]
        if _windows_fields(item)[0] in {"1", "5"}
    ]
    groups: dict[tuple[tuple[str, str, str], datetime], list[WazuhAlert]] = {}
    unknown_sources: dict[tuple[str, datetime], list[WazuhAlert]] = {}
    for alert in ordered:
        key = (_aggregation_key(alert, config), window_start(alert, window_minutes=window_minutes))
        groups.setdefault(key, []).append(alert)
        if key[0][1:] == ("account", "unknown-source"):
            unknown_sources.setdefault((key[0][0], key[1]), []).append(alert)
    for (group_key, bucket), group in groups.items():
        if group_key[1] == "account" and group_key[2] != "unknown-source":
            # Source-less authentication could belong to any source in this
            # asset bucket. Carry its uncertainty, never assign its counts.
            group.extend(unknown_sources.get((group_key[0], bucket), []))
    return FeatureBatchResponse(
        input_alert_count=len(alerts),
        unique_alert_count=len(unique_by_id),
        duplicate_alert_count=len(alerts) - len(unique_by_id),
        incidents=[
            _build_response(
                group,
                window_minutes=window_minutes,
                baseline=baseline,
                source_config=config,
                taxonomy=taxonomy,
                process_context=identities,
            )
            for group in groups.values()
        ],
    )


def _transport_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None
