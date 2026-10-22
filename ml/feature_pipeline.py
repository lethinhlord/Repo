from __future__ import annotations

import hashlib
import json
from contextlib import suppress
from datetime import timedelta
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

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _collection_sources() -> tuple[str, str]:
    document = yaml.safe_load(
        (ROOT / "config/collection-sources.yaml").read_text(encoding="utf-8")
    )
    return str(document["windows_agent_name"]), str(document["suricata_agent_name"])


@lru_cache(maxsize=1)
def _process_taxonomy() -> dict[str, Any]:
    return yaml.safe_load(
        (ROOT / "config/process-risk-taxonomy.yaml").read_text(encoding="utf-8")
    )


def _basename(value: Any) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def _is_suspicious_process(eventdata: dict[str, Any]) -> bool:
    image = _basename(eventdata.get("image"))
    command = str(eventdata.get("commandLine", "")).casefold()
    for rule in _process_taxonomy().get("rules", []):
        suffix = _basename(rule.get("image_suffix"))
        terms = [str(item).casefold() for item in rule.get("command_contains_any", [])]
        if suffix and image != suffix:
            continue
        if terms and not any(term in command for term in terms):
            continue
        if suffix or terms:
            return True
    return False


def _windows_fields(alert: WazuhAlert) -> tuple[str, dict[str, Any]]:
    win = alert.data.win if isinstance(alert.data.win, dict) else {}
    system = win.get("system") if isinstance(win.get("system"), dict) else {}
    eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    return str(system.get("eventID", "")), eventdata


def _suricata_payload(alert: WazuhAlert) -> dict[str, Any] | None:
    if not alert.full_log:
        return None
    try:
        payload = json.loads(alert.full_log)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


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
        (value or 0) > 0
        for value in (alert.data.failed_login_count, alert.data.success_after_fail)
    ):
        return "account"
    return "unknown"


def _asset_id(alert: WazuhAlert) -> str:
    windows_agent, suricata_agent = _collection_sources()
    return windows_agent if alert.agent.name == suricata_agent else alert.agent.name.strip()


def _account_name(alert: WazuhAlert) -> str:
    _, eventdata = _windows_fields(alert)
    return str(
        eventdata.get("targetUserName")
        or eventdata.get("TargetUserName")
        or eventdata.get("dstuser")
        or alert.data.dstuser
        or "unknown-user"
    ).strip().casefold()


def _aggregation_key(alert: WazuhAlert) -> tuple[str, str, str]:
    family = _family(alert)
    discriminator = _account_name(alert) if family == "account" else "behavior-window"
    if family == "unknown":
        discriminator = alert.id
    return (_asset_id(alert).casefold(), family, discriminator)


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


def _derive_raw_group(alerts: list[WazuhAlert], family: str) -> tuple[
    dict[str, float], list[str], list[str], str | None
]:
    if family == "account":
        observations: list[AccountObservation] = []
        for alert in alerts:
            event_id, eventdata = _windows_fields(alert)
            if event_id not in {"4624", "4625"}:
                continue
            source = str(
                eventdata.get("ipAddress")
                or eventdata.get("IpAddress")
                or eventdata.get("sourceIp")
                or eventdata.get("workstationName")
                or eventdata.get("WorkstationName")
                or "local-console"
            ).strip().casefold()
            observations.append(
                AccountObservation(
                    timestamp=alert.timestamp,
                    account=_account_name(alert),
                    source=source,
                    logon_type=str(
                        eventdata.get("logonType", eventdata.get("LogonType", "unknown"))
                    ),
                    success=event_id == "4624",
                )
            )
        if not observations:
            features, missing = _legacy_features(alerts[0])
            return features, missing, list(C2_FEATURES), alerts[0].data.srcip
        features = derive_account_features(observations)
        return features, [], list(C2_FEATURES), next(
            (item.source for item in observations if item.source != "local-console"), None
        )

    if family == "c2":
        network: list[NetworkObservation] = []
        suricata: list[SuricataObservation] = []
        suspicious = False
        indicator: str | None = None
        saw_process = False
        for alert in alerts:
            event_id, eventdata = _windows_fields(alert)
            if event_id == "1":
                saw_process = True
                suspicious = suspicious or _is_suspicious_process(eventdata)
            elif event_id == "3":
                destination = str(eventdata.get("destinationIp", "")).strip()
                port = None
                with suppress(TypeError, ValueError):
                    port = int(eventdata.get("destinationPort"))
                network.append(NetworkObservation(alert.timestamp, destination, port))
                indicator = indicator or destination or None
                suspicious = suspicious or _is_suspicious_process(eventdata)
            elif event_id == "22":
                query = str(eventdata.get("queryName", "")).strip(".")
                network.append(NetworkObservation(alert.timestamp, query, 53, query))
                indicator = indicator or query or None
                suspicious = suspicious or _is_suspicious_process(eventdata)

            payload = _suricata_payload(alert)
            if payload is not None:
                flow = payload.get("flow") if isinstance(payload.get("flow"), dict) else {}
                total_bytes = 0
                for field in ("bytes_toserver", "bytes_toclient"):
                    with suppress(TypeError, ValueError):
                        total_bytes += max(0, int(flow.get(field, 0)))
                severity = None
                if payload.get("event_type") == "alert":
                    with suppress(TypeError, ValueError):
                        severity = int((payload.get("alert") or {}).get("severity"))
                suricata.append(
                    SuricataObservation(
                        is_alert=payload.get("event_type") == "alert",
                        severity=severity,
                        total_bytes=total_bytes,
                    )
                )
        if not network and not suricata and not saw_process:
            features, missing = _legacy_features(alerts[0])
            return features, missing, list(ACCOUNT_FEATURES), (
                alerts[0].data.destination_ip or alerts[0].data.destination_domain
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
        return features, sorted(set(missing)), list(ACCOUNT_FEATURES), indicator

    features, _ = _legacy_features(alerts[0])
    return features, list(FEATURE_ORDER), [], None


def _build_response(alerts: list[WazuhAlert]) -> FeaturePipelineResponse:
    first = alerts[0]
    family = _family(first)
    features, missing, structural, indicator = _derive_raw_group(alerts, family)
    ordered_alerts = sorted(alerts, key=lambda item: (item.timestamp, item.id))
    refs = [f"wazuh-alert:{alert.id}" for alert in ordered_alerts]
    location_names = [
        PurePath(alert.location.replace("\\", "/")).name.lower()
        for alert in ordered_alerts
        if PurePath(alert.location.replace("\\", "/")).name
    ]
    refs.extend(f"source-log:{name}" for name in dict.fromkeys(location_names))
    digest = hashlib.sha256(
        "|".join([_asset_id(first).casefold(), family, *sorted(refs)]).encode()
    ).hexdigest()[:12].upper()
    sources = ["wazuh"]
    if any(_suricata_payload(alert) is not None for alert in alerts):
        sources.append("suricata-eve")
    applicable = ACCOUNT_FEATURES if family == "account" else C2_FEATURES
    completeness = (
        (len(applicable) - len(set(missing) & set(applicable))) / len(applicable)
        if family in {"account", "c2"}
        else 0.0
    )
    if family == "account":
        source_coverage = float("wazuh" in sources)
        relevant_events = sum(_windows_fields(alert)[0] in {"4624", "4625"} for alert in alerts)
        correlation = min(relevant_events / 3.0, 1.0)
    elif family == "c2":
        source_coverage = len(set(sources) & {"wazuh", "suricata-eve"}) / 2.0
        has_network = any(_windows_fields(alert)[0] in {"3", "22"} for alert in alerts)
        has_suricata = any(_suricata_payload(alert) is not None for alert in alerts)
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
        incident_id=f"INC-FV2-{digest}",
        asset_id=_asset_id(first),
        start_time=ordered_alerts[0].timestamp,
        end_time=ordered_alerts[-1].timestamp,
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
    alerts: list[WazuhAlert], *, window_minutes: int = 5
) -> FeatureBatchResponse:
    if not 1 <= window_minutes <= 5:
        raise ValueError("window_minutes must be between 1 and 5")
    unique_by_id: dict[str, WazuhAlert] = {}
    for alert in alerts:
        existing = unique_by_id.get(alert.id)
        if existing is not None and existing.model_dump() != alert.model_dump():
            raise ValueError(f"duplicate alert id has conflicting payload: {alert.id}")
        unique_by_id.setdefault(alert.id, alert)
    ordered = sorted(unique_by_id.values(), key=lambda item: (item.timestamp, item.id))
    groups: list[list[WazuhAlert]] = []
    for alert in ordered:
        match = None
        for group in reversed(groups):
            if (
                _aggregation_key(group[0]) == _aggregation_key(alert)
                and alert.timestamp - group[0].timestamp < timedelta(minutes=window_minutes)
            ):
                match = group
                break
        if match is None:
            groups.append([alert])
        else:
            match.append(alert)
    return FeatureBatchResponse(
        input_alert_count=len(alerts),
        unique_alert_count=len(unique_by_id),
        duplicate_alert_count=len(alerts) - len(unique_by_id),
        incidents=[_build_response(group) for group in groups],
    )
