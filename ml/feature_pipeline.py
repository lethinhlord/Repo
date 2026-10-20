import hashlib
from datetime import timedelta
from pathlib import PurePath

from api.app.contracts import (
    FeatureBatchResponse,
    FeaturePipelineResponse,
    IncidentRequest,
    WazuhAlert,
)

FEATURE_ORDER = (
    "failed_login_count",
    "success_after_fail",
    "suspicious_process",
    "periodicity_score",
    "suricata_alert_count",
    "outbound_connection_count",
    "destination_port_count",
)
ACCOUNT_FEATURES = ("failed_login_count", "success_after_fail")
C2_FEATURES = (
    "suspicious_process",
    "periodicity_score",
    "suricata_alert_count",
    "outbound_connection_count",
    "destination_port_count",
)


def _value_or_zero(value: float | None) -> float:
    return 0.0 if value is None else float(value)


def _family(alert: WazuhAlert) -> str:
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


def extract_wazuh_features(alert: WazuhAlert) -> FeaturePipelineResponse:
    """Normalize one Wazuh alert into the frozen Week 2 feature contract.

    Only observed telemetry is copied. Threat intelligence and asset context are
    intentionally excluded to prevent target leakage and risk-score double counting.
    """

    raw_values = {
        "failed_login_count": alert.data.failed_login_count,
        "success_after_fail": alert.data.success_after_fail,
        "suspicious_process": alert.data.suspicious_process,
        "periodicity_score": alert.data.periodicity_score,
        "suricata_alert_count": alert.data.suricata_alert_count,
        "outbound_connection_count": alert.data.outbound_connection_count,
        "destination_port_count": alert.data.destination_port_count,
    }
    features = {name: _value_or_zero(raw_values[name]) for name in FEATURE_ORDER}

    location_name = PurePath(alert.location.replace("\\", "/")).name or "unknown-log"
    indicator = (
        alert.data.srcip
        or alert.data.destination_ip
        or alert.data.destination_domain
    )
    family = _family(alert)
    incident = IncidentRequest(
        incident_id=alert.id,
        asset_id=alert.agent.name.strip(),
        start_time=alert.timestamp,
        end_time=alert.timestamp,
        family_hint=family,
        features=features,
        evidence_sources=["wazuh"],
        base_severity=alert.rule.level,
        raw_refs=[f"wazuh-alert:{alert.id}", f"source-log:{location_name.lower()}"],
        indicator=indicator,
    )
    applicable = ACCOUNT_FEATURES if family == "account" else C2_FEATURES
    structural = C2_FEATURES if family == "account" else ACCOUNT_FEATURES
    if family == "unknown":
        applicable = FEATURE_ORDER
        structural = ()
    missing = [name for name in applicable if raw_values[name] is None]
    return FeaturePipelineResponse(
        feature_order=list(FEATURE_ORDER),
        ordered_vector=[features[name] for name in FEATURE_ORDER],
        quality_status="PARTIAL" if missing or family == "unknown" else "COMPLETE",
        missing_required_features=missing,
        structural_zero_features=[
            name for name in structural if raw_values[name] is None
        ],
        incident=incident,
    )


def aggregate_wazuh_alerts(
    alerts: list[WazuhAlert],
    *,
    window_minutes: int = 5,
) -> FeatureBatchResponse:
    """Deduplicate and group alerts into deterministic 1–5 minute incident windows."""

    if not 1 <= window_minutes <= 5:
        raise ValueError("window_minutes must be between 1 and 5")
    unique_by_id: dict[str, WazuhAlert] = {}
    for alert in alerts:
        existing = unique_by_id.get(alert.id)
        if existing is not None and existing.model_dump() != alert.model_dump():
            raise ValueError(f"duplicate alert id has conflicting payload: {alert.id}")
        unique_by_id.setdefault(alert.id, alert)
    normalized = [
        (alert, extract_wazuh_features(alert)) for alert in unique_by_id.values()
    ]
    normalized.sort(
        key=lambda pair: (pair[1].incident.start_time, pair[1].incident.incident_id)
    )

    grouped: list[list[tuple[WazuhAlert, FeaturePipelineResponse]]] = []
    for alert, item in normalized:
        matching_group = None
        for group in reversed(grouped):
            head_alert, head_item = group[0]
            head = head_item.incident
            if (
                _aggregation_key(head_alert, head_item)
                == _aggregation_key(alert, item)
                and item.incident.start_time - head.start_time
                < timedelta(minutes=window_minutes)
            ):
                matching_group = group
                break
        if matching_group is None:
            grouped.append([(alert, item)])
        else:
            matching_group.append((alert, item))

    incidents = [_merge_group([item for _, item in group]) for group in grouped]
    return FeatureBatchResponse(
        input_alert_count=len(alerts),
        unique_alert_count=len(unique_by_id),
        duplicate_alert_count=len(alerts) - len(unique_by_id),
        incidents=incidents,
    )


def _aggregation_key(
    alert: WazuhAlert,
    item: FeaturePipelineResponse,
) -> tuple[str, str, str]:
    family = item.incident.family_hint
    if family == "account":
        discriminator = (alert.data.dstuser or "unknown-user").strip().casefold()
    elif family == "c2":
        discriminator = (item.incident.indicator or "unknown-destination").casefold()
    else:
        discriminator = alert.id
    return (item.incident.asset_id.strip().casefold(), family, discriminator)


def _merge_group(group: list[FeaturePipelineResponse]) -> FeaturePipelineResponse:
    first = group[0]
    family = first.incident.family_hint
    features: dict[str, float] = {}
    for name in FEATURE_ORDER:
        values = [item.incident.features[name] for item in group]
        if name in {"success_after_fail", "suspicious_process", "periodicity_score"}:
            features[name] = max(values)
        else:
            features[name] = sum(values)

    end_time = max(item.incident.start_time for item in group)
    raw_refs = list(
        dict.fromkeys(ref for item in group for ref in item.incident.raw_refs)
    )
    evidence_sources = list(
        dict.fromkeys(
            source for item in group for source in item.incident.evidence_sources
        )
    )
    indicators = [item.incident.indicator for item in group if item.incident.indicator]
    alert_refs = sorted(
        ref
        for item in group
        for ref in item.incident.raw_refs
        if ref.startswith("wazuh-alert:")
    )
    digest_input = "|".join(
        [first.incident.asset_id.casefold(), family, *alert_refs]
    ).encode()
    incident_id = f"INC-W2-{hashlib.sha256(digest_input).hexdigest()[:12].upper()}"
    incident = IncidentRequest(
        incident_id=incident_id,
        asset_id=first.incident.asset_id,
        start_time=first.incident.start_time,
        end_time=end_time,
        family_hint=family,
        features=features,
        evidence_sources=evidence_sources,
        base_severity=max(item.incident.base_severity for item in group),
        raw_refs=raw_refs,
        indicator=indicators[0] if indicators else None,
    )
    missing = sorted(
        set.intersection(
            *(set(item.missing_required_features) for item in group)
        )
    ) if group else []
    structural = sorted(
        set.intersection(
            *(set(item.structural_zero_features) for item in group)
        )
    ) if group else []
    return FeaturePipelineResponse(
        feature_order=list(FEATURE_ORDER),
        ordered_vector=[features[name] for name in FEATURE_ORDER],
        quality_status="PARTIAL" if missing or family == "unknown" else "COMPLETE",
        missing_required_features=missing,
        structural_zero_features=structural,
        incident=incident,
    )
