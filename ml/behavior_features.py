from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from datetime import datetime

FEATURE_SCHEMA_VERSION = "features-v3"

ACCOUNT_FEATURES = (
    "failed_login_count",
    "successful_login_count",
    "success_after_fail",
    "unique_target_account_count",
    "unique_source_count",
    "remote_logon_ratio",
    "failure_window_seconds",
    "attempt_rate_per_minute",
    "source_history_known",
    "new_source_for_user",
)

C2_FEATURES = (
    "suspicious_process",
    "periodicity_score",
    "connection_interval_cv",
    "mean_interval_seconds",
    "suricata_alert_count",
    "suricata_severity_score",
    "outbound_connection_count",
    "unique_destination_count",
    "destination_port_count",
    "dns_query_count",
    "dns_unique_query_ratio",
    "flow_total_bytes_log1p",
    "destination_history_known",
    "new_destination",
)

FEATURE_ORDER = (*ACCOUNT_FEATURES, *C2_FEATURES)

REMOTE_WINDOWS_LOGON_TYPES = frozenset({"3", "8", "9", "10"})


@dataclass(frozen=True)
class AccountObservation:
    timestamp: datetime
    account: str
    source: str
    logon_type: str
    success: bool


@dataclass(frozen=True)
class NetworkObservation:
    timestamp: datetime
    destination: str
    destination_port: int | None
    dns_query: str | None = None
    source: str | None = None
    source_port: int | None = None
    protocol: str | None = None


@dataclass(frozen=True)
class SuricataObservation:
    is_alert: bool
    severity: int | None = None
    total_bytes: int = 0


def empty_feature_vector() -> dict[str, float]:
    return {name: 0.0 for name in FEATURE_ORDER}


def _ordered_unique_times(timestamps: list[datetime]) -> list[datetime]:
    return sorted(set(timestamps))


def interval_features(timestamps: list[datetime]) -> tuple[float, float, float]:
    ordered = _ordered_unique_times(timestamps)
    if len(ordered) < 2:
        return 0.0, 0.0, 0.0
    intervals = [
        (current - previous).total_seconds()
        for previous, current in zip(ordered, ordered[1:], strict=False)
    ]
    mean = statistics.fmean(intervals)
    if mean <= 0 or not math.isfinite(mean):
        return 0.0, 0.0, 0.0
    deviation = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    cv = deviation / mean
    periodicity = 0.0 if len(ordered) < 3 else max(0.0, min(1.0, 1.0 - cv))
    return round(periodicity, 6), round(mean, 6), round(cv, 6)


def derive_account_features(observations: list[AccountObservation]) -> dict[str, float]:
    features = empty_feature_vector()
    if not observations:
        return features
    ordered = sorted(observations, key=lambda item: item.timestamp)
    failures = [item for item in ordered if not item.success]
    successes = [item for item in ordered if item.success]
    success_after_fail = any(
        success.timestamp > failure.timestamp
        and success.account == failure.account
        and success.source == failure.source
        for failure in failures
        for success in successes
    )
    sources = {item.source or "local-console" for item in ordered}
    accounts = {item.account for item in ordered}
    remote = sum(item.logon_type.strip() in REMOTE_WINDOWS_LOGON_TYPES for item in ordered)
    failure_window = (
        (
            max(item.timestamp for item in failures) - min(item.timestamp for item in failures)
        ).total_seconds()
        if len(failures) > 1
        else 0.0
    )
    observation_seconds = max(
        1.0,
        (ordered[-1].timestamp - ordered[0].timestamp).total_seconds(),
    )
    features.update(
        {
            "failed_login_count": float(len(failures)),
            "successful_login_count": float(len(successes)),
            "success_after_fail": float(success_after_fail),
            "unique_target_account_count": float(len(accounts)),
            "unique_source_count": float(len(sources)),
            "remote_logon_ratio": round(remote / len(ordered), 6),
            "failure_window_seconds": round(failure_window, 6),
            "attempt_rate_per_minute": round(len(ordered) * 60.0 / observation_seconds, 6),
        }
    )
    return features


def derive_c2_features(
    network: list[NetworkObservation],
    suricata: list[SuricataObservation],
    *,
    suspicious_process: bool,
) -> dict[str, float]:
    features = empty_feature_vector()
    timestamps = [item.timestamp for item in network]
    periodicity, mean_interval, interval_cv = interval_features(timestamps)
    destinations = {item.destination.casefold() for item in network if item.destination}
    ports = {item.destination_port for item in network if item.destination_port is not None}
    dns_queries = [
        item.dns_query.strip(".").casefold()
        for item in network
        if item.dns_query and item.dns_query.strip(".")
    ]
    alerts = [item for item in suricata if item.is_alert]
    severity_scores = [
        max(0.0, min(1.0, (4.0 - float(item.severity)) / 3.0))
        for item in alerts
        if item.severity is not None
    ]
    total_bytes = sum(max(0, item.total_bytes) for item in suricata)
    features.update(
        {
            "suspicious_process": float(suspicious_process),
            "periodicity_score": periodicity,
            "connection_interval_cv": interval_cv,
            "mean_interval_seconds": mean_interval,
            "suricata_alert_count": float(len(alerts)),
            "suricata_severity_score": round(max(severity_scores, default=0.0), 6),
            "outbound_connection_count": float(len(network)),
            "unique_destination_count": float(len(destinations)),
            "destination_port_count": float(len(ports)),
            "dns_query_count": float(len(dns_queries)),
            "dns_unique_query_ratio": (
                round(len(set(dns_queries)) / len(dns_queries), 6) if dns_queries else 0.0
            ),
            "flow_total_bytes_log1p": round(math.log1p(total_bytes), 6),
        }
    )
    return features
