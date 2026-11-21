"""Observed conversation descriptors; no scenario or response authorization input."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from statistics import fmean

from ml.behavior_features import NetworkObservation, interval_features
from ml.context import BaselineSnapshot, assess_context
from ml.telemetry import basename, normalize_ip

STREAM_SCHEMA_VERSION = "features-v4-stream-v1"
STREAM_FEATURES = (
    "tcp_connection_count", "udp_connection_count", "dns_observation_fraction",
    "network_process_count", "tcp_conversation_count", "dominant_tcp_share",
    "dominant_tcp_observation_count", "dominant_tcp_unique",
    "dominant_tcp_timing_available", "dominant_tcp_periodicity_available",
    "dominant_tcp_order_available", "dominant_tcp_periodicity_score",
    "dominant_tcp_interval_cv", "dominant_tcp_mean_interval_seconds",
    "dominant_tcp_duration_seconds", "dominant_tcp_interval_alternation",
    "dominant_tcp_context_known", "dominant_tcp_new_destination",
    "novel_tcp_conversation_fraction", "dns_only_window",
)


@dataclass(frozen=True)
class StreamObservation:
    network: NetworkObservation
    process_instance: str
    process_image: str


def conversation_key(item: StreamObservation) -> tuple[str, str, int | None, str]:
    n = item.network
    return (basename(item.process_image), normalize_ip(n.destination).strip("."),
            n.destination_port, str(n.protocol or "").casefold())


def tcp_conversations(observations: list[StreamObservation]) -> list[list[StreamObservation]]:
    groups = defaultdict(list)
    identities = {}
    for item in observations:
        image, guid = basename(item.process_image), item.process_instance.strip().casefold()
        if not guid or not image or image in {"<unknown process>", "&lt;unknown process&gt;"}:
            raise ValueError("verified process identity is required for stream observations")
        if guid in identities and identities[guid] != image:
            raise ValueError("conflicting process identity in stream observations")
        identities[guid] = image
        if item.network.dns_query is None and str(item.network.protocol).casefold() == "tcp":
            groups[conversation_key(item)].append(item)
    return sorted(groups.values(), key=lambda group: (-len(group), conversation_key(group[0])))


def dominant_tcp_conversation(observations: list[StreamObservation]) -> list[StreamObservation]:
    groups = tcp_conversations(observations)
    if not groups or (len(groups) > 1 and len(groups[0]) == len(groups[1])):
        return []
    return groups[0]


def derive_stream_features(
    observations: list[StreamObservation], *, baseline: BaselineSnapshot | None = None,
    asset_id: str = "", as_of: datetime | None = None,
) -> dict[str, float]:
    features = dict.fromkeys(STREAM_FEATURES, 0.0)
    groups = tcp_conversations(observations)
    tcp = [item for group in groups for item in group]
    dns = [item for item in observations if item.network.dns_query is not None]
    udp = [item for item in observations if item.network.dns_query is None
           and str(item.network.protocol).casefold() == "udp"]
    winner = dominant_tcp_conversation(observations)
    features.update({
        "tcp_connection_count": float(len(tcp)),
        "udp_connection_count": float(len(udp)),
        "dns_observation_fraction": round(len(dns) / len(observations), 6) if observations else 0.0,
        "network_process_count": float(len({
            x.process_instance.strip().casefold() for x in observations
        })),
        "tcp_conversation_count": float(len(groups)),
        "dominant_tcp_share": round(len(groups[0]) / len(tcp), 6) if tcp else 0.0,
        "dominant_tcp_observation_count": float(len(groups[0])) if groups else 0.0,
        "dominant_tcp_unique": float(bool(winner)),
        "dns_only_window": float(bool(dns) and len(dns) == len(observations)),
    })
    if winner:
        times = sorted({x.network.timestamp for x in winner})
        periodicity, mean, cv = interval_features(times)
        gaps = [(b-a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
        center = fmean(gaps) if gaps else 0.0
        changes = sum((a-center)*(b-center) < 0 for a, b in zip(gaps, gaps[1:], strict=False))
        features.update({
            "dominant_tcp_timing_available": float(len(times) >= 2),
            "dominant_tcp_periodicity_available": float(len(times) >= 3),
            "dominant_tcp_order_available": float(len(times) >= 4),
            "dominant_tcp_periodicity_score": periodicity,
            "dominant_tcp_interval_cv": cv,
            "dominant_tcp_mean_interval_seconds": mean,
            "dominant_tcp_duration_seconds": round((times[-1]-times[0]).total_seconds(), 6),
            "dominant_tcp_interval_alternation": (
                round(changes / (len(gaps)-1), 6) if len(times) >= 4 else 0.0
            ),
        })
    if groups and baseline is not None and asset_id:
        when = as_of or max(x.network.timestamp for x in observations)
        contexts = [assess_context(
            baseline, at=when, asset_id=asset_id, network=[x.network for x in group],
        ) for group in groups]
        if all(c.status == "AVAILABLE" and c.features["destination_history_known"]
               for c in contexts):
            features["novel_tcp_conversation_fraction"] = round(
                sum(c.features["new_destination"] for c in contexts) / len(contexts), 6,
            )
            if winner:
                features["dominant_tcp_context_known"] = 1.0
                features["dominant_tcp_new_destination"] = contexts[0].features["new_destination"]
    return features
