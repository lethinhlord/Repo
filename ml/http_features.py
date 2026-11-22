"""Observable HTTP/flow/context descriptors; no labels, nonce or scenario input."""

from __future__ import annotations

import json
import math
from statistics import fmean, pstdev

from ml.feature_pipeline import _process_creation_index, _suricata_payload
from ml.stream_features import dominant_tcp_conversation
from ml.telemetry import (
    basename,
    event_time,
    flow_connection_key,
    flow_counter_issues,
    linked_flow,
    process_guid,
    same_flow_direction,
    suricata_correlates,
    sysmon_clock_issues,
    windows_fields,
)

HTTP_SCHEMA_VERSION = "features-v5-http-v1"
HTTP_FEATURES = (
    "http_transaction_count",
    "http_post_fraction",
    "http_method_switch_fraction",
    "http_response_bytes_log1p",
    "flow_upload_fraction",
    "flow_total_bytes_cv",
    "http_evidence_available",
    "flow_evidence_available",
    "flow_dispersion_available",
    "reported_parent_fraction",
    "verified_parent_fraction",
    "verified_shell_parent_fraction",
)


def _parent_features(alerts, winner, windows_agent):
    parents = [
        a.model_dump(mode="json")
        for a in alerts
        if a.agent.name == windows_agent and windows_fields(a.model_dump())[0] in {"1", "5"}
    ]
    children = {x.process_instance.casefold() for x in winner}
    claims = proven = shells = 0
    for guid in children:
        records = [
            a
            for a in parents
            if process_guid(windows_fields(a)[2]) == guid and windows_fields(a)[0] == "1"
        ]
        if not records:
            continue
        child = records[0]
        fields = windows_fields(child)[2]
        parent_guid = str(fields.get("parentProcessGuid", "")).strip().casefold()
        image = str(fields.get("parentImage", "")).strip()
        pid = str(fields.get("parentProcessId", "")).strip()
        claims += bool(parent_guid and image and pid)
        if not parent_guid or not image or not pid or parent_guid == guid:
            continue

        def native(row):
            return str(
                windows_fields(row)[1].get("providerName", "")
            ).casefold() == "microsoft-windows-sysmon" and not sysmon_clock_issues(row)

        if not native(child):
            continue
        index = _process_creation_index(
            [p for p in parents if native(p)],
            windows_agent,
            as_of=event_time(child),
        )
        actual = index.get(parent_guid)
        if actual is None:
            continue
        native = windows_fields(actual)[2]
        if (
            str(native.get("processId", "")) != pid
            or str(native.get("image", "")).replace("/", "\\").casefold()
            != image.replace("/", "\\").casefold()
        ):
            raise ValueError("reported parent contradicts independent native parent identity")
        proven += 1
        shells += basename(image) in {"powershell.exe", "pwsh.exe", "cmd.exe"}
    total = len(children)
    return {
        "reported_parent_fraction": round(claims / total, 6) if total else 0.0,
        "verified_parent_fraction": round(proven / total, 6) if total else 0.0,
        "verified_shell_parent_fraction": round(shells / total, 6) if total else 0.0,
    }


def derive_http_features(alerts, proof, config, *, window_minutes: int = 5) -> dict[str, float]:
    """Use only the dominant proven TCP stream and its complete native evidence.

    Zero descriptors with a zero availability mask mean unknown, not benign.
    Flow counters describe observed network bytes, including protocol headers.
    Parent context is bounded to this same bucket for portable online/offline parity.
    """
    from datetime import UTC, datetime, timedelta

    result = dict.fromkeys(HTTP_FEATURES, 0.0)
    winner = dominant_tcp_conversation(list(proof.streams))
    winner = list({(x.network, x.process_instance.casefold()): x for x in winner}.values())
    if not winner:
        return result
    result.update(_parent_features(alerts, winner, config["windows_agent_name"]))
    tolerance = config.get("correlation_window_seconds", 10)
    payloads = {}
    for alert in alerts:
        if alert.agent.name != config["suricata_agent_name"]:
            continue
        payload = _suricata_payload(alert)
        if payload is not None:
            payloads[json.dumps(payload, sort_keys=True, separators=(",", ":"))] = (
                payload,
                event_time(alert.model_dump(mode="json")),
            )
    transactions = [
        (p, at)
        for p, at in payloads.values()
        if p.get("event_type") == "http"
        and at is not None
        and suricata_correlates(p, at, [x.network for x in winner], tolerance)
    ]
    edges = [
        [
            i
            for i, (p, at) in enumerate(transactions)
            if suricata_correlates(p, at, [x.network], tolerance)
        ]
        for x in winner
    ]
    if (
        len(transactions) != len(winner)
        or any(len(e) != 1 for e in edges)
        or len({e[0] for e in edges if e}) != len(transactions)
    ):
        return result
    connections = sorted(zip(winner, edges, strict=True), key=lambda x: x[0].network.timestamp)
    ordered = [transactions[edge[0]] for _, edge in connections]
    if len({x.network.timestamp for x, _ in connections}) != len(connections):
        return result  # Equal timestamps do not prove HTTP method sequence.
    methods, lengths = [], []
    for p, _ in ordered:
        http = p.get("http")
        if (
            not isinstance(http, dict)
            or http.get("http_method") not in {"GET", "POST"}
            or type(http.get("length")) is not int
            or not 0 <= http["length"] <= 10**9
            or type(http.get("status")) is not int
            or not 100 <= http["status"] <= 599
        ):
            return result
        methods.append(http["http_method"])
        lengths.append(http["length"])
    result.update(
        http_evidence_available=1.0,
        http_transaction_count=float(len(methods)),
        http_post_fraction=round(methods.count("POST") / len(methods), 6),
        http_method_switch_fraction=(
            round(
                sum(a != b for a, b in zip(methods, methods[1:], strict=False))
                / (len(methods) - 1),
                6,
            )
            if len(methods) > 1
            else 0.0
        ),
        http_response_bytes_log1p=round(math.log1p(sum(lengths)), 6),
    )
    flows = [p for p, _ in payloads.values() if linked_flow(p, transactions, tolerance)]
    if type(window_minutes) is not int or not 1 <= window_minutes <= 5:
        raise ValueError("HTTP evidence window must be an integer in1..5 minutes")
    # A creation can be in an earlier bucket; network time defines this stream.
    seconds = window_minutes * 60
    start = datetime.fromtimestamp(
        int(min(x.network.timestamp for x in winner).timestamp()) // seconds * seconds, UTC
    )
    end = start + timedelta(minutes=window_minutes)
    if not flows or flow_counter_issues(
        [p for p, _ in transactions] + flows, window_start=start, window_end=end
    ):
        return result
    finals = {}
    for flow in flows:
        key = flow_connection_key(flow)
        if not any(same_flow_direction(flow, p) for p, _ in transactions):
            return result
        counters = (flow["flow"]["bytes_toserver"], flow["flow"]["bytes_toclient"])
        response_bytes = sum(
            p["http"]["length"] for p, _ in transactions if flow_connection_key(p) == key
        )
        if counters[0] <= 0 or counters[1] <= 0 or counters[1] < response_bytes:
            return result
        if key in finals and finals[key] != counters:
            raise ValueError("conflicting final flow counters in HTTP evidence")
        finals[key] = counters
    if set(finals) != {flow_connection_key(p) for p, _ in transactions}:
        return result
    total = [sum(v) for v in finals.values()]
    size = sum(total)
    result.update(
        flow_evidence_available=1.0,
        flow_upload_fraction=round(sum(v[0] for v in finals.values()) / size, 6) if size else 0.0,
        flow_dispersion_available=float(len(total) >= 2 and fmean(total) > 0),
        flow_total_bytes_cv=(
            round(pstdev(total) / fmean(total), 6) if len(total) >= 2 and fmean(total) > 0 else 0.0
        ),
    )
    return result
