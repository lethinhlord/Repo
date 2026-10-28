"""Canonical raw telemetry parsing shared by collection and online inference."""

from __future__ import annotations

import ipaddress
import json
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from ml.behavior_features import NetworkObservation


def parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
            normalized = normalized[:-2] + ":" + normalized[-2:]
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def windows_fields(event: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    data = event.get("data")
    win = data.get("win") if isinstance(data, dict) else None
    if not isinstance(win, dict):
        return "", {}, {}
    system = win.get("system")
    system = system if isinstance(system, dict) else {}
    eventdata = win.get("eventdata")
    eventdata = eventdata if isinstance(eventdata, dict) else {}
    return str(system.get("eventID", "")), system, eventdata


def suricata_payload(event: dict[str, Any]) -> dict[str, Any] | None:
    full_log = event.get("full_log")
    payload = None
    if isinstance(full_log, str):
        with suppress(json.JSONDecodeError):
            payload = json.loads(full_log)
    if not isinstance(payload, dict):
        payload = event.get("data")
    if isinstance(payload, dict) and isinstance(payload.get("event_type"), str) and payload.get(
        "event_type"
    ) in {
        "alert",
        "flow",
        "dns",
        "http",
        "tls",
    }:
        return payload
    return None


def event_time(event: dict[str, Any]) -> datetime | None:
    _, system, _ = windows_fields(event)
    if system:
        return parse_time(system.get("systemTime"))
    payload = suricata_payload(event)
    if payload is not None:
        return parse_time(payload.get("timestamp"))
    return parse_time(event.get("timestamp"))


def basename(value: Any) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def normalize_ip(value: Any) -> str:
    raw = str(value or "").strip().casefold()
    with suppress(ValueError):
        address = ipaddress.ip_address(raw)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(address)
    return raw


def account_user(eventdata: dict[str, Any]) -> str:
    for name in ("targetUserName", "TargetUserName", "dstuser", "subjectUserName"):
        value = eventdata.get(name)
        if value:
            return str(value).strip().casefold()
    return ""


def account_source(eventdata: dict[str, Any]) -> str:
    return normalize_ip(
        eventdata.get("ipAddress")
        or eventdata.get("IpAddress")
        or eventdata.get("sourceIp")
        or eventdata.get("workstationName")
        or eventdata.get("WorkstationName")
        or "local-console"
    )


def is_interactive_logon(
    eventdata: dict[str, Any], allowed_logon_types: tuple[int, ...] | list[int] = (2, 3, 10)
) -> bool:
    value = str(eventdata.get("logonType", eventdata.get("LogonType", ""))).strip()
    return value in {str(item) for item in allowed_logon_types}


def process_guid(eventdata: dict[str, Any]) -> str:
    return (
        str(eventdata.get("processGuid") or eventdata.get("ProcessGuid") or "").strip().casefold()
    )


def taxonomy_match(eventdata: dict[str, Any], taxonomy: dict[str, Any]) -> bool:
    image = basename(eventdata.get("image"))
    command = str(eventdata.get("commandLine", "")).casefold()
    for rule in taxonomy.get("rules", []):
        if not isinstance(rule, dict):
            continue
        suffix = basename(rule.get("image_suffix"))
        terms = [str(item).casefold() for item in rule.get("command_contains_any", [])]
        if suffix and image != suffix:
            continue
        if terms and not any(term in command for term in terms):
            continue
        if suffix or terms:
            return True
    return False


def network_is_outbound(eventdata: dict[str, Any]) -> bool:
    initiated = str(eventdata.get("initiated", "")).strip().casefold()
    if initiated != "true":
        return False
    try:
        ipaddress.ip_address(normalize_ip(eventdata.get("sourceIp")))
        ipaddress.ip_address(normalize_ip(eventdata.get("destinationIp")))
    except ValueError:
        return False
    return True


def suricata_dns_names(dns: object) -> list[str]:
    if not isinstance(dns, dict):
        return []
    raw_names: list[object] = [dns.get("rrname")]
    for field in ("queries", "query"):
        records = dns.get(field)
        if isinstance(records, dict):
            records = [records]
        if isinstance(records, list):
            raw_names.extend(record.get("rrname") for record in records if isinstance(record, dict))
    legacy_answer = dns.get("answer")
    if isinstance(legacy_answer, dict):
        raw_names.append(legacy_answer.get("rrname"))
    normalized = [
        name.strip().strip(".").casefold()
        for name in raw_names
        if isinstance(name, str) and name.strip().strip(".")
    ]
    return list(dict.fromkeys(normalized))


def suricata_dns_is_response(dns: object) -> bool:
    if not isinstance(dns, dict):
        return False
    if str(dns.get("type", "")).casefold() in {"answer", "response"}:
        return True
    answer = dns.get("answer")
    return isinstance(answer, dict) and str(answer.get("type", "")).casefold() in {
        "answer",
        "response",
    }


def suricata_correlates(
    payload: dict[str, Any],
    timestamp: datetime,
    observations: list[NetworkObservation],
    maximum_delta_seconds: float,
    *,
    source_ips: tuple[str, ...] | list[str] | set[str] = (),
) -> bool:
    response = suricata_dns_is_response(payload.get("dns"))
    source_field, destination_field = ("dest_ip", "src_ip") if response else ("src_ip", "dest_ip")
    if source_ips and normalize_ip(payload.get(source_field)) not in {
        normalize_ip(value) for value in source_ips
    }:
        return False
    dns_names = set(suricata_dns_names(payload.get("dns")))
    payload_ip = normalize_ip(payload.get(destination_field))
    payload_port = None
    with suppress(TypeError, ValueError):
        payload_port = int(payload.get("src_port" if response else "dest_port"))
    for observation in observations:
        if abs((timestamp - observation.timestamp).total_seconds()) > maximum_delta_seconds:
            continue
        if observation.dns_query is not None:
            if observation.dns_query.strip(".").casefold() in dns_names:
                return True
        elif (
            normalize_ip(observation.destination) == payload_ip
            and observation.destination_port is not None
            and observation.destination_port == payload_port
        ):
            return True
    return False
