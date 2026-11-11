"""Canonical raw telemetry parsing shared by collection and online inference."""

from __future__ import annotations

import ipaddress
import json
import re
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from ml.behavior_features import NetworkObservation, SuricataObservation


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
    if (
        isinstance(payload, dict)
        and isinstance(payload.get("event_type"), str)
        and payload.get("event_type")
        in {
            "alert",
            "flow",
            "dns",
            "http",
            "tls",
        }
    ):
        return payload
    return None


def sysmon_clock_issues(event: dict[str, Any], *, maximum_skew_seconds: float = 5.0) -> list[str]:
    """Check native Sysmon UTC evidence without changing any source timestamp.

    Provider-less historical adapters may omit native clocks. When a native UTC
    field is present it is still checked; a real Sysmon source must supply it.
    Named Sysmon UtcTime values without an offset have a documented UTC meaning.
    """
    event_id, system, fields = windows_fields(event)
    if event_id not in {"1", "3", "5", "22"}:
        return []
    provider = str(system.get("providerName", "")).strip().casefold()
    decoder = event.get("decoder")
    decoder = str(decoder.get("name", "")) if isinstance(decoder, dict) else ""
    declared = provider == "microsoft-windows-sysmon" or decoder.casefold() == "sysmon-c2"
    # An explicitly different provider is not a Sysmon event-ID namespace.
    if provider and provider != "microsoft-windows-sysmon":
        return []
    native_values = [value for key, value in fields.items() if key.casefold() == "utctime"]
    message = system.get("message")
    message_values = []
    if isinstance(message, str):
        message_values = re.findall(r"(?:^|[\r\n])\s*UtcTime:\s*([^\r\n]*)", message, re.IGNORECASE)
    if not declared and not native_values and not message_values:
        return []
    if not 0 < maximum_skew_seconds <= 5:
        raise ValueError("Sysmon clock skew limit must be in (0,5]")
    def seconds(value: Any, *, system_clock: bool = False) -> Decimal | None:
        if not isinstance(value, str):
            return None
        match = re.fullmatch(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?",
            value.strip(),
        )
        if match is None or (system_clock and match[2] is None):
            return None
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            if not system_clock and parsed.utcoffset().total_seconds() != 0:
                return None
            whole = parsed.replace(microsecond=0) - datetime(1970, 1, 1, tzinfo=UTC)
            return Decimal(whole.days * 86400 + whole.seconds) + Decimal("0." + (match[1] or "0"))
        except (ValueError, AttributeError, OverflowError):
            return None

    issues = []
    system_at = seconds(system.get("systemTime"), system_clock=True)
    if system_at is None:
        issues.append("clock:invalid_sysmon_system_time")
    if not native_values:
        issues.append("clock:missing_sysmon_utc_time")
    parsed_values = []
    for value in native_values + message_values:
        parsed = seconds(value)
        if parsed is None:
            issues.append("clock:invalid_sysmon_utc_time")
        else:
            parsed_values.append(parsed)
    clocks = ([system_at] if system_at is not None else []) + parsed_values
    if clocks and max(clocks) - min(clocks) > Decimal(str(maximum_skew_seconds)):
        issues.append("clock:sysmon_timestamp_mismatch")
    return sorted(set(issues))


def event_time(event: dict[str, Any]) -> datetime | None:
    event_id, system, fields = windows_fields(event)

    if system:
        system_at = parse_time(system.get("systemTime"))

        provider = str(
            system.get("providerName", "")
        ).strip().casefold()

        # Sysmon Event 3: native UtcTime describes network activity,
        # while SystemTime can reflect delayed event publication.
        if (
            event_id == "3"
            and provider == "microsoft-windows-sysmon"
            and system_at is not None
            and not sysmon_clock_issues(event)
        ):
            native = fields.get("utcTime")

            if isinstance(native, str):
                try:
                    normalized = native.strip().replace(" ", "T")
                    normalized = normalized.replace("Z", "+00:00")

                    native_at = datetime.fromisoformat(normalized)

                    if native_at.tzinfo is None:
                        native_at = native_at.replace(tzinfo=UTC)

                    if (
                        native_at.utcoffset() == timedelta(0)
                        and abs(
                            (system_at - native_at).total_seconds()
                        ) <= 5
                    ):
                        return native_at.astimezone(UTC)

                except (ValueError, OverflowError):
                    pass

        return system_at

    payload = suricata_payload(event)
    if payload is not None:
        if payload.get("event_type") == "flow" and isinstance(payload.get("flow"), dict):
            # Flow emission may be delayed by timeouts. Keep its original EVE
            # timestamp in raw evidence, but attribute support to the flow start.
            started = parse_time(payload["flow"].get("start"))
            if started is not None:
                return started
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
    # A Windows logon subject is the actor, not the account being logged on.
    for name in ("targetUserName", "TargetUserName", "dstuser"):
        value = eventdata.get(name)
        if value:
            return str(value).strip().casefold()
    return ""


def account_source(eventdata: dict[str, Any]) -> str:
    for field in ("ipAddress", "IpAddress", "sourceIp", "workstationName", "WorkstationName"):
        value = str(eventdata.get(field) or "").strip()
        if value and value != "-":
            return normalize_ip(value)
    # Only an explicitly interactive console logon proves a local source.
    logon_type = str(eventdata.get("logonType", eventdata.get("LogonType", ""))).strip()
    return "local-console" if logon_type == "2" else "unknown-source"


def account_observation_issues(eventdata: dict[str, Any]) -> list[str]:
    """Do not silently discard authentication whose scope cannot be decided."""
    logon_type = str(eventdata.get("logonType", eventdata.get("LogonType", ""))).strip()
    if logon_type in {"0", "4", "5", "7", "8", "9", "11", "12", "13"}:
        return []
    if (account_user(eventdata) and is_interactive_logon(eventdata)
            and not account_observation_eligible(eventdata)):
        return []  # Proven virtual OS session identity.
    issues = []
    if logon_type not in {"2", "3", "10"}:
        issues.append("telemetry:missing_or_invalid_logon_type")
    if not account_user(eventdata):
        issues.append("telemetry:missing_target_account")
    if account_source(eventdata) == "unknown-source":
        issues.append("telemetry:unknown_account_source")
    return issues


def is_interactive_logon(
    eventdata: dict[str, Any], allowed_logon_types: tuple[int, ...] | list[int] = (2, 3, 10)
) -> bool:
    value = str(eventdata.get("logonType", eventdata.get("LogonType", ""))).strip()
    return value in {str(item) for item in allowed_logon_types}


def account_observation_eligible(
    eventdata: dict[str, Any],
    allowed_logon_types: tuple[int, ...] | list[int] = (2, 3, 10),
) -> bool:
    """Human-account scope, independent of scenario names or labels.

    Virtual session identities require their OS SID namespace, domain and name;
    a local account merely named DWM-1 must remain observable.
    """
    if not account_user(eventdata) or not is_interactive_logon(eventdata, allowed_logon_types):
        return False
    sid = str(eventdata.get("targetUserSid", eventdata.get("TargetUserSid", ""))).casefold()
    domain = str(
        eventdata.get("targetDomainName", eventdata.get("TargetDomainName", "")),
    ).casefold()
    user = account_user(eventdata)
    virtual_session = (
        domain == "window manager"
        and re.fullmatch(r"dwm-\d+", user)
        and re.fullmatch(r"s-1-5-90-\d+-\d+", sid)
    ) or (
        domain == "font driver host"
        and re.fullmatch(r"umfd-\d+", user)
        and re.fullmatch(r"s-1-5-96-\d+-\d+", sid)
    )
    return not virtual_session


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
    if flow_connection_key(payload) is None:
        return False
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
            observation.source is not None
            and normalize_ip(observation.source) == normalize_ip(payload.get(source_field))
            and observation.source_port is not None
            and observation.source_port == payload.get("dest_port" if response else "src_port")
            and observation.protocol is not None
            and observation.protocol.casefold() == str(payload.get("proto", "")).casefold()
            and normalize_ip(observation.destination) == payload_ip
            and observation.destination_port is not None
            and observation.destination_port == payload_port
        ):
            return True
    return False


def suricata_observations(payloads: list[dict[str, Any]]) -> list[SuricataObservation]:
    """Use final cumulative counters; retain alert counts and severity."""
    observations = []
    counters: dict[tuple[str, ...], tuple[int, int]] = {}
    for payload in payloads:
        alert = payload.get("event_type") == "alert"
        severity = None
        if alert:
            with suppress(TypeError, ValueError):
                severity = int((payload.get("alert") or {}).get("severity"))
        observations.append(SuricataObservation(alert, severity, 0))
        if payload.get("event_type") != "flow":
            continue
        flow = payload.get("flow")
        key = flow_connection_key(payload)
        if not isinstance(flow, dict) or key is None:
            continue
        started = parse_time(flow.get("start"))
        if started is None:
            continue
        counter_key = (*key, started.isoformat())
        values = []
        for field in ("bytes_toserver", "bytes_toclient"):
            value = flow.get(field, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("flow counters must be non-negative integers")
            values.append(value)
        previous = counters.get(counter_key, (0, 0))
        counters[counter_key] = (max(previous[0], values[0]), max(previous[1], values[1]))
    observations.extend(SuricataObservation(False, None, sum(value)) for value in counters.values())
    return observations


def flow_connection_key(payload: dict[str, Any]) -> tuple[str, ...] | None:
    if not payload.get("flow_id") or str(payload.get("proto", "")).casefold() not in {"tcp", "udp"}:
        return None
    for field in ("src_ip", "dest_ip"):
        try:
            ipaddress.ip_address(normalize_ip(payload.get(field)))
        except ValueError:
            return None
    for field in ("src_port", "dest_port"):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 65535:
            return None
    endpoints = sorted(
        (
            f"{normalize_ip(payload.get('src_ip'))}:{payload.get('src_port', '')}",
            f"{normalize_ip(payload.get('dest_ip'))}:{payload.get('dest_port', '')}",
        )
    )
    return (
        str(payload.get("sensor_instance", "")),
        str(payload["flow_id"]),
        str(payload.get("proto", "")).casefold(),
        *endpoints,
    )


def linked_flow(
    payload: dict[str, Any],
    references: list[tuple[dict[str, Any], datetime]],
    tolerance: float,
) -> bool:
    """A final flow needs an attributable transaction, tuple and time interval."""
    if payload.get("event_type") != "flow":
        return False
    key = flow_connection_key(payload)
    flow = payload.get("flow")
    if key is None or not isinstance(flow, dict):
        return False
    start, end = parse_time(flow.get("start")), parse_time(flow.get("end"))
    if start is None or end is None or end < start:
        return False
    return any(
        reference.get("event_type") in {"http", "dns", "tls"}
        and flow_connection_key(reference) == key
        and -tolerance <= (at - start).total_seconds()
        and (at - end).total_seconds() <= tolerance
        for reference, at in references
    )


def flow_counter_issues(
    payloads: list[dict[str, Any]],
    *,
    window_start: datetime,
    window_end: datetime,
) -> list[str]:
    keys = {flow_connection_key(item) for item in payloads}
    keys.discard(None)
    if not keys:
        return ["flow:missing_final_counters"]
    reasons = set()
    for key in keys:
        related = [item for item in payloads if flow_connection_key(item) == key]
        final = [item for item in related if item.get("event_type") == "flow"]
        if not final:
            reasons.add("flow:missing_final_counters")
            continue
        related_flows = [item["flow"] for item in related if isinstance(item.get("flow"), dict)]
        final_flows = [item["flow"] if isinstance(item.get("flow"), dict) else {} for item in final]
        starts = {parse_time(flow.get("start")) for flow in final_flows}
        if len(starts) != 1:
            reasons.add("flow:ambiguous_reused_id")
        for flow in final_flows:
            start, end = parse_time(flow.get("start")), parse_time(flow.get("end"))
            if start is None or end is None or not window_start <= start <= end < window_end:
                reasons.add("flow:cross_window_or_invalid_interval")
            for field in ("bytes_toserver", "bytes_toclient"):
                value = flow.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    reasons.add("flow:invalid_counter")
                elif any(
                    isinstance(row.get(field), int) and row[field] > value for row in related_flows
                ):
                    reasons.add("flow:counter_reset_or_conflict")
    return sorted(reasons)


def unambiguous_transactions(
    references: list[tuple[dict[str, Any], datetime]], tolerance: float
) -> list[tuple[dict[str, Any], datetime]]:
    """DNS22 has no socket: competing tuples for the same query stay uncertain."""
    result = []
    for payload, at in references:
        names = set(suricata_dns_names(payload.get("dns")))
        competing = {
            flow_connection_key(other)
            for other, other_at in references
            if names.intersection(suricata_dns_names(other.get("dns")))
            and abs((at - other_at).total_seconds()) <= 2 * tolerance
        }
        if not names or len(competing) == 1:
            result.append((payload, at))
    return result


def linked_transaction(
    payload: dict[str, Any], at: datetime,
    references: list[tuple[dict[str, Any], datetime]], tolerance: float,
) -> bool:
    """Nonce inheritance requires the retained transaction's full identity and time."""
    key = flow_connection_key(payload)
    return key is not None and any(
        flow_connection_key(reference) == key
        and abs((at - reference_at).total_seconds()) <= tolerance
        for reference, reference_at in references
    )
