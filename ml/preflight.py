"""Replayable canary verifier; verifies native evidence without creating telemetry."""

import json
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from ml.telemetry import (
    event_time,
    flow_connection_key,
    flow_counter_issues,
    normalize_ip,
    parse_time,
    process_guid,
    suricata_dns_is_response,
    suricata_dns_names,
    suricata_payload,
    windows_fields,
)


def verify_preflight_capture(
    capture: Path, nonce: str, since: str, checked_at: str | None = None
) -> dict:
    decision_at = parse_time(checked_at) if checked_at is not None else datetime.now(UTC)
    if decision_at is None:
        raise ValueError("Invalid preflight decision UTC")
    started = parse_time(since)
    if started is None or decision_at < started:
        raise ValueError("Invalid canary start UTC")
    payloads, windows = [], []
    for line in Path(capture).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        at = event_time(row)
        if at is None or not started - timedelta(seconds=5) <= at <= decision_at + timedelta(
            seconds=5
        ):
            continue
        if row.get("agent", {}).get("name") == "WIN11-TARGET":
            windows.append(windows_fields(row))
        if row.get("agent", {}).get("name") == "NET-SENSOR":
            payload = suricata_payload(row)
            if payload:
                payloads.append(payload)

    def verify_security_canary(records):
        """Require fresh console logons and a separate SMB source/type pair."""
        for user, kind in (("datn_benign", "2"), ("datn_attack", "3")):
            for event_id in ("4624", "4625"):
                if not any(
                    eid == event_id
                    and str(fields.get("targetUserName", "")).casefold() == user
                    and str(fields.get("logonType", "")) == kind
                    for eid, _, fields in records
                ):
                    raise ValueError(
                        f"Missing Security event={event_id} account={user} logonType={kind}"
                    )
        if not any(
            eid == "4624"
            and str(fields.get("targetUserName", "")).casefold() == "datn_attack"
            and str(fields.get("logonType", "")) == "3"
            and normalize_ip(fields.get("ipAddress")) == "10.40.0.10"
            for eid, _, fields in records
        ):
            raise ValueError("Missing SMB success from Kali data IP")

    verify_security_canary(windows)

    guids = {
        process_guid(fields)
        for event_id, _, fields in windows
        if event_id == "1" and nonce in str(fields.get("commandLine", "")).casefold()
    }
    guids.discard("")

    def precise(value, naive_utc=False):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("missing timestamp")
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            if not naive_utc:
                raise ValueError("SystemTime must include timezone")
            dt = dt.replace(tzinfo=UTC)
        whole = dt.astimezone(UTC).replace(microsecond=0) - datetime(1970, 1, 1, tzinfo=UTC)
        fraction = re.search(r"\d{2}:\d{2}:\d{2}[.,](\d+)", value)
        return Decimal(whole.days * 86400 + whole.seconds) + (
            Decimal("0." + fraction[1]) if fraction else 0
        )

    clock_ids, clock_rows = set(), 0
    for event_id, system, fields in windows:
        if event_id not in {"1", "3", "22"} or process_guid(fields) not in guids:
            continue
        system_value = precise(system.get("systemTime"))
        event_value = precise(fields.get("utcTime"), True)
        delta = abs(system_value - event_value)
        lower, upper = precise(since) - 5, precise(decision_at.isoformat()) + 5
        if not lower <= system_value <= upper or not lower <= event_value <= upper:
            raise ValueError("Canary exported timestamp is outside the fresh capture interval")
        if delta > 5:
            raise ValueError(
                f"Canary Sysmon time mismatch record={system.get('eventRecordID')} delta={delta}s"
            )
        clock_ids.add(event_id)
        clock_rows += 1
    if clock_ids != {"1", "3", "22"}:
        raise ValueError("Missing nonce-bound Sysmon process/network/DNS time evidence")
    transactions = []
    http_ports, queries, responses = set(), set(), set()
    for payload in payloads:
        event_type = payload.get("event_type")
        url = str((payload.get("http") or {}).get("url", ""))
        names = {n.casefold() for n in suricata_dns_names(payload.get("dns")) if nonce in n}
        if event_type == "http" and f"preflight={nonce}" in url:
            if payload.get("src_ip") != "10.20.0.10" or payload.get("dest_ip") != "10.40.0.10":
                raise ValueError("Canary HTTP uses wrong data network")
            http_ports.add(payload.get("dest_port"))
            transactions.append(payload)
        elif event_type == "dns" and names:
            reverse = suricata_dns_is_response(payload.get("dns"))
            expected_ips = ("10.40.0.10", "10.20.0.10") if reverse else ("10.20.0.10", "10.40.0.10")
            if (payload.get("src_ip"), payload.get("dest_ip")) != expected_ips:
                raise ValueError("Canary DNS uses wrong data network")
            (responses if reverse else queries).update(names)
            transactions.append(payload)
    expected = {
        f"{nonce}-{marker}0-{n:02d}.{domain}"
        for marker, domain in [("b", "www.datn.test"), ("r", "beacon.datn.test")]
        for n in (1, 2)
    }
    if http_ports != {8080, 8081, 9001} or not expected <= queries or not expected <= responses:
        raise ValueError("Waiting for all three HTTP ports and four DNS request/response pairs")
    keys = {flow_connection_key(row) for row in transactions}
    if not keys or None in keys:
        raise ValueError("Missing/invalid full tuple, protocol or flow_id in transaction")
    finals = [
        row
        for row in payloads
        if row.get("event_type") == "flow" and flow_connection_key(row) in keys
    ]
    issues = flow_counter_issues(
        transactions + finals,
        window_start=started - timedelta(seconds=5),
        window_end=decision_at + timedelta(seconds=5),
    )
    if issues:
        raise ValueError("Canary final-flow check: " + ",".join(issues))
    return {
        "canary_id": nonce,
        "http_ports": sorted(http_ports),
        "dns_queries": sorted(queries),
        "dns_responses": sorted(responses),
        "transaction_connections": len(keys),
        "sysmon_time_rows": clock_rows,
        "final_connections": len({flow_connection_key(row) for row in finals}),
        "flow_issues": issues,
        "capture_started_at": since,
        "checked_at": decision_at.isoformat(),
    }
