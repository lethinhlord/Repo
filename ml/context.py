"""Independent, immutable-as-of history; no scenario labels or inferred approval."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ml.behavior_features import AccountObservation, NetworkObservation
from ml.telemetry import (
    account_observation_eligible,
    account_source,
    account_user,
    basename,
    event_time,
    network_is_outbound,
    normalize_ip,
    windows_fields,
)

CONTEXT_FEATURES = (
    "source_history_known", "new_source_for_user",
    "destination_history_known", "new_destination",
)


class AccountHistory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=1)
    account: str = Field(min_length=1)
    known_sources: list[str] = Field(min_length=1)


class DestinationHistory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    port: int = Field(gt=0, le=65535)
    process_images: list[str] = Field(min_length=1)
    match: Literal["exact", "dns_suffix"] = "exact"


class BaselineSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["context-baseline-v1"]
    revision: str = Field(min_length=1, max_length=128)
    captured_at: datetime
    observed_through: datetime
    valid_until: datetime
    source_capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accounts: list[AccountHistory]
    destinations: list[DestinationHistory]

    @field_validator("captured_at", "observed_through", "valid_until")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("context timestamps require a timezone")
        return value

    @model_validator(mode="after")
    def chronological(self) -> BaselineSnapshot:
        if not self.observed_through <= self.captured_at < self.valid_until:
            raise ValueError("context must be observed before capture and expire afterwards")
        accounts = [(x.asset_id.casefold(), x.account.casefold()) for x in self.accounts]
        if len(set(accounts)) != len(accounts):
            raise ValueError("duplicate account history")
        destinations = [
            (x.asset_id.casefold(), normalize_ip(x.destination), x.port, x.match)
            for x in self.destinations
        ]
        if len(set(destinations)) != len(destinations):
            raise ValueError("duplicate destination history")
        return self


@dataclass(frozen=True)
class ContextAssessment:
    status: Literal["AVAILABLE", "MISSING", "STALE", "FUTURE", "UNKNOWN"]
    revision: str | None
    features: dict[str, float]
    review_reasons: list[str]


def load_baseline(path: Path | None) -> BaselineSnapshot | None:
    if path is None or not path.is_file():
        return None
    return BaselineSnapshot.model_validate_json(path.read_text(encoding="utf-8"))


def assess_context(
    snapshot: BaselineSnapshot | None, *, at: datetime, asset_id: str,
    accounts: list[AccountObservation] | tuple = (),
    network: list[NetworkObservation] | tuple = (),
) -> ContextAssessment:
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("context as-of requires a timezone")
    times = [item.timestamp for item in (*accounts, *network)]
    if any(value.tzinfo is None or value.utcoffset() is None or value > at for value in times):
        raise ValueError("observations must be timezone-aware and not after the decision as-of")
    features = dict.fromkeys(CONTEXT_FEATURES, 0.0)
    revision = snapshot.revision if snapshot else None

    def unavailable(status: str) -> ContextAssessment:
        return ContextAssessment(status, revision, features, [f"context:{status.lower()}"])

    if snapshot is None:
        return unavailable("MISSING")
    if snapshot.captured_at > min(times, default=at):
        return unavailable("FUTURE")
    if snapshot.valid_until <= at:
        return unavailable("STALE")
    reasons = []
    known = {
        item.account.casefold(): {normalize_ip(x) for x in item.known_sources}
        for item in snapshot.accounts if item.asset_id.casefold() == asset_id.casefold()
    }
    if accounts:
        if all(item.account.casefold() in known for item in accounts):
            features["source_history_known"] = 1.0
            features["new_source_for_user"] = float(any(
                normalize_ip(item.source) not in known[item.account.casefold()]
                for item in accounts
            ))
        else:
            reasons.append("context:unknown_account_history")
    history = [
        item for item in snapshot.destinations if item.asset_id.casefold() == asset_id.casefold()
    ]
    if network:
        if history:
            features["destination_history_known"] = 1.0
            def matches(observation: NetworkObservation, item: DestinationHistory) -> bool:
                destination = normalize_ip(observation.destination).strip(".")
                expected = normalize_ip(item.destination).strip(".")
                name_matches = destination == expected or (
                    item.match == "dns_suffix" and observation.dns_query is not None
                    and destination.endswith("." + expected)
                )
                return name_matches and observation.destination_port == item.port
            features["new_destination"] = float(any(
                not any(matches(observation, item) for item in history) for observation in network
            ))
        else:
            reasons.append("context:unknown_destination_history")
    return ContextAssessment("UNKNOWN" if reasons else "AVAILABLE", revision, features, reasons)


def build_baseline(
    events: list[dict], *, revision: str, captured_at: datetime, valid_until: datetime,
    source_capture_sha256: str, windows_agent_name: str = "WIN11-TARGET",
) -> BaselineSnapshot:
    """Enroll only observed successful logons and outbound activity from an approved capture."""
    if captured_at.tzinfo is None or captured_at.utcoffset() is None:
        raise ValueError("baseline capture time requires a timezone")
    accounts: dict[tuple[str, str], set[str]] = {}
    destinations: dict[tuple[str, str, int], set[str]] = {}
    times = []
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("agent"), dict):
            raise ValueError("enrollment records require an agent object")
        if event["agent"].get("name") != windows_agent_name:
            continue
        at = event_time(event)
        if at is None or at > captured_at:
            raise ValueError("baseline capture contains missing/future source event timestamps")
        event_id, _, fields = windows_fields(event)
        asset = windows_agent_name.casefold()
        if event_id == "4624" and account_observation_eligible(fields):
            key = (asset, account_user(fields))
            accounts.setdefault(key, set()).add(account_source(fields))
            times.append(at)
        elif event_id in {"3", "22"} and basename(fields.get("image")):
            if event_id == "3":
                if not network_is_outbound(fields):
                    continue
                destination = normalize_ip(fields.get("destinationIp"))
                raw_port = fields.get("destinationPort")
                if isinstance(raw_port, bool) or not str(raw_port).isdigit():
                    raise ValueError("invalid baseline destination port")
                try:
                    port = int(raw_port)
                except (TypeError, ValueError) as exc:
                    raise ValueError("invalid baseline destination port") from exc
            else:
                destination = str(fields.get("queryName", "")).casefold().strip(".")
                port = 53
            if not destination or not 0 < port <= 65535:
                raise ValueError("invalid baseline destination/port")
            destinations.setdefault((asset, destination, port), set()).add(
                basename(fields.get("image"))
            )
            times.append(at)
    if not times:
        raise ValueError("baseline capture contains no usable enrollment telemetry")
    return BaselineSnapshot(
        version="context-baseline-v1", revision=revision, captured_at=captured_at,
        observed_through=max(times), valid_until=valid_until,
        source_capture_sha256=source_capture_sha256,
        accounts=[AccountHistory(asset_id=asset, account=user, known_sources=sorted(sources))
                  for (asset, user), sources in sorted(accounts.items())],
        destinations=[DestinationHistory(
            asset_id=asset, destination=destination, port=port, process_images=sorted(images),
        ) for (asset, destination, port), images in sorted(destinations.items())],
    )


def with_dns_suffix_history(snapshot: BaselineSnapshot, suffixes: list[str]) -> BaselineSnapshot:
    """Promote observed DNS history to an explicit pre-run inventory boundary.

    This is destination matching, not an approval/benign feature. Unobserved,
    wildcard or overlapping inventory cannot silently trust future names.
    """
    normalized = []
    for value in suffixes:
        name = value.strip().strip('.').casefold().encode('idna').decode('ascii')
        labels = name.split('.')
        try:
            ipaddress.ip_address(name)
        except ValueError:
            pass
        else:
            raise ValueError('DNS suffix inventory must not contain IP addresses')
        if len(labels) < 2 or len(name) > 253 or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in labels
        ):
            raise ValueError('DNS suffix inventory requires specific valid domain suffixes')
        if any(name == other or name.endswith('.'+other) or other.endswith('.'+name)
               for other in normalized):
            raise ValueError('DNS suffix inventory must be unique and nonoverlapping')
        normalized.append(name)
    seen = set()
    grouped: dict[tuple[str, str, int, str], set[str]] = {}
    for item in snapshot.destinations:
        destination, match = item.destination, item.match
        if item.port == 53:
            for suffix in normalized:
                if destination == suffix or destination.endswith('.'+suffix):
                    seen.add(suffix)
                    destination, match = suffix, 'dns_suffix'
                    break
        key = (item.asset_id.casefold(), destination, item.port, match)
        grouped.setdefault(key, set()).update(item.process_images)
    if set(normalized) != seen:
        missing = sorted(set(normalized) - seen)
        raise ValueError(f'DNS suffix inventory has no enrollment evidence: {missing}')
    return BaselineSnapshot.model_validate({
        **snapshot.model_dump(),
        'destinations': [DestinationHistory(
            asset_id=asset, destination=destination, port=port, match=match,
            process_images=sorted(images),
        ) for (asset, destination, port, match), images in sorted(grouped.items())],
    })


def context_from_events(
    snapshot: BaselineSnapshot | None, events: list[dict], *, at: datetime, asset_id: str,
) -> ContextAssessment:
    """Apply identical history semantics to already-attributed offline/online rows."""
    accounts = []
    network = []
    for event in events:
        event_id, _, fields = windows_fields(event)
        timestamp = event_time(event)
        if timestamp is None:
            continue
        if event_id in {"4624", "4625"} and account_observation_eligible(fields):
            accounts.append(AccountObservation(
                timestamp, account_user(fields), account_source(fields),
                str(fields.get("logonType", fields.get("LogonType", ""))), event_id == "4624",
            ))
        elif event_id == "3" and network_is_outbound(fields):
            network.append(NetworkObservation(
                timestamp, normalize_ip(fields.get("destinationIp")),
                int(fields["destinationPort"]),
            ))
        elif event_id == "22" and fields.get("queryName"):
            query = str(fields["queryName"]).strip(".").casefold()
            network.append(NetworkObservation(timestamp, query, 53, query))
    return assess_context(snapshot, at=at, asset_id=asset_id, accounts=accounts, network=network)
