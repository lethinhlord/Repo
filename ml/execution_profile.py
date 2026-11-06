"""Frozen, label-independent action schedules for the controlled four-VM lab."""

from __future__ import annotations

import hashlib
import math
import random
from typing import Any

_COMMON = {"transport", "expected_action_count", "base_intervals_seconds"}
_ALLOWED = {
    "console": _COMMON | {"accounts_csv", "attempts_csv"},
    "smb": _COMMON | {"accounts_csv", "attempts_csv"},
    "http": _COMMON | {"endpoint"},
    "dns": _COMMON | {"domain_suffix", "dns_server"},
}
LAB_ACCOUNTS = frozenset({"datn_lab01", "datn_lab02", "datn_lab03"})


def profile_intervals(profile: dict[str, Any]) -> list[float]:
    transport = profile.get("transport")
    if transport not in _ALLOWED or set(profile) != _ALLOWED[transport]:
        raise ValueError("execution profile has missing, unknown or unsupported fields")
    if any(not isinstance(v, str) for k, v in profile.items() if k != "expected_action_count"):
        raise ValueError("execution profile text fields must be strings")
    count = profile["expected_action_count"]
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 64:
        raise ValueError("profile action count must be an integer in 1..64")
    text = profile["base_intervals_seconds"]
    if not isinstance(text, str):
        raise ValueError("profile intervals must be CSV text")
    gaps = [] if text == "" else [float(x) for x in text.split(",")]
    if len(gaps) != count - 1 or any(not math.isfinite(x) or not 1 <= x <= 300 for x in gaps):
        raise ValueError("profile intervals do not match its finite action schedule")
    if sum(gaps) * 1.3 >= 240:
        raise ValueError("profile worst-case schedule leaves insufficient bucket reserve")
    if transport in {"console", "smb"}:
        users = profile["accounts_csv"].split(",")
        actions = [x.split(":") for x in profile["attempts_csv"].split(",")]
        if (
            not users
            or len(users) != len(set(users))
            or not set(users) <= LAB_ACCOUNTS
            or len(actions) != count
            or any(
                len(a) != 2 or a[0] not in users or a[1] not in {"fail", "success"} for a in actions
            )
            or {a[0] for a in actions} != set(users)
        ):
            raise ValueError("account profile must name exact disposable lab account actions")
    elif transport == "http" and profile["endpoint"] != "http://10.40.0.10:8081/beacon":
        raise ValueError("HTTP profile must use the shared isolated lab endpoint")
    elif transport == "dns" and (
        profile["domain_suffix"] != "www.datn.test" or profile["dns_server"] != "10.40.0.10"
    ):
        raise ValueError("DNS profile must use the shared isolated lab resolver and inventory")
    return gaps


def freeze_execution_profile(
    profile: dict[str, Any],
    rng: random.Random,
    common: dict[str, Any],
    run_id: str,
    seed: int,
) -> dict[str, Any]:
    gaps = profile_intervals(profile)
    percent = rng.randint(10, 30)
    direction = rng.choice((-1, 1))
    factor = 1 + direction * percent / 100
    return {
        **common,
        **profile,
        "execution_profile_version": "lab-action-profile-v1",
        "interval_jitter_percent": percent,
        "interval_jitter_direction": direction,
        "variant_index": rng.randint(0, 999_999),
        "run_nonce": hashlib.sha256(f"{run_id}:{seed}".encode()).hexdigest()[:16],
        "expected_intervals_seconds": ",".join(str(round(x * factor, 3)) for x in gaps),
    }


def validate_frozen_profile(profile: dict[str, Any], parameters: dict[str, Any]) -> None:
    gaps = profile_intervals(profile)
    if any(
        parameters.get(k) != v or type(parameters.get(k)) is not type(v) for k, v in profile.items()
    ):
        raise ValueError("frozen execution parameters differ from the catalog profile")
    percent = parameters.get("interval_jitter_percent")
    direction = parameters.get("interval_jitter_direction")
    if (
        isinstance(percent, bool)
        or not isinstance(percent, int)
        or not 10 <= percent <= 30
        or isinstance(direction, bool)
        or direction not in {-1, 1}
        or parameters.get("execution_profile_version") != "lab-action-profile-v1"
    ):
        raise ValueError("invalid frozen profile jitter/version")
    expected = ",".join(str(round(x * (1 + direction * percent / 100), 3)) for x in gaps)
    if parameters.get("expected_intervals_seconds") != expected:
        raise ValueError("frozen timing differs from the declared profile and jitter")


def validate_account_observations(parameters: dict[str, Any], observations: list) -> None:
    if parameters.get("execution_profile_version") != "lab-action-profile-v1":
        return
    rows = sorted(observations, key=lambda item: item.timestamp)
    observed = [f"{row.account.casefold()}:{'success' if row.success else 'fail'}" for row in rows]
    if observed != parameters["attempts_csv"].split(","):
        raise ValueError("observed account sequence differs from the frozen profile")
    expected = (
        []
        if not parameters["expected_intervals_seconds"]
        else [float(s) for s in parameters["expected_intervals_seconds"].split(",")]
    )
    actual = [
        (b.timestamp - a.timestamp).total_seconds() for a, b in zip(rows, rows[1:], strict=False)
    ]
    if len(actual) != len(expected) or any(
        abs(a - b) > max(3.0, b * 0.20) for a, b in zip(actual, expected, strict=True)
    ):
        raise ValueError("observed account timing differs from the frozen profile")
