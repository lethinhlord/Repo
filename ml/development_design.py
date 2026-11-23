"""Explicit three-day development scope; formal216 validation is unchanged."""

from collections import Counter
from datetime import date

PROTOCOL = "development-three-day-grouped-cv"


def validate_development_design(value: dict) -> None:
    from ml.supplemental_design import validate_design

    if (
        value.get("evaluation_protocol") != PROTOCOL
        or value.get("partition_contexts") != dict(train=12, validation=0, locked_test=0)
        or any(type(v) is not int for v in value["partition_contexts"].values())
        or type(value.get("repetitions_per_label")) is not int
        or value["repetitions_per_label"] != 1
    ):
        raise ValueError("development requires48 runs, three real days and no external assessment")
    # Reuse every shared identity/schema/actor/template restriction. Only this
    # named protocol replaces the original quota and external partition design.
    formal = {
        **value,
        "version": "supplemental-design-v1",
        "evaluation_protocol": "known-template-new-host-day",
        "partition_contexts": dict(train=10, validation=4, locked_test=4),
        "repetitions_per_label": 3,
    }
    validate_design(formal)


def validate_development_days(contexts: dict, expected: dict) -> None:
    counts = Counter(
        (expected[key]["family"], row["collection_date"]) for key, row in contexts.items()
    )
    days = sorted({date.fromisoformat(row["collection_date"]) for row in contexts.values()})
    if (
        len(days) != 3
        or (days[-1] - days[0]).days != 2
        or set(counts.values()) != {4}
        or len(counts) != 6
        or {row["partition"] for row in contexts.values()} != {"train"}
    ):
        raise ValueError("register exactly four paired contexts per family on each of3 UTC days")
