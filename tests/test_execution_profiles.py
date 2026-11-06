import random

import pytest

from ml.execution_profile import freeze_execution_profile, validate_frozen_profile


def profile(count=3):
    return {
        "transport": "http",
        "endpoint": "http://10.40.0.10:8081/beacon",
        "expected_action_count": count,
        "base_intervals_seconds": "2,2" if count == 3 else "",
    }


def test_freeze_profile_is_label_free_reproducible_and_bound():
    value = freeze_execution_profile(profile(), random.Random(7), {}, "RUN-TEST", 7)
    assert value == freeze_execution_profile(profile(), random.Random(7), {}, "RUN-TEST", 7)
    assert value["expected_action_count"] == 3
    assert len(value["expected_intervals_seconds"].split(",")) == 2
    validate_frozen_profile(profile(), value)
    value["endpoint"] = "http://example.com/"
    with pytest.raises(ValueError):
        validate_frozen_profile(profile(), value)


@pytest.mark.parametrize(
    "change",
    [
        {"expected_action_count": True},
        {"expected_action_count": 0},
        {"base_intervals_seconds": "NaN,2"},
        {"base_intervals_seconds": "100,100"},
        {"base_intervals_seconds": "2"},
        {"endpoint": "http://example.com"},
        {"unexpected": "ignored"},
    ],
)
def test_unsafe_or_inconsistent_profile_rejected(change):
    with pytest.raises(ValueError):
        freeze_execution_profile({**profile(), **change}, random.Random(1), {}, "RUN-TEST", 1)


def test_single_request_has_no_gap_and_account_sequence_exact():
    one = freeze_execution_profile(profile(1), random.Random(1), {}, "RUN-ONE", 1)
    assert one["expected_intervals_seconds"] == ""
    account = {
        "transport": "console",
        "accounts_csv": "datn_lab01",
        "attempts_csv": "datn_lab01:fail,datn_lab01:success",
        "expected_action_count": 2,
        "base_intervals_seconds": "5",
    }
    frozen = freeze_execution_profile(account, random.Random(1), {}, "RUN-ACCOUNT", 1)
    validate_frozen_profile(account, frozen)
    frozen["attempts_csv"] = "datn_lab01:success,datn_lab01:fail"
    with pytest.raises(ValueError):
        validate_frozen_profile(account, frozen)
