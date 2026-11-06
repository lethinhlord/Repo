from datetime import UTC, datetime, timedelta

import pytest

from ml.behavior_features import AccountObservation
from ml.execution_profile import validate_account_observations


def test_observed_account_order_and_timing_must_match_frozen_profile():
    start = datetime(2026, 11, 6, tzinfo=UTC)
    rows = [
        AccountObservation(start, "datn_lab01", "127.0.0.1", "2", False),
        AccountObservation(start + timedelta(seconds=5), "datn_lab01", "127.0.0.1", "2", True),
    ]
    params = {
        "execution_profile_version": "lab-action-profile-v1",
        "transport": "console",
        "attempts_csv": "datn_lab01:fail,datn_lab01:success",
        "expected_intervals_seconds": "5",
    }
    validate_account_observations(params, rows)
    validate_account_observations(params, list(reversed(rows)))
    with pytest.raises(ValueError, match="sequence"):
        validate_account_observations(
            {**params, "attempts_csv": "datn_lab01:success,datn_lab01:fail"}, rows
        )
    with pytest.raises(ValueError, match="timing"):
        validate_account_observations({**params, "expected_intervals_seconds": "30"}, rows)
