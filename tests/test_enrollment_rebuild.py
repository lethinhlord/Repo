import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from ml.context import build_baseline, verify_baseline_capture, verify_lab_enrollment


def test_enrollment_cannot_invent_known_sources():
    at = datetime(2026, 11, 6, tzinfo=UTC)
    event = {
        "agent": {"name": "WIN11-TARGET"},
        "data": {
            "win": {
                "system": {"eventID": "4624", "systemTime": at.isoformat()},
                "eventdata": {
                    "targetUserName": "datn_lab01",
                    "logonType": "2",
                    "ipAddress": "127.0.0.1",
                },
            }
        },
    }
    raw = (json.dumps(event) + "\n").encode()
    baseline = build_baseline(
        [event],
        revision="UNIT",
        captured_at=at,
        valid_until=at + timedelta(days=1),
        source_capture_sha256=hashlib.sha256(raw).hexdigest(),
    )
    verify_baseline_capture(baseline, raw)
    with pytest.raises(ValueError, match="all three"):
        verify_lab_enrollment(baseline, raw)
    baseline.accounts[0].known_sources.append("10.40.0.10")
    with pytest.raises(ValueError, match="reproduce"):
        verify_baseline_capture(baseline, raw)
