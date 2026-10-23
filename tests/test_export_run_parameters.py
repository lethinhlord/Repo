from __future__ import annotations

from ml.scenario_collection import ClockPreflight, RunDraft
from scripts.export_run_parameters import render_parameters


def clock_preflight() -> ClockPreflight:
    return ClockPreflight.model_validate(
        {
            "captured_at": "2026-10-23T00:00:02Z",
            "maximum_skew_seconds": 5,
            "controller_utc": "2026-10-23T00:00:00Z",
            "target_utc": "2026-10-23T00:00:01Z",
            "wazuh_utc": "2026-10-23T00:00:00Z",
            "sensor_utc": "2026-10-23T00:00:00Z",
            "attacker_utc": "2026-10-23T00:00:00Z",
        }
    )


def draft() -> RunDraft:
    return RunDraft.model_validate(
        {
            "scenario_id": "C2-MALICIOUS-HTTP-BEACON",
            "run_id": "C2-MALICIOUS-HTTP-BEACON-R01-20261023",
            "family": "c2",
            "label": "malicious",
            "host": "WIN11-TARGET",
            "expected_behavior": "safe lab beacon",
            "operator": "Kien",
            "attribution": {
                "source_ips": ["10.20.0.10"],
                "destination_ips": ["10.40.0.10"],
                "destination_ports": [8081],
            },
            "quality_gates": {"min_network_events": 8},
            "collection_seed": 123,
            "scenario_parameters": {
                "pre_action_delay_seconds": 1.25,
                "interval_jitter_percent": 17,
                "interval_jitter_direction": -1,
                "variant_index": 42,
            },
            "expected_observables": ["network telemetry"],
            "clock_preflight": clock_preflight().model_dump(mode="json"),
        }
    )


def test_render_powershell_parameters() -> None:
    rendered = render_parameters(draft(), "powershell")

    assert "$DatnRunId = 'C2-MALICIOUS-HTTP-BEACON-R01-20261023'" in rendered
    assert "interval_jitter_direction = -1" in rendered
    assert "variant_index = 42" in rendered


def test_render_bash_parameters() -> None:
    rendered = render_parameters(draft(), "bash")

    assert "DATN_RUN_ID=C2-MALICIOUS-HTTP-BEACON-R01-20261023" in rendered
    assert "DATN_INTERVAL_JITTER_PERCENT=17" in rendered
    assert "DATN_INTERVAL_JITTER_DIRECTION=-1" in rendered
