import json
from datetime import datetime, timezone
from types import SimpleNamespace

import yaml

from api.app.contracts import WazuhAlert
from ml import scenario_collection as sc
from ml import feature_pipeline as fp


def make_alert(agent, timestamp, data, decoder=None):
    payload = {
        "id": f"test-{agent}-{timestamp}",
        "timestamp": timestamp,
        "agent": {"name": agent},
        "rule": {"id": "100", "level": 0},
        "data": data,
    }
    if decoder:
        payload["decoder"] = {"name": decoder}
    return WazuhAlert.model_validate(payload)


def test_sensor_os_log_remains_sensor_asset():
    config = {
        "windows_agent_name": "WIN11-TARGET",
        "suricata_agent_name": "NET-SENSOR",
    }
    ssh = make_alert(
        "NET-SENSOR",
        "2026-11-14T06:51:32Z",
        {},
        decoder="sshd",
    )
    assert fp._aggregation_key(ssh, config) == (
        "net-sensor", "account", "unknown-source"
    )

    eve = make_alert(
        "NET-SENSOR",
        "2026-11-14T06:51:33Z",
        {
            "event_type": "http",
            "src_ip": "10.20.0.10",
            "dest_ip": "10.40.0.10",
            "dest_port": 8081,
            "http": {"url": "/beacon"},
        },
    )
    assert fp._asset_id(eve, config) == "WIN11-TARGET"


def test_parity_uses_action_window_not_session_window(
    tmp_path, monkeypatch
):
    receipt = {
        "action_started_at": "2026-11-14T06:50:05Z",
        "aggregation_window_start": "2026-11-14T06:50:00Z",
        "aggregation_window_end": "2026-11-14T06:55:00Z",
    }
    (tmp_path / "execution_receipt.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )

    config = yaml.safe_load(
        open("config/collection-sources.yaml", encoding="utf-8")
    )
    source = sc.SourceConfig.model_validate(config)

    def raw_event(timestamp):
        return make_alert(
            "WIN11-TARGET",
            timestamp,
            {
                "win": {
                    "system": {
                        "eventID": "4625",
                        "systemTime": timestamp,
                    },
                    "eventdata": {
                        "targetUserName": "datn_lab01",
                        "ipAddress": "10.40.0.10",
                        "logonType": "3",
                    },
                }
            },
            decoder="windows_eventchannel",
        ).model_dump(mode="json", exclude_none=True)

    captured = [
        raw_event("2026-11-14T06:47:12Z"),
        raw_event("2026-11-14T06:50:12Z"),
    ]

    incident = SimpleNamespace(
        asset_id="WIN11-TARGET",
        family_hint="account",
        start_time=datetime(
            2026, 11, 14, 6, 47, 35, tzinfo=timezone.utc
        ),
    )

    def fake_aggregate(alerts, **kwargs):
        assert len(alerts) == 1
        assert sc._event_time(captured[1]) == sc._event_time(
            alerts[0].model_dump(mode="json")
        )
        return SimpleNamespace(
            incidents=[SimpleNamespace(incident=incident)]
        )

    monkeypatch.setattr(sc, "aggregate_wazuh_alerts", fake_aggregate)
    monkeypatch.setattr(sc, "load_baseline", lambda path: None)
    monkeypatch.setattr(sc, "_load_taxonomy", lambda path: {})

    result = sc._verify_full_capture_parity(
        captured, incident, source, tmp_path, compare=False
    )
    assert result is incident
