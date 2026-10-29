"""Independent check of incomplete account telemetry handling."""

import pytest
from test_feature_state import raw_account_alert

from api.app.feature_state import FeatureStateStore
from ml.feature_pipeline import aggregate_wazuh_alerts


@pytest.mark.parametrize("missing", ["targetUserName", "logonType"])
def test_incomplete_account_event_remains_visible_as_unknown(missing):
    alert = raw_account_alert("INCOMPLETE", "2026-10-27T00:00:05Z", 4624)
    alert.data.win["eventdata"].pop(missing, None)
    batch = aggregate_wazuh_alerts([alert], use_runtime_baseline=False)
    assert len(batch.incidents) == 1
    assert batch.incidents[0].incident.family_hint == "unknown"
    assert batch.incidents[0].quality_status == "PARTIAL"


def test_os_only_window_can_be_ingested_and_closed(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    timestamp = datetime(2026, 10, 27, tzinfo=UTC).timestamp()
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: timestamp + 20)
    alert = raw_account_alert("BACKGROUND", "2026-10-27T00:00:05Z", 4624)
    alert.data.win["eventdata"].update({"targetUserName": "SYSTEM", "logonType": "5"})
    store = FeatureStateStore(tmp_path / "state.sqlite3")
    assert store.ingest(alert).feature.incident.family_hint == "unknown"
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: timestamp + 400)
    assert store.finalize_window(alert.id).feature.quality_status == "PARTIAL"
