"""Fresh synthetic QA for account scope and online flow attribution; never lab evidence."""

from __future__ import annotations

import copy
import sqlite3
from datetime import UTC, datetime

import pytest
import test_collection_acceptance as acceptance
import yaml

from api.app.contracts import WazuhAlert
from api.app.feature_state import FeatureStateStore
from ml.context import load_baseline
from ml.feature_pipeline import aggregate_wazuh_alerts
from ml.scenario_collection import CollectionError


@pytest.mark.parametrize(
    "scenario_id,background",
    [
        (
            "ACCOUNT-BENIGN-NORMAL-LOGON",
            {
                "targetUserName": "DWM-1",
                "targetDomainName": "Window Manager",
                "targetUserSid": "S-1-5-90-0-1",
                "virtualAccount": "%%1842",
                "logonType": "2",
            },
        ),
        (
            "ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS",
            {
                "targetUserName": "SYSTEM",
                "targetDomainName": "NT AUTHORITY",
                "targetUserSid": "S-1-5-18",
                "logonType": "5",
                "ipAddress": "-",
            },
        ),
    ],
)
def test_full_collection_excludes_verified_background_without_changing_user_features(
    tmp_path,
    monkeypatch,
    scenario_id,
    background,
):
    archive, sources, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == scenario_id)
    original = acceptance._account_events
    captured = {}

    def events(*args, **kwargs):
        rows, ended = original(*args, **kwargs)
        extra = copy.deepcopy(rows[-1])
        extra["id"] += "-BACKGROUND"
        extra["data"]["win"]["eventdata"].update(background)
        captured.update(real=rows, background=extra)
        return rows + [extra], ended

    monkeypatch.setattr(acceptance, "_account_events", events)
    run_id = acceptance._collect_run(tmp_path, archive, sources, scenario, sequence=0, repeat=0)
    config = yaml.safe_load(sources.read_text())
    snapshot = load_baseline(tmp_path / "evidence/context-baseline.json")

    def features(rows):
        alerts = [
            WazuhAlert.model_validate({**r, "rule": {"id": "synthetic-qa", "level": 0}})
            for r in rows
        ]
        return aggregate_wazuh_alerts(
            alerts, baseline=snapshot, source_config=config, use_runtime_baseline=False
        ).incidents

    clean = features(captured["real"])
    noisy = features(captured["real"] + [captured["background"]])
    accounts = [item for item in noisy if item.incident.family_hint == "account"]
    unknown = [item for item in noisy if item.incident.family_hint == "unknown"]
    assert len(clean) == len(accounts) == len(unknown) == 1
    assert accounts[0].incident.features == clean[0].incident.features
    assert accounts[0].incident.raw_refs == clean[0].incident.raw_refs
    assert unknown[0].quality_status == "PARTIAL"
    assert f'wazuh-alert:{captured["background"]["id"]}' in unknown[0].incident.raw_refs
    raw = (tmp_path / "evidence/scenario-runs" / run_id / "archive_capture.jsonl").read_text()
    assert captured["background"]["id"] in raw  # Exclusion must not erase evidence.


@pytest.mark.parametrize("username", ["additional-real-user", "DWM-1"])
def test_full_collection_rejects_real_extra_user_and_username_only_virtual_spoof(
    tmp_path, monkeypatch, username
):
    archive, sources, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == "ACCOUNT-BENIGN-NORMAL-LOGON")
    original = acceptance._account_events

    def events(*args, **kwargs):
        rows, ended = original(*args, **kwargs)
        extra = copy.deepcopy(rows[-1])
        extra["id"] += "-EXTRA-USER"
        extra["data"]["win"]["eventdata"]["targetUserName"] = username
        return rows + [extra], ended

    monkeypatch.setattr(acceptance, "_account_events", events)
    with pytest.raises(CollectionError, match="(?i)group|unattribut|account|contaminat"):
        acceptance._collect_run(tmp_path, archive, sources, scenario, sequence=0, repeat=0)


def test_excluded_os_record_is_auditable_without_polluting_online_account_window(
    tmp_path,
    monkeypatch,
):
    from test_context_feature_contract import baseline
    from test_feature_state import raw_account_alert

    monkeypatch.setattr(
        "api.app.feature_state.aggregate_wazuh_alerts",
        lambda alerts, **kw: aggregate_wazuh_alerts(alerts, baseline=baseline(), **kw),
    )
    bucket = datetime(2026, 10, 27, tzinfo=UTC).timestamp()
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: bucket + 20)
    path = tmp_path / "state.sqlite3"
    store = FeatureStateStore(path)
    real = raw_account_alert("HUMAN", "2026-10-27T00:00:05Z", 4624)
    background = raw_account_alert("SERVICE", "2026-10-27T00:00:10Z", 4624)
    background.data.win["eventdata"].update(
        {
            "targetUserName": "SYSTEM",
            "targetDomainName": "NT AUTHORITY",
            "targetUserSid": "S-1-5-18",
            "logonType": "5",
            "ipAddress": "-",
        }
    )
    store.ingest(real)
    ignored = store.ingest(background)
    assert ignored.feature.incident.family_hint == "unknown"
    assert ignored.feature.quality_status == "PARTIAL"
    assert store.ingest(background).ingest_status == "duplicate"
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM wazuh_alerts").fetchone()[0] == 2
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: bucket + 400)
    closed = store.finalize_window(real.id)
    assert closed.stored_event_count == 1
    assert closed.feature.incident.features["successful_login_count"] == 1
    excluded_close = store.finalize_window(background.id)
    assert excluded_close.feature.incident.family_hint == "unknown"
    assert excluded_close.feature.quality_status == "PARTIAL"
    assert store.finalize_window(background.id).ingest_status == "duplicate"
