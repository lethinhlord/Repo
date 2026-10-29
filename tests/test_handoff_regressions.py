"""Regression specifications from the 2026-10-28 collection handoff audit.

Windows events are deterministic test telemetry. The flow-counter unit tests use
actual Suricata 8.0.7 output from an offline synthetic PCAP, with deliberately
reduced quality gates to isolate one flow; they are not full-catalog VM acceptance.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import math
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from api.app.contracts import WazuhAlert
from ml.context import BaselineSnapshot, load_baseline
from ml.feature_pipeline import aggregate_wazuh_alerts
from ml.scenario_collection import (
    CollectionError,
    QualityGates,
    RunDraft,
    SourceConfig,
    _derive_c2,
    begin_action,
    create_run_draft,
    start_run,
    validate_run,
)

ROOT = Path(__file__).resolve().parents[1]
EVE_FIXTURE = ROOT / "fixtures/collection-audit-suricata8-eve.jsonl"


def test_full_capture_background_cannot_be_hidden_by_scenario_nonce(
    tmp_path: Path, acceptance: ModuleType, monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, sources, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(x for x in catalog.scenarios if x.scenario_id == 'C2-BENIGN-SINGLE-DOWNLOAD')
    original = acceptance._c2_events

    def with_background(*args, **kwargs):
        rows, ended = original(*args, **kwargs)
        extra = copy.deepcopy([x for x in rows if x.get('data', {}).get('win')])
        for index, item in enumerate(extra):
            item['id'] = f'unrelated-background-{index}'
            fields = item['data']['win']['eventdata']
            fields['processGuid'] = '{BACKGROUND-PROCESS}'
            if 'commandLine' in fields:
                fields['commandLine'] = 'curl.exe https://ordinary-service.local/status'
            if 'destinationIp' in fields:
                fields['destinationIp'] = '10.40.0.99'
        return rows + extra, ended

    monkeypatch.setattr(acceptance, '_c2_events', with_background)
    with pytest.raises(CollectionError, match='full.capture|parity'):
        acceptance._collect_run(tmp_path, archive, sources, scenario, sequence=0, repeat=0)
    assert list((tmp_path/'evidence/scenario-runs').glob('*/archive_capture.jsonl'))


def test_start_freezes_the_context_bytes_it_validated_before_a_concurrent_publish(
    tmp_path: Path, acceptance: ModuleType, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib

    import ml.scenario_collection as collector
    _, sources, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(x for x in catalog.scenarios if x.family == 'account')
    context_path = tmp_path/'evidence/context-baseline.json'
    validated = context_path.read_bytes()
    started = acceptance.COLLECTION_BASE
    draft = tmp_path/'run-drafts/CONTEXT-PUBLISH-RACE.yaml'
    create_run_draft(tmp_path/'config/scenario-catalog.yaml', scenario.scenario_id,
        'CONTEXT-PUBLISH-RACE', 'unit-race', draft,
        clock_preflight=acceptance._clock_preflight(started))
    original = collector._normalized_source

    def publish_after_validation(*args, **kwargs):
        replacement = json.loads(validated)
        replacement['revision'] = 'CONCURRENT-NEW-REVISION'
        replacement['source_capture_sha256'] = 'b'*64
        context_path.write_text(json.dumps(replacement), encoding='utf-8')
        return original(*args, **kwargs)

    monkeypatch.setattr(collector, '_normalized_source', publish_after_validation)
    start_run(draft, sources, tmp_path, now=started)
    evidence = tmp_path/'evidence/scenario-runs/CONTEXT-PUBLISH-RACE'
    frozen = (evidence/'context-baseline.json').read_bytes()
    assert frozen == validated
    assert json.loads(frozen)['source_capture_sha256'] == hashlib.sha256(
        (evidence/'context-capture.jsonl').read_bytes(),
    ).hexdigest()


@pytest.fixture
def acceptance() -> ModuleType:
    # A fresh module keeps monkeypatched fixture clocks/events isolated per test.
    path = ROOT / "tests/test_collection_acceptance.py"
    spec = importlib.util.spec_from_file_location("handoff_acceptance_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def online_features(
    rows: list[dict[str, Any]], baseline: BaselineSnapshot | None = None,
) -> dict[str, float]:
    alerts = []
    for index, row in enumerate(rows):
        envelope = copy.deepcopy(row)
        envelope.update(
            id=f"handoff-regression-{index}",
            rule={"id": "audit-unit", "level": 3},
            location="handoff-test-telemetry",
        )
        alerts.append(WazuhAlert.model_validate(envelope))
    batch = aggregate_wazuh_alerts(alerts, baseline=baseline)
    assert len(batch.incidents) == 1
    return batch.incidents[0].incident.features


def test_second_action_cannot_reuse_a_finalized_runs_utc_bucket(
    tmp_path: Path, acceptance: ModuleType,
) -> None:
    archive, sources, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(
        item for item in catalog.scenarios
        if item.scenario_id == "C2-BENIGN-SINGLE-DOWNLOAD"
    )
    acceptance._collect_run(
        tmp_path, archive, sources, scenario, sequence=0, repeat=0,
    )
    second_start = acceptance.COLLECTION_BASE + timedelta(seconds=175)
    second_id = "SECOND-SHORT-RUN-SAME-BUCKET"
    draft_path = tmp_path / "run-drafts" / f"{second_id}.yaml"
    create_run_draft(
        tmp_path / "config/scenario-catalog.yaml",
        scenario.scenario_id,
        second_id,
        "handoff-regression",
        draft_path,
        collection_seed=12345,
        clock_preflight=acceptance._clock_preflight(second_start),
    )
    start_run(draft_path, sources, tmp_path, now=second_start)

    with pytest.raises(CollectionError):
        begin_action(second_id, tmp_path, now=second_start + timedelta(seconds=5))

    evidence = tmp_path / "evidence/scenario-runs" / second_id
    state = json.loads((evidence / ".collection_state.json").read_text())
    assert state["execution_receipt"] is None
    assert not (evidence / "execution_receipt.json").exists()


def test_restored_run_validates_without_original_checkout_or_live_archive(
    tmp_path: Path, acceptance: ModuleType,
) -> None:
    original = tmp_path / "original"
    original.mkdir()
    archive, sources, catalog = acceptance._prepare_collection_root(original)
    scenario = next(
        item for item in catalog.scenarios
        if item.scenario_id == "C2-BENIGN-SINGLE-DOWNLOAD"
    )
    run_id = acceptance._collect_run(
        original, archive, sources, scenario, sequence=0, repeat=0,
    )
    restored = tmp_path / "different-home" / "restored-checkout"
    shutil.copytree(original, restored)
    # A portable verifier must use evidence snapshots, not the live source.
    archive.unlink()

    assert validate_run(run_id, restored) == {
        "status": "VALID", "run_id": run_id, "family": "c2", "label": "benign",
    }

    incidents = restored / "data/raw" / run_id / "incidents.jsonl"
    incidents.write_bytes(incidents.read_bytes() + b"\n")
    with pytest.raises(CollectionError, match="checksum"):
        validate_run(run_id, restored)


def test_equivalent_ip_forms_produce_identical_offline_and_online_features(
    tmp_path: Path, acceptance: ModuleType, monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, sources, catalog = acceptance._prepare_collection_root(tmp_path)
    scenario = next(
        item for item in catalog.scenarios
        if item.scenario_id == "C2-BENIGN-IRREGULAR-API"
    )
    original_events = acceptance._c2_events

    def mixed_ip_events(*args: Any, **kwargs: Any):
        rows, ended = original_events(*args, **kwargs)
        count = 0
        for row in rows:
            win = row.get("data", {}).get("win", {})
            if win.get("system", {}).get("eventID") == "3":
                if count % 2:
                    win["eventdata"]["destinationIp"] = "::ffff:10.40.0.10"
                count += 1
        assert count == 4
        return rows, ended

    monkeypatch.setattr(acceptance, "_c2_events", mixed_ip_events)
    run_id = acceptance._collect_run(
        tmp_path, archive, sources, scenario, sequence=0, repeat=0,
    )
    incident = json.loads((tmp_path / "data/raw" / run_id / "incidents.jsonl").read_text())
    evidence_path = tmp_path / "evidence/scenario-runs" / run_id / "wazuh_archives.jsonl"
    rows = [json.loads(line) for line in evidence_path.read_text().splitlines()]
    offline = incident["features"]
    online = online_features(rows, load_baseline(tmp_path / "evidence/context-baseline.json"))

    assert validate_run(run_id, tmp_path)["status"] == "VALID"
    assert offline["outbound_connection_count"] == online["outbound_connection_count"] == 4
    assert offline["unique_destination_count"] == online["unique_destination_count"] == 1
    assert offline == online


@pytest.mark.parametrize(
    ("kind", "port", "expected_bytes"), [("http", 8081, 654), ("dns", 53, 202)],
)
def test_real_eve_flow_counters_count_each_direction_once(
    tmp_path: Path, acceptance: ModuleType, kind: str, port: int, expected_bytes: int,
) -> None:
    """One-flow feature derivation, not proof of a finalized catalog collection."""
    _, sources_path, catalog = acceptance._prepare_collection_root(tmp_path)
    source = SourceConfig.model_validate(yaml.safe_load(sources_path.read_text()))
    taxonomy = yaml.safe_load(
        (tmp_path / "config/suspicious-process-taxonomy.yaml").read_text()
    )
    eve = [json.loads(line) for line in EVE_FIXTURE.read_text().splitlines()]
    nonce = "auditnonce123"
    query = f"{nonce}-r7-01.www.datn.test"
    if kind == "http":
        scenario_id = "C2-BENIGN-HEALTH-POLL"
        selected = [row for row in eve if row.get("dest_port") == port]
        first = datetime(2026, 10, 28, 0, 0, 20, tzinfo=UTC)
        image = "curl.exe"
        command = f"curl.exe http://10.40.0.10:8081/beacon?run={nonce}"
        action_event = {
            "image": image,
            "sourceIp": "10.20.0.10",
            "sourcePort": str(selected[0]["src_port"]),
            "protocol": str(selected[0]["proto"]),
            "destinationIp": "10.40.0.10",
            "destinationPort": "8081",
            "initiated": "true",
        }
        event_id = 3
        gates = QualityGates(min_process_events=1, min_network_events=1, min_suricata_events=1)
    else:
        scenario_id = "C2-BENIGN-DNS"
        flow_id = next(
            row["flow_id"] for row in eve if query in json.dumps(row.get("dns", {}))
        )
        selected = [row for row in eve if row.get("flow_id") == flow_id]
        first = datetime(2026, 10, 28, 0, 0, 10, tzinfo=UTC)
        image = "powershell.exe"
        command = f"powershell.exe Resolve-DnsName {query}"
        action_event = {"image": image, "queryName": query}
        event_id = 22
        gates = QualityGates(min_process_events=1, min_dns_events=1, min_suricata_events=1)
    scenario = next(item for item in catalog.scenarios if item.scenario_id == scenario_id)
    draft = RunDraft(
        scenario_id="UNIT-FLOW-COUNTER",
        run_id=f"UNIT-{kind.upper()}-FLOW",
        family="c2",
        label="benign",
        host="WIN11-TARGET",
        expected_behavior="Derive bytes for one attributable offline PCAP flow.",
        operator="unit-test",
        attribution=scenario.attribution,
        quality_gates=gates,
        collection_seed=42,
        scenario_parameters={
            "run_nonce": nonce,
            "expected_action_count": 1,
            "expected_intervals_seconds": "",
        },
        expected_observables=["one Sysmon action and its real Suricata flow"],
        clock_preflight=acceptance._clock_preflight(first),
    )
    guid = "{HANDOFF-UNIT-FLOW}"
    windows = [
        acceptance._windows_event(
            "unit-flow", first - timedelta(milliseconds=100), 1,
            {"image": image, "commandLine": command, "processGuid": guid}, 0,
        ),
        acceptance._windows_event(
            "unit-flow", first, event_id, {**action_event, "processGuid": guid}, 1,
        ),
    ]
    rows = windows + [
        acceptance._suricata_event(datetime.fromisoformat(row["timestamp"]), row)
        for row in selected
    ]
    final = next(row["flow"] for row in selected if row["event_type"] == "flow")
    assert final["bytes_toserver"] + final["bytes_toclient"] == expected_bytes

    offline, _, _, _ = _derive_c2(rows, draft, source, taxonomy)
    expected_feature = round(math.log1p(expected_bytes), 6)
    assert offline["flow_total_bytes_log1p"] == expected_feature
    assert online_features(rows)["flow_total_bytes_log1p"] == expected_feature
