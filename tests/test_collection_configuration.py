from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest
import yaml

from ml.scenario_collection import (
    ClockPreflight,
    RunDraft,
    ScenarioCatalog,
    SourceConfig,
    create_run_draft,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def clock_preflight() -> ClockPreflight:
    return ClockPreflight.model_validate(
        {
            "captured_at": "2026-10-16T01:00:00Z",
            "controller_utc": "2026-10-16T01:00:00Z",
            "target_utc": "2026-10-16T01:00:00Z",
            "wazuh_utc": "2026-10-16T01:00:00Z",
            "sensor_utc": "2026-10-16T01:00:00Z",
            "attacker_utc": "2026-10-16T01:00:00Z",
            "maximum_skew_seconds": 2.0,
        }
    )


def test_c2_model_includes_observed_process_behavior_without_identity() -> None:
    schema = json.loads(
        (PROJECT_ROOT / "ml/feature_schema.json").read_text(encoding="utf-8")
    )

    assert "suspicious_process" in schema["properties"]
    assert "suspicious_process" in schema["x-family-features"]["c2"]
    assert "account_identity" in schema["x-excluded-context"]
    assert "exact_destination_identity" in schema["x-excluded-context"]


def test_collection_runbook_is_portable_isolated_and_failure_safe() -> None:
    runbook = (PROJECT_ROOT / "docs/scenario-collection-runbook.md").read_text(
        encoding="utf-8"
    )

    assert "/home/lethinh" not in runbook
    assert "scp lethinh@" not in runbook
    assert "server=1.1.1.1" not in runbook
    assert "IEX (IWR" not in runbook
    assert "OpenSSH.Client~~~~0.0.1.0" in runbook
    assert "OpenSSH.Server~~~~0.0.1.0" in runbook
    assert "MAX_CLOCK_SKEW_SECONDS=5" in runbook
    assert "BACKUP_ID=" in runbook
    assert "Checkpoint đã sealed trước lỗi bước tạo feature/output" in runbook
    assert "Chưa từng chạy intake trước cutoff" in runbook
    assert "finalize muộn báo thiếu checkpoint hợp lệ" in runbook
    assert "Connect a host virtual adapter to this network" in runbook
    assert "/etc/suricata/rules/datn.rules" in runbook
    assert "--init-errors-fatal -T" in runbook
    assert "systemctl restart suricata" in runbook
    assert "systemctl restart wazuh-agent" in runbook
    assert "wazuh-agent=$WAZUH_VERSION" in runbook
    assert "dnsutils" in runbook
    assert "END_TO_END_PREFLIGHT=PASS" in runbook
    assert "scripts.scenario_session quarantine" in runbook
    assert "curl.exe --fail --silent --show-error" in runbook
    assert "HOST_BACKUP_VERIFY=PASS" in runbook
    assert "0CCE9215-69AE-11D9-BED3-505054503030" in runbook
    assert "LogonType=2" in runbook
    assert "LogonType=3" in runbook
    assert "scripts.export_run_parameters" in runbook
    assert "DATN_ATTEMPT_DELAY_SECONDS" in runbook
    assert "payload_size_bytes" not in runbook
    assert "3-2-2-2-2" in runbook
    assert "LEGACY_DATASET_NOT_ACCEPTED=PASS" in runbook
    assert "events_raw.jsonl" in runbook
    assert "WIN11-01" in runbook
    assert "incompatible raw dataset layout" in runbook
    assert "enable --now suricata" not in runbook
    assert "enable --now wazuh-agent" not in runbook
    assert 'echo "audit_exit=$?"' not in runbook


def test_committed_source_and_taxonomy_configuration_is_valid() -> None:
    source_payload = yaml.safe_load(
        (PROJECT_ROOT / "config/collection-sources.yaml").read_text(encoding="utf-8")
    )
    source = SourceConfig.model_validate(source_payload)
    taxonomy_path = PROJECT_ROOT / source.taxonomy_path
    taxonomy = yaml.safe_load(taxonomy_path.read_text(encoding="utf-8"))

    assert source.windows_agent_name == "WIN11-TARGET"
    assert source.suricata_agent_name == "NET-SENSOR"
    assert source.scenario_catalog_path == "config/scenario-catalog.yaml"
    assert taxonomy["revision"] == "datn-process-taxonomy-v1"
    assert len(taxonomy["rules"]) >= 3


def test_sysmon_configuration_enables_required_event_families() -> None:
    root = ElementTree.parse(PROJECT_ROOT / "config/sysmon-datn.xml").getroot()
    event_filtering = root.find("EventFiltering")

    assert event_filtering is not None
    enabled = {
        child.tag
        for child in event_filtering
        if child.attrib.get("onmatch") == "exclude"
    }
    assert {"ProcessCreate", "NetworkConnect", "DnsQuery"} <= enabled


def test_windows_wazuh_snippet_adds_sysmon_without_duplicate_security_channel() -> None:
    snippet = (
        PROJECT_ROOT / "config/wazuh-windows-localfile.xml"
    ).read_text(encoding="utf-8")

    wrapped = ElementTree.fromstring(f"<ossec_config>{snippet}</ossec_config>")
    locations = [node.findtext("location") for node in wrapped.findall("localfile")]

    assert locations == ["Microsoft-Windows-Sysmon/Operational"]
    assert "<location>Security</location>" not in snippet


def test_suricata_lab_rules_use_unique_local_signature_ids() -> None:
    lines = [
        line.strip()
        for line in (PROJECT_ROOT / "config/suricata-datn.rules")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert len(lines) == 3
    assert sum("sid:900001" in line for line in lines) == 1
    assert sum("sid:900002" in line for line in lines) == 1
    assert sum("sid:900004" in line for line in lines) == 1
    assert not any("sid:900003" in line for line in lines)


def test_scenario_catalog_covers_four_strata_with_five_scenarios_each() -> None:
    catalog = ScenarioCatalog.model_validate(
        yaml.safe_load(
            (PROJECT_ROOT / "config/scenario-catalog.yaml").read_text(encoding="utf-8")
        )
    )
    strata: dict[str, list[str]] = {}
    for scenario in catalog.scenarios:
        strata.setdefault(f"{scenario.family}:{scenario.label}", []).append(
            scenario.scenario_id
        )

    assert set(strata) == {
        "account:benign",
        "account:malicious",
        "c2:benign",
        "c2:malicious",
    }
    assert all(len(set(ids)) == 5 for ids in strata.values())

    smb_scenario = next(
        item
        for item in catalog.scenarios
        if item.scenario_id == "ACCOUNT-MALICIOUS-FAIL-THEN-SUCCESS"
    )
    assert smb_scenario.attribution.logon_types == [3]
    assert smb_scenario.attribution.source_ips == ["10.40.0.10"]


def test_scenario_catalog_has_enforceable_quality_gates_and_alert_overlap() -> None:
    catalog = ScenarioCatalog.model_validate(
        yaml.safe_load(
            (PROJECT_ROOT / "config/scenario-catalog.yaml").read_text(encoding="utf-8")
        )
    )

    for scenario in catalog.scenarios:
        gates = scenario.quality_gates
        if scenario.family == "account":
            assert (
                gates.min_account_failures > 0
                or gates.min_account_successes > 0
            )
            if gates.min_account_successes:
                assert gates.max_account_successes == gates.min_account_successes
        else:
            assert scenario.attribution.source_ips == ["10.20.0.10"]
            assert gates.min_suricata_events > 0
            assert gates.min_network_events > 0 or gates.min_dns_events > 0

    benign_c2 = [
        item for item in catalog.scenarios if item.family == "c2" and item.label == "benign"
    ]
    malicious_c2 = [
        item
        for item in catalog.scenarios
        if item.family == "c2" and item.label == "malicious"
    ]
    assert any(item.quality_gates.required_suricata_signature_ids for item in benign_c2)
    assert any(not item.quality_gates.required_suricata_signature_ids for item in malicious_c2)


def test_catalog_design_does_not_encode_labels_in_known_low_cardinality_pairs() -> None:
    catalog = ScenarioCatalog.model_validate(
        yaml.safe_load(
            (PROJECT_ROOT / "config/scenario-catalog.yaml").read_text(encoding="utf-8")
        )
    )
    taxonomy = yaml.safe_load(
        (PROJECT_ROOT / "config/suspicious-process-taxonomy.yaml").read_text(
            encoding="utf-8"
        )
    )
    suspicious_terms = {
        str(term).casefold()
        for rule in taxonomy["rules"]
        for term in rule.get("command_contains_any", [])
    }

    account_pairs: dict[str, set[tuple[float, float]]] = {
        "benign": set(),
        "malicious": set(),
    }
    c2_pairs: dict[str, set[tuple[float, float]]] = {
        "benign": set(),
        "malicious": set(),
    }
    for scenario in catalog.scenarios:
        if scenario.family == "account":
            account_pairs[scenario.label].add(
                (
                    float(scenario.quality_gates.min_account_successes),
                    float(3 in scenario.attribution.logon_types),
                )
            )
            continue
        command_terms = {
            item.casefold() for item in scenario.attribution.command_contains_any
        }
        c2_pairs[scenario.label].add(
            (
                float(bool(command_terms & suspicious_terms)),
                float(scenario.quality_gates.min_dns_events),
            )
        )

    assert account_pairs["benign"] & account_pairs["malicious"]
    assert c2_pairs["benign"] & c2_pairs["malicious"]


def test_create_run_draft_uses_catalog_without_copying_execution_commands(
    tmp_path: Path,
) -> None:
    output = tmp_path / "run.yaml"
    result = create_run_draft(
        catalog_path=PROJECT_ROOT / "config/scenario-catalog.yaml",
        scenario_id="C2-MALICIOUS-HTTP-BEACON",
        run_id="C2-MALICIOUS-HTTP-BEACON-R01",
        operator="Kien",
        output_path=output,
        clock_preflight=clock_preflight(),
    )

    draft = RunDraft.model_validate(yaml.safe_load(output.read_text(encoding="utf-8")))
    serialized = output.read_text(encoding="utf-8")
    assert result["status"] == "CREATED"
    assert draft.attribution.destination_ips == ["10.40.0.10"]
    assert draft.attribution.destination_ports == [8081]
    assert draft.quality_gates.min_network_events == 8
    assert draft.quality_gates.required_suricata_signature_ids == [900001]
    assert "execution_steps" not in serialized
    assert draft.collection_seed >= 0
    assert draft.scenario_parameters["interval_jitter_percent"] >= 10
    assert draft.scenario_parameters["interval_jitter_direction"] in {-1, 1}
    assert draft.scenario_parameters["pre_action_delay_seconds"] >= 1
    assert "payload_size_bytes" not in draft.scenario_parameters
    assert draft.expected_observables


def test_create_run_draft_refuses_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "run.yaml"
    output.write_text("existing\n", encoding="utf-8")

    try:
        create_run_draft(
            catalog_path=PROJECT_ROOT / "config/scenario-catalog.yaml",
            scenario_id="ACCOUNT-BENIGN-NORMAL-LOGON",
            run_id="ACCOUNT-BENIGN-NORMAL-LOGON-R01",
            operator="Kien",
            output_path=output,
            clock_preflight=clock_preflight(),
        )
    except Exception as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected create_run_draft to refuse overwrite")


def test_clock_preflight_rejects_cross_vm_skew() -> None:
    payload = clock_preflight().model_dump(mode="json")
    payload["sensor_utc"] = "2026-10-16T01:00:05Z"

    with pytest.raises(ValueError, match="clock skew"):
        ClockPreflight.model_validate(payload)


def test_clock_preflight_rejects_stale_measurements() -> None:
    payload = clock_preflight().model_dump(mode="json")
    payload["captured_at"] = "2026-10-16T01:03:00Z"

    with pytest.raises(ValueError, match="stale"):
        ClockPreflight.model_validate(payload)


def test_run_parameters_are_deterministic_for_the_recorded_seed(tmp_path: Path) -> None:
    outputs = [tmp_path / "first.yaml", tmp_path / "second.yaml"]
    for output in outputs:
        create_run_draft(
            catalog_path=PROJECT_ROOT / "config/scenario-catalog.yaml",
            scenario_id="C2-BENIGN-HEALTH-POLL",
            run_id="C2-BENIGN-HEALTH-POLL-R01",
            operator="Kien",
            output_path=output,
            clock_preflight=clock_preflight(),
            collection_seed=20261022,
        )

    first = RunDraft.model_validate(yaml.safe_load(outputs[0].read_text(encoding="utf-8")))
    second = RunDraft.model_validate(yaml.safe_load(outputs[1].read_text(encoding="utf-8")))
    assert first.scenario_parameters == second.scenario_parameters


def test_documented_cli_modules_start_from_repository_root() -> None:
    for module in (
        "scripts.create_run_draft",
        "scripts.build_clock_preflight",
        "scripts.scenario_session",
        "scripts.audit_dataset",
    ):
        completed = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert "usage:" in completed.stdout
