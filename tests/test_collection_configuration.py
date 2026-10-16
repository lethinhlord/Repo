from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import yaml

from ml.scenario_collection import (
    RunDraft,
    ScenarioCatalog,
    SourceConfig,
    create_run_draft,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_c2_model_excludes_taxonomy_derived_suspicious_process_proxy() -> None:
    schema = json.loads(
        (PROJECT_ROOT / "ml/feature_schema.json").read_text(encoding="utf-8")
    )

    assert "suspicious_process" in schema["properties"]
    assert "suspicious_process" not in schema["x-family-features"]["c2"]


def test_collection_runbook_is_portable_isolated_and_failure_safe() -> None:
    runbook = (PROJECT_ROOT / "docs/scenario-collection-runbook.md").read_text(
        encoding="utf-8"
    )

    assert "/home/lethinh" not in runbook
    assert "scp lethinh@" not in runbook
    assert "server=1.1.1.1" not in runbook
    assert "IEX (IWR" not in runbook
    assert "OpenSSH.Client~~~~0.0.1.0" in runbook
    assert "MAX_CLOCK_SKEW_SECONDS=5" in runbook
    assert "BACKUP_ID=" in runbook
    assert "retry finalize" in runbook


def test_committed_source_and_taxonomy_configuration_is_valid() -> None:
    source_payload = yaml.safe_load(
        (PROJECT_ROOT / "config/collection-sources.yaml").read_text(encoding="utf-8")
    )
    source = SourceConfig.model_validate(source_payload)
    taxonomy_path = PROJECT_ROOT / source.taxonomy_path
    taxonomy = yaml.safe_load(taxonomy_path.read_text(encoding="utf-8"))

    assert source.windows_agent_name == "WIN11-TARGET"
    assert source.suricata_agent_name == "NET-SENSOR"
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
        else:
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
    )

    draft = RunDraft.model_validate(yaml.safe_load(output.read_text(encoding="utf-8")))
    serialized = output.read_text(encoding="utf-8")
    assert result["status"] == "CREATED"
    assert draft.attribution.destination_ips == ["10.40.0.10"]
    assert draft.attribution.destination_ports == [8081]
    assert draft.quality_gates.min_network_events == 8
    assert draft.quality_gates.required_suricata_signature_ids == [900001]
    assert "execution_steps" not in serialized


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
        )
    except Exception as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected create_run_draft to refuse overwrite")


def test_documented_cli_modules_start_from_repository_root() -> None:
    for module in (
        "scripts.create_run_draft",
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
