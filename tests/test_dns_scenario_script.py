from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNBOOK_PATH = PROJECT_ROOT / "docs/scenario-collection-runbook.md"
CATALOG_PATH = PROJECT_ROOT / "config/scenario-catalog.yaml"
DNS_SCRIPT_PATH = PROJECT_ROOT / "scripts/run_dns_scenario.ps1"


def _runbook_section(start: str, end: str) -> str:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
    return runbook.split(start, 1)[1].split(end, 1)[0]


def _catalog_scenario(scenario_id: str) -> dict:
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    return next(
        scenario
        for scenario in catalog["scenarios"]
        if scenario["scenario_id"] == scenario_id
    )


def test_dns_scenarios_use_one_traceable_child_powershell_process() -> None:
    for scenario_id in ("C2-BENIGN-DNS", "C2-MALICIOUS-DNS-BEACON"):
        scenario = _catalog_scenario(scenario_id)
        execution = " ".join(scenario["execution_steps"])

        assert scenario["quality_gates"]["min_process_events"] == 1
        assert "scripts/run_dns_scenario.ps1" in execution
        assert "child powershell.exe" in execution
        assert "frozen" in execution


def test_dns_runbook_passes_frozen_values_on_child_command_line() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
    benign = _runbook_section(
        "### C2-BENIGN-DNS", "### C2-BENIGN-API-BURST"
    )
    malicious = _runbook_section(
        "### C2-MALICIOUS-DNS-BEACON", "### C2-MALICIOUS-STAGED-TRANSFER"
    )

    assert "function Start-DatnDnsScenario" in runbook
    assert "powershell.exe" in runbook
    assert "run_dns_scenario.ps1" in runbook
    for argument in ("-RunNonce", "-DomainSuffix", "-Count", "-GapsCsv"):
        assert argument in runbook

    for section, suffix in (
        (benign, "www.datn.test"),
        (malicious, "beacon.datn.test"),
    ):
        assert "Start-DatnDnsScenario" in section
        assert "-DomainSuffix" in section
        assert suffix in section
        assert "Resolve-DnsName" not in section


def test_dns_script_validates_and_executes_only_lab_dns_queries() -> None:
    script = DNS_SCRIPT_PATH.read_text(encoding="utf-8")

    for parameter in (
        "RunNonce",
        "DomainSuffix",
        "Count",
        "GapsCsv",
        "VariantIndex",
        "DnsServer",
    ):
        assert f"${parameter}" in script
    assert "www.datn.test" in script
    assert "beacon.datn.test" in script
    assert "10.40.0.10" in script
    assert "Resolve-DnsName" in script
    assert "Start-Sleep -Milliseconds" in script
    assert "Set-ExecutionPolicy" not in script
    assert "-ExecutionPolicy" not in script


def test_dns_runbook_uses_child_only_remotesigned_policy() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "'-ExecutionPolicy','RemoteSigned'" in runbook
    assert "Get-ExecutionPolicy -List" in runbook
    assert "Zone.Identifier" in runbook
    assert "AllSigned" in runbook
    assert "about_execution_policies?view=powershell-5.1" in runbook
    assert re.search(r"(?i)-ExecutionPolicy\s+(Bypass|Unrestricted)", runbook) is None
    assert re.search(r"(?m)^\s*Set-ExecutionPolicy\b", runbook) is None


def test_remotesigned_child_runs_dns_runner_with_mocked_resolver(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("Windows PowerShell is unavailable")

    environment = os.environ.copy()
    windows_modules = (
        Path(powershell).parents[3]
        / "System32/WindowsPowerShell/v1.0/Modules"
    )
    environment["PSModulePath"] = os.pathsep.join(
        (str(windows_modules), environment.get("PSModulePath", ""))
    )
    policy_result = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-ExecutionPolicy -List | Select-Object "
            "@{n='Scope';e={$_.Scope.ToString()}},"
            "@{n='ExecutionPolicy';e={$_.ExecutionPolicy.ToString()}} | "
            "ConvertTo-Json -Compress",
        ],
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    )
    policies = json.loads(policy_result.stdout)
    if isinstance(policies, dict):
        policies = [policies]
    group_policies = {
        item["Scope"]: item["ExecutionPolicy"]
        for item in policies
        if item["Scope"] in {"MachinePolicy", "UserPolicy"}
    }
    if any(policy != "Undefined" for policy in group_policies.values()):
        pytest.skip("host Group Policy controls Windows PowerShell script execution")

    harness = tmp_path / "dns-runner-harness.ps1"
    harness.write_text(
        """param([Parameter(Mandatory=$true)][string]$RunnerPath)
$script:Queries = @()
function Resolve-DnsName {
  param([string]$Name,[string]$Server,[string]$Type,[switch]$DnsOnly)
  $script:Queries += [pscustomobject]@{
    Name=$Name; Server=$Server; Type=$Type; DnsOnly=$DnsOnly.IsPresent
  }
  [pscustomobject]@{ IPAddress='10.40.0.10' }
}
function Start-Sleep { param([int]$Milliseconds) }
. $RunnerPath -RunNonce 'mocknonce1234' -DomainSuffix 'www.datn.test' `
  -Count 2 -GapsCsv '1' -VariantIndex 7 -DnsServer '10.40.0.10' | Out-Null
[pscustomobject]@{
  Policy=[string](Get-ExecutionPolicy); Queries=$script:Queries
} | ConvertTo-Json -Depth 4 -Compress
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-File",
            str(harness),
            "-RunnerPath",
            str(DNS_SCRIPT_PATH),
        ],
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    )
    observed = json.loads(result.stdout.strip().splitlines()[-1])

    assert observed["Policy"] == "RemoteSigned"
    assert observed["Queries"] == [
        {
            "Name": "mocknonce1234-b7-01.www.datn.test",
            "Server": "10.40.0.10",
            "Type": "A",
            "DnsOnly": True,
        },
        {
            "Name": "mocknonce1234-b7-02.www.datn.test",
            "Server": "10.40.0.10",
            "Type": "A",
            "DnsOnly": True,
        },
    ]


def test_health_poll_runbook_executes_all_eight_frozen_actions() -> None:
    health = _runbook_section(
        "### C2-BENIGN-HEALTH-POLL", "### C2-BENIGN-SINGLE-DOWNLOAD"
    )
    scenario = _catalog_scenario("C2-BENIGN-HEALTH-POLL")

    assert scenario["quality_gates"]["min_process_events"] == 8
    assert scenario["quality_gates"]["min_network_events"] == 8
    assert "1..8 | ForEach-Object" in health
    assert "$_ -lt 8" in health
    assert "1..5 | ForEach-Object" not in health


def test_account_unlock_uses_supported_winnt_adsi_and_cim_verification() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "Unlock-LocalUser" not in runbook
    assert '[ADSI]("WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $name)' in runbook
    assert "$user.IsAccountLocked = $false" in runbook
    assert "$user.SetInfo()" in runbook
    assert "Get-CimInstance Win32_UserAccount" in runbook
    assert "if ($invalidAccounts)" in runbook
    assert re.search(r"(?m)^\s*Set-ExecutionPolicy\b", runbook) is None
    assert "winnt-account-lockout" in runbook
