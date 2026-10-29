"""Read-only Windows preflight regressions: no host accounts or rules are changed."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/Test-DatnWindowsPreflight.ps1"
RUNBOOK = ROOT / "docs/scenario-collection-runbook.md"


def _case(
    name: str,
    expected: str,
    *,
    protocol: str = "TCP",
    ports: tuple[str, ...] = ("445",),
    remote: tuple[str, ...] = ("Any",),
    program: str = "System",
    service: str = "LanmanServer",
) -> dict[str, object]:
    return {
        "Name": name,
        "Expected": expected,
        "Protocol": protocol,
        "LocalPort": list(ports),
        "RemoteAddress": list(remote),
        "Program": program,
        "Service": service,
    }


CASES = [
    _case("udp_any_port_is_not_smb", "NOT_SMB", protocol="UDP", ports=("Any",)),
    _case("numeric_udp_is_not_smb", "NOT_SMB", protocol="17", ports=("Any",)),
    _case("ipv6_tunnel_protocol_is_not_smb", "NOT_SMB", protocol="41", ports=("Any",)),
    _case("tcp_http_port_is_not_smb", "NOT_SMB", ports=("80", "8080")),
    _case("tcp_port_range_exposes_smb", "BROAD", ports=("400-500",)),
    _case("tcp_any_port_exposes_smb", "BROAD", ports=("Any",)),
    _case("any_protocol_includes_tcp", "BROAD", protocol="Any"),
    _case("all_programs_and_services_expose_smb", "BROAD", program="Any", service="Any"),
    _case("local_subnet_is_broader_than_kali", "BROAD", remote=("LocalSubnet",)),
    _case("ipv4_subnet_is_broader_than_kali", "BROAD", remote=("10.40.0.0/24",)),
    _case("ipv4_range_is_broader_than_kali", "BROAD", remote=("10.40.0.10-10.40.0.11",)),
    _case("ipv6_default_route_is_broad", "BROAD", remote=("::/0",)),
    _case("second_remote_address_is_not_allowed", "BROAD", remote=("10.40.0.10", "10.40.0.11")),
    _case("specific_browser_rule_does_not_allow_server_smb", "NOT_SMB",
          program=r"C:\Program Files\Browser\msedge.exe", service="Any", ports=("Any",)),
    _case("kali_only_is_scoped", "SCOPED", remote=("10.40.0.10",)),
    _case("numeric_tcp_and_host_prefix_are_scoped", "SCOPED", protocol="6",
          remote=("10.40.0.10/32",)),
    _case("unknown_protocol_does_not_report_safe", "INCONCLUSIVE", protocol="UnknownProtocol"),
    _case("unresolved_dynamic_port_does_not_report_safe", "INCONCLUSIVE", ports=("RPC",)),
    _case("empty_application_and_service_do_not_report_safe", "INCONCLUSIVE",
          program="", service=""),
    _case("unknown_remote_address_does_not_report_safe", "INCONCLUSIVE", remote=("not-an-ip",)),
]


def test_windows_preflight_pure_helper_is_shipped() -> None:
    assert SCRIPT.is_file(), "Ship the read-only Windows preflight helper with the runbook"


@pytest.fixture(scope="module")
def assessments(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, object]]:
    powershell = shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("Windows PowerShell 5.1 is unavailable on this platform")
    assert SCRIPT.is_file(), "The firewall regression must call the delivered preflight helper"
    payload = tmp_path_factory.mktemp("windows-preflight") / "cases.json"
    payload.write_text(json.dumps(CASES), encoding="utf-8")
    environment = os.environ.copy()
    environment["DATN_PREFLIGHT_SCRIPT"] = str(SCRIPT)
    environment["DATN_PREFLIGHT_CASES"] = str(payload)
    command = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
function Get-NetFirewallRule { throw 'Pure helper unexpectedly inspected host firewall' }
function New-NetFirewallRule { throw 'Pure helper unexpectedly changed host firewall' }
function Set-NetFirewallRule { throw 'Pure helper unexpectedly changed host firewall' }
function Remove-NetFirewallRule { throw 'Pure helper unexpectedly changed host firewall' }
function New-LocalUser { throw 'Pure helper unexpectedly changed host users' }
function Set-LocalUser { throw 'Pure helper unexpectedly changed host users' }
function Set-Service { throw 'Pure helper unexpectedly changed host services' }
function Start-Service { throw 'Pure helper unexpectedly changed host services' }
. $env:DATN_PREFLIGHT_SCRIPT
$cases = Get-Content -LiteralPath $env:DATN_PREFLIGHT_CASES -Raw | ConvertFrom-Json
$results = @(foreach ($case in $cases) {
  $parameters = @{
    Protocol = [string]$case.Protocol
    LocalPort = [string[]]$case.LocalPort
    RemoteAddress = [string[]]$case.RemoteAddress
    Program = [string]$case.Program
    Service = [string]$case.Service
    AllowedSource = '10.40.0.10'
  }
  $assessment = Get-DatnSmbRuleAssessment @parameters
  [pscustomobject]@{ Name=$case.Name; Status=$assessment.Status }
})
ConvertTo-Json -InputObject $results -Depth 4 -Compress
"""
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "RemoteSigned", "-Command", command],
        capture_output=True,
        env=environment,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    rows = json.loads(result.stdout)
    return {row["Name"]: row for row in rows}


@pytest.mark.parametrize("case", CASES, ids=[str(case["Name"]) for case in CASES])
def test_smb_assessment_reports_actual_tcp445_scope(
    assessments: dict[str, dict[str, object]], case: dict[str, object]
) -> None:
    assert assessments[str(case["Name"])]["Status"] == case["Expected"]


def test_console_canary_requires_new_password_logon_not_unlock() -> None:
    section = RUNBOOK.read_text(encoding="utf-8").split("### 10.4", 1)[1].split("### 10.5", 1)[0]
    normalized = section.casefold()
    assert "khóa màn hình, nhập sai" not in normalized
    assert any(term in normalized for term in ("đăng xuất", "sign out", "sign-out"))
    assert any(term in normalized for term in ("đăng nhập mới", "new logon", "new sign-in"))
    assert "mật khẩu" in normalized
    assert 'tostring)=="2"' in section, "The console canary still needs fresh LogonType 2 evidence"
    assert 'tostring)=="3"' in section, "SMB must retain its separate network-logon check"
