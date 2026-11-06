"""Run real PowerShell5 scripts with native calls replaced, never authenticate or network."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def shell():
    result = shutil.which("powershell.exe")
    if result is None:
        pytest.skip("Windows PowerShell native runner test")
    return result


def native_environment():
    env = os.environ.copy()
    # Python inherits PS7's module paths from Codex; Windows PowerShell does not
    # sanitize them as it does when directly launched by PS7. Use the PS5 builtins.
    env["PSModulePath"] = str(
        Path(env.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/Modules"
    )
    return env


@pytest.mark.parametrize("enrollment", (False, True))
def test_console_single_account_closes_token_without_real_logon(tmp_path, enrollment):
    harness = tmp_path / "test.ps1"
    harness.write_text(
        r"""param([string]$Runner,[string]$Enrollment)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
public static class DatnTrainingLogon {
 public static int Calls=0; public static int Closed=0;
 public static bool LogonUser(string u,string d,string p,int t,int v,out IntPtr h) {
   Calls++; h=new IntPtr(123); return true;
 }
 public static bool CloseHandle(IntPtr h) {Closed++; return true;}
}
'@
function Get-Credential {param($UserName,$Message)
 $secret=ConvertTo-SecureString 'unit' -AsPlainText -Force
 return New-Object System.Management.Automation.PSCredential($UserName,$secret)
}
function Read-Host {param($Prompt) return ''}
function Start-Sleep {param($Milliseconds,$Seconds)}
& $Runner -AccountsCsv 'datn_lab01' -AttemptsCsv 'datn_lab01:success' `
 -GapsCsv '' -RunNonce 'unitnonce123' -Enrollment:($Enrollment -eq 'True')
if ([DatnTrainingLogon]::Calls -ne 1 -or [DatnTrainingLogon]::Closed -ne 1) {
 throw 'Token lifecycle mismatch'
}
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            shell(),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
            str(ROOT / "scripts/run_training_account.ps1"),
            str(enrollment),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=native_environment(),
    )
    assert result.returncode == 0, result.stderr


def test_frozen_single_http_preserves_empty_gaps_and_shared_endpoint(tmp_path):
    parameters = {
        "run_id": "UNIT-HTTP-RUN-001",
        "scenario_parameters": {
            "execution_profile_version": "lab-action-profile-v1",
            "transport": "http",
            "endpoint": "http://10.40.0.10:8081/beacon",
            "pre_action_delay_seconds": 1.1,
            "expected_action_count": 1,
            "expected_intervals_seconds": "",
            "run_nonce": "unitnonce123",
            "variant_index": 7,
        },
    }
    path = tmp_path / "parameters.json"
    path.write_text(json.dumps(parameters))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    harness = tmp_path / "test.ps1"
    harness.write_text(
        r"""param($Runner,$Root,$Parameters,$Digest)
$ErrorActionPreference='Stop'
$code=@'
using System; using System.IO;
class CurlUnit {static int Main(string[] args) {
 File.AppendAllText(Environment.GetEnvironmentVariable("DATN_TRACE"),
   String.Join(" ",args)+Environment.NewLine);
 Console.Write("200"); return 0;
}}
'@
Add-Type -TypeDefinition $code -OutputAssembly (Join-Path $Root 'curl.exe') `
 -OutputType ConsoleApplication
$env:PATH=$Root+';'+$env:PATH
$env:DATN_TRACE=Join-Path $Root 'trace.txt'
function Read-Host {param($Prompt) return ''}
function Start-Sleep {param($Milliseconds,$Seconds)}
& $Runner -ParametersFile $Parameters -ExpectedFileSha256 $Digest
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            shell(),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
            str(ROOT / "scripts/run_frozen_windows.ps1"),
            str(tmp_path),
            str(path),
            digest,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=native_environment(),
    )
    assert result.returncode == 0, result.stderr
    trace = (tmp_path / "trace.txt").read_text().splitlines()
    assert len(trace) == 1
    assert "http://10.40.0.10:8081/beacon?run=unitnonce123&v=7&n=1" in trace[0]
