from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run_http_scenario.ps1"


@pytest.mark.parametrize(
    ("scenario", "count", "first_response_ms"),
    [
        ("C2-MALICIOUS-HTTP-BEACON", 8, 250),
        ("C2-MALICIOUS-HTTP-BEACON", 8, 1500),
        ("C2-BENIGN-HEALTH-POLL", 8, 250),
        ("C2-BENIGN-IRREGULAR-API", 4, 250),
        ("C2-BENIGN-API-BURST", 6, 250),
    ],
)
def test_http_runner_uses_frozen_start_to_start_schedule_with_actual_native_process(
    tmp_path: Path, scenario: str, count: int, first_response_ms: int,
) -> None:
    assert SCRIPT.is_file()
    shell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    # A native executable test double logs arguments and returns200. No network
    # request is sent; the production runner still starts actual curl processes.
    harness = tmp_path / "harness.ps1"
    harness.write_text(
        r'''param([string]$Runner,[string]$Root,[int]$FirstDelay,[string]$Scenario,[int]$Count)
$ErrorActionPreference='Stop'
$source=@'
using System; using System.IO;
class TestCurl { static int Main(string[] args) {
 File.AppendAllText(Environment.GetEnvironmentVariable("DATN_HTTP_TRACE"),
 DateTime.UtcNow.ToString("o")+" "+String.Join(" ",args)+Environment.NewLine);
 int count=File.ReadAllLines(Environment.GetEnvironmentVariable("DATN_HTTP_TRACE")).Length;
 int delay=Int32.Parse(Environment.GetEnvironmentVariable("DATN_FIRST_DELAY"));
 System.Threading.Thread.Sleep(count==1 ? delay : 250);
 Console.Write("200"); return 0;
}}
'@
Add-Type -TypeDefinition $source -OutputAssembly (Join-Path $Root 'curl.exe') `
 -OutputType ConsoleApplication
$env:PATH=$Root+[IO.Path]::PathSeparator+$env:PATH
$env:DATN_HTTP_TRACE=Join-Path $Root 'trace.txt'
$env:DATN_FIRST_DELAY=[string]$FirstDelay
$gaps=(@(1..($Count-1) | ForEach-Object {'1'}) -join ',')
& $Runner -RunNonce 'nativeclock1234' -Count $Count -GapsCsv $gaps -VariantIndex 7 `
 -ScenarioId $Scenario
if (-not $?) { throw 'Runner failed' }
$lines=@([IO.File]::ReadAllLines($env:DATN_HTTP_TRACE))
[pscustomobject]@{Count=$lines.Count; Rows=$lines} | ConvertTo-Json -Compress
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(harness),
         str(SCRIPT), str(tmp_path), str(first_response_ms), scenario, str(count)],
        capture_output=True, text=True, timeout=45,
    )
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout.strip().splitlines()[-1])
    assert observed["Count"] == count
    starts = [datetime.fromisoformat(row.split(" ", 1)[0]) for row in observed["Rows"]]
    # Request latency must not accumulate into the seven frozen one-second gaps.
    assert (starts[-1] - starts[0]).total_seconds() == pytest.approx(count-1, abs=0.75)
    gaps = [(second-first).total_seconds()
            for first, second in zip(starts, starts[1:], strict=False)]
    # PowerShell's first native invocation has one-time launch/JIT overhead;
    # subsequent gaps, especially after the deliberately slow first response,
    # must never be compressed to catch up to an absolute original schedule.
    assert gaps[0] >= 0.7
    assert all(gap >= 0.9 for gap in gaps[1:])
    for index, row in enumerate(observed["Rows"], 1):
        assert f"run=nativeclock1234&v=7&n={index}" in row
        assert "--http1.1" in row and "Connection: close" in row
        assert "--noproxy *" in row
        if scenario == "C2-BENIGN-HEALTH-POLL":
            assert "/beacon?mode=health&" in row
        elif "API" in scenario:
            assert "10.40.0.10:8080/api/status?" in row
    assert f"HTTP_ACTION_COMPLETE count={count}" in result.stdout


@pytest.mark.parametrize("gaps", ["1,1", "NaN,1,1,1,1,1,1", "0,1,1,1,1,1,1"])
def test_http_runner_rejects_invalid_frozen_schedule_before_execution(gaps: str) -> None:
    assert SCRIPT.is_file()
    shell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
         "-RunNonce", "nativeclock1234", "-Count", "8", "-GapsCsv", gaps,
         "-VariantIndex", "7"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0
    assert "HTTP_ACTION_START" not in result.stdout
