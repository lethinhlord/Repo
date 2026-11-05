from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/Export-DatnSysmonClockEvidence.ps1"


@pytest.mark.parametrize(
    ("system_time", "utc_time", "status", "delta"),
    [
        ("2026-11-04T14:35:12.0254694Z", "2026-11-03 22:42:19.330", "MISMATCH", 57172.6954694),
        ("2026-11-04T14:35:12.0000000Z", "2026-11-04 14:35:07.0000000", "PASS", 5),
        ("2026-11-04T14:35:12.0000001Z", "2026-11-04 14:35:07.0000000", "MISMATCH", 5.0000001),
        ("2026-11-04T14:35:12Z", "", "INVALID", None),
        ("2026-11-04T14:35:12Z", "not-a-time", "INVALID", None),
        ("2026-11-04T00:00:00Z", "2026-11-04", "INVALID", None),
    ],
)
def test_native_xml_clock_assessment_preserves_exact_fields(
    tmp_path: Path, system_time: str, utc_time: str, status: str, delta: float | None,
) -> None:
    assert SCRIPT.is_file(), "Native clock forensics helper must exist"
    shell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    xml = tmp_path / "event.xml"
    xml.write_text(
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>22</EventID>'
        f'<TimeCreated SystemTime="{system_time}"/><EventRecordID>149398</EventRecordID>'
        '<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>'
        f'<EventData><Data Name="UtcTime">{utc_time}</Data>'
        '<Data Name="ProcessGuid">{original-guid}</Data></EventData></Event>',
        encoding="utf-8",
    )
    harness = tmp_path / "check.ps1"
    harness.write_text(
        "param([string]$Helper,[string]$Xml)\n"
        "$ErrorActionPreference='Stop'\n"
        ". $Helper\n"
        "Get-DatnSysmonClockRecord -EventXml (Get-Content -Raw -LiteralPath $Xml) "
        "| ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(harness), str(SCRIPT), str(xml)],
        check=True, capture_output=True, text=True,
    )
    record = json.loads(result.stdout)
    assert record["Status"] == status
    assert record["SystemTime"] == system_time
    assert record["UtcTime"] == utc_time
    assert record["ProcessGuid"] == "{original-guid}"
    assert record["EventRecordID"] == "149398"
    if delta is None:
        assert record["DeltaSeconds"] is None
    else:
        assert record["DeltaSeconds"] == pytest.approx(delta, abs=0.00000001, rel=0)


def test_evtx_batches_export_exact_selected_ids_without_broadening(tmp_path: Path) -> None:
    shell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    harness = tmp_path / "batch.ps1"
    harness.write_text(
        "param([string]$Helper)\n. $Helper\n"
        "@(Get-DatnEventExportBatches -RecordIds @(1..1000)) | ConvertTo-Json -Depth 5\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(harness), str(SCRIPT)],
        capture_output=True, text=True, check=True,
    )
    batches = json.loads(result.stdout)
    assert [value for batch in batches for value in batch["RecordIds"]] == list(range(1, 1001))
    assert all(1 <= len(batch["RecordIds"]) <= 16 for batch in batches)
    for batch in batches:
        assert len(batch["XPath"]) < 4096
        assert "EventID=" not in batch["XPath"]
        assert all(f"EventRecordID={value}" in batch["XPath"] for value in batch["RecordIds"])
