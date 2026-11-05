[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [ValidateRange(1, 50000)][int]$MaxEvents = 5000,
    [long[]]$EventRecordIds = @()
)

# Dot sourcing defines helpers only; exporting is an explicit, read-only host operation.
function Get-DatnSysmonClockRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$EventXml)
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($EventXml), $settings)
    $document = New-Object System.Xml.XmlDocument
    $document.XmlResolver = $null
    try { $document.Load($reader) } finally { $reader.Dispose() }
    $system = $document.SelectSingleNode('/*[local-name()="Event"]/*[local-name()="System"]')
    if ($null -eq $system) { throw 'Native event XML has no System section' }
    $provider = $system.SelectSingleNode('*[local-name()="Provider"]')
    $created = $system.SelectSingleNode('*[local-name()="TimeCreated"]')
    $recordNode = $system.SelectSingleNode('*[local-name()="EventRecordID"]')
    $idNode = $system.SelectSingleNode('*[local-name()="EventID"]')
    if ($null -eq $provider -or $null -eq $created -or $null -eq $recordNode -or
        $null -eq $idNode) { throw 'Native event XML is missing source identity or time' }
    $fields = @{}
    foreach ($node in $document.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]')) {
        $name = $node.GetAttribute('Name')
        if ($fields.ContainsKey($name)) { throw "Duplicate native event field: $name" }
        $fields[$name] = $node.InnerText
    }
    $result = [ordered]@{
        EventRecordID = $recordNode.InnerText
        EventID = $idNode.InnerText
        Provider = $provider.GetAttribute('Name')
        SystemTime = $created.GetAttribute('SystemTime')
        UtcTime = [string]$fields['UtcTime']
        ProcessGuid = [string]$fields['ProcessGuid']
        DeltaSeconds = $null
        Status = 'INVALID'
    }
    if ($result.Provider -ne 'Microsoft-Windows-Sysmon' -or $result.EventID -notin '1','3','22') {
        $result.Status = 'NOT_SYSMON_SIGNAL'
    } elseif ($result.SystemTime -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+]00:00)$' -and
              $result.UtcTime -match '^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+]00:00)?$') {
        try {
            $culture = [Globalization.CultureInfo]::InvariantCulture
            $style = [Globalization.DateTimeStyles]::AssumeUniversal -bor
                     [Globalization.DateTimeStyles]::AdjustToUniversal
            $first = [DateTimeOffset]::Parse($result.SystemTime, $culture, $style)
            $second = [DateTimeOffset]::Parse($result.UtcTime, $culture, $style)
            # Tick accounting keeps the seventh fractional digit at the 5s boundary.
            $ticks = [Math]::Abs($first.UtcTicks - $second.UtcTicks)
            $result.DeltaSeconds = [decimal]$ticks / [decimal]10000000
            $result.Status = if ($ticks -le 50000000) { 'PASS' } else { 'MISMATCH' }
        } catch { $result.Status = 'INVALID' }
    }
    [pscustomobject]$result
}

function Get-DatnEventExportBatches {
    param([Parameter(Mandatory=$true)][long[]]$RecordIds)
    $ordered=@($RecordIds | Select-Object -Unique | Sort-Object)
    if (@($ordered | Where-Object { $_ -le 0 }).Count) { throw 'Record IDs must be positive' }
    # Stay below Windows Event Log's compound XPath expression limit.
    for ($index=0; $index -lt $ordered.Count; $index+=16) {
        $last=[Math]::Min($ordered.Count-1,$index+15)
        $batch=@($ordered[$index..$last])
        $clauses=@($batch | ForEach-Object { "EventRecordID=$_" })
        [pscustomobject]@{
            RecordIds=$batch
            XPath=('*[System[(' + ($clauses -join ' or ') + ')]]')
        }
    }
}

function Export-DatnSysmonClockEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Directory,
        [ValidateRange(1,50000)][int]$Limit = 5000,
        [long[]]$RecordIds = @()
    )
    $ErrorActionPreference = 'Stop'
    if (Test-Path -LiteralPath $Directory) { throw 'Output already exists; select a new forensic directory' }
    if (@($RecordIds | Where-Object { $_ -le 0 }).Count) { throw 'Record IDs must be positive' }
    $channel = 'Microsoft-Windows-Sysmon/Operational'
    $xpath = '*[System[(EventID=1 or EventID=3 or EventID=22)]]'
    if ($RecordIds.Count) {
        $uniqueIds=@($RecordIds | Select-Object -Unique)
        if ($uniqueIds.Count -gt $Limit) { throw 'Requested record IDs exceed MaxEvents; increase the explicit limit' }
        $events=@(
            foreach ($batch in @(Get-DatnEventExportBatches -RecordIds $uniqueIds)) {
                # Missing requested IDs are recorded separately, not fabricated.
                Get-WinEvent -LogName $channel -FilterXPath $batch.XPath -MaxEvents $Limit `
                    -ErrorAction SilentlyContinue
            }
        )
    } else {
        $events = @(Get-WinEvent -LogName $channel -FilterXPath $xpath -MaxEvents $Limit)
    }
    if (-not $events.Count) { throw 'No matching native Sysmon records; preserve full logs and investigate retention' }
    New-Item -ItemType Directory -Path $Directory -ErrorAction Stop | Out-Null
    $xmlDir = Join-Path $Directory 'native-xml'
    New-Item -ItemType Directory -Path $xmlDir | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $assessments = @(
        foreach ($event in $events) {
            $raw = $event.ToXml()
            $path = Join-Path $xmlDir ("record-{0}.xml" -f $event.RecordId)
            [IO.File]::WriteAllText($path, $raw, $utf8)
            Get-DatnSysmonClockRecord -EventXml $raw
        }
    )
    $found = @($events | ForEach-Object { [long]$_.RecordId })
    $missing = @($RecordIds | Where-Object { $_ -notin $found })
    $summary = [ordered]@{
        version='native-sysmon-clock-evidence-v1'
        captured_at=[DateTimeOffset]::UtcNow.ToString('o')
        host=$env:COMPUTERNAME
        channel=$channel
        requested_record_ids=@($RecordIds)
        missing_record_ids=$missing
        records=$assessments
        status='EXPORT_INCOMPLETE'
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Directory 'clock-evidence.json') -Encoding UTF8
    Get-CimInstance Win32_Service -Filter "Name='Sysmon64' OR Name='Sysmon' OR Name='W32Time' OR Name='VMTools'" |
        Select-Object Name,State,ProcessId,PathName |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Directory 'services.json') -Encoding UTF8
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption,Version,BuildNumber,LastBootUpTime,LocalDateTime |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Directory 'operating-system.json') -Encoding UTF8
    Get-CimInstance Win32_SystemDriver -Filter "Name='SysmonDrv'" |
        Select-Object Name,State,PathName |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Directory 'sysmon-driver.json') -Encoding UTF8
    & w32tm.exe /query /status /verbose 2>&1 |
        Out-File -LiteralPath (Join-Path $Directory 'w32tm-status.txt') -Encoding UTF8
    $w32Exit = $LASTEXITCODE
    "exit_code=$w32Exit" | Add-Content -LiteralPath (Join-Path $Directory 'w32tm-status.txt')
    Get-TimeZone | Format-List * |
        Out-File -LiteralPath (Join-Path $Directory 'timezone.txt') -Encoding UTF8
    # Export only IDs actually observed above; a fresh event cannot expand scope.
    # Batching also keeps each native command below Windows command-line limits.
    $batchNumber=0
    $exports=@(
        foreach ($batch in @(Get-DatnEventExportBatches -RecordIds $found)) {
            $batchNumber++
            $name='sysmon-selected-{0:D3}.evtx' -f $batchNumber
            $exportPath=Join-Path $Directory $name
            & wevtutil.exe epl $channel $exportPath "/q:$($batch.XPath)" /ow:false
            if ($LASTEXITCODE -ne 0) { throw 'EVTX export failed; keep partial forensic directory' }
            $exported=@(Get-WinEvent -Path $exportPath -Oldest)
            $exportIds=@($exported | ForEach-Object { [long]$_.RecordId })
            if ($exportIds.Count -ne $batch.RecordIds.Count -or
                @(Compare-Object $batch.RecordIds $exportIds).Count) {
                throw 'Native log selection changed during export; preserve partial evidence'
            }
            foreach ($event in $exported) {
                $original=Join-Path $xmlDir ("record-{0}.xml" -f $event.RecordId)
                if ([IO.File]::ReadAllText($original) -cne $event.ToXml()) {
                    throw 'Native event changed during export; preserve XML and EVTX for review'
                }
            }
            [pscustomobject]@{File=$name; RecordIds=$exportIds}
        }
    )
    $summary['evtx_exports']=$exports
    $summary.status=if ($missing.Count -or @($assessments | Where-Object {$_.Status -ne 'PASS'}).Count) {'REVIEW'} else {'OBSERVED_PAIRS_PASS'}
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Directory 'clock-evidence.json') -Encoding UTF8
    Get-ChildItem -LiteralPath $Directory -Recurse -File |
      Where-Object { $_.Name -ne 'checksums.sha256' } | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring((Get-Item -LiteralPath $Directory).FullName.Length + 1)
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    } | Set-Content -LiteralPath (Join-Path $Directory 'checksums.sha256') -Encoding ASCII
    $summary | ConvertTo-Json -Depth 8
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $OutputDirectory) { throw 'Specify a new -OutputDirectory; this does not change source logs, clocks or services' }
    Export-DatnSysmonClockEvidence -Directory $OutputDirectory -Limit $MaxEvents -RecordIds $EventRecordIds
}
