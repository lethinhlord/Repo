[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{8,64}$')][string]$RunNonce,
    [Parameter(Mandatory=$true)][ValidateRange(1,64)][int]$Count,
    [Parameter(Mandatory=$true)][string]$GapsCsv,
    [Parameter(Mandatory=$true)][ValidateRange(0,999999)][int]$VariantIndex,
    [ValidateSet('C2-BENIGN-HEALTH-POLL','C2-BENIGN-IRREGULAR-API','C2-BENIGN-API-BURST',
        'C2-MALICIOUS-HTTP-BEACON','C2-MALICIOUS-JITTER-BEACON')]
    [string]$ScenarioId='C2-MALICIOUS-HTTP-BEACON'
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$expectedCounts=@{
    'C2-BENIGN-HEALTH-POLL'=8
    'C2-BENIGN-IRREGULAR-API'=4
    'C2-BENIGN-API-BURST'=6
    'C2-MALICIOUS-HTTP-BEACON'=8
    'C2-MALICIOUS-JITTER-BEACON'=8
}
if ($Count -ne $expectedCounts[$ScenarioId]) { throw 'Action count does not match the scenario contract' }
$culture=[Globalization.CultureInfo]::InvariantCulture
$gaps=@($GapsCsv.Split(',') | ForEach-Object {
    $value=[double]::Parse($_.Trim(),$culture)
    if ([double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 1 -or $value -gt 300) {
        throw 'Invalid frozen HTTP interval'
    }
    $value
})
if ($gaps.Count -ne $Count-1) { throw 'Interval count does not match the action count' }
$curl=@(Get-Command curl.exe -CommandType Application -ErrorAction Stop)[0].Source
$base='http://10.40.0.10:8081/beacon'
$prefix=''
if ($ScenarioId -eq 'C2-BENIGN-HEALTH-POLL') { $prefix='mode=health&' }
if ($ScenarioId -in 'C2-BENIGN-IRREGULAR-API','C2-BENIGN-API-BURST') {
    $base='http://10.40.0.10:8080/api/status'
}

Write-Output "HTTP_ACTION_START count=$Count nonce=$RunNonce"
$clock=[Diagnostics.Stopwatch]::StartNew()
$scheduled=0.0
$previousStart=0.0
for ($index=1; $index -le $Count; $index++) {
    if ($index -gt 1) { $scheduled = $previousStart + $gaps[$index-2] }
    $remaining=$scheduled-$clock.Elapsed.TotalSeconds
    if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000)) }
    # A slow prior request must not silently compress the frozen action schedule.
    if ($clock.Elapsed.TotalSeconds-$scheduled -gt 2) { throw 'HTTP action missed its frozen start deadline; abort run' }
    $previousStart=$clock.Elapsed.TotalSeconds
    $url="${base}?${prefix}run=$RunNonce&v=$VariantIndex&n=$index"
    $LASTEXITCODE=0
    $status=& $curl --http1.1 --noproxy '*' --connect-timeout 4 --max-time 8 `
        --fail --silent --show-error --header 'Connection: close' `
        --output NUL --write-out '%{http_code}' $url
    if ($LASTEXITCODE -ne 0 -or "$status".Trim() -ne '200') {
        throw "HTTP request $index failed: curl_exit=$LASTEXITCODE http=$status"
    }
    Write-Output "HTTP_REQUEST_OK seq=$index status=200"
}
# This gives queued Sysmon events time to be attributed before the parent exits.
Start-Sleep -Seconds 5
Write-Output "HTTP_ACTION_COMPLETE count=$Count"
