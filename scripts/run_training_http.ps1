[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{8,64}$')][string]$RunNonce,
    [Parameter(Mandatory=$true)][ValidateRange(1,64)][int]$Count,
    [Parameter(Mandatory=$true)][AllowEmptyString()][string]$GapsCsv,
    [Parameter(Mandatory=$true)][ValidateRange(0,999999)][int]$VariantIndex
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$culture=[Globalization.CultureInfo]::InvariantCulture
$gaps=@()
if ($GapsCsv -ne '') {
    $gaps=@($GapsCsv.Split(',') | ForEach-Object {
        $value=[double]::Parse($_.Trim(),$culture)
        if ([double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0.7 -or $value -gt 300) {
            throw 'Invalid frozen interval'
        }
        $value
    })
}
if ($gaps.Count -ne $Count-1 -or ($gaps | Measure-Object -Sum).Sum -gt 240) {
    throw 'Frozen action count or duration mismatch'
}
$curl=@(Get-Command curl.exe -CommandType Application -ErrorAction Stop)[0].Source
$clock=[Diagnostics.Stopwatch]::StartNew()
$previousStart=0.0
for ($index=1; $index -le $Count; $index++) {
    $scheduled=0.0
    if ($index -gt 1) { $scheduled=$previousStart+$gaps[$index-2] }
    $remaining=$scheduled-$clock.Elapsed.TotalSeconds
    if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000)) }
    if ($clock.Elapsed.TotalSeconds-$scheduled -gt 2) { throw 'HTTP missed schedule; abort run' }
    $previousStart=$clock.Elapsed.TotalSeconds
    $url="http://10.40.0.10:8081/beacon?run=$RunNonce&v=$VariantIndex&n=$index"
    $LASTEXITCODE=0
    $status=& $curl --http1.1 --noproxy '*' --connect-timeout 4 --max-time 8 `
        --fail --silent --show-error --header 'Connection: close' `
        --output NUL --write-out '%{http_code}' $url
    if ($LASTEXITCODE -ne 0 -or "$status".Trim() -ne '200') { throw "HTTP request $index failed" }
    Write-Output "HTTP_REQUEST_OK seq=$index status=200"
}
Start-Sleep -Seconds 5
Write-Output "HTTP_ACTION_COMPLETE count=$Count nonce=$RunNonce"
