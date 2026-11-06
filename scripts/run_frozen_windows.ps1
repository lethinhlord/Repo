[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ParametersFile,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedFileSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$actual=(Get-FileHash -LiteralPath $ParametersFile -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $ExpectedFileSha256.ToLowerInvariant()) { throw 'Parameter export transport hash mismatch' }
$document=Get-Content -LiteralPath $ParametersFile -Raw -Encoding UTF8 | ConvertFrom-Json
$p=$document.scenario_parameters
if ($p.execution_profile_version -ne 'lab-action-profile-v1' -or
    $document.run_id -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{3,127}$') {
    throw 'Not an official frozen lab action export'
}
$delay=[double]$p.pre_action_delay_seconds
if ([double]::IsNaN($delay) -or [double]::IsInfinity($delay) -or $delay -lt 1 -or $delay -gt 5) {
    throw 'Invalid frozen pre-action delay'
}
if ($p.transport -eq 'console') {
    & (Join-Path $PSScriptRoot 'run_training_account.ps1') `
        -AccountsCsv $p.accounts_csv -AttemptsCsv $p.attempts_csv `
        -GapsCsv $p.expected_intervals_seconds -RunNonce $p.run_nonce `
        -PreActionDelaySeconds $delay
} elseif ($p.transport -in @('http','dns')) {
    Write-Output "ACTION_READY run=$($document.run_id) transport=$($p.transport)"
    Read-Host 'Start SOC begin-action, then press Enter here' | Out-Null
    Start-Sleep -Milliseconds ([int][Math]::Ceiling($delay*1000))
    $exe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if ($p.transport -eq 'http') {
        if ($p.endpoint -ne 'http://10.40.0.10:8081/beacon') { throw 'Unexpected HTTP endpoint' }
        $script=Join-Path $PSScriptRoot 'run_training_http.ps1'
        # Invoke HTTP in this process: Windows PowerShell's native argv marshaling
        # may drop the empty GapsCsv of the single-request profile.
        & $script -RunNonce $p.run_nonce `
            -Count $p.expected_action_count -GapsCsv $p.expected_intervals_seconds `
            -VariantIndex $p.variant_index
    } else {
        if ($p.domain_suffix -ne 'www.datn.test' -or $p.dns_server -ne '10.40.0.10') {
            throw 'Unexpected DNS inventory'
        }
        $script=Join-Path $PSScriptRoot 'run_dns_scenario.ps1'
        & $exe -NoProfile -ExecutionPolicy RemoteSigned -File $script -RunNonce $p.run_nonce `
            -Count $p.expected_action_count -GapsCsv $p.expected_intervals_seconds `
            -VariantIndex $p.variant_index -DomainSuffix $p.domain_suffix -DnsServer $p.dns_server
    }
    if ($p.transport -eq 'dns' -and $LASTEXITCODE -ne 0) {
        throw 'Child action failed; preserve evidence and abort run'
    }
} else {
    throw 'SMB profiles run on Kali, not Windows'
}
