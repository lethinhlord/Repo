[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]{8,64}$')]
    [string]$RunNonce,

    [Parameter(Mandatory = $true)]
    [ValidateSet('www.datn.test', 'beacon.datn.test')]
    [string]$DomainSuffix,

    [Parameter(Mandatory = $true)]
    [ValidateRange(2, 64)]
    [int]$Count,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GapsCsv,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 999999)]
    [int]$VariantIndex,

    [ValidateSet('10.40.0.10')]
    [string]$DnsServer = '10.40.0.10'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$invariant = [Globalization.CultureInfo]::InvariantCulture
$gaps = @(
    $GapsCsv.Split(',') | ForEach-Object {
        $value = [double]::Parse($_, $invariant)
        if ([double]::IsNaN($value) -or [double]::IsInfinity($value) -or
            $value -lt 1 -or $value -gt 300) {
            throw "Invalid DNS interval: $_"
        }
        $value
    }
)
if ($gaps.Count -ne ($Count - 1)) {
    throw "GapsCsv must contain exactly $($Count - 1) intervals for Count=$Count"
}

if ($DomainSuffix -eq 'www.datn.test') {
    $scenarioMarker = 'b'
} else {
    $scenarioMarker = 'r'
}

for ($index = 1; $index -le $Count; $index++) {
    $name = '{0}-{1}{2}-{3:D2}.{4}' -f `
        $RunNonce, $scenarioMarker, $VariantIndex, $index, $DomainSuffix
    $answer = Resolve-DnsName -Name $name -Server $DnsServer -Type A -DnsOnly
    if ('10.40.0.10' -notin @($answer.IPAddress)) {
        throw "Wrong DNS answer for ${name}: expected 10.40.0.10"
    }
    Write-Output "DNS_QUERY_OK name=$name answer=10.40.0.10"
    if ($index -lt $Count) {
        $milliseconds = [int][Math]::Round($gaps[$index - 1] * 1000)
        Start-Sleep -Milliseconds $milliseconds
    }
}
