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
if (-not (Test-Path -LiteralPath 'C:\Windows\win.ini' -PathType Leaf)) {
    throw 'Required local curl hold file is missing'
}
$clock=[Diagnostics.Stopwatch]::StartNew()
$previousStart=0.0
$processes=[Collections.Generic.List[object]]::new()
$tempDir=Join-Path $env:TEMP ("datn-http-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir -ErrorAction Stop | Out-Null

try {
    for ($index=1; $index -le $Count; $index++) {
        $scheduled=0.0
        if ($index -gt 1) { $scheduled=$previousStart+$gaps[$index-2] }

        $remaining=$scheduled-$clock.Elapsed.TotalSeconds
        if ($remaining -gt 0) {
            Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000))
        }

        if ($clock.Elapsed.TotalSeconds-$scheduled -gt 2) {
            throw 'HTTP missed schedule; abort run'
        }

        $previousStart=$clock.Elapsed.TotalSeconds
        $url="http://10.40.0.10:8081/beacon?run=$RunNonce&v=$VariantIndex&n=$index"

        $stdout=Join-Path $tempDir "curl-$index.out"
        $stderr=Join-Path $tempDir "curl-$index.err"

        $arguments=@(
            '--rate','1/2s','--fail-early','--noproxy','*',
            '--http1.0','--connect-timeout','4','--max-time','8',
            '--fail','--silent','--show-error',
            '--header','Connection:close',
            '--output','NUL','--write-out','%{http_code}', $url,
            '--next','--noproxy','*','--silent','--show-error',
            '--output','NUL','file:///C:/Windows/win.ini',
            '--next','--noproxy','*','--silent','--show-error',
            '--output','NUL','file:///C:/Windows/win.ini'
        )

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $curl
        $psi.Arguments = $arguments -join ' '
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $proc = [System.Diagnostics.Process]::Start($psi)

        if ($null -eq $proc) {
            throw "Failed to start curl seq=$index"
        }

        $processes.Add([pscustomobject]@{
            Index = $index
            Process = $proc
        })
        Write-Output "HTTP_REQUEST_LAUNCHED seq=$index"
    }

    foreach ($item in $processes) {
        $proc = $item.Process

        if (-not $proc.WaitForExit(15000)) {
            throw "HTTP curl timeout seq=$($item.Index)"
        }

        $proc.WaitForExit()
        $status = $proc.StandardOutput.ReadToEnd().Trim()
        $errorText = $proc.StandardError.ReadToEnd()
        $exitCode = $proc.ExitCode

        Write-Host "CURL_RESULT seq=$($item.Index) exit=$exitCode status=$status"

        if ($exitCode -ne 0 -or $status -ne '200') {
            throw "HTTP request $($item.Index) failed: exit=$exitCode status=$status stderr=$errorText"
        }

        Write-Output "HTTP_REQUEST_OK seq=$($item.Index) status=200"
    }
    Start-Sleep -Seconds 5
    Write-Output "HTTP_ACTION_COMPLETE count=$Count nonce=$RunNonce"
}
finally {
    foreach ($item in $processes) {
        if (-not $item.Process.HasExited) {
            $item.Process.Kill()
            $item.Process.WaitForExit()
        }
        $item.Process.Dispose()
    }
}
