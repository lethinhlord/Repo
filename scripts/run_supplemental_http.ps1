[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ParametersPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$profile=Get-Content -LiteralPath $ParametersPath -Raw | ConvertFrom-Json
if ($profile.execution_profile_version -ne 'lab-http-workflow-v2' -or
    $profile.transport -ne 'http' -or $profile.endpoint -ne 'http://10.40.0.10:8081/beacon') {
    throw 'Wrong frozen HTTP workflow version or endpoint'
}
$nonce=[string]$profile.run_nonce
if ($nonce -notmatch '^[A-Za-z0-9_-]{8,64}$') { throw 'Invalid attribution nonce' }
if ($profile.expected_action_count -isnot [int] -or
    $profile.expected_action_count -lt 1 -or $profile.expected_action_count -gt 64 -or
    $profile.variant_index -isnot [int] -or
    $profile.variant_index -lt 0 -or $profile.variant_index -gt 999999) { throw 'Invalid counters' }
$count=[int]$profile.expected_action_count
$methods=@(([string]$profile.http_methods_csv).Split(','))
$uploads=@(([string]$profile.request_body_bytes_csv).Split(','))
$downloads=@(([string]$profile.response_body_bytes_csv).Split(','))
if ($methods.Count -ne $count -or $uploads.Count -ne $count -or $downloads.Count -ne $count) {
    throw 'Workflow column count mismatch'
}
for ($i=0;$i -lt $count;$i++) {
    if ($methods[$i] -notin @('GET','POST') -or $uploads[$i] -notmatch '^(0|[1-9][0-9]{0,4})$' -or
        $downloads[$i] -notmatch '^[1-9][0-9]{0,4}$' -or [int]$uploads[$i] -gt 65536 -or
        [int]$downloads[$i] -gt 65536 -or
        ($methods[$i] -eq 'GET' -and [int]$uploads[$i] -ne 0) -or
        ($methods[$i] -eq 'POST' -and [int]$uploads[$i] -eq 0)) { throw 'Invalid action payload' }
}
$gaps=@()
if ([string]$profile.expected_intervals_seconds -ne '') {
    $gaps=@($profile.expected_intervals_seconds.Split(',') | ForEach-Object {
        $x=[double]::Parse($_,[Globalization.CultureInfo]::InvariantCulture)
        if ([double]::IsNaN($x) -or [double]::IsInfinity($x) -or $x -lt 0.7 -or $x -gt 300) {
            throw 'Invalid frozen timing'
        }
        $x
    })
}
if ($gaps.Count -ne $count-1 -or ($gaps | Measure-Object -Sum).Sum -gt 240) {
    throw 'Frozen schedule does not fit the capture contract'
}
$curl=@(Get-Command curl.exe -CommandType Application -ErrorAction Stop)[0].Source
$taskTempBase=[IO.Path]::GetFullPath($env:TEMP)
$taskTempName='datn-http-workflow-'+[guid]::NewGuid().ToString('N')
$taskTemp=Join-Path $taskTempBase $taskTempName
New-Item -ItemType Directory -Path $taskTemp -ErrorAction Stop | Out-Null
$processes=[Collections.Generic.List[object]]::new()
$clock=[Diagnostics.Stopwatch]::StartNew()
$previousStart=0.0
try {
    for ($i=0;$i -lt $count;$i++) {
        $arguments=@('--rate','1/2s','--fail-early','--noproxy','*','--http1.0',
            '--connect-timeout','4','--max-time','8','--fail','--silent','--show-error',
            '--header','Connection:close','--request',$methods[$i])
        if ($methods[$i] -eq 'POST') {
            $file=Join-Path $taskTemp ('request-'+$i+'.bin')
            $body=New-Object byte[] ([int]$uploads[$i])
            for ($j=0;$j -lt $body.Length;$j++) { $body[$j]=90 }
            [IO.File]::WriteAllBytes($file,$body)
            $arguments+=@('--header','Content-Type:application/octet-stream','--data-binary',('@'+$file))
        }
        $seq=$i+1
        $url="http://10.40.0.10:8081/beacon?run=$nonce&v=$($profile.variant_index)&n=$seq&z=$($downloads[$i])"
        $arguments+=@('--output','NUL','--write-out','%{http_code}',$url,
            '--next','--noproxy','*','--silent','--show-error','--output','NUL','file:///C:/Windows/win.ini',
            '--next','--noproxy','*','--silent','--show-error','--output','NUL','file:///C:/Windows/win.ini')
        # All values are generated/validated and none may contain native quote/control syntax.
        foreach ($value in $arguments) {
            if ($value -match '["\r\n\x00]' -or $value.EndsWith('\')) { throw 'Unsafe native argument' }
        }
        $scheduled=0.0
        if ($i -gt 0) { $scheduled=$previousStart+$gaps[$i-1] }
        $remaining=$scheduled-$clock.Elapsed.TotalSeconds
        if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000)) }
        if ($clock.Elapsed.TotalSeconds-$scheduled -gt 2) { throw 'Missed frozen action deadline' }
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=$curl
        $info.Arguments=($arguments | ForEach-Object { '"'+$_+'"' }) -join ' '
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        $previousStart=$clock.Elapsed.TotalSeconds
        $proc=[Diagnostics.Process]::Start($info)
        if ($null -eq $proc) { throw 'Native HTTP process failed to start' }
        $processes.Add([pscustomobject]@{Sequence=$seq; Process=$proc})
        Write-Output "HTTP_REQUEST_LAUNCHED seq=$seq method=$($methods[$i])"
    }
    foreach ($item in $processes) {
        if (-not $item.Process.WaitForExit(15000)) { throw 'Native HTTP process timed out' }
        $status=$item.Process.StandardOutput.ReadToEnd().Trim()
        $errorText=$item.Process.StandardError.ReadToEnd()
        if ($item.Process.ExitCode -ne 0 -or $status -ne '200') {
            throw "HTTP request failed seq=$($item.Sequence) status=$status $errorText"
        }
        Write-Output "HTTP_REQUEST_OK seq=$($item.Sequence) status=200"
    }
    Start-Sleep -Seconds 5
    Write-Output "HTTP_ACTION_COMPLETE count=$count nonce=$nonce"
} finally {
    foreach ($item in $processes) {
        if (-not $item.Process.HasExited) { $item.Process.Kill(); $item.Process.WaitForExit() }
        $item.Process.Dispose()
    }
    $resolvedTask=[IO.Path]::GetFullPath($taskTemp)
    $expectedTask=[IO.Path]::GetFullPath((Join-Path $taskTempBase $taskTempName))
    if ($resolvedTask -ne $expectedTask -or
        -not $resolvedTask.StartsWith($taskTempBase+[IO.Path]::DirectorySeparatorChar,
                                     [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe cleanup path' }
    Remove-Item -LiteralPath $resolvedTask -Recurse -Force
}
