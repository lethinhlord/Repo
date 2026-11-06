[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$AccountsCsv,
    [Parameter(Mandatory=$true)][string]$AttemptsCsv,
    [Parameter(Mandatory=$true)][AllowEmptyString()][string]$GapsCsv,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{8,64}$')][string]$RunNonce,
    [ValidateRange(0,5)][double]$PreActionDelaySeconds=0,
    [switch]$Enrollment
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$users=@($AccountsCsv.Split(','))
$actions=@($AttemptsCsv.Split(','))
if ($users.Count -lt 1 -or $users.Count -gt 3 -or @($users | Select-Object -Unique).Count -ne $users.Count) {
    throw 'Invalid disposable account list'
}
foreach ($user in $users) { if ($user -notmatch '^datn_lab0[123]$') { throw 'Only disposable lab accounts allowed' } }
if ($actions.Count -lt 1 -or $actions.Count -gt 64) { throw 'Invalid action count' }
foreach ($action in $actions) {
    $parts=$action.Split(':')
    if ($parts.Count -ne 2 -or $parts[0] -notin $users -or $parts[1] -notin @('fail','success')) {
        throw 'Invalid frozen account action'
    }
}
if ($Enrollment -and ($actions.Count -ne $users.Count -or
    @($actions | Select-Object -Unique).Count -ne $users.Count -or
    @($actions | Where-Object { $_ -notmatch ':success$' }).Count -ne 0)) {
    throw 'Enrollment permits one successful authentication per account only'
}
$culture=[Globalization.CultureInfo]::InvariantCulture
$gaps=@()
if ($GapsCsv -ne '') {
    $gaps=@($GapsCsv.Split(',') | ForEach-Object {
        $v=[double]::Parse($_,$culture)
        if ([double]::IsNaN($v) -or [double]::IsInfinity($v) -or $v -lt 0.7 -or $v -gt 300) {
            throw 'Invalid frozen account interval'
        }
        $v
    })
}
if ($gaps.Count -ne $actions.Count-1 -or ($gaps | Measure-Object -Sum).Sum -gt 240) {
    throw 'Frozen account schedule mismatch'
}
$credentials=@{}
foreach ($user in $users) {
    $credential=Get-Credential -UserName "$env:COMPUTERNAME\$user" -Message "Lab credential for $user"
    if ($null -eq $credential -or $credential.UserName -ne "$env:COMPUTERNAME\$user") { throw 'Credential identity mismatch' }
    $credentials[$user]=$credential
}
if (-not ('DatnTrainingLogon' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DatnTrainingLogon {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password,
        int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
}
Write-Output "ACCOUNT_READY nonce=$RunNonce count=$($actions.Count)"
if ($Enrollment) {
    Read-Host 'Credentials loaded. Confirm SOC enrollment capture cursor is open, then press Enter' | Out-Null
} else {
    Read-Host 'Credentials loaded. Start SOC begin-action, then press Enter here' | Out-Null
}
Start-Sleep -Milliseconds ([int][Math]::Ceiling($PreActionDelaySeconds*1000))
$clock=[Diagnostics.Stopwatch]::StartNew()
$previousStart=0.0
for ($index=0; $index -lt $actions.Count; $index++) {
    $scheduled=0.0
    if ($index -gt 0) { $scheduled=$previousStart+$gaps[$index-1] }
    $remaining=$scheduled-$clock.Elapsed.TotalSeconds
    if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000)) }
    if ($clock.Elapsed.TotalSeconds-$scheduled -gt 2) { throw 'Account missed schedule; abort run' }
    $previousStart=$clock.Elapsed.TotalSeconds
    $user,$expected=$actions[$index].Split(':')
    $password=$credentials[$user].GetNetworkCredential().Password
    if ($expected -eq 'fail') { $password=$password+'__DATN_WRONG_'+$RunNonce }
    $token=[IntPtr]::Zero
    try {
        $ok=[DatnTrainingLogon]::LogonUser($user,$env:COMPUTERNAME,$password,2,0,[ref]$token)
        $code=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (($expected -eq 'success' -and -not $ok) -or
            ($expected -eq 'fail' -and ($ok -or $code -ne 1326))) {
            throw "Unexpected authentication result seq=$($index+1) win32=$code"
        }
    } finally {
        if ($token -ne [IntPtr]::Zero) { [void][DatnTrainingLogon]::CloseHandle($token) }
        $password=$null
    }
    Write-Output "ACCOUNT_ATTEMPT_OK seq=$($index+1) user=$user expected=$expected"
}
Start-Sleep -Seconds 5
Write-Output "ACCOUNT_ACTION_COMPLETE count=$($actions.Count)"
