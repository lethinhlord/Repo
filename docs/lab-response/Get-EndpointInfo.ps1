# Read-only endpoint inventory. Does not block addresses, disable users or change policy.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$destination = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw "Output already exists: $destination" }
$warnings = [Collections.Generic.List[string]]::new()
$os = Get-CimInstance Win32_OperatingSystem
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*'
} | Select-Object InterfaceAlias, IPAddress, PrefixLength)
$services = @('WazuhSvc', 'wazuh', 'sshd', 'WinRM', 'Schedule') | ForEach-Object {
    $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        name = $_; installed = [bool]$service
        status = $(if ($service) { [string]$service.Status } else { 'NOT_INSTALLED' })
    }
}
$localUsers = @()
$administrators = @()
$adminMembershipKnown = $false
try {
    $administrators = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
        $_.SID.Value
    })
    $adminMembershipKnown = $true
} catch { $warnings.Add('Could not inspect local Administrators membership.') }
foreach ($name in @('datn_lab01', 'datn_lab02', 'datn_lab03')) {
    try {
        $user = Get-LocalUser -Name $name -ErrorAction Stop
        $localUsers += [PSCustomObject]@{
            name = $user.Name; sid = $user.SID.Value; enabled = $user.Enabled
            administrator_membership_known = $adminMembershipKnown
            direct_administrator_member = $(
                if ($adminMembershipKnown) { $user.SID.Value -in $administrators } else { $null }
            )
        }
    } catch { $warnings.Add("Lab user unavailable or unreadable: $name") }
}
$firewall = @()
try { $firewall = @(Get-NetFirewallProfile | Select-Object Name, Enabled) }
catch { $warnings.Add('Could not inspect Windows Firewall profiles.') }
$fingerprint = $null
$publicKey = Join-Path $env:ProgramData 'ssh/ssh_host_ed25519_key.pub'
if ((Test-Path -LiteralPath $publicKey) -and (Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue)) {
    $value = & ssh-keygen.exe -lf $publicKey
    if ($LASTEXITCODE -eq 0) { $fingerprint = [string]($value -join ' ') }
}
$commandAvailability = [ordered]@{}
foreach ($name in @('New-NetFirewallRule', 'Get-NetFirewallRule', 'Remove-NetFirewallRule',
    'Disable-LocalUser', 'Enable-LocalUser', 'Register-ScheduledTask', 'Get-ScheduledTask')) {
    $commandAvailability[$name] = [bool](Get-Command $name -ErrorAction SilentlyContinue)
}
$policies = @(Get-ExecutionPolicy -List | ForEach-Object {
    [PSCustomObject]@{ scope = [string]$_.Scope; execution_policy = [string]$_.ExecutionPolicy }
})
$report = [ordered]@{
    version = 'datn-endpoint-response-inventory-v1'
    collected_at_utc = [DateTime]::UtcNow.ToString('o')
    hostname = $env:COMPUTERNAME
    expected_lab_hostname = ($env:COMPUTERNAME -ieq 'WIN11-TARGET')
    operating_system = $os.Caption
    build_number = $os.BuildNumber
    windows11_workstation = ([int]$os.ProductType -eq 1 -and [int]$os.BuildNumber -ge 22000)
    powershell_version = $PSVersionTable.PSVersion.ToString()
    process_is_64_bit = [Environment]::Is64BitProcess
    administrator = $admin
    ipv4 = $addresses
    services = @($services)
    firewall_profiles = $firewall
    lab_users = $localUsers
    available_commands = $commandAvailability
    execution_policies = $policies
    ssh_host_ed25519_fingerprint = $fingerprint
    actions_executed = $false
    system_rollback_execution_tested = $false
    response_enabled = $false
    warnings = @($warnings.ToArray())
}
$text = $report | ConvertTo-Json -Depth 8
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
$stream = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
} finally { $stream.Dispose() }
Write-Output "Saved read-only endpoint inventory: $destination"
