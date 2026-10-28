[CmdletBinding()]
param(
  [switch]$InspectHost,
  [string]$AllowedSource = '10.40.0.10'
)

# Dot-sourcing only defines pure helpers. Host inspection is an explicit read-only mode.
function Get-DatnSmbRuleAssessment {
  [CmdletBinding()]
  param(
    [AllowEmptyString()][string]$Protocol,
    [string[]]$LocalPort,
    [string[]]$RemoteAddress,
    [AllowEmptyString()][string]$Program,
    [AllowEmptyString()][string]$Service,
    [string]$AllowedSource = '10.40.0.10'
  )
  $status = 'INCONCLUSIVE'
  $reason = 'Unresolved firewall filter; verify effective connectivity'
  $protocolName = $Protocol.Trim().ToLowerInvariant()
  if ($protocolName -notin @('tcp','6','any','256')) {
    if ($protocolName -in @('udp','17','41','icmpv4','icmpv6','1','58') -or
        $protocolName -match '^\d+$') {
      return [pscustomobject]@{Status='NOT_SMB'; Reason='Protocol cannot permit TCP 445'}
    }
    return [pscustomobject]@{Status=$status; Reason=$reason}
  }
  $has445 = $false
  $unknownPort = $false
  foreach ($entry in $LocalPort) {
    foreach ($port in ($entry -split ',')) {
      $port = $port.Trim()
      if ($port -eq 'Any' -or $port -eq '445') { $has445 = $true }
      elseif ($port -match '^(\d+)-(\d+)$') {
        $first = [int]$Matches[1]; $last = [int]$Matches[2]
        if ($first -gt $last -or $last -gt 65535) { $unknownPort = $true }
        elseif ($first -le 445 -and $last -ge 445) { $has445 = $true }
      } elseif ($port -notmatch '^\d+$') { $unknownPort = $true }
    }
  }
  if (-not $LocalPort -or $unknownPort) {
    return [pscustomobject]@{Status=$status; Reason=$reason}
  }
  if (-not $has445) {
    return [pscustomobject]@{Status='NOT_SMB'; Reason='Port filter excludes TCP 445'}
  }
  if (-not $Program -or -not $Service) {
    return [pscustomobject]@{Status=$status; Reason=$reason}
  }
  $application = $Program.Trim('"').Trim()
  if ($application -notin @('Any','System')) {
    if ($application -match '\\[^\\*?]+\.exe$' -and
        $application -notmatch '\\svchost\.exe$') {
      return [pscustomobject]@{Status='NOT_SMB'; Reason='Application filter excludes the SMB server'}
    }
    return [pscustomobject]@{Status=$status; Reason=$reason}
  }
  if ($Service -notin @('Any','LanmanServer')) {
    return [pscustomobject]@{Status=$status; Reason=$reason}
  }
  $allowed = [System.Net.IPAddress]::Parse($AllowedSource)
  $broad = $false
  $unknown = -not $RemoteAddress
  foreach ($entry in $RemoteAddress) {
    foreach ($remote in ($entry -split ',')) {
      $remote = $remote.Trim()
      if ($remote -in @('Any','LocalSubnet','Internet','Intranet','DNS','DHCP','WINS')) {
        $broad = $true; continue
      }
      $address = $null
      if ($remote -match '^(.+)/(\d+)$') {
        $hostPart = $Matches[1]; $prefix = [int]$Matches[2]
        if (-not [System.Net.IPAddress]::TryParse($hostPart,[ref]$address)) {
          $unknown = $true; continue
        }
        $width = $address.GetAddressBytes().Length * 8
        if ($prefix -gt $width) { $unknown = $true; continue }
        if ($prefix -ne $width -or -not $address.Equals($allowed)) { $broad = $true }
      } elseif ($remote -match '^(.+)-(.+)$') {
        $first = $null; $last = $null
        $valid = [System.Net.IPAddress]::TryParse($Matches[1],[ref]$first) -and
                 [System.Net.IPAddress]::TryParse($Matches[2],[ref]$last)
        if (-not $valid -or $first.AddressFamily -ne $last.AddressFamily) {
          $unknown = $true; continue
        }
        if (-not $first.Equals($allowed) -or -not $last.Equals($allowed)) { $broad = $true }
      } elseif ([System.Net.IPAddress]::TryParse($remote,[ref]$address)) {
        if (-not $address.Equals($allowed)) { $broad = $true }
      } else { $unknown = $true }
    }
  }
  if ($broad) { $status='BROAD'; $reason='Rule permits TCP 445 beyond the allowed lab source' }
  elseif (-not $unknown) { $status='SCOPED'; $reason='TCP 445 is limited to the allowed source' }
  [pscustomobject]@{Status=$status; Reason=$reason}
}

function Invoke-DatnWindowsFirewallInspection {
  param([string]$AllowedSource)
  $ErrorActionPreference = 'Stop'
  $profiles = @(Get-NetConnectionProfile | ForEach-Object {
    if ($_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' }
    else { [string]$_.NetworkCategory }
  })
  $disabled = @(Get-NetFirewallProfile -PolicyStore ActiveStore |
    Where-Object { $_.Name -in $profiles -and -not $_.Enabled })
  if ($disabled.Count) { throw 'An active Windows firewall profile is disabled' }
  $rows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True `
    -Direction Inbound -Action Allow | ForEach-Object {
      $rule = $_
      $port = $rule | Get-NetFirewallPortFilter
      $address = $rule | Get-NetFirewallAddressFilter
      $application = $rule | Get-NetFirewallApplicationFilter
      $service = $rule | Get-NetFirewallServiceFilter
      $assessment = Get-DatnSmbRuleAssessment -Protocol ([string]$port.Protocol) `
        -LocalPort $port.LocalPort -RemoteAddress $address.RemoteAddress `
        -Program ([string]$application.Program) -Service ([string]$service.Service) `
        -AllowedSource $AllowedSource
      if ($assessment.Status -ne 'NOT_SMB') {
        [pscustomobject]@{
          Name=$rule.Name; Status=$assessment.Status; Reason=$assessment.Reason
          Profile=[string]$rule.Profile; Program=$application.Program
          Service=$service.Service; RemoteAddress=($address.RemoteAddress -join ',')
          InterfaceAlias=(($rule | Get-NetFirewallInterfaceFilter).InterfaceAlias -join ',')
          LocalAddress=($address.LocalAddress -join ',')
        }
      }
    })
  $rows | Format-Table Name,Status,Profile,RemoteAddress -AutoSize
  $unresolved = @($rows | Where-Object Status -in @('BROAD','INCONCLUSIVE'))
  if ($unresolved.Count) {
    $unresolved | Format-List *
    throw 'Review TCP 445 rules with profile/interface/local-address filters; retain firewall and verify allowed/denied connectivity'
  }
  Write-Output 'Rule filters are scoped; still verify effective TCP 445 connectivity from allowed and denied VMs.'
}

if ($MyInvocation.InvocationName -ne '.' -and $InspectHost) {
  Invoke-DatnWindowsFirewallInspection -AllowedSource $AllowedSource
}
