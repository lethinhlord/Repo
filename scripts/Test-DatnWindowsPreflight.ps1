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
  if (-not $Program -or -not $Service) {
    return [pscustomobject]@{Status=$status; Reason=$reason}
  }
  if ($Service -notin @('Any','LanmanServer')) {
    return [pscustomobject]@{Status='NOT_SMB'; Reason='Service filter excludes the SMB server'}
  }
  $application = $Program.Trim('"').Trim()
  if ($application -notin @('Any','System')) {
    if ($application -match '\\[^\\*?]+\.exe$') {
      return [pscustomobject]@{Status='NOT_SMB'; Reason='Application filter excludes the SMB server'}
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

function Compare-DatnIPBytes {
  param([byte[]]$First, [byte[]]$Second)
  for ($i=0; $i -lt $First.Length; $i++) {
    if ($First[$i] -lt $Second[$i]) { return -1 }
    if ($First[$i] -gt $Second[$i]) { return 1 }
  }
  return 0
}

function Test-DatnLocalAddressScope {
  param([string]$Scope, [string]$Address)
  if ($Scope -in @('Any','*')) { return $true }
  $current = $null
  if (-not [System.Net.IPAddress]::TryParse($Address,[ref]$current)) { return $null }
  if ($Scope -match '^(.+)/(\d+)$') {
    $network = $null; $prefix = [int]$Matches[2]
    if (-not [System.Net.IPAddress]::TryParse($Matches[1],[ref]$network)) { return $null }
    $netBytes = $network.GetAddressBytes(); $addressBytes = $current.GetAddressBytes()
    if ($prefix -gt $netBytes.Length * 8) { return $null }
    if ($netBytes.Length -ne $addressBytes.Length) { return $false }
    for ($i=0; $i -lt $netBytes.Length; $i++) {
      $used = [Math]::Min(8,[Math]::Max(0,$prefix - $i*8))
      $mask = [int](256 - [Math]::Pow(2,8-$used))
      if (($netBytes[$i] -band $mask) -ne ($addressBytes[$i] -band $mask)) { return $false }
    }
    return $true
  }
  if ($Scope -match '^(.+)-(.+)$') {
    $first = $null; $last = $null
    if (-not [System.Net.IPAddress]::TryParse($Matches[1],[ref]$first) -or
        -not [System.Net.IPAddress]::TryParse($Matches[2],[ref]$last)) { return $null }
    $lo = $first.GetAddressBytes(); $hi = $last.GetAddressBytes()
    if ($lo.Length -ne $hi.Length -or (Compare-DatnIPBytes $lo $hi) -gt 0) { return $null }
    $value = $current.GetAddressBytes()
    if ($lo.Length -ne $value.Length) { return $false }
    return (Compare-DatnIPBytes $lo $value) -le 0 -and (Compare-DatnIPBytes $value $hi) -le 0
  }
  $exact = $null
  if ([System.Net.IPAddress]::TryParse($Scope,[ref]$exact)) { return $exact.Equals($current) }
  return $null
}

function Get-DatnFirewallRuleApplicability {
  param(
    [string[]]$Profiles, [string[]]$InterfaceAliases, [string[]]$LocalAddresses,
    [string[]]$InterfaceTypes, [object[]]$Adapters
  )
  if (-not $Profiles -or -not $InterfaceAliases -or -not $LocalAddresses -or
      -not $InterfaceTypes -or -not $Adapters) {
    return [pscustomobject]@{Status='INCONCLUSIVE'; Reason='Missing effective adapter/filter data'}
  }
  $unresolved = $false
  foreach ($adapter in $Adapters) {
    $aliasMatches = 'Any' -in $InterfaceAliases -or @($InterfaceAliases | Where-Object {
      $adapter.Name -like $_
    }).Count -gt 0
    if (-not $aliasMatches) { continue }
    $unknown = $false
    if ('Any' -notin $Profiles) {
      if (-not $adapter.Profile -or $adapter.Profile -eq 'Unknown') { $unknown = $true }
      elseif ($adapter.Profile -notin $Profiles) { continue }
    }
    if ('Any' -notin $InterfaceTypes) {
      if (-not $adapter.InterfaceType -or $adapter.InterfaceType -eq 'Unknown') { $unknown = $true }
      elseif ($adapter.InterfaceType -notin $InterfaceTypes) { continue }
    }
    $addressMatches = $false; $addressUnknown = -not $adapter.Addresses
    foreach ($scope in $LocalAddresses) {
      foreach ($address in $adapter.Addresses) {
        $match = Test-DatnLocalAddressScope -Scope $scope -Address $address
        if ($null -eq $match) { $addressUnknown = $true }
        elseif ($match) { $addressMatches = $true }
      }
    }
    if (-not $addressMatches -and -not $addressUnknown) { continue }
    if ($unknown -or (-not $addressMatches -and $addressUnknown)) { $unresolved = $true }
    else { return [pscustomobject]@{Status='APPLIES'; Reason='Filters intersect on an active adapter'} }
  }
  if ($unresolved) {
    return [pscustomobject]@{Status='INCONCLUSIVE'; Reason='Effective adapter scope is unresolved'}
  }
  return [pscustomobject]@{Status='NOT_APPLICABLE'; Reason='No active adapter matches all filters'}
}

function Invoke-DatnWindowsFirewallInspection {
  param([string]$AllowedSource)
  $ErrorActionPreference = 'Stop'
  $connections = @(Get-NetConnectionProfile)
  $adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
    $nic = $_
    $connection = @($connections | Where-Object InterfaceIndex -eq $nic.ifIndex)
    $profile = 'Unknown'
    if ($connection.Count -eq 1) {
      $profile = [string]$connection[0].NetworkCategory
      if ($profile -eq 'DomainAuthenticated') { $profile = 'Domain' }
    }
    $media = [string]$nic.MediaType
    $interfaceType = 'Unknown'
    if ($media -match '802[. ]11') { $interfaceType = 'Wireless' }
    elseif ($media -eq '802.3') { $interfaceType = 'Lan' }
    elseif ($media -eq 'WAN') { $interfaceType = 'RemoteAccess' }
    [pscustomobject]@{
      Name=$nic.Name; Profile=$profile; InterfaceType=$interfaceType
      Addresses=@(Get-NetIPAddress -InterfaceIndex $nic.ifIndex |
        Where-Object AddressState -in @('Preferred','Deprecated') |
        Select-Object -ExpandProperty IPAddress)
    }
  })
  $profiles = @($adapters | Select-Object -ExpandProperty Profile -Unique)
  $disabled = @(Get-NetFirewallProfile -PolicyStore ActiveStore |
    Where-Object { ($_.Name -in $profiles -or 'Unknown' -in $profiles) -and -not $_.Enabled })
  if ($disabled.Count) { throw 'An active Windows firewall profile is disabled' }
  $rows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True `
    -Direction Inbound -Action Allow | ForEach-Object {
      $rule = $_
      $ruleProfiles = @(([string]$rule.Profile -split ',') | ForEach-Object { $_.Trim() })
      $port = $rule | Get-NetFirewallPortFilter
      $address = $rule | Get-NetFirewallAddressFilter
      $application = $rule | Get-NetFirewallApplicationFilter
      $service = $rule | Get-NetFirewallServiceFilter
      $interfaces = $rule | Get-NetFirewallInterfaceFilter
      $interfaceTypes = $rule | Get-NetFirewallInterfaceTypeFilter
      $assessment = Get-DatnSmbRuleAssessment -Protocol ([string]$port.Protocol) `
        -LocalPort $port.LocalPort -RemoteAddress $address.RemoteAddress `
        -Program ([string]$application.Program) -Service ([string]$service.Service) `
        -AllowedSource $AllowedSource
      if ($assessment.Status -ne 'NOT_SMB') {
        $scope = Get-DatnFirewallRuleApplicability -Profiles $ruleProfiles `
          -InterfaceAliases $interfaces.InterfaceAlias -LocalAddresses $address.LocalAddress `
          -InterfaceTypes $interfaceTypes.InterfaceType -Adapters $adapters
        if ($scope.Status -eq 'NOT_APPLICABLE') { return }
        if ($scope.Status -eq 'INCONCLUSIVE') { $assessment = $scope }
        [pscustomobject]@{
          Name=$rule.Name; Status=$assessment.Status; Reason=$assessment.Reason
          Profile=[string]$rule.Profile; Program=$application.Program
          Service=$service.Service; RemoteAddress=($address.RemoteAddress -join ',')
          InterfaceAlias=($interfaces.InterfaceAlias -join ',')
          InterfaceType=($interfaceTypes.InterfaceType -join ',')
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
