[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$MgmtHostIPAddress = '192.168.49.254',
    [int]$MgmtPrefixLength = 24,
    [bool]$ConfigureMgmtNat = $true,
    [string]$MgmtNatName = 'Atlaso-Mgmt-NAT'
)

$ErrorActionPreference = 'Stop'

$switches = @(
    @{ Name = 'Atlaso-Mgmt'; Type = 'Internal' },
    @{ Name = 'Atlaso-Services'; Type = 'Private' },
    @{ Name = 'Atlaso-SiteA'; Type = 'Private' },
    @{ Name = 'Atlaso-SiteB'; Type = 'Private' },
    @{ Name = 'Atlaso-Trunk'; Type = 'Private' }
)

foreach ($switch in $switches) {
    $existing = Get-VMSwitch -Name $switch.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Switch already exists: $($switch.Name)"
        continue
    }

    if ($PSCmdlet.ShouldProcess($switch.Name, "Create $($switch.Type) Hyper-V switch")) {
        New-VMSwitch -Name $switch.Name -SwitchType $switch.Type | Out-Null
        Write-Host "Created switch: $($switch.Name)"
    }
}

$mgmtAdapterName = 'vEthernet (Atlaso-Mgmt)'
$mgmtAdapter = Get-NetAdapter -Name $mgmtAdapterName -ErrorAction SilentlyContinue
if (-not $mgmtAdapter) {
    Write-Warning "Host adapter not found: $mgmtAdapterName"
    return
}

Set-NetIPInterface -InterfaceAlias $mgmtAdapterName -AddressFamily IPv4 -Dhcp Disabled -DadTransmits 0

$mgmtAddresses = Get-NetIPAddress -InterfaceAlias $mgmtAdapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue
$mgmtAddresses |
    Where-Object { $_.IPAddress -like '169.254.*' } |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

$existingAddress = $mgmtAddresses |
    Where-Object { $_.IPAddress -eq $MgmtHostIPAddress -and $_.PrefixLength -eq $MgmtPrefixLength }
$preferredAddress = $existingAddress | Where-Object { $_.AddressState -eq 'Preferred' }

if ($existingAddress -and -not $preferredAddress) {
    if ($PSCmdlet.ShouldProcess($mgmtAdapterName, "Repair non-preferred $MgmtHostIPAddress/$MgmtPrefixLength address")) {
        $existingAddress |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        $existingAddress = $null
        Write-Host "Removed non-preferred $MgmtHostIPAddress/$MgmtPrefixLength from $mgmtAdapterName"
    }
}

if (-not $existingAddress) {
    if ($PSCmdlet.ShouldProcess($mgmtAdapterName, "Assign $MgmtHostIPAddress/$MgmtPrefixLength")) {
        Get-NetIPAddress -InterfaceAlias $mgmtAdapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceAlias $mgmtAdapterName -IPAddress $MgmtHostIPAddress -PrefixLength $MgmtPrefixLength | Out-Null
        Write-Host "Assigned $MgmtHostIPAddress/$MgmtPrefixLength to $mgmtAdapterName"
    }
} else {
    Write-Host "$mgmtAdapterName already has $MgmtHostIPAddress/$MgmtPrefixLength"
}

if ($ConfigureMgmtNat) {
    $prefixOctets = $MgmtHostIPAddress.Split('.')
    $natPrefix = "$($prefixOctets[0]).$($prefixOctets[1]).$($prefixOctets[2]).0/$MgmtPrefixLength"
    $existingNat = Get-NetNat -Name $MgmtNatName -ErrorAction SilentlyContinue
    if ($existingNat -and $existingNat.InternalIPInterfaceAddressPrefix -ne $natPrefix) {
        if ($PSCmdlet.ShouldProcess($MgmtNatName, "Replace NAT prefix $($existingNat.InternalIPInterfaceAddressPrefix) with $natPrefix")) {
            Remove-NetNat -Name $MgmtNatName -Confirm:$false
            $existingNat = $null
            Write-Host "Removed NAT $MgmtNatName with old prefix"
        }
    }

    if (-not $existingNat) {
        if ($PSCmdlet.ShouldProcess($MgmtNatName, "Create NAT for $natPrefix")) {
            New-NetNat -Name $MgmtNatName -InternalIPInterfaceAddressPrefix $natPrefix | Out-Null
            Write-Host "Created NAT $MgmtNatName for $natPrefix"
        }
    } else {
        Write-Host "NAT already exists: $MgmtNatName ($($existingNat.InternalIPInterfaceAddressPrefix))"
    }
}

Write-Host ""
Write-Host "Atlaso management network summary:"
Get-NetIPAddress -InterfaceAlias $mgmtAdapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, IPAddress, PrefixLength |
    Format-Table -AutoSize
if ($ConfigureMgmtNat) {
    Get-NetNat -Name $MgmtNatName -ErrorAction SilentlyContinue |
        Select-Object Name, InternalIPInterfaceAddressPrefix |
        Format-Table -AutoSize
}
