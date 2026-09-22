<#
.SYNOPSIS
Configure stable Atlaso VMware Workstation lifecycle network adapters.
.PARAMETER VmxPath
Exact task-owned VMware configuration to update.
.PARAMETER ManagementNetwork
Network assigned to the appliance management adapter.
.PARAMETER SiteANetwork
Network assigned to the site A adapter.
.PARAMETER SiteBNetwork
Network assigned to the site B adapter.
.PARAMETER TrunkNetwork
Network assigned to the trunk adapter.
.PARAMETER SkipLabNetworkAdapters
Configure only the management adapter.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,
    [string]$ManagementNetwork = 'VMnet8',
    [string]$SiteANetwork = 'VMnet2',
    [string]$SiteBNetwork = 'VMnet3',
    [string]$TrunkNetwork = 'VMnet4',
    [switch]$SkipLabNetworkAdapters
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Quote one VMware configuration string value.
.PARAMETER Value
Value to quote for a VMX assignment.
#>
function ConvertTo-VmxString {
    param([string]$Value)
    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

<#
.SYNOPSIS
Replace or append one VMware configuration assignment.
.PARAMETER Path
VMX file to update.
.PARAMETER Key
Assignment name.
.PARAMETER Value
Literal VMware configuration value to quote before writing the assignment.
#>
function Set-VmxValue {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )

    $line = "$Key = $(ConvertTo-VmxString -Value $Value)"
    $content = @(Get-Content -LiteralPath $Path)
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
        if ($_ -match $pattern) {
            $updated = $true
            $line
        } else {
            $_
        }
    })
    if (-not $updated) {
        $content += $line
    }
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

<#
.SYNOPSIS
Bind one VMX adapter to its network and optional PCI slot.
.PARAMETER Path
VMX file to update.
.PARAMETER Index
Zero-based VMware adapter index.
.PARAMETER Vmnet
VMware network or LAN segment assigned to the adapter.
.PARAMETER PciSlotNumber
Explicit slot that preserves guest eth0 through eth3 ordering in a four-NIC lab.
#>
function Set-VmxNetworkAdapter {
    param(
        [string]$Path,
        [int]$Index,
        [string]$Vmnet,
        [int]$PciSlotNumber = 0
    )

    $prefix = "ethernet$Index"
    if ($Vmnet -match '^(?i)vmnet(\d+)$') {
        $Vmnet = "VMnet$($Matches[1])"
    }
    Set-VmxValue -Path $Path -Key "$prefix.present" -Value 'TRUE'
    Set-VmxValue -Path $Path -Key "$prefix.connectionType" -Value 'custom'
    Set-VmxValue -Path $Path -Key "$prefix.vnet" -Value $Vmnet
    Set-VmxValue -Path $Path -Key "$prefix.virtualDev" -Value 'vmxnet3'
    Set-VmxValue -Path $Path -Key "$prefix.startConnected" -Value 'TRUE'
    if ($PciSlotNumber -gt 0) {
        Set-VmxValue -Path $Path -Key "$prefix.pciSlotNumber" -Value ([string]$PciSlotNumber)
    }
}

$resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path

if ($PSCmdlet.ShouldProcess($resolvedVmxPath, 'Configure Atlaso VMware Workstation lab NICs')) {
    if ($SkipLabNetworkAdapters) {
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 0 -Vmnet $ManagementNetwork
    }
    else {
        # VMware otherwise assigns the fourth NIC slot 1184 and Photon enumerates
        # it as eth0, leaving the real management NIC unmanaged and without DHCP.
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 0 -Vmnet $ManagementNetwork -PciSlotNumber 1184
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 1 -Vmnet $SiteANetwork -PciSlotNumber 192
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 2 -Vmnet $TrunkNetwork -PciSlotNumber 224
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 3 -Vmnet $SiteBNetwork -PciSlotNumber 256
    }
}

Write-Host "Configured VMware Workstation NICs: $resolvedVmxPath"
