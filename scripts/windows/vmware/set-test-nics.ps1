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

function ConvertTo-VmxString {
    param([string]$Value)
    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

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

function Set-VmxNetworkAdapter {
    param(
        [string]$Path,
        [int]$Index,
        [string]$Vmnet
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
}

$resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path

if ($PSCmdlet.ShouldProcess($resolvedVmxPath, 'Configure Atlaso VMware Workstation lab NICs')) {
    Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 0 -Vmnet $ManagementNetwork
    if (-not $SkipLabNetworkAdapters) {
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 1 -Vmnet $SiteANetwork
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 2 -Vmnet $TrunkNetwork
        Set-VmxNetworkAdapter -Path $resolvedVmxPath -Index 3 -Vmnet $SiteBNetwork
    }
}

Write-Host "Configured VMware Workstation NICs: $resolvedVmxPath"
