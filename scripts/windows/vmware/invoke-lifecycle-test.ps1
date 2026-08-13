#requires -Version 7.0

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'CleanupVms')]
    [string]$LabName = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceVmxPath = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ClientVmdkPath = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'PrepareNetworks')]
    [string]$VmrunPath = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'PrepareNetworks')]
    [string]$ManagementNetwork = 'VMnet8',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'PrepareNetworks')]
    [string]$BridgedInterfaceAlias = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'PrepareNetworks')]
    [string]$SiteANetwork = 'VMnet2',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'PrepareNetworks')]
    [string]$SiteBNetwork = 'VMnet3',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'PrepareNetworks')]
    [string]$TrunkNetwork = 'VMnet4',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceIPAddress = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceUrl = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$SiteInterface = 'eth1',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$SiteCidr = '192.168.12.1/24',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$AdminUsername = 'admin',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$AdminPassword = 'VMware01!Test',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceSshUser = 'admin',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ClientSshUser = 'alpine',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$SshPassword = 'VMware01!Test',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$VcfBackupPassword = 'VMware01!Test',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [int]$VlanId = 50,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$TaggedVlanCidr = '192.168.60.1/24',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$WanCidr = '172.31.50.1/24',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$RoutingWanOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$OidcOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$FullEsxiPxeInstall,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$PxeInstallerIsoPath = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$KeepVms,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$SkipClientPrepare,

    [Parameter(Mandatory = $true, ParameterSetName = 'PrepareNetworks')]
    [switch]$PrepareNetworksOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'CleanupVms')]
    [switch]$CleanupVmsOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$AllowDryRunApply,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$SkipBackupRestoreTest,

    [Parameter(Mandatory = $true, ParameterSetName = 'Plan')]
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
$applianceIpWasPassed = $PSBoundParameters.ContainsKey('ApplianceIPAddress')

function Find-LatestApplianceVmx {
    $outputRoot = Join-Path $repoRoot 'image\vmware-workstation\output'
    if (-not (Test-Path -LiteralPath $outputRoot)) {
        throw "VMware Workstation output directory not found: $outputRoot"
    }
    $selected = Get-ChildItem -Path $outputRoot -Recurse -Filter '*.vmx' |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $selected) {
        throw "No appliance VMX found under $outputRoot. Build the Workstation image or pass -ApplianceVmxPath."
    }
    return $selected.FullName
}

function Resolve-PowerShell7Path {
    $powerShell7 = Get-Command -Name 'pwsh' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $powerShell7 -or [string]::IsNullOrWhiteSpace($powerShell7.Source)) {
        throw "PowerShell 7 (pwsh) is required to run the VMware Workstation lifecycle test."
    }
    return $powerShell7.Source
}

function Get-Ipv4AddressFromSubnetOffset {
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][uint32]$HostOffset
    )

    $bytes = [System.Net.IPAddress]::Parse($Subnet).GetAddressBytes()
    if ($bytes.Count -ne 4) {
        throw "Expected an IPv4 subnet, got: $Subnet"
    }
    $address = (([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]) + $HostOffset
    $next = [byte[]]@(
        (($address -shr 24) -band 0xff),
        (($address -shr 16) -band 0xff),
        (($address -shr 8) -band 0xff),
        ($address -band 0xff)
    )
    return ([System.Net.IPAddress]::new($next)).ToString()
}

function Get-ManagementNetworkPlan {
    param(
        [Parameter(Mandatory = $true)][string]$NetworkName,
        [string]$Vmrun,
        [string]$BridgeAlias,
        [switch]$AllLifecycleNetworks
    )

    $networkArgs = @{
        ManagementNetwork = $NetworkName
        PlanOnly          = $true
    }
    if (-not $AllLifecycleNetworks) {
        $networkArgs['ManagementOnly'] = $true
    }
    if ($AllLifecycleNetworks) {
        $networkArgs['SiteANetwork'] = $SiteANetwork
        $networkArgs['SiteBNetwork'] = $SiteBNetwork
        $networkArgs['TrunkNetwork'] = $TrunkNetwork
    }
    if (-not [string]::IsNullOrWhiteSpace($Vmrun)) {
        $networkArgs['VmrunPath'] = $Vmrun
    }
    if (-not [string]::IsNullOrWhiteSpace($BridgeAlias)) {
        $networkArgs['BridgedInterfaceAlias'] = $BridgeAlias
    }

    $planText = (& (Join-Path $PSScriptRoot 'prepare-networks.ps1') @networkArgs | Out-String).Trim()
    if (-not $?) {
        throw "VMware Workstation network discovery failed."
    }
    return $planText | ConvertFrom-Json
}

if (-not $LabName) {
    if ($PSCmdlet.ParameterSetName -eq 'CleanupVms') {
        $LabName = 'AtlasoWorkstationLifecycle'
    } else {
        $LabName = "AtlasoWorkstationLifecycle-$(Get-Date -Format 'yyyyMMddHHmmss')"
    }
}

if ($PSCmdlet.ParameterSetName -eq 'PrepareNetworks') {
    & (Join-Path $PSScriptRoot 'prepare-networks.ps1') `
        -VmrunPath $VmrunPath `
        -ManagementNetwork $ManagementNetwork `
        -BridgedInterfaceAlias $BridgedInterfaceAlias `
        -SiteANetwork $SiteANetwork `
        -SiteBNetwork $SiteBNetwork `
        -TrunkNetwork $TrunkNetwork
    if (-not $?) {
        throw "VMware Workstation network preparation failed."
    }
    return
}

if ($PSCmdlet.ParameterSetName -eq 'CleanupVms') {
    & (Join-Path $PSScriptRoot 'remove-lifecycle-vms.ps1') `
        -LabName $LabName `
        -VmrunPath $VmrunPath
    if (-not $?) {
        throw "VMware Workstation lifecycle VM cleanup failed."
    }
    return
}

if (-not $SshPassword) {
    $SshPassword = $AdminPassword
}
if (-not $VcfBackupPassword) {
    $VcfBackupPassword = 'VMware01!Test'
}
if (($RoutingWanOnly -and $FullEsxiPxeInstall) -or ($OidcOnly -and ($RoutingWanOnly -or $FullEsxiPxeInstall))) {
    throw "-OidcOnly, -RoutingWanOnly, and -FullEsxiPxeInstall are mutually exclusive."
}
if (-not $ApplianceVmxPath) {
    if ($PlanOnly) {
        $ApplianceVmxPath = Join-Path $repoRoot 'image\vmware-workstation\output\Atlaso-VMware\Atlaso-VMware.vmx'
    } else {
        $ApplianceVmxPath = Find-LatestApplianceVmx
    }
}
if (-not $ClientVmdkPath) {
    $ClientVmdkPath = Join-Path $repoRoot 'image\vmware-workstation\clients\alpine-cloud\atlaso-tiny-linux-client.vmdk'
}
if (-not $applianceIpWasPassed) {
    $networkPlan = Get-ManagementNetworkPlan -NetworkName $ManagementNetwork -Vmrun $VmrunPath -BridgeAlias $BridgedInterfaceAlias
    if ($networkPlan.missing_networks.Count -gt 0) {
        throw "Missing VMware Workstation networks: $($networkPlan.missing_networks -join ', ')."
    }
}
if (-not $PlanOnly -and $PSCmdlet.ParameterSetName -eq 'Run') {
    $usesLanSegments = @($SiteANetwork, $SiteBNetwork, $TrunkNetwork) | Where-Object { $_.StartsWith('lan:') }
    if (-not $usesLanSegments) {
        $lifecycleNetworkPlan = Get-ManagementNetworkPlan -NetworkName $ManagementNetwork -Vmrun $VmrunPath -BridgeAlias $BridgedInterfaceAlias -AllLifecycleNetworks
        if ($lifecycleNetworkPlan.missing_networks.Count -gt 0) {
            throw "Missing VMware Workstation lifecycle networks: $($lifecycleNetworkPlan.missing_networks -join ', '). Create them in Virtual Network Editor, pass lan:<segment-name> for isolated Workstation LAN segments, or run -PrepareNetworksOnly after configuring Workstation host-only vmnets."
        }
    }
}
$effectiveApplianceUrl = if ($ApplianceUrl) { $ApplianceUrl } elseif ($ApplianceIPAddress) { "https://${ApplianceIPAddress}" } else { "" }

if (-not $SkipClientPrepare -and -not $PlanOnly) {
    & (Join-Path $PSScriptRoot 'prepare-tiny-linux-client.ps1')
    if (-not $?) {
        throw "Tiny Linux VMware client preparation failed."
    }
}

$effectiveSkipBackupRestoreTest = [bool]($SkipBackupRestoreTest -or $RoutingWanOnly -or $OidcOnly)
$powerShell7Path = Resolve-PowerShell7Path

$arguments = @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $PSScriptRoot 'run-lifecycle-test.ps1'),
    '-LabName', $LabName,
    '-ApplianceVmxPath', $ApplianceVmxPath,
    '-ClientVmdkPath', $ClientVmdkPath,
    '-ManagementNetwork', $ManagementNetwork,
    '-SiteANetwork', $SiteANetwork,
    '-SiteBNetwork', $SiteBNetwork,
    '-TrunkNetwork', $TrunkNetwork,
    '-SiteInterface', $SiteInterface,
    '-SiteCidr', $SiteCidr,
    '-AdminUsername', $AdminUsername,
    '-AdminPassword', $AdminPassword,
    '-ApplianceSshUser', $ApplianceSshUser,
    '-ClientSshUser', $ClientSshUser,
    '-SshPassword', $SshPassword,
    '-VcfBackupPassword', $VcfBackupPassword,
    '-VlanId', "$VlanId",
    '-TaggedVlanCidr', $TaggedVlanCidr,
    '-WanCidr', $WanCidr
)
if ($ApplianceIPAddress) { $arguments += @('-ApplianceIPAddress', $ApplianceIPAddress) }
if ($effectiveApplianceUrl) { $arguments += @('-ApplianceUrl', $effectiveApplianceUrl) }
if ($VmrunPath) { $arguments += @('-VmrunPath', $VmrunPath) }
if (-not $KeepVms) { $arguments += '-CleanupCreatedLab' }
if ($AllowDryRunApply) { $arguments += '-AllowDryRunApply' }
if ($effectiveSkipBackupRestoreTest) { $arguments += '-SkipBackupRestoreTest' }
if ($OidcOnly) { $arguments += '-OidcOnly' }
if ($RoutingWanOnly) { $arguments += '-RoutingWanOnly' }
if ($FullEsxiPxeInstall) { $arguments += '-FullEsxiPxeInstall' }
if ($PxeInstallerIsoPath) { $arguments += @('-PxeInstallerIsoPath', $PxeInstallerIsoPath) }
if ($PlanOnly) { $arguments += '-PlanOnly' }

Write-Host "Workstation lifecycle lab: $LabName"
Write-Host "Appliance VMX: $ApplianceVmxPath"
Write-Host "Client VMDK: $ClientVmdkPath"
Write-Host "Appliance URL: $(if ($effectiveApplianceUrl) { $effectiveApplianceUrl } else { 'discovered at runtime' })"
Write-Host ("Routing/WAN only: {0}" -f ([bool]$RoutingWanOnly))
Write-Host ("OIDC only: {0}" -f ([bool]$OidcOnly))
Write-Host ("Full ESXi PXE install: {0}" -f ([bool]$FullEsxiPxeInstall))
Write-Host ("Backup/restore validation: {0}" -f (-not $effectiveSkipBackupRestoreTest))
Write-Host ("Cleanup created VMs: {0}" -f (-not $KeepVms))

& $powerShell7Path @arguments
if ($LASTEXITCODE -ne 0) {
    throw "VMware Workstation lifecycle test failed with exit code $LASTEXITCODE"
}
