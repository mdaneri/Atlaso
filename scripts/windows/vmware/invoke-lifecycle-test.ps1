#requires -Version 7.0

<#
.SYNOPSIS
Launch the bounded VMware Workstation lifecycle test with secure credential handoff.
.PARAMETER PullRequestNumber
Exact positive GitHub pull-request number that owns this lifecycle lab.
.PARAMETER Purpose
Short purpose text sanitized into the canonical lifecycle identity.
.PARAMETER CollisionSuffix
Optional collision-safe suffix. Run and plan modes generate one when omitted;
cleanup requires the exact suffix reported by the creating run.
.PARAMETER ApplianceVmxPath
Path to the source appliance VMX used for the lifecycle VM.
.PARAMETER ClientVmdkPath
Path to the base client VMDK used by generated lifecycle guests.
.PARAMETER VmrunPath
Optional explicit path to the VMware vmrun executable.
.PARAMETER ManagementNetwork
VMware network used for appliance management traffic.
.PARAMETER BridgedInterfaceAlias
Host adapter alias bridged to the management network.
.PARAMETER SiteANetwork
VMware network used for site A traffic.
.PARAMETER SiteBNetwork
VMware network used for site B traffic.
.PARAMETER TrunkNetwork
VMware network used for tagged trunk traffic.
.PARAMETER ApplianceIPAddress
Management IPv4 address assigned to or expected from the appliance.
.PARAMETER ApplianceUrl
HTTPS URL used for appliance API validation.
.PARAMETER SiteInterface
Appliance interface used for the site-network scenario.
.PARAMETER SiteCidr
IPv4 CIDR assigned to the site-network scenario.
.PARAMETER AdminUsername
Atlaso administrator account used by the lifecycle harness.
.PARAMETER AdminPassword
Secure Admin Password supplied at runtime; no repository default is used.
.PARAMETER ApplianceSshUser
SSH account used for appliance guest operations.
.PARAMETER ClientSshUser
SSH account used for lifecycle client guests.
.PARAMETER SshPassword
Secure SSH Password supplied at runtime; no repository default is used.
.PARAMETER VcfBackupPassword
Secure VCF Backup Password supplied for the full lifecycle; focused OIDC and WAN-routing runs do not require it.
.PARAMETER EsxiPassword
Secure Esxi Password supplied at runtime; no repository default is used.
.PARAMETER VlanId
VLAN identifier used by the tagged-network scenario.
.PARAMETER TaggedVlanCidr
IPv4 CIDR used by the tagged-network scenario.
.PARAMETER WanCidr
IPv4 CIDR used by the simulated WAN scenario.
.PARAMETER RoutingWanOnly
Run only the routing and WAN lifecycle scenario.
.PARAMETER OidcOnly
Run only the OIDC lifecycle scenario.
.PARAMETER FullEsxiPxeInstall
Include the full ESXi PXE installation scenario.
.PARAMETER PxeInstallerIsoPath
Path to the ESXi installer ISO used for PXE publication.
.PARAMETER KeepVms
Retain generated lifecycle VMs after the run completes.
.PARAMETER SkipClientPrepare
Reuse the existing client image instead of rebuilding it.
.PARAMETER PrepareNetworksOnly
Prepare required lifecycle networks and exit without creating VMs.
.PARAMETER CleanupVmsOnly
Remove VMs for the selected lifecycle lab and exit.
.PARAMETER AllowDryRunApply
Allow the harness to exercise the appliance dry-run apply path.
.PARAMETER SkipBackupRestoreTest
Skip the backup and restore lifecycle phase.
.PARAMETER PlanOnly
Emit the resolved lifecycle plan without prompting for secrets or mutating the host.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Plan')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CleanupVms')]
    [ValidateRange(1, 2147483647)]
    [int]$PullRequestNumber,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'CleanupVms')]
    [string]$Purpose = 'lifecycle',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CleanupVms')]
    [string]$CollisionSuffix = '',

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
    [SecureString]$AdminPassword,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceSshUser = 'admin',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ClientSshUser = 'alpine',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [SecureString]$SshPassword,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [SecureString]$VcfBackupPassword,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [SecureString]$EsxiPassword,

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
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force

<#
.SYNOPSIS
Return the newest eligible appliance VMX from VMware build output.
#>
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

<#
.SYNOPSIS
Resolve the PowerShell 7 executable required by the VMware lifecycle runner.
#>
function Resolve-PowerShell7Path {
    $powerShell7 = Get-Command -Name 'pwsh' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $powerShell7 -or [string]::IsNullOrWhiteSpace($powerShell7.Source)) {
        throw "PowerShell 7 (pwsh) is required to run the VMware Workstation lifecycle test."
    }
    return $powerShell7.Source
}

<#
.SYNOPSIS
Return the IPv4 host address at a deterministic subnet offset.
.PARAMETER Subnet
Base IPv4 address of the subnet used for deterministic host allocation.
.PARAMETER HostOffset
Host-number offset added to the subnet base address.
#>
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

<#
.SYNOPSIS
Return the validated VMware network plan used by lifecycle execution.
.PARAMETER NetworkName
VMware management network whose readiness plan is requested.
.PARAMETER Vmrun
Optional vmrun executable passed to network discovery.
.PARAMETER BridgeAlias
Optional host adapter alias used for bridged network discovery.
.PARAMETER AllLifecycleNetworks
Include site and trunk networks in addition to management.
#>
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

if ([string]::IsNullOrWhiteSpace($CollisionSuffix)) {
    # A timestamp keeps the result recognizable; the random tail prevents two
    # same-second lifecycle starts for one PR from claiming the same lab root.
    $CollisionSuffix = "$(Get-Date -Format 'yyyyMMddHHmmss')-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
}
$vmIdentity = New-AtlasoVmwareTestIdentity `
    -PullRequestNumber $PullRequestNumber `
    -Purpose $Purpose `
    -CollisionSuffix $CollisionSuffix
$LabName = $vmIdentity.Name
$lifecycleApplianceVmx = Join-Path $repoRoot (
    "test-results\vmware-workstation-lifecycle\$LabName\vms\$LabName-Appliance\$LabName-Appliance.vmx"
)

if ($PSCmdlet.ParameterSetName -eq 'CleanupVms') {
    & (Join-Path $PSScriptRoot 'remove-lifecycle-vms.ps1') `
        -PullRequestNumber $PullRequestNumber `
        -Purpose $vmIdentity.Purpose `
        -CollisionSuffix $vmIdentity.CollisionSuffix `
        -VmrunPath $VmrunPath
    if (-not $?) {
        throw "VMware Workstation lifecycle VM cleanup failed."
    }
    return
}

if (-not $PlanOnly) {
    if ($null -eq $AdminPassword) {
        $AdminPassword = Read-Host -Prompt 'Atlaso lifecycle administrator password' -AsSecureString
    }
    if ($null -eq $SshPassword) {
        $SshPassword = $AdminPassword
    }
    if (-not ($OidcOnly -or $RoutingWanOnly) -and $null -eq $VcfBackupPassword) {
        $VcfBackupPassword = Read-Host -Prompt 'VCF Backup lifecycle password' -AsSecureString
    }
    if ($FullEsxiPxeInstall -and $null -eq $EsxiPassword) {
        $EsxiPassword = Read-Host -Prompt 'ESXi root password for lifecycle probing' -AsSecureString
    }
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

$secretBundlePath = ''
try {
    if (-not $PlanOnly) {
        $secretBundlePath = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-vmware-lifecycle-$([guid]::NewGuid().ToString('N')).clixml"
        # Enter the cleanup scope before serialization because Export-Clixml
        # can leave a partial current-user-decryptable file when it fails.
        [pscustomobject]@{
            AdminPassword     = $AdminPassword
            SshPassword       = $SshPassword
            VcfBackupPassword = $VcfBackupPassword
            EsxiPassword      = $EsxiPassword
        } | Export-Clixml -LiteralPath $secretBundlePath -Force
    }

$arguments = @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $PSScriptRoot 'run-lifecycle-test.ps1'),
    '-PullRequestNumber', "$PullRequestNumber",
    '-Purpose', $vmIdentity.Purpose,
    '-CollisionSuffix', $vmIdentity.CollisionSuffix,
    '-ApplianceVmxPath', $ApplianceVmxPath,
    '-ClientVmdkPath', $ClientVmdkPath,
    '-ManagementNetwork', $ManagementNetwork,
    '-SiteANetwork', $SiteANetwork,
    '-SiteBNetwork', $SiteBNetwork,
    '-TrunkNetwork', $TrunkNetwork,
    '-SiteInterface', $SiteInterface,
    '-SiteCidr', $SiteCidr,
    '-AdminUsername', $AdminUsername,
    '-ApplianceSshUser', $ApplianceSshUser,
    '-ClientSshUser', $ClientSshUser,
    '-VlanId', "$VlanId",
    '-TaggedVlanCidr', $TaggedVlanCidr,
    '-WanCidr', $WanCidr
)
if (-not $PlanOnly) { $arguments += @('-SecretBundlePath', $secretBundlePath) }
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
Write-Host "Pull request: #$PullRequestNumber"
Write-Host "Lifecycle appliance VMX: $lifecycleApplianceVmx"
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
} finally {
    if ($secretBundlePath -and (Test-Path -LiteralPath $secretBundlePath)) {
        Remove-Item -LiteralPath $secretBundlePath -Force -ErrorAction Stop
    }
    if ($secretBundlePath -and (Test-Path -LiteralPath $secretBundlePath)) {
        throw "Lifecycle secret bundle cleanup did not complete: $secretBundlePath"
    }
}
