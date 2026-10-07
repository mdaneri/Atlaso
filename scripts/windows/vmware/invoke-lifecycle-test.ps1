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
.PARAMETER OwnershipRoot
Existing permitted durable root containing the source checkout for human lifecycle runs. Agent runs enforce active Codex configuration.
.PARAMETER OwnershipTaskId
Optional human run ownership identifier. Agent runs enforce their originating task identifier.
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
.PARAMETER SignedReleaseRepositoryUrl
Credential-free HTTPS base URL of a pre-published signed release lifecycle fixture.
.PARAMETER SiteInterface
Appliance interface used for the site-network scenario.
.PARAMETER SiteCidr
IPv4 CIDR assigned to the site-network scenario.
.PARAMETER AdminUsername
Atlaso administrator account used by the lifecycle harness.
.PARAMETER AdminPassword
Protected administrator identity credential.
.PARAMETER RootPassword
Protected root identity credential; required for private overlap and optional for existing lifecycle modes.
.PARAMETER ApplianceSshUser
SSH account used for appliance guest operations.
.PARAMETER ClientSshUser
SSH account used for lifecycle client guests.
.PARAMETER SshPassword
Secure SSH Password supplied at runtime; no repository default is used.
.PARAMETER VcfBackupPassword
Secure VCF Backup Password supplied for the full lifecycle; focused OIDC, time-source, reverse-proxy, and WAN-routing runs do not require it.
.PARAMETER EsxiPassword
Secure Esxi Password supplied at runtime; no repository default is used.
.PARAMETER VlanId
VLAN identifier used by the tagged-network scenario.
.PARAMETER TaggedVlanCidr
IPv4 CIDR used by the tagged-network scenario.
.PARAMETER WanCidr
IPv4 CIDR used by the simulated WAN scenario.
.PARAMETER RoutingWanOnly
Run the focused WAN routing scenario.
.PARAMETER RoutingOverlapOnly
Run isolated DHCP and SLAAC same-prefix acceptance on task-owned private LAN segments.
.PARAMETER SameAddressHandoffOnly
Run only the same-address IPv4 handoff within RoutingOverlapOnly.
.PARAMETER OidcOnly
Run only the OIDC lifecycle scenario.
.PARAMETER TimeSourceOnly
Run focused NTP clock-source Apply and host/client UDP acceptance without lifecycle clients.
.PARAMETER ReverseProxyOnly
Run the focused public reverse-proxy lifecycle scenario on the appliance's management and host-reachable Site A interfaces.
.PARAMETER ReverseProxyScreenshotNode
Path to the installed Node.js executable used for optional reverse-proxy browser evidence.
.PARAMETER ReverseProxyScreenshotPackages
Read-only installed Node.js package root used for optional reverse-proxy browser evidence.
.PARAMETER ReverseProxyScreenshotBrowser
Path to the installed Chrome executable used for optional reverse-proxy browser evidence.
.PARAMETER CertificateOnly
Prepare a retained appliance clone for the certificate handoff acceptance scenario.
.PARAMETER CertificateDhcpPeer
Prepare an owned private DHCP peer for certificate management handoff.
.PARAMETER CertificatePeerCidr
Private peer address and prefix for the certificate management segment.
.PARAMETER CertificateLeaseAddress
Exact reserved DHCP address for the appliance management MAC.
.PARAMETER CertificatePeerPublicKeyPath
Existing Ed25519 public key whose private half is loaded in the local SSH agent.
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
    [string]$OwnershipRoot = '',

    [Parameter(ParameterSetName = 'Run')]
    [string]$OwnershipTaskId = '',

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
    [string]$SignedReleaseRepositoryUrl = '',

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
    [SecureString]$RootPassword,

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
    [switch]$RoutingOverlapOnly,
    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$SameAddressHandoffOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$OidcOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$TimeSourceOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$ReverseProxyOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ReverseProxyScreenshotNode = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ReverseProxyScreenshotPackages = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ReverseProxyScreenshotBrowser = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$CertificateOnly,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$CertificateDhcpPeer,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$CertificatePeerCidr = '192.168.77.1/24',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$CertificateLeaseAddress = '192.168.77.10',
    [string]$CertificatePeerPublicKeyPath = '',

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
if ($SameAddressHandoffOnly -and -not $RoutingOverlapOnly) {
    throw '-SameAddressHandoffOnly requires -RoutingOverlapOnly.'
}


$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
$applianceIpWasPassed = $PSBoundParameters.ContainsKey('ApplianceIPAddress')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OidcSiteNetwork.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.LifecycleSecretStaging.ps1')
if (($OidcOnly -or $TimeSourceOnly) -and $SiteANetwork.StartsWith('lan:', [StringComparison]::OrdinalIgnoreCase)) {
    throw '-OidcOnly and -TimeSourceOnly require a host-reachable SiteANetwork; VMware LAN segments cannot carry the host-side verified probe.'
}
if ($ReverseProxyOnly -and $SiteANetwork.StartsWith('lan:', [StringComparison]::OrdinalIgnoreCase)) {
    throw '-ReverseProxyOnly requires a host-reachable SiteANetwork; VMware LAN segments cannot carry the host upstream fixture.'
}
if (($OidcOnly -or $TimeSourceOnly) -and $SiteInterface -ne 'eth1') {
    throw '-OidcOnly and -TimeSourceOnly require SiteInterface eth1 because Site A is attached to the appliance second adapter.'
}
if ($ReverseProxyOnly -and $SiteInterface -ne 'eth1') {
    throw '-ReverseProxyOnly requires SiteInterface eth1 because Site A is attached to the appliance second adapter.'
}
if ($ReverseProxyOnly -and @(@($OidcOnly, $TimeSourceOnly, $RoutingWanOnly, $CertificateOnly, $RoutingOverlapOnly, $FullEsxiPxeInstall) | Where-Object { $_ }).Count -gt 0) {
    throw '-ReverseProxyOnly cannot be combined with another focused lifecycle mode.'
}
if (($ReverseProxyScreenshotNode -or $ReverseProxyScreenshotPackages -or $ReverseProxyScreenshotBrowser) -and -not $ReverseProxyOnly) {
    throw 'Reverse-proxy screenshot tooling is accepted only with -ReverseProxyOnly.'
}
if ($ReverseProxyScreenshotNode -or $ReverseProxyScreenshotPackages -or $ReverseProxyScreenshotBrowser) {
    if (-not ($ReverseProxyScreenshotNode -and $ReverseProxyScreenshotPackages -and $ReverseProxyScreenshotBrowser) -or
        -not (Test-Path -LiteralPath $ReverseProxyScreenshotNode -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ReverseProxyScreenshotPackages -PathType Container) -or
        -not (Test-Path -LiteralPath $ReverseProxyScreenshotBrowser -PathType Leaf)) {
        throw 'Optional reverse-proxy screenshot evidence requires existing Node.js, package-root, and Chrome paths.'
    }
}
if ($SignedReleaseRepositoryUrl -and ($OidcOnly -or $TimeSourceOnly -or $RoutingWanOnly -or $CertificateOnly)) {
    throw '-SignedReleaseRepositoryUrl requires the full lifecycle; it cannot be combined with -OidcOnly, -TimeSourceOnly, -RoutingWanOnly, or -CertificateOnly.'
}
if ($SignedReleaseRepositoryUrl -and $ReverseProxyOnly) {
    throw '-SignedReleaseRepositoryUrl requires the full lifecycle and cannot be combined with -ReverseProxyOnly.'
}
if ($SignedReleaseRepositoryUrl) {
    [Uri]$fixtureUri = $null
    if (-not [Uri]::TryCreate($SignedReleaseRepositoryUrl, [UriKind]::Absolute, [ref]$fixtureUri) -or
        -not $fixtureUri.IsWellFormedOriginalString() -or $fixtureUri.Scheme -cne 'https' -or
        -not $fixtureUri.Host -or $fixtureUri.UserInfo -or $fixtureUri.Query -or $fixtureUri.Fragment) {
        throw '-SignedReleaseRepositoryUrl must be a credential-free absolute HTTPS base URL without a query or fragment.'
    }
}

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

<#
.SYNOPSIS
Return the unique Windows host IPv4 address for the focused Site A upstream fixture.
.PARAMETER NetworkName
Host-reachable VMware Site A network attached to the appliance's second adapter.
.PARAMETER SiteCidr
Appliance IPv4 address and prefix used to select the matching host route.
.PARAMETER Vmrun
Optional vmrun executable passed to VMware network discovery.
.PARAMETER BridgeAlias
Optional host interface alias used for a bridged network.
#>
function Get-AtlasoSiteHostIpv4Address {
    param(
        [Parameter(Mandatory = $true)][string]$NetworkName,
        [Parameter(Mandatory = $true)][string]$SiteCidr,
        [string]$Vmrun = '',
        [string]$BridgeAlias = ''
    )

    if ($SiteCidr -notmatch '^([0-9]{1,3}(?:\.[0-9]{1,3}){3})/([0-9]|[12][0-9]|3[0-2])$') {
        throw 'Reverse-proxy SiteCidr must be an IPv4 CIDR.'
    }
    $siteAddress = [System.Net.IPAddress]::Parse($Matches[1])
    $prefix = [int]$Matches[2]
    $networkPlan = Get-ManagementNetworkPlan -NetworkName $NetworkName -Vmrun $Vmrun -BridgeAlias $BridgeAlias
    $network = @($networkPlan.discovered_networks | Where-Object { $_.Name -eq $NetworkName.ToLowerInvariant() }) | Select-Object -First 1
    if (-not $network) { throw 'Reverse-proxy Site A network was not present in VMware network discovery.' }
    $hostAlias = if ($network.PSObject.Properties['InterfaceAlias']) { $network.InterfaceAlias } else { "VMware Network Adapter $NetworkName" }
    $adapter = Get-NetAdapter -Name $hostAlias -ErrorAction SilentlyContinue
    if (-not $adapter -or $adapter.Status -ne 'Up') { throw 'Reverse-proxy Site A host adapter must be active for the upstream fixture.' }
    $expectedMask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl (32 - $prefix)) }
    $siteBytes = $siteAddress.GetAddressBytes()
    $siteIp = (([uint32]$siteBytes[0] -shl 24) -bor ([uint32]$siteBytes[1] -shl 16) -bor ([uint32]$siteBytes[2] -shl 8) -bor [uint32]$siteBytes[3])
    $siteNetwork = $siteIp -band $expectedMask
    $matchingAddresses = @(Get-NetIPAddress -InterfaceAlias $hostAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        if ($_.AddressState -ne 'Preferred' -or $_.PrefixLength -ne $prefix) { return $false }
        $bytes = ([System.Net.IPAddress]::Parse($_.IPAddress)).GetAddressBytes()
        $hostIp = (([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3])
        ($hostIp -band $expectedMask) -eq $siteNetwork
    })
    if ($matchingAddresses.Count -ne 1) {
        throw 'Reverse-proxy Site A requires exactly one preferred host IPv4 address in the appliance SiteCidr subnet.'
    }
    $hostAddress = $matchingAddresses[0].IPAddress
    $route = @(Find-NetRoute -RemoteIPAddress $siteAddress.IPAddressToString -LocalIPAddress $hostAddress -ErrorAction SilentlyContinue | Where-Object {
        $_.PSObject.Properties['DestinationPrefix']
    }) | Select-Object -First 1
    if (-not $route -or $route.InterfaceIndex -ne $adapter.InterfaceIndex) {
        throw 'Reverse-proxy Site A host IPv4 address does not select the matching VMware adapter route to the appliance.'
    }
    return $hostAddress
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

if ($OidcOnly -or $TimeSourceOnly -or $ReverseProxyOnly) {
    Assert-AtlasoOidcSiteNetwork -SiteANetwork $SiteANetwork -SiteCidr $SiteCidr `
        -PrepareNetworksPath (Join-Path $PSScriptRoot 'prepare-networks.ps1') `
        -VmrunPath $VmrunPath -BridgedInterfaceAlias $BridgedInterfaceAlias `
        -BindSiteSource:($TimeSourceOnly -or $ReverseProxyOnly)
}
$reverseProxyUpstreamHost = if ($ReverseProxyOnly) {
    Get-AtlasoSiteHostIpv4Address -NetworkName $SiteANetwork -SiteCidr $SiteCidr -Vmrun $VmrunPath -BridgeAlias $BridgedInterfaceAlias
} else { '' }

if (-not $PlanOnly) {
    if ($null -eq $AdminPassword) {
        $AdminPassword = Read-Host -Prompt 'Atlaso lifecycle administrator password' -AsSecureString
    }
    if ($null -eq $SshPassword) {
        $SshPassword = $AdminPassword
    }
    if (-not ($OidcOnly -or $TimeSourceOnly -or $RoutingWanOnly -or $CertificateOnly -or $RoutingOverlapOnly) -and $null -eq $VcfBackupPassword) {
        if (-not $ReverseProxyOnly) {
            $VcfBackupPassword = Read-Host -Prompt 'VCF Backup lifecycle password' -AsSecureString
        }
    }
    if ($FullEsxiPxeInstall -and $null -eq $EsxiPassword) {
        $EsxiPassword = Read-Host -Prompt 'ESXi root password for lifecycle probing' -AsSecureString
    }
}
if (@(@($OidcOnly, $TimeSourceOnly, $RoutingWanOnly, $CertificateOnly, $RoutingOverlapOnly, $FullEsxiPxeInstall) | Where-Object { $_ }).Count -gt 1) {
    throw "-OidcOnly, -TimeSourceOnly, -RoutingWanOnly, -CertificateOnly, -RoutingOverlapOnly, and -FullEsxiPxeInstall are mutually exclusive."
}
if ($RoutingOverlapOnly -and -not $PlanOnly -and (-not $SkipClientPrepare -or -not $ClientVmdkPath -or $ApplianceSshUser -cne 'root' -or
    $ApplianceIPAddress -or $ApplianceUrl -or $AllowDryRunApply -or $ManagementNetwork -notmatch '^VMnet\d+$')) {
    throw 'Private overlap requires a prepared client disk, SkipClientPrepare, root appliance SSH, discovered addressing, and real Apply.'
}
if ($RoutingOverlapOnly -and -not $PlanOnly -and $null -eq $RootPassword) {
    throw 'Private overlap requires the corresponding root identity through protected RootPassword.'
}
if ($CertificateOnly -and -not $KeepVms -and -not $PlanOnly) {
    throw '-CertificateOnly requires -KeepVms so the retained appliance can undergo native acceptance.'
}
if ($CertificateDhcpPeer -and ($PullRequestNumber -ne 871 -or -not $CertificateOnly -or -not $SiteANetwork.StartsWith('lan:', [StringComparison]::OrdinalIgnoreCase) -or $SiteANetwork.Length -le 4 -or $SiteInterface -ne 'eth0')) {
    throw '-CertificateDhcpPeer requires PR 871, -CertificateOnly, a named private lan: SiteANetwork, and SiteInterface eth0.'
}
if ($CertificateDhcpPeer -and -not $PlanOnly -and -not $PSBoundParameters.ContainsKey('ClientVmdkPath')) {
    throw '-CertificateDhcpPeer requires an explicit, provenance-admitted -ClientVmdkPath.'
}
if ($CertificateDhcpPeer -and -not $PlanOnly -and -not $CertificatePeerPublicKeyPath) {
    throw '-CertificateDhcpPeer requires -CertificatePeerPublicKeyPath for passwordless bootstrap.'
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
if ($ReverseProxyOnly) {
    $ClientVmdkPath = ''
    $SkipClientPrepare = $true
}
if (-not $applianceIpWasPassed) {
    $networkPlan = Get-ManagementNetworkPlan -NetworkName $ManagementNetwork -Vmrun $VmrunPath -BridgeAlias $BridgedInterfaceAlias
    if ($networkPlan.missing_networks.Count -gt 0) {
        throw "Missing VMware Workstation networks: $($networkPlan.missing_networks -join ', ')."
    }
}
if (-not $ReverseProxyOnly) {
    if (-not $PlanOnly -and $PSCmdlet.ParameterSetName -eq 'Run' -and -not $RoutingOverlapOnly) {
        $usesLanSegments = @($SiteANetwork, $SiteBNetwork, $TrunkNetwork) | Where-Object { $_.StartsWith('lan:') }
        if (-not $usesLanSegments -and -not ($CertificateOnly -or $TimeSourceOnly)) {
            $lifecycleNetworkPlan = Get-ManagementNetworkPlan -NetworkName $ManagementNetwork -Vmrun $VmrunPath -BridgeAlias $BridgedInterfaceAlias -AllLifecycleNetworks
            if ($lifecycleNetworkPlan.missing_networks.Count -gt 0) {
                throw "Missing VMware Workstation lifecycle networks: $($lifecycleNetworkPlan.missing_networks -join ', '). Create them in Virtual Network Editor, pass lan:<segment-name> for isolated Workstation LAN segments, or run -PrepareNetworksOnly after configuring Workstation host-only vmnets."
            }
        }
    }
}
$effectiveApplianceUrl = if ($ApplianceUrl) { $ApplianceUrl } elseif ($ApplianceIPAddress) { "https://${ApplianceIPAddress}" } else { "" }

if (-not $SkipClientPrepare -and -not ($TimeSourceOnly -or $CertificateOnly) -and -not $PlanOnly) {
    & (Join-Path $PSScriptRoot 'prepare-tiny-linux-client.ps1')
    if (-not $?) {
        throw "Tiny Linux VMware client preparation failed."
    }
}

$effectiveSkipBackupRestoreTest = [bool]($SkipBackupRestoreTest -or $RoutingWanOnly -or $OidcOnly -or $TimeSourceOnly -or $CertificateOnly -or $RoutingOverlapOnly)
if ($ReverseProxyOnly) { $effectiveSkipBackupRestoreTest = $true }
$powerShell7Path = Resolve-PowerShell7Path

$secretBundlePath = ''
try {
    if (-not $PlanOnly) {
        $secretBundleRoot = Initialize-AtlasoLifecycleSecretBundleRoot -RepositoryRoot $repoRoot
        $secretBundlePath = Join-Path $secretBundleRoot "atlaso-vmware-lifecycle-$([guid]::NewGuid().ToString('N')).clixml"
        # Enter the cleanup scope before serialization because Export-Clixml
        # can leave a partial current-user-decryptable file when it fails.
        [pscustomobject]@{
            AdminPassword     = $AdminPassword
            RootPassword      = $RootPassword
            SshPassword       = $SshPassword
            VcfBackupPassword = $VcfBackupPassword
            EsxiPassword      = $EsxiPassword
        } | Export-Clixml -LiteralPath $secretBundlePath -NoClobber
        Protect-AtlasoLifecycleSecretBundleFile -Path $secretBundlePath
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
if ($SignedReleaseRepositoryUrl) { $arguments += @('-SignedReleaseRepositoryUrl', $SignedReleaseRepositoryUrl) }
if ($VmrunPath) { $arguments += @('-VmrunPath', $VmrunPath) }
if ($BridgedInterfaceAlias) { $arguments += @('-BridgedInterfaceAlias', $BridgedInterfaceAlias) }
if (-not $KeepVms) { $arguments += '-CleanupCreatedLab' }
if ($AllowDryRunApply) { $arguments += '-AllowDryRunApply' }
if ($effectiveSkipBackupRestoreTest) { $arguments += '-SkipBackupRestoreTest' }
if ($OidcOnly) { $arguments += '-OidcOnly' }
if ($TimeSourceOnly) { $arguments += '-TimeSourceOnly' }
if ($ReverseProxyOnly) {
    $arguments += @('-ReverseProxyOnly', '-ReverseProxyUpstreamHost', $reverseProxyUpstreamHost)
    if ($ReverseProxyScreenshotNode) {
        $arguments += @(
            '-ReverseProxyScreenshotNode', $ReverseProxyScreenshotNode,
            '-ReverseProxyScreenshotPackages', $ReverseProxyScreenshotPackages,
            '-ReverseProxyScreenshotBrowser', $ReverseProxyScreenshotBrowser
        )
    }
}
if ($CertificateOnly) { $arguments += '-CertificateOnly' }
if ($CertificateDhcpPeer) {
    $arguments += @('-CertificateDhcpPeer', '-CertificatePeerCidr', $CertificatePeerCidr,
        '-CertificateLeaseAddress', $CertificateLeaseAddress)
    if ($CertificatePeerPublicKeyPath) { $arguments += @('-CertificatePeerPublicKeyPath', $CertificatePeerPublicKeyPath) }
}
if ($RoutingWanOnly) { $arguments += '-RoutingWanOnly' }
if ($RoutingOverlapOnly) { $arguments += '-RoutingOverlapOnly' }
if ($SameAddressHandoffOnly) { $arguments += '-SameAddressHandoffOnly' }
if ($OwnershipRoot) { $arguments += @('-OwnershipRoot', $OwnershipRoot) }
if ($OwnershipTaskId) { $arguments += @('-OwnershipTaskId', $OwnershipTaskId) }
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
Write-Host ("Time-source only: {0}" -f ([bool]$TimeSourceOnly))
Write-Host ("Reverse-proxy only: {0}" -f ([bool]$ReverseProxyOnly))
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
