<#
.SYNOPSIS
Launch the bounded Hyper-V lifecycle test with secure credential handoff.
.PARAMETER LabName
Name prefix used to isolate generated lifecycle resources.
.PARAMETER ApplianceVhdxPath
Path to the source appliance VHDX used for the lifecycle VM.
.PARAMETER ClientVhdxPath
Path to the prepared client VHDX used by lifecycle guests.
.PARAMETER EsxIsoPath
Optional path to an ESXi installer ISO used by PXE coverage.
.PARAMETER ClientManagementSwitch
Hyper-V switch that connects lifecycle client management adapters.
.PARAMETER ApplianceIPAddress
Management IPv4 address assigned to or expected from the appliance.
.PARAMETER ApplianceUrl
HTTPS URL used for appliance API validation.
.PARAMETER SiteInterface
Appliance interface used for the site-network scenario.
.PARAMETER SiteCidr
IPv4 CIDR assigned to the site-network scenario.
.PARAMETER SiteVlanId
VLAN identifier used by the site-network scenario.
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
Secure VCF Backup Password supplied at runtime; no repository default is used.
.PARAMETER VlanId
VLAN identifier used by the tagged-network scenario.
.PARAMETER TaggedVlanCidr
IPv4 CIDR used by the tagged-network scenario.
.PARAMETER WanCidr
IPv4 CIDR used by the simulated WAN scenario.
.PARAMETER KeepVms
Retain generated lifecycle VMs after the run completes.
.PARAMETER SkipClientPrepare
Reuse the existing client image instead of rebuilding it.
.PARAMETER PrepareNetworksOnly
Prepare required lifecycle networks and exit without creating VMs.
.PARAMETER CleanupNetworksOnly
Remove lifecycle networks and exit without running scenarios.
.PARAMETER CleanupVmsOnly
Remove VMs for the selected lifecycle lab and exit.
.PARAMETER CleanupNetworksAfterTest
Remove lifecycle networks after a successful or failed run.
.PARAMETER AllowDryRunApply
Allow the harness to exercise the appliance dry-run apply path.
.PARAMETER SkipBackupRestoreTest
Skip the backup and restore lifecycle phase.
.PARAMETER SignedReleaseRepositoryUrl
Signed release repository URL used by update lifecycle validation.
.PARAMETER PlanOnly
Emit the resolved lifecycle plan without prompting for secrets or mutating the host.
#>
[CmdletBinding(DefaultParameterSetName = 'Run', SupportsShouldProcess = $true)]
param(
    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'CleanupVms')]
    [string]$LabName = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceVhdxPath = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ClientVhdxPath = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$EsxIsoPath = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ClientManagementSwitch = 'Default Switch',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceIPAddress = '192.168.49.1',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$ApplianceUrl = '',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$SiteInterface = 'eth1.12',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$SiteCidr = '192.168.12.1/24',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [int]$SiteVlanId = 12,

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
    [int]$VlanId = 50,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$TaggedVlanCidr = '192.168.60.1/24',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$WanCidr = '172.31.50.1/24',

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$KeepVms,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$SkipClientPrepare,

    [Parameter(Mandatory = $true, ParameterSetName = 'PrepareNetworks')]
    [switch]$PrepareNetworksOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'CleanupNetworks')]
    [switch]$CleanupNetworksOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'CleanupVms')]
    [switch]$CleanupVmsOnly,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$CleanupNetworksAfterTest,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$AllowDryRunApply,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$SkipBackupRestoreTest,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Plan')]
    [string]$SignedReleaseRepositoryUrl = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'Plan')]
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')

<#
.SYNOPSIS
Return the newest eligible appliance VHDX from the Hyper-V build output.
#>
function Find-LatestApplianceVhdx {
    $outputRoot = Join-Path $repoRoot 'image\hyperv\output'
    if (-not (Test-Path -LiteralPath $outputRoot)) {
        throw "Hyper-V output directory not found: $outputRoot"
    }
    $candidates = Get-ChildItem -Path $outputRoot -Recurse -Filter '*.vhdx' |
        Where-Object {
            $_.Name -notmatch 'Depot|Backups' -and
            $_.FullName -notmatch '\\clients\\'
        } |
        Sort-Object -Property LastWriteTime -Descending
    $selected = $candidates | Select-Object -First 1
    if (-not $selected) {
        throw "No appliance VHDX found under $outputRoot. Build the Hyper-V image or pass -ApplianceVhdxPath."
    }
    return $selected.FullName
}

if (-not $LabName) {
    if ($PSCmdlet.ParameterSetName -eq 'CleanupVms') {
        $LabName = 'AtlasoLifecycle'
    } else {
        $LabName = "AtlasoLifecycle-$(Get-Date -Format 'yyyyMMddHHmmss')"
    }
}

if ($PSCmdlet.ParameterSetName -eq 'PrepareNetworks') {
    & (Join-Path $PSScriptRoot 'create-switches.ps1')
    if (-not $?) {
        throw "Hyper-V network preparation failed."
    }
    return
}

if ($PSCmdlet.ParameterSetName -eq 'CleanupNetworks') {
    & (Join-Path $PSScriptRoot 'remove-lifecycle-networks.ps1')
    if (-not $?) {
        throw "Hyper-V network cleanup failed."
    }
    return
}

if ($PSCmdlet.ParameterSetName -eq 'CleanupVms') {
    & (Join-Path $PSScriptRoot 'remove-lifecycle-vms.ps1') -LabName $LabName
    if (-not $?) {
        throw "Hyper-V VM cleanup failed."
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
    if ($null -eq $VcfBackupPassword) {
        $VcfBackupPassword = Read-Host -Prompt 'VCF Backup lifecycle password' -AsSecureString
    }
}
if (-not $ApplianceVhdxPath) {
    $ApplianceVhdxPath = Find-LatestApplianceVhdx
}
if (-not $ClientVhdxPath) {
    $ClientVhdxPath = Join-Path $repoRoot 'image\hyperv\clients\alpine-cloud\atlaso-tiny-linux-client.vhdx'
}
if ($EsxIsoPath) {
    $EsxIsoPath = (Resolve-Path -LiteralPath $EsxIsoPath).Path
    if ([System.IO.Path]::GetExtension($EsxIsoPath).ToLowerInvariant() -ne '.iso') {
        throw "-EsxIsoPath must point to an .iso file."
    }
}
$effectiveApplianceUrl = if ($ApplianceUrl) { $ApplianceUrl } else { "https://${ApplianceIPAddress}" }

if (-not $SkipClientPrepare -and -not $PlanOnly) {
    & (Join-Path $PSScriptRoot 'prepare-tiny-linux-client.ps1')
    if (-not $?) {
        throw "Tiny Linux client preparation failed."
    }
}

$secretBundlePath = ''
if (-not $PlanOnly) {
    $secretBundlePath = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-hyperv-lifecycle-$([guid]::NewGuid().ToString('N')).clixml"
    # CLIXML uses the current Windows user's DPAPI protection for SecureString
    # members, avoiding plaintext password arguments across the PowerShell process boundary.
    [pscustomobject]@{
        AdminPassword     = $AdminPassword
        SshPassword       = $SshPassword
        VcfBackupPassword = $VcfBackupPassword
    } | Export-Clixml -LiteralPath $secretBundlePath -Force
}

$arguments = @(
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $PSScriptRoot 'run-lifecycle-test.ps1'),
    '-LabName', $LabName,
    '-ApplianceVhdxPath', $ApplianceVhdxPath,
    '-ClientVhdxPath', $ClientVhdxPath,
    '-ClientManagementSwitch', $ClientManagementSwitch,
    '-ApplianceIPAddress', $ApplianceIPAddress,
    '-ApplianceUrl', $effectiveApplianceUrl,
    '-SiteInterface', $SiteInterface,
    '-SiteCidr', $SiteCidr,
    '-SiteVlanId', "$SiteVlanId",
    '-AdminUsername', $AdminUsername,
    '-ApplianceSshUser', $ApplianceSshUser,
    '-ClientSshUser', $ClientSshUser,
    '-VlanId', "$VlanId",
    '-TaggedVlanCidr', $TaggedVlanCidr,
    '-WanCidr', $WanCidr
)
if (-not $PlanOnly) {
    $arguments += @('-SecretBundlePath', $secretBundlePath)
}
if ($EsxIsoPath) {
    $arguments += @('-EsxIsoPath', $EsxIsoPath)
}

if (-not $KeepVms) {
    $arguments += '-CleanupCreatedLab'
}
if ($AllowDryRunApply) {
    $arguments += '-AllowDryRunApply'
}
if ($SkipBackupRestoreTest) {
    $arguments += '-SkipBackupRestoreTest'
}
if ($SignedReleaseRepositoryUrl) {
    $arguments += @('-SignedReleaseRepositoryUrl', $SignedReleaseRepositoryUrl)
}
if ($PlanOnly) {
    $arguments += '-PlanOnly'
}

Write-Host "Lifecycle lab: $LabName"
Write-Host "Appliance VHDX: $ApplianceVhdxPath"
Write-Host "Client VHDX: $ClientVhdxPath"
Write-Host "Appliance URL: $effectiveApplianceUrl"
Write-Host "Signed release lifecycle repository: $SignedReleaseRepositoryUrl"
Write-Host ("Backup/restore validation: {0}" -f (-not $SkipBackupRestoreTest))
Write-Host ("Cleanup created VMs: {0}" -f (-not $KeepVms))

try {
    & powershell.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Hyper-V lifecycle test failed with exit code $LASTEXITCODE"
    }
} finally {
    if ($secretBundlePath) {
        Remove-Item -LiteralPath $secretBundlePath -Force -ErrorAction SilentlyContinue
    }
}

if ($CleanupNetworksAfterTest) {
    & (Join-Path $PSScriptRoot 'remove-lifecycle-networks.ps1')
    if (-not $?) {
        throw "Hyper-V network cleanup failed."
    }
}
