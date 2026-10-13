<#
.SYNOPSIS
Safely remove one exact VMware Workstation VM and its artifact directory.

.PARAMETER VmxPath
Exact VMX file whose VMware Workstation artifacts are removed.

.PARAMETER VmrunPath
Optional path to the vmrun executable. When omitted, use a standard installation path or PATH lookup.

.PARAMETER ExpectedName
Optional exact VMware display name required before cleanup.

.PARAMETER ExpectedRootIdentity
Optional original VM directory filesystem identity from an immutable ownership receipt.

.PARAMETER ExpectedPersistentVmIdentitySha256
Optional SHA-256 of the persistent Atlaso cleanup identity in the VMX. Must be paired with ExpectedRootIdentity.

.PARAMETER AllowImageOutputRemoval
Allow removal under the built image output directory for intentional image cleanup.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,
    [string]$VmrunPath = '',
    [string]$ExpectedName = '',
    [string]$ExpectedRootIdentity = '',
    [string]$ExpectedPersistentVmIdentitySha256 = '',
    [switch]$AllowImageOutputRemoval
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force

<#
.SYNOPSIS
Resolve the requested or installed VMware vmrun executable.

.PARAMETER Path
Optional explicit vmrun executable path.
#>
function Resolve-VmrunPath {
    param([string]$Path)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "vmrun.exe not found: $Path" }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    foreach ($candidate in @('C:\Program Files\VMware\VMware Workstation\vmrun.exe', 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

$resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
$vmDirectory = Split-Path -Parent $resolvedVmxPath
$hasExpectedRootIdentity = -not [string]::IsNullOrEmpty($ExpectedRootIdentity)
$hasExpectedPersistentVmIdentity = -not [string]::IsNullOrEmpty($ExpectedPersistentVmIdentitySha256)
if ($hasExpectedRootIdentity -ne $hasExpectedPersistentVmIdentity) {
    throw 'Caller-preserved cleanup identities must be supplied together.'
}
if ($hasExpectedRootIdentity -and
    ($ExpectedRootIdentity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
     $ExpectedPersistentVmIdentitySha256 -cnotmatch '^[0-9A-Fa-f]{64}$')) {
    throw 'Caller-preserved cleanup identities are malformed.'
}
if ($hasExpectedRootIdentity) {
    $currentRootIdentity = Get-AtlasoPathIdentity -Path $vmDirectory -Description 'VMware artifact root'
    if ($currentRootIdentity -cne $ExpectedRootIdentity) {
        throw "VMware artifact root does not match the caller-preserved original identity; artifacts were preserved: $vmDirectory"
    }
}
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$imageOutputRoot = Join-Path $repoRoot 'image\vmware-workstation\output'

if (-not $AllowImageOutputRemoval -and (Test-Path -LiteralPath $imageOutputRoot)) {
    $resolvedImageOutputRoot = (Resolve-Path -LiteralPath $imageOutputRoot).Path
    if (
        $vmDirectory.Equals($resolvedImageOutputRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        (Test-AtlasoStrictDescendantPath -ParentPath $resolvedImageOutputRoot -ChildPath $vmDirectory)
    ) {
        throw "Refusing to remove a VM under built image output: $vmDirectory. Pass -AllowImageOutputRemoval only for intentional image cleanup."
    }
}

if ($ExpectedName) {
    $displayName = Get-AtlasoVmxDisplayName -Path $resolvedVmxPath
    if (-not $displayName.Equals($ExpectedName, [System.StringComparison]::Ordinal)) {
        throw "Refusing to remove VMware artifacts because VMX displayName '$displayName' does not match expected name '$ExpectedName'."
    }
}

$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath

if ($PSCmdlet.ShouldProcess($vmDirectory, 'Stop and delete VMware Workstation VM artifacts')) {
    Remove-AtlasoWorkstationVmArtifacts `
        -VmrunPath $resolvedVmrun `
        -VmxPaths @($resolvedVmxPath) `
        -RemovalRoot $vmDirectory `
        -ExpectedRootIdentity $ExpectedRootIdentity `
        -ExpectedPersistentVmIdentitySha256 $ExpectedPersistentVmIdentitySha256 `
        -Confirm:$false
    Write-Host "Removed VMware Workstation VM directory: $vmDirectory"
}
