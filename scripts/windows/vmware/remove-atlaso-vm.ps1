[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,
    [string]$VmrunPath = '',
    [string]$ExpectedName = '',
    [switch]$AllowImageOutputRemoval
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force

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

if ($PSCmdlet.ShouldProcess($vmDirectory, 'Stop, unregister, and remove VMware Workstation VM artifacts')) {
    Remove-AtlasoWorkstationVmArtifacts `
        -VmrunPath $resolvedVmrun `
        -VmxPaths @($resolvedVmxPath) `
        -RemovalRoot $vmDirectory `
        -Confirm:$false
    Write-Host "Removed VMware Workstation VM directory: $vmDirectory"
}
