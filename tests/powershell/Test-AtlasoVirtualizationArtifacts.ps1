<#
.SYNOPSIS
Verify the constrained OVA-to-Hyper-V exporter and importer safety contract.
.PARAMETER RepositoryRoot
Atlaso checkout containing the virtualization scripts.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\Atlaso.VirtualizationArtifacts.psm1'
$exporterPath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\export-artifacts.ps1'
$importerPath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\templates\Import-Atlaso.ps1'
$hyperVSmokePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\smoke-hyperv.ps1'
$vmwareSmokePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\smoke-ova-vmware.ps1'
$ovaExporterPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\export-ovf.ps1'
Import-Module $modulePath -Force

$head = [string](& git -C $RepositoryRoot rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve the current checkout commit for the version contract test.'
}
$version = Get-AtlasoTemplateVersion -RepoRoot $RepositoryRoot -SourceCommit $head
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'The source-commit version resolver did not return a semantic version.'
}

$resolvedRoot = Resolve-AtlasoHyperVOutputRoot -RepoRoot $RepositoryRoot
$expectedRoot = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'artifacts\virtualization'))
if ($resolvedRoot -ne $expectedRoot) {
    throw 'The default Hyper-V artifact root is not the repository-owned virtualization directory.'
}
try {
    Resolve-AtlasoHyperVOutputRoot -RepoRoot $RepositoryRoot -OutputRoot ([System.IO.Path]::GetTempPath()) | Out-Null
    throw 'An output root outside the repository-owned virtualization directory was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'An output root outside the repository-owned virtualization directory was accepted.') {
        throw
    }
}

$exporter = Get-Content -Raw -LiteralPath $exporterPath
$importer = Get-Content -Raw -LiteralPath $importerPath
$module = Get-Content -Raw -LiteralPath $modulePath
$ovaExporter = Get-Content -Raw -LiteralPath $ovaExporterPath
$hyperVSmoke = Get-Content -Raw -LiteralPath $hyperVSmokePath
$vmwareSmoke = Get-Content -Raw -LiteralPath $vmwareSmokePath
foreach ($required in @(
        'Invoke-AtlasoOvaValidation',
        'Get-AtlasoTemplateVersion',
        'atlaso-v$version-hyperv-x86_64.zip',
        "'convert', '-p', '-f', 'vmdk', '-O', 'vhdx'",
        "'create', '-f', 'vhdx'",
        '536870912000',
        'Import-Atlaso.ps1',
        'Write-AtlasoArtifactChecksums',
        'ssh_host_ed25519_public_key'
    )) {
    if (-not $exporter.Contains($required)) {
        throw "The Hyper-V exporter is missing required contract marker: $required"
    }
}
foreach ($retired in @("'Kvm'", "'Proxmox'", "'qcow2'", 'AllowedTargetNames')) {
    if ($exporter.Contains($retired) -or $module.Contains($retired)) {
        throw "The standalone QCOW2 exporter contract remains: $retired"
    }
}
foreach ($required in @(
        'Write-AtlasoOvaProvenance',
        'atlaso-provenance.json',
        'atlaso-vmware-ova-provenance',
        'Assert-AtlasoCanonicalOva',
        'scripts\virtualization\validate_ova.py'
    )) {
    if (-not $ovaExporter.Contains($required)) {
        throw "The canonical OVA exporter is missing provenance or validation marker: $required"
    }
}
foreach ($required in @(
        "'atlaso-hyperv-artifact'",
        "'atlaso-validated-ova'",
        "@('photon_os', 'atlaso_system', 'vcf_offline_depot', 'vcf_backups')",
        '@(42949672960, 21474836480, 536870912000, 536870912000)',
        '-Generation 2',
        '-EnableSecureBoot Off',
        'Get-VHD -Path $destinationDisk',
        "VhdType -ne 'Dynamic'",
        'ssh_host_ed25519_public_key',
        '-ControllerType SCSI',
        '-FirstBootDevice $drives[0]',
        'if ($vmCreated -and $null -ne $vm)',
        'Remove-VM -VM $vm',
        '$vmRemovalVerified',
        'Get-VM -ErrorAction Stop | Where-Object Id -eq $vm.Id',
        'if ($vmRootCreated'
    )) {
    if (-not $importer.Contains($required)) {
        throw "The Hyper-V importer is missing required topology or rollback marker: $required"
    }
}
foreach ($required in @(
        'listRegisteredVM',
        '$vmRootSafeToRemove',
        '$cleanupFailure',
        'its files were preserved'
    )) {
    if (-not $vmwareSmoke.Contains($required)) {
        throw "The VMware smoke cleanup is missing fail-closed marker: $required"
    }
}
foreach ($required in @(
        'Remove-VM -VM $createdVm -Force -ErrorAction Stop',
        'Get-VM -ErrorAction Stop | Where-Object Id -eq $createdVm.Id',
        '$operationRootSafeToRemove',
        'its files were preserved'
    )) {
    if (-not $hyperVSmoke.Contains($required)) {
        throw "The Hyper-V smoke cleanup is missing fail-closed marker: $required"
    }
}
if ($importer.Contains('Remove-VM -VM $vm -Force -ErrorAction Continue') -or
    $hyperVSmoke.Contains('Remove-VM -Name $Name -Force -ErrorAction Continue')) {
    throw 'A Hyper-V cleanup still ignores VM removal failure.'
}

Write-Host 'Hyper-V virtualization artifact contract test passed.'
