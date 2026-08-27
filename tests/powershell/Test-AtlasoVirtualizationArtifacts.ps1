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
$smokeIdentityModulePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\Atlaso.VirtualizationSmokeIdentity.psm1'
$exporterPath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\export-artifacts.ps1'
$importerPath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\templates\Import-Atlaso.ps1'
$hyperVSmokePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\smoke-hyperv.ps1'
$vmwareSmokePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\smoke-ova-vmware.ps1'
$ovaExporterPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\export-ovf.ps1'
Import-Module $modulePath -Force
Import-Module $smokeIdentityModulePath -Force

$head = [string](& git -C $RepositoryRoot rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve the current checkout commit for the version contract test.'
}
$version = Get-AtlasoTemplateVersion -RepoRoot $RepositoryRoot -SourceCommit $head
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'The source-commit version resolver did not return a semantic version.'
}

$hyperVAdapters = @(
    [pscustomobject]@{
        Name = 'Services'; Id = 'service-id'; SwitchName = 'Services';
        MacAddress = '00155D445566'; IPAddresses = @('198.51.100.20')
    },
    [pscustomobject]@{
        Name = 'Management'; Id = 'management-id'; SwitchName = 'Management';
        MacAddress = '00155D112233'; IPAddresses = @('192.0.2.20')
    }
)
$hyperVIdentity = Resolve-AtlasoHyperVSmokeNetworkIdentity `
    -Adapters $hyperVAdapters `
    -ManagementSwitch 'Management' `
    -ServiceSwitch 'Services'
if ($hyperVIdentity.Address -ne '192.0.2.20' -or
    $hyperVIdentity.ManagementMac -ne '00:15:5d:11:22:33') {
    throw 'Services-first Hyper-V evidence did not select the named Management adapter address.'
}
try {
    $changedHyperVAdapters = @($hyperVAdapters | ForEach-Object { $_.PSObject.Copy() })
    $changedHyperVAdapters[1].MacAddress = '00155DAABBCC'
    Resolve-AtlasoHyperVSmokeNetworkIdentity `
        -Adapters $changedHyperVAdapters `
        -ManagementSwitch 'Management' `
        -ServiceSwitch 'Services' `
        -ExpectedIdentity $hyperVIdentity | Out-Null
    throw 'Changed Hyper-V management MAC evidence was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'Changed Hyper-V management MAC evidence was accepted.') { throw }
}
try {
    $duplicateHyperVAdapters = @($hyperVAdapters | ForEach-Object { $_.PSObject.Copy() })
    $duplicateHyperVAdapters[0].IPAddresses = @('192.0.2.20')
    Resolve-AtlasoHyperVSmokeNetworkIdentity `
        -Adapters $duplicateHyperVAdapters `
        -ManagementSwitch 'Management' `
        -ServiceSwitch 'Services' | Out-Null
    throw 'Duplicate Hyper-V management address evidence was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'Duplicate Hyper-V management address evidence was accepted.') { throw }
}

$vmxFixture = Join-Path ([IO.Path]::GetTempPath()) ('atlaso-smoke-identity-' + [guid]::NewGuid().ToString('N') + '.vmx')
try {
    [IO.File]::WriteAllLines($vmxFixture, @(
            'ethernet0.vnet = "VMnet8"',
            'ethernet0.generatedAddress = "00:0c:29:11:22:33"',
            'ethernet1.vnet = "VMnet1"',
            'ethernet1.generatedAddress = "00:0c:29:44:55:66"'
        ))
    $vmxIdentity = Get-AtlasoVmwareSmokeVmxNetworkIdentity `
        -VmxPath $vmxFixture `
        -ManagementVmnet 'VMnet8' `
        -ServiceVmnet 'VMnet1'
    $vmwareIdentity = Resolve-AtlasoVmwareSmokeAddressIdentity `
        -VmxIdentity $vmxIdentity `
        -NetworkAdapters @(
            [pscustomobject]@{
                Name = 'VMware Network Adapter VMnet8';
                InterfaceDescription = 'VMware Virtual Ethernet Adapter for VMnet8';
                ifIndex = 8; Status = 'Up'
            }
        ) `
        -Neighbors @(
            [pscustomobject]@{
                InterfaceIndex = 8; IPAddress = '198.51.100.20';
                LinkLayerAddress = '00-0c-29-44-55-66'; State = 'Reachable'
            },
            [pscustomobject]@{
                InterfaceIndex = 8; IPAddress = '192.0.2.20';
                LinkLayerAddress = '00-0c-29-11-22-33'; State = 'Reachable'
            }
        ) `
        -ExpectedIdentity $vmxIdentity
    if ($vmwareIdentity.Address -ne '192.0.2.20' -or
        $vmwareIdentity.ManagementMac -ne '00:0c:29:11:22:33') {
        throw 'Services-first VMware neighbor evidence did not select ethernet0 on the management vmnet.'
    }
    try {
        $driftedVmwareIdentity = $vmwareIdentity.PSObject.Copy()
        $driftedVmwareIdentity.Address = '192.0.2.21'
        Resolve-AtlasoVmwareSmokeAddressIdentity `
            -VmxIdentity $vmxIdentity `
            -NetworkAdapters @(
                [pscustomobject]@{
                    Name = 'VMware Network Adapter VMnet8';
                    InterfaceDescription = 'VMware Virtual Ethernet Adapter for VMnet8';
                    ifIndex = 8; Status = 'Up'
                }
            ) `
            -Neighbors @(
                [pscustomobject]@{
                    InterfaceIndex = 8; IPAddress = '192.0.2.20';
                    LinkLayerAddress = '00-0c-29-11-22-33'; State = 'Reachable'
                }
            ) `
            -ExpectedIdentity $driftedVmwareIdentity | Out-Null
        throw 'Changed VMware management address evidence was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'Changed VMware management address evidence was accepted.') { throw }
    }
}
finally {
    Remove-Item -LiteralPath $vmxFixture -Force -ErrorAction SilentlyContinue
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
if ($vmwareSmoke.Contains('"--prop:atlaso.admin_password=$passwordText"') -or
    $vmwareSmoke.Contains('"--prop:atlaso.root_password=$passwordText"')) {
    throw 'VMware smoke still exposes the disposable credential through OVF Tool process arguments.'
}
foreach ($required in @(
        "Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'",
        'must be a strict descendant of its owned output root',
        'owned directory cannot be a reparse point',
        'Get-AtlasoWindowsFileId',
        'Assert-AtlasoVmwareVmIdentity',
        'Get-AtlasoVmwareDescendantIdentity',
        'Get-AtlasoVmwareInventoryPathById',
        '$ownedDescendantIds.ContainsKey($_)',
        'The pre-provider VMware smoke root identity changed',
        '$partialDescendants.ContainsKey($_)',
        'unexpected VMX set',
        'unexpected display name',
        'root identity changed after provider deletion',
        '"--configFile=$ovfToolConfigPath"',
        '$configAcl.SetAccessRuleProtection($true, $false)',
        'Remove-Item -LiteralPath $ovfToolConfigPath -Force',
        '$passwordText = $null'
    )) {
    if (-not $vmwareSmoke.Contains($required)) {
        throw "VMware smoke is missing a protected non-argv OVF Tool credential marker: $required"
    }
}
foreach ($required in @(
        'Invoke-AtlasoOvaValidation',
        'Get-AtlasoTemplateVersion',
        'atlaso-v$version-hyperv-x86_64.zip',
        "'convert', '-p', '-f', 'vmdk', '-O', 'vhdx'",
        "'create', '-f', 'vhdx'",
        '536870912000',
        'Import-Atlaso.ps1',
        'Write-AtlasoArtifactChecksums'
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
        '-ControllerType SCSI',
        '-FirstBootDevice $drives[0]',
        'if ($vmCreated -and $null -ne $vm)',
        'Remove-VM -VM $vm',
        '$vmRemovalVerified',
        'Get-VM -ErrorAction Stop | Where-Object Id -eq $vm.Id',
        '$verifiedVmMatches',
        '$verifiedVm = $verifiedVmMatches[0]',
        'exact created Hyper-V VM identity changed',
        'if ($vmRootCreated',
        'Get-AtlasoHyperVWindowsFileId',
        'Get-AtlasoHyperVDescendantIdentity',
        '$ownedDescendantIds[[string]$disk.file]',
        '$ownedDescendantIds.ContainsKey($_)',
        'an unrecorded partial copy is preserved',
        'root identity changed before filesystem deletion',
        'descendant identity changed before filesystem deletion',
        'files were preserved'
    )) {
    if (-not $importer.Contains($required)) {
        throw "The Hyper-V importer is missing required topology or rollback marker: $required"
    }
}
foreach ($required in @(
        'listRegisteredVM',
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
        'Get-Command vmrun',
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
        'atlaso.first_boot_access',
        'Get-AtlasoHyperVFirstBootAccess',
        'did not return an exact created VM identity',
        '$createdVmMatches = @(',
        '& $importer',
        'did not return one exact created virtual-machine identity',
        '$operationRootSafeToRemove = -not $importAttempted',
        '$operationRootSafeToRemove',
        'Get-AtlasoHyperVSmokeWindowsFileId',
        'Get-AtlasoHyperVSmokeDescendantIdentity',
        '$ownedDescendantIds.ContainsKey($_)',
        'root identity changed before filesystem deletion',
        'descendant identity changed before filesystem deletion',
        'Atlaso.VirtualizationSmokeIdentity.psm1',
        'Resolve-AtlasoHyperVSmokeNetworkIdentity',
        'Wait-AtlasoHyperVSmokeNetworkIdentity',
        "'--phase' 'post-reboot'",
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
if ($importer.Contains('Get-VM -Name $Name')) {
    throw 'The Hyper-V importer reacquires its invocation-owned VM by name.'
}
if (($hyperVSmoke.Split('Get-VM -ErrorAction Stop | Where-Object Name -eq $Name').Count - 1) -ne 1) {
    throw 'Hyper-V smoke cleanup still claims a post-failure VM by name instead of a captured ID.'
}
if ($hyperVSmoke.Contains('-Start | Out-Null') -or
    $hyperVSmoke.Contains('$createdVmMatches = @(Get-VM -Name $Name')) {
    throw 'Hyper-V smoke discards the importer-owned VM identity and reacquires it by name.'
}
if ($hyperVSmoke.Contains('ForEach-Object IPAddresses')) {
    throw 'Hyper-V smoke still flattens addresses across the Management and Services adapters.'
}
foreach ($required in @(
        'Atlaso.VirtualizationSmokeIdentity.psm1',
        'Get-AtlasoVmwareSmokeVmxNetworkIdentity',
        'Resolve-AtlasoVmwareSmokeAddressIdentity',
        'Wait-AtlasoVmwareSmokeNetworkIdentity',
        'Get-NetNeighbor -AddressFamily IPv4',
        "'--phase' 'post-reboot'"
    )) {
    if (-not $vmwareSmoke.Contains($required)) {
        throw "VMware smoke is missing a provider-bound management identity marker: $required"
    }
}
if ($vmwareSmoke.Contains('getGuestIPAddress')) {
    throw 'VMware smoke still trusts the unqualified VMware Tools guest address result.'
}

Write-Host 'Hyper-V virtualization artifact contract test passed.'
