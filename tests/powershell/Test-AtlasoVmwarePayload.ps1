<#
.SYNOPSIS
Verify canonical and rejected VMware payload layouts and provenance.
.PARAMETER RepositoryRoot
Atlaso repository root.
.PARAMETER OutputDirectory
Isolated test-output directory.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.VmwarePayload.psm1'
Import-Module $modulePath -Force

<#
.SYNOPSIS
Write a compact synthetic VMDK descriptor.
.PARAMETER Path
Destination descriptor path.
.PARAMETER CapacityBytes
Declared virtual capacity.
#>
function Write-TestVmdk {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$CapacityBytes
    )

    if ($CapacityBytes % 512 -ne 0) {
        throw 'Test VMDK capacity must align to 512-byte sectors.'
    }
    $sectors = $CapacityBytes / 512
    [System.IO.File]::WriteAllText(
        $Path,
        "# Disk DescriptorFile`nversion=1`nRW $sectors SPARSE `"payload.bin`"`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}

<#
.SYNOPSIS
Write a synthetic two-payload VMX.
.PARAMETER Path
Destination VMX path.
.PARAMETER UnitZero
Unit-zero VMDK filename.
.PARAMETER UnitOne
Unit-one VMDK filename.
#>
function Write-TestVmx {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$UnitZero,
        [Parameter(Mandatory = $true)][string]$UnitOne
    )

    $content = @(
        "displayName = `"$([System.IO.Path]::GetFileNameWithoutExtension($Path))`"",
        'scsi0.virtualdev = "pvscsi"',
        'scsi0:0.present = "TRUE"',
        "scsi0:0.filename = `"$UnitZero`"",
        'scsi0:1.present = "TRUE"',
        "scsi0:1.filename = `"$UnitOne`""
    )
    [System.IO.File]::WriteAllLines($Path, $content, [System.Text.UTF8Encoding]::new($false))
}

<#
.SYNOPSIS
Write synthetic role-bound payload provenance.
.PARAMETER VmxPath
VMX whose bytes are recorded.
.PARAMETER Layout
Verified payload layout records.
.PARAMETER SchemaVersion
Provenance schema version.
.PARAMETER ReverseRoles
Swap recorded roles to test rejection.
.PARAMETER BuilderKind
Builder identity kind recorded in the fixture provenance.
#>
function Write-TestProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)]$Layout,
        [int]$SchemaVersion = 3,
        [switch]$ReverseRoles,
        [ValidateSet('pull_request', 'local', 'release')]
        [string]$BuilderKind = 'pull_request'
    )

    $vmx = Get-Item -LiteralPath $VmxPath
    $records = @($Layout | ForEach-Object {
            $role = $_.Role
            if ($ReverseRoles) {
                $role = if ($role -eq 'photon_os') { 'atlaso_system' } else { 'photon_os' }
            }
            [ordered]@{
                role           = $role
                scsi_unit      = $_.ScsiUnit
                name           = $_.File.Name
                capacity_bytes = $_.CapacityBytes
                bytes          = $_.File.Length
                sha256         = (Get-FileHash -LiteralPath $_.File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        })
    $builderIdentity = switch ($BuilderKind) {
        'local' {
            [ordered]@{
                schema_version      = 1
                kind                = 'local'
                name                = $vmx.BaseName
                repository          = 'mdaneri/Atlaso'
                pull_request_number = 0
                source_branch       = 'enhancement/703-local-photon-builder'
                source_commit       = ('a' * 40)
                collision_suffix    = ''
                release_version     = ''
                workflow_run_id     = 0
            }
        }
        'release' {
            [ordered]@{
                schema_version      = 1
                kind                = 'release'
                name                = $vmx.BaseName
                repository          = ''
                pull_request_number = 0
                source_branch       = ''
                source_commit       = ('a' * 40)
                collision_suffix    = ''
                release_version     = '0.9.250'
                workflow_run_id     = 0
            }
        }
        default {
            [ordered]@{
                schema_version      = 1
                kind                = 'pull_request'
                name                = $vmx.BaseName
                repository          = 'mdaneri/Atlaso'
                pull_request_number = 653
                source_branch       = 'enhancement/653-pr-photon-builder-identity'
                source_commit       = ('a' * 40)
                collision_suffix    = ''
                release_version     = ''
                workflow_run_id     = 0
            }
        }
    }
    $provenance = [ordered]@{
        schema_version       = $SchemaVersion
        source_commit        = ('a' * 40)
        tracked_source_dirty = $false
        source_snapshot      = [ordered]@{
            schema_version = 1
            file_count     = 42
            sha256         = ('b' * 64)
        }
        builder_identity     = $builderIdentity
        vmx                  = [ordered]@{
            name   = $vmx.Name
            bytes  = $vmx.Length
            sha256 = (Get-FileHash -LiteralPath $vmx.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        payload_disks        = $records
    }
    $path = [System.IO.Path]::ChangeExtension($vmx.FullName, 'provenance.json')
    [System.IO.File]::WriteAllText(
        $path,
        (($provenance | ConvertTo-Json -Depth 6) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    return $path
}

$builderName = 'Atlaso-PR-653-Photon-Builder-VMware'
$OutputDirectory = Join-Path $OutputDirectory $builderName
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$osDisk = Join-Path $OutputDirectory 'photon.vmdk'
$systemDisk = Join-Path $OutputDirectory 'atlaso-system.vmdk'
$vmxPath = Join-Path $OutputDirectory "$builderName.vmx"
Write-TestVmdk -Path $osDisk -CapacityBytes 40GB
Write-TestVmdk -Path $systemDisk -CapacityBytes 20GB
Write-TestVmx -Path $vmxPath -UnitZero 'photon.vmdk' -UnitOne 'atlaso-system.vmdk'

$layout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $vmxPath -RequireExactlyTwoVmdks)
if (($layout.Role -join ',') -ne 'photon_os,atlaso_system' -or
    ($layout.ScsiUnit -join ',') -ne '0,1') {
    throw 'Correct VMware payload layout did not retain the canonical role and unit ordering.'
}
$provenancePath = Write-TestProvenance -VmxPath $vmxPath -Layout $layout
$null = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmxPath -ProvenancePath $provenancePath
$null = Assert-AtlasoVmwarePayloadProvenance `
    -VmxPath $vmxPath `
    -ProvenancePath $provenancePath `
    -ExpectedSourceCommit ('a' * 40) `
    -RequireCleanSource

$fixtureParent = Split-Path -Parent $OutputDirectory
$localBuilderName = 'Atlaso-Local-aaaaaaaaaaaa-Photon-Builder-VMware'
$localOutput = Join-Path $fixtureParent $localBuilderName
New-Item -ItemType Directory -Force -Path $localOutput | Out-Null
$localOsDisk = Join-Path $localOutput 'photon.vmdk'
$localSystemDisk = Join-Path $localOutput 'atlaso-system.vmdk'
$localVmxPath = Join-Path $localOutput "$localBuilderName.vmx"
Write-TestVmdk -Path $localOsDisk -CapacityBytes 40GB
Write-TestVmdk -Path $localSystemDisk -CapacityBytes 20GB
Write-TestVmx -Path $localVmxPath -UnitZero 'photon.vmdk' -UnitOne 'atlaso-system.vmdk'
$localLayout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $localVmxPath -RequireExactlyTwoVmdks)
$localProvenancePath = Write-TestProvenance `
    -VmxPath $localVmxPath `
    -Layout $localLayout `
    -BuilderKind local
$null = Assert-AtlasoVmwarePayloadProvenance `
    -VmxPath $localVmxPath `
    -ProvenancePath $localProvenancePath
try {
    $null = Assert-AtlasoVmwarePayloadProvenance `
        -VmxPath $localVmxPath `
        -ProvenancePath $localProvenancePath `
        -RequireReleaseBuilder
    throw 'Local/test VMware provenance was accepted for protected release work.'
}
catch {
    if ($_.Exception.Message -notlike '*requires release-builder provenance*') {
        throw
    }
}

$releaseBuilderName = 'Atlaso-Release-v0-9-250-aaaaaaaaaaaa-Photon-Builder-VMware'
$releaseOutput = Join-Path $fixtureParent $releaseBuilderName
New-Item -ItemType Directory -Force -Path $releaseOutput | Out-Null
$releaseOsDisk = Join-Path $releaseOutput 'photon.vmdk'
$releaseSystemDisk = Join-Path $releaseOutput 'atlaso-system.vmdk'
$releaseVmxPath = Join-Path $releaseOutput "$releaseBuilderName.vmx"
Write-TestVmdk -Path $releaseOsDisk -CapacityBytes 40GB
Write-TestVmdk -Path $releaseSystemDisk -CapacityBytes 20GB
Write-TestVmx -Path $releaseVmxPath -UnitZero 'photon.vmdk' -UnitOne 'atlaso-system.vmdk'
$releaseLayout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $releaseVmxPath -RequireExactlyTwoVmdks)
$releaseProvenancePath = Write-TestProvenance `
    -VmxPath $releaseVmxPath `
    -Layout $releaseLayout `
    -BuilderKind release
$null = Assert-AtlasoVmwarePayloadProvenance `
    -VmxPath $releaseVmxPath `
    -ProvenancePath $releaseProvenancePath `
    -RequireReleaseBuilder
try {
    $null = Assert-AtlasoVmwarePayloadProvenance `
        -VmxPath $vmxPath `
        -ProvenancePath $provenancePath `
        -ExpectedSourceCommit ('b' * 40)
    throw 'VMware provenance for a different release commit was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*does not identify expected source commit*') {
        throw
    }
}
$dirtyProvenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
$dirtyProvenance.tracked_source_dirty = $true
[System.IO.File]::WriteAllText(
    $provenancePath,
    (($dirtyProvenance | ConvertTo-Json -Depth 6) + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)
try {
    $null = Assert-AtlasoVmwarePayloadProvenance `
        -VmxPath $vmxPath `
        -ProvenancePath $provenancePath `
        -ExpectedSourceCommit ('a' * 40) `
        -RequireCleanSource
    throw 'Dirty VMware build provenance was accepted for release.'
}
catch {
    if ($_.Exception.Message -notlike '*records a dirty tracked source tree*') {
        throw
    }
}
$provenancePath = Write-TestProvenance -VmxPath $vmxPath -Layout $layout

Write-TestVmx -Path $vmxPath -UnitZero 'atlaso-system.vmdk' -UnitOne 'photon.vmdk'
try {
    $null = Get-AtlasoVmwarePayloadLayout -VmxPath $vmxPath -RequireExactlyTwoVmdks
    throw 'Reversed VMware payload layout was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*Photon OS payload at SCSI unit 0 must expose 42949672960 bytes*') {
        throw
    }
}

Write-TestVmx -Path $vmxPath -UnitZero 'photon.vmdk' -UnitOne 'atlaso-system.vmdk'
[System.IO.File]::AppendAllText(
    $vmxPath,
    "scsi0:0.filename = `"photon.vmdk`"`n",
    [System.Text.UTF8Encoding]::new($false)
)
try {
    $null = Get-AtlasoVmwarePayloadLayout -VmxPath $vmxPath -RequireExactlyTwoVmdks
    throw 'Duplicate VMware payload assignment was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*exactly one scsi0:0.fileName assignment; found 2*') {
        throw
    }
}

Write-TestVmx -Path $vmxPath -UnitZero 'photon.vmdk' -UnitOne 'atlaso-system.vmdk'
$layout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $vmxPath -RequireExactlyTwoVmdks)
$legacyPath = Write-TestProvenance -VmxPath $vmxPath -Layout $layout -SchemaVersion 2
try {
    $null = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmxPath -ProvenancePath $legacyPath
    throw 'Legacy VMware provenance without verified payload roles was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*does not contain a verified immutable source snapshot, builder identity, and payload-disk roles*') {
        throw
    }
}

$reversedRolePath = Write-TestProvenance -VmxPath $vmxPath -Layout $layout -ReverseRoles
try {
    $null = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmxPath -ProvenancePath $reversedRolePath
    throw 'VMware provenance with reversed payload roles was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*does not match the verified Photon OS payload at SCSI unit 0*') {
        throw
    }
}

$provenancePath = Write-TestProvenance -VmxPath $vmxPath -Layout $layout
$deploymentSourcePath = Join-Path $OutputDirectory 'virtualization-source.json'
[System.IO.File]::WriteAllText(
    $deploymentSourcePath,
    "{`"schema_version`":1}`n",
    [System.Text.UTF8Encoding]::new($false)
)
[System.IO.File]::AppendAllText(
    $systemDisk,
    'deployed-application-wheel',
    [System.Text.UTF8Encoding]::new($false)
)
$refreshed = Update-AtlasoVmwarePayloadProvenance `
    -VmxPath $vmxPath `
    -DeploymentSourcePath $deploymentSourcePath `
    -ProvenancePath $provenancePath
if ($refreshed.payload_state -cne 'software-deployed' -or
    $refreshed.deployment_source_name -cne 'virtualization-source.json' -or
    $refreshed.deployment_source_sha256 -cne (
        Get-FileHash -LiteralPath $deploymentSourcePath -Algorithm SHA256
    ).Hash.ToLowerInvariant()) {
    throw 'Refreshed VMware payload provenance did not bind the deployed source metadata.'
}
$null = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmxPath -ProvenancePath $provenancePath

Write-Output 'Atlaso VMware payload layout and provenance tests passed.'
