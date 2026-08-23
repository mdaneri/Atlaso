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

function Write-TestVmx {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$UnitZero,
        [Parameter(Mandatory = $true)][string]$UnitOne
    )

    $content = @(
        'scsi0.virtualdev = "pvscsi"',
        'scsi0:0.present = "TRUE"',
        "scsi0:0.filename = `"$UnitZero`"",
        'scsi0:1.present = "TRUE"',
        "scsi0:1.filename = `"$UnitOne`""
    )
    [System.IO.File]::WriteAllLines($Path, $content, [System.Text.UTF8Encoding]::new($false))
}

function Write-TestProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)]$Layout,
        [int]$SchemaVersion = 2,
        [switch]$ReverseRoles
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
    $provenance = [ordered]@{
        schema_version       = $SchemaVersion
        source_commit        = ('a' * 40)
        tracked_source_dirty = $false
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

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$osDisk = Join-Path $OutputDirectory 'photon.vmdk'
$systemDisk = Join-Path $OutputDirectory 'atlaso-system.vmdk'
$vmxPath = Join-Path $OutputDirectory 'atlaso.vmx'
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
$legacyPath = Write-TestProvenance -VmxPath $vmxPath -Layout $layout -SchemaVersion 1
try {
    $null = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmxPath -ProvenancePath $legacyPath
    throw 'Legacy VMware provenance without verified payload roles was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*does not contain verified payload-disk roles*') {
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

Write-Output 'Atlaso VMware payload layout and provenance tests passed.'
