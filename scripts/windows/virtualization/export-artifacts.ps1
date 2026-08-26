<#
.SYNOPSIS
Convert the exact validated Atlaso OVA into one versioned Hyper-V ZIP.
.PARAMETER OvaPath
Canonical Atlaso VMware OVA input.
.PARAMETER OutputRoot
Optional output root beneath the repository-owned artifacts/virtualization directory.
.PARAMETER QemuImgPath
Optional qemu-img executable path.
.PARAMETER PythonPath
Optional Python executable used by the canonical OVA validator.
.PARAMETER Force
Replace only the exact versioned ZIP that this invocation would publish.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OvaPath,
    [string]$OutputRoot = '',
    [string]$QemuImgPath = '',
    [string]$PythonPath = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VirtualizationArtifacts.psm1') -Force

$sourceOva = Get-Item -LiteralPath $OvaPath -ErrorAction Stop
if ($sourceOva.PSIsContainer -or
    ($sourceOva.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The canonical OVA input must be an ordinary file, not a directory or reparse point.'
}
$qemuImg = Resolve-AtlasoQemuImgPath -Path $QemuImgPath
$python = Resolve-AtlasoPythonPath -Path $PythonPath
$outputDirectory = Resolve-AtlasoHyperVOutputRoot -RepoRoot $repoRoot -OutputRoot $OutputRoot

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$outputDirectoryItem = Get-Item -LiteralPath $outputDirectory -Force
if (($outputDirectoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The Hyper-V output root became a reparse point.'
}

$operationRoot = Join-Path $outputDirectory ('.hyperv.partial-' + [guid]::NewGuid().ToString('N'))
$extractRoot = Join-Path $operationRoot 'ova'
$packageRoot = Join-Path $operationRoot 'package'
New-Item -ItemType Directory -Path $extractRoot | Out-Null
New-Item -ItemType Directory -Path $packageRoot | Out-Null

try {
    $validated = Invoke-AtlasoOvaValidation `
        -RepoRoot $repoRoot `
        -OvaPath $sourceOva.FullName `
        -ExtractDirectory $extractRoot `
        -PythonPath $python
    if ($validated.kind -ne 'atlaso-validated-ova' -or [int]$validated.schema_version -ne 1) {
        throw 'The OVA validator returned an unsupported contract.'
    }
    $version = [string]$validated.product_version
    if ($version -notmatch '^\d+\.\d+\.\d+$') {
        throw 'The validated OVA contains an invalid product version.'
    }
    $sourceCommit = [string]$validated.source_commit
    $commitVersion = Get-AtlasoTemplateVersion -RepoRoot $repoRoot -SourceCommit $sourceCommit
    if ($commitVersion -ne $version) {
        throw "OVA version $version does not match source commit version $commitVersion."
    }
    $payloads = @($validated.payloads | Sort-Object scsi_slot)
    if ($payloads.Count -ne 2 -or
        (@($payloads | ForEach-Object { [int]$_.scsi_slot }) -join ',') -ne '0,1' -or
        (@($payloads | ForEach-Object { [string]$_.role }) -join ',') -ne 'photon_os,atlaso_system') {
        throw 'The validated OVA payload roles and SCSI slots do not match the Atlaso contract.'
    }

    $diskRecords = @()
    foreach ($payload in $payloads) {
        $inputName = [string]$payload.file
        if ([System.IO.Path]::GetFileName($inputName) -ne $inputName) {
            throw 'The validated OVA payload contains an unsafe file name.'
        }
        $roleName = if ([string]$payload.role -eq 'photon_os') { 'photon-os' } else { 'atlaso-system' }
        $outputName = "$roleName.vhdx"
        $outputPath = Join-Path $packageRoot $outputName
        Invoke-AtlasoQemuImg -QemuImgPath $qemuImg -Arguments @(
            'convert', '-p', '-f', 'vmdk', '-O', 'vhdx',
            '-o', 'subformat=dynamic,block_size=2097152',
            (Join-Path $extractRoot $inputName), $outputPath
        ) | Out-Null
        Assert-AtlasoGeneratedVhdx `
            -QemuImgPath $qemuImg `
            -Path $outputPath `
            -VirtualSizeBytes ([long]$payload.virtual_size_bytes)
        $diskRecords += [ordered]@{
            role               = [string]$payload.role
            scsi_slot          = [int]$payload.scsi_slot
            file               = $outputName
            format             = 'vhdx'
            virtual_size_bytes = [long]$payload.virtual_size_bytes
            bytes              = (Get-Item -LiteralPath $outputPath).Length
            sha256             = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    foreach ($dataDisk in @(
            @{ Role = 'vcf_offline_depot'; Slot = 2; Name = 'vcf-offline-depot.vhdx' },
            @{ Role = 'vcf_backups'; Slot = 3; Name = 'vcf-backups.vhdx' }
        )) {
        $outputPath = Join-Path $packageRoot $dataDisk.Name
        Invoke-AtlasoQemuImg -QemuImgPath $qemuImg -Arguments @(
            'create', '-f', 'vhdx', '-o', 'subformat=dynamic,block_size=2097152',
            $outputPath, '536870912000'
        ) | Out-Null
        Assert-AtlasoGeneratedVhdx -QemuImgPath $qemuImg -Path $outputPath -VirtualSizeBytes 536870912000
        $diskRecords += [ordered]@{
            role               = $dataDisk.Role
            scsi_slot          = $dataDisk.Slot
            file               = $dataDisk.Name
            format             = 'vhdx'
            virtual_size_bytes = 536870912000
            bytes              = (Get-Item -LiteralPath $outputPath).Length
            sha256             = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    Copy-Item `
        -LiteralPath (Join-Path $PSScriptRoot 'templates\Import-Atlaso.ps1') `
        -Destination (Join-Path $packageRoot 'Import-Atlaso.ps1')
    $manifest = [ordered]@{
        schema_version  = 1
        kind            = 'atlaso-hyperv-artifact'
        product_version = $version
        source          = [ordered]@{
            kind          = 'atlaso-validated-ova'
            commit        = $sourceCommit
            ova_name      = $sourceOva.Name
            ova_sha256    = [string]$validated.ova_sha256
            ova_validator = 1
        }
        ssh_host_ed25519_public_key = [string]$validated.ssh_host_ed25519_public_key
        machine         = [ordered]@{
            firmware    = 'uefi'
            secure_boot = $false
            cpu_count   = 4
            memory_mib  = 4096
            nic_count   = 2
            disk_bus    = 'scsi'
        }
        disks           = $diskRecords
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $packageRoot 'manifest.json'),
        (($manifest | ConvertTo-Json -Depth 8) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-AtlasoArtifactChecksums -Directory $packageRoot

    $archiveName = "atlaso-v$version-hyperv-x86_64.zip"
    $archivePath = Join-Path $outputDirectory $archiveName
    if (Test-Path -LiteralPath $archivePath) {
        $existing = Get-Item -LiteralPath $archivePath -Force
        if ($existing.PSIsContainer -or
            ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Existing artifact is not a replaceable ordinary file: $archivePath"
        }
        if (-not $Force) {
            throw "Hyper-V artifact already exists; pass -Force to replace only this exact file: $archivePath"
        }
    }
    $partialArchive = Join-Path $operationRoot $archiveName
    $packageFiles = @(Get-ChildItem -LiteralPath $packageRoot -File | Sort-Object Name | ForEach-Object FullName)
    Compress-Archive -LiteralPath $packageFiles -DestinationPath $partialArchive -CompressionLevel Optimal
    $archive = Get-Item -LiteralPath $partialArchive -ErrorAction Stop
    if ($archive.Length -le 0 -or $archive.Length -ge 2147483648) {
        throw 'The Hyper-V ZIP is empty or exceeds the existing GitHub asset limit.'
    }
    Move-Item -LiteralPath $partialArchive -Destination $archivePath -Force
    Get-Item -LiteralPath $archivePath
}
finally {
    # The invocation owns only its GUID-scoped staging tree; final archive replacement is handled separately above.
    if (Test-Path -LiteralPath $operationRoot) {
        Remove-Item -LiteralPath $operationRoot -Recurse -Force
    }
}
