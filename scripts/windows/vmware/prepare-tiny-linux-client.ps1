<#
.SYNOPSIS
Prepare a verified Alpine cloud image with enough disk capacity for VMware lifecycle probes.
.PARAMETER Version
Version label recorded for the selected Alpine cloud image.
.PARAMETER ImageName
File name of the pinned Alpine QCOW2 download.
.PARAMETER BaseUrl
Release directory containing the Alpine image and checksum.
.PARAMETER ExpectedSha512
Pinned SHA-512 digest required for the source image.
.PARAMETER OutputDirectory
Directory for the verified cache and converted VMware disk.
.PARAMETER OutputVmdkName
File name of the converted VMware client disk.
.PARAMETER Force
Re-download and reconvert the verified source image.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Version = '3.24.1',
    [string]$ImageName = 'generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2',
    [string]$BaseUrl = 'https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud',
    [ValidatePattern('^[0-9A-Fa-f]{128}$')]
    [string]$ExpectedSha512 = 'ed976ef40de1f73adcb0a3b253ec9e73e43c408208fcc3c30dcdf7a69b91a387a4777f88c6b72345123edf3832d7cb49403ecce28ec84d496d4b3bad6fbd0923',
    [string]$OutputDirectory = '',
    [string]$OutputVmdkName = 'atlaso-tiny-linux-client.vmdk',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Import-Module (Join-Path $PSScriptRoot '..\common\Atlaso.VerifiedDownload.psm1') -Force

<#
.SYNOPSIS
Compute an uppercase SHA-512 digest for a downloaded image.
.PARAMETER Path
Local image path to hash.
#>
function Get-Sha512FileHash {
    param([string]$Path)

    $hashCommand = Get-Command Get-FileHash -ErrorAction SilentlyContinue
    if ($hashCommand) {
        return (Get-FileHash -Algorithm SHA512 -LiteralPath $Path).Hash.ToUpperInvariant()
    }

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        try {
            return (($sha512.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
        } finally {
            $sha512.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'image\vmware-workstation\clients\alpine-cloud'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$qcowPath = Join-Path $OutputDirectory $ImageName
$checksumPath = Join-Path $OutputDirectory "$ImageName.sha512"
$vmdkPath = Join-Path $OutputDirectory $OutputVmdkName
$convertedThisRun = $false

if (-not (Get-Command qemu-img -ErrorAction SilentlyContinue)) {
    throw "qemu-img is required to convert Alpine QCOW2 to VMware VMDK."
}

$actual = Save-AtlasoVerifiedDownloadPair `
    -PayloadUri "$BaseUrl/$ImageName" `
    -ChecksumUri "$BaseUrl/$ImageName.sha512" `
    -PayloadPath $qcowPath `
    -ChecksumPath $checksumPath `
    -Algorithm SHA512 `
    -ExpectedDigest $ExpectedSha512 `
    -GetFileHash { param($Path) Get-Sha512FileHash -Path $Path } `
    -Force:$Force `
    -WhatIf:$WhatIfPreference
if (-not $actual) {
    return
}

if ((Test-Path -LiteralPath $vmdkPath) -and -not $Force) {
    Write-Host "VMDK already exists: $vmdkPath"
} else {
    if ((Test-Path -LiteralPath $vmdkPath) -and $Force) {
        Remove-Item -LiteralPath $vmdkPath -Force
    }
    if ($PSCmdlet.ShouldProcess($vmdkPath, 'Convert Alpine QCOW2 to growable VMware VMDK')) {
        qemu-img convert -p -f qcow2 -O vmdk -o subformat=monolithicSparse $qcowPath $vmdkPath
        $convertExitCode = $LASTEXITCODE
        if ($convertExitCode -ne 0) {
            if (Test-Path -LiteralPath $vmdkPath) {
                try {
                    Remove-Item -LiteralPath $vmdkPath -Force -ErrorAction Stop
                } catch {
                    throw "qemu-img convert failed with exit code $convertExitCode, and the partial VMDK could not be removed: $($_.Exception.Message)"
                }
            }
            throw "qemu-img convert failed with exit code $convertExitCode."
        }
        $convertedThisRun = $true
    }
}

try {
    $minimumVirtualSize = [int64]2GB
    $imageInfoJson = qemu-img info --output=json -f vmdk $vmdkPath
    if ($LASTEXITCODE -ne 0) {
        throw "qemu-img could not inspect the VMware client disk before capacity validation."
    }
    $virtualSize = [int64](($imageInfoJson -join "`n") | ConvertFrom-Json).'virtual-size'
    if ($virtualSize -lt $minimumVirtualSize) {
        if (-not $PSCmdlet.ShouldProcess($vmdkPath, 'Expand the powered-off VMware client disk to 2 GiB')) {
            return
        }
        $diskManagerCommand = Get-Command vmware-vdiskmanager.exe -ErrorAction SilentlyContinue
        $diskManagerPath = if ($diskManagerCommand) { $diskManagerCommand.Source } else { '' }
        if (-not $diskManagerPath) {
            foreach ($candidate in @(
                'C:\Program Files\VMware\VMware Workstation\vmware-vdiskmanager.exe',
                'C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe'
            )) {
                if (Test-Path -LiteralPath $candidate) {
                    $diskManagerPath = $candidate
                    break
                }
            }
        }
        if (-not $diskManagerPath) {
            throw 'vmware-vdiskmanager.exe is required to expand the powered-off VMware client disk.'
        }
        & $diskManagerPath -x 2GB $vmdkPath
        if ($LASTEXITCODE -ne 0) {
            throw "vmware-vdiskmanager could not expand the VMware client disk to 2 GiB."
        }
    }

    $info = qemu-img info $vmdkPath
    $infoExitCode = $LASTEXITCODE
    if ($infoExitCode -ne 0) {
        throw "qemu-img info failed with exit code $infoExitCode."
    }
    $verifiedInfoJson = qemu-img info --output=json -f vmdk $vmdkPath
    if ($LASTEXITCODE -ne 0 -or [int64](($verifiedInfoJson -join "`n") | ConvertFrom-Json).'virtual-size' -lt $minimumVirtualSize) {
        throw "The VMware client disk is smaller than the required 2 GiB virtual capacity."
    }
    [pscustomobject]@{
        version       = $Version
        qcow2         = (Resolve-Path -LiteralPath $qcowPath).Path
        sha512        = $actual
        vmdk          = (Resolve-Path -LiteralPath $vmdkPath).Path
        qemu_img_info = ($info -join "`n")
    } | ConvertTo-Json -Depth 3
} catch {
    $inspectionError = $_
    if ($convertedThisRun -and (Test-Path -LiteralPath $vmdkPath)) {
        try {
            Remove-Item -LiteralPath $vmdkPath -Force -ErrorAction Stop
        } catch {
            throw "VMware client disk verification failed, and the newly converted VMDK could not be removed: $($_.Exception.Message)"
        }
    }
    throw $inspectionError
}
