[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Version = '3.24.1',
    [string]$ImageName = 'generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2',
    [string]$BaseUrl = 'https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud',
    [string]$OutputDirectory = '',
    [string]$OutputVhdxName = 'atlaso-tiny-linux-client.vhdx',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Import-Module (Join-Path $PSScriptRoot '..\common\Atlaso.VerifiedDownload.psm1') -Force

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'image\hyperv\clients\alpine-cloud'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$qcowPath = Join-Path $OutputDirectory $ImageName
$checksumPath = Join-Path $OutputDirectory "$ImageName.sha512"
$vhdxPath = Join-Path $OutputDirectory $OutputVhdxName
$convertedThisRun = $false

if (-not (Get-Command qemu-img -ErrorAction SilentlyContinue)) {
    throw "qemu-img is required to convert Alpine QCOW2 to Hyper-V VHDX."
}

$actual = Save-AtlasoVerifiedDownloadPair `
    -PayloadUri "$BaseUrl/$ImageName" `
    -ChecksumUri "$BaseUrl/$ImageName.sha512" `
    -PayloadPath $qcowPath `
    -ChecksumPath $checksumPath `
    -Algorithm SHA512 `
    -GetFileHash { param($Path) (Get-FileHash -Algorithm SHA512 -LiteralPath $Path).Hash } `
    -Force:$Force `
    -WhatIf:$WhatIfPreference
if (-not $actual) {
    return
}

if ((Test-Path -LiteralPath $vhdxPath) -and -not $Force) {
    Write-Host "VHDX already exists: $vhdxPath"
} else {
    if ((Test-Path -LiteralPath $vhdxPath) -and $Force) {
        Remove-Item -LiteralPath $vhdxPath -Force
    }
    if ($PSCmdlet.ShouldProcess($vhdxPath, 'Convert Alpine QCOW2 to dynamic VHDX')) {
        qemu-img convert -p -f qcow2 -O vhdx -o subformat=dynamic $qcowPath $vhdxPath
        $convertExitCode = $LASTEXITCODE
        if ($convertExitCode -ne 0) {
            if (Test-Path -LiteralPath $vhdxPath) {
                try {
                    Remove-Item -LiteralPath $vhdxPath -Force -ErrorAction Stop
                } catch {
                    throw "qemu-img convert failed with exit code $convertExitCode, and the partial VHDX could not be removed: $($_.Exception.Message)"
                }
            }
            throw "qemu-img convert failed with exit code $convertExitCode."
        }
        $convertedThisRun = $true
    }
}

$info = qemu-img info $vhdxPath
$infoExitCode = $LASTEXITCODE
if ($infoExitCode -ne 0) {
    if ($convertedThisRun -and (Test-Path -LiteralPath $vhdxPath)) {
        try {
            Remove-Item -LiteralPath $vhdxPath -Force -ErrorAction Stop
        } catch {
            throw "qemu-img info failed with exit code $infoExitCode, and the unverified VHDX could not be removed: $($_.Exception.Message)"
        }
    }
    throw "qemu-img info failed with exit code $infoExitCode."
}
[pscustomobject]@{
    version = $Version
    qcow2 = (Resolve-Path -LiteralPath $qcowPath).Path
    sha512 = $actual
    vhdx = (Resolve-Path -LiteralPath $vhdxPath).Path
    qemu_img_info = ($info -join "`n")
} | ConvertTo-Json -Depth 3
