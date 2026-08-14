[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Version = '3.24.1',
    [string]$ImageName = 'generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2',
    [string]$BaseUrl = 'https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud',
    [string]$OutputDirectory = '',
    [string]$OutputVmdkName = 'atlaso-tiny-linux-client.vmdk',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

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

foreach ($file in @($ImageName, "$ImageName.sha512")) {
    $target = Join-Path $OutputDirectory $file
    if ((Test-Path -LiteralPath $target) -and -not $Force) {
        Write-Host "Already downloaded: $target"
        continue
    }
    if ($PSCmdlet.ShouldProcess($target, "Download $file")) {
        Invoke-WebRequest -Uri "$BaseUrl/$file" -OutFile $target
    }
}

$expected = (Get-Content -LiteralPath $checksumPath -Raw).Trim().Split()[0].ToUpperInvariant()
$actual = Get-Sha512FileHash -Path $qcowPath
if ($expected -ne $actual) {
    throw "SHA512 mismatch for $qcowPath. Expected $expected, got $actual."
}
Write-Host "SHA512 verified: $ImageName"

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

$info = qemu-img info $vmdkPath
$infoExitCode = $LASTEXITCODE
if ($infoExitCode -ne 0) {
    if ($convertedThisRun -and (Test-Path -LiteralPath $vmdkPath)) {
        try {
            Remove-Item -LiteralPath $vmdkPath -Force -ErrorAction Stop
        } catch {
            throw "qemu-img info failed with exit code $infoExitCode, and the unverified VMDK could not be removed: $($_.Exception.Message)"
        }
    }
    throw "qemu-img info failed with exit code $infoExitCode."
}
[pscustomobject]@{
    version       = $Version
    qcow2         = (Resolve-Path -LiteralPath $qcowPath).Path
    sha512        = $actual
    vmdk          = (Resolve-Path -LiteralPath $vmdkPath).Path
    qemu_img_info = ($info -join "`n")
} | ConvertTo-Json -Depth 3
