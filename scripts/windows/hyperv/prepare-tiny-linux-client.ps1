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

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'image\hyperv\clients\alpine-cloud'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$qcowPath = Join-Path $OutputDirectory $ImageName
$checksumPath = Join-Path $OutputDirectory "$ImageName.sha512"
$vhdxPath = Join-Path $OutputDirectory $OutputVhdxName

if (-not (Get-Command qemu-img -ErrorAction SilentlyContinue)) {
    throw "qemu-img is required to convert Alpine QCOW2 to Hyper-V VHDX."
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
$actual = (Get-FileHash -Algorithm SHA512 -LiteralPath $qcowPath).Hash.ToUpperInvariant()
if ($expected -ne $actual) {
    throw "SHA512 mismatch for $qcowPath. Expected $expected, got $actual."
}
Write-Host "SHA512 verified: $ImageName"

if ((Test-Path -LiteralPath $vhdxPath) -and -not $Force) {
    Write-Host "VHDX already exists: $vhdxPath"
} else {
    if ((Test-Path -LiteralPath $vhdxPath) -and $Force) {
        Remove-Item -LiteralPath $vhdxPath -Force
    }
    if ($PSCmdlet.ShouldProcess($vhdxPath, 'Convert Alpine QCOW2 to dynamic VHDX')) {
        qemu-img convert -p -f qcow2 -O vhdx -o subformat=dynamic $qcowPath $vhdxPath
    }
}

$info = qemu-img info $vhdxPath
[pscustomobject]@{
    version = $Version
    qcow2 = (Resolve-Path -LiteralPath $qcowPath).Path
    sha512 = $actual
    vhdx = (Resolve-Path -LiteralPath $vhdxPath).Path
    qemu_img_info = ($info -join "`n")
} | ConvertTo-Json -Depth 3
