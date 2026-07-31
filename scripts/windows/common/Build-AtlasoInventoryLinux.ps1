[CmdletBinding()]
param(
    [string]$RepositoryRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
}
$buildScript = Join-Path $RepositoryRoot 'image\inventory-linux\build.sh'
if (-not (Test-Path -LiteralPath $buildScript -PathType Leaf)) {
    throw "Atlaso Inventory Linux build script was not found: $buildScript"
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL is required to build the bundled Atlaso Inventory Linux image.'
}

$linuxScript = (wsl.exe wslpath -a ($buildScript -replace '\\', '/')).Trim()
if ([string]::IsNullOrWhiteSpace($linuxScript)) {
    throw 'WSL could not resolve the Atlaso Inventory Linux build path.'
}
$linuxPath = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
$linuxCacheRoot = (wsl.exe --exec env "PATH=$linuxPath" sh -c 'printf "%s" "${XDG_CACHE_HOME:-$HOME/.cache}/atlaso/inventory-linux"').Trim()
if ([string]::IsNullOrWhiteSpace($linuxCacheRoot) -or $linuxCacheRoot -match '\s') {
    throw 'WSL could not resolve a whitespace-free Atlaso Inventory Linux cache path.'
}
$repositoryHash = [System.Security.Cryptography.SHA256]::HashData(
    [System.Text.Encoding]::UTF8.GetBytes($RepositoryRoot.ToLowerInvariant())
)
$repositoryKey = [System.Convert]::ToHexString($repositoryHash).Substring(0, 16).ToLowerInvariant()
$linuxBuildRoot = "$linuxCacheRoot/$repositoryKey"
wsl.exe --exec env `
    "PATH=$linuxPath" `
    "ATLASO_INVENTORY_BUILD_ROOT=$linuxBuildRoot" `
    sh -c 'mkdir -p "$1"; exec flock --exclusive "$2" bash "$3"' `
    atlaso-inventory-build $linuxCacheRoot "$linuxBuildRoot.lock" $linuxScript
if ($LASTEXITCODE -ne 0) {
    throw "Atlaso Inventory Linux build failed with exit code $LASTEXITCODE."
}

$outputDirectory = Join-Path $RepositoryRoot 'image\inventory-linux\output'
foreach ($name in @('bzImage', 'rootfs.cpio.gz', 'manifest.json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $outputDirectory $name) -PathType Leaf)) {
        throw "Atlaso Inventory Linux build did not produce $name."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $outputDirectory 'legal-info') -PathType Container)) {
    throw 'Atlaso Inventory Linux build did not produce Buildroot legal-info.'
}
