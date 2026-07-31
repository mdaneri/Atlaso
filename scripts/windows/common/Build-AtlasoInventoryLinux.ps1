[CmdletBinding()]
param(
    [string]$RepositoryRoot = '',
    [string]$WslDistribution = 'Atlaso-Build'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
}
if ([string]::IsNullOrWhiteSpace($WslDistribution)) {
    throw 'WslDistribution must name an installed WSL distribution.'
}

Import-Module (Join-Path $PSScriptRoot 'Atlaso.WslBuild.psm1') -Force
$contract = Get-AtlasoWslBuildContract -RepositoryRoot $RepositoryRoot
$environment = Assert-AtlasoWslBuildEnvironment -Contract $contract -Distribution $WslDistribution

$buildScript = Join-Path $RepositoryRoot 'image\inventory-linux\build.sh'
if (-not (Test-Path -LiteralPath $buildScript -PathType Leaf)) {
    throw "Atlaso Inventory Linux build script was not found: $buildScript"
}

$linuxScript = Invoke-AtlasoWslCapture `
    -Distribution $WslDistribution `
    -User $environment.User `
    -Arguments @('wslpath', '-a', ($buildScript -replace '\\', '/')) `
    -FailureMessage 'WSL could not resolve the Atlaso Inventory Linux build path.'
if ([string]::IsNullOrWhiteSpace($linuxScript)) {
    throw 'WSL could not resolve the Atlaso Inventory Linux build path.'
}
$linuxPath = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
$linuxCacheRoot = $environment.CacheRoot
$repositoryHash = [System.Security.Cryptography.SHA256]::HashData(
    [System.Text.Encoding]::UTF8.GetBytes($RepositoryRoot.ToLowerInvariant())
)
$repositoryKey = [System.Convert]::ToHexString($repositoryHash).Substring(0, 16).ToLowerInvariant()
$linuxBuildRoot = "$linuxCacheRoot/$repositoryKey"
$wsl = Assert-AtlasoWslAvailable
$wslArguments = @('--distribution', $WslDistribution)
if (-not [string]::IsNullOrWhiteSpace($environment.User)) {
    $wslArguments += @('--user', $environment.User)
}
$wslArguments += @('--exec', 'env')
$wslArguments += @(
    "PATH=$linuxPath",
    "ATLASO_INVENTORY_BUILD_ROOT=$linuxBuildRoot",
    'sh',
    '-c',
    'mkdir -p "$1"; exec flock --exclusive "$2" bash "$3"',
    'atlaso-inventory-build',
    $linuxCacheRoot,
    "$linuxBuildRoot.lock",
    $linuxScript
)
& $wsl @wslArguments
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
