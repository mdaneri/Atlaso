Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AtlasoWslBuildContract {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $path = Join-Path $RepositoryRoot 'image\inventory-linux\wsl-build-contract.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Atlaso WSL build contract was not found: $path"
    }
    try {
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    } catch {
        throw "Atlaso WSL build contract is invalid: $path"
    }
}

function Assert-AtlasoWslAvailable {
    $command = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'WSL is required for Atlaso image builds. Install WSL separately, then run the Atlaso distribution setup command; Atlaso will not enable Windows features or install WSL.'
    }

    $wslPath = $command.Source
    & $wslPath --list --quiet *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'WSL is installed but unavailable or incomplete. Repair WSL separately; Atlaso will not enable Windows features, elevate, reboot, or run wsl --install.'
    }
    return $wslPath
}

function Get-AtlasoWslDistributions {
    $wsl = Assert-AtlasoWslAvailable
    $names = @(& $wsl --list --quiet 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw 'WSL could not list installed distributions. Repair WSL separately, then retry.'
    }
    return @(
        $names |
            ForEach-Object { ([string]$_).Replace("`0", '').Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Test-AtlasoWslDistributionInstalled {
    param([Parameter(Mandatory = $true)][string]$Distribution)

    foreach ($name in @(Get-AtlasoWslDistributions)) {
        if ($name.Equals($Distribution, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-AtlasoWslDefaultDistribution {
    $wsl = Assert-AtlasoWslAvailable
    $lines = @(& $wsl --list --verbose 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw 'WSL could not determine the current default distribution. Atlaso will not import a distribution without preserving that setting.'
    }
    foreach ($line in $lines) {
        $text = ([string]$line).Replace("`0", '')
        if ($text -match '^\s*\*\s+(.+?)\s{2,}\S+') {
            return $Matches[1].Trim()
        }
    }
    return ''
}

function Invoke-AtlasoWslCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Distribution,
        [string]$User = '',
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    $wsl = Assert-AtlasoWslAvailable
    $wslArguments = @('--distribution', $Distribution)
    if (-not [string]::IsNullOrWhiteSpace($User)) {
        $wslArguments += @('--user', $User)
    }
    $wslArguments += '--exec'
    $wslArguments += $Arguments
    $output = (& $wsl @wslArguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        $detail = if ([string]::IsNullOrWhiteSpace($output)) { '' } else { "`n$output" }
        throw "$FailureMessage$detail"
    }
    return $output
}

function Get-AtlasoWslBuildUser {
    param(
        [Parameter(Mandatory = $true)]$Contract,
        [Parameter(Mandatory = $true)][string]$Distribution
    )

    if ($Distribution.Equals([string]$Contract.distribution_name, [System.StringComparison]::OrdinalIgnoreCase)) {
        return [string]$Contract.build_user
    }
    return ''
}

function Assert-AtlasoManagedWslContract {
    param(
        [Parameter(Mandatory = $true)]$Contract,
        [Parameter(Mandatory = $true)][string]$Distribution,
        [string]$User = ''
    )

    if (-not $Distribution.Equals([string]$Contract.distribution_name, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    $setupCommand = 'pwsh -File scripts/windows/common/Initialize-AtlasoBuildWslDistribution.ps1'
    $markerText = Invoke-AtlasoWslCapture `
        -Distribution $Distribution `
        -User $User `
        -Arguments @('cat', '/var/lib/atlaso-build/contract.json') `
        -FailureMessage "The requested Atlaso-Build distribution is not fully provisioned. Run: $setupCommand"
    try {
        $marker = $markerText | ConvertFrom-Json
    } catch {
        throw "The Atlaso-Build ownership marker is invalid. Export or recreate the distribution; Atlaso will not repair an unrecognized distribution automatically."
    }
    if ([string]$marker.base_sha256 -ne [string]$Contract.base.sha256) {
        throw 'Atlaso-Build uses a different pinned base image. Export anything needed, unregister it manually, and rerun the Atlaso distribution setup command.'
    }
    if ([string]$marker.contract_version -ne [string]$Contract.contract_version) {
        throw "Atlaso-Build does not match the current host dependency contract. Run: $setupCommand"
    }
    if ([string]$marker.build_user -ne [string]$Contract.build_user) {
        throw "Atlaso-Build has an incompatible build-user configuration. Run: $setupCommand"
    }
}

function Get-AtlasoWslCacheRoot {
    param(
        [Parameter(Mandatory = $true)]$Contract,
        [Parameter(Mandatory = $true)][string]$Distribution,
        [string]$User = ''
    )

    $commands = @($Contract.required_commands | ForEach-Object { [string]$_ })
    $probe = @'
set -eu
if [ "$(id -u)" -eq 0 ]; then
  echo "Buildroot must run as a non-root WSL user." >&2
  exit 21
fi
for command_name in $1; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required Buildroot host command: $command_name" >&2
    exit 22
  fi
done
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/atlaso/inventory-linux"
case "$cache_root" in
  *[[:space:]]*)
    echo "Atlaso Inventory Linux cache path contains whitespace: $cache_root" >&2
    exit 23
    ;;
esac
mkdir -p "$cache_root"
probe_dir="$cache_root/.atlaso-case-probe-$$"
mkdir "$probe_dir"
trap 'rm -rf "$probe_dir"' EXIT
: >"$probe_dir/case"
: >"$probe_dir/CASE"
probe_count="$(find "$probe_dir" -maxdepth 1 -type f | wc -l | tr -d ' ')"
if [ "$probe_count" != "2" ]; then
  echo "Atlaso Inventory Linux cache storage is not case-sensitive." >&2
  exit 24
fi
printf '%s' "$cache_root"
'@
    return Invoke-AtlasoWslCapture `
        -Distribution $Distribution `
        -User $User `
        -Arguments @('sh', '-c', $probe, 'atlaso-wsl-probe', ($commands -join ' ')) `
        -FailureMessage "WSL distribution '$Distribution' is not ready for Atlaso image builds. If it is stuck, run 'wsl --terminate $Distribution', then retry."
}

function Assert-AtlasoWslBuildEnvironment {
    param(
        [Parameter(Mandatory = $true)]$Contract,
        [Parameter(Mandatory = $true)][string]$Distribution
    )

    $installed = @(Get-AtlasoWslDistributions)
    if ($installed.Count -eq 0) {
        throw "WSL is available but no Linux distributions are installed. Provision Atlaso-Build explicitly with: pwsh -File scripts/windows/common/Initialize-AtlasoBuildWslDistribution.ps1"
    }
    $matchingDistribution = $installed | Where-Object {
        $_.Equals($Distribution, [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if (-not $matchingDistribution) {
        if ($Distribution.Equals([string]$Contract.distribution_name, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "WSL distribution '$Distribution' is not installed. Provision it explicitly with: pwsh -File scripts/windows/common/Initialize-AtlasoBuildWslDistribution.ps1"
        }
        throw "WSL distribution '$Distribution' is not installed. List installed distributions with 'wsl --list --verbose', then pass a compatible name or provision Atlaso-Build explicitly."
    }

    $user = Get-AtlasoWslBuildUser -Contract $Contract -Distribution $Distribution
    Assert-AtlasoManagedWslContract -Contract $Contract -Distribution $Distribution -User $user
    $cacheRoot = Get-AtlasoWslCacheRoot -Contract $Contract -Distribution $Distribution -User $user
    return [pscustomobject]@{
        User = $user
        CacheRoot = $cacheRoot
    }
}

Export-ModuleMember -Function @(
    'Assert-AtlasoWslAvailable',
    'Assert-AtlasoWslBuildEnvironment',
    'Get-AtlasoWslBuildContract',
    'Get-AtlasoWslBuildUser',
    'Get-AtlasoWslDefaultDistribution',
    'Get-AtlasoWslDistributions',
    'Invoke-AtlasoWslCapture',
    'Test-AtlasoWslDistributionInstalled'
)
