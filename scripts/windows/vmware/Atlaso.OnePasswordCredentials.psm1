<#
.SYNOPSIS
Provide the shared bounded Windows 1Password credential bridge for Atlaso.

.DESCRIPTION
Resolves the pinned Atlaso Environment selector, prepares the hash-locked SDK
runtime, and exchanges only current-user DPAPI ciphertext with credential
children. Plaintext remains confined to the bounded helper process.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force

<#
.SYNOPSIS
Resolve one deterministic credential-free HTTPS pip package-source pair.

.PARAMETER PipGlobalIndex
Optional pip `global.index` repository or API endpoint.

.PARAMETER PipGlobalIndexUrl
Optional pip `global.index-url` PEP 503 simple-index endpoint.
#>
function Resolve-AtlasoPipPackageSource {
    param(
        [AllowEmptyString()][string]$PipGlobalIndex = '',
        [AllowEmptyString()][string]$PipGlobalIndexUrl = ''
    )

    $hasIndex = -not [string]::IsNullOrWhiteSpace($PipGlobalIndex)
    $hasIndexUrl = -not [string]::IsNullOrWhiteSpace($PipGlobalIndexUrl)
    if ($hasIndex -xor $hasIndexUrl) {
        throw 'PipGlobalIndex and PipGlobalIndexUrl must be supplied together so Atlaso never fills a partial override from public PyPI.'
    }
    $resolvedIndex = if ($hasIndex) { $PipGlobalIndex } else { 'https://pypi.org/pypi' }
    $resolvedIndexUrl = if ($hasIndexUrl) { $PipGlobalIndexUrl } else { 'https://pypi.org/simple' }
    foreach ($source in @(
            [pscustomobject]@{ Name = 'PipGlobalIndex'; Value = $resolvedIndex },
            [pscustomobject]@{ Name = 'PipGlobalIndexUrl'; Value = $resolvedIndexUrl }
        )) {
        $candidate = [string]$source.Value
        $uri = $null
        if ($candidate.Length -gt 2048 -or $candidate -cne $candidate.Trim() -or
            $candidate -match '[\x00-\x20\x7f]' -or
            -not [uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -cne 'https' -or [string]::IsNullOrWhiteSpace($uri.Host) -or
            -not [string]::IsNullOrEmpty($uri.UserInfo) -or
            -not [string]::IsNullOrEmpty($uri.Query) -or
            -not [string]::IsNullOrEmpty($uri.Fragment)) {
            throw "$($source.Name) must be a credential-free absolute HTTPS URL without whitespace, user information, query, or fragment data."
        }
    }
    return [pscustomobject][ordered]@{
        PipGlobalIndex    = $resolvedIndex
        PipGlobalIndexUrl = $resolvedIndexUrl
        IsExplicit        = $hasIndex
    }
}

<#
.SYNOPSIS
Write the private pip configuration used by the isolated SDK download.

.PARAMETER Path
Task-private configuration path beneath the bounded bridge root.

.PARAMETER PipGlobalIndex
Resolved pip `global.index` value.

.PARAMETER PipGlobalIndexUrl
Resolved pip `global.index-url` value.
#>
function New-AtlasoOnePasswordPipConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$PipGlobalIndex,
        [Parameter(Mandatory = $true)][string]$PipGlobalIndexUrl
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($resolvedPath))
    try {
        [System.IO.File]::WriteAllLines(
            $resolvedPath,
            @(
                '[global]',
                "index = $PipGlobalIndex",
                "index-url = $PipGlobalIndexUrl",
                'disable-pip-version-check = true',
                'no-cache-dir = true'
            ),
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        throw 'The private 1Password dependency package-source configuration could not be prepared.'
    }
    return $resolvedPath
}

<#
.SYNOPSIS
Classify a failed 1Password dependency preparation without exposing child output.

.PARAMETER ExitCode
Nonzero exit code returned by the bounded dependency child.

.PARAMETER StandardOutput
Captured standard output inspected only through the bounded allowlist.

.PARAMETER StandardError
Captured standard error inspected only through the bounded allowlist.
#>
function Get-AtlasoOnePasswordDependencyFailure {
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [AllowEmptyString()][string]$StandardOutput = '',
        [AllowEmptyString()][string]$StandardError = ''
    )

    $combined = "$StandardError`n$StandardOutput"
    if ($combined.Length -gt 16384) {
        $combined = $combined.Substring(0, 8192) + "`n" + $combined.Substring($combined.Length - 8192)
    }
    $sample = [regex]::Replace($combined, '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ')
    $category = 'unclassified'
    $message = ''
    if ($sample -match 'hash(?:es)? (?:do not|does not) match|hash mismatch|package hashes|expected sha256|THESE PACKAGES DO NOT MATCH THE HASHES') {
        $category = 'hash_mismatch'
        $message = 'Downloaded dependency bytes did not match the checked-in hash lock. Verify mirror synchronization and the exact checkout; no dependency was installed.'
    }
    elseif ($sample -match 'connectionreset|connection refused|connection aborted|connection timed out|read timed out|max retries exceeded|proxyerror|proxy error|sslerror|certificate verify failed|tls|temporary failure in name resolution|name or service not known|network is unreachable|unable to fetch|could not fetch url|httpsconnectionpool') {
        $category = 'index_connectivity_tls_proxy'
        $message = 'The selected package source could not be reached because of an index, connectivity, TLS, or proxy failure. Verify host trust and proxy access to the configured pair; Atlaso did not try a public fallback.'
    }
    elseif ($sample -match 'no matching distribution found|could not find a version that satisfies|not a supported wheel|unsupported wheel|requires-python|incompatible (?:platform|python)') {
        $category = 'distribution_unavailable'
        $message = 'The selected package source does not offer a required binary distribution for standard Windows x64 CPython 3.14. Verify mirror completeness and retained platform wheels.'
    }
    elseif ($sample -match 'no module named pip|unknown option|unrecognized arguments|invalid choice|usage:|syntaxerror|modulenotfounderror|failed to create process|cannot start process') {
        $category = 'invocation_runtime'
        $message = 'The isolated pip invocation or Python runtime failed before dependency preparation. Verify the selected standard Windows x64 CPython 3.14 runtime and its bundled pip installation.'
    }
    else {
        $stdoutState = if ([string]::IsNullOrWhiteSpace($StandardOutput)) { 'absent' } else { 'present' }
        $stderrState = if ([string]::IsNullOrWhiteSpace($StandardError)) { 'absent' } else { 'present' }
        $message = "The dependency failure did not match an allowlisted diagnostic class (stdout $stdoutState; stderr $stderrState). Record only this sanitized message and exit code; do not share raw child streams."
    }
    return [pscustomobject][ordered]@{
        Category = $category
        Message  = "The hash-verified 1Password SDK wheel download failed with exit code $ExitCode. $message"
    }
}

<#
.SYNOPSIS
Resolve the exact Atlaso 1Password Environment ID without printing it.

.PARAMETER EnvironmentId
Optional explicit opaque Environment ID supplied by the operator.

.PARAMETER EnvironmentIdFile
Optional path to the single-line local Environment ID file.

.PARAMETER RepositoryRoot
Atlaso checkout root containing the default .atlaso-local configuration.

.PARAMETER ConsumerDescription
Sanitized workflow name used in actionable missing-selector guidance.
#>
function Resolve-AtlasoOnePasswordEnvironmentId {
    param(
        [string]$EnvironmentId = '',
        [string]$EnvironmentIdFile = '',
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [string]$ConsumerDescription = 'this Atlaso workflow'
    )

    if (-not [string]::IsNullOrWhiteSpace($EnvironmentId)) {
        return $EnvironmentId
    }
    $resolvedEnvironmentIdFile = $EnvironmentIdFile
    if ([string]::IsNullOrWhiteSpace($resolvedEnvironmentIdFile)) {
        $resolvedEnvironmentIdFile = Join-Path $RepositoryRoot '.atlaso-local\onepassword-environment-id'
    }
    if (-not (Test-Path -LiteralPath $resolvedEnvironmentIdFile -PathType Leaf)) {
        throw "OnePasswordEnvironmentId is required for $ConsumerDescription. Pass it explicitly or store it as the only line in .atlaso-local\onepassword-environment-id."
    }
    $environmentIdLines = [System.IO.File]::ReadAllLines($resolvedEnvironmentIdFile)
    if ($environmentIdLines.Count -ne 1 -or [string]::IsNullOrWhiteSpace($environmentIdLines[0])) {
        throw 'The local 1Password Environment ID file must contain exactly one non-empty line.'
    }
    return $environmentIdLines[0].Trim()
}

<#
.SYNOPSIS
Validate the opaque ID of the exact Atlaso 1Password Environment.

.PARAMETER EnvironmentId
Opaque ID copied from the exact Atlaso 1Password Environment.

.PARAMETER ExpectedEnvironmentIdSha256
Pinned SHA-256 identity of the exact Atlaso Environment. The override exists
only so focused tests can exercise the guard without publishing the real ID.
#>
function Assert-AtlasoOnePasswordEnvironmentId {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$EnvironmentId,
        [string]$ExpectedEnvironmentIdSha256 = 'FE14B62FB2D23460202299784CB1080B9E0FCF202ED5D75B4843202CD68BDF06'
    )

    if ($EnvironmentId -notmatch '^[A-Za-z0-9_-]{8,128}$') {
        throw 'OnePasswordEnvironmentId is required and must be the opaque ID of the exact Atlaso Environment.'
    }
    $environmentIdDigest = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($EnvironmentId)
    )
    try {
        $expectedEnvironmentIdDigest = [Convert]::FromHexString($ExpectedEnvironmentIdSha256)
    }
    catch {
        throw 'The pinned Atlaso 1Password Environment identity is invalid.'
    }
    if (-not [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
            $environmentIdDigest,
            $expectedEnvironmentIdDigest
        )) {
        throw 'OnePasswordEnvironmentId does not identify the exact Atlaso Environment.'
    }
}

<#
.SYNOPSIS
Validate the non-secret 1Password account selector used by desktop authorization.

.PARAMETER Account
1Password account name or ID.
#>
function Assert-AtlasoOnePasswordAccount {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Account)

    if ([string]::IsNullOrWhiteSpace($Account) -or $Account.Length -gt 255 -or $Account -match '[\x00-\x1f\x7f]') {
        throw 'OnePasswordAccount is required and must be a bounded 1Password account name or ID.'
    }
}

<#
.SYNOPSIS
Select one bounded account ID from the 1Password CLI inventory.

.PARAMETER AccountOutput
JSON returned by the bounded 1Password CLI account inventory.
#>
function ConvertFrom-AtlasoOnePasswordAccountInventory {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$AccountOutput)

    try {
        $accounts = @($AccountOutput | ConvertFrom-Json)
    }
    catch {
        throw 'The 1Password account inventory is unavailable. Sign in to 1Password CLI or pass -OnePasswordAccount explicitly.'
    }
    if ($accounts.Count -ne 1) {
        throw 'Omitted Atlaso credentials require exactly one discoverable 1Password account. Pass -OnePasswordAccount explicitly when zero or multiple accounts are configured.'
    }
    $resolvedAccount = [string]$accounts[0].account_uuid
    Assert-AtlasoOnePasswordAccount -Account $resolvedAccount
    return $resolvedAccount
}

<#
.SYNOPSIS
Resolve one installed 1Password CLI executable.

.PARAMETER CandidatePaths
Preferred exact executable paths, including the Environments-enabled install.

.PARAMETER PackageRoot
WinGet package root used only when command and shim discovery fail.

.PARAMETER CommandResolver
Command-discovery callback used by focused tests.
#>
function Resolve-AtlasoOnePasswordCliPath {
    param(
        [string[]]$CandidatePaths = @(
            (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) '1Password CLI\op.exe'),
            (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\WinGet\Links\op.exe')
        ),
        [string]$PackageRoot = (
            Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\WinGet\Packages'
        ),
        [scriptblock]$CommandResolver = {
            param($Name)
            Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue
        }
    )

    foreach ($candidate in $CandidatePaths) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $command = & $CommandResolver 'op.exe'
    if (-not $command) {
        $command = & $CommandResolver 'op'
    }
    if ($command) {
        return $command.Source
    }
    if ($PackageRoot -and (Test-Path -LiteralPath $PackageRoot -PathType Container)) {
        $packageCandidates = @(Get-ChildItem -LiteralPath $PackageRoot -Directory |
            Where-Object { $_.Name -like 'AgileBits.1Password.CLI_*' } |
            ForEach-Object { Join-Path $_.FullName 'op.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
        if ($packageCandidates.Count -eq 1) {
            return (Resolve-Path -LiteralPath $packageCandidates[0]).Path
        }
        if ($packageCandidates.Count -gt 1) {
            throw 'Multiple 1Password CLI package executables were found; repair WinGet links or pass -OnePasswordAccount explicitly.'
        }
    }
    throw 'Omitted Atlaso credentials require one discoverable 1Password account. Install 1Password CLI or pass -OnePasswordAccount explicitly.'
}

<#
.SYNOPSIS
Resolve the 1Password account used by desktop SDK authorization.

.PARAMETER Account
Optional explicit 1Password account name or ID.

.PARAMETER TimeoutSeconds
Positive deadline for the bounded account inventory.

.PARAMETER CliPath
Optional exact CLI path already verified by the caller.
#>
function Resolve-AtlasoOnePasswordAccount {
    param(
        [AllowEmptyString()][string]$Account = '',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$CliPath = ''
    )

    if (-not [string]::IsNullOrWhiteSpace($Account)) {
        Assert-AtlasoOnePasswordAccount -Account $Account
        return $Account
    }

    $opPath = if ([string]::IsNullOrWhiteSpace($CliPath)) {
        Resolve-AtlasoOnePasswordCliPath
    }
    elseif (Test-Path -LiteralPath $CliPath -PathType Leaf) {
        (Resolve-Path -LiteralPath $CliPath).Path
    }
    else {
        throw 'The resolved 1Password CLI path is unavailable; repair the installation or pass -OnePasswordAccount explicitly.'
    }

    try {
        $accountOutput = Invoke-AtlasoBoundedProcess `
            -FilePath $opPath `
            -ArgumentList @('account', 'list', '--format', 'json') `
            -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30)) `
            -Action 'The bounded 1Password account inventory'
    }
    catch {
        throw 'The 1Password account inventory is unavailable. Sign in to 1Password CLI or pass -OnePasswordAccount explicitly.'
    }
    return ConvertFrom-AtlasoOnePasswordAccountInventory -AccountOutput $accountOutput
}

<#
.SYNOPSIS
Select the highest compatible registered Python runtime.

.PARAMETER LauncherOutput
Text returned by the bounded Windows Python launcher inventory.

.PARAMETER TimeoutSeconds
Positive deadline for an architecture probe when launcher metadata omits it.

.PARAMETER ArchitectureResolver
Optional architecture-probe callback used by focused tests.

.PARAMETER AllCandidates
Return every metadata-compatible candidate in rank order so the caller can
perform the complete runtime probe and continue after an incompatible entry.
#>
function Select-AtlasoOnePasswordPythonFromLauncherInventory {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$LauncherOutput,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 30,
        [scriptblock]$ArchitectureResolver,
        [switch]$AllCandidates
    )

    $launcherPatterns = @(
        ('^\s*-V:(?:[^/]+/)?CPython(?<Version>3\.14(?:\.\d+)?)' +
        '(?:(?:-(?<Architecture>32|64|arm64))|(?:\[-(?<Architecture>32|64|arm64)\]))?' +
        '\s+\*?\s*(?<Path>.+?\.exe)\s*\*?\s*$'),
        ('^\s*-V:(?<Version>3\.14(?:\.\d+)?)' +
        '(?:(?:-(?<Architecture>32|64|arm64))|(?:\[-(?<Architecture>32|64|arm64)\]))?' +
        '\s+\*?\s*(?<Path>.+?\.exe)\s*\*?\s*$'),
        ('^\s*-(?<Version>3\.14)' +
        '(?:(?:-(?<Architecture>32|64|arm64))|(?:\[-(?<Architecture>32|64|arm64)\]))?' +
        '\s+\*?\s*(?<Path>.+?\.exe)\s*\*?\s*$')
    )
    $candidates = foreach ($line in @($LauncherOutput -split "`r?`n")) {
        $versionText = ''
        $architecture = ''
        $executablePath = ''
        foreach ($launcherPattern in $launcherPatterns) {
            if ($line -match $launcherPattern) {
                $versionText = $Matches['Version']
                $architecture = $Matches['Architecture']
                $executablePath = $Matches['Path']
                break
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($executablePath)) {
            [pscustomobject]@{
                Version      = [version]$versionText
                Architecture = ([string]$architecture).ToLowerInvariant()
                Path         = $executablePath.Trim()
            }
        }
    }
    $rankedCandidates = @($candidates |
        Where-Object { Test-Path -LiteralPath $_.Path -PathType Leaf } |
        Sort-Object -Property @{ Expression = 'Version'; Descending = $true }, @{ Expression = 'Path'; Descending = $false })
    $compatibleCandidates = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in $rankedCandidates) {
        # The temporary compatibility artifact is intentionally narrower than
        # upstream: only ordinary Windows x64 CPython 3.14 is approved.
        if (-not [string]::IsNullOrWhiteSpace($candidate.Architecture) -and
            $candidate.Architecture -cne '64') {
            continue
        }
        if ([string]::IsNullOrWhiteSpace($candidate.Architecture)) {
            try {
                $pointerWidth = if ($ArchitectureResolver) {
                    & $ArchitectureResolver $candidate.Path $TimeoutSeconds
                }
                else {
                    Invoke-AtlasoBoundedProcess `
                        -FilePath $candidate.Path `
                        -ArgumentList @('-I', '-S', '-c', 'import struct; print(struct.calcsize("P") * 8)') `
                        -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30)) `
                        -Action 'The registered Python architecture probe'
                }
            }
            catch {
                # An incompatible runtime is safe to skip only after its probe
                # process and redirected streams are proven inactive. Preserve
                # the bounded-process fail-closed signal across selection.
                if ($_.Exception.Data['AtlasoProcessTreeTerminationUnproven']) {
                    throw
                }
                continue
            }
            if (([string]$pointerWidth).Trim() -cne '64') {
                continue
            }
        }
        if (-not $AllCandidates) {
            return @($candidate)
        }
        $compatibleCandidates.Add($candidate)
    }
    return @($compatibleCandidates)
}

<#
.SYNOPSIS
Run the complete isolated 1Password SDK Python compatibility probe.

.PARAMETER PythonCommand
Exact candidate Python executable.

.PARAMETER TimeoutSeconds
Positive deadline for the bounded runtime probe.
#>
function Get-AtlasoOnePasswordRuntimeProbe {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    return (Invoke-AtlasoBoundedProcess `
            -FilePath $PythonCommand `
            -ArgumentList @(
                '-I', '-S', '-c',
                ('import json,platform,struct,sys,sysconfig; print(json.dumps({' +
                '"implementation":platform.python_implementation(),' +
                '"version":f"{sys.version_info.major}.{sys.version_info.minor}",' +
                '"bits":struct.calcsize("P")*8,"machine":platform.machine().lower(),' +
                '"gil_disabled":bool(sysconfig.get_config_var("Py_GIL_DISABLED"))}))')
            ) `
            -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30)) `
            -Action 'The 1Password SDK Python runtime probe').Trim()
}

<#
.SYNOPSIS
Validate the isolated CPython runtime probe result.

.PARAMETER RuntimeJson
JSON emitted by the bounded implementation, version, architecture, and GIL probe.

.PARAMETER ConsumerDescription
Sanitized workflow name used in unsupported-runtime guidance.
#>
function Assert-AtlasoOnePasswordRuntimeProbe {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RuntimeJson,
        [string]$ConsumerDescription = 'Atlaso credentials'
    )

    try {
        $runtime = $RuntimeJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "$ConsumerDescription could not validate the selected CPython runtime."
    }
    if ($runtime.implementation -cne 'CPython' -or $runtime.version -cne '3.14' -or
        [int]$runtime.bits -ne 64 -or $runtime.machine -notin @('amd64', 'x86_64') -or
        [bool]$runtime.gil_disabled) {
        throw "$ConsumerDescription requires standard GIL-enabled Windows x64 CPython 3.14; x86, ARM64, Python 3.10 through 3.13, and free-threaded 3.14t are unsupported."
    }
}

<#
.SYNOPSIS
Resolve a Python runtime supported by the 1Password SDK Windows wheel.

.PARAMETER PythonCommand
Explicit standard Windows x64 CPython 3.14 executable or command.

.PARAMETER TimeoutSeconds
Positive deadline for the version probe.

.PARAMETER ConsumerDescription
Sanitized workflow name used in unsupported-runtime guidance.
#>
function Resolve-AtlasoOnePasswordPython {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$PythonCommand,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$ConsumerDescription = 'Atlaso credentials'
    )

    $resolvedCommand = ''
    if ([string]::IsNullOrWhiteSpace($PythonCommand)) {
        $launcherCommand = Get-Command -Name 'py' -CommandType Application -ErrorAction SilentlyContinue
        $systemLauncherPath = Join-Path $env:WINDIR 'py.exe'
        $launcherPath = if ($launcherCommand) {
            $launcherCommand.Source
        }
        elseif (Test-Path -LiteralPath $systemLauncherPath -PathType Leaf) {
            $systemLauncherPath
        }
        else { '' }
        if ([string]::IsNullOrWhiteSpace($launcherPath)) {
            throw "$ConsumerDescription requires a Windows-registered standard x64 CPython 3.14 runtime or an explicit -OnePasswordPython path."
        }
        try {
            $launcherOutput = Invoke-AtlasoBoundedProcess `
                -FilePath $launcherPath `
                -ArgumentList @('-0p') `
                -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30)) `
                -Action 'The registered Python runtime inventory'
        }
        catch {
            throw "$ConsumerDescription could not inventory Windows-registered Python runtimes; pass -OnePasswordPython explicitly."
        }
        $selectedCandidates = @(Select-AtlasoOnePasswordPythonFromLauncherInventory `
                -LauncherOutput $launcherOutput `
                -TimeoutSeconds $TimeoutSeconds `
                -AllCandidates)
        foreach ($candidate in $selectedCandidates) {
            try {
                $candidateRuntimeJson = Get-AtlasoOnePasswordRuntimeProbe `
                    -PythonCommand $candidate.Path `
                    -TimeoutSeconds $TimeoutSeconds
                Assert-AtlasoOnePasswordRuntimeProbe `
                    -RuntimeJson $candidateRuntimeJson `
                    -ConsumerDescription $ConsumerDescription
                $resolvedCommand = $candidate.Path
                break
            }
            catch {
                # Do not probe another registration while the prior runtime
                # probe may still be active or own redirected streams.
                if ($_.Exception.Data['AtlasoProcessTreeTerminationUnproven']) {
                    throw
                }
                continue
            }
        }
        if ([string]::IsNullOrWhiteSpace($resolvedCommand)) {
            throw "$ConsumerDescription requires a Windows-registered standard x64 CPython 3.14 runtime or an explicit -OnePasswordPython path."
        }
    }
    else {
        $command = Get-Command -Name $PythonCommand -CommandType Application -ErrorAction SilentlyContinue
        if (-not $command) {
            throw "The 1Password SDK Python executable was not found: $PythonCommand."
        }
        $resolvedCommand = $command.Source
    }
    if (-not [string]::IsNullOrWhiteSpace($PythonCommand)) {
        $runtimeJson = Get-AtlasoOnePasswordRuntimeProbe `
            -PythonCommand $resolvedCommand `
            -TimeoutSeconds $TimeoutSeconds
        Assert-AtlasoOnePasswordRuntimeProbe `
            -RuntimeJson $runtimeJson `
            -ConsumerDescription $ConsumerDescription
    }
    return $resolvedCommand
}

<#
.SYNOPSIS
Download the exact approved temporary CPython 3.14 1Password wheel.

.PARAMETER PythonCommand
Approved standard Windows x64 CPython 3.14 executable.

.PARAMETER RepositoryRoot
Atlaso checkout containing the immutable artifact manifest.

.PARAMETER Destination
Private wheel directory receiving the verified release asset.

.PARAMETER TimeoutSeconds
Positive network deadline for the bounded download.
#>
function Save-AtlasoOnePasswordWheel {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $manifestPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\onepassword-sdk-cp314-wheel.json'
    $downloaderPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\download-onepassword-wheel.py'
    foreach ($requiredPath in @($manifestPath, $downloaderPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "The approved 1Password wheel input is unavailable: $requiredPath."
        }
    }
    $output = Invoke-AtlasoBoundedProcess `
        -FilePath $PythonCommand `
        -ArgumentList @(
            '-I', '-S', $downloaderPath,
            '--manifest', $manifestPath,
            '--destination', $Destination,
            '--timeout-seconds', [string]([Math]::Min($TimeoutSeconds, 120)),
            '--max-size-bytes', [string](10 * 1024 * 1024)
        ) `
        -TimeoutSeconds ([Math]::Min($TimeoutSeconds + 5, 125)) `
        -Action 'The approved 1Password compatibility wheel download'
    $wheelPath = ([string]$output).Trim()
    if (-not (Test-Path -LiteralPath $wheelPath -PathType Leaf) -or
        [System.IO.Path]::GetFileName($wheelPath) -cne 'onepassword_sdk-0.4.1-cp314-cp314-win_amd64.whl') {
        throw 'The approved 1Password compatibility wheel download did not produce the exact expected asset.'
    }
    return $wheelPath
}

<#
.SYNOPSIS
Create a startup-hook-free pip command inside a private virtual environment.

.PARAMETER PythonCommand
Approved standard Windows x64 CPython 3.14 executable.

.PARAMETER RuntimeRoot
Private task-specific directory that receives the isolated pip environment.

.PARAMETER TimeoutSeconds
Positive deadline for virtual-environment creation.
#>
function New-AtlasoIsolatedPipRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $resolvedRoot = [System.IO.Path]::GetFullPath($RuntimeRoot)
    Invoke-AtlasoBoundedProcess `
        -FilePath $PythonCommand `
        -ArgumentList @('-I', '-S', '-m', 'venv', '--clear', $resolvedRoot) `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The startup-hook-free pip environment creation' | Out-Null
    $runtimePython = Join-Path $resolvedRoot 'Scripts\python.exe'
    $sitePackages = Join-Path $resolvedRoot 'Lib\site-packages'
    $pipMain = Join-Path $sitePackages 'pip\__main__.py'
    if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf) -or
        -not (Test-Path -LiteralPath $pipMain -PathType Leaf)) {
        throw 'The startup-hook-free pip environment is incomplete.'
    }
    $pipBootstrap = 'import runpy,sys;site_packages=sys.argv.pop(1);sys.path.insert(0,site_packages);sys.argv[0]="pip";runpy.run_module("pip",run_name="__main__")'
    return [pscustomobject]@{
        PythonCommand   = $runtimePython
        ArgumentsPrefix = @('-I', '-S', '-c', $pipBootstrap, $sitePackages)
    }
}

<#
.SYNOPSIS
Create the hash-locked index-download input without the preverified 1Password SDK wheel.

.PARAMETER LockPath
Canonical deployment lock containing exactly one onepassword-sdk 0.4.1 requirement.

.PARAMETER DestinationPath
Private task-specific path that receives the remaining index-download requirements.
#>
function New-AtlasoOnePasswordIndexLock {
    param(
        [Parameter(Mandatory = $true)][string]$LockPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) {
        throw "The vetted 1Password deployment lock is unavailable: $LockPath."
    }
    $lines = [System.IO.File]::ReadAllLines([System.IO.Path]::GetFullPath($LockPath))
    $requirementIndexes = @(
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -cmatch '^onepassword-sdk==0\.4\.1\s+\\\s*$') {
                $index
            }
        }
    )
    if ($requirementIndexes.Count -ne 1) {
        throw 'The vetted deployment lock must contain exactly one onepassword-sdk==0.4.1 requirement.'
    }

    $startIndex = [int]$requirementIndexes[0]
    $endIndex = $startIndex
    $sawHash = $false
    while ($endIndex -lt $lines.Count) {
        if ($lines[$endIndex] -cmatch '^\s+--hash=sha256:[0-9a-f]{64}(?:\s+\\)?\s*$') {
            $sawHash = $true
        }
        if ($lines[$endIndex] -cnotmatch '\\\s*$') {
            break
        }
        $endIndex++
    }
    if (-not $sawHash -or $endIndex -ge $lines.Count) {
        throw 'The onepassword-sdk requirement in the vetted deployment lock is malformed.'
    }
    if (($endIndex + 1) -lt $lines.Count -and $lines[$endIndex + 1] -cmatch '^\s+# via ') {
        $endIndex++
    }

    $remainingLines = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($index -lt $startIndex -or $index -gt $endIndex) {
            $remainingLines.Add($lines[$index])
        }
    }
    $resolvedDestination = [System.IO.Path]::GetFullPath($DestinationPath)
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($resolvedDestination))
    [System.IO.File]::WriteAllLines(
        $resolvedDestination,
        $remainingLines,
        [System.Text.UTF8Encoding]::new($false)
    )
    return $resolvedDestination
}

<#
.SYNOPSIS
Prepare the isolated hash-locked 1Password SDK runtime.

.PARAMETER PythonCommand
Approved standard Windows x64 CPython 3.14 executable.

.PARAMETER RepositoryRoot
Atlaso checkout containing requirements-onepassword-deploy.lock.

.PARAMETER BridgeRoot
Private task-specific temporary root for wheels and installed dependencies.

.PARAMETER PipGlobalIndex
Resolved pip `global.index` value shared with the Photon guest build.

.PARAMETER PipGlobalIndexUrl
Resolved pip `global.index-url` value shared with the Photon guest build.

.PARAMETER TimeoutSeconds
Positive deadline for each dependency operation.
#>
function Initialize-AtlasoOnePasswordSdkRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$BridgeRoot,
        [string]$PipGlobalIndex = 'https://pypi.org/pypi',
        [string]$PipGlobalIndexUrl = 'https://pypi.org/simple',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $lockPath = Join-Path $RepositoryRoot 'requirements-onepassword-deploy.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw "The vetted 1Password deployment lock is unavailable: $lockPath."
    }
    $wheelDirectory = Join-Path $BridgeRoot 'wheels'
    $dependencyDirectory = Join-Path $BridgeRoot 'python-dependencies'
    $pipRuntimeRoot = Join-Path $BridgeRoot 'pip-runtime'
    $indexLockPath = Join-Path $BridgeRoot 'requirements-onepassword-index.lock'
    $pipConfigurationPath = Join-Path $BridgeRoot 'pip.ini'
    [void][System.IO.Directory]::CreateDirectory($wheelDirectory)
    [void][System.IO.Directory]::CreateDirectory($dependencyDirectory)

    Save-AtlasoOnePasswordWheel `
        -PythonCommand $PythonCommand `
        -RepositoryRoot $RepositoryRoot `
        -Destination $wheelDirectory `
        -TimeoutSeconds $TimeoutSeconds | Out-Null
    New-AtlasoOnePasswordIndexLock `
        -LockPath $lockPath `
        -DestinationPath $indexLockPath | Out-Null
    $pipRuntime = New-AtlasoIsolatedPipRuntime `
        -PythonCommand $PythonCommand `
        -RuntimeRoot $pipRuntimeRoot `
        -TimeoutSeconds $TimeoutSeconds
    $null = New-AtlasoOnePasswordPipConfiguration `
        -Path $pipConfigurationPath `
        -PipGlobalIndex $PipGlobalIndex `
        -PipGlobalIndexUrl $PipGlobalIndexUrl

    # Download is the only index-enabled step. Installation is deliberately
    # offline from the exact hash-verified wheel set, matching deploy-wheel.ps1.
    $downloadResult = Invoke-AtlasoBoundedProcess `
        -FilePath $pipRuntime.PythonCommand `
        -ArgumentList @(
            @($pipRuntime.ArgumentsPrefix)
            'download',
            '--disable-pip-version-check',
            '--find-links', $wheelDirectory,
            '--require-hashes',
            '--only-binary=:all:',
            '--dest', $wheelDirectory,
            '-r', $indexLockPath
        ) `
        -ClearEnvironmentVariablePrefixes @('PIP_') `
        -EnvironmentVariables @{
            PIP_CONFIG_FILE       = $pipConfigurationPath
            PIP_EXTRA_INDEX_URL   = ''
            PIP_NO_INPUT          = '1'
        } `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The hash-verified 1Password SDK wheel download' `
        -ReturnResult
    if ($downloadResult.ExitCode -ne 0) {
        $failure = Get-AtlasoOnePasswordDependencyFailure `
            -ExitCode $downloadResult.ExitCode `
            -StandardOutput $downloadResult.StandardOutput `
            -StandardError $downloadResult.StandardError
        throw $failure.Message
    }
    Invoke-AtlasoBoundedProcess `
        -FilePath $pipRuntime.PythonCommand `
        -ArgumentList @(
            @($pipRuntime.ArgumentsPrefix)
            'install',
            '--disable-pip-version-check',
            '--no-index',
            '--find-links', $wheelDirectory,
            '--require-hashes',
            '--target', $dependencyDirectory,
            '-r', $lockPath
        ) `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The isolated offline 1Password SDK runtime preparation' | Out-Null
    return $dependencyDirectory
}

<#
.SYNOPSIS
Translate a safe credential-bridge status code into actionable guidance.

.PARAMETER Code
Machine-readable status emitted by the bounded credential helper.

.PARAMETER ConsumerDescription
Sanitized workflow name used in the guidance.
#>
function Get-AtlasoOnePasswordCredentialBridgeError {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [string]$ConsumerDescription = 'Atlaso workflow'
    )

    $message = switch ($Code) {
        'sdk_configuration_missing' {
            "Omitted $ConsumerDescription credentials require OnePasswordAccount and OnePasswordPython for the supported 1Password SDK bridge."
        }
        'sdk_access_failed' {
            "1Password desktop authorization or exact Atlaso Environment access failed; no $ConsumerDescription mutation was attempted."
        }
        'admin_variable_invalid' {
            'The exact Atlaso 1Password Environment must contain exactly one concealed DEFAULT_ADMIN_PASSWORD variable.'
        }
        'root_variable_invalid' {
            'The exact Atlaso 1Password Environment must contain exactly one concealed DEFAULT_ROOT_PASSWORD variable.'
        }
        'admin_password_invalid' {
            'DEFAULT_ADMIN_PASSWORD or the explicit administrator password does not satisfy the Atlaso credential policy.'
        }
        'root_password_invalid' {
            'DEFAULT_ROOT_PASSWORD or the explicit root password does not satisfy the Atlaso credential policy.'
        }
        'sdk_runtime_invalid' {
            "The isolated 1Password SDK runtime could not be loaded; no $ConsumerDescription mutation was attempted."
        }
        'sdk_output_protection_failed' {
            'The bounded 1Password child could not protect its credential result with current-user DPAPI.'
        }
        'credential_ciphertext_invalid' {
            'The current-user DPAPI credential handoff could not be decrypted in the bounded validation child.'
        }
        default {
            "The bounded $ConsumerDescription credential bridge failed safely ($Code)."
        }
    }
    return $message
}

<#
.SYNOPSIS
Remove one exact task-created 1Password bridge root.

.PARAMETER BridgeRoot
Exact private temporary root created for the bounded credential bridge.

.PARAMETER ExpectedRootIdentity
Optional pinned filesystem identity required immediately before recursive deletion.
#>
function Remove-AtlasoOnePasswordCredentialBridge {
    param(
        [Parameter(Mandatory = $true)][string]$BridgeRoot,
        [string]$ExpectedRootIdentity = ''
    )

    $resolvedBridgeRoot = [System.IO.Path]::GetFullPath($BridgeRoot).TrimEnd('\')
    $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
    $bridgeName = [System.IO.Path]::GetFileName($resolvedBridgeRoot)
    if (
        -not $resolvedBridgeRoot.StartsWith(
            $resolvedTempRoot + '\',
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $bridgeName.StartsWith('atlaso-onepassword-credentials-', [System.StringComparison]::Ordinal)
    ) {
        throw "Refusing to remove an unrecognized credential bridge root: $resolvedBridgeRoot"
    }
    if (Test-Path -LiteralPath $resolvedBridgeRoot) {
        $bridgeItem = Get-Item -LiteralPath $resolvedBridgeRoot -Force
        if (($bridgeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to remove a reparse-point credential bridge root: $resolvedBridgeRoot"
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedRootIdentity) -and
            (Get-AtlasoPathIdentity `
                -Path $resolvedBridgeRoot `
                -Description '1Password credential bridge root') -cne $ExpectedRootIdentity) {
            throw 'The 1Password credential bridge root identity changed before deletion.'
        }
        [System.IO.Directory]::Delete($resolvedBridgeRoot, $true)
    }
    if (Test-Path -LiteralPath $resolvedBridgeRoot) {
        throw "Credential bridge cleanup did not remove the exact task-created root: $resolvedBridgeRoot"
    }
    # The checkout-local marker can reside on another volume, so first flush
    # deletion metadata through the bridge root's own parent directory.
    Sync-AtlasoDirectoryMetadata -DirectoryPath (Split-Path -Parent $resolvedBridgeRoot)
}

<#
.SYNOPSIS
Return the checkout-local durable credential-cleanup marker path.

.PARAMETER RepositoryRoot
Atlaso checkout owning the recovery marker.
#>
function Get-AtlasoOnePasswordCleanupMarkerPath {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    return Join-Path $RepositoryRoot '.atlaso-local\onepassword-credential-cleanup.json'
}

<#
.SYNOPSIS
Remove a proven-inactive credential root and durably retire its marker.

.PARAMETER MarkerPath
Exact non-secret cleanup marker path.

.PARAMETER Marker
Validated marker payload owning the exact bridge root.
#>
function Complete-AtlasoOnePasswordCredentialCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][object]$Marker
    )

    $markerProperties = @($Marker.PSObject.Properties.Name)
    $expectedRootIdentity = if ('RootIdentity' -in $markerProperties) {
        [string]$Marker.RootIdentity
    }
    else {
        ''
    }
    Remove-AtlasoOnePasswordCredentialBridge `
        -BridgeRoot ([string]$Marker.RootPath) `
        -ExpectedRootIdentity $expectedRootIdentity
    $Marker.Phase = 'root-absent'
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
    $Marker.Phase = 'retired'
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
    Remove-Item -LiteralPath $MarkerPath -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $MarkerPath) {
        throw 'The credential cleanup marker removal did not complete.'
    }
}

<#
.SYNOPSIS
Recover a retained 1Password bridge after proven process-tree inactivity.

.PARAMETER RepositoryRoot
Atlaso checkout owning the durable marker.
#>
function Invoke-AtlasoOnePasswordCredentialCleanupRecovery {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $markerPath = Get-AtlasoOnePasswordCleanupMarkerPath -RepositoryRoot $RepositoryRoot
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        return
    }
    try {
        $marker = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $properties = @($marker.PSObject.Properties.Name)
        $legacyMarker = $properties.Count -eq 4 -and
            'Schema' -in $properties -and
            'RootPath' -in $properties -and
            'BootIdentity' -in $properties -and
            'Phase' -in $properties -and
            $marker.Schema -eq 1
        $ownedMarker = $properties.Count -eq 11 -and
            'Schema' -in $properties -and
            'RootPath' -in $properties -and
            'BootIdentity' -in $properties -and
            'Phase' -in $properties -and
            'OwnerProcessId' -in $properties -and
            'OwnerProcessStartFileTimeUtc' -in $properties -and
            'ProcessJobName' -in $properties -and
            'ChildProcessId' -in $properties -and
            'ChildProcessStartFileTimeUtc' -in $properties -and
            'ProcessOwnershipPhase' -in $properties -and
            'RootIdentity' -in $properties -and
            $marker.Schema -eq 2
        if ((-not $legacyMarker -and -not $ownedMarker) -or
            $marker.Phase -notin @('active', 'root-absent', 'retired')) {
            throw 'Invalid credential cleanup marker.'
        }
        $resolvedRoot = [System.IO.Path]::GetFullPath([string]$marker.RootPath)
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $tempRootPrefix = $resolvedTempRoot.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith($tempRootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedRoot) -notmatch '^atlaso-onepassword-credentials-[0-9a-f]{32}$') {
            throw 'Invalid credential cleanup root.'
        }
        if ($marker.Phase -ceq 'active') {
            $bootIdentityState = Get-AtlasoWindowsBootIdentityState -BootIdentity $marker.BootIdentity
            if ($bootIdentityState -ceq 'invalid') {
                throw 'The retained credential marker has an invalid boot identity.'
            }
            if ($bootIdentityState -ceq 'current') {
                if (-not $ownedMarker) {
                    throw 'A Windows restart is required before retained legacy credential artifacts can be cleaned safely.'
                }
                Complete-AtlasoSameBootBoundedProcessRecovery `
                    -Marker $marker `
                    -JobNamePattern '^Local\\Atlaso-OnePassword-[0-9a-f]{32}$' `
                    -ProcessDescription '1Password credential bridge'
            }
        }
        Complete-AtlasoOnePasswordCredentialCleanup -MarkerPath $markerPath -Marker $marker
    }
    catch {
        throw 'A prior 1Password credential bridge has unresolved cleanup. Restart Windows, then rerun the workflow.'
    }
}

<#
.SYNOPSIS
Admit the pinned wheel before shared credential recovery or state creation.

.PARAMETER PythonCommand
Optional standard GIL-enabled Windows x64 CPython 3.14 executable.

.PARAMETER RepositoryRoot
Atlaso checkout containing the approved wheel manifest and downloader.

.PARAMETER TimeoutSeconds
Positive deadline for runtime selection and artifact download.

.PARAMETER ConsumerDescription
Sanitized workflow name used in unsupported-runtime guidance.
#>
function Confirm-AtlasoOnePasswordArtifact {
    param(
        [AllowEmptyString()][string]$PythonCommand = '',
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$ConsumerDescription = 'Atlaso credentials'
    )

    $resolvedPython = Resolve-AtlasoOnePasswordPython `
        -PythonCommand $PythonCommand `
        -TimeoutSeconds $TimeoutSeconds `
        -ConsumerDescription $ConsumerDescription
    $artifactRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "atlaso-onepassword-artifact-$([guid]::NewGuid().ToString('N'))"
    )
    [void][System.IO.Directory]::CreateDirectory($artifactRoot)
    try {
        $null = Save-AtlasoOnePasswordWheel `
            -PythonCommand $resolvedPython `
            -RepositoryRoot $RepositoryRoot `
            -Destination $artifactRoot `
            -TimeoutSeconds $TimeoutSeconds
        return $resolvedPython
    }
    finally {
        if (Test-Path -LiteralPath $artifactRoot) {
            [System.IO.Directory]::Delete($artifactRoot, $true)
        }
    }
}

<#
.SYNOPSIS
Return validated SecureStrings from explicit inputs or the exact Atlaso Environment.

.PARAMETER RepositoryRoot
Atlaso checkout containing the generated 1Password dependency lock.

.PARAMETER EnvironmentId
Opaque ID of the pinned Atlaso Environment when either value is omitted.

.PARAMETER OnePasswordAccount
Account name or ID used for desktop SDK authorization when a default is needed.

.PARAMETER OnePasswordPython
Standard Windows x64 CPython 3.14 executable used when a default is needed.

.PARAMETER OnePasswordCliPath
Optional exact CLI path already verified by a parent workflow.

.PARAMETER AdminPassword
Optional explicit administrator SecureString override.

.PARAMETER RootPassword
Optional explicit root SecureString override.

.PARAMETER PipGlobalIndex
Resolved pip `global.index` value for SDK dependency preparation.

.PARAMETER PipGlobalIndexUrl
Resolved pip `global.index-url` value for SDK dependency preparation.

.PARAMETER TimeoutSeconds
Positive deadline for dependency and credential children.

.PARAMETER ConsumerDescription
Sanitized workflow name used in errors and child diagnostics.
#>
function Get-AtlasoOnePasswordCredentialPair {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'OnePasswordAccount',
        Justification = 'Desktop authorization account identifier, not an account password.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'OnePasswordPython',
        Justification = 'Executable selector for the isolated SDK runtime, not a password.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'OnePasswordCliPath',
        Justification = 'Path to the approved 1Password CLI executable, not a password.'
    )]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [string]$EnvironmentId = '',
        [string]$OnePasswordAccount = '',
        [string]$OnePasswordPython = '',
        [string]$OnePasswordCliPath = '',
        [SecureString]$AdminPassword,
        [SecureString]$RootPassword,
        [string]$PipGlobalIndex = 'https://pypi.org/pypi',
        [string]$PipGlobalIndexUrl = 'https://pypi.org/simple',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$ConsumerDescription = 'Atlaso workflow'
    )

    if ($env:DEFAULT_ADMIN_PASSWORD -or $env:DEFAULT_ROOT_PASSWORD) {
        throw 'DEFAULT_ADMIN_PASSWORD and DEFAULT_ROOT_PASSWORD must not be supplied by the caller; use the exact Atlaso 1Password Environment bridge.'
    }
    if (-not (Get-Command Invoke-AtlasoBoundedProcess -ErrorAction SilentlyContinue)) {
        throw 'The bounded Atlaso process runner is unavailable.'
    }
    $needsDefaults = $null -eq $AdminPassword -or $null -eq $RootPassword
    $resolvedPython = ''
    if ($needsDefaults) {
        Assert-AtlasoOnePasswordEnvironmentId -EnvironmentId $EnvironmentId
        # The exported bridge remains fail-closed when called directly: admit
        # the exact artifact before prior-root recovery, marker creation, or
        # account inventory. Runtime setup verifies it again before install.
        $resolvedPython = Confirm-AtlasoOnePasswordArtifact `
            -PythonCommand $OnePasswordPython `
            -RepositoryRoot $RepositoryRoot `
            -TimeoutSeconds $TimeoutSeconds `
            -ConsumerDescription $ConsumerDescription
    }
    Invoke-AtlasoOnePasswordCredentialCleanupRecovery -RepositoryRoot $RepositoryRoot
    $bridgeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "atlaso-onepassword-credentials-$([guid]::NewGuid().ToString('N'))"
    )
    [void][System.IO.Directory]::CreateDirectory($bridgeRoot)
    $cleanupMarkerPath = Get-AtlasoOnePasswordCleanupMarkerPath -RepositoryRoot $RepositoryRoot
    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $cleanupMarkerPath))
    $controllerProcess = Get-Process -Id $PID -ErrorAction Stop
    $processJobName = 'Local\Atlaso-OnePassword-' + [guid]::NewGuid().ToString('N')
    $cleanupMarker = [ordered]@{
        Schema                       = 2
        RootPath                     = [System.IO.Path]::GetFullPath($bridgeRoot)
        RootIdentity                 = Get-AtlasoPathIdentity `
            -Path $bridgeRoot `
            -Description '1Password credential bridge root'
        BootIdentity                 = Get-AtlasoWindowsBootIdentity
        Phase                        = 'active'
        OwnerProcessId               = $PID
        OwnerProcessStartFileTimeUtc = $controllerProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
        ProcessJobName               = $processJobName
        ChildProcessId               = 0
        ChildProcessStartFileTimeUtc = 0
        ProcessOwnershipPhase        = 'prepared'
    }
    $controllerProcess.Dispose()
    Write-AtlasoDurableJsonFile -Path $cleanupMarkerPath -Payload $cleanupMarker
    $failure = $null
    $result = $null
    $processTreeTerminationUnproven = $false
    try {
        $requestPath = Join-Path $bridgeRoot 'request.json'
        $statusPath = Join-Path $bridgeRoot 'status.json'
        $credentialBundlePath = Join-Path $bridgeRoot 'credentials.dpapi.json'
        $request = [ordered]@{
            AdminPasswordCiphertext = if ($null -eq $AdminPassword) {
                ''
            }
            else {
                ConvertFrom-SecureString -SecureString $AdminPassword
            }
            RootPasswordCiphertext  = if ($null -eq $RootPassword) {
                ''
            }
            else {
                ConvertFrom-SecureString -SecureString $RootPassword
            }
        }
        [System.IO.File]::WriteAllText(
            $requestPath,
            ($request | ConvertTo-Json -Compress),
            [System.Text.UTF8Encoding]::new($false)
        )

        $dependencyPath = ''
        if ($needsDefaults) {
            $dependencyPath = Initialize-AtlasoOnePasswordSdkRuntime `
                -PythonCommand $resolvedPython `
                -RepositoryRoot $RepositoryRoot `
                -BridgeRoot $bridgeRoot `
                -PipGlobalIndex $PipGlobalIndex `
                -PipGlobalIndexUrl $PipGlobalIndexUrl `
                -TimeoutSeconds $TimeoutSeconds
            # Artifact admission must complete before any 1Password CLI or
            # desktop activity, including automatic account inventory.
            $resolvedAccount = Resolve-AtlasoOnePasswordAccount `
                -Account $OnePasswordAccount `
                -TimeoutSeconds $TimeoutSeconds `
                -CliPath $OnePasswordCliPath
        }

        $helperPath = Join-Path $PSScriptRoot 'Invoke-AtlasoOnePasswordCredentials.ps1'
        $arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $helperPath,
            '-RequestPath', $requestPath,
            '-StatusPath', $statusPath,
            '-CredentialBundlePath', $credentialBundlePath,
            '-TimeoutSeconds', "$TimeoutSeconds"
        )
        if ($needsDefaults) {
            $arguments += @(
                '-PythonCommand', $resolvedPython,
                '-DependencyPath', $dependencyPath,
                '-OnePasswordAccount', $resolvedAccount,
                '-EnvironmentId', $EnvironmentId
            )
        }
        $processOwnershipPublisher = {
            param($ProcessJob)

            $cleanupMarker['ChildProcessId'] = [int]$ProcessJob.RootProcess.Id
            $cleanupMarker['ChildProcessStartFileTimeUtc'] = `
                $ProcessJob.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
            $cleanupMarker['ProcessOwnershipPhase'] = 'assigned'
            Write-AtlasoDurableJsonFile -Path $cleanupMarkerPath -Payload $cleanupMarker -Replace
        }
        Invoke-AtlasoBoundedStreamingProcess `
            -FilePath (Get-Process -Id $PID).Path `
            -ArgumentList $arguments `
            -TimeoutSeconds $TimeoutSeconds `
            -Action "The bounded $ConsumerDescription credential preparation child" `
            -ProcessJobName $processJobName `
            -ProcessOwnershipPublisher $processOwnershipPublisher | Out-Null
        if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
            throw "The bounded $ConsumerDescription credential child returned no safe status."
        }
        $status = [System.IO.File]::ReadAllText($statusPath) | ConvertFrom-Json
        if (-not [bool]$status.Success) {
            throw (Get-AtlasoOnePasswordCredentialBridgeError `
                    -Code ([string]$status.Code) `
                    -ConsumerDescription $ConsumerDescription)
        }
        if (-not (Test-Path -LiteralPath $credentialBundlePath -PathType Leaf)) {
            throw "The bounded $ConsumerDescription credential child returned no protected bundle."
        }
        $bundle = [System.IO.File]::ReadAllText($credentialBundlePath) | ConvertFrom-Json
        $result = [pscustomobject]@{
            AdminPassword = ConvertTo-SecureString -String ([string]$bundle.AdminPasswordCiphertext)
            RootPassword  = ConvertTo-SecureString -String ([string]$bundle.RootPasswordCiphertext)
        }
    }
    catch {
        $failure = $_
        if ($_.Exception.Data['AtlasoProcessTreeTerminationUnproven']) {
            $processTreeTerminationUnproven = $true
        }
    }

    if (-not $processTreeTerminationUnproven) {
        try {
            Complete-AtlasoOnePasswordCredentialCleanup `
                -MarkerPath $cleanupMarkerPath `
                -Marker $cleanupMarker
        }
        catch {
            if ($failure) {
                throw "$($failure.Exception.Message) Credential bridge cleanup also failed: $($_.Exception.Message)"
            }
            throw
        }
    }
    else {
        throw 'The bounded credential process tree could not be proven inactive. Restart Windows, then rerun the workflow to complete sensitive cleanup.'
    }
    if ($failure) {
        throw $failure
    }
    return $result
}

Export-ModuleMember -Function @(
    'Resolve-AtlasoPipPackageSource',
    'Resolve-AtlasoOnePasswordEnvironmentId',
    'Assert-AtlasoOnePasswordEnvironmentId',
    'Assert-AtlasoOnePasswordAccount',
    'Resolve-AtlasoOnePasswordCliPath',
    'Resolve-AtlasoOnePasswordAccount',
    'Resolve-AtlasoOnePasswordPython',
    'Save-AtlasoOnePasswordWheel',
    'New-AtlasoIsolatedPipRuntime',
    'New-AtlasoOnePasswordIndexLock',
    'Initialize-AtlasoOnePasswordSdkRuntime',
    'Get-AtlasoOnePasswordCredentialBridgeError',
    'Remove-AtlasoOnePasswordCredentialBridge',
    'Get-AtlasoOnePasswordCredentialPair'
)
