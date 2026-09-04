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

if (-not ('Atlaso.OnePasswordTokenFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Atlaso
{
    public static class OnePasswordTokenFileIdentity
    {
        private const uint FileReadAttributes = 0x80;
        private const uint FileShareRead = 0x1;
        private const uint FileShareWrite = 0x2;
        private const uint FileShareDelete = 0x4;
        private const uint OpenExisting = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information
        );

        public static uint GetLinkCount(string path)
        {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero
            ))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information.NumberOfLinks;
            }
        }
    }
}
'@
}

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

.PARAMETER LocalWheelDirectory
Private directory containing the admitted compatibility wheel.
#>
function New-AtlasoOnePasswordPipConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$PipGlobalIndex,
        [Parameter(Mandatory = $true)][string]$PipGlobalIndexUrl,
        [Parameter(Mandatory = $true)][string]$LocalWheelDirectory
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($resolvedPath))
    try {
        # PIP_CONFIG_FILE loads after system, user, and site files, but pip's
        # command section outranks its global section. Override every source
        # key in both scopes so an inherited extra index or find-links value
        # cannot survive the explicit pair.
        [System.IO.File]::WriteAllLines(
            $resolvedPath,
            @(
                '[global]',
                "index = $PipGlobalIndex",
                "index-url = $PipGlobalIndexUrl",
                "extra-index-url = $PipGlobalIndexUrl",
                "find-links = $LocalWheelDirectory",
                'no-index = false',
                'disable-pip-version-check = true',
                'no-cache-dir = true',
                '',
                '[download]',
                "index = $PipGlobalIndex",
                "index-url = $PipGlobalIndexUrl",
                "extra-index-url = $PipGlobalIndexUrl",
                "find-links = $LocalWheelDirectory",
                'no-index = false'
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
Validate a current-user DPAPI-protected 1Password service-account token file.

.PARAMETER Path
Exact local ciphertext file to validate without decrypting it in the caller.
#>
function Assert-AtlasoOnePasswordServiceAccountTokenFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows
        )) {
        throw 'The Atlaso 1Password service-account token file requires Windows current-user DPAPI.'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'The 1Password service-account token file is unavailable.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The 1Password service-account token file must not be a reparse point.'
    }
    if ([Atlaso.OnePasswordTokenFileIdentity]::GetLinkCount($item.FullName) -ne 1) {
        throw 'The 1Password service-account token file must have exactly one hard link.'
    }
    if ($item.Length -lt 32 -or $item.Length -gt 65536) {
        throw 'The 1Password service-account token file has an invalid ciphertext size.'
    }

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl = Get-Acl -LiteralPath $item.FullName
    try {
        $ownerSid = if ($acl.Owner -match '^S-1-') {
            [System.Security.Principal.SecurityIdentifier]::new($acl.Owner)
        }
        else {
            ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
                [System.Security.Principal.SecurityIdentifier]
            )
        }
    }
    catch {
        throw 'The 1Password service-account token file owner could not be verified.'
    }
    if (-not $ownerSid.Equals($currentSid) -or -not $acl.AreAccessRulesProtected) {
        throw 'The 1Password service-account token file must be owned by the current user with inherited access disabled.'
    }
    $rules = @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ))
    $currentUserCanRead = $false
    $systemCanRead = $false
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw 'The 1Password service-account token file contains an unsupported access-control rule.'
        }
        if (-not $rule.IdentityReference.Equals($currentSid) -and
            -not $rule.IdentityReference.Equals($systemSid)) {
            throw 'The 1Password service-account token file grants access outside the current user and SYSTEM.'
        }
        if ($rule.IdentityReference.Equals($currentSid) -and
            ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadData) -ne 0) {
            $currentUserCanRead = $true
        }
        if ($rule.IdentityReference.Equals($systemSid) -and
            ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadData) -ne 0) {
            $systemCanRead = $true
        }
    }
    if (-not $currentUserCanRead) {
        throw 'The current user cannot read the 1Password service-account token file.'
    }
    if (-not $systemCanRead) {
        throw 'SYSTEM cannot read the 1Password service-account token file.'
    }
    return $item.FullName
}

<#
.SYNOPSIS
Resolve the optional local DPAPI-protected service-account token file.

.PARAMETER TokenFile
Optional explicit ciphertext file. An explicit missing or unsafe file fails closed.

.PARAMETER RepositoryRoot
Atlaso checkout containing the default Git-ignored .atlaso-local path.
#>
function Resolve-AtlasoOnePasswordServiceAccountTokenFile {
    param(
        [AllowEmptyString()][string]$TokenFile = '',
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    $resolvedRepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)
    $atlasoLocalRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $resolvedRepositoryRoot '.atlaso-local')
    )
    $atlasoLocalPrefix = $atlasoLocalRoot.TrimEnd('\') + '\'
    $isExplicit = -not [string]::IsNullOrWhiteSpace($TokenFile)
    $candidate = if ($isExplicit) {
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TokenFile)
    }
    else {
        Join-Path $atlasoLocalRoot 'onepassword-service-account-token.dpapi'
    }
    $candidate = [System.IO.Path]::GetFullPath($candidate)
    if (-not $candidate.StartsWith(
            $atlasoLocalPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'The 1Password service-account token must be stored beneath this checkout''s .atlaso-local directory.'
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        if ($isExplicit) {
            throw 'The explicit 1Password service-account token file is unavailable.'
        }
        return ''
    }
    $ancestorPath = [System.IO.Path]::GetDirectoryName($candidate)
    while ($ancestorPath.Length -ge $atlasoLocalRoot.Length) {
        $ancestorItem = Get-Item -LiteralPath $ancestorPath -Force
        if (-not $ancestorItem.PSIsContainer -or
            ($ancestorItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The 1Password service-account token path must not traverse a reparse point.'
        }
        if ($ancestorPath.Equals($atlasoLocalRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $ancestorPath = [System.IO.Path]::GetDirectoryName($ancestorPath)
    }
    return Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $candidate
}

<#
.SYNOPSIS
Select service-account or desktop authorization without exposing credentials.

.PARAMETER RepositoryRoot
Atlaso checkout containing the default Git-ignored token-file location.

.PARAMETER ServiceAccountTokenFile
Optional explicit current-user DPAPI ciphertext file.

.PARAMETER Account
Optional desktop authorization account. An explicit token file has precedence.

.PARAMETER TimeoutSeconds
Positive deadline for legacy desktop account discovery.

.PARAMETER CliPath
Optional exact CLI path already verified by the caller.
#>
function Resolve-AtlasoOnePasswordAuthentication {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [AllowEmptyString()][string]$ServiceAccountTokenFile = '',
        [AllowEmptyString()][string]$Account = '',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [AllowEmptyString()][string]$CliPath = ''
    )

    if (-not [string]::IsNullOrWhiteSpace($ServiceAccountTokenFile)) {
        return [pscustomobject][ordered]@{
            Mode      = 'service-account'
            TokenFile = Resolve-AtlasoOnePasswordServiceAccountTokenFile `
                -TokenFile $ServiceAccountTokenFile `
                -RepositoryRoot $RepositoryRoot
            Account   = ''
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Account)) {
        return [pscustomobject][ordered]@{
            Mode      = 'desktop'
            TokenFile = ''
            Account   = Resolve-AtlasoOnePasswordAccount `
                -Account $Account `
                -TimeoutSeconds $TimeoutSeconds `
                -CliPath $CliPath
        }
    }
    $defaultTokenFile = Resolve-AtlasoOnePasswordServiceAccountTokenFile `
        -RepositoryRoot $RepositoryRoot
    if (-not [string]::IsNullOrWhiteSpace($defaultTokenFile)) {
        return [pscustomobject][ordered]@{
            Mode      = 'service-account'
            TokenFile = $defaultTokenFile
            Account   = ''
        }
    }
    return [pscustomobject][ordered]@{
        Mode      = 'desktop'
        TokenFile = ''
        Account   = Resolve-AtlasoOnePasswordAccount `
            -TimeoutSeconds $TimeoutSeconds `
            -CliPath $CliPath
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
        [AllowEmptyString()][string]$PipGlobalIndex = '',
        [AllowEmptyString()][string]$PipGlobalIndexUrl = '',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    # Revalidate at the exported network boundary so a direct caller cannot
    # combine one explicit value with the other field's public default.
    $validatedPackageSource = Resolve-AtlasoPipPackageSource `
        -PipGlobalIndex $PipGlobalIndex `
        -PipGlobalIndexUrl $PipGlobalIndexUrl
    $PipGlobalIndex = $validatedPackageSource.PipGlobalIndex
    $PipGlobalIndexUrl = $validatedPackageSource.PipGlobalIndexUrl
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
        -PipGlobalIndexUrl $PipGlobalIndexUrl `
        -LocalWheelDirectory $wheelDirectory

    # Download is the only index-enabled step. Installation is deliberately
    # offline from the exact hash-verified wheel set, matching deploy-wheel.ps1.
    Invoke-AtlasoBoundedProcess `
        -FilePath $pipRuntime.PythonCommand `
        -ArgumentList @(
            @($pipRuntime.ArgumentsPrefix)
            'download',
            '--disable-pip-version-check',
            '--require-hashes',
            '--only-binary=:all:',
            '--dest', $wheelDirectory,
            '-r', $indexLockPath
        ) `
        -ClearEnvironmentVariablePrefixes @('PIP_') `
        -EnvironmentVariables @{
            PIP_CONFIG_FILE       = $pipConfigurationPath
            PIP_NO_INPUT          = '1'
        } `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The hash-verified 1Password SDK wheel download' `
        -FailureClassification onepassword_dependency `
        -DiscardOutput
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
            "Omitted $ConsumerDescription credentials require a service-account token file or OnePasswordAccount, plus OnePasswordPython, for the supported 1Password SDK bridge."
        }
        'sdk_access_failed' {
            "1Password authorization or exact Atlaso Environment access failed; no $ConsumerDescription mutation was attempted."
        }
        'service_account_token_invalid' {
            "The current-user DPAPI 1Password service-account token could not be used; no $ConsumerDescription mutation was attempted."
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

.PARAMETER TemporaryRootPath
Optional creation-time temporary parent recorded for recovery in another shell.

.PARAMETER ExpectedTemporaryRootIdentity
Optional pinned filesystem identity for the creation-time temporary parent.
#>
function Remove-AtlasoOnePasswordCredentialBridge {
    param(
        [Parameter(Mandatory = $true)][string]$BridgeRoot,
        [string]$ExpectedRootIdentity = '',
        [string]$TemporaryRootPath = '',
        [string]$ExpectedTemporaryRootIdentity = ''
    )

    $resolvedBridgeRoot = [System.IO.Path]::GetFullPath($BridgeRoot).TrimEnd('\')
    $resolvedTempRoot = if ([string]::IsNullOrWhiteSpace($TemporaryRootPath)) {
        [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
    }
    else {
        [System.IO.Path]::GetFullPath($TemporaryRootPath).TrimEnd('\')
    }
    $bridgeName = [System.IO.Path]::GetFileName($resolvedBridgeRoot)
    if (
        -not ([System.IO.Path]::GetFullPath((Split-Path -Parent $resolvedBridgeRoot)).Equals(
                $resolvedTempRoot,
                [System.StringComparison]::OrdinalIgnoreCase
            )) -or
        $bridgeName -cnotmatch '^atlaso-onepassword-credentials-[0-9a-f]{32}$'
    ) {
        throw 'Refusing to remove an unrecognized 1Password credential bridge root.'
    }
    try {
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedTempRoot `
            -ChildPath $resolvedBridgeRoot `
            -FailureMessage 'Invalid 1Password credential bridge root ancestry'
    }
    catch {
        throw 'The 1Password credential bridge root ancestry is invalid or contains a reparse point.'
    }
    $bridgeItem = Get-AtlasoOptionalOnePasswordRecoveryItem `
        -Path $resolvedBridgeRoot `
        -FailureCode 'root-state-unavailable' `
        -FailureMessage 'The recorded credential bridge root state cannot be inspected safely.'
    if ($null -ne $bridgeItem) {
        if (($bridgeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing to remove a reparse-point 1Password credential bridge root.'
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedTemporaryRootIdentity) -and
            (Get-AtlasoPathIdentity `
                -Path $resolvedTempRoot `
                -Description '1Password credential bridge temporary root') -cne
            $ExpectedTemporaryRootIdentity) {
            throw 'The 1Password credential bridge temporary root identity changed before deletion.'
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
        throw 'Credential bridge cleanup did not remove the exact task-created root.'
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
Create a sanitized credential-recovery exception.

.PARAMETER Code
Stable non-secret recovery blocker code.

.PARAMETER Message
Operator-safe recovery guidance that contains no marker values or paths.
#>
function New-AtlasoOnePasswordRecoveryException {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $exception = [System.InvalidOperationException]::new($Message)
    $exception.Data['AtlasoOnePasswordRecoverySafe'] = $true
    $exception.Data['AtlasoOnePasswordRecoveryCode'] = $Code
    return $exception
}

<#
.SYNOPSIS
Read one optional filesystem item without hiding inspection failures.

.PARAMETER Path
Exact filesystem path to inspect.

.PARAMETER FailureCode
Stable non-secret recovery blocker code for a failed inspection.

.PARAMETER FailureMessage
Operator-safe recovery guidance for a failed inspection.

.PARAMETER ItemReader
Filesystem lookup operation overridden only by focused tests.
#>
function Get-AtlasoOptionalOnePasswordRecoveryItem {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$FailureCode,
        [Parameter(Mandatory = $true)][string]$FailureMessage,
        [scriptblock]$ItemReader = {
            param([string]$ItemPath)
            Get-Item -LiteralPath $ItemPath -Force -ErrorAction Stop
        }
    )

    try {
        return & $ItemReader $Path
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
    catch {
        throw (New-AtlasoOnePasswordRecoveryException `
                -Code $FailureCode `
                -Message $FailureMessage)
    }
}

<#
.SYNOPSIS
Flush the nearest existing parent and re-prove that a recovery path is absent.

.PARAMETER Path
Exact already-absent path whose directory-entry deletion must be durable.

.PARAMETER DirectorySynchronizer
Directory metadata flush operation overridden only by focused tests.
#>
function Sync-AtlasoOnePasswordAbsentPathMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [scriptblock]$DirectorySynchronizer = {
            param([string]$DirectoryPath)
            Sync-AtlasoDirectoryMetadata -DirectoryPath $DirectoryPath
        }
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $candidateParent = Split-Path -Parent $resolvedPath
    while (-not [string]::IsNullOrWhiteSpace($candidateParent)) {
        $parentItem = Get-AtlasoOptionalOnePasswordRecoveryItem `
            -Path $candidateParent `
            -FailureCode 'root-parent-state-unavailable' `
            -FailureMessage 'The credential bridge parent state cannot be inspected safely.'
        if ($null -ne $parentItem) {
            if (-not ($parentItem -is [System.IO.DirectoryInfo]) -or
                ($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'root-parent-invalid' `
                        -Message 'The nearest credential bridge parent is not an ordinary directory; state was preserved.')
            }
            $volumeRoot = [System.IO.Path]::GetPathRoot($candidateParent)
            if (-not $candidateParent.TrimEnd('\').Equals(
                    $volumeRoot.TrimEnd('\'),
                    [System.StringComparison]::OrdinalIgnoreCase
                )) {
                Assert-AtlasoStrictDescendantPath `
                    -ParentPath $volumeRoot `
                    -ChildPath $candidateParent `
                    -FailureMessage 'Invalid credential bridge parent ancestry'
            }
            & $DirectorySynchronizer $candidateParent
            $remainingPath = Get-AtlasoOptionalOnePasswordRecoveryItem `
                -Path $resolvedPath `
                -FailureCode 'root-state-unavailable' `
                -FailureMessage 'The recorded credential bridge root state cannot be inspected safely.'
            if ($null -ne $remainingPath) {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'root-reappeared-before-retirement' `
                        -Message 'The credential bridge root reappeared before durable retirement; state was preserved.')
            }
            return
        }
        $nextParent = Split-Path -Parent $candidateParent
        if ($nextParent -ceq $candidateParent) {
            break
        }
        $candidateParent = $nextParent
    }
    throw (New-AtlasoOnePasswordRecoveryException `
            -Code 'root-parent-unavailable' `
            -Message 'No existing credential bridge parent could be flushed; state was preserved.')
}

<#
.SYNOPSIS
Test whether a marker value is an integer inside an exact bound.

.PARAMETER Value
Value deserialized from the durable JSON marker.

.PARAMETER Minimum
Lowest integer the marker field may contain for the requested contract.

.PARAMETER Maximum
Highest integer the marker field may contain for the requested contract.
#>
function Test-AtlasoOnePasswordMarkerInteger {
    [OutputType([bool])]
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][long]$Minimum,
        [Parameter(Mandatory = $true)][long]$Maximum
    )

    if ($null -eq $Value -or -not (
            $Value -is [byte] -or $Value -is [sbyte] -or
            $Value -is [int16] -or $Value -is [uint16] -or
            $Value -is [int32] -or $Value -is [uint32] -or
            $Value -is [int64]
        )) {
        return $false
    }
    $number = [long]$Value
    return $number -ge $Minimum -and $number -le $Maximum
}

<#
.SYNOPSIS
Read and fully validate the current checkout's schema-2 or schema-3 recovery marker.

.PARAMETER RepositoryRoot
Exact Atlaso checkout that owns the fixed cleanup marker.

.PARAMETER RootItemReader
Recorded-root lookup operation overridden only by focused tests.
#>
function Get-AtlasoOnePasswordCredentialRecoveryContext {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [scriptblock]$RootItemReader = {
            param([string]$ItemPath)
            Get-Item -LiteralPath $ItemPath -Force -ErrorAction Stop
        }
    )

    try {
        $resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
        $markerPath = [System.IO.Path]::GetFullPath(
            (Get-AtlasoOnePasswordCleanupMarkerPath -RepositoryRoot $resolvedRepositoryRoot)
        )
        $markerItem = Get-AtlasoOptionalOnePasswordRecoveryItem `
            -Path $markerPath `
            -FailureCode 'marker-state-unavailable' `
            -FailureMessage 'The checkout-local credential cleanup marker state cannot be inspected safely.'
        if ($null -eq $markerItem) {
            return [pscustomobject][ordered]@{
                MarkerState            = 'absent'
                MarkerPath             = $markerPath
                Marker                 = $null
                MarkerIdentity         = ''
                MarkerDirectory        = Split-Path -Parent $markerPath
                MarkerDirectoryIdentity = ''
                Phase                  = 'none'
                BootRelation           = 'not-applicable'
                OwnerState             = 'not-recorded'
                ChildState             = 'not-recorded'
                JobState               = 'not-recorded'
                RootState              = 'not-recorded'
            }
        }
        if (-not ($markerItem -is [System.IO.FileInfo]) -or
            ($markerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $markerItem.Length -gt 65536) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'marker-invalid' `
                    -Message 'The checkout-local credential cleanup marker is not a bounded regular file.')
        }
        $markerDirectory = Split-Path -Parent $markerPath
        try {
            Assert-AtlasoStrictDescendantPath `
                -ParentPath $resolvedRepositoryRoot `
                -ChildPath $markerPath `
                -FailureMessage 'Invalid credential cleanup marker ancestry'
            $markerDirectoryIdentity = Get-AtlasoPathIdentity `
                -Path $markerDirectory `
                -Description 'Credential cleanup marker directory'
            $markerIdentity = Get-AtlasoPathIdentity `
                -Path $markerPath `
                -Description 'Credential cleanup marker'
        }
        catch {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'marker-ancestry-invalid' `
                    -Message 'The checkout-local credential cleanup marker ancestry is invalid or contains a reparse point.')
        }
        $jsonDocument = $null
        try {
            $rawMarker = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop
            $jsonDocument = [System.Text.Json.JsonDocument]::Parse($rawMarker)
            if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
                throw 'marker root is not an object'
            }
            $jsonPropertyNames = [System.Collections.Generic.List[string]]::new()
            $jsonPropertyEnumerator = $jsonDocument.RootElement.EnumerateObject()
            while ($jsonPropertyEnumerator.MoveNext()) {
                $jsonPropertyNames.Add($jsonPropertyEnumerator.Current.Name)
            }
            $marker = $rawMarker | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'marker-json-invalid' `
                    -Message 'The checkout-local credential cleanup marker is not valid bounded JSON.')
        }
        finally {
            if ($null -ne $jsonDocument) {
                $jsonDocument.Dispose()
            }
        }
        if (@($jsonPropertyNames | Sort-Object -Unique -CaseSensitive).Count -ne $jsonPropertyNames.Count) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'marker-schema-invalid' `
                    -Message 'The credential cleanup marker contains duplicate property names.')
        }
        $properties = @($marker.PSObject.Properties.Name)
        $legacyProperties = @('BootIdentity', 'Phase', 'RootPath', 'Schema')
        if ($properties.Count -eq $legacyProperties.Count -and
            -not (Compare-Object -ReferenceObject $legacyProperties -DifferenceObject $properties -CaseSensitive) -and
            (Test-AtlasoOnePasswordMarkerInteger -Value $marker.Schema -Minimum 1 -Maximum 1)) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'legacy-marker' `
                    -Message 'Legacy credential cleanup markers cannot be reset on the current boot. Restart Windows, then rerun the original VMware workflow so its compatibility recovery can retire the marker.')
        }
        $schema2Properties = @(
            'BootIdentity',
            'ChildProcessId',
            'ChildProcessStartFileTimeUtc',
            'OwnerProcessId',
            'OwnerProcessStartFileTimeUtc',
            'Phase',
            'ProcessJobName',
            'ProcessOwnershipPhase',
            'RootIdentity',
            'RootPath',
            'Schema'
        )
        $schema3Properties = @(
            $schema2Properties
            'TemporaryRootIdentity',
            'TemporaryRootPath'
        )
        $isSchema2 = $properties.Count -eq $schema2Properties.Count -and
            -not (Compare-Object -ReferenceObject $schema2Properties -DifferenceObject $properties -CaseSensitive) -and
            (Test-AtlasoOnePasswordMarkerInteger -Value $marker.Schema -Minimum 2 -Maximum 2)
        $isSchema3 = $properties.Count -eq $schema3Properties.Count -and
            -not (Compare-Object -ReferenceObject $schema3Properties -DifferenceObject $properties -CaseSensitive) -and
            (Test-AtlasoOnePasswordMarkerInteger -Value $marker.Schema -Minimum 3 -Maximum 3)
        if (-not $isSchema2 -and -not $isSchema3) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'marker-schema-invalid' `
                    -Message 'The credential cleanup marker does not match an exact supported schema-2 or schema-3 contract.')
        }
        $bootIdentityTicks = 0L
        $validBootIdentity = $marker.BootIdentity -is [string] -and
            [string]$marker.BootIdentity -cmatch '^[0-9]{1,19}$' -and
            [long]::TryParse(
                [string]$marker.BootIdentity,
                [System.Globalization.NumberStyles]::None,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref]$bootIdentityTicks
            ) -and $bootIdentityTicks -gt 0
        if (-not ($marker.RootPath -is [string]) -or [string]::IsNullOrWhiteSpace($marker.RootPath) -or
            -not ($marker.RootIdentity -is [string]) -or
            [string]$marker.RootIdentity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
            ($isSchema3 -and (
                -not ($marker.TemporaryRootPath -is [string]) -or
                [string]::IsNullOrWhiteSpace($marker.TemporaryRootPath) -or
                -not ($marker.TemporaryRootIdentity -is [string]) -or
                [string]$marker.TemporaryRootIdentity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$'
            )) -or
            -not $validBootIdentity -or
            -not ($marker.Phase -is [string]) -or [string]$marker.Phase -cnotin @('active', 'root-absent', 'retired') -or
            -not (Test-AtlasoOnePasswordMarkerInteger -Value $marker.OwnerProcessId -Minimum 1 -Maximum ([int]::MaxValue)) -or
            -not (Test-AtlasoOnePasswordMarkerInteger -Value $marker.OwnerProcessStartFileTimeUtc -Minimum 1 -Maximum ([long]::MaxValue)) -or
            -not ($marker.ProcessJobName -is [string]) -or
            [string]$marker.ProcessJobName -cnotmatch '^Local\\Atlaso-OnePassword-[0-9a-f]{32}$' -or
            -not ($marker.ProcessOwnershipPhase -is [string]) -or
            [string]$marker.ProcessOwnershipPhase -cnotin @('prepared', 'assigned')) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'marker-schema-invalid' `
                    -Message 'The credential cleanup marker does not match an exact supported schema-2 or schema-3 contract.')
        }
        $preparedOwnership = [string]$marker.ProcessOwnershipPhase -ceq 'prepared'
        if (($preparedOwnership -and (
                    -not (Test-AtlasoOnePasswordMarkerInteger -Value $marker.ChildProcessId -Minimum 0 -Maximum 0) -or
                    -not (Test-AtlasoOnePasswordMarkerInteger -Value $marker.ChildProcessStartFileTimeUtc -Minimum 0 -Maximum 0)
                )) -or
            (-not $preparedOwnership -and (
                    -not (Test-AtlasoOnePasswordMarkerInteger -Value $marker.ChildProcessId -Minimum 1 -Maximum ([int]::MaxValue)) -or
                    -not (Test-AtlasoOnePasswordMarkerInteger -Value $marker.ChildProcessStartFileTimeUtc -Minimum 1 -Maximum ([long]::MaxValue))
                ))) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'process-ownership-invalid' `
                    -Message 'The credential cleanup marker has inconsistent process-ownership fields.')
        }
        try {
            $recordedRoot = [string]$marker.RootPath
            $resolvedRoot = [System.IO.Path]::GetFullPath($recordedRoot).TrimEnd('\')
            $recordedTempRoot = if ($isSchema3) {
                [string]$marker.TemporaryRootPath
            }
            else {
                Split-Path -Parent $resolvedRoot
            }
            $resolvedTempRoot = [System.IO.Path]::GetFullPath($recordedTempRoot).TrimEnd('\')
        }
        catch {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'root-path-invalid' `
                    -Message 'The recorded credential bridge root path is invalid.')
        }
        if (-not $recordedRoot.TrimEnd('\').Equals(
                $resolvedRoot,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -or
            ($isSchema3 -and
                -not $recordedTempRoot.TrimEnd('\').Equals(
                    $resolvedTempRoot,
                    [System.StringComparison]::OrdinalIgnoreCase
                )) -or
            -not ([System.IO.Path]::GetFullPath((Split-Path -Parent $resolvedRoot)).Equals(
                    $resolvedTempRoot,
                    [System.StringComparison]::OrdinalIgnoreCase
                )) -or
            (Split-Path -Leaf $resolvedRoot) -cnotmatch '^atlaso-onepassword-credentials-[0-9a-f]{32}$') {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'root-path-invalid' `
                    -Message 'The recorded credential bridge root is outside the exact supported temporary-root namespace.')
        }
        try {
            Assert-AtlasoStrictDescendantPath `
                -ParentPath $resolvedTempRoot `
                -ChildPath $resolvedRoot `
                -FailureMessage 'Invalid credential bridge root ancestry'
        }
        catch {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'root-ancestry-invalid' `
                    -Message 'The recorded credential bridge root ancestry is invalid or contains a reparse point.')
        }
        $rootItem = Get-AtlasoOptionalOnePasswordRecoveryItem `
            -Path $resolvedRoot `
            -FailureCode 'root-state-unavailable' `
            -FailureMessage 'The recorded credential bridge root state cannot be inspected safely.' `
            -ItemReader $RootItemReader
        $rootState = 'absent'
        if ($null -ne $rootItem) {
            if ($isSchema3) {
                try {
                    if ((Get-AtlasoPathIdentity `
                            -Path $resolvedTempRoot `
                            -Description '1Password credential bridge temporary root') -cne
                        [string]$marker.TemporaryRootIdentity) {
                        throw 'temporary root changed'
                    }
                }
                catch {
                    throw (New-AtlasoOnePasswordRecoveryException `
                            -Code 'temporary-root-identity-mismatch' `
                            -Message 'The recorded credential bridge temporary root changed; the marker and root were preserved.')
                }
            }
            if (-not ($rootItem -is [System.IO.DirectoryInfo]) -or
                ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'root-type-invalid' `
                        -Message 'The recorded credential bridge root is not an ordinary directory.')
            }
            $actualRootIdentity = ''
            try {
                $actualRootIdentity = Get-AtlasoPathIdentity `
                    -Path $resolvedRoot `
                    -Description '1Password credential bridge root'
            }
            catch {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'root-identity-unavailable' `
                        -Message 'The recorded credential bridge root identity cannot be verified.')
            }
            if ($actualRootIdentity -cne [string]$marker.RootIdentity) {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'root-identity-mismatch' `
                        -Message 'The recorded credential bridge root was replaced; the marker and root were preserved.')
            }
            $rootState = 'identity-matching'
        }
        if ([string]$marker.Phase -cin @('root-absent', 'retired') -and $rootState -cne 'absent') {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'terminal-root-present' `
                    -Message 'The credential bridge root is present despite a terminal marker phase; state was preserved for investigation.')
        }
        $bootRelation = Get-AtlasoWindowsBootIdentityState -BootIdentity ([long]$marker.BootIdentity)
        if ($bootRelation -ceq 'invalid') {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'boot-identity-invalid' `
                    -Message 'The credential cleanup marker has an invalid Windows boot identity.')
        }
        return [pscustomobject][ordered]@{
            MarkerState             = if ($isSchema3) { 'schema-3' } else { 'schema-2' }
            MarkerPath              = $markerPath
            Marker                  = $marker
            MarkerIdentity          = $markerIdentity
            MarkerDirectory         = $markerDirectory
            MarkerDirectoryIdentity = $markerDirectoryIdentity
            Phase                   = [string]$marker.Phase
            BootRelation            = $bootRelation
            OwnerState              = 'not-evaluated'
            ChildState              = 'not-evaluated'
            JobState                = 'not-evaluated'
            RootState               = $rootState
        }
    }
    catch {
        if ($_.Exception.Data['AtlasoOnePasswordRecoverySafe']) {
            throw
        }
        throw (New-AtlasoOnePasswordRecoveryException `
                -Code 'inspection-failed' `
                -Message 'The retained credential bridge state could not be inspected safely; no process or file was changed.')
    }
}

<#
.SYNOPSIS
Verify that the cleanup marker and its directory retain their captured identities.

.PARAMETER MarkerPath
Exact checkout-local cleanup marker path.

.PARAMETER ExpectedMarkerIdentity
Filesystem identity captured from the validated marker.

.PARAMETER MarkerDirectory
Exact checkout-local marker directory.

.PARAMETER ExpectedMarkerDirectoryIdentity
Filesystem identity captured from the marker directory.
#>
function Assert-AtlasoOnePasswordMarkerOwnership {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$ExpectedMarkerIdentity,
        [Parameter(Mandatory = $true)][string]$MarkerDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedMarkerDirectoryIdentity
    )

    try {
        if ((Get-AtlasoPathIdentity -Path $MarkerDirectory -Description 'Credential cleanup marker directory') -cne
            $ExpectedMarkerDirectoryIdentity -or
            (Get-AtlasoPathIdentity -Path $MarkerPath -Description 'Credential cleanup marker') -cne
            $ExpectedMarkerIdentity) {
            throw 'identity mismatch'
        }
    }
    catch {
        throw (New-AtlasoOnePasswordRecoveryException `
                -Code 'marker-identity-mismatch' `
                -Message 'The checkout-local credential cleanup marker or its directory changed during recovery; state was preserved.')
    }
}

<#
.SYNOPSIS
Revalidate the exact credential-root state captured during recovery inspection.

.PARAMETER Context
Validated credential-recovery context containing the root path and identity.
#>
function Assert-AtlasoOnePasswordCredentialRootOwnership {
    param([Parameter(Mandatory = $true)][object]$Context)

    try {
        $rootPath = [string]$Context.Marker.RootPath
        $markerProperties = @($Context.Marker.PSObject.Properties.Name)
        $hasTemporaryRootIdentity = 'TemporaryRootPath' -in $markerProperties -and
            'TemporaryRootIdentity' -in $markerProperties
        $tempRoot = if ($hasTemporaryRootIdentity) {
            [System.IO.Path]::GetFullPath(
                [string]$Context.Marker.TemporaryRootPath
            ).TrimEnd('\')
        }
        else {
            [System.IO.Path]::GetFullPath((Split-Path -Parent $rootPath)).TrimEnd('\')
        }
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $tempRoot `
            -ChildPath $rootPath `
            -FailureMessage 'Invalid credential bridge root ancestry'
        $rootItem = Get-AtlasoOptionalOnePasswordRecoveryItem `
            -Path $rootPath `
            -FailureCode 'root-state-unavailable' `
            -FailureMessage 'The recorded credential bridge root state cannot be inspected safely.'
        if ($null -ne $rootItem -and $hasTemporaryRootIdentity -and
            (Get-AtlasoPathIdentity `
                -Path $tempRoot `
                -Description '1Password credential bridge temporary root') -cne
            [string]$Context.Marker.TemporaryRootIdentity) {
            throw 'temporary root changed'
        }
        if ($Context.RootState -ceq 'absent') {
            if ($null -ne $rootItem) {
                throw 'root appeared'
            }
            return
        }
        if ($null -eq $rootItem -or -not ($rootItem -is [System.IO.DirectoryInfo]) -or
            ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-AtlasoPathIdentity -Path $rootPath -Description '1Password credential bridge root') -cne
            [string]$Context.Marker.RootIdentity) {
            throw 'root changed'
        }
    }
    catch {
        throw (New-AtlasoOnePasswordRecoveryException `
                -Code 'root-changed-before-mutation' `
                -Message 'The credential bridge root changed after inspection and before mutation; no process or file was changed.')
    }
}

<#
.SYNOPSIS
Classify the safe action for one fully validated schema-2 or schema-3 marker.

.PARAMETER Context
Validated credential-recovery context containing the durable marker.
#>
function Get-AtlasoOnePasswordCredentialRecoveryPlan {
    param([Parameter(Mandatory = $true)][object]$Context)

    $plan = [ordered]@{
        MarkerState        = [string]$Context.MarkerState
        Phase              = [string]$Context.Phase
        BootRelation       = [string]$Context.BootRelation
        OwnerState         = [string]$Context.OwnerState
        ChildState         = [string]$Context.ChildState
        JobState           = [string]$Context.JobState
        RootState          = [string]$Context.RootState
        Action             = 'none'
        BlockerCode        = ''
        BlockerMessage     = ''
        RequiresTermination = $false
    }
    if ($Context.MarkerState -ceq 'absent') {
        $plan.Action = 'already-reset'
        return [pscustomobject]$plan
    }
    if ($Context.Phase -cin @('root-absent', 'retired')) {
        $plan.OwnerState = 'not-applicable'
        $plan.ChildState = 'not-applicable'
        $plan.JobState = 'not-applicable'
        $plan.Action = 'finish-marker-retirement'
        return [pscustomobject]$plan
    }
    if ($Context.BootRelation -ceq 'prior') {
        $plan.OwnerState = 'not-applicable'
        $plan.ChildState = 'not-applicable'
        $plan.JobState = 'not-applicable'
        $plan.Action = 'remove-root-and-retire-marker'
        return [pscustomobject]$plan
    }

    $marker = $Context.Marker
    try {
        $plan.OwnerState = Get-AtlasoRecordedProcessIdentityState `
            -ProcessId ([int]$marker.OwnerProcessId) `
            -StartFileTimeUtc ([long]$marker.OwnerProcessStartFileTimeUtc)
    }
    catch {
        $plan.OwnerState = 'unavailable'
        $plan.BlockerCode = 'owner-identity-unavailable'
        $plan.BlockerMessage = 'The recorded credential-bridge controller identity cannot be inspected safely.'
        $plan.Action = 'preserve-and-investigate'
        return [pscustomobject]$plan
    }
    if ($plan.OwnerState -ceq 'matching') {
        $plan.BlockerCode = 'owner-active'
        $plan.BlockerMessage = 'The exact recorded credential-bridge controller is still active. Allow the original VMware workflow to exit before resetting; the recovery command never terminates that controller.'
        $plan.Action = 'wait-for-controller-exit'
        return [pscustomobject]$plan
    }
    if ($plan.OwnerState -ceq 'reused') {
        $plan.BlockerCode = 'owner-pid-reused'
        $plan.BlockerMessage = 'The recorded controller process identifier was reused on this boot. No process or file can be changed safely; restart Windows, then rerun the original VMware workflow.'
        $plan.Action = 'restart-windows-and-rerun-workflow'
        return [pscustomobject]$plan
    }

    $ownershipPhase = [string]$marker.ProcessOwnershipPhase
    if ($ownershipPhase -ceq 'prepared') {
        $plan.ChildState = 'not-recorded'
    }
    else {
        try {
            $plan.ChildState = Get-AtlasoRecordedProcessIdentityState `
                -ProcessId ([int]$marker.ChildProcessId) `
                -StartFileTimeUtc ([long]$marker.ChildProcessStartFileTimeUtc)
        }
        catch {
            $plan.ChildState = 'unavailable'
            $plan.BlockerCode = 'child-identity-unavailable'
            $plan.BlockerMessage = 'The recorded credential-bridge child identity cannot be inspected safely.'
            $plan.Action = 'preserve-and-investigate'
            return [pscustomobject]$plan
        }
        if ($plan.ChildState -ceq 'reused') {
            $plan.BlockerCode = 'child-pid-reused'
            $plan.BlockerMessage = 'The recorded child process identifier was reused. The unrelated process will not be terminated; restart Windows, then rerun the original VMware workflow.'
            $plan.Action = 'restart-windows-and-rerun-workflow'
            return [pscustomobject]$plan
        }
    }

    $job = $null
    try {
        try {
            $job = Open-AtlasoBoundedProcessJob -ProcessJobName ([string]$marker.ProcessJobName)
            if ($null -eq $job) {
                $plan.JobState = 'absent'
            }
            else {
                $activeProcessIds = @($job.GetActiveProcessIds())
                $plan.JobState = if ($activeProcessIds.Count -eq 0) { 'inactive' } else { 'active' }
            }
        }
        catch {
            $plan.JobState = 'unavailable'
            $plan.BlockerCode = 'job-state-unavailable'
            $plan.BlockerMessage = 'The exact recorded credential-bridge process job cannot be inspected safely.'
            $plan.Action = 'preserve-and-investigate'
            return [pscustomobject]$plan
        }
        if ($ownershipPhase -ceq 'prepared') {
            if ($null -ne $job -and $activeProcessIds.Count -ne 0) {
                $plan.JobState = 'active-unrecorded'
                $plan.BlockerCode = 'unrecorded-job-descendants'
                $plan.BlockerMessage = 'The retained process job has active descendants but no durably recorded root child. Same-boot termination is not provable; restart Windows, then rerun the original VMware workflow.'
                $plan.Action = 'restart-windows-and-rerun-workflow'
                return [pscustomobject]$plan
            }
            $plan.Action = 'remove-root-and-retire-marker'
            return [pscustomobject]$plan
        }
        if ($plan.ChildState -ceq 'matching') {
            if ($null -eq $job) {
                $plan.BlockerCode = 'active-child-missing-job'
                $plan.BlockerMessage = 'The exact recorded credential-bridge child is active without its named process job. It will not be terminated; restart Windows, then rerun the original VMware workflow.'
                $plan.Action = 'restart-windows-and-rerun-workflow'
                return [pscustomobject]$plan
            }
            $childProcess = $null
            try {
                $childProcess = Get-Process -Id ([int]$marker.ChildProcessId) -ErrorAction Stop
                if (-not $job.ContainsProcess($childProcess) -or
                    [int]$marker.ChildProcessId -notin $activeProcessIds) {
                    $plan.BlockerCode = 'child-job-mismatch'
                    $plan.BlockerMessage = 'The recorded credential-bridge child is not provably owned by its exact named process job. No process will be terminated.'
                    $plan.Action = 'preserve-and-investigate'
                    return [pscustomobject]$plan
                }
            }
            finally {
                if ($null -ne $childProcess) {
                    $childProcess.Dispose()
                }
            }
            $plan.JobState = 'active-owned'
            $plan.RequiresTermination = $true
            $plan.Action = 'terminate-exact-job-remove-root-and-retire-marker'
            return [pscustomobject]$plan
        }
        if ($null -ne $job -and $activeProcessIds.Count -ne 0) {
            $plan.JobState = 'active-unrecorded'
            $plan.BlockerCode = 'surviving-descendant-without-root'
            $plan.BlockerMessage = 'The retained process job has active descendants after its recorded root child exited. Same-boot termination is not provable; restart Windows, then rerun the original VMware workflow.'
            $plan.Action = 'restart-windows-and-rerun-workflow'
            return [pscustomobject]$plan
        }
        $plan.Action = 'remove-root-and-retire-marker'
        return [pscustomobject]$plan
    }
    finally {
        if ($null -ne $job) {
            $job.Dispose()
        }
    }
}

<#
.SYNOPSIS
Terminate the exact recorded credential job and prove its captured processes inactive.

.PARAMETER Context
Validated current-boot schema-2 or schema-3 recovery context.
#>
function Stop-AtlasoOnePasswordCredentialRecoveryJob {
    param([Parameter(Mandatory = $true)][object]$Context)

    $marker = $Context.Marker
    $job = $null
    $childProcess = $null
    try {
        Assert-AtlasoOnePasswordMarkerOwnership `
            -MarkerPath $Context.MarkerPath `
            -ExpectedMarkerIdentity $Context.MarkerIdentity `
            -MarkerDirectory $Context.MarkerDirectory `
            -ExpectedMarkerDirectoryIdentity $Context.MarkerDirectoryIdentity
        Assert-AtlasoOnePasswordCredentialRootOwnership -Context $Context
        if ((Get-AtlasoRecordedProcessIdentityState `
                -ProcessId ([int]$marker.OwnerProcessId) `
                -StartFileTimeUtc ([long]$marker.OwnerProcessStartFileTimeUtc)) -cne 'absent') {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'owner-changed-before-termination' `
                    -Message 'The recorded controller identity changed before recovery could terminate the child job; state was preserved.')
        }
        if ([string]$marker.ProcessOwnershipPhase -cne 'assigned' -or
            (Get-AtlasoRecordedProcessIdentityState `
                -ProcessId ([int]$marker.ChildProcessId) `
                -StartFileTimeUtc ([long]$marker.ChildProcessStartFileTimeUtc)) -cne 'matching') {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'child-changed-before-termination' `
                    -Message 'The recorded child identity changed before recovery could terminate its job; state was preserved.')
        }
        $job = Open-AtlasoBoundedProcessJob -ProcessJobName ([string]$marker.ProcessJobName)
        if ($null -eq $job) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'job-missing-before-termination' `
                    -Message 'The recorded child remains active but its exact process job disappeared; no process was terminated.')
        }
        $childProcess = Get-Process -Id ([int]$marker.ChildProcessId) -ErrorAction Stop
        $activeProcessIds = @($job.GetActiveProcessIds())
        if (-not $job.ContainsProcess($childProcess) -or
            [int]$marker.ChildProcessId -notin $activeProcessIds) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'child-job-mismatch-before-termination' `
                    -Message 'The recorded child is no longer provably owned by its exact process job; no process was terminated.')
        }
        $capturedProcesses = @()
        foreach ($processId in $activeProcessIds) {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($null -eq $process) {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'job-membership-changed' `
                        -Message 'The exact process-job membership changed during recovery admission; no process was terminated.')
            }
            try {
                $capturedProcesses += [pscustomobject]@{
                    ProcessId       = $processId
                    StartFileTimeUtc = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
                }
            }
            catch {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'job-member-identity-unavailable' `
                        -Message 'A recorded process-job member identity could not be captured; no process was terminated.')
            }
            finally {
                $process.Dispose()
            }
        }
        $job.TerminateAndWait(10000)
        if (@($job.GetActiveProcessIds()).Count -ne 0) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'job-termination-incomplete' `
                    -Message 'The exact credential-bridge process job remained active after termination; the marker and root were preserved.')
        }
        foreach ($capturedProcess in $capturedProcesses) {
            if ((Get-AtlasoRecordedProcessIdentityState `
                    -ProcessId ([int]$capturedProcess.ProcessId) `
                    -StartFileTimeUtc ([long]$capturedProcess.StartFileTimeUtc)) -ceq 'matching') {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'captured-process-still-active' `
                        -Message 'A captured credential-bridge process remained active after job termination; the marker and root were preserved.')
            }
        }
        if ((Get-AtlasoRecordedProcessIdentityState `
                -ProcessId ([int]$marker.ChildProcessId) `
                -StartFileTimeUtc ([long]$marker.ChildProcessStartFileTimeUtc)) -ceq 'matching' -or
            (Get-AtlasoRecordedProcessIdentityState `
                -ProcessId ([int]$marker.OwnerProcessId) `
                -StartFileTimeUtc ([long]$marker.OwnerProcessStartFileTimeUtc)) -cne 'absent') {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'process-inactivity-unproven' `
                    -Message 'Credential-bridge process inactivity could not be proven after job termination; the marker and root were preserved.')
        }
    }
    catch {
        if ($_.Exception.Data['AtlasoOnePasswordRecoverySafe']) {
            throw
        }
        throw (New-AtlasoOnePasswordRecoveryException `
                -Code 'job-termination-failed' `
                -Message 'The exact credential-bridge process job could not be terminated and verified; the marker and root were preserved.')
    }
    finally {
        if ($null -ne $childProcess) {
            $childProcess.Dispose()
        }
        if ($null -ne $job) {
            $job.Dispose()
        }
    }
}

<#
.SYNOPSIS
Remove a proven-inactive credential root and durably retire its marker.

.PARAMETER MarkerPath
Exact non-secret cleanup marker path.

.PARAMETER Marker
Validated marker payload owning the exact bridge root.

.PARAMETER ExpectedMarkerIdentity
Optional filesystem identity captured from the validated marker.

.PARAMETER MarkerDirectory
Optional exact directory containing the marker.

.PARAMETER ExpectedMarkerDirectoryIdentity
Optional filesystem identity captured from the marker directory.
#>
function Complete-AtlasoOnePasswordCredentialCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][object]$Marker,
        [string]$ExpectedMarkerIdentity = '',
        [string]$MarkerDirectory = '',
        [string]$ExpectedMarkerDirectoryIdentity = ''
    )

    $verifyMarkerOwnership = -not [string]::IsNullOrWhiteSpace($ExpectedMarkerIdentity)
    $currentMarkerIdentity = $ExpectedMarkerIdentity
    if ($verifyMarkerOwnership) {
        Assert-AtlasoOnePasswordMarkerOwnership `
            -MarkerPath $MarkerPath `
            -ExpectedMarkerIdentity $currentMarkerIdentity `
            -MarkerDirectory $MarkerDirectory `
            -ExpectedMarkerDirectoryIdentity $ExpectedMarkerDirectoryIdentity
    }
    $markerProperties = @($Marker.PSObject.Properties.Name)
    $expectedRootIdentity = if ('RootIdentity' -in $markerProperties) {
        [string]$Marker.RootIdentity
    }
    else {
        ''
    }
    $temporaryRootPath = if ('TemporaryRootPath' -in $markerProperties) {
        [string]$Marker.TemporaryRootPath
    }
    else {
        Split-Path -Parent ([string]$Marker.RootPath)
    }
    $expectedTemporaryRootIdentity = if ('TemporaryRootIdentity' -in $markerProperties) {
        [string]$Marker.TemporaryRootIdentity
    }
    else {
        ''
    }
    if ([string]$Marker.Phase -ceq 'active') {
        $activeRoot = Get-AtlasoOptionalOnePasswordRecoveryItem `
            -Path ([string]$Marker.RootPath) `
            -FailureCode 'root-state-unavailable' `
            -FailureMessage 'The recorded credential bridge root state cannot be inspected safely.'
        if ($null -ne $activeRoot) {
            Remove-AtlasoOnePasswordCredentialBridge `
                -BridgeRoot ([string]$Marker.RootPath) `
                -ExpectedRootIdentity $expectedRootIdentity `
                -TemporaryRootPath $temporaryRootPath `
                -ExpectedTemporaryRootIdentity $expectedTemporaryRootIdentity
        }
        else {
            # An observed absence is not yet durable evidence. Flush the
            # nearest surviving parent before advancing the marker phase.
            Sync-AtlasoOnePasswordAbsentPathMetadata -Path ([string]$Marker.RootPath)
        }
        if ($verifyMarkerOwnership) {
            Assert-AtlasoOnePasswordMarkerOwnership `
                -MarkerPath $MarkerPath `
                -ExpectedMarkerIdentity $currentMarkerIdentity `
                -MarkerDirectory $MarkerDirectory `
                -ExpectedMarkerDirectoryIdentity $ExpectedMarkerDirectoryIdentity
        }
        $Marker.Phase = 'root-absent'
        Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
        if ($verifyMarkerOwnership) {
            $currentMarkerIdentity = Get-AtlasoPathIdentity `
                -Path $MarkerPath `
                -Description 'Credential cleanup marker'
        }
    }
    if ([string]$Marker.Phase -ceq 'root-absent') {
        $remainingRoot = Get-AtlasoOptionalOnePasswordRecoveryItem `
            -Path ([string]$Marker.RootPath) `
            -FailureCode 'root-state-unavailable' `
            -FailureMessage 'The recorded credential bridge root state cannot be inspected safely.'
        if ($null -ne $remainingRoot) {
            throw 'The credential bridge root reappeared after its durable root-absent transition.'
        }
        if ($verifyMarkerOwnership) {
            Assert-AtlasoOnePasswordMarkerOwnership `
                -MarkerPath $MarkerPath `
                -ExpectedMarkerIdentity $currentMarkerIdentity `
                -MarkerDirectory $MarkerDirectory `
                -ExpectedMarkerDirectoryIdentity $ExpectedMarkerDirectoryIdentity
        }
        $Marker.Phase = 'retired'
        Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
        if ($verifyMarkerOwnership) {
            $currentMarkerIdentity = Get-AtlasoPathIdentity `
                -Path $MarkerPath `
                -Description 'Credential cleanup marker'
        }
    }
    if ($verifyMarkerOwnership) {
        Assert-AtlasoOnePasswordMarkerOwnership `
            -MarkerPath $MarkerPath `
            -ExpectedMarkerIdentity $currentMarkerIdentity `
            -MarkerDirectory $MarkerDirectory `
            -ExpectedMarkerDirectoryIdentity $ExpectedMarkerDirectoryIdentity
    }
    Remove-Item -LiteralPath $MarkerPath -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $MarkerPath) {
        throw 'The credential cleanup marker removal did not complete.'
    }
    Sync-AtlasoDirectoryMetadata -DirectoryPath (Split-Path -Parent $MarkerPath)
    if ($verifyMarkerOwnership -and
        (Get-AtlasoPathIdentity -Path $MarkerDirectory -Description 'Credential cleanup marker directory') -cne
        $ExpectedMarkerDirectoryIdentity) {
        throw 'The credential cleanup marker directory changed during retirement.'
    }
}

<#
.SYNOPSIS
Return the sanitized public projection of a credential-recovery plan.

.PARAMETER Plan
Internal recovery plan containing only fixed state and blocker fields.

.PARAMETER Result
Outcome for the requested inspection or reset operation.
#>
function ConvertTo-AtlasoOnePasswordCredentialRecoveryStatus {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string]$Result
    )

    return [pscustomobject][ordered]@{
        MarkerState  = [string]$Plan.MarkerState
        Phase        = [string]$Plan.Phase
        BootRelation = [string]$Plan.BootRelation
        OwnerState   = [string]$Plan.OwnerState
        ChildState   = [string]$Plan.ChildState
        JobState     = [string]$Plan.JobState
        RootState    = [string]$Plan.RootState
        Action       = [string]$Plan.Action
        Result       = $Result
        Blocker      = [string]$Plan.BlockerCode
    }
}

<#
.SYNOPSIS
Inspect or safely reset the current checkout's retained schema-2 or schema-3 credential bridge.

.PARAMETER RepositoryRoot
Exact Atlaso checkout that owns the fixed cleanup marker.

.PARAMETER Inspect
Return a sanitized read-only state report without changing a process or file.

.PARAMETER TerminateOwnedProcess
Permit termination of the exact matching recorded child job after all ownership checks pass.
#>
function Invoke-AtlasoOnePasswordCredentialBridgeReset {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [switch]$Inspect,
        [switch]$TerminateOwnedProcess
    )

    try {
        $context = Get-AtlasoOnePasswordCredentialRecoveryContext -RepositoryRoot $RepositoryRoot
        $plan = Get-AtlasoOnePasswordCredentialRecoveryPlan -Context $context
        if ($Inspect -or $WhatIfPreference) {
            $result = if ($WhatIfPreference) { 'what-if' } else { 'inspection' }
            if ($plan.RequiresTermination -and -not $TerminateOwnedProcess) {
                $plan.Action = 'rerun-with-terminate-owned-process'
            }
            return ConvertTo-AtlasoOnePasswordCredentialRecoveryStatus -Plan $plan -Result $result
        }
        if (-not [string]::IsNullOrWhiteSpace($plan.BlockerCode)) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code $plan.BlockerCode `
                    -Message $plan.BlockerMessage)
        }
        if ($plan.MarkerState -ceq 'absent') {
            return ConvertTo-AtlasoOnePasswordCredentialRecoveryStatus -Plan $plan -Result 'already-reset'
        }
        if ($plan.RequiresTermination -and -not $TerminateOwnedProcess) {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'termination-switch-required' `
                    -Message 'The exact recorded credential-bridge child and job are active. Inspect first, then rerun with -TerminateOwnedProcess to authorize only that owned job termination.')
        }
        if (-not $PSCmdlet.ShouldProcess(
                'the exact retained 1Password credential bridge',
                'verify process inactivity, remove its identity-matching root, and durably retire its marker'
            )) {
            return ConvertTo-AtlasoOnePasswordCredentialRecoveryStatus -Plan $plan -Result 'not-changed'
        }
        if ($plan.RequiresTermination) {
            Stop-AtlasoOnePasswordCredentialRecoveryJob -Context $context
            $context = Get-AtlasoOnePasswordCredentialRecoveryContext -RepositoryRoot $RepositoryRoot
            $plan = Get-AtlasoOnePasswordCredentialRecoveryPlan -Context $context
            if (-not [string]::IsNullOrWhiteSpace($plan.BlockerCode) -or $plan.RequiresTermination) {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'post-termination-state-unproven' `
                        -Message 'The credential-bridge state could not be proven inactive after exact job termination; the marker and root were preserved.')
            }
        }
        Assert-AtlasoOnePasswordCredentialRootOwnership -Context $context
        Complete-AtlasoOnePasswordCredentialCleanup `
            -MarkerPath $context.MarkerPath `
            -Marker $context.Marker `
            -ExpectedMarkerIdentity $context.MarkerIdentity `
            -MarkerDirectory $context.MarkerDirectory `
            -ExpectedMarkerDirectoryIdentity $context.MarkerDirectoryIdentity
        $completedContext = Get-AtlasoOnePasswordCredentialRecoveryContext -RepositoryRoot $RepositoryRoot
        $completedPlan = Get-AtlasoOnePasswordCredentialRecoveryPlan -Context $completedContext
        if ($completedPlan.MarkerState -cne 'absent') {
            throw (New-AtlasoOnePasswordRecoveryException `
                    -Code 'marker-retirement-incomplete' `
                    -Message 'The credential cleanup marker remained after reset; retained state was preserved for investigation.')
        }
        $completedPlan.Action = 'reset-complete'
        return ConvertTo-AtlasoOnePasswordCredentialRecoveryStatus -Plan $completedPlan -Result 'reset'
    }
    catch {
        if ($_.Exception.Data['AtlasoOnePasswordRecoverySafe']) {
            throw
        }
        throw (New-AtlasoOnePasswordRecoveryException `
                -Code 'reset-failed' `
                -Message 'The retained credential bridge could not be reset safely; no unverified process or path was changed.')
    }
}

<#
.SYNOPSIS
Retire a legacy credential marker only after a different Windows boot is proven.

.PARAMETER RepositoryRoot
Atlaso checkout owning the legacy compatibility marker.
#>
function Invoke-AtlasoLegacyOnePasswordCredentialCleanupRecovery {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    try {
        $markerPath = [System.IO.Path]::GetFullPath(
            (Get-AtlasoOnePasswordCleanupMarkerPath -RepositoryRoot $RepositoryRoot)
        )
        $markerItem = Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop
        if (-not ($markerItem -is [System.IO.FileInfo]) -or
            ($markerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $markerItem.Length -gt 65536) {
            throw 'invalid legacy marker file'
        }
        $marker = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $properties = @($marker.PSObject.Properties.Name)
        $expectedProperties = @('BootIdentity', 'Phase', 'RootPath', 'Schema')
        if ($properties.Count -ne $expectedProperties.Count -or
            (Compare-Object -ReferenceObject $expectedProperties -DifferenceObject $properties -CaseSensitive) -or
            -not (Test-AtlasoOnePasswordMarkerInteger -Value $marker.Schema -Minimum 1 -Maximum 1) -or
            -not ($marker.RootPath -is [string]) -or [string]::IsNullOrWhiteSpace($marker.RootPath) -or
            -not ($marker.Phase -is [string]) -or [string]$marker.Phase -cnotin @('active', 'root-absent', 'retired')) {
            throw 'invalid legacy marker schema'
        }
        $resolvedRoot = [System.IO.Path]::GetFullPath([string]$marker.RootPath).TrimEnd('\')
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
        if (-not ([System.IO.Path]::GetFullPath((Split-Path -Parent $resolvedRoot)).Equals(
                    $resolvedTempRoot,
                    [System.StringComparison]::OrdinalIgnoreCase
                )) -or
            (Split-Path -Leaf $resolvedRoot) -cnotmatch '^atlaso-onepassword-credentials-[0-9a-f]{32}$') {
            throw 'invalid legacy root namespace'
        }
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedTempRoot `
            -ChildPath $resolvedRoot `
            -FailureMessage 'Invalid legacy credential root ancestry'
        $rootPresent = $null -ne (Get-AtlasoOptionalOnePasswordRecoveryItem `
                -Path $resolvedRoot `
                -FailureCode 'root-state-unavailable' `
                -FailureMessage 'The recorded credential bridge root state cannot be inspected safely.')
        if ([string]$marker.Phase -cin @('root-absent', 'retired') -and $rootPresent) {
            throw 'legacy terminal root present'
        }
        if ([string]$marker.Phase -ceq 'active') {
            $bootRelation = Get-AtlasoWindowsBootIdentityState -BootIdentity $marker.BootIdentity
            if ($bootRelation -cne 'prior') {
                throw (New-AtlasoOnePasswordRecoveryException `
                        -Code 'legacy-marker-current-boot' `
                        -Message 'The legacy credential marker lacks process ownership evidence. Restart Windows, then rerun the original VMware workflow; no same-boot reset is permitted.')
            }
        }
        Complete-AtlasoOnePasswordCredentialCleanup -MarkerPath $markerPath -Marker $marker
    }
    catch {
        if ($_.Exception.Data['AtlasoOnePasswordRecoverySafe']) {
            throw
        }
        throw (New-AtlasoOnePasswordRecoveryException `
                -Code 'legacy-marker-invalid' `
                -Message 'The legacy credential marker or root cannot be verified for compatibility recovery. Preserve it and obtain maintainer guidance.')
    }
}

<#
.SYNOPSIS
Recover a retained 1Password bridge during an ordinary VMware workflow admission.

.PARAMETER RepositoryRoot
Atlaso checkout owning the durable marker.
#>
function Invoke-AtlasoOnePasswordCredentialCleanupRecovery {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    try {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $RepositoryRoot `
            -Confirm:$false | Out-Null
    }
    catch {
        $recoveryFailure = $_
        if ($recoveryFailure.Exception.Data['AtlasoOnePasswordRecoveryCode'] -ceq 'legacy-marker') {
            try {
                Invoke-AtlasoLegacyOnePasswordCredentialCleanupRecovery -RepositoryRoot $RepositoryRoot
                return
            }
            catch {
                $recoveryFailure = $_
            }
        }
        $safeMessage = if ($recoveryFailure.Exception.Data['AtlasoOnePasswordRecoverySafe']) {
            $recoveryFailure.Exception.Message
        }
        else {
            'The retained credential bridge state could not be classified safely.'
        }
        throw "A prior 1Password credential bridge has unresolved cleanup. Run .\scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1 -Inspect, then follow its sanitized recovery guidance. Blocker: $safeMessage"
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

.PARAMETER OnePasswordServiceAccountTokenFile
Optional explicit current-user DPAPI ciphertext file. When omitted, the
Git-ignored checkout-local default is preferred over desktop discovery.

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
        'OnePasswordServiceAccountTokenFile',
        Justification = 'Path to current-user DPAPI ciphertext, not a plaintext token.'
    )]
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
        [string]$OnePasswordServiceAccountTokenFile = '',
        [string]$OnePasswordPython = '',
        [string]$OnePasswordCliPath = '',
        [SecureString]$AdminPassword,
        [SecureString]$RootPassword,
        [AllowEmptyString()][string]$PipGlobalIndex = '',
        [AllowEmptyString()][string]$PipGlobalIndexUrl = '',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$ConsumerDescription = 'Atlaso workflow'
    )

    # Validate the exported bridge before artifact admission or recovery. This
    # prevents a direct caller from combining one explicit field with a public
    # default before the lower-level download boundary revalidates the pair.
    $validatedPackageSource = Resolve-AtlasoPipPackageSource `
        -PipGlobalIndex $PipGlobalIndex `
        -PipGlobalIndexUrl $PipGlobalIndexUrl
    $PipGlobalIndex = $validatedPackageSource.PipGlobalIndex
    $PipGlobalIndexUrl = $validatedPackageSource.PipGlobalIndexUrl
    if ($env:DEFAULT_ADMIN_PASSWORD -or $env:DEFAULT_ROOT_PASSWORD) {
        throw 'DEFAULT_ADMIN_PASSWORD and DEFAULT_ROOT_PASSWORD must not be supplied by the caller; use the exact Atlaso 1Password Environment bridge.'
    }
    if ($env:OP_SERVICE_ACCOUNT_TOKEN) {
        throw 'OP_SERVICE_ACCOUNT_TOKEN must not be supplied by the caller; use the current-user DPAPI token file.'
    }
    if (-not (Get-Command Invoke-AtlasoBoundedProcess -ErrorAction SilentlyContinue)) {
        throw 'The bounded Atlaso process runner is unavailable.'
    }
    $needsDefaults = $null -eq $AdminPassword -or $null -eq $RootPassword
    $resolvedPython = ''
    $authentication = [pscustomobject]@{ Mode = 'desktop'; TokenFile = ''; Account = '' }
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
        $authentication = Resolve-AtlasoOnePasswordAuthentication `
            -RepositoryRoot $RepositoryRoot `
            -ServiceAccountTokenFile $OnePasswordServiceAccountTokenFile `
            -Account $OnePasswordAccount `
            -TimeoutSeconds $TimeoutSeconds `
            -CliPath $OnePasswordCliPath
    }
    Invoke-AtlasoOnePasswordCredentialCleanupRecovery -RepositoryRoot $RepositoryRoot
    $temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
    $bridgeRoot = Join-Path $temporaryRoot (
        "atlaso-onepassword-credentials-$([guid]::NewGuid().ToString('N'))"
    )
    [void][System.IO.Directory]::CreateDirectory($bridgeRoot)
    $cleanupMarkerPath = Get-AtlasoOnePasswordCleanupMarkerPath -RepositoryRoot $RepositoryRoot
    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $cleanupMarkerPath))
    $controllerProcess = Get-Process -Id $PID -ErrorAction Stop
    $processJobName = 'Local\Atlaso-OnePassword-' + [guid]::NewGuid().ToString('N')
    $cleanupMarker = [ordered]@{
        Schema                       = 3
        RootPath                     = [System.IO.Path]::GetFullPath($bridgeRoot)
        RootIdentity                 = Get-AtlasoPathIdentity `
            -Path $bridgeRoot `
            -Description '1Password credential bridge root'
        TemporaryRootPath            = $temporaryRoot
        TemporaryRootIdentity        = Get-AtlasoPathIdentity `
            -Path $temporaryRoot `
            -Description '1Password credential bridge temporary root'
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
        }

        $helperPath = Join-Path $PSScriptRoot 'Invoke-AtlasoOnePasswordCredentials.ps1'
        $arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $helperPath,
            '-RequestPath', $requestPath,
            '-StatusPath', $statusPath,
            '-CredentialBundlePath', $credentialBundlePath,
            '-RepositoryRoot', $RepositoryRoot,
            '-TimeoutSeconds', "$TimeoutSeconds"
        )
        if ($needsDefaults) {
            $arguments += @(
                '-PythonCommand', $resolvedPython,
                '-DependencyPath', $dependencyPath,
                '-OnePasswordAuthenticationMode', $authentication.Mode,
                '-OnePasswordAccount', $authentication.Account,
                '-OnePasswordServiceAccountTokenFile', $authentication.TokenFile,
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
    'Assert-AtlasoOnePasswordServiceAccountTokenFile',
    'Resolve-AtlasoOnePasswordServiceAccountTokenFile',
    'Resolve-AtlasoOnePasswordAuthentication',
    'Assert-AtlasoOnePasswordAccount',
    'Resolve-AtlasoOnePasswordCliPath',
    'Resolve-AtlasoOnePasswordAccount',
    'Resolve-AtlasoOnePasswordPython',
    'Save-AtlasoOnePasswordWheel',
    'New-AtlasoIsolatedPipRuntime',
    'New-AtlasoOnePasswordIndexLock',
    'Initialize-AtlasoOnePasswordSdkRuntime',
    'Get-AtlasoOnePasswordCredentialBridgeError',
    'Invoke-AtlasoOnePasswordCredentialBridgeReset',
    'Remove-AtlasoOnePasswordCredentialBridge',
    'Invoke-AtlasoBoundedStreamingProcess',
    'Get-AtlasoOnePasswordCredentialPair'
)
