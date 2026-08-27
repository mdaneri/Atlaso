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
    param([Parameter(Mandatory = $true)][string]$Account)

    if ([string]::IsNullOrWhiteSpace($Account) -or $Account.Length -gt 255 -or $Account -match '[\x00-\x1f\x7f]') {
        throw 'OnePasswordAccount is required and must be a bounded 1Password account name or ID.'
    }
}

<#
.SYNOPSIS
Resolve a Python runtime supported by the 1Password SDK Windows wheel.

.PARAMETER PythonCommand
Explicit CPython 3.10 through 3.13 executable or command.

.PARAMETER TimeoutSeconds
Positive deadline for the version probe.

.PARAMETER ConsumerDescription
Sanitized workflow name used in unsupported-runtime guidance.
#>
function Resolve-AtlasoOnePasswordPython {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$ConsumerDescription = 'Atlaso credentials'
    )

    $command = Get-Command -Name $PythonCommand -CommandType Application -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "The 1Password SDK Python executable was not found: $PythonCommand."
    }
    $resolvedCommand = $command.Source
    $version = (Invoke-AtlasoBoundedProcess `
            -FilePath $resolvedCommand `
            -ArgumentList @('-I', '-S', '-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') `
            -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30)) `
            -Action 'The 1Password SDK Python version probe').Trim()
    if ($version -notmatch '^3\.1[0-3]$') {
        throw "$ConsumerDescription requires CPython 3.10 through 3.13 for the locked 1Password SDK Windows runtime."
    }
    return $resolvedCommand
}

<#
.SYNOPSIS
Prepare the isolated hash-locked 1Password SDK runtime.

.PARAMETER PythonCommand
Approved CPython 3.10 through 3.13 executable.

.PARAMETER RepositoryRoot
Atlaso checkout containing requirements-onepassword-deploy.lock.

.PARAMETER BridgeRoot
Private task-specific temporary root for wheels and installed dependencies.

.PARAMETER TimeoutSeconds
Positive deadline for each dependency operation.
#>
function Initialize-AtlasoOnePasswordSdkRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$BridgeRoot,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $lockPath = Join-Path $RepositoryRoot 'requirements-onepassword-deploy.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw "The vetted 1Password deployment lock is unavailable: $lockPath."
    }
    $wheelDirectory = Join-Path $BridgeRoot 'wheels'
    $dependencyDirectory = Join-Path $BridgeRoot 'python-dependencies'
    [void][System.IO.Directory]::CreateDirectory($wheelDirectory)
    [void][System.IO.Directory]::CreateDirectory($dependencyDirectory)

    # Download is the only index-enabled step. Installation is deliberately
    # offline from the exact hash-verified wheel set, matching deploy-wheel.ps1.
    Invoke-AtlasoBoundedProcess `
        -FilePath $PythonCommand `
        -ArgumentList @(
            '-I', '-m', 'pip', 'download',
            '--disable-pip-version-check',
            '--index-url', 'https://pypi.org/simple',
            '--require-hashes',
            '--only-binary=:all:',
            '--dest', $wheelDirectory,
            '-r', $lockPath
        ) `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The hash-verified 1Password SDK wheel download' | Out-Null
    Invoke-AtlasoBoundedProcess `
        -FilePath $PythonCommand `
        -ArgumentList @(
            '-I', '-m', 'pip', 'install',
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
#>
function Remove-AtlasoOnePasswordCredentialBridge {
    param([Parameter(Mandatory = $true)][string]$BridgeRoot)

    if (-not (Test-Path -LiteralPath $BridgeRoot)) {
        return
    }
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
    $bridgeItem = Get-Item -LiteralPath $resolvedBridgeRoot -Force
    if (($bridgeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove a reparse-point credential bridge root: $resolvedBridgeRoot"
    }
    [System.IO.Directory]::Delete($resolvedBridgeRoot, $true)
    if (Test-Path -LiteralPath $resolvedBridgeRoot) {
        throw "Credential bridge cleanup did not remove the exact task-created root: $resolvedBridgeRoot"
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
CPython 3.10 through 3.13 executable used when a default is needed.

.PARAMETER AdminPassword
Optional explicit administrator SecureString override.

.PARAMETER RootPassword
Optional explicit root SecureString override.

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
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [string]$EnvironmentId = '',
        [string]$OnePasswordAccount = '',
        [string]$OnePasswordPython = '',
        [SecureString]$AdminPassword,
        [SecureString]$RootPassword,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$ConsumerDescription = 'Atlaso workflow'
    )

    if ($env:DEFAULT_ADMIN_PASSWORD -or $env:DEFAULT_ROOT_PASSWORD) {
        throw 'DEFAULT_ADMIN_PASSWORD and DEFAULT_ROOT_PASSWORD must not be supplied by the caller; use the exact Atlaso 1Password Environment bridge.'
    }
    if (-not (Get-Command Invoke-AtlasoBoundedProcess -ErrorAction SilentlyContinue)) {
        throw 'The bounded Atlaso process runner is unavailable.'
    }
    $bridgeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "atlaso-onepassword-credentials-$([guid]::NewGuid().ToString('N'))"
    )
    [void][System.IO.Directory]::CreateDirectory($bridgeRoot)
    $failure = $null
    $result = $null
    try {
        $requestPath = Join-Path $bridgeRoot 'request.json'
        $statusPath = Join-Path $bridgeRoot 'status.json'
        $credentialBundlePath = Join-Path $bridgeRoot 'credentials.dpapi.json'
        $needsDefaults = $null -eq $AdminPassword -or $null -eq $RootPassword
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

        $resolvedPython = ''
        $dependencyPath = ''
        if ($needsDefaults) {
            Assert-AtlasoOnePasswordEnvironmentId -EnvironmentId $EnvironmentId
            Assert-AtlasoOnePasswordAccount -Account $OnePasswordAccount
            if ([string]::IsNullOrWhiteSpace($OnePasswordPython)) {
                throw 'OnePasswordPython is required when an Atlaso credential is omitted.'
            }
            $resolvedPython = Resolve-AtlasoOnePasswordPython `
                -PythonCommand $OnePasswordPython `
                -TimeoutSeconds $TimeoutSeconds `
                -ConsumerDescription $ConsumerDescription
            $dependencyPath = Initialize-AtlasoOnePasswordSdkRuntime `
                -PythonCommand $resolvedPython `
                -RepositoryRoot $RepositoryRoot `
                -BridgeRoot $bridgeRoot `
                -TimeoutSeconds $TimeoutSeconds
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
                '-OnePasswordAccount', $OnePasswordAccount,
                '-EnvironmentId', $EnvironmentId
            )
        }
        Invoke-AtlasoBoundedProcess `
            -FilePath (Get-Process -Id $PID).Path `
            -ArgumentList $arguments `
            -TimeoutSeconds $TimeoutSeconds `
            -Action "The bounded $ConsumerDescription credential preparation child" | Out-Null
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
    }

    try {
        Remove-AtlasoOnePasswordCredentialBridge -BridgeRoot $bridgeRoot
    }
    catch {
        if ($failure) {
            throw "$($failure.Exception.Message) Credential bridge cleanup also failed: $($_.Exception.Message)"
        }
        throw
    }
    if ($failure) {
        throw $failure
    }
    return $result
}

Export-ModuleMember -Function @(
    'Resolve-AtlasoOnePasswordEnvironmentId',
    'Assert-AtlasoOnePasswordEnvironmentId',
    'Assert-AtlasoOnePasswordAccount',
    'Resolve-AtlasoOnePasswordPython',
    'Initialize-AtlasoOnePasswordSdkRuntime',
    'Get-AtlasoOnePasswordCredentialBridgeError',
    'Remove-AtlasoOnePasswordCredentialBridge',
    'Get-AtlasoOnePasswordCredentialPair'
)
