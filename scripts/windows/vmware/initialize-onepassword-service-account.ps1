<#
.SYNOPSIS
Store the Atlaso 1Password service-account token as current-user DPAPI ciphertext.

.DESCRIPTION
Prompts without echo when Token is omitted, validates the bounded 1Password
service-account token contract without displaying the value, and atomically
writes only current-user DPAPI ciphertext. The file ACL is restricted to the
current Windows user and SYSTEM with inherited access disabled.

.PARAMETER Token
Optional service-account token supplied as a SecureString. When omitted, the
script prompts without echo.

.PARAMETER TokenFile
Optional exact destination. The default is the Git-ignored
.atlaso-local/onepassword-service-account-token.dpapi file in this checkout.

.PARAMETER Force
Explicitly authorize replacing an existing safe token file during rotation.

.EXAMPLE
./scripts/windows/vmware/initialize-onepassword-service-account.ps1

.EXAMPLE
./scripts/windows/vmware/initialize-onepassword-service-account.ps1 -Force
#>
[CmdletBinding()]
param(
    [SecureString]$Token,
    [AllowEmptyString()][string]$TokenFile = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1'
Import-Module $modulePath -Force

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
    throw 'The Atlaso 1Password service-account token file requires Windows current-user DPAPI.'
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$resolvedTokenFile = if ([string]::IsNullOrWhiteSpace($TokenFile)) {
    Join-Path $repositoryRoot '.atlaso-local\onepassword-service-account-token.dpapi'
}
else {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TokenFile)
}
$parentPath = [System.IO.Path]::GetDirectoryName($resolvedTokenFile)
if ([string]::IsNullOrWhiteSpace($parentPath)) {
    throw 'The 1Password service-account token destination must have a parent directory.'
}

if (Test-Path -LiteralPath $resolvedTokenFile) {
    $existingItem = Get-Item -LiteralPath $resolvedTokenFile -Force
    if (-not $existingItem.PSIsContainer -and
        ($existingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
        $null = Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $resolvedTokenFile
    }
    else {
        throw 'The existing 1Password service-account token path is not a safe regular file.'
    }
    if (-not $Force) {
        throw 'The 1Password service-account token file already exists. Pass -Force to rotate it.'
    }
}

if (Test-Path -LiteralPath $parentPath) {
    $parentItem = Get-Item -LiteralPath $parentPath -Force
    if (-not $parentItem.PSIsContainer -or
        ($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The 1Password service-account token parent must be a regular local directory.'
    }
}
else {
    [void][System.IO.Directory]::CreateDirectory($parentPath)
}

if ($null -eq $Token) {
    $Token = Read-Host -Prompt '1Password service-account token' -AsSecureString
}
if ($Token.Length -lt 84 -or $Token.Length -gt 8192) {
    throw 'The 1Password service-account token has an invalid format.'
}

$tokenText = $null
$temporaryPath = Join-Path $parentPath (
    ".onepassword-service-account-token.$([guid]::NewGuid().ToString('N')).tmp"
)
try {
    $tokenText = ConvertFrom-SecureString -SecureString $Token -AsPlainText
    if ($tokenText -notmatch '^ops_[A-Za-z0-9_-]{80,8188}$') {
        throw 'The 1Password service-account token has an invalid format.'
    }
    $ciphertext = ConvertFrom-SecureString -SecureString $Token
    [System.IO.File]::WriteAllText(
        $temporaryPath,
        $ciphertext,
        [System.Text.UTF8Encoding]::new($false)
    )

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = $currentIdentity.User
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($currentSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($currentSid, $systemSid)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $temporaryPath -AclObject $acl

    [System.IO.File]::Move($temporaryPath, $resolvedTokenFile, [bool]$Force)
    $null = Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $resolvedTokenFile
    Write-Output "Stored current-user DPAPI ciphertext at $resolvedTokenFile"
}
finally {
    $tokenText = $null
    $ciphertext = $null
    if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
        [System.IO.File]::Delete($temporaryPath)
    }
}
