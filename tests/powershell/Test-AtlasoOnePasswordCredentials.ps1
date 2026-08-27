<#
.SYNOPSIS
Exercise the shared Atlaso 1Password credential bridge without live secrets.

.DESCRIPTION
Validates explicit SecureString round trips, policy rejection, independent
omission handling, caller-environment rejection, and bridge cleanup.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    '',
    Justification = 'Focused test constructs fixed synthetic values and never handles real credentials.'
)]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.OnePasswordCredentials.psm1') -Force
$initialBridgeRoots = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory |
    Where-Object { $_.Name -like 'atlaso-onepassword-credentials-*' } |
    ForEach-Object { $_.FullName })

$adminText = 'unit-admin-credential-123!'
$rootText = 'unit-root-credential-456!'
$adminPassword = ConvertTo-SecureString $adminText -AsPlainText -Force
$rootPassword = ConvertTo-SecureString $rootText -AsPlainText -Force
$pair = Get-AtlasoOnePasswordCredentialPair `
    -RepositoryRoot $repositoryRoot `
    -AdminPassword $adminPassword `
    -RootPassword $rootPassword `
    -TimeoutSeconds 30 `
    -ConsumerDescription 'focused test'
try {
    if ((ConvertFrom-SecureString $pair.AdminPassword -AsPlainText) -cne $adminText) {
        throw 'The administrator SecureString did not round trip exactly.'
    }
    if ((ConvertFrom-SecureString $pair.RootPassword -AsPlainText) -cne $rootText) {
        throw 'The root SecureString did not round trip exactly.'
    }
}
finally {
    $adminText = $null
    $rootText = $null
    $pair = $null
}

$shortPassword = ConvertTo-SecureString 'too-short' -AsPlainText -Force
try {
    Get-AtlasoOnePasswordCredentialPair `
        -RepositoryRoot $repositoryRoot `
        -AdminPassword $adminPassword `
        -RootPassword $shortPassword `
        -TimeoutSeconds 30 `
        -ConsumerDescription 'focused test' | Out-Null
    throw 'A policy-invalid explicit credential was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*explicit root password does not satisfy*') {
        throw
    }
}

try {
    Get-AtlasoOnePasswordCredentialPair `
        -RepositoryRoot $repositoryRoot `
        -AdminPassword $adminPassword `
        -RootPassword $null `
        -TimeoutSeconds 30 `
        -ConsumerDescription 'focused test' | Out-Null
    throw 'An omitted credential was accepted without the exact Environment.'
}
catch {
    if ($_.Exception.Message -notlike 'OnePasswordEnvironmentId is required*') {
        throw
    }
}

$previousAdminEnvironment = $env:DEFAULT_ADMIN_PASSWORD
$previousRootEnvironment = $env:DEFAULT_ROOT_PASSWORD
try {
    $env:DEFAULT_ADMIN_PASSWORD = 'caller-admin-must-not-be-used'
    $env:DEFAULT_ROOT_PASSWORD = 'caller-root-must-not-be-used'
    try {
        Get-AtlasoOnePasswordCredentialPair `
            -RepositoryRoot $repositoryRoot `
            -AdminPassword $adminPassword `
            -RootPassword $rootPassword `
            -TimeoutSeconds 30 `
            -ConsumerDescription 'focused test' | Out-Null
        throw 'Caller credential environment variables were accepted.'
    }
    catch {
        if ($_.Exception.Message -notlike 'DEFAULT_ADMIN_PASSWORD and DEFAULT_ROOT_PASSWORD must not be supplied*') {
            throw
        }
    }
}
finally {
    $env:DEFAULT_ADMIN_PASSWORD = $previousAdminEnvironment
    $env:DEFAULT_ROOT_PASSWORD = $previousRootEnvironment
}

$newBridgeRoots = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory |
    Where-Object {
        $_.Name -like 'atlaso-onepassword-credentials-*' -and
        $_.FullName -notin $initialBridgeRoots
    })
if ($newBridgeRoots.Count -ne 0) {
    throw 'A focused credential bridge test left a task-created temporary root.'
}

Write-Host 'Shared Atlaso 1Password credential bridge tests passed.'
