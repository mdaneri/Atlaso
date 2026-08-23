<#
.SYNOPSIS
Exercise the VMware Workstation first-boot public-key helpers.

.PARAMETER RepositoryRoot
Atlaso checkout containing the helper under test.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')

<#
.SYNOPSIS
Assert that two scalar test values are equal.

.PARAMETER Actual
Value produced by the helper under test.

.PARAMETER Expected
Required value.

.PARAMETER Message
Failure context shown when the values differ.
#>
function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected', received '$Actual'."
    }
}

<#
.SYNOPSIS
Assert that one test action terminates with an error.

.PARAMETER Action
Action expected to throw.

.PARAMETER Message
Failure context shown when the action does not throw.
#>
function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Message
    )

    try {
        & $Action
    }
    catch {
        return
    }
    throw $Message
}

$validKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f atlaso&test'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-workstation-key-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $keyPath = Join-Path $temporaryRoot 'id_ed25519.pub'
    [System.IO.File]::WriteAllText($keyPath, "$validKey`r`n", [System.Text.UTF8Encoding]::new($false))
    $resolved = Resolve-AtlasoWorkstationAdminSshPublicKey -Path $keyPath
    Assert-Equal $resolved.PublicKey $validKey 'The public key resolver must preserve one normalized Ed25519 key.'
    Assert-Equal $resolved.Path (Resolve-Path -LiteralPath $keyPath).Path 'The public key resolver must return the exact path.'

    $withoutKey = New-AtlasoWorkstationOvfEnvironment `
        -Fqdn 'atlaso-test.atlaso.internal' `
        -AdminPassword 'VMware01!Test' `
        -RootPassword 'VMware01!Test'
    if ($withoutKey.Contains('development_admin_ssh_public_key', [System.StringComparison]::Ordinal)) {
        throw 'Ordinary Workstation OVF input must not contain the development administrator key property.'
    }

    $withKey = New-AtlasoWorkstationOvfEnvironment `
        -Fqdn 'atlaso-test.atlaso.internal' `
        -AdminPassword 'VMware01!Test' `
        -RootPassword 'VMware01!Test' `
        -DevelopmentAdminSshPublicKey $validKey
    if (-not $withKey.Contains("oe:key='atlaso.development_admin_ssh_public_key'", [System.StringComparison]::Ordinal)) {
        throw 'The test-VM OVF input must contain the development administrator key property.'
    }
    if (-not $withKey.Contains('atlaso&amp;test', [System.StringComparison]::Ordinal)) {
        throw 'The test-VM public-key comment must remain XML escaped.'
    }

    Assert-Throws { Assert-AtlasoWorkstationEd25519PublicKey -PublicKey 'ssh-rsa invalid' } 'Non-Ed25519 keys must fail.'
    Assert-Throws { Assert-AtlasoWorkstationEd25519PublicKey -PublicKey "$validKey`nsecond" } 'Multiline keys must fail.'
    Assert-Throws { Resolve-AtlasoWorkstationAdminSshPublicKey -Path (Join-Path $temporaryRoot 'missing.pub') } 'Missing key files must fail.'
}
finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Atlaso Workstation first-boot public-key tests passed.'
