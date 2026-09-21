<#
.SYNOPSIS
Exercises checksum-bound ISO cache reuse without downloading an ISO.
.PARAMETER RepositoryRoot
Exact checkout containing the capacity module.
.PARAMETER TaskStateRoot
Owned fixture parent; callers can select a permitted validation root.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [string]$TaskStateRoot = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path 'test-results')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/virtualization/Atlaso.VirtualizationCapacity.psm1') -Force
$module = Get-Module Atlaso.VirtualizationCapacity
& $module {
    Set-Item function:script:Get-AtlasoStorageVolume -Value {
        param($Path)
        [pscustomobject]@{ VolumeId='fixture'; Path=$Path }
    }
}
$fixture = Join-Path $TaskStateRoot ('iso-capacity-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path (Join-Path $fixture 'scripts/windows/vmware')
$null = New-Item -ItemType Directory -Path (Join-Path $fixture 'image/common/source')
$iso = Join-Path $fixture 'image/common/source/fixture.iso'
$builder = Join-Path $fixture 'scripts/windows/vmware/build-photon-image.ps1'
try {
    [IO.File]::WriteAllText($iso, 'verified-iso-bytes')
    $checksum = (Get-FileHash -LiteralPath $iso -Algorithm SHA512).Hash
    $defaults = 'param([string]$IsoUrl = ''https://example.invalid/fixture.iso'', [string]$IsoChecksum = ''sha512:' + $checksum + ''')'
    [IO.File]::WriteAllText($builder, $defaults)
    if (-not (Test-AtlasoVirtualizationIsoCache -RepoRoot $fixture)) { throw 'Verified ISO was not reused.' }
    [IO.File]::WriteAllText($iso, 'tampered-iso-bytes')
    if (Test-AtlasoVirtualizationIsoCache -RepoRoot $fixture) { throw 'Unverified ISO received a capacity credit.' }
    if ([IO.File]::ReadAllText($iso) -cne 'tampered-iso-bytes') { throw 'Read-only capacity verification changed the ISO.' }
    Remove-Item -LiteralPath $iso
    if (Test-AtlasoVirtualizationIsoCache -RepoRoot $fixture) { throw 'Missing ISO received a capacity credit.' }
    [IO.File]::WriteAllText($builder, ($defaults -replace 'sha512:', 'unsupported:'))
    try {
        $null = Test-AtlasoVirtualizationIsoCache -RepoRoot $fixture
        throw 'Unknown checksum scheme was accepted.'
    } catch {
        if ($_.Exception.Message -cne 'Canonical ISO checksum is unsupported.') { throw }
    }
} finally {
    # This test owns only the fresh GUID fixture, never the caller's parent root.
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
Write-Host 'Verified ISO cache capacity tests passed.'
