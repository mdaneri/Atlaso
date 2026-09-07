<#
.SYNOPSIS
Exercise Hyper-V disk admission, ZIP limits, and streaming archive compatibility.
.PARAMETER RepositoryRoot
Atlaso checkout containing the exporter module.
.PARAMETER IncludeLargeFiles
Also round-trip a compressible member larger than 4 GiB through ZIP64 and Expand-Archive.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [switch]$IncludeLargeFiles
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $RepositoryRoot 'scripts/windows/virtualization/Atlaso.VirtualizationArtifacts.psm1'
Import-Module $modulePath -Force
$module = Get-Module Atlaso.VirtualizationArtifacts
$fixtureRoot = Join-Path $RepositoryRoot ('test-results/hyperv-packaging-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

<#
.SYNOPSIS
Require an action to throw the specified diagnostic.
.PARAMETER Action
Operation expected to fail.
.PARAMETER Pattern
Wildcard matching the required exception message.
#>
function Assert-PackagingFailure {
    param([scriptblock]$Action, [string]$Pattern)
    try { & $Action }
    catch {
        if ($_.Exception.Message -notlike $Pattern) { throw }
        return
    }
    throw "Expected failure matching: $Pattern"
}

try {
    # Model byte boundaries without allocating multi-GiB files in routine CI.
    & $module {
        $script:FixtureLength = [long]1
        $script:FixtureInfo = '{"format":"vhdx","virtual-size":42949672960}'
        $script:InfoCalls = 0
        <#
        .SYNOPSIS
        Supply an ordinary generated-file observation with a controlled length.
        .PARAMETER LiteralPath
        Fixture identity used by the validator.
        .PARAMETER Force
        Accept the production file inspection switch.
        #>
        function script:Get-Item {
            [CmdletBinding()]
            param([string]$LiteralPath, [switch]$Force)
            [pscustomobject]@{
                Name = 'fixture.vhdx'; FullName = $LiteralPath
                Length = $script:FixtureLength; PSIsContainer = $false
                Attributes = [IO.FileAttributes]::Normal
            }
        }
        <#
        .SYNOPSIS
        Supply controlled qemu inspection output without invoking an executable.
        .PARAMETER QemuImgPath
        Unused converter identity accepted by the production interface.
        .PARAMETER Arguments
        Unused inspection arguments accepted by the production interface.
        #>
        function script:Invoke-AtlasoQemuImg {
            param([string]$QemuImgPath, [string[]]$Arguments)
            $script:InfoCalls++
            $script:FixtureInfo
        }
    }
    foreach ($length in @([long]1, [long]2147483647, [long]2147483648, [long]2147483649)) {
        $module.SessionState.PSVariable.Set('FixtureLength', $length)
        Assert-AtlasoGeneratedVhdx -QemuImgPath unused -Path fixture -VirtualSizeBytes 42949672960
    }
    $module.SessionState.PSVariable.Set('FixtureLength', [long]0)
    $callsBefore = $module.SessionState.PSVariable.GetValue('InfoCalls')
    Assert-PackagingFailure {
        Assert-AtlasoGeneratedVhdx -QemuImgPath unused -Path fixture -VirtualSizeBytes 42949672960
    } '*empty*file_bytes=0*'
    if ($module.SessionState.PSVariable.GetValue('InfoCalls') -ne $callsBefore) { throw 'Empty disk invoked qemu.' }
    $module.SessionState.PSVariable.Set('FixtureLength', [long]1)
    foreach ($json in @('{"format":"qcow2","virtual-size":42949672960}', '{"format":"vhdx","virtual-size":1024}')) {
        $module.SessionState.PSVariable.Set('FixtureInfo', $json)
        Assert-PackagingFailure {
            Assert-AtlasoGeneratedVhdx -QemuImgPath unused -Path fixture -VirtualSizeBytes 42949672960
        } '*does not match*'
    }
    $module.SessionState.PSVariable.Set('FixtureInfo', 'invalid-json')
    Assert-PackagingFailure {
        Assert-AtlasoGeneratedVhdx -QemuImgPath unused -Path fixture -VirtualSizeBytes 42949672960
    } '*invalid JSON*'
    foreach ($length in @([long]0, [long]1, [long]2147483647, [long]2147483648, [long]2147483649)) {
        $module.SessionState.PSVariable.Set('FixtureLength', $length)
        if ($length -eq 0) {
            Assert-PackagingFailure { Assert-AtlasoHyperVArchiveSize -Path fixture } '*empty*archive_bytes=0*'
        }
        elseif ($length -ge 2147483648) {
            Assert-PackagingFailure { Assert-AtlasoHyperVArchiveSize -Path fixture } "*archive_bytes=$length*limit_bytes=2147483648*"
        }
        else { Assert-AtlasoHyperVArchiveSize -Path fixture }
    }
    # Discard the module-scoped mocks before exercising real filesystem operations.
    Remove-Module Atlaso.VirtualizationArtifacts -Force
    Import-Module $modulePath -Force
    $module = Get-Module Atlaso.VirtualizationArtifacts
    $member = Join-Path $fixtureRoot 'member.bin'
    [byte[]]$bytes = [byte[]]::new(8192)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    [IO.File]::WriteAllBytes($member, $bytes)
    $archive = Join-Path $fixtureRoot 'package.zip'
    New-AtlasoHyperVArchive -Files @($member) -DestinationPath $archive
    $originalHash = (Get-FileHash -LiteralPath $archive).Hash
    Assert-PackagingFailure { New-AtlasoHyperVArchive -Files @($member) -DestinationPath $archive } '*already exists*'
    if ((Get-FileHash -LiteralPath $archive).Hash -ne $originalHash) { throw 'Existing ZIP was overwritten.' }
    $duplicateArchive = Join-Path $fixtureRoot 'duplicate.zip'
    Assert-PackagingFailure {
        New-AtlasoHyperVArchive -Files @($member, $member) -DestinationPath $duplicateArchive
    } '*unique names*'
    if (Test-Path -LiteralPath $duplicateArchive) { throw 'Duplicate names created an archive.' }
    $expanded = Join-Path $fixtureRoot 'expanded'
    Expand-Archive -LiteralPath $archive -DestinationPath $expanded
    if ((Get-FileHash -LiteralPath $member).Hash -ne (Get-FileHash -LiteralPath (Join-Path $expanded 'member.bin')).Hash) {
        throw 'ZIP round-trip changed member bytes or root layout.'
    }
    # A bounded incompressible fixture proves the real writer enforces its final gate.
    $module.SessionState.PSVariable.Set('MaximumGitHubAssetBytes', [long]1024)
    try {
        Assert-PackagingFailure {
            New-AtlasoHyperVArchive -Files @($member) -DestinationPath (Join-Path $fixtureRoot 'oversized.zip')
        } '*exceeds the release asset limit*limit_bytes=1024*'
    }
    finally { $module.SessionState.PSVariable.Set('MaximumGitHubAssetBytes', [long]2147483648) }

    $module.SessionState.PSVariable.Set('MaximumHyperVExpandedBytes', [long]8192)
    try {
        New-AtlasoHyperVArchive -Files @($member) -DestinationPath (Join-Path $fixtureRoot 'exact-budget.zip')
        $module.SessionState.PSVariable.Set('MaximumHyperVExpandedBytes', [long]8191)
        $overBudget = Join-Path $fixtureRoot 'over-budget.zip'
        Assert-PackagingFailure {
            New-AtlasoHyperVArchive -Files @($member) -DestinationPath $overBudget
        } '*extraction budget*uncompressed_bytes=8192*limit_bytes=8191*'
        if (Test-Path -LiteralPath $overBudget) { throw 'Exceeded extraction budget created a ZIP.' }
    }
    finally { $module.SessionState.PSVariable.Set('MaximumHyperVExpandedBytes', [long]8589934592) }

    if ($IncludeLargeFiles) {
        $largeFile = Join-Path $fixtureRoot 'large.bin'
        $stream = [IO.File]::Open($largeFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $stream.SetLength([long]4294967297)
            $stream.WriteByte(42)
            $stream.Position = [long]4294967296
            $stream.WriteByte(99)
        }
        finally { $stream.Dispose() }
        $largeArchive = Join-Path $fixtureRoot 'large.zip'
        New-AtlasoHyperVArchive -Files @($largeFile) -DestinationPath $largeArchive
        $zip = [IO.Compression.ZipFile]::OpenRead($largeArchive)
        try {
            if ($zip.Entries.Count -ne 1 -or $zip.GetEntry('large.bin').Length -ne [long]4294967297) {
                throw 'ZIP64 member length or inventory changed.'
            }
        }
        finally { $zip.Dispose() }
        $largeExpanded = Join-Path $fixtureRoot 'large-expanded'
        Expand-Archive -LiteralPath $largeArchive -DestinationPath $largeExpanded
        if ((Get-FileHash -LiteralPath $largeFile).Hash -ne
            (Get-FileHash -LiteralPath (Join-Path $largeExpanded 'large.bin')).Hash) {
            throw 'ZIP64 extraction changed the large member bytes.'
        }
        Write-Host 'ZIP64 round-trip passed for 4294967297 bytes with the 2 GiB archive limit intact.'
    }
}
finally {
    Remove-Module Atlaso.VirtualizationArtifacts -Force
    Import-Module $modulePath -Force
    # Only the unique directory created by this test is eligible for removal.
    $allowedPrefix = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'test-results')) + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($fixtureRoot).StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture cleanup escaped test-results.'
    }
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
Write-Host 'Hyper-V packaging regression tests passed.'
