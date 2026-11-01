<#
.SYNOPSIS
Publish immutable task-bound selectors for development ISO refresh runs.
.DESCRIPTION
Receipt documents preserve the original VM and boot selector objects returned
by the canonical VMware harness. Publication is bounded, pinned and no-overwrite.
#>

# Reuse an existing caller import: forcing a nested reload removes the caller's
# cleanup commands before the installer can stop and verify its original VM.
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1')

<#
.SYNOPSIS
Validate and pin an existing durable receipt directory for this ISO test.
.PARAMETER ReceiptDirectory
Existing directory beneath the independently configured Codex worktree root.
.PARAMETER Worktree
Exact task worktree that must remain outside the durable directory.
.PARAMETER OutputDirectory
VM artifact directory that must remain outside the durable directory.
#>
function Assert-AtlasoInstallationRefreshReceiptDirectory {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][string]$ReceiptDirectory,
        [Parameter(Mandatory)][string]$Worktree,
        [Parameter(Mandatory)][string]$OutputDirectory
    )

    if (-not [IO.Path]::IsPathFullyQualified($ReceiptDirectory) -or
        -not (Test-Path -LiteralPath $ReceiptDirectory -PathType Container)) {
        throw 'ReceiptDirectory must be an existing absolute ordinary directory.'
    }
    if (-not (Get-Command Get-AtlasoLifecycleDurableRoot -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Atlaso.LifecycleOwnership.ps1')
    }
    $configuredRoot = [IO.Path]::GetFullPath((Get-AtlasoLifecycleDurableRoot)).TrimEnd('\', '/')
    $rootPrefix = $configuredRoot + [IO.Path]::DirectorySeparatorChar
    $directory = [IO.Path]::GetFullPath($ReceiptDirectory).TrimEnd('\', '/')
    $worktree = [IO.Path]::GetFullPath($Worktree).TrimEnd('\', '/')
    $output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
    $directoryPrefix = $directory + [IO.Path]::DirectorySeparatorChar
    $worktreePrefix = $worktree + [IO.Path]::DirectorySeparatorChar
    $outputPrefix = $output + [IO.Path]::DirectorySeparatorChar
    if (-not $directory.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $directory.Equals($worktree, [StringComparison]::OrdinalIgnoreCase) -or
        $directory.StartsWith($worktreePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $worktree.StartsWith($directoryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $directory.Equals($output, [StringComparison]::OrdinalIgnoreCase) -or
        $directory.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $output.StartsWith($directoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ReceiptDirectory must be beneath the configured durable root and outside the task worktree and VM output directory.'
    }
    $rootPin = $null
    $directoryPin = $null
    try {
        $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($configuredRoot, $true)
        $directoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($directory, $true)
        [pscustomobject]@{
            Path = $directory
            Root = $configuredRoot
            RootIdentity = [Atlaso.WorkstationFileIdentity]::Get($configuredRoot)
            DirectoryIdentity = [Atlaso.WorkstationFileIdentity]::Get($directory)
        }
    }
    finally {
        if ($directoryPin) { $directoryPin.Dispose() }
        if ($rootPin) { $rootPin.Dispose() }
    }
}

<#
.SYNOPSIS
Publish one immutable bounded selector document beside its durable receipt root.
.PARAMETER Directory
Previously validated durable directory identity.
.PARAMETER Filename
Fixed selector filename.
.PARAMETER Record
Non-secret task, source, media and canonical returned selector data.
#>
function Publish-AtlasoInstallationRefreshSelector {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][psobject]$Directory,
        [Parameter(Mandatory)][ValidateSet('vm-original-selectors.json', 'vm-selectors.json', 'boot-selectors.json')][string]$Filename,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Record
    )

    $path = Join-Path ([string]$Directory.Path) $Filename
    $parentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([string]$Directory.Path, $true)
    $writer = $null
    try {
        if ([Atlaso.WorkstationFileIdentity]::Get([string]$Directory.Root) -cne [string]$Directory.RootIdentity -or
            [Atlaso.WorkstationFileIdentity]::Get([string]$Directory.Path) -cne [string]$Directory.DirectoryIdentity) {
            throw 'Durable receipt directory identity changed before selector publication.'
        }
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 8 -Compress) + "`n")
        if ($bytes.Length -gt 65536) { throw 'Installation selector document exceeds its bounded size.' }
        $stagePath = Join-Path ([string]$Directory.Path) ('.atlaso-installation-selector-' + [guid]::NewGuid().ToString('N') + '.pending')
        $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stagePath)
        $writer.Write($bytes, 0, $bytes.Length)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $path, $false)
        $writer.Dispose()
        $writer = $null
        $readbackPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true)
        try {
            $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            $expected = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            if ($digest -cne $expected) { throw 'Durable selector readback differs from its published bytes.' }
        }
        finally { $readbackPin.Dispose() }
        [pscustomobject]@{ Path = $path; Sha256 = $expected }
    }
    catch {
        if ($writer) { $writer.Dispose(); $writer = $null }
        throw
    }
    finally {
        if ($writer) { $writer.Dispose() }
        $parentPin.Dispose()
    }
}

Export-ModuleMember -Function Assert-AtlasoInstallationRefreshReceiptDirectory, Publish-AtlasoInstallationRefreshSelector
