<#
.SYNOPSIS
Fail-closed VMware Workstation artifact cleanup primitives for Atlaso.

.DESCRIPTION
This module validates canonical paths and Windows filesystem identities before it
removes VMware build or lifecycle artifacts. Running state comes from the checked
vmrun command surface. Registration state comes from stable, structurally complete
Workstation inventory snapshots. Current Workstation releases do not expose an
unregister-only automation command, so a registered target is removed with checked
vmrun deleteVM only after every fail-closed preflight succeeds.

The final deletion gate repeats both inventories around filesystem discovery. Any
missing, malformed, changing, or unverifiable preflight state preserves the root,
except an exact canonical missing registration below the validated cleanup scope.
With the Workstation UI closed, cleanup atomically removes those stale library rows.

.NOTES
Keep this module self-contained for the Windows image-build and lifecycle scripts.
Do not weaken the exact-root, non-reparse-point, stable-inventory, or file-identity
checks when adding another cleanup entry point.
#>

Set-StrictMode -Version Latest

# Native helpers bind path checks and inventory entries to Windows file identity.

if (-not ('Atlaso.WorkstationFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Atlaso
{
    public static class WorkstationFileIdentity
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

        public static string Get(string path)
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

                return String.Format(
                    "{0:X8}:{1:X8}{2:X8}",
                    information.VolumeSerialNumber,
                    information.FileIndexHigh,
                    information.FileIndexLow
                );
            }
        }
    }
}
'@
}

# Path admission and identity helpers deliberately precede every VMware state
# transition. Later inventory checks rely on these canonical identities rather
# than path spelling alone, including hard-link aliases.

function Get-AtlasoCanonicalPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPath = [System.IO.Path]::GetPathRoot($fullPath)
    if ($rootPath -and $fullPath.Equals($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $rootPath
    }
    return $fullPath.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}

function Test-AtlasoSamePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,
        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    $leftPath = Get-AtlasoCanonicalPath -Path $Left
    $rightPath = Get-AtlasoCanonicalPath -Path $Right
    return $leftPath.Equals($rightPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-AtlasoStrictDescendantPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParentPath,
        [Parameter(Mandatory = $true)]
        [string]$ChildPath
    )

    $resolvedParent = Get-AtlasoCanonicalPath -Path $ParentPath
    $resolvedChild = Get-AtlasoCanonicalPath -Path $ChildPath
    $relativePath = [System.IO.Path]::GetRelativePath($resolvedParent, $resolvedChild)
    if ($relativePath -eq '.' -or [System.IO.Path]::IsPathRooted($relativePath)) {
        return $false
    }

    $parentToken = '..'
    return -not (
        $relativePath.Equals($parentToken, [System.StringComparison]::OrdinalIgnoreCase) -or
        $relativePath.StartsWith(
            $parentToken + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        $relativePath.StartsWith(
            $parentToken + [System.IO.Path]::AltDirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    )
}

function Assert-AtlasoPathHasNoReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $currentPath = Get-AtlasoCanonicalPath -Path $Path
    while ($currentPath) {
        if (Test-Path -LiteralPath $currentPath) {
            $item = Get-Item -LiteralPath $currentPath -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing recursive VMware cleanup through reparse point: $currentPath"
            }
        }

        $parentPath = Split-Path -Parent $currentPath
        if (-not $parentPath -or (Test-AtlasoSamePath -Left $currentPath -Right $parentPath)) {
            break
        }
        $currentPath = $parentPath
    }
}

function Assert-AtlasoStrictDescendantPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParentPath,
        [Parameter(Mandatory = $true)]
        [string]$ChildPath,
        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    if (-not (Test-AtlasoStrictDescendantPath -ParentPath $ParentPath -ChildPath $ChildPath)) {
        throw "$FailureMessage`: $ChildPath"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $ParentPath
    Assert-AtlasoPathHasNoReparsePoint -Path $ChildPath
}

function Invoke-AtlasoVmrunChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Action
    )

    $output = @(& $VmrunPath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $detail = ($output | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) -join ' '
        if ($detail) {
            throw "$Action failed with exit code $exitCode. vmrun output: $detail"
        }
        throw "$Action failed with exit code $exitCode."
    }
    return $output
}

function Get-AtlasoVmxFileIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$InventoryDescription
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$InventoryDescription contains a VMX path whose filesystem identity cannot be resolved; refusing filesystem cleanup: $Path"
    }
    try {
        return [Atlaso.WorkstationFileIdentity]::Get($Path)
    }
    catch {
        throw "$InventoryDescription contains a VMX path whose filesystem identity cannot be resolved; refusing filesystem cleanup: $Path"
    }
}

function Get-AtlasoVmxDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $displayNameLines = @(
        Get-Content -LiteralPath $Path -ErrorAction Stop |
            Where-Object { $_ -match '^\s*displayName\b' }
    )
    if ($displayNameLines.Count -ne 1) {
        throw "Refusing VMware cleanup because the VMX must contain exactly one displayName assignment: $Path"
    }
    if ($displayNameLines[0] -notmatch '^\s*displayName\s*=\s*"([^"\r\n]+)"\s*$') {
        throw "Refusing VMware cleanup because the VMX displayName assignment is malformed: $Path"
    }
    return $Matches[1]
}

function Resolve-AtlasoVerifiedVmxInventoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$InventoryDescription,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AllowMissingUnderRoot = ''
    )

    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) {
        throw "$InventoryDescription contains a non-absolute VMX path; refusing filesystem cleanup: $Path"
    }
    if (-not [System.IO.Path]::GetExtension($Path).Equals('.vmx', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$InventoryDescription contains a non-VMX path; refusing filesystem cleanup: $Path"
    }

    $canonicalPath = Get-AtlasoCanonicalPath -Path $Path
    if (-not $Path.Equals($canonicalPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$InventoryDescription contains a non-canonical VMX path; refusing filesystem cleanup: $Path"
    }
    if (-not (Test-Path -LiteralPath $canonicalPath -PathType Leaf)) {
        if (
            $AllowMissingUnderRoot -and
            (Test-AtlasoStrictDescendantPath -ParentPath $AllowMissingUnderRoot -ChildPath $canonicalPath)
        ) {
            Assert-AtlasoPathHasNoReparsePoint -Path $AllowMissingUnderRoot
            Assert-AtlasoPathHasNoReparsePoint -Path $canonicalPath
            return $canonicalPath
        }
    }
    Get-AtlasoVmxFileIdentity -Path $canonicalPath -InventoryDescription $InventoryDescription | Out-Null
    return $canonicalPath
}

function Get-AtlasoWorkstationInventoryPathToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$InventoryDescription
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return "identity|$(Get-AtlasoVmxFileIdentity -Path $Path -InventoryDescription $InventoryDescription)"
    }
    return "missing|$($Path.ToUpperInvariant())"
}

function ConvertFrom-AtlasoVmrunInventoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$InventoryLine
    )

    $candidate = $InventoryLine.Trim()
    if (-not $candidate) {
        return $null
    }
    if ($candidate.Contains('"')) {
        if ($candidate -notmatch '^"([^\"]+)"$') {
            throw 'vmrun running-VM inventory contains an unbalanced or embedded quote; refusing filesystem cleanup.'
        }
        return $Matches[1]
    }
    return $candidate
}

function Get-AtlasoWorkstationVmPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $false)]
        [ValidateSet('running')]
        [string]$State = 'running'
    )

    $output = @(Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'list') `
            -Action 'List running VMware Workstation VMs')
    if ($output.Count -lt 1 -or $output[0].ToString() -notmatch '^Total running VMs:\s*(\d+)\s*$') {
        throw 'vmrun list returned an unrecognized running-VM inventory; refusing filesystem cleanup.'
    }

    $declaredCount = [int]$Matches[1]
    $reportedPaths = @(
        $output |
            Select-Object -Skip 1 |
            ForEach-Object { ConvertFrom-AtlasoVmrunInventoryPath -InventoryLine $_.ToString() } |
            Where-Object { $_ }
    )
    if ($reportedPaths.Count -ne $declaredCount) {
        throw "vmrun list reported $declaredCount VMs but returned $($reportedPaths.Count) paths; refusing filesystem cleanup."
    }
    $paths = @(
        $reportedPaths | ForEach-Object {
            Resolve-AtlasoVerifiedVmxInventoryPath `
                -Path $_ `
                -InventoryDescription 'vmrun running-VM inventory'
        }
    )
    $fileIdentities = @(
        $paths | ForEach-Object {
            Get-AtlasoVmxFileIdentity -Path $_ -InventoryDescription 'vmrun running-VM inventory'
        }
    )
    $uniqueFileIdentities = @($fileIdentities | Select-Object -Unique)
    if ($uniqueFileIdentities.Count -ne $paths.Count) {
        throw 'vmrun running-VM inventory contains duplicate VMX paths; refusing filesystem cleanup.'
    }
    return $paths
}

# Workstation does not expose registered-VM enumeration through vmrun. Treat its
# inventory as a safety-critical database: require a stable file identity, stable
# bytes, complete mirrored config/index records, and resolvable VMX identities.
function Resolve-AtlasoWorkstationInventoryPath {
    if (-not $env:APPDATA) {
        throw 'APPDATA is unavailable; refusing cleanup because VMware Workstation registration state cannot be verified.'
    }
    $inventoryPath = Join-Path $env:APPDATA 'VMware\inventory.vmls'
    if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
        throw "VMware Workstation inventory was not found; refusing cleanup because registration state cannot be verified: $inventoryPath"
    }
    return (Resolve-Path -LiteralPath $inventoryPath).Path
}

function Get-AtlasoWorkstationInventorySnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath
    )

    $before = Get-Item -LiteralPath $InventoryPath -Force -ErrorAction Stop
    $identityBefore = [Atlaso.WorkstationFileIdentity]::Get($InventoryPath)
    $content = [string](Get-Content -LiteralPath $InventoryPath -ErrorAction Stop -Raw)
    $identityAfter = [Atlaso.WorkstationFileIdentity]::Get($InventoryPath)
    $after = Get-Item -LiteralPath $InventoryPath -Force -ErrorAction Stop
    if (
        $identityBefore -ne $identityAfter -or
        $before.Length -ne $after.Length -or
        $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks
    ) {
        throw "VMware Workstation registration inventory changed during verification; refusing filesystem cleanup: $InventoryPath"
    }
    return [pscustomobject]@{
        Content = $content
        Identity = $identityAfter
        Length = $after.Length
        LastWriteTimeUtcTicks = $after.LastWriteTimeUtc.Ticks
    }
}

function Assert-AtlasoWorkstationInventorySnapshotsEqual {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$First,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Second,
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath
    )

    if (
        $First.Identity -ne $Second.Identity -or
        $First.Length -ne $Second.Length -or
        $First.LastWriteTimeUtcTicks -ne $Second.LastWriteTimeUtcTicks -or
        -not $First.Content.Equals($Second.Content, [System.StringComparison]::Ordinal)
    ) {
        throw "VMware Workstation registration inventory changed during verification; refusing filesystem cleanup: $InventoryPath"
    }
}

function Get-AtlasoStableWorkstationInventoryLines {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath
    )

    $first = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $InventoryPath
    Start-Sleep -Milliseconds 250
    $second = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $InventoryPath
    Assert-AtlasoWorkstationInventorySnapshotsEqual `
        -First $first `
        -Second $second `
        -InventoryPath $InventoryPath
    return @($second.Content -split '\r?\n')
}

function ConvertFrom-AtlasoWorkstationRegisteredVmInventoryLines {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$InventoryLines,
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AllowMissingUnderRoot = ''
    )

    $paths = @()
    $indexPaths = @()
    $indexNumbers = @()
    $declaredIndexCounts = @()
    foreach ($line in $inventoryLines) {
        $assignmentSeparator = $line.IndexOf('=')
        $inventoryKey = if ($assignmentSeparator -ge 0) {
            $line.Substring(0, $assignmentSeparator)
        } else {
            $line
        }

        if ($inventoryKey -match '^\s*vmlist.*config\b') {
            if ($line -notmatch '^\s*vmlist\d+\.config\s*=\s*"(.*)"\s*$') {
                throw "VMware Workstation inventory contains an unrecognized registration entry; refusing filesystem cleanup: $InventoryPath"
            }
            $registeredPath = $Matches[1]
            if ($registeredPath) {
                $paths += Resolve-AtlasoVerifiedVmxInventoryPath `
                    -Path $registeredPath `
                    -InventoryDescription 'VMware Workstation registration inventory' `
                    -AllowMissingUnderRoot $AllowMissingUnderRoot
            }
            continue
        }

        if ($inventoryKey -match '^\s*index\s*\.\s*count\s*$') {
            if ($line -notmatch '^\s*index\.count\s*=\s*"(\d+)"\s*$') {
                throw "VMware Workstation inventory contains an unrecognized index count; refusing filesystem cleanup: $InventoryPath"
            }
            $declaredIndexCounts += [int]$Matches[1]
            continue
        }

        if ($inventoryKey -match '^\s*index\s*\d+\s*\.\s*id\s*$') {
            if ($line -notmatch '^\s*index(\d+)\.id\s*=\s*"(.+)"\s*$') {
                throw "VMware Workstation inventory contains an unrecognized index entry; refusing filesystem cleanup: $InventoryPath"
            }
            $indexNumbers += [int]$Matches[1]
            $indexPaths += Resolve-AtlasoVerifiedVmxInventoryPath `
                -Path $Matches[2] `
                -InventoryDescription 'VMware Workstation registration index' `
                -AllowMissingUnderRoot $AllowMissingUnderRoot
        }
    }
    $pathTokens = @(
        $paths | ForEach-Object {
            Get-AtlasoWorkstationInventoryPathToken `
                -Path $_ `
                -InventoryDescription 'VMware Workstation registration inventory'
        }
    )
    if (@($pathTokens | Select-Object -Unique).Count -ne $paths.Count) {
        throw "VMware Workstation registration inventory contains duplicate VMX paths; refusing filesystem cleanup: $InventoryPath"
    }
    $indexPathTokens = @(
        $indexPaths | ForEach-Object {
            Get-AtlasoWorkstationInventoryPathToken `
                -Path $_ `
                -InventoryDescription 'VMware Workstation registration index'
        }
    )
    if (
        $declaredIndexCounts.Count -ne 1 -or
        $declaredIndexCounts[0] -ne $indexPaths.Count -or
        $paths.Count -ne $indexPaths.Count -or
        @($indexNumbers | Select-Object -Unique).Count -ne $indexNumbers.Count -or
        @($indexPathTokens | Select-Object -Unique).Count -ne $indexPaths.Count
    ) {
        throw "VMware Workstation registration inventory is incomplete or changing; refusing filesystem cleanup: $InventoryPath"
    }
    foreach ($path in $paths) {
        $pathToken = Get-AtlasoWorkstationInventoryPathToken `
            -Path $path `
            -InventoryDescription 'VMware Workstation registration inventory'
        if ($indexPathTokens -notcontains $pathToken) {
            throw "VMware Workstation registration inventory is incomplete or changing; refusing filesystem cleanup: $InventoryPath"
        }
    }
    return $paths
}

function Get-AtlasoWorkstationRegisteredVmPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath
    )

    $inventoryLines = @(Get-AtlasoStableWorkstationInventoryLines -InventoryPath $InventoryPath)
    return @(
        ConvertFrom-AtlasoWorkstationRegisteredVmInventoryLines `
            -InventoryLines $inventoryLines `
            -InventoryPath $InventoryPath
    )
}

function Restore-AtlasoWorkstationInventoryAfterCasFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedCurrentContent,
        [Parameter(Mandatory = $true)]
        [string]$ReplacementPath,
        [Parameter(Mandatory = $true)]
        [string]$ReplacementContent
    )

    # File.Replace captures the exact displaced file. If another writer won the
    # path race, atomically put that captured state back. Repeat when a writer
    # races the rollback itself so no observed provider update is discarded.
    foreach ($attempt in 1..16) {
        $capturedPath = "$InventoryPath.atlaso-cas-$([System.Guid]::NewGuid().ToString('N')).tmp"
        try {
            [System.IO.File]::Replace($ReplacementPath, $InventoryPath, $capturedPath, $true)
        }
        catch {
            $replaceError = $_.Exception.Message
            $recoveryPath = "$InventoryPath.atlaso-recovery-$([System.Guid]::NewGuid().ToString('N')).vmls"
            [System.IO.File]::Move($ReplacementPath, $recoveryPath)
            throw "VMware Workstation inventory rollback failed; the newest captured provider state was preserved for recovery at '$recoveryPath'. Replace error: $replaceError"
        }
        $capturedContent = [System.IO.File]::ReadAllText($capturedPath)
        if ($capturedContent.Equals($ExpectedCurrentContent, [System.StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $capturedPath -Force -ErrorAction Stop
            return
        }

        $ExpectedCurrentContent = $ReplacementContent
        $ReplacementPath = $capturedPath
        $ReplacementContent = $capturedContent
    }

    $recoveryPath = "$InventoryPath.atlaso-recovery-$([System.Guid]::NewGuid().ToString('N')).vmls"
    [System.IO.File]::Move($ReplacementPath, $recoveryPath)
    throw "VMware Workstation inventory changed repeatedly during stale registration rollback; the newest captured provider state was preserved for recovery: $recoveryPath"
}

function Remove-AtlasoWorkstationMissingRegistrations {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$MissingPaths
    )

    if ($MissingPaths.Count -eq 0) {
        return
    }
    $realInventoryPath = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware\inventory.vmls'
    if (
        (Test-AtlasoSamePath -Left $InventoryPath -Right $realInventoryPath) -and
        (Get-Process vmware -ErrorAction SilentlyContinue)
    ) {
        throw 'Close the VMware Workstation UI before removing stale VM library entries.'
    }

    $snapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $InventoryPath
    $lines = @($snapshot.Content -split '\r?\n')
    $targets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($missingPath in $MissingPaths) {
        $targets.Add($missingPath) | Out-Null
    }
    $vmlistIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $presentTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $indexedTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $indexGroups = @{}
    $targetIndexNumbers = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($line in $lines) {
        if ($line -match '^\s*vmlist(?<id>\d+)\.config\s*=\s*"(?<path>.*)"\s*$' -and $targets.Contains($Matches.path)) {
            $vmlistIds.Add($Matches.id) | Out-Null
            $presentTargets.Add($Matches.path) | Out-Null
        }
        if ($line -match '^\s*index(?<number>\d+)(?<suffix>\..*)$') {
            $number = [int]$Matches.number
            if (-not $indexGroups.ContainsKey($number)) {
                $indexGroups[$number] = [System.Collections.Generic.List[string]]::new()
            }
            $indexGroups[$number].Add($line)
            if ($line -match '^\s*index\d+\.id\s*=\s*"(?<path>.+)"\s*$' -and $targets.Contains($Matches.path)) {
                $targetIndexNumbers.Add($number) | Out-Null
                $indexedTargets.Add($Matches.path) | Out-Null
            }
        }
    }
    if ($presentTargets.Count -eq 0 -and $indexedTargets.Count -eq 0) {
        return
    }
    if (
        $vmlistIds.Count -ne $presentTargets.Count -or
        $targetIndexNumbers.Count -ne $indexedTargets.Count -or
        $presentTargets.Count -ne $indexedTargets.Count -or
        @($presentTargets | Where-Object { -not $indexedTargets.Contains($_) }).Count -ne 0
    ) {
        throw 'VMware Workstation inventory changed before stale registration removal; refusing to rewrite it.'
    }

    $updatedLines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -match '^\s*vmlist(?<id>\d+)\.') {
            $lineVmlistId = $Matches.id
            if ($vmlistIds.Contains($lineVmlistId)) {
                if ($line -match '^\s*vmlist\d+\.config\s*=') {
                    $updatedLines.Add("vmlist$lineVmlistId.config = `"`"")
                }
                continue
            }
        }
        if ($line -match '^\s*index(?:\d+\.|\.count)') {
            continue
        }
        $updatedLines.Add($line)
    }
    $newIndex = 0
    foreach ($oldIndex in @($indexGroups.Keys | Sort-Object)) {
        if ($targetIndexNumbers.Contains([int]$oldIndex)) {
            continue
        }
        foreach ($line in $indexGroups[$oldIndex]) {
            $updatedLines.Add(($line -replace '^\s*index\d+', "index$newIndex"))
        }
        $newIndex++
    }
    $updatedLines.Add("index.count = `"$newIndex`"")

    $secondSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $InventoryPath
    Assert-AtlasoWorkstationInventorySnapshotsEqual -First $snapshot -Second $secondSnapshot -InventoryPath $InventoryPath
    $temporaryInventoryPath = "$InventoryPath.atlaso-cleanup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $backupInventoryPath = "$InventoryPath.atlaso-backup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $preserveBackupInventoryPath = $false
    try {
        [System.IO.File]::WriteAllLines($temporaryInventoryPath, $updatedLines, [System.Text.UTF8Encoding]::new($false))
        $replacementContent = [System.IO.File]::ReadAllText($temporaryInventoryPath)
        # Deny writers from the last byte comparison through the atomic replace.
        # ShareDelete permits ReplaceFile to replace the path while this handle
        # continues to protect the verified old file from concurrent mutation.
        $inventoryWriteLock = [System.IO.File]::Open(
            $InventoryPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete)
        )
        try {
            $inventoryReader = [System.IO.StreamReader]::new(
                $inventoryWriteLock,
                [System.Text.UTF8Encoding]::new($false),
                $true,
                1024,
                $true
            )
            try {
                $lockedContent = $inventoryReader.ReadToEnd()
            }
            finally {
                $inventoryReader.Dispose()
            }
            if (-not $snapshot.Content.Equals($lockedContent, [System.StringComparison]::Ordinal)) {
                throw 'VMware Workstation inventory changed before stale registration removal; refusing to rewrite it.'
            }
            [System.IO.File]::Replace($temporaryInventoryPath, $InventoryPath, $backupInventoryPath, $true)
        }
        finally {
            $inventoryWriteLock.Dispose()
        }
        $displacedContent = [System.IO.File]::ReadAllText($backupInventoryPath)
        if (-not $snapshot.Content.Equals($displacedContent, [System.StringComparison]::Ordinal)) {
            $preserveBackupInventoryPath = $true
            Restore-AtlasoWorkstationInventoryAfterCasFailure `
                -InventoryPath $InventoryPath `
                -ExpectedCurrentContent $replacementContent `
                -ReplacementPath $backupInventoryPath `
                -ReplacementContent $displacedContent
            throw 'VMware Workstation inventory was replaced during stale registration removal; the provider state was restored and artifacts were preserved.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryInventoryPath) {
            Remove-Item -LiteralPath $temporaryInventoryPath -Force -ErrorAction SilentlyContinue
        }
        if (-not $preserveBackupInventoryPath -and (Test-Path -LiteralPath $backupInventoryPath)) {
            Remove-Item -LiteralPath $backupInventoryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AtlasoWorkstationVmListed {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Paths,
        [Parameter(Mandatory = $true)]
        [string]$VmxPath
    )

    $targetIdentity = Get-AtlasoVmxFileIdentity -Path $VmxPath -InventoryDescription 'VMware cleanup target'
    foreach ($candidate in $Paths) {
        $candidateIdentity = Get-AtlasoVmxFileIdentity -Path $candidate -InventoryDescription 'VMware Workstation inventory'
        if ($candidateIdentity.Equals($targetIdentity, [System.StringComparison]::Ordinal)) {
            return $true
        }
    }
    return $false
}

function Test-AtlasoWorkstationVmPathSetsEqual {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Left,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Right
    )

    if ($Left.Count -ne $Right.Count) {
        return $false
    }
    foreach ($path in $Left) {
        if (-not (Test-AtlasoWorkstationVmListed -Paths $Right -VmxPath $path)) {
            return $false
        }
    }
    return $true
}

function Assert-AtlasoWorkstationRemovalVmxSet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemovalRoot,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ValidatedVmxPaths
    )

    $discoveredVmxPaths = @(
        Get-ChildItem `
            -LiteralPath $RemovalRoot `
            -Filter '*.vmx' `
            -File `
            -Recurse `
            -Force `
            -ErrorAction Stop |
            ForEach-Object {
                Assert-AtlasoStrictDescendantPath `
                    -ParentPath $RemovalRoot `
                    -ChildPath $_.FullName `
                    -FailureMessage 'Refusing to inspect a VMware VMX outside the exact artifact directory'
                (Resolve-Path -LiteralPath $_.FullName).Path
            }
    )
    $hasUnvalidatedVmx = $discoveredVmxPaths.Count -ne $ValidatedVmxPaths.Count
    if (-not $hasUnvalidatedVmx) {
        foreach ($discoveredVmxPath in $discoveredVmxPaths) {
            if (-not (Test-AtlasoWorkstationVmListed -Paths $ValidatedVmxPaths -VmxPath $discoveredVmxPath)) {
                $hasUnvalidatedVmx = $true
                break
            }
        }
    }
    if ($hasUnvalidatedVmx) {
        throw "Refusing to remove VMware artifacts because the directory contains an unvalidated VMX: $RemovalRoot"
    }
}

function Confirm-AtlasoWorkstationVmInactive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true)]
        [string]$VmxPath
    )

    $runningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    if (Test-AtlasoWorkstationVmListed -Paths $runningPaths -VmxPath $VmxPath) {
        Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'stop', $VmxPath, 'hard') `
            -Action "Stop VMware Workstation VM '$VmxPath'" | Out-Null
        $runningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
        if (Test-AtlasoWorkstationVmListed -Paths $runningPaths -VmxPath $VmxPath) {
            throw "VMware Workstation VM remains running after stop succeeded: $VmxPath"
        }
    }
}

function Disconnect-AtlasoWorkstationExternalVmdks {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmxPath,
        [Parameter(Mandatory = $true)]
        [string]$RemovalRoot
    )

    $vmxDirectory = Split-Path -Parent $VmxPath
    $originalVmxBytes = [System.IO.File]::ReadAllBytes($VmxPath)
    $lines = @([System.IO.File]::ReadAllLines($VmxPath))
    $externalDevices = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($line in $lines) {
        if ($line -notmatch '^\s*(?<device>(?:scsi|sata|ide|nvme)\d+:\d+)\.fileName\s*=') {
            continue
        }
        $device = $Matches.device
        if ($line -notmatch '^\s*(?:scsi|sata|ide|nvme)\d+:\d+\.fileName\s*=\s*"(?<path>[^"\r\n]+)"\s*$') {
            throw "VMware cleanup found a malformed attached-disk path; artifacts were preserved: $VmxPath"
        }
        $configuredPath = $Matches.path
        if (-not [System.IO.Path]::GetExtension($configuredPath).Equals('.vmdk', [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $diskPath = if ([System.IO.Path]::IsPathFullyQualified($configuredPath)) {
            [System.IO.Path]::GetFullPath($configuredPath)
        } else {
            [System.IO.Path]::GetFullPath((Join-Path $vmxDirectory $configuredPath))
        }
        $relativeDiskPath = [System.IO.Path]::GetRelativePath($RemovalRoot, $diskPath)
        $isInsideRemovalRoot = (
            -not [System.IO.Path]::IsPathFullyQualified($relativeDiskPath) -and
            $relativeDiskPath -ne '..' -and
            -not $relativeDiskPath.StartsWith("..$([System.IO.Path]::DirectorySeparatorChar)")
        )
        if (-not $isInsideRemovalRoot) {
            $externalDevices.Add($device) | Out-Null
        } elseif (Test-Path -LiteralPath $diskPath) {
            Assert-AtlasoPathHasNoReparsePoint -Path $diskPath
        }
    }
    if ($externalDevices.Count -eq 0) {
        return
    }

    # deleteVM follows attached virtual disks. Remove every property for an
    # external disk device from the stopped VMX before giving deletion to VMware.
    $protectedLines = @(
        $lines | Where-Object {
            if ($_ -match '^\s*(?<device>(?:scsi|sata|ide|nvme)\d+:\d+)\.') {
                return -not $externalDevices.Contains($Matches.device)
            }
            return $true
        }
    )
    $temporaryVmxPath = "$VmxPath.atlaso-cleanup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllLines(
            $temporaryVmxPath,
            $protectedLines,
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::Move($temporaryVmxPath, $VmxPath, $true)
        return [pscustomobject]@{ OriginalBytes = $originalVmxBytes }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryVmxPath) {
            Remove-Item -LiteralPath $temporaryVmxPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Restore-AtlasoWorkstationDetachedVmdks {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmxPath,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [psobject]$Detachment
    )

    if ($null -eq $Detachment -or -not (Test-Path -LiteralPath $VmxPath -PathType Leaf)) {
        return
    }

    # A provider failure or an unfulfilled success postcondition must leave a
    # surviving VM exactly as it was before external disks were protected.
    $restorePath = "$VmxPath.atlaso-restore-$([System.Guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllBytes($restorePath, $Detachment.OriginalBytes)
        [System.IO.File]::Move($restorePath, $VmxPath, $true)
    }
    finally {
        if (Test-Path -LiteralPath $restorePath) {
            Remove-Item -LiteralPath $restorePath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Whole-root removal is intentionally multi-phase: admit the exact filesystem
# target, reconcile each known VM, stabilize global state, then repeat the state
# and VMX-set checks immediately before recursive deletion.
function Remove-AtlasoWorkstationVmArtifacts {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$VmxPaths,
        [Parameter(Mandatory = $true)]
        [string]$RemovalRoot,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AllowMissingRegistrationsUnderRoot = ''
    )

    $resolvedRemovalRoot = Get-AtlasoCanonicalPath -Path $RemovalRoot
    $resolvedMissingRegistrationRoot = if ($AllowMissingRegistrationsUnderRoot) {
        Get-AtlasoCanonicalPath -Path $AllowMissingRegistrationsUnderRoot
    } else {
        $resolvedRemovalRoot
    }
    if (
        -not (Test-AtlasoSamePath -Left $resolvedMissingRegistrationRoot -Right $resolvedRemovalRoot) -and
        -not (Test-AtlasoStrictDescendantPath `
            -ParentPath $resolvedMissingRegistrationRoot `
            -ChildPath $resolvedRemovalRoot)
    ) {
        throw 'The missing-registration allowance must contain the exact VMware removal root.'
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $resolvedMissingRegistrationRoot
    $inventoryPath = Resolve-AtlasoWorkstationInventoryPath
    $filesystemRoot = [System.IO.Path]::GetPathRoot($resolvedRemovalRoot)
    if (-not $filesystemRoot -or (Test-AtlasoSamePath -Left $resolvedRemovalRoot -Right $filesystemRoot)) {
        throw "Refusing to remove a filesystem root as a VMware artifact directory: $resolvedRemovalRoot"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $resolvedRemovalRoot

    $resolvedVmxPaths = @()
    foreach ($vmxPath in $VmxPaths) {
        $resolvedVmxPath = (Resolve-Path -LiteralPath $vmxPath).Path
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedRemovalRoot `
            -ChildPath $resolvedVmxPath `
            -FailureMessage 'Refusing to remove a VMware VMX outside the exact artifact directory'
        $resolvedVmxPaths += $resolvedVmxPath
    }
    Assert-AtlasoWorkstationRemovalVmxSet `
        -RemovalRoot $resolvedRemovalRoot `
        -ValidatedVmxPaths $resolvedVmxPaths
    if (-not $PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Stop and delete VMware Workstation VM artifacts')) {
        return
    }

    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        Confirm-AtlasoWorkstationVmInactive `
            -VmrunPath $VmrunPath `
            -VmxPath $resolvedVmxPath
    }

    Assert-AtlasoWorkstationRemovalVmxSet `
        -RemovalRoot $resolvedRemovalRoot `
        -ValidatedVmxPaths $resolvedVmxPaths

    $firstRunningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    $firstRegistrationSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $inventoryPath
    Start-Sleep -Milliseconds 250
    $secondRunningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    $secondRegistrationSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $inventoryPath
    Assert-AtlasoWorkstationInventorySnapshotsEqual `
        -First $firstRegistrationSnapshot `
        -Second $secondRegistrationSnapshot `
        -InventoryPath $inventoryPath
    if (-not (Test-AtlasoWorkstationVmPathSetsEqual -Left $firstRunningPaths -Right $secondRunningPaths)) {
        throw 'VMware Workstation running inventory changed during final verification; artifacts were preserved.'
    }

    $finalRootVmxPaths = @(
        Get-ChildItem `
            -LiteralPath $resolvedRemovalRoot `
            -Filter '*.vmx' `
            -File `
            -Recurse `
            -Force `
            -ErrorAction Stop |
            ForEach-Object { (Resolve-Path -LiteralPath $_.FullName -ErrorAction Stop).Path }
    )
    Assert-AtlasoWorkstationRemovalVmxSet `
        -RemovalRoot $resolvedRemovalRoot `
        -ValidatedVmxPaths $resolvedVmxPaths

    $finalRunningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    $finalRegistrationSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $inventoryPath
    Assert-AtlasoWorkstationInventorySnapshotsEqual `
        -First $secondRegistrationSnapshot `
        -Second $finalRegistrationSnapshot `
        -InventoryPath $inventoryPath
    if (-not (Test-AtlasoWorkstationVmPathSetsEqual -Left $secondRunningPaths -Right $finalRunningPaths)) {
        throw 'VMware Workstation running inventory changed during final verification; artifacts were preserved.'
    }
    $finalRegisteredPaths = @(
        ConvertFrom-AtlasoWorkstationRegisteredVmInventoryLines `
            -InventoryLines @($finalRegistrationSnapshot.Content -split '\r?\n') `
            -InventoryPath $inventoryPath `
            -AllowMissingUnderRoot $resolvedMissingRegistrationRoot
    )
    foreach ($finalInventoryPath in $finalRunningPaths) {
        if (
            (Test-AtlasoStrictDescendantPath -ParentPath $resolvedRemovalRoot -ChildPath $finalInventoryPath) -or
            (Test-AtlasoWorkstationVmListed -Paths $finalRootVmxPaths -VmxPath $finalInventoryPath)
        ) {
            throw "A new running VMware VMX appeared before filesystem cleanup; artifacts were preserved: $finalInventoryPath"
        }
    }
    foreach ($finalRegisteredPath in $finalRegisteredPaths) {
        if (
            (Test-AtlasoStrictDescendantPath -ParentPath $resolvedRemovalRoot -ChildPath $finalRegisteredPath) -and
            (Test-Path -LiteralPath $finalRegisteredPath -PathType Leaf) -and
            -not (Test-AtlasoWorkstationVmListed -Paths $resolvedVmxPaths -VmxPath $finalRegisteredPath)
        ) {
            throw "A new registered VMware VMX appeared before filesystem cleanup; artifacts were preserved: $finalRegisteredPath"
        }
    }

    # deleteVM is the only supported non-interactive Workstation command that
    # removes a registered local VM. Run it only after every fail-closed preflight;
    # it performs the provider-owned registration and file deletion transition.
    $existingFinalRegisteredPaths = @(
        $finalRegisteredPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    )
    $registeredTargetPaths = @()
    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        $matchingRegisteredPaths = @(
            $existingFinalRegisteredPaths | Where-Object {
                Test-AtlasoWorkstationVmListed -Paths @($_) -VmxPath $resolvedVmxPath
            }
        )
        if ($matchingRegisteredPaths.Count -eq 0) {
            continue
        }
        if (
            @($matchingRegisteredPaths | Where-Object {
                    Test-AtlasoSamePath -Left $_ -Right $resolvedVmxPath
                }).Count -ne 1
        ) {
            throw "VMware Workstation registered the cleanup target through a filesystem alias; artifacts were preserved: $resolvedVmxPath"
        }
        $registeredTargetPaths += $resolvedVmxPath
    }
    foreach ($registeredTargetPath in $registeredTargetPaths) {
        $externalDiskDetachment = Disconnect-AtlasoWorkstationExternalVmdks `
            -VmxPath $registeredTargetPath `
            -RemovalRoot $resolvedRemovalRoot
        try {
            Invoke-AtlasoVmrunChecked `
                -VmrunPath $VmrunPath `
                -Arguments @('-T', 'ws', 'deleteVM', $registeredTargetPath) `
                -Action "Delete VMware Workstation VM '$registeredTargetPath'" | Out-Null
        }
        catch {
            Restore-AtlasoWorkstationDetachedVmdks `
                -VmxPath $registeredTargetPath `
                -Detachment $externalDiskDetachment
            throw
        }
        if (Test-Path -LiteralPath $registeredTargetPath) {
            Restore-AtlasoWorkstationDetachedVmdks `
                -VmxPath $registeredTargetPath `
                -Detachment $externalDiskDetachment
            throw "VMware Workstation VMX remains after deleteVM succeeded: $registeredTargetPath"
        }
    }

    $missingFinalRegisteredPaths = @(
        $finalRegisteredPaths | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }
    )
    Remove-AtlasoWorkstationMissingRegistrations `
        -InventoryPath $inventoryPath `
        -MissingPaths $missingFinalRegisteredPaths

    # Provider deletion can take long enough for another build to populate the
    # same output root. Re-read stable registration state and then admit only
    # the still-existing members of the original VMX set immediately before the
    # recursive filesystem operation.
    $postDeleteRegistrationFirstSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $inventoryPath
    Start-Sleep -Milliseconds 250
    $postDeleteRegistrationSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $inventoryPath
    Assert-AtlasoWorkstationInventorySnapshotsEqual `
        -First $postDeleteRegistrationFirstSnapshot `
        -Second $postDeleteRegistrationSnapshot `
        -InventoryPath $inventoryPath
    $postDeleteRegisteredPaths = @(
        ConvertFrom-AtlasoWorkstationRegisteredVmInventoryLines `
            -InventoryLines @($postDeleteRegistrationSnapshot.Content -split '\r?\n') `
            -InventoryPath $inventoryPath `
            -AllowMissingUnderRoot $resolvedMissingRegistrationRoot
    )
    $postDeleteValidatedVmxPaths = @(
        $resolvedVmxPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    )
    Assert-AtlasoWorkstationRemovalVmxSet `
        -RemovalRoot $resolvedRemovalRoot `
        -ValidatedVmxPaths $postDeleteValidatedVmxPaths
    foreach ($postDeleteRegisteredPath in $postDeleteRegisteredPaths) {
        if (
            (Test-AtlasoStrictDescendantPath -ParentPath $resolvedRemovalRoot -ChildPath $postDeleteRegisteredPath) -or
            (
                (Test-Path -LiteralPath $postDeleteRegisteredPath -PathType Leaf) -and
                (Test-AtlasoWorkstationVmListed `
                    -Paths $postDeleteValidatedVmxPaths `
                    -VmxPath $postDeleteRegisteredPath)
            )
        ) {
            throw "A VMware Workstation VM became registered before filesystem cleanup; artifacts were preserved: $postDeleteRegisteredPath"
        }
    }

    # Keep the checked running inventory last: registration stabilization waits
    # long enough for an unregistered target to start without changing the
    # provider inventory. Match aliases by file identity as well as root path.
    $postDeleteRunningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    foreach ($postDeleteRunningPath in $postDeleteRunningPaths) {
        if (
            (Test-AtlasoStrictDescendantPath -ParentPath $resolvedRemovalRoot -ChildPath $postDeleteRunningPath) -or
            (
                $postDeleteValidatedVmxPaths.Count -gt 0 -and
                (Test-AtlasoWorkstationVmListed `
                    -Paths $postDeleteValidatedVmxPaths `
                    -VmxPath $postDeleteRunningPath)
            )
        ) {
            throw "A VMware Workstation VM remains running after deleteVM succeeded: $postDeleteRunningPath"
        }
    }

    $postRunningRegistrationFirstSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $inventoryPath
    Assert-AtlasoWorkstationInventorySnapshotsEqual `
        -First $postDeleteRegistrationSnapshot `
        -Second $postRunningRegistrationFirstSnapshot `
        -InventoryPath $inventoryPath
    Assert-AtlasoWorkstationRemovalVmxSet `
        -RemovalRoot $resolvedRemovalRoot `
        -ValidatedVmxPaths $postDeleteValidatedVmxPaths
    $postRunningRegistrationSecondSnapshot = Get-AtlasoWorkstationInventorySnapshot -InventoryPath $inventoryPath
    Assert-AtlasoWorkstationInventorySnapshotsEqual `
        -First $postRunningRegistrationFirstSnapshot `
        -Second $postRunningRegistrationSecondSnapshot `
        -InventoryPath $inventoryPath

    if (Test-Path -LiteralPath $resolvedRemovalRoot) {
        Remove-Item -LiteralPath $resolvedRemovalRoot -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $resolvedRemovalRoot) {
        throw "VMware artifact directory remains after recursive cleanup; refusing to report success: $resolvedRemovalRoot"
    }
}

function Remove-AtlasoWorkstationArtifactRoot {
    [CmdletBinding(DefaultParameterSetName = 'CanonicalParent', SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'CanonicalParent')]
        [string]$ArtifactParentRoot,
        [Parameter(Mandatory = $true, ParameterSetName = 'ExactConfiguredRoot')]
        [string]$ExpectedRemovalRoot,
        [Parameter(Mandatory = $true)]
        [string]$RemovalRoot
    )

    if ($null -eq (Get-Item -LiteralPath $RemovalRoot -Force -ErrorAction SilentlyContinue)) {
        return
    }
    if (-not (Test-Path -LiteralPath $RemovalRoot -PathType Container)) {
        throw "VMware artifact target exists but is not a directory; refusing to report cleanup success: $RemovalRoot"
    }

    $resolvedRemovalRoot = (Resolve-Path -LiteralPath $RemovalRoot -ErrorAction Stop).Path
    if ($PSCmdlet.ParameterSetName -eq 'ExactConfiguredRoot') {
        $resolvedExpectedRoot = (Resolve-Path -LiteralPath $ExpectedRemovalRoot -ErrorAction Stop).Path
        if (-not (Test-AtlasoSamePath -Left $resolvedExpectedRoot -Right $resolvedRemovalRoot)) {
            throw 'Refusing to remove a VMware artifact directory other than the exact configured output root'
        }
        $missingRegistrationRoot = $resolvedRemovalRoot
    } else {
        $resolvedParentRoot = (Resolve-Path -LiteralPath $ArtifactParentRoot -ErrorAction Stop).Path
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedParentRoot `
            -ChildPath $resolvedRemovalRoot `
            -FailureMessage 'Refusing to remove a VMware artifact directory outside the canonical parent root'
        $missingRegistrationRoot = $resolvedParentRoot
    }
    $vmxPaths = @(
        Get-ChildItem `
            -LiteralPath $resolvedRemovalRoot `
            -Filter '*.vmx' `
            -File `
            -Recurse `
            -Force `
            -ErrorAction Stop |
            ForEach-Object { $_.FullName }
    )

    if ($PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Verify VMware VM state and remove artifact root')) {
        Remove-AtlasoWorkstationVmArtifacts `
            -VmrunPath $VmrunPath `
            -VmxPaths $vmxPaths `
            -RemovalRoot $resolvedRemovalRoot `
            -AllowMissingRegistrationsUnderRoot $missingRegistrationRoot `
            -Confirm:$false
    }
}

Export-ModuleMember -Function @(
    'Assert-AtlasoStrictDescendantPath',
    'Get-AtlasoVmxDisplayName',
    'Remove-AtlasoWorkstationArtifactRoot',
    'Remove-AtlasoWorkstationVmArtifacts',
    'Test-AtlasoStrictDescendantPath'
)
