<#
.SYNOPSIS
Root-scoped VMware Workstation artifact cleanup primitives for Atlaso.

.DESCRIPTION
Cleanup is authoritative only for an explicitly validated Atlaso artifact root.
It discovers VMX files below that root, stops running targets, protects attached
VMDKs outside the root, removes registered targets through checked vmrun deleteVM,
and deletes the remaining root. Unrelated VMware library entries are not cleanup
prerequisites.

The Workstation inventory is consulted only to decide whether an existing target
needs deleteVM and to remove stale registrations for missing VMX files in the
approved Atlaso scope. That narrow fallback leaves unrelated registration records
unchanged and does not require them to resolve.
#>

Set-StrictMode -Version Latest

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
        private const uint BackupSemantics = 0x02000000;

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
                BackupSemantics,
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

function Get-AtlasoCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

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
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    return (Get-AtlasoCanonicalPath -Path $Left).Equals(
        (Get-AtlasoCanonicalPath -Path $Right),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Test-AtlasoStrictDescendantPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ParentPath,
        [Parameter(Mandatory = $true)][string]$ChildPath
    )

    $relativePath = [System.IO.Path]::GetRelativePath(
        (Get-AtlasoCanonicalPath -Path $ParentPath),
        (Get-AtlasoCanonicalPath -Path $ChildPath)
    )
    if ($relativePath -eq '.' -or [System.IO.Path]::IsPathRooted($relativePath)) {
        return $false
    }
    return -not (
        $relativePath.Equals('..', [System.StringComparison]::OrdinalIgnoreCase) -or
        $relativePath.StartsWith("..$([System.IO.Path]::DirectorySeparatorChar)") -or
        $relativePath.StartsWith("..$([System.IO.Path]::AltDirectorySeparatorChar)")
    )
}

function Assert-AtlasoPathHasNoReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    $currentPath = Get-AtlasoCanonicalPath -Path $Path
    while ($currentPath) {
        $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing recursive VMware cleanup through reparse point: $currentPath"
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
        [Parameter(Mandatory = $true)][string]$ParentPath,
        [Parameter(Mandatory = $true)][string]$ChildPath,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    if (-not (Test-AtlasoStrictDescendantPath -ParentPath $ParentPath -ChildPath $ChildPath)) {
        throw "$FailureMessage`: $ChildPath"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $ParentPath
    Assert-AtlasoPathHasNoReparsePoint -Path $ChildPath
}

function Get-AtlasoPathIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($null -eq (Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        throw "$Description no longer exists; artifacts were preserved: $Path"
    }
    try {
        return [Atlaso.WorkstationFileIdentity]::Get($Path)
    }
    catch {
        throw "$Description filesystem identity cannot be resolved; artifacts were preserved: $Path"
    }
}

function Get-AtlasoFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}

function Invoke-AtlasoVmrunChecked {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Action
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

function Get-AtlasoVmxDisplayName {
    param([Parameter(Mandatory = $true)][string]$Path)

    $displayNameLines = @(Get-Content -LiteralPath $Path -ErrorAction Stop | Where-Object { $_ -match '^\s*displayName\b' })
    if ($displayNameLines.Count -ne 1) {
        throw "Refusing VMware cleanup because the VMX must contain exactly one displayName assignment: $Path"
    }
    if ($displayNameLines[0] -notmatch '^\s*displayName\s*=\s*"([^"\r\n]+)"\s*$') {
        throw "Refusing VMware cleanup because the VMX displayName assignment is malformed: $Path"
    }
    return $Matches[1]
}

function ConvertFrom-AtlasoVmrunInventoryPath {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$InventoryLine)

    $candidate = $InventoryLine.Trim()
    if (-not $candidate) {
        return $null
    }
    if ($candidate.StartsWith('"') -and $candidate.EndsWith('"') -and $candidate.Length -ge 2) {
        return $candidate.Substring(1, $candidate.Length - 2)
    }
    return $candidate
}

function Get-AtlasoWorkstationVmPaths {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $false)]
        [ValidateSet('running')]
        [string]$State = 'running'
    )

    $output = @(Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'list') `
            -Action 'List running VMware Workstation VMs')
    if ($output.Count -lt 1 -or $output[0].ToString() -notmatch '^Total running VMs:\s*(\d+)\s*$') {
        throw 'vmrun list returned an unrecognized running-VM inventory; artifacts were preserved.'
    }
    $declaredCount = [int]$Matches[1]
    $reportedPaths = @(
        $output | Select-Object -Skip 1 | ForEach-Object {
            ConvertFrom-AtlasoVmrunInventoryPath -InventoryLine $_.ToString()
        } | Where-Object { $_ }
    )
    if ($reportedPaths.Count -ne $declaredCount) {
        throw "vmrun list reported $declaredCount VMs but returned $($reportedPaths.Count) paths; artifacts were preserved."
    }
    return $reportedPaths
}

function Resolve-AtlasoWorkstationInventoryPath {
    $inventoryPath = Join-Path $env:APPDATA 'VMware\inventory.vmls'
    if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
        return $null
    }
    return (Resolve-Path -LiteralPath $inventoryPath -ErrorAction Stop).Path
}

function Get-AtlasoScopedInventoryEntries {
    param(
        [Parameter(Mandatory = $true)][string]$InventoryPath,
        [Parameter(Mandatory = $true)][string]$ScopeRoot
    )

    $entries = @()
    foreach ($line in Get-Content -LiteralPath $InventoryPath -ErrorAction Stop) {
        if ($line -notmatch '^\s*vmlist(?<id>\d+)\.config\s*=\s*"(?<path>.*)"\s*$') {
            continue
        }
        $candidate = $Matches.path
        if (-not $candidate -or -not [System.IO.Path]::IsPathFullyQualified($candidate)) {
            continue
        }
        $canonicalPath = Get-AtlasoCanonicalPath -Path $candidate
        if (
            (Test-AtlasoSamePath -Left $canonicalPath -Right $ScopeRoot) -or
            (Test-AtlasoStrictDescendantPath -ParentPath $ScopeRoot -ChildPath $canonicalPath)
        ) {
            $entries += [pscustomobject]@{
                Id = $Matches.id
                Path = $canonicalPath
                Exists = [bool](Test-Path -LiteralPath $canonicalPath -PathType Leaf)
            }
        }
    }
    return $entries
}

function Test-AtlasoWorkstationVmxRegistered {
    param(
        [Parameter(Mandatory = $false)][AllowNull()][string]$InventoryPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$ScopeRoot
    )

    if (-not $InventoryPath) {
        return $false
    }
    return @(
        Get-AtlasoScopedInventoryEntries -InventoryPath $InventoryPath -ScopeRoot $ScopeRoot |
            Where-Object { Test-AtlasoSamePath -Left $_.Path -Right $VmxPath }
    ).Count -gt 0
}

function Remove-AtlasoWorkstationStaleRegistrations {
    param(
        [Parameter(Mandatory = $false)][AllowNull()][string]$InventoryPath,
        [Parameter(Mandatory = $true)][string]$ScopeRoot
    )

    if (-not $InventoryPath) {
        return
    }
    $staleEntries = @(
        Get-AtlasoScopedInventoryEntries -InventoryPath $InventoryPath -ScopeRoot $ScopeRoot |
            Where-Object { -not $_.Exists }
    )
    if ($staleEntries.Count -eq 0) {
        return
    }

    $realInventoryPath = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware\inventory.vmls'
    if (
        (Test-AtlasoSamePath -Left $InventoryPath -Right $realInventoryPath) -and
        (Get-Process vmware -ErrorAction SilentlyContinue)
    ) {
        throw 'Close the VMware Workstation UI before removing stale Atlaso VM library entries.'
    }

    $originalBytes = [System.IO.File]::ReadAllBytes($InventoryPath)
    $lines = @([System.Text.Encoding]::UTF8.GetString($originalBytes) -split '\r?\n')
    $targetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $targetPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $staleEntries) {
        $targetIds.Add($entry.Id) | Out-Null
        $targetPaths.Add($entry.Path) | Out-Null
    }

    $targetIndexes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $lines) {
        if ($line -match '^\s*index(?<index>\d+)\.id\s*=\s*"(?<path>.*)"\s*$') {
            $candidate = $Matches.path
            if ([System.IO.Path]::IsPathFullyQualified($candidate)) {
                $canonicalPath = Get-AtlasoCanonicalPath -Path $candidate
                if ($targetPaths.Contains($canonicalPath)) {
                    $targetIndexes.Add($Matches.index) | Out-Null
                }
            }
        }
    }

    $updatedLines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -match '^\s*vmlist(?<id>\d+)\.' -and $targetIds.Contains($Matches.id)) {
            continue
        }
        if ($line -match '^\s*index(?<index>\d+)\.' -and $targetIndexes.Contains($Matches.index)) {
            continue
        }
        if ($line -match '^\s*index\.count\s*=\s*"(?<count>\d+)"\s*$') {
            $updatedLines.Add("index.count = `"$([Math]::Max(0, [int]$Matches.count - $targetIndexes.Count))`"")
            continue
        }
        $updatedLines.Add($line)
    }
    $replacementBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($updatedLines -join [Environment]::NewLine))

    foreach ($entry in $staleEntries) {
        if (Test-Path -LiteralPath $entry.Path -PathType Leaf) {
            throw "A stale Atlaso VMX was recreated before inventory repair; artifacts were preserved: $($entry.Path)"
        }
    }
    if (-not [System.Linq.Enumerable]::SequenceEqual($originalBytes, [System.IO.File]::ReadAllBytes($InventoryPath))) {
        throw 'VMware Workstation inventory changed before scoped stale-registration repair; artifacts were preserved.'
    }

    $temporaryPath = "$InventoryPath.atlaso-cleanup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$InventoryPath.atlaso-backup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllBytes($temporaryPath, $replacementBytes)
        [System.IO.File]::Replace($temporaryPath, $InventoryPath, $backupPath, $true)
        if (-not [System.Linq.Enumerable]::SequenceEqual(
                $originalBytes,
                [System.IO.File]::ReadAllBytes($backupPath)
            )) {
            $displacedRepairPath = "$InventoryPath.atlaso-repair-$([System.Guid]::NewGuid().ToString('N')).tmp"
            try {
                [System.IO.File]::Replace($backupPath, $InventoryPath, $displacedRepairPath, $true)
            }
            finally {
                Remove-Item -LiteralPath $displacedRepairPath -Force -ErrorAction SilentlyContinue
            }
            throw 'VMware Workstation inventory was replaced during scoped stale-registration repair.'
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-AtlasoRootSnapshot {
    param([Parameter(Mandatory = $true)][string]$RemovalRoot)

    $items = @{}
    foreach ($item in Get-ChildItem -LiteralPath $RemovalRoot -Force -Recurse -ErrorAction Stop) {
        Assert-AtlasoPathHasNoReparsePoint -Path $item.FullName
        $relativePath = [System.IO.Path]::GetRelativePath($RemovalRoot, $item.FullName)
        $items[$relativePath] = Get-AtlasoPathIdentity -Path $item.FullName -Description 'VMware artifact entry'
    }
    return [pscustomobject]@{
        RootIdentity = Get-AtlasoPathIdentity -Path $RemovalRoot -Description 'VMware artifact root'
        Items = $items
    }
}

function Assert-AtlasoRootSnapshotUnreplaced {
    param(
        [Parameter(Mandatory = $true)][string]$RemovalRoot,
        [Parameter(Mandatory = $true)][psobject]$Snapshot
    )

    $rootIdentity = Get-AtlasoPathIdentity -Path $RemovalRoot -Description 'VMware artifact root'
    if ($rootIdentity -ne $Snapshot.RootIdentity) {
        throw "VMware artifact root was replaced during cleanup; the replacement was preserved: $RemovalRoot"
    }
    foreach ($item in Get-ChildItem -LiteralPath $RemovalRoot -Force -Recurse -ErrorAction Stop) {
        Assert-AtlasoPathHasNoReparsePoint -Path $item.FullName
        $relativePath = [System.IO.Path]::GetRelativePath($RemovalRoot, $item.FullName)
        if (-not $Snapshot.Items.ContainsKey($relativePath)) {
            throw "A new VMware artifact appeared during cleanup; the root was preserved: $($item.FullName)"
        }
        $identity = Get-AtlasoPathIdentity -Path $item.FullName -Description 'VMware artifact entry'
        if ($identity -ne $Snapshot.Items[$relativePath]) {
            throw "A VMware artifact was replaced during cleanup; the replacement was preserved: $($item.FullName)"
        }
    }
}

function Test-AtlasoRunningPathMatchesTarget {
    param(
        [Parameter(Mandatory = $true)][string]$RunningPath,
        [Parameter(Mandatory = $true)][string]$VmxPath
    )

    if (-not [System.IO.Path]::IsPathFullyQualified($RunningPath)) {
        return $false
    }
    return Test-AtlasoSamePath -Left $RunningPath -Right $VmxPath
}

function Confirm-AtlasoWorkstationVmInactive {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath
    )

    $runningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    if (@($runningPaths | Where-Object { Test-AtlasoRunningPathMatchesTarget -RunningPath $_ -VmxPath $VmxPath }).Count -gt 0) {
        Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'stop', $VmxPath, 'hard') `
            -Action "Stop VMware Workstation VM '$VmxPath'" | Out-Null
    }
    $remainingPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    if (@($remainingPaths | Where-Object { Test-AtlasoRunningPathMatchesTarget -RunningPath $_ -VmxPath $VmxPath }).Count -gt 0) {
        throw "VMware Workstation VM remains running after stop succeeded: $VmxPath"
    }
}

function Disconnect-AtlasoWorkstationExternalVmdks {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$RemovalRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedIdentity
    )

    if ((Get-AtlasoPathIdentity -Path $VmxPath -Description 'VMware cleanup target') -ne $ExpectedIdentity) {
        throw "VMware Workstation VMX was replaced before external-disk protection; artifacts were preserved: $VmxPath"
    }
    $originalBytes = [System.IO.File]::ReadAllBytes($VmxPath)
    $lines = @([System.Text.Encoding]::UTF8.GetString($originalBytes) -split '\r?\n')
    $externalDevices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $vmxDirectory = Split-Path -Parent $VmxPath
    foreach ($line in $lines) {
        if (
            $line -match '^\s*(?:scsi|sata|ide|nvme)\d+:\d+\.fileName\s*=' -and
            $line -notmatch '^\s*(?<device>(?:scsi|sata|ide|nvme)\d+:\d+)\.fileName\s*=\s*"(?<path>[^"\r\n]+)"\s*$'
        ) {
            throw "VMware cleanup found a malformed attached-disk path; artifacts were preserved: $VmxPath"
        }
        if ($line -notmatch '^\s*(?<device>(?:scsi|sata|ide|nvme)\d+:\d+)\.fileName\s*=\s*"(?<path>[^"\r\n]+)"\s*$') {
            continue
        }
        $configuredPath = $Matches.path
        if (-not [System.IO.Path]::GetExtension($configuredPath).Equals('.vmdk', [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $diskPath = if ([System.IO.Path]::IsPathFullyQualified($configuredPath)) {
            Get-AtlasoCanonicalPath -Path $configuredPath
        } else {
            Get-AtlasoCanonicalPath -Path (Join-Path $vmxDirectory $configuredPath)
        }
        if (-not (Test-AtlasoStrictDescendantPath -ParentPath $RemovalRoot -ChildPath $diskPath)) {
            $externalDevices.Add($Matches.device) | Out-Null
        } elseif (Test-Path -LiteralPath $diskPath) {
            Assert-AtlasoPathHasNoReparsePoint -Path $diskPath
        }
    }
    if ($externalDevices.Count -eq 0) {
        return $null
    }

    $protectedLines = @($lines | Where-Object {
            if ($_ -match '^\s*(?<device>(?:scsi|sata|ide|nvme)\d+:\d+)\.') {
                return -not $externalDevices.Contains($Matches.device)
            }
            return $true
        })
    $protectedBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($protectedLines -join [Environment]::NewLine))
    [System.IO.File]::WriteAllBytes($VmxPath, $protectedBytes)
    if (
        (Get-AtlasoPathIdentity -Path $VmxPath -Description 'VMware cleanup target') -ne $ExpectedIdentity -or
        (Get-AtlasoFileSha256 -Path $VmxPath) -ne ([System.BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::HashData($protectedBytes)
            ).Replace('-', ''))
    ) {
        throw "VMware Workstation VMX changed during external-disk protection; artifacts were preserved: $VmxPath"
    }
    return [pscustomobject]@{
        Identity = $ExpectedIdentity
        OriginalBytes = $originalBytes
        ProtectedHash = Get-AtlasoFileSha256 -Path $VmxPath
    }
}

function Restore-AtlasoWorkstationExternalVmdks {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $false)][AllowNull()][psobject]$Detachment
    )

    if ($null -eq $Detachment -or -not (Test-Path -LiteralPath $VmxPath -PathType Leaf)) {
        return
    }
    if (
        (Get-AtlasoPathIdentity -Path $VmxPath -Description 'detached VMware cleanup target') -ne $Detachment.Identity -or
        (Get-AtlasoFileSha256 -Path $VmxPath) -ne $Detachment.ProtectedHash
    ) {
        throw "VMware Workstation VMX was replaced while deleteVM was running; the replacement was preserved: $VmxPath"
    }
    [System.IO.File]::WriteAllBytes($VmxPath, $Detachment.OriginalBytes)
}

function Remove-AtlasoWorkstationVmArtifacts {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$VmxPaths,
        [Parameter(Mandatory = $true)][string]$RemovalRoot,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$AllowMissingRegistrationsUnderRoot = ''
    )

    $resolvedRemovalRoot = Get-AtlasoCanonicalPath -Path $RemovalRoot
    $filesystemRoot = [System.IO.Path]::GetPathRoot($resolvedRemovalRoot)
    if (-not $filesystemRoot -or (Test-AtlasoSamePath -Left $resolvedRemovalRoot -Right $filesystemRoot)) {
        throw "Refusing to remove a filesystem root as a VMware artifact directory: $resolvedRemovalRoot"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $resolvedRemovalRoot
    $staleScope = if ($AllowMissingRegistrationsUnderRoot) {
        Get-AtlasoCanonicalPath -Path $AllowMissingRegistrationsUnderRoot
    } else {
        $resolvedRemovalRoot
    }
    if (
        -not (Test-AtlasoSamePath -Left $staleScope -Right $resolvedRemovalRoot) -and
        -not (Test-AtlasoStrictDescendantPath -ParentPath $staleScope -ChildPath $resolvedRemovalRoot)
    ) {
        throw 'The missing-registration scope must contain the exact VMware removal root.'
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $staleScope

    $resolvedVmxPaths = @($VmxPaths | ForEach-Object {
            $resolvedVmxPath = (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path
            Assert-AtlasoStrictDescendantPath `
                -ParentPath $resolvedRemovalRoot `
                -ChildPath $resolvedVmxPath `
                -FailureMessage 'Refusing to remove a VMware VMX outside the exact artifact directory'
            $resolvedVmxPath
        })
    $discoveredVmxPaths = @(
        Get-ChildItem -LiteralPath $resolvedRemovalRoot -Filter '*.vmx' -File -Recurse -Force -ErrorAction Stop |
            ForEach-Object { (Resolve-Path -LiteralPath $_.FullName -ErrorAction Stop).Path }
    )
    $expectedSet = @($resolvedVmxPaths | Sort-Object -Unique)
    $discoveredSet = @($discoveredVmxPaths | Sort-Object -Unique)
    if (@(Compare-Object -ReferenceObject $expectedSet -DifferenceObject $discoveredSet).Count -ne 0) {
        throw 'VMware artifact root contains an unvalidated VMX; artifacts were preserved.'
    }
    if (-not $PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Stop and delete VMware Workstation VM artifacts')) {
        return
    }

    $snapshot = Get-AtlasoRootSnapshot -RemovalRoot $resolvedRemovalRoot
    $inventoryPath = Resolve-AtlasoWorkstationInventoryPath
    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        $targetIdentity = Get-AtlasoPathIdentity -Path $resolvedVmxPath -Description 'VMware cleanup target'
        Confirm-AtlasoWorkstationVmInactive -VmrunPath $VmrunPath -VmxPath $resolvedVmxPath
        if (-not (Test-AtlasoWorkstationVmxRegistered `
                -InventoryPath $inventoryPath `
                -VmxPath $resolvedVmxPath `
                -ScopeRoot $resolvedRemovalRoot)) {
            continue
        }
        if ((Get-AtlasoPathIdentity -Path $resolvedVmxPath -Description 'VMware cleanup target') -ne $targetIdentity) {
            throw "VMware Workstation VMX was replaced before deleteVM; artifacts were preserved: $resolvedVmxPath"
        }
        $detachment = Disconnect-AtlasoWorkstationExternalVmdks `
            -VmxPath $resolvedVmxPath `
            -RemovalRoot $resolvedRemovalRoot `
            -ExpectedIdentity $targetIdentity
        try {
            Invoke-AtlasoVmrunChecked `
                -VmrunPath $VmrunPath `
                -Arguments @('-T', 'ws', 'deleteVM', $resolvedVmxPath) `
                -Action "Delete VMware Workstation VM '$resolvedVmxPath'" | Out-Null
        }
        catch {
            Restore-AtlasoWorkstationExternalVmdks -VmxPath $resolvedVmxPath -Detachment $detachment
            throw
        }
        if (Test-Path -LiteralPath $resolvedVmxPath) {
            Restore-AtlasoWorkstationExternalVmdks -VmxPath $resolvedVmxPath -Detachment $detachment
            throw "VMware Workstation VMX remains after deleteVM succeeded: $resolvedVmxPath"
        }
    }

    Remove-AtlasoWorkstationStaleRegistrations -InventoryPath $inventoryPath -ScopeRoot $staleScope
    Assert-AtlasoRootSnapshotUnreplaced -RemovalRoot $resolvedRemovalRoot -Snapshot $snapshot
    foreach ($runningPath in @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)) {
        if (
            [System.IO.Path]::IsPathFullyQualified($runningPath) -and
            (Test-AtlasoStrictDescendantPath -ParentPath $resolvedRemovalRoot -ChildPath $runningPath)
        ) {
            throw "A VMware Workstation VM remains running inside the cleanup root; artifacts were preserved: $runningPath"
        }
    }
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
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'CanonicalParent')][string]$ArtifactParentRoot,
        [Parameter(Mandatory = $true, ParameterSetName = 'ExactConfiguredRoot')][string]$ExpectedRemovalRoot,
        [Parameter(Mandatory = $true)][string]$RemovalRoot
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
        $staleScope = $resolvedRemovalRoot
    } else {
        $resolvedParentRoot = (Resolve-Path -LiteralPath $ArtifactParentRoot -ErrorAction Stop).Path
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedParentRoot `
            -ChildPath $resolvedRemovalRoot `
            -FailureMessage 'Refusing to remove a VMware artifact directory outside the canonical parent root'
        $staleScope = $resolvedParentRoot
    }
    $vmxPaths = @(
        Get-ChildItem -LiteralPath $resolvedRemovalRoot -Filter '*.vmx' -File -Recurse -Force -ErrorAction Stop |
            ForEach-Object { $_.FullName }
    )
    if ($PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Verify VMware VM state and remove artifact root')) {
        Remove-AtlasoWorkstationVmArtifacts `
            -VmrunPath $VmrunPath `
            -VmxPaths $vmxPaths `
            -RemovalRoot $resolvedRemovalRoot `
            -AllowMissingRegistrationsUnderRoot $staleScope `
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
