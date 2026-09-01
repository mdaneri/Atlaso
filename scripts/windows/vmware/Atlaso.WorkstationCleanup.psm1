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
<#
.SYNOPSIS
Return a normalized absolute path without a non-root trailing separator.

.PARAMETER Path
Path to normalize.
#>
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
<#
.SYNOPSIS
Compare two paths using Windows path semantics.

.PARAMETER Left
First path.

.PARAMETER Right
Second path.
#>
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
<#
.SYNOPSIS
Return whether a child is strictly below a parent path.

.PARAMETER ParentPath
Candidate parent directory.

.PARAMETER ChildPath
Candidate descendant path.
#>
function Test-AtlasoStrictDescendantPath {
    [CmdletBinding()][OutputType([bool])]
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
<#
.SYNOPSIS
Reject a path whose existing ancestry contains a reparse point.

.PARAMETER Path
Path whose ancestry is validated.
#>
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
<#
.SYNOPSIS
Require a reparse-free path to be strictly below a parent.

.PARAMETER ParentPath
Required parent directory.

.PARAMETER ChildPath
Path required below the parent.

.PARAMETER FailureMessage
Error prefix used when validation fails.
#>
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
<#
.SYNOPSIS
Return the stable Windows filesystem identity for an existing path.

.PARAMETER Path
Existing path to identify.

.PARAMETER Description
Safe object description used in errors.
#>
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
<#
.SYNOPSIS
Return the SHA-256 content hash of a file.

.PARAMETER Path
File to hash.
#>
function Get-AtlasoFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}
<#
.SYNOPSIS
Compare two byte arrays without text conversion.

.PARAMETER Left
First byte array.

.PARAMETER Right
Second byte array.
#>
function Test-AtlasoByteArraysEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}
<#
.SYNOPSIS
Invoke vmrun and reject every nonzero provider result.

.PARAMETER VmrunPath
Path to the vmrun executable.

.PARAMETER Arguments
Arguments passed directly to vmrun.

.PARAMETER Action
Safe action description used in errors.
#>
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
<#
.SYNOPSIS
Read the single well-formed display name from a VMX file.

.PARAMETER Path
VMX file to inspect.
#>
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
<#
.SYNOPSIS
Normalize one path line returned by vmrun.

.PARAMETER InventoryLine
Raw vmrun output line.
#>
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
<#
.SYNOPSIS
Parse and validate the complete output from VMware Workstation vmrun list.

.PARAMETER Output
Complete line-oriented stdout from one successful vmrun list invocation.
#>
function ConvertFrom-AtlasoVmrunListOutput {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Output)
    if ($Output.Count -lt 1 -or $Output[0].ToString() -notmatch '^Total running VMs:\s*(\d+)\s*$') {
        throw 'vmrun list returned an unrecognized running-VM inventory; artifacts were preserved.'
    }
    $declaredCount = [int]$Matches[1]
    $reportedPaths = @($Output | Select-Object -Skip 1 | ForEach-Object { ConvertFrom-AtlasoVmrunInventoryPath -InventoryLine $_.ToString() } | Where-Object { $_ })
    if ($reportedPaths.Count -ne $declaredCount) { throw "vmrun list reported $declaredCount VMs but returned $($reportedPaths.Count) paths; artifacts were preserved." }
    if (@($reportedPaths | Where-Object {
                -not [System.IO.Path]::IsPathFullyQualified($_) -or $_.Contains('"')
            }).Count -gt 0) {
        throw 'vmrun list returned a non-absolute or malformed VMX path; artifacts were preserved.'
    }
    if (@($reportedPaths | Where-Object { [System.IO.Path]::GetExtension($_) -ine '.vmx' -or -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count -gt 0) { throw 'vmrun list returned a missing or non-VMX running path; artifacts were preserved.' }
    return $reportedPaths
}
<#
.SYNOPSIS
Return the checked VMware Workstation running-VM paths.

.PARAMETER VmrunPath
Path to the vmrun executable.

.PARAMETER State
Provider state to query; currently only running is supported.
#>
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
    return @(ConvertFrom-AtlasoVmrunListOutput -Output $output)
}
<#
.SYNOPSIS
Return the current user's Workstation inventory path when it exists.
#>
function Resolve-AtlasoWorkstationInventoryPath {
    $inventoryPath = Join-Path $env:APPDATA 'VMware\inventory.vmls'
    if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
        return $null
    }
    return (Resolve-Path -LiteralPath $inventoryPath -ErrorAction Stop).Path
}
<#
.SYNOPSIS
Parse well-formed Workstation registrations inside one cleanup scope.

.PARAMETER Lines
Inventory snapshot lines to parse.

.PARAMETER ScopeRoot
Canonical root that bounds returned registrations.
#>
function Get-AtlasoScopedInventoryEntriesFromLines {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$ScopeRoot
    )
    $entries = @()
    foreach ($line in $Lines) {
        if ($line -notmatch '^\s*vmlist(?<id>\d+)\.config\s*=\s*"(?<path>.*)"\s*$') {
            continue
        }
        $candidate = $Matches.path
        if (-not $candidate -or -not [System.IO.Path]::IsPathFullyQualified($candidate) -or [System.IO.Path]::GetExtension($candidate) -ine '.vmx') {
            continue
        }
        try { $canonicalPath = Get-AtlasoCanonicalPath -Path $candidate } catch { continue }
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
<#
.SYNOPSIS
Return whether one unambiguously owned registration identifies a VMX.

.PARAMETER InventoryPath
Optional Workstation inventory file.

.PARAMETER VmxPath
Existing cleanup target VMX.

.PARAMETER ScopeRoot
Validated cleanup root associated with the query.
#>
function Test-AtlasoWorkstationVmxRegistered {
    param(
        [Parameter(Mandatory = $false)][AllowNull()][string]$InventoryPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$ScopeRoot
    )
    if (-not $InventoryPath) {
        return $false
    }
    $targetIdentity = Get-AtlasoPathIdentity -Path $VmxPath -Description 'VMware cleanup target'
    $inventoryStream = [System.IO.FileStream]::new($InventoryPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try { $inventoryBytes = Read-AtlasoStreamBytes -Stream $inventoryStream } finally { $inventoryStream.Dispose() }
    $inventoryLines = @([System.Text.Encoding]::UTF8.GetString($inventoryBytes) -split '\r?\n')
    $ownersById = @{}
    $invalidOwnerIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $inventoryLines) {
        if ($line -notmatch '^\s*vmlist(?<id>\d+)\.config\s*=') { continue }
        $id = $Matches.id
        if ($line -notmatch '^\s*vmlist\d+\.config\s*=\s*"(?<path>.*)"\s*$') {
            $invalidOwnerIds.Add($id) | Out-Null
            continue
        }
        $candidate = $Matches.path
        if (-not $candidate -or -not [System.IO.Path]::IsPathFullyQualified($candidate)) {
            $invalidOwnerIds.Add($id) | Out-Null
            continue
        }
        if ([System.IO.Path]::GetExtension($candidate) -ine '.vmx') { $invalidOwnerIds.Add($id) | Out-Null }
        try { $canonicalPath = Get-AtlasoCanonicalPath -Path $candidate }
        catch { $invalidOwnerIds.Add($id) | Out-Null; continue }
        if (-not $ownersById.ContainsKey($id)) {
            $ownersById[$id] = [System.Collections.Generic.List[string]]::new()
        }
        $ownersById[$id].Add($canonicalPath)
    }
    $matchingIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $ownersById.Keys) {
        foreach ($canonicalPath in $ownersById[$id]) {
            $matchesExactPath = Test-AtlasoSamePath -Left $canonicalPath -Right $VmxPath
            $matchesTarget = $matchesExactPath
            if (-not $matchesExactPath -and (Test-Path -LiteralPath $canonicalPath -PathType Leaf)) {
                $matchesTarget = (
                    (Get-AtlasoPathIdentity -Path $canonicalPath -Description 'registered VMware VMX') -eq
                    $targetIdentity
                )
            }
            if ($matchesTarget -and (-not $matchesExactPath -or -not (Test-AtlasoStrictDescendantPath -ParentPath $ScopeRoot -ChildPath $canonicalPath))) {
                throw 'VMware Workstation inventory registers the cleanup target through a non-exact or out-of-scope library path; artifacts were preserved.'
            }
            if ($matchesTarget) { $matchingIds.Add($id) | Out-Null }
        }
    }
    foreach ($id in $matchingIds) {
        if (
            $invalidOwnerIds.Contains($id) -or
            $ownersById[$id].Count -ne 1 -or
            $matchingIds.Count -ne 1
        ) {
            throw "VMware Workstation inventory assigns the live cleanup target to an ambiguous library ID; artifacts were preserved."
        }
    }
    return $matchingIds.Count -eq 1
}
<#
.SYNOPSIS
Read all bytes from the beginning of an open stream.

.PARAMETER Stream
Readable seekable stream.
#>
function Read-AtlasoStreamBytes {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)
    $Stream.Position = 0
    $memory = [System.IO.MemoryStream]::new()
    try {
        $Stream.CopyTo($memory)
        return $memory.ToArray()
    }
    finally {
        $memory.Dispose()
    }
}
<#
.SYNOPSIS
Restore the newest file state with bounded identity-and-content CAS retries.

.PARAMETER TargetPath
Live path whose state is restored.

.PARAMETER ExpectedCurrentBytes
Bytes expected to be displaced by the next atomic replacement.

.PARAMETER ReplacementPath
File containing the state to restore.

.PARAMETER ReplacementBytes
Expected bytes of the replacement file.

.PARAMETER Description
Safe object description used in recovery errors.

.PARAMETER ExpectedCurrentIdentity
Optional filesystem identity expected at the target.

.PARAMETER ReplacementIdentity
Optional filesystem identity of the replacement.

.PARAMETER PreserveCapturedOnSuccess
Retain the displaced expected state as an actionable recovery copy.
#>
function Restore-AtlasoFileAfterCasFailure {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][byte[]]$ExpectedCurrentBytes,
        [Parameter(Mandatory = $true)][string]$ReplacementPath,
        [Parameter(Mandatory = $true)][byte[]]$ReplacementBytes,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $false)][AllowNull()][string]$ExpectedCurrentIdentity,
        [Parameter(Mandatory = $false)][AllowNull()][string]$ReplacementIdentity,
        [Parameter(Mandatory = $false)][switch]$PreserveCapturedOnSuccess
    )
    foreach ($attempt in 1..16) {
        $capturedPath = "$TargetPath.atlaso-cas-$([System.Guid]::NewGuid().ToString('N')).tmp"
        try {
            [System.IO.File]::Replace($ReplacementPath, $TargetPath, $capturedPath, $true)
        }
        catch {
            $recoveryPath = "$TargetPath.atlaso-recovery-$([System.Guid]::NewGuid().ToString('N')).tmp"
            [System.IO.File]::Move($ReplacementPath, $recoveryPath)
            throw "$Description rollback failed; the newest captured state was preserved at '$recoveryPath'."
        }
        $capturedBytes = [System.IO.File]::ReadAllBytes($capturedPath)
        $capturedIdentity = if ($ExpectedCurrentIdentity) {
            Get-AtlasoPathIdentity -Path $capturedPath -Description $Description
        } else {
            $null
        }
        if (
            (Test-AtlasoByteArraysEqual -Left $ExpectedCurrentBytes -Right $capturedBytes) -and
            (-not $ExpectedCurrentIdentity -or $capturedIdentity -eq $ExpectedCurrentIdentity)
        ) {
            if ($PreserveCapturedOnSuccess) {
                $recoveryPath = "$TargetPath.atlaso-recovery-$([System.Guid]::NewGuid().ToString('N')).tmp"
                [System.IO.File]::Move($capturedPath, $recoveryPath)
                return $recoveryPath
            }
            Remove-Item -LiteralPath $capturedPath -Force -ErrorAction Stop
            return $null
        }
        $ExpectedCurrentBytes = $ReplacementBytes
        $ExpectedCurrentIdentity = $ReplacementIdentity
        $ReplacementPath = $capturedPath
        $ReplacementBytes = $capturedBytes
        $ReplacementIdentity = $capturedIdentity
    }
    $recoveryPath = "$TargetPath.atlaso-recovery-$([System.Guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::Move($ReplacementPath, $recoveryPath)
    throw "$Description changed repeatedly during rollback; the newest captured state was preserved at '$recoveryPath'."
}
<#
.SYNOPSIS
Remove only uniquely owned stale registrations inside an Atlaso scope.

.PARAMETER InventoryPath
Optional Workstation inventory file.

.PARAMETER ScopeRoot
Canonical root that bounds stale registration selection.

.PARAMETER VmxPath
Optional exact missing VMX path to repair without selecting sibling registrations.

.PARAMETER ExpectedDisplayName
Exact Workstation display name required for the selected VMX registration.

.PARAMETER OnVerified
Optional recovery action to run while verified provider state remains write-excluded.
#>
function Remove-AtlasoWorkstationStaleRegistrations {
    param(
        [Parameter(Mandatory = $false)][AllowNull()][string]$InventoryPath,
        [Parameter(Mandatory = $true)][string]$ScopeRoot,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$VmxPath = '',
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$ExpectedDisplayName = '',
        [Parameter(Mandatory = $false)][AllowNull()][scriptblock]$OnVerified
    )
    if ([string]::IsNullOrWhiteSpace($VmxPath) -ne [string]::IsNullOrWhiteSpace($ExpectedDisplayName)) {
        throw 'Exact stale-registration repair requires both a VMX path and display name.'
    }
    $resolvedScopeRoot = Get-AtlasoCanonicalPath -Path $ScopeRoot
    $resolvedVmxPath = if ($VmxPath) { Get-AtlasoCanonicalPath -Path $VmxPath } else { '' }
    if ($resolvedVmxPath) {
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedScopeRoot `
            -ChildPath $resolvedVmxPath `
            -FailureMessage 'Exact stale-registration VMX is outside the approved cleanup scope'
        if (Test-Path -LiteralPath $resolvedVmxPath) {
            throw "Exact stale-registration VMX still exists; provider state was preserved: $resolvedVmxPath"
        }
    }
    if (-not $InventoryPath -and -not $resolvedVmxPath -and -not $OnVerified) { return }
    $realInventoryPath = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware\inventory.vmls'
    $missingInventoryPath = Join-Path $env:APPDATA 'VMware\inventory.vmls'
    $isRealInventory = if ($InventoryPath) {
        Test-AtlasoSamePath -Left $InventoryPath -Right $realInventoryPath
    } else { Test-AtlasoSamePath -Left $missingInventoryPath -Right $realInventoryPath }
    if ($isRealInventory -and (Get-Process vmware -ErrorAction SilentlyContinue)) {
        throw 'Close the VMware Workstation UI before removing stale Atlaso VM library entries.'
    }
    if (-not $InventoryPath) {
        $appearedInventoryPath = Resolve-AtlasoWorkstationInventoryPath
        if ($appearedInventoryPath) { throw "VMware Workstation inventory appeared while its absence was being verified; provider state was preserved: $appearedInventoryPath" }
        if (-not (Test-Path -LiteralPath (Split-Path -Parent $missingInventoryPath) -PathType Container)) {
            throw 'VMware Workstation inventory directory is absent, so provider write exclusion cannot be established.'
        }
        try {
            # A locked empty inventory makes zero ownership durable before the
            # recovery marker is retired and before Workstation may be reopened.
            $missingInventoryLock = [System.IO.File]::Open($missingInventoryPath, 'CreateNew', 'ReadWrite', 'Read')
        } catch { throw "VMware Workstation inventory appeared while write exclusion was being established; provider state was preserved: $missingInventoryPath" }
        try {
            if ($resolvedVmxPath -and (Test-Path -LiteralPath $resolvedVmxPath)) {
                throw "The exact stale-registration VMX was recreated before inventory absence could be proven: $resolvedVmxPath"
            }
            if ($OnVerified) { & $OnVerified }
        }
        finally { $missingInventoryLock.Dispose() }
        return
    }
    $originalBytes = [System.IO.File]::ReadAllBytes($InventoryPath)
    $lines = @([System.Text.Encoding]::UTF8.GetString($originalBytes) -split '\r?\n')
    $staleEntries = @(
        Get-AtlasoScopedInventoryEntriesFromLines -Lines $lines -ScopeRoot $resolvedScopeRoot |
            Where-Object { -not $_.Exists }
    )
    if ($resolvedVmxPath) {
        $rawExactConfigCount = 0
        $rawExactIndexCount = 0
        foreach ($line in $lines) {
            if ($line -notmatch '^\s*(?<owner>vmlist\d+\.config|index\d+\.id)\s*=\s*(?<value>.*)$') { continue }
            $rawValue = $Matches.value.Trim()
            $rawOwner = $Matches.owner
            $rawCandidates = @($rawValue)
            $hasCompleteQuotedValue = $false
            if ($rawValue.Length -gt 0 -and $rawValue[0] -in @([char]34, [char]39)) {
                $openingQuote = $rawValue[0]; $candidateStart = 1
                while ($candidateStart -lt $rawValue.Length -and $rawValue[$candidateStart] -eq $openingQuote) { $candidateStart++ }
                $rawCandidates = @()
                for ($quoteIndex = $candidateStart; $quoteIndex -lt $rawValue.Length; $quoteIndex++) {
                    if ($rawValue[$quoteIndex] -ne $openingQuote) { continue }
                    $rawCandidate = $rawValue.Substring($candidateStart, $quoteIndex - $candidateStart)
                    $quotedSuffix = $rawValue.Substring($quoteIndex + 1).Trim()
                    if ($quotedSuffix -match '(?i)\.vmx' -and ($quotedSuffix.EndsWith([string]$openingQuote) -or $rawCandidate -notmatch '(?i)\.vmx$')) { continue }
                    $hasCompleteQuotedValue = $true; $rawCandidates += $rawCandidate
                }
                if (-not $hasCompleteQuotedValue) { $rawCandidates = @($rawValue.Substring($candidateStart)) }
            }
            $rawRefersToExactPath = $false
            foreach ($rawCandidate in $rawCandidates) {
                if ([System.IO.Path]::IsPathFullyQualified($rawCandidate)) {
                    try { $rawRefersToExactPath = Test-AtlasoSamePath -Left $rawCandidate -Right $resolvedVmxPath }
                    catch {
                        Write-Verbose "Ignored an uncanonicalizable raw Workstation inventory row: $($_.Exception.Message)"
                    }
                }
                if ($rawRefersToExactPath) { break }
            }
            if (-not $rawRefersToExactPath -and -not $hasCompleteQuotedValue -and
                $rawCandidate -match '^(?<path>.+?\.vmx)(?=$|["''\s])') {
                try { $rawRefersToExactPath = Test-AtlasoSamePath -Left $Matches.path -Right $resolvedVmxPath }
                catch { Write-Verbose "Ignored an uncanonicalizable malformed Workstation owner prefix: $($_.Exception.Message)" }
            }
            if ($rawRefersToExactPath) {
                if ($rawOwner.StartsWith('vmlist')) { $rawExactConfigCount++ } else { $rawExactIndexCount++ }
            }
        }
        $staleEntries = @($staleEntries | Where-Object {
                Test-AtlasoSamePath -Left $_.Path -Right $resolvedVmxPath
            })
        if ($rawExactConfigCount -ne $staleEntries.Count) {
            throw "VMware Workstation inventory contains a malformed or ambiguous registration for the exact missing VMX; provider state was preserved: $resolvedVmxPath"
        }
        if ($staleEntries.Count -gt 1) {
            throw "VMware Workstation inventory contains multiple registrations for the exact missing VMX; provider state was preserved: $resolvedVmxPath"
        }
        if ($staleEntries.Count -eq 1) {
            $selectedId = $staleEntries[0].Id
            $displayNameLines = @($lines | Where-Object { $_ -match "^\s*vmlist$selectedId\.DisplayName\s*=" })
            if (
                $displayNameLines.Count -ne 1 -or
                $displayNameLines[0] -notmatch '^\s*vmlist\d+\.DisplayName\s*=\s*"(?<name>[^"\r\n]+)"\s*$' -or
                -not $Matches.name.Equals($ExpectedDisplayName, [System.StringComparison]::Ordinal)
            ) {
                throw "VMware Workstation registration for the exact missing VMX does not have the expected display name; provider state was preserved: $resolvedVmxPath"
            }
        }
    }
    if ($staleEntries.Count -eq 0 -and (-not $resolvedVmxPath -or $rawExactIndexCount -eq 0)) {
        $absenceLock = [System.IO.File]::Open(
            $InventoryPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
            $lockedAbsenceBytes = Read-AtlasoStreamBytes -Stream $absenceLock
            if (-not (Test-AtlasoByteArraysEqual -Left $originalBytes -Right $lockedAbsenceBytes)) {
                throw 'VMware Workstation inventory changed before exact registration absence could be proven.'
            }
            if ($resolvedVmxPath -and (Test-Path -LiteralPath $resolvedVmxPath)) {
                throw "The exact stale-registration VMX was recreated before absence could be proven: $resolvedVmxPath"
            }
            if ($OnVerified) { & $OnVerified }
        }
        finally {
            $absenceLock.Dispose()
        }
        return
    }
    $targetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $targetPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $targetIdPaths = @{}
    foreach ($entry in $staleEntries) {
        $targetIds.Add($entry.Id) | Out-Null
        $targetPaths.Add($entry.Path) | Out-Null
        if (-not $targetIdPaths.ContainsKey($entry.Id)) { $targetIdPaths[$entry.Id] = $entry.Path }
    }
    if ($resolvedVmxPath) { $targetPaths.Add($resolvedVmxPath) | Out-Null }
    $selectedIdOwners = @{}
    $invalidSelectedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $lines) {
        if ($line -notmatch '^\s*vmlist(?<id>\d+)\.config\s*=') { continue }
        $selectedId = $Matches.id
        if (-not $targetIds.Contains($selectedId)) { continue }
        if ($line -notmatch '^\s*vmlist\d+\.config\s*=\s*"(?<path>.*)"\s*$' -or -not [System.IO.Path]::IsPathFullyQualified($Matches.path)) {
            $invalidSelectedIds.Add($selectedId) | Out-Null
            continue
        }
        if (-not $selectedIdOwners.ContainsKey($selectedId)) { $selectedIdOwners[$selectedId] = [System.Collections.Generic.List[string]]::new() }
        $selectedIdOwners[$selectedId].Add($Matches.path)
    }
    foreach ($targetId in $targetIds) {
        if (
            $invalidSelectedIds.Contains($targetId) -or
            -not $selectedIdOwners.ContainsKey($targetId) -or
            $selectedIdOwners[$targetId].Count -ne 1 -or
            -not (Test-AtlasoSamePath `
                -Left $targetIdPaths[$targetId] `
                -Right (Get-AtlasoCanonicalPath -Path $selectedIdOwners[$targetId][0]))
        ) {
            throw "VMware Workstation inventory assigns selected library ID '$targetId' to multiple config paths; artifacts were preserved."
        }
    }
    $indexOwners = @{}
    $invalidIndexes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $lines) {
        if ($line -notmatch '^\s*index(?<index>\d+)\.id\s*=') { continue }
        $index = $Matches.index
        if ($line -notmatch '^\s*index\d+\.id\s*=\s*"(?<path>.*)"\s*$' -or
            -not [System.IO.Path]::IsPathFullyQualified($Matches.path)) {
            $invalidIndexes.Add($index) | Out-Null
            continue
        }
        if (-not $indexOwners.ContainsKey($index)) {
            $indexOwners[$index] = [System.Collections.Generic.List[string]]::new()
        }
        try { $indexOwners[$index].Add((Get-AtlasoCanonicalPath -Path $Matches.path)) } catch { $invalidIndexes.Add($index) | Out-Null }
    }
    $targetIndexes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($index in $indexOwners.Keys) {
        if (-not $invalidIndexes.Contains($index) -and
            $indexOwners[$index].Count -eq 1 -and
            $targetPaths.Contains($indexOwners[$index][0])) {
            $targetIndexes.Add($index) | Out-Null
        }
    }
    if ($resolvedVmxPath -and $rawExactIndexCount -ne $targetIndexes.Count) {
        throw "VMware Workstation inventory contains a malformed or ambiguous index for the exact missing VMX; provider state was preserved: $resolvedVmxPath"
    }
    $indexRenumbering = if ($targetIndexes.Count -gt 0) { @{} } else { $null }
    foreach ($line in $lines) {
        if ($null -eq $indexRenumbering) { break }
        if ($line -match '^\s*index(?<index>\d+)\.' -and -not $targetIndexes.Contains($Matches.index) -and -not $indexRenumbering.ContainsKey($Matches.index)) {
            if ($invalidIndexes.Contains($Matches.index) -or -not $indexOwners.ContainsKey($Matches.index) -or $indexOwners[$Matches.index].Count -ne 1) { $indexRenumbering = $null; break }
            $indexRenumbering[$Matches.index] = $indexRenumbering.Count
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
        if ($line -match '^(?<indent>\s*)index(?<index>\d+)(?<suffix>\..*)$' -and $null -ne $indexRenumbering -and $indexRenumbering.ContainsKey($Matches.index)) {
            $line = "$($Matches.indent)index$($indexRenumbering[$Matches.index])$($Matches.suffix)"
        }
        if ($line -match '^\s*index\.count\s*=\s*"(?<count>\d+)"\s*$') {
            $count = 0
            if (-not [int]::TryParse($Matches.count, [ref]$count)) { $updatedLines.Add($line); continue }
            if ($null -eq $indexRenumbering) { $updatedLines.Add($line) } else { $updatedLines.Add("index.count = `"$($indexRenumbering.Count)`"") }
            continue
        }
        $updatedLines.Add($line)
    }
    $replacementBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($updatedLines -join [Environment]::NewLine))
    foreach ($candidatePath in $targetPaths) {
        if (Test-Path -LiteralPath $candidatePath) {
            throw "A stale Atlaso VMX was recreated before inventory repair; artifacts were preserved: $candidatePath"
        }
    }
    if (-not (Test-AtlasoByteArraysEqual -Left $originalBytes -Right ([System.IO.File]::ReadAllBytes($InventoryPath)))) {
        throw 'VMware Workstation inventory changed before scoped stale-registration repair; artifacts were preserved.'
    }
    $temporaryPath = "$InventoryPath.atlaso-cleanup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$InventoryPath.atlaso-backup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $preserveBackup = $false
    $replacementApplied = $false
    try {
        [System.IO.File]::WriteAllBytes($temporaryPath, $replacementBytes)
        $inventoryLock = [System.IO.File]::Open(
            $InventoryPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete)
        )
        try {
            $lockedBytes = Read-AtlasoStreamBytes -Stream $inventoryLock
            if (-not (Test-AtlasoByteArraysEqual -Left $originalBytes -Right $lockedBytes)) {
                throw 'VMware Workstation inventory changed before scoped stale-registration repair; artifacts were preserved.'
            }
            foreach ($candidatePath in $targetPaths) {
                if (Test-Path -LiteralPath $candidatePath) {
                    throw "A stale Atlaso VMX was recreated before inventory repair; artifacts were preserved: $candidatePath"
                }
            }
            [System.IO.File]::Replace($temporaryPath, $InventoryPath, $backupPath, $true)
            $replacementApplied = $true
            $displacedBytes = [System.IO.File]::ReadAllBytes($backupPath)
            if (-not (Test-AtlasoByteArraysEqual -Left $originalBytes -Right $displacedBytes)) {
                $preserveBackup = $true
                $replacementApplied = $false
                Restore-AtlasoFileAfterCasFailure `
                    -TargetPath $InventoryPath `
                    -ExpectedCurrentBytes $replacementBytes `
                    -ReplacementPath $backupPath `
                    -ReplacementBytes $displacedBytes `
                    -Description 'VMware Workstation inventory'
                throw 'VMware Workstation inventory was replaced during scoped stale-registration repair; provider state was restored.'
            }
            $replacementLock = [System.IO.File]::Open($InventoryPath, 'Open', 'Read', 'Read')
            try {
                $verifiedReplacementBytes = Read-AtlasoStreamBytes -Stream $replacementLock
                if (-not (Test-AtlasoByteArraysEqual -Left $replacementBytes -Right $verifiedReplacementBytes)) {
                    throw 'VMware Workstation inventory changed after scoped stale-registration repair; provider state will be restored.'
                }
                # A verified replacement is a safe monotonic repair. Preserve it if
                # the recovery-release callback fails so the durable marker can retry.
                $replacementApplied = $false
                if ($OnVerified) { & $OnVerified }
            }
            finally { $replacementLock.Dispose() }
        }
        finally {
            $inventoryLock.Dispose()
        }
    }
    catch {
        $repairError = $_
        if ($replacementApplied) {
            $preserveBackup = $true
            try {
                Restore-AtlasoFileAfterCasFailure -TargetPath $InventoryPath -ExpectedCurrentBytes $replacementBytes -ReplacementPath $backupPath -ReplacementBytes $originalBytes -Description 'VMware Workstation inventory'
                $preserveBackup = $false
            } catch { throw "VMware Workstation inventory repair failed and rollback also failed: $($_.Exception.Message)" }
        }
        throw $repairError
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        if (-not $preserveBackup) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
    }
}

<#
.SYNOPSIS
Repair missing VMware Workstation registrations inside one exact Atlaso scope.

.PARAMETER ScopeRoot
Exact non-reparse-point Atlaso scope that bounds missing registration repair.

.PARAMETER VmxPath
Optional exact missing VMX path to repair without selecting sibling registrations.

.PARAMETER ExpectedDisplayName
Exact Workstation display name required for the selected VMX registration.

.PARAMETER OnVerified
Optional recovery action to run while verified provider state remains write-excluded.
#>
function Repair-AtlasoWorkstationStaleRegistrations {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$ScopeRoot,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$VmxPath = '',
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$ExpectedDisplayName = '',
        [Parameter(Mandatory = $false)][AllowNull()][scriptblock]$OnVerified
    )
    $resolvedScopeRoot = Get-AtlasoCanonicalPath -Path $ScopeRoot
    $filesystemRoot = [System.IO.Path]::GetPathRoot($resolvedScopeRoot)
    if (-not $filesystemRoot -or (Test-AtlasoSamePath -Left $resolvedScopeRoot -Right $filesystemRoot)) {
        throw "Refusing to repair VMware registrations for a filesystem root: $resolvedScopeRoot"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $resolvedScopeRoot
    if ($PSCmdlet.ShouldProcess($resolvedScopeRoot, 'Remove missing Atlaso VMware Workstation registrations')) {
        Remove-AtlasoWorkstationStaleRegistrations `
            -InventoryPath (Resolve-AtlasoWorkstationInventoryPath) `
            -ScopeRoot $resolvedScopeRoot `
            -VmxPath $VmxPath `
            -ExpectedDisplayName $ExpectedDisplayName `
            -OnVerified $OnVerified
    }
}
<#
.SYNOPSIS
Capture filesystem identities for a validated artifact root and descendants.

.PARAMETER RemovalRoot
Exact artifact root to snapshot.
#>
function Get-AtlasoRootSnapshot {
    param([Parameter(Mandatory = $true)][string]$RemovalRoot)
    $rootIdentity = Get-AtlasoPathIdentity -Path $RemovalRoot -Description 'VMware artifact root'
    $items = @{}
    foreach ($item in Get-ChildItem -LiteralPath $RemovalRoot -Force -Recurse -ErrorAction Stop) {
        Assert-AtlasoPathHasNoReparsePoint -Path $item.FullName
        $relativePath = [System.IO.Path]::GetRelativePath($RemovalRoot, $item.FullName)
        $items[$relativePath] = Get-AtlasoPathIdentity -Path $item.FullName -Description 'VMware artifact entry'
    }
    if ((Get-AtlasoPathIdentity -Path $RemovalRoot -Description 'VMware artifact root') -ne $rootIdentity) { throw "VMware artifact root changed while its cleanup snapshot was captured; artifacts were preserved: $RemovalRoot" }
    return [pscustomobject]@{
        RootIdentity = $rootIdentity
        Items = $items
    }
}
<#
.SYNOPSIS
Reject new or identity-replaced entries in a captured artifact root.

.PARAMETER RemovalRoot
Exact artifact root being revalidated.

.PARAMETER Snapshot
Previously captured root and descendant identities.
#>
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
    if ((Get-AtlasoPathIdentity -Path $RemovalRoot -Description 'VMware artifact root') -ne $Snapshot.RootIdentity) { throw "VMware artifact root was replaced during cleanup; the replacement was preserved: $RemovalRoot" }
}
<#
.SYNOPSIS
Match a running VMX path to a target by path or filesystem identity.

.PARAMETER RunningPath
Path reported by vmrun.

.PARAMETER VmxPath
Validated cleanup target VMX.

.PARAMETER TargetIdentity
Optional earlier identity that still identifies the running target.
#>
function Test-AtlasoRunningPathMatchesTarget {
    param(
        [Parameter(Mandatory = $true)][string]$RunningPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$TargetIdentity = ''
    )
    if (-not [System.IO.Path]::IsPathFullyQualified($RunningPath)) { return $false }
    if (Test-AtlasoSamePath -Left $RunningPath -Right $VmxPath) { return $true }
    if (
        (Test-Path -LiteralPath $RunningPath -PathType Leaf) -and
        (Test-Path -LiteralPath $VmxPath -PathType Leaf)
    ) {
        $runningIdentity = Get-AtlasoPathIdentity -Path $RunningPath -Description 'running VMware VMX'
        return ($TargetIdentity -and $runningIdentity -eq $TargetIdentity) -or
            $runningIdentity -eq (Get-AtlasoPathIdentity -Path $VmxPath -Description 'VMware cleanup target')
    }
    return $false
}

<#
.SYNOPSIS
Stop an exact running target and prove it is inactive.

.PARAMETER VmrunPath
Path to the vmrun executable.

.PARAMETER VmxPath
Validated cleanup target VMX.

.PARAMETER TargetIdentity
Optional earlier identity that still identifies the running target.
#>
function Confirm-AtlasoWorkstationVmInactive {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$TargetIdentity = ''
    )
    $runningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    $runningTargets = @($runningPaths | Where-Object { Test-AtlasoRunningPathMatchesTarget -RunningPath $_ -VmxPath $VmxPath -TargetIdentity $TargetIdentity })
    if ($runningTargets.Count -gt 0) {
        Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'stop', $runningTargets[0], 'hard') `
            -Action "Stop VMware Workstation VM '$VmxPath'" | Out-Null
    }
    $remainingPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    if (@($remainingPaths | Where-Object { Test-AtlasoRunningPathMatchesTarget -RunningPath $_ -VmxPath $VmxPath -TargetIdentity $TargetIdentity }).Count -gt 0) { throw "VMware Workstation VM remains running after stop succeeded: $VmxPath" }
}

<#
.SYNOPSIS
Reject a running VM that belongs to the validated cleanup root.

.PARAMETER VmrunPath
Path to the vmrun executable.

.PARAMETER RemovalRoot
Validated cleanup root.

.PARAMETER ValidatedTargetIdentities
Captured identities for every expected VMX.
#>
function Assert-AtlasoWorkstationNoRunningTarget {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$RemovalRoot,
        [Parameter(Mandatory = $true)][hashtable]$ValidatedTargetIdentities
    )
    foreach ($runningPath in @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)) {
        $runningIdentity = Get-AtlasoPathIdentity -Path $runningPath -Description 'running VMware VMX'
        if (
            @($ValidatedTargetIdentities.Values | Where-Object { $_ -eq $runningIdentity }).Count -gt 0 -or
            (Test-AtlasoStrictDescendantPath -ParentPath $RemovalRoot -ChildPath $runningPath)
        ) { throw "A VMware Workstation VM remains running inside the cleanup root; artifacts were preserved: $runningPath" }
    }
}

<#
.SYNOPSIS
Atomically detach external VMDKs and return immutable delete evidence.

.PARAMETER VmxPath
Validated cleanup target VMX.

.PARAMETER RemovalRoot
Exact recursive removal boundary.

.PARAMETER ExpectedIdentity
Filesystem identity captured before provider operations.
#>
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
    $originalHash = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::HashData($originalBytes)
    ).Replace('-', '')
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
        return [pscustomobject]@{
            Detached = $false
            ProtectedIdentity = $ExpectedIdentity
            ProtectedBytes = $originalBytes
            ProtectedHash = $originalHash
        }
    }

    $protectedLines = @($lines | Where-Object {
            if ($_ -match '^\s*(?<device>(?:scsi|sata|ide|nvme)\d+:\d+)\.') {
                return -not $externalDevices.Contains($Matches.device)
            }
            return $true
        })
    $protectedBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($protectedLines -join [Environment]::NewLine))
    $protectedHash = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::HashData($protectedBytes)
    ).Replace('-', '')
    $temporaryPath = "$VmxPath.atlaso-detach-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$VmxPath.atlaso-backup-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $replacementApplied = $false
    $detachment = $null
    try {
        [System.IO.File]::WriteAllBytes($temporaryPath, $protectedBytes)
        $detachment = [pscustomobject]@{
            Detached = $true
            OriginalIdentity = $ExpectedIdentity
            OriginalBytes = $originalBytes
            OriginalHash = $originalHash
            ProtectedIdentity = Get-AtlasoPathIdentity -Path $temporaryPath -Description 'protected VMware cleanup target'
            ProtectedBytes = $protectedBytes
            ProtectedHash = $protectedHash
            BackupPath = $backupPath
        }
        $vmxLock = [System.IO.File]::Open(
            $VmxPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete)
        )
        try {
            if (
                (Get-AtlasoPathIdentity -Path $VmxPath -Description 'VMware cleanup target') -ne $ExpectedIdentity -or
                -not (Test-AtlasoByteArraysEqual -Left $originalBytes -Right (Read-AtlasoStreamBytes -Stream $vmxLock))
            ) {
                throw "VMware Workstation VMX changed before external-disk protection; artifacts were preserved: $VmxPath"
            }
            [System.IO.File]::Replace($temporaryPath, $VmxPath, $backupPath, $true)
            $replacementApplied = $true
        }
        finally {
            $vmxLock.Dispose()
        }

        if (
            (Get-AtlasoPathIdentity -Path $VmxPath -Description 'detached VMware cleanup target') -ne $detachment.ProtectedIdentity -or
            -not (Test-AtlasoByteArraysEqual -Left $originalBytes -Right ([System.IO.File]::ReadAllBytes($backupPath))) -or
            (Get-AtlasoFileSha256 -Path $VmxPath) -ne $protectedHash
        ) {
            throw "VMware Workstation VMX changed during external-disk protection: $VmxPath"
        }
        return $detachment
    }
    catch {
        $protectionError = $_
        if ($replacementApplied) {
            try {
                Restore-AtlasoWorkstationExternalVmdks -VmxPath $VmxPath -Detachment $detachment
            }
            catch {
                throw "VMware Workstation VMX protection failed and automatic restoration also failed: $($_.Exception.Message)"
            }
        }
        throw $protectionError
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        if (-not $replacementApplied) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
    }
}

<#
.SYNOPSIS
Restore an externally protected VMX without overwriting concurrent state.

.PARAMETER VmxPath
VMX path to restore.

.PARAMETER Detachment
Immutable detachment evidence and retained backup.
#>
function Restore-AtlasoWorkstationExternalVmdks {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $false)][AllowNull()][psobject]$Detachment
    )
    if ($null -eq $Detachment -or -not $Detachment.Detached) {
        return
    }
    if (-not (Test-Path -LiteralPath $VmxPath -PathType Leaf)) {
        throw "Detached VMware Workstation VMX is missing; original bytes remain at '$($Detachment.BackupPath)'."
    }
    $displacedPath = "$VmxPath.atlaso-displaced-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $originalRecoveryPath = "$VmxPath.atlaso-original-$([System.Guid]::NewGuid().ToString('N')).tmp"
    $preserveDisplaced = $false
    $recoveryCreated = $false
    $restorationVerified = $false
    try {
        # Retain and flush an independent copy because File.Replace consumes the detachment backup.
        $recoveryStream = [System.IO.File]::Open($originalRecoveryPath, 'CreateNew', 'Write', 'Read')
        try {
            $recoveryStream.Write($Detachment.OriginalBytes, 0, $Detachment.OriginalBytes.Length)
            $recoveryStream.Flush($true)
            $recoveryCreated = $true
        }
        finally {
            $recoveryStream.Dispose()
        }
        $vmxLock = [System.IO.File]::Open($VmxPath, 'Open', 'Read', ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete))
        try {
            if (
                (Get-AtlasoPathIdentity -Path $VmxPath -Description 'detached VMware cleanup target') -ne $Detachment.ProtectedIdentity -or
                -not (Test-AtlasoByteArraysEqual -Left $Detachment.ProtectedBytes -Right (Read-AtlasoStreamBytes -Stream $vmxLock))
            ) {
                throw "VMware Workstation VMX was replaced while deleteVM was running; the replacement and original backup were preserved: $VmxPath"
            }
            [System.IO.File]::Replace($Detachment.BackupPath, $VmxPath, $displacedPath, $true)
            $displacedBytes = [System.IO.File]::ReadAllBytes($displacedPath)
            $displacedIdentity = Get-AtlasoPathIdentity -Path $displacedPath -Description 'detached VMware cleanup target'
            if (
                $displacedIdentity -ne $Detachment.ProtectedIdentity -or
                -not (Test-AtlasoByteArraysEqual -Left $Detachment.ProtectedBytes -Right $displacedBytes)
            ) {
                $preserveDisplaced = $true
                $recoveryPath = Restore-AtlasoFileAfterCasFailure -TargetPath $VmxPath `
                    -ExpectedCurrentBytes $Detachment.OriginalBytes -ExpectedCurrentIdentity $Detachment.OriginalIdentity `
                    -ReplacementPath $displacedPath -ReplacementBytes $displacedBytes `
                    -ReplacementIdentity $displacedIdentity -Description 'VMware Workstation VMX' -PreserveCapturedOnSuccess
                throw "VMware Workstation VMX changed during rollback; the replacement was restored and a recovery copy was preserved at '$recoveryPath'."
            }
        }
        finally {
            $vmxLock.Dispose()
        }
        # Verify the new path while denying writers, deletion, and another atomic replacement.
        $restoredLock = [System.IO.File]::Open($VmxPath, 'Open', 'Read', 'Read')
        try {
            if ((Get-AtlasoPathIdentity -Path $VmxPath -Description 'restored VMware cleanup target') -ne $Detachment.OriginalIdentity -or
                -not (Test-AtlasoByteArraysEqual -Left $Detachment.OriginalBytes -Right (Read-AtlasoStreamBytes -Stream $restoredLock))) {
                throw "VMware Workstation VMX restoration could not verify the original file: $VmxPath"
            }
            $restorationVerified = $true
        }
        finally {
            $restoredLock.Dispose()
        }
    }
    catch {
        if ($recoveryCreated -and -not $restorationVerified) {
            throw "$($_.Exception.Message) Original bytes remain at '$originalRecoveryPath'."
        }
        throw
    }
    finally {
        if (-not $preserveDisplaced) { Remove-Item -LiteralPath $displacedPath -Force -ErrorAction SilentlyContinue }
        if ($restorationVerified -or -not $recoveryCreated) { Remove-Item -LiteralPath $originalRecoveryPath -Force -ErrorAction SilentlyContinue }
    }
}

<#
.SYNOPSIS
Safely remove validated VMware Workstation artifacts under one exact root.

.PARAMETER VmrunPath
Path to the vmrun executable.

.PARAMETER VmxPaths
Complete set of expected VMX files below the root.

.PARAMETER RemovalRoot
Exact non-reparse-point artifact root to remove.

.PARAMETER AllowMissingRegistrationsUnderRoot
Optional containing scope for narrow stale-registration repair.
#>
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
    $snapshot = Get-AtlasoRootSnapshot -RemovalRoot $resolvedRemovalRoot
    $validatedTargetIdentities = @{}
    $validatedTargetHashes = @{}
    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        $relativeVmxPath = [System.IO.Path]::GetRelativePath($resolvedRemovalRoot, $resolvedVmxPath)
        $validatedTargetIdentities[$resolvedVmxPath] = $snapshot.Items[$relativeVmxPath]
        $validatedTargetHashes[$resolvedVmxPath] = Get-AtlasoFileSha256 -Path $resolvedVmxPath
    }
    if (-not $PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Stop and delete VMware Workstation VM artifacts')) {
        return
    }
    Assert-AtlasoRootSnapshotUnreplaced -RemovalRoot $resolvedRemovalRoot -Snapshot $snapshot
    $inventoryPath = Resolve-AtlasoWorkstationInventoryPath
    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        if ((Get-AtlasoPathIdentity -Path $resolvedVmxPath -Description 'VMware cleanup target') -ne $validatedTargetIdentities[$resolvedVmxPath]) { throw "VMware Workstation VMX was replaced after root validation; artifacts were preserved: $resolvedVmxPath" }
        Test-AtlasoWorkstationVmxRegistered -InventoryPath $inventoryPath -VmxPath $resolvedVmxPath -ScopeRoot $resolvedRemovalRoot | Out-Null
        Confirm-AtlasoWorkstationVmInactive -VmrunPath $VmrunPath -VmxPath $resolvedVmxPath
    }
    $providerRemovedRoot = $false
    $deletedVmxPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        if ($providerRemovedRoot) { break }
        $targetIdentity = $validatedTargetIdentities[$resolvedVmxPath]
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
            $expectedDeleteIdentity = $detachment.ProtectedIdentity
            if ((Get-AtlasoPathIdentity -Path $resolvedVmxPath -Description 'VMware cleanup target') -ne $expectedDeleteIdentity) {
                throw "VMware Workstation VMX was replaced immediately before deleteVM; artifacts were preserved: $resolvedVmxPath"
            }
            $currentKnownVmxPaths = @($resolvedVmxPaths | Where-Object { -not $deletedVmxPaths.Contains($_) } | ForEach-Object {
                    $expectedSurvivorIdentity = if (Test-AtlasoSamePath -Left $_ -Right $resolvedVmxPath) { $expectedDeleteIdentity } else { $validatedTargetIdentities[$_] }
                    $expectedSurvivorHash = if (Test-AtlasoSamePath -Left $_ -Right $resolvedVmxPath) { $detachment.ProtectedHash } else { $validatedTargetHashes[$_] }
                    $earlierIdentity = if ((Test-AtlasoSamePath -Left $_ -Right $resolvedVmxPath) -and $detachment.Detached) { $detachment.OriginalIdentity } else { '' }
                    Confirm-AtlasoWorkstationVmInactive -VmrunPath $VmrunPath -VmxPath $_ -TargetIdentity $earlierIdentity
                    if ((Get-AtlasoPathIdentity -Path $_ -Description 'VMware cleanup target') -ne $expectedSurvivorIdentity) { throw "VMware Workstation VMX was replaced immediately before deleteVM; artifacts were preserved: $_" }
                    if ((Get-AtlasoFileSha256 -Path $_) -ne $expectedSurvivorHash) { throw "VMware Workstation VMX changed immediately before deleteVM; artifacts were preserved: $_" }
                    $_
                })
            $currentDiscoveredVmxPaths = @(
                Get-ChildItem -LiteralPath $resolvedRemovalRoot -Filter '*.vmx' -File -Recurse -Force -ErrorAction Stop |
                    ForEach-Object { (Resolve-Path -LiteralPath $_.FullName -ErrorAction Stop).Path }
            )
            if (@(Compare-Object `
                    -ReferenceObject @($currentKnownVmxPaths | Sort-Object -Unique) `
                    -DifferenceObject @($currentDiscoveredVmxPaths | Sort-Object -Unique)).Count -ne 0) {
                throw 'VMware artifact root changed immediately before deleteVM; artifacts were preserved.'
            }
            if (-not (Test-AtlasoWorkstationVmxRegistered `
                    -InventoryPath $inventoryPath `
                    -VmxPath $resolvedVmxPath `
                    -ScopeRoot $resolvedRemovalRoot)) {
                # A hard-link alias still references the pre-replacement file, so
                # falling back to recursive deletion would strand its registration.
                throw "VMware Workstation registration changed after VMX protection; the original VMX and artifacts were preserved: $resolvedVmxPath"
            }
            $relativeDeleteVmxPath = [System.IO.Path]::GetRelativePath($resolvedRemovalRoot, $resolvedVmxPath); $snapshot.Items[$relativeDeleteVmxPath] = $expectedDeleteIdentity
            $backupRelativePath = if ($detachment.Detached) { [System.IO.Path]::GetRelativePath($resolvedRemovalRoot, $detachment.BackupPath) } else { $null }
            if ($backupRelativePath) { $snapshot.Items[$backupRelativePath] = $detachment.OriginalIdentity }
            try { Assert-AtlasoRootSnapshotUnreplaced -RemovalRoot $resolvedRemovalRoot -Snapshot $snapshot }
            finally {
                $snapshot.Items[$relativeDeleteVmxPath] = $targetIdentity
                if ($backupRelativePath) { $snapshot.Items.Remove($backupRelativePath) | Out-Null }
            }
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
        $deletedVmxPaths.Add($resolvedVmxPath) | Out-Null
        $providerRemovedRoot = -not (Test-Path -LiteralPath $resolvedRemovalRoot)
        if ($detachment.Detached -and (Test-Path -LiteralPath $detachment.BackupPath -PathType Leaf)) { Remove-Item -LiteralPath $detachment.BackupPath -Force -ErrorAction Stop }
    }
    if ($providerRemovedRoot -and (Test-Path -LiteralPath $resolvedRemovalRoot)) {
        throw "The VMware artifact root reappeared after provider deletion; artifacts were preserved: $resolvedRemovalRoot"
    }
    if (-not $providerRemovedRoot) {
        Assert-AtlasoRootSnapshotUnreplaced -RemovalRoot $resolvedRemovalRoot -Snapshot $snapshot
    }
    Assert-AtlasoWorkstationNoRunningTarget -VmrunPath $VmrunPath -RemovalRoot $resolvedRemovalRoot -ValidatedTargetIdentities $validatedTargetIdentities
    if ($providerRemovedRoot -and (Test-Path -LiteralPath $resolvedRemovalRoot)) { throw "The VMware artifact root reappeared after provider deletion; artifacts were preserved: $resolvedRemovalRoot" }
    # Re-resolve the inventory because it may have appeared after the initial
    # snapshot; surviving VMX files are safe for direct removal only while unregistered.
    $finalInventoryPath = Resolve-AtlasoWorkstationInventoryPath
    Remove-AtlasoWorkstationStaleRegistrations -InventoryPath $finalInventoryPath -ScopeRoot $staleScope
    foreach ($survivingVmxPath in @($resolvedVmxPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })) {
        if (Test-AtlasoWorkstationVmxRegistered -InventoryPath $finalInventoryPath -VmxPath $survivingVmxPath -ScopeRoot $resolvedRemovalRoot) {
            throw "A VMware Workstation VM became registered during cleanup; artifacts were preserved: $survivingVmxPath"
        }
    }
    Assert-AtlasoWorkstationNoRunningTarget -VmrunPath $VmrunPath -RemovalRoot $resolvedRemovalRoot -ValidatedTargetIdentities $validatedTargetIdentities
    $finalInventoryPath = Resolve-AtlasoWorkstationInventoryPath
    foreach ($survivingVmxPath in @($resolvedVmxPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })) {
        if (Test-AtlasoWorkstationVmxRegistered -InventoryPath $finalInventoryPath -VmxPath $survivingVmxPath -ScopeRoot $resolvedRemovalRoot) {
            throw "A VMware Workstation VM became registered during cleanup; artifacts were preserved: $survivingVmxPath"
        }
    }
    if ($providerRemovedRoot -and (Test-Path -LiteralPath $resolvedRemovalRoot)) {
        throw "The VMware artifact root reappeared after provider deletion; artifacts were preserved: $resolvedRemovalRoot"
    }
    if (-not $providerRemovedRoot) {
        Assert-AtlasoRootSnapshotUnreplaced -RemovalRoot $resolvedRemovalRoot -Snapshot $snapshot
        if (Test-Path -LiteralPath $resolvedRemovalRoot) { Remove-Item -LiteralPath $resolvedRemovalRoot -Recurse -Force -ErrorAction Stop }
    }
    if (Test-Path -LiteralPath $resolvedRemovalRoot) {
        throw "VMware artifact directory remains after recursive cleanup; refusing to report success: $resolvedRemovalRoot"
    }
}

<#
.SYNOPSIS
Validate a configured or canonical artifact root and remove it safely.

.PARAMETER VmrunPath
Path to the vmrun executable.

.PARAMETER ArtifactParentRoot
Canonical parent that must strictly contain the removal root.

.PARAMETER ExpectedRemovalRoot
Exact configured root allowed for removal.

.PARAMETER RemovalRoot
Requested artifact root.
#>
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
    $wrapperSnapshot = Get-AtlasoRootSnapshot -RemovalRoot $resolvedRemovalRoot
    if ($PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Verify VMware VM state and remove artifact root')) {
        Assert-AtlasoRootSnapshotUnreplaced -RemovalRoot $resolvedRemovalRoot -Snapshot $wrapperSnapshot
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
    'ConvertFrom-AtlasoVmrunListOutput',
    'Get-AtlasoVmxDisplayName',
    'Repair-AtlasoWorkstationStaleRegistrations',
    'Remove-AtlasoWorkstationArtifactRoot',
    'Remove-AtlasoWorkstationVmArtifacts',
    'Test-AtlasoStrictDescendantPath'
)
