<#
.SYNOPSIS
Receipt-bound source snapshot and wheel pinning primitives for VMware fixture and lifecycle runs.
.DESCRIPTION
Exports the lifecycle runner's hardened source exporter and wheel identity checks from one admitted Git module.
#>
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Refuse consumer output after any snapshot namespace or security change.
.PARAMETER Pins
Retained snapshot objects including native recursive change guards.
#>
function Assert-LifecycleSourcePins {
    param([Collections.Generic.List[IDisposable]]$Pins)
    foreach ($pin in $Pins) {
        if ($pin.GetType().FullName -eq 'Atlaso.LifecycleSourceChangeGuardV1') { $pin.AssertUnchanged() }
    }
}

<#
.SYNOPSIS
Export an admitted Git object into a fresh task-owned wheel source directory.
.PARAMETER RepositoryRoot
Repository containing the admitted immutable commit object.
.PARAMETER Commit
Full admitted commit SHA; the live checkout is never a build input.
.PARAMETER DestinationRoot
Existing task-owned wheel output root containing the unique archive and source directory.
.PARAMETER PreflightGuard
Optional invocation inventory receiving the exact archive paths before extraction.
.PARAMETER ConsumerPins
Caller-owned directory pins that must remain alive until every snapshot consumer exits.
#>
function New-LifecycleSourceSnapshot {
    param([Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
        [Parameter(Mandatory)][string]$DestinationRoot, [object]$PreflightGuard,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[IDisposable]]$ConsumerPins)
    if (-not ('Atlaso.SnapshotFileIdentityV1' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Atlaso {
    public static class SnapshotFileIdentityV1 {
        [StructLayout(LayoutKind.Sequential)] private struct Info {
            public uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle h, out Info info);
        public static string Get(SafeFileHandle handle) {
            Info info;
            if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (info.Links != 1 || (info.Attributes & 0x410) != 0)
                throw new IOException("Snapshot creation identity or single-link requirement failed.");
            return info.Volume.ToString("X8") + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
        }
    }
}
'@
    }
    if (-not ('Atlaso.SnapshotDirectoryPinV2' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Atlaso {
    public static class SnapshotDirectoryPinV2 {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
            IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
            out TagInfo info, uint size);
        [StructLayout(LayoutKind.Sequential)] private struct TagInfo { public uint Attributes, Tag; }
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[] descriptor);
        public static void SetDacl(SafeFileHandle handle, byte[] descriptor) {
            // Set only this kernel object: do not propagate ACLs into unverified children.
            if (!SetKernelObjectSecurity(handle, 4, descriptor))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public static SafeFileHandle Open(string path, bool writeDacl = false) {
            var handle = CreateFile(path, writeDacl ? 0x40081u : 0x81u, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
            try {
                TagInfo info;
                if (!GetFileInformationByHandleEx(handle, 9, out info, 8))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if ((info.Attributes & 0x410) != 0x10)
                    throw new IOException("Snapshot directory must be an ordinary non-reparse directory.");
                return handle;
            } catch { handle.Dispose(); throw; }
        }
    }
}
'@
    }
if (-not ('Atlaso.LifecycleSourceChangeGuardV1' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Atlaso {
    public sealed class LifecycleSourceChangeGuardV1 : IDisposable {
        [StructLayout(LayoutKind.Sequential)]
        private struct Overlapped {
            public IntPtr Internal, InternalHigh;
            public uint Offset, OffsetHigh;
            public IntPtr Event;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadDirectoryChangesW(SafeFileHandle directory, IntPtr buffer,
            uint length, bool subtree, uint filter, IntPtr returned, IntPtr overlapped, IntPtr completion);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetOverlappedResult(SafeFileHandle directory, IntPtr overlapped,
            out uint transferred, bool wait);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CancelIoEx(SafeFileHandle directory, IntPtr overlapped);
        private SafeFileHandle handle;
        private IntPtr buffer, overlapped;
        private bool pending;
        public LifecycleSourceChangeGuardV1(string path, EventWaitHandle changes) {
            try {
                // Arm before enumeration. Unlike FileSystemWatcher callbacks, polling
                // the native completion has no managed event-delivery lag. One event or
                // buffer overflow permanently invalidates this scan; never rearm it.
                handle = CreateFileW(path, 1, 3, IntPtr.Zero, 3, 0x42000000, IntPtr.Zero);
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                buffer = Marshal.AllocHGlobal(65536);
                overlapped = Marshal.AllocHGlobal(Marshal.SizeOf<Overlapped>());
                Marshal.StructureToPtr(new Overlapped { Event = changes.SafeWaitHandle.DangerousGetHandle() }, overlapped, false);
                if (!ReadDirectoryChangesW(handle, buffer, 65536, true, 0x15F,
                    IntPtr.Zero, overlapped, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                pending = true;
            } catch { Dispose(); throw; }
        }
        public void AssertUnchanged() {
            uint transferred;
            if (GetOverlappedResult(handle, overlapped, out transferred, false))
                throw new InvalidOperationException("Admitted source snapshot changed during consumption.");
            int error = Marshal.GetLastWin32Error();
            if (error != 996) // ERROR_IO_INCOMPLETE is the only unchanged state.
                throw new Win32Exception(error, "Admitted source snapshot change tracking failed.");
        }
        public void Dispose() {
            if (handle != null && !handle.IsClosed) {
                if (pending) {
                    CancelIoEx(handle, overlapped);
                    uint transferred;
                    // Another request can signal the shared event before this cancellation
                    // completes. Confirm this exact request is terminal before freeing.
                    while (!GetOverlappedResult(handle, overlapped, out transferred, false) &&
                        Marshal.GetLastWin32Error() == 996) Thread.Sleep(1);
                    pending = false;
                }
                handle.Dispose();
            }
            if (overlapped != IntPtr.Zero) { Marshal.FreeHGlobal(overlapped); overlapped = IntPtr.Zero; }
            if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); buffer = IntPtr.Zero; }
        }
    }
}
'@
}

    $snapshotChangePins = [Collections.Generic.List[IDisposable]]::new()
    $snapshotDirectoryPins = [Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $snapshotDirectoryHandles = @{}
    $snapshotDirectoryAcls = @{}
    $snapshotFileAcls = @{}
    $snapshotAclApplied = $false
    $snapshotAccepted = $false
    $snapshotIdentities = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $snapshotPins = [Collections.Generic.List[IO.FileStream]]::new()
    $snapshotId = [guid]::NewGuid().ToString('N')
    $archivePath = Join-Path $DestinationRoot "source-$snapshotId.zip"
    $snapshotPath = Join-Path $DestinationRoot "source-$snapshotId"
    if ($PreflightGuard) { $PreflightGuard.Expect($archivePath) }
    # Capture Git output in memory so the trusted archive digest never comes from
    # a writable pathname. A later disk substitution must match these exact bytes.
    $archiveProcess = [Diagnostics.Process]::new()
    $archiveProcess.StartInfo.FileName = (Get-Command git -ErrorAction Stop).Source
    $archiveProcess.StartInfo.UseShellExecute = $false
    $archiveProcess.StartInfo.CreateNoWindow = $true
    $archiveProcess.StartInfo.RedirectStandardOutput = $true
    $archiveProcess.StartInfo.RedirectStandardError = $true
    foreach ($argument in @('-C', $RepositoryRoot, 'archive', '--format=zip', $Commit)) {
        $archiveProcess.StartInfo.ArgumentList.Add($argument)
    }
    $archiveMemory = [IO.MemoryStream]::new()
    try {
        if (-not $archiveProcess.Start()) { throw 'Could not start admitted commit archiving.' }
        $archiveError = $archiveProcess.StandardError.ReadToEndAsync()
        $archiveProcess.StandardOutput.BaseStream.CopyTo($archiveMemory)
        $archiveProcess.WaitForExit()
        if ($archiveProcess.ExitCode -ne 0) { throw "Could not archive the admitted lifecycle commit: $($archiveError.GetAwaiter().GetResult())" }
        $archiveBytes = $archiveMemory.ToArray()
    } finally { $archiveMemory.Dispose(); $archiveProcess.Dispose() }
    $archiveDigest = [Security.Cryptography.SHA256]::HashData($archiveBytes)
    $archiveWriter = [IO.File]::Open($archivePath, 'CreateNew', 'Write', 'None')
    try { if ($PreflightGuard) { $PreflightGuard.Record($archivePath, $archiveWriter.SafeFileHandle) }; $archiveWriter.Write($archiveBytes); $archiveWriter.Flush($true) } finally { $archiveWriter.Dispose() }
    $archiveRead = [IO.File]::Open($archivePath, 'Open', 'Read', 'Read')
    try {
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($archiveRead)) -cne [Convert]::ToHexString($archiveDigest)) {
        throw 'Admitted source archive bytes changed before extraction.'
    }
    $archiveRead.Position = 0
    if ($PreflightGuard) {
        $PreflightGuard.Expect($snapshotPath)
        $archiveInventory = [IO.Compression.ZipArchive]::new($archiveRead, [IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            foreach ($entry in $archiveInventory.Entries) {
                $expectedPath = [IO.Path]::GetFullPath((Join-Path $snapshotPath $entry.FullName))
                $PreflightGuard.Expect($expectedPath)
                $expectedParent = [IO.Path]::GetDirectoryName($expectedPath)
                while ($expectedParent -and $expectedParent.Length -ge $snapshotPath.Length) {
                    $PreflightGuard.Expect($expectedParent)
                    $expectedParent = [IO.Path]::GetDirectoryName($expectedParent)
                }
            }
        } finally { $archiveInventory.Dispose() }
    }
    # Pin ancestors top-down and each fresh directory before any child write.
    # No delete sharing prevents replacement by a junction during extraction.
    $snapshotAncestors = [Collections.Generic.Stack[string]]::new()
    $snapshotAncestor = [IO.Path]::GetFullPath($DestinationRoot)
    while ($snapshotAncestor) {
        $snapshotAncestors.Push($snapshotAncestor)
        $snapshotAncestor = [IO.Path]::GetDirectoryName($snapshotAncestor)
    }
    # The preflight guard already retains these ancestor and result-root pins.
    while (-not $PreflightGuard -and $snapshotAncestors.Count) {
        $snapshotDirectoryPins.Add([Atlaso.SnapshotDirectoryPinV2]::Open($snapshotAncestors.Pop()))
    }
    New-Item -ItemType Directory -Path $snapshotPath -ErrorAction Stop | Out-Null
    $snapshotRootPin = [Atlaso.SnapshotDirectoryPinV2]::Open($snapshotPath, $true)
    $snapshotDirectoryPins.Add($snapshotRootPin)
    $snapshotDirectoryHandles[$snapshotPath] = $snapshotRootPin
    if ($PreflightGuard) { $PreflightGuard.RecordDirectory($snapshotPath) }
    $archiveRead.Position = 0
    $extractArchive = [IO.Compression.ZipArchive]::new($archiveRead, [IO.Compression.ZipArchiveMode]::Read, $true)
    $createdDirectories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $createdDirectories.Add($snapshotPath) | Out-Null
    try {
        foreach ($entry in $extractArchive.Entries) {
            $entryPath = [IO.Path]::GetFullPath((Join-Path $snapshotPath $entry.FullName)).TrimEnd([IO.Path]::DirectorySeparatorChar)
            if (-not $entryPath.StartsWith($snapshotPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Archive entry escaped its snapshot root.'
            }
            $directoryPath = if ($entry.FullName.EndsWith('/')) { $entryPath } else { [IO.Path]::GetDirectoryName($entryPath) }
            $missing = [Collections.Generic.Stack[string]]::new()
            while (-not $createdDirectories.Contains($directoryPath)) {
                $missing.Push($directoryPath); $directoryPath = [IO.Path]::GetDirectoryName($directoryPath)
            }
            while ($missing.Count) {
                $directoryPath = $missing.Pop()
                New-Item -ItemType Directory -Path $directoryPath -ErrorAction Stop | Out-Null
                $snapshotChildPin = [Atlaso.SnapshotDirectoryPinV2]::Open($directoryPath, $true)
                $snapshotDirectoryPins.Add($snapshotChildPin)
                $snapshotDirectoryHandles[$directoryPath] = $snapshotChildPin
                if ($PreflightGuard) { $PreflightGuard.RecordDirectory($directoryPath) }
                $createdDirectories.Add($directoryPath) | Out-Null
            }
            if ($entry.FullName.EndsWith('/')) { continue }
            $entryWriter = [IO.File]::Open($entryPath, 'CreateNew', 'Write', 'None')
            try {
                $snapshotIdentities.Add($entryPath, [Atlaso.SnapshotFileIdentityV1]::Get($entryWriter.SafeFileHandle))
                if ($PreflightGuard) { $PreflightGuard.Record($entryPath, $entryWriter.SafeFileHandle) }
                $entryReader = $entry.Open()
                try { $entryReader.CopyTo($entryWriter) } finally { $entryReader.Dispose() }
                $entryWriter.Flush($true)
            } finally { $entryWriter.Dispose() }
        }
    } finally { $extractArchive.Dispose() }
    # Deny ordinary same-user writes, including creation/replacement beneath every
    # directory. Keep DELETE rights available to supported owned-artifact cleanup.
    # Pin the actual creation objects before propagating any inherited ACL. A
    # same-byte hard-link substitution must never change an external descriptor.
    foreach ($createdFile in $snapshotIdentities.Keys) {
        $snapshotFilePin = [IO.File]::Open($createdFile, 'Open', 'Read', 'Read')
        $snapshotPins.Add($snapshotFilePin)
        if ([Atlaso.SnapshotFileIdentityV1]::Get($snapshotFilePin.SafeFileHandle) -cne $snapshotIdentities[$createdFile]) {
            throw 'Snapshot creation identity or single-link requirement failed.'
        }
        $snapshotFileAcls[$createdFile] = Get-Acl -LiteralPath $createdFile
    }
    $sourceSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $directoryOnlyDeny = [Security.AccessControl.FileSystemAccessRule]::new($sourceSid,
        [Security.AccessControl.FileSystemRights]::Write, [Security.AccessControl.AccessControlType]::Deny)
    foreach ($expectedDirectory in $createdDirectories) {
        $directoryAcl = Get-Acl -LiteralPath $expectedDirectory
        $snapshotDirectoryAcls[$expectedDirectory] = $directoryAcl.GetSecurityDescriptorBinaryForm()
        $directoryAcl.AddAccessRule($directoryOnlyDeny)
        [Atlaso.SnapshotDirectoryPinV2]::SetDacl($snapshotDirectoryHandles[$expectedDirectory], $directoryAcl.GetSecurityDescriptorBinaryForm())
    }
    # Every expected directory now rejects child creation. Inspect immediate entries
    # only, refusing unknown directories before traversing or touching their ACLs.
    foreach ($expectedDirectory in $createdDirectories) {
        foreach ($child in Get-ChildItem -LiteralPath $expectedDirectory -Force -ErrorAction Stop) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint -or
                ($child.PSIsContainer -and -not $createdDirectories.Contains($child.FullName)) -or
                (-not $child.PSIsContainer -and -not $snapshotIdentities.ContainsKey($child.FullName))) {
                throw 'Admitted source snapshot contains an unexpected entry before ACL propagation.'
            }
        }
    }
    $denyWrite = [Security.AccessControl.FileSystemAccessRule]::new($sourceSid,
        [Security.AccessControl.FileSystemRights]::Write,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Deny)
    $sourceAcl = Get-Acl -LiteralPath $snapshotPath
    $sourceAcl.AddAccessRule($denyWrite)
    $snapshotAclApplied = $true
    Set-Acl -LiteralPath $snapshotPath -AclObject $sourceAcl -ErrorAction Stop
    $sourceChanges = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset)
    $snapshotChangePins.Add($sourceChanges)
    $sourceChangeGuard = [Atlaso.LifecycleSourceChangeGuardV1]::new($snapshotPath, $sourceChanges)
    $snapshotChangePins.Add($sourceChangeGuard)
    $archiveRead.Position = 0
    $verifiedArchive = [IO.Compression.ZipArchive]::new($archiveRead, [IO.Compression.ZipArchiveMode]::Read, $true)
    $expectedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($entry in $verifiedArchive.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            $filePath = [IO.Path]::GetFullPath((Join-Path $snapshotPath $entry.FullName))
            $expectedFiles.Add($filePath) | Out-Null
            $expectedStream = $entry.Open()
            $actualStream = [IO.File]::Open($filePath, 'Open', 'Read', 'Read')
            try {
                if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expectedStream)) -cne
                    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($actualStream))) {
                    throw 'Admitted source snapshot bytes differ from the Git archive.'
                }
            } finally { $actualStream.Dispose(); $expectedStream.Dispose() }
        }
        foreach ($entry in Get-ChildItem -LiteralPath $snapshotPath -Recurse -Force -ErrorAction Stop) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint -or
                (-not $entry.PSIsContainer -and -not $expectedFiles.Contains($entry.FullName))) {
                throw 'Admitted source snapshot contains an unexpected entry.'
            }
        }
    } finally { $verifiedArchive.Dispose() }
    $sourceChangeGuard.AssertUnchanged()
    $snapshotAccepted = $true
    foreach ($directoryPin in $snapshotDirectoryPins) { $ConsumerPins.Add($directoryPin) }
    foreach ($filePin in $snapshotPins) { $ConsumerPins.Add($filePin) }
    $snapshotDirectoryPins.Clear()
    $snapshotPins.Clear()
    foreach ($changePin in $snapshotChangePins) { $ConsumerPins.Add($changePin) }
    $snapshotChangePins.Clear()
    return $snapshotPath
    } finally {
        try {
        if (-not $snapshotAccepted) {
            foreach ($frozenDirectory in $snapshotDirectoryAcls.Keys) {
                [Atlaso.SnapshotDirectoryPinV2]::SetDacl($snapshotDirectoryHandles[$frozenDirectory], $snapshotDirectoryAcls[$frozenDirectory])
            }
            if ($snapshotAclApplied) {
                foreach ($createdFile in $snapshotFileAcls.Keys) { Set-Acl -LiteralPath $createdFile -AclObject $snapshotFileAcls[$createdFile] -ErrorAction Stop }
            }
        }
        } finally {
        for ($pinIndex = $snapshotChangePins.Count - 1; $pinIndex -ge 0; $pinIndex--) { $snapshotChangePins[$pinIndex].Dispose() }
        foreach ($snapshotFilePin in $snapshotPins) { $snapshotFilePin.Dispose() }
        for ($pinIndex = $snapshotDirectoryPins.Count - 1; $pinIndex -ge 0; $pinIndex--) { $snapshotDirectoryPins[$pinIndex].Dispose() }
        $archiveRead.Dispose()
        }
    }
}

<#
.SYNOPSIS
Pin the single wheel matching the filename and digest emitted by this build.
.PARAMETER OutputRoot
Fresh output directory retained under the build's directory pins.
.PARAMETER BuildOutput
Captured pip output from this invocation, including its created-wheel digest.
.PARAMETER ConsumerPins
Caller-owned pins retained through guest upload and installation.
#>
function Get-LifecycleBuiltWheel {
    param([string]$OutputRoot, [object[]]$BuildOutput,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[IDisposable]]$ConsumerPins)
    $records = [regex]::Matches(($BuildOutput -join "`n"),
        '(?im)^\s*Created wheel for atlaso: filename=(atlaso-[A-Za-z0-9_.+\-]+\.whl) size=(\d+) sha256=([a-f0-9]{64})\s*$')
    if ($records.Count -ne 1) { throw 'Build did not report one exact Atlaso wheel identity and digest.' }
    $record = $records[0]
    $candidates = @(Get-ChildItem -LiteralPath $OutputRoot -Filter '*.whl' -File -Force)
    if ($candidates.Count -ne 1 -or $candidates[0].Name -cne $record.Groups[1].Value) {
        throw 'Wheel output does not contain exactly the artifact reported by this build.'
    }
    $wheel = $candidates[0]
    $ConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($wheel.FullName, $true))
    $wheel.Refresh()
    $digest = (Get-FileHash -LiteralPath $wheel.FullName -Algorithm SHA256).Hash
    if ($wheel.Length -ne [long]$record.Groups[2].Value -or $digest -ine $record.Groups[3].Value) {
        throw 'Built wheel bytes differ from the digest reported by this invocation.'
    }
    return [pscustomobject]@{ Name = $wheel.Name; FullName = $wheel.FullName; Sha256 = $digest }
}
Export-ModuleMember -Function Assert-LifecycleSourcePins, New-LifecycleSourceSnapshot, Get-LifecycleBuiltWheel
