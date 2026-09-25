<#
.SYNOPSIS
Run the VMware Workstation lifecycle interop scenario for Atlaso image regression and backup/restore verification.

.PARAMETER PullRequestNumber
Exact positive GitHub pull-request number that owns this lifecycle lab.
.PARAMETER Purpose
Short purpose text sanitized into the canonical lifecycle identity.
.PARAMETER CollisionSuffix
Exact collision-safe suffix that distinguishes this lab for the pull request.
.PARAMETER ApplianceVmxPath
Path to the appliance source VMX.
.PARAMETER ClientVmdkPath
Path to the base client VMDK used by generated clients.
.PARAMETER VmrunPath
Optional explicit vmrun.exe path.
.PARAMETER ManagementNetwork
VMnet/LAN segment name for management traffic.
.PARAMETER SiteANetwork
VMnet/LAN segment name for site A traffic.
.PARAMETER SiteBNetwork
VMnet/LAN segment name for site B traffic.
.PARAMETER TrunkNetwork
VMnet/LAN segment name for trunk connectivity.
.PARAMETER ApplianceIPAddress
Optional override for appliance management IPv4.
.PARAMETER ApplianceUrl
Optional override for appliance URL.
.PARAMETER SignedReleaseRepositoryUrl
Credential-free HTTPS base URL of a pre-published signed release lifecycle fixture.
.PARAMETER SiteInterface
Interface name used for site routing in workload checks.
.PARAMETER SiteCidr
Site A IPv4 CIDR used in test harness arguments.
.PARAMETER BridgedInterfaceAlias
Host interface selected for bridged VMware VMnet0 discovery.
.PARAMETER AdminUsername
Atlaso web admin username.
.PARAMETER SecretBundlePath
Path to the current-user DPAPI-protected CLIXML bundle; required unless PlanOnly is set.
.PARAMETER ApplianceSshUser
SSH username for appliance interactions.
.PARAMETER ClientSshUser
SSH username for client guest interactions.
.PARAMETER VlanId
VLAN identifier for WAN scenario traffic.
.PARAMETER TaggedVlanCidr
Tagged VLAN IPv4 CIDR.
.PARAMETER WanCidr
WAN IPv4 CIDR used by workload tests.
.PARAMETER AllowDryRunApply
Permit dry-run apply mode for the Python lifecycle harness.
.PARAMETER SkipBackupRestoreTest
Skip backup/restore validation pass.
.PARAMETER OidcOnly
Run only OIDC scenario path.
.PARAMETER CertificateOnly
Prepare only a retained appliance for the certificate handoff acceptance scenario.
.PARAMETER CertificateDhcpPeer
Prepare an owned private DHCP peer and rewire the certificate appliance management adapter to it.
.PARAMETER CertificatePeerCidr
Private peer address and prefix for the certificate management segment.
.PARAMETER CertificateLeaseAddress
Exact reserved DHCP address for the appliance management MAC.
.PARAMETER CertificatePeerPublicKeyPath
Existing Ed25519 public key whose private half is loaded in the local SSH agent.
.PARAMETER RoutingWanOnly
Run only WAN routing scenario.
.PARAMETER FullEsxiPxeInstall
Include ESXi PXE install scenario.
.PARAMETER PxeInstallerIsoPath
Path to ESXi installer ISO when PXE mode is enabled.
.PARAMETER PxeClientIPAddress
Optional explicit ESXi PXE client address.
.PARAMETER EsxiInstallTimeoutSeconds
Timeout waiting for ESXi installer guest IP.
.PARAMETER EsxiInstallProbeDelaySeconds
Delay before probing PXE-installed guest.
.PARAMETER CleanupCreatedLab
Remove generated lifecycle VM artifacts when complete.
.PARAMETER PlanOnly
Emit and return planning JSON without executing scenarios.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$PullRequestNumber,
    [string]$Purpose = 'lifecycle',
    [Parameter(Mandatory = $true)]
    [string]$CollisionSuffix,
    [Parameter(Mandatory = $true)]
    [string]$ApplianceVmxPath,
    [Parameter(Mandatory = $true)]
    [string]$ClientVmdkPath,
    [string]$VmrunPath = '',
    [string]$ManagementNetwork = 'VMnet8',
    [string]$SiteANetwork = 'VMnet2',
    [string]$SiteBNetwork = 'VMnet3',
    [string]$TrunkNetwork = 'VMnet4',
    [string]$ApplianceIPAddress = '',
    [string]$ApplianceUrl = '',
    [string]$SignedReleaseRepositoryUrl = '',
    [string]$SiteInterface = 'eth1',
    [string]$SiteCidr = '192.168.12.1/24',
    [string]$BridgedInterfaceAlias = '',
    [string]$AdminUsername = 'admin',
    [string]$SecretBundlePath = '',
    [string]$ApplianceSshUser = 'admin',
    [string]$ClientSshUser = 'alpine',
    [int]$VlanId = 50,
    [string]$TaggedVlanCidr = '192.168.60.1/24',
    [string]$WanCidr = '172.31.50.1/24',
    [switch]$AllowDryRunApply,
    [switch]$SkipBackupRestoreTest,
    [switch]$OidcOnly,
    [switch]$CertificateOnly,
    [switch]$CertificateDhcpPeer,
    [string]$CertificatePeerCidr = '192.168.77.1/24',
    [string]$CertificateLeaseAddress = '192.168.77.10',
    [string]$CertificatePeerPublicKeyPath = '',
    [switch]$RoutingWanOnly,
    [switch]$FullEsxiPxeInstall,
    [string]$PxeInstallerIsoPath = '',
    [string]$PxeClientIPAddress = '',
    [int]$EsxiInstallTimeoutSeconds = 3600,
    [int]$EsxiInstallProbeDelaySeconds = 300,
    [switch]$CleanupCreatedLab,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
if ($OidcOnly -and $SiteANetwork.StartsWith('lan:', [StringComparison]::OrdinalIgnoreCase)) {
    throw '-OidcOnly requires a host-reachable SiteANetwork; VMware LAN segments cannot carry the host-side verified OIDC probe.'
}
if ($OidcOnly -and $SiteInterface -ne 'eth1') {
    throw '-OidcOnly requires SiteInterface eth1 because its Site A vmnet is attached to the appliance second adapter.'
}
if ($CertificateDhcpPeer) {
    if ($PullRequestNumber -ne 871 -or -not $CertificateOnly -or -not $SiteANetwork.StartsWith('lan:', [StringComparison]::OrdinalIgnoreCase) -or
        $SiteANetwork.Length -le 4 -or $SiteInterface -ne 'eth0') {
        throw '-CertificateDhcpPeer requires PR 871, -CertificateOnly, a named private lan: SiteANetwork, and SiteInterface eth0.'
    }
    if (-not $PlanOnly -and -not (Test-Path -LiteralPath $ClientVmdkPath -PathType Leaf)) {
        throw 'Certificate DHCP peer requires a prepared, explicitly supplied client VMDK.'
    }
    if (-not $PlanOnly -and -not (Test-Path -LiteralPath $CertificatePeerPublicKeyPath -PathType Leaf)) {
        throw 'Certificate DHCP peer requires an existing SSH-agent Ed25519 public key.'
    }
}
if ($SignedReleaseRepositoryUrl -and ($OidcOnly -or $RoutingWanOnly -or $CertificateOnly)) {
    throw '-SignedReleaseRepositoryUrl requires the full lifecycle; it cannot be combined with -OidcOnly, -RoutingWanOnly, or -CertificateOnly.'
}
if ($SignedReleaseRepositoryUrl) {
    [Uri]$fixtureUri = $null
    if (-not [Uri]::TryCreate($SignedReleaseRepositoryUrl, [UriKind]::Absolute, [ref]$fixtureUri) -or
        -not $fixtureUri.IsWellFormedOriginalString() -or $fixtureUri.Scheme -cne 'https' -or
        -not $fixtureUri.Host -or $fixtureUri.UserInfo -or $fixtureUri.Query -or $fixtureUri.Fragment) {
        throw '-SignedReleaseRepositoryUrl must be a credential-free absolute HTTPS base URL without a query or fragment.'
    }
}
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
Bind runtime lifecycle resources to one clean source commit.
.PARAMETER RepositoryRoot
Exact lifecycle source checkout to inspect.
.PARAMETER ExpectedCommit
Previously admitted source commit required for a later resource or wheel operation.
#>
function Get-LifecycleSourceCommit {
    param([Parameter(Mandatory)][string]$RepositoryRoot, [string]$ExpectedCommit = '')
    $activeSourcePins = Get-Variable -Name runtimeConsumerPins -ValueOnly -ErrorAction SilentlyContinue
    if ($activeSourcePins) { Assert-LifecycleSourcePins -Pins $activeSourcePins }
    $commit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot resolve lifecycle source commit.' }
    $changes = @(& git -C $RepositoryRoot status --porcelain --untracked-files=normal)
    if ($LASTEXITCODE -ne 0 -or $changes.Count -gt 0) { throw 'Lifecycle runtime requires a clean source worktree before resource creation or wheel publication.' }
    $confirmed = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $confirmed -cne $commit -or ($ExpectedCommit -and $ExpectedCommit -cne $commit)) {
        throw 'Lifecycle source commit changed after admission.'
    }
    return $commit
}


<#
.SYNOPSIS
Verify the already parsed orchestration script against the admitted Git object.
.PARAMETER RepositoryRoot
Repository containing the admitted runner object.
.PARAMETER Commit
Full admitted source commit.
.PARAMETER ParsedScript
Text from the executing script block AST, not a reread of its mutable pathname.
#>
function Assert-LifecycleRunnerSource {
    param([Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$Commit, [Parameter(Mandatory)][string]$ParsedScript)
    $admittedLines = @(& git -C $RepositoryRoot show "${Commit}:scripts/windows/vmware/run-lifecycle-test.ps1")
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read the admitted lifecycle runner object.' }
    $admittedText = ($admittedLines -join "`n").TrimStart([char]0xFEFF).TrimEnd("`r", "`n")
    $parsedText = $ParsedScript.Replace("`r`n", "`n").TrimStart([char]0xFEFF).TrimEnd("`r", "`n")
    if ($parsedText -cne $admittedText) {
        throw 'Parsed lifecycle runner differs from the admitted commit; no resources may be created.'
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
Pin a fresh preflight root and delete only individually pinned descendants on failure.
.PARAMETER Path
Fresh result directory owned by this invocation.
#>
function New-LifecyclePreflightGuard {
    param([Parameter(Mandatory)][string]$Path)
    if (-not ('Atlaso.PreflightRootGuardV3' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Atlaso {
    public sealed class PreflightRootGuardV3 : IDisposable {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string p, uint a, uint s, IntPtr x, uint d, uint f, IntPtr t);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle h, int c, ref byte data, uint n);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int c, out TagInfo data, uint n);
        [StructLayout(LayoutKind.Sequential)] private struct TagInfo { public uint Attributes, Tag; }
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool GetKernelObjectSecurity(SafeFileHandle h, uint info, byte[] data, uint size, out uint needed);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool SetKernelObjectSecurity(SafeFileHandle h, uint info, byte[] data);
        [StructLayout(LayoutKind.Sequential)] private struct FileInfo {
            public uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle h, out FileInfo info);
        private readonly Dictionary<SafeFileHandle,byte[]> frozenAcls = new Dictionary<SafeFileHandle,byte[]>();
        private void Freeze(SafeFileHandle handle) {
            uint needed;
            GetKernelObjectSecurity(handle, 4, null, 0, out needed);
            if (needed == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            var original = new byte[needed];
            if (!GetKernelObjectSecurity(handle, 4, original, needed, out needed))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var acl = new System.Security.AccessControl.DirectorySecurity();
            acl.SetSecurityDescriptorBinaryForm(original);
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                System.Security.Principal.WindowsIdentity.GetCurrent().User,
                System.Security.AccessControl.FileSystemRights.Write,
                System.Security.AccessControl.AccessControlType.Deny));
            frozenAcls.Add(handle, original);
            if (!SetKernelObjectSecurity(handle, 4, acl.GetSecurityDescriptorBinaryForm()))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public void RestorePermissions() {
            foreach (var entry in frozenAcls) {
                if (!entry.Key.IsClosed && !SetKernelObjectSecurity(entry.Key, 4, entry.Value))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            frozenAcls.Clear();
        }
        public string Root { get; private set; }
        private string rootIdentity;
        private readonly List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
        private readonly List<SafeFileHandle> entries = new List<SafeFileHandle>();
        private readonly HashSet<string> capturedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> capturedDirectories = new List<string>();
        private readonly Dictionary<string,string> expected = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        [StructLayout(LayoutKind.Sequential)] private struct FileId { public ulong Volume, Low, High; }
        [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)]
        private static extern bool GetIdentity(SafeFileHandle h, int c, out FileId data, uint n);
        private string Identity(SafeFileHandle h) {
            FileId id;
            if (!GetIdentity(h, 18, out id, 24)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return id.Volume.ToString("X16") + id.Low.ToString("X16") + id.High.ToString("X16");
        }
        public void Record(string path, SafeFileHandle handle) { expected[Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar)] = Identity(handle); }
        public void RecordDirectory(string path) { using (var h = Open(path, false, true)) Record(path, h); }
        public void Published(string stage, string destination) {
            expected[Path.GetFullPath(destination)] = expected[Path.GetFullPath(stage)];
        }
        public void Expect(string path) {
            string full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            if (!full.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Preflight inventory path escaped its root.");
            if (!expected.ContainsKey(full)) expected.Add(full, null);
        }
        private SafeFileHandle Open(string path, bool delete, bool directory) {
            var h = CreateFileW(path, 0x81u | (delete ? (directory ? 0x70000u : 0x10000u) : 0), directory ? 3u : 1u,
                IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (h.IsInvalid) { h.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
            TagInfo tag;
            if (!GetFileInformationByHandleEx(h, 9, out tag, 8) || (tag.Attributes & 0x400) != 0 ||
                ((tag.Attributes & 0x10) != 0) != directory) {
                h.Dispose(); throw new IOException("Preflight entry changed type or is a reparse point.");
            }
            if (!directory) {
                FileInfo info;
                if (!GetFileInformationByHandle(h, out info) || info.Links != 1) {
                    h.Dispose(); throw new IOException("Preflight artifact is not an ordinary single-link file.");
                }
            }
            return h;
        }
        public PreflightRootGuardV3(string path) {
            Root = Path.GetFullPath(path);
            try {
                var chain = new Stack<string>();
                for (var p = Directory.GetParent(Root); p != null; p = p.Parent) chain.Push(p.FullName);
                foreach (var p in chain) ancestors.Add(Open(p, false, true));
                entries.Add(Open(Root, false, true));
                rootIdentity = Identity(entries[0]);
                capturedDirectories.Add(Root);
            } catch { Dispose(); throw; }
        }
        private void Capture(string parent) {
            foreach (string path in Directory.GetFileSystemEntries(parent)) {
                if (!expected.ContainsKey(Path.GetFullPath(path)))
                    throw new IOException("Unrecorded preflight artifact; preserve the result root.");
                bool directory = (File.GetAttributes(path) & FileAttributes.Directory) != 0;
                var captured = Open(path, true, directory);
                entries.Add(captured);
                if (expected[Path.GetFullPath(path)] == null || Identity(captured) != expected[Path.GetFullPath(path)])
                    throw new IOException("Preflight artifact creation identity changed; preserve the result root.");
                capturedPaths.Add(Path.GetFullPath(path));
                if (directory) { Freeze(captured); capturedDirectories.Add(path); Capture(path); }
            }
        }
        public void CaptureSnapshot() {
            // Upgrade only for failure cleanup, verifying the creation identity
            // before touching any ACL or descendant after the handle transition.
            entries[0].Dispose();
            entries[0] = Open(Root, true, true);
            if (Identity(entries[0]) != rootIdentity)
                throw new IOException("Preflight root creation identity changed; preserve all resources.");
            Freeze(entries[0]); Capture(Root);
        }
        public void Remove() {
            // Check the entire captured namespace before the first destructive step.
            // Pins prevent replacement/removal; unfamiliar descendants refuse the
            // whole operation instead of first consuming owned evidence.
            var observed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string directory in capturedDirectories) {
                foreach (string path in Directory.GetFileSystemEntries(directory)) {
                    string full = Path.GetFullPath(path);
                    if (!capturedPaths.Contains(full))
                        throw new IOException("Preflight descendant set changed before deletion.");
                    observed.Add(full);
                }
            }
            if (!observed.SetEquals(capturedPaths)) throw new IOException("Preflight descendant set changed before deletion.");
            // Capture each child under its already pinned parent. No recursive path
            // deletion: additions after capture make directory deletion fail closed.
            for (int i = entries.Count - 1; i >= 0; --i) {
                byte delete = 1;
                if (!SetFileInformationByHandle(entries[i], 4, ref delete, 1))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                entries[i].Dispose();
            }
        }
        public void Dispose() {
            try { RestorePermissions(); }
            finally {
                for (int i = entries.Count - 1; i >= 0; --i) entries[i].Dispose();
                for (int i = ancestors.Count - 1; i >= 0; --i) ancestors[i].Dispose();
            }
        }
    }
}
'@
    }
    return [Atlaso.PreflightRootGuardV3]::new($Path)
}

<#
.SYNOPSIS
Release only this invocation's result directory after a pre-resource failure.
.PARAMETER Path
Fresh result directory created by the current preflight invocation.
.PARAMETER ExpectedParent
Independently derived lifecycle results parent in the admitted repository.
.PARAMETER Guard
Root identity pin retained from this invocation's directory creation.
#>
function Remove-LifecyclePreflightArtifacts {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedParent,
        [Parameter(Mandatory)][object]$Guard)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $parentPath = [IO.Path]::GetFullPath($ExpectedParent)
    if (-not [IO.Path]::GetDirectoryName($fullPath).Equals($parentPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Preflight cleanup root is outside its independently derived lifecycle parent.'
    }
    $cursor = $fullPath
    while ($cursor) {
        $entry = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Preflight cleanup path contains a reparse point; preserve it.' }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    if (-not $Guard.Root.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) { throw 'Preflight root guard mismatch.' }
    try {
    $Guard.CaptureSnapshot()
    # This entry point is reachable only before provider/resource creation. Refuse
    # unexpected output instead of turning a preflight retry into VM cleanup.
    foreach ($entry in Get-ChildItem -LiteralPath $fullPath -Force -ErrorAction Stop) {
        if ($entry.Name -notmatch '^(source-[0-9a-f]{32}(\.zip)?|plan\.json|vmware-identity\.json|\.vmware-identity\..*\.tmp|vms|seed)$') {
            throw 'Unexpected preflight artifact; preserve the result root for diagnosis.'
        }
        if ($entry.Name -in @('vms', 'seed') -and @(Get-ChildItem -LiteralPath $entry.FullName -Force).Count) {
            throw 'Preflight root contains runtime artifacts; preserve it for owned resource cleanup.'
        }
    }
    if (@(Get-ChildItem -LiteralPath $fullPath -Force -Recurse -ErrorAction Stop |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
        throw 'Preflight artifacts contain a reparse point; preserve them.'
    }
    if (-not $Guard.Root.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) { throw 'Preflight root guard mismatch.' }
    $Guard.Remove()
    if (Test-Path -LiteralPath $fullPath) { throw 'Preflight artifact removal was not verified.' }
    } finally {
        $Guard.RestorePermissions()
    }
}

# Plan-only output creates no runtime resource and makes no source-provenance claim.
$sourceCommit = if ($PlanOnly) { '' } else { Get-LifecycleSourceCommit -RepositoryRoot $repoRoot }
if (-not $PlanOnly) {
    Assert-LifecycleRunnerSource -RepositoryRoot $repoRoot -Commit $sourceCommit `
        -ParsedScript $MyInvocation.MyCommand.ScriptBlock.Ast.Extent.Text
}
if ($OidcOnly) {
    if ($PlanOnly) {
        Import-Module (Join-Path $PSScriptRoot 'Atlaso.OidcSiteNetwork.psm1') -Force
    } else {
        $siteNetworkSource = @(& git -C $repoRoot show "${sourceCommit}:scripts/windows/vmware/Atlaso.OidcSiteNetwork.psm1")
        if ($LASTEXITCODE -ne 0) { throw 'Cannot load the admitted OIDC site network helper.' }
        New-Module -Name Atlaso.OidcSiteNetwork -ScriptBlock ([scriptblock]::Create(($siteNetworkSource -join "`n"))) |
            Import-Module -Force
    }
    $siteNetworkArgs = @{
        SiteANetwork = $SiteANetwork
        SiteCidr = $SiteCidr
        VmrunPath = $VmrunPath
        BridgedInterfaceAlias = $BridgedInterfaceAlias
    }
    if ($PlanOnly) {
        $siteNetworkArgs['PrepareNetworksPath'] = Join-Path $PSScriptRoot 'prepare-networks.ps1'
    } else {
        $prepareNetworksSource = @(& git -C $repoRoot show "${sourceCommit}:scripts/windows/vmware/prepare-networks.ps1")
        if ($LASTEXITCODE -ne 0) { throw 'Cannot load the admitted VMware network inventory script.' }
        $siteNetworkArgs['PrepareNetworksScript'] = [scriptblock]::Create(($prepareNetworksSource -join "`n"))
    }
    Assert-AtlasoOidcSiteNetwork @siteNetworkArgs
}
if ($PlanOnly) {
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force
} else {
    $identitySource = @(& git -C $repoRoot show "${sourceCommit}:scripts/windows/vmware/Atlaso.VmwareTestIdentity.psm1")
    if ($LASTEXITCODE -ne 0) { throw 'Cannot load the admitted lifecycle identity helper.' }
    New-Module -Name Atlaso.VmwareTestIdentity -ScriptBlock ([scriptblock]::Create(($identitySource -join "`n"))) |
        Import-Module -Force
}
$vmIdentity = New-AtlasoVmwareTestIdentity `
    -PullRequestNumber $PullRequestNumber `
    -Purpose $Purpose `
    -CollisionSuffix $CollisionSuffix
$LabName = $vmIdentity.Name
$resultRoot = Assert-AtlasoVmwareIdentityDirectory `
    -Path (Join-Path $repoRoot "test-results\vmware-workstation-lifecycle\$LabName") `
    -ExpectedName $LabName `
    -ParameterName 'LifecycleResultDirectory'
if (Test-Path -LiteralPath $resultRoot) {
    throw "Refusing lifecycle reuse because the exact PR-owned result root already exists: $resultRoot"
}
$preflightRootCreated = $false
$preflightGuard = $null
$runtimeConsumerPins = [Collections.Generic.List[IDisposable]]::new()
try {
try {
$runtimeSourceRoot = $repoRoot
if (-not $PlanOnly) {
    New-Item -ItemType Directory -Path $resultRoot -ErrorAction Stop | Out-Null
    $preflightRootCreated = $true
    $preflightGuard = New-LifecyclePreflightGuard -Path $resultRoot
    foreach ($artifact in @('plan.json', 'vmware-identity.json', 'vms', 'seed')) {
        $preflightGuard.Expect((Join-Path $resultRoot $artifact))
    }
    $runtimeSourceRoot = New-LifecycleSourceSnapshot -RepositoryRoot $repoRoot -Commit $sourceCommit -DestinationRoot $resultRoot -PreflightGuard $preflightGuard -ConsumerPins $runtimeConsumerPins
}
$runtimeVmwareRoot = Join-Path $runtimeSourceRoot 'scripts/windows/vmware'
$vmRoot = Join-Path $resultRoot 'vms'
$seedRoot = Join-Path $resultRoot 'seed'
$createdVmxPaths = New-Object System.Collections.Generic.List[string]
$diagnosticTerminationUnproven = $false

# Plan-only execution consumes no credentials. Runtime execution imports the
# current-user-protected bundle before VMware or the harness needs plaintext.
$adminPasswordSecure = $null
$sshPasswordSecure = $null
$vcfBackupPasswordSecure = $null
$esxiPasswordSecure = $null
$AdminPassword = ''
$SshPassword = ''
$VcfBackupPassword = ''
if (-not $PlanOnly) {
    if ([string]::IsNullOrWhiteSpace($SecretBundlePath)) {
        throw 'SecretBundlePath is required unless PlanOnly is set.'
    }
    $secretBundle = Import-Clixml -LiteralPath $SecretBundlePath
    foreach ($propertyName in @('AdminPassword', 'SshPassword')) {
        if ($secretBundle.$propertyName -isnot [SecureString]) {
            throw "Lifecycle secret bundle property is missing or invalid: $propertyName"
        }
    }
    $focusedRun = $OidcOnly -or $RoutingWanOnly -or $CertificateOnly
    if (-not $focusedRun -and $secretBundle.VcfBackupPassword -isnot [SecureString]) {
        throw 'Lifecycle secret bundle property is missing or invalid: VcfBackupPassword'
    }
    if ($focusedRun -and $null -ne $secretBundle.VcfBackupPassword -and $secretBundle.VcfBackupPassword -isnot [SecureString]) {
        throw 'Lifecycle secret bundle property is invalid: VcfBackupPassword'
    }
    if ($FullEsxiPxeInstall -and $secretBundle.EsxiPassword -isnot [SecureString]) {
        throw 'Lifecycle secret bundle property is missing or invalid: EsxiPassword'
    }
    $adminPasswordSecure = $secretBundle.AdminPassword
    $sshPasswordSecure = $secretBundle.SshPassword
    $vcfBackupPasswordSecure = $secretBundle.VcfBackupPassword
    $esxiPasswordSecure = $secretBundle.EsxiPassword
    $AdminPassword = ConvertFrom-SecureString -SecureString $adminPasswordSecure -AsPlainText
    $SshPassword = ConvertFrom-SecureString -SecureString $sshPasswordSecure -AsPlainText
    if ($null -ne $vcfBackupPasswordSecure) {
        $VcfBackupPassword = ConvertFrom-SecureString -SecureString $vcfBackupPasswordSecure -AsPlainText
    }
}
. (Join-Path $runtimeVmwareRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $runtimeVmwareRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $runtimeVmwareRoot 'Atlaso.VmwarePayload.psm1') -Force
if (-not $SshPassword) {
    $SshPassword = $AdminPassword
}
$ApplianceGuestPassword = $AdminPassword
if ($RoutingWanOnly) {
    $SkipBackupRestoreTest = $true
}
if ($OidcOnly) {
    $SkipBackupRestoreTest = $true
}
if ($CertificateOnly) {
    $SkipBackupRestoreTest = $true
    if (-not $PlanOnly) {
        if ($CleanupCreatedLab) { throw 'Certificate preparation must retain its appliance until native acceptance and owned cleanup.' }
        if (-not $env:CODEX_THREAD_ID) { throw 'Certificate preparation requires the originating task ID before resource creation.' }
    }
}

<#
.SYNOPSIS
Run the Python lifecycle consumer with a secret envelope supplied through standard input.

.PARAMETER Arguments
Literal Python arguments that contain no lifecycle passwords.

.PARAMETER SourcePins
Retained admitted-source handles and recursive change guards for this consumer.

.PARAMETER AdminPassword
Protected Atlaso administrator password written only to the child process standard-input stream.

.PARAMETER SshPassword
Protected client SSH password written only to the child process standard-input stream.

.PARAMETER VcfBackupPassword
Optional protected VCF Backup password written only to the child process standard-input stream.

.PARAMETER EsxiPassword
Optional protected ESXi password written only to the child process standard-input stream.
#>
function Invoke-LifecyclePython {
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[IDisposable]]$SourcePins,
        [Parameter(Mandatory = $true)][SecureString]$AdminPassword,
        [Parameter(Mandatory = $true)][SecureString]$SshPassword,
        [SecureString]$VcfBackupPassword,
        [SecureString]$EsxiPassword
    )

    $adminPasswordText = ''
    $sshPasswordText = ''
    $vcfBackupPasswordText = ''
    $esxiPasswordText = ''
    $secretPayload = ''
    try {
        $adminPasswordText = ConvertFrom-SecureString -SecureString $AdminPassword -AsPlainText
        $sshPasswordText = ConvertFrom-SecureString -SecureString $SshPassword -AsPlainText
        if ($null -ne $VcfBackupPassword) {
            $vcfBackupPasswordText = ConvertFrom-SecureString -SecureString $VcfBackupPassword -AsPlainText
        }
        if ($null -ne $EsxiPassword) {
            $esxiPasswordText = ConvertFrom-SecureString -SecureString $EsxiPassword -AsPlainText
        }
        # One compressed JSON line keeps every lifecycle credential out of the
        # child command line without creating another plaintext file boundary.
        $secretPayload = [pscustomobject]@{
            password               = $adminPasswordText
            appliance_ssh_password = $adminPasswordText
            ssh_password           = $sshPasswordText
            vcf_backup_password    = $vcfBackupPasswordText
            esxi_password          = $esxiPasswordText
        } | ConvertTo-Json -Compress
        # Keep the child's progress output visible without adding it to this
        # function's success stream, which is reserved for the exit code.
        Assert-LifecycleSourcePins -Pins $SourcePins
        # Isolated mode excludes the script directory, cwd and PYTHONPATH from imports.
        # Newly added snapshot entries cannot shadow installed consumer dependencies.
        $secretPayload | & python -I @Arguments | Out-Host
        $consumerExitCode = $LASTEXITCODE
        Assert-LifecycleSourcePins -Pins $SourcePins
        return $consumerExitCode
    }
    finally {
        $adminPasswordText = $null
        $sshPasswordText = $null
        $vcfBackupPasswordText = $null
        $esxiPasswordText = $null
        $secretPayload = $null
    }
}

<#
.SYNOPSIS
Resolve the vmrun path from a user override or common install locations.

.PARAMETER VmrunPath
Optional vmrun.exe path or install directory.
#>

function Resolve-VmrunPath {
    if ($VmrunPath) {
        if (-not (Test-Path -LiteralPath $VmrunPath)) {
            throw "vmrun.exe not found: $VmrunPath"
        }
        return (Resolve-Path -LiteralPath $VmrunPath).Path
    }
    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

<#
.SYNOPSIS
Resolve vmware-vdiskmanager from supported installation locations.
#>
function Resolve-VdiskManagerPath {
    $vmrunDirectory = Split-Path -Parent $resolvedVmrun
    $candidate = Join-Path $vmrunDirectory 'vmware-vdiskmanager.exe'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }
    foreach ($path in @(
        'C:\Program Files\VMware\VMware Workstation\vmware-vdiskmanager.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe'
    )) {
        if (Test-Path -LiteralPath $path) {
            return $path
        }
    }
    $command = Get-Command vmware-vdiskmanager -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmware-vdiskmanager.exe was not found. It is required for lifecycle appliance storage and -FullEsxiPxeInstall.'
}

<#
.SYNOPSIS
Reject reserved VM names to avoid clobbering protected environments.

.PARAMETER Name
VM name to validate.
#>
function Assert-SafeLifecycleName {
    param([string]$Name)

    $reserved = @('Atlaso', 'Atlaso-Photon-Builder', 'Atlaso-Photon-Builder-VMware')
    if ($reserved -contains $Name) {
        throw "Refusing to use reserved VM name '$Name'. Lifecycle tests must use a separate VM set."
    }
    $escapedLabName = [regex]::Escape($LabName)
    if ($Name -cnotmatch "^$escapedLabName-(Appliance|ClientA|ClientB|ESXiPXE)$") {
        throw "Refusing VM name '$Name' because it is not an exact child of PR-owned lifecycle lab '$LabName'."
    }
}

<#
.SYNOPSIS
Escape a value for single-quoted shell expansion.

.PARAMETER Value
String value to escape.
#>
function ConvertTo-GuestShellSingleQuote {
    param([string]$Value)
    return "'" + ($Value -replace "'", "'\''") + "'"
}

<#
.SYNOPSIS
Escape an argument for native command execution.

.PARAMETER Value
Input string to escape.
#>
function ConvertTo-NativeArgument {
    param([string]$Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

<#
.SYNOPSIS
Run vmrun through .NET process execution with bounded timeout.

.PARAMETER Arguments
Argument list for vmrun.
.PARAMETER TimeoutSeconds
Bounded timeout in seconds.
#>
function Invoke-VmrunBounded {
    param(
        [string[]]$Arguments,
        [int]$TimeoutSeconds = 30
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedVmrun
    $startInfo.Arguments = ($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try {
            $process.Kill()
        } catch {
            Write-Verbose "Could not terminate timed-out vmrun process: $($_.Exception.Message)"
        }
        return [pscustomobject]@{
            ExitCode = -1
            TimedOut = $true
            StdOut   = ''
            StdErr   = "vmrun timed out after $TimeoutSeconds seconds: $($Arguments -join ' ')"
        }
    }
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        TimedOut = $false
        StdOut   = $process.StandardOutput.ReadToEnd()
        StdErr   = $process.StandardError.ReadToEnd()
    }
}

<#
.SYNOPSIS
Generate a randomized static MAC in VMware OUI space.
#>

function New-StaticVmwareMac {
    $bytes = [guid]::NewGuid().ToByteArray()
    return ('00:50:56:{0:x2}:{1:x2}:{2:x2}' -f (0x20 -bor ($bytes[0] -band 0x1f)), $bytes[1], $bytes[2])
}

<#
.SYNOPSIS
Escape a literal value for a VMX assignment.
.PARAMETER Value
Unquoted VMX property text to escape and quote.
#>
function ConvertTo-VmxString {
    param([string]$Value)
    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

<#
.SYNOPSIS
Set one VMX key while preserving unrelated configuration.
.PARAMETER Path
VMX file whose exact key assignment is updated.
.PARAMETER Key
VMX property name to replace or append.
.PARAMETER Value
Unquoted VMX property value to serialize.
#>
function Set-VmxValue {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )

    $line = "$Key = $(ConvertTo-VmxString -Value $Value)"
    $content = if (Test-Path -LiteralPath $Path) {
        @(Get-Content -LiteralPath $Path)
    } else {
        @()
    }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
        if ($_ -match $pattern) {
            $updated = $true
            $line
        } else {
            $_
        }
    })
    if (-not $updated) {
        $content += $line
    }
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

<#
.SYNOPSIS
Remove a VMX setting key from a VMX file.

.PARAMETER Path
Path to VMX file.
.PARAMETER Key
VMX key name to remove.
#>
function Remove-VmxValue {
    param(
        [string]$Path,
        [string]$Key
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $content = @(Get-Content -LiteralPath $Path | Where-Object { $_ -notmatch $pattern })
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

<#
.SYNOPSIS
Resolve a LAN segment and retain creation receipts only for this lifecycle task.
.PARAMETER Name
Exact requested LAN segment name.
#>
function Resolve-LanSegmentId {
    param([string]$Name)
    Get-LifecycleSourceCommit -RepositoryRoot $repoRoot -ExpectedCommit $sourceCommit | Out-Null
    $segment = Resolve-AtlasoOwnedLanSegment -Name $Name -Owner $lanSegmentOwner -PublishReceipt {
        param($pendingSegment)
        $ownedLanSegments.Add($pendingSegment)
        Write-LifecycleIdentityEvidence
    }
    return $segment.Id
}

<#
.SYNOPSIS
Apply a VMX ethernet adapter configuration.

.PARAMETER Path
VMX path to mutate.
.PARAMETER Index
Ethernet adapter index.
.PARAMETER Vmnet
VMnet or lan-segment reference.
.PARAMETER StaticMac
Optional static MAC address.
.PARAMETER VirtualDev
VMXNET device type.
.PARAMETER PciSlotNumber
Explicit slot for stable guest enumeration of the four appliance adapters.
#>
function Set-VmxNetworkAdapter {
    param(
        [string]$Path,
        [int]$Index,
        [string]$Vmnet,
        [string]$StaticMac = '',
        [string]$VirtualDev = 'vmxnet3',
        [int]$PciSlotNumber = 0
    )

    $prefix = "ethernet$Index"
    if ($Vmnet -match '^(?i)vmnet(\d+)$') {
        $Vmnet = "VMnet$($Matches[1])"
    }
    Set-VmxValue -Path $Path -Key "$prefix.present" -Value 'TRUE'
    if ($Vmnet.StartsWith('lan:')) {
        $segmentName = $Vmnet.Substring(4)
        $pvnId = Resolve-LanSegmentId -Name $segmentName
        Set-VmxValue -Path $Path -Key "$prefix.connectionType" -Value 'pvn'
        Set-VmxValue -Path $Path -Key "$prefix.pvnID" -Value $pvnId
        Remove-VmxValue -Path $Path -Key "$prefix.vnet"
    } else {
        Set-VmxValue -Path $Path -Key "$prefix.connectionType" -Value 'custom'
        Set-VmxValue -Path $Path -Key "$prefix.vnet" -Value $Vmnet
        Remove-VmxValue -Path $Path -Key "$prefix.pvnID"
    }
    Set-VmxValue -Path $Path -Key "$prefix.virtualDev" -Value $VirtualDev
    if ($StaticMac) {
        Set-VmxValue -Path $Path -Key "$prefix.addressType" -Value 'static'
        Set-VmxValue -Path $Path -Key "$prefix.address" -Value $StaticMac
    }
    Set-VmxValue -Path $Path -Key "$prefix.startConnected" -Value 'TRUE'
    if ($PciSlotNumber -gt 0) {
        Set-VmxValue -Path $Path -Key "$prefix.pciSlotNumber" -Value ([string]$PciSlotNumber)
    }
}

<#
.SYNOPSIS
Clone a verified appliance with its required data disks into the lifecycle lab.

.PARAMETER SourceVmx
Source VMX path.
.PARAMETER DestinationDirectory
Destination directory for the copied appliance.
.PARAMETER Name
Lifecycle VM name.
.PARAMETER PreparedDirectoryIdentity
Original identity of an empty certificate VM directory recorded before cloning.
#>
function Copy-VmDirectory {
    param(
        [string]$SourceVmx,
        [string]$DestinationDirectory,
        [string]$Name,
        [string]$PreparedDirectoryIdentity = ''
    )

    Assert-SafeLifecycleName -Name $Name
    $resolvedSourceVmx = (Resolve-Path -LiteralPath $SourceVmx).Path
    Assert-AtlasoTemplatePoweredOff -VmxPath $resolvedSourceVmx -VmrunPath $resolvedVmrun
    Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx | Out-Null
    if (Test-Path -LiteralPath $DestinationDirectory) {
        if (-not $PreparedDirectoryIdentity -or
            (Get-AtlasoPathIdentity -Path $DestinationDirectory -Description 'prepared certificate VM directory') -cne $PreparedDirectoryIdentity -or
            @(Get-ChildItem -LiteralPath $DestinationDirectory -Force).Count) {
            throw "Lifecycle VM directory already exists or changed: $DestinationDirectory"
        }
    } elseif ($PreparedDirectoryIdentity) {
        throw 'Prepared certificate VM directory disappeared before cloning.'
    }
    $targetVmx = Join-Path $DestinationDirectory "$Name.vmx"
    if ($PSCmdlet.ShouldProcess($DestinationDirectory, "Clone Workstation VM $Name with dedicated storage")) {
        try {
            # Reuse the normal clone contract: immutable two-payload source,
            # private 500 GiB thin depot/backup disks at SCSI units 2 and 3.
            # Lifecycle-specific LAN adapters are configured by the caller.
            & (Join-Path $runtimeVmwareRoot 'create-atlaso-vm.ps1') `
                -Name $Name -ApplianceVmxPath $resolvedSourceVmx `
                -OutputDirectory $DestinationDirectory -VmrunPath $resolvedVmrun `
                -VdiskManagerPath (Resolve-VdiskManagerPath) `
                -ManagementNetwork $ManagementNetwork -SkipLabNetworkAdapters | Out-Host
        }
        finally {
            # A failed disk creation can leave a valid clone. Retain its exact
            # identity for supported cleanup even when provisioning throws.
            if (Test-Path -LiteralPath $targetVmx -PathType Leaf) {
                $createdVmxPaths.Add($targetVmx)
            }
        }
    }
    return $targetVmx
}

<#
.SYNOPSIS
Create a new client VM from a base VMDK and seed ISO.

.PARAMETER Name
Client VM name.
.PARAMETER Directory
Destination VM directory.
.PARAMETER DiskPath
Base client VMDK path.
.PARAMETER SeedIso
NoCloud seed ISO path.
.PARAMETER Networks
VM adapter target networks by index.
#>
function New-ClientVm {
    param(
        [string]$Name,
        [string]$Directory,
        [string]$DiskPath,
        [string]$SeedIso,
        [string[]]$Networks
    )

    Assert-SafeLifecycleName -Name $Name
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $diskTarget = Join-Path $Directory "$Name.vmdk"
    if ($PSCmdlet.ShouldProcess($diskTarget, "Copy client VMDK for $Name")) {
        Copy-Item -LiteralPath $DiskPath -Destination $diskTarget
    }
    $vmxPath = Join-Path $Directory "$Name.vmx"
    $lines = @(
        '.encoding = "windows-1252"',
        'config.version = "8"',
        'virtualHW.version = "21"',
        'firmware = "efi"',
        'uefi.secureBoot.enabled = "FALSE"',
        "displayName = $(ConvertTo-VmxString -Value $Name)",
        'guestOS = "other5xlinux-64"',
        'memsize = "1024"',
        'numvcpus = "1"',
        'sata0.present = "TRUE"',
        'sata0:0.present = "TRUE"',
        "sata0:0.fileName = $(ConvertTo-VmxString -Value (Split-Path -Leaf $diskTarget))",
        'sata0:0.deviceType = "disk"',
        'sata0:1.present = "TRUE"',
        "sata0:1.fileName = $(ConvertTo-VmxString -Value $SeedIso)",
        'sata0:1.deviceType = "cdrom-image"',
        'sata0:1.startConnected = "TRUE"'
    )
    [System.IO.File]::WriteAllLines($vmxPath, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    for ($index = 0; $index -lt $Networks.Count; $index++) {
        Set-VmxNetworkAdapter -Path $vmxPath -Index $index -Vmnet $Networks[$index] -VirtualDev 'e1000'
    }
    $createdVmxPaths.Add($vmxPath)
    return $vmxPath
}

<#
.SYNOPSIS
Create a temporary ESXi PXE install VM for extended lifecycle coverage.

.PARAMETER Name
ESXi VM name.
.PARAMETER Directory
VM directory.
.PARAMETER Network
Initial network attachment.
.PARAMETER MacAddress
Optional static MAC address.
#>
function New-EsxiPxeVm {
    param(
        [string]$Name,
        [string]$Directory,
        [string]$Network,
        [string]$MacAddress
    )

    Assert-SafeLifecycleName -Name $Name
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $diskTarget = Join-Path $Directory "$Name.vmdk"
    $vdiskManager = Resolve-VdiskManagerPath
    if ($PSCmdlet.ShouldProcess($diskTarget, "Create ESXi PXE install disk for $Name")) {
        & $vdiskManager -c -s 32GB -a pvscsi -t 0 $diskTarget | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create ESXi PXE install disk with vmware-vdiskmanager."
        }
    }
    $vmxPath = Join-Path $Directory "$Name.vmx"
    $lines = @(
        '.encoding = "windows-1252"',
        'config.version = "8"',
        'virtualHW.version = "22"',
        'pciBridge0.present = "TRUE"',
        'pciBridge4.present = "TRUE"',
        'pciBridge4.virtualDev = "pcieRootPort"',
        'pciBridge4.functions = "8"',
        'pciBridge5.present = "TRUE"',
        'pciBridge5.virtualDev = "pcieRootPort"',
        'pciBridge5.functions = "8"',
        'pciBridge6.present = "TRUE"',
        'pciBridge6.virtualDev = "pcieRootPort"',
        'pciBridge6.functions = "8"',
        'pciBridge7.present = "TRUE"',
        'pciBridge7.virtualDev = "pcieRootPort"',
        'pciBridge7.functions = "8"',
        'vmci0.present = "TRUE"',
        'virtualHW.productCompatibility = "hosted"',
        'firmware = "efi"',
        'uefi.secureBoot.enabled = "FALSE"',
        "displayName = $(ConvertTo-VmxString -Value $Name)",
        'guestOS = "vmkernel9"',
        'memsize = "8192"',
        'numvcpus = "4"',
        'vhv.enable = "FALSE"',
        'tools.syncTime = "FALSE"',
        'floppy0.present = "FALSE"',
        'scsi0.present = "TRUE"',
        'scsi0.virtualDev = "pvscsi"',
        'scsi0:0.present = "TRUE"',
        "scsi0:0.fileName = $(ConvertTo-VmxString -Value (Split-Path -Leaf $diskTarget))"
    )
    [System.IO.File]::WriteAllLines($vmxPath, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    Set-VmxNetworkAdapter -Path $vmxPath -Index 0 -Vmnet $Network -StaticMac $MacAddress -VirtualDev 'vmxnet3'
    $createdVmxPaths.Add($vmxPath)
    return $vmxPath
}

<#
.SYNOPSIS
Create a NoCloud seed ISO for a client VM.

.PARAMETER Path
Seed ISO output path.
.PARAMETER HostName
Client hostname for cloud-init metadata.
#>
function New-CloudInitSeedIso {
    param(
        [string]$Path,
        [string]$HostName
    )

    if ($PSCmdlet.ShouldProcess($Path, "Create NoCloud seed disk for $HostName")) {
        python -c 'import pycdlib' 2>$null
        if ($LASTEXITCODE -ne 0) {
            python -m pip install pycdlib
        }
        $helper = Join-Path $runtimeSourceRoot 'scripts\interop\create_nocloud_seed_iso.py'
        # The repository-controlled seed helper reads one password line from
        # stdin so the client credential never appears in process arguments.
        $SshPassword | & python $helper --output $Path --hostname $HostName --user $ClientSshUser --password-stdin | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create NoCloud seed ISO for $HostName"
        }
    }
}

<#
.SYNOPSIS
Create the first-boot seed for the task-owned certificate DHCP peer.
.PARAMETER Path
New task-owned seed ISO path.
.PARAMETER HostName
Peer guest hostname.
.PARAMETER ClientMac
Exact reserved appliance management MAC.
#>
function New-CertificatePeerSeedIso {
    param([string]$Path, [string]$HostName, [string]$ClientMac)
    if ($PSCmdlet.ShouldProcess($Path, "Create private certificate DHCP peer seed for $HostName")) {
        python -c 'import pycdlib' 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'pycdlib must be installed before creating the certificate peer seed.' }
        $helper = Join-Path $runtimeSourceRoot 'scripts\interop\create_certificate_peer_seed_iso.py'
        & python $helper --output $Path --hostname $HostName --user $ClientSshUser `
            --public-key $certificatePeerPublicKey --server-cidr $CertificatePeerCidr --lease-address $CertificateLeaseAddress `
            --client-mac $ClientMac | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Certificate peer seed creation failed for $HostName." }
    }
}

<#
.SYNOPSIS
Verify that the certificate peer consumed its seed and started dnsmasq.
.PARAMETER Path
Task-owned peer VMX path.
#>
function Assert-CertificatePeerBootReady {
    param([string]$Path)
    $address = Wait-CertificatePeerManagementAddress -Path $Path
    $probe = Invoke-CertificatePeerSsh -Address $address -Command `
        'cloud-init status --wait >/dev/null 2>&1 && sudo dnsmasq --test --conf-file=/etc/dnsmasq.conf >/dev/null 2>&1 && sudo rc-service dnsmasq status >/dev/null 2>&1'
    if ($probe.ExitCode -ne 0) {
        throw 'Certificate DHCP peer did not complete first boot with an active, valid dnsmasq configuration.'
    }
}

<#
.SYNOPSIS
Wait for VMware Tools to report the peer management address without guest credentials.
.PARAMETER Path
Owned peer VMX path.
#>
function Wait-CertificatePeerManagementAddress {
    param([Parameter(Mandatory)][string]$Path)
    $deadline = (Get-Date).AddSeconds(300)
    while ((Get-Date) -lt $deadline) {
        $reported = Invoke-VmrunBounded -Arguments @('-T', 'ws', 'getGuestIPAddress', $Path) -TimeoutSeconds 10
        if (-not $reported.TimedOut -and $reported.ExitCode -eq 0) {
            $address = Get-GuestIPv4FromAddressText -Lines @($reported.StdOut -split "`r?`n")
            if ($address) { return $address }
        }
        Start-Sleep -Seconds 5
    }
    throw 'Certificate peer management address was unavailable from owned VMware Tools.'
}

<#
.SYNOPSIS
Run a peer command using only the selected local SSH agent key.
.PARAMETER Address
VMware-reported peer management address.
.PARAMETER Command
Read-only guest command with nonsecret output.
.PARAMETER TimeoutSeconds
Maximum bounded SSH execution time.
#>
function Invoke-CertificatePeerSsh {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$Command,
        [int]$TimeoutSeconds = 300
    )
    $ssh = (Get-Command ssh.exe -CommandType Application -ErrorAction Stop).Source
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ssh
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'IdentitiesOnly=yes',
            '-o', 'HostKeyAlgorithms=ssh-ed25519',
            '-o', 'StrictHostKeyChecking=accept-new', '-o', 'HashKnownHosts=no',
            '-o', 'UpdateHostKeys=no', '-o', "HostKeyAlias=$clientAName",
            '-o', "UserKnownHostsFile=$certificatePeerKnownHostsPath", '-o', 'ConnectTimeout=10',
            '-i', $certificatePeerPublicKeySnapshot,
            "$ClientSshUser@$Address", $Command
        )) { [void]$startInfo.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
            throw 'Certificate peer SSH command timed out.'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        if ($output.Length -gt 1024) { throw 'Certificate peer SSH output exceeded the identity bound.' }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = @($output -split "`r?`n" | Where-Object { $_ }) }
    } finally {
        $process.Dispose()
    }
}

<#
.SYNOPSIS
Capture the owned peer's management address and SSH host key through VMware Tools and agent SSH.
.PARAMETER Path
Original task-owned peer VMX path.
#>
function Get-CertificatePeerOriginalIdentity {
    param([Parameter(Mandatory)][string]$Path)
    $addressFromVmware = Wait-CertificatePeerManagementAddress -Path $Path
    $query = Invoke-CertificatePeerSsh -Address $addressFromVmware -Command `
        "ip -4 -o addr show dev eth0 | awk 'NR == 1 { print `$4 }'; cat /etc/ssh/ssh_host_ed25519_key.pub"
    if ($query.ExitCode -ne 0) { throw 'Certificate peer original identity query failed.' }
    $lines = @($query.Output)
    if ($lines.Count -gt 2 -or -not (Test-Path -LiteralPath $certificatePeerKnownHostsPath -PathType Leaf) -or
        (Get-Item -LiteralPath $certificatePeerKnownHostsPath).Length -gt 1024) {
        throw 'Certificate peer original identity readback is missing or oversized.'
    }
    $addressMatch = if ($lines.Count -eq 2) { [regex]::Match($lines[0], '^(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})/[0-9]{1,2}$') }
    $keyMatch = if ($lines.Count -eq 2) { [regex]::Match($lines[1], '^ssh-ed25519 (?<key>[A-Za-z0-9+/]+={0,2})(?:\s+[^\r\n]{1,128})?$') }
    if ($lines.Count -ne 2 -or -not $addressMatch.Success -or -not $keyMatch.Success) {
        throw 'Certificate peer original identity shape is invalid.'
    }
    $address = [Net.IPAddress]::Parse($addressMatch.Groups['ip'].Value)
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $address.ToString() -ceq '0.0.0.0') { throw 'Certificate peer management address is invalid.' }
    $key = [Convert]::FromBase64String($keyMatch.Groups['key'].Value)
    $fingerprint = 'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($key)).TrimEnd('=')
    if ($fingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
        throw 'Certificate peer SSH host key is invalid.'
    }
    if ($address.ToString() -cne $addressFromVmware) { throw 'Certificate peer SSH address differs from VMware Tools.' }
    $knownHost = @(Get-Content -LiteralPath $certificatePeerKnownHostsPath)
    if ($knownHost.Count -ne 1 -or $knownHost[0] -cne "$clientAName ssh-ed25519 $($keyMatch.Groups['key'].Value)") {
        throw 'Certificate peer SSH host key differs from the pinned agent connection.'
    }
    return [ordered]@{ management_address = $address.ToString(); ssh_host_key = $fingerprint }
}

<#
.SYNOPSIS
Invoke vmrun with fail-fast behavior.

.PARAMETER Arguments
vmrun arguments.
#>
function Invoke-Vmrun {
    param([string[]]$Arguments)
    & $resolvedVmrun @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

<#
.SYNOPSIS
Register a Workstation VM if possible.

.PARAMETER Path
VMX path to register.
#>
function Register-WorkstationVm {
    param([string]$Path)
    if ($PSCmdlet.ShouldProcess($Path, 'Register Workstation VM')) {
        & $resolvedVmrun -T ws register $Path 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Verbose "Workstation VM may already be registered: $Path"
        }
    }
}

<#
.SYNOPSIS
Start a Workstation VM with bounded registration workflow.

.PARAMETER Path
VMX path to start.
#>
function Start-WorkstationVm {
    param([string]$Path)
    if ($PSCmdlet.ShouldProcess($Path, 'Start Workstation VM')) {
        Register-WorkstationVm -Path $Path
        Invoke-Vmrun -Arguments @('-T', 'ws', 'start', $Path, 'nogui')
    }
}

<#
.SYNOPSIS
Report whether an exact VMware Workstation VMX is running.

.PARAMETER Path
VMX path whose running state is queried.
#>
function Test-WorkstationVmRunning {
    param([string]$Path)

    $listResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', 'list') -TimeoutSeconds 15
    if ($listResult.ExitCode -ne 0) {
        throw "Failed to list running VMware Workstation VMs before seed cleanup: $($listResult.StdErr)"
    }
    $targetPath = [System.IO.Path]::GetFullPath($Path)
    foreach ($line in @($listResult.StdOut -split "`r?`n")) {
        $candidate = $line.Trim()
        if (-not $candidate -or $candidate -match '^Total running VMs:') {
            continue
        }
        try {
            $candidatePath = [System.IO.Path]::GetFullPath($candidate)
        } catch {
            continue
        }
        if ([string]::Equals($candidatePath, $targetPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

<#
.SYNOPSIS
Stop one running client VM before detaching its credential-bearing seed.

.PARAMETER Path
Client VMX path to stop.
#>
function Stop-WorkstationVmForSeedCleanup {
    [OutputType([bool])]
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or -not (Test-WorkstationVmRunning -Path $Path)) {
        return $false
    }
    [void](Invoke-VmrunBounded -Arguments @('-T', 'ws', 'stop', $Path, 'soft') -TimeoutSeconds 45)
    if (Test-WorkstationVmRunning -Path $Path) {
        [void](Invoke-VmrunBounded -Arguments @('-T', 'ws', 'stop', $Path, 'hard') -TimeoutSeconds 30)
    }
    if (Test-WorkstationVmRunning -Path $Path) {
        throw "Client VM remained running during credential-bearing seed cleanup: $Path"
    }
    return $true
}

<#
.SYNOPSIS
Detach and delete credential-bearing client seed ISOs with absence verification.

.PARAMETER VmxPaths
Client VMX paths that may reference the seed ISOs.

.PARAMETER SeedPaths
Exact seed ISO paths to delete.

.PARAMETER Restart
Restart client VMs that were running after all seeds are verifiably absent.
#>
function Remove-ClientSeedArtifacts {
    param(
        [string[]]$VmxPaths,
        [string[]]$SeedPaths,
        [switch]$Restart
    )

    $restartPaths = New-Object System.Collections.Generic.List[string]
    foreach ($vmxPath in @($VmxPaths | Where-Object { $_ })) {
        if (Stop-WorkstationVmForSeedCleanup -Path $vmxPath) {
            $restartPaths.Add($vmxPath)
        }
        if (Test-Path -LiteralPath $vmxPath -PathType Leaf) {
            # A stopped VM cannot retain an open seed handle. Detach before
            # deletion so a later restart cannot reacquire the secret artifact.
            Set-VmxValue -Path $vmxPath -Key 'sata0:1.present' -Value 'FALSE'
            foreach ($key in @('sata0:1.fileName', 'sata0:1.deviceType', 'sata0:1.startConnected')) {
                Remove-VmxValue -Path $vmxPath -Key $key
            }
        }
    }
    foreach ($seedPath in @($SeedPaths | Where-Object { $_ })) {
        if (Test-Path -LiteralPath $seedPath) {
            if ($PSCmdlet.ShouldProcess($seedPath, 'Delete credential-bearing client seed ISO')) {
                Remove-Item -LiteralPath $seedPath -Force -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $seedPath) {
            throw "Credential-bearing client seed ISO remains after cleanup: $seedPath"
        }
    }
    if ($Restart) {
        foreach ($vmxPath in $restartPaths) {
            $startParameters = @{ Path = $vmxPath }
            Start-WorkstationVm @startParameters
        }
    }
}

function Test-TcpPort {
<#
.SYNOPSIS
Check host/port reachability with bounded timeout.

.PARAMETER HostName
Target host.
.PARAMETER Port
Target TCP port.
.PARAMETER TimeoutMilliseconds
Connection timeout in milliseconds.
#>
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 1000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

<#
.SYNOPSIS
Read host SSH key fingerprint text via plink probe.

.PARAMETER HostName
SSH host to probe.
.PARAMETER UserName
SSH username.
.PARAMETER Password
SSH password.
#>
function Get-PlinkHostKey {
    param(
        [string]$HostName,
        [string]$UserName,
        [SecureString]$Password
    )

    if (-not $HostName -or -not $Password -or -not (Get-Command plink -ErrorAction SilentlyContinue)) {
        return ''
    }

    $passwordText = ConvertFrom-SecureString -SecureString $Password -AsPlainText

    $deadline = (Get-Date).AddMinutes(4)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-TcpPort -HostName $HostName -Port 22 -TimeoutMilliseconds 1000)) {
            Start-Sleep -Seconds 5
            continue
        }

        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & plink -batch -ssh -pw $passwordText "$UserName@$HostName" 'hostname' 2>&1
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $text = ($output | Out-String)
        if ($text -match '(ssh-[A-Za-z0-9-]+\s+\d+\s+SHA256:[A-Za-z0-9+/=]+)') {
            $hostKey = $Matches[1]
            $passwordText = $null
            return $hostKey
        }
        if ($exitCode -eq 0) {
            $passwordText = $null
            return ''
        }
        Start-Sleep -Seconds 5
    }
    $passwordText = $null
    Write-Warning "Timed out waiting for SSH host key from $UserName@$HostName; continuing without host key pinning."
    return ''
}

<#
.SYNOPSIS
Parse IPv4 addresses from text lines.

.PARAMETER Lines
Text lines to scan.
#>
function Get-GuestIPv4FromAddressText {
    param([string[]]$Lines)

    foreach ($line in $Lines) {
        foreach ($match in [regex]::Matches($line, '(?<ip>(?:\d{1,3}\.){3}\d{1,3})/\d+')) {
            $ip = $match.Groups['ip'].Value
            if ($ip -notlike '127.*' -and $ip -notlike '169.254.*') {
                return $ip
            }
        }
        if ($line -match '^\s*(?<ip>(?:\d{1,3}\.){3}\d{1,3})\s*$') {
            $ip = $Matches['ip']
            if ($ip -notlike '127.*' -and $ip -notlike '169.254.*') {
                return $ip
            }
        }
    }
    return ''
}

<#
.SYNOPSIS
Normalize MAC addresses to hyphen format.

.PARAMETER MacAddress
MAC address input.
#>
function ConvertTo-HyphenMac {
    param([string]$MacAddress)

    return ($MacAddress -replace '[^0-9A-Fa-f]', '').ToLowerInvariant() -replace '(.{2})(?!$)', '$1-'
}

<#
.SYNOPSIS
Read a VMX ethernet MAC address by adapter index.

.PARAMETER Path
VMX path.
.PARAMETER Index
Ethernet adapter index.
#>
function Get-VmxEthernetMacAddress {
    param(
        [string]$Path,
        [int]$Index = 0
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }
    $content = Get-Content -LiteralPath $Path
    $prefix = "ethernet$Index"
    foreach ($key in @('address', 'generatedAddress')) {
        $pattern = '^\s*' + [regex]::Escape("$prefix.$key") + '\s*=\s*"(?<value>[^"]+)"\s*$'
        $line = $content | Where-Object { $_ -match $pattern } | Select-Object -First 1
        if ($line -and $line -match $pattern) {
            return ConvertTo-HyphenMac -MacAddress $Matches['value']
        }
    }
    return ''
}

<#
.SYNOPSIS
Resolve a guest IPv4 address from neighbor cache by MAC.

.PARAMETER Path
VMX path.
.PARAMETER Index
Ethernet adapter index.
#>
function Get-GuestIPv4FromHostNeighbor {
    param(
        [string]$Path,
        [int]$Index = 0
    )

    $mac = Get-VmxEthernetMacAddress -Path $Path -Index $Index
    if (-not $mac) {
        return ''
    }
    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop
    } catch {
        return ''
    }
    foreach ($neighbor in $neighbors) {
        if (($neighbor.LinkLayerAddress -as [string]).ToLowerInvariant() -ne $mac) {
            continue
        }
        $ip = $neighbor.IPAddress -as [string]
        if ($ip -and $ip -notlike '127.*' -and $ip -notlike '169.254.*') {
            return $ip
        }
    }
    return ''
}

<#
.SYNOPSIS
Resolve guest IPv4 using VMware guest operations.

.PARAMETER Path
VMX path.
.PARAMETER GuestUser
Guest username.
.PARAMETER GuestPassword
Guest password.
.PARAMETER Name
VM-friendly name for temporary host output names.
#>
function Get-GuestIPv4ViaGuestOps {
    param(
        [string]$Path,
        [string]$GuestUser,
        [SecureString]$GuestPassword,
        [string]$Name
    )

    if (-not $GuestUser -or -not $GuestPassword) {
        return ''
    }
    $guestPasswordText = ConvertFrom-SecureString -SecureString $GuestPassword -AsPlainText
    $safeName = ($Name -replace '[^A-Za-z0-9_.-]', '-')
    $guestOutput = "/tmp/atlaso-ipv4-$safeName.txt"
    $hostOutput = Join-Path $resultRoot "guest-ipv4-$safeName.txt"
    $script = "ip -4 -br addr > $guestOutput 2>/dev/null || /sbin/ip -4 -br addr > $guestOutput 2>/dev/null || ifconfig > $guestOutput 2>/dev/null"
    $runResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', '-gu', $GuestUser, '-gp', $guestPasswordText, 'runScriptInGuest', $Path, '/bin/sh', $script) -TimeoutSeconds 15
    if ($runResult.ExitCode -ne 0) {
        $guestPasswordText = $null
        return ''
    }
    $copyResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', '-gu', $GuestUser, '-gp', $guestPasswordText, 'copyFileFromGuestToHost', $Path, $guestOutput, $hostOutput) -TimeoutSeconds 15
    if ($copyResult.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $hostOutput)) {
        $guestPasswordText = $null
        return ''
    }
    $guestAddress = Get-GuestIPv4FromAddressText -Lines @(Get-Content -LiteralPath $hostOutput)
    $guestPasswordText = $null
    return $guestAddress
}

<#
.SYNOPSIS
Wait for a guest IPv4 address from multiple retrieval methods.

.PARAMETER Path
VMX path.
.PARAMETER TimeoutSeconds
Maximum seconds to wait.
.PARAMETER GuestUser
Guest username used for guest-ops probing.
.PARAMETER GuestPassword
Guest password used for guest-ops probing.
.PARAMETER Name
VM name used for temporary artifacts.
.PARAMETER ExpectedAddress
Require this exact IPv4 address before returning; ignore stale address observations.
.PARAMETER SkipHostNeighbor
Do not use the host neighbor cache when proving a guest address after a network rewire.
#>
function Wait-GuestIPv4 {
    param(
        [string]$Path,
        [int]$TimeoutSeconds = 240,
        [string]$GuestUser = '',
        [SecureString]$GuestPassword,
        [string]$Name = 'guest',
        [string]$ExpectedAddress = '',
        [switch]$SkipHostNeighbor
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $reported = Invoke-VmrunBounded -Arguments @('-T', 'ws', 'getGuestIPAddress', $Path) -TimeoutSeconds 10
        if ($reported.ExitCode -eq 0) {
            $ip = Get-GuestIPv4FromAddressText -Lines @($reported.StdOut -split "`r?`n")
            if ($ip -and (-not $ExpectedAddress -or $ip -ceq $ExpectedAddress)) {
                return $ip
            }
        }
        if (-not $SkipHostNeighbor) {
            $neighborIp = Get-GuestIPv4FromHostNeighbor -Path $Path
            if ($neighborIp -and (-not $ExpectedAddress -or $neighborIp -ceq $ExpectedAddress)) {
                return $neighborIp
            }
        }
        $fallbackIp = Get-GuestIPv4ViaGuestOps -Path $Path -GuestUser $GuestUser -GuestPassword $GuestPassword -Name $Name
        if ($fallbackIp -and (-not $ExpectedAddress -or $fallbackIp -ceq $ExpectedAddress)) {
            return $fallbackIp
        }
        Start-Sleep -Seconds 5
    }
    return ''
}

<#
.SYNOPSIS
Execute a shell command inside the appliance guest.

.PARAMETER ApplianceVmx
Appliance VMX path.
.PARAMETER Script
Shell script content.
#>
function Invoke-ApplianceGuestScript {
    param(
        [string]$ApplianceVmx,
        [string]$Script
    )

    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword runScriptInGuest $ApplianceVmx /bin/sh $Script | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Appliance guest operation failed."
    }
}

<#
.SYNOPSIS
Probe a URL for successful openapi endpoint response.

.PARAMETER Url
OpenAPI URL to probe.
#>
function Test-ApplianceOpenApi {
    param([string]$Url)

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -k -f -sS $Url 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    }

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -SkipCertificateCheck -TimeoutSec 10
        return $response.StatusCode -eq 200
    } catch [System.Management.Automation.ParameterBindingException] {
        $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            return $response.StatusCode -eq 200
        } catch {
            return $false
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
        }
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
Read bounded, non-secret startup prerequisite state after a lifecycle deployment failure.
.PARAMETER ApplianceVmx
Exact task-owned appliance VMX whose service states are queried.
#>
function Get-ApplianceStartupDiagnostic {
    param([Parameter(Mandatory = $true)][string]$ApplianceVmx)

    $guestOutput = '/tmp/atlaso-lifecycle-startup-state.txt'
    $hostOutput = Join-Path $resultRoot 'appliance-startup-state.txt'
    # Keep untrusted readback outside retained results. The deterministic lab
    # directory identifies interrupted staging for operator recovery.
    $stagingRoot = Join-Path $repoRoot ".atlaso-local/lifecycle-startup-diagnostics/$LabName"
    $rawOutput = Join-Path $stagingRoot 'guest-readback.txt'
    $publishOutput = Join-Path $resultRoot 'appliance-startup-state.pending'
    $units = @('atlaso-data-disks.service', 'atlaso-bootstrap-https.service', 'atlaso.service', 'nginx.service')
    $probe = "systemctl show $($units -join ' ') --property=Id,LoadState,ActiveState,SubState,Result > $guestOutput"
    $validatedArtifact = $false
    $terminationUnproven = $false
    try {
        if (Test-Path -LiteralPath $hostOutput) { Remove-Item -LiteralPath $hostOutput -Force }
        [IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
        foreach ($pending in @($rawOutput, $publishOutput)) {
            if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force }
        }
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
            '-T', 'ws', '-gu', $ApplianceSshUser, '-gp', $ApplianceGuestPassword,
            'runScriptInGuest', $ApplianceVmx, '/bin/sh', $probe
        ) -TimeoutSeconds 15 -Action 'Lifecycle startup query'
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
            '-T', 'ws', '-gu', $ApplianceSshUser, '-gp', $ApplianceGuestPassword,
            'copyFileFromGuestToHost', $ApplianceVmx, $guestOutput, $rawOutput
        ) -TimeoutSeconds 15 -Action 'Lifecycle startup readback'
        if (-not (Test-Path -LiteralPath $rawOutput -PathType Leaf)) {
            return 'Startup prerequisite state unavailable (guest readback failed).'
        }
        if ((Get-Item -LiteralPath $rawOutput).Length -gt 4096) {
            return 'Startup prerequisite state unavailable (oversized readback).'
        }
        # Report only fixed unit names and systemd state tokens, never journals,
        # guest commands, or arbitrary guest output from a failed operation.
        $states = @(Get-Content -LiteralPath $rawOutput | Where-Object {
            $_ -match '^(?:LoadState|ActiveState|SubState|Result)=[a-z-]{1,40}$' -or
            ($_ -match '^Id=(.+)$' -and $Matches[1] -in $units)
        })
        if ($states.Count -eq 0) { return 'Startup prerequisite state unavailable (invalid readback).' }
        # Retained evidence must contain the same allowlisted data as the error.
        Set-Content -LiteralPath $publishOutput -Value $states -Encoding utf8
        [IO.File]::Move($publishOutput, $hostOutput)
        $validatedArtifact = $true
        return "Startup prerequisites: $($states -join '; ')."
    }
    catch {
        $failure = $_.Exception
        while ($null -ne $failure) {
            if ($failure.Data['AtlasoProcessTreeTerminationUnproven']) { $terminationUnproven = $true }
            $failure = $failure.InnerException
        }
        if ($terminationUnproven) {
            $script:diagnosticTerminationUnproven = $true
            throw "Startup diagnostic process termination is unproven. Preserve staging for recovery: $stagingRoot"
        }
        return 'Startup prerequisite state unavailable (bounded provider failure).'
    }
    finally {
        if (-not $terminationUnproven) {
            foreach ($pending in @($rawOutput, $publishOutput)) {
                if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force -ErrorAction Stop }
            }
        }
        if (-not $validatedArtifact -and (Test-Path -LiteralPath $hostOutput)) {
            Remove-Item -LiteralPath $hostOutput -Force -ErrorAction Stop
        }
    }
}

<#
.SYNOPSIS
Upload the lifecycle helper script to the appliance guest.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest that receives the helper.
#>
function Sync-ApplianceHelperScript {
    param([string]$ApplianceVmx)

    $localHelper = Join-Path $runtimeSourceRoot 'scripts\appliance\atlaso-helper'
    if (-not (Test-Path -LiteralPath $localHelper)) {
        throw "Atlaso helper script not found: $localHelper"
    }
    $guestTemp = "/tmp/atlaso-helper"
    if ($PSCmdlet.ShouldProcess($ApplianceVmx, "Sync Atlaso helper into appliance")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $localHelper $guestTemp | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy Atlaso helper into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedTemp = ConvertTo-GuestShellSingleQuote -Value $guestTemp
        $script = "printf '%s\n' $quotedPassword | sudo -S install -o root -g root -m 0755 $quotedTemp /opt/atlaso/bin/atlaso-helper"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
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

<#
.SYNOPSIS
Upload and install the lifecycle application wheel in the appliance guest.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest where the wheel is installed.
#>
function Sync-ApplianceApplicationWheel {
    param([string]$ApplianceVmx)

    Get-LifecycleSourceCommit -RepositoryRoot $repoRoot -ExpectedCommit $sourceCommit | Out-Null
    $wheelRoot = Join-Path $resultRoot 'wheel'
    if (Test-Path -LiteralPath $wheelRoot) {
        throw 'Lifecycle wheel output root already exists; preserve it for ownership-aware cleanup.'
    }
    New-Item -ItemType Directory -Path $wheelRoot -ErrorAction Stop | Out-Null
    $wheelConsumerPins = [Collections.Generic.List[IDisposable]]::new()
    try {
        $wheelSource = New-LifecycleSourceSnapshot -RepositoryRoot $repoRoot -Commit $sourceCommit -DestinationRoot $wheelRoot -ConsumerPins $wheelConsumerPins
        Write-Host "Building Atlaso wheel from admitted commit $sourceCommit."
        Assert-LifecycleSourcePins -Pins $wheelConsumerPins
        $wheelBuildOutput = @(& python -m pip wheel $wheelSource --no-deps -w $wheelRoot 2>&1)
        $wheelBuildOutput | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build Atlaso wheel from $repoRoot."
        }
        Get-LifecycleSourceCommit -RepositoryRoot $repoRoot -ExpectedCommit $sourceCommit | Out-Null
        Assert-LifecycleSourcePins -Pins $wheelConsumerPins
        $wheel = Get-LifecycleBuiltWheel -OutputRoot $wheelRoot -BuildOutput $wheelBuildOutput -ConsumerPins $wheelConsumerPins

        $guestWheel = "/tmp/$($wheel.Name)"
        if ($PSCmdlet.ShouldProcess($ApplianceVmx, "Install current Atlaso wheel into appliance")) {
            & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $wheel.FullName $guestWheel | Out-Host
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to copy Atlaso wheel into the appliance with VMware guest operations."
            }
            $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
            $quotedWheel = ConvertTo-GuestShellSingleQuote -Value $guestWheel
            $script = "printf '%s  %s\n' '$($wheel.Sha256)' $quotedWheel | sha256sum -c - && printf '%s\n' $quotedPassword | sudo -S /opt/atlaso/.venv/bin/python -m pip install --force-reinstall --no-deps $quotedWheel && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv -type d -exec chmod 0755 {} + && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv -type f -exec chmod 0644 {} + && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv/bin -type f -exec chmod 0755 {} + && printf '%s\n' $quotedPassword | sudo -S systemctl restart atlaso.service"
            Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
        }

        $deadline = (Get-Date).AddMinutes(3)
        do {
            if (Test-ApplianceOpenApi -Url "$ApplianceUrl/openapi.json") {
                # Return the digest established while both the source snapshot
                # and wheel file remain pinned. Later receipts must not reopen
                # an unpinned pathname after this function releases its pins.
                return $wheel
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $deadline)
        throw "Timed out waiting for Atlaso web service after installing $($wheel.Name)."
    } finally {
        for ($pinIndex = $wheelConsumerPins.Count - 1; $pinIndex -ge 0; $pinIndex--) { $wheelConsumerPins[$pinIndex].Dispose() }
    }
}

<#
.SYNOPSIS
Find an ESXi installer ISO already stored on the appliance.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest whose depot is searched.
#>
function Find-ApplianceEsxiIsoPath {
    param([string]$ApplianceVmx)

    $guestOutput = '/tmp/atlaso-esxi-iso.txt'
    $hostOutput = Join-Path $resultRoot 'appliance-esxi-iso.txt'
    $script = "find /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST -maxdepth 1 -type f -iname '*.iso' | head -n 1 > $guestOutput"
    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword runScriptInGuest $ApplianceVmx /bin/sh $script 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return ''
    }
    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromGuestToHost $ApplianceVmx $guestOutput $hostOutput 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hostOutput)) {
        return ''
    }
    return ((Get-Content -LiteralPath $hostOutput | Select-Object -First 1) -as [string]).Trim()
}

<#
.SYNOPSIS
Resolve or upload the ESXi ISO required by the PXE scenario.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest that owns the ESXi depot.
#>
function Resolve-ApplianceEsxiIsoPath {
    param([string]$ApplianceVmx)

    if (-not $FullEsxiPxeInstall) {
        return ''
    }
    if (-not $PxeInstallerIsoPath) {
        $discovered = Find-ApplianceEsxiIsoPath -ApplianceVmx $ApplianceVmx
        if ($discovered) {
            return $discovered
        }
        throw "-FullEsxiPxeInstall requires -PxeInstallerIsoPath or an existing ESXi ISO under /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST on the appliance."
    }
    if ($PxeInstallerIsoPath.StartsWith('/')) {
        return $PxeInstallerIsoPath
    }
    $localIso = Resolve-Path -LiteralPath $PxeInstallerIsoPath
    $leaf = Split-Path -Leaf $localIso.Path
    $guestTemp = "/tmp/$leaf"
    $guestTarget = "/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/$leaf"
    if ($PSCmdlet.ShouldProcess($guestTarget, "Stage ESXi installer ISO into appliance depot")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $localIso.Path $guestTemp | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy ESXi installer ISO into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedTemp = ConvertTo-GuestShellSingleQuote -Value $guestTemp
        $quotedTarget = ConvertTo-GuestShellSingleQuote -Value $guestTarget
        $script = "printf '%s\n' $quotedPassword | sudo -S mkdir -p /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST && printf '%s\n' $quotedPassword | sudo -S mv $quotedTemp $quotedTarget && printf '%s\n' $quotedPassword | sudo -S chmod 0644 $quotedTarget"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
    }
    return $guestTarget
}

<#
.SYNOPSIS
Append one timestamped validation step to the lifecycle result.
.PARAMETER ResultDirectory
Directory containing the lifecycle result JSON to update.
.PARAMETER Name
Stable result-step name recorded for the validation.
.PARAMETER Status
Validation outcome written to the step and aggregate result.
.PARAMETER Evidence
Non-secret structured evidence captured for the validation.
.PARAMETER ErrorMessage
Optional sanitized failure context for an unsuccessful step.
#>
function Add-LifecycleResultStep {
    param(
        [string]$ResultDirectory,
        [string]$Name,
        [string]$Status,
        [hashtable]$Evidence,
        [string]$ErrorMessage = ''
    )

    $path = Join-Path $ResultDirectory 'result.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Lifecycle result JSON not found: $path"
    }
    $result = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $step = [ordered]@{
        name        = $Name
        status      = $Status
        started_at  = (Get-Date).ToUniversalTime().ToString('o')
        finished_at = (Get-Date).ToUniversalTime().ToString('o')
        evidence    = $Evidence
        error       = $ErrorMessage
    }
    $result.steps += @($step)
    if ($Status -ne 'passed') {
        $result.status = 'failed'
        if ($result.PSObject.Properties.Name -contains 'error') {
            $result.error = $ErrorMessage
        } else {
            $result | Add-Member -MemberType NoteProperty -Name 'error' -Value $ErrorMessage
        }
    }
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
}

$resolvedVmrun = Resolve-VmrunPath
if (@(@($OidcOnly, $RoutingWanOnly, $CertificateOnly, $FullEsxiPxeInstall) | Where-Object { $_ }).Count -gt 1) {
    throw "-OidcOnly, -RoutingWanOnly, -CertificateOnly, and -FullEsxiPxeInstall are mutually exclusive."
}
$applianceName = "$LabName-Appliance"
$clientAName = "$LabName-ClientA"
$clientBName = "$LabName-ClientB"
$esxiName = "$LabName-ESXiPXE"
$esxiMacAddress = if ($FullEsxiPxeInstall) { New-StaticVmwareMac } else { '' }
$certificateAppliancePeerMac = if ($CertificateDhcpPeer) { New-StaticVmwareMac } else { '' }
$planApplianceVmx = if (Test-Path -LiteralPath $ApplianceVmxPath) { (Resolve-Path -LiteralPath $ApplianceVmxPath).Path } else { $ApplianceVmxPath }
$planClientVmdk = if (Test-Path -LiteralPath $ClientVmdkPath) { (Resolve-Path -LiteralPath $ClientVmdkPath).Path } else { $ClientVmdkPath }

$lanSegmentOwner = @{
    task_id = $(if ($env:CODEX_THREAD_ID) { $env:CODEX_THREAD_ID } else { $LabName })
    repository = 'mdaneri/Atlaso'; source_commit = $sourceCommit
    pr = $PullRequestNumber; lab_root = $resultRoot
}
$ownedLanSegments = [System.Collections.Generic.List[object]]::new()
$plan = [ordered]@{
    lan_segment_owner     = $lanSegmentOwner
    name                  = 'vmware workstation lifecycle interop'
    lab_name              = $LabName
    pull_request_number   = $PullRequestNumber
    purpose               = $vmIdentity.Purpose
    collision_suffix      = $vmIdentity.CollisionSuffix
    appliance_vmx         = $planApplianceVmx
    client_vmdk           = $planClientVmdk
    result_root           = $resultRoot
    lifecycle_appliance_vmx = (Join-Path $vmRoot "$applianceName\$applianceName.vmx")
    management_network    = $ManagementNetwork
    bridged_interface_alias = $BridgedInterfaceAlias
    site_a_network        = $SiteANetwork
    trunk_network         = $TrunkNetwork
    site_b_network        = $SiteBNetwork
    oidc_only             = [bool]$OidcOnly
    certificate_only      = [bool]$CertificateOnly
    certificate_dhcp_peer = [bool]$CertificateDhcpPeer
    certificate_peer_cidr = if ($CertificateDhcpPeer) { $CertificatePeerCidr } else { '' }
    certificate_lease_address = if ($CertificateDhcpPeer) { $CertificateLeaseAddress } else { '' }
    certificate_appliance_peer_mac = $certificateAppliancePeerMac
    routing_wan_only      = [bool]$RoutingWanOnly
    full_esxi_pxe_install = [bool]$FullEsxiPxeInstall
    signed_release_update_check = [bool]$SignedReleaseRepositoryUrl
    signed_release_fixture_operations = if ($SignedReleaseRepositoryUrl) {
        'preview availability check and upgrade, development availability check and rollback, and two audited appliance reboots'
    } else { 'not requested' }
    pxe_installer_iso     = $PxeInstallerIsoPath
    pxe_client_ip         = $PxeClientIPAddress
    esxi_probe_delay_seconds = $EsxiInstallProbeDelaySeconds
    esxi_pxe_vm           = if ($FullEsxiPxeInstall) { $esxiName } else { '' }
    esxi_pxe_mac          = $esxiMacAddress
    workstation_fidelity  = 'Workstation vmnets are isolated layer-2 segments; tagged trunk behavior requires a compatible upstream virtual-network configuration.'
}
$planJson = $plan | ConvertTo-Json -Depth 5

if ($PlanOnly) {
    New-Item -ItemType Directory -Force -Path $resultRoot | Out-Null
    $planJson | Set-Content -LiteralPath (Join-Path $resultRoot 'plan.json') -Encoding UTF8
    $planJson
    return
}

# Cleanup must retain the same identity proof for a kept runtime lab that it
# receives for a plan-only lab. Publish it before any VM can be created.
New-Item -ItemType Directory -Force -Path $resultRoot | Out-Null
$planPath = Join-Path $resultRoot 'plan.json'
$planWriter = [IO.File]::Open($planPath, 'CreateNew', 'Write', 'None')
try {
    $preflightGuard.Record($planPath, $planWriter.SafeFileHandle)
    $planWriter.Write([Text.UTF8Encoding]::new($false).GetBytes($planJson)); $planWriter.Flush($true)
} finally { $planWriter.Dispose() }

$firstBootOvfEnvironment = New-AtlasoWorkstationOvfEnvironment `
    -Fqdn (New-AtlasoWorkstationFqdn -Name $applianceName) `
    -AdminPassword $adminPasswordSecure `
    -RootPassword $adminPasswordSecure `
    -RootSshEnabled:($ApplianceSshUser -eq 'root')

New-Item -ItemType Directory -Path $vmRoot -ErrorAction Stop | Out-Null
$runtimeConsumerPins.Add([Atlaso.SnapshotDirectoryPinV2]::Open($vmRoot))
$preflightGuard.RecordDirectory($vmRoot)
New-Item -ItemType Directory -Path $seedRoot -ErrorAction Stop | Out-Null
$runtimeConsumerPins.Add([Atlaso.SnapshotDirectoryPinV2]::Open($seedRoot))
$preflightGuard.RecordDirectory($seedRoot)
$identityPath = Join-Path $resultRoot 'vmware-identity.json'
$identityVms = [System.Collections.Generic.List[object]]::new()

<#
.SYNOPSIS
Durably refresh the lifecycle identity evidence for every admitted VM record.
#>
function Write-LifecycleIdentityEvidence {
    $identityJson = [ordered]@{
        lab_name            = $LabName
        pull_request_number = $PullRequestNumber
        purpose             = $vmIdentity.Purpose
        collision_suffix    = $vmIdentity.CollisionSuffix
        result_root         = $resultRoot
        log_identity        = $LabName
        vms                 = @($identityVms)
        lan_segments        = @($ownedLanSegments)
    } | ConvertTo-Json -Depth 5

    # Keep every observable ownership manifest complete. The temporary file is
    # created beside the destination so the final replace stays on one volume.
    $identityTempPath = Join-Path $resultRoot ('.vmware-identity.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    if ($preflightGuard) { $preflightGuard.Expect($identityTempPath) }
    $identityBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($identityJson)
    $identityWriter = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($identityTempPath)
    try {
        if ($preflightGuard) { $preflightGuard.Record($identityTempPath, $identityWriter.SafeFileHandle) }
        $identityWriter.Write($identityBytes)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($identityWriter, $identityPath)
    }
    finally { $identityWriter.Dispose() }
    if ($preflightGuard) { $preflightGuard.Published($identityTempPath, $identityPath) }
    # Failed publication retains its exact stage for ownership-aware recovery;
    # never delete a reopened staging pathname after releasing its creation handle.
}

<#
.SYNOPSIS
Publish one immutable certificate-lab receipt outside its disposable VM root.
.PARAMETER Name
Unique receipt filename beneath this lab's durable evidence directory.
.PARAMETER Value
Non-secret structured evidence to serialize and flush.
#>
function Write-CertificateLabReceipt {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Value)

    if (-not $CertificateOnly -or $Name -notmatch '^[a-z][a-z0-9-]*\.json$') {
        throw 'Certificate evidence publication was requested outside its supported mode.'
    }
    $evidenceRoot = Join-Path $repoRoot "test-results/certificate-native-evidence/$LabName"
    [IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null
    $target = Join-Path $evidenceRoot $Name
    if (Test-Path -LiteralPath $target) { throw "Certificate evidence already exists: $target" }
    $stage = Join-Path $evidenceRoot ('.' + [guid]::NewGuid().ToString('N') + '.pending')
    $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stage)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 8))
        $publishedSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        $writer.Write($bytes)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $target, $false)
    } finally { $writer.Dispose() }
    return [pscustomobject]@{ Path = $target; Sha256 = $publishedSha256 }
}

<#
.SYNOPSIS
Capture bounded guest service state before certificate-lab helper and wheel deployment.
.PARAMETER ApplianceVmx
Exact cloned appliance VMX whose guest state is queried.
#>
function Get-CertificateSourceGuestState {
    param([Parameter(Mandatory)][string]$ApplianceVmx)

    $guestPath = "/tmp/$LabName-source-app.txt"
    $hostPath = Join-Path $resultRoot 'source-app-readback.txt'
    $script = "systemctl show atlaso.service --property=LoadState,ActiveState > '$guestPath'"
    $password = ConvertFrom-SecureString -SecureString $adminPasswordSecure -AsPlainText
    try {
        $query = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', $ApplianceSshUser, '-gp', $password,
            'runScriptInGuest', $ApplianceVmx, '/bin/sh', $script
        ) -TimeoutSeconds 20
        if ($query.TimedOut -or $query.ExitCode -ne 0) { throw 'Certificate source guest query failed.' }
        $readback = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', $ApplianceSshUser, '-gp', $password,
            'copyFileFromGuestToHost', $ApplianceVmx, $guestPath, $hostPath
        ) -TimeoutSeconds 20
        if ($readback.TimedOut -or $readback.ExitCode -ne 0) { throw 'Certificate source guest readback failed.' }
        if (-not (Test-Path -LiteralPath $hostPath -PathType Leaf) -or (Get-Item -LiteralPath $hostPath).Length -gt 1024) {
            throw 'Certificate source guest readback is missing or oversized.'
        }
        $values = @{}
        foreach ($line in Get-Content -LiteralPath $hostPath) {
            if ($line -notmatch '^(LoadState|ActiveState)=([a-z-]{1,40})$' -or $values.ContainsKey($Matches[1])) {
                throw 'Certificate source guest readback is invalid.'
            }
            $values[$Matches[1]] = $Matches[2]
        }
        if ($values.Count -ne 2) { throw 'Certificate source guest state is incomplete.' }
        return $values
    } finally {
        $password = $null
        if (Test-Path -LiteralPath $hostPath) { Remove-Item -LiteralPath $hostPath -Force -ErrorAction Stop }
    }
}

<#
.SYNOPSIS
Read a bounded, read-only routing-intent snapshot from the cloned guest database before deployment.
.PARAMETER ApplianceVmx
Exact cloned appliance VMX whose source database is queried.
#>
function Get-CertificateSourceRoutingSnapshot {
    param([Parameter(Mandatory)][string]$ApplianceVmx)

    # The routing-absence claim must be made by the admitted source, not by a
    # transient checkout edit that disappears before the later cleanliness check.
    Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
    $localProbe = Join-Path $runtimeSourceRoot 'scripts/interop/certificate_source_probe.py'
    $probeSha256 = (Get-FileHash -LiteralPath $localProbe -Algorithm SHA256).Hash.ToLowerInvariant()
    $probeToken = [guid]::NewGuid().ToString('N')
    $guestProbe = "/root/atlaso-certificate-source-$probeToken.py"
    $guestOutput = "/root/atlaso-certificate-source-$probeToken.json"
    $hostOutput = Join-Path $resultRoot "source-routing-$probeToken.json"
    if (Test-Path -LiteralPath $hostOutput) { throw 'Certificate source routing output already exists.' }
    $password = ConvertFrom-SecureString -SecureString $adminPasswordSecure -AsPlainText
    try {
        $copy = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', 'root', '-gp', $password,
            'copyFileFromHostToGuest', $ApplianceVmx, $localProbe, $guestProbe
        ) -TimeoutSeconds 20
        if ($copy.TimedOut -or $copy.ExitCode -ne 0) { throw 'Certificate source routing probe copy failed.' }
        Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
        $script = "printf '%s  %s\n' '$probeSha256' '$guestProbe' | sha256sum -c - >/dev/null && python3 '$guestProbe' > '$guestOutput'"
        $query = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', 'root', '-gp', $password,
            'runScriptInGuest', $ApplianceVmx, '/bin/sh', $script
        ) -TimeoutSeconds 20
        if ($query.TimedOut -or $query.ExitCode -ne 0) { throw 'Certificate source routing probe failed.' }
        Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
        $readback = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', 'root', '-gp', $password,
            'copyFileFromGuestToHost', $ApplianceVmx, $guestOutput, $hostOutput
        ) -TimeoutSeconds 20
        if ($readback.TimedOut -or $readback.ExitCode -ne 0) { throw 'Certificate source routing readback failed.' }
        Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
        if (-not (Test-Path -LiteralPath $hostOutput -PathType Leaf) -or (Get-Item -LiteralPath $hostOutput).Length -gt 4096) {
            throw 'Certificate source routing readback is missing or oversized.'
        }
        $snapshot = Get-Content -LiteralPath $hostOutput -Raw | ConvertFrom-Json -AsHashtable
        if ($snapshot.schema -ne 1 -or $snapshot.database -ne '/var/lib/atlaso/atlaso.db' -or
            $snapshot.state -ne 'proven-absent') {
            throw 'Certificate source routing intent is present or unproven.'
        }
        $expectedCounts = @('routes', 'routing_rules', 'nat_rules', 'port_forwards', 'wan_policies', 'route_physical_interfaces', 'route_vlan_interfaces')
        if (@($snapshot.counts.Keys).Count -ne $expectedCounts.Count -or
            @($snapshot.settings.Keys).Count -ne 4) {
            throw 'Certificate source routing snapshot has an unexpected schema.'
        }
        foreach ($key in $expectedCounts) {
            if (-not $snapshot.counts.ContainsKey($key) -or $snapshot.counts[$key] -isnot [long] -or $snapshot.counts[$key] -ne 0) {
                throw 'Certificate source routing desired state is not empty.'
            }
        }
        foreach ($key in @('routes_wan.routing_enabled', 'routes_wan.wan_simulation_enabled', 'routes_wan.nat_enabled', 'traffic_publishing.nat_enabled')) {
            if (-not $snapshot.settings.ContainsKey($key) -or
                ($null -ne $snapshot.settings[$key] -and $snapshot.settings[$key] -isnot [bool]) -or
                $snapshot.settings[$key] -eq $true) {
                throw 'Certificate source routing feature is enabled or unproven.'
            }
        }
        if ($null -ne $snapshot.routing_service -and
            (@($snapshot.routing_service.Keys).Count -ne 2 -or
             $snapshot.routing_service.enabled -isnot [bool] -or $snapshot.routing_service.running -isnot [bool] -or
             $snapshot.routing_service.enabled -or $snapshot.routing_service.running)) {
            throw 'Certificate source routing service intent is present.'
        }
        $snapshot.probe_sha256 = $probeSha256
        Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
        return $snapshot
    } finally {
        # These unique files exist only in this task-owned clone; the host receipt is published separately.
        $null = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', 'root', '-gp', $password,
            'runScriptInGuest', $ApplianceVmx, '/bin/sh', "rm -f -- '$guestProbe' '$guestOutput'"
        ) -TimeoutSeconds 20
        $password = $null
        if (Test-Path -LiteralPath $hostOutput) { Remove-Item -LiteralPath $hostOutput -Force -ErrorAction Stop }
    }
}

<#
.SYNOPSIS
Measure the installed appliance helper by a bounded guest readback.
.PARAMETER ApplianceVmx
Exact cloned appliance VMX whose helper is measured.
#>
function Get-CertificateInstalledHelperSha256 {
    param([Parameter(Mandatory)][string]$ApplianceVmx)

    $guestPath = "/tmp/$LabName-helper-sha256.txt"
    $hostPath = Join-Path $resultRoot 'helper-sha256-readback.txt'
    $script = "sha256sum /opt/atlaso/bin/atlaso-helper > '$guestPath'"
    $password = ConvertFrom-SecureString -SecureString $adminPasswordSecure -AsPlainText
    try {
        $query = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', $ApplianceSshUser, '-gp', $password,
            'runScriptInGuest', $ApplianceVmx, '/bin/sh', $script
        ) -TimeoutSeconds 20
        if ($query.TimedOut -or $query.ExitCode -ne 0) { throw 'Installed appliance helper measurement failed.' }
        $readback = Invoke-VmrunBounded -Arguments @(
            '-T', 'ws', '-gu', $ApplianceSshUser, '-gp', $password,
            'copyFileFromGuestToHost', $ApplianceVmx, $guestPath, $hostPath
        ) -TimeoutSeconds 20
        if ($readback.TimedOut -or $readback.ExitCode -ne 0) { throw 'Installed appliance helper readback failed.' }
        if (-not (Test-Path -LiteralPath $hostPath -PathType Leaf) -or (Get-Item -LiteralPath $hostPath).Length -gt 256) {
            throw 'Installed appliance helper digest is missing or oversized.'
        }
        $lines = @(Get-Content -LiteralPath $hostPath)
        if ($lines.Count -ne 1 -or $lines[0] -notmatch '^([a-f0-9]{64})  /opt/atlaso/bin/atlaso-helper$') {
            throw 'Installed appliance helper digest is invalid.'
        }
        return $Matches[1]
    } finally {
        $password = $null
        if (Test-Path -LiteralPath $hostPath) { Remove-Item -LiteralPath $hostPath -Force -ErrorAction Stop }
    }
}

<#
.SYNOPSIS
Publish one expected VM identity before running its artifact-producing action.

.PARAMETER Role
Canonical lifecycle role recorded for the VM.

.PARAMETER DisplayName
Exact canonical VMware display name.

.PARAMETER VmxPath
Deterministic absolute VMX path the action must produce.

.PARAMETER Action
Artifact-producing action that must return the exact VMX path.
#>
function Invoke-TrackedLifecycleVmCreation {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $expectedVmxPath = [System.IO.Path]::GetFullPath($VmxPath)
    Get-LifecycleSourceCommit -RepositoryRoot $repoRoot -ExpectedCommit $sourceCommit | Out-Null
    $record = [ordered]@{
        role         = $Role
        display_name = $DisplayName
        vmx          = $expectedVmxPath
    }
    $identityVms.Add($record)
    # Publish ownership before an external copy or VMX writer can leave an
    # artifact behind. A failure with no VMX retracts only this pending record.
    Write-LifecycleIdentityEvidence
    try {
        $createdVmxPath = & $Action
        Assert-AtlasoVmwareOwnedVmx `
            -VmxPath $createdVmxPath `
            -ExpectedDirectory (Split-Path -Parent $expectedVmxPath) `
            -ExpectedName $DisplayName | Out-Null
        if (-not (Resolve-Path -LiteralPath $createdVmxPath).Path.Equals(
                $expectedVmxPath,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Lifecycle VM creation returned a VMX outside its published identity: $createdVmxPath"
        }
        Write-LifecycleIdentityEvidence
        return $expectedVmxPath
    }
    catch {
        $failure = $_
        if (-not (Test-Path -LiteralPath $expectedVmxPath -PathType Leaf)) {
            $identityVms.Remove($record) | Out-Null
            Write-LifecycleIdentityEvidence
        }
        throw $failure
    }
}

Write-LifecycleIdentityEvidence
} catch {
    $preflightFailure = $_
    for ($pinIndex = $runtimeConsumerPins.Count - 1; $pinIndex -ge 0; $pinIndex--) { $runtimeConsumerPins[$pinIndex].Dispose() }
    $runtimeConsumerPins.Clear()
    if ($preflightRootCreated) {
        try {
            Remove-LifecyclePreflightArtifacts -Path $resultRoot `
                -ExpectedParent (Join-Path $repoRoot 'test-results/vmware-workstation-lifecycle') -Guard $preflightGuard
        } catch {
            throw "Lifecycle preflight failed: $($preflightFailure.Exception.Message) Preflight cleanup refused: $($_.Exception.Message)"
        }
    }
    throw $preflightFailure
}

$clientASeedIso = ''
$clientBSeedIso = ''
$clientAVmx = ''
$clientBVmx = ''
$certificatePeerSeedIso = ''
$certificatePeerVmx = ''
$certificateDiskSourcePin = $null
$certificatePeerDiskPin = $null
$certificateKnownHostsPin = $null
$certificatePeerPublicKeyPin = $null
$certificatePeerPublicKey = ''
$certificatePeerPublicKeySnapshot = Join-Path $resultRoot 'certificate-peer-authorized-key.pub'
$certificatePeerKnownHostsPath = Join-Path $resultRoot 'certificate-peer-known-hosts'
$seedArtifactsRetired = [bool]($OidcOnly -or ($CertificateOnly -and -not $CertificateDhcpPeer))
$scenarioFailure = $null
try {
    if ($CertificateDhcpPeer -and -not $PlanOnly) {
        $keyFile = Get-Item -LiteralPath $CertificatePeerPublicKeyPath -Force -ErrorAction Stop
        if ($keyFile.PSIsContainer -or ($keyFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $keyFile.Length -gt 1024) {
            throw 'Certificate peer public key must be one ordinary bounded file.'
        }
        $certificatePeerPublicKey = (Get-Content -LiteralPath $CertificatePeerPublicKeyPath -Raw).Trim()
        if ($certificatePeerPublicKey -notmatch '^ssh-ed25519 (?<blob>[A-Za-z0-9+/]+={0,2})(?: [^\r\n]{1,128})?$') {
            throw 'Certificate peer requires one Ed25519 public key.'
        }
        $selectedBlob = $Matches['blob']
        $agentKeys = @(& ssh-add.exe -L 2>$null)
        if ($LASTEXITCODE -ne 0 -or -not @($agentKeys | Where-Object { ($_ -split ' ')[0] -ceq 'ssh-ed25519' -and ($_ -split ' ')[1] -ceq $selectedBlob }).Count) {
            throw 'Certificate peer public key is not loaded in the local SSH agent.'
        }
        $keyBytes = [Text.UTF8Encoding]::new($false).GetBytes("$certificatePeerPublicKey`n")
        $keyStream = [IO.FileStream]::new($certificatePeerPublicKeySnapshot, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $keyStream.Write($keyBytes, 0, $keyBytes.Length)
            $keyStream.Flush($true)
        } finally { $keyStream.Dispose() }
        $certificatePeerPublicKeyPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($certificatePeerPublicKeySnapshot, $true)
        if ((Get-FileHash -LiteralPath $certificatePeerPublicKeySnapshot -Algorithm SHA256).Hash -cne
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($keyBytes))) {
            throw 'Certificate peer public-key snapshot changed before pinning.'
        }
    }
    if (-not ($OidcOnly -or $CertificateOnly)) {
        $clientASeedIso = Join-Path $seedRoot "$clientAName-seed.iso"
        $clientBSeedIso = Join-Path $seedRoot "$clientBName-seed.iso"
        New-CloudInitSeedIso -Path $clientASeedIso -HostName ($clientAName.ToLowerInvariant())
        New-CloudInitSeedIso -Path $clientBSeedIso -HostName ($clientBName.ToLowerInvariant())
    }
    if ($CertificateDhcpPeer) {
        $certificateClientVmdkSha256 = (Get-FileHash -LiteralPath $ClientVmdkPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $certificatePeerSeedIso = Join-Path $seedRoot "$clientAName-seed.iso"
        New-CertificatePeerSeedIso -Path $certificatePeerSeedIso -HostName ($clientAName.ToLowerInvariant()) -ClientMac $certificateAppliancePeerMac
    }
    $applianceDirectory = Join-Path $vmRoot $applianceName
    $preparedApplianceDirectoryIdentity = ''
    if ($CertificateOnly) {
        # The immutable intent precedes directory creation. The second receipt
        # captures the directory's original identity before vmrun can populate it.
        $certificateIntent = Write-CertificateLabReceipt -Name 'vm-creation-intent.json' -Value ([ordered]@{
            schema = 1; kind = 'vm-creation-intent'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber
            source_commit = $sourceCommit; path = (Join-Path $applianceDirectory "$applianceName.vmx")
            root_path = $applianceDirectory; lab_root = $resultRoot
        })
        New-Item -ItemType Directory -Path $applianceDirectory -ErrorAction Stop | Out-Null
        $identityCode = @'
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
from scripts.completed_task_files import WindowsFiles
with WindowsFiles().opened(Path(sys.argv[1]), directory=True) as (_, identity, _):
    print(json.dumps(list(identity)))
'@
        $identityOutput = @(& python -I -c $identityCode $applianceDirectory $runtimeSourceRoot)
        if ($LASTEXITCODE -ne 0 -or $identityOutput.Count -ne 1) {
            throw 'Certificate VM directory creation identity could not be captured.'
        }
        $originalDirectoryIdentity = @($identityOutput[0] | ConvertFrom-Json)
        if ($originalDirectoryIdentity.Count -ne 3) { throw 'Certificate VM directory identity is invalid.' }
        $preparedApplianceDirectoryIdentity = Get-AtlasoPathIdentity -Path $applianceDirectory -Description 'certificate VM directory'
        $certificateOwnership = Write-CertificateLabReceipt -Name 'vm-original-ownership.json' -Value ([ordered]@{
            schema = 1; kind = 'vm'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber
            source_commit = $sourceCommit; path = (Join-Path $applianceDirectory "$applianceName.vmx")
            root_path = $applianceDirectory; root_identity = $originalDirectoryIdentity
            intent_sha256 = $certificateIntent.Sha256; lab_root = $resultRoot
        })
    }
    $applianceVmx = Invoke-TrackedLifecycleVmCreation `
        -Role 'appliance' `
        -DisplayName $applianceName `
        -VmxPath (Join-Path $applianceDirectory "$applianceName.vmx") `
        -Action {
            Copy-VmDirectory `
                -SourceVmx $ApplianceVmxPath `
                -DestinationDirectory $applianceDirectory `
                -Name $applianceName `
                -PreparedDirectoryIdentity $preparedApplianceDirectoryIdentity
        }
    if ($OidcOnly -or $CertificateOnly) {
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 0 -Vmnet $ManagementNetwork
    }
    else {
        # Workstation otherwise places the fourth NIC in slot 1184, which Photon
        # enumerates as eth0 instead of the management NIC.
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 0 -Vmnet $ManagementNetwork -PciSlotNumber 1184
    }
    if ($CertificateDhcpPeer) {
        # Pin eth0's final MAC before first boot, while the bootstrap adapter
        # remains host-reachable on VMnet8 for the supported deploy workflow.
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 0 -Vmnet $ManagementNetwork -StaticMac $certificateAppliancePeerMac
    }
    Set-AtlasoWorkstationOvfEnvironment -VmxPath $applianceVmx -OvfEnvironment $firstBootOvfEnvironment
    if ($OidcOnly) {
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 1 -Vmnet $SiteANetwork
    }
    if (-not ($OidcOnly -or $CertificateOnly)) {
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 1 -Vmnet $SiteANetwork -PciSlotNumber 192
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 2 -Vmnet $TrunkNetwork -PciSlotNumber 224
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 3 -Vmnet $SiteBNetwork -PciSlotNumber 256
        $clientADirectory = Join-Path $vmRoot $clientAName
        $clientAVmx = Invoke-TrackedLifecycleVmCreation `
            -Role 'client-a' `
            -DisplayName $clientAName `
            -VmxPath (Join-Path $clientADirectory "$clientAName.vmx") `
            -Action {
                New-ClientVm `
                    -Name $clientAName `
                    -Directory $clientADirectory `
                    -DiskPath $ClientVmdkPath `
                    -SeedIso $clientASeedIso `
                    -Networks @($ManagementNetwork, $SiteANetwork, $TrunkNetwork)
            }
        $clientBDirectory = Join-Path $vmRoot $clientBName
        $clientBVmx = Invoke-TrackedLifecycleVmCreation `
            -Role 'client-b' `
            -DisplayName $clientBName `
            -VmxPath (Join-Path $clientBDirectory "$clientBName.vmx") `
            -Action {
                New-ClientVm `
                    -Name $clientBName `
                    -Directory $clientBDirectory `
                    -DiskPath $ClientVmdkPath `
                    -SeedIso $clientBSeedIso `
                    -Networks @($ManagementNetwork, $SiteBNetwork)
            }
    }
    if ($CertificateDhcpPeer) {
        $certificateDiskSourcePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($ClientVmdkPath, $true)
        if ((Get-FileHash -LiteralPath $ClientVmdkPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $certificateClientVmdkSha256) {
            throw 'Certificate peer client disk source changed during fixture preparation.'
        }
        $certificatePeerDirectory = Join-Path $vmRoot $clientAName
        $peerIntent = Write-CertificateLabReceipt -Name 'peer-vm-creation-intent.json' -Value ([ordered]@{
            schema = 1; kind = 'vm-creation-intent'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber; source_commit = $sourceCommit
            path = (Join-Path $certificatePeerDirectory "$clientAName.vmx")
            root_path = $certificatePeerDirectory; lab_root = $resultRoot
        })
        New-Item -ItemType Directory -Path $certificatePeerDirectory -ErrorAction Stop | Out-Null
        $peerIdentityOutput = @(& python -I -c $identityCode $certificatePeerDirectory $runtimeSourceRoot)
        if ($LASTEXITCODE -ne 0 -or $peerIdentityOutput.Count -ne 1) {
            throw 'Certificate peer directory original identity could not be captured.'
        }
        $peerDirectoryIdentity = @($peerIdentityOutput[0] | ConvertFrom-Json)
        if ($peerDirectoryIdentity.Count -ne 3) { throw 'Certificate peer directory identity is invalid.' }
        $peerOwnership = Write-CertificateLabReceipt -Name 'peer-vm-original-ownership.json' -Value ([ordered]@{
            schema = 1; kind = 'vm'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber; source_commit = $sourceCommit
            path = (Join-Path $certificatePeerDirectory "$clientAName.vmx")
            root_path = $certificatePeerDirectory; root_identity = $peerDirectoryIdentity
            intent_sha256 = $peerIntent.Sha256; lab_root = $resultRoot
        })
        $certificatePeerVmx = Invoke-TrackedLifecycleVmCreation `
            -Role 'certificate-dhcp-peer' -DisplayName $clientAName `
            -VmxPath (Join-Path $certificatePeerDirectory "$clientAName.vmx") `
            -Action {
                New-ClientVm -Name $clientAName -Directory $certificatePeerDirectory `
                    -DiskPath $ClientVmdkPath -SeedIso $certificatePeerSeedIso `
                    -Networks @($ManagementNetwork, $SiteANetwork)
            }
        $certificatePeerDiskPath = Join-Path $certificatePeerDirectory "$clientAName.vmdk"
        $certificatePeerDiskPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryMutableFile($certificatePeerDiskPath)
        $certificatePeerDiskSha256 = (Get-FileHash -LiteralPath $certificatePeerDiskPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($certificatePeerDiskSha256 -cne $certificateClientVmdkSha256) {
            throw 'Certificate peer copied disk differs from its pinned source before boot.'
        }
        $certificatePeerDiskIdentity = [Atlaso.WorkstationFileIdentity]::Get($certificatePeerDiskPath)
        if ($ownedLanSegments.Count -ne 1 -or -not $ownedLanSegments[0].ReceiptPath -or -not $ownedLanSegments[0].ReceiptSha256) {
            throw 'Certificate DHCP peer requires a newly created, receipt-bound private LAN segment.'
        }
        $peerFixture = Write-CertificateLabReceipt -Name 'peer-fixture.json' -Value ([ordered]@{
            schema = 1; kind = 'certificate-dhcp-peer-fixture'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber; source_commit = $sourceCommit
            peer_vmx = $certificatePeerVmx; peer_ownership_sha256 = $peerOwnership.Sha256
            appliance_vmx = $applianceVmx; appliance_ownership_sha256 = $certificateOwnership.Sha256
            private_network = $SiteANetwork; peer_cidr = $CertificatePeerCidr
            management_network = $ManagementNetwork
            lease_address = $CertificateLeaseAddress; appliance_mac = $certificateAppliancePeerMac
            lan_segment_receipt = $ownedLanSegments[0].ReceiptPath
            lan_segment_receipt_sha256 = $ownedLanSegments[0].ReceiptSha256.ToLowerInvariant()
            lan_segment_id = $ownedLanSegments[0].Id
            client_vmdk_source = (Resolve-Path -LiteralPath $ClientVmdkPath).Path
            client_vmdk_sha256 = $certificateClientVmdkSha256
            client_vmdk_copy = $certificatePeerDiskPath
            client_vmdk_copy_preboot_sha256 = $certificatePeerDiskSha256
            client_vmdk_copy_identity = $certificatePeerDiskIdentity
            ssh_public_key = $certificatePeerPublicKey
            address_ownership_state = 'awaiting-live-readback'
        })
    }
    $esxiVmx = ''
    if ($FullEsxiPxeInstall) {
        $esxiDirectory = Join-Path $vmRoot $esxiName
        $esxiVmx = Invoke-TrackedLifecycleVmCreation `
            -Role 'esxi-pxe' `
            -DisplayName $esxiName `
            -VmxPath (Join-Path $esxiDirectory "$esxiName.vmx") `
            -Action {
                New-EsxiPxeVm `
                    -Name $esxiName `
                    -Directory $esxiDirectory `
                    -Network $SiteANetwork `
                    -MacAddress $esxiMacAddress
            }
    }
    Write-Host "Lifecycle identity evidence: $identityPath"
    foreach ($identityVm in $identityVms) {
        Write-Host "Lifecycle VM [$($identityVm.role)]: $($identityVm.display_name) => $($identityVm.vmx)"
    }

    $vmxsToStart = @($applianceVmx)
    if ($CertificateDhcpPeer) { $vmxsToStart += $certificatePeerVmx }
    if (-not ($OidcOnly -or $CertificateOnly)) {
        $vmxsToStart += @($clientAVmx, $clientBVmx)
    }
    foreach ($vmx in $vmxsToStart) {
        Start-WorkstationVm -Path $vmx
    }

    Start-Sleep -Seconds 20
    if (-not $ApplianceIPAddress) {
        $ApplianceIPAddress = Wait-GuestIPv4 -Path $applianceVmx -TimeoutSeconds 300 -GuestUser $ApplianceSshUser -GuestPassword $adminPasswordSecure -Name $applianceName
        if (-not $ApplianceIPAddress) {
            throw "Timed out waiting for VMware Tools to report the appliance management IPv4 address."
        }
    }
    if (-not $ApplianceUrl) {
        $ApplianceUrl = "https://${ApplianceIPAddress}"
    }
    [pscustomobject]@{
        appliance_ip  = $ApplianceIPAddress
        appliance_url = $ApplianceUrl
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $resultRoot 'discovered-appliance.json') -Encoding UTF8
    if ($CertificateOnly) {
        $sourceGuestState = Get-CertificateSourceGuestState -ApplianceVmx $applianceVmx
        $sourceRoutingSnapshot = Get-CertificateSourceRoutingSnapshot -ApplianceVmx $applianceVmx
        $certificateSource = Write-CertificateLabReceipt -Name 'predeployment-network.json' -Value ([ordered]@{
            schema = 1; phase = 'before-lifecycle-deployment'
            task_id = $env:CODEX_THREAD_ID; vmx_path = $applianceVmx
            source_commit = $sourceCommit; app_service = $sourceGuestState
            routing_intent_state = 'proven-absent'; route_snapshot = $sourceRoutingSnapshot
        })
    }
    try {
        Sync-ApplianceHelperScript -ApplianceVmx $applianceVmx
        $applianceWheel = Sync-ApplianceApplicationWheel -ApplianceVmx $applianceVmx
    }
    catch {
        $deploymentFailure = $_
        $startupDiagnostic = Get-ApplianceStartupDiagnostic -ApplianceVmx $applianceVmx
        throw [System.InvalidOperationException]::new(
            "Lifecycle application deployment failed. $startupDiagnostic Original failure: $($deploymentFailure.Exception.Message)",
            $deploymentFailure.Exception
        )
    }
    if ($CertificateOnly) {
        $sourceHelperSha256 = (Get-FileHash -LiteralPath (Join-Path $runtimeSourceRoot 'scripts/appliance/atlaso-helper') -Algorithm SHA256).Hash.ToLowerInvariant()
        $installedHelperSha256 = Get-CertificateInstalledHelperSha256 -ApplianceVmx $applianceVmx
        if ($installedHelperSha256 -cne $sourceHelperSha256) {
            throw 'Installed appliance helper digest differs from the admitted source helper.'
        }
        $certificateRuntime = Write-CertificateLabReceipt -Name 'deployed-runtime.json' -Value ([ordered]@{
            schema = 1; task_id = $env:CODEX_THREAD_ID; repository = 'mdaneri/Atlaso'
            pr = $PullRequestNumber; vmx_path = $applianceVmx
            vm_ownership_sha256 = $certificateOwnership.Sha256
            predeployment_sha256 = $certificateSource.Sha256
            deployed_commit = $sourceCommit
            wheel_sha256 = $applianceWheel.Sha256.ToLowerInvariant()
            helper_sha256 = $installedHelperSha256
            url = $ApplianceUrl; interface = 'eth0'
            mac = (Get-VmxEthernetMacAddress -Path $applianceVmx -Index 0)
            observed_address = $ApplianceIPAddress
            address_ownership_state = 'unproven'
        })
        Write-Host "Certificate clone evidence: $($certificateRuntime.Path)"
    } else {
    $applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress -UserName $ApplianceSshUser -Password $adminPasswordSecure
    $clientAHost = ''
    $clientBHost = ''
    $clientAHostKey = ''
    $clientBHostKey = ''
    if (-not ($OidcOnly -or $CertificateOnly)) {
        $clientAHost = Wait-GuestIPv4 -Path $clientAVmx -GuestUser $ClientSshUser -GuestPassword $sshPasswordSecure -Name $clientAName
        $clientBHost = Wait-GuestIPv4 -Path $clientBVmx -GuestUser $ClientSshUser -GuestPassword $sshPasswordSecure -Name $clientBName
        if (-not $clientAHost -or -not $clientBHost) {
            throw 'Client guest readiness did not return both lifecycle addresses.'
        }
        $clientAHostKey = Get-PlinkHostKey -HostName $clientAHost -UserName $ClientSshUser -Password $sshPasswordSecure
        $clientBHostKey = Get-PlinkHostKey -HostName $clientBHost -UserName $ClientSshUser -Password $sshPasswordSecure
    }
    $appliancePxeInstallerIsoPath = if ($FullEsxiPxeInstall) {
        Resolve-ApplianceEsxiIsoPath -ApplianceVmx $applianceVmx
    } else {
        ''
    }

    $basePythonArgs = @(
        (Join-Path $runtimeSourceRoot 'scripts\interop\lifecycle_test.py'),
        '--appliance-url', $ApplianceUrl,
        '--appliance-ssh-host', $ApplianceIPAddress,
        '--username', $AdminUsername,
        '--appliance-ssh-user', $ApplianceSshUser,
        '--client-ssh-user', $ClientSshUser,
        '--secret-stdin',
        '--site-interface', $SiteInterface,
        '--site-cidr', $SiteCidr,
        '--vlan-id', "$VlanId",
        '--vlan-cidr', $TaggedVlanCidr,
        '--wan-cidr', $WanCidr,
        '--pxe-test-mode', $(if ($FullEsxiPxeInstall) { 'esxi' } else { 'linux' })
    )
    if ($FullEsxiPxeInstall) {
        $basePythonArgs += @(
            '--pxe-client-mac', $esxiMacAddress,
            '--pxe-installer-iso-path', $appliancePxeInstallerIsoPath
        )
        if ($PxeClientIPAddress) {
            $basePythonArgs += @('--pxe-client-ip', $PxeClientIPAddress)
        }
    }
    if ($applianceHostKey) { $basePythonArgs += @('--appliance-ssh-hostkey', $applianceHostKey) }
    if ($clientAHost) { $basePythonArgs += @('--client-a-host', $clientAHost) }
    if ($clientBHost) { $basePythonArgs += @('--client-b-host', $clientBHost) }
    if ($clientAHostKey) { $basePythonArgs += @('--client-a-hostkey', $clientAHostKey) }
    if ($clientBHostKey) { $basePythonArgs += @('--client-b-hostkey', $clientBHostKey) }
    if ($AllowDryRunApply) { $basePythonArgs += '--allow-dry-run' }
    if ($OidcOnly) { $basePythonArgs += '--oidc-only' }
    if ($RoutingWanOnly) { $basePythonArgs += '--routing-wan-only' }

    $initialResultRoot = if ($SkipBackupRestoreTest) { $resultRoot } else { Join-Path $resultRoot 'initial' }
    $restoredResultRoot = Join-Path $resultRoot 'restored'
    $backupArchivePath = Join-Path $resultRoot 'settings-backup.json'

    $initialPythonArgs = @($basePythonArgs + @('--result-dir', $initialResultRoot))
    # The restored-state pass validates backup portability, not a second release transaction.
    if ($SignedReleaseRepositoryUrl) { $initialPythonArgs += @('--signed-release-repository-url', $SignedReleaseRepositoryUrl) }
    if (-not $SkipBackupRestoreTest) {
        $initialPythonArgs += @('--export-settings-backup', $backupArchivePath)
    }

    if ($PSCmdlet.ShouldProcess($LabName, 'Run Workstation lifecycle interop scenario')) {
        $pythonExitCode = Invoke-LifecyclePython -Arguments $initialPythonArgs -SourcePins $runtimeConsumerPins `
            -AdminPassword $adminPasswordSecure `
            -SshPassword $sshPasswordSecure `
            -VcfBackupPassword $vcfBackupPasswordSecure `
            -EsxiPassword $esxiPasswordSecure
        if ($pythonExitCode -ne 0) {
            throw "Lifecycle interop runner failed with exit code $pythonExitCode"
        }
        if ($FullEsxiPxeInstall) {
            try {
                Start-WorkstationVm -Path $esxiVmx
                if ($EsxiInstallProbeDelaySeconds -gt 0) {
                    Write-Host "Waiting $EsxiInstallProbeDelaySeconds seconds before probing ESXi guest operations."
                    Start-Sleep -Seconds $EsxiInstallProbeDelaySeconds
                }
                $esxiDetectedIp = Wait-GuestIPv4 -Path $esxiVmx -TimeoutSeconds $EsxiInstallTimeoutSeconds -GuestUser 'root' -GuestPassword $esxiPasswordSecure -Name $esxiName
                if (-not $esxiDetectedIp) {
                    throw "Timed out waiting for ESXi PXE install guest IP after $EsxiInstallTimeoutSeconds seconds."
                }
                Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'passed' -Evidence @{
                    vmx                = $esxiVmx
                    mac_address        = $esxiMacAddress
                    detected_ip        = $esxiDetectedIp
                    installer_iso_path = $appliancePxeInstallerIsoPath
                }
            } catch {
                Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'failed' -Evidence @{
                    vmx                = $esxiVmx
                    mac_address        = $esxiMacAddress
                    installer_iso_path = $appliancePxeInstallerIsoPath
                } -ErrorMessage $_.Exception.Message
                throw
            }
        }
        if (-not $SkipBackupRestoreTest) {
            $restoredPythonArgs = @($basePythonArgs + @(
                '--result-dir', $restoredResultRoot,
                '--restore-settings-backup', $backupArchivePath,
                '--restored-state-run',
                '--certificate-baseline-result', (Join-Path $initialResultRoot 'result.json')
            ))
            $pythonExitCode = Invoke-LifecyclePython -Arguments $restoredPythonArgs -SourcePins $runtimeConsumerPins `
                -AdminPassword $adminPasswordSecure `
                -SshPassword $sshPasswordSecure `
                -VcfBackupPassword $vcfBackupPasswordSecure `
                -EsxiPassword $esxiPasswordSecure
            if ($pythonExitCode -ne 0) {
                throw "Restored lifecycle interop runner failed with exit code $pythonExitCode"
            }
        }
    }
    }
    if ($CertificateDhcpPeer) {
        # The NoCloud seed contains only a public key. Pin the SSH host key
        # established on first boot across the required seed-removal restart.
        Assert-CertificatePeerBootReady -Path $certificatePeerVmx
        $initialPeerIdentity = Get-CertificatePeerOriginalIdentity -Path $certificatePeerVmx
        $certificateKnownHostsPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($certificatePeerKnownHostsPath, $true)
        Remove-ClientSeedArtifacts -VmxPaths @($certificatePeerVmx) -SeedPaths @($certificatePeerSeedIso) -Restart:(-not $CleanupCreatedLab)
        $seedArtifactsRetired = $true
        if (-not $CleanupCreatedLab) {
            Assert-CertificatePeerBootReady -Path $certificatePeerVmx
            $peerIdentityReadback = Get-CertificatePeerOriginalIdentity -Path $certificatePeerVmx
            if ($peerIdentityReadback.ssh_host_key -cne $initialPeerIdentity.ssh_host_key) {
                throw 'Certificate peer SSH host key changed across seed retirement.'
            }
        } else {
            $peerIdentityReadback = $initialPeerIdentity
        }
        if ([Atlaso.WorkstationFileIdentity]::Get($certificatePeerDiskPath) -cne $certificatePeerDiskIdentity) {
            throw 'Certificate peer copied disk identity changed during boot or seed retirement.'
        }
        $certificatePeerIdentity = Write-CertificateLabReceipt -Name 'peer-identity.json' -Value ([ordered]@{
            schema = 1; kind = 'certificate-peer-original-identity'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber
            peer_vmx = $certificatePeerVmx; peer_ownership_sha256 = $peerOwnership.Sha256
            peer_fixture_sha256 = $peerFixture.Sha256
            client_vmdk_copy_identity = $certificatePeerDiskIdentity
            management_network = $ManagementNetwork; management_address = $peerIdentityReadback.management_address
            ssh_user = $ClientSshUser; ssh_host_key = $peerIdentityReadback.ssh_host_key
            ssh_public_key = $certificatePeerPublicKey
            observation = 'owned-vmware-tools-and-agent-ssh-after-management-restart'
        })
        $certificatePeerDiskPin.Dispose()
        $certificatePeerDiskPin = $null
        $certificateDiskSourcePin.Dispose()
        $certificateDiskSourcePin = $null
        if (-not (Test-WorkstationVmRunning -Path $applianceVmx) -or
            (Get-VmxEthernetMacAddress -Path $applianceVmx -Index 0) -cne (ConvertTo-HyphenMac -MacAddress $certificateAppliancePeerMac)) {
            throw 'Certificate appliance bootstrap MAC or running state changed before private handoff.'
        }
        $rewireIntent = Write-CertificateLabReceipt -Name 'management-rewire-intent.json' -Value ([ordered]@{
            schema = 1; kind = 'certificate-management-rewire-intent'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber; source_commit = $sourceCommit
            appliance_vmx = $applianceVmx; appliance_ownership_sha256 = $certificateOwnership.Sha256
            bootstrap_runtime_sha256 = $certificateRuntime.Sha256
            peer_fixture_sha256 = $peerFixture.Sha256
            peer_identity_sha256 = $certificatePeerIdentity.Sha256
            from_network = $ManagementNetwork; to_network = $SiteANetwork
            lan_segment_receipt_sha256 = $ownedLanSegments[0].ReceiptSha256.ToLowerInvariant()
            mac = $certificateAppliancePeerMac; expected_dhcp_address = $CertificateLeaseAddress
        })
        $softStop = Invoke-VmrunBounded -Arguments @('-T', 'ws', 'stop', $applianceVmx, 'soft') -TimeoutSeconds 45
        if ($softStop.ExitCode -ne 0) { throw 'Certificate appliance soft stop failed before private handoff.' }
        $stopDeadline = (Get-Date).AddSeconds(45)
        while ((Test-WorkstationVmRunning -Path $applianceVmx) -and (Get-Date) -lt $stopDeadline) {
            Start-Sleep -Seconds 3
        }
        if (Test-WorkstationVmRunning -Path $applianceVmx) {
            throw 'Certificate appliance remained powered on; private eth0 rewire was refused.'
        }
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 0 -Vmnet $SiteANetwork -StaticMac $certificateAppliancePeerMac
        $rewiredAdapterLines = @(Get-Content -LiteralPath $applianceVmx | Where-Object { $_ -match '^\s*ethernet0\.pvnID\s*=' })
        if ($rewiredAdapterLines.Count -ne 1 -or $rewiredAdapterLines[0] -notmatch '^\s*ethernet0\.pvnID\s*=\s*"(?<id>[^"]+)"\s*$' -or
            $Matches['id'] -cne $ownedLanSegments[0].Id -or
            (Get-VmxEthernetMacAddress -Path $applianceVmx -Index 0) -cne (ConvertTo-HyphenMac -MacAddress $certificateAppliancePeerMac)) {
            throw 'Certificate appliance eth0 private LAN or preserved MAC readback failed.'
        }
        Start-WorkstationVm -Path $applianceVmx
        # The preserved MAC can leave an old management address in the host neighbor cache.
        # Wait for the reserved lease from VMware Tools or guest operations instead.
        $privateAddress = Wait-GuestIPv4 -Path $applianceVmx -TimeoutSeconds 300 -GuestUser $ApplianceSshUser -GuestPassword $adminPasswordSecure -Name $applianceName -ExpectedAddress $CertificateLeaseAddress -SkipHostNeighbor
        if ($privateAddress -cne $CertificateLeaseAddress) {
            throw 'Certificate appliance did not report the reserved private DHCP address after eth0 rewire.'
        }
        if ((Get-CertificateInstalledHelperSha256 -ApplianceVmx $applianceVmx) -cne $installedHelperSha256) {
            throw 'Installed appliance helper changed during certificate private handoff.'
        }
        $rewiredRuntime = Write-CertificateLabReceipt -Name 'rewired-runtime.json' -Value ([ordered]@{
            schema = 1; kind = 'certificate-rewired-runtime'; task_id = $env:CODEX_THREAD_ID
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber
            vmx_path = $applianceVmx; vm_ownership_sha256 = $certificateOwnership.Sha256
            bootstrap_runtime_sha256 = $certificateRuntime.Sha256
            predeployment_sha256 = $certificateSource.Sha256
            rewire_intent_sha256 = $rewireIntent.Sha256
            peer_identity_sha256 = $certificatePeerIdentity.Sha256
            deployed_commit = $sourceCommit; wheel_sha256 = $applianceWheel.Sha256.ToLowerInvariant()
            helper_sha256 = $installedHelperSha256
            url = "https://$(New-AtlasoWorkstationFqdn -Name $applianceName)"
            interface = 'eth0'; mac = (Get-VmxEthernetMacAddress -Path $applianceVmx -Index 0)
            observed_address = $privateAddress; address_ownership_state = 'unproven'
        })
        Write-Host "Certificate private handoff evidence: $($rewiredRuntime.Path)"
    }
    if (-not ($OidcOnly -or $CertificateOnly)) {
        # Successful lifecycle client access proves cloud-init consumed both
        # seeds. Leave retained labs running only after verified deletion.
        Remove-ClientSeedArtifacts `
            -VmxPaths @($clientAVmx, $clientBVmx) `
            -SeedPaths @($clientASeedIso, $clientBSeedIso) `
            -Restart:(-not $CleanupCreatedLab)
        $seedArtifactsRetired = $true
    }
} catch {
    $scenarioFailure = $_
}

# A failed boot still owns its copied disk; release admission handles before
# the documented seed and task-owned VM cleanup paths inspect that VM.
if ($scenarioFailure) {
    if ($certificatePeerDiskPin) { $certificatePeerDiskPin.Dispose(); $certificatePeerDiskPin = $null }
    if ($certificateKnownHostsPin) { $certificateKnownHostsPin.Dispose(); $certificateKnownHostsPin = $null }
    if ($certificatePeerPublicKeyPin) { $certificatePeerPublicKeyPin.Dispose(); $certificatePeerPublicKeyPin = $null }
    if ($certificateDiskSourcePin) { $certificateDiskSourcePin.Dispose(); $certificateDiskSourcePin = $null }
}

# No further provider operations are safe while a diagnostic writer may survive.
if ($diagnosticTerminationUnproven) {
    throw "Lifecycle provider termination is unproven. VM and diagnostic staging cleanup is blocked; preserve lab '$LabName' at '$vmRoot' until the owning process tree is proven inactive."
}

$seedCleanupFailure = $null
if (-not $seedArtifactsRetired) {
    try {
        # Failure cleanup intentionally leaves affected clients stopped: a
        # restart is unsafe until every credential-bearing ISO is absent.
        Remove-ClientSeedArtifacts `
            -VmxPaths @($clientAVmx, $clientBVmx, $certificatePeerVmx) `
            -SeedPaths @($clientASeedIso, $clientBSeedIso, $certificatePeerSeedIso)
        $seedArtifactsRetired = $true
    } catch {
        $seedCleanupFailure = $_
    }
}

$cleanupFailure = $null
if ($CleanupCreatedLab) {
    $createdVmxPathArray = @($createdVmxPaths.ToArray())
    if ($createdVmxPathArray.Count -gt 0) {
        try {
            if ($PSCmdlet.ShouldProcess($vmRoot, 'Stop and delete created VMware Workstation lifecycle artifacts')) {
                Remove-AtlasoWorkstationVmArtifacts `
                    -VmrunPath $resolvedVmrun `
                    -VmxPaths $createdVmxPathArray `
                    -RemovalRoot $vmRoot `
                    -KeepRemovalRoot `
                    -Confirm:$false
            }
        } catch {
            $cleanupFailure = $_
        }
    }
} else {
    Write-Host "Workstation lifecycle VMs were left in place under: $vmRoot"
}

if ($scenarioFailure) {
    if ($seedCleanupFailure -or $cleanupFailure) {
        $cleanupMessages = @(
            $seedCleanupFailure,
            $cleanupFailure
        ) | Where-Object { $null -ne $_ } | ForEach-Object { $_.Exception.Message }
        $combinedMessage = "Lifecycle scenario failed: $($scenarioFailure.Exception.Message) Cleanup also failed; VM artifacts were preserved at '$vmRoot': $($cleanupMessages -join '; ')"
        throw [System.InvalidOperationException]::new($combinedMessage, $scenarioFailure.Exception)
    }
    throw $scenarioFailure
}
if ($seedCleanupFailure) {
    if ($cleanupFailure) {
        throw "Credential-bearing seed cleanup failed: $($seedCleanupFailure.Exception.Message) VM cleanup also failed: $($cleanupFailure.Exception.Message)"
    }
    throw $seedCleanupFailure
}
if ($cleanupFailure) {
    throw $cleanupFailure
}
} finally {
    if ($certificatePeerDiskPin) { $certificatePeerDiskPin.Dispose() }
    if ($certificateKnownHostsPin) { $certificateKnownHostsPin.Dispose() }
    if ($certificatePeerPublicKeyPin) { $certificatePeerPublicKeyPin.Dispose() }
    if ($certificateDiskSourcePin) { $certificateDiskSourcePin.Dispose() }
    for ($pinIndex = $runtimeConsumerPins.Count - 1; $pinIndex -ge 0; $pinIndex--) { $runtimeConsumerPins[$pinIndex].Dispose() }
    if ($preflightGuard) { $preflightGuard.Dispose() }
}
