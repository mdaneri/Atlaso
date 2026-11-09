<#
.SYNOPSIS
Define private Windows suspended-job and deadline primitives for capture qualification.
#>

Set-StrictMode -Version Latest

if ($IsWindows -and -not ('Atlaso.RestorationCaptureJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Atlaso
{
    public sealed class RestorationCaptureChild
    {
        public string JobName { get; }
        public uint ProcessId { get; }
        public long CreationFileTimeUtc { get; }

        internal RestorationCaptureChild(string jobName, uint processId, long creationFileTimeUtc)
        {
            JobName = jobName;
            ProcessId = processId;
            CreationFileTimeUtc = creationFileTimeUtc;
        }
    }

    public sealed class RestorationCaptureJob : IDisposable
    {
        private const uint Suspended = 4;
        private const uint UnicodeEnvironment = 0x400;
        private const uint ExtendedStartup = 0x80000;
        private const uint NoWindow = 0x08000000;
        private const uint KillOnClose = 0x2000;
        private const uint WaitTimeout = 258;
        private const uint FailureExit = 0xE0000001;
        private const int CleanupMilliseconds = 5000;
        private static readonly List<object> Unresolved = new List<object>();

        private enum Phase { Suspended, Publishing, Running, ForcedFailure, NaturalExitVerified }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            internal int Length;
            internal IntPtr Descriptor;
            internal int Inherit;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenLogonGroup
        {
            internal uint Count;
            internal IntPtr Sid;
            internal uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimits
        {
            internal long ProcessTime;
            internal long JobTime;
            internal uint Flags;
            internal UIntPtr MinimumWorkingSet;
            internal UIntPtr MaximumWorkingSet;
            internal uint ActiveLimit;
            internal UIntPtr Affinity;
            internal uint Priority;
            internal uint Scheduling;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            internal ulong Read, Write, Other, ReadBytes, WriteBytes, OtherBytes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimits
        {
            internal BasicLimits Basic;
            internal IoCounters Io;
            internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Accounting
        {
            internal long TotalUser, TotalKernel, PeriodUser, PeriodKernel;
            internal uint Faults, Total, Active, Terminated;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            internal uint Size;
            internal IntPtr Reserved, Desktop, Title;
            internal uint X, Y, Width, Height, Columns, Rows, Fill, Flags;
            internal ushort Show, ReservedSize;
            internal IntPtr ReservedBytes, Input, Output, Error;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            internal StartupInfo Startup;
            internal IntPtr Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInfo
        {
            internal IntPtr Process, Thread;
            internal uint ProcessId, ThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateJobObjectW(ref SecurityAttributes security, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(SafeFileHandle job, int information,
            ref ExtendedLimits limits, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(SafeFileHandle job, int information,
            out Accounting accounting, uint size, out uint returned);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr attributes, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr attributes, uint flags, UIntPtr attribute,
            IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributes);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string executable, StringBuilder command, IntPtr processSecurity,
            IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string directory,
            ref StartupInfoEx startup, out ProcessInfo process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(SafeFileHandle process, SafeFileHandle job, out bool result);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(SafeFileHandle process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(SafeFileHandle process, out long created, out long exited,
            out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageNameW(SafeFileHandle process, uint flags,
            StringBuilder path, ref uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(SafeFileHandle thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")]
        private static extern bool QueryPerformanceCounter(out long ticks);
        [DllImport("kernel32.dll")]
        private static extern bool QueryPerformanceFrequency(out long frequency);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int information,
            IntPtr buffer, uint length, out uint required);
        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
            out IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        private readonly SafeFileHandle job;
        private readonly SafeFileHandle process;
        private readonly SafeFileHandle thread;
        private readonly RawSecurityDescriptor security;
        private readonly Thread owner = Thread.CurrentThread;
        private readonly Thread watcher;
        private readonly ManualResetEventSlim armed = new ManualResetEventSlim();
        private readonly ManualResetEventSlim wake = new ManualResetEventSlim();
        private readonly object gate = new object();
        private readonly long deadlineCounter;
        private readonly long frequency;
        private readonly DateTimeOffset deadlineUtc;
        private Phase phase;
        private bool watcherStarted;
        private bool terminationRequested;
        private bool disposed;
        private bool retained;

        public string Name { get; }
        public uint ProcessId { get; }
        public long CreationFileTimeUtc { get; }

        private RestorationCaptureJob(SafeFileHandle job, SafeFileHandle process, SafeFileHandle thread,
            RawSecurityDescriptor security, string name, uint pid, long created, long end, long hz, DateTimeOffset utc)
        {
            this.job = job;
            this.process = process;
            this.thread = thread;
            this.security = security;
            Name = name;
            ProcessId = pid;
            CreationFileTimeUtc = created;
            deadlineCounter = end;
            frequency = hz;
            deadlineUtc = utc;
            watcher = new Thread(Watch) { IsBackground = true, Name = "Atlaso owned capture watchdog" };
        }

        private static Win32Exception Error(string message) => new Win32Exception(Marshal.GetLastWin32Error(), message);

        private static int WaitBudget(long end, long hz, DateTimeOffset utc)
        {
            if (!QueryPerformanceCounter(out long now) || now < 0 || now >= end)
                throw new TimeoutException("The original capture job deadline elapsed.");
            double counter = (end - now) * 1000d / hz;
            double wall = (utc - DateTimeOffset.UtcNow).TotalMilliseconds;
            if (counter > 420000 || wall > 420000)
                throw new ArgumentException("The original capture job budget exceeds its maximum.");
            int remaining = (int)Math.Floor(Math.Min(counter, wall));
            if (remaining < 1)
                throw new TimeoutException("The original capture job deadline elapsed.");
            return Math.Min(remaining, 50);
        }

        private int WaitBudget() => WaitBudget(deadlineCounter, frequency, deadlineUtc);

        private static RawSecurityDescriptor OriginalSecurity()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                const int tokenLogonSid = 28;
                const uint logonId = 0xC0000000;
                const uint enabled = 4;
                const uint denyOnly = 16;
                if (GetTokenInformation(identity.AccessToken, tokenLogonSid, IntPtr.Zero, 0, out uint size) ||
                    Marshal.GetLastWin32Error() != 122 || size < Marshal.SizeOf<TokenLogonGroup>() || size > 4096 ||
                    identity.User == null)
                    throw new InvalidOperationException("The original job logon identity is unavailable.");
                IntPtr buffer = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (!GetTokenInformation(identity.AccessToken, tokenLogonSid, buffer, size, out _))
                        throw Error("The original job logon identity could not be read.");
                    TokenLogonGroup group = Marshal.PtrToStructure<TokenLogonGroup>(buffer);
                    if (group.Count != 1 || group.Sid == IntPtr.Zero ||
                        (group.Attributes & (logonId | enabled | denyOnly)) != (logonId | enabled))
                        throw new InvalidOperationException("The original job logon group differs.");
                    SecurityIdentifier logon = new SecurityIdentifier(group.Sid);
                    if (!logon.IsWellKnown(WellKnownSidType.LogonIdsSid))
                        throw new InvalidOperationException("The original job logon SID differs.");
                    return new RawSecurityDescriptor("O:" + identity.User.Value + "D:P(A;;0x4;;;" +
                        logon.Value + ")(A;;RC;;;OW)");
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }

        private static void VerifySecurity(SafeFileHandle job, RawSecurityDescriptor expected)
        {
            const int kernelObject = 6;
            const uint ownerAndDacl = 5;
            uint error = GetSecurityInfo(job, kernelObject, ownerAndDacl, out _, IntPtr.Zero, out _, IntPtr.Zero,
                out IntPtr pointer);
            if (error != 0)
                throw new Win32Exception((int)error, "The original job security could not be read.");
            try
            {
                uint length = GetSecurityDescriptorLength(pointer);
                if (length < 20 || length > 4096)
                    throw new InvalidOperationException("The original job security descriptor size differs.");
                byte[] bytes = new byte[length];
                Marshal.Copy(pointer, bytes, 0, bytes.Length);
                var actual = new RawSecurityDescriptor(bytes, 0);
                var acl = actual.DiscretionaryAcl;
                var required = expected.DiscretionaryAcl;
                if (!expected.Owner.Equals(actual.Owner) || (actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                    acl == null || acl.Count != required.Count)
                    throw new InvalidOperationException("The original job owner or DACL differs.");
                for (int index = 0; index < acl.Count; index++)
                    if (!acl[index].Equals(required[index]))
                        throw new InvalidOperationException("The original job access rules differ.");
            }
            finally { LocalFree(pointer); }
        }

        private static SafeFileHandle CreateJob(string name, RawSecurityDescriptor security)
        {
            byte[] descriptor = new byte[security.BinaryLength];
            security.GetBinaryForm(descriptor, 0);
            GCHandle pin = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
            try
            {
                var attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = pin.AddrOfPinnedObject()
                };
                SafeFileHandle result = CreateJobObjectW(ref attributes, name);
                int error = Marshal.GetLastWin32Error();
                if (result.IsInvalid || error == 183)
                {
                    result.Dispose();
                    throw new Win32Exception(error, "The original capture job name is unavailable.");
                }
                return result;
            }
            finally { pin.Free(); }
        }

        private static string Quote(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0)
                throw new ArgumentException("The capture child argument differs.");
            var quoted = new StringBuilder().Append('"');
            int slashes = 0;
            foreach (char character in value)
            {
                if (character == '\\') { slashes++; continue; }
                if (character == '"')
                    quoted.Append('\\', slashes + 1);
                quoted.Append('\\', slashes).Append(character);
                slashes = 0;
            }
            return quoted.Append('\\', slashes * 2).Append('"').ToString();
        }

        private static string ExactPath(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
                !StringComparer.Ordinal.Equals(Path.GetFullPath(path), path))
                throw new ArgumentException("The capture fixture path must be an exact local path.");
            return path;
        }

        private static ProcessInfo StartSuspended(SafeFileHandle job, string executable, string[] args, string directory)
        {
            IntPtr size = IntPtr.Zero;
            if (InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size) ||
                Marshal.GetLastWin32Error() != 122 || size.ToInt64() < IntPtr.Size || size.ToInt64() > 65536)
                throw new InvalidOperationException("Creation-time job attributes are unavailable.");
            IntPtr attributes = IntPtr.Zero, value = IntPtr.Zero, environment = IntPtr.Zero;
            bool initialized = false;
            try
            {
                attributes = Marshal.AllocHGlobal(size);
                value = Marshal.AllocHGlobal(IntPtr.Size);
                if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size))
                    throw Error("Creation-time job attributes could not be initialized.");
                initialized = true;
                Marshal.WriteIntPtr(value, job.DangerousGetHandle());
                // PROC_THREAD_ATTRIBUTE_JOB_LIST binds the only allowed job during process creation.
                if (!UpdateProcThreadAttribute(attributes, 0, new UIntPtr(0x0002000D), value, new IntPtr(IntPtr.Size),
                    IntPtr.Zero, IntPtr.Zero))
                    throw Error("Creation-time job assignment is unavailable.");
                string windows = ExactPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
                byte[] block = Encoding.Unicode.GetBytes("ATLASO_CAPTURE_FIXTURE=1\0SystemRoot=" + windows +
                    "\0TEMP=" + directory + "\0TMP=" + directory + "\0\0");
                environment = Marshal.AllocHGlobal(block.Length);
                Marshal.Copy(block, 0, environment, block.Length);
                var command = new StringBuilder(Quote(executable));
                foreach (string argument in args)
                    command.Append(' ').Append(Quote(argument));
                if (command.Length >= 32767)
                    throw new ArgumentException("The capture child command exceeds its bound.");
                var startup = new StartupInfoEx {
                    Startup = new StartupInfo { Size = (uint)Marshal.SizeOf<StartupInfoEx>() }, Attributes = attributes
                };
                if (!CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, false,
                    Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow, environment, directory, ref startup,
                    out ProcessInfo info))
                    throw Error("The original capture child could not be created suspended.");
                return info;
            }
            finally
            {
                if (initialized) DeleteProcThreadAttributeList(attributes);
                if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if (value != IntPtr.Zero) Marshal.FreeHGlobal(value);
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
            }
        }

        public static RestorationCaptureJob Create(Guid nonce, string executable, string[] arguments, string directory,
            long end, long hz, DateTimeOffset utc)
        {
            ExactPath(executable);
            ExactPath(directory);
            if (nonce == Guid.Empty || arguments == null || arguments.Length > 32 || end <= 0 ||
                !QueryPerformanceFrequency(out long actual) || actual <= 0 || actual != hz)
                throw new ArgumentException("The original capture job inputs differ.");
            int argumentLength = executable.Length;
            foreach (string argument in arguments)
            {
                if (argument == null || argument.Length > 16384 || argument.IndexOf('\0') >= 0)
                    throw new ArgumentException("The original capture job argument differs.");
                argumentLength += argument.Length;
                if (argumentLength >= 32767)
                    throw new ArgumentException("The original capture job arguments exceed their bound.");
            }
            WaitBudget(end, hz, utc);
            string name = @"Local\AtlasoRestorationCapture-" + nonce.ToString("N");
            RawSecurityDescriptor security = OriginalSecurity();
            SafeFileHandle job = CreateJob(name, security);
            SafeFileHandle process = null, thread = null;
            RestorationCaptureJob owned = null;
            bool member = false;
            try
            {
                VerifySecurity(job, security);
                var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = KillOnClose } };
                if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()))
                    throw Error("The original job limits could not be set.");
                WaitBudget(end, hz, utc);
                ProcessInfo info = StartSuspended(job, executable, arguments, directory);
                process = new SafeFileHandle(info.Process, true);
                thread = new SafeFileHandle(info.Thread, true);
                var image = new StringBuilder(32768);
                uint capacity = (uint)image.Capacity;
                if (!IsProcessInJob(process, job, out member) || !member || info.ProcessId == 0 ||
                    GetProcessId(process) != info.ProcessId || !GetProcessTimes(process, out long created, out _, out _, out _) ||
                    created <= 0 || !QueryFullProcessImageNameW(process, 0, image, ref capacity) ||
                    !StringComparer.OrdinalIgnoreCase.Equals(executable, image.ToString()) || IsSignaled(process, 0))
                    throw new InvalidOperationException("The original suspended child identity differs.");
                owned = new RestorationCaptureJob(job, process, thread, security, name, info.ProcessId, created, end, hz, utc);
                owned.watcher.Start();
                owned.watcherStarted = true;
                while (!owned.armed.Wait(owned.WaitBudget())) { }
                owned.WaitBudget();
                return owned;
            }
            catch
            {
                if (owned != null && owned.watcherStarted)
                    owned.Dispose();
                else
                {
                    // A process whose membership cannot be confirmed stays suspended and uses its original handle.
                    if (process != null)
                    {
                        bool terminated = member ? TerminateJobObject(job, FailureExit) : TerminateProcess(process, FailureExit);
                        if (!terminated || !WaitForStop(job, process))
                        {
                            lock (Unresolved) { Unresolved.Add(new object[] { job, process, thread }); }
                            throw new InvalidOperationException("Original suspended launch custody remains unresolved.");
                        }
                    }
                    thread?.Dispose();
                    process?.Dispose();
                    job.Dispose();
                }
                throw;
            }
        }

        private static bool IsSignaled(SafeFileHandle process, uint milliseconds)
        {
            uint result = WaitForSingleObject(process, milliseconds);
            if (result == 0) return true;
            if (result == WaitTimeout) return false;
            throw Error("The original root process wait could not be verified.");
        }

        private static uint Active(SafeFileHandle job)
        {
            uint size = (uint)Marshal.SizeOf<Accounting>();
            if (!QueryInformationJobObject(job, 1, out Accounting accounting, size, out uint returned) || returned != size)
                throw new InvalidOperationException("The original job activity could not be verified.");
            return accounting.Active;
        }

        private static bool WaitForStop(SafeFileHandle job, SafeFileHandle process)
        {
            try
            {
                Stopwatch grace = Stopwatch.StartNew();
                do
                {
                    if (IsSignaled(process, 0) && Active(job) == 0) return true;
                    Thread.Sleep(10);
                } while (grace.ElapsedMilliseconds < CleanupMilliseconds);
            }
            catch (Win32Exception) { }
            catch (InvalidOperationException) { }
            return false;
        }

        private void RequireOwner()
        {
            if (Thread.CurrentThread != owner || disposed || retained)
                throw new InvalidOperationException("The original capture job owner or lifetime differs.");
        }

        private void ForceFailure()
        {
            lock (gate)
            {
                if (phase != Phase.NaturalExitVerified)
                    phase = Phase.ForcedFailure;
                wake.Set();
            }
        }

        private void Watch()
        {
            try
            {
                WaitBudget();
                armed.Set();
                while (true)
                {
                    lock (gate)
                    {
                        if (phase == Phase.NaturalExitVerified) return;
                        if (phase == Phase.ForcedFailure) break;
                    }
                    wake.Wait(WaitBudget());
                }
            }
            catch (TimeoutException) { ForceFailure(); }
            catch (ArgumentException) { ForceFailure(); }
            finally { armed.Set(); }

            lock (gate)
            {
                if (phase == Phase.NaturalExitVerified) return;
            }
            terminationRequested = TerminateJobObject(job, FailureExit);
        }

        public bool OriginalJobStopped()
        {
            RequireOwner();
            return IsSignaled(process, 0) && Active(job) == 0;
        }

        public void PublishAndResume(Action<RestorationCaptureChild> publish)
        {
            RequireOwner();
            if (publish == null) throw new ArgumentNullException(nameof(publish));
            try
            {
                lock (gate)
                {
                    if (phase != Phase.Suspended) throw new InvalidOperationException("The original child cannot publish.");
                    WaitBudget();
                    phase = Phase.Publishing;
                }
                VerifySecurity(job, security);
                // The controller publishes and verifies its own durable original receipt here.
                // Its return is not proof and the watchdog can terminate while it is blocked.
                publish(new RestorationCaptureChild(Name, ProcessId, CreationFileTimeUtc));
                VerifySecurity(job, security);
                lock (gate)
                {
                    if (phase != Phase.Publishing) throw new InvalidOperationException("The original child cannot resume.");
                    WaitBudget();
                    if (ResumeThread(thread) != 1)
                        throw new InvalidOperationException("The original suspended thread count differs.");
                    WaitBudget();
                    phase = Phase.Running;
                }
            }
            catch { ForceFailure(); throw; }
        }

        public void WaitForNaturalExit()
        {
            RequireOwner();
            try
            {
                while (true)
                {
                    lock (gate)
                    {
                        if (phase != Phase.Running)
                            throw new InvalidOperationException("The original child cannot complete naturally.");
                    }
                    int wait = WaitBudget();
                    if (!IsSignaled(process, (uint)wait)) continue;
                    if (!GetExitCodeProcess(process, out uint exitCode))
                        throw Error("The original root exit status could not be read.");
                    lock (gate)
                    {
                        if (phase != Phase.Running)
                            throw new InvalidOperationException("The original child cannot complete naturally.");
                    }
                    if (exitCode != 0)
                        throw new InvalidOperationException("The original root did not exit successfully.");
                    if (Active(job) != 0) { wake.Wait(Math.Min(wait, 10)); continue; }
                    VerifySecurity(job, security);
                    lock (gate)
                    {
                        if (phase != Phase.Running)
                            throw new InvalidOperationException("The original job failure cannot be cleared.");
                        WaitBudget();
                        phase = Phase.NaturalExitVerified;
                        wake.Set();
                        return;
                    }
                }
            }
            catch { ForceFailure(); throw; }
        }

        private static void CloseOriginal(SafeFileHandle handle)
        {
            if (handle.IsClosed) return;
            if (!CloseHandle(handle.DangerousGetHandle()))
                throw Error("The original job handle could not be closed.");
            handle.SetHandleAsInvalid();
        }

        public void Dispose()
        {
            if (disposed) return;
            RequireOwner();
            ForceFailure();
            bool natural;
            lock (gate) { natural = phase == Phase.NaturalExitVerified; }
            try
            {
                if (!watcher.Join(CleanupMilliseconds) || (!natural && !terminationRequested) ||
                    !WaitForStop(job, process))
                    throw new InvalidOperationException("Original job stop or watchdog join remains unresolved.");
                CloseOriginal(thread);
                CloseOriginal(process);
                CloseOriginal(job);
                armed.Dispose();
                wake.Dispose();
                disposed = true;
            }
            catch
            {
                retained = true;
                lock (Unresolved) { Unresolved.Add(this); }
                throw;
            }
        }
    }
}
'@
}

Export-ModuleMember -Function @()
