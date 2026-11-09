<#
.SYNOPSIS
Define the private local Windows pipe primitives for restoration capture qualification.
#>

Set-StrictMode -Version Latest

if ($IsWindows -and -not ('Atlaso.RestorationCapturePipe' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Atlaso
{
    public sealed class RestorationPipeDeadline
    {
        [DllImport("kernel32.dll")]
        private static extern bool QueryPerformanceCounter(out long ticks);

        [DllImport("kernel32.dll")]
        private static extern bool QueryPerformanceFrequency(out long frequency);

        private readonly long end;
        private readonly long frequency;
        private readonly DateTimeOffset utcEnd;

        public RestorationPipeDeadline(long end, long frequency, DateTimeOffset utcEnd)
        {
            if (end <= 0 || frequency <= 0 || !QueryPerformanceFrequency(out long actual) || actual != frequency)
                throw new ArgumentException("Original pipe clock frequency is invalid.");
            this.end = end;
            this.frequency = frequency;
            this.utcEnd = utcEnd;
            RemainingMilliseconds();
        }

        // Round down and sample UTC again even during a long pending operation.
        internal int RemainingMilliseconds()
        {
            if (!QueryPerformanceCounter(out long now) || now < 0 || now >= end)
                throw new TimeoutException("Original pipe counter deadline elapsed.");
            double counterMilliseconds = (end - now) * 1000d / frequency;
            double utcMilliseconds = (utcEnd - DateTimeOffset.UtcNow).TotalMilliseconds;
            if (counterMilliseconds > 420000 || utcMilliseconds > 420000)
                throw new ArgumentException("Original pipe deadline exceeds its maximum budget.");
            int remaining = (int)Math.Floor(Math.Min(counterMilliseconds, utcMilliseconds));
            if (remaining <= 0)
                throw new TimeoutException("Original pipe deadline elapsed.");
            return Math.Min(remaining, 200);
        }
    }

    public sealed class RestorationCapturePipe : IDisposable
    {
        private const uint Duplex = 3;
        private const uint Overlapped = 0x40000000;
        private const uint FirstInstance = 0x00080000;
        private const uint RejectRemoteClients = 8;
        // Individual data/attribute/read-control/synchronize rights. Generic write also grants create-instance.
        private const uint ClientAccess = 0x00120083;
        private const uint OpenExisting = 3;
        private const uint IdentificationQos = 0x00110000;
        private const int BrokenPipe = 109;
        private const int AlreadyConnected = 535;
        private const int IoPending = 997;
        private const int OperationNotFound = 1168;
        private const int OperationAborted = 995;
        private const int NoData = 232;
        private const int PipeNotConnected = 233;
        private const int MaximumBytes = 393226;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            internal int Length;
            internal IntPtr Descriptor;
            internal int Inherit;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OperationData
        {
            internal IntPtr Internal;
            internal IntPtr InternalHigh;
            internal uint Offset;
            internal uint OffsetHigh;
            internal IntPtr Event;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenLogonGroup
        {
            internal uint Count;
            internal IntPtr Sid;
            internal uint Attributes;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafePipeHandle CreateNamedPipeW(string name, uint access, uint mode,
            uint instances, uint outputSize, uint inputSize, uint timeout, ref SecurityAttributes attributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafePipeHandle CreateFileW(string name, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ConnectNamedPipe(SafePipeHandle handle, IntPtr operation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(SafePipeHandle handle, out uint id);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle, out uint id);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(SafePipeHandle handle, IntPtr buffer, uint length, IntPtr unused, IntPtr operation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(SafePipeHandle handle, IntPtr buffer, uint length, IntPtr unused, IntPtr operation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetOverlappedResult(SafePipeHandle handle, IntPtr operation, out uint bytes, bool wait);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CancelIoEx(SafePipeHandle handle, IntPtr operation);

        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityInfo(SafePipeHandle handle, int objectType, uint information,
            out IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);

        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int information,
            IntPtr buffer, uint length, out uint required);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        private sealed class Operation : IDisposable
        {
            internal readonly EventWaitHandle Event = new EventWaitHandle(false, EventResetMode.ManualReset);
            internal IntPtr Data;
            internal IntPtr Buffer;
            internal readonly int Length;

            internal Operation(int length)
            {
                Length = length;
                try
                {
                    Data = Marshal.AllocHGlobal(Marshal.SizeOf<OperationData>());
                    if (length != 0)
                        Buffer = Marshal.AllocHGlobal(length);
                    Marshal.StructureToPtr(new OperationData { Event = Event.SafeWaitHandle.DangerousGetHandle() }, Data, false);
                }
                catch
                {
                    Dispose();
                    throw;
                }
            }

            public void Dispose()
            {
                if (Buffer != IntPtr.Zero)
                {
                    for (int index = 0; index < Length; index++)
                        Marshal.WriteByte(Buffer, index, 0);
                    Marshal.FreeHGlobal(Buffer);
                }
                if (Data != IntPtr.Zero)
                    Marshal.FreeHGlobal(Data);
                Event.Dispose();
            }
        }

        // A failed drain cannot release either the original endpoint or its native operation storage.
        private static readonly List<RestorationCapturePipe> Unresolved = new List<RestorationCapturePipe>();
        private readonly SafePipeHandle handle;
        private readonly RestorationPipeDeadline deadline;
        private readonly Thread owner = Thread.CurrentThread;
        private readonly bool server;
        private Operation pending;
        private bool connected;
        private bool failed;
        private bool ended;

        private RestorationCapturePipe(SafePipeHandle handle, RestorationPipeDeadline deadline, bool server)
        {
            this.handle = handle;
            this.deadline = deadline;
            this.server = server;
        }

        private static string Name(Guid nonce)
        {
            if (nonce == Guid.Empty)
                throw new ArgumentException("Original pipe nonce is missing.");
            return @"\\.\pipe\AtlasoRestorationCapture-" + nonce.ToString("N");
        }

        private static RawSecurityDescriptor ExpectedSecurity()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                // WindowsIdentity.Groups omits logon groups. Ask the token for its exact logon SID.
                const int tokenLogonSid = 28;
                const uint logonId = 0xC0000000;
                const uint enabled = 4;
                const uint denyOnly = 16;
                if (GetTokenInformation(identity.AccessToken, tokenLogonSid, IntPtr.Zero, 0, out uint length) ||
                    Marshal.GetLastWin32Error() != 122 || length < Marshal.SizeOf<TokenLogonGroup>() || length > 4096 ||
                    identity.User == null)
                    throw new InvalidOperationException("Pipe logon identity is unavailable.");
                IntPtr buffer = Marshal.AllocHGlobal((int)length);
                try
                {
                    if (!GetTokenInformation(identity.AccessToken, tokenLogonSid, buffer, length, out _))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Pipe logon identity read failed.");
                    TokenLogonGroup group = Marshal.PtrToStructure<TokenLogonGroup>(buffer);
                    if (group.Count != 1 || group.Sid == IntPtr.Zero ||
                        (group.Attributes & (logonId | enabled | denyOnly)) != (logonId | enabled))
                        throw new InvalidOperationException("Pipe logon identity is ambiguous or disabled.");
                    SecurityIdentifier logon = new SecurityIdentifier(group.Sid);
                    if (!logon.IsWellKnown(WellKnownSidType.LogonIdsSid))
                        throw new InvalidOperationException("Pipe logon SID differs.");
                    string mask = ClientAccess.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
                    return new RawSecurityDescriptor("O:" + identity.User.Value + "D:P(D;;0x000C0004;;;" +
                        logon.Value + ")(A;;0x" + mask + ";;;" + logon.Value + ")(A;;RC;;;OW)");
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }

        private static void VerifySecurity(SafePipeHandle handle, RawSecurityDescriptor expected)
        {
            uint error = GetSecurityInfo(handle, 1, 5, out _, IntPtr.Zero, out _, IntPtr.Zero, out IntPtr pointer);
            if (error != 0)
                throw new Win32Exception((int)error, "Original pipe security readback failed.");
            try
            {
                uint length = GetSecurityDescriptorLength(pointer);
                if (length < 20 || length > 4096)
                    throw new InvalidOperationException("Original pipe security descriptor size differs.");
                byte[] bytes = new byte[length];
                Marshal.Copy(pointer, bytes, 0, bytes.Length);
                RawSecurityDescriptor actual = new RawSecurityDescriptor(bytes, 0);
                RawAcl acl = actual.DiscretionaryAcl;
                RawAcl required = expected.DiscretionaryAcl;
                if (!expected.Owner.Equals(actual.Owner) || (actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                    acl == null || acl.Count != required.Count)
                    throw new InvalidOperationException("Original pipe security differs.");
                for (int index = 0; index < acl.Count; index++)
                {
                    if (!acl[index].Equals(required[index]))
                        throw new InvalidOperationException("Original pipe access rule differs.");
                }
            }
            finally { LocalFree(pointer); }
        }

        public static RestorationCapturePipe Reserve(Guid nonce, RestorationPipeDeadline deadline)
        {
            deadline.RemainingMilliseconds();
            RawSecurityDescriptor security = ExpectedSecurity();
            byte[] bytes = new byte[security.BinaryLength];
            security.GetBinaryForm(bytes, 0);
            GCHandle pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                SecurityAttributes attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = pin.AddrOfPinnedObject()
                };
                SafePipeHandle pipe = CreateNamedPipeW(Name(nonce), Duplex | Overlapped | FirstInstance,
                    RejectRemoteClients, 1, 4096, 4096, 0, ref attributes);
                return Admit(pipe, deadline, true, security);
            }
            finally { pin.Free(); }
        }

        public static RestorationCapturePipe Open(Guid nonce, RestorationPipeDeadline deadline, uint expectedServer)
        {
            deadline.RemainingMilliseconds();
            RawSecurityDescriptor security = ExpectedSecurity();
            SafePipeHandle pipe = CreateFileW(Name(nonce), ClientAccess, 0, IntPtr.Zero, OpenExisting,
                Overlapped | IdentificationQos, IntPtr.Zero);
            RestorationCapturePipe endpoint = Admit(pipe, deadline, false, security);
            try
            {
                endpoint.connected = true;
                endpoint.VerifyPeer(expectedServer);
                return endpoint;
            }
            catch { endpoint.Dispose(); throw; }
        }

        private static RestorationCapturePipe Admit(SafePipeHandle pipe, RestorationPipeDeadline deadline,
            bool server, RawSecurityDescriptor security)
        {
            int error = Marshal.GetLastWin32Error();
            try
            {
                if (pipe.IsInvalid)
                    throw new Win32Exception(error, "The original private pipe could not be opened.");
                VerifySecurity(pipe, security);
                deadline.RemainingMilliseconds();
                return new RestorationCapturePipe(pipe, deadline, server);
            }
            catch { pipe.Dispose(); throw; }
        }

        private void RequireOwner()
        {
            if (Thread.CurrentThread != owner)
                throw new InvalidOperationException("The original pipe thread changed.");
        }

        private void RequireUsable(bool requireConnection)
        {
            RequireOwner();
            if (failed || ended || handle.IsClosed || pending != null || connected != requireConnection)
                throw new InvalidOperationException("The original pipe phase is unavailable.");
        }

        public void Connect(uint expectedClient)
        {
            RequireUsable(false);
            if (!server)
                throw new InvalidOperationException("Only the original pipe server can accept a peer.");
            try
            {
                Run(0, null, true, false);
                connected = true;
                VerifyPeer(expectedClient);
            }
            catch { failed = true; throw; }
        }

        public void VerifyPeer(uint expectedProcess)
        {
            RequireUsable(true);
            try
            {
                deadline.RemainingMilliseconds();
                uint actual;
                bool success = server ? GetNamedPipeClientProcessId(handle, out actual) :
                    GetNamedPipeServerProcessId(handle, out actual);
                if (!success || actual == 0 || actual != expectedProcess)
                    throw new InvalidOperationException("The original pipe peer PID differs.");
                deadline.RemainingMilliseconds();
            }
            catch { failed = true; throw; }
        }

        public void Write(byte[] bytes)
        {
            RequireUsable(true);
            if (bytes == null || bytes.Length < 1 || bytes.Length > MaximumBytes)
                throw new ArgumentException("The original pipe write length is outside its bound.");
            Run(bytes.Length, bytes, false, false);
        }

        public byte[] Read(int maximum)
        {
            RequireUsable(true);
            if (maximum < 1 || maximum > MaximumBytes)
                throw new ArgumentException("The original pipe read length is outside its bound.");
            return Run(maximum, null, false, false);
        }

        public void RequirePeerClosure()
        {
            RequireUsable(true);
            Run(1, null, false, true);
            ended = true;
        }

        private byte[] Run(int length, byte[] output, bool connect, bool expectClosure)
        {
            Operation operation = null;
            try
            {
                deadline.RemainingMilliseconds();
                operation = new Operation(length);
                if (output != null)
                    Marshal.Copy(output, 0, operation.Buffer, output.Length);
                bool submitted = connect ? ConnectNamedPipe(handle, operation.Data) : output == null ?
                    ReadFile(handle, operation.Buffer, (uint)length, IntPtr.Zero, operation.Data) :
                    WriteFile(handle, operation.Buffer, (uint)length, IntPtr.Zero, operation.Data);
                int error = submitted ? 0 : Marshal.GetLastWin32Error();
                uint count = 0;
                if (error == IoPending)
                {
                    pending = operation;
                    while (!operation.Event.WaitOne(deadline.RemainingMilliseconds())) { }
                    error = Collect(operation, out count);
                    if (!IsTerminalCompletion(error))
                        throw new InvalidOperationException("Original pipe completion is uncertain.");
                    pending = null;
                }
                else if (submitted)
                {
                    error = Collect(operation, out count);
                    if (!IsTerminalCompletion(error))
                    {
                        pending = operation;
                        throw new InvalidOperationException("Original pipe completion is uncertain.");
                    }
                }
                deadline.RemainingMilliseconds();
                if ((connect && (error == 0 || error == AlreadyConnected)) || (expectClosure && error == BrokenPipe))
                    return Array.Empty<byte>();
                if (error != 0)
                    throw new Win32Exception(error, "Original private pipe operation failed.");
                if (expectClosure || count == 0 || count > length || (output != null && count != length))
                    throw new InvalidOperationException("Original pipe transfer or peer closure differs.");
                if (output != null)
                    return Array.Empty<byte>();
                byte[] bytes = new byte[count];
                Marshal.Copy(operation.Buffer, bytes, 0, bytes.Length);
                return bytes;
            }
            catch
            {
                failed = true;
                if (pending != null)
                    DrainPending();
                throw;
            }
            finally
            {
                if (operation != null && pending != operation)
                    operation.Dispose();
            }
        }

        private int Collect(Operation operation, out uint count)
        {
            return GetOverlappedResult(handle, operation.Data, out count, false) ? 0 : Marshal.GetLastWin32Error();
        }

        private static bool IsTerminalCompletion(int error)
        {
            return error == 0 || error == OperationAborted || error == BrokenPipe ||
                error == NoData || error == PipeNotConnected;
        }

        private void DrainPending()
        {
            Operation operation = pending;
            bool requested = CancelIoEx(handle, operation.Data);
            int error = requested ? 0 : Marshal.GetLastWin32Error();
            if ((requested || error == OperationNotFound) && operation.Event.WaitOne(2000) &&
                IsTerminalCompletion(Collect(operation, out _)))
            {
                pending = null;
                return;
            }
            lock (Unresolved) { Unresolved.Add(this); }
            throw new InvalidOperationException("Original pipe cancellation remains unresolved.");
        }

        public void Dispose()
        {
            RequireOwner();
            if (pending != null)
                throw new InvalidOperationException("Original pipe resources remain retained for an unresolved operation.");
            ended = true;
            handle.Dispose();
        }
    }
}
'@
}

Export-ModuleMember -Function @()
