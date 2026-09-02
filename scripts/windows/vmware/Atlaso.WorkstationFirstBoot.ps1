<#
.SYNOPSIS
Build and install Atlaso VMware Workstation first-boot metadata.

.DESCRIPTION
Provides the shared raw-VMX first-boot contract used by the normal Workstation
test-VM wrapper and the lifecycle runner. The helper validates deployment inputs,
serializes an OVF environment safely, and writes only the exact guestinfo entry.

The optional development administrator public key is accepted only as one canonical
Ed25519 OpenSSH key. Callers decide whether to include it; lifecycle and export paths
omit it.
#>

<#
.SYNOPSIS
Load the native Windows process-job boundary once per PowerShell process.
#>
function Initialize-AtlasoWorkstationProcessJobType {
    if (-not $IsWindows) {
        throw 'Bounded process-tree jobs require Windows.'
    }
    if (-not ('Atlaso.WorkstationProcessJob' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Atlaso
{
    public sealed class WorkstationProcessStreams : IDisposable
    {
        private readonly StreamReader standardOutput;
        private readonly StreamReader standardError;
        private readonly StringBuilder output = new StringBuilder();
        private readonly StringBuilder error = new StringBuilder();
        private readonly object outputLock = new object();
        private readonly object errorLock = new object();
        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private readonly Task outputTask;
        private readonly Task errorTask;

        public WorkstationProcessStreams(Process process)
        {
            standardOutput = process.StandardOutput;
            standardError = process.StandardError;
            outputTask = CopyAsync(standardOutput, output, outputLock, cancellation.Token);
            errorTask = CopyAsync(standardError, error, errorLock, cancellation.Token);
        }

        private static async Task CopyAsync(
            StreamReader reader,
            StringBuilder destination,
            object syncRoot,
            CancellationToken cancellationToken)
        {
            char[] buffer = new char[4096];
            try
            {
                while (true)
                {
                    int count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                    if (count == 0)
                    {
                        return;
                    }
                    lock (syncRoot)
                    {
                        destination.Append(buffer, 0, count);
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                // The bounded caller closes a descendant-held stream after its
                // drain deadline. Bytes copied before closure remain available.
            }
            catch (IOException)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                // Closing the Windows pipe can surface as an I/O failure on the
                // asynchronous reader; already copied diagnostics remain valid.
            }
            catch (OperationCanceledException)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                // A descendant-held pipe reached its explicit drain deadline.
            }
        }

        public bool WaitForCompletion(int timeoutMilliseconds)
        {
            return Task.WaitAll(new[] { outputTask, errorTask }, timeoutMilliseconds);
        }

        public void CloseAndWait(int timeoutMilliseconds)
        {
            cancellation.Cancel();
            standardOutput.Dispose();
            standardError.Dispose();
            if (!Task.WaitAll(new[] { outputTask, errorTask }, timeoutMilliseconds))
            {
                throw new TimeoutException("Redirected process streams remained active after closure.");
            }
        }

        public string GetOutput()
        {
            lock (outputLock)
            {
                return output.ToString();
            }
        }

        public string GetError()
        {
            lock (errorLock)
            {
                return error.ToString();
            }
        }

        public void Dispose()
        {
            cancellation.Cancel();
            standardOutput.Dispose();
            standardError.Dispose();
            cancellation.Dispose();
            GC.SuppressFinalize(this);
        }
    }

    public sealed class WorkstationProcessJob : IDisposable
    {
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const uint JOB_OBJECT_QUERY = 0x0004;
        private const uint JOB_OBJECT_TERMINATE = 0x0008;
        private IntPtr handle;
        private IntPtr suspendedProcessHandle;
        private IntPtr suspendedThreadHandle;

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation
        {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicAccountingInformation
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInformation
        {
            public uint Size;
            public string Reserved;
            public string Desktop;
            public string Title;
            public uint X;
            public uint Y;
            public uint XSize;
            public uint YSize;
            public uint XCountChars;
            public uint YCountChars;
            public uint FillAttribute;
            public uint Flags;
            public ushort ShowWindow;
            public ushort Reserved2;
            public IntPtr Reserved2Pointer;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr Process;
            public IntPtr Thread;
            public uint ProcessId;
            public uint ThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenJobObject(uint desiredAccess, bool inheritHandle, string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcess(
            string applicationName,
            System.Text.StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInformation startupInformation,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            ref ExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            int informationClass,
            out BasicAccountingInformation information,
            uint informationLength,
            IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public Process RootProcess { get; private set; }

        private WorkstationProcessJob(
            IntPtr jobHandle,
            Process rootProcess,
            IntPtr processHandle,
            IntPtr threadHandle)
        {
            handle = jobHandle;
            RootProcess = rootProcess;
            suspendedProcessHandle = processHandle;
            suspendedThreadHandle = threadHandle;
        }

        private static string QuoteArgument(string value)
        {
            if (value.Length != 0 && value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '\r', '"' }) < 0)
            {
                return value;
            }
            System.Text.StringBuilder quoted = new System.Text.StringBuilder();
            quoted.Append('"');
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1);
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                quoted.Append('\\', backslashes);
                backslashes = 0;
                quoted.Append(character);
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        public static WorkstationProcessJob StartSuspended(string filePath, string[] arguments)
        {
            WorkstationProcessJob job = CreateSuspended(filePath, arguments, null);
            try
            {
                job.Resume();
                return job;
            }
            catch
            {
                job.Dispose();
                throw;
            }
        }

        public static WorkstationProcessJob CreateSuspended(
            string filePath,
            string[] arguments,
            string name)
        {
            const uint CREATE_SUSPENDED = 0x00000004;
            IntPtr job = CreateJobObject(IntPtr.Zero, name);
            if (job == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows process job creation failed.");
            }
            ProcessInformation processInformation = new ProcessInformation();
            try
            {
                ExtendedLimitInformation limits = new ExtendedLimitInformation();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows process job limits could not be established.");
                }
                System.Text.StringBuilder commandLine = new System.Text.StringBuilder(QuoteArgument(filePath));
                foreach (string argument in arguments)
                {
                    commandLine.Append(' ');
                    commandLine.Append(QuoteArgument(argument));
                }
                StartupInformation startup = new StartupInformation();
                startup.Size = (uint)Marshal.SizeOf(typeof(StartupInformation));
                if (!CreateProcess(
                    filePath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_SUSPENDED,
                    IntPtr.Zero,
                    null,
                    ref startup,
                    out processInformation))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "The bounded process could not be created suspended.");
                }
                if (!AssignProcessToJobObject(job, processInformation.Process))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "The bounded process could not be assigned to its Windows job.");
                }
                Process rootProcess = Process.GetProcessById((int)processInformation.ProcessId);
                IntPtr managedProcessHandle = rootProcess.Handle;
                WorkstationProcessJob result = new WorkstationProcessJob(
                    job,
                    rootProcess,
                    processInformation.Process,
                    processInformation.Thread);
                processInformation.Process = IntPtr.Zero;
                processInformation.Thread = IntPtr.Zero;
                return result;
            }
            catch
            {
                if (processInformation.Process != IntPtr.Zero)
                {
                    TerminateProcess(processInformation.Process, 1);
                    WaitForSingleObject(processInformation.Process, 10000);
                    CloseHandle(processInformation.Process);
                }
                if (processInformation.Thread != IntPtr.Zero)
                {
                    CloseHandle(processInformation.Thread);
                }
                CloseHandle(job);
                throw;
            }
        }

        public static WorkstationProcessJob OpenExisting(string name)
        {
            IntPtr job = OpenJobObject(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE, false, name);
            if (job == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 2)
                {
                    return null;
                }
                throw new Win32Exception(error, "The recorded Windows process job could not be opened.");
            }
            return new WorkstationProcessJob(job, null, IntPtr.Zero, IntPtr.Zero);
        }

        public void Resume()
        {
            if (suspendedThreadHandle == IntPtr.Zero || suspendedProcessHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException("The bounded process is not suspended by this owner.");
            }
            if (ResumeThread(suspendedThreadHandle) == UInt32.MaxValue)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "The bounded process could not be resumed after job assignment.");
            }
            CloseHandle(suspendedThreadHandle);
            suspendedThreadHandle = IntPtr.Zero;
            CloseHandle(suspendedProcessHandle);
            suspendedProcessHandle = IntPtr.Zero;
        }

        public bool ContainsProcess(Process process)
        {
            bool result;
            if (!IsProcessInJob(process.Handle, handle, out result))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Recorded process-job membership could not be verified.");
            }
            return result;
        }

        public static Process StartBreakaway(string filePath, string[] arguments)
        {
            const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
            ProcessInformation processInformation = new ProcessInformation();
            try
            {
                System.Text.StringBuilder commandLine = new System.Text.StringBuilder(QuoteArgument(filePath));
                foreach (string argument in arguments)
                {
                    commandLine.Append(' ');
                    commandLine.Append(QuoteArgument(argument));
                }
                StartupInformation startup = new StartupInformation();
                startup.Size = (uint)Marshal.SizeOf(typeof(StartupInformation));
                if (!CreateProcess(
                    filePath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_BREAKAWAY_FROM_JOB,
                    IntPtr.Zero,
                    null,
                    ref startup,
                    out processInformation))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "The verified breakaway process could not be created.");
                }
                Process process = Process.GetProcessById((int)processInformation.ProcessId);
                IntPtr managedProcessHandle = process.Handle;
                CloseHandle(processInformation.Thread);
                processInformation.Thread = IntPtr.Zero;
                CloseHandle(processInformation.Process);
                processInformation.Process = IntPtr.Zero;
                return process;
            }
            catch
            {
                if (processInformation.Process != IntPtr.Zero)
                {
                    TerminateProcess(processInformation.Process, 1);
                    WaitForSingleObject(processInformation.Process, 10000);
                    CloseHandle(processInformation.Process);
                }
                if (processInformation.Thread != IntPtr.Zero)
                {
                    CloseHandle(processInformation.Thread);
                }
                throw;
            }
        }

        public void TerminateAndWait(int timeoutMilliseconds)
        {
            if (!TerminateJobObject(handle, 1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows process-job termination failed.");
            }
            Stopwatch deadline = Stopwatch.StartNew();
            while (deadline.ElapsedMilliseconds <= timeoutMilliseconds)
            {
                BasicAccountingInformation accounting;
                if (!QueryInformationJobObject(
                    handle,
                    1,
                    out accounting,
                    (uint)Marshal.SizeOf(typeof(BasicAccountingInformation)),
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows process-job accounting failed.");
                }
                if (accounting.ActiveProcesses == 0)
                {
                    return;
                }
                System.Threading.Thread.Sleep(50);
            }
            throw new TimeoutException("A process-job descendant remained active after termination.");
        }

        public void CompleteAndWait(int timeoutMilliseconds)
        {
            BasicAccountingInformation accounting;
            if (!QueryInformationJobObject(
                handle,
                1,
                out accounting,
                (uint)Marshal.SizeOf(typeof(BasicAccountingInformation)),
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows process-job accounting failed.");
            }
            if (accounting.ActiveProcesses != 0)
            {
                TerminateAndWait(timeoutMilliseconds);
            }
        }

        public void Dispose()
        {
            if (suspendedThreadHandle != IntPtr.Zero)
            {
                CloseHandle(suspendedThreadHandle);
                suspendedThreadHandle = IntPtr.Zero;
            }
            if (suspendedProcessHandle != IntPtr.Zero)
            {
                CloseHandle(suspendedProcessHandle);
                suspendedProcessHandle = IntPtr.Zero;
            }
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
                handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
    }
}
'@
    }
}

<#
.SYNOPSIS
Create a suspended process, assign its Windows job, and only then resume it.

.PARAMETER FilePath
Exact executable to start without shell interpretation.

.PARAMETER ArgumentList
Individual process arguments encoded through the Windows argv contract.
.PARAMETER ProcessJobName
Optional exact named job used by durable same-boot recovery.
.PARAMETER DeferResume
Return the root suspended so its ownership can be durably published first.
#>
function New-AtlasoBoundedProcessJob {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$ArgumentList,
        [string]$ProcessJobName = '',
        [switch]$DeferResume
    )

    Initialize-AtlasoWorkstationProcessJobType
    try {
        if ($DeferResume) {
            if ([string]::IsNullOrWhiteSpace($ProcessJobName)) {
                throw 'A deferred bounded process requires an exact process-job name.'
            }
            return [Atlaso.WorkstationProcessJob]::CreateSuspended(
                $FilePath,
                $ArgumentList,
                $ProcessJobName
            )
        }
        return [Atlaso.WorkstationProcessJob]::StartSuspended($FilePath, $ArgumentList)
    }
    catch {
        $assignmentFailure = [System.InvalidOperationException]::new(
            'The bounded process could not establish whole-process-tree ownership.',
            $_.Exception
        )
        $assignmentFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
        throw $assignmentFailure
    }
}

<#
.SYNOPSIS
Open an exact named Windows process job for recovery.
.PARAMETER ProcessJobName
Durably recorded non-secret job name owned by one bounded invocation.
#>
function Open-AtlasoBoundedProcessJob {
    param(
        [Parameter(Mandatory = $true)][string]$ProcessJobName
    )

    Initialize-AtlasoWorkstationProcessJobType
    return [Atlaso.WorkstationProcessJob]::OpenExisting($ProcessJobName)
}

<#
.SYNOPSIS
Classify one durably recorded Windows process identity.

.PARAMETER ProcessId
Positive process identifier read from a durable ownership marker.

.PARAMETER StartFileTimeUtc
Invariant Windows file time captured before the owned process was resumed.
#>
function Get-AtlasoRecordedProcessIdentityState {
    param(
        [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ProcessId,
        [Parameter(Mandatory = $true)][ValidateRange(1, [long]::MaxValue)][long]$StartFileTimeUtc
    )

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return 'absent'
    }
    try {
        $actualStart = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
    }
    catch {
        throw 'Recorded process start identity could not be read.'
    }
    if ($actualStart -ne $StartFileTimeUtc) {
        return 'reused'
    }
    return 'matching'
}

<#
.SYNOPSIS
Recover one exactly recorded bounded process tree on the current boot.

.PARAMETER Marker
Validated durable marker containing controller, job, child, and phase ownership.

.PARAMETER JobNamePattern
Anchored regular expression admitting only the caller's named-job namespace.

.PARAMETER ProcessDescription
Sanitized workflow description used in fail-closed diagnostics.
#>
function Complete-AtlasoSameBootBoundedProcessRecovery {
    param(
        [Parameter(Mandatory = $true)][object]$Marker,
        [Parameter(Mandatory = $true)][string]$JobNamePattern,
        [Parameter(Mandatory = $true)][string]$ProcessDescription
    )

    $ownerState = Get-AtlasoRecordedProcessIdentityState `
        -ProcessId ([int]$Marker.OwnerProcessId) `
        -StartFileTimeUtc ([long]$Marker.OwnerProcessStartFileTimeUtc)
    if ($ownerState -ne 'absent') {
        throw "The prior $ProcessDescription controller is active or its process identifier was reused."
    }
    $jobName = [string]$Marker.ProcessJobName
    if ($jobName -notmatch $JobNamePattern) {
        throw "Recorded $ProcessDescription process-job identity is invalid."
    }
    $ownershipPhase = [string]$Marker.ProcessOwnershipPhase
    if ($ownershipPhase -notin @('prepared', 'assigned')) {
        throw "Recorded $ProcessDescription process ownership phase is invalid."
    }
    $childState = 'absent'
    if ($ownershipPhase -ceq 'assigned') {
        $childState = Get-AtlasoRecordedProcessIdentityState `
            -ProcessId ([int]$Marker.ChildProcessId) `
            -StartFileTimeUtc ([long]$Marker.ChildProcessStartFileTimeUtc)
    }
    $job = $null
    $childProcess = $null
    try {
        $job = Open-AtlasoBoundedProcessJob -ProcessJobName $jobName
        if ($null -ne $job) {
            if ($ownershipPhase -cne 'assigned' -or $childState -cne 'matching') {
                throw "The retained $ProcessDescription process job cannot be bound to its exact recorded child ($ownershipPhase/$childState)."
            }
            $childProcess = Get-Process -Id ([int]$Marker.ChildProcessId) -ErrorAction Stop
            if (-not $job.ContainsProcess($childProcess)) {
                throw "The recorded $ProcessDescription child is not owned by the retained process job."
            }
            $job.TerminateAndWait(10000)
            if (-not $childProcess.WaitForExit(10000)) {
                throw "The recorded $ProcessDescription child remained active after process-job termination."
            }
        }
        elseif ($ownershipPhase -ceq 'assigned' -and $childState -ne 'absent') {
            throw "The recorded $ProcessDescription child remains present without its exact process job."
        }
    }
    finally {
        if ($null -ne $childProcess) {
            $childProcess.Dispose()
        }
        if ($null -ne $job) {
            $job.Dispose()
        }
    }
    if ($ownershipPhase -ceq 'assigned' -and (
            (Get-AtlasoRecordedProcessIdentityState `
                -ProcessId ([int]$Marker.ChildProcessId) `
                -StartFileTimeUtc ([long]$Marker.ChildProcessStartFileTimeUtc)) -ne 'absent'
        )) {
        throw "$ProcessDescription child termination could not be proven after recovery."
    }
    if ((Get-AtlasoRecordedProcessIdentityState `
            -ProcessId ([int]$Marker.OwnerProcessId) `
            -StartFileTimeUtc ([long]$Marker.OwnerProcessStartFileTimeUtc)) -ne 'absent') {
        throw "$ProcessDescription controller identity changed during same-boot recovery."
    }
}

<#
.SYNOPSIS
Terminate a bounded process tree and prove every captured descendant exited.

.PARAMETER Process
Started root process whose descendants must be terminated.

.PARAMETER Job
Owned Windows job tracking the root and every descendant.

.PARAMETER TimeoutSeconds
Configured deadline included in sanitized failure messages.

.PARAMETER Action
Safe action description used in the sanitized timeout failure.
#>
function Stop-AtlasoBoundedProcessTree {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][object]$Job,
        [Parameter(Mandatory = $true)][ValidateRange(1, 86400)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Action
    )

    try {
        # Job accounting is the authoritative descendant set. Immediate-child
        # exit alone does not prove that Packer or plugin consumers are inactive.
        $Job.TerminateAndWait(10000)
        if (-not $Process.WaitForExit(10000)) {
            throw 'The bounded root remained active after process-job termination.'
        }
    }
    catch {
        $terminationFailure = [System.TimeoutException]::new(
            "$Action exceeded its $TimeoutSeconds-second deadline and whole-process-tree cleanup could not be proven.",
            $_.Exception
        )
        $terminationFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
        throw $terminationFailure
    }
    $deadlineFailure = [System.TimeoutException]::new(
        "$Action exceeded its $TimeoutSeconds-second deadline after proven whole-process-tree termination."
    )
    $deadlineFailure.Data['AtlasoProcessTreeTerminationProven'] = $true
    throw $deadlineFailure
}

<#
.SYNOPSIS
Prove a normally exited bounded root has no remaining job descendants.

.PARAMETER Process
Exited root process whose job must be empty.

.PARAMETER Job
Owned Windows job tracking the root and every descendant.

.PARAMETER Action
Safe action description used in sanitized failure messages.
#>
function Complete-AtlasoBoundedProcessTree {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][object]$Job,
        [Parameter(Mandatory = $true)][string]$Action
    )

    try {
        if (-not $Process.HasExited) {
            throw 'The bounded root had not exited before completion proof.'
        }
        $Job.CompleteAndWait(10000)
    }
    catch {
        $completionFailure = [System.InvalidOperationException]::new(
            "$Action exited but whole-process-tree cleanup could not be proven.",
            $_.Exception
        )
        $completionFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
        throw $completionFailure
    }
}

<#
.SYNOPSIS
Run one external process with a deadline and whole-tree termination.

.PARAMETER FilePath
Exact executable to start without shell interpretation.

.PARAMETER ArgumentList
Individual process arguments added without command-line interpolation.

.PARAMETER TimeoutSeconds
Positive deadline for the external process.

.PARAMETER Action
Safe action description used in failure messages.

#>
function Invoke-AtlasoBoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][ValidateRange(1, 86400)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Action
    )

    Initialize-AtlasoWorkstationProcessJobType
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $streams = $null
    try {
        if (-not $process.Start()) {
            throw "$Action could not be started."
        }
        # Drain both streams concurrently and retain each copied chunk. A
        # descendant-held writer can then be closed at a bounded deadline
        # without discarding diagnostics that already reached this process.
        $streams = [Atlaso.WorkstationProcessStreams]::new($process)
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                $process.Kill($true)
                if (-not $process.WaitForExit(10000)) {
                    throw 'The process remained active after whole-tree termination.'
                }
            }
            catch {
                $terminationFailure = [System.TimeoutException]::new(
                    "$Action exceeded its $TimeoutSeconds-second deadline and whole-process-tree cleanup could not be proven.",
                    $_.Exception
                )
                $terminationFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
                throw $terminationFailure
            }
            throw "$Action exceeded its $TimeoutSeconds-second deadline."
        }
        $streamTimeoutMilliseconds = [Math]::Min($TimeoutSeconds * 1000, 10000)
        if (-not $streams.WaitForCompletion($streamTimeoutMilliseconds)) {
            try {
                $streams.CloseAndWait($streamTimeoutMilliseconds)
            }
            catch {
                $streamFailure = [System.InvalidOperationException]::new(
                    "$Action exited but redirected-stream completion could not be proven.",
                    $_.Exception
                )
                $streamFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
                throw $streamFailure
            }
            $streamFailure = [System.InvalidOperationException]::new(
                "$Action exited but a descendant retained redirected output handles."
            )
            $streamFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
            throw $streamFailure
        }
        $output = $streams.GetOutput()
        $null = $streams.GetError()
        if ($process.ExitCode -ne 0) {
            throw "$Action failed with exit code $($process.ExitCode)."
        }
        return $output
    }
    finally {
        if ($streams) {
            $streams.Dispose()
        }
        $process.Dispose()
    }
}

<#
.SYNOPSIS
Run one external process with live inherited diagnostics and a deadline.

.PARAMETER FilePath
Exact executable to start without shell interpretation.

.PARAMETER ArgumentList
Individual process arguments added without command-line interpolation.

.PARAMETER TimeoutSeconds
Positive deadline for the external process.

.PARAMETER Action
Safe action description used in failure messages.
.PARAMETER ProcessJobName
Optional exact named job used by durable same-boot recovery.
.PARAMETER ProcessOwnershipPublisher
Callback that durably records the suspended root before it is resumed.
#>
function Invoke-AtlasoBoundedStreamingProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][ValidateRange(1, 86400)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Action,
        [string]$ProcessJobName = '',
        [scriptblock]$ProcessOwnershipPublisher
    )

    # The isolated image child owns redaction. Inheriting the console preserves
    # its sanitized Packer heartbeats and diagnostics without copying plaintext
    # credentials or buffered output into the PowerShell parent.
    $recoverable = $null -ne $ProcessOwnershipPublisher
    $processJob = New-AtlasoBoundedProcessJob `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -ProcessJobName $ProcessJobName `
        -DeferResume:$recoverable
    $process = $processJob.RootProcess
    $jobCompletionProven = $false
    $interruptionTerminationProven = $false
    $pendingFailure = $null
    try {
        if ($recoverable) {
            & $ProcessOwnershipPublisher $processJob
            $processJob.Resume()
        }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                Stop-AtlasoBoundedProcessTree `
                    -Process $process `
                    -Job $processJob `
                    -TimeoutSeconds $TimeoutSeconds `
                    -Action $Action
            }
            catch {
                if ($_.Exception.Data['AtlasoProcessTreeTerminationProven']) {
                    $jobCompletionProven = $true
                }
                throw
            }
        }
        Complete-AtlasoBoundedProcessTree `
            -Process $process `
            -Job $processJob `
            -Action $Action
        $jobCompletionProven = $true
        if ($process.ExitCode -ne 0) {
            $processFailure = [System.InvalidOperationException]::new(
                "$Action failed with exit code $($process.ExitCode) after proven whole-process-tree termination."
            )
            $processFailure.Data['AtlasoProcessTreeTerminationProven'] = $true
            $processFailure.Data['AtlasoProcessExitCode'] = $process.ExitCode
            throw $processFailure
        }
    }
    catch {
        # Retain the initiating failure across the mandatory job cleanup below.
        # Without this inner exception, a publication or resume failure is
        # indistinguishable from an operator interruption during diagnosis.
        $pendingFailure = $_.Exception
        throw
    }
    finally {
        try {
            if (-not $jobCompletionProven) {
                # Ctrl+C and other pipeline interruptions can bypass the normal
                # timeout/completion branches. Prove the job empty before its
                # kill-on-close handle is released and sensitive cleanup resumes.
                $processJob.TerminateAndWait(10000)
                if (-not $process.WaitForExit(10000)) {
                    throw 'The bounded root remained active after interruption cleanup.'
                }
                $jobCompletionProven = $true
                $interruptionTerminationProven = $true
            }
        }
        catch {
            $interruptionFailure = [System.InvalidOperationException]::new(
                "$Action was interrupted and whole-process-tree cleanup could not be proven.",
                $_.Exception
            )
            $interruptionFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
            throw $interruptionFailure
        }
        finally {
            $processJob.Dispose()
            $process.Dispose()
        }
        if ($interruptionTerminationProven) {
            $interruptionFailure = [System.InvalidOperationException]::new(
                "$Action was interrupted after proven whole-process-tree termination.",
                $pendingFailure
            )
            $interruptionFailure.Data['AtlasoProcessTreeTerminationProven'] = $true
            throw $interruptionFailure
        }
    }
}

<#
.SYNOPSIS
Return a stable identity for the current Windows boot.
#>
function Get-AtlasoWindowsBootIdentity {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    return ([DateTimeOffset]$operatingSystem.LastBootUpTime).ToUniversalTime().Ticks.ToString(
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

<#
.SYNOPSIS
Classify a persisted boot identity against the current Windows boot.

.PARAMETER BootIdentity
Value read from a durable cleanup marker, accepted as invariant UTC ticks or a legacy ISO 8601 timestamp.
#>
function Get-AtlasoWindowsBootIdentityState {
    param([Parameter(Mandatory = $true)][object]$BootIdentity)

    $currentIdentity = Get-AtlasoWindowsBootIdentity
    if ([string]$BootIdentity -ceq $currentIdentity) {
        return 'current'
    }
    if ($currentIdentity -notmatch '^[0-9]{1,19}$') {
        # Focused tests replace the provider with stable symbolic boot names.
        return 'prior'
    }
    $legacyTicks = if ($BootIdentity -is [DateTime]) {
        $BootIdentity.ToUniversalTime().Ticks
    }
    elseif ([string]$BootIdentity -match '^[0-9]{1,19}$') {
        $parsedTicks = 0L
        if (-not [long]::TryParse(
                [string]$BootIdentity,
                [System.Globalization.NumberStyles]::None,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref]$parsedTicks
            ) -or $parsedTicks -le 0) {
            return 'invalid'
        }
        $parsedTicks
    }
    else {
        $legacyTimestamp = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                [string]$BootIdentity,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$legacyTimestamp
            )) {
            return 'invalid'
        }
        $legacyTimestamp.ToUniversalTime().Ticks
    }
    if ($legacyTicks -le 0) {
        return 'invalid'
    }
    $currentTicks = [long]::Parse(
        $currentIdentity,
        [System.Globalization.NumberStyles]::None,
        [System.Globalization.CultureInfo]::InvariantCulture
    )
    if ($legacyTicks -eq $currentTicks) {
        return 'current'
    }
    if ($legacyTicks -gt $currentTicks) {
        return 'invalid'
    }
    return 'prior'
}

<#
.SYNOPSIS
Test whether a persisted boot identity describes the current Windows boot.

.PARAMETER BootIdentity
Value read from a durable cleanup marker and classified by the fail-closed boot parser.
#>
function Test-AtlasoWindowsBootIdentityCurrent {
    param([Parameter(Mandatory = $true)][object]$BootIdentity)

    return (Get-AtlasoWindowsBootIdentityState -BootIdentity $BootIdentity) -ceq 'current'
}

<#
.SYNOPSIS
Atomically rename one file with Windows write-through durability.

.PARAMETER SourcePath
Exact flushed temporary file.

.PARAMETER DestinationPath
Exact destination in the same directory.

.PARAMETER Replace
Replace an existing destination during a validated state transition.
#>
function Move-AtlasoDurableFile {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [switch]$Replace
    )

    if (-not $IsWindows) {
        throw 'Durable file replacement requires Windows.'
    }
    $resolvedSourcePath = (Resolve-Path -LiteralPath $SourcePath).Path
    $resolvedDestinationPath = [System.IO.Path]::GetFullPath($DestinationPath)
    if (-not ('Atlaso.WorkstationDurableFile' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

namespace Atlaso
{
    public static class WorkstationDurableFile
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool MoveFileEx(string existingPath, string newPath, uint flags);
    }
}
'@
    }
    [uint32]$flags = 0x00000008
    if ($Replace) {
        $flags = $flags -bor 0x00000001
    }
    if (-not [Atlaso.WorkstationDurableFile]::MoveFileEx(
            $resolvedSourcePath,
            $resolvedDestinationPath,
            $flags
        )) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [System.ComponentModel.Win32Exception]::new(
            $errorCode,
            'Durable write-through file replacement failed.'
        )
    }
    if ((Test-Path -LiteralPath $resolvedSourcePath) -or
        -not (Test-Path -LiteralPath $resolvedDestinationPath -PathType Leaf)) {
        throw 'Durable write-through file replacement could not be proven.'
    }
}

<#
.SYNOPSIS
Flush directory metadata through an exact Windows directory handle.

.PARAMETER DirectoryPath
Existing non-reparse-point directory whose metadata changes must reach its own volume.
#>
function Sync-AtlasoDirectoryMetadata {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)

    if (-not $IsWindows) {
        throw 'Durable directory metadata synchronization requires Windows.'
    }
    $resolvedDirectoryPath = (Resolve-Path -LiteralPath $DirectoryPath).Path
    $directoryItem = Get-Item -LiteralPath $resolvedDirectoryPath -Force -ErrorAction Stop
    if (-not $directoryItem.PSIsContainer -or
        ($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Durable directory metadata synchronization requires a non-reparse-point directory.'
    }
    if (-not ('Atlaso.WorkstationDurableDirectory' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Atlaso
{
    public static class WorkstationDurableDirectory
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string path,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushFileBuffers(SafeFileHandle handle);
    }
}
'@
    }
    # FILE_FLAG_BACKUP_SEMANTICS permits an ordinary directory handle, while
    # WRITE_THROUGH and FlushFileBuffers commit its metadata on this volume.
    [uint32]$directoryFlags = 0x02000000
    $directoryFlags = $directoryFlags -bor [uint32]::Parse(
        '80000000',
        [System.Globalization.NumberStyles]::HexNumber
    )
    $directoryHandle = [Atlaso.WorkstationDurableDirectory]::CreateFileW(
        $resolvedDirectoryPath,
        [uint32]0x40000000,
        [uint32]0x00000007,
        [IntPtr]::Zero,
        [uint32]0x00000003,
        $directoryFlags,
        [IntPtr]::Zero
    )
    try {
        if ($directoryHandle.IsInvalid) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw [System.ComponentModel.Win32Exception]::new(
                $errorCode,
                'Opening the directory for durable metadata synchronization failed.'
            )
        }
        if (-not [Atlaso.WorkstationDurableDirectory]::FlushFileBuffers($directoryHandle)) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw [System.ComponentModel.Win32Exception]::new(
                $errorCode,
                'Durable directory metadata synchronization failed.'
            )
        }
    }
    finally {
        $directoryHandle.Dispose()
    }
}

<#
.SYNOPSIS
Durably publish one non-secret JSON ownership marker.

.PARAMETER Path
Exact marker path.

.PARAMETER Payload
Validated non-secret payload to serialize.

.PARAMETER Replace
Replace an existing marker during a validated state transition.
#>
function Write-AtlasoDurableJsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Payload,
        [switch]$Replace
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $temporaryPath = "$resolvedPath.$([guid]::NewGuid().ToString('N')).tmp"
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Payload | ConvertTo-Json -Depth 4 -Compress)
    )
    try {
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        Move-AtlasoDurableFile `
            -SourcePath $temporaryPath `
            -DestinationPath $resolvedPath `
            -Replace:$Replace
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
Run one vmrun operation through the bounded process boundary.

.PARAMETER VmrunPath
Exact vmrun executable, or a focused-test function seam.

.PARAMETER ArgumentList
Individual vmrun arguments.

.PARAMETER TimeoutSeconds
Positive per-operation deadline.

.PARAMETER Action
Safe action description used in failure messages.
#>
function Invoke-AtlasoBoundedVmrun {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Action
    )

    $command = Get-Command $VmrunPath -ErrorAction SilentlyContinue
    if ($command -and $command.CommandType -eq [System.Management.Automation.CommandTypes]::Function) {
        $output = @(& $VmrunPath @ArgumentList)
        if ($LASTEXITCODE -ne 0) {
            throw "$Action failed."
        }
        return ($output -join [Environment]::NewLine)
    }
    return Invoke-AtlasoBoundedProcess `
        -FilePath $VmrunPath `
        -ArgumentList $ArgumentList `
        -TimeoutSeconds $TimeoutSeconds `
        -Action $Action
}

<#
.SYNOPSIS
Escape one value for an OVF XML attribute.

.PARAMETER Value
The possibly empty value to encode.
#>
function ConvertTo-AtlasoOvfXmlValue {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return [System.Security.SecurityElement]::Escape($Value)
}

<#
.SYNOPSIS
Quote one string for a VMX assignment.

.PARAMETER Value
Unquoted VMX property text to escape and surround with quotes.
#>
function ConvertTo-AtlasoVmxString {
    param([string]$Value)

    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

<#
.SYNOPSIS
Validate and normalize one OpenSSH Ed25519 public key.

.DESCRIPTION
Checks the bounded single-line text form, canonical base64, embedded SSH algorithm,
and exact 32-byte Ed25519 public-key payload. The private key is never accessed.

.PARAMETER PublicKey
The OpenSSH public-key line to validate.
#>
function Assert-AtlasoWorkstationEd25519PublicKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PublicKey
    )

    $key = $PublicKey
    # Public-key files conventionally end with one newline. Remove only that final
    # terminator so an embedded or repeated newline still fails closed below.
    if ($key.EndsWith("`r`n", [System.StringComparison]::Ordinal)) {
        $key = $key.Substring(0, $key.Length - 2)
    }
    elseif ($key.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $key = $key.Substring(0, $key.Length - 1)
    }
    $key = $key.Trim('"')
    if (
        [string]::IsNullOrWhiteSpace($key) -or
        $key.Length -gt 4096 -or
        $key -ne $key.Trim() -or
        $key -match '[\x00-\x1F\x7F]'
    ) {
        throw 'The SSH public key must be one bounded, non-empty OpenSSH line without surrounding whitespace or control characters.'
    }

    $parts = @($key -split ' +', 3)
    if ($parts.Count -lt 2 -or $parts[0] -ne 'ssh-ed25519') {
        throw 'The SSH public key must use the ssh-ed25519 algorithm.'
    }
    try {
        $blob = [System.Convert]::FromBase64String($parts[1])
    }
    catch {
        throw 'The SSH public key payload is not valid base64.'
    }
    if ([System.Convert]::ToBase64String($blob) -ne $parts[1] -or $blob.Length -ne 51) {
        throw 'The SSH public key payload is not a canonical Ed25519 OpenSSH key.'
    }

    <#
    .SYNOPSIS
    Read one big-endian length from an SSH wire-format blob.

    .PARAMETER Bytes
    The complete decoded SSH public-key blob.

    .PARAMETER Offset
    The zero-based position of the four-byte length.
    #>
    function Read-AtlasoSshBlobLength {
        param(
            [Parameter(Mandatory = $true)][byte[]]$Bytes,
            [Parameter(Mandatory = $true)][int]$Offset
        )

        if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
            throw 'The SSH public key payload is truncated.'
        }
        return [int](
            ([uint64]$Bytes[$Offset] * 16777216) +
            ([uint64]$Bytes[$Offset + 1] * 65536) +
            ([uint64]$Bytes[$Offset + 2] * 256) +
            [uint64]$Bytes[$Offset + 3]
        )
    }

    # Decode the wire format as well as the visible prefix so a mislabeled base64
    # payload cannot gain test-VM authorization.
    $algorithmLength = Read-AtlasoSshBlobLength -Bytes $blob -Offset 0
    if ($algorithmLength -ne 11 -or 4 + $algorithmLength + 4 -gt $blob.Length) {
        throw 'The SSH public key payload does not contain an Ed25519 algorithm identifier.'
    }
    $algorithm = [System.Text.Encoding]::ASCII.GetString($blob, 4, $algorithmLength)
    $publicKeyLengthOffset = 4 + $algorithmLength
    $publicKeyLength = Read-AtlasoSshBlobLength -Bytes $blob -Offset $publicKeyLengthOffset
    if (
        $algorithm -ne 'ssh-ed25519' -or
        $publicKeyLength -ne 32 -or
        $publicKeyLengthOffset + 4 + $publicKeyLength -ne $blob.Length
    ) {
        throw 'The SSH public key payload does not contain one complete Ed25519 public key.'
    }

    $normalized = "ssh-ed25519 $($parts[1])"
    if ($parts.Count -eq 3 -and $parts[2]) {
        $normalized += " $($parts[2])"
    }
    try {
        [void][System.Xml.XmlConvert]::VerifyXmlChars($normalized)
    }
    catch {
        throw 'The SSH public key contains characters that cannot be represented in the OVF environment.'
    }
    return $normalized
}

<#
.SYNOPSIS
Resolve the existing host public key used by the normal Workstation test VM.

.DESCRIPTION
Uses an explicit path when supplied; otherwise selects the current Windows user's
.ssh/id_ed25519.pub. This function validates only an existing public key and never
generates, reads, or copies a private key.

.PARAMETER Path
Optional path to an existing Ed25519 OpenSSH public-key file.
#>
function Resolve-AtlasoWorkstationAdminSshPublicKey {
    param([string]$Path = '')

    $resolvedPath = $Path
    if (-not $resolvedPath) {
        $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if ([string]::IsNullOrWhiteSpace($userProfile)) {
            throw 'The current Windows user profile could not be resolved. Pass -SshPublicKeyPath or -SkipSshKeyProvisioning.'
        }
        # A deterministic file default lets every local coding task under the same
        # Windows user share the identity without agent-key ambiguity.
        $resolvedPath = Join-Path $userProfile '.ssh\id_ed25519.pub'
    }
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw "SSH public key not found: $resolvedPath. Create the existing key outside this script, pass -SshPublicKeyPath, or pass -SkipSshKeyProvisioning."
    }
    $fullPath = (Resolve-Path -LiteralPath $resolvedPath).Path
    $publicKey = Assert-AtlasoWorkstationEd25519PublicKey -PublicKey ([System.IO.File]::ReadAllText($fullPath))
    return [pscustomobject]@{
        Path      = $fullPath
        PublicKey = $publicKey
    }
}

<#
.SYNOPSIS
Normalize and fingerprint one verified Ed25519 SSH host public key.

.PARAMETER PublicKey
The host-derived OpenSSH public-key line.
#>
function ConvertTo-AtlasoWorkstationSshHostKeyEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKey
    )

    $normalized = Assert-AtlasoWorkstationEd25519PublicKey -PublicKey $PublicKey
    $parts = @($normalized -split ' +', 3)
    $hostPublicKey = "ssh-ed25519 $($parts[1])"
    $blob = [System.Convert]::FromBase64String($parts[1])
    $digest = [System.Security.Cryptography.SHA256]::HashData($blob)
    $fingerprint = 'SHA256:' + [System.Convert]::ToBase64String($digest).TrimEnd('=')
    return [pscustomobject]@{
        PublicKey   = $hostPublicKey
        Fingerprint = $fingerprint
    }
}

<#
.SYNOPSIS
Read and fingerprint the normal test VM's verified Ed25519 SSH host key.

.DESCRIPTION
Polls the test-only VMware runtime guest-info value written during first boot.
The value comes through the host-controlled VM channel rather than an
unauthenticated network scan.

.PARAMETER VmxPath
The exact running test VMX path.

.PARAMETER VmrunPath
Optional VMware vmrun executable override.

.PARAMETER TimeoutSeconds
The total time allowed for first boot to publish the host key.

.PARAMETER PollSeconds
The delay between empty guest-info reads.
#>
function Get-AtlasoWorkstationSshHostKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [string]$VmrunPath = '',
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $resolvedVmrunPath = $VmrunPath
    if ($resolvedVmrunPath) {
        if (-not (Test-Path -LiteralPath $resolvedVmrunPath -PathType Leaf)) {
            throw "vmrun.exe not found: $resolvedVmrunPath"
        }
        $resolvedVmrunPath = (Resolve-Path -LiteralPath $resolvedVmrunPath).Path
    }
    else {
        $vmrunCommand = Get-Command vmrun -ErrorAction SilentlyContinue
        foreach ($candidate in @(
                'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
                'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
            )) {
            if (-not $resolvedVmrunPath -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $resolvedVmrunPath = $candidate
            }
        }
        if (-not $resolvedVmrunPath -and $vmrunCommand) {
            $resolvedVmrunPath = $vmrunCommand.Source
        }
        if (-not $resolvedVmrunPath) {
            throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
        }
    }

    $guestInfoName = 'guestinfo.atlaso.test_vm_ssh_host_ed25519_public_key'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        $value = Invoke-AtlasoBoundedVmrun `
            -VmrunPath $resolvedVmrunPath `
            -ArgumentList @('-T', 'ws', 'readVariable', $resolvedVmxPath, 'runtimeConfig', $guestInfoName) `
            -TimeoutSeconds $remainingSeconds `
            -Action 'Read the normal test VM SSH host key guest-info value'
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return ConvertTo-AtlasoWorkstationSshHostKeyEvidence -PublicKey $value
        }
        if ((Get-Date) -lt $deadline) {
            # A caller's general readiness cadence must not extend this bounded host-key lookup past its deadline.
            $remainingPollMilliseconds = [int][Math]::Ceiling(
                [Math]::Max(0, ($deadline - (Get-Date)).TotalMilliseconds)
            )
            if ($remainingPollMilliseconds -gt 0) {
                Start-Sleep -Milliseconds ([Math]::Min($PollSeconds * 1000, $remainingPollMilliseconds))
            }
        }
    } while ((Get-Date) -lt $deadline)

    throw "Timed out after $TimeoutSeconds seconds waiting for the verified test VM SSH host key. Confirm first-boot customization and VMware Tools are healthy."
}

<#
.SYNOPSIS
Derive a valid development FQDN from a Workstation VM name.

.PARAMETER Name
The requested Workstation VM display name.
#>
function New-AtlasoWorkstationFqdn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $label = ($Name.Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-' -replace '-+', '-').Trim('-')
    if (-not $label) {
        $label = 'appliance'
    }
    if ($label.Length -gt 63) {
        $label = $label.Substring(0, 63).TrimEnd('-')
    }
    return "$label.atlaso.internal"
}

<#
.SYNOPSIS
Create the complete raw-clone OVF environment for Atlaso first boot.

.PARAMETER Fqdn
The appliance fully qualified domain name.

.PARAMETER AdminPassword
The initial Atlaso and Photon bootstrap administrator password.

.PARAMETER RootPassword
The Photon root console password.

.PARAMETER RootSshEnabled
Whether first boot enables password-backed root SSH.

.PARAMETER DevelopmentAdminSshPublicKey
Optional validated public key used only by the normal development test wrapper.

.PARAMETER NormalTestVm
Mark this raw clone as a normal test VM whose actual hostname may be published.

.PARAMETER DevelopmentRootCaCertificatePem
Optional public development root certificate used only by the normal test wrapper.
#>
function New-AtlasoWorkstationOvfEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [SecureString]$AdminPassword,

        [Parameter(Mandatory = $true)]
        [SecureString]$RootPassword,

        [switch]$RootSshEnabled,

        [switch]$NormalTestVm,

        [AllowEmptyString()]
        [string]$DevelopmentAdminSshPublicKey = '',

        [AllowEmptyString()]
        [string]$DevelopmentRootCaCertificatePem = ''
    )

    # OVF properties are XML strings, so unwrap only inside the serializer that
    # validates and emits them; callers retain SecureString boundaries.
    $adminPasswordText = ConvertFrom-SecureString -SecureString $AdminPassword -AsPlainText
    $rootPasswordText = ConvertFrom-SecureString -SecureString $RootPassword -AsPlainText

    foreach ($passwordInput in @(
            @{ Name = 'AdminPassword'; Value = $adminPasswordText },
            @{ Name = 'RootPassword'; Value = $rootPasswordText }
        )) {
        try {
            [void][System.Xml.XmlConvert]::VerifyXmlChars($passwordInput.Value)
        }
        catch {
            throw "$($passwordInput.Name) contains characters that cannot be represented in the OVF environment."
        }
        if ($passwordInput.Value -ne $passwordInput.Value.Trim() -or $passwordInput.Value -match '[\r\n\t]') {
            throw "$($passwordInput.Name) cannot contain leading, trailing, or XML-normalized control whitespace."
        }
        if ($passwordInput.Value.Length -lt 12) {
            throw "$($passwordInput.Name) must contain at least 12 characters for Atlaso first-boot customization."
        }
    }
    if ($Fqdn -notmatch '^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$') {
        throw "First-boot FQDN is invalid: $Fqdn"
    }
    if ($Fqdn.TrimEnd('.').ToLowerInvariant().EndsWith('.local')) {
        throw 'First-boot FQDN must not use .local.'
    }

    if ($DevelopmentAdminSshPublicKey) {
        # Revalidate at the serialization boundary so another caller cannot bypass
        # the test-wrapper resolver and inject arbitrary authorized_keys content.
        $DevelopmentAdminSshPublicKey = Assert-AtlasoWorkstationEd25519PublicKey -PublicKey $DevelopmentAdminSshPublicKey
    }
    $properties = [ordered]@{
        'atlaso.deployment_id'    = [guid]::NewGuid().ToString('D')
        'atlaso.management_mode'  = 'dhcp'
        'atlaso.cidr'             = ''
        'atlaso.gateway'          = ''
        'atlaso.ipv6_enabled'     = 'false'
        'atlaso.ipv6_cidr'        = ''
        'atlaso.ipv6_gateway'     = ''
        'atlaso.dns_servers'      = ''
        'atlaso.fqdn'             = $Fqdn
        'atlaso.admin_password'   = $adminPasswordText
        'atlaso.root_password'    = $rootPasswordText
        'atlaso.root_ssh_enabled' = $RootSshEnabled.IsPresent.ToString().ToLowerInvariant()
    }
    if ($NormalTestVm) {
        # Keep the non-secret hostname publication decision independent of optional
        # SSH key provisioning while excluding lifecycle and exported appliances.
        $properties['atlaso.normal_test_vm'] = 'true'
    }
    if ($DevelopmentAdminSshPublicKey) {
        $properties['atlaso.development_admin_ssh_public_key'] = $DevelopmentAdminSshPublicKey
    }
    if ($DevelopmentRootCaCertificatePem) {
        # This internal marker is emitted only by the normal test wrapper. It
        # keeps shared-CA eligibility independent from optional SSH-key setup.
        $properties['atlaso.development_test_vm'] = 'true'
        $properties['atlaso.development_root_ca_certificate'] = [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes($DevelopmentRootCaCertificatePem)
        )
    }
    $propertyXml = foreach ($entry in $properties.GetEnumerator()) {
        $key = ConvertTo-AtlasoOvfXmlValue -Value $entry.Key
        $value = ConvertTo-AtlasoOvfXmlValue -Value $entry.Value
        "<Property oe:key='$key' oe:value='$value'/>"
    }
    $environmentXml = "<Environment xmlns='http://schemas.dmtf.org/ovf/environment/1' xmlns:oe='http://schemas.dmtf.org/ovf/environment/1' oe:id='vm'><PlatformSection><Kind>VMware Workstation</Kind><Version>17</Version><Vendor>VMware, Inc.</Vendor><Locale>en</Locale></PlatformSection><PropertySection>$($propertyXml -join '')</PropertySection></Environment>"
    $adminPasswordText = $null
    $rootPasswordText = $null
    return $environmentXml
}

<#
.SYNOPSIS
Validate the checked-in development root certificate and matching private key.

.DESCRIPTION
Validates the development-only trust anchor before any normal test VM mutation.
The private key is accepted only in memory and is never written by this helper.

.PARAMETER CertificatePath
Exact path to the checked-in public development root certificate.

.PARAMETER PrivateKeyPem
Private-key PEM supplied by the bounded 1Password Environment child.
#>
function Assert-AtlasoDevelopmentRootCaMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPem
    )

    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "Atlaso development root certificate not found: $CertificatePath"
    }
    $normalizedPrivateKeyPem = $PrivateKeyPem.Replace("`r`n", "`n").Replace("`r", "`n")
    $privateKeyPattern = '\A-----BEGIN (?<label>(?:RSA )?PRIVATE KEY)-----\n' +
        '(?<body>[A-Za-z0-9+/=]+(?:\n[A-Za-z0-9+/=]+)*)\n' +
        '-----END \k<label>-----(?:\n)?\z'
    if (
        $PrivateKeyPem.Length -gt 16384 -or
        -not [System.Text.RegularExpressions.Regex]::IsMatch(
            $normalizedPrivateKeyPem,
            $privateKeyPattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
    ) {
        throw 'ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY is absent or is not one bounded PEM private key.'
    }
    $certificatePem = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $CertificatePath).Path)
    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
            $certificatePem,
            $PrivateKeyPem
        )
    }
    catch {
        throw 'The Atlaso development root certificate and 1Password private key do not match.'
    }
    try {
        if (-not $certificate.HasPrivateKey -or $certificate.Subject -ne $certificate.Issuer) {
            throw 'The Atlaso development root certificate must be self-signed and match its private key.'
        }
        $commonName = $certificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        if ($commonName -ne 'Atlaso Development Root CA') {
            throw 'The checked-in certificate is not the Atlaso Development Root CA.'
        }
        if ($certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
            throw 'The Atlaso development root certificate is not currently valid.'
        }
        if ($certificate.SignatureAlgorithm.Value -ne '1.2.840.113549.1.1.11') {
            throw 'The Atlaso development root certificate must use RSA with SHA-256.'
        }
        $basicConstraints = @($certificate.Extensions | Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
            }) | Select-Object -First 1
        $keyUsage = @($certificate.Extensions | Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]
            }) | Select-Object -First 1
        $requiredUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        if (-not $basicConstraints -or -not $basicConstraints.CertificateAuthority -or
            -not $keyUsage -or ($keyUsage.KeyUsages -band $requiredUsage) -ne $requiredUsage) {
            throw 'The Atlaso development root certificate is not CA-capable.'
        }
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
            $certificate
        )
        if (-not $rsa -or $rsa.KeySize -ne 4096) {
            throw 'The Atlaso development root certificate must use a 4096-bit RSA key.'
        }
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $chain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            [void]$chain.ChainPolicy.CustomTrustStore.Add($certificate)
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            if (-not $chain.Build($certificate)) {
                throw 'The Atlaso development root certificate signature could not be verified.'
            }
        }
        finally {
            $chain.Dispose()
        }
    }
    finally {
        if ($rsa) {
            $rsa.Dispose()
        }
        $certificate.Dispose()
    }
}

<#
.SYNOPSIS
Atomically replace one VMX with write-through durability.

.PARAMETER VmxPath
Exact powered-off VMX to replace.

.PARAMETER Lines
Complete validated VMX lines to publish.
#>
function Write-AtlasoWorkstationDurableVmxLines {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $temporaryPath = "$resolvedVmxPath.$([guid]::NewGuid().ToString('N')).tmp"
    if (-not ('Atlaso.WorkstationDurableFile' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Atlaso
{
    public static class WorkstationDurableFile
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(string existingPath, string newPath, uint flags);
    }
}
'@
    }
    try {
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            $writer = [System.IO.StreamWriter]::new(
                $stream,
                [System.Text.UTF8Encoding]::new($false),
                4096,
                $true
            )
            try {
                foreach ($line in $Lines) {
                    $writer.WriteLine($line)
                }
                $writer.Flush()
                $stream.Flush($true)
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
        # MOVEFILE_REPLACE_EXISTING plus MOVEFILE_WRITE_THROUGH binds the
        # durable phase transition to bytes already published at the VMX path.
        if (-not [Atlaso.WorkstationDurableFile]::MoveFileEx(
                $temporaryPath,
                $resolvedVmxPath,
                0x1 -bor 0x8
            )) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "The powered-off VMX durable replacement failed with Windows error $errorCode."
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
Stage the development root private key in one powered-off normal test VM.

.PARAMETER VmxPath
Exact VMX path owned by the current normal test VM invocation.

.PARAMETER PrivateKeyPem
Validated development root private-key PEM held only by the bounded child.
#>
function Set-AtlasoWorkstationDevelopmentRootCaPrivateKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPem
    )

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $pkcs8PrivateKey = $null
    try {
        $rsa.ImportFromPem($PrivateKeyPem)
        $pkcs8PrivateKey = $rsa.ExportPkcs8PrivateKey()
        # Encoding the PEM text a second time pushes a 4096-bit key beyond
        # VMware's single-line VMX parser boundary. Canonical PKCS#8 DER keeps
        # the same validated key inside one bounded guest-info assignment.
        $encoded = [Convert]::ToBase64String($pkcs8PrivateKey)
    }
    catch {
        throw 'The Atlaso development root private key could not be normalized as PKCS#8.'
    }
    finally {
        if ($null -ne $pkcs8PrivateKey) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($pkcs8PrivateKey)
        }
        $rsa.Dispose()
    }
    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_private_key'
    $line = "$guestInfoName = " + (ConvertTo-AtlasoVmxString -Value $encoded)
    if ($line.Length -gt 4095) {
        throw 'The PKCS#8 Atlaso development root private key exceeds the VMware VMX line boundary.'
    }
    $content = @(Get-Content -LiteralPath $VmxPath)
    $pattern = '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*='
    $importProofPattern = '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_imported\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
            # A prior matching proof must never satisfy this invocation before
            # the newly staged signer has been imported and scrubbed.
            if ($_ -match $importProofPattern) {
                return
            }
            if ($_ -match $pattern) {
                if (-not $updated) {
                    $line
                    $updated = $true
                }
            }
            else {
                $_
            }
        })
    if (-not $updated) {
        $content += $line
    }
    Write-AtlasoWorkstationDurableVmxLines -VmxPath $VmxPath -Lines ([string[]]$content)
}

<#
.SYNOPSIS
Remove the development root private-key assignment from a powered-off VMX.

.PARAMETER VmxPath
Exact failed normal-test-VM VMX whose signer assignment must be scrubbed.
#>
function Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath
    )

    $pattern = '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*='
    $content = @(Get-Content -LiteralPath $VmxPath | Where-Object { $_ -notmatch $pattern })
    Write-AtlasoWorkstationDurableVmxLines -VmxPath $VmxPath -Lines ([string[]]$content)
    if (Select-String -LiteralPath $VmxPath -Pattern $pattern -Quiet) {
        throw 'The powered-off normal test VM still contains the development signing-key assignment.'
    }
}

<#
.SYNOPSIS
Clear and verify the development signer through VMware runtime guest-info.

.PARAMETER VmxPath
Exact normal test VMX whose runtime signer value must be scrubbed.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER TimeoutSeconds
Bounded time allowed for three empty runtime readbacks.

.PARAMETER PollSeconds
Delay between runtime readbacks.
#>
function Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_private_key'
    Invoke-AtlasoBoundedVmrun `
        -VmrunPath $VmrunPath `
        -ArgumentList @('-T', 'ws', 'writeVariable', $VmxPath, 'runtimeConfig', $guestInfoName, '') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'Clear the development signing key from runtime guest-info' | Out-Null
    Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub `
        -VmxPath $VmxPath `
        -VmrunPath $VmrunPath `
        -TimeoutSeconds $TimeoutSeconds `
        -PollSeconds $PollSeconds
}

<#
.SYNOPSIS
Return the SHA-256 fingerprint of one public development root certificate.

.PARAMETER CertificatePath
Exact checked-in PEM certificate path.
#>
function Get-AtlasoDevelopmentRootCaFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePath
    )

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
        [System.IO.File]::ReadAllText($CertificatePath)
    )
    try {
        return $certificate.GetCertHashString(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        ).ToUpperInvariant()
    }
    finally {
        $certificate.Dispose()
    }
}

<#
.SYNOPSIS
Wait for proof that the guest encrypted the development signer and scrubbed staging.

.PARAMETER VmxPath
Exact running normal test VMX path.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER ExpectedFingerprint
Checked-in development root SHA-256 fingerprint expected from the guest.

.PARAMETER TimeoutSeconds
Bounded time allowed for HTTPS bootstrap to import and scrub the signer.

.PARAMETER PollSeconds
Delay between guest-info reads.
#>
function Wait-AtlasoWorkstationDevelopmentRootCaImportProof {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$ExpectedFingerprint,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $normalizedExpected = $ExpectedFingerprint.Replace(':', '').ToUpperInvariant()
    if ($normalizedExpected -notmatch '^[0-9A-F]{64}$') {
        throw 'The expected Atlaso development root SHA-256 fingerprint is invalid.'
    }
    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_imported'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $matchingReads = 0
    $lastFirstBootStage = ''
    do {
        $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        $value = Invoke-AtlasoBoundedVmrun `
            -VmrunPath $VmrunPath `
            -ArgumentList @('-T', 'ws', 'readVariable', $VmxPath, 'runtimeConfig', $guestInfoName) `
            -TimeoutSeconds $remainingSeconds `
            -Action 'Read the development-root encrypted-import proof'
        $normalizedValue = if ($null -ne $value) {
            $value.Trim().Replace(':', '').ToUpperInvariant()
        }
        else {
            ''
        }
        if ($normalizedValue -ceq $normalizedExpected) {
            $matchingReads += 1
            if ($matchingReads -ge 3) {
                return
            }
        }
        else {
            $matchingReads = 0
            $lastFirstBootStage = Get-AtlasoWorkstationFirstBootStage `
                -VmxPath $VmxPath `
                -VmrunPath $VmrunPath `
                -TimeoutSeconds ([Math]::Min($remainingSeconds, 5))
        }
        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $PollSeconds
        }
    } while ((Get-Date) -lt $deadline)
    $diagnostic = if ($lastFirstBootStage) {
        " Last reported first-boot stage: $lastFirstBootStage."
    }
    else {
        ' No bounded first-boot stage was reported; guest-agent selection or customizer startup did not complete.'
    }
    throw "The normal test VM did not prove encrypted development-root import and plaintext staging removal.$diagnostic"
}

<#
.SYNOPSIS
Read one bounded sanitized normal-test-VM first-boot stage.

.PARAMETER VmxPath
Exact running normal test VMX path.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER TimeoutSeconds
Positive bounded time allowed for the guest-info read.
#>
function Get-AtlasoWorkstationFirstBootStage {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    try {
        $value = Invoke-AtlasoBoundedVmrun `
            -VmrunPath $VmrunPath `
            -ArgumentList @(
                '-T', 'ws', 'readVariable', $VmxPath, 'runtimeConfig',
                'guestinfo.atlaso.test_vm_first_boot_stage'
            ) `
            -TimeoutSeconds $TimeoutSeconds `
            -Action 'Read the bounded normal-test-VM first-boot stage'
    }
    catch {
        # A best-effort diagnostic must never replace the primary readiness error.
        return ''
    }
    $normalized = if ($null -eq $value) { '' } else { $value.Trim().ToLowerInvariant() }
    $layerStages = @(
        'management-network',
        'resolver',
        'management-web-server',
        'firewall',
        'hostname',
        'root-password',
        'root-ssh',
        'bootstrap-administrator-password',
        'ssh-host-key',
        'development-administrator-ssh',
        'test-vm-hostname',
        'appliance-environment',
        'development-root-ca-staging-and-guest-info-scrub',
        'console-credential-refresh',
        'host-state-durability',
        'pending-success-marker',
        'ovf-credential-scrub',
        'applied-marker'
    )
    $knownStages = @($layerStages)
    $knownStages += @($layerStages | ForEach-Object { "failed-$_" })
    $knownStages += @(
        'vmware-customization-complete',
        'https-development-root-proof',
        'https-development-root-proof-complete',
        'https-development-root-import',
        'https-development-root-import-complete',
        'failed-https-development-root-proof',
        'failed-https-development-root-import',
        'failed-https-development-root-staging-removal'
    )
    if ($knownStages -ccontains $normalized) {
        return $normalized
    }
    return ''
}

<#
.SYNOPSIS
Wait until the guest proves the development signing key was scrubbed.

.PARAMETER VmxPath
Exact running normal test VMX path.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER TimeoutSeconds
Bounded time allowed for guest-side staging and scrub.

.PARAMETER PollSeconds
Delay between guest-info reads.
#>
function Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_private_key'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $emptyReads = 0
    $lastFirstBootStage = ''
    do {
        $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        $value = Invoke-AtlasoBoundedVmrun `
            -VmrunPath $VmrunPath `
            -ArgumentList @('-T', 'ws', 'readVariable', $VmxPath, 'runtimeConfig', $guestInfoName) `
            -TimeoutSeconds $remainingSeconds `
            -Action 'Read the development signing-key guest-info value'
        $normalizedValue = if ($null -eq $value) { '' } else { $value.Trim() }
        # vmrun serializes an empty runtimeConfig value as the literal VMX
        # empty-string sentinel. Treat only that exact sentinel as empty; other
        # quoted or unquoted text remains a non-empty secret-bearing value.
        if ([string]::IsNullOrWhiteSpace($normalizedValue) -or $normalizedValue -ceq '""') {
            $emptyReads += 1
            if ($emptyReads -ge 3) {
                return
            }
        }
        else {
            $emptyReads = 0
            $lastFirstBootStage = Get-AtlasoWorkstationFirstBootStage `
                -VmxPath $VmxPath `
                -VmrunPath $VmrunPath `
                -TimeoutSeconds ([Math]::Min($remainingSeconds, 5))
        }
        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $PollSeconds
        }
    } while ((Get-Date) -lt $deadline)
    $diagnostic = if ($lastFirstBootStage) {
        " Last reported first-boot stage: $lastFirstBootStage."
    }
    else {
        ' No bounded first-boot stage was reported; guest-agent selection or customizer startup did not complete.'
    }
    throw "The normal test VM did not prove that its development signing key guest-info value was scrubbed.$diagnostic"
}

<#
.SYNOPSIS
Replace the exact guestinfo.ovfEnv assignment in a VMX file.

.PARAMETER VmxPath
The VMX file to update before power-on.

.PARAMETER OvfEnvironment
The complete validated OVF environment XML.
#>
function Set-AtlasoWorkstationOvfEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmxPath,

        [Parameter(Mandatory = $true)]
        [string]$OvfEnvironment
    )

    $line = "guestinfo.ovfEnv = " + (ConvertTo-AtlasoVmxString -Value $OvfEnvironment)
    $content = @(Get-Content -LiteralPath $VmxPath)
    $pattern = '^\s*guestinfo\.ovfEnv\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
            if ($_ -match $pattern) {
                if (-not $updated) {
                    $line
                    $updated = $true
                }
            }
            else {
                $_
            }
        })
    if (-not $updated) {
        $content += $line
    }
    [System.IO.File]::WriteAllLines($VmxPath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}
