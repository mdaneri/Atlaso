<#
.SYNOPSIS
Start one exact Atlaso VMware Workstation VM without propagating launcher output pipes.

.DESCRIPTION
Resolves the supported vmrun executable, starts the requested exact VMX in GUI
or headless mode, and waits only for the vmrun root process. The vmrun child is
started without redirected standard streams so a successfully detached VMware
GUI or VMX process cannot retain the calling wrapper's output pipes.

.PARAMETER VmxPath
Existing exact VMX to start.

.PARAMETER VmrunPath
Optional explicit vmrun executable path.

.PARAMETER Mode
Supported VMware start mode, either gui or nogui.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,
    [string]$VmrunPath = '',
    [ValidateSet('gui', 'nogui')]
    [string]$Mode = 'gui'
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Resolve the supported VMware vmrun executable.

.PARAMETER Path
Optional explicit vmrun executable path.
#>
function Resolve-VmrunPath {
    param([string]$Path)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "vmrun.exe not found: $Path" }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    foreach ($candidate in @('C:\Program Files\VMware\VMware Workstation\vmrun.exe', 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

<#
.SYNOPSIS
Start vmrun without inheriting this launcher's standard handles.

.PARAMETER FilePath
Exact resolved vmrun executable.

.PARAMETER ArgumentList
Exact VMware arguments encoded through the Windows argv contract.
#>
function Start-AtlasoVmrunWithoutInheritedHandles {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )

    if (-not ('Atlaso.DetachedVmrun' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlaso
{
    public static class DetachedVmrun
    {
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
        private static extern bool CreateProcess(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInformation startupInformation,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private static string QuoteArgument(string value)
        {
            if (value.Length != 0 && value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '\r', '"' }) < 0)
            {
                return value;
            }
            StringBuilder quoted = new StringBuilder();
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

        public static Process Start(string filePath, string[] arguments)
        {
            StringBuilder commandLine = new StringBuilder(QuoteArgument(filePath));
            foreach (string argument in arguments)
            {
                commandLine.Append(' ');
                commandLine.Append(QuoteArgument(argument));
            }
            StartupInformation startup = new StartupInformation();
            startup.Size = (uint)Marshal.SizeOf(typeof(StartupInformation));
            ProcessInformation process;
            if (!CreateProcess(
                filePath,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                null,
                ref startup,
                out process))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "vmrun could not be started without inherited handles.");
            }
            try
            {
                Process managedProcess = Process.GetProcessById((int)process.ProcessId);
                IntPtr managedHandle = managedProcess.Handle;
                return managedProcess;
            }
            finally
            {
                CloseHandle(process.Thread);
                CloseHandle(process.Process);
            }
        }
    }
}
'@
    }
    return [Atlaso.DetachedVmrun]::Start($FilePath, $ArgumentList)
}

$resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
# CreateProcess receives inheritHandles=false, so neither vmrun nor any VMware
# process it detaches can receive the bounded wrapper's redirected pipe handles.
$process = Start-AtlasoVmrunWithoutInheritedHandles `
    -FilePath $resolvedVmrun `
    -ArgumentList @('-T', 'ws', 'start', $resolvedVmxPath, $Mode)
try {
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "vmrun start failed with exit code $($process.ExitCode)."
    }
}
finally {
    $process.Dispose()
}
Write-Host "Started VMware Workstation VM: $resolvedVmxPath"
