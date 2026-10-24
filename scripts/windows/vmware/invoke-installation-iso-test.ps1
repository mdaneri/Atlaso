<#
.SYNOPSIS
Drive an isolated development installer through a private serial console.
.DESCRIPTION
The bounded child owns the local pipe server and never records raw console bytes.
Only the current Windows user and SYSTEM can connect. Credentials remain inside
the supported 1Password consumer and are sent only to concealed installer fields.
.PARAMETER IsoPath
Verified development installation ISO.
.PARAMETER IsoSha256
Independently retained ISO digest.
.PARAMETER OutputDirectory
Absent task-owned VM output directory.
.PARAMETER PullRequestNumber
Exact owning pull request.
.PARAMETER Scenario
Probe the native UI, cancel before writes, or run the single-disk Auto installation.
.PARAMETER TimeoutSeconds
Whole test and console deadline.
.PARAMETER Child
Internal bounded-child selector.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$IsoPath,
    [Parameter(Mandatory = $true)][string]$IsoSha256,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
    [ValidateSet('Probe', 'Cancel', 'Auto')][string]$Scenario = 'Probe',
    [ValidateRange(60, 14400)][int]$TimeoutSeconds = 3600,
    [switch]$Child
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
if (-not $Child) {
    Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path -ArgumentList @(
        '-NoProfile', '-File', $PSCommandPath, '-Child', '-IsoPath', $IsoPath,
        '-IsoSha256', $IsoSha256, '-OutputDirectory', $OutputDirectory,
        '-PullRequestNumber', [string]$PullRequestNumber, '-Scenario', $Scenario,
        '-TimeoutSeconds', [string]$TimeoutSeconds
    ) -TimeoutSeconds $TimeoutSeconds -Action 'Private installation serial-console test'
    return
}

<#
.SYNOPSIS
Write public console control bytes without logging the console stream.
.PARAMETER Pipe
Connected private serial pipe.
.PARAMETER Text
Public keystrokes or control characters.
#>
function Send-InstallationConsoleText {
    param([IO.Pipes.NamedPipeServerStream]$Pipe, [string]$Text)
    $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
    try { $Pipe.Write($bytes, 0, $bytes.Length); $Pipe.Flush() }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

<#
.SYNOPSIS
Send a concealed account value only at its expected masked installer field.
.PARAMETER Pipe
Connected private serial pipe.
.PARAMETER Value
Concealed account password from the supported credential bridge.
#>
function Send-InstallationConsoleSecret {
    param([IO.Pipes.NamedPipeServerStream]$Pipe, [Security.SecureString]$Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    $bytes = $null
    try {
        $length = [Runtime.InteropServices.Marshal]::ReadInt32($pointer, -4) / 2
        $bytes = [byte[]]::new($length + 1)
        for ($index = 0; $index -lt $length; $index++) {
            $character = [Runtime.InteropServices.Marshal]::ReadInt16($pointer, $index * 2)
            if ($character -lt 32 -or $character -gt 126) { throw 'Installer credential must satisfy the ASCII account policy.' }
            $bytes[$index] = [byte]$character
        }
        $bytes[$length] = 10
        $Pipe.Write($bytes, 0, $bytes.Length)
        $Pipe.Flush()
    }
    finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

<#
.SYNOPSIS
Wait for a known public installer state while retaining console bytes only in memory.
.PARAMETER Pipe
Connected private serial pipe.
.PARAMETER Pattern
Expected public prompt text.
.PARAMETER Deadline
Absolute test deadline.
#>
function Wait-InstallationConsoleState {
    param([IO.Pipes.NamedPipeServerStream]$Pipe, [string]$Pattern, [DateTimeOffset]$Deadline)
    $buffer = [byte[]]::new(4096)
    $text = ''
    try {
        while ([DateTimeOffset]::UtcNow -lt $Deadline) {
            $remaining = [int][Math]::Min(30000, ($Deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
            if ($remaining -le 0) { break }
            $cancel = [Threading.CancellationTokenSource]::new($remaining)
            try {
                $count = $Pipe.ReadAsync($buffer, 0, $buffer.Length, $cancel.Token).GetAwaiter().GetResult()
            }
            catch [OperationCanceledException] { continue }
            finally { $cancel.Dispose() }
            if ($count -eq 0) { throw 'The owned VM serial console disconnected before the expected state.' }
            $text += [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
            $plain = [regex]::Replace($text, '\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()][A-Z0-9]|\x1b[=>]', '')
            if ($plain.Contains('Traceback (most recent call last):', [StringComparison]::Ordinal)) {
                # Report only a fixed public classification, never raw exception
                # text that could contain credential-bearing subprocess output.
                throw 'The installer reported a Python failure before the expected console state.'
            }
            if ($plain.Contains($Pattern, [StringComparison]::Ordinal)) { return }
            if ($text.Length -gt 131072) { $text = $text.Substring($text.Length - 65536) }
        }
        throw 'The installer did not reach the expected public console state before its deadline.'
    }
    finally { [Array]::Clear($buffer, 0, $buffer.Length); $text = ''; $plain = '' }
}

$worktree = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
$commit = ([string](& git -C $worktree rev-parse HEAD)).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not admit the installer console source commit.' }
$branch = ([string](& git -C $worktree branch --show-current)).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not admit the installer console source branch.' }
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force
$vmName = (New-AtlasoVmwareTestIdentity -PullRequestNumber $PullRequestNumber -Purpose installation-iso).Name
$sourceContext = New-AtlasoTestVmOwnershipContext -Worktree $worktree -OutputDirectory $OutputDirectory `
    -VmxPath (Join-Path $OutputDirectory "$vmName.vmx") -Name $vmName -SourceCommit $commit `
    -SourceBranch $branch -PullRequestNumber $PullRequestNumber
Assert-AtlasoTestVmCheckoutSource -Context $sourceContext
$credentials = $null
if ($Scenario -eq 'Auto') {
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
    $selector = Resolve-AtlasoOnePasswordEnvironmentId -RepositoryRoot $worktree
    $token = Resolve-AtlasoOnePasswordServiceAccountTokenFile -RepositoryRoot $worktree `
        -TokenFile (Join-Path $worktree '.atlaso-local/onepassword-service-account-token.dpapi')
    $credentials = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $worktree -EnvironmentId $selector `
        -OnePasswordServiceAccountTokenFile $token -TimeoutSeconds 300 -ConsumerDescription 'development installer console'
}

$pipeName = 'Atlaso-Installation-' + [guid]::NewGuid().ToString('N')
$security = [IO.Pipes.PipeSecurity]::new()
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$security.SetOwner($user)
$security.SetAccessRuleProtection($true, $false)
foreach ($identity in @($user, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new($identity, [IO.Pipes.PipeAccessRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
}
$pipe = [IO.Pipes.NamedPipeServerStreamAcl]::Create($pipeName, [IO.Pipes.PipeDirection]::InOut, 1,
    [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous, 8192, 8192, $security)
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
try {
    $connection = $pipe.WaitForConnectionAsync()
    $vm = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Create -Worktree $worktree `
        -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -IsoPath $IsoPath -IsoSha256 $IsoSha256 `
        -SerialPipePath "\\.\pipe\$pipeName" -Confirm:$false
    Write-Host ('Installation VM ownership: ' + ($vm | ConvertTo-Json -Compress))
    if (-not $connection.Wait(120000)) { throw 'The owned VM did not connect its private serial console.' }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class AtlasoInstallationPipePeer {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint length);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int QueryProcess(SafeProcessHandle process, int informationClass, IntPtr buffer, uint length, out uint returned);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr allocation);
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    // WMI omits these fields for Workstation's protected process. Query only
    // limited process metadata, using one live handle for both identity proofs.
    // Never return or log the command line, and refuse unavailable native APIs.
    public static bool MatchesExpectedProcess(uint processId, string[] allowedImages, string expectedArgument) {
        if (allowedImages == null || allowedImages.Length == 0 || String.IsNullOrEmpty(expectedArgument)) return false;
        using (SafeProcessHandle process = OpenProcess(0x1000, false, processId)) {
            if (process.IsInvalid) return false;
            var image = new StringBuilder(32768);
            uint imageLength = (uint)image.Capacity;
            if (!QueryFullProcessImageNameW(process, 0, image, ref imageLength)) return false;
            if (!Array.Exists(allowedImages, path => String.Equals(path, image.ToString(), StringComparison.OrdinalIgnoreCase))) return false;
            IntPtr library = IntPtr.Zero, buffer = IntPtr.Zero, arguments = IntPtr.Zero;
            try {
                // Restrict dynamic loading to the Windows system directory.
                string nativePath = System.IO.Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                if (!NativeLibrary.TryLoad(nativePath, out library) ||
                    !NativeLibrary.TryGetExport(library, "NtQueryInformationProcess", out IntPtr entry)) return false;
                var query = Marshal.GetDelegateForFunctionPointer<QueryProcess>(entry);
                uint required;
                query(process, 60, IntPtr.Zero, 0, out required);
                int headerSize = Marshal.SizeOf<UnicodeString>();
                if (required < headerSize || required > 1048576) return false;
                buffer = Marshal.AllocHGlobal((int)required);
                if (query(process, 60, buffer, required, out uint returned) != 0 || returned < headerSize || returned > required) return false;
                var value = Marshal.PtrToStructure<UnicodeString>(buffer);
                long offset = checked(value.Buffer.ToInt64() - buffer.ToInt64());
                if ((value.Length & 1) != 0 || value.Length > value.MaximumLength ||
                    offset < headerSize || offset > returned || value.Length > returned - offset) return false;
                string commandLine = Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
                arguments = CommandLineToArgvW(commandLine, out int count);
                if (arguments == IntPtr.Zero || count < 1 || count > 32768) return false;
                for (int index = 1; index < count; index++) {
                    string argument = Marshal.PtrToStringUni(Marshal.ReadIntPtr(arguments, checked(index * IntPtr.Size)));
                    if (String.Equals(argument, expectedArgument, StringComparison.OrdinalIgnoreCase)) return true;
                }
                return false;
            }
            catch (Exception exception) when (exception is ArgumentException || exception is OverflowException ||
                exception is DllNotFoundException || exception is EntryPointNotFoundException) { return false; }
            finally {
                if (arguments != IntPtr.Zero) LocalFree(arguments);
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                if (library != IntPtr.Zero) NativeLibrary.Free(library);
            }
        }
    }
}
'@
    $peerId = [uint32]0
    if (-not [AtlasoInstallationPipePeer]::GetNamedPipeClientProcessId($pipe.SafePipeHandle, [ref]$peerId)) {
        throw 'Could not prove the serial console peer process.'
    }
    $vmxPath = [IO.Path]::GetFullPath([string]$vm.VmxPath)
    $providerImages = @(
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/x64/vmware-vmx.exe'),
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/vmware-vmx.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'VMware/VMware Workstation/x64/vmware-vmx.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object { [IO.Path]::GetFullPath($_) }
    if (-not [AtlasoInstallationPipePeer]::MatchesExpectedProcess($peerId, [string[]]$providerImages, $vmxPath)) {
        throw 'The private console peer is not the receipt-bound VMware guest.'
    }
    Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Select a disk' -Deadline $deadline
    Write-Host 'Installer reached the native Photon disk selection screen.'
    if ($Scenario -eq 'Cancel') {
        # The pinned serial getty uses TERM=screen with application cursor keys.
        Send-InstallationConsoleText -Pipe $pipe -Text "`eOD`eOD`n"
        Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Installation cancelled' -Deadline $deadline
        Write-Host 'Installer cancellation returned without admitting disk writes.'
    }
    elseif ($Scenario -eq 'Auto') {
        Send-InstallationConsoleText -Pipe $pipe -Text "`n"
        Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Review planned partitions' -Deadline $deadline
        Send-InstallationConsoleText -Pipe $pipe -Text "NEXT`n"
        Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Review Atlaso installation disk' -Deadline $deadline
        Send-InstallationConsoleText -Pipe $pipe -Text "ERASE /dev/sda`n"
        foreach ($account in @('admin', 'root')) {
            $value = if ($account -eq 'admin') { $credentials.AdminPassword } else { $credentials.RootPassword }
            foreach ($verb in @('Set', 'Confirm')) {
                Wait-InstallationConsoleState -Pipe $pipe -Pattern "$verb $account password" -Deadline $deadline
                Send-InstallationConsoleSecret -Pipe $pipe -Value $value
            }
        }
        Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Atlaso installation completed.' -Deadline $deadline
        Write-Host 'Disconnected Auto installation completed; reboot and persistence acceptance remain separate.'
    }
    # Keep checked provider stop and disk comparison inside this runner's existing
    # whole-process-tree deadline, including the shared vmrun inactivity checks.
    $verification = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Verify -Worktree $worktree `
        -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber `
        -OriginalReceiptPath $vm.ReceiptPath -OriginalReceiptSha256 $vm.ReceiptSha256 `
        -BaselineReceiptPath $vm.BaselineReceiptPath -BaselineReceiptSha256 $vm.BaselineReceiptSha256 `
        -VerifyTarget:($Scenario -ne 'Auto') -Confirm:$false
    Write-Host ('Installation disk verification: ' + ($verification | ConvertTo-Json -Depth 4 -Compress))
}
finally {
    $pipe.Dispose()
    if ($credentials) { $credentials.AdminPassword.Dispose(); $credentials.RootPassword.Dispose() }
    if ($sourceContext.PSObject.Properties['CheckoutSourcePin'] -and $sourceContext.CheckoutSourcePin) {
        $sourceContext.CheckoutSourcePin.Dispose()
    }
}
