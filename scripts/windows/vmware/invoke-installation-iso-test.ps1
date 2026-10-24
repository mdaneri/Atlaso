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
            if ($plain.Contains($Pattern, [StringComparison]::Ordinal)) { return }
            if ($text.Length -gt 131072) { $text = $text.Substring($text.Length - 65536) }
        }
        throw 'The installer did not reach the expected public console state before its deadline.'
    }
    finally { [Array]::Clear($buffer, 0, $buffer.Length); $text = ''; $plain = '' }
}

$worktree = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
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
    if (-not $connection.Wait(120000)) { throw 'The owned VM did not connect its private serial console.' }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class AtlasoInstallationPipePeer {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
}
'@
    $peerId = [uint32]0
    if (-not [AtlasoInstallationPipePeer]::GetNamedPipeClientProcessId($pipe.SafePipeHandle, [ref]$peerId)) {
        throw 'Could not prove the serial console peer process.'
    }
    $peer = Get-CimInstance Win32_Process -Filter "ProcessId=$peerId"
    $vmxPath = [IO.Path]::GetFullPath([string]$vm.VmxPath)
    $providerImages = @(
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/x64/vmware-vmx.exe'),
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/vmware-vmx.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'VMware/VMware Workstation/x64/vmware-vmx.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object { [IO.Path]::GetFullPath($_) }
    $vmxArgument = '(?i)(?:^|\s)"?' + [regex]::Escape($vmxPath) + '"?(?=\s|$)'
    if ($peer.Name -ine 'vmware-vmx.exe' -or $peer.ExecutablePath -notin $providerImages -or
        -not [regex]::IsMatch([string]$peer.CommandLine, $vmxArgument)) {
        throw 'The private console peer is not the receipt-bound VMware guest.'
    }
    Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Select a disk' -Deadline $deadline
    Write-Host 'Installer reached the native Photon disk selection screen.'
    if ($Scenario -eq 'Probe') { return }
    if ($Scenario -eq 'Cancel') {
        Send-InstallationConsoleText -Pipe $pipe -Text "`e[D`e[D`n"
        Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Installation cancelled' -Deadline $deadline
        Write-Host 'Installer cancellation returned without admitting disk writes.'
        return
    }
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
finally {
    $pipe.Dispose()
    if ($credentials) { $credentials.AdminPassword.Dispose(); $credentials.RootPassword.Dispose() }
    if ($sourceContext.PSObject.Properties['CheckoutSourcePin'] -and $sourceContext.CheckoutSourcePin) {
        $sourceContext.CheckoutSourcePin.Dispose()
    }
}
