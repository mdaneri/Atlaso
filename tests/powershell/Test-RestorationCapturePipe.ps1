<#
.SYNOPSIS
Exercise the private overlapped pipe with original same-process Windows endpoints.
.PARAMETER RepositoryRoot
Exact source root containing the private capture pipe module.
.PARAMETER Nonces
Eight unique original fixture nonces receipted before endpoint creation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][guid[]]$Nonces
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $Nonces.Count -ne 8 -or [guid]::Empty -in $Nonces -or
    @($Nonces | Sort-Object -Unique).Count -ne $Nonces.Count) {
    throw 'Original Windows pipe fixtures require eight distinct nonempty nonces.'
}
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.RestorationCapturePipe.psm1')

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Atlaso.Tests
{
    public static class RestorationPipeAccessProbe
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafePipeHandle CreateFileW(string name, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafePipeHandle CreateNamedPipeW(string name, uint access, uint mode, uint instances,
            uint outputSize, uint inputSize, uint timeout, IntPtr security);

        private static string Name(Guid nonce) => @"\\.\pipe\AtlasoRestorationCapture-" + nonce.ToString("N");

        public static int OpenError(Guid nonce, uint access)
        {
            using (SafePipeHandle pipe = CreateFileW(Name(nonce), access, 0, IntPtr.Zero, 3, 0x40110000, IntPtr.Zero))
                return pipe.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }

        public static int SecondServerError(Guid nonce)
        {
            using (SafePipeHandle pipe = CreateNamedPipeW(Name(nonce), 0x40000003, 8, 1, 4096, 4096, 0, IntPtr.Zero))
                return pipe.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
    }
}
'@

<#
.SYNOPSIS
Construct one original absolute fixture deadline.
.PARAMETER Milliseconds
Maximum duration from the original clock sample.
#>
function New-PipeFixtureDeadline([int]$Milliseconds = 3000) {
    $frequency = [Diagnostics.Stopwatch]::Frequency
    $counter = [Diagnostics.Stopwatch]::GetTimestamp() + [long]($frequency * $Milliseconds / 1000)
    [Atlaso.RestorationPipeDeadline]::new($counter, $frequency, [DateTimeOffset]::UtcNow.AddMilliseconds($Milliseconds))
}

<#
.SYNOPSIS
Require an exact refusal with its originating exception type and optional native error.
.PARAMETER Action
Single operation expected to refuse.
.PARAMETER ExceptionType
Expected underlying exception type.
.PARAMETER NativeError
Exact expected Win32 error if the failure uses the native error channel.
#>
function Assert-PipeRefusal([scriptblock]$Action, [type]$ExceptionType, [int]$NativeError = 0) {
    try { & $Action | Out-Null }
    catch {
        $cause = $_.Exception
        while ($cause.InnerException -and -not $ExceptionType.IsInstanceOfType($cause)) {
            $cause = $cause.InnerException
        }
        if (-not $ExceptionType.IsInstanceOfType($cause) -or
            ($NativeError -and $cause.NativeErrorCode -ne $NativeError)) { throw }
        return
    }
    throw 'The original pipe operation unexpectedly succeeded.'
}

$deadline = New-PipeFixtureDeadline
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[0], $deadline)
try {
    Assert-PipeRefusal { [Atlaso.RestorationCapturePipe]::Reserve($Nonces[0], $deadline) } ([ComponentModel.Win32Exception]) 5
    $client = [Atlaso.RestorationCapturePipe]::Open($Nonces[0], $deadline, $PID)
    try {
        $server.Connect($PID)
        $server.VerifyPeer($PID)
        $client.VerifyPeer($PID)
        Assert-PipeRefusal { [Atlaso.RestorationCapturePipe]::Open($Nonces[0], $deadline, $PID) } ([ComponentModel.Win32Exception]) 231
        $server.Write([byte[]]@(0, 255, 1))
        if ([Convert]::ToHexString($client.Read(2)) -cne '00FF' -or
            [Convert]::ToHexString($client.Read(1)) -cne '01') { throw 'Original pipe split read differed.' }
        $client.Write([byte[]]@(13, 10))
        if ([Convert]::ToHexString($server.Read(2)) -cne '0D0A') { throw 'Original pipe reverse transfer differed.' }
        Assert-PipeRefusal { $server.Read(393227) } ([ArgumentException])
        Assert-PipeRefusal { $client.Write([byte[]]@()) } ([ArgumentException])
    }
    finally { $client.Dispose() }
    $server.RequirePeerClosure()
    Assert-PipeRefusal { $server.Connect($PID) } ([InvalidOperationException])
}
finally { $server.Dispose() }

$deadline = New-PipeFixtureDeadline
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[1], $deadline)
try {
    Assert-PipeRefusal { [Atlaso.RestorationCapturePipe]::Open($Nonces[1], $deadline, 0) } ([InvalidOperationException])
    Assert-PipeRefusal { $server.Connect($PID) } ([ComponentModel.Win32Exception]) 232
}
finally { $server.Dispose() }

$deadline = New-PipeFixtureDeadline
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[2], $deadline)
try {
    $client = [Atlaso.RestorationCapturePipe]::Open($Nonces[2], $deadline, $PID)
    try {
        Assert-PipeRefusal { $server.Connect(0) } ([InvalidOperationException])
        Assert-PipeRefusal { $server.Connect($PID) } ([InvalidOperationException])
    }
    finally { $client.Dispose() }
}
finally { $server.Dispose() }

$deadline = New-PipeFixtureDeadline
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[3], $deadline)
try {
    $client = [Atlaso.RestorationCapturePipe]::Open($Nonces[3], $deadline, $PID)
    try {
        $server.Connect($PID)
        $client.Write([byte[]]@(1))
        Assert-PipeRefusal { $server.RequirePeerClosure() } ([InvalidOperationException])
        Assert-PipeRefusal { $server.Read(1) } ([InvalidOperationException])
    }
    finally { $client.Dispose() }
}
finally { $server.Dispose() }

$deadline = New-PipeFixtureDeadline 700
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[4], $deadline)
try {
    Assert-PipeRefusal { $server.Connect($PID) } ([TimeoutException])
    Assert-PipeRefusal { $server.Connect($PID) } ([InvalidOperationException])
}
finally { $server.Dispose() }

$deadline = New-PipeFixtureDeadline 700
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[5], $deadline)
try {
    $client = [Atlaso.RestorationCapturePipe]::Open($Nonces[5], $deadline, $PID)
    try {
        $server.Connect($PID)
        Assert-PipeRefusal { $server.Read(1) } ([TimeoutException])
        Assert-PipeRefusal { $server.Read(1) } ([InvalidOperationException])
    }
    finally { $client.Dispose() }
}
finally { $server.Dispose() }

$deadline = New-PipeFixtureDeadline
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[6], $deadline)
try {
    $client = [Atlaso.RestorationCapturePipe]::Open($Nonces[6], $deadline, $PID)
    try { $server.Connect($PID) }
    finally { $client.Dispose() }
    Assert-PipeRefusal { $server.Read(1) } ([ComponentModel.Win32Exception]) 109
    Assert-PipeRefusal { $server.RequirePeerClosure() } ([InvalidOperationException])
}
finally { $server.Dispose() }

$deadline = New-PipeFixtureDeadline
$server = [Atlaso.RestorationCapturePipe]::Reserve($Nonces[7], $deadline)
try {
    # Check generic-write access and the actual second-server operation independently.
    $accessError = [Atlaso.Tests.RestorationPipeAccessProbe]::OpenError($Nonces[7], 0x40000000)
    if ($accessError -ne 5) {
        throw "Unexpected generic-write client result, Win32 $accessError."
    }
    $secondServerError = [Atlaso.Tests.RestorationPipeAccessProbe]::SecondServerError($Nonces[7])
    if ($secondServerError -notin @(5, 231)) {
        throw "Unexpected second server result, Win32 $secondServerError."
    }
    $client = [Atlaso.RestorationCapturePipe]::Open($Nonces[7], $deadline, $PID)
    try { $server.Connect($PID) }
    finally { $client.Dispose() }
    $server.RequirePeerClosure()
}
finally { $server.Dispose() }

Write-Output 'Eight original local Windows pipe fixtures passed.'
