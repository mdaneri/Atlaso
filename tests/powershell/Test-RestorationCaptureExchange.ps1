<#
.SYNOPSIS
Qualify the local synthetic pipe exchange with an original suspended Windows job child.
.PARAMETER RepositoryRoot
Exact source root containing the pinned fixture and primitives.
.PARAMETER FixtureRoot
Exact original synthetic working directory.
.PARAMETER FixtureIdentity
Native identity recorded before parent fixture use.
.PARAMETER EvidenceRoot
Original parent evidence directory outside the synthetic working directory.
.PARAMETER Nonces
Two distinct original fixture nonces recorded before any endpoint or child creation.
.PARAMETER Child
Run only the synthetic client under the original suspended job.
.PARAMETER LaunchIntent
Exact original launch receipt file.
.PARAMETER LaunchSha256
Expected digest of the original launch receipt.
#>
[CmdletBinding(DefaultParameterSetName = 'Parent')]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory, ParameterSetName = 'Parent')][string]$FixtureIdentity,
    [Parameter(Mandatory, ParameterSetName = 'Parent')][string]$EvidenceRoot,
    [Parameter(Mandatory, ParameterSetName = 'Parent')][guid[]]$Nonces,
    [Parameter(Mandatory, ParameterSetName = 'Child')][switch]$Child,
    [Parameter(Mandatory, ParameterSetName = 'Child')][string]$LaunchIntent,
    [Parameter(Mandatory, ParameterSetName = 'Child')][ValidatePattern('^[0-9a-f]{64}$')][string]$LaunchSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'The synthetic exchange requires Windows.' }
$pipeModule = Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.RestorationCapturePipe.psm1'
$jobModule = Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.RestorationCaptureJob.psm1'
$cleanupModule = Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1'

<#
.SYNOPSIS
Flush and read back exact fixture bytes through the retained original creation handle.
.PARAMETER Path
New fixture receipt path in the original evidence directory.
.PARAMETER Record
Public synthetic fixture selectors or original observations.
#>
function New-ExchangeFixtureReceipt([string]$Path, [hashtable]$Record) {
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($Record | ConvertTo-Json -Depth 6))
    $stream = [IO.File]::Open($Path, 'CreateNew', 'ReadWrite', 'Read')
    try {
        $stream.Write($bytes)
        $stream.Flush($true)
        $stream.Position = 0
        $readback = [byte[]]::new($bytes.Length)
        $stream.ReadExactly($readback, 0, $readback.Length)
        if ([Convert]::ToHexString($readback) -cne [Convert]::ToHexString($bytes)) {
            throw 'The original fixture receipt bytes differ.'
        }
        [pscustomobject]@{
            Stream=$stream; Sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($readback)).ToLowerInvariant()
        }
    }
    catch { $stream.Dispose(); throw }
}

<#
.SYNOPSIS
Read bounded bytes from an original fixture receipt still held by the parent.
.PARAMETER Path
Exact fixture receipt path.
.PARAMETER ExpectedSha256
Optional previously frozen digest.
#>
function Read-ExchangeFixtureReceipt([string]$Path, [string]$ExpectedSha256 = '') {
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 16384) {
            throw 'The original fixture receipt size differs.'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $stream.ReadExactly($bytes, 0, $bytes.Length)
        $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        if ($ExpectedSha256 -and $digest -cne $ExpectedSha256) { throw 'The original fixture receipt digest differs.' }
        [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json -AsHashtable
    }
    finally { $stream.Dispose() }
}

<#
.SYNOPSIS
Read one fixed small synthetic byte sequence without assuming a single native read.
.PARAMETER Pipe
Original connected fixture endpoint.
.PARAMETER Count
Exact byte count for this fixture phase.
#>
function Read-ExchangeFixtureBytes($Pipe, [int]$Count) {
    $result = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $chunk = $Pipe.Read($Count - $offset)
        [Array]::Copy($chunk, 0, $result, $offset, $chunk.Length)
        $offset += $chunk.Length
    }
    return ,$result
}

if ($Child) {
    if ($env:ATLASO_CAPTURE_FIXTURE -cne '1' -or [Environment]::CurrentDirectory -cne $FixtureRoot) {
        throw 'The original isolated exchange child environment differs.'
    }
    $intent = Read-ExchangeFixtureReceipt $LaunchIntent $LaunchSha256
    if ($intent.kind -cne 'synthetic-capture-exchange-intent' -or $intent.fixture_root -cne $FixtureRoot -or
        $intent.fixture_sha256 -cne (Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant() -or
        $intent.pipe_sha256 -cne (Get-FileHash -LiteralPath $pipeModule).Hash.ToLowerInvariant()) {
        throw 'The original exchange child launch binding differs.'
    }
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Atlaso.Tests
{
    public static class CaptureExchangeProbe
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(SafeFileHandle process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr process, out long created, out long exited,
            out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeFileHandle process, uint wait);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle OpenJobObjectW(uint access, bool inherit, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(IntPtr process, SafeFileHandle job, out bool member);

        public static long SelfCreation()
        {
            if (!GetProcessTimes(GetCurrentProcess(), out long created, out _, out _, out _) || created <= 0)
                throw new InvalidOperationException("Native fixture self creation time is unavailable.");
            return created;
        }

        public static SafeFileHandle RetainParent(uint pid, long creation)
        {
            SafeFileHandle process = OpenProcess(0x00101000, false, pid);
            try { VerifyParent(process, pid, creation); return process; }
            catch { process.Dispose(); throw; }
        }

        public static void VerifyParent(SafeFileHandle process, uint pid, long creation)
        {
            if (process.IsInvalid || GetProcessId(process) != pid ||
                !GetProcessTimes(process.DangerousGetHandle(), out long actual, out _, out _, out _) ||
                actual != creation || WaitForSingleObject(process, 0) != 258)
                throw new InvalidOperationException("The original live fixture parent differs.");
        }

        public static void VerifySelfJob(string name)
        {
            using (SafeFileHandle job = OpenJobObjectW(4, false, name))
            {
                if (job.IsInvalid || !IsProcessInJob(GetCurrentProcess(), job, out bool member) || !member)
                    throw new InvalidOperationException("The original fixture child job membership differs.");
            }
        }
    }
}
'@

Import-Module $pipeModule
if ($Child) {
    $nonce = [guid]$intent.nonce
    $stem = 'capture-exchange-fixture-' + $nonce.ToString('N')
    $jobName = 'Local\AtlasoRestorationCapture-' + $nonce.ToString('N')
    $parentId = [uint32]$intent.controller_pid
    $parentCreated = [long]$intent.controller_created
    $parentHandle = [Atlaso.Tests.CaptureExchangeProbe]::RetainParent($parentId, $parentCreated)
    try {
        $ownedPath = Join-Path (Split-Path -Parent $LaunchIntent) "$stem-suspended-original.json"
        $owned = Read-ExchangeFixtureReceipt $ownedPath
        if ($owned.kind -cne 'synthetic-capture-exchange-suspended' -or $owned.launch_sha256 -cne $LaunchSha256 -or
            $owned.job -cne $jobName -or $owned.pid -ne $PID -or
            $owned.creation_filetime_utc -ne [Atlaso.Tests.CaptureExchangeProbe]::SelfCreation()) {
            throw 'The original suspended child receipt differs.'
        }
        [Atlaso.Tests.CaptureExchangeProbe]::VerifySelfJob($jobName)
        $deadline = [Atlaso.RestorationPipeDeadline]::new(
            [long]$intent.deadline_counter, [long]$intent.counter_frequency, [DateTimeOffset]$intent.deadline_utc)
        $client = [Atlaso.RestorationCapturePipe]::Open($nonce, $deadline, $parentId)
        try {
            [Atlaso.Tests.CaptureExchangeProbe]::VerifyParent($parentHandle, $parentId, $parentCreated)
            if ([Convert]::ToHexString((Read-ExchangeFixtureBytes $client 3)) -cne '00FF20') {
                throw 'The original synthetic request bytes differ.'
            }
            $client.VerifyPeer($parentId)
            [Atlaso.Tests.CaptureExchangeProbe]::VerifyParent($parentHandle, $parentId, $parentCreated)
            $client.Write([byte[]]@(32, 255, 0))
            if ([Convert]::ToHexString((Read-ExchangeFixtureBytes $client 1)) -cne 'A5') {
                throw 'The original synthetic final byte differs.'
            }
            $client.VerifyPeer($parentId)
            [Atlaso.Tests.CaptureExchangeProbe]::VerifyParent($parentHandle, $parentId, $parentCreated)
        }
        finally { $client.Dispose() }
    }
    finally { $parentHandle.Dispose() }
    return
}

if ($Nonces.Count -ne 2 -or [guid]::Empty -in $Nonces -or $Nonces[0] -eq $Nonces[1]) {
    throw 'The original exchange requires two distinct fixture nonces.'
}
Import-Module $cleanupModule
Import-Module $jobModule
if ([Atlaso.WorkstationFileIdentity]::Get($FixtureRoot) -cne $FixtureIdentity) {
    throw 'The original fixture working directory identity differs.'
}
$pins = [Collections.Generic.List[IDisposable]]::new()
$executable = [Environment]::ProcessPath
try {
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($FixtureRoot, $true, $true))
    foreach ($path in @($executable, $PSCommandPath, $pipeModule, $jobModule)) {
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path))
    }
    $source = git -C $RepositoryRoot rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'The original fixture source could not be read.' }
    $controllerCreated = [Atlaso.Tests.CaptureExchangeProbe]::SelfCreation()
    $fixtureDigest = (Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
    $pipeDigest = (Get-FileHash -LiteralPath $pipeModule).Hash.ToLowerInvariant()
    for ($index = 0; $index -lt $Nonces.Count; $index++) {
        $nonce = $Nonces[$index]
        $stem = 'capture-exchange-fixture-' + $nonce.ToString('N')
        $intentPath = Join-Path $EvidenceRoot "$stem-intent-original.json"
        $frequency = [Diagnostics.Stopwatch]::Frequency
        $end = [Diagnostics.Stopwatch]::GetTimestamp() + $frequency * 15
        $utc = [DateTimeOffset]::UtcNow.AddSeconds(15)
        $intentRecord = New-ExchangeFixtureReceipt $intentPath @{
            kind='synthetic-capture-exchange-intent'; nonce=$nonce.ToString('D'); source_parent=$source
            controller_pid=$PID; controller_created=$controllerCreated; fixture_root=$FixtureRoot
            fixture_identity=$FixtureIdentity; fixture_sha256=$fixtureDigest; pipe_sha256=$pipeDigest
            job_sha256=(Get-FileHash -LiteralPath $jobModule).Hash.ToLowerInvariant()
            image_sha256=(Get-FileHash -LiteralPath $executable).Hash.ToLowerInvariant()
            image_identity=[Atlaso.WorkstationFileIdentity]::Get($executable)
            deadline_counter=$end; counter_frequency=$frequency; deadline_utc=$utc.ToString('O'); case=$index
        }
        $server = $null
        $job = $null
        $publication = [Collections.Generic.List[object]]::new()
        try {
            $deadline = [Atlaso.RestorationPipeDeadline]::new($end, $frequency, $utc)
            $server = [Atlaso.RestorationCapturePipe]::Reserve($nonce, $deadline)
            $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath, '-Child',
                '-RepositoryRoot', $RepositoryRoot, '-FixtureRoot', $FixtureRoot, '-LaunchIntent', $intentPath,
                '-LaunchSha256', $intentRecord.Sha256)
            $job = [Atlaso.RestorationCaptureJob]::Create($nonce, $executable, $arguments, $FixtureRoot, $end, $frequency, $utc)
            $job.PublishAndResume([Action[Atlaso.RestorationCaptureChild]]{
                param($original)
                $publication.Add((New-ExchangeFixtureReceipt (Join-Path $EvidenceRoot "$stem-suspended-original.json") @{
                    kind='synthetic-capture-exchange-suspended'; launch_sha256=$intentRecord.Sha256
                    job=$original.JobName; pid=$original.ProcessId; creation_filetime_utc=$original.CreationFileTimeUtc
                }))
            })
            $ownedRecord = $publication[0]
            $job.VerifyOriginalRunningChild()
            if ($index -eq 0) {
                $server.Connect($job.ProcessId)
                $job.VerifyOriginalRunningChild()
                $server.Write([byte[]]@(0, 255, 32))
                if ([Convert]::ToHexString((Read-ExchangeFixtureBytes $server 3)) -cne '20FF00') {
                    throw 'The original synthetic response bytes differ.'
                }
                $server.VerifyPeer($job.ProcessId)
                $job.VerifyOriginalRunningChild()
                $server.Write([byte[]]@(165))
                $server.RequirePeerClosure()
                $job.WaitForNaturalExit()
            }
            else {
                $refused = $false
                try { $server.Connect($PID) }
                catch {
                    $cause = $_.Exception
                    while ($cause.InnerException) { $cause = $cause.InnerException }
                    if ($cause.Message -cne 'The original pipe peer PID differs.') { throw }
                    $refused = $true
                }
                if (-not $refused) { throw 'The wrong expected client PID was accepted.' }
            }
            $job.Dispose()
            $server.Dispose()
            $terminal = New-ExchangeFixtureReceipt (Join-Path $EvidenceRoot "$stem-terminal-original.json") @{
                kind='synthetic-capture-exchange-terminal'; launch_sha256=$intentRecord.Sha256
                suspended_sha256=$ownedRecord.Sha256; case=$index; actual_job_stop_and_disposal=$true
                natural_exchange=($index -eq 0); wrong_peer_refused_before_transfer=($index -eq 1)
            }
            $terminal.Stream.Dispose()
        }
        finally {
            try { if ($null -ne $job) { $job.Dispose() } }
            finally {
                try { if ($null -ne $server) { $server.Dispose() } }
                finally {
                    foreach ($record in $publication) { $record.Stream.Dispose() }
                    $intentRecord.Stream.Dispose()
                }
            }
        }
    }
}
finally {
    for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Dispose() }
}

Write-Output 'Two original cross-process Windows capture exchange fixtures passed.'
