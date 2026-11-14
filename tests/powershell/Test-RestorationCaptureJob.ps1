<#
.SYNOPSIS
Exercise original suspended-child ownership and the independent watchdog with local Windows fixtures.
.PARAMETER RepositoryRoot
Exact source root containing the job primitive.
.PARAMETER TestRoot
Fresh original fixture directory containing the synthetic child outputs.
.PARAMETER TestRootIdentity
Native identity recorded before fixture use.
.PARAMETER EvidenceRoot
Original evidence directory outside the fixture root.
.PARAMETER Nonces
Five distinct original fixture nonces receipted before any child creation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][string]$TestRoot,
    [Parameter(Mandatory)][string]$TestRootIdentity,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [Parameter(Mandatory)][guid[]]$Nonces
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $Nonces.Count -ne 5 -or [guid]::Empty -in $Nonces -or
    @($Nonces | Sort-Object -Unique).Count -ne $Nonces.Count) {
    throw 'The fixture requires five original distinct nonces.'
}
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1')
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.RestorationCaptureJob.psm1')

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Atlaso.Tests
{
    public static class RestorationJobAccessProbe
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle OpenJobObjectW(uint access, bool inherit, string name);

        public static SafeFileHandle Query(string name) => OpenJobObjectW(4, false, name);

        public static int OpenError(string name, uint access)
        {
            using (SafeFileHandle job = OpenJobObjectW(access, false, name))
                return job.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
    }
}
'@

<#
.SYNOPSIS
Flush one immutable synthetic fixture receipt outside the fixture root.
.PARAMETER Name
New receipt filename.
.PARAMETER Value
Public fixture identity or outcome.
#>
function Write-CaptureJobFixtureReceipt([string]$Name, $Value) {
    $stream = [IO.File]::Open((Join-Path $EvidenceRoot $Name), 'CreateNew', 'Write', 'Read')
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 8))
        $stream.Write($bytes)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

<#
.SYNOPSIS
Require a named failure without accepting a different underlying exception.
.PARAMETER Action
Operation expected to refuse.
.PARAMETER Expected
Allowed sanitized exception message patterns for the case.
#>
function Assert-CaptureJobRefusal([scriptblock]$Action, [string[]]$Expected) {
    try { & $Action | Out-Null }
    catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        foreach ($pattern in $Expected) {
            if ($cause.Message -like $pattern) { return }
        }
        throw
    }
    throw 'The capture job operation unexpectedly succeeded.'
}

$executable = [Environment]::ProcessPath
$source = git -C $RepositoryRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or [Atlaso.WorkstationFileIdentity]::Get($TestRoot) -cne $TestRootIdentity) {
    throw 'Original job fixture source or directory differs.'
}
$rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($TestRoot, $true, $true)
$imagePin = $null
$prior = [Environment]::GetEnvironmentVariable('ATLASO_CAPTURE_AMBIENT_SENTINEL', 'Process')
try {
    $imagePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($executable)
    $imageIdentity = [Atlaso.WorkstationFileIdentity]::Get($executable)
    $imageSha256 = (Get-FileHash -LiteralPath $executable).Hash.ToLowerInvariant()
    [Environment]::SetEnvironmentVariable('ATLASO_CAPTURE_AMBIENT_SENTINEL', 'synthetic-fixture-only', 'Process')
    $commands = @(
        'exit 0',
        'exit 7',
        'exit 0',
        'Start-Sleep -Seconds 30',
        '$p=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath);$p.UseShellExecute=$false;$p.CreateNoWindow=$true;$p.ArgumentList.Add("-NoProfile");$p.ArgumentList.Add("-Command");$p.ArgumentList.Add("Start-Sleep -Seconds 30");$descendant=[Diagnostics.Process]::Start($p);if ($null -eq $descendant){exit 8};$descendant.Dispose();$d=[IO.File]::Open("@DESCENDANT@", "CreateNew", "Write", "Read");try{$d.WriteByte(1);$d.Flush($true)}finally{$d.Dispose()};exit 0'
    )
    $childTemplate = @'
if ([Environment]::CurrentDirectory -cne '@DIRECTORY@' -or
    $env:ATLASO_CAPTURE_FIXTURE -cne '1' -or
    $env:ATLASO_CAPTURE_AMBIENT_SENTINEL -or
    $env:TEMP -cne '@DIRECTORY@' -or $env:TMP -cne '@DIRECTORY@' -or
    -not [IO.File]::Exists('@RECEIPT@')) { exit 9 }
$f = [IO.File]::Open('@MARKER@', 'CreateNew', 'Write', 'Read')
try { $f.WriteByte(1); $f.Flush($true) } finally { $f.Dispose() }
@COMMAND@
'@
    $budgets = @(5000, 5000, 1100, 1700, 2700)
    for ($index = 0; $index -lt $Nonces.Count; $index++) {
        $nonce = $Nonces[$index]
        $stem = 'capture-job-fixture-' + $nonce.ToString('N')
        $marker = "$stem.ran"
        $ownedReceipt = "$stem-suspended-original.json"
        $markerPath = Join-Path $TestRoot $marker
        $descendantPath = "$markerPath.descendant"
        if ((Test-Path -LiteralPath $markerPath) -or (Test-Path -LiteralPath $descendantPath)) {
            throw 'The original fixture marker already exists.'
        }
        $directoryLiteral = $TestRoot.Replace("'", "''")
        $receiptLiteral = (Join-Path $EvidenceRoot $ownedReceipt).Replace("'", "''")
        $child = $childTemplate.Replace('@DIRECTORY@', $directoryLiteral).Replace('@RECEIPT@', $receiptLiteral).
            Replace('@MARKER@', $marker).Replace('@COMMAND@', $commands[$index]).Replace('@DESCENDANT@', "$marker.descendant")
        $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $child)
        $frequency = [Diagnostics.Stopwatch]::Frequency
        $end = [Diagnostics.Stopwatch]::GetTimestamp() + [long]($frequency * $budgets[$index] / 1000)
        $utc = [DateTimeOffset]::UtcNow.AddMilliseconds($budgets[$index])
        Write-CaptureJobFixtureReceipt "$stem-intent-original.json" @{
            source_parent=$source; task=$env:CODEX_THREAD_ID; nonce=$nonce; original_root=$TestRootIdentity
            controller_pid=$PID; executable=$executable; image_identity=$imageIdentity; image_sha256=$imageSha256
            case=$index; deadline_utc=$utc.ToString('O')
            deadline_counter=$end; counter_frequency=$frequency; marker_absent=$true; local_synthetic_only=$true
        }
        $job = [Atlaso.RestorationCaptureJob]::Create($nonce, $executable, $arguments, $TestRoot, $end, $frequency, $utc)
        $query = $null
        try {
            if ($job.ProcessId -le 0 -or $job.ProcessId -eq $PID -or $job.CreationFileTimeUtc -le 0) {
                throw 'The original native root identity differs.'
            }
            $query = [Atlaso.Tests.RestorationJobAccessProbe]::Query($job.Name)
            if ($query.IsInvalid) { throw 'The original named job could not be opened for query.' }
            foreach ($access in @(1, 2, 8, 0x40000, 0x80000)) {
                if ([Atlaso.Tests.RestorationJobAccessProbe]::OpenError($job.Name, $access) -ne 5) {
                    throw 'The original named job granted mutation access.'
                }
            }
            $publish = [Action[Atlaso.RestorationCaptureChild]]{
                param($original)
                if ($index -eq 2) {
                    Start-Sleep -Milliseconds 1600
                    if (-not $job.OriginalJobStopped()) {
                        throw 'The independent watchdog left the suspended original root active.'
                    }
                }
                if (Test-Path -LiteralPath $markerPath) { throw 'The fixture child ran before original publication.' }
                Write-CaptureJobFixtureReceipt $ownedReceipt @{
                    source_parent=$source; nonce=$nonce; job=$original.JobName; pid=$original.ProcessId
                    creation_filetime_utc=$original.CreationFileTimeUtc; controller_pid=$PID
                    suspended_before_publication=$true; local_synthetic_only=$true
                }
            }
            switch ($index) {
                0 { $job.PublishAndResume($publish); $job.WaitForNaturalExit() }
                1 {
                    $job.PublishAndResume($publish)
                    Assert-CaptureJobRefusal { $job.WaitForNaturalExit() } '*did not exit successfully*'
                }
                2 {
                    Assert-CaptureJobRefusal { $job.PublishAndResume($publish) } '*cannot resume*'
                    if (Test-Path -LiteralPath $markerPath) { throw 'The late publisher resumed its original child.' }
                }
                3 {
                    $job.PublishAndResume($publish)
                    Start-Sleep -Milliseconds 2200
                    if (-not $job.OriginalJobStopped()) { throw 'The independent watchdog left the running job active.' }
                    Assert-CaptureJobRefusal { $job.WaitForNaturalExit() } '*cannot complete naturally*'
                }
                4 {
                    $job.PublishAndResume($publish)
                    Assert-CaptureJobRefusal { $job.WaitForNaturalExit() } @('*deadline elapsed*', '*cannot complete naturally*')
                    if (-not [IO.File]::Exists($descendantPath) -or
                        [Diagnostics.Stopwatch]::GetTimestamp() + [long]($frequency / 1000) -lt $end) {
                        throw 'The original descendant or deadline evidence differs.'
                    }
                }
            }
            if ($index -ne 2 -and -not [IO.File]::Exists($markerPath)) {
                throw 'The original isolated child did not produce its fixture marker.'
            }
            $job.Dispose()
            Write-CaptureJobFixtureReceipt "$stem-terminal-original.json" @{
                source_parent=$source; case=$index; nonce=$nonce; natural_success=($index -eq 0)
                watchdog_joined=$true; original_job_empty=$true; handles_closed=$true
                separate_query_handle_still_held=$true; synthetic_only=$true
            }
        }
        finally {
            try { $job.Dispose() }
            finally { if ($null -ne $query) { $query.Dispose() } }
        }
    }
}
finally {
    [Environment]::SetEnvironmentVariable('ATLASO_CAPTURE_AMBIENT_SENTINEL', $prior, 'Process')
    if ($null -ne $imagePin) { $imagePin.Dispose() }
    $rootPin.Dispose()
}

Write-Output 'Five original local Windows capture job fixtures passed.'
