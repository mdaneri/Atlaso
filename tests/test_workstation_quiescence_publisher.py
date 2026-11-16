"""Exercise the opt-in quiescence callback on synthetic Windows processes."""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows job boundary")


def _ps(value: str | Path) -> str:
    """Quote one public PowerShell literal without expression interpolation.

    Args:
        value: Public path or value to represent as a literal.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _job_name(label: str) -> str:
    """Create a unique public named-job value for one isolated test process.

    Args:
        label: Short stable case label for diagnostic context.
    """
    return f"Local\\Atlaso-Quiescence-{label}-{uuid.uuid4().hex}"


def _run(body: str, directory: Path, *, timeout: int = 25) -> str:
    """Load the production process-job runner and run a synthetic fixture.

    Args:
        body: PowerShell statements for the isolated process-job fixture.
        directory: Originally owned test directory used as the subprocess working directory.
        timeout: Maximum duration for this synthetic PowerShell subprocess.
    """
    setup = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$repository=$env:QUIESCENCE_TEST_REPOSITORY
Import-Module (Join-Path $repository 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $repository 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
"""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", setup + body],
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=directory,
        env={**os.environ, "QUIESCENCE_TEST_REPOSITORY": str(ROOT)},
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def _call(
    job_name: str,
    child: str,
    *,
    timeout_seconds: int = 8,
    deadline: str = "([DateTimeOffset]::UtcNow.AddSeconds(5))",
) -> str:
    """Build one bounded invocation with ordering and public-result checks.

    Args:
        job_name: Unique named job for this fixture subprocess.
        child: Synthetic PowerShell command run by the bounded child.
        timeout_seconds: Maximum process wait duration.
        deadline: PowerShell expression supplying the original absolute deadline.
    """
    return rf"""
$jobName={_ps(job_name)}
$script:runnerFailure=$null
$state=[pscustomobject]@{{Record=$null}}
$events=[Collections.Generic.List[string]]::new()
$ownership={{param($job)
    $events.Add('ownership')
    if($job.RootProcess.HasExited){{throw 'Root exited before durable ownership'}}
}}
$publish={{param($receipt)
    $remainingJob=Open-AtlasoBoundedProcessJob -ProcessJobName $jobName
    if($null -ne $remainingJob){{
        $remainingJob.Dispose()
        throw 'Named job remained open at the public callback boundary'
    }}
    $events.Add('quiescence')
    $state.Record=$receipt
}}.GetNewClosure()
$deadline={deadline}
try {{ Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoProfile','-NonInteractive','-Command',{_ps(child)}) `
    -TimeoutSeconds {timeout_seconds} -DeadlineUtc $deadline -Action 'Synthetic callback fixture' `
    -ProcessJobName $jobName -ProcessOwnershipPublisher $ownership `
    -ProcessQuiescencePublisher $publish }} catch {{ $script:runnerFailure=$_.Exception }}
"""


def test_quiescence_callback_is_after_resume_and_publishes_success(tmp_path: Path) -> None:
    """Publish success once, after durable ownership and empty-job proof.

    Args:
        tmp_path: Originally owned pytest directory for the public child marker.
    """
    marker = tmp_path / "resumed.txt"
    child = f"[IO.File]::WriteAllText({_ps(marker)},'resumed')"
    script = _call(_job_name("success"), child)
    script += rf"""
if($events.Count -ne 2 -or $events[0] -cne 'ownership' -or $events[1] -cne 'quiescence'){{
    throw 'Callback ordering changed'
}}
if(-not (Test-Path -LiteralPath {_ps(marker)})){{throw 'Child did not resume after ownership'}}
if($null -ne $script:runnerFailure){{throw 'Successful child produced a runner failure'}}
$record=$state.Record
if($record.Schema -ne 1 -or $record.ProcessJobName -cne $jobName -or $record.RootProcessId -le 0 -or
   $record.WholeJobEmpty -ne $true -or $record.Outcome -cne 'succeeded' -or
   $record.RootExitCode -ne 0){{throw 'Success receipt fields differ'}}
$parsedStart=[DateTimeOffset]::MinValue
if(-not [DateTimeOffset]::TryParse([string]$record.RootStartTimeUtc,[ref]$parsedStart) -or
   $parsedStart.Offset -ne [TimeSpan]::Zero){{throw 'Start time is not round-trip UTC'}}
$parsedDeadline=[DateTimeOffset]::MinValue
if(-not [DateTimeOffset]::TryParse([string]$record.DeadlineUtc,[ref]$parsedDeadline) -or
   $parsedDeadline -ne $deadline){{throw 'Deadline was not preserved as round-trip UTC'}}
Write-Output 'success-receipt-after-quiescence'
"""
    output = _run(script, tmp_path)
    assert "success-receipt-after-quiescence" in output


@pytest.mark.parametrize(
    ("name", "command", "expected_exit", "expected_outcome"),
    [
        ("nonzero", "exit 7", 7, "terminated_failure"),
        ("timeout", "Start-Sleep -Seconds 20", None, "terminated_failure"),
    ],
)
def test_quiescence_callback_classifies_terminated_failure(
    tmp_path: Path, name: str, command: str, expected_exit: int | None, expected_outcome: str
) -> None:
    """Distinguish submitted failure and deadline termination after job empties.

    Args:
        tmp_path: Originally owned pytest directory for the synthetic subprocess.
        name: Stable suffix identifying the failure case.
        command: Child PowerShell command that fails or overruns its deadline.
        expected_exit: Expected root exit code for the ordinary failure case.
        expected_outcome: Public receipt outcome expected after whole-job proof.
    """
    job_name = _job_name(name)
    script = _call(
        job_name,
        command,
        timeout_seconds=1 if name == "timeout" else 8,
        deadline=(
            "([DateTimeOffset]::UtcNow.AddMilliseconds(300))"
            if name == "timeout"
            else "([DateTimeOffset]::UtcNow.AddSeconds(5))"
        ),
    )
    script += rf"""
if($events.Count -ne 2 -or $events[1] -cne 'quiescence'){{throw 'Callback was missing or repeated'}}
$record=$state.Record
if($null -eq $script:runnerFailure -or
   $script:runnerFailure.Data['AtlasoProcessTreeTerminationProven'] -ne $true){{
    throw 'Failure did not retain the whole-job proof'
}}
if($record.WholeJobEmpty -ne $true -or $record.Outcome -cne {_ps(expected_outcome)}){{throw 'Failure was mislabeled'}}
if($null -eq $record.RootExitCode){{throw 'Root exit code was not captured'}}
"""
    if expected_exit is not None:
        script += f"if($record.RootExitCode -ne {expected_exit}){{throw 'Root exit code changed'}}\n"
    else:
        script += "if($record.RootExitCode -eq 0){throw 'Timed out process was reported successful'}\n"
    script += "Write-Output 'terminated-failure-receipt'"
    assert "terminated-failure-receipt" in _run(script, tmp_path, timeout=22)


def test_ownership_publication_failure_stops_suspended_root_before_callback(tmp_path: Path) -> None:
    """Do not resume a root whose original process ownership was not published.

    Args:
        tmp_path: Originally owned pytest directory for the never-run child marker.
    """
    marker = tmp_path / "must-not-run.txt"
    script = rf"""
$jobName={_ps(_job_name('ownership'))}
$count=[pscustomobject]@{{Value=0}}
$ownership={{param($job) throw 'Synthetic ownership write failed'}}
$quiescence={{param($receipt) $count.Value++}}.GetNewClosure()
$refused=$false
try{{Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
  -ArgumentList @('-NoProfile','-NonInteractive','-Command',{_ps(f"[IO.File]::WriteAllText('{marker}','ran')")}) `
  -TimeoutSeconds 8 -DeadlineUtc ([DateTimeOffset]::UtcNow.AddSeconds(5)) -Action 'Synthetic ownership fixture' `
  -ProcessJobName $jobName -ProcessOwnershipPublisher $ownership -ProcessQuiescencePublisher $quiescence}}
catch{{$refused=$true}}
if(-not $refused -or (Test-Path -LiteralPath {_ps(marker)})){{
    throw 'Ownership failure allowed the suspended root to run'
}}
if($count.Value -ne 1){{throw 'Quiescence callback was not emitted once after proven termination'}}
Write-Output 'suspended-root-preserved'
"""
    assert "suspended-root-preserved" in _run(script, tmp_path)


def test_ownership_write_error_is_stopping_even_under_continue_policy(tmp_path: Path) -> None:
    """Treat a nonterminating ownership error as a refusal before root resume.

    Args:
        tmp_path: Originally owned pytest directory for the never-run child marker.
    """
    marker = tmp_path / "ownership-write-error.txt"
    script = rf"""
$ErrorActionPreference='Continue'
$jobName={_ps(_job_name('ownership-error'))}
$count=[pscustomobject]@{{Value=0}}
$ownership={{param($job) Write-Error 'synthetic ownership publication error'}}
$quiescence={{param($receipt) $count.Value++}}.GetNewClosure()
try {{ Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
  -ArgumentList @('-NoProfile','-NonInteractive','-Command',{_ps(f"[IO.File]::WriteAllText('{marker}','ran')")}) `
  -TimeoutSeconds 8 -DeadlineUtc ([DateTimeOffset]::UtcNow.AddSeconds(5)) -Action 'Synthetic ownership error' `
  -ProcessJobName $jobName -ProcessOwnershipPublisher $ownership -ProcessQuiescencePublisher $quiescence }}
catch {{ $script:runnerFailure=$_.Exception }}
if(Test-Path -LiteralPath {_ps(marker)}){{throw 'Ownership Write-Error allowed the root to resume'}}
if($count.Value -ne 1 -or $null -eq $script:runnerFailure -or
   $script:runnerFailure.Data['AtlasoProcessTreeTerminationProven'] -ne $true){{
    throw 'Nonterminating ownership failure was not contained and recorded'
}}
Write-Output 'ownership-write-error-contained'
"""
    assert "ownership-write-error-contained" in _run(script, tmp_path)


def test_lingering_descendant_never_produces_success_receipt(tmp_path: Path) -> None:
    """Keep a surviving descendant inside the job until the runner terminates it.

    Args:
        tmp_path: Originally owned pytest directory for the synthetic job.
    """
    child = (
        "Start-Process -FilePath (Get-Process -Id $PID).Path "
        "-WindowStyle Hidden -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') | Out-Null"
    )
    script = _call(
        _job_name("descendant"),
        child,
        timeout_seconds=8,
    )
    script += r"""
$record=$state.Record
if($events[-1] -cne 'quiescence' -or $record.WholeJobEmpty -ne $true -or $record.Outcome -cne 'terminated_failure'){
 throw 'Lingering descendant was accepted as normal success'
}
if($record.RootExitCode -ne 0 -or $null -eq $script:runnerFailure -or
   $script:runnerFailure.Message -notmatch 'descendants remained'){
 throw 'Fixture did not exercise normal root exit with a surviving descendant'
}
Write-Output 'descendant-terminated-before-receipt'
"""
    assert "descendant-terminated-before-receipt" in _run(script, tmp_path, timeout=22)


def test_callback_failure_is_not_retried_and_retains_quiescence_fact(tmp_path: Path) -> None:
    """Surface durable receipt failure without retrying or losing empty-job proof.

    Args:
        tmp_path: Originally owned pytest directory for the synthetic process.
    """
    script = rf"""
$jobName={_ps(_job_name('publish-failure'))}
$calls=[pscustomobject]@{{Value=0}}
$ownership={{param($job)}}
$quiescence={{param($receipt) $calls.Value++; throw 'synthetic durable writer failure'}}.GetNewClosure()
$failure=$null
try{{Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
  -ArgumentList @('-NoProfile','-NonInteractive','-Command','exit 0') -TimeoutSeconds 8 `
  -DeadlineUtc ([DateTimeOffset]::UtcNow.AddSeconds(5)) -Action 'Synthetic callback fixture' `
  -ProcessJobName $jobName -ProcessOwnershipPublisher $ownership -ProcessQuiescencePublisher $quiescence}}
catch{{$failure=$_.Exception}}
if($calls.Value -ne 1 -or $null -eq $failure){{throw 'Failed callback was retried or ignored'}}
if($failure.Data['AtlasoProcessTreeTerminationProven'] -ne $true -or
   $failure.Data['AtlasoQuiescencePublicationFailed'] -ne $true){{
    throw 'Quiescence or publication failure was lost'
}}
Write-Output 'callback-failed-once'
"""
    assert "callback-failed-once" in _run(script, tmp_path)


def test_callback_write_error_is_fatal_and_not_retried_under_continue_policy(tmp_path: Path) -> None:
    """Turn a nonterminating receipt-writer error into one fail-closed result.

    Args:
        tmp_path: Originally owned pytest directory for the synthetic process.
    """
    script = rf"""
$ErrorActionPreference='Continue'
$jobName={_ps(_job_name('callback-error'))}
$calls=[pscustomobject]@{{Value=0}}
$ownership={{param($job)}}
$quiescence={{param($receipt) $calls.Value++; Write-Error 'synthetic receipt writer error'}}.GetNewClosure()
try{{Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
  -ArgumentList @('-NoProfile','-NonInteractive','-Command','exit 0') -TimeoutSeconds 8 `
  -DeadlineUtc ([DateTimeOffset]::UtcNow.AddSeconds(5)) -Action 'Synthetic callback error' `
  -ProcessJobName $jobName -ProcessOwnershipPublisher $ownership -ProcessQuiescencePublisher $quiescence}}
catch{{$script:runnerFailure=$_.Exception}}
if($calls.Value -ne 1 -or $null -eq $script:runnerFailure -or
   $script:runnerFailure.Data['AtlasoProcessTreeTerminationProven'] -ne $true -or
   $script:runnerFailure.Data['AtlasoQuiescencePublicationFailed'] -ne $true){{
    throw 'Callback Write-Error was retried or failed open'
}}
Write-Output 'callback-write-error-failed-closed'
"""
    assert "callback-write-error-failed-closed" in _run(script, tmp_path)


def test_late_zero_exit_after_resume_is_terminated_failure(tmp_path: Path) -> None:
    """Refuse an exit-zero root whose original ExitTime exceeds its deadline.

    Args:
        tmp_path: Originally owned pytest subprocess working directory.
    """
    script = r"""
Add-Type -TypeDefinition @'
using System;
using System.Threading;
public sealed class SyntheticTimedRoot {
 private DateTime exitTime = DateTime.MinValue;
 public bool HasExited { get { return exitTime != DateTime.MinValue; } }
 public int ExitCode { get { return 0; } }
 public int Id { get { return 5432; } }
 public DateTime StartTime { get; } = DateTime.UtcNow;
 public DateTime ExitTime { get { return exitTime == DateTime.MinValue ? DateTime.UtcNow : exitTime; } }
 public bool WaitForExit(int milliseconds) { return HasExited; }
 public void MarkLateExit() { Thread.Sleep(800); exitTime = DateTime.UtcNow; }
 public void Dispose() { }
}
public sealed class SyntheticTimedJob : IDisposable {
 public SyntheticTimedRoot RootProcess { get; } = new SyntheticTimedRoot();
 public void Resume() { RootProcess.MarkLateExit(); }
 public int[] GetActiveProcessIds() { return Array.Empty<int>(); }
 public void TerminateAndWait(int milliseconds) { throw new InvalidOperationException("unexpected termination"); }
 public void Dispose() { }
}
'@
function New-AtlasoBoundedProcessJob {
 param($FilePath,$ArgumentList,$ProcessJobName,$DeferResume,$DiscardOutput)
 return [SyntheticTimedJob]::new()
}
function Complete-AtlasoBoundedProcessTree { param($Process,$Job,$Action) }
$jobName='Local\Atlaso-Quiescence-LateExit-'+'j'*16
$state=[pscustomobject]@{Record=$null}
$publisher={param($receipt) $state.Record=$receipt}.GetNewClosure()
$deadline=[DateTimeOffset]::UtcNow.AddMilliseconds(500)
try { Invoke-AtlasoBoundedStreamingProcess -FilePath 'unused' -ArgumentList @('synthetic') -TimeoutSeconds 1 `
  -DeadlineUtc $deadline -Action 'Synthetic late exit' -ProcessJobName $jobName `
  -ProcessOwnershipPublisher {param($job)} -ProcessQuiescencePublisher $publisher }
catch { $script:runnerFailure=$_.Exception }
$record=$state.Record
if($null -eq $record -or $record.RootExitCode -ne 0 -or $record.Outcome -cne 'terminated_failure' -or
   $record.WholeJobEmpty -ne $true) { throw 'Late exit zero was accepted as success' }
if($null -eq $script:runnerFailure -or
   $script:runnerFailure.Data['AtlasoProcessTreeTerminationProven'] -ne $true) {
    throw 'Late exit refusal lacks the quiescence proof'
}
Write-Output 'late-exit-zero-refused'
"""
    assert "late-exit-zero-refused" in _run(script, tmp_path)


@pytest.mark.parametrize(
    "parameters",
    [
        "-ProcessOwnershipPublisher {param($job)} -DeadlineUtc ([DateTimeOffset]::UtcNow.AddSeconds(5)) "
        "-ProcessQuiescencePublisher {param($receipt)}",
        "-ProcessJobName ('Local\\Atlaso-Partial-'+[guid]::NewGuid().ToString('N')) "
        "-DeadlineUtc ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ProcessQuiescencePublisher {param($receipt)}",
        (
            "-ProcessJobName ('Local\\Atlaso-Partial-'+[guid]::NewGuid().ToString('N')) "
            "-ProcessOwnershipPublisher {param($job)} -ProcessQuiescencePublisher {param($receipt)}"
        ),
        "-ProcessJobName ('Local\\Atlaso-Partial-'+[guid]::NewGuid().ToString('N')) "
        "-ProcessOwnershipPublisher {param($job)} -DeadlineUtc ([DateTimeOffset]::UtcNow.AddSeconds(-1)) "
        "-ProcessQuiescencePublisher {param($receipt)}",
    ],
)
def test_partial_quiescence_opt_in_refuses_before_child_creation(tmp_path: Path, parameters: str) -> None:
    """Reject incomplete callback admission before starting a synthetic child.

    Args:
        tmp_path: Originally owned pytest directory for the never-run child marker.
        parameters: Incomplete callback options that must be refused at preflight.
    """
    marker = tmp_path / "partial-opt-in.txt"
    script = rf"""
$refused=$false
try{{Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
  -ArgumentList @('-NoProfile','-NonInteractive','-Command',{_ps(f"[IO.File]::WriteAllText('{marker}','ran')")}) `
  -TimeoutSeconds 8 -Action 'Synthetic partial opt-in' {parameters}}}
catch{{$refused=$true}}
if(-not $refused -or (Test-Path -LiteralPath {_ps(marker)})){{throw 'Partial opt-in started a process'}}
Write-Output 'partial-opt-in-refused'
"""
    assert "partial-opt-in-refused" in _run(script, tmp_path)


def test_unproven_fake_job_never_invokes_quiescence_callback(tmp_path: Path) -> None:
    """Fail closed when even the runner cannot prove job termination.

    Args:
        tmp_path: Originally owned pytest subprocess working directory.
    """
    script = r"""
Add-Type -TypeDefinition @'
using System;
public sealed class SyntheticRoot {
 public bool HasExited { get { return false; } }
 public int ExitCode { get { return -1; } }
 public int Id { get { return 4321; } }
 public DateTime StartTime { get { return DateTime.UtcNow; } }
 public bool WaitForExit(int milliseconds) { return false; }
 public void Dispose() { }
}
public sealed class SyntheticJob : IDisposable {
 public SyntheticRoot RootProcess { get; } = new SyntheticRoot();
 public void TerminateAndWait(int milliseconds) { throw new InvalidOperationException("job remains active"); }
 public void Resume() { }
 public int[] GetActiveProcessIds() { return Array.Empty<int>(); }
 public void Dispose() { }
}
'@
function New-AtlasoBoundedProcessJob {
 param($FilePath,$ArgumentList,$ProcessJobName,$DeferResume,$DiscardOutput)
 return [SyntheticJob]::new()
}
$jobName='Local\Atlaso-Quiescence-Unproven-'+'g'*16
$called=$false
$failure=$null
try{Invoke-AtlasoBoundedStreamingProcess -FilePath 'unused' -ArgumentList @('synthetic') -TimeoutSeconds 1 `
 -DeadlineUtc ([DateTimeOffset]::UtcNow.AddMilliseconds(100)) -Action 'Synthetic unproven job' `
 -ProcessJobName $jobName -ProcessOwnershipPublisher {param($job)} -ProcessQuiescencePublisher {$script:called=$true}}
catch{$failure=$_.Exception}
if($called -or $null -eq $failure -or $failure.Data['AtlasoProcessTreeTerminationUnproven'] -ne $true){
 throw 'Unproven job published a receipt'
}
Write-Output 'unproven-job-refused'
"""
    assert "unproven-job-refused" in _run(script, tmp_path)


@pytest.mark.parametrize("mode", ["success", "nonzero", "descendant"])
def test_legacy_runner_without_quiescence_publisher_retains_behavior(tmp_path: Path, mode: str) -> None:
    """Preserve ordinary success, failure and descendant cleanup for existing callers.

    Args:
        tmp_path: Originally owned pytest subprocess working directory.
        mode: Legacy root exit or surviving-descendant scenario.
    """
    child = "exit 7" if mode == "nonzero" else "exit 0"
    if mode == "descendant":
        child = (
            "Start-Process -FilePath (Get-Process -Id $PID).Path -WindowStyle Hidden "
            "-ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') | Out-Null"
        )
    script = rf"""
$failure=$null
try {{ Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
 -ArgumentList @('-NoProfile','-NonInteractive','-Command',{_ps(child)}) `
 -TimeoutSeconds 8 -Action 'Synthetic legacy fixture' }}
catch {{ $failure=$_.Exception }}
"""
    if mode == "nonzero":
        script += r"""
if($null -eq $failure -or $failure.Data['AtlasoProcessTreeTerminationProven'] -ne $true -or
   $failure.Data['AtlasoProcessExitCode'] -ne 7){throw 'Legacy nonzero classification changed'}
"""
    else:
        script += "if($null -ne $failure){throw 'Legacy success or descendant completion changed'}\n"
    script += "Write-Output 'legacy-contract-preserved'"
    assert "legacy-contract-preserved" in _run(script, tmp_path)
