"""Exercise native refresh publication and live-consumer refusal without VMware."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/windows/vmware/invoke-installation-refresh.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Native Windows job checks")


def _run(script: str, directory: Path) -> str:
    """Run a focused PowerShell snippet against the checked-in refresh functions.

    Args:
        script: PowerShell statements to evaluate after importing the helpers.
        directory: Isolated working directory exposed to the script.
    """
    setup = r"""
$ErrorActionPreference='Stop'
$repository=$env:REFRESH_TEST_REPOSITORY
$directory=$env:REFRESH_TEST_DIRECTORY
Import-Module (Join-Path $repository 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $repository 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repository 'scripts/windows/vmware/invoke-installation-refresh.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parser failed'}
foreach($function in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
 Invoke-Expression $function.Extent.Text
}
"""
    result = subprocess.run(["pwsh", "-NoProfile", "-Command", setup + script], text=True, capture_output=True,
                            timeout=60, env={**os.environ, "REFRESH_TEST_REPOSITORY": str(ROOT),
                                             "REFRESH_TEST_DIRECTORY": str(directory)})
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_native_evidence_publisher_never_replaces_original_and_rejects_oversize(tmp_path):
    """Keep original evidence immutable and reject oversized records.

    Args:
        tmp_path: Isolated directory for durable-evidence fixtures.
    """
    output = _run(r"""
Write-InstallationRefreshEvidence -Directory $directory -Name 'original.json' -Record @{value='original'}
$before=(Get-FileHash -LiteralPath (Join-Path $directory 'original.json')).Hash
$refused=$false
try{Write-InstallationRefreshEvidence -Directory $directory -Name 'original.json' -Record @{value='replacement'}}catch{$refused=$true}
if(-not $refused -or (Get-FileHash -LiteralPath (Join-Path $directory 'original.json')).Hash -cne $before){throw 'Original publication changed'}
$refused=$false
try{Write-InstallationRefreshEvidence -Directory $directory -Name 'oversize.json' -Record @{value=('x'*65536)}}catch{$refused=$true}
if(-not $refused -or (Test-Path -LiteralPath (Join-Path $directory 'oversize.json'))){throw 'Oversize record accepted'}
Write-Output 'original-preserved'
""", tmp_path)
    assert "original-preserved" in output


def test_live_original_child_is_refused_and_not_stopped_by_reconciliation(tmp_path):
    """Refuse reconciliation while an original consumer remains active.

    Args:
        tmp_path: Isolated directory for child and phase evidence.
    """
    output = _run(r"""
$jobName='Local\Atlaso-RefreshFixture-'+[guid]::NewGuid().ToString('N')
$job=New-AtlasoBoundedProcessJob -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile','-Command','Start-Sleep -Seconds 30') -ProcessJobName $jobName -DeferResume
try{
 $child=$job.RootProcess
 Write-InstallationRefreshEvidence -Directory $directory -Name 'drift-child.json' -Record @{phase='drift';plan_sha256=('a'*64);pid=$child.Id;start_filetime_utc=$child.StartTime.ToUniversalTime().ToFileTimeUtc();job_name=$jobName}
 Write-InstallationRefreshEvidence -Directory $directory -Name 'drift-result.json' -Record @{plan_sha256=('a'*64);whole_job_quiescent=$true}
 $refused=$false
 try{Assert-InstallationRefreshConsumersQuiescent -Directory $directory -PlanSha256 ('a'*64)}catch{$refused=$true}
 if(-not $refused -or -not $job.ContainsProcess($child) -or $child.HasExited){throw 'Active original child was altered or admitted'}
 Write-Output 'active-original-preserved'
}finally{
 $job.TerminateAndWait(10000)
 $job.Dispose()
}
""", tmp_path)
    assert "active-original-preserved" in output


def test_absolute_deadline_includes_suspended_child_publication(tmp_path):
    """Count ownership-publication time against the original process deadline.

    Args:
        tmp_path: Isolated directory for the bounded-process job fixture.
    """
    output = _run(r"""
$jobName='Local\Atlaso-RefreshDeadlineFixture-'+[guid]::NewGuid().ToString('N')
$publisher={param($Job) Start-Sleep -Milliseconds 300}
$watch=[Diagnostics.Stopwatch]::StartNew()
$refused=$false
try{
 Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile','-Command','Start-Sleep -Seconds 30') -TimeoutSeconds 30 -DeadlineUtc ([DateTimeOffset]::UtcNow.AddMilliseconds(150)) -Action 'Synthetic deadline fixture' -ProcessJobName $jobName -ProcessOwnershipPublisher $publisher
}catch{
 $refused=$_.Exception.Data['AtlasoProcessTreeTerminationProven'] -eq $true
}
if(-not $refused -or $watch.Elapsed.TotalSeconds -gt 10){throw 'Publication extended the absolute phase deadline'}
$remaining=Open-AtlasoBoundedProcessJob -ProcessJobName $jobName
if($remaining){try{if(@($remaining.GetActiveProcessIds()).Count){throw 'Deadline fixture left live descendants'}}finally{$remaining.Dispose()}}
Write-Output 'absolute-deadline-preserved'
""", tmp_path)
    assert "absolute-deadline-preserved" in output
