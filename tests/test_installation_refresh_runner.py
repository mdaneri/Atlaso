"""Exercise native refresh publication and live-consumer refusal without VMware."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
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


def test_output_creation_callback_resolves_evidence_writer_from_closure(tmp_path):
    """Invoke the launcher's exact output callback through its actual closure.

    Args:
        tmp_path: Receipted pytest fixture directory for original evidence.
    """
    output = _run(r"""
$assignment=$ast.FindAll({param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -ceq '$callback' -and
    $node.Right.Extent.Text.Contains('output-native-original.json')
},$true)
if($assignment.Count -ne 1){throw 'Expected one canonical output creation callback'}
$stateDirectory=$directory
$taskId='01a19320-0e85-76f0-a1ba-e68ff3ac6d71'
$planValue=@{installer_commit=('b'*40)}
$planHash='a'*64
$writeEvidence=${function:Write-InstallationRefreshEvidence}
Invoke-Expression $assignment[0].Extent.Text
& $callback (Join-Path $directory 'output') 'native-directory-identity'
$record=Read-InstallationRefreshEvidence -Path (Join-Path $directory 'output-native-original.json')
if($record.task_id -cne $taskId -or $record.plan_sha256 -cne $planHash -or
   $record.native_identity -cne 'native-directory-identity') { throw 'Closure published different original evidence' }
Write-Output 'captured-evidence-writer'
""", tmp_path)
    assert "captured-evidence-writer" in output


@pytest.mark.parametrize("use_venv,unsafe_descendant", [(False, False), (True, False), (True, True)])
def test_script_initialize_and_worker_run_under_the_original_job(tmp_path, use_venv, unsafe_descendant):
    """Invoke the copied production launcher with a real venv and named Windows job.

    The fixture uses an isolated synthetic task identity when CI has no Codex
    task, and stubs only source-checkout admission and the ISO phase protocol;
    the production PowerShell launcher, filesystem publisher, process job,
    interpreter probe and Python native-child admission remain active.

    Args:
        tmp_path: Receipted pytest fixture directory for the bounded source copy and evidence.
        use_venv: Exercise the redirector rather than the base interpreter directly.
        unsafe_descendant: Refuse an extra generation and prove whole-job cleanup.
    """
    task_id = os.environ.get("CODEX_THREAD_ID") or str(uuid.uuid4())
    fixture = tmp_path / "fixture"
    worktree = fixture / "worktree"
    vmware = worktree / "scripts" / "windows" / "vmware"
    shutil.copytree(ROOT / "scripts", worktree / "scripts", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in (
        "Atlaso.WorkstationCleanup.psm1", "Atlaso.WorkstationFirstBoot.ps1",
        "Atlaso.WorkstationLanSegments.ps1", "Atlaso.LifecycleOwnership.ps1",
    ):
        shutil.copy2(ROOT / "scripts/windows/vmware" / name, vmware / name)
    shutil.copy2(RUNNER, vmware / RUNNER.name)
    (vmware / "Atlaso.TestVmOwnership.ps1").write_text(
        """<#
.SYNOPSIS
Admit only the synthetic fixture checkout used by this process boundary test.
.PARAMETER Context
Synthetic source context; no infrastructure is created by this fixture.
#>
function Assert-AtlasoTestVmCheckoutSource { param([psobject]$Context) }
function git {
    $global:LASTEXITCODE=0
    if($args[-1] -ceq '--show-current'){Write-Output 'codex/refresh-process-fixture'}
}
""",
        encoding="utf-8",
    )
    # Resolve the active configured root at the test boundary without invoking
    # the copied helper's separate config-parser subprocess.
    lifecycle = vmware / "Atlaso.LifecycleOwnership.ps1"
    lifecycle.write_text(lifecycle.read_text(encoding="utf-8") + "\nfunction Get-AtlasoLifecycleDurableRoot { return $env:REFRESH_FIXTURE_CONFIGURED_ROOT }\n",
                         encoding="utf-8")
    protocol = worktree / "scripts" / "refresh_installation_iso.py"
    protocol.write_text(
        r'''from __future__ import annotations
import argparse, json, os, subprocess, sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.installation import refresh
parser = argparse.ArgumentParser()
parser.add_argument("action")
parser.add_argument("--plan", type=Path, required=True)
parser.add_argument("--configured-root", type=Path, required=True)
parser.add_argument("--phase")
parser.add_argument("--child-receipt", type=Path)
args = parser.parse_args()
plan, state, plan_hash = refresh.context(args.plan, args.configured_root)
if args.action == "describe":
    print(json.dumps({"plan": plan, "plan_sha256": plan_hash, "state": str(state), "interpreter": refresh.interpreter_identity()}))
elif args.action == "initialize":
    refresh.initialize(plan, state, plan_hash)
elif args.action == "preflight":
    intent = {"intent_id": "e" * 32, "plan_sha256": plan_hash,
              "deadline_utc": (datetime.now(UTC) + timedelta(seconds=300)).isoformat()}
    refresh.publish(state / f"{args.phase}-intent.json", intent)
    print(json.dumps(intent))
elif args.action == "run":
    refresh.assert_native_child(args.child_receipt, plan, plan_hash, args.phase, state)
    if os.environ.get("REFRESH_FIXTURE_UNSAFE_DESCENDANT") == "1":
        child_code = "\n".join((
            "import sys",
            f"sys.path.insert(0, {str(ROOT)!r})",
            "from pathlib import Path",
            "from scripts.installation import refresh",
            f"plan, state, plan_hash = refresh.context(Path({str(args.plan)!r}), Path({str(args.configured_root)!r}))",
            "try:",
            f"    refresh.assert_native_child(Path({str(args.child_receipt)!r}), plan, plan_hash, 'drift', state)",
            "except refresh.RefreshRefusal as error:",
            f"    Path({str(state / 'grandchild-result.json')!r}).write_text(str(error))",
            "    raise SystemExit(7)",
            "raise SystemExit(8)",
        ))
        descendant = subprocess.run([sys.executable, "-I", "-c", child_code], timeout=30, check=False)
        if descendant.returncode != 7:
            raise SystemExit(8)
        subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
        raise SystemExit(9)
    refresh.publish(state / f"{args.phase}-report.json", {"status": "fixture-phase-complete", "disposition": "requires_capture"})
''',
        encoding="utf-8",
    )
    state = fixture / "evidence"
    state.mkdir(parents=True)
    output_parent = worktree / "test-results"
    output_parent.mkdir(parents=True)
    operation_id = "a" * 32
    plan = {
        "schema": 1, "operation_id": operation_id, "task_id": task_id,
        "installer_commit": "b" * 40,
        "software": {"path": str(fixture / "software"), "version": "0.9.476", "source_commit": "c" * 40},
        "source_iso": str(fixture / "photon.iso"),
        "rpms": str(fixture / f"iso-inputs-{operation_id}" / "rpms"),
        "powercli": str(fixture / f"iso-inputs-{operation_id}" / "powercli"),
        "output_root": str(output_parent / "refresh-output"), "pull_request_number": 1100,
        "native_distribution": None, "protected_files": [], "capture_receipt": None,
    }
    # Use a canonical fixed plan and keep the venv below the receipted pytest root.
    plan_path = state / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    venv = tmp_path / "venv"
    env = {
        **os.environ,
        "CODEX_THREAD_ID": task_id,
        "REFRESH_FIXTURE_CONFIGURED_ROOT": str(ROOT.parent.parent),
        "REFRESH_TEST_REPOSITORY": str(ROOT),
        "TEMP": str(tmp_path),
        "TMP": str(tmp_path),
        "PYTHONDONTWRITEBYTECODE": "1",
        "REFRESH_FIXTURE_UNSAFE_DESCENDANT": "1" if unsafe_descendant else "0",
    }
    if use_venv:
        subprocess.run(["python", "-B", "-m", "venv", "--without-pip", str(venv)],
                       check=True, timeout=60, env=env)
        python = venv / "Scripts" / "python.exe"
    else:
        python = Path(shutil.which("python"))
    initialize = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(vmware / RUNNER.name), "-Plan", str(plan_path),
         "-Phase", "Initialize", "-PythonPath", str(python)],
        text=True, capture_output=True, timeout=90, env=env,
    )
    assert initialize.returncode == 0, initialize.stdout + initialize.stderr
    original = json.loads((state / "output-native-original.json").read_text(encoding="utf-8"))
    assert original["task_id"] == task_id
    assert original["native_identity"]

    drift = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(vmware / RUNNER.name), "-Plan", str(plan_path),
         "-Phase", "drift", "-PythonPath", str(python)],
        text=True, capture_output=True, timeout=90, env=env,
    )
    if unsafe_descendant:
        assert drift.returncode != 0
        assert "not the original launcher's direct venv child" in (state / "grandchild-result.json").read_text(encoding="utf-8")
        failed = json.loads((state / "drift-result.json").read_text(encoding="utf-8"))
        assert failed["status"] == "failed"
        assert failed["whole_job_quiescent"] is True
        return
    assert drift.returncode == 0, drift.stdout + drift.stderr
    launcher = json.loads((state / "drift-child.json").read_text(encoding="utf-8"))
    worker = json.loads((state / "drift-worker-original.json").read_text(encoding="utf-8"))
    result = json.loads((state / "drift-result.json").read_text(encoding="utf-8"))
    assert launcher["schema"] == 2
    assert launcher["interpreter"]["kind"] == ("venv" if use_venv else "direct")
    if use_venv:
        assert launcher["pid"] != worker["pid"]
        assert worker["parent_pid"] == launcher["pid"]
        assert worker["start_filetime_utc"] > launcher["start_filetime_utc"]
    else:
        assert launcher["pid"] == worker["pid"]
        assert worker["start_filetime_utc"] == launcher["start_filetime_utc"]
    assert worker["executable"] == launcher["interpreter"]["worker"]
    assert worker["child_receipt_sha256"]
    assert result["whole_job_quiescent"] is True


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
