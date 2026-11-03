"""Exercise receipt-preserving successor admission with real Windows file primitives."""

import json
import os
import shutil
from pathlib import Path

import pytest

from tests.test_vmware_test_vm_ownership import (
    context_script,
    ownership_prefix,
    ps_literal,
    run_powershell,
)

pytestmark = pytest.mark.skipif(os.name != "nt" or not shutil.which("pwsh"), reason="Windows ownership primitives")


def continuation_script(tmp_path: Path) -> str:
    """Prepare explicitly synthetic public ownership and controller evidence.

    Args:
        tmp_path: Creation-owned pytest root containing all synthetic objects.
    """
    (tmp_path / ".task-ownership").mkdir()
    output = tmp_path / "checkout/test-vm"
    output.mkdir(parents=True)
    (output / "Atlaso-PR-946-test-vm.vmx").write_text(
        'displayName = "Atlaso-PR-946-test-vm"\n'
        'guestinfo.atlaso.test_vm_cleanup_identity = "' + "a" * 32 + '"\n', encoding="utf-8"
    )
    context = context_script(tmp_path).replace(ps_literal(tmp_path / "evidence"), ps_literal(tmp_path / ".task-ownership"))
    return ownership_prefix() + context + f"""
$env:CODEX_THREAD_ID='successor-fixture';
$ctx.TaskId='successor-fixture';
$ctx | Add-Member WorktreeDirectoryId ([Atlaso.WorkstationFileIdentity]::Get($ctx.Worktree));
$ctx | Add-Member PermittedRoot {ps_literal(tmp_path)};
$ctx | Add-Member ReceiptPath (Join-Path $evidence 'original.json');
$ctx | Add-Member ReceiptSha256 '';
function git {{ $global:LASTEXITCODE=0 }}
function WriteFixture {{ param($path,$value) [IO.File]::WriteAllText($path,($value|ConvertTo-Json -Depth 8)); (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() }}
$original=[ordered]@{{schema=1;phase='original-clone-created';task_id='synthetic-task';repository=$ctx.Repository;
    worktree=$ctx.Worktree;source_branch=$ctx.Branch;source_commit=$ctx.SourceCommit;canonical_name=$ctx.Name;
    output_directory=$ctx.OutputDirectory;vmx_path=$ctx.VmxPath;pull_request_number=$ctx.PullRequestNumber;local_builder=$false;
    original_identities=@{{directory=[Atlaso.WorkstationFileIdentity]::Get($output)}};
    persistent_vm_identity_sha256=(Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value (Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath $vmx))}};
$ctx.ReceiptSha256=WriteFixture $ctx.ReceiptPath $original;
$controllerPath=Join-Path {ps_literal(tmp_path)} 'controller.json';
$controller=[ordered]@{{schema=1;successor_task_id='successor-fixture';originating_task_id='synthetic-task';
    original_receipt_path=$ctx.ReceiptPath;original_receipt_sha256=$ctx.ReceiptSha256;source_commit=$ctx.SourceCommit;
    human_authorized=$true;originating_chat_idle=$true;original_native_consumers_terminal=$true;exclusive_successor=$true;
    evidence_refs=@('synthetic-human-authorization','synthetic-supported-thread-read');observed_at=[DateTimeOffset]::UtcNow.ToString('o')}};
$controllerHash=WriteFixture $controllerPath $controller;
$record=[ordered]@{{schema=1;phase='test-vm-successor-authorized';originating_task_id='synthetic-task';successor_task_id='successor-fixture';
    repository=$ctx.Repository;worktree=$ctx.Worktree;worktree_directory_identity=$ctx.WorktreeDirectoryId;
    source_branch=$ctx.Branch;source_commit=$ctx.SourceCommit;canonical_name=$ctx.Name;output_directory=$ctx.OutputDirectory;
    vmx_path=$ctx.VmxPath;pull_request_number=$ctx.PullRequestNumber;local_builder=$false;
    original_receipt_path=$ctx.ReceiptPath;original_receipt_sha256=$ctx.ReceiptSha256;
    controller_evidence_path=$controllerPath;controller_evidence_sha256=$controllerHash}};
$path=Get-AtlasoTestVmContinuationPath -Context $ctx;
$pins=[Collections.Generic.List[object]]::new();
"""


@pytest.mark.parametrize("defect", [
    "none", "active", "owner", "scope", "worktree", "source", "original", "authorization",
    "string-approval", "nonterminal", "controller-digest", "record-digest", "partial", "missing", "new-resource", "replaced",
])
def test_successor_admission_preserves_owner_and_refuses_substitutions(tmp_path, defect):
    """Reach retained admission only for unchanged original ownership and explicit consent.

    Args:
        tmp_path: Creation-owned synthetic fixture root.
        defect: Independent identity, scope, authorization or immutable-byte substitution.
    """
    command = continuation_script(tmp_path)
    mutations = {
        "none": "",
        "active": "$env:CODEX_THREAD_ID='another-chat';",
        "owner": "$record.originating_task_id='another-owner';",
        "scope": "$record.vmx_path=$record.vmx_path+'.other';",
        "worktree": "$record.worktree_directory_identity='00000000:0000000000000000';",
        "source": "function git { $global:LASTEXITCODE=1 };",
        "original": "[IO.File]::AppendAllText($ctx.ReceiptPath,' ');",
        "authorization": "$controller.human_authorized=$false;",
        "string-approval": "$controller.human_authorized='True';",
        "nonterminal": "$controller.original_native_consumers_terminal=$false;",
        "controller-digest": "$record.controller_evidence_sha256='a'*64;",
        "record-digest": "",
        "partial": "",
        "missing": "",
        "new-resource": "",
        "replaced": "$saved=$output+'-retained';[IO.Directory]::Move($output,$saved);[IO.Directory]::CreateDirectory($output)|Out-Null;[IO.File]::Copy((Join-Path $saved 'Atlaso-PR-946-test-vm.vmx'),$vmx);",
    }
    command += mutations[defect]
    if defect in {"authorization", "string-approval", "nonterminal"}:
        command += "$record.controller_evidence_sha256=WriteFixture $controllerPath $controller;"
    command += "$digest=WriteFixture $path $record;"
    command += {
        "record-digest": "$digest='b'*64;",
        "partial": "$digest='';",
        "missing": "$path='';$digest='';",
        "new-resource": "$ctx.ReceiptPath='';",
    }.get(defect, "")
    command += "try { $owner=Resolve-AtlasoTestVmContinuation -Context $ctx -Path $path -Sha256 $digest -Pins $pins;"
    command += "@{owner=$owner;active=$env:CODEX_THREAD_ID}|ConvertTo-Json -Compress } finally {foreach($pin in $pins){$pin.Dispose()}}"
    result = run_powershell(command, check=False)
    if defect == "none":
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout.strip().splitlines()[-1]) == {"owner": "synthetic-task", "active": "successor-fixture"}
    else:
        assert result.returncode != 0, result.stdout
        assert "Continuation" in result.stderr or "continuation" in result.stderr or "retained VM" in result.stderr


@pytest.mark.parametrize("defect", ["none", "stale", "active-owner", "duplicate", "outside"])
def test_successor_publication_is_immutable_fresh_and_receipt_bound(tmp_path, defect):
    """Publish through native durable primitives and refuse replay or source-less adoption.

    Args:
        tmp_path: Creation-owned fixture root with an explicitly synthetic VM.
        defect: Fresh authorized publication, stale evidence, unchanged owner, replay or out-of-root evidence.
    """
    command = continuation_script(tmp_path)
    command += "function Assert-AtlasoTestVmCheckoutSource { param($Context) };"
    if defect == "stale":
        command += "$controller.observed_at=[DateTimeOffset]::UtcNow.AddMinutes(-6).ToString('o');$controllerHash=WriteFixture $controllerPath $controller;"
    elif defect == "active-owner":
        command += "$original.task_id='successor-fixture';$ctx.ReceiptSha256=WriteFixture $ctx.ReceiptPath $original;"
    elif defect == "outside":
        command += "$ctx.PermittedRoot=Join-Path $ctx.PermittedRoot 'other';"
    call = "New-AtlasoTestVmContinuation -Context $ctx -ControllerEvidencePath $controllerPath -ControllerEvidenceSha256 $controllerHash"
    command += "$receipt=" + call + ";"
    if defect == "duplicate":
        command += "$null=" + call + ";"
    command += "try { $owner=Resolve-AtlasoTestVmContinuation -Context $ctx -Path $receipt.Path -Sha256 $receipt.Sha256 -Pins $pins;"
    command += "@{owner=$owner;original=$original.task_id;originalHash=(Get-FileHash $ctx.ReceiptPath -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress } finally {foreach($pin in $pins){$pin.Dispose()}}"
    result = run_powershell(command, check=False)
    if defect == "none":
        assert result.returncode == 0, result.stdout + result.stderr
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        assert payload["owner"] == payload["original"] == "synthetic-task"
        assert len(payload["originalHash"]) == 64
    else:
        assert result.returncode != 0, result.stdout


def test_successor_evidence_stays_pinned_until_native_consumer_exits(tmp_path):
    """Exclude writers and replacement through the caller-owned admission lifetime.

    Args:
        tmp_path: Creation-owned synthetic retained-resource root.
    """
    command = continuation_script(tmp_path)
    command += "$digest=WriteFixture $path $record;try {"
    command += "$null=Resolve-AtlasoTestVmContinuation -Context $ctx -Path $path -Sha256 $digest -Pins $pins;"
    command += "foreach($selected in @($path,$ctx.ReceiptPath,$controllerPath)){ $refused=$false;try{[IO.File]::AppendAllText($selected,'changed')}catch{$refused=$true};if(-not $refused){throw 'Pinned evidence was writable'}}"
    command += "}finally{foreach($pin in $pins){$pin.Dispose()}};[IO.File]::AppendAllText($controllerPath,' ');"
    result = run_powershell(command, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_context_and_mutation_guard_recheck_the_actual_successor_selectors(tmp_path):
    """Exercise constructor wiring and reject receipt drift before any provider boundary.

    Args:
        tmp_path: Creation-owned root for synthetic Git metadata and original evidence.
    """
    command = continuation_script(tmp_path)
    command += "$digest=WriteFixture $path $record;"
    command += "function Get-AtlasoLifecycleDurableRoot {$ctx.PermittedRoot};"
    command += "function git { $global:LASTEXITCODE=0;"
    command += "if($args -contains '--show-toplevel'){$ctx.Worktree}"
    command += "elseif($args -contains 'HEAD'){$ctx.SourceCommit}"
    command += "elseif($args -contains '--show-current'){$ctx.Branch}"
    command += "elseif($args -contains '--get'){'https://github.com/mdaneri/Atlaso.git'}"
    command += "elseif($args -contains 'worktree'){'worktree '+$ctx.Worktree}};"
    command += "$next=New-AtlasoTestVmOwnershipContext -Worktree $ctx.Worktree -OutputDirectory $ctx.OutputDirectory "
    command += "-VmxPath $ctx.VmxPath -Name $ctx.Name -SourceCommit $ctx.SourceCommit -SourceBranch $ctx.Branch "
    command += "-PullRequestNumber $ctx.PullRequestNumber -OwnershipReceiptPath $ctx.ReceiptPath -OwnershipReceiptSha256 $ctx.ReceiptSha256 "
    command += "-ContinuationReceiptPath $path -ContinuationReceiptSha256 $digest;"
    command += "if($next.TaskId -cne 'synthetic-task' -or $next.ActiveTaskId -cne 'successor-fixture'){throw 'Constructor lost the original owner or active executor'};"
    command += "[IO.File]::AppendAllText($path,' ');$refused=$false;try{Assert-AtlasoTestVmCheckoutSource -Context $next}catch{if($_.Exception.Message -like '*Continuation evidence changed*'){$refused=$true}else{throw}};"
    command += "if(-not $refused){throw 'Changed continuation reached the native boundary'};"
    result = run_powershell(command, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_successor_cannot_create_or_redeploy_and_resume_keeps_both_identities(tmp_path):
    """Reject creation before source/provider access and preserve executor attribution on resume.

    Args:
        tmp_path: Creation-owned root containing synthetic retained VM evidence.
    """
    command = continuation_script(tmp_path)
    command += "$digest=WriteFixture $path $record;$ctx.TaskId='synthetic-task';"
    command += "$ctx | Add-Member ActiveTaskId 'successor-fixture';$ctx | Add-Member ContinuationReceiptPath $path;$ctx | Add-Member ContinuationReceiptSha256 $digest;"
    command += "$refused=$false;try{New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath 'unavailable' -SourceVmxIdentity 'unavailable'}catch{if($_.Exception.Message -eq 'Continuation cannot create or redeploy a VM.'){$refused=$true}else{throw}};"
    command += "if(-not $refused){throw 'Continuation reached a creation boundary'};"
    command += "$resume=Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record @{schema=1;task_id=$ctx.TaskId;phase='installation-resume-without-media'} -Kind installation-resume;"
    command += "$readback=Get-Content -LiteralPath $resume.Path -Raw|ConvertFrom-Json;"
    command += "@{owner=$readback.task_id;executor=$readback.executor_task_id;path=$readback.continuation_receipt_path;digest=$readback.continuation_receipt_sha256}|ConvertTo-Json -Compress;"
    result = run_powershell(command, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["owner"] == "synthetic-task"
    assert payload["executor"] == "successor-fixture"
    assert Path(payload["path"]).parent == tmp_path / ".task-ownership"
    assert len(payload["digest"]) == 64


@pytest.mark.parametrize("timestamp", ["z", "offset", "stale-z", "future-z", "unspecified", "malformed"])
def test_successor_freshness_preserves_json_timestamp_instants(tmp_path, timestamp):
    """Interpret parsed UTC values without reinterpreting their wall time in the host zone.

    Args:
        tmp_path: Creation-owned root containing synthetic original and controller evidence.
        timestamp: Equivalent fresh encodings, expired/future UTC, or ambiguous/invalid values.
    """
    command = continuation_script(tmp_path)
    command += "function Assert-AtlasoTestVmCheckoutSource { param($Context) };$instant=[DateTimeOffset]::UtcNow;"
    if timestamp == "stale-z":
        command += "$instant=$instant.AddMinutes(-6);"
    elif timestamp == "future-z":
        command += "$instant=$instant.AddMinutes(6);"
    if timestamp == "offset":
        command += "$controller.observed_at=$instant.ToString('o');"
    elif timestamp == "unspecified":
        command += "$controller.observed_at=$instant.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fff');"
    elif timestamp == "malformed":
        command += "$controller.observed_at='not-an-instant';"
    else:
        command += "$controller.observed_at=$instant.UtcDateTime.ToString(\"yyyy-MM-dd'T'HH:mm:ss.fff'Z'\");"
    command += "$controllerHash=WriteFixture $controllerPath $controller;"
    command += "$receipt=New-AtlasoTestVmContinuation -Context $ctx -ControllerEvidencePath $controllerPath -ControllerEvidenceSha256 $controllerHash;"
    command += "Get-Content -LiteralPath $receipt.Path -Raw|ConvertFrom-Json|Select-Object successor_task_id|ConvertTo-Json -Compress;"
    result = run_powershell(command, check=False)
    if timestamp in {"z", "offset"}:
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout.strip().splitlines()[-1])["successor_task_id"] == "successor-fixture"
    else:
        assert result.returncode != 0, result.stdout
        assert "fresh controller evidence" in result.stderr
