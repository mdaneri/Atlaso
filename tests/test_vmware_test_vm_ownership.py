"""Exercise durable normal VMware test-VM ownership receipts on Windows."""

import json
import os
import shutil
import subprocess
import tomllib
import uuid
from pathlib import Path

import pytest

from scripts.pytest_git_fixtures import PytestGitFixtures

ROOT = Path(__file__).resolve().parents[1]
VMWARE = ROOT / "scripts/windows/vmware"
pytestmark = pytest.mark.skipif(os.name != "nt" or not shutil.which("pwsh"), reason="Windows ownership primitives")


def ps_literal(value: str | Path) -> str:
    """Quote a PowerShell string literal without invoking shell interpolation.

    Args:
        value: Public fixture path or value.
    """
    return "'" + str(value).replace("'", "''") + "'"


def context_script(tmp_path: Path, *, invocation_id: str = "") -> str:
    """Build a synthetic, task-bound context under one pytest-owned root.

    Args:
        tmp_path: Existing pytest temporary root.
        invocation_id: Optional deterministic receipt ID for collision testing.
    """
    evidence = tmp_path / "evidence"
    output = tmp_path / "checkout" / "test-vm"
    vmx = output / "Atlaso-PR-946-test-vm.vmx"
    return (
        f"$evidence={ps_literal(evidence)}; "
        f"$output={ps_literal(output)}; "
        f"$vmx={ps_literal(vmx)}; "
        f"$ctx=[pscustomobject]@{{Enabled=$true; TaskId='synthetic-task'; Repository='mdaneri/Atlaso'; "
        f"Branch='bug/946-test-vm-ownership'; SourceCommit='{'a' * 40}'; Worktree={ps_literal(tmp_path / 'checkout')}; "
        f"PullRequestNumber=946; LocalBuilder=$false; Name='Atlaso-PR-946-test-vm'; OutputDirectory=$output; "
        f"VmxPath=$vmx; EvidenceDirectory=$evidence; EvidenceDirectoryId=$null; InvocationId={ps_literal(invocation_id)}}}; "
        "$ctx.EvidenceDirectoryId=[Atlaso.WorkstationFileIdentity]::Get($evidence); "
    )


def run_powershell(command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one bounded PowerShell ownership operation.

    Args:
        command: Complete PowerShell source to execute.
        check: Raise for a nonzero result when true.
    """
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=check,
    )


def ownership_prefix() -> str:
    """Import the actual Windows identity and durable publisher primitives."""
    return (
        "$ErrorActionPreference='Stop'; "
        f"Import-Module {ps_literal(VMWARE / 'Atlaso.WorkstationCleanup.psm1')} -Force; "
        f". {ps_literal(VMWARE / 'Atlaso.TestVmOwnership.ps1')}; "
    )


def test_original_vm_directory_and_vmx_are_published_before_configuration(tmp_path):
    """The real publisher captures both original identities before VMX edits.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("config.version = \"8\"\n", encoding="utf-8")
    output = tmp_path / "checkout" / "test-vm"
    command = (
        ownership_prefix()
        + context_script(tmp_path)
        + f"$source={ps_literal(source)}; $sourceId=[Atlaso.WorkstationFileIdentity]::Get($source); "
        + "$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath $source -SourceVmxIdentity $sourceId; "
        + "$cleanupIdentity=('d'*32); [void][System.IO.Directory]::CreateDirectory($output); "
        + "[System.IO.File]::WriteAllText($vmx, ('source clone' + [Environment]::NewLine + 'guestinfo.atlaso.test_vm_cleanup_identity = ' + [char]34 + $cleanupIdentity + [char]34 + [Environment]::NewLine)); "
        + "$events=[System.Collections.Generic.List[string]]::new(); function git { "
        + "if ($args.Count -eq 6 -and $args[0] -eq '-C' -and $args[2] -eq 'merge-base' -and "
        + "$args[3] -eq '--is-ancestor' -and $args[4] -eq ('a'*40) -and $args[5] -eq ('a'*40)) { "
        + "$global:LASTEXITCODE=0; return }; throw 'Unexpected Git command in publisher test' }; "
        + "Publish-AtlasoTestVmOriginalOwnership -Context $ctx -DirectoryPath $output -VmxPath $vmx -CleanupIdentity $cleanupIdentity | Out-Null; "
        + "$events.Add('receipt'); $replacement=($vmx + '.replacement'); "
        + "[System.IO.File]::WriteAllText($replacement, ('configured' + [Environment]::NewLine + 'guestinfo.atlaso.test_vm_cleanup_identity = ' + [char]34 + $cleanupIdentity + [char]34 + [Environment]::NewLine)); "
        + "$backup=($vmx + '.backup'); [System.IO.File]::Replace($replacement,$vmx,$backup); $events.Add('configured'); "
        + "$verified=Assert-AtlasoTestVmOriginalOwnership -Context $ctx; "
        + "$record=Get-Content -LiteralPath $ctx.ReceiptPath -Raw | ConvertFrom-Json; "
        + "$oldIntent=$ctx.IntentPath; $ctx.InvocationId=[guid]::NewGuid().ToString('N'); "
        + "$redeploy=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath $source -SourceVmxIdentity $sourceId -ExistingReceipt $verified; "
        + "[pscustomobject]@{intent=$oldIntent; receipt=$ctx.ReceiptPath; hash=$ctx.ReceiptSha256; redeployIntent=$redeploy.IntentPath; "
        + "events=@($events); verified=($verified.Path -eq $ctx.ReceiptPath); directory=$record.original_identities.directory; vmx=$record.original_identities.vmx; "
        + "persistentIdentityHash=$record.persistent_vm_identity_sha256; currentVmx=([Atlaso.WorkstationFileIdentity]::Get($vmx)); backupExists=(Test-Path -LiteralPath $backup); "
        + "task=$record.task_id; source=$record.source_commit; cleanup=$record.cleanup_tool; "
        + "sourceRole=$record.source_template.role} | ConvertTo-Json -Compress"
    )
    result = run_powershell(command)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["events"] == ["receipt", "configured"]
    assert payload["verified"]
    assert Path(payload["intent"]).parent == evidence
    assert Path(payload["receipt"]).parent == evidence
    assert Path(payload["intent"]) != output and Path(payload["receipt"]) != output
    assert payload["directory"] and payload["vmx"]
    assert payload["vmx"] != payload["currentVmx"]
    assert payload["backupExists"]
    assert len(payload["persistentIdentityHash"]) == 64
    assert Path(payload["redeployIntent"]).is_file()
    assert payload["redeployIntent"] != payload["intent"]
    assert payload["task"] == "synthetic-task" and payload["source"] == "a" * 40
    assert payload["sourceRole"] == "read-only source template; not cleanup-owned"
    assert "remove-atlaso-vm.ps1" in payload["cleanup"]


def test_intent_refuses_preexisting_output_without_original_receipt(tmp_path):
    """A preexisting directory cannot receive a retroactive creation intent.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    (tmp_path / "evidence").mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("source", encoding="utf-8")
    output = tmp_path / "checkout" / "test-vm"
    output.mkdir(parents=True)
    command = (
        ownership_prefix()
        + context_script(tmp_path)
        + f"$source={ps_literal(source)}; $sourceId=[Atlaso.WorkstationFileIdentity]::Get($source); "
        + "New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath $source -SourceVmxIdentity $sourceId"
    )
    result = run_powershell(command, check=False)
    assert result.returncode != 0
    assert not list((tmp_path / "evidence").glob("atlaso-test-vm-*.json"))
    assert output.is_dir()


def test_receipt_publication_failure_preserves_clone_and_blocks_configuration(tmp_path):
    """A failed immutable receipt publication leaves the clone stopped and intact.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    (tmp_path / "evidence").mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("source", encoding="utf-8")
    invocation_id = "b" * 32
    collision = tmp_path / "evidence" / f"atlaso-test-vm-original-{invocation_id}.json"
    collision.write_text("preserve", encoding="utf-8")
    command = (
        ownership_prefix()
        + context_script(tmp_path, invocation_id=invocation_id)
        + f"$source={ps_literal(source)}; $sourceId=[Atlaso.WorkstationFileIdentity]::Get($source); "
        + "$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath $source -SourceVmxIdentity $sourceId; "
        + "$cleanupIdentity=('d'*32); [void][System.IO.Directory]::CreateDirectory($output); "
        + "[System.IO.File]::WriteAllText($vmx, ('clone' + [Environment]::NewLine + 'guestinfo.atlaso.test_vm_cleanup_identity = ' + [char]34 + $cleanupIdentity + [char]34)); "
        + "$configured=$false; try { Publish-AtlasoTestVmOriginalOwnership -Context $ctx -DirectoryPath $output -VmxPath $vmx -CleanupIdentity $cleanupIdentity | Out-Null; $configured=$true } catch { }; "
        + "[pscustomobject]@{configured=$configured; vmxExists=(Test-Path -LiteralPath $vmx); collision=Get-Content -LiteralPath "
        + f"{ps_literal(collision)} -Raw}} | ConvertTo-Json -Compress"
    )
    result = run_powershell(command)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload == {"configured": False, "vmxExists": True, "collision": "preserve"}
    assert (tmp_path / "evidence" / f"atlaso-test-vm-original-{invocation_id}.json").read_text() == "preserve"


def test_publisher_rejects_evidence_root_inside_vm_removal_root(tmp_path):
    """The durable receipt directory cannot overlap the recursively removed VM root.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    (tmp_path / "evidence").mkdir()
    (tmp_path / "checkout" / "test-vm").mkdir(parents=True)
    command = (
        ownership_prefix()
        + context_script(tmp_path)
        + "$ctx.EvidenceDirectory=$output; $ctx.EvidenceDirectoryId=[Atlaso.WorkstationFileIdentity]::Get($output); "
        + "$record=[ordered]@{schema=1}; Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record $record -Kind original"
    )
    result = run_powershell(command, check=False)
    assert result.returncode != 0
    assert not list((tmp_path / "checkout" / "test-vm").glob("atlaso-test-vm-*.json"))


def test_publisher_rejects_reparse_point_evidence_directory(tmp_path):
    """The publisher refuses a junction in the durable receipt path.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    real_root = tmp_path / "checkout"
    real_root.mkdir()
    (tmp_path / "evidence").mkdir()
    link_root = tmp_path / "evidence-link"
    command = (
        ownership_prefix()
        + context_script(tmp_path)
        + f"try {{ New-Item -ItemType Junction -Path {ps_literal(link_root)} -Target {ps_literal(real_root)} | Out-Null }} catch {{ Write-Output 'JUNCTION_UNAVAILABLE'; exit 77 }}; "
        + f"$ctx.EvidenceDirectory={ps_literal(link_root)}; $ctx.EvidenceDirectoryId=[Atlaso.WorkstationFileIdentity]::Get($link_root); "
        + "$record=[ordered]@{schema=1}; Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record $record -Kind original"
    )
    result = run_powershell(command, check=False)
    if result.returncode == 77:
        pytest.skip("This Windows host cannot create a synthetic directory junction.")
    assert result.returncode != 0
    assert not list(real_root.glob("atlaso-test-vm-*.json"))


def test_agent_context_uses_configured_root_and_requires_registered_clean_worktree(tmp_path, request):
    """Agent mode resolves Codex configuration and rejects dirty source checkout state.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    config_path = codex_home / "config.toml"
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    configured_root = Path(config["desktop"]["git-worktree-root"]).resolve()
    evidence = configured_root / ".task-ownership"
    task_id = os.environ.get("CODEX_THREAD_ID")
    if not task_id:
        pytest.skip("This agent-context test requires the active Codex task identity.")
    if not evidence.is_dir():
        pytest.skip("This agent-context test requires the preexisting durable ownership directory.")
    source_commit = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    fixture_root = tmp_path / f"vm-ownership-{uuid.uuid4().hex}"
    fixture_receipt = evidence / f"pytest-git-fixture-vm-ownership-{uuid.uuid4().hex}.json"
    owner = PytestGitFixtures(
        config_path,
        fixture_receipt,
        {
            "id": "pytest-vm-ownership",
            "task_id": task_id,
            "repository": "mdaneri/Atlaso",
            "source_commit": source_commit,
            "path": str(fixture_root),
        },
    )
    owner.create()
    request.addfinalizer(owner.seal)
    checkout = owner.root / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init", "-b", "bug/946-test-vm-ownership", str(checkout)], check=True,
                   capture_output=True, text=True)
    owner.register(checkout)
    subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", "https://github.com/mdaneri/Atlaso.git"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Synthetic Test"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.email", "synthetic@example.invalid"], check=True)
    (checkout / "source.txt").write_text("source", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "source.txt"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-m", "source"], check=True,
                   capture_output=True, text=True)
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True).stdout.strip()
    output = checkout / "image" / "vmware-workstation" / "test-vms" / "Atlaso-PR-946-test-vm"
    vmx = output / "Atlaso-PR-946-test-vm.vmx"
    command = (
        ownership_prefix()
        + f"$ctx=New-AtlasoTestVmOwnershipContext -Worktree {ps_literal(checkout)} "
        + f"-OutputDirectory {ps_literal(output)} -VmxPath {ps_literal(vmx)} "
        + "-Name 'Atlaso-PR-946-test-vm' "
        + f"-SourceCommit '{commit}' -SourceBranch 'bug/946-test-vm-ownership' -PullRequestNumber 946; "
        + "[pscustomobject]@{enabled=$ctx.Enabled; task=$ctx.TaskId; root=$ctx.EvidenceDirectory; "
        + "worktree=$ctx.Worktree; commit=$ctx.SourceCommit} | ConvertTo-Json -Compress"
    )
    result = run_powershell(command)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload == {
        "enabled": True,
        "task": task_id,
        "root": str(evidence),
        "worktree": str(checkout),
        "commit": commit,
    }

    (checkout / "untracked.txt").write_text("dirty", encoding="utf-8")
    dirty = run_powershell(command, check=False)
    assert dirty.returncode != 0


def test_context_rejects_output_directory_inside_durable_evidence(tmp_path):
    """The recursively removable VM root cannot contain or overlap receipts.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    configured_root = tmp_path / "permitted"
    checkout = configured_root / "task" / "Atlaso"
    evidence = configured_root / ".task-ownership"
    codex_home = tmp_path / "codex"
    evidence.mkdir(parents=True)
    checkout.mkdir(parents=True)
    codex_home.mkdir()
    (codex_home / "config.toml").write_text(
        f"[desktop]\ngit-worktree-root = '{configured_root.as_posix()}'\n",
        encoding="utf-8",
    )
    output = evidence / "vm"
    vmx = output / "Atlaso-PR-946-test-vm.vmx"
    command = (
        ownership_prefix()
        + f"$env:CODEX_HOME={ps_literal(codex_home)}; $env:CODEX_THREAD_ID='synthetic-task'; "
        + f"$ctx=New-AtlasoTestVmOwnershipContext -Worktree {ps_literal(checkout)} "
        + f"-OutputDirectory {ps_literal(output)} -VmxPath {ps_literal(vmx)} "
        + "-Name 'Atlaso-PR-946-test-vm' -SourceCommit ('a'*40) "
        + "-SourceBranch 'bug/946-test-vm-ownership' -PullRequestNumber 946"
    )
    result = run_powershell(command, check=False)
    assert result.returncode != 0
