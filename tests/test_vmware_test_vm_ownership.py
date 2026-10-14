"""Exercise durable normal VMware test-VM ownership receipts on Windows."""

import json
import os
import shutil
import subprocess
import time
import tomllib
import uuid
from pathlib import Path

import pytest

from scripts.pytest_git_fixtures import PytestGitFixtures
from tests.test_vmware_cleanup import _write_fake_vmrun, _write_vmware_payload_fixture

ROOT = Path(__file__).resolve().parents[1]
VMWARE = ROOT / "scripts/windows/vmware"
pytestmark = pytest.mark.skipif(os.name != "nt" or not shutil.which("pwsh"), reason="Windows ownership primitives")


def ps_literal(value: str | Path) -> str:
    """Quote a PowerShell string literal without invoking shell interpolation.

    Args:
        value: Public fixture path or value.
    """
    return "'" + str(value).replace("'", "''") + "'"


@pytest.mark.parametrize("caller", ["rollback", "persisted"])
@pytest.mark.parametrize("admission", ["valid", "missing", "human", "foreign"])
def test_failed_creation_removal_callers_require_original_identity_selectors(tmp_path, caller, admission):
    """Execute actual removal caller blocks and refuse provider launch when receipt admission fails.

    Args:
        tmp_path: Original pytest-owned temporary root.
        caller: Immediate rollback or persisted cleanup child invocation.
        admission: Valid, missing or foreign receipt, or ordinary human CLI context.
    """
    script = (VMWARE / "create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    variable = "rollbackOwnershipArguments" if caller == "rollback" else "persistedOwnershipArguments"
    start = script.index(f"${variable} = @()")
    end = script.index("| Out-Null", start) + len("| Out-Null")
    block = script[start:end].replace("$PSScriptRoot", ps_literal(VMWARE))
    enabled = "$false" if admission == "human" else "$true"
    destination = tmp_path / "public.vmx"
    setup = "$ErrorActionPreference='Stop'; "
    setup += f"$ownershipContext=[pscustomobject]@{{Enabled={enabled};VmxPath={ps_literal(destination)}}}; "
    setup += f"$marker=[pscustomobject]@{{VmxPath={ps_literal(destination)};Name='public'}}; "
    if admission == "foreign":
        setup += f"$ownershipContext.VmxPath={ps_literal(tmp_path / 'another.vmx')}; "
    setup += "$targetVmx=$marker.VmxPath; $rollbackVmrunPath='public-provider'; $VmrunPath=$rollbackVmrunPath; "
    setup += "$powerShellPath=(Get-Process -Id $PID).Path; $Name='public'; $TimeoutSeconds=10; $script:checked=$false; "
    setup += "function Assert-AtlasoTestVmOriginalOwnership { param($Context) $script:checked=$true; "
    if admission in {"missing", "foreign"}:
        setup += "throw 'Original receipt missing' }; "
    else:
        setup += "[pscustomobject]@{Record=@{original_identities=@{directory='12345678:0000000000000123'};persistent_vm_identity_sha256=('a'*64)}} }; "
    setup += "function Invoke-AtlasoBoundedProcess { param($FilePath,$ArgumentList,$TimeoutSeconds,$Action) "
    setup += "if ($ownershipContext.Enabled -and -not $script:checked) { throw 'Provider preceded receipt validation' }; "
    setup += "$ArgumentList | ConvertTo-Json -Compress }; "
    # The production block discards provider output; the fixture captures invocation arguments instead.
    setup += block.replace("| Out-Null", f"| Set-Content -LiteralPath {ps_literal(tmp_path / 'args.json')}")
    result = run_powershell(setup, check=False)
    captured = tmp_path / "args.json"
    if admission in {"missing", "foreign"}:
        assert result.returncode != 0
        message = "Persisted cleanup requires the original receipt" if admission == "foreign" and caller == "persisted" else "Original receipt missing"
        assert message in result.stderr
        assert not captured.exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        arguments = json.loads(captured.read_text(encoding="utf-8-sig"))
        if admission == "valid":
            assert arguments[arguments.index("-ExpectedRootIdentity") + 1] == "12345678:0000000000000123"
            assert arguments[arguments.index("-ExpectedPersistentVmIdentitySha256") + 1] == "a" * 64
        else:
            assert "-ExpectedRootIdentity" not in arguments


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


def run_powershell(command: str, *, check: bool = True, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run one bounded PowerShell ownership operation.

    Args:
        command: Complete PowerShell source to execute.
        check: Raise for a nonzero result when true.
        environment: Optional isolated fake-provider environment.
    """
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=check,
        env=environment,
    )


def ownership_prefix() -> str:
    """Import the actual Windows identity and durable publisher primitives."""
    return (
        "$ErrorActionPreference='Stop'; "
        f"Import-Module {ps_literal(VMWARE / 'Atlaso.WorkstationCleanup.psm1')} -Force; "
        f". {ps_literal(VMWARE / 'Atlaso.TestVmOwnership.ps1')}; "
    )


def test_exclusive_destination_retains_creation_identity_and_allows_provider_children(tmp_path):
    """A created destination permits clone files while excluding replacement and directory writers.

    Args:
        tmp_path: Original pytest-owned temporary root.
    """
    destination = tmp_path / "new-parent" / "new-vm"
    result = run_powershell(
        ownership_prefix()
        + f"$target={ps_literal(destination)}; $records=[Collections.Generic.List[object]]::new(); "
        + "$publish=[Action[string,string]]{param($path,$identity) $records.Add(@{path=$path;identity=$identity})}; "
        + "$pin=[Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath($target,$publish); try { "
        + "[IO.File]::WriteAllText((Join-Path $target 'test.vmx'),'public fixture'); "
        + "$blocked=$false; try { [IO.Directory]::Move($target,($target+'-replaced')) } catch { $blocked=$true }; "
        + "if (-not $blocked) { throw 'Created directory was replaceable' }; "
        + "if ($pin.Created[$target] -cne [Atlaso.WorkstationFileIdentity]::Get($target)) { throw 'Identity drift' }; "
        + "$records | ConvertTo-Json -Compress } finally { $pin.Dispose() }"
    )
    records = json.loads(result.stdout)
    assert len(records) == 2
    assert records[-1]["path"] == str(destination)
    assert (destination / "test.vmx").read_text() == "public fixture"


def test_exclusive_destination_refuses_concurrently_inserted_child(tmp_path):
    """A competing child created after the parent callback cannot be adopted by the creator.

    Args:
        tmp_path: Original pytest-owned temporary root.
    """
    destination = tmp_path / "new-parent" / "competing-vm"
    result = run_powershell(
        ownership_prefix()
        + f"$target={ps_literal(destination)}; "
        + "$publish=[Action[string,string]]{param($path,$identity) "
        + "[void][IO.Directory]::CreateDirectory((Join-Path $path 'competing-vm'))}; "
        + "$pin=[Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath($target,$publish)",
        check=False,
    )
    assert result.returncode != 0
    assert "Exclusive directory creation refused" in result.stderr
    assert destination.is_dir()
    assert not list(destination.iterdir())


def test_prepared_destination_publishes_each_creation_before_clone_use(tmp_path):
    """The real helper seals creation identities before any provider VMX is written.

    Args:
        tmp_path: Original pytest-owned temporary root.
    """
    (tmp_path / "evidence").mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("public fixture", encoding="utf-8")
    result = run_powershell(
        ownership_prefix()
        + context_script(tmp_path)
        + f"$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath {ps_literal(source)} "
        + f"-SourceVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get({ps_literal(source)})); "
        + "$pin=New-AtlasoTestVmPreparedOutput -Context $ctx; try { "
        + "if (Test-Path -LiteralPath $vmx) { throw 'Premature VMX' }; "
        + "if ($ctx.PreparedOutputIdentity -cne [Atlaso.WorkstationFileIdentity]::Get($output)) { throw 'Wrong original identity' }; "
        + "[IO.File]::WriteAllText($vmx,'public fixture') } finally { $pin.Dispose() }"
    )
    receipts = list((tmp_path / "evidence").glob("atlaso-test-vm-directory-*.json"))
    assert len(receipts) == 2
    records = [json.loads(path.read_text(encoding="utf-8-sig")) for path in receipts]
    assert {record["path"] for record in records} == {
        str(tmp_path / "checkout"), str(tmp_path / "checkout" / "test-vm")
    }
    assert all(record["task_id"] == "synthetic-task" and record["original_identity"] for record in records)
    assert "prepared directory receipt SHA-256" in result.stdout


@pytest.mark.parametrize("case", ["empty", "partial", "digest", "replaced", "vmx", "unsupported", "foreign", "process_digest"])
def test_prepared_directory_recovery_requires_original_receipt_and_no_completed_vm(tmp_path, case):
    """A pre-callback failure can recover only its original incomplete destination.

    Args:
        tmp_path: Original pytest-owned temporary root.
        case: Empty/partial recovery or a receipt, identity, VMX, artifact, or owner refusal.
    """
    (tmp_path / "evidence").mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("public fixture", encoding="utf-8")
    provider, environment, _, _ = _write_fake_vmrun(tmp_path / "provider", [], registered=False)
    setup = (
        ownership_prefix()
        + context_script(tmp_path)
        + f"$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath {ps_literal(source)} "
        + f"-SourceVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get({ps_literal(source)})); "
        + "function Assert-AtlasoTestVmCheckoutSource { param($Context) }; "
        + "Invoke-AtlasoTestVmOwnedClone -Context $ctx -FilePath $env:ComSpec -ArgumentList @('/c','exit','0') -TimeoutSeconds 30; "
        + "$ctx.CloneOutputPin.Dispose(); "
        + "[pscustomobject]@{path=$ctx.PreparedReceiptPath; sha=$ctx.PreparedReceiptSha256} | ConvertTo-Json -Compress"
    )
    preparation = run_powershell(setup)
    selectors = json.loads(preparation.stdout.strip().splitlines()[-1])
    changes = {
        "empty": "",
        "partial": "[IO.File]::WriteAllText((Join-Path $output 'partial.vmdk'),'public incomplete disk'); ",
        "digest": "$ctx.PreparedReceiptSha256='0'*64; ",
        "replaced": "[IO.Directory]::Move($output,($output+'-original')); [void][IO.Directory]::CreateDirectory($output); ",
        "vmx": "[IO.File]::WriteAllText($vmx,'public VMX'); ",
        "unsupported": "[IO.File]::WriteAllText((Join-Path $output 'unrelated.txt'),'preserve'); ",
        "foreign": "$ctx.TaskId='another-task'; ",
        "process_digest": "$directory=Get-Content -LiteralPath $ctx.PreparedReceiptPath -Raw | ConvertFrom-Json; [IO.File]::AppendAllText($directory.clone_process.path,' '); ",
    }
    result = run_powershell(
        ownership_prefix() + context_script(tmp_path)
        + f"$ctx | Add-Member -NotePropertyName PreparedReceiptPath -NotePropertyValue {ps_literal(selectors['path'])}; "
        + f"$ctx | Add-Member -NotePropertyName PreparedReceiptSha256 -NotePropertyValue '{selectors['sha']}'; "
        + changes[case]
        + "Remove-AtlasoTestVmPreparedOutput -Context $ctx -ReceiptPath $ctx.PreparedReceiptPath "
        + f"-ReceiptSha256 $ctx.PreparedReceiptSha256 -VmrunPath {ps_literal(provider)} -Confirm:$false; "
        + "if (Test-Path -LiteralPath $output) { throw 'Recovery did not retire the original directory' }",
        check=False,
        environment=environment,
    )
    if case in {"empty", "partial"}:
        assert result.returncode == 0, result.stdout + result.stderr
        assert not (tmp_path / "checkout" / "test-vm").exists()
    else:
        assert result.returncode != 0
        assert (tmp_path / "checkout" / "test-vm").exists()


@pytest.mark.parametrize("mode", ["active", "publication", "legacy", "whatif"])
def test_clone_process_publication_and_active_controller_fail_closed(tmp_path, mode):
    """No child starts without publication and active or legacy controllers prevent recovery.

    Args:
        tmp_path: Original pytest-owned temporary root.
        mode: Active-controller, failed-publication, missing-evidence, or dry-run boundary.
    """
    (tmp_path / "evidence").mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("public fixture", encoding="utf-8")
    provider, environment, _, _ = _write_fake_vmrun(tmp_path / "provider", [], registered=False)
    setup = ownership_prefix() + context_script(tmp_path)
    setup += f"$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath {ps_literal(source)} "
    setup += f"-SourceVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get({ps_literal(source)})); "
    setup += "function Assert-AtlasoTestVmCheckoutSource { param($Context) }; "
    if mode == "publication":
        sentinel = tmp_path / "child-started.txt"
        setup += "$collision=Join-Path $evidence ('atlaso-test-vm-clone-process-'+$ctx.InvocationId+'.json'); "
        setup += "[IO.File]::WriteAllText($collision,'preserve'); $failure=$null; "
        child = f"[IO.File]::WriteAllText({ps_literal(sentinel)},'ran')"
        setup += "try { Invoke-AtlasoTestVmOwnedClone -Context $ctx -FilePath (Get-Process -Id $PID).Path "
        setup += f"-ArgumentList @('-NoProfile','-NonInteractive','-Command',{ps_literal(child)}) -TimeoutSeconds 30 "
        setup += "} catch { $failure=$_.Exception }; "
        setup += "if (-not $failure -or -not $failure.Data['AtlasoProcessTreeTerminationProven']) { throw 'No proven failed-publication termination' }; "
        setup += "if (Test-Path -LiteralPath $output) { throw 'Directory preceded child publication' }; "
        setup += ". '" + str(VMWARE / "Atlaso.WorkstationFirstBoot.ps1").replace("'", "''") + "'; "
        setup += "if (Open-AtlasoBoundedProcessJob -ProcessJobName ('Local\\Atlaso-TestVm-Clone-'+$ctx.InvocationId)) { throw 'Failed child job survived' }"
        result = run_powershell(setup, check=False, environment=environment)
        assert result.returncode == 0, result.stdout + result.stderr
        assert not sentinel.exists()
    else:
        if mode in {"legacy", "whatif"}:
            setup += "$pin=New-AtlasoTestVmPreparedOutput -Context $ctx; $pin.Dispose(); "
        else:
            setup += "Invoke-AtlasoTestVmOwnedClone -Context $ctx -FilePath $env:ComSpec -ArgumentList @('/c','exit','0') -TimeoutSeconds 30; $ctx.CloneOutputPin.Dispose(); "
        if mode == "whatif":
            setup += "function Assert-AtlasoTestVmCloneQuiescence { throw 'Dry run entered process recovery' }; "
        setup += "Remove-AtlasoTestVmPreparedOutput -Context $ctx -ReceiptPath $ctx.PreparedReceiptPath "
        setup += f"-ReceiptSha256 $ctx.PreparedReceiptSha256 -VmrunPath {ps_literal(provider)} -Confirm:$false"
        if mode == "whatif":
            setup += " -WhatIf"
        result = run_powershell(setup, check=False, environment=environment)
        assert (result.returncode == 0) if mode == "whatif" else (result.returncode != 0)
        assert (tmp_path / "checkout" / "test-vm").exists()
        if mode != "whatif":
            assert ("controller is active" if mode == "active" else "lacks clone process creation evidence") in result.stderr


def test_interrupted_clone_controller_requires_original_tree_quiescence(tmp_path):
    """A live clone refuses recovery; terminating its original controller permits exact recovery.

    Args:
        tmp_path: Original pytest-owned temporary root.
    """
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("public fixture", encoding="utf-8")
    output = tmp_path / "checkout" / "test-vm"
    partial = output / "partial.vmdk"
    provider, environment, _, _ = _write_fake_vmrun(tmp_path / "provider", [], registered=False)
    child = f"[IO.File]::WriteAllText({ps_literal(partial)},'partial'); Start-Sleep -Seconds 40"
    setup = ownership_prefix() + context_script(tmp_path)
    setup += f"$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath {ps_literal(source)} "
    setup += f"-SourceVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get({ps_literal(source)})); "
    setup += "function Assert-AtlasoTestVmCheckoutSource { param($Context) }; "
    setup += "try { Invoke-AtlasoTestVmOwnedClone -Context $ctx -FilePath (Get-Process -Id $PID).Path "
    setup += f"-ArgumentList @('-NoProfile','-NonInteractive','-Command',{ps_literal(child)}) -TimeoutSeconds 50 "
    setup += "} finally { if ($ctx.PSObject.Properties['CloneOutputPin']) { $ctx.CloneOutputPin.Dispose() } }"
    controller = subprocess.Popen(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", setup],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment,
    )
    try:
        deadline = time.monotonic() + 25
        while not partial.exists() and time.monotonic() < deadline and controller.poll() is None:
            time.sleep(0.1)
        assert partial.exists(), "The receipt-bound child did not reach its partial-clone boundary"
        paths = list(evidence.glob("atlaso-test-vm-directory-*.json"))
        directory_path = next(path for path in paths if json.loads(path.read_text(encoding="utf-8-sig"))["path"] == str(output))
        # Original publication selectors are read from the controller stream after its interruption.
        refusal = run_powershell(
            ownership_prefix() + context_script(tmp_path)
            + f"$directory=Get-Content -LiteralPath {ps_literal(directory_path)} -Raw | ConvertFrom-Json; "
            + "Assert-AtlasoTestVmCloneQuiescence -Context $ctx -DirectoryRecord $directory",
            check=False, environment=environment,
        )
        assert refusal.returncode != 0
        assert "controller is active" in refusal.stderr
        assert partial.exists()
        controller.terminate()
        stdout, stderr = controller.communicate(timeout=15)
        receipt_line = next(line for line in stdout.splitlines() if line == f"Test VM prepared directory receipt: {directory_path}")
        # Select the leaf publication from the emitted path and SHA pair, never re-hash later evidence.
        lines = stdout.splitlines()
        index = lines.index(receipt_line)
        receipt_path = receipt_line.split(": ", 1)[1]
        receipt_sha = lines[index + 1].split(": ", 1)[1]
        assert receipt_path == str(directory_path), stdout + stderr
        recovery = run_powershell(
            ownership_prefix() + context_script(tmp_path)
            + f"Remove-AtlasoTestVmPreparedOutput -Context $ctx -ReceiptPath {ps_literal(receipt_path)} "
            + f"-ReceiptSha256 '{receipt_sha}' -VmrunPath {ps_literal(provider)} -Confirm:$false",
            check=False, environment=environment,
        )
        assert recovery.returncode == 0, recovery.stdout + recovery.stderr
        assert not output.exists()
    finally:
        if controller.poll() is None:
            controller.terminate()
        controller.communicate(timeout=15)


def test_named_clone_job_collision_preserves_existing_child(tmp_path):
    """An existing named job is never adopted or terminated by a second clone.

    Args:
        tmp_path: Original pytest-owned temporary root.
    """
    (tmp_path / "evidence").mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("public fixture", encoding="utf-8")
    result = run_powershell(
        ownership_prefix() + context_script(tmp_path)
        + f"$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath {ps_literal(source)} "
        + f"-SourceVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get({ps_literal(source)})); "
        + f". {ps_literal(VMWARE / 'Atlaso.WorkstationFirstBoot.ps1')}; "
        + "$seed=New-AtlasoBoundedProcessJob -FilePath $env:ComSpec -ArgumentList @('/c','exit','0') "
        + "-ProcessJobName ('Local\\Atlaso-TestVm-Clone-'+$ctx.InvocationId) -DeferResume; try { "
        + "$refused=$false; try { Invoke-AtlasoTestVmOwnedClone -Context $ctx -FilePath $env:ComSpec "
        + "-ArgumentList @('/c','exit','0') -TimeoutSeconds 10 } catch { $refused=$true }; "
        + "if (-not $refused -or $seed.RootProcess.HasExited) { throw 'Existing job was adopted or terminated' }; "
        + "if (Test-Path -LiteralPath $output) { throw 'Collision prepared a directory' } "
        + "} finally { $seed.TerminateAndWait(10000); $seed.Dispose() }",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_prepared_root_removal_keeps_original_handle_through_retirement(tmp_path):
    """A concurrent rename cannot swap the captured root before handle deletion.

    Args:
        tmp_path: Original pytest-owned temporary root.
    """
    output = tmp_path / "prepared"
    output.mkdir()
    (output / "partial.vmdk").write_text("public incomplete disk", encoding="utf-8")
    result = run_powershell(
        ownership_prefix()
        + f"$output={ps_literal(output)}; $snapshot=& (Get-Module Atlaso.WorkstationCleanup) "
        + "{param($root) Get-AtlasoRootSnapshot -RemovalRoot $root} $output; "
        + "$inventory=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase); "
        + "foreach ($path in $snapshot.Items.Keys) { $inventory.Add($path,$snapshot.Items[$path]) }; "
        + "$removal=[Atlaso.WorkstationCapturedContentsV1]::new($output,$snapshot.RootIdentity,$inventory,$true); "
        + "try { $removal.CaptureSnapshot(); $renameBlocked=$false; "
        + "try { [IO.Directory]::Move($output,($output+'-replaced')) } catch { $renameBlocked=$true }; "
        + "if (-not $renameBlocked) { throw 'The original prepared root could be replaced' }; "
        + "$removal.RemoveRoot() } finally { $removal.Dispose() }; "
        + "if (Test-Path -LiteralPath $output) { throw 'Original root was not retired' }",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not output.exists()
    assert not output.with_name("prepared-replaced").exists()


@pytest.mark.parametrize("parameter", ["NoStart", "SkipLabNetworkAdapters", "IncludeLabNetworkAdapters", "SshPublicKeyPath", "ApplianceVmxPath"])
def test_prepared_recovery_rejects_creation_inputs_before_removal(tmp_path, parameter):
    """Invalid creation options preserve a recoverable destination and its evidence.

    Args:
        tmp_path: Original pytest-owned temporary root.
        parameter: Creation option forbidden by the cleanup-only invocation.
    """
    (tmp_path / "evidence").mkdir()
    source = tmp_path / "source.vmx"
    source.write_text("public fixture", encoding="utf-8")
    result = run_powershell(
        ownership_prefix() + context_script(tmp_path)
        + f"$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath {ps_literal(source)} "
        + f"-SourceVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get({ps_literal(source)})); "
        + "$pin=New-AtlasoTestVmPreparedOutput -Context $ctx; $pin.Dispose(); "
        + "$bound=@{RecoverPreparedDirectory=$true; PreparedDirectoryReceiptPath=$ctx.PreparedReceiptPath; "
        + "PreparedDirectoryReceiptSha256=$ctx.PreparedReceiptSha256}; "
        + f"$bound[{ps_literal(parameter)}]='invalid'; "
        + "Assert-AtlasoPreparedRecoveryParameters -BoundParameters $bound; "
        + "[IO.Directory]::Delete($output)",
        check=False,
    )
    assert result.returncode != 0
    assert "cleanup-only" in result.stderr
    assert (tmp_path / "checkout" / "test-vm").is_dir()
    assert list((tmp_path / "evidence").glob("atlaso-test-vm-directory-*.json"))


def identity_writer_prefix() -> str:
    """Load the actual VMX identity writer without executing VM creation."""
    return (
        f". {ps_literal(VMWARE / 'Atlaso.WorkstationFirstBoot.ps1')}; "
        "$tokens=$null; $parseErrors=$null; "
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile({ps_literal(VMWARE / 'create-atlaso-test-vm.ps1')}, "
        "[ref]$tokens,[ref]$parseErrors); if ($parseErrors) { throw 'Wrapper parse failed' }; "
        "$names=@('Set-AtlasoTestVmCleanupIdentity','Get-AtlasoTestVmCleanupIdentity',"
        "'Get-AtlasoTestVmCleanupIdentityHash','Get-AtlasoCleanupIdentityHash'); "
        "foreach ($node in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)) { "
        "if ($node.Name -in $names) { . ([scriptblock]::Create($node.Extent.Text)) } }; "
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
        + identity_writer_prefix()
        + context_script(tmp_path)
        + f"$source={ps_literal(source)}; $sourceId=[Atlaso.WorkstationFileIdentity]::Get($source); "
        + "$ctx=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath $source -SourceVmxIdentity $sourceId; "
        + "$cleanupIdentity=('d'*32); [void][System.IO.Directory]::CreateDirectory($output); "
        + "[System.IO.File]::WriteAllText($vmx, ('source clone' + [Environment]::NewLine)); "
        + "$events=[System.Collections.Generic.List[string]]::new(); function git { "
        + "if ($args.Count -eq 6 -and $args[0] -eq '-C' -and $args[2] -eq 'merge-base' -and "
        + "$args[3] -eq '--is-ancestor' -and $args[4] -eq ('a'*40) -and $args[5] -eq ('a'*40)) { "
        + "$global:LASTEXITCODE=0; return }; throw 'Unexpected Git command in publisher test' }; "
        + "$publication={param($held) Publish-AtlasoTestVmOriginalOwnership -Context $ctx -DirectoryPath $output "
        + "-VmxPath $vmx -CleanupIdentity $cleanupIdentity -HeldVmxStream $held | Out-Null}; "
        + "Set-AtlasoTestVmCleanupIdentity -VmxPath $vmx -Identity $cleanupIdentity "
        + "-ExpectedVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get($vmx)) -DurableIdentityAction $publication; "
        + "$events.Add('receipt'); $replacement=($vmx + '.replacement'); "
        + "[System.IO.File]::WriteAllText($replacement, ('configured' + [Environment]::NewLine + 'guestinfo.atlaso.test_vm_cleanup_identity = ' + [char]34 + $cleanupIdentity + [char]34 + [Environment]::NewLine)); "
        + "$backup=($vmx + '.backup'); [System.IO.File]::Replace($replacement,$vmx,$backup); $events.Add('configured'); "
        + "$verified=Assert-AtlasoTestVmOriginalOwnership -Context $ctx; "
        + "$record=Get-Content -LiteralPath $ctx.ReceiptPath -Raw | ConvertFrom-Json; "
        + "$oldIntent=$ctx.IntentPath; $ctx.InvocationId=[guid]::NewGuid().ToString('N'); "
        + "$redeploy=New-AtlasoTestVmOwnershipIntent -Context $ctx -SourceVmxPath $source -SourceVmxIdentity $sourceId -ExistingReceipt $verified; "
        + "$receiptBytes=[System.IO.File]::ReadAllBytes($ctx.ReceiptPath); "
        + "[System.IO.File]::AppendAllText($ctx.ReceiptPath,' '); $tamperRejected=$false; "
        + "try { Assert-AtlasoTestVmOriginalOwnership -Context $ctx | Out-Null } catch { $tamperRejected=$true }; "
        + "[System.IO.File]::WriteAllBytes($ctx.ReceiptPath,$receiptBytes); "
        + "$preservedDigest=$ctx.ReceiptSha256; $ctx.ReceiptSha256=''; $missingDigestRejected=$false; "
        + "try { Assert-AtlasoTestVmOriginalOwnership -Context $ctx | Out-Null } catch { $missingDigestRejected=$true }; "
        + "$ctx.ReceiptSha256=$preservedDigest; "
        + "[pscustomobject]@{intent=$oldIntent; receipt=$ctx.ReceiptPath; hash=$ctx.ReceiptSha256; redeployIntent=$redeploy.IntentPath; "
        + "events=@($events); verified=($verified.Path -eq $ctx.ReceiptPath); directory=$record.original_identities.directory; vmx=$record.original_identities.vmx; "
        + "persistentIdentityHash=$record.persistent_vm_identity_sha256; currentVmx=([Atlaso.WorkstationFileIdentity]::Get($vmx)); backupExists=(Test-Path -LiteralPath $backup); "
        + "tamperRejected=$tamperRejected; missingDigestRejected=$missingDigestRejected; "
        + "task=$record.task_id; source=$record.source_commit; cleanup=$record.cleanup_tool; "
        + "sourceRole=$record.source_template.role} | ConvertTo-Json -Compress"
    )
    result = run_powershell(command)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["events"] == ["receipt", "configured"]
    assert payload["verified"]
    assert payload["tamperRejected"] and payload["missingDigestRejected"]
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
        request: Pytest finalizer registration for the isolated Git fixture.
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
    (checkout / ".gitattributes").write_text("*.txt text\n", encoding="utf-8")
    (checkout / "spaced name.txt").write_bytes(b"line\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-m", "source"], check=True,
                   capture_output=True, text=True)
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True).stdout.strip()
    (checkout / "spaced name.txt").write_bytes(b"line\r\n")
    subprocess.run(["git", "-C", str(checkout), "add", "spaced name.txt"], check=True,
                   capture_output=True, text=True)
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

    admission = command.split("[pscustomobject]@{enabled=", 1)[0]
    provider_sentinel = owner.root / "provider-called.txt"
    mutations = [
        f"[IO.File]::AppendAllText({ps_literal(checkout / 'source.txt')},'edit'); ",
        f"[IO.File]::WriteAllText({ps_literal(checkout / 'untracked.txt')},'new'); ",
        f"git -C {ps_literal(checkout)} switch -c late-branch; ",
        f"git -C {ps_literal(checkout)} switch -c late-commit; git -C {ps_literal(checkout)} commit --allow-empty -m later; ",
        f"git -C {ps_literal(checkout)} update-index --assume-unchanged source.txt; "
        + f"[IO.File]::WriteAllText({ps_literal(checkout / 'source.txt')},'hidden'); ",
        f"git -C {ps_literal(checkout)} update-index --skip-worktree source.txt; "
        + f"[IO.File]::WriteAllText({ps_literal(checkout / 'source.txt')},'hidden'); ",
        # Model a stale clean-status result while leaving enumeration and byte hashing real.
        f"[IO.File]::WriteAllText({ps_literal(checkout / 'source.txt')},'hidden'); "
        + "function git { if ($args -contains 'status') { $global:LASTEXITCODE=0; return }; "
        + f"$input | & {ps_literal(shutil.which('git'))} @args }}; ",
    ]
    for mutation in mutations:
        drifted = run_powershell(
            admission + mutation
            + "Assert-AtlasoTestVmCheckoutSource -Context $ctx; "
            + f"[IO.File]::WriteAllText({ps_literal(provider_sentinel)},'provider mutation')",
            check=False,
        )
        assert drifted.returncode != 0
        assert "changed during preflight" in drifted.stderr
        if "function git" in mutation:
            assert "Tracked source bytes changed" in drifted.stderr
        assert not provider_sentinel.exists()
        for flag in ("--no-assume-unchanged", "--no-skip-worktree"):
            subprocess.run(["git", "-C", str(checkout), "update-index", flag, "source.txt"],
                           check=True, capture_output=True, text=True)
        (checkout / "source.txt").write_text("source", encoding="utf-8")
        (checkout / "untracked.txt").unlink(missing_ok=True)
        subprocess.run(["git", "-C", str(checkout), "switch", "bug/946-test-vm-ownership"],
                       check=True, capture_output=True, text=True)
    clean = run_powershell(admission + "Assert-AtlasoTestVmCheckoutSource -Context $ctx")
    assert clean.returncode == 0

    (checkout / "untracked.txt").write_text("dirty", encoding="utf-8")
    dirty = run_powershell(command, check=False)
    assert dirty.returncode != 0


def test_output_ancestor_pin_rejects_junction_before_clone(tmp_path):
    """Reject a redirected output ancestor before any provider can clone.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    target = tmp_path / "other"
    target.mkdir()
    link = tmp_path / "link"
    output = link / "new-vm"
    command = (
        ownership_prefix()
        + f"New-Item -ItemType Junction -Path {ps_literal(link)} -Target {ps_literal(target)} | Out-Null; "
        + f"Get-AtlasoTestVmOutputAncestorPin -OutputDirectory {ps_literal(output)}"
    )
    result = run_powershell(command, check=False)
    assert result.returncode != 0
    assert "ordinary directory" in result.stderr.lower()
    assert not (target / "new-vm").exists()


@pytest.mark.parametrize("failure", [False, True])
def test_clone_source_pins_protect_payload_bytes_and_release_on_failure(tmp_path, failure):
    """Real provenance checks retain both disks and release every handle on refusal.

    Args:
        tmp_path: Original pytest-owned temporary root.
        failure: Whether provenance intentionally fails after disk handles are acquired.
    """
    source = _write_vmware_payload_fixture(tmp_path / "source")
    expected = "0" * 40 if failure else "a" * 40
    result = run_powershell(
        ownership_prefix()
        + f"Import-Module {ps_literal(VMWARE / 'Atlaso.VmwarePayload.psm1')}; "
        + f"$source={ps_literal(source)}; $identity=[Atlaso.WorkstationFileIdentity]::Get($source); "
        + "$pin=$null; $rejected=$false; try { "
        + f"$pin=Get-AtlasoTestVmCloneSourcePin -SourceVmxPath $source -SourceVmxIdentity $identity -ExpectedSourceCommit '{expected}'; "
        + "foreach ($payload in @(Get-AtlasoVmwarePayloadLayout -VmxPath $source -RequireExactlyTwoVmdks)) { "
        + "$writeBlocked=$false; $renameBlocked=$false; "
        + "try { [IO.File]::AppendAllText($payload.File.FullName,'mutation') } catch { $writeBlocked=$true }; "
        + "try { [IO.File]::Move($payload.File.FullName,($payload.File.FullName+'.replacement')) } catch { $renameBlocked=$true }; "
        + "if (-not ($writeBlocked -and $renameBlocked)) { throw 'Source payload bytes could change under the clone pin' } } "
        + "} catch { $rejected=$true; if ($pin) { throw } } finally { if ($pin) { $pin.Dispose() } }; "
        + f"if ($rejected -ne ${str(failure).lower()}) {{ throw 'Unexpected provenance result' }}; "
        + "foreach ($file in @(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($source)) -File)) { "
        + "$writer=[IO.File]::Open($file.FullName,'Open','Write','None'); $writer.Dispose() }; "
        + "$parent=[IO.Path]::GetDirectoryName($source); [IO.Directory]::Move($parent,($parent+'-released'))",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_clone_source_pin_rejects_replaced_template(tmp_path):
    """A template replaced during preflight cannot supply the later clone.

    Args:
        tmp_path: Existing pytest temporary root.
    """
    source = tmp_path / "source.vmx"
    source.write_text("original", encoding="utf-8")
    replacement = tmp_path / "replacement.vmx"
    replacement.write_text("replacement", encoding="utf-8")
    command = (
        ownership_prefix()
        + f"$source={ps_literal(source)}; $identity=[Atlaso.WorkstationFileIdentity]::Get($source); "
        + f"[System.IO.File]::Replace({ps_literal(replacement)},$source,{ps_literal(tmp_path / 'backup.vmx')}); "
        + "Get-AtlasoTestVmCloneSourcePin -SourceVmxPath $source -SourceVmxIdentity $identity"
    )
    result = run_powershell(command, check=False)
    assert result.returncode != 0
    assert "template changed before cloning" in result.stderr.lower()
    assert source.read_text(encoding="utf-8") == "replacement"


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


@pytest.mark.parametrize("mismatch", ["root", "marker", "duplicate", "partial", "none"])
def test_cleanup_binds_caller_original_identities_before_provider(tmp_path, mismatch):
    """Native cleanup refuses substituted identities before its provider boundary.

    Args:
        tmp_path: Existing pytest temporary root.
        mismatch: Original ownership selector to mismatch, or a valid dry run.
    """
    output = tmp_path / "vm"
    output.mkdir()
    vmx = output / "test.vmx"
    marker = "a" * 32
    marker_line = f'guestinfo.atlaso.test_vm_cleanup_identity = "{marker}"\n'
    contents = 'displayName = "test"\n' + marker_line
    if mismatch == "duplicate":
        contents += marker_line
    vmx.write_text(contents, encoding="utf-8")
    command = (
        ownership_prefix()
        + f"$output={ps_literal(output)}; $vmx={ps_literal(vmx)}; "
        + "$rootId=[Atlaso.WorkstationFileIdentity]::Get($output); "
        + f"$markerHash=Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value '{marker}'; "
    )
    if mismatch == "root":
        command += "$rootId='00000000:0000000000000000'; "
    if mismatch == "marker":
        command += "$markerHash='0'*64; "
    selectors = "-ExpectedRootIdentity $rootId "
    if mismatch != "partial":
        selectors += "-ExpectedPersistentVmIdentitySha256 $markerHash "
    command += (
        "Remove-AtlasoWorkstationVmArtifacts -VmrunPath 'provider-must-not-run.exe' "
        "-VmxPaths @($vmx) -RemovalRoot $output " + selectors + "-WhatIf"
    )
    result = run_powershell(command, check=False)
    assert (result.returncode == 0) == (mismatch == "none")
    if mismatch == "root":
        assert "original identity" in result.stderr.lower()
    elif mismatch == "marker":
        assert "persistent vm identity" in result.stderr.lower()
    elif mismatch == "duplicate":
        assert "exactly one valid persistent" in result.stderr.lower()
    elif mismatch == "partial":
        assert "supplied together" in result.stderr.lower()
    assert vmx.read_text(encoding="utf-8") == contents


@pytest.mark.parametrize("registered", [False, True])
def test_receipt_bound_vm_cleanup_uses_captured_root_handles(tmp_path, registered):
    """Both unregistered and provider-surviving VM roots avoid pathname deletion.

    Args:
        tmp_path: Original pytest-owned temporary root.
        registered: Whether provider deletion runs before remaining artifacts retire.
    """
    output = tmp_path / "vm"
    output.mkdir()
    vmx = output / "test.vmx"
    marker = "a" * 32
    vmx.write_text(f'displayName = "test"\nguestinfo.atlaso.test_vm_cleanup_identity = "{marker}"\n', encoding="utf-8")
    (output / "test.vmdk").write_text("public fixture", encoding="utf-8")
    provider, environment, _, _ = _write_fake_vmrun(tmp_path / "provider", [vmx], registered=registered)
    result = run_powershell(
        ownership_prefix()
        + f"$output={ps_literal(output)}; $vmx={ps_literal(vmx)}; "
        + "$rootId=[Atlaso.WorkstationFileIdentity]::Get($output); "
        + f"$markerHash=Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value '{marker}'; "
        + "& (Get-Module Atlaso.WorkstationCleanup) { function script:Remove-Item { "
        + "param($LiteralPath,[switch]$Recurse,[switch]$Force,$ErrorAction) throw 'Pathname cleanup is forbidden in this test' } }; "
        + f"Remove-AtlasoWorkstationVmArtifacts -VmrunPath {ps_literal(provider)} -VmxPaths @($vmx) "
        + "-RemovalRoot $output -ExpectedRootIdentity $rootId -ExpectedPersistentVmIdentitySha256 $markerHash -Confirm:$false",
        check=False,
        environment=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not output.exists()
