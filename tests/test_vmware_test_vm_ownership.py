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


@pytest.mark.parametrize("admission", ["valid", "foreign", "missing", "legacy"])
@pytest.mark.parametrize("phase", ["retired", "staged", "stopped-vmx-scrubbed"])
def test_pending_cleanup_admits_original_owner_before_any_marker_mutation(tmp_path, admission, phase):
    """Run the real pending loop and preserve foreign or unreceipted marker state.

    Args:
        tmp_path: Original pytest-owned fixture directory.
        admission: Exact original owner, foreign destination, absent receipt or legacy repair.
        phase: Retired, signer-bearing or rollback marker phase.
    """
    markers = tmp_path / "markers"
    markers.mkdir()
    marker_path = markers / "pending.json"
    marker_path.write_text("public marker fixture", encoding="utf-8")
    sentinel = tmp_path / "mutation.txt"
    vmx = tmp_path / "vm" / "test.vmx"
    destination = tmp_path / "other" / "test.vmx" if admission == "foreign" else vmx
    setup = "$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
    setup += f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(VMWARE / 'create-atlaso-test-vm.ps1')},[ref]$tokens,[ref]$errors); "
    setup += "$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-PendingAtlasoDevelopmentCaCleanup'},$true); "
    setup += ". ([scriptblock]::Create($fn.Extent.Text)); $script:admitted=$false; "
    setup += f"$ctx=[pscustomobject]@{{Enabled=$true;VmxPath={ps_literal(vmx)};OutputDirectory={ps_literal(vmx.parent)};Name='test'}}; "
    setup += f"$fixture=[pscustomobject]@{{VmxPath={ps_literal(destination)};OutputDirectory={ps_literal(destination.parent)};Name='test';Phase='{phase}';MarkerPath={ps_literal(marker_path)}}}; "
    setup += "function Assert-AtlasoStrictDescendantPath { param($ParentPath,$ChildPath,$FailureMessage) }; "
    setup += "function Assert-AtlasoTestVmOriginalOwnership { param($Context) "
    setup += "throw 'Original receipt missing' }; " if admission == "missing" else "$script:admitted=$true }; "
    setup += "function Read-AtlasoDevelopmentCaCleanupMarker { param($MarkerPath,$MarkerRoot) "
    setup += "throw 'The marked VMX changed filesystem identity; preserve it' }; " if admission == "legacy" else "$fixture }; "
    for name in ("Repair-AtlasoLegacyDevelopmentCaCleanupMarkerIdentity", "Remove-AtlasoDevelopmentCaCleanupMarker",
                 "Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub", "Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey",
                 "Stop-AtlasoTestVmForRollback", "Complete-AtlasoDevelopmentCaSuccessfulImport"):
        setup += f"function {name} {{ if (-not $script:admitted) {{ throw 'Mutation preceded original receipt' }}; "
        setup += f"[IO.File]::WriteAllText({ps_literal(sentinel)},'mutation'); throw 'Admitted mutation boundary' }}; "
    setup += f"Invoke-PendingAtlasoDevelopmentCaCleanup -VmrunPath 'unused' -TimeoutSeconds 5 -MarkerRoot {ps_literal(markers)} -OwnershipContext $ctx"
    result = run_powershell(setup, check=False)
    assert result.returncode != 0
    assert marker_path.read_text(encoding="utf-8") == "public marker fixture"
    if admission == "valid":
        assert sentinel.exists(), result.stdout + result.stderr
    else:
        assert not sentinel.exists(), result.stdout + result.stderr
        expected = {"foreign": "preserve unrelated markers", "missing": "Original receipt missing", "legacy": "changed filesystem identity"}
        assert expected[admission] in result.stderr


@pytest.mark.parametrize("recovery", ["healthy", "removed", "refused", "missing_receipt", "whatif"])
@pytest.mark.parametrize("template_condition", ["valid", "missing", "replaced"])
def test_existing_vm_rejection_follows_receipt_bound_pending_recovery(tmp_path, recovery, template_condition):
    """Execute parent preflight ordering without redeploying a recovered healthy VM.

    Args:
        tmp_path: Original pytest-owned fixture directory.
        recovery: Pending outcome, absent original receipt or mutation-free preview.
        template_condition: Fresh clone source available, absent or invalidated.
    """
    script = (VMWARE / "create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    start = script.index("if ($ownershipContext.Enabled -and (Test-Path -LiteralPath $resolvedOutputDirectory)")
    end = script.index("    # Resolve new Environment configuration", start)
    block = script[start:end].rsplit("if (-not $WhatIfPreference) {", 1)[0]
    output = tmp_path / "vm"
    output.mkdir()
    vmx = output / "test.vmx"
    vmx.write_text("public VM fixture", encoding="utf-8")
    captured = tmp_path / "events.json"
    setup = "$ErrorActionPreference='Stop'; $events=[Collections.Generic.List[string]]::new(); "
    template = tmp_path / "template.vmx"
    if template_condition != "missing":
        template.write_text("public template fixture", encoding="utf-8")
    setup += f"$repoRoot={ps_literal(ROOT)}; $resolvedOutputDirectory={ps_literal(output)}; $targetVmx={ps_literal(vmx)}; $ApplianceVmxPath={ps_literal(template)}; "
    setup += "$ownershipContext=[pscustomobject]@{Enabled=$true}; $LocalBuilder=$false; $NoStart=$false; $Redeploy=$false; $TimeoutSeconds=10; "
    setup += f"$WhatIfPreference=${str(recovery == 'whatif').lower()}; "
    setup += "function Assert-AtlasoTestVmOriginalOwnership { param($Context) $events.Add('receipt'); "
    setup += "throw 'Original receipt missing' }; " if recovery == "missing_receipt" else "[pscustomobject]@{} }; "
    setup += "function Assert-AtlasoVmwarePayloadProvenance { param($VmxPath,$ExpectedSourceCommit) $events.Add('template'); "
    setup += "throw 'Replaced template refused' }; " if template_condition == "replaced" else "}; "
    setup += "function New-AtlasoTestVmOwnershipIntent { param($Context,$SourceVmxPath,$SourceVmxIdentity,$ExistingReceipt) $events.Add('intent'); $Context }; "
    setup += "function Get-AtlasoDevelopmentRootCaFingerprint { param($CertificatePath) '0'*64 }; "
    setup += "function Confirm-OnePasswordTestVmArtifact { param($RepositoryRoot,$PythonCommand,$TimeoutSeconds) 'unused' }; "
    setup += "function Resolve-TestVmVmrunPath { param($Path) 'unused-provider' }; "
    setup += "function Assert-AtlasoTestVmCheckoutSource { param($Context) $events.Add('checkout') }; "
    setup += "function Invoke-PendingAtlasoDevelopmentCaCleanup { param($VmrunPath,$TimeoutSeconds,$ExpectedFingerprint,$OwnershipContext) $events.Add('recovery'); "
    if recovery == "removed":
        setup += "Remove-Item -LiteralPath $targetVmx; "
    elif recovery == "refused":
        setup += "throw 'Pending recovery refused'; "
    setup += "}; $failure=''; try { " + block + "; $events.Add('credential-boundary') } catch { $failure=$_.Exception.Message } finally { "
    setup += f"[IO.File]::WriteAllText({ps_literal(captured)},(@{{events=@($events);failure=$failure}} | ConvertTo-Json)) }}"
    result = run_powershell(ownership_prefix() + setup, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(captured.read_text(encoding="utf-8-sig"))
    events = evidence["events"]
    if recovery == "removed":
        if template_condition == "valid":
            assert events == ["receipt", "checkout", "recovery", "template", "intent", "credential-boundary"]
        elif template_condition == "missing":
            assert events == ["receipt", "checkout", "recovery"]
            assert "Cannot find path" in evidence["failure"]
        else:
            assert events == ["receipt", "checkout", "recovery", "template"]
            assert evidence["failure"] == "Replaced template refused"
        assert not vmx.exists()
    elif recovery == "healthy":
        assert events == ["receipt", "checkout", "recovery"]
        assert "VM already exists" in evidence["failure"]
        assert vmx.read_text(encoding="utf-8") == "public VM fixture"
    elif recovery == "refused":
        assert events == ["receipt", "checkout", "recovery"]
        assert evidence["failure"] == "Pending recovery refused"
    else:
        assert events == ["receipt"]
        assert ("Original receipt missing" if recovery == "missing_receipt" else "VM already exists") in evidence["failure"]


@pytest.mark.parametrize("caller", ["rollback", "persisted"])
@pytest.mark.parametrize("admission", ["valid", "missing", "human", "foreign", "drift"])
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
    setup += "function Assert-AtlasoTestVmCheckoutSource { param($Context) "
    setup += "throw 'Source drift refused' }; " if admission == "drift" else "}; "
    # The production block discards provider output; the fixture captures invocation arguments instead.
    setup += block.replace("| Out-Null", f"| Set-Content -LiteralPath {ps_literal(tmp_path / 'args.json')}")
    result = run_powershell(setup, check=False)
    captured = tmp_path / "args.json"
    if admission in {"missing", "foreign", "drift"}:
        assert result.returncode != 0
        message = "Source drift refused" if admission == "drift" else (
            "Persisted cleanup requires the original receipt" if admission == "foreign" and caller == "persisted" else "Original receipt missing"
        )
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


@pytest.mark.parametrize("case", ["valid", "retired", "missing", "missing_marker", "tampered", "vm_tampered", "intent_tampered", "foreign", "disk_binding", "active", "replacement"])
def test_post_removal_pending_recovery_requires_original_marker_receipt(tmp_path, case):
    """Actual pending recovery reaches restoration only with original immutable evidence.

    Args:
        tmp_path: Original pytest-owned fixture directory.
        case: Valid recovery or a selector, ownership, disk, child or root refusal.
    """
    (tmp_path / "evidence").mkdir()
    output = tmp_path / "checkout" / "test-vm"
    output.mkdir(parents=True)
    marker_root = tmp_path / "markers"
    marker_root.mkdir()
    marker_path = marker_root / "original-marker.json"
    marker_path.write_text("public marker", encoding="utf-8")
    sentinel = tmp_path / "restored.txt"
    command = ownership_prefix() + context_script(tmp_path)
    command += "function git { $global:LASTEXITCODE=0 }; function Get-AtlasoHostBootIdentity { '123' }; "
    command += "$base=[ordered]@{schema=1; task_id=$ctx.TaskId;repository=$ctx.Repository;worktree=$ctx.Worktree;source_branch=$ctx.Branch;"
    command += "source_commit=$ctx.SourceCommit;output_directory=$ctx.OutputDirectory;vmx_path=$ctx.VmxPath;canonical_name=$ctx.Name;pull_request_number=$ctx.PullRequestNumber;local_builder=$ctx.LocalBuilder}; "
    command += "function FixtureRecord { param($phase) $r=[ordered]@{}; foreach($k in $base.Keys){$r[$k]=$base[$k]};$r.phase=$phase;return $r }; "
    command += "$intent=Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record (FixtureRecord 'clone-pending') -Kind intent; "
    command += "$vm=FixtureRecord 'original-clone-created'; $vm.intent_path=$intent.Path; $vm.intent_sha256=$intent.Sha256; "
    command += "$vm.original_identities=@{directory=[Atlaso.WorkstationFileIdentity]::Get($output)}; $vm.persistent_vm_identity_sha256='a'*64; "
    command += "$original=Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record $vm -Kind original; "
    command += "$ctx | Add-Member ReceiptPath $original.Path; $ctx | Add-Member ReceiptSha256 $original.Sha256; "
    command += f"$marker=[pscustomobject]@{{MarkerPath={ps_literal(marker_path)};Name=$ctx.Name;VmxPath=$ctx.VmxPath;OutputDirectory=$output;"
    command += "Phase='stopped-vmx-scrubbed';HostBootIdentity='123';ArtifactsRemoved=$true;CleanupIdentityHash=('b'*64);DataDisks=@();QuarantineDirectory=($output+'-quarantine')}; "
    command += "$proof=FixtureRecord 'ca-marker-original'; $proof.original_receipt_path=$original.Path;$proof.original_receipt_sha256=$original.Sha256; "
    command += "$proof.original_directory_identity=$vm.original_identities.directory;$proof.persistent_vm_identity_sha256=$vm.persistent_vm_identity_sha256; "
    command += "$proof.marker_path=$marker.MarkerPath;$proof.host_boot_identity=$marker.HostBootIdentity;$proof.marker_projection=Get-AtlasoTestVmMarkerProjection $marker; "
    command += "$published=Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record $proof -Kind ca-marker; "
    command += "$ctx | Add-Member CleanupRecoveryReceiptPath $published.Path;$ctx | Add-Member CleanupRecoveryReceiptSha256 $published.Sha256; "
    command += "[IO.Directory]::Delete($output); "
    changes = {
        "valid": "", "retired": "$marker.Phase='retired'; ", "missing": "$ctx.CleanupRecoveryReceiptSha256=''; ",
        "missing_marker": "[IO.File]::Delete($marker.MarkerPath); ",
        "tampered": "[IO.File]::AppendAllText($published.Path,' '); ",
        "vm_tampered": "[IO.File]::AppendAllText($original.Path,' '); ",
        "intent_tampered": "[IO.File]::AppendAllText($intent.Path,' '); ",
        "foreign": "$ctx.TaskId='foreign-task'; ",
        "disk_binding": "$marker.DataDisks=@([pscustomobject]@{Path='foreign-disk';Identity='foreign'}); ",
        "active": "$marker.Phase='removal-child-active'; ",
        "replacement": "[void][IO.Directory]::CreateDirectory($output); $marker.ArtifactsRemoved=$false; ",
    }
    command += changes[case]
    command += "$tokens=$null;$errors=$null; "
    command += f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(VMWARE / 'create-atlaso-test-vm.ps1')},[ref]$tokens,[ref]$errors); "
    command += "$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-PendingAtlasoDevelopmentCaCleanup'},$true); . ([scriptblock]::Create($fn.Extent.Text)); "
    command += "function Assert-AtlasoStrictDescendantPath {param($ParentPath,$ChildPath,$FailureMessage)}; function Read-AtlasoDevelopmentCaCleanupMarker {param($MarkerPath,$MarkerRoot) $marker}; "
    command += "function Repair-AtlasoWorkstationStaleRegistrations {param($ScopeRoot,$VmxPath,$ExpectedDisplayName,$OnVerified,[switch]$Confirm) & $OnVerified }; "
    command += "function Restore-AtlasoRollbackDataDisksFromQuarantine {param($DataDiskStates,$QuarantineDirectory)}; "
    command += f"function Remove-AtlasoDevelopmentCaCleanupMarker {{param($MarkerPath) [IO.File]::WriteAllText({ps_literal(sentinel)},'restoration completed') }}; "
    command += f"Invoke-PendingAtlasoDevelopmentCaCleanup -VmrunPath 'must-not-run' -TimeoutSeconds 5 -MarkerRoot {ps_literal(marker_root)} -OwnershipContext $ctx"
    result = run_powershell(command, check=False)
    assert (result.returncode == 0) == (case in {"valid", "retired"}), result.stdout + result.stderr
    assert sentinel.exists() == (case in {"valid", "retired"})
    if case != "missing_marker":
        assert marker_path.read_text() == "public marker"


@pytest.mark.parametrize("failure", [False, True])
def test_owned_marker_callback_publishes_original_binding_before_marker(tmp_path, failure):
    """Exercise the VMX-locked production callback and publication refusal.

    Args:
        tmp_path: Original pytest-owned fixture directory.
        failure: Refuse original proof publication before the durable marker.
    """
    (tmp_path / "evidence").mkdir()
    output = tmp_path / "checkout" / "test-vm"
    output.mkdir(parents=True)
    vmx = output / "Atlaso-PR-946-test-vm.vmx"
    vmx.write_text('guestinfo.atlaso.test_vm_cleanup_identity = "' + "d" * 32 + '"\n', encoding="utf-8")
    disk = output / "preserved.vmdk"
    disk.write_text("public preserved data fixture", encoding="utf-8")
    markers = tmp_path / "markers"
    markers.mkdir()
    command = ownership_prefix() + context_script(tmp_path)
    command += f". {ps_literal(VMWARE / 'Atlaso.WorkstationFirstBoot.ps1')}; "
    command += "$tokens=$null;$errors=$null;"
    command += f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(VMWARE / 'create-atlaso-test-vm.ps1')},[ref]$tokens,[ref]$errors); "
    command += "foreach($fn in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($fn.Extent.Text))}; "
    command += "function git { $global:LASTEXITCODE=0 }; "
    command += "$base=[ordered]@{schema=1;task_id=$ctx.TaskId;repository=$ctx.Repository;worktree=$ctx.Worktree;source_branch=$ctx.Branch;source_commit=$ctx.SourceCommit;output_directory=$output;vmx_path=$vmx;canonical_name=$ctx.Name;pull_request_number=946;local_builder=$false}; "
    command += "function FixtureRecord {param($phase) $r=[ordered]@{};foreach($k in $base.Keys){$r[$k]=$base[$k]};$r.phase=$phase;return $r}; "
    command += "$intent=Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record (FixtureRecord 'clone-pending') -Kind intent; "
    command += "$vm=FixtureRecord 'original-clone-created';$vm.intent_path=$intent.Path;$vm.intent_sha256=$intent.Sha256;"
    command += "$vm.original_identities=@{directory=[Atlaso.WorkstationFileIdentity]::Get($output);vmx=[Atlaso.WorkstationFileIdentity]::Get($vmx)};"
    command += "$vm.persistent_vm_identity_sha256=Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value ('d'*32);"
    command += "$original=Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record $vm -Kind original;"
    command += "$ctx | Add-Member ReceiptPath $original.Path;$ctx | Add-Member ReceiptSha256 $original.Sha256;"
    if failure:
        command += "function Publish-AtlasoTestVmOwnershipRecord {throw 'Original proof publication refused'}; "
    command += f"$diskPath={ps_literal(disk)};$diskState=[pscustomobject]@{{Path=$diskPath;RelativePath='preserved.vmdk';Identity=[Atlaso.WorkstationFileIdentity]::Get($diskPath)}};"
    command += f"$marker=New-AtlasoDevelopmentCaCleanupMarker -VmxPath $vmx -Name $ctx.Name -OutputDirectory $output -DataDiskStates @($diskState) -MarkerRoot {ps_literal(markers)} -InitialPhase stopped-vmx-scrubbed -AllowExistingCleanupIdentity -OwnershipContext $ctx; "
    command += "$proofFile=@(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-test-vm-ca-marker-*')[0];"
    command += "$proof=Get-Content -LiteralPath $proofFile.FullName -Raw | ConvertFrom-Json;"
    command += "$ctx | Add-Member CleanupRecoveryReceiptPath $proofFile.FullName;$ctx | Add-Member CleanupRecoveryReceiptSha256 ((Get-FileHash $proofFile.FullName).Hash.ToLowerInvariant());"
    command += "$read=Read-AtlasoDevelopmentCaCleanupMarker -MarkerPath $marker -MarkerRoot ([IO.Path]::GetDirectoryName($marker));"
    command += "if($proof.original_receipt_sha256 -cne $original.Sha256 -or $proof.marker_projection -cne (Get-AtlasoTestVmMarkerProjection $read)){throw 'Original callback binding mismatch'};"
    command += "$writer=[IO.File]::Open($vmx,'Open','Write','None');$writer.Dispose();"
    command += "$quarantine=$read.QuarantineDirectory;[IO.Directory]::CreateDirectory($quarantine)|Out-Null;"
    command += "[IO.File]::Move($diskPath,(Join-Path $quarantine 'preserved.vmdk'));[IO.File]::Delete($vmx);[IO.Directory]::Delete($output);"
    command += "function Repair-AtlasoWorkstationStaleRegistrations {param($ScopeRoot,$VmxPath,$ExpectedDisplayName,$OnVerified,[switch]$Confirm) & $OnVerified};"
    command += f"Invoke-PendingAtlasoDevelopmentCaCleanup -VmrunPath 'provider-must-not-run' -TimeoutSeconds 5 -MarkerRoot {ps_literal(markers)} -OwnershipContext $ctx;"
    command += "if([Atlaso.WorkstationFileIdentity]::Get($diskPath) -cne $diskState.Identity){throw 'Restoration replaced original data'};"
    command += "[pscustomobject]@{marker=$marker;proof=$proofFile.FullName} | ConvertTo-Json -Compress"
    result = run_powershell(command, check=False)
    assert (result.returncode == 0) == (not failure), result.stdout + result.stderr
    if failure:
        assert "Original proof publication refused" in result.stderr
        assert not list(markers.iterdir())
    else:
        evidence = json.loads(result.stdout.strip().splitlines()[-1])
        assert not Path(evidence["marker"]).exists()
        assert Path(evidence["proof"]).exists()
        assert "Test VM cleanup recovery receipt SHA-256:" in result.stdout
    assert disk.read_text() == "public preserved data fixture"


@pytest.mark.parametrize("case", ["valid", "refused", "whatif", "unpaired", "redeploy"])
def test_parent_cleanup_recovery_selectors_stop_before_fresh_creation(tmp_path, case):
    """Execute the parent recovery-only selector gates and mutation-free preview.

    Args:
        tmp_path: Original pytest-owned fixture directory.
        case: Successful, refused, preview or invalid CLI selector combination.
    """
    script = (VMWARE / "create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    start = script.index("$existingOwnershipReceipt = $null")
    end = script.index("if ($ownershipContext.Enabled -and (Test-Path -LiteralPath $targetVmx) -and -not $Redeploy)", start)
    block = script[start:end]
    command = "$ErrorActionPreference='Stop';$events=[Collections.Generic.List[string]]::new();"
    command += f"$repoRoot={ps_literal(ROOT)};$resolvedOutputDirectory={ps_literal(tmp_path / 'removed')};$targetVmx=Join-Path $resolvedOutputDirectory 'vm.vmx';"
    command += "$ownershipContext=[pscustomobject]@{Enabled=$true};$CleanupRecoveryReceiptPath='original-marker-proof';"
    command += "$CleanupRecoveryReceiptSha256=" + ("'';" if case == "unpaired" else "('a'*64);")
    command += f"$Redeploy=${str(case == 'redeploy').lower()};$WhatIfPreference=${str(case == 'whatif').lower()};"
    command += "$TimeoutSeconds=5;$NoStart=$false;$RecoverPreparedDirectory=$false;$PreparedDirectoryReceiptPath='';$PreparedDirectoryReceiptSha256='';"
    command += "function Get-AtlasoDevelopmentRootCaFingerprint {'a'*64};function Confirm-OnePasswordTestVmArtifact {'unused'};function Resolve-TestVmVmrunPath {'unused'};function Assert-AtlasoTestVmCheckoutSource {$events.Add('source')};"
    command += "function Invoke-PendingAtlasoDevelopmentCaCleanup {$events.Add('recovery');"
    command += "throw 'Original recovery refused'};" if case == "refused" else "};"
    command += "$failure='';try { & {" + block + ";$events.Add('fresh-creation')} }catch{$failure=$_.Exception.Message};"
    command += "[pscustomobject]@{events=@($events);failure=$failure}|ConvertTo-Json -Compress"
    result = run_powershell(command)
    evidence = json.loads(result.stdout.strip().splitlines()[-1])
    assert "fresh-creation" not in evidence["events"]
    assert evidence["events"] == (["source", "recovery"] if case in {"valid", "refused"} else [])
    assert bool(evidence["failure"]) == (case in {"refused", "unpaired", "redeploy"})


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


@pytest.mark.parametrize("nonempty", [False, True])
def test_directory_publication_failure_retires_only_original_empty_leaf(tmp_path, nonempty):
    """Publication failure retires the retained empty object and preserves inserted artifacts.

    Args:
        tmp_path: Original pytest-owned temporary root.
        nonempty: Whether a concurrently inserted ordinary file prevents retirement.
    """
    destination = tmp_path / "failed-leaf"
    callback = "param($path,$identity) $blocked=$false; try { [IO.Directory]::Move($path,($path+'-replacement')) } catch { $blocked=$true }; "
    callback += "if (-not $blocked) { throw 'Original handle did not exclude replacement' }; "
    if nonempty:
        callback += "[IO.File]::WriteAllText((Join-Path $path 'preserve.txt'),'foreign child'); "
    callback += "throw 'Injected directory receipt publication failure'"
    result = run_powershell(
        ownership_prefix() + f"$publish=[Action[string,string]]{{{callback}}}; "
        + f"[Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath({ps_literal(destination)},$publish)",
        check=False,
    )
    assert result.returncode != 0
    assert "Injected directory receipt publication failure" in result.stderr
    assert destination.exists() == nonempty
    if nonempty:
        assert (destination / "preserve.txt").read_text() == "foreign child"
    else:
        retry = run_powershell(
            ownership_prefix()
            + f"$pin=[Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath({ps_literal(destination)},[Action[string,string]]{{param($path,$identity)}}); $pin.Dispose()"
        )
        assert retry.returncode == 0


@pytest.mark.parametrize("drift", [False, True])
@pytest.mark.parametrize("caller", ["initial", "restart"])
def test_post_signer_start_revalidates_source_before_provider_launch(tmp_path, drift, caller):
    """The actual post-signer launch block refuses source drift before calling the provider.

    Args:
        tmp_path: Original pytest-owned temporary root.
        drift: Whether the source guard reports a late edit.
        caller: Initial signer-bearing start or powered-off scrub restart.
    """
    script = (VMWARE / "create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    phase = script.index("-Phase vm-start-child-active", script.index("if (-not $createdThisInvocation")) if caller == "initial" else script.index("-Phase vm-restart-child-active")
    token = "Assert-AtlasoTestVmCheckoutSource" if caller == "initial" else "if ($OwnershipContext) { Assert-AtlasoTestVmCheckoutSource"
    start = script.index(token, phase)
    end = script.index("| Out-Null", start) + len("| Out-Null")
    block = script[start:end].replace("$PSScriptRoot", ps_literal(VMWARE))
    sentinel = tmp_path / "provider-called.txt"
    setup = "$ErrorActionPreference='Stop'; $ownershipContext=@{Enabled=$true}; $powerShellPath=(Get-Process -Id $PID).Path; "
    setup += "$targetVmx='public.vmx'; $resolvedVmrunPath='public-provider'; $TimeoutSeconds=10; $script:checked=$false; "
    setup += "$Marker=@{VmxPath=$targetVmx}; $VmrunPath=$resolvedVmrunPath; "
    setup += "function Assert-AtlasoTestVmCheckoutSource { param($Context) "
    setup += "throw 'Source drift refused' }; " if drift else "$script:checked=$true }; "
    setup += "function Invoke-AtlasoBoundedProcess { param($FilePath,$ArgumentList,$TimeoutSeconds,$Action) "
    setup += "if (-not $script:checked) { throw 'Provider preceded byte validation' }; "
    setup += f"[IO.File]::WriteAllText({ps_literal(sentinel)},'called') }}; "
    result = run_powershell(setup + block, check=False)
    assert (result.returncode != 0) if drift else (result.returncode == 0)
    assert sentinel.exists() == (not drift)


def test_post_clone_nic_helper_requires_parent_source_guard():
    """The low-level mutable NIC helper receives the admitted parent's immediate source guard."""
    parent = (VMWARE / "create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    child = (VMWARE / "create-atlaso-vm.ps1").read_text(encoding="utf-8")
    assert "MutationGuard = {\n                    param($Context)\n                    Assert-AtlasoTestVmCheckoutSource -Context $Context" in parent
    assert "if ($MutationGuard) { & $MutationGuard $CloneCreatedContext }\n& (Join-Path $PSScriptRoot 'set-test-nics.ps1')" in child


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


@pytest.mark.parametrize("case", ["empty", "partial", "backup", "digest", "replaced", "vmx", "unsupported", "foreign", "process_digest"])
def test_prepared_directory_recovery_requires_original_receipt_and_no_completed_vm(tmp_path, case):
    """A pre-callback failure can recover only its original incomplete destination.

    Args:
        tmp_path: Original pytest-owned temporary root.
        case: Empty recovery or a child, receipt, identity, VMX, artifact, or owner refusal.
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
        "backup": "[IO.File]::WriteAllText((Join-Path $output 'backup.vmdk'),'foreign backup after clone completion'); ",
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
    if case == "empty":
        assert result.returncode == 0, result.stdout + result.stderr
        assert not (tmp_path / "checkout" / "test-vm").exists()
    else:
        assert result.returncode != 0
        assert (tmp_path / "checkout" / "test-vm").exists()
        if case in {"partial", "backup"}:
            expected = "public incomplete disk" if case == "partial" else "foreign backup after clone completion"
            assert (tmp_path / "checkout" / "test-vm" / f"{case}.vmdk").read_text() == expected
            assert "no original child creation evidence" in result.stderr


@pytest.mark.parametrize("mode", ["active", "publication", "directory", "legacy", "whatif"])
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
    if mode in {"publication", "directory"}:
        sentinel = tmp_path / "child-started.txt"
        if mode == "directory":
            (tmp_path / "checkout").mkdir()
            setup += "$script:publisher=${function:Publish-AtlasoTestVmOwnershipRecord}; "
            setup += "function Publish-AtlasoTestVmOwnershipRecord { param($Context,$Record,$Kind) "
            setup += "if ($Kind -eq 'directory') { throw 'Injected directory publication failure' }; "
            setup += "& $script:publisher -Context $Context -Record $Record -Kind $Kind }; $failure=$null; "
        else:
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
    """Proven clone quiescence does not authorize deleting unreceipted children.

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
        assert recovery.returncode != 0, recovery.stdout + recovery.stderr
        assert "no original child creation evidence" in recovery.stderr
        assert partial.read_text() == "partial"
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


@pytest.mark.parametrize("late", [False, True])
def test_empty_prepared_cleanup_preserves_foreign_stale_registration(tmp_path, late):
    """A receipt for an empty directory does not own provider inventory entries.

    Args:
        tmp_path: Original pytest-owned fixture directory.
        late: Insert the foreign registration only at final inventory resolution.
    """
    output = tmp_path / "prepared"
    output.mkdir()
    inventory = tmp_path / "inventory.vmls"
    foreign = output / "foreign.vmx"
    original = f'vmlist9.config = "{foreign}"\nvmlist9.DisplayName = "Foreign VM"\nindex9.id = "{foreign}"\n'
    inventory.write_text("" if late else original, encoding="utf-8")
    provider, environment, _, _ = _write_fake_vmrun(tmp_path / "provider", [], registered=False)
    command = ownership_prefix() + f"$output={ps_literal(output)}; $identity=[Atlaso.WorkstationFileIdentity]::Get($output); "
    command += "& (Get-Module Atlaso.WorkstationCleanup) { "
    command += "$script:inventoryReads=0; "
    command += "function script:Resolve-AtlasoWorkstationInventoryPath { $script:inventoryReads++; "
    if late:
        command += f"if($script:inventoryReads -eq 2){{[IO.File]::WriteAllText({ps_literal(inventory)},{ps_literal(original)})}}; "
    command += f"{ps_literal(inventory)} }} "
    command += "function script:Remove-AtlasoWorkstationStaleRegistrations { throw 'Unowned provider repair reached' } }; "
    command += f"Remove-AtlasoWorkstationVmArtifacts -VmrunPath {ps_literal(provider)} -VmxPaths @() -RemovalRoot $output "
    command += "-ExpectedPreparedDirectoryIdentity $identity -Confirm:$false"
    result = run_powershell(command, check=False, environment=environment)
    assert result.returncode == 0, result.stdout + result.stderr
    assert inventory.read_text(encoding="utf-8") == original
    assert not output.exists()


def test_context_keeps_evidence_identity_captured_before_pin_release(tmp_path):
    """A native replacement immediately after admission cannot become the receipt root.

    Args:
        tmp_path: Original pytest-owned fixture directory.
    """
    permitted = tmp_path / "permitted"
    evidence = permitted / ".task-ownership"
    checkout = permitted / "task"
    evidence.mkdir(parents=True)
    checkout.mkdir()
    output = checkout / "test-vm"
    vmx = output / "test-vm.vmx"
    command = ownership_prefix() + "$env:CODEX_THREAD_ID=''; "
    command += f"$checkout={ps_literal(checkout)}; $evidence={ps_literal(evidence)}; $originalId=[Atlaso.WorkstationFileIdentity]::Get($evidence); "
    command += "function git { $global:LASTEXITCODE=0; "
    command += "if ($args -contains '--show-toplevel') { return $checkout }; if ($args -contains 'HEAD') { return ('a'*40) }; "
    command += "if ($args -contains '--show-current') { return 'bug/fixture' }; if ($args -contains 'status') { return }; "
    command += "if ($args -contains 'remote.origin.url') { return 'https://github.com/mdaneri/Atlaso.git' }; "
    command += "if ($args -contains 'worktree') { return ('worktree '+$checkout) }; throw 'Unexpected Git query' }; "
    command += "$body=${function:New-AtlasoTestVmOwnershipContext}.ToString(); "
    command += "$body=$body.Replace('if ($rootPin) { $rootPin.Dispose() }', 'if ($rootPin) { $rootPin.Dispose(); [IO.Directory]::Move($evidenceFullPath,($evidenceFullPath+''-original'')); [void][IO.Directory]::CreateDirectory($evidenceFullPath) }'); "
    command += "Set-Item function:New-AtlasoTestVmOwnershipContext ([scriptblock]::Create($body)); "
    command += f"$ctx=New-AtlasoTestVmOwnershipContext -Worktree $checkout -OwnershipRoot {ps_literal(permitted)} -OwnershipTaskId 'fixture-task' "
    command += f"-OutputDirectory {ps_literal(output)} -VmxPath {ps_literal(vmx)} -Name 'test-vm' -SourceCommit ('a'*40) -SourceBranch 'bug/fixture' -PullRequestNumber 947; "
    command += "if ($ctx.EvidenceDirectoryId -cne $originalId) { throw 'Replacement root was admitted' }; "
    command += "$refused=$false; try { Publish-AtlasoTestVmOwnershipRecord -Context $ctx -Record @{schema=1} -Kind original } catch { "
    command += "if ($_.Exception.Message -notlike '*identity changed before publication*') { throw }; $refused=$true }; "
    command += "if (-not $refused) { throw 'Replacement root accepted publication' }"
    result = run_powershell(command, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not list(evidence.glob("atlaso-test-vm-*.json"))


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


@pytest.mark.parametrize("retained", [False, True])
def test_original_vm_directory_and_vmx_are_published_before_configuration(tmp_path, retained):
    """The real publisher captures both original identities before VMX edits.

    Args:
        tmp_path: Existing pytest temporary root.
        retained: Whether the normal clone's original delete-capable creation handle remains held.
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
        + "$cleanupIdentity=('d'*32); "
        + ("$ctx | Add-Member -NotePropertyName CloneOutputPin -NotePropertyValue (New-AtlasoTestVmPreparedOutput -Context $ctx); " if retained
           else "[void][System.IO.Directory]::CreateDirectory($output); ")
        + "[System.IO.File]::WriteAllText($vmx, ('source clone' + [Environment]::NewLine)); "
        + "$events=[System.Collections.Generic.List[string]]::new(); function git { "
        + "if ($args.Count -eq 6 -and $args[0] -eq '-C' -and $args[2] -eq 'merge-base' -and "
        + "$args[3] -eq '--is-ancestor' -and $args[4] -eq ('a'*40) -and $args[5] -eq ('a'*40)) { "
        + "$global:LASTEXITCODE=0; return }; throw 'Unexpected Git command in publisher test' }; "
        + "$publication={param($held) Publish-AtlasoTestVmOriginalOwnership -Context $ctx -DirectoryPath $output "
        + "-VmxPath $vmx -CleanupIdentity $cleanupIdentity -HeldVmxStream $held | Out-Null}; "
        + "Set-AtlasoTestVmCleanupIdentity -VmxPath $vmx -Identity $cleanupIdentity "
        + "-ExpectedVmxIdentity ([Atlaso.WorkstationFileIdentity]::Get($vmx)) -DurableIdentityAction $publication; "
        + ("$ctx.CloneOutputPin.Dispose(); $ctx.CloneOutputPin=$null; " if retained else "")
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
