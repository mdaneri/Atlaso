"""Behavior tests for fail-closed Hyper-V artifact cleanup."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HYPERV_MODULE = REPOSITORY_ROOT / "scripts" / "windows" / "hyperv" / "Atlaso.HypervCleanup.psm1"


def _pwsh_path() -> str:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required for Hyper-V cleanup behavior tests")
    return pwsh


def _run_hyperv_cleanup(
    tmp_path: Path,
    *,
    hyperv_root: Path,
    removal_root: Path,
    state: str = "Running",
    stop_fails: bool = False,
    remove_fails: bool = False,
    include_vm: bool = True,
    stop_sticky: bool = False,
    remove_sticky: bool = False,
    inventory_move_timing: str | None = None,
    inventory_path: Path | None = None,
    inventory_disk_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the cleanup module against deterministic in-process Hyper-V cmdlet fakes.

    Args:
        tmp_path: Isolated test directory.
        hyperv_root: Canonical provider artifact root.
        removal_root: Exact artifact child selected for recursive cleanup.
        state: Initial fake VM state.
        stop_fails: Whether the fake stop command throws.
        remove_fails: Whether the fake remove command throws.
        include_vm: Whether the fake inventory contains a VM using the artifact root.
        stop_sticky: Whether a successful stop leaves the VM active.
        remove_sticky: Whether a successful removal leaves the VM registered.
        inventory_move_timing: Whether fake storage moves before or during the stop refresh.
        inventory_path: Optional fake VM configuration and disk parent path.
        inventory_disk_path: Optional fake attached-disk path.

    Returns:
        Completed PowerShell process.
    """
    state_path = tmp_path / "hyperv-state.json"
    effective_inventory_path = inventory_path or removal_root / "Atlaso-Test"
    state_path.write_text(
        json.dumps(
            {
                "vms": [
                    {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "name": "Atlaso-Test",
                        "state": state,
                        "path": str(effective_inventory_path),
                        "disk": str(inventory_disk_path or effective_inventory_path / "disk.vhdx"),
                    }
                ]
                if include_vm
                else [],
                "stop_fails": stop_fails,
                "remove_fails": remove_fails,
                "stop_sticky": stop_sticky,
                "remove_sticky": remove_sticky,
                "move_before_stop": inventory_move_timing == "before-stop",
                "move_after_stop": inventory_move_timing == "after-stop",
                "outside_path": str(hyperv_root.parent / "moved" / "Atlaso-Test"),
                "get_calls": 0,
            }
        ),
        encoding="utf-8",
    )
    wrapper = tmp_path / "hyperv-cleanup-test.ps1"
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
$global:StatePath = '{state_path}'
function Read-FakeState {{ Get-Content -LiteralPath $global:StatePath -Raw | ConvertFrom-Json }}
function Write-FakeState([object]$State) {{
    [System.IO.File]::WriteAllText($global:StatePath, ($State | ConvertTo-Json -Depth 5))
}}
function Get-VM {{
    param([object]$ErrorAction)
    $state = Read-FakeState
    $state.get_calls = [int]$state.get_calls + 1
    if ($state.move_before_stop -and $state.get_calls -eq 2) {{
        foreach ($entry in $state.vms) {{
            $entry.path = $state.outside_path
            $entry.disk = Join-Path $state.outside_path 'disk.vhdx'
        }}
    }}
    Write-FakeState $state
    @($state.vms | ForEach-Object {{
        [pscustomobject]@{{
            Id = [guid]$_.id; Name = $_.name; State = $_.state; Path = $_.path
            ConfigurationLocation = $_.path; CheckpointFileLocation = $_.path
            SnapshotFileLocation = $_.path; SmartPagingFilePath = $_.path
            DiskPath = $_.disk
        }}
    }})
}}
function Get-VMHardDiskDrive {{
    param([object]$VM, [object]$ErrorAction)
    [pscustomobject]@{{ Path = $VM.DiskPath }}
}}
function Stop-VM {{
    param([object]$VM, [switch]$TurnOff, [switch]$Force, [object]$ErrorAction)
    $state = Read-FakeState
    if ($state.stop_fails) {{ throw 'simulated Hyper-V stop failure' }}
    if (-not $state.stop_sticky) {{
        foreach ($entry in $state.vms) {{ if ($entry.id -eq $VM.Id) {{ $entry.state = 'Off' }} }}
    }}
    if ($state.move_after_stop) {{
        foreach ($entry in $state.vms) {{
            $entry.path = $state.outside_path
            $entry.disk = Join-Path $state.outside_path 'disk.vhdx'
        }}
    }}
    Write-FakeState $state
}}
function Remove-VM {{
    param([object]$VM, [switch]$Force, [object]$ErrorAction)
    $state = Read-FakeState
    if ($state.remove_fails) {{ throw 'simulated Hyper-V remove failure' }}
    if (-not $state.remove_sticky) {{
        $state.vms = @($state.vms | Where-Object {{ $_.id -ne $VM.Id }})
    }}
    Write-FakeState $state
}}
Import-Module '{HYPERV_MODULE}' -Force
Remove-AtlasoHypervArtifactRoot `
    -HypervRoot '{hyperv_root}' `
    -RemovalRoot '{removal_root}' `
    -Confirm:$false
Write-Host 'HYPERV CLEANUP SUCCEEDED'
""",
        encoding="utf-8",
    )
    return subprocess.run(
        [_pwsh_path(), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(wrapper)],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("stop_fails", "remove_fails", "expected_error"),
    [
        (True, False, "simulated Hyper-V stop failure"),
        (False, True, "simulated Hyper-V remove failure"),
    ],
)
def test_hyperv_cleanup_preserves_artifacts_after_platform_failure(
    tmp_path: Path,
    stop_fails: bool,
    remove_fails: bool,
    expected_error: str,
) -> None:
    """A failed stop or unregister-equivalent removal must preserve the artifact tree."""
    hyperv_root = tmp_path / "hyperv"
    removal_root = hyperv_root / "test-vms"
    disk_path = removal_root / "Atlaso-Test" / "disk.vhdx"
    disk_path.parent.mkdir(parents=True)
    disk_path.write_text("preserve", encoding="utf-8")

    result = _run_hyperv_cleanup(
        tmp_path,
        hyperv_root=hyperv_root,
        removal_root=removal_root,
        stop_fails=stop_fails,
        remove_fails=remove_fails,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert "HYPERV CLEANUP SUCCEEDED" not in result.stdout
    assert disk_path.read_text(encoding="utf-8") == "preserve"


def test_hyperv_cleanup_verifies_transitions_then_removes_artifacts(tmp_path: Path) -> None:
    """The successful path stops, removes, rechecks, and deletes the exact artifact root."""
    hyperv_root = tmp_path / "hyperv"
    removal_root = hyperv_root / "output"
    disk_path = removal_root / "Atlaso-Test" / "disk.vhdx"
    disk_path.parent.mkdir(parents=True)
    disk_path.write_text("payload", encoding="utf-8")

    result = _run_hyperv_cleanup(
        tmp_path,
        hyperv_root=hyperv_root,
        removal_root=removal_root,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "HYPERV CLEANUP SUCCEEDED" in result.stdout
    assert not removal_root.exists()


@pytest.mark.parametrize(
    ("stop_sticky", "remove_sticky", "expected_error"),
    [
        (True, False, "remains active after stop succeeded"),
        (False, True, "remains registered after removal succeeded"),
    ],
)
def test_hyperv_cleanup_rejects_incomplete_platform_transition(
    tmp_path: Path,
    stop_sticky: bool,
    remove_sticky: bool,
    expected_error: str,
) -> None:
    """Hyper-V success returns must be confirmed through a fresh inventory read."""
    hyperv_root = tmp_path / "hyperv"
    removal_root = hyperv_root / "test-vms"
    disk_path = removal_root / "Atlaso-Test" / "disk.vhdx"
    disk_path.parent.mkdir(parents=True)
    disk_path.write_text("preserve", encoding="utf-8")

    result = _run_hyperv_cleanup(
        tmp_path,
        hyperv_root=hyperv_root,
        removal_root=removal_root,
        stop_sticky=stop_sticky,
        remove_sticky=remove_sticky,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert disk_path.exists()


@pytest.mark.parametrize("inventory_move_timing", ("before-stop", "after-stop"))
def test_hyperv_cleanup_revalidates_vm_artifact_paths_before_removal(
    tmp_path: Path, inventory_move_timing: str
) -> None:
    """A VM whose storage moves after admission must remain registered with artifacts preserved."""
    hyperv_root = tmp_path / "hyperv"
    removal_root = hyperv_root / "test-vms"
    disk_path = removal_root / "Atlaso-Test" / "disk.vhdx"
    disk_path.parent.mkdir(parents=True)
    disk_path.write_text("preserve", encoding="utf-8")

    result = _run_hyperv_cleanup(
        tmp_path,
        hyperv_root=hyperv_root,
        removal_root=removal_root,
        inventory_move_timing=inventory_move_timing,
    )

    state = json.loads((tmp_path / "hyperv-state.json").read_text(encoding="utf-8"))
    assert result.returncode != 0
    assert "no longer references the requested artifact root" in result.stderr
    assert len(state["vms"]) == 1
    assert disk_path.read_text(encoding="utf-8") == "preserve"


def test_hyperv_cleanup_rejects_reparse_component_in_vm_inventory_path(tmp_path: Path) -> None:
    """A lexical child that resolves through a link cannot establish VM ownership."""
    hyperv_root = tmp_path / "hyperv"
    removal_root = hyperv_root / "test-vms"
    outside_root = tmp_path / "outside" / "Atlaso-Test"
    outside_disk = outside_root / "disk.vhdx"
    removal_root.mkdir(parents=True)
    outside_root.mkdir(parents=True)
    outside_disk.write_text("external", encoding="utf-8")
    linked_path = removal_root / "linked"
    try:
        linked_path.symlink_to(outside_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory links are unavailable: {error}")

    result = _run_hyperv_cleanup(
        tmp_path,
        hyperv_root=hyperv_root,
        removal_root=removal_root,
        inventory_path=linked_path,
    )

    state = json.loads((tmp_path / "hyperv-state.json").read_text(encoding="utf-8"))
    assert result.returncode != 0
    assert "reparse point" in result.stderr
    assert len(state["vms"]) == 1
    assert outside_disk.read_text(encoding="utf-8") == "external"
    assert removal_root.exists()


def test_hyperv_cleanup_validates_every_matching_vm_inventory_path(tmp_path: Path) -> None:
    """One safe configuration path cannot hide a later disk path through a directory link."""
    hyperv_root = tmp_path / "hyperv"
    removal_root = hyperv_root / "test-vms"
    safe_inventory_path = removal_root / "Atlaso-Test"
    safe_inventory_path.mkdir(parents=True)
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    outside_disk = outside_root / "disk.vhdx"
    outside_disk.write_text("external", encoding="utf-8")
    linked_path = removal_root / "linked"
    try:
        linked_path.symlink_to(outside_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory links are unavailable: {error}")

    result = _run_hyperv_cleanup(
        tmp_path,
        hyperv_root=hyperv_root,
        removal_root=removal_root,
        inventory_path=safe_inventory_path,
        inventory_disk_path=linked_path / "disk.vhdx",
    )

    state = json.loads((tmp_path / "hyperv-state.json").read_text(encoding="utf-8"))
    assert result.returncode != 0
    assert "reparse point" in result.stderr
    assert len(state["vms"]) == 1
    assert outside_disk.read_text(encoding="utf-8") == "external"
    assert removal_root.exists()


def test_standalone_cleanup_scripts_report_success_only_after_checked_removal() -> None:
    """Provider cleanup wrappers must delegate and keep success after every checked target."""
    vmware = (REPOSITORY_ROOT / "scripts/windows/vmware/clean-artifacts.ps1").read_text(
        encoding="utf-8"
    )
    hyperv = (REPOSITORY_ROOT / "scripts/windows/hyperv/clean-artifacts.ps1").read_text(
        encoding="utf-8"
    )

    assert "$ErrorActionPreference = 'Stop'" in vmware
    assert "Remove-AtlasoWorkstationArtifactRoot" in vmware
    assert vmware.index("Remove-AtlasoWorkstationArtifactRoot") < vmware.index("Cleaned up VMware")
    assert "$ErrorActionPreference = 'Stop'" in hyperv
    assert "Remove-AtlasoHypervArtifactRoot" in hyperv
    assert hyperv.index("Remove-AtlasoHypervArtifactRoot") < hyperv.index("Cleaned up Hyper-V")


@pytest.mark.parametrize(
    ("provider", "module_name", "success_text", "expected_error"),
    [
        (
            "vmware",
            "Atlaso.WorkstationCleanup.psm1",
            "Cleaned up VMware Workstation build artifacts.",
            "VMware artifact target exists but is not a directory",
        ),
        (
            "hyperv",
            "Atlaso.HypervCleanup.psm1",
            "Cleaned up Hyper-V build artifacts.",
            "Hyper-V artifact target exists but is not a directory",
        ),
    ],
)
def test_standalone_cleanup_rejects_file_shaped_canonical_target(
    tmp_path: Path,
    provider: str,
    module_name: str,
    success_text: str,
    expected_error: str,
) -> None:
    """A canonical artifact target that is a file must block the wrapper's success claim."""
    fixture_root = tmp_path / provider
    script_directory = fixture_root / "scripts" / "windows" / provider
    image_name = "vmware-workstation" if provider == "vmware" else provider
    image_directory = fixture_root / "image" / image_name
    script_directory.mkdir(parents=True)
    image_directory.mkdir(parents=True)
    source_directory = REPOSITORY_ROOT / "scripts" / "windows" / provider
    shutil.copy2(source_directory / "clean-artifacts.ps1", script_directory)
    shutil.copy2(source_directory / module_name, script_directory)
    canonical_target = image_directory / "output"
    canonical_target.write_text("not a directory", encoding="utf-8")
    arguments: list[str] = []
    if provider == "vmware":
        vmrun_path = fixture_root / "vmrun.exe"
        vmrun_path.write_text("not executed", encoding="utf-8")
        arguments = ["-VmrunPath", str(vmrun_path)]

    result = subprocess.run(
        [
            _pwsh_path(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_directory / "clean-artifacts.ps1"),
            *arguments,
        ],
        cwd=fixture_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert success_text not in result.stdout
    assert canonical_target.is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows file-sharing semantics are required")
def test_hyperv_cleanup_does_not_claim_success_after_locked_file(tmp_path: Path) -> None:
    """A locked artifact must make recursive cleanup fail without a success claim."""
    hyperv_root = tmp_path / "hyperv"
    removal_root = hyperv_root / "output"
    removal_root.mkdir(parents=True)
    locked_path = removal_root / "locked.vhdx"
    locked_path.write_text("locked", encoding="utf-8")

    with locked_path.open("rb"):
        result = _run_hyperv_cleanup(
            tmp_path,
            hyperv_root=hyperv_root,
            removal_root=removal_root,
            include_vm=False,
        )

    assert result.returncode != 0
    assert "HYPERV CLEANUP SUCCEEDED" not in result.stdout
    assert locked_path.exists()
