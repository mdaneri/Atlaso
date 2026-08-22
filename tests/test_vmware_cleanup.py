"""Behavior tests for fail-closed VMware Workstation cleanup."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VMWARE_SCRIPT_ROOT = REPOSITORY_ROOT / "scripts" / "windows" / "vmware"


def _pwsh_path() -> str:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required for VMware cleanup behavior tests")
    return pwsh


def _write_fake_vmrun(
    directory: Path,
    vmx_paths: list[Path],
    *,
    running: bool,
    registered: bool,
    stop_exit: int = 0,
    unregister_exit: int = 0,
    running_path_format: str = "{}",
    stop_sticky: bool = False,
    unregister_sticky: bool = False,
    late_registered_vmx: Path | None = None,
    late_registered_alias: Path | None = None,
    late_registered_list_count: int = 3,
    late_running_vmx: Path | None = None,
    late_running_list_count: int = 4,
    replace_after_delete_vmx: Path | None = None,
) -> tuple[Path, dict[str, str], Path]:
    """Create a stateful fake ``vmrun`` command and Workstation inventory.

    Args:
        directory: Directory that receives the fake command and mutable state.
        vmx_paths: VMX paths available to the fake running and registered inventories.
        running: Whether the supplied VMX paths begin in the running inventory.
        registered: Whether the supplied VMX paths begin in the registration inventory.
        stop_exit: Exit code returned by a requested stop operation.
        unregister_exit: Exit code returned by a requested deleteVM operation.
        running_path_format: Format applied to each path printed by ``vmrun list``.
        stop_sticky: Whether a successful stop leaves the VM in running inventory.
        unregister_sticky: Whether a successful deleteVM leaves the VM registered.
        late_registered_vmx: VMX injected into registration inventory at the final state gate.
        late_registered_alias: Optional hard-link alias registered instead of the injected VMX path.
        late_registered_list_count: Checked running-state read that triggers late registration.
        late_running_vmx: VMX injected into running inventory after registration stabilizes.
        late_running_list_count: Checked running-state read that triggers late running state.
        replace_after_delete_vmx: VMX replaced after the first successful deleteVM operation.

    Returns:
        The fake command path, its environment, and the command-log path.
    """
    directory.mkdir(parents=True, exist_ok=True)
    state_directory = directory / "state"
    state_directory.mkdir()
    canonical_paths = [str(path.resolve()) for path in vmx_paths]
    (state_directory / "running.json").write_text(
        json.dumps(canonical_paths if running else []), encoding="utf-8"
    )
    (state_directory / "registered.json").write_text(
        json.dumps(canonical_paths if registered else []), encoding="utf-8"
    )
    appdata_directory = directory / "appdata"
    inventory_path = appdata_directory / "VMware" / "inventory.vmls"
    inventory_path.parent.mkdir(parents=True)
    registered_paths = canonical_paths if registered else []
    inventory_path.write_text(
        '.encoding = "UTF-8"\n'
        + "".join(
            f'vmlist{index}.config = "{path}"\n'
            for index, path in enumerate(registered_paths, start=1)
        )
        + "".join(
            f'index{index}.id = "{path}"\n'
            for index, path in enumerate(registered_paths)
        )
        + f'index.count = "{len(registered_paths)}"\n',
        encoding="utf-8",
    )
    log_path = directory / "commands.jsonl"
    fake_script = directory / "fake_vmrun.py"
    fake_script.write_text(
        """from __future__ import annotations
import json
import os
from pathlib import Path
import sys

state = Path(os.environ["ATLASO_FAKE_VMRUN_STATE"])
log = Path(os.environ["ATLASO_FAKE_VMRUN_LOG"])
inventory = Path(os.environ["ATLASO_FAKE_VMRUN_INVENTORY"])
arguments = sys.argv[1:]
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\\n")
if len(arguments) < 3 or arguments[:2] != ["-T", "ws"]:
    print("unexpected vmrun arguments", file=sys.stderr)
    raise SystemExit(64)
command = arguments[2]

def read_paths(name: str) -> list[str]:
    return json.loads((state / f"{name}.json").read_text(encoding="utf-8"))

def write_paths(name: str, paths: list[str]) -> None:
    (state / f"{name}.json").write_text(json.dumps(paths), encoding="utf-8")

def same_file(left: str, right: str) -> bool:
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError):
        return Path(left) == Path(right)

def write_inventory(paths: list[str]) -> None:
    inventory.write_text(
        '.encoding = "UTF-8"\\n'
        + "".join(
            f'vmlist{index}.config = "{path}"\\n'
            for index, path in enumerate(paths, start=1)
        )
        + "".join(
            f'index{index}.id = "{path}"\\n'
            for index, path in enumerate(paths)
        )
        + f'index.count = "{len(paths)}"\\n',
        encoding="utf-8",
    )

if command == "list":
    count_path = state / "list-count.txt"
    list_count = int(count_path.read_text(encoding="utf-8")) + 1 if count_path.exists() else 1
    count_path.write_text(str(list_count), encoding="utf-8")
    late_registered = os.environ.get("ATLASO_FAKE_VMRUN_LATE_REGISTERED_VMX", "")
    late_registered_list_count = int(os.environ["ATLASO_FAKE_VMRUN_LATE_REGISTERED_LIST_COUNT"])
    if late_registered and list_count == late_registered_list_count:
        late_path = Path(late_registered)
        late_path.parent.mkdir(parents=True, exist_ok=True)
        late_path.write_text(f'displayName = "{late_path.stem}"\\n', encoding="utf-8")
        registered_path = late_path
        late_alias = os.environ.get("ATLASO_FAKE_VMRUN_LATE_REGISTERED_ALIAS", "")
        if late_alias:
            alias_path = Path(late_alias)
            alias_path.parent.mkdir(parents=True, exist_ok=True)
            os.link(late_path, alias_path)
            registered_path = alias_path
        registered_paths = read_paths("registered")
        registered_paths.append(str(registered_path.resolve()))
        write_paths("registered", registered_paths)
        write_inventory(registered_paths)
    late_running = os.environ.get("ATLASO_FAKE_VMRUN_LATE_RUNNING_VMX", "")
    late_running_list_count = int(os.environ["ATLASO_FAKE_VMRUN_LATE_RUNNING_LIST_COUNT"])
    if late_running and list_count == late_running_list_count:
        running_paths = read_paths("running")
        running_paths.append(str(Path(late_running).resolve()))
        write_paths("running", running_paths)
    paths = read_paths("running")
    print(f"Total running VMs: {len(paths)}")
    output_format = os.environ.get("ATLASO_FAKE_VMRUN_RUNNING_PATH_FORMAT", "{}")
    print("\\n".join(output_format.format(path) for path in paths))
    raise SystemExit(0)
if len(arguments) < 4:
    print("missing VMX path", file=sys.stderr)
    raise SystemExit(64)
target = str(Path(arguments[3]).resolve())
if command == "stop":
    exit_code = int(os.environ.get("ATLASO_FAKE_VMRUN_STOP_EXIT", "0"))
    if exit_code:
        print("simulated stop failure", file=sys.stderr)
        raise SystemExit(exit_code)
    if os.environ.get("ATLASO_FAKE_VMRUN_STOP_STICKY") != "1":
        write_paths("running", [path for path in read_paths("running") if not same_file(path, target)])
    raise SystemExit(0)
if command == "deleteVM":
    exit_code = int(os.environ.get("ATLASO_FAKE_VMRUN_UNREGISTER_EXIT", "0"))
    if exit_code:
        print("simulated deleteVM failure", file=sys.stderr)
        raise SystemExit(exit_code)
    registered_paths = read_paths("registered")
    if os.environ.get("ATLASO_FAKE_VMRUN_UNREGISTER_STICKY") != "1":
        registered_paths = [path for path in registered_paths if not same_file(path, target)]
        target_path = Path(target)
        for line in target_path.read_text(encoding="utf-8").splitlines():
            if ".fileName" not in line or "=" not in line:
                continue
            configured_path = line.split("=", 1)[1].strip().strip('"')
            if Path(configured_path).suffix.lower() != ".vmdk":
                continue
            disk_path = Path(configured_path)
            if not disk_path.is_absolute():
                disk_path = target_path.parent / disk_path
            disk_path.unlink(missing_ok=True)
        target_path.unlink(missing_ok=True)
    write_paths("registered", registered_paths)
    write_inventory(registered_paths)
    replacement = os.environ.get("ATLASO_FAKE_VMRUN_REPLACE_AFTER_DELETE_VMX", "")
    replacement_marker = state / "replacement-injected"
    if replacement and not replacement_marker.exists():
        replacement_path = Path(replacement)
        replacement_path.unlink(missing_ok=True)
        replacement_path.write_text(
            '.encoding = "UTF-8"\\ndisplayName = "Concurrent replacement"\\n',
            encoding="utf-8",
        )
        replacement_marker.write_text("done", encoding="utf-8")
    raise SystemExit(0)
print(f"unsupported vmrun command: {command}", file=sys.stderr)
raise SystemExit(64)
""",
        encoding="utf-8",
    )

    if os.name == "nt":
        wrapper = directory / "vmrun.cmd"
        wrapper.write_text(
            f'@echo off\r\n"{sys.executable}" "{fake_script}" %*\r\n',
            encoding="utf-8",
        )
    else:
        wrapper = directory / "vmrun"
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{fake_script}" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

    environment = os.environ.copy()
    environment.update(
        {
            "ATLASO_FAKE_VMRUN_STATE": str(state_directory),
            "ATLASO_FAKE_VMRUN_LOG": str(log_path),
            "ATLASO_FAKE_VMRUN_INVENTORY": str(inventory_path),
            "ATLASO_FAKE_VMRUN_STOP_EXIT": str(stop_exit),
            "ATLASO_FAKE_VMRUN_UNREGISTER_EXIT": str(unregister_exit),
            "ATLASO_FAKE_VMRUN_RUNNING_PATH_FORMAT": running_path_format,
            "ATLASO_FAKE_VMRUN_STOP_STICKY": "1" if stop_sticky else "0",
            "ATLASO_FAKE_VMRUN_UNREGISTER_STICKY": "1" if unregister_sticky else "0",
            "ATLASO_FAKE_VMRUN_LATE_REGISTERED_VMX": str(late_registered_vmx or ""),
            "ATLASO_FAKE_VMRUN_LATE_REGISTERED_ALIAS": str(late_registered_alias or ""),
            "ATLASO_FAKE_VMRUN_LATE_REGISTERED_LIST_COUNT": str(late_registered_list_count),
            "ATLASO_FAKE_VMRUN_LATE_RUNNING_VMX": str(late_running_vmx or ""),
            "ATLASO_FAKE_VMRUN_LATE_RUNNING_LIST_COUNT": str(late_running_list_count),
            "ATLASO_FAKE_VMRUN_REPLACE_AFTER_DELETE_VMX": str(
                replace_after_delete_vmx or ""
            ),
            "APPDATA": str(appdata_directory),
        }
    )
    return wrapper, environment, log_path


def _run_script(script: Path, *arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run a PowerShell test script without prompts.

    Args:
        script: PowerShell script to execute.
        *arguments: Command-line arguments passed to the script.
        environment: Environment containing the fake Workstation state.

    Returns:
        Completed process with captured text output.
    """
    return subprocess.run(
        [
            _pwsh_path(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *arguments,
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _write_vmx(path: Path, display_name: str) -> None:
    """Write a minimal VMX with a known display name.

    Args:
        path: VMX path to create.
        display_name: Display name stored in the VMX.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'displayName = "{display_name}"\n', encoding="utf-8")


def _run_artifact_root_cleanup(
    tmp_path: Path,
    *,
    artifact_parent: Path | None = None,
    expected_removal_root: Path | None = None,
    removal_root: Path,
    vmrun_path: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    """Invoke the shared whole-root cleanup entry point from an isolated wrapper.

    Args:
        tmp_path: Isolated test directory.
        artifact_parent: Optional canonical parent containing the removal root.
        expected_removal_root: Optional exact configured removal root.
        removal_root: Artifact directory requested for cleanup.
        vmrun_path: Fake vmrun executable path.
        environment: Environment for the PowerShell wrapper.

    Returns:
        Completed PowerShell process.
    """
    wrapper = tmp_path / "remove-artifact-root.ps1"
    module_path = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    if (artifact_parent is None) == (expected_removal_root is None):
        raise ValueError("Select exactly one cleanup root binding")
    root_binding = (
        f"-ArtifactParentRoot '{artifact_parent}'"
        if artifact_parent is not None
        else f"-ExpectedRemovalRoot '{expected_removal_root}'"
    )
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
Import-Module '{module_path}' -Force
Remove-AtlasoWorkstationArtifactRoot `
    -VmrunPath '{vmrun_path}' `
    {root_binding} `
    -RemovalRoot '{removal_root}' `
    -Confirm:$false
Write-Host 'ROOT CLEANUP SUCCEEDED'
""",
        encoding="utf-8",
    )
    return _run_script(wrapper, environment=environment)


def test_whole_artifact_root_cleanup_accepts_exact_absolute_configured_root(
    tmp_path: Path,
) -> None:
    """A supported absolute build output remains cleanable outside the Packer tree.

    Args:
        tmp_path: Isolated test directory.
    """
    removal_root = tmp_path / "custom-output" / "atlaso-photon"
    sentinel = removal_root / "sentinel.txt"
    removal_root.mkdir(parents=True)
    sentinel.write_text("replace", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake", [], running=False, registered=False
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        expected_removal_root=removal_root,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not removal_root.exists()


def test_whole_artifact_root_cleanup_accepts_stale_missing_registration_in_artifact_parent(
    tmp_path: Path,
) -> None:
    """Multi-root cleanup may pass a stale row from an already-removed sibling.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "test-vms"
    stale_vmx = artifact_parent / "output" / "Atlaso-Builder.vmx"
    sentinel = removal_root / "sentinel.txt"
    _write_vmx(stale_vmx, "Atlaso-Builder")
    removal_root.mkdir(parents=True)
    sentinel.write_text("remaining artifact", encoding="utf-8")
    vmrun_path, environment, log_path = _write_fake_vmrun(
        tmp_path / "fake", [stale_vmx], running=False, registered=True
    )
    stale_vmx.unlink()

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not removal_root.exists()
    commands = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert "deleteVM" not in [command[2] for command in commands]
    inventory_path = Path(environment["ATLASO_FAKE_VMRUN_INVENTORY"])
    assert str(stale_vmx.resolve()) not in inventory_path.read_text(encoding="utf-8")


def test_whole_artifact_root_cleanup_rejects_shared_vmlist_config_id(
    tmp_path: Path,
) -> None:
    """A stale and valid registration sharing one library ID must fail closed.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "test-vms"
    stale_vmx = artifact_parent / "output" / "Atlaso-Builder.vmx"
    valid_vmx = tmp_path / "unrelated" / "Unrelated.vmx"
    sentinel = removal_root / "sentinel.txt"
    _write_vmx(stale_vmx, "Atlaso-Builder")
    _write_vmx(valid_vmx, "Unrelated")
    removal_root.mkdir(parents=True)
    sentinel.write_text("remaining artifact", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake", [stale_vmx, valid_vmx], running=False, registered=True
    )
    inventory_path = Path(environment["ATLASO_FAKE_VMRUN_INVENTORY"])
    malformed_inventory = inventory_path.read_text(encoding="utf-8").replace(
        "vmlist2.config", "vmlist1.config"
    )
    inventory_path.write_text(malformed_inventory, encoding="utf-8")
    stale_vmx.unlink()

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "one library ID to multiple config paths" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "remaining artifact"
    assert str(valid_vmx.resolve()) in inventory_path.read_text(encoding="utf-8")


def test_whole_artifact_root_cleanup_rejects_stale_missing_registration_outside_root(
    tmp_path: Path,
) -> None:
    """A missing unrelated inventory entry must retain strict global verification.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    stale_vmx = tmp_path / "unrelated" / "Missing.vmx"
    sentinel = removal_root / "sentinel.txt"
    _write_vmx(stale_vmx, "Missing")
    removal_root.mkdir(parents=True)
    sentinel.write_text("preserve", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake", [stale_vmx], running=False, registered=True
    )
    stale_vmx.unlink()

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "filesystem identity cannot be resolved" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_whole_artifact_root_cleanup_rejects_configured_root_mismatch(tmp_path: Path) -> None:
    """Exact-root mode cannot be redirected to a sibling of the configured output.

    Args:
        tmp_path: Isolated test directory.
    """
    expected_root = tmp_path / "configured-output"
    removal_root = tmp_path / "other-output"
    expected_root.mkdir()
    removal_root.mkdir()
    sentinel = removal_root / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake", [], running=False, registered=False
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        expected_removal_root=expected_root,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "other than the exact configured output root" in result.stderr
    assert sentinel.exists()


@pytest.mark.parametrize(
    ("stop_exit", "unregister_exit", "expected_error"),
    [
        (9, 0, "Stop VMware Workstation VM"),
        (0, 9, "Delete VMware Workstation VM"),
    ],
)
def test_whole_artifact_root_cleanup_preserves_files_after_vmrun_failure(
    tmp_path: Path,
    stop_exit: int,
    unregister_exit: int,
    expected_error: str,
) -> None:
    """Forced rebuild cleanup must stop before deletion when vmrun cannot transition a VM.

    Args:
        tmp_path: Isolated test directory.
        stop_exit: Fake vmrun stop exit code.
        unregister_exit: Fake vmrun unregister exit code.
        expected_error: Expected cleanup failure text.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    vmx_path = removal_root / "Atlaso-Builder.vmx"
    sentinel = removal_root / "sentinel.txt"
    _write_vmx(vmx_path, "Atlaso-Builder")
    sentinel.write_text("preserve", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=True,
        registered=True,
        stop_exit=stop_exit,
        unregister_exit=unregister_exit,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert "ROOT CLEANUP SUCCEEDED" not in result.stdout
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_whole_artifact_root_cleanup_removes_all_verified_vms(tmp_path: Path) -> None:
    """The whole-root helper must reconcile every discovered VMX before deletion.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "test-vms"
    vmx_paths = [
        removal_root / "one" / "One.vmx",
        removal_root / "two" / "Two.vmx",
    ]
    for vmx_path in vmx_paths:
        _write_vmx(vmx_path, vmx_path.stem)
    vmrun_path, environment, log_path = _write_fake_vmrun(
        tmp_path / "fake",
        vmx_paths,
        running=True,
        registered=True,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not removal_root.exists()
    commands = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert [command[2] for command in commands].count("stop") == 2
    assert [command[2] for command in commands].count("deleteVM") == 2


def test_whole_artifact_root_cleanup_revalidates_each_target_before_delete(
    tmp_path: Path,
) -> None:
    """Replacing a later VMX during an earlier delete must preserve the new VM.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "test-vms"
    first_vmx = removal_root / "one" / "One.vmx"
    second_vmx = removal_root / "two" / "Two.vmx"
    _write_vmx(first_vmx, "One")
    _write_vmx(second_vmx, "Two")
    vmrun_path, environment, log_path = _write_fake_vmrun(
        tmp_path / "fake",
        [first_vmx, second_vmx],
        running=False,
        registered=True,
        replace_after_delete_vmx=second_vmx,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "VMX was replaced before provider deletion" in result.stderr
    assert second_vmx.read_text(encoding="utf-8").endswith(
        'displayName = "Concurrent replacement"\n'
    )
    commands = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert [command[2] for command in commands].count("deleteVM") == 1


def test_whole_artifact_root_cleanup_detaches_external_vmdks_before_delete(
    tmp_path: Path,
) -> None:
    """Provider deletion must not remove a data disk outside the cleanup root.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "test-vms" / "Atlaso-Test"
    vmx_path = removal_root / "Atlaso-Test.vmx"
    external_vmdk = tmp_path / "shared-disks" / "Atlaso-Depot.vmdk"
    _write_vmx(vmx_path, "Atlaso-Test")
    external_vmdk.parent.mkdir(parents=True)
    external_vmdk.write_text("shared depot disk", encoding="utf-8")
    with vmx_path.open("a", encoding="utf-8") as stream:
        stream.write('scsi0:2.present = "TRUE"\n')
        stream.write(f'scsi0:2.fileName = "{external_vmdk.resolve()}"\n')
        stream.write('scsi0:2.redo = ""\n')
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx_path], running=False, registered=True
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not removal_root.exists()
    assert external_vmdk.read_text(encoding="utf-8") == "shared depot disk"


def test_whole_artifact_root_cleanup_rejects_registered_hard_link_alias(
    tmp_path: Path,
) -> None:
    """A registered hard-link alias must fail before VMX replacement breaks identity.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "test-vms" / "Atlaso-Test"
    vmx_path = removal_root / "Atlaso-Test.vmx"
    registered_alias = tmp_path / "inventory-alias" / "Atlaso-Test-Alias.vmx"
    external_vmdk = tmp_path / "shared-disks" / "Atlaso-Depot.vmdk"
    _write_vmx(vmx_path, "Atlaso-Test")
    registered_alias.parent.mkdir(parents=True)
    os.link(vmx_path, registered_alias)
    external_vmdk.parent.mkdir(parents=True)
    external_vmdk.write_text("shared depot disk", encoding="utf-8")
    with vmx_path.open("a", encoding="utf-8") as stream:
        stream.write('scsi0:2.present = "TRUE"\n')
        stream.write(f'scsi0:2.fileName = "{external_vmdk.resolve()}"\n')
    original_vmx = vmx_path.read_bytes()
    vmrun_path, environment, log_path = _write_fake_vmrun(
        tmp_path / "fake", [registered_alias], running=False, registered=True
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "registered the cleanup target through a filesystem alias" in result.stderr
    assert vmx_path.read_bytes() == original_vmx
    assert registered_alias.read_bytes() == original_vmx
    assert external_vmdk.read_text(encoding="utf-8") == "shared depot disk"
    commands = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert "deleteVM" not in [command[2] for command in commands]


@pytest.mark.parametrize(
    ("unregister_exit", "unregister_sticky", "expected_error"),
    [
        (9, False, "Delete VMware Workstation VM"),
        (0, True, "VMX remains after deleteVM succeeded"),
    ],
)
def test_whole_artifact_root_cleanup_restores_external_vmdks_after_failed_delete(
    tmp_path: Path,
    unregister_exit: int,
    unregister_sticky: bool,
    expected_error: str,
) -> None:
    """A failed deletion transition must restore the surviving VMX byte-for-byte.

    Args:
        tmp_path: Isolated test directory.
        unregister_exit: Exit code returned by the fake deleteVM operation.
        unregister_sticky: Whether a successful deleteVM leaves the VMX in place.
        expected_error: Expected cleanup failure text.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "test-vms" / "Atlaso-Test"
    vmx_path = removal_root / "Atlaso-Test.vmx"
    external_vmdk = tmp_path / "shared-disks" / "Atlaso-Depot.vmdk"
    _write_vmx(vmx_path, "Atlaso-Test")
    external_vmdk.parent.mkdir(parents=True)
    external_vmdk.write_text("shared depot disk", encoding="utf-8")
    with vmx_path.open("a", encoding="utf-8") as stream:
        stream.write('scsi0:2.present = "TRUE"\n')
        stream.write(f'scsi0:2.fileName = "{external_vmdk.resolve()}"\n')
        stream.write('scsi0:2.redo = ""\n')
    original_vmx = vmx_path.read_bytes()
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=True,
        unregister_exit=unregister_exit,
        unregister_sticky=unregister_sticky,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert vmx_path.read_bytes() == original_vmx
    assert external_vmdk.read_text(encoding="utf-8") == "shared depot disk"


@pytest.mark.parametrize(
    ("stop_sticky", "unregister_sticky", "expected_error"),
    [
        (True, False, "remains running after stop succeeded"),
        (False, True, "VMX remains after deleteVM succeeded"),
    ],
)
def test_whole_artifact_root_cleanup_rejects_incomplete_vmrun_transition(
    tmp_path: Path,
    stop_sticky: bool,
    unregister_sticky: bool,
    expected_error: str,
) -> None:
    """A zero exit is insufficient when the follow-up inventory still contains the VM.

    Args:
        tmp_path: Isolated test directory.
        stop_sticky: Whether the fake running inventory remains unchanged after stop.
        unregister_sticky: Whether registration remains after deleteVM.
        expected_error: Expected cleanup failure text.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    vmx_path = removal_root / "Atlaso-Builder.vmx"
    _write_vmx(vmx_path, "Atlaso-Builder")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=True,
        registered=True,
        stop_sticky=stop_sticky,
        unregister_sticky=unregister_sticky,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert vmx_path.exists()


def test_whole_artifact_root_cleanup_rejects_late_registered_vmx(tmp_path: Path) -> None:
    """The final full inventory gate must preserve a late-registered VMX.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    initial_vmx = removal_root / "initial" / "Initial.vmx"
    late_vmx = removal_root / "late" / "Late.vmx"
    _write_vmx(initial_vmx, "Initial")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [initial_vmx],
        running=True,
        registered=True,
        late_registered_vmx=late_vmx,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "directory contains an unvalidated VMX" in result.stderr
    assert removal_root.exists()
    assert late_vmx.exists()


def test_whole_artifact_root_cleanup_rejects_vmx_created_during_delete(
    tmp_path: Path,
) -> None:
    """The post-delete VMX and registration gates must preserve a concurrent build.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    initial_vmx = removal_root / "initial" / "Initial.vmx"
    late_vmx = removal_root / "late" / "Late.vmx"
    _write_vmx(initial_vmx, "Initial")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [initial_vmx],
        running=False,
        registered=True,
        late_registered_vmx=late_vmx,
        late_registered_list_count=7,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "registration inventory changed during verification" in result.stderr
    assert removal_root.exists()
    assert late_vmx.exists()


def test_whole_artifact_root_cleanup_rechecks_running_vms_after_inventory_stability(
    tmp_path: Path,
) -> None:
    """A VM restarted during registration stabilization must preserve its artifacts.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    vmx_path = removal_root / "Atlaso-Builder.vmx"
    _write_vmx(vmx_path, "Atlaso-Builder")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=True,
        registered=True,
        late_running_vmx=vmx_path,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "running inventory changed during final verification" in result.stderr
    assert vmx_path.exists()


def test_whole_artifact_root_cleanup_rechecks_running_alias_immediately_before_removal(
    tmp_path: Path,
) -> None:
    """The last running check must match an unregistered target through a hard link.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    vmx_path = removal_root / "Atlaso-Builder.vmx"
    running_alias = tmp_path / "running-alias" / "Atlaso-Builder-Alias.vmx"
    _write_vmx(vmx_path, "Atlaso-Builder")
    running_alias.parent.mkdir(parents=True)
    os.link(vmx_path, running_alias)
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
        late_running_vmx=running_alias,
        late_running_list_count=5,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "remains running after deleteVM succeeded" in result.stderr
    assert vmx_path.exists()
    assert running_alias.exists()


def test_whole_artifact_root_cleanup_rechecks_registration_after_final_running_query(
    tmp_path: Path,
) -> None:
    """A VM registered by the final running query must preserve its artifacts.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    vmx_path = removal_root / "Atlaso-Builder.vmx"
    _write_vmx(vmx_path, "Atlaso-Builder")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=True,
        registered=True,
        late_registered_vmx=vmx_path,
        late_registered_list_count=4,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "registration inventory changed during verification" in result.stderr
    assert vmx_path.exists()


def test_whole_artifact_root_cleanup_matches_late_inventory_alias_by_file_identity(
    tmp_path: Path,
) -> None:
    """A late VMX registered through an out-of-root alias must preserve the root.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "output"
    initial_vmx = removal_root / "initial" / "Initial.vmx"
    late_vmx = removal_root / "late" / "Late.vmx"
    late_alias = tmp_path / "inventory-alias" / "LateAlias.vmx"
    _write_vmx(initial_vmx, "Initial")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [initial_vmx],
        running=True,
        registered=True,
        late_registered_vmx=late_vmx,
        late_registered_alias=late_alias,
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "directory contains an unvalidated VMX" in result.stderr
    assert removal_root.exists()
    assert late_vmx.exists()
    assert late_alias.exists()


def test_whole_artifact_root_cleanup_rejects_an_out_of_root_target(tmp_path: Path) -> None:
    """A caller cannot widen recursive deletion beyond its canonical image root.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    artifact_parent.mkdir()
    removal_root = tmp_path / "outside"
    removal_root.mkdir()
    sentinel = removal_root / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake", [], running=False, registered=False
    )

    result = _run_artifact_root_cleanup(
        tmp_path,
        artifact_parent=artifact_parent,
        removal_root=removal_root,
        vmrun_path=vmrun_path,
        environment=environment,
    )

    assert result.returncode != 0
    assert "outside the canonical parent root" in result.stderr
    assert sentinel.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows file-sharing semantics are required")
def test_whole_artifact_root_cleanup_does_not_claim_success_after_locked_file(
    tmp_path: Path,
) -> None:
    """A terminating recursive-delete failure preserves the root and suppresses success.

    Args:
        tmp_path: Isolated test directory.
    """
    artifact_parent = tmp_path / "image-root"
    removal_root = artifact_parent / "ovf"
    removal_root.mkdir(parents=True)
    locked_path = removal_root / "locked.ova"
    locked_path.write_text("locked", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake", [], running=False, registered=False
    )

    with locked_path.open("rb"):
        result = _run_artifact_root_cleanup(
            tmp_path,
            artifact_parent=artifact_parent,
            removal_root=removal_root,
            vmrun_path=vmrun_path,
            environment=environment,
        )

    assert result.returncode != 0
    assert "ROOT CLEANUP SUCCEEDED" not in result.stdout
    assert locked_path.exists()


@pytest.mark.parametrize(
    ("running", "registered", "stop_exit", "unregister_exit", "expected_error"),
    [
        (True, True, 9, 0, "Stop VMware Workstation VM"),
        (False, True, 0, 9, "Delete VMware Workstation VM"),
    ],
)
def test_general_removal_preserves_artifacts_after_vmrun_failure(
    tmp_path: Path,
    running: bool,
    registered: bool,
    stop_exit: int,
    unregister_exit: int,
    expected_error: str,
) -> None:
    """A failed stop or deleteVM must prevent recursive VM-directory deletion.

    Args:
        tmp_path: Isolated test directory.
        running: Whether the VM begins in the running inventory.
        registered: Whether the VM begins in the registration inventory.
        stop_exit: Exit code returned by the fake stop operation.
        unregister_exit: Exit code returned by the fake deleteVM operation.
        expected_error: Action text expected in the propagated failure.
    """
    vm_directory = tmp_path / "Atlaso-Test"
    vmx_path = vm_directory / "Atlaso-Test.vmx"
    sentinel = vm_directory / "sentinel.txt"
    _write_vmx(vmx_path, "Atlaso-Test")
    sentinel.write_text("preserve", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=running,
        registered=registered,
        stop_exit=stop_exit,
        unregister_exit=unregister_exit,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Test",
        environment=environment,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize(("running", "registered"), [(True, True), (False, False)])
def test_general_removal_is_verified_and_idempotent(
    tmp_path: Path, running: bool, registered: bool
) -> None:
    """Successful and already-inactive cleanup both remove the exact VM artifact directory.

    Args:
        tmp_path: Isolated test directory.
        running: Whether the VM begins in the running inventory.
        registered: Whether the VM begins in the registration inventory.
    """
    vm_directory = tmp_path / f"Atlaso-{running}-{registered}"
    display_name = vm_directory.name
    vmx_path = vm_directory / f"{display_name}.vmx"
    _write_vmx(vmx_path, display_name)
    vmrun_path, environment, log_path = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=running,
        registered=registered,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        display_name,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not vm_directory.exists()
    commands = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    action_names = [command[2] for command in commands]
    assert ("stop" in action_names) is running
    assert ("deleteVM" in action_names) is registered


def test_general_removal_rejects_an_unvalidated_vmx_in_the_removal_root(
    tmp_path: Path,
) -> None:
    """Recursive deletion must not include a VMX omitted by the caller.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Multiple"
    requested_vmx = vm_directory / "Atlaso-Multiple.vmx"
    unvalidated_vmx = vm_directory / "copied-source" / "Source.vmx"
    _write_vmx(requested_vmx, "Atlaso-Multiple")
    _write_vmx(unvalidated_vmx, "Source")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [requested_vmx, unvalidated_vmx],
        running=False,
        registered=False,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(requested_vmx),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Multiple",
        environment=environment,
    )

    assert result.returncode != 0
    assert "contains an unvalidated VMX" in result.stderr
    assert requested_vmx.exists()
    assert unvalidated_vmx.exists()


def test_general_removal_rejects_a_relative_running_inventory_path(
    tmp_path: Path,
) -> None:
    """A malformed vmrun entry must not let cleanup mistake a running VM for inactive.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Relative-Running"
    vmx_path = vm_directory / "Atlaso-Relative-Running.vmx"
    _write_vmx(vmx_path, "Atlaso-Relative-Running")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
    )
    state_directory = Path(environment["ATLASO_FAKE_VMRUN_STATE"])
    (state_directory / "running.json").write_text(
        json.dumps(["relative-running.vmx"]), encoding="utf-8"
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Relative-Running",
        environment=environment,
    )

    assert result.returncode != 0
    assert "non-absolute VMX path" in result.stderr
    assert vmx_path.exists()


@pytest.mark.parametrize("inventory_format", ['"{}', '{}"'])
def test_general_removal_rejects_unbalanced_running_inventory_quotes(
    tmp_path: Path,
    inventory_format: str,
) -> None:
    """An asymmetrically quoted vmrun path must preserve the target artifacts.

    Args:
        tmp_path: Isolated test directory.
        inventory_format: Format that adds only a leading or trailing quote.
    """
    vm_directory = tmp_path / "Atlaso-Unbalanced-Running"
    vmx_path = vm_directory / "Atlaso-Unbalanced-Running.vmx"
    _write_vmx(vmx_path, "Atlaso-Unbalanced-Running")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=True,
        registered=False,
        running_path_format=inventory_format,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Unbalanced-Running",
        environment=environment,
    )

    assert result.returncode != 0
    assert "unbalanced or embedded quote" in result.stderr
    assert vmx_path.exists()


def test_general_removal_accepts_balanced_running_inventory_quotes(tmp_path: Path) -> None:
    """A fully quoted canonical vmrun path remains valid inventory.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Balanced-Running"
    vmx_path = vm_directory / "Atlaso-Balanced-Running.vmx"
    _write_vmx(vmx_path, "Atlaso-Balanced-Running")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=True,
        registered=False,
        running_path_format='"{}"',
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Balanced-Running",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not vm_directory.exists()


@pytest.mark.parametrize(
    "registration_entry",
    [
        "vmlist0.config\n",
        'vmlist.config = "C:\\VMs\\Atlaso.vmx"\n',
        'vmlistA.config = "C:\\VMs\\Atlaso.vmx"\n',
        'vmlist 0.config = "C:\\VMs\\Atlaso.vmx"\n',
        'vmlist0 .config = "C:\\VMs\\Atlaso.vmx"\n',
        'vmlist0config = "C:\\VMs\\Atlaso.vmx"\n',
        'vmlist0 config = "C:\\VMs\\Atlaso.vmx"\n',
        'vmlist0.config = "relative-registered.vmx"\n',
    ],
)
def test_general_removal_rejects_malformed_registration_entries(
    tmp_path: Path,
    registration_entry: str,
) -> None:
    """Malformed-key, incomplete, or relative registrations must preserve artifacts.

    Args:
        tmp_path: Isolated test directory.
        registration_entry: Registration line written to the fake inventory.
    """
    vm_directory = tmp_path / "Atlaso-Malformed-Registration"
    vmx_path = vm_directory / "Atlaso-Malformed-Registration.vmx"
    _write_vmx(vmx_path, "Atlaso-Malformed-Registration")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
    )
    inventory_path = Path(environment["ATLASO_FAKE_VMRUN_INVENTORY"])
    inventory_path.write_text(registration_entry, encoding="utf-8")

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Malformed-Registration",
        environment=environment,
    )

    assert result.returncode != 0
    assert "refusing filesystem cleanup" in result.stderr
    assert vmx_path.exists()


def test_general_removal_ignores_config_text_in_unrelated_registration_values(
    tmp_path: Path,
) -> None:
    """A non-config inventory key remains unrelated when its value contains config text.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Unrelated-Registration"
    vmx_path = vm_directory / "Atlaso-Unrelated-Registration.vmx"
    _write_vmx(vmx_path, "Atlaso-Unrelated-Registration")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
    )
    inventory_path = Path(environment["ATLASO_FAKE_VMRUN_INVENTORY"])
    inventory_path.write_text(
        'vmlist0.DisplayName = "Atlaso.config"\nindex.count = "0"\n',
        encoding="utf-8",
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Unrelated-Registration",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not vm_directory.exists()


def test_cleanup_safety_content_read_errors_are_terminating() -> None:
    """Incomplete VMX and inventory reads must abort instead of returning partial state."""
    module = (VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1").read_text(encoding="utf-8")

    assert "Get-Content -LiteralPath $Path -ErrorAction Stop" in module
    assert "Get-Content -LiteralPath $InventoryPath -ErrorAction Stop" in module
    assert module.count("Get-Content") == module.count("Get-Content -LiteralPath") == 2
    assert "Start-Sleep -Milliseconds 250" in module
    assert "registration inventory changed during verification" in module
    write_lock = module.index("$inventoryWriteLock = [System.IO.File]::Open(")
    locked_read = module.index("$lockedContent = $inventoryReader.ReadToEnd()", write_lock)
    locked_comparison = module.index("$snapshot.Content.Equals($lockedContent", locked_read)
    inventory_replace = module.index(
        "[System.IO.File]::Replace($temporaryInventoryPath, $InventoryPath, $backupInventoryPath, $true)",
        locked_comparison,
    )
    lock_release = module.index("$inventoryWriteLock.Dispose()", inventory_replace)
    displaced_read = module.index(
        "$displacedContent = [System.IO.File]::ReadAllText($backupInventoryPath)",
        lock_release,
    )
    cas_rollback = module.index(
        "Restore-AtlasoWorkstationInventoryAfterCasFailure `", displaced_read
    )
    assert "[System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete" in module
    assert (
        write_lock
        < locked_read
        < locked_comparison
        < inventory_replace
        < lock_release
        < displaced_read
        < cas_rollback
    )


def test_general_removal_uses_inventory_file_for_registered_state(tmp_path: Path) -> None:
    """Registered state must not depend on an unsupported vmrun command.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Registered-Inventory"
    vmx_path = vm_directory / "Atlaso-Registered-Inventory.vmx"
    _write_vmx(vmx_path, "Atlaso-Registered-Inventory")
    vmrun_path, environment, log_path = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=True,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Registered-Inventory",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not vm_directory.exists()
    commands = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    command_names = [command[2] for command in commands]
    assert "deleteVM" in command_names
    assert "listRegisteredVM" not in command_names


def test_general_removal_rejects_an_incomplete_registration_inventory(tmp_path: Path) -> None:
    """A header-only Workstation inventory must preserve registered artifacts.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Incomplete-Registration"
    vmx_path = vm_directory / "Atlaso-Incomplete-Registration.vmx"
    _write_vmx(vmx_path, "Atlaso-Incomplete-Registration")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=True,
    )
    inventory_path = Path(environment["ATLASO_FAKE_VMRUN_INVENTORY"])
    inventory_path.write_text('.encoding = "UTF-8"\n', encoding="utf-8")

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Incomplete-Registration",
        environment=environment,
    )

    assert result.returncode != 0
    assert "registration inventory is incomplete or changing" in result.stderr
    assert vmx_path.exists()


def test_registered_inventory_rejects_a_snapshot_that_changes_during_stability_window(
    tmp_path: Path,
) -> None:
    """Two different complete snapshots must not authorize cleanup state.

    Args:
        tmp_path: Isolated test directory.
    """
    vmx_path = tmp_path / "registered" / "Atlaso-Changing-Registration.vmx"
    _write_vmx(vmx_path, "Atlaso-Changing-Registration")
    inventory_path = tmp_path / "inventory.vmls"
    replacement_path = tmp_path / "inventory-replacement.vmls"
    inventory_path.write_text('.encoding = "UTF-8"\nindex.count = "0"\n', encoding="utf-8")
    replacement_path.write_text(
        '.encoding = "UTF-8"\n'
        f'vmlist1.config = "{vmx_path.resolve()}"\n'
        f'index0.id = "{vmx_path.resolve()}"\n'
        'index.count = "1"\n',
        encoding="utf-8",
    )
    module_path = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    wrapper = tmp_path / "read-changing-inventory.ps1"
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
$module = Import-Module '{module_path}' -Force -PassThru
& $module {{
    param($inventoryPath, $replacementPath)
    function Start-Sleep {{
        param([int]$Milliseconds)
        Copy-Item -LiteralPath $replacementPath -Destination $inventoryPath -Force
    }}
    Get-AtlasoWorkstationRegisteredVmPaths -InventoryPath $inventoryPath
}} '{inventory_path}' '{replacement_path}'
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=os.environ.copy())

    assert result.returncode != 0
    assert "registration inventory changed during verification" in result.stderr


def test_inventory_cas_rollback_restores_concurrent_provider_replacement(
    tmp_path: Path,
) -> None:
    """A failed inventory compare-and-swap must restore the displaced provider state.

    Args:
        tmp_path: Isolated test directory.
    """
    inventory_path = tmp_path / "inventory.vmls"
    replacement_path = tmp_path / "captured-provider.vmls"
    inventory_path.write_text("concurrent provider state", encoding="utf-8")
    replacement_path.write_text("original provider state", encoding="utf-8")
    module_path = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    wrapper = tmp_path / "restore-inventory-cas.ps1"
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
$module = Import-Module '{module_path}' -Force -PassThru
& $module {{
    param($inventoryPath, $replacementPath)
    Restore-AtlasoWorkstationInventoryAfterCasFailure `
        -InventoryPath $inventoryPath `
        -ExpectedCurrentContent 'cleanup candidate state' `
        -ReplacementPath $replacementPath `
        -ReplacementContent 'original provider state'
}} '{inventory_path}' '{replacement_path}'
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=os.environ.copy())

    assert result.returncode == 0, result.stdout + result.stderr
    assert inventory_path.read_text(encoding="utf-8") == "concurrent provider state"
    assert not list(tmp_path.glob("inventory.vmls.atlaso-cas-*.tmp"))
    assert not list(tmp_path.glob("inventory.vmls.atlaso-recovery-*.vmls"))


def test_general_removal_matches_a_running_vmx_by_filesystem_identity(
    tmp_path: Path,
) -> None:
    """A Windows path alias must still trigger the required running-VM transition.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Alias"
    vmx_path = vm_directory / "Atlaso-Alias.vmx"
    vmx_alias = tmp_path / "aliases" / "Atlaso-Alias-Link.vmx"
    _write_vmx(vmx_path, "Atlaso-Alias")
    vmx_alias.parent.mkdir()
    os.link(vmx_path, vmx_alias)
    vmrun_path, environment, log_path = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_alias],
        running=True,
        registered=False,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Alias",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not vm_directory.exists()
    commands = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert "stop" in [command[2] for command in commands]


def test_general_removal_accepts_an_empty_registration_tombstone(
    tmp_path: Path,
) -> None:
    """A complete empty Workstation inventory slot is not a malformed registration.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Empty-Registration"
    vmx_path = vm_directory / "Atlaso-Empty-Registration.vmx"
    _write_vmx(vmx_path, "Atlaso-Empty-Registration")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
    )
    inventory_path = Path(environment["ATLASO_FAKE_VMRUN_INVENTORY"])
    inventory_path.write_text(
        'vmlist0.config = ""\nindex.count = "0"\n',
        encoding="utf-8",
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Empty-Registration",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not vm_directory.exists()


def test_general_removal_honors_explicit_confirmation(tmp_path: Path) -> None:
    """Explicit confirmation cannot be suppressed by the nested cleanup helper.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-Confirm"
    vmx_path = vm_directory / "Atlaso-Confirm.vmx"
    _write_vmx(vmx_path, "Atlaso-Confirm")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Confirm",
        "-Confirm",
        environment=environment,
    )

    assert result.returncode != 0
    assert "PowerShell is in NonInteractive mode" in result.stderr
    assert vmx_path.exists()


def test_general_removal_allows_explicit_confirmation_suppression(
    tmp_path: Path,
) -> None:
    """Automation may still opt out of confirmation through the common parameter.

    Args:
        tmp_path: Isolated test directory.
    """
    vm_directory = tmp_path / "Atlaso-No-Confirm"
    vmx_path = vm_directory / "Atlaso-No-Confirm.vmx"
    _write_vmx(vmx_path, "Atlaso-No-Confirm")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-No-Confirm",
        "-Confirm:$false",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not vm_directory.exists()


@pytest.mark.parametrize(
    "vmx_content",
    [
        'displayName = "Atlaso-Ambiguous"\ndisplayName = "Other"\n',
        'displayName = "Atlaso-Ambiguous"\ndisplayName\n',
        "displayName = Atlaso-Ambiguous\n",
    ],
)
def test_general_removal_rejects_ambiguous_display_name_assignments(
    tmp_path: Path,
    vmx_content: str,
) -> None:
    """Cleanup must preserve a VMX whose display identity is not unambiguous.

    Args:
        tmp_path: Isolated test directory.
        vmx_content: Duplicate or malformed VMX display-name content.
    """
    vm_directory = tmp_path / "Atlaso-Ambiguous"
    vmx_path = vm_directory / "Atlaso-Ambiguous.vmx"
    vmx_path.parent.mkdir(parents=True)
    vmx_path.write_text(vmx_content, encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=False,
        registered=False,
    )

    result = _run_script(
        VMWARE_SCRIPT_ROOT / "remove-atlaso-vm.ps1",
        "-VmxPath",
        str(vmx_path),
        "-VmrunPath",
        str(vmrun_path),
        "-ExpectedName",
        "Atlaso-Ambiguous",
        "-Confirm:$false",
        environment=environment,
    )

    assert result.returncode != 0
    assert "Refusing VMware cleanup" in result.stderr
    assert vmx_path.exists()


def test_redeploy_missing_target_and_sibling_disk_fail_closed(tmp_path: Path) -> None:
    """Redeploy and data-disk reset must preserve unproven or sibling-prefix paths.

    Args:
        tmp_path: Isolated test directory.
    """
    source_vmx = tmp_path / "source" / "source.vmx"
    _write_vmx(source_vmx, "Source")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        running=False,
        registered=False,
    )
    output_directory = tmp_path / "vm"
    output_directory.mkdir()
    sentinel = output_directory / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")

    redeploy = _run_script(
        VMWARE_SCRIPT_ROOT / "create-atlaso-test-vm.ps1",
        "-Name",
        "MissingTarget",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(output_directory),
        "-VmrunPath",
        str(vmrun_path),
        "-VdiskManagerPath",
        str(vmrun_path),
        "-Redeploy",
        "-SkipNetworkPrepare",
        "-NoStart",
        environment=environment,
    )
    assert redeploy.returncode != 0
    assert "expected Atlaso VMX is missing" in redeploy.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"

    sibling_directory = tmp_path / "vm-sibling"
    sibling_directory.mkdir()
    sibling_disk = sibling_directory / "unrelated.vmdk"
    sibling_disk.write_text("preserve", encoding="utf-8")
    disk_reset = _run_script(
        VMWARE_SCRIPT_ROOT / "create-atlaso-test-vm.ps1",
        "-Name",
        "SiblingDisk",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(output_directory),
        "-VmrunPath",
        str(vmrun_path),
        "-VdiskManagerPath",
        str(vmrun_path),
        "-DepotVmdkPath",
        str(sibling_disk),
        "-ResetDataDisks",
        "-SkipNetworkPrepare",
        "-NoStart",
        environment=environment,
    )
    assert disk_reset.returncode != 0
    assert "outside the VM output directory" in disk_reset.stderr
    assert sibling_disk.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize(
    ("running", "registered", "stop_exit", "unregister_exit"),
    [(True, True, 9, 0), (False, True, 0, 9)],
)
def test_standalone_lifecycle_cleanup_preserves_artifacts_after_vmrun_failure(
    tmp_path: Path,
    running: bool,
    registered: bool,
    stop_exit: int,
    unregister_exit: int,
) -> None:
    """The standalone lifecycle remover propagates vmrun failures without deleting files.

    Args:
        tmp_path: Isolated test directory.
        running: Whether the lifecycle VM begins in the running inventory.
        registered: Whether the lifecycle VM begins in the registration inventory.
        stop_exit: Exit code returned by the fake stop operation.
        unregister_exit: Exit code returned by the fake deleteVM operation.
    """
    copied_script_root = tmp_path / "repo" / "scripts" / "windows" / "vmware"
    copied_script_root.mkdir(parents=True)
    for name in ("remove-lifecycle-vms.ps1", "Atlaso.WorkstationCleanup.psm1"):
        shutil.copy2(VMWARE_SCRIPT_ROOT / name, copied_script_root / name)
    vm_directory = (
        tmp_path
        / "repo"
        / "test-results"
        / "vmware-workstation-lifecycle"
        / "run"
        / "vms"
        / "AtlasoWorkstationLifecycle-Test"
    )
    vmx_path = vm_directory / "AtlasoWorkstationLifecycle-Test.vmx"
    sentinel = vm_directory / "sentinel.txt"
    _write_vmx(vmx_path, "AtlasoWorkstationLifecycle-Test")
    sentinel.write_text("preserve", encoding="utf-8")
    vmrun_path, environment, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx_path],
        running=running,
        registered=registered,
        stop_exit=stop_exit,
        unregister_exit=unregister_exit,
    )

    result = _run_script(
        copied_script_root / "remove-lifecycle-vms.ps1",
        "-LabName",
        "AtlasoWorkstationLifecycle",
        "-VmrunPath",
        str(vmrun_path),
        environment=environment,
    )

    assert result.returncode != 0
    assert sentinel.read_text(encoding="utf-8") == "preserve"
