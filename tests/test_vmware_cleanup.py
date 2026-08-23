"""Behavior tests for root-scoped VMware Workstation cleanup."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VMWARE_SCRIPT_ROOT = REPOSITORY_ROOT / "scripts" / "windows" / "vmware"


def _pwsh_path() -> str:
    """Return PowerShell 7 or skip behavior tests when it is unavailable."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required for VMware cleanup behavior tests")
    return pwsh


def _write_vmx(path: Path, display_name: str = "Atlaso-Test", *extra_lines: str) -> None:
    """Write one minimal VMX file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = [f'displayName = "{display_name}"', *extra_lines]
    path.write_text("\n".join(content) + "\n", encoding="utf-8")


def _write_fake_vmrun(
    directory: Path,
    vmx_paths: list[Path],
    *,
    running: bool = False,
    registered: bool = False,
    stop_exit: int = 0,
    delete_exit: int = 0,
    stop_sticky: bool = False,
    delete_sticky: bool = False,
    replace_after_delete: bool = False,
    rewrite_on_list: int = 0,
    rewrite_disk: Path | None = None,
    create_on_list: int = 0,
    create_path: Path | None = None,
    inventory_suffix: str = "",
) -> tuple[Path, dict[str, str], Path, Path]:
    """Create a stateful fake vmrun command and Workstation inventory."""
    directory.mkdir(parents=True)
    state = directory / "state"
    state.mkdir()
    canonical_paths = [str(path.resolve()) for path in vmx_paths]
    (state / "running.json").write_text(
        json.dumps(canonical_paths if running else []), encoding="utf-8"
    )
    (state / "registered.json").write_text(
        json.dumps(canonical_paths if registered else []), encoding="utf-8"
    )

    appdata = directory / "appdata"
    inventory = appdata / "VMware" / "inventory.vmls"
    inventory.parent.mkdir(parents=True)
    registered_paths = canonical_paths if registered else []
    inventory.write_text(
        '.encoding = "UTF-8"\n'
        + "".join(
            f'vmlist{index}.config = "{path}"\n'
            for index, path in enumerate(registered_paths, start=1)
        )
        + "".join(
            f'index{index}.id = "{path}"\n'
            for index, path in enumerate(registered_paths)
        )
        + f'index.count = "{len(registered_paths)}"\n'
        + inventory_suffix,
        encoding="utf-8",
    )

    log = directory / "commands.jsonl"
    fake = directory / "fake_vmrun.py"
    fake.write_text(
        r'''from __future__ import annotations
import json
import os
from pathlib import Path
import sys

state = Path(os.environ["ATLASO_FAKE_VMRUN_STATE"])
log = Path(os.environ["ATLASO_FAKE_VMRUN_LOG"])
inventory = Path(os.environ["ATLASO_FAKE_VMRUN_INVENTORY"])
arguments = sys.argv[1:]
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\n")
if len(arguments) < 3 or arguments[:2] != ["-T", "ws"]:
    raise SystemExit(64)
command = arguments[2]

def read_paths(name: str) -> list[str]:
    return json.loads((state / f"{name}.json").read_text(encoding="utf-8"))

def write_paths(name: str, paths: list[str]) -> None:
    (state / f"{name}.json").write_text(json.dumps(paths), encoding="utf-8")

def same_path(left: str, right: str) -> bool:
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError):
        return Path(left).resolve() == Path(right).resolve()

def update_inventory(paths: list[str]) -> None:
    old_lines = inventory.read_text(encoding="utf-8").splitlines()
    suffix = [
        line for line in old_lines
        if not line.lstrip().startswith("vmlist")
        and not line.lstrip().startswith("index")
        and not line.startswith(".encoding")
    ]
    inventory.write_text(
        '.encoding = "UTF-8"\n'
        + "".join(f'vmlist{i}.config = "{path}"\n' for i, path in enumerate(paths, start=1))
        + "".join(f'index{i}.id = "{path}"\n' for i, path in enumerate(paths))
        + f'index.count = "{len(paths)}"\n'
        + "\n".join(suffix)
        + ("\n" if suffix else ""),
        encoding="utf-8",
    )

if command == "list":
    count_path = state / "list-count.txt"
    list_count = int(count_path.read_text(encoding="utf-8")) + 1 if count_path.exists() else 1
    count_path.write_text(str(list_count), encoding="utf-8")
    if list_count == int(os.environ["ATLASO_FAKE_VMRUN_REWRITE_ON_LIST"]):
        rewrite_target = Path(os.environ["ATLASO_FAKE_VMRUN_REWRITE_TARGET"])
        rewrite_disk = os.environ["ATLASO_FAKE_VMRUN_REWRITE_DISK"]
        with rewrite_target.open("a", encoding="utf-8") as stream:
            stream.write(f'scsi0:2.fileName = "{rewrite_disk}"\n')
    if list_count == int(os.environ["ATLASO_FAKE_VMRUN_CREATE_ON_LIST"]):
        Path(os.environ["ATLASO_FAKE_VMRUN_CREATE_PATH"]).write_text(
            "late artifact", encoding="utf-8"
        )
    paths = read_paths("running")
    print(f"Total running VMs: {len(paths)}")
    print("\n".join(paths))
    raise SystemExit(0)

if len(arguments) < 4:
    raise SystemExit(64)
target = str(Path(arguments[3]).resolve())
if command == "stop":
    exit_code = int(os.environ["ATLASO_FAKE_VMRUN_STOP_EXIT"])
    if exit_code:
        print("simulated stop failure", file=sys.stderr)
        raise SystemExit(exit_code)
    if os.environ["ATLASO_FAKE_VMRUN_STOP_STICKY"] != "1":
        write_paths("running", [path for path in read_paths("running") if not same_path(path, target)])
    raise SystemExit(0)

if command == "deleteVM":
    exit_code = int(os.environ["ATLASO_FAKE_VMRUN_DELETE_EXIT"])
    if exit_code:
        print("simulated delete failure", file=sys.stderr)
        raise SystemExit(exit_code)
    if os.environ["ATLASO_FAKE_VMRUN_DELETE_STICKY"] != "1":
        target_path = Path(target)
        if target_path.exists():
            for line in target_path.read_text(encoding="utf-8").splitlines():
                if ".fileName" not in line or "=" not in line:
                    continue
                configured = line.split("=", 1)[1].strip().strip('"')
                if Path(configured).suffix.lower() != ".vmdk":
                    continue
                disk = Path(configured)
                if not disk.is_absolute():
                    disk = target_path.parent / disk
                disk.unlink(missing_ok=True)
            target_path.unlink(missing_ok=True)
        registered_paths = [
            path for path in read_paths("registered") if not same_path(path, target)
        ]
        write_paths("registered", registered_paths)
        update_inventory(registered_paths)
    if os.environ["ATLASO_FAKE_VMRUN_REPLACE_AFTER_DELETE"] == "1":
        Path(target).write_text('displayName = "Concurrent replacement"\n', encoding="utf-8")
    raise SystemExit(0)

raise SystemExit(64)
''',
        encoding="utf-8",
    )
    if os.name == "nt":
        command = directory / "vmrun.cmd"
        command.write_text(
            f'@echo off\r\n"{sys.executable}" "{fake}" %*\r\n', encoding="utf-8"
        )
    else:
        command = directory / "vmrun"
        command.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{fake}" "$@"\n', encoding="utf-8"
        )
        command.chmod(0o755)

    environment = os.environ.copy()
    environment.update(
        {
            "APPDATA": str(appdata),
            "ATLASO_FAKE_VMRUN_STATE": str(state),
            "ATLASO_FAKE_VMRUN_LOG": str(log),
            "ATLASO_FAKE_VMRUN_INVENTORY": str(inventory),
            "ATLASO_FAKE_VMRUN_STOP_EXIT": str(stop_exit),
            "ATLASO_FAKE_VMRUN_DELETE_EXIT": str(delete_exit),
            "ATLASO_FAKE_VMRUN_STOP_STICKY": "1" if stop_sticky else "0",
            "ATLASO_FAKE_VMRUN_DELETE_STICKY": "1" if delete_sticky else "0",
            "ATLASO_FAKE_VMRUN_REPLACE_AFTER_DELETE": "1" if replace_after_delete else "0",
            "ATLASO_FAKE_VMRUN_REWRITE_ON_LIST": str(rewrite_on_list),
            "ATLASO_FAKE_VMRUN_REWRITE_TARGET": canonical_paths[0] if canonical_paths else "",
            "ATLASO_FAKE_VMRUN_REWRITE_DISK": str(rewrite_disk or ""),
            "ATLASO_FAKE_VMRUN_CREATE_ON_LIST": str(create_on_list),
            "ATLASO_FAKE_VMRUN_CREATE_PATH": str(create_path or ""),
        }
    )
    return command, environment, log, inventory


def _run_script(
    script: Path, *arguments: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run one PowerShell wrapper without prompts."""
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


def _run_root_cleanup(
    tmp_path: Path,
    *,
    removal_root: Path,
    vmrun_path: Path,
    environment: dict[str, str],
    artifact_parent: Path | None = None,
    expected_root: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke the whole-root cleanup entry point."""
    if (artifact_parent is None) == (expected_root is None):
        raise ValueError("Select exactly one root binding")
    binding = (
        f"-ArtifactParentRoot '{artifact_parent}'"
        if artifact_parent is not None
        else f"-ExpectedRemovalRoot '{expected_root}'"
    )
    wrapper = tmp_path / "cleanup.ps1"
    module = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
Import-Module '{module}' -Force
Remove-AtlasoWorkstationArtifactRoot `
    -VmrunPath '{vmrun_path}' `
    {binding} `
    -RemovalRoot '{removal_root}' `
    -Confirm:$false
Write-Host 'CLEANUP SUCCEEDED'
""",
        encoding="utf-8",
    )
    return _run_script(wrapper, environment=environment)


def _commands(log: Path) -> list[list[str]]:
    """Read fake vmrun invocations."""
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_registered_vm_uses_checked_deletevm(tmp_path: Path) -> None:
    """An existing registered Atlaso VM is deleted through the provider."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    unrelated_missing = tmp_path / "unrelated" / "missing.vmx"
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        inventory_suffix=(
            f'vmlist8.config = "{unrelated_missing.resolve()}"\n'
            "vmlistBROKEN.config = malformed\n"
        ),
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not root.exists()
    assert [command[2] for command in _commands(log)].count("deleteVM") == 1


def test_running_registered_vm_is_stopped_hard_before_delete(tmp_path: Path) -> None:
    """A running target is stopped with the checked local-provider operation."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], running=True, registered=True
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    commands = _commands(log)
    stop = next(command for command in commands if command[2] == "stop")
    delete = next(command for command in commands if command[2] == "deleteVM")
    assert stop[-1] == "hard"
    assert commands.index(stop) < commands.index(delete)


def test_running_hard_link_alias_is_matched_by_filesystem_identity(tmp_path: Path) -> None:
    """An out-of-root alias cannot conceal a running in-root target."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    alias = tmp_path / "aliases" / "Atlaso-alias.vmx"
    _write_vmx(vmx)
    alias.parent.mkdir(parents=True)
    os.link(vmx, alias)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], registered=True
    )
    state = Path(environment["ATLASO_FAKE_VMRUN_STATE"])
    (state / "running.json").write_text(json.dumps([str(alias.resolve())]), encoding="utf-8")

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "stop" in [command[2] for command in _commands(log)]


def test_registered_hard_link_alias_uses_deletevm(tmp_path: Path) -> None:
    """An out-of-root library alias still identifies the registered target."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    alias = tmp_path / "aliases" / "Atlaso-alias.vmx"
    _write_vmx(vmx)
    alias.parent.mkdir(parents=True)
    os.link(vmx, alias)
    vmrun, environment, log, inventory = _write_fake_vmrun(
        tmp_path / "fake", [vmx], registered=True
    )
    inventory.write_text(
        '.encoding = "UTF-8"\n'
        f'vmlist1.config = "{alias.resolve()}"\n'
        f'index0.id = "{alias.resolve()}"\n'
        'index.count = "1"\n',
        encoding="utf-8",
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert [command[2] for command in _commands(log)].count("deleteVM") == 1


def test_live_registration_rejects_duplicate_library_id(tmp_path: Path) -> None:
    """A live target's selected library ID must have one config owner."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    unrelated = tmp_path / "other" / "Unrelated.vmx"
    _write_vmx(vmx)
    _write_vmx(unrelated, "Unrelated")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        inventory_suffix=f'vmlist1.config = "{unrelated.resolve()}"\n',
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "ambiguous library ID" in result.stderr
    assert vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_already_unregistered_vm_uses_filesystem_cleanup_only(tmp_path: Path) -> None:
    """An existing unregistered target remains an idempotent cleanup case."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(tmp_path / "fake", [vmx])

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not root.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_stale_atlaso_registration_ignores_unrelated_broken_entries(tmp_path: Path) -> None:
    """Scoped stale repair does not validate or remove unrelated library rows."""
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    (root / "sentinel.txt").write_text("artifact", encoding="utf-8")
    stale = root / "missing.vmx"
    unrelated_missing = tmp_path / "other" / "missing.vmx"
    unrelated_suffix = (
        f'vmlist7.config = "{stale.resolve()}"\n'
        f'index7.id = "{stale.resolve()}"\n'
        f'vmlist8.config = "{unrelated_missing.resolve()}"\n'
        "vmlistBROKEN.config = malformed\n"
        "unrelated.value = keep-me\n"
    )
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=unrelated_suffix
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        artifact_parent=parent,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not root.exists()
    inventory_text = inventory.read_text(encoding="utf-8")
    assert str(stale.resolve()) not in inventory_text
    assert str(unrelated_missing.resolve()) in inventory_text
    assert "vmlistBROKEN.config = malformed" in inventory_text
    assert "unrelated.value = keep-me" in inventory_text


def test_stale_repair_rejects_duplicate_selected_library_id(tmp_path: Path) -> None:
    """Scoped repair never prunes an ID that also owns another config path."""
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    sentinel = root / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    stale = root / "missing.vmx"
    unrelated = tmp_path / "other" / "Unrelated.vmx"
    _write_vmx(unrelated, "Unrelated")
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist7.config = "{stale.resolve()}"\n'
            f'vmlist7.config = "{unrelated.resolve()}"\n'
            f'index7.id = "{stale.resolve()}"\n'
        ),
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        artifact_parent=parent,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "selected library ID '7' to multiple config paths" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert str(unrelated.resolve()) in inventory.read_text(encoding="utf-8")


def test_stale_repair_preserves_ambiguously_owned_index(tmp_path: Path) -> None:
    """Duplicate index ownership is left untouched during scoped repair."""
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    stale = root / "missing.vmx"
    unrelated = tmp_path / "other" / "Unrelated.vmx"
    _write_vmx(unrelated, "Unrelated")
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist7.config = "{stale.resolve()}"\n'
            f'index7.id = "{stale.resolve()}"\n'
            f'index7.id = "{unrelated.resolve()}"\n'
        ),
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        artifact_parent=parent,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    inventory_text = inventory.read_text(encoding="utf-8")
    assert f'vmlist7.config = "{stale.resolve()}"' not in inventory_text
    assert f'index7.id = "{stale.resolve()}"' in inventory_text
    assert f'index7.id = "{unrelated.resolve()}"' in inventory_text


def test_external_vmdk_is_detached_before_deletevm(tmp_path: Path) -> None:
    """Provider deletion never follows a disk path outside the removal root."""
    root = tmp_path / "artifacts" / "vm"
    external_disk = tmp_path / "shared" / "depot.vmdk"
    external_disk.parent.mkdir(parents=True)
    external_disk.write_text("shared", encoding="utf-8")
    vmx = root / "Atlaso.vmx"
    _write_vmx(
        vmx,
        "Atlaso",
        f'scsi0:2.fileName = "{external_disk.resolve()}"',
        'scsi0:2.present = "TRUE"',
    )
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], registered=True
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert external_disk.read_text(encoding="utf-8") == "shared"


def test_in_place_vmx_rewrite_after_scan_blocks_deletevm(tmp_path: Path) -> None:
    """Content evidence is rechecked even when initial detachment was unnecessary."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    external_disk = tmp_path / "shared" / "depot.vmdk"
    external_disk.parent.mkdir(parents=True)
    external_disk.write_text("shared", encoding="utf-8")
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        rewrite_on_list=3,
        rewrite_disk=external_disk,
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "changed immediately before deleteVM" in result.stderr
    assert external_disk.read_text(encoding="utf-8") == "shared"
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_failed_deletevm_atomically_restores_external_vmdk_attachment(tmp_path: Path) -> None:
    """A provider failure restores the complete original VMX from its backup."""
    root = tmp_path / "artifacts" / "vm"
    external_disk = tmp_path / "shared" / "depot.vmdk"
    external_disk.parent.mkdir(parents=True)
    external_disk.write_text("shared", encoding="utf-8")
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx, "Atlaso", f'scsi0:2.fileName = "{external_disk.resolve()}"')
    original_bytes = vmx.read_bytes()
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], registered=True, delete_exit=9
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "Delete VMware Workstation VM" in result.stderr
    assert vmx.read_bytes() == original_bytes
    assert external_disk.read_text(encoding="utf-8") == "shared"
    assert not list(root.glob("*.atlaso-*.tmp"))


def test_concurrent_vmx_replacement_is_preserved(tmp_path: Path) -> None:
    """A provider-time replacement blocks recursive root deletion."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], registered=True, replace_after_delete=True
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "VMX remains after deleteVM succeeded" in result.stderr
    assert "Concurrent replacement" in vmx.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("running", "stop_exit", "delete_exit", "expected"),
    [
        (True, 9, 0, "Stop VMware Workstation VM"),
        (False, 0, 9, "Delete VMware Workstation VM"),
    ],
)
def test_vmrun_failures_preserve_artifacts(
    tmp_path: Path,
    running: bool,
    stop_exit: int,
    delete_exit: int,
    expected: str,
) -> None:
    """Checked provider failures remain terminating."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        running=running,
        registered=True,
        stop_exit=stop_exit,
        delete_exit=delete_exit,
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert expected in result.stderr
    assert root.exists()


@pytest.mark.parametrize(
    ("running", "stop_sticky", "delete_sticky", "expected"),
    [
        (True, True, False, "remains running after stop succeeded"),
        (False, False, True, "VMX remains after deleteVM succeeded"),
    ],
)
def test_successful_vmrun_must_complete_the_requested_transition(
    tmp_path: Path,
    running: bool,
    stop_sticky: bool,
    delete_sticky: bool,
    expected: str,
) -> None:
    """A zero provider exit code does not replace post-operation verification."""
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        running=running,
        registered=True,
        stop_sticky=stop_sticky,
        delete_sticky=delete_sticky,
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert expected in result.stderr
    assert root.exists()


def test_configured_root_mismatch_is_rejected(tmp_path: Path) -> None:
    """Exact configured cleanup cannot be redirected to a sibling."""
    expected = tmp_path / "artifacts" / "expected"
    target = tmp_path / "artifacts" / "target"
    expected.mkdir(parents=True)
    target.mkdir(parents=True)
    sentinel = target / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    vmrun, environment, _, _ = _write_fake_vmrun(tmp_path / "fake", [])

    result = _run_root_cleanup(
        tmp_path,
        removal_root=target,
        expected_root=expected,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "exact configured output root" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_reparse_point_root_is_rejected(tmp_path: Path) -> None:
    """Recursive cleanup never traverses a linked artifact root."""
    real_root = tmp_path / "real"
    real_root.mkdir()
    sentinel = real_root / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    linked_root = tmp_path / "linked"
    try:
        linked_root.symlink_to(real_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink creation is unavailable: {error}")
    vmrun, environment, _, _ = _write_fake_vmrun(tmp_path / "fake", [])

    result = _run_root_cleanup(
        tmp_path,
        removal_root=linked_root,
        expected_root=linked_root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "reparse point" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_unvalidated_vmx_is_rejected_by_direct_entry_point(tmp_path: Path) -> None:
    """Callers cannot omit an in-root VMX from the validated target set."""
    root = tmp_path / "artifacts" / "vm"
    first = root / "first.vmx"
    second = root / "second.vmx"
    _write_vmx(first, "First")
    _write_vmx(second, "Second")
    vmrun, environment, _, _ = _write_fake_vmrun(tmp_path / "fake", [])
    wrapper = tmp_path / "direct.ps1"
    module = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
Import-Module '{module}' -Force
Remove-AtlasoWorkstationVmArtifacts `
    -VmrunPath '{vmrun}' `
    -VmxPaths @('{first}') `
    -RemovalRoot '{root}' `
    -Confirm:$false
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=environment)

    assert result.returncode != 0
    assert "unvalidated VMX" in result.stderr
    assert first.exists() and second.exists()


def test_late_artifact_after_final_vmrun_list_blocks_root_removal(tmp_path: Path) -> None:
    """The root snapshot is rechecked after the final provider-state query."""
    root = tmp_path / "artifacts" / "vm"
    root.mkdir(parents=True)
    sentinel = root / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    late = root / "late.txt"
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake", [], create_on_list=1, create_path=late
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "new VMware artifact appeared" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert late.read_text(encoding="utf-8") == "late artifact"


def test_test_vm_ssh_key_inputs_fail_before_cleanup(tmp_path: Path) -> None:
    """Missing or conflicting SSH key inputs preserve an existing test VM."""
    source_vmx = tmp_path / "source" / "source.vmx"
    _write_vmx(source_vmx, "Source")
    output_directory = tmp_path / "vm"
    target_vmx = output_directory / "ProtectedVm.vmx"
    _write_vmx(target_vmx, "ProtectedVm")
    sentinel = output_directory / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")

    missing_key = _run_script(
        VMWARE_SCRIPT_ROOT / "create-atlaso-test-vm.ps1",
        "-Name",
        "ProtectedVm",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(output_directory),
        "-SshPublicKeyPath",
        str(tmp_path / "missing.pub"),
        "-Redeploy",
        "-SkipNetworkPrepare",
        "-NoStart",
        environment=os.environ.copy(),
    )
    assert missing_key.returncode != 0
    assert "SSH public key not found" in missing_key.stderr
    assert target_vmx.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"

    conflicting_key_options = _run_script(
        VMWARE_SCRIPT_ROOT / "create-atlaso-test-vm.ps1",
        "-Name",
        "ProtectedVm",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(output_directory),
        "-SshPublicKeyPath",
        str(tmp_path / "missing.pub"),
        "-SkipSshKeyProvisioning",
        "-Redeploy",
        "-SkipNetworkPrepare",
        "-NoStart",
        environment=os.environ.copy(),
    )
    assert conflicting_key_options.returncode != 0
    assert "Pass either -SshPublicKeyPath or -SkipSshKeyProvisioning" in conflicting_key_options.stderr
    assert target_vmx.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_module_keeps_inventory_work_out_of_normal_delete_path() -> None:
    """Regression guard for the simplified root-scoped architecture."""
    module = (VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1").read_text(
        encoding="utf-8"
    )
    normal_path = module.split("function Remove-AtlasoWorkstationVmArtifacts", 1)[1]

    assert "Test-AtlasoWorkstationVmxRegistered" in normal_path
    assert "Remove-AtlasoWorkstationStaleRegistrations" in normal_path
    assert "Start-Sleep" not in normal_path
    assert "InventorySnapshotsEqual" not in module
    assert "index.count" not in normal_path
    assert normal_path.count("Confirm-AtlasoWorkstationVmInactive") >= 2
    assert "[System.IO.File]::Replace($temporaryPath, $VmxPath, $backupPath, $true)" in module
    assert "[System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete" in module
    assert "Get-AtlasoScopedInventoryEntriesFromLines -Lines $lines" in module
    assert "-ExpectedCurrentIdentity $Detachment.OriginalIdentity" in module
    assert "-ReplacementIdentity $displacedIdentity" in module
    assert "-PreserveCapturedOnSuccess" in module
    implementation = re.sub(r"<#.*?#>\s*", "", module, flags=re.DOTALL)
    assert len(implementation.splitlines()) < 1_100
