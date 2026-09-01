"""Behavior tests for root-scoped VMware Workstation cleanup."""

from __future__ import annotations

import hashlib
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
    """Write one minimal VMX file.

    Args:
        path: Destination VMX file path.
        display_name: Optional display name written into the VMX content.
        *extra_lines: Extra VMX lines appended before writing.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = [f'displayName = "{display_name}"', *extra_lines]
    path.write_text("\n".join(content) + "\n", encoding="utf-8")


def _write_vmware_payload_fixture(directory: Path) -> Path:
    """Write one minimal schema-v3 VMware source payload.

    Args:
        directory: Destination directory for the VMX, VMDKs, and provenance.

    Returns:
        Path to the provenance-bound source VMX.
    """
    source_vmx = directory / "source.vmx"
    photon_disk = directory / "photon.vmdk"
    system_disk = directory / "atlaso-system.vmdk"
    photon_disk.parent.mkdir(parents=True, exist_ok=True)
    photon_disk.write_text('RW 83886080 SPARSE "photon-flat.vmdk"\n', encoding="ascii")
    system_disk.write_text(
        'RW 41943040 SPARSE "atlaso-system-flat.vmdk"\n', encoding="ascii"
    )
    _write_vmx(
        source_vmx,
        "Source",
        'scsi0.virtualDev = "pvscsi"',
        'scsi0:0.present = "TRUE"',
        'scsi0:0.fileName = "photon.vmdk"',
        'scsi0:1.present = "TRUE"',
        'scsi0:1.fileName = "atlaso-system.vmdk"',
    )

    def _artifact_record(
        path: Path, *, role: str, unit: int, capacity: int
    ) -> dict[str, object]:
        """Describe one provenance-bound payload disk.

        Args:
            path: Payload VMDK path.
            role: Canonical payload role.
            unit: PVSCSI unit number.
            capacity: Expected virtual capacity in bytes.

        Returns:
            JSON-compatible payload provenance record.
        """
        return {
            "role": role,
            "scsi_unit": unit,
            "name": path.name,
            "capacity_bytes": capacity,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    provenance = {
        "schema_version": 3,
        "source_commit": "a" * 40,
        "tracked_source_dirty": False,
        "source_snapshot": {
            "schema_version": 1,
            "file_count": 42,
            "sha256": "b" * 64,
        },
        "vmx": {
            "name": source_vmx.name,
            "bytes": source_vmx.stat().st_size,
            "sha256": hashlib.sha256(source_vmx.read_bytes()).hexdigest(),
        },
        "payload_disks": [
            _artifact_record(
                photon_disk, role="photon_os", unit=0, capacity=40 * 1024**3
            ),
            _artifact_record(
                system_disk,
                role="atlaso_system",
                unit=1,
                capacity=20 * 1024**3,
            ),
        ],
    }
    source_vmx.with_suffix(".provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )
    return source_vmx


def _write_fake_vdisk_manager(directory: Path) -> Path:
    """Create a fake virtual-disk manager that writes a 500 GiB descriptor.

    Args:
        directory: Destination directory for the fake executable.

    Returns:
        Path to the fake virtual-disk manager command.
    """
    directory.mkdir(parents=True)
    fake = directory / "fake_vdisk_manager.py"
    fake.write_text(
        """from pathlib import Path
import sys

target = Path(sys.argv[-1])
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text('RW 1048576000 SPARSE "data-flat.vmdk"\\n', encoding='ascii')
""",
        encoding="utf-8",
    )
    if os.name == "nt":
        command = directory / "vmware-vdiskmanager.cmd"
        command.write_text(
            f'@echo off\r\n"{sys.executable}" "{fake}" %*\r\n', encoding="utf-8"
        )
    else:
        command = directory / "vmware-vdiskmanager"
        command.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{fake}" "$@"\n', encoding="utf-8"
        )
        command.chmod(0o755)
    return command


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
    remove_root_after_delete: bool = False,
    rewrite_on_list: int = 0,
    rewrite_disk: Path | None = None,
    create_on_list: int = 0,
    create_path: Path | None = None,
    replace_on_list: int = 0,
    replace_target: Path | None = None,
    replace_with: str = 'displayName = "Concurrent replacement"\n',
    register_on_list: int = 0,
    run_on_list: int = 0,
    run_target: Path | None = None,
    remove_on_list: int = 0,
    remove_target: Path | None = None,
    inventory_suffix: str = "",
) -> tuple[Path, dict[str, str], Path, Path]:
    """Create a stateful fake vmrun command and Workstation inventory.

    Args:
        directory: Working directory for fake vmrun state and artifacts.
        vmx_paths: VMX files to pre-populate as cataloged targets.
        running: Marks those VMX paths as running.
        registered: Marks those VMX paths as registered in inventory.
        stop_exit: Exit code to return for stop commands.
        delete_exit: Exit code to return for deleteVM commands.
        stop_sticky: If true, keep a stopped VM running in fake state.
        delete_sticky: If true, keep deleteVM from removing files.
        replace_after_delete: If true, rewrite the VMX after deleteVM.
        remove_root_after_delete: If true, remove the VMX parent after deleteVM.
        rewrite_on_list: Provider call count at which to inject a VMDK path.
        rewrite_disk: Path written during list-based rewrite.
        create_on_list: Provider call count that creates extra artifact.
        create_path: Artifact path written when create_on_list matches.
        replace_on_list: Provider list call count that replaces a VMX path.
        replace_target: VMX path rewritten when replace_on_list matches.
        replace_with: Replacement VMX content written by replace_on_list.
        register_on_list: Provider call count that registers a VM.
        run_on_list: Provider list call count that starts a VM.
        run_target: VMX path marked running when run_on_list matches.
        remove_on_list: Provider list call count that removes a VMX.
        remove_target: VMX path removed when remove_on_list matches.
        inventory_suffix: Extra inventory file text appended to the fixture.
    """
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
import shutil
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
    if (
        list_count == int(os.environ["ATLASO_FAKE_VMRUN_REPLACE_ON_LIST"]) and
        os.environ["ATLASO_FAKE_VMRUN_REPLACE_TARGET"]
    ):
        replace_target = Path(os.environ["ATLASO_FAKE_VMRUN_REPLACE_TARGET"])
        replace_with = os.environ["ATLASO_FAKE_VMRUN_REPLACE_WITH"]
        staging_target = replace_target.with_suffix(".atlaso-replacement.vmx")
        staging_target.write_text(replace_with, encoding="utf-8")
        staging_target.replace(replace_target)
    if list_count == int(os.environ["ATLASO_FAKE_VMRUN_REWRITE_ON_LIST"]):
        rewrite_target = Path(os.environ["ATLASO_FAKE_VMRUN_REWRITE_TARGET"])
        rewrite_disk = os.environ["ATLASO_FAKE_VMRUN_REWRITE_DISK"]
        with rewrite_target.open("a", encoding="utf-8") as stream:
            stream.write(f'scsi0:2.fileName = "{rewrite_disk}"\n')
    if list_count == int(os.environ["ATLASO_FAKE_VMRUN_CREATE_ON_LIST"]):
        create_path = Path(os.environ["ATLASO_FAKE_VMRUN_CREATE_PATH"])
        create_path.parent.mkdir(parents=True, exist_ok=True)
        create_path.write_text(
            "late artifact", encoding="utf-8"
        )
    if list_count == int(os.environ["ATLASO_FAKE_VMRUN_REGISTER_ON_LIST"]):
        late_target = os.environ["ATLASO_FAKE_VMRUN_REWRITE_TARGET"]
        write_paths("registered", [late_target])
        update_inventory([late_target])
    if list_count == int(os.environ["ATLASO_FAKE_VMRUN_RUN_ON_LIST"]):
        write_paths("running", [os.environ["ATLASO_FAKE_VMRUN_RUN_TARGET"]])
    if list_count == int(os.environ["ATLASO_FAKE_VMRUN_REMOVE_ON_LIST"]):
        Path(os.environ["ATLASO_FAKE_VMRUN_REMOVE_TARGET"]).unlink(missing_ok=True)
    paths = read_paths("running")
    print(f"Total running VMs: {len(paths)}")
    print("\n".join(paths))
    raise SystemExit(0)

if len(arguments) < 4:
    raise SystemExit(64)
if command == "clone":
    if len(arguments) < 5:
        raise SystemExit(64)
    source = Path(arguments[3]).resolve()
    destination = Path(arguments[4]).resolve()
    shutil.copytree(source.parent, destination.parent)
    (destination.parent / source.name).replace(destination)
    raise SystemExit(0)
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
    if os.environ["ATLASO_FAKE_VMRUN_REMOVE_ROOT_AFTER_DELETE"] == "1":
        shutil.rmtree(Path(target).parent)
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
            "ATLASO_FAKE_VMRUN_REMOVE_ROOT_AFTER_DELETE": "1" if remove_root_after_delete else "0",
            "ATLASO_FAKE_VMRUN_REWRITE_ON_LIST": str(rewrite_on_list),
            "ATLASO_FAKE_VMRUN_REWRITE_TARGET": canonical_paths[0] if canonical_paths else "",
            "ATLASO_FAKE_VMRUN_REWRITE_DISK": str(rewrite_disk or ""),
            "ATLASO_FAKE_VMRUN_CREATE_ON_LIST": str(create_on_list),
            "ATLASO_FAKE_VMRUN_CREATE_PATH": str(create_path or ""),
            "ATLASO_FAKE_VMRUN_REPLACE_ON_LIST": str(replace_on_list),
            "ATLASO_FAKE_VMRUN_REPLACE_TARGET": str(replace_target or ""),
            "ATLASO_FAKE_VMRUN_REPLACE_WITH": replace_with,
            "ATLASO_FAKE_VMRUN_REGISTER_ON_LIST": str(register_on_list),
            "ATLASO_FAKE_VMRUN_RUN_ON_LIST": str(run_on_list),
            "ATLASO_FAKE_VMRUN_RUN_TARGET": str(run_target or ""),
            "ATLASO_FAKE_VMRUN_REMOVE_ON_LIST": str(remove_on_list),
            "ATLASO_FAKE_VMRUN_REMOVE_TARGET": str(remove_target or ""),
        }
    )
    return command, environment, log, inventory


def _run_script(
    script: Path, *arguments: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run one PowerShell wrapper without prompts.

    Args:
        script: Script path to execute.
        *arguments: Additional positional arguments passed to the script.
        environment: Environment variables for the subprocess.
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


def _write_test_vm_wrapper_harness(directory: Path) -> Path:
    """Create a test-only wrapper that stops after the real clone boundary.

    The harness retains the normal wrapper's input validation, redeploy cleanup,
    data-disk checks, and clone orchestration. It removes only the host-global
    pending-signer recovery and 1Password credential boundaries, then returns
    immediately after the low-level clone succeeds. Production code receives no
    test switch, and the forbidden ``-NoStart`` parameter remains untouched.

    Args:
        directory: Destination directory for the generated harness.

    Returns:
        Path to the generated PowerShell wrapper.
    """

    source = (VMWARE_SCRIPT_ROOT / "create-atlaso-test-vm.ps1").read_text(
        encoding="utf-8"
    )

    def replace_segment(start: str, end: str, replacement: str) -> None:
        """Replace one exact source segment or reject wrapper drift.

        Args:
            start: Unique segment start marker.
            end: Unique following marker retained in the result.
            replacement: Test-harness text replacing the selected segment.
        """

        nonlocal source
        start_index = source.find(start)
        end_index = source.find(end, start_index + len(start))
        if start_index < 0 or end_index < 0 or source.find(start, start_index + 1) >= 0:
            raise AssertionError("Normal test-VM wrapper harness marker drifted")
        source = source[:start_index] + replacement + source[end_index:]

    source = source.replace("$PSScriptRoot", "$script:AtlasoWrapperScriptRoot")
    error_preference = "$ErrorActionPreference = 'Stop'"
    if source.count(error_preference) != 1:
        raise AssertionError("Normal test-VM wrapper error-preference marker drifted")
    script_root = str(VMWARE_SCRIPT_ROOT).replace("'", "''")
    source = source.replace(
        error_preference,
        f"$script:AtlasoWrapperScriptRoot = '{script_root}'\n{error_preference}",
        1,
    )

    replace_segment(
        "if (-not $WhatIfPreference) {\n"
        "    # Recovery consumes no 1Password material.",
        "if ($NoStart) {",
        "$resolvedVmrunPath = $VmrunPath\n",
    )
    replace_segment(
        "if (-not $WhatIfPreference) {\n"
        "    # Resolve new Environment configuration only after credential-independent",
        "# Key input validation intentionally precedes",
        "",
    )
    replace_segment(
        "$credentialBridgeState = $null\n"
        "if (-not $WhatIfPreference) {\n"
        "    # The parent converts explicit SecureStrings",
        "\ntry {\nif ($SkipLabNetworkAdapters",
        "$credentialBridgeState = $null",
    )

    clone_success = "$createdThisInvocation = $true\n        try {"
    if source.count(clone_success) != 1:
        raise AssertionError("Normal test-VM wrapper clone boundary drifted")
    source = source.replace(
        clone_success,
        "$createdThisInvocation = $true\n        return\n        try {",
        1,
    )

    directory.mkdir(parents=True, exist_ok=True)
    harness = directory / "create-atlaso-test-vm-harness.ps1"
    harness.write_text(source, encoding="utf-8")
    return harness


def _run_root_cleanup(
    tmp_path: Path,
    *,
    removal_root: Path,
    vmrun_path: Path,
    environment: dict[str, str],
    artifact_parent: Path | None = None,
    expected_root: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke the whole-root cleanup entry point.

    Args:
        tmp_path: Scratch directory for test artifacts and generated wrapper.
        removal_root: Root path to remove during cleanup.
        vmrun_path: Fake or real vmrun executable path.
        environment: Environment used to invoke the cleanup command.
        artifact_parent: Optional artifact parent root for binding mode.
        expected_root: Optional expected configured cleanup root for validation mode.
    """
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


def _run_stale_registration_repair(
    tmp_path: Path,
    *,
    scope_root: Path,
    environment: dict[str, str],
    vmx_path: Path | None = None,
    expected_display_name: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke only the exported pre-GUI stale-registration repair.

    Args:
        tmp_path: Scratch directory for the generated wrapper.
        scope_root: Exact scope allowed for missing registration repair.
        environment: Environment used to invoke the repair command.
        vmx_path: Optional exact missing VMX registration to select.
        expected_display_name: Required display name for an exact selection.
    """
    wrapper = tmp_path / "repair-stale-registrations.ps1"
    module = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    module_literal = str(module).replace("'", "''")
    scope_literal = str(scope_root).replace("'", "''")
    exact_selection = ""
    if vmx_path is not None or expected_display_name is not None:
        vmx_literal = str(vmx_path).replace("'", "''")
        display_name_literal = str(expected_display_name).replace("'", "''")
        exact_selection = (
            f"    -VmxPath '{vmx_literal}' `\n"
            f"    -ExpectedDisplayName '{display_name_literal}' `\n"
        )
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
Import-Module '{module_literal}' -Force
Repair-AtlasoWorkstationStaleRegistrations `
    -ScopeRoot '{scope_literal}' `
{exact_selection}    -Confirm:$false
Write-Host 'REPAIR SUCCEEDED'
""",
        encoding="utf-8",
    )
    return _run_script(wrapper, environment=environment)


def _commands(log: Path) -> list[list[str]]:
    """Read fake vmrun invocations.

    Args:
        log: Path to the JSONL command log file.
    """
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_registered_vm_uses_checked_deletevm(tmp_path: Path) -> None:
    """An existing registered Atlaso VM is deleted through the provider.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    """A running target is stopped with the checked local-provider operation.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    """An out-of-root alias cannot conceal a running in-root target.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


@pytest.mark.parametrize("reported_path", ["relative-running.vmx", 'C:\\Atlaso.vmx"'])
def test_malformed_running_inventory_path_fails_closed(
    tmp_path: Path, reported_path: str
) -> None:
    """Every declared running path must be absolute and unambiguously quoted.

    Args:
        tmp_path: Pytest temporary directory path.
        reported_path: Inventory path string passed through fake state.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, _, _ = _write_fake_vmrun(tmp_path / "fake", [vmx])
    state = Path(environment["ATLASO_FAKE_VMRUN_STATE"])
    (state / "running.json").write_text(json.dumps([reported_path]), encoding="utf-8")

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "non-absolute or malformed VMX path" in result.stderr
    assert vmx.exists()


def test_missing_running_inventory_path_fails_closed(tmp_path: Path) -> None:
    """A missing out-of-root running alias prevents recursive cleanup.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    missing_alias = tmp_path / "aliases" / "missing.vmx"
    _write_vmx(vmx)
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake", [missing_alias], running=True
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "missing or non-VMX running path" in result.stderr
    assert vmx.exists()


def test_registered_hard_link_alias_fails_closed(tmp_path: Path) -> None:
    """Provider deletion requires the exact in-root registration path.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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

    assert result.returncode != 0
    assert "non-exact or out-of-scope library path" in result.stderr
    assert vmx.exists()
    assert alias.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_registered_alias_with_external_vmdk_fails_closed(tmp_path: Path) -> None:
    """Atomic detachment cannot silently strand an out-of-root registration.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    alias = tmp_path / "aliases" / "Atlaso-alias.vmx"
    external_disk = tmp_path / "shared" / "depot.vmdk"
    external_disk.parent.mkdir(parents=True)
    external_disk.write_text("shared", encoding="utf-8")
    _write_vmx(vmx, "Atlaso", f'scsi0:2.fileName = "{external_disk.resolve()}"')
    original_bytes = vmx.read_bytes()
    alias.parent.mkdir(parents=True)
    os.link(vmx, alias)
    vmrun, environment, _, inventory = _write_fake_vmrun(
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

    assert result.returncode != 0
    assert "non-exact or out-of-scope library path" in result.stderr
    assert vmx.read_bytes() == original_bytes
    assert alias.read_bytes() == original_bytes
    assert external_disk.read_text(encoding="utf-8") == "shared"


def test_live_registration_requires_a_read_stable_inventory_snapshot(
    tmp_path: Path,
) -> None:
    """An active inventory writer blocks registration approval and deletion.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
    )
    wrapper = tmp_path / "cleanup-with-inventory-writer.ps1"
    module = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
Import-Module '{module}' -Force
$writer = [System.IO.FileStream]::new(
    $env:ATLASO_FAKE_VMRUN_INVENTORY,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::ReadWrite
)
try {{
    Remove-AtlasoWorkstationArtifactRoot `
        -VmrunPath '{vmrun}' `
        -ExpectedRemovalRoot '{root}' `
        -RemovalRoot '{root}' `
        -Confirm:$false
}}
finally {{
    $writer.Dispose()
}}
""",
        encoding="utf-8",
    )
    result = _run_script(wrapper, environment=environment)

    assert result.returncode != 0
    assert "deleteVM" not in [command[2] for command in _commands(log)]
    assert vmx.exists()


def test_multiple_vmx_cleanup_preflights_all_targets_before_first_delete(
    tmp_path: Path,
) -> None:
    """Preflight every target before attempting the first provider deleteVM.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    first_vmx = root / "first.vmx"
    second_vmx = root / "second.vmx"
    _write_vmx(first_vmx, "First")
    _write_vmx(second_vmx, "Second")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [first_vmx, second_vmx],
        running=True,
        registered=True,
        remove_root_after_delete=True,
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    commands = _commands(log)
    stop_indices = [index for index, command in enumerate(commands) if command[2] == "stop"]
    delete_indices = [
        index for index, command in enumerate(commands) if command[2] == "deleteVM"
    ]
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(stop_indices) == 2
    assert delete_indices, commands
    assert max(stop_indices) < min(delete_indices)


def test_multi_vmx_later_registration_replaced_before_first_delete_preserves_root(
    tmp_path: Path,
) -> None:
    """A later VMX identity replacement blocks cleanup before any provider delete.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    first_vmx = root / "first.vmx"
    second_vmx = root / "second.vmx"
    _write_vmx(first_vmx, "First")
    _write_vmx(second_vmx, "Second")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [first_vmx, second_vmx],
        replace_on_list=3,
        replace_target=second_vmx,
        replace_with='displayName = "Replaced later"\n',
        inventory_suffix=(
            f'vmlist1.config = "{first_vmx.resolve()}"\n'
            f'index0.id = "{first_vmx.resolve()}"\n'
            'index.count = "1"\n'
        ),
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "replaced immediately before deleteVM" in result.stderr
    assert root.exists()
    assert first_vmx.exists()
    assert second_vmx.exists()
    assert second_vmx.read_text(encoding="utf-8") == 'displayName = "Replaced later"\n'
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_multi_vmx_later_restart_before_first_delete_preserves_root(
    tmp_path: Path,
) -> None:
    """Recheck every survivor when a later VM restarts before provider deletion.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    first_vmx = root / "first.vmx"
    second_vmx = root / "second.vmx"
    _write_vmx(first_vmx, "First")
    _write_vmx(second_vmx, "Second")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [first_vmx, second_vmx],
        registered=True,
        stop_sticky=True,
        remove_root_after_delete=True,
        run_on_list=7,
        run_target=second_vmx,
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "VMware Workstation VM remains running after stop succeeded" in result.stderr
    assert root.exists()
    assert first_vmx.exists()
    assert second_vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_multi_vmx_later_disappearance_before_first_delete_preserves_root(
    tmp_path: Path,
) -> None:
    """A later expected VMX cannot disappear during final provider checks.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    first_vmx = root / "first.vmx"
    second_vmx = root / "second.vmx"
    _write_vmx(first_vmx, "First")
    _write_vmx(second_vmx, "Second")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [first_vmx, second_vmx],
        registered=True,
        remove_on_list=5,
        remove_target=second_vmx,
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "VMware cleanup target no longer exists" in result.stderr
    assert root.exists()
    assert first_vmx.exists()
    assert not second_vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_multi_vmx_later_ambiguous_registration_blocks_first_delete(
    tmp_path: Path,
) -> None:
    """Preflight every target registration before a provider can remove the root.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    first_vmx = root / "first.vmx"
    second_vmx = root / "second.vmx"
    unrelated = tmp_path / "other" / "unrelated.vmx"
    _write_vmx(first_vmx, "First")
    _write_vmx(second_vmx, "Second")
    _write_vmx(unrelated, "Unrelated")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [first_vmx, second_vmx],
        registered=True,
        remove_root_after_delete=True,
        inventory_suffix=f'vmlist2.config = "{unrelated.resolve()}"\n',
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
    assert first_vmx.exists()
    assert second_vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_live_registration_rejects_non_vmx_hardlink_inventory_entry(
    tmp_path: Path,
) -> None:
    """Reject hard-link aliases whose inventory owner path is an absolute non-vmx file.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    alias = tmp_path / "aliases" / "Atlaso-alias.txt"
    alias.parent.mkdir(parents=True)
    os.link(vmx, alias)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        inventory_suffix=(
            f'vmlist1.config = "{alias.resolve()}"\n'
            f'index0.id = "{alias.resolve()}"\n'
            'index.count = "1"\n'
        ),
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "non-exact or out-of-scope library path" in result.stderr
    assert vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_live_registration_rejects_duplicate_library_id(tmp_path: Path) -> None:
    """A live target's selected library ID must have one config owner.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


@pytest.mark.parametrize(
    "malformed_owner",
    ['vmlist1.config = relative.vmx\n', 'vmlist1.config = "relative.vmx"\n'],
)
def test_live_registration_rejects_malformed_duplicate_library_id(
    tmp_path: Path, malformed_owner: str
) -> None:
    """A malformed second owner cannot make the selected library ID unique.

    Args:
        tmp_path: Pytest temporary directory path.
        malformed_owner: Inventory row content injected as a malformed owner.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        inventory_suffix=malformed_owner,
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
    """An existing unregistered target remains an idempotent cleanup case.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


def test_provider_delete_may_remove_the_complete_validated_root(tmp_path: Path) -> None:
    """A checked provider deletion may satisfy cleanup by removing the exact root.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    (root / "provider-owned.log").write_text("provider", encoding="utf-8")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        remove_root_after_delete=True,
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
    assert "deleteVM" in [command[2] for command in _commands(log)]


def test_redeploy_continues_after_provider_removes_artifact_root(
    tmp_path: Path,
) -> None:
    """The redeploy wrapper clones after the provider removes its artifact root.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    source_vmx = _write_vmware_payload_fixture(tmp_path / "source")
    identity = "Atlaso-PR-634-redeploy"
    vm_directory = tmp_path / identity
    vmx = vm_directory / f"{identity}.vmx"
    _write_vmx(vmx, identity)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake-redeploy",
        [vmx],
        registered=True,
        remove_root_after_delete=True,
    )
    vdisk_manager = _write_fake_vdisk_manager(tmp_path / "fake-vdisk-manager")

    wrapper = _write_test_vm_wrapper_harness(tmp_path / "wrapper-harness")
    result = _run_script(
        wrapper,
        "-PullRequestNumber",
        "634",
        "-Purpose",
        "redeploy",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(vm_directory),
        "-VmrunPath",
        str(vmrun),
        "-VdiskManagerPath",
        str(vdisk_manager),
        "-Redeploy",
        "-SkipSshKeyProvisioning",
        "-SkipNetworkPrepare",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert vmx.exists()
    assert f'displayName = "{identity}"' in vmx.read_text(encoding="utf-8")
    command_names = [command[2] for command in _commands(log)]
    assert command_names.index("deleteVM") < command_names.index("clone")


def test_provider_delete_rejects_a_late_non_vmx_artifact(tmp_path: Path) -> None:
    """A late non-VMX descendant blocks provider-owned root deletion.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    late_artifact = root / "late-provider-artifact.txt"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        remove_root_after_delete=True,
        create_on_list=4,
        create_path=late_artifact,
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
    assert vmx.exists()
    assert late_artifact.read_text(encoding="utf-8") == "late artifact"
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_provider_removed_root_rejects_ambiguous_recreation(tmp_path: Path) -> None:
    """A root recreated after provider deletion is preserved and rejected.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    replacement = root / "replacement.txt"
    _write_vmx(vmx)
    vmrun, environment, _, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        remove_root_after_delete=True,
        create_on_list=5,
        create_path=replacement,
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "reappeared after provider deletion" in result.stderr
    assert replacement.read_text(encoding="utf-8") == "late artifact"


def test_registration_appearing_before_root_removal_fails_closed(tmp_path: Path) -> None:
    """A VMX registered after its initial check prevents recursive deletion.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], register_on_list=3
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "became registered during cleanup" in result.stderr
    assert vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_vm_started_during_final_inventory_work_fails_closed(tmp_path: Path) -> None:
    """Repeat running-state validation after final inventory work.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], run_on_list=4, run_target=vmx
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "remains running inside the cleanup root" in result.stderr
    assert vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_vm_registered_during_final_running_check_fails_closed(tmp_path: Path) -> None:
    """Repeat registration validation after the final running-state query.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake", [vmx], register_on_list=4
    )

    result = _run_root_cleanup(
        tmp_path,
        removal_root=root,
        expected_root=root,
        vmrun_path=vmrun,
        environment=environment,
    )

    assert result.returncode != 0
    assert "became registered during cleanup" in result.stderr
    assert vmx.exists()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_missing_vmx_registered_before_root_removal_is_repaired(tmp_path: Path) -> None:
    """Repair a late stale in-scope registration before removing the root.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    vmrun, environment, log, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        register_on_list=3,
        remove_on_list=3,
        remove_target=vmx,
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
    assert not vmx.exists()
    assert str(vmx.resolve()) not in inventory.read_text(encoding="utf-8")
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_stale_atlaso_registration_ignores_unrelated_broken_entries(tmp_path: Path) -> None:
    """Scoped stale repair does not validate or remove unrelated library rows.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    assert f'= "{stale.resolve()}"' not in inventory_text
    assert str(unrelated_missing.resolve()) in inventory_text
    assert "vmlistBROKEN.config = malformed" in inventory_text
    assert "unrelated.value = keep-me" in inventory_text


def test_pre_gui_repair_removes_only_missing_scoped_registration(tmp_path: Path) -> None:
    """Repair the stale row without deleting the configured output root.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "image" / "vmware-workstation" / "output"
    root.mkdir(parents=True)
    sentinel = root / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    stale = root / "missing.vmx"
    unrelated = tmp_path / "other" / "missing.vmx"
    suffix = (
        f'vmlist7.config = "{stale.resolve()}"\n'
        f'index7.id = "{stale.resolve()}"\n'
        f'vmlist8.config = "{unrelated.resolve()}"\n'
        "unrelated.value = keep-me\n"
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    inventory_text = inventory.read_text(encoding="utf-8")
    assert str(stale.resolve()) not in inventory_text
    assert str(unrelated.resolve()) in inventory_text
    assert "unrelated.value = keep-me" in inventory_text


def test_exact_stale_repair_matches_marker_path_and_display_name(tmp_path: Path) -> None:
    """Repair only the exact marker-bound row after its artifact root disappeared.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    unrelated = root.parent / "Atlaso-PR-671-unrelated" / "missing.vmx"
    prefixed_unrelated = root / "Atlaso-PR-672-cleanup.vmx backup.vmx"
    apostrophe_prefixed_unrelated = root / "Atlaso-PR-672-cleanup.vmx' backup.vmx"
    suffix = (
        f'vmlist6.config = "{stale.resolve()}"\n'
        'vmlist6.DisplayName = "Atlaso-PR-672-cleanup"\n'
        f'index6.id = "{stale.resolve()}"\n'
        f'vmlist7.config = "{unrelated.resolve()}"\n'
        'vmlist7.DisplayName = "Atlaso-PR-671-unrelated"\n'
        f'index7.id = "{unrelated.resolve()}"\n'
        f'vmlist8.config = "{prefixed_unrelated.resolve()}"\n'
        'vmlist8.DisplayName = "Prefixed unrelated VM"\n'
        f'index8.id = "{prefixed_unrelated.resolve()}"\n'
        f"vmlist9.config = '{apostrophe_prefixed_unrelated.resolve()}'\n"
        'vmlist9.DisplayName = "Apostrophe-prefixed unrelated VM"\n'
        "unrelated.value = keep-me\n"
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        vmx_path=stale,
        expected_display_name="Atlaso-PR-672-cleanup",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    inventory_text = inventory.read_text(encoding="utf-8")
    assert f'= "{stale.resolve()}"' not in inventory_text
    assert 'vmlist6.DisplayName = "Atlaso-PR-672-cleanup"' not in inventory_text
    assert str(unrelated.resolve()) in inventory_text
    assert str(prefixed_unrelated.resolve()) in inventory_text
    assert str(apostrophe_prefixed_unrelated.resolve()) in inventory_text
    assert "Atlaso-PR-671-unrelated" in inventory_text
    assert "unrelated.value = keep-me" in inventory_text


def test_exact_stale_repair_rechecks_initially_absent_inventory(tmp_path: Path) -> None:
    """Reject provider inventory that appears after the caller resolved absence.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    suffix = (
        f'vmlist6.config = "{stale.resolve()}"\n'
        'vmlist6.DisplayName = "Atlaso-PR-672-cleanup"\n'
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )
    original_inventory = inventory.read_bytes()
    wrapper = tmp_path / "repair-after-inventory-appears.ps1"
    module_literal = str(
        VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    ).replace("'", "''")
    scope_literal = str(root).replace("'", "''")
    vmx_literal = str(stale).replace("'", "''")
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
$module = Import-Module '{module_literal}' -Force -PassThru
& $module {{
    param($ScopeRoot, $VmxPath)
    Remove-AtlasoWorkstationStaleRegistrations `
        -InventoryPath $null `
        -ScopeRoot $ScopeRoot `
        -VmxPath $VmxPath `
        -ExpectedDisplayName 'Atlaso-PR-672-cleanup'
}} '{scope_literal}' '{vmx_literal}'
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=environment)

    assert result.returncode != 0
    assert "inventory appeared while its absence was being verified" in result.stderr
    assert inventory.read_bytes() == original_inventory


def test_exact_stale_repair_locks_absent_inventory_through_callback(
    tmp_path: Path,
) -> None:
    """Exclude provider creation until verified recovery release completes.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    _, environment, _, inventory = _write_fake_vmrun(tmp_path / "fake", [])
    inventory.unlink()
    callback_proof = tmp_path / "callback-proof.txt"
    wrapper = tmp_path / "repair-while-inventory-absent.ps1"
    module_literal = str(
        VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    ).replace("'", "''")
    scope_literal = str(root).replace("'", "''")
    vmx_literal = str(stale).replace("'", "''")
    inventory_literal = str(inventory).replace("'", "''")
    proof_literal = str(callback_proof).replace("'", "''")
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
Import-Module '{module_literal}' -Force
Repair-AtlasoWorkstationStaleRegistrations `
    -ScopeRoot '{scope_literal}' `
    -VmxPath '{vmx_literal}' `
    -ExpectedDisplayName 'Atlaso-PR-672-cleanup' `
    -OnVerified {{
        $writeBlocked = $false
        try {{
            $providerWrite = [System.IO.File]::Open('{inventory_literal}', 'OpenOrCreate', 'Write', 'ReadWrite')
            $providerWrite.Dispose()
        }} catch {{ $writeBlocked = $true }}
        if (-not $writeBlocked) {{ throw 'Provider inventory write was admitted during recovery release.' }}
        Set-Content -LiteralPath '{proof_literal}' -Value 'blocked'
    }} `
    -Confirm:$false
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=environment)

    assert result.returncode == 0, result.stdout + result.stderr
    assert callback_proof.read_text(encoding="utf-8").strip() == "blocked"
    assert inventory.read_bytes() == b""


def test_normal_stale_cleanup_keeps_missing_inventory_noop(tmp_path: Path) -> None:
    """Do not require provider-state creation for ordinary scoped cleanup.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-ordinary-cleanup"
    appdata = tmp_path / "missing-appdata"
    wrapper = tmp_path / "repair-ordinary-missing-inventory.ps1"
    module_literal = str(
        VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    ).replace("'", "''")
    scope_literal = str(root).replace("'", "''")
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
$env:APPDATA = '{str(appdata).replace("'", "''")}'
$module = Import-Module '{module_literal}' -Force -PassThru
& $module {{
    param($ScopeRoot)
    Remove-AtlasoWorkstationStaleRegistrations -InventoryPath $null -ScopeRoot $ScopeRoot
}} '{scope_literal}'
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=os.environ.copy())

    assert result.returncode == 0, result.stdout + result.stderr
    assert not appdata.exists()


def test_normal_stale_cleanup_keeps_present_zero_stale_noop(tmp_path: Path) -> None:
    """Do not lock a present inventory when ordinary cleanup selects no rows.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-ordinary-cleanup"
    _, environment, _, inventory = _write_fake_vmrun(tmp_path / "fake", [])
    wrapper = tmp_path / "repair-ordinary-zero-stale.ps1"
    module_literal = str(
        VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    ).replace("'", "''")
    scope_literal = str(root).replace("'", "''")
    inventory_literal = str(inventory).replace("'", "''")
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
$module = Import-Module '{module_literal}' -Force -PassThru
& $module {{ Set-Item -Path Function:script:Get-Process -Value {{ [pscustomobject]@{{ Name = 'vmware' }} }} }}
& $module {{
    param($InventoryPath, $ScopeRoot)
    Remove-AtlasoWorkstationStaleRegistrations `
        -InventoryPath $InventoryPath `
        -ScopeRoot $ScopeRoot
}} '{inventory_literal}' '{scope_literal}'
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=environment)

    assert result.returncode == 0, result.stdout + result.stderr


def test_exact_stale_repair_removes_orphaned_marker_index(tmp_path: Path) -> None:
    """Remove an exact stale index even when its config group is already absent.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    unrelated = root.parent / "Atlaso-PR-671-unrelated" / "missing.vmx"
    suffix = (
        f'index6.id = "{stale.resolve()}"\n'
        f'index7.id = "{unrelated.resolve()}"\n'
        "unrelated.value = keep-me\n"
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        vmx_path=stale,
        expected_display_name="Atlaso-PR-672-cleanup",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    inventory_text = inventory.read_text(encoding="utf-8")
    assert str(stale.resolve()) not in inventory_text
    assert str(unrelated.resolve()) in inventory_text
    assert "unrelated.value = keep-me" in inventory_text


def test_exact_stale_repair_preserves_mismatched_display_name(tmp_path: Path) -> None:
    """Keep the exact row when its provider display name is ambiguous.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    suffix = (
        f'vmlist6.config = "{stale.resolve()}"\n'
        'vmlist6.DisplayName = "Different VM"\n'
        f'index6.id = "{stale.resolve()}"\n'
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )
    original_inventory = inventory.read_bytes()

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        vmx_path=stale,
        expected_display_name="Atlaso-PR-672-cleanup",
        environment=environment,
    )

    assert result.returncode != 0
    assert "does not have the expected display name" in result.stderr
    assert inventory.read_bytes() == original_inventory


@pytest.mark.parametrize(
    ("malformed_owner", "leading_quote", "trailing_text", "use_parent_segment"),
    [
        ("config", "", "", False),
        ("index", "", "", False),
        ("config", '"', '" junk', False),
        ("index", '"', '" junk', False),
        ("config", '"', '" junk "', False),
        ("index", '"', '" junk "', False),
        ("config", '"', '" junk.vmx', False),
        ("index", '"', '" junk.vmx', False),
        ("config", '""', '"', False),
        ("index", '""', '"', False),
        ("config", "'", "'", False),
        ("index", "'", "'", False),
        ("config", "'", "", False),
        ("index", "'", "", False),
        ("config", "'", "' junk'", False),
        ("index", "'", "' junk'", False),
        ("config", "", '" junk', False),
        ("index", "", '" junk', False),
        ("config", '"', '" junk', True),
        ("index", '"', '" junk', True),
    ],
)
def test_exact_stale_repair_preserves_malformed_marker_owner_syntax(
    tmp_path: Path,
    malformed_owner: str,
    leading_quote: str,
    trailing_text: str,
    use_parent_segment: bool,
) -> None:
    """Reject a raw exact owner row that the strict inventory parser omits.

    Args:
        tmp_path: Pytest temporary directory path.
        malformed_owner: Inventory owner kind written with invalid syntax.
        leading_quote: Optional quote preceding the raw VMX path.
        trailing_text: Optional quote or junk following the raw VMX path.
        use_parent_segment: Whether the raw path is lexically noncanonical.
    """
    path_root = tmp_path / "O'Brien" if leading_quote == "'" else tmp_path
    root = path_root / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    raw_stale = stale.parent / "subdirectory" / ".." / stale.name if use_parent_segment else stale.resolve()
    malformed_value = f"{leading_quote}{raw_stale}{trailing_text}"
    config_value = malformed_value if malformed_owner == "config" else f'"{stale.resolve()}"'
    index_value = malformed_value if malformed_owner == "index" else f'"{stale.resolve()}"'
    suffix = (
        f"vmlist6.config = {config_value}\n"
        'vmlist6.DisplayName = "Atlaso-PR-672-cleanup"\n'
        f"index6.id = {index_value}\n"
        "vmlistBROKEN.config = unrelated-malformed-row\n"
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )
    original_inventory = inventory.read_bytes()

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        vmx_path=stale,
        expected_display_name="Atlaso-PR-672-cleanup",
        environment=environment,
    )

    assert result.returncode != 0
    assert "malformed or ambiguous" in result.stderr
    assert inventory.read_bytes() == original_inventory


def test_exact_stale_repair_preserves_duplicate_marker_path(tmp_path: Path) -> None:
    """Reject duplicate library owners for the exact marker-bound VMX path.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    suffix = (
        f'vmlist6.config = "{stale.resolve()}"\n'
        'vmlist6.DisplayName = "Atlaso-PR-672-cleanup"\n'
        f'vmlist7.config = "{stale.resolve()}"\n'
        'vmlist7.DisplayName = "Atlaso-PR-672-cleanup"\n'
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )
    original_inventory = inventory.read_bytes()

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        vmx_path=stale,
        expected_display_name="Atlaso-PR-672-cleanup",
        environment=environment,
    )

    assert result.returncode != 0
    assert "multiple registrations for the exact missing VMX" in result.stderr
    assert inventory.read_bytes() == original_inventory


def test_exact_stale_repair_finds_unterminated_path_after_vmx_apostrophe(
    tmp_path: Path,
) -> None:
    """Reject an exact unterminated owner after a VMX-like apostrophe segment.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "root.vmx'child" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    suffix = (
        f"vmlist6.config = '{stale.resolve()}\n"
        'vmlist6.DisplayName = "Atlaso-PR-672-cleanup"\n'
    )
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )
    original_inventory = inventory.read_bytes()

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        vmx_path=stale,
        expected_display_name="Atlaso-PR-672-cleanup",
        environment=environment,
    )

    assert result.returncode != 0
    assert "malformed or ambiguous" in result.stderr
    assert inventory.read_bytes() == original_inventory


def test_exact_stale_repair_preserves_unterminated_unrelated_vmx_name(
    tmp_path: Path,
) -> None:
    """Treat one complete VMX path as unrelated despite a missing opening delimiter.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "test-vms" / "Atlaso-PR-672-cleanup"
    stale = root / "Atlaso-PR-672-cleanup.vmx"
    unrelated = root / "Atlaso-PR-672-cleanup.vmx backup.vmx"
    suffix = f'vmlist6.config = "{unrelated.resolve()}\n'
    _, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake", [], inventory_suffix=suffix
    )
    original_inventory = inventory.read_bytes()

    result = _run_stale_registration_repair(
        tmp_path,
        scope_root=root,
        vmx_path=stale,
        expected_display_name="Atlaso-PR-672-cleanup",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert inventory.read_bytes() == original_inventory


def test_unrelated_uncanonicalizable_inventory_owner_does_not_block_cleanup(
    tmp_path: Path,
) -> None:
    """Ignore an unrelated absolute VMX owner whose path cannot be canonicalized.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    malformed = f'vmlist7.config = "{tmp_path.resolve()}\\bad\x00owner.vmx"\n'
    vmrun, environment, log, inventory = _write_fake_vmrun(
        tmp_path / "fake", [vmx], inventory_suffix=malformed
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
    assert b"bad\x00owner.vmx" in inventory.read_bytes()
    assert "deleteVM" not in [command[2] for command in _commands(log)]


def test_unrelated_uncanonicalizable_inventory_index_does_not_block_repair(
    tmp_path: Path,
) -> None:
    """Ignore an unrelated index path that cannot be canonicalized.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    stale = root / "missing.vmx"
    malformed = f'index8.id = "{tmp_path.resolve()}\\bad\x00index.vmx"\n'
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist7.config = "{stale.resolve()}"\n'
            f'index7.id = "{stale.resolve()}"\n'
            f"{malformed}"
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
    assert not root.exists()
    assert str(stale.resolve()).encode() not in inventory.read_bytes()
    assert b"bad\x00index.vmx" in inventory.read_bytes()


def test_stale_repair_compacts_surviving_inventory_indexes(tmp_path: Path) -> None:
    """Removing index0 renumbers an unrelated index1 group without losing properties.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    stale = root / "missing.vmx"
    unrelated = tmp_path / "unrelated" / "live.vmx"
    _write_vmx(unrelated)
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist1.config = "{stale.resolve()}"\n'
            f'vmlist2.config = "{unrelated.resolve()}"\n'
            f'index0.id = "{stale.resolve()}"\n'
            f'index1.id = "{unrelated.resolve()}"\n'
            'index1.favorite = "TRUE"\n'
            'index.count = "2"\n'
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
    assert f'index0.id = "{unrelated.resolve()}"' in inventory_text
    assert 'index0.favorite = "TRUE"' in inventory_text
    assert "index1." not in inventory_text
    assert 'index.count = "1"' in inventory_text


def test_stale_repair_does_not_compact_without_a_removed_index(tmp_path: Path) -> None:
    """A stale vmlist-only row does not normalize unrelated index numbering.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    stale = root / "missing.vmx"
    unrelated = tmp_path / "unrelated" / "live.vmx"
    _write_vmx(unrelated)
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist7.config = "{stale.resolve()}"\n'
            f'index7.id = "{unrelated.resolve()}"\n'
            'index.count = "1"\n'
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
    assert f'index7.id = "{unrelated.resolve()}"' in inventory_text
    assert "index0." not in inventory_text
    assert 'index.count = "1"' in inventory_text


def test_unrelated_oversized_inventory_index_count_does_not_block_repair(
    tmp_path: Path,
) -> None:
    """Preserve an unrelated index count outside the supported integer range.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    stale = root / "missing.vmx"
    oversized_count = "999999999999999999999"
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist7.config = "{stale.resolve()}"\n'
            f'index7.id = "{stale.resolve()}"\n'
            f'index.count = "{oversized_count}"\n'
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
    assert not root.exists()
    inventory_text = inventory.read_text(encoding="utf-8")
    assert str(stale.resolve()) not in inventory_text
    assert f'index.count = "{oversized_count}"' in inventory_text


def test_stale_repair_rejects_duplicate_selected_library_id(tmp_path: Path) -> None:
    """Scoped repair never prunes an ID that also owns another config path.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


@pytest.mark.parametrize(
    "malformed_owner",
    ['vmlist7.config = relative.vmx\n', 'vmlist7.config = "relative.vmx"\n'],
)
def test_stale_repair_rejects_malformed_selected_library_owner(
    tmp_path: Path, malformed_owner: str
) -> None:
    """Scoped repair preserves a selected ID with a malformed second owner.

    Args:
        tmp_path: Pytest temporary directory path.
        malformed_owner: Malformed selected-ID row appended to the inventory.
    """
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    sentinel = root / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    stale = root / "missing.vmx"
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist7.config = "{stale.resolve()}"\n'
            f'index7.id = "{stale.resolve()}"\n'
            f"{malformed_owner}"
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
    assert malformed_owner.strip() in inventory.read_text(encoding="utf-8")


def test_stale_repair_preserves_ambiguously_owned_index(tmp_path: Path) -> None:
    """Duplicate index ownership is left untouched during scoped repair.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


def test_stale_repair_preserves_count_when_index_compaction_is_unsafe(
    tmp_path: Path,
) -> None:
    """An unrelated malformed group keeps the declared range covering index2.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    stale = root / "missing.vmx"
    unrelated = tmp_path / "other" / "live.vmx"
    _write_vmx(unrelated)
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist1.config = "{stale.resolve()}"\n'
            f'index0.id = "{stale.resolve()}"\n'
            'index1.id = relative.vmx\n'
            f'index2.id = "{unrelated.resolve()}"\n'
            'index.count = "3"\n'
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
    assert f'index0.id = "{stale.resolve()}"' not in inventory_text
    assert "index1.id = relative.vmx" in inventory_text
    assert f'index2.id = "{unrelated.resolve()}"' in inventory_text
    assert 'index.count = "3"' in inventory_text


def test_stale_repair_preserves_missing_non_vmx_in_scope_entry(tmp_path: Path) -> None:
    """Missing non-vmx absolute entries are preserved during scoped stale repair.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    parent = tmp_path / "image" / "vmware-workstation"
    root = parent / "test-vms"
    root.mkdir(parents=True)
    vmx = root / "Atlaso.vmx"
    _write_vmx(vmx)
    missing_entry = root / "unused-note.txt"
    vmrun, environment, _, inventory = _write_fake_vmrun(
        tmp_path / "fake",
        [],
        inventory_suffix=(
            f'vmlist7.config = "{missing_entry.resolve()}"\n'
            f'index7.id = "{missing_entry.resolve()}"\n'
            'index.count = "1"\n'
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
    assert not root.exists()
    inventory_text = inventory.read_text(encoding="utf-8")
    assert f'vmlist7.config = "{missing_entry.resolve()}"' in inventory_text
    assert f'index7.id = "{missing_entry.resolve()}"' in inventory_text


def test_external_vmdk_is_detached_before_deletevm(tmp_path: Path) -> None:
    """Provider deletion never follows a disk path outside the removal root.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


def test_original_hard_link_started_after_detachment_is_stopped(tmp_path: Path) -> None:
    """The final running check matches the original VMX identity after detachment.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    alias = tmp_path / "aliases" / "Atlaso-alias.vmx"
    external_disk = tmp_path / "shared" / "depot.vmdk"
    external_disk.parent.mkdir(parents=True)
    external_disk.write_text("shared", encoding="utf-8")
    _write_vmx(vmx, "Atlaso", f'scsi0:2.fileName = "{external_disk.resolve()}"')
    alias.parent.mkdir(parents=True)
    os.link(vmx, alias)
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake",
        [vmx],
        registered=True,
        run_on_list=3,
        run_target=alias,
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
    assert Path(stop[3]).resolve() == alias.resolve()
    assert commands.index(stop) < commands.index(delete)
    assert external_disk.read_text(encoding="utf-8") == "shared"


def test_in_place_vmx_rewrite_after_scan_blocks_deletevm(tmp_path: Path) -> None:
    """Content evidence is rechecked even when initial detachment was unnecessary.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    """A provider failure restores the complete original VMX from its backup.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


def test_post_detachment_validation_failure_restores_original_vmx(tmp_path: Path) -> None:
    """An exception after atomic replacement restores the retained original.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    root = tmp_path / "artifacts" / "vm"
    vmx = root / "Atlaso.vmx"
    external_disk = tmp_path / "shared" / "depot.vmdk"
    external_disk.parent.mkdir(parents=True)
    external_disk.write_text("shared", encoding="utf-8")
    _write_vmx(vmx, "Atlaso", f'scsi0:2.fileName = "{external_disk.resolve()}"')
    original_bytes = vmx.read_bytes()
    wrapper = tmp_path / "post-swap-failure.ps1"
    module_path = VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1"
    wrapper.write_text(
        f"""$ErrorActionPreference = 'Stop'
$module = Import-Module '{module_path}' -Force -PassThru
& $module {{
    param([string]$VmxPath, [string]$RemovalRoot)
    $script:atlasoTestHashCalls = 0
    function script:Get-AtlasoFileSha256 {{
        param([string]$Path)
        $script:atlasoTestHashCalls++
        if ($script:atlasoTestHashCalls -eq 1) {{
            throw 'simulated post-replacement hash failure'
        }}
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }}
    $identity = Get-AtlasoPathIdentity -Path $VmxPath -Description 'test VMX'
    Disconnect-AtlasoWorkstationExternalVmdks `
        -VmxPath $VmxPath `
        -RemovalRoot $RemovalRoot `
        -ExpectedIdentity $identity
}} '{vmx}' '{root}'
""",
        encoding="utf-8",
    )

    result = _run_script(wrapper, environment=os.environ.copy())

    assert result.returncode != 0
    assert "simulated post-replacement hash failure" in result.stderr
    assert vmx.read_bytes() == original_bytes
    assert external_disk.read_text(encoding="utf-8") == "shared"
    assert not list(root.glob("*.atlaso-*.tmp"))


def test_concurrent_vmx_replacement_is_preserved(tmp_path: Path) -> None:
    """A provider-time replacement blocks recursive root deletion.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    """Checked provider failures remain terminating.

    Args:
        tmp_path: Pytest temporary directory path.
        running: Whether the VMX is marked as running.
        stop_exit: Simulated stop exit code for the fake vmrun.
        delete_exit: Simulated deleteVM exit code for the fake vmrun.
        expected: Expected error substring for stderr assertions.
    """
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
    """A zero provider exit code does not replace post-operation verification.

    Args:
        tmp_path: Pytest temporary directory path.
        running: Whether the VMX is marked as running.
        stop_sticky: Simulate stop command not removing running state.
        delete_sticky: Simulate deleteVM not removing the VMX.
        expected: Expected error substring for stderr assertions.
    """
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
    """Exact configured cleanup cannot be redirected to a sibling.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    """Recursive cleanup never traverses a linked artifact root.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    """Callers cannot omit an in-root VMX from the validated target set.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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
    """The root snapshot is rechecked after the final provider-state query.

    Args:
        tmp_path: Pytest temporary directory path.
    """
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


def test_redeploy_missing_target_and_sibling_disk_fail_closed(tmp_path: Path) -> None:
    """Redeploy and data-disk reset preserve unproven or sibling-prefix paths.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    source_vmx = _write_vmware_payload_fixture(tmp_path / "source")
    vmrun, environment, _, _ = _write_fake_vmrun(tmp_path / "fake", [])
    output_directory = tmp_path / "Atlaso-PR-634-missing-target"
    output_directory.mkdir()
    sentinel = output_directory / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    wrapper = _write_test_vm_wrapper_harness(tmp_path / "wrapper-harness")

    redeploy = _run_script(
        wrapper,
        "-PullRequestNumber",
        "634",
        "-Purpose",
        "missing-target",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(output_directory),
        "-VmrunPath",
        str(vmrun),
        "-VdiskManagerPath",
        str(vmrun),
        "-Redeploy",
        "-SkipSshKeyProvisioning",
        "-SkipNetworkPrepare",
        environment=environment,
    )
    assert redeploy.returncode != 0
    assert (
        "canonical PR-owned output directory already exists without its exact VMX"
        in redeploy.stderr
    )
    assert sentinel.read_text(encoding="utf-8") == "preserve"

    disk_output_directory = tmp_path / "Atlaso-PR-634-sibling-disk"
    sibling_directory = tmp_path / "vm-sibling"
    sibling_directory.mkdir()
    sibling_disk = sibling_directory / "unrelated.vmdk"
    sibling_disk.write_text("preserve", encoding="utf-8")
    disk_reset = _run_script(
        wrapper,
        "-PullRequestNumber",
        "634",
        "-Purpose",
        "sibling-disk",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(disk_output_directory),
        "-VmrunPath",
        str(vmrun),
        "-VdiskManagerPath",
        str(vmrun),
        "-DepotVmdkPath",
        str(sibling_disk),
        "-ResetDataDisks",
        "-SkipSshKeyProvisioning",
        "-SkipNetworkPrepare",
        environment=environment,
    )
    assert disk_reset.returncode != 0
    assert "outside the VM output directory" in disk_reset.stderr
    assert sibling_disk.read_text(encoding="utf-8") == "preserve"


def test_test_vm_ssh_key_inputs_fail_before_cleanup(tmp_path: Path) -> None:
    """Missing or conflicting SSH key inputs preserve an existing test VM.

    Args:
        tmp_path: Pytest temporary directory path.
    """
    source_vmx = tmp_path / "source" / "source.vmx"
    _write_vmx(source_vmx, "Source")
    identity = "Atlaso-PR-634-protected-vm"
    output_directory = tmp_path / identity
    target_vmx = output_directory / f"{identity}.vmx"
    _write_vmx(target_vmx, identity)
    sentinel = output_directory / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    vmrun, environment, log, _ = _write_fake_vmrun(
        tmp_path / "fake-ssh-preflight", [target_vmx], registered=True
    )
    wrapper = _write_test_vm_wrapper_harness(tmp_path / "wrapper-harness")

    missing_key = _run_script(
        wrapper,
        "-PullRequestNumber",
        "634",
        "-Purpose",
        "protected-vm",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(output_directory),
        "-VmrunPath",
        str(vmrun),
        "-SshPublicKeyPath",
        str(tmp_path / "missing.pub"),
        "-Redeploy",
        "-SkipNetworkPrepare",
        environment=environment,
    )
    assert missing_key.returncode != 0
    assert "SSH public key not found" in missing_key.stderr
    assert target_vmx.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert _commands(log) == []

    conflicting_key_options = _run_script(
        wrapper,
        "-PullRequestNumber",
        "634",
        "-Purpose",
        "protected-vm",
        "-ApplianceVmxPath",
        str(source_vmx),
        "-OutputDirectory",
        str(output_directory),
        "-VmrunPath",
        str(vmrun),
        "-SshPublicKeyPath",
        str(tmp_path / "missing.pub"),
        "-SkipSshKeyProvisioning",
        "-Redeploy",
        "-SkipNetworkPrepare",
        environment=environment,
    )
    assert conflicting_key_options.returncode != 0
    assert "Pass either -SshPublicKeyPath or -SkipSshKeyProvisioning" in conflicting_key_options.stderr
    assert target_vmx.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert _commands(log) == []


def test_module_keeps_inventory_work_out_of_normal_delete_path() -> None:
    """Regression guard for the simplified root-scoped architecture."""
    module = (VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1").read_text(
        encoding="utf-8"
    )
    normal_path = module.split("function Remove-AtlasoWorkstationVmArtifacts", 1)[1].split(
        "function Remove-AtlasoWorkstationArtifactRoot", 1
    )[0]

    assert "Test-AtlasoWorkstationVmxRegistered" in normal_path
    assert "Remove-AtlasoWorkstationStaleRegistrations" in normal_path
    assert "function Repair-AtlasoWorkstationStaleRegistrations" in module
    assert "'Repair-AtlasoWorkstationStaleRegistrations'" in module
    pre_gui_repair = module.split(
        "function Repair-AtlasoWorkstationStaleRegistrations", 1
    )[1].split("function Get-AtlasoRootSnapshot", 1)[0]
    assert "Assert-AtlasoPathHasNoReparsePoint -Path $resolvedScopeRoot" in pre_gui_repair
    assert "Remove-AtlasoWorkstationStaleRegistrations" in pre_gui_repair
    assert "Remove-Item -LiteralPath $resolvedScopeRoot" not in pre_gui_repair
    assert (
        "Close the VMware Workstation UI before removing stale Atlaso VM library entries."
        in module
    )
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
    assert ".atlaso-original-" in module
    assert "$recoveryStream.Flush($true)" in module
    assert "-Right (Read-AtlasoStreamBytes -Stream $restoredLock)" in module
    assert "$restoredLock = [System.IO.File]::Open($VmxPath, 'Open', 'Read', 'Read')" in module
    snapshot_index = normal_path.index("$snapshot = Get-AtlasoRootSnapshot")
    confirmation_index = normal_path.index("$PSCmdlet.ShouldProcess")
    post_confirmation_guard = normal_path.index(
        "Assert-AtlasoRootSnapshotUnreplaced", confirmation_index
    )
    assert snapshot_index < confirmation_index < post_confirmation_guard
    wrapper_path = module.split("function Remove-AtlasoWorkstationArtifactRoot", 1)[1]
    wrapper_snapshot = wrapper_path.index("$wrapperSnapshot = Get-AtlasoRootSnapshot")
    wrapper_confirmation = wrapper_path.index("$PSCmdlet.ShouldProcess")
    wrapper_guard = wrapper_path.index("Assert-AtlasoRootSnapshotUnreplaced")
    assert wrapper_snapshot < wrapper_confirmation < wrapper_guard
    snapshot_function = module.split("function Get-AtlasoRootSnapshot", 1)[1].split(
        "function Assert-AtlasoRootSnapshotUnreplaced", 1
    )[0]
    traversal = snapshot_function.index("Get-ChildItem -LiteralPath $RemovalRoot")
    identity_reads = [
        match.start()
        for match in re.finditer(
            re.escape("Get-AtlasoPathIdentity -Path $RemovalRoot"), snapshot_function
        )
    ]
    assert identity_reads[0] < traversal < identity_reads[1]
    assertion_function = module.split(
        "function Assert-AtlasoRootSnapshotUnreplaced", 1
    )[1].split("function Test-AtlasoRunningPathMatchesTarget", 1)[0]
    assertion_traversal = assertion_function.index(
        "Get-ChildItem -LiteralPath $RemovalRoot"
    )
    assertion_reads = [
        match.start()
        for match in re.finditer(
            re.escape("Get-AtlasoPathIdentity -Path $RemovalRoot"), assertion_function
        )
    ]
    assert assertion_reads[0] < assertion_traversal < assertion_reads[1]
    stale_repair = module.split(
        "function Remove-AtlasoWorkstationStaleRegistrations", 1
    )[1].split("function Get-AtlasoRootSnapshot", 1)[0]
    inventory_replace = stale_repair.index(
        "[System.IO.File]::Replace($temporaryPath, $InventoryPath, $backupPath, $true)"
    )
    rollback_catch = stale_repair.index("catch {", inventory_replace)
    rollback_call = stale_repair.index(
        "Restore-AtlasoFileAfterCasFailure -TargetPath $InventoryPath", rollback_catch
    )
    assert inventory_replace < rollback_catch < rollback_call
    replacement_lock = stale_repair.index(
        "$replacementLock = [System.IO.File]::Open(", inventory_replace
    )
    replacement_verification = stale_repair.index(
        "Test-AtlasoByteArraysEqual -Left $replacementBytes", replacement_lock
    )
    replacement_unlock = stale_repair.index(
        "$replacementLock.Dispose()", replacement_verification
    )
    assert inventory_replace < replacement_lock < replacement_verification < replacement_unlock
    assert stale_repair.count("foreach ($candidatePath in $targetPaths)") == 2
    assert stale_repair.count("Test-Path -LiteralPath $resolvedVmxPath") >= 3
    assert "Test-Path -LiteralPath $resolvedVmxPath -PathType Leaf" not in stale_repair
    assert "Test-Path -LiteralPath $candidatePath -PathType Leaf" not in stale_repair
    ordinary_zero = stale_repair.index(
        "if ($staleEntries.Count -eq 0 -and -not $resolvedVmxPath)"
    )
    process_gate = stale_repair.index("Get-Process vmware", ordinary_zero)
    assert ordinary_zero < process_gate
    zero_owner_proof = stale_repair.split(
        "if ($staleEntries.Count -eq 0 -and (-not $resolvedVmxPath", 1
    )[1].split("$realInventoryPath", 1)[0]
    assert "$absenceLock = [System.IO.File]::Open(" in zero_owner_proof
    assert "[System.IO.FileShare]::Read" in zero_owner_proof
    assert "Test-AtlasoByteArraysEqual -Left $originalBytes" in zero_owner_proof
    assert zero_owner_proof.index("if ($OnVerified)") < zero_owner_proof.index(
        "$absenceLock.Dispose()"
    )
    assert zero_owner_proof.index("$absenceLock.Dispose()") < zero_owner_proof.index(
        "return"
    )
    assert stale_repair.index("if ($OnVerified)", replacement_verification) < replacement_unlock
    implementation = re.sub(r"<#.*?#>\s*", "", module, flags=re.DOTALL)
    assert len(implementation.splitlines()) < 1_260


def test_development_ca_cleanup_releases_recovery_inside_provider_proof() -> None:
    """Keep quarantine and marker retirement inside the verified provider callback."""
    script = (VMWARE_SCRIPT_ROOT / "create-atlaso-test-vm.ps1").read_text(
        encoding="utf-8"
    )
    cleanup = script.split("function Invoke-PendingAtlasoDevelopmentCaCleanup", 1)[1].split(
        "function Invoke-AtlasoTestVmProvisioning", 1
    )[0]
    callback = cleanup.split("-OnVerified {", 1)[1].split("} `", 1)[0]

    assert "Restore-AtlasoRollbackDataDisksFromQuarantine" in callback
    assert "Remove-AtlasoDevelopmentCaCleanupMarker" in callback
    restore = callback.index("Restore-AtlasoRollbackDataDisksFromQuarantine")
    final_vmx_check = callback.index("Test-Path -LiteralPath $marker.VmxPath")
    marker_removal = callback.index("Remove-AtlasoDevelopmentCaCleanupMarker")
    assert restore < final_vmx_check < marker_removal


def test_pre_gui_repair_retains_exact_open_ui_refusal() -> None:
    """Keep the real-inventory process gate and its operator diagnostic exact."""
    module = (VMWARE_SCRIPT_ROOT / "Atlaso.WorkstationCleanup.psm1").read_text(
        encoding="utf-8"
    )
    stale_repair = module.split(
        "function Remove-AtlasoWorkstationStaleRegistrations", 1
    )[1].split("function Repair-AtlasoWorkstationStaleRegistrations", 1)[0]
    process_gate = stale_repair.index("Get-Process vmware -ErrorAction SilentlyContinue")
    refusal = stale_repair.index(
        "Close the VMware Workstation UI before removing stale Atlaso VM library entries."
    )

    assert "Test-AtlasoSamePath -Left $InventoryPath -Right $realInventoryPath" in stale_repair
    assert process_gate < refusal
