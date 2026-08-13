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
) -> tuple[Path, dict[str, str], Path]:
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
        ),
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

if command == "list":
    paths = read_paths("running")
    print(f"Total running VMs: {len(paths)}")
    print("\\n".join(paths))
    raise SystemExit(0)
if command == "listRegisteredVM":
    paths = read_paths("registered")
    print(f"Total registered VMs: {len(paths)}")
    print("\\n".join(paths))
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
    write_paths("running", [path for path in read_paths("running") if not same_file(path, target)])
    raise SystemExit(0)
if command == "unregister":
    exit_code = int(os.environ.get("ATLASO_FAKE_VMRUN_UNREGISTER_EXIT", "0"))
    if exit_code:
        print("simulated unregister failure", file=sys.stderr)
        raise SystemExit(exit_code)
    registered_paths = [path for path in read_paths("registered") if not same_file(path, target)]
    write_paths("registered", registered_paths)
    inventory.write_text(
        '.encoding = "UTF-8"\\n'
        + "".join(
            f'vmlist{index}.config = "{path}"\\n'
            for index, path in enumerate(registered_paths, start=1)
        ),
        encoding="utf-8",
    )
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
            "APPDATA": str(appdata_directory),
        }
    )
    return wrapper, environment, log_path


def _run_script(script: Path, *arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'displayName = "{display_name}"\n', encoding="utf-8")


@pytest.mark.parametrize(
    ("running", "registered", "stop_exit", "unregister_exit", "expected_error"),
    [
        (True, True, 9, 0, "Stop VMware Workstation VM"),
        (False, True, 0, 9, "Unregister VMware Workstation VM"),
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
    """A failed stop or unregister must prevent recursive VM-directory deletion."""
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
    """Successful and already-inactive cleanup both remove the exact VM artifact directory."""
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
    assert ("unregister" in action_names) is registered


def test_general_removal_rejects_an_unvalidated_vmx_in_the_removal_root(
    tmp_path: Path,
) -> None:
    """Recursive deletion must not include a VMX omitted by the caller."""
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
    """A malformed vmrun entry must not let cleanup mistake a running VM for inactive."""
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


@pytest.mark.parametrize(
    "registration_entry",
    [
        "vmlist0.config\n",
        'vmlist0.config = "relative-registered.vmx"\n',
    ],
)
def test_general_removal_rejects_malformed_registration_entries(
    tmp_path: Path,
    registration_entry: str,
) -> None:
    """Incomplete or relative Workstation registrations must preserve artifacts."""
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


def test_general_removal_matches_a_running_vmx_by_filesystem_identity(
    tmp_path: Path,
) -> None:
    """A Windows path alias must still trigger the required running-VM transition."""
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
    """A complete empty Workstation inventory slot is not a malformed registration."""
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
    inventory_path.write_text('vmlist0.config = ""\n', encoding="utf-8")

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
    """Explicit confirmation cannot be suppressed by the nested cleanup helper."""
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
    """Automation may still opt out of confirmation through the common parameter."""
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


def test_redeploy_missing_target_and_sibling_disk_fail_closed(tmp_path: Path) -> None:
    """Redeploy and data-disk reset must preserve unproven or sibling-prefix paths."""
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
    """The standalone lifecycle remover propagates vmrun failures without deleting files."""
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
