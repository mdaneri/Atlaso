"""Behavior tests for fail-closed tiny lifecycle-client preparation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PREPARATION_SCRIPTS = {
    "hyperv": (
        REPOSITORY_ROOT / "scripts/windows/hyperv/prepare-tiny-linux-client.ps1",
        "-OutputVhdxName",
        "tiny-client.vhdx",
        "vhdx",
    ),
    "vmware": (
        REPOSITORY_ROOT / "scripts/windows/vmware/prepare-tiny-linux-client.ps1",
        "-OutputVmdkName",
        "tiny-client.vmdk",
        "vmdk",
    ),
}


def _pwsh_path() -> str:
    """Return PowerShell 7 or skip the behavior tests when it is unavailable."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required for tiny-client preparation tests")
    return pwsh


def _write_fake_qemu_img(directory: Path) -> Path:
    """Create a fake qemu-img command controlled by an environment mode.

    Args:
        directory: Directory that receives the fake command.

    Returns:
        Path to the directory that must be prepended to ``PATH``.
    """
    directory.mkdir(parents=True)
    fake_script = directory / "fake_qemu_img.py"
    fake_script.write_text(
        """from __future__ import annotations
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
mode = os.environ["ATLASO_FAKE_QEMU_IMG_MODE"]
if not arguments:
    print("missing qemu-img operation", file=sys.stderr)
    raise SystemExit(64)
if arguments[0] == "convert":
    destination = Path(arguments[-1])
    destination.write_bytes(b"partial" if mode == "convert-fail" else b"converted")
    if mode == "convert-fail":
        print("qemu-img: simulated conversion failure", file=sys.stderr)
        raise SystemExit(23)
    raise SystemExit(0)
if arguments[0] == "info":
    if mode == "info-fail":
        print("qemu-img: invalid image", file=sys.stderr)
        raise SystemExit(24)
    print('{"format": "prepared"}')
    raise SystemExit(0)
print(f"unsupported qemu-img operation: {arguments[0]}", file=sys.stderr)
raise SystemExit(64)
""",
        encoding="utf-8",
    )

    if os.name == "nt":
        wrapper = directory / "qemu-img.cmd"
        wrapper.write_text(
            f'@echo off\r\n"{sys.executable}" "{fake_script}" %*\r\n',
            encoding="utf-8",
        )
    else:
        wrapper = directory / "qemu-img"
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{fake_script}" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
    return directory


def _run_preparation(
    tmp_path: Path,
    platform: str,
    mode: str,
    *,
    preexisting_disk: bytes | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run one preparation wrapper against the controlled qemu-img command.

    Args:
        tmp_path: Isolated test directory.
        platform: Preparation wrapper key.
        mode: Fake qemu-img behavior mode.
        preexisting_disk: Optional bytes to place at the destination before execution.

    Returns:
        Completed wrapper process and its expected disk output path.
    """
    script, output_name_argument, output_name, _ = PREPARATION_SCRIPTS[platform]
    output_directory = tmp_path / platform / mode / "output"
    output_directory.mkdir(parents=True)
    image_name = "fixture.qcow2"
    image_bytes = b"verified fixture image"
    (output_directory / image_name).write_bytes(image_bytes)
    (output_directory / f"{image_name}.sha512").write_text(
        f"{hashlib.sha512(image_bytes).hexdigest()}  {image_name}\n",
        encoding="utf-8",
    )
    disk_path = output_directory / output_name
    if preexisting_disk is not None:
        disk_path.write_bytes(preexisting_disk)
    fake_directory = _write_fake_qemu_img(tmp_path / platform / mode / "fake-bin")
    environment = os.environ.copy()
    environment.update(
        {
            "ATLASO_FAKE_QEMU_IMG_MODE": mode,
            "PATH": os.pathsep.join((str(fake_directory), environment["PATH"])),
        }
    )
    result = subprocess.run(
        [
            _pwsh_path(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-OutputDirectory",
            str(output_directory),
            "-ImageName",
            image_name,
            output_name_argument,
            output_name,
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    return result, disk_path


@pytest.mark.parametrize("platform", PREPARATION_SCRIPTS)
@pytest.mark.parametrize(
    ("mode", "exit_code", "failure_text"),
    [
        ("convert-fail", 23, "qemu-img convert failed with exit code 23"),
        ("info-fail", 24, "qemu-img info failed with exit code 24"),
    ],
)
def test_qemu_img_failure_is_propagated_without_a_prepared_disk(
    tmp_path: Path,
    platform: str,
    mode: str,
    exit_code: int,
    failure_text: str,
) -> None:
    """Native conversion and inspection failures must not report preparation success.

    Args:
        tmp_path: Isolated test directory.
        platform: Preparation wrapper key.
        mode: Fake qemu-img behavior mode.
        exit_code: Native exit code emitted by the fake command.
        failure_text: Expected checked-command failure text.
    """
    result, disk_path = _run_preparation(tmp_path, platform, mode)

    assert result.returncode != 0
    assert failure_text in result.stderr
    assert str(exit_code) in result.stderr
    assert '"qemu_img_info"' not in result.stdout
    assert not disk_path.exists()


@pytest.mark.parametrize("platform", PREPARATION_SCRIPTS)
def test_successful_qemu_img_preparation_still_emits_json(
    tmp_path: Path,
    platform: str,
) -> None:
    """Successful conversion and inspection retain the existing JSON result contract.

    Args:
        tmp_path: Isolated test directory.
        platform: Preparation wrapper key.
    """
    result, disk_path = _run_preparation(tmp_path, platform, "success")

    assert result.returncode == 0, result.stdout + result.stderr
    json_start = result.stdout.index("{")
    payload = json.loads(result.stdout[json_start:])
    _, _, _, disk_property = PREPARATION_SCRIPTS[platform]
    assert Path(payload[disk_property]) == disk_path.resolve()
    assert payload["qemu_img_info"] == '{"format": "prepared"}'


@pytest.mark.parametrize("platform", PREPARATION_SCRIPTS)
def test_failed_inspection_preserves_a_preexisting_disk(
    tmp_path: Path,
    platform: str,
) -> None:
    """Inspection failure must not delete an artifact the current run did not create.

    Args:
        tmp_path: Isolated test directory.
        platform: Preparation wrapper key.
    """
    original = b"preexisting image"
    result, disk_path = _run_preparation(
        tmp_path,
        platform,
        "info-fail",
        preexisting_disk=original,
    )

    assert result.returncode != 0
    assert "qemu-img info failed with exit code 24" in result.stderr
    assert '"qemu_img_info"' not in result.stdout
    assert disk_path.read_bytes() == original
