"""Regression tests for optional Photon installation-input capture."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

TEMPLATE = Path("image/vmware-workstation/atlaso-photon.pkr.hcl")


def _bash_path(path: Path) -> str:
    """Convert a Windows drive path to its WSL mount path.

    Args:
        path: Windows path passed to Linux bash.

    Returns:
        Path spelling accepted by WSL bash.
    """
    value = path.as_posix()
    match = re.match(r"^([A-Za-z]):/(.*)$", value)
    if match is None:
        return value
    return f"/mnt/{match.group(1).lower()}/{match.group(2)}"


def _shell_provisioners(template: str) -> list[tuple[int, str, list[str]]]:
    """Extract shell provisioner inline commands from the Packer template.

    Args:
        template: Packer HCL source containing the capture provisioners.

    Returns:
        Provisioner source positions, block text, and decoded inline commands.
    """
    result = []
    for match in re.finditer(
        r'  provisioner "shell" \{(.*?)\n  \}', template, re.DOTALL
    ):
        block = match.group(1)
        inline_match = re.search(r"inline\s*=\s*\[(.*?)\n\s*\]", block, re.DOTALL)
        commands = []
        if inline_match:
            commands = [
                json.loads(command.group(0))
                for command in re.finditer(r'"(?:\\.|[^"\\])*"', inline_match.group(1))
            ]
        result.append((match.start(), block, commands))
    return result


def _capture_archive_commands() -> list[tuple[str, str, str, str, str, str]]:
    """Validate the captured archive permission commands and return their fixture data.

    Returns:
        Archive source names, commands, and destination paths for shell fixtures.
    """
    template = TEMPLATE.read_text(encoding="utf-8")
    cases = (
        (
            "atlaso-installation-rpms",
            "/var/tmp/atlaso-installation-rpms.tar",
            "atlaso-installation-rpms",
            "/var/tmp/atlaso-installation-rpms.tar",
            "installation-rpms.tar",
        ),
        (
            "atlaso-installation-powercli",
            "/var/tmp/atlaso-installation-powercli.tar",
            "Modules",
            "/var/tmp/atlaso-installation-powercli.tar",
            "installation-powercli.tar",
        ),
    )
    provisioners = _shell_provisioners(template)

    captures = []
    for (
        name,
        guest_archive,
        source_name,
        command_archive,
        output_name,
    ) in cases:
        capture = next(
            item
            for item in provisioners
            if any(
                command_archive in command and command.startswith("tar ")
                for command in item[2]
            )
        )
        commands = capture[2]
        tar_command = next(
            command
            for command in commands
            if command.startswith("tar ") and command_archive in command
        )
        chmod_command = f"chmod 0644 {guest_archive}"
        assert commands.index(tar_command) < commands.index(chmod_command)
        assert "only            = var.capture_installation_rpms ?" in capture[1]
        assert all(
            re.search(r"(?<![A-Za-z])/tmp/atlaso-installation-", command) is None
            for command in commands
        )
        if name.endswith("rpms"):
            assert any(
                'Path("/var/tmp/atlaso-installation-rpms")' in command
                for command in commands
            )

        download_start = template.find('direction   = "download"', capture[0])
        source_line = f'source      = "{guest_archive}"'
        destination_line = f'destination = "${{local.verified_capture_directory}}/{output_name}"'
        assert download_start > capture[0]
        assert template.find(source_line, download_start) > download_start
        assert template.find(destination_line, download_start) > download_start
        captures.append(
            (
                name,
                source_name,
                tar_command,
                chmod_command,
                command_archive,
                guest_archive,
            )
        )

    return captures


def test_capture_archives_are_public_readable_before_packer_download() -> None:
    """Ensure capture archives have explicit public-read mode before download."""
    assert len(_capture_archive_commands()) == 2


def test_capture_permission_commands_handle_restrictive_umask(tmp_path: Path) -> None:
    """Execute extracted tar and chmod commands with a restrictive umask.

    Args:
        tmp_path: Temporary directory for extracted archive command fixtures.
    """
    captures = _capture_archive_commands()
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to exercise the archive permission commands")

    for (
        name,
        source_name,
        tar_command,
        chmod_command,
        command_archive,
        guest_archive,
    ) in captures:
        root = tmp_path / name
        archive_root = root / "source"
        source = archive_root / source_name
        if name.endswith("powercli"):
            source = source / "VCF.PowerCLI" / "example.psd1"
        else:
            source = source / "example.rpm"
        source.parent.mkdir(parents=True)
        source.write_text("public package fixture", encoding="utf-8")
        archive = root / "output.tar"
        bash_archive = _bash_path(archive)
        bash_source_root = _bash_path(archive_root)
        chmod_command = chmod_command.replace(guest_archive, shlex.quote(bash_archive))
        tar_command = tar_command.replace(command_archive, shlex.quote(bash_archive))
        if name.endswith("powercli"):
            tar_command = tar_command.replace(
                "/usr/local/share/powershell", shlex.quote(bash_source_root)
            )
        else:
            tar_command = tar_command.replace(
                "-C /var/tmp", f"-C {shlex.quote(bash_source_root)}"
            )
        subprocess.run(
            [bash, "-c", f"umask 077; {tar_command}; {chmod_command}"], check=True
        )
        mode = subprocess.check_output(
            [bash, "-c", f"stat -c '%a' {shlex.quote(bash_archive)}"], text=True
        ).strip()
        if os.name == "nt":
            # WSL on a Windows-backed mount may report ACL-derived mode 0777;
            # the extracted chmod still must leave the archive readable.
            assert int(mode, 8) & 0o044 == 0o044
        else:
            assert mode == "644"


def test_capture_root_admission_fixture(tmp_path: Path) -> None:
    """Exercise capture-root identity, overlap, emptiness, and archive retention gates.

    Args:
        tmp_path: Pytest-owned directory for isolated filesystem fixtures.
    """
    if os.name != "nt":
        pytest.skip("Windows filesystem identity handles are required for capture-root admission")
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required to exercise capture-root admission")

    repository = TEMPLATE.resolve().parents[2]
    fixture = repository / "tests" / "powershell" / "Test-InstallationCaptureRoot.ps1"
    result = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-File",
            str(fixture),
            "-RepositoryRoot",
            str(repository),
            "-FixtureRoot",
            str(tmp_path),
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_capture_hcl_requires_separate_directory() -> None:
    """Keep capture destinations distinct from Packer's cleaned VM output."""
    template = TEMPLATE.read_text(encoding="utf-8")
    assert 'variable "capture_directory"' in template
    assert 'default     = ""' in template
    assert 'verified_capture_directory   = var.capture_installation_rpms ? regex(".+", var.capture_directory) : ""' in template
    assert 'destination = "${var.output_directory}/installation-rpms.tar"' not in template
    assert 'destination = "${var.output_directory}/installation-powercli.tar"' not in template
