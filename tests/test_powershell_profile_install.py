"""Focused tests for Photon PowerShell global-profile installation."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from scripts.appliance import atlaso_install_powershell_profile as installer

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="profile installation uses POSIX descriptor semantics"
)


def _layout(tmp_path: Path, relative_binary: str) -> tuple[Path, Path, Path]:
    """Create one safe fixture layout and return its root, command, and binary.

    Args:
        tmp_path: Pytest-owned temporary directory.
        relative_binary: Reviewed executable path relative to the fixture root.
    """

    trusted_root = tmp_path / "root"
    binary = trusted_root / relative_binary
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"fixture pwsh\n")
    binary.chmod(0o755)
    command = trusted_root / "usr/bin/pwsh"
    command.parent.mkdir(parents=True, exist_ok=True)
    if command != binary:
        command.symlink_to(binary)
    for directory in (trusted_root, *binary.parents):
        if directory == tmp_path.parent:
            break
        if directory.exists() and directory.is_relative_to(trusted_root):
            directory.chmod(0o755)
    return trusted_root, command, binary


def _source(trusted_root: Path) -> Path:
    """Create a safe canonical profile source beneath the fixture root.

    Args:
        trusted_root: Fixture trust boundary.
    """

    source = trusted_root / "opt/atlaso/profile.ps1"
    source.parent.mkdir(parents=True)
    source.write_text(". '/opt/atlaso/bin/atlaso-vault-profile.ps1'\n", encoding="utf-8")
    source.chmod(0o644)
    return source


@pytest.mark.parametrize(
    "relative_binary",
    ("usr/share/powershell/pwsh", "opt/microsoft/powershell/7/pwsh"),
)
def test_installs_current_and_supported_legacy_layouts(
    tmp_path: Path, relative_binary: str
) -> None:
    """Install exact content in both reviewed PowerShell package layouts.

    Args:
        tmp_path: Pytest-owned temporary directory.
        relative_binary: Current or supported legacy executable identity.
    """

    trusted_root, command, binary = _layout(tmp_path, relative_binary)
    source = _source(trusted_root)

    installed = installer.install_global_profile(
        command,
        source,
        supported_binaries={binary},
        trusted_ancestor=trusted_root,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    )

    assert installed == binary.parent / "profile.ps1"
    assert installed.read_bytes() == source.read_bytes()
    metadata = installed.lstat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o644
    assert metadata.st_uid == os.getuid()
    assert metadata.st_gid == os.getgid()


def test_rejects_unexpected_profile_root_with_exact_diagnostic(tmp_path: Path) -> None:
    """Reject an executable outside every reviewed package layout.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, binary = _layout(tmp_path, "srv/unreviewed/pwsh")
    expected = trusted_root / "usr/share/powershell/pwsh"

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.resolve_profile_root(
            command,
            supported_binaries={expected},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        "PowerShell resolved to an unsupported global profile directory: "
        f"{binary.parent}"
    )


def test_rejects_supported_path_that_escapes_through_symlink(tmp_path: Path) -> None:
    """Treat a nominally supported directory symlink as an escaping path.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root = tmp_path / "root"
    outside = tmp_path / "outside"
    outside.mkdir()
    escaped_binary = outside / "pwsh"
    escaped_binary.write_bytes(b"fixture pwsh\n")
    nominal_root = trusted_root / "usr/share/powershell"
    nominal_root.parent.mkdir(parents=True)
    nominal_root.symlink_to(outside, target_is_directory=True)
    command = trusted_root / "usr/bin/pwsh"
    command.parent.mkdir(parents=True)
    command.symlink_to(nominal_root / "pwsh")

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.resolve_profile_root(
            command,
            supported_binaries={nominal_root / "pwsh"},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        "PowerShell resolved to an unsupported global profile directory: "
        f"{outside}"
    )


def test_rejects_existing_profile_symlink_without_following_it(tmp_path: Path) -> None:
    """Never replace content through a producer-controlled profile symlink.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, binary = _layout(tmp_path, "usr/share/powershell/pwsh")
    source = _source(trusted_root)
    escape = tmp_path / "escape.ps1"
    escape.write_text("untrusted\n", encoding="utf-8")
    target = binary.parent / "profile.ps1"
    target.symlink_to(escape)

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.install_global_profile(
            command,
            source,
            supported_binaries={binary},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        f"PowerShell global profile path must be a regular file or absent: {target}"
    )
    assert escape.read_text(encoding="utf-8") == "untrusted\n"


def test_rejects_group_writable_profile_root_with_exact_diagnostic(tmp_path: Path) -> None:
    """Reject a reviewed directory that another group member can replace.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, binary = _layout(tmp_path, "usr/share/powershell/pwsh")
    binary.parent.chmod(0o775)

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.resolve_profile_root(
            command,
            supported_binaries={binary},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        "PowerShell profile directory must not be writable by group or other: "
        f"{binary.parent}"
    )


def test_rejects_group_writable_powershell_binary_with_exact_diagnostic(
    tmp_path: Path,
) -> None:
    """Reject a supported executable whose bytes are not root-controlled.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, binary = _layout(tmp_path, "usr/share/powershell/pwsh")
    binary.chmod(0o775)

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.resolve_profile_root(
            command,
            supported_binaries={binary},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        "PowerShell executable must be root-owned, executable, and non-writable "
        f"by group or other: {binary}"
    )


def test_rejects_wrong_directory_owner_with_exact_diagnostic(tmp_path: Path) -> None:
    """Reject a layout whose trusted ancestry is not root-owned.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, binary = _layout(tmp_path, "usr/share/powershell/pwsh")

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.resolve_profile_root(
            command,
            supported_binaries={binary},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid() + 1,
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        f"PowerShell profile directory must be owned by root: {trusted_root}"
    )


def test_production_allowlist_names_current_and_legacy_photon_layouts() -> None:
    """Keep the reviewed Photon identities explicit and bounded."""

    assert installer.SUPPORTED_POWERSHELL_BINARIES == {
        Path("/usr/share/powershell/pwsh"),
        Path("/opt/microsoft/powershell/7/pwsh"),
    }
