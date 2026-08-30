"""Focused tests for Photon PowerShell global-profile installation."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.appliance import atlaso_install_powershell_profile as installer

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="profile installation uses POSIX descriptor semantics"
)


def _supported_binary(trusted_root: Path, relative_binary: str) -> Path:
    """Create one safely owned supported executable fixture.

    Args:
        trusted_root: Fixture trust boundary.
        relative_binary: Reviewed executable path relative to the fixture root.

    Returns:
        Canonical executable fixture path.
    """

    binary = trusted_root / relative_binary
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"fixture pwsh\n")
    binary.chmod(0o755)
    for directory in (trusted_root, *binary.parents):
        if directory == trusted_root.parent:
            break
        if directory.exists() and directory.is_relative_to(trusted_root):
            directory.chmod(0o755)
    return binary


def _layout(tmp_path: Path, relative_binary: str) -> tuple[Path, Path, Path]:
    """Create one safe fixture layout and return its root, command, and binary.

    Args:
        tmp_path: Pytest-owned temporary directory.
        relative_binary: Reviewed executable path relative to the fixture root.
    """

    trusted_root = tmp_path / "root"
    binary = _supported_binary(trusted_root, relative_binary)
    command = trusted_root / "usr/bin/pwsh"
    command.parent.mkdir(parents=True, exist_ok=True)
    if command != binary:
        command.symlink_to(binary)
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


def test_removes_exact_atlaso_profile_from_inactive_supported_layout(
    tmp_path: Path,
) -> None:
    """Retire the old Atlaso copy after PowerShell moves to another layout.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, current_binary = _layout(
        tmp_path, "usr/share/powershell/pwsh"
    )
    legacy_binary = _supported_binary(
        trusted_root, "opt/microsoft/powershell/7/pwsh"
    )
    source = _source(trusted_root)
    inactive_profile = legacy_binary.parent / "profile.ps1"
    inactive_profile.write_bytes(source.read_bytes())
    inactive_profile.chmod(0o644)

    installed = installer.install_global_profile(
        command,
        source,
        supported_binaries={current_binary, legacy_binary},
        trusted_ancestor=trusted_root,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    )

    assert installed == current_binary.parent / "profile.ps1"
    assert installed.read_bytes() == source.read_bytes()
    assert not inactive_profile.exists()


def test_rejects_non_atlaso_profile_in_inactive_supported_layout(
    tmp_path: Path,
) -> None:
    """Never delete producer content from an inactive reviewed directory.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, current_binary = _layout(
        tmp_path, "usr/share/powershell/pwsh"
    )
    legacy_binary = _supported_binary(
        trusted_root, "opt/microsoft/powershell/7/pwsh"
    )
    source = _source(trusted_root)
    inactive_profile = legacy_binary.parent / "profile.ps1"
    inactive_profile.write_text("producer content\n", encoding="utf-8")
    inactive_profile.chmod(0o644)

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.install_global_profile(
            command,
            source,
            supported_binaries={current_binary, legacy_binary},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        f"Inactive PowerShell global profile is not Atlaso-owned: {inactive_profile}"
    )
    assert inactive_profile.read_text(encoding="utf-8") == "producer content\n"


def test_rejects_inactive_supported_directory_symlink(tmp_path: Path) -> None:
    """Never inspect or remove a profile through an inactive-root symlink.

    Args:
        tmp_path: Pytest-owned temporary directory.
    """

    trusted_root, command, current_binary = _layout(
        tmp_path, "usr/share/powershell/pwsh"
    )
    source = _source(trusted_root)
    outside = tmp_path / "outside"
    outside.mkdir()
    inactive_root = trusted_root / "opt/microsoft/powershell/7"
    inactive_root.parent.mkdir(parents=True)
    inactive_root.symlink_to(outside, target_is_directory=True)
    inactive_binary = inactive_root / "pwsh"
    outside_profile = outside / "profile.ps1"
    outside_profile.write_bytes(source.read_bytes())
    outside_profile.chmod(0o644)

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.install_global_profile(
            command,
            source,
            supported_binaries={current_binary, inactive_binary},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        "PowerShell profile directory must be a canonical directory: "
        f"{inactive_root}"
    )
    assert outside_profile.exists()


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
    escaped_binary.chmod(0o755)
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


def test_rejects_wrong_directory_owner_with_exact_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject a layout whose trusted ancestry is not root-owned.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture used to model an unsafe directory owner.
    """

    trusted_root, command, binary = _layout(tmp_path, "usr/share/powershell/pwsh")
    original_lstat = Path.lstat

    def mismatched_root_owner(path: Path) -> os.stat_result | SimpleNamespace:
        """Report only the trusted root as owned by an unexpected identity."""

        metadata = original_lstat(path)
        if path == trusted_root:
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_uid=os.getuid() + 1,
                st_gid=metadata.st_gid,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", mismatched_root_owner)

    with pytest.raises(installer.ProfileInstallError) as error:
        installer.resolve_profile_root(
            command,
            supported_binaries={binary},
            trusted_ancestor=trusted_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    assert str(error.value) == (
        f"PowerShell profile directory must be owned by root: {trusted_root}"
    )


def test_main_does_not_log_untrusted_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Keep operator-controlled paths out of the command-line diagnostic.

    Args:
        monkeypatch: Pytest fixture used to drive the CLI failure boundary.
        capsys: Pytest fixture used to inspect bounded CLI output.
    """

    secret_path = "/tmp/operator-secret/pwsh"

    def reject_profile(*_args: object, **_kwargs: object) -> Path:
        """Raise one detailed internal error containing an untrusted path."""

        raise installer.ProfileInstallError(f"unsafe profile path: {secret_path}")

    monkeypatch.setattr(installer, "install_global_profile", reject_profile)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "atlaso_install_powershell_profile.py",
            "--pwsh-path",
            secret_path,
            "--profile-source",
            "/tmp/operator-secret/profile.ps1",
        ],
    )

    assert installer.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Atlaso PowerShell profile installation failed safely\n"
    assert secret_path not in captured.err


def test_main_does_not_log_installed_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Keep the resolved installation identity out of successful CLI output.

    Args:
        monkeypatch: Pytest fixture used to drive the CLI success boundary.
        capsys: Pytest fixture used to inspect bounded CLI output.
    """

    secret_path = Path("/tmp/operator-secret/powershell/profile.ps1")

    def install_profile(*_args: object, **_kwargs: object) -> Path:
        """Return one installation path derived from untrusted CLI input."""

        return secret_path

    monkeypatch.setattr(installer, "install_global_profile", install_profile)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "atlaso_install_powershell_profile.py",
            "--pwsh-path",
            "/tmp/operator-secret/pwsh",
            "--profile-source",
            "/tmp/operator-secret/profile.ps1",
        ],
    )

    assert installer.main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == "Installed Atlaso PowerShell global profile\n"
    assert str(secret_path) not in captured.out


def test_production_allowlist_names_current_and_legacy_photon_layouts() -> None:
    """Keep the reviewed Photon identities explicit and bounded."""

    assert installer.SUPPORTED_POWERSHELL_BINARIES == {
        Path("/usr/share/powershell/pwsh"),
        Path("/opt/microsoft/powershell/7/pwsh"),
    }
