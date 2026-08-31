"""Tests for protected verification of the wheel installed in a guest disk."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from scripts import verify_virtualization_guest_wheel as verifier

SOURCE_COMMIT = "a" * 40


def _metadata_output(
    commands: list[str], overrides: dict[str, tuple[int, int, int]] | None = None
) -> list[str] | None:
    """Return guestfish lstatns output for one bounded metadata query.

    Args:
        commands: Guestfish commands issued by the verifier.
        overrides: Optional path-specific mode, uid, and gid records.
    """

    if not any(command.startswith("lstatns ") for command in commands):
        return None
    overrides = overrides or {}
    lines: list[str] = []
    for command in commands:
        if command.startswith("echo ATLASO-METADATA:"):
            lines.append(command.removeprefix("echo "))
        elif command.startswith("lstatns "):
            path = command.removeprefix("lstatns ")
            is_file = (
                path in verifier.DEPLOYED_FILE_MODES
                or path in verifier.POWERSHELL_PROFILE_TARGETS
                or path.startswith("/etc/atlaso/update-trust.d/")
            )
            file_mode = verifier.DEPLOYED_FILE_MODES.get(path, 0o644)
            default_mode = (stat.S_IFREG | file_mode) if is_file else (stat.S_IFDIR | 0o755)
            mode, uid, gid = overrides.get(path, (default_mode, 0, 0))
            lines.extend((f"st_mode: {mode}", f"st_uid: {uid}", f"st_gid: {gid}"))
    return lines


def _powershell_profile_output(commands: list[str], target: str) -> list[str] | None:
    """Return the resolved guest PowerShell executable for one profile target.

    Args:
        commands: Guestfish commands issued by the verifier.
        target: PowerShell profile target whose executable path is expected.
    """

    if commands[-1] != "realpath /usr/bin/pwsh":
        return None
    return [f"{PurePosixPath(target).parent.as_posix()}/pwsh"]


def _powershell_profile_layout_output(
    commands: list[str],
    present: dict[str, tuple[int, int, int]],
) -> list[str] | None:
    """Return guestfish-shaped optional no-follow profile metadata.

    Args:
        commands: Guestfish commands issued by the verifier.
        present: Path-specific mode, uid, and gid records for existing objects.
    """

    if not any(
        command.startswith("echo ATLASO-POWERSHELL-PROFILE:")
        for command in commands
    ):
        return None
    lines: list[str] = []
    for command in commands:
        if command.startswith("echo ATLASO-POWERSHELL-PROFILE:"):
            lines.append(command.removeprefix("echo "))
        elif command.startswith("-lstatns "):
            path = command.removeprefix("-lstatns ")
            if path in present:
                mode, uid, gid = present[path]
                lines.extend(
                    (f"st_mode: {mode}", f"st_uid: {uid}", f"st_gid: {gid}")
                )
        elif command.startswith("echo ATLASO-POWERSHELL-PROFILE-END:"):
            lines.append(command.removeprefix("echo "))
    return lines


@pytest.fixture
def bypass_system_content(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep wheel-focused tests scoped to their existing guest archives.

    Args:
        monkeypatch: Pytest fixture used to isolate system and runtime checks.
    """

    monkeypatch.setattr(
        verifier, "_verify_deployed_system_content", lambda *_arguments: 0
    )
    monkeypatch.setattr(verifier, "_verify_python_runtime", lambda *_arguments: 2)


def _wheel(path: Path) -> tuple[Path, dict[str, bytes]]:
    """Create a small valid Atlaso wheel and return its installed members.

    Args:
        path: Destination wheel path.
    """

    members = {
        "atlaso/__init__.py": b'__version__ = "0.9.242"\n',
        "atlaso-0.9.242.dist-info/METADATA": b"Metadata-Version: 2.4\nName: Atlaso\nVersion: 0.9.242\n",
        "atlaso-0.9.242.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "atlaso-0.9.242.dist-info/entry_points.txt": (
            b"[console_scripts]\n"
            b"atlaso-console = atlaso.app.appliance_console:main\n"
            b"atlaso-kmip = atlaso.app.kmip.server:main\n"
            b"atlaso-vault = atlaso.app.vault_cli:main\n"
            b"atlaso-worker = atlaso.app.worker:main\n"
        ),
    }
    rows: list[list[str]] = []
    for name, content in members.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest())
            .decode()
            .rstrip("=")
        )
        rows.append([name, f"sha256={digest}", str(len(content))])
    record_name = "atlaso-0.9.242.dist-info/RECORD"
    rows.append([record_name, "", ""])
    output = io.StringIO()
    csv.writer(output, lineterminator="\n").writerows(rows)
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
        archive.writestr(record_name, output.getvalue())
    return path, members


def _dependency_wheel(path: Path) -> tuple[Path, dict[str, bytes]]:
    """Create one signed-wheelhouse dependency fixture.

    Args:
        path: Destination wheel path.
    """

    members = {
        "authlib/__init__.py": b'__version__ = "1.6.4"\n',
        "authlib-1.6.4.dist-info/METADATA": b"Metadata-Version: 2.4\nName: Authlib\nVersion: 1.6.4\n",
        "authlib-1.6.4.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    rows: list[list[str]] = []
    for name, content in members.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest())
            .decode()
            .rstrip("=")
        )
        rows.append([name, f"sha256={digest}", str(len(content))])
    record_name = "authlib-1.6.4.dist-info/RECORD"
    rows.append([record_name, "", ""])
    output = io.StringIO()
    csv.writer(output, lineterminator="\n").writerows(rows)
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
        archive.writestr(record_name, output.getvalue())
    return path, members


def _site_archive(
    path: Path, members: dict[str, bytes], extra: dict[str, bytes] | None = None
) -> None:
    """Write a guestfish-shaped site-packages tar archive.

    Args:
        path: Destination tar path.
        members: Signed installed files.
        extra: Optional producer-controlled files.
    """

    with tarfile.open(path, "w") as archive:
        for name, content in {**members, **(extra or {})}.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def _runtime_archive(
    path: Path,
    *,
    python_target: str = "/usr/bin/python3.14",
    altered_script: str = "",
) -> None:
    """Write a guestfish-shaped active virtualenv bin tar archive.

    Args:
        path: Destination tar path.
        python_target: Virtualenv Python symbolic-link target.
        altered_script: Console script replaced by the fixture.
    """

    scripts = {
        "atlaso-console": ("atlaso.app.appliance_console", "main"),
        "atlaso-kmip": ("atlaso.app.kmip.server", "main"),
        "atlaso-vault": ("atlaso.app.vault_cli", "main"),
        "atlaso-worker": ("atlaso.app.worker", "main"),
    }
    with tarfile.open(path, "w") as archive:
        python = tarfile.TarInfo("python")
        python.type = tarfile.SYMTYPE
        python.linkname = python_target
        python.mode = 0o777
        archive.addfile(python)
        for name, (module, function) in scripts.items():
            content = verifier._console_script_bytes(
                "/opt/atlaso/.venv/bin/python", module, function
            )
            if name == altered_script:
                content = b"#!/bin/sh\nexec producer-controlled\n"
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(content))


def _write_guest_archive(
    destination: Path,
    source: str,
    installed: dict[str, bytes],
    *,
    extra: dict[str, bytes] | None = None,
    python_target: str = "/usr/bin/python3.14",
    altered_script: str = "",
) -> None:
    """Write the requested site-packages or virtualenv-bin guest archive.

    Args:
        destination: Destination tar path.
        source: Guest directory requested by the verifier.
        installed: Signed installed-file fixture.
        extra: Optional producer-controlled files.
        python_target: Virtualenv Python symbolic-link target.
        altered_script: Console script replaced by the fixture.
    """

    if source.endswith("/bin"):
        _runtime_archive(
            destination,
            python_target=python_target,
            altered_script=altered_script,
        )
    else:
        _site_archive(destination, installed, extra)


def _assets(path: Path) -> None:
    """Create the minimum system-content provenance fixture.

    Args:
        path: Candidate asset directory to create.
    """

    path.mkdir()
    (path / "atlaso-system.vmdk").write_bytes(b"vmdk")
    (path / "photon.vmdk").write_bytes(b"vmdk")
    (path / "atlaso-v0.9.242-provenance.json").write_text(
        json.dumps(
            {
                "payloads": [
                    {"role": "photon_os", "file": "photon.vmdk"},
                    {"role": "atlaso_system", "file": "atlaso-system.vmdk"},
                ]
            }
        ),
        encoding="utf-8",
    )


def test_verifies_every_hashed_wheel_member_in_active_venv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bypass_system_content: None,
) -> None:
    """Installed Atlaso files must match the exact signed-release wheel.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to emulate guestfish.
        bypass_system_content: Fixture isolating wheel verification.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    wheel, members = _wheel(tmp_path / "atlaso-0.9.242-py3-none-any.whl")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _, dependencies = _dependency_wheel(
        wheelhouse / "authlib-1.6.4-py2.py3-none-any.whl"
    )
    installed = {**members, **dependencies}

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return deterministic guest data.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        source = tar_command.split(" ", 2)[1]
        destination = tar_command.rsplit(" ", 1)[1]
        _write_guest_archive(Path(destination), source, installed)
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    result = verifier.verify_installed_environment(
        assets, wheel, wheelhouse, digest, SOURCE_COMMIT, tmp_path
    )
    assert result["wheel_sha256"] == digest
    assert result["distributions_verified"] == 2
    assert result["files_verified"] == len(installed)


def test_rejects_altered_installed_wheel_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bypass_system_content: None,
) -> None:
    """A producer cannot substitute guest package bytes and retain signing.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to emulate guestfish.
        bypass_system_content: Fixture isolating wheel verification.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    wheel, members = _wheel(tmp_path / "atlaso-0.9.242-py3-none-any.whl")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _, dependencies = _dependency_wheel(
        wheelhouse / "authlib-1.6.4-py2.py3-none-any.whl"
    )
    installed = {**members, **dependencies}

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return one altered installed wheel member.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        source = tar_command.split(" ", 2)[1]
        destination = tar_command.rsplit(" ", 1)[1]
        altered = {**installed, "authlib/__init__.py": b"substituted"}
        _write_guest_archive(Path(destination), source, altered)
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="installed wheel member does not match"):
        verifier.verify_installed_environment(
            assets, wheel, wheelhouse, digest, SOURCE_COMMIT, tmp_path
        )


def test_rejects_unexpected_active_pth_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bypass_system_content: None,
) -> None:
    """The protected inventory rejects producer-injected active environment files.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to emulate guestfish.
        bypass_system_content: Fixture isolating wheel verification.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    wheel, members = _wheel(tmp_path / "atlaso-0.9.242-py3-none-any.whl")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _, dependencies = _dependency_wheel(
        wheelhouse / "authlib-1.6.4-py2.py3-none-any.whl"
    )

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return one producer-injected active environment file.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        source = tar_command.split(" ", 2)[1]
        destination = tar_command.rsplit(" ", 1)[1]
        _write_guest_archive(
            Path(destination),
            source,
            {**members, **dependencies},
            extra={"producer-injected.pth": b"import os\n"},
        )
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="unexpected file: producer-injected.pth"):
        verifier.verify_installed_environment(
            assets, wheel, wheelhouse, digest, SOURCE_COMMIT, tmp_path
        )


def test_rejects_generated_active_bytecode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bypass_system_content: None,
) -> None:
    """The protected inventory rejects executable bytecode absent from wheels.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to emulate guestfish.
        bypass_system_content: Fixture isolating wheel verification.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    wheel, members = _wheel(tmp_path / "atlaso-0.9.242-py3-none-any.whl")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _, dependencies = _dependency_wheel(
        wheelhouse / "authlib-1.6.4-py2.py3-none-any.whl"
    )

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return producer-generated active bytecode beside signed source.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """

        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        source = tar_command.split(" ", 2)[1]
        destination = tar_command.rsplit(" ", 1)[1]
        _write_guest_archive(
            Path(destination),
            source,
            {**members, **dependencies},
            extra={"atlaso/__pycache__/__init__.cpython-314.pyc": b"producer-bytecode"},
        )
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="unexpected file: atlaso/__pycache__"):
        verifier.verify_installed_environment(
            assets, wheel, wheelhouse, digest, SOURCE_COMMIT, tmp_path
        )


@pytest.mark.parametrize(
    ("python_target", "altered_script", "message"),
    [
        ("/tmp/producer-python", "", "untrusted interpreter"),
        ("/usr/bin/python3.14", "atlaso-console", "does not match the signed wheel"),
    ],
)
def test_rejects_altered_runtime_executables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    python_target: str,
    altered_script: str,
    message: str,
    bypass_system_content: None,
) -> None:
    """Protected signing rejects replaced Python and console launchers.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to emulate guestfish.
        python_target: Virtualenv Python symbolic-link target.
        altered_script: Console script replaced by the fixture.
        message: Expected fail-closed diagnostic.
        bypass_system_content: Fixture isolating wheel verification.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    wheel, members = _wheel(tmp_path / "atlaso-0.9.242-py3-none-any.whl")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _, dependencies = _dependency_wheel(
        wheelhouse / "authlib-1.6.4-py2.py3-none-any.whl"
    )
    installed = {**members, **dependencies}

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return altered runtime launcher data.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        source = tar_command.split(" ", 2)[1]
        destination = Path(tar_command.rsplit(" ", 1)[1])
        _write_guest_archive(
            destination,
            source,
            installed,
            python_target=python_target,
            altered_script=altered_script,
        )
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match=message):
        verifier.verify_installed_environment(
            assets, wheel, wheelhouse, digest, SOURCE_COMMIT, tmp_path
        )


@pytest.mark.parametrize(
    ("altered_target", "extra_trust_key", "message"),
    [
        (
            "/opt-atlaso/bin/atlaso-helper",
            False,
            "does not match admitted commit",
        ),
        (
            "/usr/share/powershell/profile.ps1",
            False,
            "does not match admitted commit",
        ),
        ("", True, "update-trust key set does not match admitted commit"),
    ],
)
def test_rejects_altered_non_wheel_system_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    altered_target: str,
    extra_trust_key: bool,
    message: str,
) -> None:
    """Protected signing binds deployed helpers and the complete trust-key set.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to isolate source and guest reads.
        altered_target: Guest file replaced by the fixture.
        extra_trust_key: Whether the guest exposes an unexpected trust key.
        message: Expected fail-closed diagnostic.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    trust_source = "image/common/update-trust/atlaso-release-test.pem"
    source_bytes = {
        **{source: f"source:{source}\n".encode() for source in verifier.DEPLOYED_TEXT_FILES},
        **{source: f"binary:{source}".encode() for source in verifier.DEPLOYED_BINARY_FILES},
        verifier.POWERSHELL_PROFILE_SOURCE: b"canonical profile\n",
        trust_source: b"public trust key\n",
    }
    guest_bytes = {
        **{
            target: source_bytes[source]
            for source, target in verifier.DEPLOYED_TEXT_FILES.items()
        },
        **{
            target: source_bytes[source]
            for source, target in verifier.DEPLOYED_BINARY_FILES.items()
        },
        "/usr/share/powershell/profile.ps1": source_bytes[
            verifier.POWERSHELL_PROFILE_SOURCE
        ],
        "/etc/atlaso/update-trust.d/atlaso-release-test.pem": source_bytes[
            trust_source
        ],
    }
    if altered_target:
        guest_bytes[altered_target] = b"producer-controlled\n"

    monkeypatch.setattr(
        verifier,
        "_git_source_bytes",
        lambda _root, _commit, source: source_bytes[source],
    )
    monkeypatch.setattr(
        verifier,
        "_git_trust_key_paths",
        lambda _root, _commit: [trust_source],
    )

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return deployed system content from the fixture.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        profile_layout = _powershell_profile_layout_output(
            commands,
            {
                "/usr/share/powershell/profile.ps1": (
                    stat.S_IFREG | 0o644,
                    0,
                    0,
                )
            },
        )
        if profile_layout is not None:
            return profile_layout
        if commands[-1] == "ls /etc/atlaso/update-trust.d":
            names = ["atlaso-release-test.pem"]
            if extra_trust_key:
                names.append("producer.pem")
            return names
        powershell_profile = _powershell_profile_output(
            commands, "/usr/share/powershell/profile.ps1"
        )
        if powershell_profile is not None:
            return powershell_profile
        metadata = _metadata_output(commands)
        if metadata is not None:
            return metadata
        download = commands[-1].split(" ", 2)
        assert download[0] == "download"
        Path(download[2]).write_bytes(guest_bytes[download[1]])
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    with pytest.raises(SystemExit, match=message):
        verifier._verify_deployed_system_content(assets, SOURCE_COMMIT, tmp_path)


@pytest.mark.parametrize("powershell_profile_target", verifier.POWERSHELL_PROFILE_TARGETS)
def test_verifies_every_release_refreshed_non_wheel_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    powershell_profile_target: str,
) -> None:
    """The admitted commit supplies every expected deployed system byte.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to isolate source and guest reads.
        powershell_profile_target: Release-refreshed PowerShell profile target to verify.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    trust_source = "image/common/update-trust/atlaso-release-test.pem"
    source_bytes = {
        **{source: f"source:{source}\n".encode() for source in verifier.DEPLOYED_TEXT_FILES},
        **{source: f"binary:{source}".encode() for source in verifier.DEPLOYED_BINARY_FILES},
        verifier.POWERSHELL_PROFILE_SOURCE: b"canonical profile\n",
        trust_source: b"public trust key\n",
    }
    guest_bytes = {
        **{
            target: source_bytes[source]
            for source, target in verifier.DEPLOYED_TEXT_FILES.items()
        },
        **{
            target: source_bytes[source]
            for source, target in verifier.DEPLOYED_BINARY_FILES.items()
        },
        "/usr/share/powershell/profile.ps1": source_bytes[
            verifier.POWERSHELL_PROFILE_SOURCE
        ],
        "/etc/atlaso/update-trust.d/atlaso-release-test.pem": source_bytes[
            trust_source
        ],
    }
    default_profile_target = verifier.DEPLOYED_TEXT_FILES[
        verifier.POWERSHELL_PROFILE_SOURCE
    ]
    if powershell_profile_target != default_profile_target:
        guest_bytes[powershell_profile_target] = guest_bytes.pop(default_profile_target)
    metadata_queries: set[str] = set()
    monkeypatch.setattr(
        verifier,
        "_git_source_bytes",
        lambda _root, _commit, source: source_bytes[source],
    )
    monkeypatch.setattr(
        verifier,
        "_git_trust_key_paths",
        lambda _root, _commit: [trust_source],
    )

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return exact deployed system content.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        profile_layout = _powershell_profile_layout_output(
            commands,
            {powershell_profile_target: (stat.S_IFREG | 0o644, 0, 0)},
        )
        if profile_layout is not None:
            return profile_layout
        if commands[-1] == "ls /etc/atlaso/update-trust.d":
            return ["atlaso-release-test.pem"]
        powershell_profile = _powershell_profile_output(
            commands, powershell_profile_target
        )
        if powershell_profile is not None:
            return powershell_profile
        metadata = _metadata_output(commands)
        if metadata is not None:
            metadata_queries.update(
                command.removeprefix("lstatns ")
                for command in commands
                if command.startswith("lstatns ")
            )
            return metadata
        download = commands[-1].split(" ", 2)
        Path(download[2]).write_bytes(guest_bytes[download[1]])
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    verified = verifier._verify_deployed_system_content(
        assets, SOURCE_COMMIT, tmp_path
    )
    assert verified == len(source_bytes)
    expected_metadata = {
        *verifier.DEPLOYED_FILE_MODES,
        powershell_profile_target,
        "/etc/atlaso/update-trust.d/atlaso-release-test.pem",
    }
    expected_metadata.remove(default_profile_target)
    expected_metadata.add(powershell_profile_target)
    expected_metadata.update(
        parent.as_posix()
        for path in tuple(expected_metadata)
        for parent in PurePosixPath(path).parents
    )
    assert metadata_queries == expected_metadata


def test_rejects_dangling_symlink_in_inactive_powershell_profile_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dangling inactive profile symlink blocks protected publication.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to isolate guest reads.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    current = "/usr/share/powershell/profile.ps1"
    legacy = "/opt/microsoft/powershell/7/profile.ps1"
    observed_commands: list[str] = []

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        """Return one regular profile and one dangling symlink.

        Args:
            _disk: Unused virtual-disk path.
            commands: Guestfish command sequence.
        """

        observed_commands.extend(commands)
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        profile_layout = _powershell_profile_layout_output(
            commands,
            {
                current: (stat.S_IFREG | 0o644, 0, 0),
                legacy: (stat.S_IFLNK | 0o777, 0, 0),
            },
        )
        if profile_layout is not None:
            return profile_layout
        raise AssertionError(f"unexpected guestfish commands: {commands}")

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    with pytest.raises(
        SystemExit,
        match="PowerShell global profile must exist in exactly one supported layout",
    ):
        verifier._verify_deployed_system_content(assets, SOURCE_COMMIT, tmp_path)
    assert f"-lstatns {current}" in observed_commands
    assert f"-lstatns {legacy}" in observed_commands


@pytest.mark.parametrize(
    ("path", "metadata", "message"),
    [
        (
            "/opt-atlaso/bin/atlaso-helper",
            (stat.S_IFREG | 0o755, 1000, 0),
            "not root-owned",
        ),
        (
            "/opt-atlaso/bin/atlaso-helper",
            (stat.S_IFLNK | 0o777, 0, 0),
            "file has unsafe metadata",
        ),
        (
            "/opt-atlaso/bin/atlaso-helper",
            (stat.S_IFREG | 0o775, 0, 0),
            "file has unsafe metadata",
        ),
        (
            "/opt-atlaso/bin",
            (stat.S_IFDIR | 0o775, 0, 0),
            "ancestry is unsafe",
        ),
    ],
)
def test_rejects_unsafe_privileged_guest_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    metadata: tuple[int, int, int],
    message: str,
) -> None:
    """Protected signing rejects mutable files and ancestry.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to emulate guestfish metadata.
        path: Guest path whose metadata is unsafe.
        metadata: Mode, uid, and gid returned for the path.
        message: Expected fail-closed diagnostic.
    """

    disk = tmp_path / "system.vmdk"
    disk.write_bytes(b"vmdk")
    monkeypatch.setattr(
        verifier,
        "_guestfish",
        lambda _disk, commands: _metadata_output(commands, {path: metadata}) or [],
    )
    with pytest.raises(SystemExit, match=message):
        verifier._verify_guest_path_metadata(
            disk,
            "/dev/sda",
            {"/opt-atlaso/bin/atlaso-helper": 0o755},
        )


def test_deployed_system_sources_exist_in_the_checkout() -> None:
    """Every trusted deployed-file mapping names a tracked source file."""

    sources = {
        *verifier.DEPLOYED_TEXT_FILES,
        *verifier.DEPLOYED_BINARY_FILES,
        verifier.POWERSHELL_PROFILE_SOURCE,
    }
    missing = sorted(source for source in sources if not Path(source).is_file())
    assert missing == []
    assert set(verifier.DEPLOYED_FILE_MODES) == {
        *verifier.DEPLOYED_TEXT_FILES.values(),
        *verifier.DEPLOYED_BINARY_FILES.values(),
    }
    provisioned_privileged_files = {
        "image/common/systemd/atlaso.service": "/etc/systemd/system/atlaso.service",
        "image/common/systemd/atlaso-console.service": "/etc/systemd/system/atlaso-console.service",
        "image/common/systemd/atlaso-worker.service": "/etc/systemd/system/atlaso-worker.service",
        "image/common/systemd/atlaso-data-disks.service": "/etc/systemd/system/atlaso-data-disks.service",
        "image/common/systemd/atlaso-guest-agent-select.service": "/etc/systemd/system/atlaso-guest-agent-select.service",
        "image/common/systemd/atlaso-bootstrap-https.service": "/etc/systemd/system/atlaso-bootstrap-https.service",
        "image/vmware-workstation/systemd/atlaso-vmware-ovf-customize.service": "/etc/systemd/system/atlaso-vmware-ovf-customize.service",
        "image/common/sudoers.d/atlaso-helper": "/etc/sudoers.d/atlaso-helper",
        "scripts/appliance/atlaso-helper": "/opt-atlaso/bin/atlaso-helper",
        "scripts/appliance/atlaso-install-boot-branding": "/opt-atlaso/bin/atlaso-install-boot-branding",
        "scripts/appliance/atlaso-mount-data-disks": "/opt-atlaso/bin/atlaso-mount-data-disks",
        "scripts/appliance/atlaso-select-guest-agent": "/opt-atlaso/bin/atlaso-select-guest-agent",
        "scripts/appliance/atlaso-initialize-machine-identity.py": "/opt-atlaso/bin/atlaso-initialize-machine-identity.py",
        "scripts/appliance/atlaso-bootstrap-https": "/opt-atlaso/bin/atlaso-bootstrap-https",
        "scripts/appliance/atlaso-vmware-ovf-customize.py": "/opt-atlaso/bin/atlaso-vmware-ovf-customize.py",
    }
    assert provisioned_privileged_files.items() <= verifier.DEPLOYED_TEXT_FILES.items()


def test_rejects_multiple_or_non_ext_payload_filesystems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filesystem discovery fails closed instead of guessing a mount target.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to emulate filesystem discovery.
    """

    disk = tmp_path / "system.vmdk"
    disk.write_bytes(b"vmdk")
    monkeypatch.setattr(
        verifier,
        "_guestfish",
        lambda _disk, _commands: ["/dev/sda: ext4", "/dev/sdb: ext4"],
    )
    with pytest.raises(SystemExit, match="exactly one ext filesystem"):
        verifier._filesystem(disk)


def test_runtime_package_archive_requires_exact_digest_inventory(tmp_path: Path) -> None:
    """Runtime RPM staging rejects bytes that differ from its bounded inventory.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    package = b"signed-rpm-fixture"
    digest = hashlib.sha256(package).hexdigest()
    archive_path = tmp_path / "runtime-packages.tar"
    with tarfile.open(archive_path, "w") as archive:
        for name, content in {
            "python3-3.14.rpm": package,
            "SHA256SUMS": f"{digest}  python3-3.14.rpm\n".encode(),
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    destination = tmp_path / "packages"
    destination.mkdir()
    packages = verifier._extract_runtime_package_archive(archive_path, destination)
    assert [path.name for path in packages] == ["python3-3.14.rpm"]

    bad_archive = tmp_path / "bad-runtime-packages.tar"
    with tarfile.open(bad_archive, "w") as archive:
        for name, content in {
            "python3-3.14.rpm": b"altered",
            "SHA256SUMS": f"{digest}  python3-3.14.rpm\n".encode(),
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    bad_destination = tmp_path / "bad-packages"
    bad_destination.mkdir()
    with pytest.raises(SystemExit, match="digest does not match"):
        verifier._extract_runtime_package_archive(bad_archive, bad_destination)


def test_runtime_package_requires_current_official_repository_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broadly signed historical RPM is not an admitted runtime package.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to isolate RPM header inspection.
    """

    package = tmp_path / "python3.rpm"
    package.write_bytes(b"current-official-rpm")
    identity = ("python3", "0", "3.14.5", "2.ph5", "x86_64")
    monkeypatch.setattr(
        verifier,
        "_run_runtime_tool",
        lambda _arguments: "ATLASO\t" + "\t".join(identity),
    )
    admitted = {(*identity, hashlib.sha256(package.read_bytes()).hexdigest())}
    verifier._require_admitted_runtime_package(package, "/usr/bin/rpm", admitted)

    with pytest.raises(SystemExit, match="current official metadata"):
        verifier._require_admitted_runtime_package(
            package,
            "/usr/bin/rpm",
            {(*identity, hashlib.sha256(b"historical-rpm").hexdigest())},
        )


def test_runtime_tree_manifest_detects_altered_standard_library(tmp_path: Path) -> None:
    """Standard-library comparison binds every regular file and symbolic link.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    def write_archive(path: Path, content: bytes) -> None:
        """Write one minimal standard-library archive.

        Args:
            path: Destination tar path.
            content: Python module bytes.
        """

        with tarfile.open(path, "w") as archive:
            module = tarfile.TarInfo("python3.14/os.py")
            module.size = len(content)
            archive.addfile(module, io.BytesIO(content))
            link = tarfile.TarInfo("python3.14/platform.py")
            link.type = tarfile.SYMTYPE
            link.linkname = "os.py"
            archive.addfile(link)

    expected = tmp_path / "expected.tar"
    altered = tmp_path / "altered.tar"
    write_archive(expected, b"trusted\n")
    write_archive(altered, b"producer-controlled\n")
    expected_manifest = verifier._runtime_tree_manifest(expected)
    assert expected_manifest["platform.py"] == ("symlink", "os.py")
    assert expected_manifest != verifier._runtime_tree_manifest(altered)
