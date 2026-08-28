"""Tests for protected verification of the wheel installed in a guest disk."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import verify_virtualization_guest_wheel as verifier


def _wheel(path: Path) -> tuple[Path, dict[str, bytes]]:
    """Create a small valid Atlaso wheel and return its installed members."""

    members = {
        "atlaso/__init__.py": b'__version__ = "0.9.242"\n',
        "atlaso-0.9.242.dist-info/METADATA": b"Metadata-Version: 2.4\nName: Atlaso\nVersion: 0.9.242\n",
        "atlaso-0.9.242.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
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
    """Create one signed-wheelhouse dependency fixture."""

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
    """Write a guestfish-shaped site-packages tar archive."""

    with tarfile.open(path, "w") as archive:
        for name, content in {**members, **(extra or {})}.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def _assets(path: Path) -> None:
    """Create the minimum system-content provenance fixture."""

    path.mkdir()
    (path / "atlaso-system.vmdk").write_bytes(b"vmdk")
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Installed Atlaso files must match the exact signed-release wheel."""

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
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        destination = tar_command.rsplit(" ", 1)[1]
        _site_archive(Path(destination), installed)
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    result = verifier.verify_installed_environment(assets, wheel, wheelhouse, digest)
    assert result["wheel_sha256"] == digest
    assert result["distributions_verified"] == 2
    assert result["files_verified"] == len(installed)


def test_rejects_altered_installed_wheel_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A producer cannot substitute guest package bytes and retain signing."""

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
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        destination = tar_command.rsplit(" ", 1)[1]
        altered = {**installed, "authlib/__init__.py": b"substituted"}
        _site_archive(Path(destination), altered)
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="installed wheel member does not match"):
        verifier.verify_installed_environment(assets, wheel, wheelhouse, digest)


def test_rejects_unexpected_active_pth_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The protected inventory rejects producer-injected active environment files."""

    assets = tmp_path / "assets"
    _assets(assets)
    wheel, members = _wheel(tmp_path / "atlaso-0.9.242-py3-none-any.whl")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _, dependencies = _dependency_wheel(
        wheelhouse / "authlib-1.6.4-py2.py3-none-any.whl"
    )

    def fake_guestfish(_disk: Path, commands: list[str]) -> list[str]:
        if commands == ["list-filesystems"]:
            return ["/dev/sda: ext4"]
        if commands[-1].startswith("realpath "):
            return [
                "/opt-atlaso/releases/bootstrap-0.9.242/.venv/lib/python3.14/site-packages"
            ]
        tar_command = next(
            command for command in commands if command.startswith("tar-out ")
        )
        destination = tar_command.rsplit(" ", 1)[1]
        _site_archive(
            Path(destination),
            {**members, **dependencies},
            {"producer-injected.pth": b"import os\n"},
        )
        return []

    monkeypatch.setattr(verifier, "_guestfish", fake_guestfish)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="unexpected file: producer-injected.pth"):
        verifier.verify_installed_environment(assets, wheel, wheelhouse, digest)


def test_rejects_multiple_or_non_ext_payload_filesystems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filesystem discovery fails closed instead of guessing a mount target."""

    disk = tmp_path / "system.vmdk"
    disk.write_bytes(b"vmdk")
    monkeypatch.setattr(
        verifier,
        "_guestfish",
        lambda _disk, _commands: ["/dev/sda: ext4", "/dev/sdb: ext4"],
    )
    with pytest.raises(SystemExit, match="exactly one ext filesystem"):
        verifier._filesystem(disk)
