"""Tests for the recorded ISO installation storage layout."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.installation import layout


def _mount(target: str, uuid: str, filesystem: str = "ext4") -> dict[str, str]:
    """Build one recorded filesystem mount."""
    return {"target": target, "uuid": uuid, "filesystem": filesystem}


def _layout(*mounts: dict[str, str]) -> dict:
    """Build a valid x86-64 installation layout around the supplied mounts."""
    return {"schema": 1, "architecture": "x86_64", "mounts": list(mounts)}


def test_validate_layout_accepts_root_efi_and_custom_mounts() -> None:
    """Accept the default root and EFI mounts plus separate appliance volumes."""
    value = _layout(
        _mount("/", "root-fs-01"),
        _mount("/boot/efi", "efi-fs-01", "vfat"),
        _mount("/mnt/atlaso-vcf-offline-depot", "depot-fs-01", "xfs"),
        _mount("/mnt/atlaso-vcf-backups", "backup-fs-01", "btrfs"),
    )

    assert layout.validate_layout(value) == value


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param([], "fields are invalid", id="schema-object-required"),
        pytest.param(
            {"schema": True, "architecture": "x86_64", "mounts": []},
            "version or architecture",
            id="boolean-is-not-schema-integer",
        ),
        pytest.param(
            {"schema": 1, "architecture": "aarch64", "mounts": []},
            "version or architecture",
            id="unsupported-architecture",
        ),
        pytest.param(
            {"schema": 1, "architecture": "x86_64", "mounts": "bad"},
            "mount inventory",
            id="mount-list-required",
        ),
        pytest.param(
            _layout(_mount("/boot/efi", "efi-fs-01", "vfat")),
            "requires recorded root and EFI",
            id="root-required",
        ),
        pytest.param(
            _layout(_mount("/", "root-fs-01")),
            "requires recorded root and EFI",
            id="efi-required",
        ),
        pytest.param(
            _layout(_mount("relative", "root-fs-01"), _mount("/boot/efi", "efi-fs-01", "vfat")),
            "not unique and canonical",
            id="relative-mount",
        ),
        pytest.param(
            _layout(_mount("/var/../", "root-fs-01"), _mount("/boot/efi", "efi-fs-01", "vfat")),
            "not unique and canonical",
            id="noncanonical-mount",
        ),
        pytest.param(
            _layout(_mount("/", "root-fs-01"), _mount("/", "efi-fs-01", "vfat"), _mount("/boot/efi", "third-fs-01", "vfat")),
            "not unique and canonical",
            id="duplicate-mount-target",
        ),
        pytest.param(
            _layout(_mount("/", "duplicate-fs-01"), _mount("/boot/efi", "duplicate-fs-01", "vfat")),
            "duplicated",
            id="duplicate-filesystem-uuid",
        ),
        pytest.param(
            _layout(_mount("/", "root-fs-01"), _mount("/boot/efi", "efi-fs-01", "vfat"), _mount("/run/atlaso", "run-fs-01")),
            "reserved",
            id="reserved-runtime-mount",
        ),
        pytest.param(
            _layout(_mount("/", "root-fs-01"), _mount("/boot/efi", "efi-fs-01", "vfat"), _mount("/tmp/data", "tmp-fs-01")),
            "reserved",
            id="reserved-tmp-child-mount",
        ),
        pytest.param(
            _layout(_mount("/", "bad"), _mount("/boot/efi", "efi-fs-01", "vfat")),
            "identity is invalid",
            id="malformed-uuid",
        ),
        pytest.param(
            _layout(_mount("/", "root-fs-01", "ntfs"), _mount("/boot/efi", "efi-fs-01", "vfat")),
            "filesystem is unsupported",
            id="unsupported-filesystem",
        ),
        pytest.param(
            _layout(_mount("/", "root-fs-01"), _mount("/boot/efi", "efi-fs-01", "vfat"), *[_mount(f"/extra/{index}", f"uuid-{index}") for index in range(31)]),
            "mount inventory",
            id="too-many-mounts",
        ),
    ],
)
def test_validate_layout_rejects_malformed_or_unsafe_records(value: object, message: str) -> None:
    """Reject unsupported schemas, noncanonical paths, duplicate IDs and reserved mounts."""
    with pytest.raises(ValueError, match=message):
        layout.validate_layout(value)


def test_load_layout_can_skip_host_trust_checks_for_windows_fixtures(tmp_path: Path) -> None:
    """Validate receipt bytes independently of unavailable Windows root ownership."""
    path = tmp_path / "layout.json"
    value = _layout(_mount("/", "root-fs-01"), _mount("/boot/efi", "efi-fs-01", "vfat"))
    path.write_text(json.dumps(value), encoding="utf-8")

    assert layout.load_layout(path, trusted=False) == value


@pytest.mark.parametrize("trusted_uid", [0, 1234], ids=["root-owned", "nonroot-owner"])
def test_ordinary_bytes_checks_controlled_root_trust_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trusted_uid: int
) -> None:
    """Exercise root-owner and writable-mode gates with controlled stat metadata."""
    path = tmp_path / "layout.json"
    path.write_text("{}", encoding="utf-8")
    original_stat = Path.stat
    original_fstat = os.fstat

    def controlled_stat(target: Path, *args, **kwargs):
        info = original_stat(target, *args, **kwargs)
        if target == path:
            return info
        return SimpleNamespace(st_uid=trusted_uid, st_mode=stat.S_IFDIR | 0o755)

    def controlled_fstat(descriptor: int):
        info = original_fstat(descriptor)
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_nlink=info.st_nlink,
            st_size=info.st_size,
            st_uid=0,
            st_mode=stat.S_IFREG | 0o644,
        )

    monkeypatch.setattr(layout.Path, "stat", controlled_stat)
    monkeypatch.setattr(layout.os, "fstat", controlled_fstat)

    if trusted_uid == 0:
        assert layout.ordinary_bytes(path) == b"{}"
    else:
        with pytest.raises(ValueError, match="ancestry is not root controlled"):
            layout.ordinary_bytes(path)


@pytest.mark.parametrize("observed", [
    [{"uuid": "root-fs-01", "fstype": "ext4"}],
    [{"uuid": "wrong-root", "fstype": "ext4"}],
    [{"uuid": "root-fs-01", "fstype": "xfs"}],
    [],
])
def test_verify_layout_accepts_only_exact_findmnt_identity(
    monkeypatch: pytest.MonkeyPatch, observed: list[dict[str, str]]
) -> None:
    """Compare mounted UUID and filesystem evidence without invoking mutations."""
    value = _layout(_mount("/", "root-fs-01"), _mount("/boot/efi", "efi-fs-01", "vfat"))
    commands: list[list[str]] = []

    class PosixPathShim:
        """Keep POSIX mountpoint canonicalization platform independent."""

        def __init__(self, value: str):
            self.value = value

        def resolve(self, *, strict: bool = False) -> "PosixPathShim":
            return self

        def __eq__(self, other: object) -> bool:
            return isinstance(other, PosixPathShim) and self.value == other.value

    def check_output(command: list[str], *, text: bool) -> str:
        assert text is True
        commands.append(command)
        result = observed if command[3] == "/" else [{"uuid": "efi-fs-01", "fstype": "vfat"}]
        return json.dumps({"filesystems": result})

    monkeypatch.setattr(layout, "load_layout", lambda _path: value)
    monkeypatch.setattr(layout, "Path", PosixPathShim)
    monkeypatch.setattr(layout.subprocess, "check_output", check_output)
    monkeypatch.setattr(layout.subprocess, "run", lambda *args, **kwargs: pytest.fail("verify must not mutate storage"))

    if observed == [{"uuid": "root-fs-01", "fstype": "ext4"}]:
        assert layout.verify_layout() == value
        assert len(commands) == 2
        assert all(command[0] == "findmnt" for command in commands)
    else:
        with pytest.raises(ValueError, match="identity differs from its receipt"):
            layout.verify_layout()
        assert len(commands) == 1
        assert commands[0][0] == "findmnt"


def test_record_layout_uses_blkid_and_writes_root_efi_and_custom_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Record native installer mount identities and omit non-filesystem partitions."""
    destination = tmp_path / "installation-layout.json"
    commands: list[list[str]] = []
    identities = {"/dev/nvme0n1p2": "root-fs-01", "/dev/nvme0n1p1": "efi-fs-01", "/dev/sdb1": "depot-fs-01"}

    def check_output(command: list[str], *, text: bool) -> str:
        assert text is True
        commands.append(command)
        return identities[command[-1]] + "\n"

    monkeypatch.setattr(layout.subprocess, "check_output", check_output)
    partitions = [
        {"mountpoint": "/", "filesystem": "ext4", "path": "/dev/nvme0n1p2"},
        {"mountpoint": "/boot/efi", "filesystem": "vfat", "path": "/dev/nvme0n1p1"},
        {"mountpoint": "/mnt/atlaso-vcf-offline-depot", "filesystem": "xfs", "path": "/dev/sdb1"},
        {"mountpoint": None, "filesystem": "swap", "path": "/dev/sda3"},
        {"mountpoint": None, "filesystem": "bios", "path": "/dev/sda4"},
    ]

    receipt = layout.record_layout(partitions, destination)

    assert receipt["schema"] == 1
    assert receipt["architecture"] == "x86_64"
    assert receipt["mounts"] == [
        _mount("/", "root-fs-01"),
        _mount("/boot/efi", "efi-fs-01", "vfat"),
        _mount("/mnt/atlaso-vcf-offline-depot", "depot-fs-01", "xfs"),
    ]
    assert [command[0] for command in commands] == ["blkid", "blkid", "blkid"]
    assert json.loads(destination.read_text(encoding="utf-8")) == receipt
