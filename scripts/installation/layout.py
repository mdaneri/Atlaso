"""Read the installed ISO storage profile without discovering or adopting disks.

This module also runs with the Python 3.11 interpreter on the pinned Photon ISO.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath

LAYOUT_PATH = Path("/etc/atlaso/installation-layout.json")
PROFILE_PATH = Path("/etc/atlaso/installation-profile")
PROFILE = "atlaso-installation-v1\n"
MAX_MOUNTS = 32
DATA_PATHS = ("/mnt/atlaso-vcf-offline-depot", "/mnt/atlaso-vcf-backups")
UUID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{3,127}\Z")


def ordinary_bytes(path: Path, *, trusted: bool = True) -> bytes:
    """Read a bounded single-link file and reject writable or linked trust paths.

    Args:
        path: Filesystem path to the input or target.
        trusted: Whether the profile is being read from a trusted source."""
    if path.resolve(strict=True) != path.absolute():
        raise ValueError("installation metadata cannot use symbolic links")
    if trusted:
        for ancestor in (path.parent, *path.parents):
            info = ancestor.stat()
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError("installation metadata ancestry is not root controlled")
    with path.open("rb") as handle:
        info = os.fstat(handle.fileno())
        current = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
            raise ValueError("installation metadata is not a bounded ordinary file")
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("installation metadata changed while opening")
        if trusted and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
            raise ValueError("installation metadata is not root controlled")
        return handle.read(65537)


def installation_profile(*, profile_path: Path = PROFILE_PATH) -> bool:
    """Identify an ISO installation; malformed or dangling markers fail closed.

    Args:
        profile_path: Path to the trusted installed-storage profile."""
    if not os.path.lexists(profile_path):
        return False
    if ordinary_bytes(profile_path) != PROFILE.encode():
        raise ValueError("installation profile is invalid")
    return True


def validate_layout(value: object) -> dict:
    """Validate the complete schema before any native filesystem observation.

    Args:
        value: Value to validate or serialize."""
    if not isinstance(value, dict) or set(value) != {"schema", "architecture", "mounts"}:
        raise ValueError("installation layout fields are invalid")
    if type(value["schema"]) is not int or value["schema"] != 1 or value["architecture"] != "x86_64":
        raise ValueError("installation layout version or architecture is unsupported")
    mounts = value["mounts"]
    if not isinstance(mounts, list) or not 1 <= len(mounts) <= MAX_MOUNTS:
        raise ValueError("installation layout mount inventory is invalid")
    seen = set()
    uuids = set()
    for mount in mounts:
        if not isinstance(mount, dict) or set(mount) != {"target", "uuid", "filesystem"}:
            raise ValueError("installation layout mount fields are invalid")
        target, uuid, filesystem = (mount[key] for key in ("target", "uuid", "filesystem"))
        if not all(isinstance(item, str) for item in (target, uuid, filesystem)):
            raise ValueError("installation mount fields must be strings")
        path = PurePosixPath(target)
        if not path.is_absolute() or str(path) != target or ".." in path.parts or target in seen:
            raise ValueError("installation mount target is not unique and canonical")
        if any(target == root or target.startswith(root + "/") for root in ("/proc", "/sys", "/dev", "/run", "/tmp")):
            raise ValueError("installation mount target is reserved")
        if not UUID_PATTERN.fullmatch(uuid) or uuid in uuids:
            raise ValueError("installation filesystem identity is invalid or duplicated")
        if filesystem not in {"ext4", "xfs", "btrfs", "vfat"}:
            raise ValueError("installation filesystem is unsupported")
        seen.add(target)
        uuids.add(uuid)
    if "/" not in seen or "/boot/efi" not in seen:
        raise ValueError("installation requires recorded root and EFI filesystems")
    return value


def load_layout(path: Path = LAYOUT_PATH, *, trusted: bool = True) -> dict:
    """Load a root-controlled storage record; never infer a replacement layout.

    Args:
        path: Filesystem path to the input or target.
        trusted: Whether the profile is being read from a trusted source."""
    return validate_layout(json.loads(ordinary_bytes(path, trusted=trusted)))


def verify_layout(path: Path = LAYOUT_PATH) -> dict:
    """Verify UUID-backed existing mounts only, with no mount or format commands.

    Args:
        path: Filesystem path to the input or target."""
    layout = load_layout(path)
    for mount in layout["mounts"]:
        target = mount["target"]
        if Path(target).resolve(strict=True) != Path(target):
            raise ValueError("installation mount ancestry changed")
        observed = subprocess.check_output(
            ["findmnt", "--json", "--mountpoint", target, "--output", "UUID,FSTYPE"],
            text=True,
        )
        filesystems = json.loads(observed).get("filesystems")
        if filesystems != [{"uuid": mount["uuid"], "fstype": mount["filesystem"]}]:
            raise ValueError("installation filesystem identity differs from its receipt")
    return layout


def record_layout(partitions: list[dict], destination: Path) -> dict:
    """Receipt Photon-created filesystems while the native installer holds them.

    Args:
        partitions: Installed partition records to persist in the layout.
        destination: Existing directory that receives the generated files."""
    mounts = []
    for partition in partitions:
        target = partition.get("mountpoint")
        if not target or partition.get("filesystem") in {"swap", "bios"}:
            continue
        uuid = subprocess.check_output(["blkid", "-s", "UUID", "-o", "value", partition["path"]], text=True).strip()
        mounts.append({"target": target, "uuid": uuid, "filesystem": partition["filesystem"]})
    layout = validate_layout({"schema": 1, "architecture": "x86_64", "mounts": mounts})
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(layout, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(destination, 0o644)
    return layout


def main() -> int:
    """Verify installed mounts before guest-agent selection or service startup."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "profile"))
    args = parser.parse_args()
    if not installation_profile():
        raise ValueError("ISO installation profile is missing")
    if args.operation == "verify":
        verify_layout()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
