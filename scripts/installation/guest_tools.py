"""Validate and retain authenticated ISO guest-tools closures without installing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path

PROFILES = {"vmware": "open-vm-tools", "hyperv": "hyper-v", "qemu": "atlaso-qemu-guest-agent"}
COMPATIBILITY = {"schema": 1, "distribution": "photon", "release": "5.0", "architecture": "x86_64"}


def payload_inventory(root: Path) -> dict[str, str]:
    """Verify exact, bounded closure bytes independently of media file permissions.

    Args:
        root: Ordinary payload directory authenticated by the enclosing media inventory.
    """
    for path in (root, *root.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("guest-tools payload ancestry contains a link or non-directory")
    if {path.name for path in root.iterdir()} != set(PROFILES) | {"compatibility.json", "SHA256SUMS"}:
        raise ValueError("guest-tools payload entries differ from the supported profiles")
    files = {}
    for profile in PROFILES:
        directory = root / profile
        info = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("guest-tools profile is not an ordinary directory")
        packages = list(directory.iterdir())
        if not packages:
            raise ValueError("guest-tools profile closure is empty")
        for package in packages:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*\.rpm", package.name):
                raise ValueError("guest-tools RPM filename is invalid")
            files[package.relative_to(root).as_posix()] = package
    all_files = {**files, "compatibility.json": root / "compatibility.json", "SHA256SUMS": root / "SHA256SUMS"}
    total = 0
    for name, path in all_files.items():
        info = path.lstat()
        limit = 4096 if name == "compatibility.json" else 65536 if name == "SHA256SUMS" else 512 * 1024**2
        if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1
                or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > limit):
            raise ValueError("guest-tools payload has an unsafe or oversized file")
        total += info.st_size
    if len(files) > 256 or total > 2 * 1024**3:
        raise ValueError("guest-tools payload exceeds its capacity bound")
    if json.loads((root / "compatibility.json").read_text(encoding="utf-8")) != COMPATIBILITY:
        raise ValueError("guest-tools payload compatibility differs")
    expected = {}
    for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ((?:vmware|hyperv|qemu)/[A-Za-z0-9][A-Za-z0-9+._-]*\.rpm)", line)
        if not match or match[2] in expected:
            raise ValueError("guest-tools checksum inventory is invalid")
        expected[match[2]] = match[1]
    actual = {}
    for name, path in files.items():
        with path.open("rb") as stream:
            actual[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise ValueError("guest-tools payload differs from its exact checksum inventory")
    return actual


def source_requires_payload(source: Path) -> bool:
    """Retain compatibility with older immutable sources that predate ISO payload support.

    Args:
        source: Exact-commit staged deployment source.
    """
    return (source / "scripts/installation/guest_tools.py").is_file()


def copy_payload(source: Path, destination: Path) -> None:
    """Copy verified media bytes once, preserving an existing matching protected tree.

    Args:
        source: Authenticated, read-only media payload directory.
        destination: Absent payload destination or the matching first staging pass.
    """
    expected = payload_inventory(source)
    if destination.exists() or destination.is_symlink():
        if payload_inventory(destination) != expected:
            raise ValueError("existing guest-tools payload differs; preserved")
        return
    shutil.copytree(source, destination)
    for path in (destination, *destination.rglob("*")):
        path.chmod(0o700 if path.is_dir() else 0o600)
    if payload_inventory(destination) != expected:
        raise ValueError("copied guest-tools payload differs; preserved")


def main() -> None:
    """Verify media during preflight or stage it as root without executing RPMs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "stage"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    payload_inventory(args.source)
    if args.operation == "stage":
        if os.geteuid() != 0 or args.destination is None:
            raise ValueError("guest-tools staging requires root and an explicit protected destination")
        parent = args.destination.parent
        info = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("guest-tools staging parent must be root-owned and private")
        if args.destination.exists():
            for path in (args.destination, *args.destination.rglob("*")):
                info = path.lstat()
                if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != (0o700 if path.is_dir() else 0o600):
                    raise ValueError("existing guest-tools payload ownership or permissions differ; preserved")
        already_staged = args.destination.exists()
        copy_payload(args.source, args.destination)
        if not already_staged:
            for path in (args.destination, *args.destination.rglob("*")):
                os.chown(path, 0, 0, follow_symlinks=False)


if __name__ == "__main__":
    main()
