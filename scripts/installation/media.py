"""Discover ISO media read-only and bind it to its physical backing device."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

LABEL = "ATLASO_INSTALLER"


def media_candidates(inventory: dict) -> list[dict]:
    """Find ISO filesystems, deduplicating aliases of the same block device.

    Args:
        inventory: Read-only lsblk JSON including partition children.
    """
    found = {}

    def visit(devices):
        """Inspect every child without relying on enumeration or label symlinks.

        Args:
            devices: Block-device records at one tree level.
        """
        for device in devices:
            if device.get("label") == LABEL and device.get("fstype") == "iso9660":
                number = device.get("maj:min", "")
                if not re.fullmatch(r"[0-9]+:[0-9]+", number):
                    raise ValueError("installation media has no block identity")
                found[number] = device
            visit(device.get("children", []))

    visit(inventory.get("blockdevices", []))
    return list(found.values())


def block_location(number: str) -> tuple[Path, str, str, str]:
    """Resolve an ISO block device to its physical disk and byte-origin identity.

    Args:
        number: Kernel major:minor identity, never a guessed disk name.
    """
    if not re.fullmatch(r"[0-9]+:[0-9]+", number):
        raise ValueError("installation media has no block identity")
    device = (Path("/sys/dev/block") / number).resolve(strict=True)
    partition = (device / "partition").exists()
    disk = device.parent if partition else device
    if "/virtual/" in str(disk) or any((disk / "slaves").iterdir()):
        raise ValueError("installation source requires one plain physical backing device")
    backing = (disk / "dev").read_text().strip()
    diskseq = (disk / "diskseq").read_text().strip()
    start = (device / "start").read_text().strip() if partition else "0"
    if (not diskseq.isdecimal() or not start.isdecimal()
            or not re.fullmatch(r"[0-9]+:[0-9]+", backing)):
        raise ValueError("installation source physical identity is unavailable")
    return disk, backing, diskseq, start


def select_media(inventory: dict) -> dict:
    """Reject different media while admitting a hybrid's zero-offset aliases.

    Args:
        inventory: Complete lsblk JSON from read-only discovery.
    """
    locations = {}
    for device in media_candidates(inventory):
        disk, _backing, diskseq, start = block_location(device["maj:min"])
        locations.setdefault((str(disk), diskseq, start), device)
    if len(locations) != 1:
        raise ValueError("exactly one Atlaso installation medium is required; remove duplicate media")
    return next(iter(locations.values()))


@dataclass(frozen=True)
class SourceMedia:
    """Session identity independent of /dev/sdX, partition labels and order."""

    payload: Path
    mount: tuple[str, ...]
    backing: str
    topology: str
    diskseq: str

    @classmethod
    def capture(cls, payload: Path) -> SourceMedia:
        """Prove a read-only ISO mount and its single plain physical backing disk.

        Args:
            payload: Canonical mounted payload directory.
        """
        payload = Path(payload)
        if payload != payload.resolve(strict=True) or payload.name != "atlaso":
            raise ValueError("installation payload must use its canonical media mount")
        root = payload.parent
        mounts = []
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split()
            separator = fields.index("-")
            if fields[4] == str(root):
                if (fields[3] != "/" or "ro" not in fields[5].split(",")
                        or fields[separator + 1] != "iso9660"
                        or "ro" not in fields[separator + 3].split(",")):
                    raise ValueError("installation source must remain a read-only ISO filesystem")
                mounts.append(tuple(fields))
        if len(mounts) != 1:
            raise ValueError("installation source mount is missing or ambiguous")
        mount = mounts[0]
        number = mount[2]
        info = payload.stat()
        if f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}" != number:
            raise ValueError("installation payload differs from the source mount")
        disk, backing, diskseq, _start = block_location(number)
        # diskseq changes on detach/re-attach even when the kernel reuses a dev_t.
        return cls(payload, mount, backing, str(disk), diskseq)

    def validate(self) -> None:
        """Refuse disappearance, replacement, remount or changed source topology."""
        if self.capture(self.payload) != self:
            raise ValueError("installation source identity changed; reboot and review media")


def mount_media(target: Path) -> None:
    """Mount exactly one discovered ISO using read-only, non-executable flags.

    Args:
        target: Existing empty canonical mount directory prepared by initrd.
    """
    if target != target.resolve(strict=True) or any(target.iterdir()) or target.is_mount():
        raise ValueError("installation media mount point must be empty and unmounted")
    inventory = json.loads(subprocess.check_output([
        "lsblk", "--json", "--paths", "--output", "PATH,FSTYPE,LABEL,MAJ:MIN",
    ], text=True))
    device = select_media(inventory)
    path = device.get("path", "")
    if not path.startswith("/dev/"):
        raise ValueError("installation media is not a device")
    info = os.stat(path)
    if (not stat.S_ISBLK(info.st_mode)
            or f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" != device["maj:min"]):
        raise ValueError("installation media device identity changed")
    subprocess.run(["mount", "-t", "iso9660", "-o", "ro,nosuid,nodev,noexec", "--", path, str(target)], check=True)
    source = SourceMedia.capture(target / "atlaso")
    transport = "USB" if re.search(r"/usb[0-9]+/", source.topology) else "non-USB"
    print(f"Atlaso source transport: {transport}", flush=True)


def main() -> None:
    """Enter only the initrd-owned read-only discovery operation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    mount_media(parser.parse_args().target)


if __name__ == "__main__":
    main()
