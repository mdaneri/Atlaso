"""Consent-bound disk inventory for the native Photon partitioning backend."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath

from scripts.installation.layout import MAX_MOUNTS

IDENTITY_FIELDS = ("path", "size", "serial", "wwn", "maj:min")


def require_mount_capacity(partitions: list[dict]) -> None:
    """Bound the persisted layout before mutation, reserving native EFI once.

    Args:
        partitions: Planned or native-expanded partition records.
    """
    targets = [p["mountpoint"] for p in partitions
               if p.get("mountpoint") and p.get("filesystem") not in {"swap", "bios"}]
    if len(targets) + ("/boot/efi" not in targets) > MAX_MOUNTS:
        raise ValueError("31 mounts + EFI")


def require_atlaso_mountpoint(target: str) -> None:
    """Preserve the symlink destinations created by shared Atlaso provisioning.

    Args:
        target: Proposed native mount-point field.
    """
    # A mounted directory makes ln -sfn create a link inside it instead of
    # creating the required compatibility link. Parent directory mounts remain
    # supported, including /opt/atlaso on its own system-content filesystem.
    symlinks = (
        "/opt/atlaso/current", "/opt/atlaso/.venv",
        "/usr/local/bin/atlaso-vault", "/usr/bin/atlaso-vault",
        "/etc/systemd/system-generators/systemd-ssh-generator",
    )
    if any(target == link or target.startswith(link + "/") for link in symlinks):
        raise ValueError("Atlaso symlink")


def require_fstab_safe_mountpoint(target: str) -> None:
    """Refuse mount text that Photon's verbatim fstab writer cannot preserve.

    Args:
        target: Proposed native mount-point field.
    """
    # Photon 2.2 does not escape whitespace or backslashes when writing fstab.
    # A literal backslash-octal sequence can silently identify a different path.
    if not isinstance(target, str) or any(char.isspace() or char == "\\" or ord(char) < 32 or ord(char) == 127 for char in target):
        # This text also occupies Photon's narrow inline validation row.
        raise ValueError("No spaces or \\")


def require_bootloader_mountpoint(target: str) -> None:
    """Keep kernel and GRUB paths on Photon's supported root or boot filesystem.

    Args:
        target: Canonical mount point, including the native generated EFI mount.
    """
    if target.startswith("/boot/") and target != "/boot/efi":
        # EFI's bootstrap selects the root/boot UUID and cannot discover a
        # separate grub2, theme, kernel or nested EFI filesystem.
        raise ValueError("Use /boot")


def eligible_disks(inventory: dict, *, swaps: set[str], held: set[str]) -> dict[str, dict]:
    """Exclude installation media, mounted trees, active swap, and held devices.

    Args:
        inventory: Block-device inventory returned by the system.
        swaps: Device paths currently active as swap.
        held: Device paths held by another block-device consumer."""
    result = {}

    def busy(device: dict) -> bool:
        """Determine whether a device or one of its children is in use.

        Args:
            device: Block-device record or device path to inspect."""
        return (
            device.get("path") in swaps | held
            or bool(device.get("mountpoints") and any(device["mountpoints"]))
            or any(busy(child) for child in device.get("children", []))
        )

    for device in inventory.get("blockdevices", []):
        if device.get("type") != "disk" or device.get("ro") or busy(device):
            continue
        # Photon 2.2's Device.refresh_devices uses lsblk's supported major
        # allowlist (7, 8, 179, 202, 254, 259), which excludes floppy major 2.
        # Reuse that boundary by device identity rather than guessing from names.
        major = device.get("maj:min")
        if isinstance(major, str) and major.partition(":")[0] == "2":
            continue
        if not isinstance(device.get("size"), int) or device["size"] <= 0:
            continue
        path = device.get("path", "")
        if not path.startswith("/dev/") or Path(path).name.startswith(("loop", "ram", "pmem")):
            continue
        result[path] = {field: device.get(field) for field in (*IDENTITY_FIELDS, "model")}
    return result


def disk_inventory() -> dict[str, dict]:
    """Read physical block identities without mounting or modifying any device."""
    raw = subprocess.check_output(
        ["lsblk", "--json", "--bytes", "--paths", "--output", "PATH,TYPE,RO,SIZE,MODEL,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS"],
        text=True,
    )
    swaps = {line.split()[0] for line in Path("/proc/swaps").read_text().splitlines()[1:] if line.split()}
    held = {
        f"/dev/{device.name}" for device in Path("/sys/class/block").iterdir()
        if (device / "holders").is_dir() and any((device / "holders").iterdir())
    }
    result = eligible_disks(json.loads(raw), swaps=swaps, held=held)
    for path in result:
        info = os.stat(path)
        if not stat.S_ISBLK(info.st_mode):
            raise ValueError("an installation target is not a block device")
        result[path]["rdev"] = info.st_rdev
    return result


def selected_disks(config: dict) -> list[str]:
    """Return every disk the native backend will partition, including EFI boot.

    Args:
        config: Installer configuration describing the target layout."""
    default = config.get("disk")
    partitions = config.get("partitions", [])
    selected = {default, *(partition.get("disk", default) for partition in partitions)}
    if not selected or any(not isinstance(path, str) or not path.startswith("/dev/") for path in selected):
        raise ValueError("an exact installation target is required")
    return sorted(selected)


def revalidate_disks(config: dict, consent: dict[str, dict], current: dict[str, dict]) -> None:
    """Require exact consent and unchanged eligible identities before partitioning.

    Args:
        config: Installer configuration describing the target layout.
        consent: Previously confirmed disk identities for this installation.
        current: Current eligible disk identities to compare with consent."""
    selected = selected_disks(config)
    if set(selected) != set(consent):
        raise ValueError("installation disk set differs from the confirmed plan")
    for path in selected:
        if path not in current or current[path] != consent[path]:
            raise ValueError("an installation disk identity or availability changed; review again")
    if config.get("bootmode") != "efi" or config.get("arch") != "x86_64":
        raise ValueError("only x86-64 UEFI installation is supported")
    require_mount_capacity(config.get("partitions", []))
    mountpoints = []
    for partition in config.get("partitions", []):
        target = partition.get("mountpoint")
        if partition.get("filesystem") not in {"ext4", "xfs", "btrfs", "vfat", "swap"} or "lvm" in partition:
            raise ValueError("custom installation requires supported plain filesystems")
        if target:
            require_fstab_safe_mountpoint(target)
            require_bootloader_mountpoint(target)
            require_atlaso_mountpoint(target)
            mountpoints.append(target)
            candidate = PurePosixPath(target)
            if not candidate.is_absolute() or str(candidate) != target or ".." in candidate.parts:
                raise ValueError("custom mountpoint is not canonical")
            if any(target == root or target.startswith(root + "/") for root in ("/proc", "/sys", "/dev", "/run", "/tmp", "/mnt/atlaso-install")):
                raise ValueError("custom mountpoint is reserved")
    if "/" not in mountpoints or len(mountpoints) != len(set(mountpoints)):
        raise ValueError("custom installation requires one root and unique mountpoints")
    root_filesystem = next(partition["filesystem"] for partition in config["partitions"]
                           if partition.get("mountpoint") == "/")
    if root_filesystem not in {"ext4", "xfs", "btrfs"}:
        raise ValueError("installation root filesystem must be ext4, xfs, or btrfs")
    boot_partition = next((partition for partition in config["partitions"]
                           if partition.get("mountpoint") == "/boot"), None)
    boot_filesystem = boot_partition["filesystem"] if boot_partition else root_filesystem
    if boot_filesystem != "ext4":
        raise ValueError("UEFI boot filesystem must be ext4; use a separate ext4 /boot for xfs or btrfs root")
