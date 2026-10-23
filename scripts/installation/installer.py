#!/usr/bin/env python3
"""Adapt Photon's pinned native installer to the signed offline Atlaso payload."""

from __future__ import annotations

import argparse
import curses
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE))

from atlaso.local_user_password_policy import (  # noqa: E402 - boot media supplies the standard-library-only policy.
    DEFAULT_PASSWORD_POLICY,
    validate_password,
)
from scripts.installation.disks import (  # noqa: E402 - boot media is added before local imports.
    disk_inventory,
    revalidate_disks,
    selected_disks,
)
from scripts.installation.layout import (  # noqa: E402 - boot media path bootstrap.
    PROFILE,
    record_layout,
)
from scripts.installation.manifest import (  # noqa: E402 - boot media path bootstrap.
    PHOTON_INSTALLER_SHA256,
    digest,
    verify_media,
)

NATIVE_PATH = Path("/usr/lib/python3.11/site-packages/photon_installer")
TRUST_KEY = Path("/etc/atlaso-installer/trust.pem")
MINIMUM_DISK_BYTES = 64 * 1024**3


class Cancelled(Exception):
    """Represent cancellation before admitting destructive installation."""


def environment_value(value: str) -> str:
    """Quote for the existing systemd environment file and shell consumers."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return '"' + escaped + '"'


def prompt(maxy: int, maxx: int, title: str, message: str, *, secret: bool = False, validator=None) -> str:
    """Reuse the Photon console field and masked input rather than a new UI kit."""
    from windowstringreader import WindowStringReader

    state = {}
    width = min(maxx - 4, 78)
    lines = [part for line in message.splitlines() for part in (textwrap.wrap(line, width - 4) or [""])]
    if len(lines) > maxy - 10:
        raise ValueError("installer review exceeds the console page size")
    reader = WindowStringReader(
        maxy, maxx, max(12, len(lines) + 8), width, "value", None,
        "*" if secret else None, list(range(32, 127)), validator, None, title,
        "\n".join(lines), len(lines) + 1, state,
    )
    if not reader.get_user_string().success:
        raise Cancelled()
    return state["value"]


def configure_console(screen, initial: dict[str, dict]) -> tuple[dict, dict, tuple[str, str]]:
    """Collect the native layout, exact erasure consent, and concealed credentials."""
    from custompartition import CustomPartition
    from device import Device
    from partitionpane import PartitionPane
    from selectdisk import SelectDisk

    maxy, maxx = screen.getmaxyx()
    if maxy < 25 or maxx < 80:
        raise ValueError("installer requires an 80 by 25 console")
    for index, foreground, background in ((1, curses.COLOR_WHITE, curses.COLOR_BLUE), (2, curses.COLOR_BLACK, curses.COLOR_WHITE), (3, curses.COLOR_BLACK, curses.COLOR_GREEN), (4, curses.COLOR_RED, curses.COLOR_WHITE)):
        curses.init_pair(index, foreground, background)
    screen.bkgd(" ", curses.color_pair(1))
    curses.curs_set(0)

    class MultiDiskPane(PartitionPane):
        """Keep native table rendering but show each partition's selected disk."""

        def partition(self):
            super().partition()
            width = self.text_items[0][1]
            for index in range(self.config.get("partitionsnumber", 0)):
                path = self.config.get(f"{index}partition_disk", self.config.get("partition_disk", ""))
                self.lines[index + 1] = path[-width:].ljust(width) + self.lines[index + 1][width:]

    # Photon owns the full rendering, scrolling, keyboard and navigation contract.
    import custompartition

    custompartition.PartitionPane = MultiDiskPane

    # Device discovery is read-only and shared by Auto and Custom. A disk hosting
    # the mounted ISO, any active filesystem, or swap never enters these screens.
    def devices(*, byte_sizes: bool):
        current = disk_inventory()
        return [
            Device(item.get("model") or "Unknown", path, str(item["size"]) if byte_sizes else f"{item['size'] // 1024**3} GiB")
            for path, item in current.items() if path in initial and current[path] == initial[path]
        ]

    Device.refresh_devices = staticmethod(lambda: devices(byte_sizes=False))
    Device.refresh_devices_bytes = staticmethod(lambda: devices(byte_sizes=True))

    class MultiDiskPartitions(CustomPartition):
        """Extend only disk selection; Photon still validates and builds partitions."""

        def __init__(self, *args):
            super().__init__(*args)
            self.partition_disks = {}

        def initialize_devices(self):
            if not self.disk_to_index:
                super().initialize_devices()

        def create_function(self):
            selection = {}
            if not SelectDisk(maxy, maxx, selection).display().success:
                return self.display()
            self.device_index = self.disk_to_index[selection["disk"]]
            return super().create_function()

        def validate_partition(self, values):
            if values and values[2] == "/boot/efi":
                return False, "Photon creates the EFI boot partition on the selected boot disk."
            if values and values[1] not in {"ext4", "xfs", "btrfs", "swap"}:
                return False, "Use ext4, xfs, btrfs, or swap."
            selected = self.devices[self.device_index].path
            self.has_empty = any(
                path == selected and self.cp_config.get(f"{index}partition_info0") == ""
                for index, path in self.partition_disks.items()
            )
            result = super().validate_partition(values)
            if isinstance(result, tuple) and result[0]:
                index = self.cp_config["partitionsnumber"]
                self.partition_disks[index] = selected
                self.cp_config[f"{index}partition_disk"] = selected
            return result

        def next(self):
            result = super().next()
            if result.success and "partitions" in self.install_config:
                for index, partition in enumerate(self.install_config["partitions"]):
                    partition["disk"] = self.partition_disks[index]
            return result

        def delete(self):
            self.partition_disks.clear()
            return super().delete()

    config = {"arch": "x86_64", "bootmode": "efi"}
    if not SelectDisk(maxy, maxx, config).display().success:
        raise Cancelled()
    if not config.get("autopartition"):
        if not MultiDiskPartitions(maxy, maxx, config).display().success:
            raise Cancelled()
    else:
        config["partitions"] = [{"mountpoint": "/", "size": 0, "filesystem": "ext4"}]
    paths = selected_disks(config)
    consent = {path: initial[path] for path in paths}
    revalidate_disks(config, consent, disk_inventory())
    if config.get("autopartition") and consent[config["disk"]]["size"] < MINIMUM_DISK_BYTES:
        raise ValueError("default installation requires a disk of at least 64 GiB")
    for path in paths:
        item = consent[path]
        layout = [
            f"{p.get('mountpoint') or 'swap'} {p['filesystem']} {p['size'] or 'remaining'} MiB"
            for p in config["partitions"] if p.get("disk", config["disk"]) == path
        ]
        if path == config["disk"]:
            # ESPSIZE is 10 MiB in the hash-pinned native Photon 2.2 backend.
            layout.insert(0, "/boot/efi vfat 10 MiB (Photon UEFI default)")
        for offset in range(0, len(layout), 5):
            summary = "\n".join(layout[offset:offset + 5])
            if prompt(maxy, maxx, "Review planned partitions", f"Disk {path}\n{summary}\nEFI boot files are placed on the selected boot disk.\nType NEXT to review erasure consent:") != "NEXT":
                raise Cancelled()
        message = f"{path}: {item.get('model')} {item['size'] // 1024**3} GiB\nSerial: {item.get('serial') or item.get('wwn') or 'unavailable'}\nALL EXISTING DATA ON THIS DISK WILL BE LOST.\nType ERASE {path} to confirm:"
        expected = f"ERASE {path}"
        typed = prompt(maxy, maxx, "Review Atlaso installation disk", message)
        if typed != expected:
            raise Cancelled()
    passwords = []
    for username in ("admin", "root"):
        def validator(value, account=username):
            errors = validate_password(value, account, DEFAULT_PASSWORD_POLICY)
            return not errors, " ".join(errors)

        first = prompt(maxy, maxx, f"Set {username} password", "Enter the local account password.", secret=True, validator=validator)
        second = prompt(maxy, maxx, f"Confirm {username} password", "Enter the same password again.", secret=True)
        if first != second:
            raise Cancelled()
        passwords.append(first)
    revalidate_disks(config, consent, disk_inventory())
    # Secret material never enters Photon configuration, dynamic substitutions,
    # native modules, command arguments, or its persistent installation log.
    return config, consent, (passwords[0], passwords[1])


def install(media: Path, identity: dict, config: dict, consent: dict, credentials: tuple[str, str]) -> None:
    """Delegate partitions, base OS, bootloader and fstab to the pinned backend."""
    from installer import Installer

    class AtlasoInstaller(Installer):
        """Add consent verification and the existing shared provisioner only."""

        def exit_gracefully(self, *args):
            # Photon 2.2's error helper can return to the installation sequence.
            # An Atlaso install must never turn a partial native failure green.
            raise RuntimeError("Photon installation failed; selected disks may require recovery")

        def _run_tdnf_in_docker(self, *args):
            raise RuntimeError("offline installation cannot fall back to a Docker repository")

        def _enable_network_in_chroot(self):
            return

        def _clear_vgs(self):
            # Native 2.2 clears every host volume group before each target disk.
            # These layouts use plain filesystems and admit no held devices.
            # There is no authority to alter volume groups on other disks.
            return

        def _get_disk_sizes(self):
            super()._get_disk_sizes()
            # Photon inserts EFI after gathering sizes from custom partitions.
            # The selected boot disk may contain only that generated partition.
            boot = self.install_config["disk"]
            self.disk_sizes.setdefault(boot, consent[boot]["size"])

        def _setup_install_repo(self):
            keys = sorted((media / "source/image/common/photon-rpm-gpg").glob("VMWARE-RPM-GPG-KEY*"))
            if not keys:
                raise ValueError("offline installation is missing admitted Photon RPM keys")
            for repository in self.install_config["repos"].values():
                repository["gpgcheck"] = 1
                repository["gpgkey"] = " ".join(key.as_uri() for key in keys)
            super()._setup_install_repo()
            configuration = Path(self.tdnf_conf_path)
            configuration.write_text(configuration.read_text().replace("gpgcheck=0", "gpgcheck=1"))

        def _partition_disks(self):
            revalidate_disks(self.install_config, consent, disk_inventory())
            super()._partition_disks()

        def _finalize_system(self):
            super()._finalize_system()
            target = Path(self.photon_root)
            target_media = target / str(media).lstrip("/")
            target_media.mkdir(parents=True, exist_ok=True)
            subprocess.run(["mount", "--bind", str(media), str(target_media)], check=True)
            try:
                subprocess.run(["mount", "-o", "remount,bind,ro", str(target_media)], check=True)
                for name, destination in (("source", "tmp/atlaso-src"), ("software", "tmp/atlaso-software")):
                    shutil.copytree(media / name, target / destination)
                dropin = target / "etc/systemd/system/atlaso-guest-agent-select.service.d"
                dropin.mkdir(parents=True, exist_ok=True)
                (dropin / "installation.conf").write_text("[Service]\nEnvironment=ATLASO_STORAGE_PROFILE=installation\n")
                generators = target / "etc/systemd/system-generators"
                generators.mkdir(parents=True, exist_ok=True)
                (generators / "systemd-gpt-auto-generator").symlink_to("/dev/null")
                environment = {
                    **os.environ, "ATLASO_INSTALLATION_MEDIA": str(media), "ATLASO_GUEST_PLATFORM": "none",
                    "ATLASO_SYSTEM_CONTENT_DISK": "false", "ATLASO_BOOTSTRAP_ADMIN_USERNAME": "admin",
                    "ATLASO_BOOTSTRAP_ADMIN_PASSWORD": f"A!a1{secrets.token_urlsafe(32)}",
                    "ATLASO_SOFTWARE_MANIFEST_SHA256": digest(media / "software/release-manifest.json"),
                    "ATLASO_SOFTWARE_SOURCE_COMMIT": identity["source_commit"],
                    "ATLASO_BUILD_SOURCE_COMMIT": identity["source_commit"],
                    "ATLASO_MGMT_ADDRESS": "dhcp", "ATLASO_MGMT_IPV4_METHOD": "dhcp",
                    "ATLASO_DRY_RUN_SYSTEM_ADAPTERS": "true",
                }
                subprocess.run(
                    ["chroot", str(target), "/bin/sh", "/tmp/atlaso-src/image/common/scripts/provision-atlaso.sh"],
                    env=environment, check=True,
                )
                record_layout(self.install_config["partitions"], target / "etc/atlaso/installation-layout.json")
                policy = target / "etc/atlaso/data-disks.conf"
                with policy.open("a") as handle:
                    handle.write("\nATLASO_STORAGE_PROFILE=installation\n")
                self.atlaso_provisioned = True
            finally:
                subprocess.run(["umount", str(target_media)], check=True)

        def _deactivate_network_in_chroot(self):
            # Photon runs POST_INSTALL modules (including its default root
            # password updater) after _finalize_system. Apply operator credentials
            # only after that sequence and successful bootloader/fstab creation.
            if not getattr(self, "atlaso_provisioned", False):
                raise RuntimeError("Atlaso provisioning did not complete")
            target = Path(self.photon_root)
            env_path = target / "etc/atlaso/atlaso.env"
            lines = env_path.read_text().splitlines()
            admin_value = environment_value(credentials[0])
            if sum(line.startswith("ATLASO_BOOTSTRAP_ADMIN_PASSWORD=") for line in lines) != 1:
                raise ValueError("installed bootstrap identity is ambiguous")
            lines = [f"ATLASO_BOOTSTRAP_ADMIN_PASSWORD={admin_value}" if line.startswith("ATLASO_BOOTSTRAP_ADMIN_PASSWORD=") else line for line in lines]
            # The target's existing root-owned environment is its supported
            # credential store. Never stage operator input on the ISO/live OS.
            with env_path.open("w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            subprocess.run(
                ["chroot", str(target), "chpasswd"], input=f"admin:{credentials[0]}\nroot:{credentials[1]}\n",
                text=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            with (target / "etc/atlaso/installation-profile").open("x") as handle:
                handle.write(PROFILE)
                handle.flush()
                os.fsync(handle.fileno())
            os.sync()

    config.update({"packages": identity["packages"], "ui": False, "live": True, "hostname": "atlaso", "log_level": "info"})
    engine = AtlasoInstaller(repo_paths=str(media / "rpms"), photon_release_version="5.0")
    engine.configure(config)
    try:
        # The native execute() catches failures and displays its success screen;
        # retain its actual install sequence while letting failures propagate.
        engine._unsafe_install()
    except BaseException:
        engine._unmount_all()
        raise


def main() -> int:
    """Enter installation only after trusted media and explicit disk consent."""
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path("/sys/firmware/efi").is_dir() or os.uname().machine != "x86_64":
        raise ValueError("the installer requires root on an x86-64 UEFI host")
    if digest(NATIVE_PATH / "installer.py") != PHOTON_INSTALLER_SHA256:
        raise ValueError("the native Photon installer differs from the pinned version 2.2")
    sys.path.insert(0, str(NATIVE_PATH))
    with tempfile.TemporaryDirectory(prefix="atlaso-installer-", dir="/run") as temporary:
        identity = verify_media(args.media, TRUST_KEY, scratch=Path(temporary))
    config, consent, credentials = curses.wrapper(configure_console, disk_inventory())
    try:
        install(args.media, identity, config, consent, credentials)
    finally:
        credentials = ("", "")
    print("Atlaso installation completed. Remove the installation media before reboot.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Cancelled, KeyboardInterrupt):
        print("Installation cancelled. Any installation already in progress may require reinstalling selected disks.")
        raise SystemExit(2) from None
