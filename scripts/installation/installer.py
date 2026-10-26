#!/usr/bin/env python3
"""Adapt Photon's pinned native installer to the signed offline Atlaso payload."""

from __future__ import annotations

import argparse
import curses
import os
import re
import secrets
import shutil
import stat
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
    DEVELOPMENT_KEY_ID,
    PHOTON_INSTALLER_SHA256,
    digest,
    installer_key_id,
    inventory,
    verify_media,
)

NATIVE_PATH = Path("/usr/lib/python3.11/site-packages/photon_installer")
TRUST_KEY = Path("/etc/atlaso-installer/trust.pem")
MINIMUM_DISK_BYTES = 64 * 1024**3
MAX_INSPECTION_SOFTWARE_BYTES = 2 * 1024**3


class Cancelled(Exception):
    """Represent cancellation before admitting destructive installation."""


def environment_value(value: str) -> str:
    """Quote for the existing systemd environment file and shell consumers.

    Args:
        value: Value to validate or serialize."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return '"' + escaped + '"'


def prompt(maxy: int, maxx: int, title: str, message: str, *, secret: bool = False, validator=None) -> str:
    """Reuse the Photon console field and masked input rather than a new UI kit.

    Args:
        maxy: Available terminal height in rows.
        maxx: Available terminal width in columns.
        title: Prompt title displayed to the operator.
        message: Prompt instructions displayed to the operator.
        secret: Whether input must be concealed.
        validator: Optional function that validates the entered value."""
    from windowstringreader import WindowStringReader

    state = {}
    width = min(maxx - 4, 78)
    lines = [part for line in message.splitlines() for part in (textwrap.wrap(line, width - 4) or [""])]
    if len(lines) > maxy - 10:
        raise ValueError("installer review exceeds the console page size")
    reader = WindowStringReader(
        # Native ReadText reserves two rows below input for validation errors;
        # Window's content area is five rows shorter than its outer height.
        maxy, maxx, max(12, len(lines) + 9), width, "value", None,
        "*" if secret else None, list(range(32, 127)), validator, None, title,
        "\n".join(lines), len(lines) + 1, state,
    )
    if not reader.get_user_string().success:
        raise Cancelled()
    return state["value"]


def confirm_installation(maxy: int, maxx: int, message: str) -> bool:
    """Show a native Photon confirmation with No selected initially.

    Args:
        maxy: Available terminal height in rows.
        maxx: Available terminal width in columns.
        message: Complete, already wrapped destructive-installation summary.
    """
    from confirmwindow import ConfirmWindow

    height = len(message.splitlines()) + 7
    width = maxx - 4
    if height > maxy or width < 40:
        raise ValueError("installation confirmation exceeds the console page size")
    starty = (maxy - height) // 2 + height - 4
    confirmation = ConfirmWindow(height, width, maxy, maxx, starty, message)
    confirmation.menu.position = 1
    result = confirmation.do_action()
    return bool(result.success and result.result and result.result.get("yes") is True)


def show_layout_review_pages(maxy: int, maxx: int, lines: list[str]) -> None:
    """Show every long custom-layout line in native informational pages.

    Args:
        maxy: Available terminal height in rows.
        maxx: Available terminal width in columns.
        lines: Complete layout summary lines, without truncation.
    """
    from confirmwindow import ConfirmWindow

    width = maxx - 4
    body_width = width - 5
    wrapped = [part for line in lines for part in (textwrap.wrap(line, body_width) or [""])]
    page_capacity = maxy - 12
    if body_width <= 0 or page_capacity < 1:
        raise ValueError("installation review exceeds the console page size")
    pages = [wrapped[index:index + page_capacity] for index in range(0, len(wrapped), page_capacity)]
    for index, page in enumerate(pages, start=1):
        message = "Planned installation layout ({}/{})\n{}".format(index, len(pages), "\n".join(page))
        height = len(message.splitlines()) + 7
        starty = (maxy - height) // 2 + height - 4
        result = ConfirmWindow(height, width, maxy, maxx, starty, message, info=True).do_action()
        if not result.success:
            raise Cancelled()


def configure_console(screen, initial: dict[str, dict]) -> tuple[dict, dict, tuple[str, str]]:
    """Collect the native layout, destructive consent, and concealed credentials.

    Args:
        screen: Active curses screen used by the installer.
        initial: Read-only disk identities captured before operator selection."""
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
        """Return eligible installer disks that still match the initial inventory.

        Args:
            byte_sizes: Byte counts used to format device sizes."""
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
            """Initialize the native partition editor and its per-row disk mappings.

            Args:
                *args: Arguments forwarded to the wrapped operation."""
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
            """Validate a native custom partition and bind it to its selected disk.

            Args:
                values: Partition fields collected from the operator."""
            if values and values[2] == "/boot/efi":
                return False, "Photon creates the EFI boot partition on the selected boot disk."
            if values and values[2] == "/boot" and values[1] != "ext4":
                return False, "The Photon EFI loader requires ext4 for /boot."
            if values and values[2] == "/" and values[1] not in {"ext4", "xfs", "btrfs"}:
                return False, "The root filesystem must be ext4, xfs, or btrfs."
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
            # The pinned Photon 2.2 control is Delete All, not row deletion.
            # Its delete() resets partitionsnumber to zero and clears every row.
            self.partition_disks.clear()
            return super().delete()

    while True:
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
        if not config.get("autopartition") or consent[config["disk"]]["size"] >= MINIMUM_DISK_BYTES:
            break

        # Keep the admission error inside Photon's native informational dialog.
        # Dismissing it returns to explicit disk selection; its cancel key exits
        # through the same pre-write cancellation path as other installer dialogs.
        from confirmwindow import ConfirmWindow

        selected = config["disk"]
        size = consent[selected]["size"]
        message = "\n".join((
            "Insufficient disk capacity.",
            "default installation requires a disk of at least 64 GiB",
            f"Selected {selected} has {size} bytes.",
            "Press Enter to choose another disk, or Esc to cancel.",
        ))
        height = len(message.splitlines()) + 7
        width = maxx - 4
        starty = (maxy - height) // 2 + height - 4
        result = ConfirmWindow(height, width, maxy, maxx, starty, message, info=True).do_action()
        if not result.success:
            raise Cancelled()
    summary_lines = ["Erase selected disks?"]
    layout_lines = []
    for path in paths:
        item = consent[path]
        label = f"{path}: {item.get('model') or 'Unknown'} {item['size'] // 1024**3} GiB"
        serial = item.get("serial") or item.get("wwn") or "unavailable"
        summary_lines.extend((label, f"Serial/WWN: {serial}"))
        partitions = [
            f"  {p.get('mountpoint') or 'swap'} {p['filesystem']} {p['size'] or 'remaining'} MiB"
            for p in config["partitions"] if p.get("disk", config["disk"]) == path
        ]
        if path == config["disk"]:
            # ESPSIZE is 10 MiB in the hash-pinned native Photon 2.2 backend.
            partitions.insert(0, "  /boot/efi vfat 10 MiB (Photon UEFI default)")
        layout_lines.append(f"{path} planned layout:")
        layout_lines.extend(partitions)
    wrapped_summary = [part for line in summary_lines for part in (textwrap.wrap(line, maxx - 9) or [""])]
    wrapped_layout = [part for line in layout_lines for part in (textwrap.wrap(line, maxx - 9) or [""])]
    confirmation_lines = wrapped_summary + ["", "Planned layout:"] + wrapped_layout + [
        "", "ALL EXISTING DATA ON SELECTED DISKS WILL BE LOST.", "Select Yes to continue or No to cancel."
    ]
    if len(confirmation_lines) > maxy - 10:
        show_layout_review_pages(maxy, maxx, layout_lines)
        confirmation_lines = wrapped_summary + [
            "", "Planned layout is shown above.", "ALL EXISTING DATA ON SELECTED DISKS WILL BE LOST.",
            "Select Yes to continue or No to cancel.",
        ]
    if not confirm_installation(maxy, maxx, "\n".join(confirmation_lines)):
        raise Cancelled()
    passwords = []
    for username in ("admin", "root"):
        def validator(value, account=username):
            """Apply the local password policy to one concealed password entry.

            Args:
                value: Value to validate or serialize.
                account: Local account whose password policy is being applied."""
            errors = validate_password(value, account, DEFAULT_PASSWORD_POLICY)
            return not errors, " ".join(errors)

        first = prompt(maxy, maxx, f"Set {username} password", "Enter the local account password.", secret=True, validator=validator)
        def matching_validator(value, expected=first):
            """Require confirmation to match without exposing the first entry.

            Args:
                value: Concealed confirmation value.
                expected: Concealed first entry retained only for comparison.
            """
            if value == expected:
                return True, ""
            return False, "Passwords do not match."

        prompt(
            maxy, maxx, f"Confirm {username} password", "Enter the same password again.",
            secret=True, validator=matching_validator,
        )
        passwords.append(first)
    revalidate_disks(config, consent, disk_inventory())
    # Secret material never enters Photon configuration, dynamic substitutions,
    # native modules, command arguments, or its persistent installation log.
    return config, consent, (passwords[0], passwords[1])


def verify_installed_boot_artifacts(target: Path) -> None:
    """Require the native kernel and initrd selected by Photon's GRUB environment.

    Args:
        target: Installed system root after native bootloader and fstab setup.
    """
    try:
        environment = subprocess.check_output(
            ["chroot", str(target), "/usr/bin/grub2-editenv", "/boot/photon.cfg", "list"],
            text=True, stderr=subprocess.DEVNULL, timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, UnicodeError):
        raise RuntimeError("installed Photon boot metadata could not be verified") from None
    if len(environment) > 65536:
        raise RuntimeError("installed Photon boot metadata exceeds its bounded size")
    boot = (target / "boot").resolve(strict=True)
    names = []
    for key in ("photon_linux", "photon_initrd"):
        values = [line.partition("=")[2] for line in environment.splitlines() if line.startswith(key + "=")]
        if len(values) != 1 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", values[0]):
            raise RuntimeError("installed Photon kernel or initrd selection is missing or ambiguous")
        path = boot / values[0]
        if not path.is_file() or path.stat().st_size == 0 or not path.resolve(strict=True).is_relative_to(boot):
            raise RuntimeError("installed Photon kernel or initrd image is missing")
        names.append(values[0])
    if names[0] == names[1]:
        raise RuntimeError("installed Photon kernel and initrd selections must differ")


def configure_development_serial_login(target: Path, identity: dict) -> None:
    """Enable ordinary password-protected serial login only for admitted VM test media.

    Args:
        target: Installed system root.
        identity: Signature-verified installation identity.
    """
    development = identity.get("development")
    if identity.get("signing_key_id") != DEVELOPMENT_KEY_ID and development is None:
        return
    if (identity.get("signing_key_id") != DEVELOPMENT_KEY_ID
            or not isinstance(development, dict) or development.get("non_production") is not True
            or installer_key_id() != DEVELOPMENT_KEY_ID):
        raise ValueError("serial test login requires admitted development VMware media")
    subprocess.run([
        "chroot", str(target), "/opt/atlaso/bin/atlaso-install-boot-branding",
        "/opt/atlaso/image/common/boot/grub/theme.txt", "/opt/atlaso/image/common/boot/grub/atlaso.png",
        "--development-serial-console",
    ], check=True)
    subprocess.run(["chroot", str(target), "systemctl", "enable", "serial-getty@ttyS0.service"], check=True)


def retain_development_inspection_inputs(media: Path, target: Path, identity: dict) -> None:
    """Persist authenticated public software inputs for post-reboot VM checks.

    Args:
        media: Read-only mounted installer payload already verified by the caller.
        target: Newly installed operating system root on an operator-selected disk.
        identity: Signature-verified payload manifest returned by ``verify_media``.
    """
    development = identity.get("development")
    if identity.get("signing_key_id") != DEVELOPMENT_KEY_ID:
        if development is None:
            return
        raise ValueError("production installation cannot retain development inspection inputs")
    if (not isinstance(development, dict)
            or set(development) != {"schema", "software_source_commit", "non_production"}
            or development.get("schema") != 1 or development.get("non_production") is not True
            or not re.fullmatch(r"[0-9a-f]{40}", str(development.get("software_source_commit", "")))):
        raise ValueError("inspection inputs require authenticated non-production media")

    source = media / "software"
    for media_directory in (media, source):
        media_info = media_directory.lstat()
        if (not stat.S_ISDIR(media_info.st_mode) or media_directory.is_symlink()
                or (hasattr(media_directory, "is_junction") and media_directory.is_junction())):
            raise ValueError("authenticated software media path is unsafe")
    actual = inventory(source)
    records = identity.get("files")
    if not isinstance(records, list):
        raise ValueError("authenticated software inventory is missing")
    software_records = [item for item in records if isinstance(item, dict)
                        and isinstance(item.get("path"), str) and item["path"].startswith("software/")]
    if (any(not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}
            for item in records)
            or any(not isinstance(item.get("size"), int) or isinstance(item["size"], bool)
                   or item["size"] < 0 or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
                   for item in software_records)):
        raise ValueError("authenticated software inventory record is invalid")
    expected = {
        str(item["path"])[len("software/"):]: item
        for item in software_records
    }
    if (not expected or len(expected) != len(software_records)
            or set(expected) != {item["path"] for item in actual}):
        raise ValueError("authenticated software input set is incomplete")
    total = 0
    for item in actual:
        record = expected[item["path"]]
        if item["sha256"] != record.get("sha256") or item["size"] != record.get("size"):
            raise ValueError("authenticated software input changed after verification")
        total += item["size"]
        if total > MAX_INSPECTION_SOFTWARE_BYTES:
            raise ValueError("development inspection software exceeds its retention bound")

    atlaso_state = target / "var/lib/atlaso"
    for parent in (target, target / "var", target / "var/lib", atlaso_state):
        parent_info = parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or parent.is_symlink()
                or (hasattr(parent, "is_junction") and parent.is_junction())):
            raise ValueError("installed inspection parent is unsafe")
    inspection = atlaso_state / "installation-inspection"
    if inspection.exists() or inspection.is_symlink():
        info = inspection.lstat()
        if (not stat.S_ISDIR(info.st_mode) or inspection.is_symlink()
                or (hasattr(inspection, "is_junction") and inspection.is_junction())):
            raise ValueError("installed inspection directory is unsafe")
    else:
        inspection.mkdir(mode=0o755)
    destination = inspection / "software"
    if os.path.lexists(destination):
        raise FileExistsError("installed inspection inputs already exist")
    staged = inspection / ("software.tmp-" + secrets.token_hex(12))
    try:
        shutil.copytree(source, staged, copy_function=shutil.copyfile)
        if inventory(staged) != actual:
            raise ValueError("retained inspection inputs differ from authenticated media")
        os.rename(staged, destination)
    except Exception:
        if staged.is_dir() and not staged.is_symlink():
            shutil.rmtree(staged)
        raise


def install(media: Path, identity: dict, config: dict, consent: dict, credentials: tuple[str, str]) -> None:
    """Delegate partitions, base OS, bootloader and fstab to the pinned backend.

    Args:
        media: Mounted installation payload directory.
        identity: Machine identity to initialize on the installed system.
        config: Installer configuration describing the target layout.
        consent: Previously confirmed disk identities for this installation.
        credentials: Administrator and root credentials collected by the installer."""
    from installer import Installer

    class AtlasoInstaller(Installer):
        """Add consent verification and the existing shared provisioner only."""

        def exit_gracefully(self, *args):
            # Photon 2.2's error helper can return to the installation sequence.
            # An Atlaso install must never turn a partial native failure green.
            """Stop after a native installer failure so partial installation cannot succeed.

            Args:
                *args: Arguments forwarded to the wrapped operation."""
            raise RuntimeError("Photon installation failed; selected disks may require recovery")

        def _run_tdnf_in_docker(self, *args):
            """Reject network-backed package installation during offline setup.

            Args:
                *args: Arguments forwarded to the wrapped operation."""
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

        def _setup_grub(self):
            # Shared provisioning brands and validates the generated Photon GRUB
            # configuration. Native _finalize_system runs too early for it.
            super()._setup_grub()
            self._provision_atlaso()

        def _provision_atlaso(self):
            """Reuse shared provisioning after native bootloader configuration exists."""
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
                    "ATLASO_SOFTWARE_SOURCE_COMMIT": identity.get("development", {}).get("software_source_commit", identity["source_commit"]),
                    "ATLASO_BUILD_SOURCE_COMMIT": identity["source_commit"],
                    "ATLASO_MGMT_ADDRESS": "dhcp", "ATLASO_MGMT_IPV4_METHOD": "dhcp",
                    "ATLASO_DRY_RUN_SYSTEM_ADAPTERS": "true",
                }
                subprocess.run(
                    ["chroot", str(target), "/bin/sh", "/tmp/atlaso-src/image/common/scripts/provision-atlaso.sh"],
                    env=environment, check=True,
                )
                retain_development_inspection_inputs(media, target, identity)
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
            verify_installed_boot_artifacts(target)
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
            configure_development_serial_login(target, identity)
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
        identity = verify_media(args.media, TRUST_KEY, scratch=Path(temporary), expected_key_id=installer_key_id(), boot_crypto=True)
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
