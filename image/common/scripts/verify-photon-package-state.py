#!/usr/bin/env python3
"""Verify Photon release identity and package-manager runtime prerequisites."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

PACKAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:-]*\Z")
PHOTON_DEFAULT_DISTROVERPKG = "photon-release"
INSTALLATION_FILESYSTEM_SHA256 = "7f5bba3e84f6eb50f6e5e311325089bc642549469d83793e0ba5f40d74ec6024"
INSTALLATION_SYSTEMD_SHA256 = "2ef0275f25c9b782e7f3cbbaaa5bf0d9037149b5253630c6db27e155c461618f"
INSTALLATION_SYSTEMD_TMPFILES_PATH = Path("/usr/lib/tmpfiles.d/systemd.conf")
INSTALLATION_SYSTEMD_TMPFILES_SHA256 = "68e4c097e33b30c731a359cb3af86693e5f854c53d3d6bb5ec9eb7d17f04e585"
INSTALLATION_SYSTEMD_JOURNAL_PATH = Path("/var/log/journal")
INSTALLATION_SYSTEMD_JOURNAL_TMPFILES_ROW = "z /var/log/journal 2755 root systemd-journal - -"
INSTALLATION_SYSTEMD_TMPFILES_MAX_BYTES = 1024 * 1024
INSTALLATION_AUDIT_SHA256 = "e55fac7b24b2f7546485f0b8b37fb7b105be764436dd4b139ccaa88e6c3e374f"
INSTALLATION_AUDIT_TMPFILES_PATH = Path("/usr/lib/tmpfiles.d/audit.conf")
INSTALLATION_AUDIT_TMPFILES_SHA256 = "d4ea0b752525c573cd144461ed3ac5c4e86d19501150df278add839e758c19c4"
INSTALLATION_AUDIT_TMPFILES_MAX_BYTES = 4096
INSTALLATION_AUDIT_PATH = Path("/var/log/audit")
INSTALLATION_AUDIT_TMPFILES_ROW = "d /var/log/audit 0700 root root - -"
INSTALLATION_RPCBIND_SHA256 = "2c3d001aca71e6c6c81377a7bfc7ec9c3d26ee7a9891b4a706a8205657bc31ba"
INSTALLATION_RPCBIND_PATH = Path("/var/lib/rpcbind")
INSTALLATION_OPENSSH_SHA256 = "cf1bace04bca67f58536b2cc241754bcdb3bb7e2b38c518bc283f3c90c16a2d8"
INSTALLATION_OPENSSH_PATH = Path("/usr/share/empty.sshd")
INSTALLATION_SHIM_SHA256 = "e41e6109d7be89ae83da63ef8021ef9a0e053ecd4fe1f47ae73dd79270d688c7"
INSTALLATION_GRUB_EFI_SHA256 = "516e63a3c609abecf4a4bf3ef2661d4f1bed26729a612f73e0bfcb530727e91f"
INSTALLATION_LAYOUT_HELPER_PATH = Path(__file__).resolve().parents[3] / "scripts/installation/layout.py"
INSTALLATION_LAYOUT_HELPER_SHA256 = "52e6bf44667e7e3f8d176164a76267bed7c8d9718cfcd4286e510658cf61e257"
INSTALLATION_EFI_PATH = Path("/boot/efi")
# Public sizes, hashes and modification times from the admitted shim/GRUB RPMs.
INSTALLATION_EFI_FILES = (
    ("EFI/BOOT/bootx64.efi", 1018992, "0b9a7492dcb168b00033d4ccc1edda816c9da3822fcb7e901cce72a017cf08fa", 1781509843),
    ("EFI/BOOT/revocations.efi", 74128, "e24e036243e4d97dc6c446c5c6e7e6f57235a0cc5048537b3d54c8e857b8409d", 1781509848),
    ("EFI/BOOT/grubx64.efi", 1383728, "08b51e2dc0be95bb124f0ab6d60544e2f81247da2b94b3f5169bb11bf78d77f3", 1788335074),
)
REQUIRED_RUNTIME_PACKAGES = (
    "photon-release",
    "rpm",
    "tdnf",
    "python3",
    "powershell",
    "ntpsec",
    "python3-ntp",
)
FORBIDDEN_RUNTIME_PACKAGES = ("cloud-init",)
CLOUD_INIT_RUNTIME_PATHS = (
    Path("usr/lib/systemd/system-generators/cloud-init-generator"),
    Path("usr/lib/cloud-init"),
    Path("usr/lib/systemd/system/cloud-config.service"),
    Path("usr/lib/systemd/system/cloud-final.service"),
    Path("usr/lib/systemd/system/cloud-init-hotplugd.service"),
    Path("usr/lib/systemd/system/cloud-init-hotplugd.socket"),
    Path("usr/lib/systemd/system/cloud-init-local.service"),
    Path("usr/lib/systemd/system/cloud-init-main.service"),
    Path("usr/lib/systemd/system/cloud-init-network.service"),
    Path("usr/lib/systemd/system/cloud-init.service"),
    Path("usr/lib/systemd/system/cloud-init.target"),
    Path("etc/cloud"),
    Path("var/lib/cloud"),
)


def read_os_release(path: Path) -> dict[str, str]:
    """Return the bounded key/value fields from one os-release file.

    Args:
        path: Release identity file to parse.
    """

    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"Photon release identity file is missing or empty: {path}")

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"Invalid os-release entry at {path}:{line_number}")
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def read_distroverpkg(path: Path) -> str:
    """Return the exact package identity configured by TDNF.

    Args:
        path: TDNF configuration file to inspect.
    """

    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"TDNF configuration is missing or empty: {path}")

    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as exc:
        raise ValueError(f"TDNF configuration is invalid: {path}") from exc
    package = parser.get(
        "main", "distroverpkg", fallback=PHOTON_DEFAULT_DISTROVERPKG
    ).strip()
    if not PACKAGE_NAME_PATTERN.fullmatch(package):
        raise ValueError("TDNF main.distroverpkg is not a valid RPM package identity")
    return package


def verify_rpm_packages(
    packages: Sequence[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Require every named runtime RPM to remain installed.

    Args:
        packages: Runtime RPM package identities to query.
        runner: Subprocess-compatible command runner.
    """

    for package in packages:
        completed = runner(
            ["rpm", "-q", package],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise ValueError(
                f"Required Photon runtime package is not installed: {package}"
            )


def verify_rpm_packages_absent(
    packages: Sequence[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Require every named unsupported RPM to be absent.

    Args:
        packages: Unsupported RPM package identities to query.
        runner: Subprocess-compatible command runner.
    """

    for package in packages:
        completed = runner(
            ["rpm", "-q", package],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0:
            raise ValueError(
                f"Unsupported Photon runtime package is installed: {package}"
            )
        if completed.returncode != 1:
            raise ValueError(
                f"Could not verify unsupported Photon package is absent: {package}"
            )


def verify_paths_absent(paths: Sequence[Path]) -> None:
    """Require unsupported runtime paths to be absent from the image.

    Args:
        paths: Filesystem paths that must not remain in the appliance.
    """

    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise ValueError(f"Unsupported cloud-init runtime path remains: {path}")


def verify_photon_package_state(
    *,
    os_release_path: Path,
    photon_release_path: Path,
    tdnf_config_path: Path,
    guest_platform: str,
    image_root: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Verify release files, TDNF identity, and required runtime RPMs.

    Args:
        os_release_path: Photon ``os-release`` identity file.
        photon_release_path: Photon human-readable release identity file.
        tdnf_config_path: TDNF configuration defining the distro version package.
        guest_platform: Appliance platform whose runtime packages are required.
        image_root: Root beneath which unsupported image paths are checked.
        runner: Subprocess-compatible command runner.
    """

    os_release = read_os_release(os_release_path)
    if os_release.get("ID") != "photon" or os_release.get("VERSION_ID") != "5.0":
        raise ValueError("/etc/os-release does not identify Photon OS 5.0")

    if not photon_release_path.is_file() or photon_release_path.stat().st_size == 0:
        raise ValueError(
            f"Photon release identity file is missing or empty: {photon_release_path}"
        )
    photon_release = photon_release_path.read_text(encoding="utf-8").splitlines()[0]
    if not photon_release.startswith("VMware Photon OS 5.0"):
        raise ValueError("/etc/photon-release does not identify Photon OS 5.0")

    distroverpkg = read_distroverpkg(tdnf_config_path)
    packages = [distroverpkg, *REQUIRED_RUNTIME_PACKAGES]
    if guest_platform == "vmware":
        packages.append("open-vm-tools")
    elif guest_platform != "none":
        raise ValueError(f"Unsupported Photon guest platform: {guest_platform}")
    verify_rpm_packages(tuple(dict.fromkeys(packages)), runner=runner)
    verify_rpm_packages_absent(FORBIDDEN_RUNTIME_PACKAGES, runner=runner)
    verify_paths_absent(tuple(image_root / path for path in CLOUD_INIT_RUNTIME_PATHS))
    return distroverpkg


def _read_installation_mountinfo(path: Path = Path("/proc/self/mountinfo")) -> str:
    """Read a bounded private mount table without following its leaf.

    Args:
        path: Native mount table, injectable only for isolated fixtures.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        raw = stream.read(1024 * 1024 + 1)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or len(raw) > 1024 * 1024:
        raise ValueError("installation mount table is not a bounded ordinary file")
    return raw.decode("utf-8")


def _installation_mount_rows() -> list[tuple[list[str], list[str]]]:
    """Parse the existing bounded native mount table without reporting its contents."""
    mounts = []
    for row in _read_installation_mountinfo().splitlines():
        before, separator, after = row.partition(" - ")
        fields, filesystem_fields = before.split(), after.split()
        if not separator or len(fields) < 6 or len(filesystem_fields) < 3:
            raise ValueError("installation runtime mount table is malformed")
        mounts.append((fields, filesystem_fields))
    return mounts


def verify_installation_runtime_metadata(filesystem_sha256: str) -> dict[str, bool]:
    """Verify native runtime metadata that shadows the admitted empty payload.

    Args:
        filesystem_sha256: Original checksum admitted from the ISO manifest.

    The fixed Photon filesystem RPM declares empty runtime directories and login
    records. Native mounts and systemd tmpfiles change their metadata after boot.
    Its own post-transaction script explicitly chmods /var/mail to 1755 and
    chowns it to uid 0, gid 34. No private login record contents are read here.
    """
    if filesystem_sha256 != INSTALLATION_FILESYSTEM_SHA256:
        raise ValueError("Photon filesystem runtime metadata profile is not admitted")
    from grp import getgrnam

    mounts = _installation_mount_rows()
    for name, filesystem, mode in (("/proc", "proc", 0o555), ("/run", "tmpfs", 0o755)):
        metadata = Path(name).lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != mode
                or metadata.st_uid != 0 or metadata.st_gid != 0):
            raise ValueError("installation runtime mount metadata differs")
        rows = [row for row in mounts if row[0][4] == name]
        if len(rows) != 1 or rows[0][0][3] != "/" or rows[0][1][0] != filesystem:
            raise ValueError("installation runtime mount identity differs")
    utmp_gid = getgrnam("utmp").gr_gid
    for name, mode in (("/var/log/btmp", 0o660), ("/var/log/wtmp", 0o664)):
        metadata = Path(name).lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_uid != 0 or metadata.st_gid != utmp_gid):
            raise ValueError("installation login record metadata differs")
    metadata = Path("/var/mail").lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o1755
            or metadata.st_uid != 0 or metadata.st_gid != 34):
        raise ValueError("installation mail spool metadata differs from native post-transaction policy")
    return {"runtime_proc_verified": True, "runtime_run_verified": True,
            "runtime_login_metadata_verified": True, "runtime_mail_spool_verified": True}


def _read_installation_tmpfiles(path: Path, mode: int, maximum_bytes: int, policy_name: str) -> bytes:
    """Read the admitted tmpfiles policy through a bounded no-follow handle.

    Args:
        path: Fixed public policy path selected by the package profile.
        mode: Native packaged permission bits for that policy.
        maximum_bytes: Maximum policy size admitted by the profile.
        policy_name: Fixed package name used in non-secret error categories.

    This reads public package policy only. Root ownership, ordinary-file identity
    and stable metadata are checked before the caller verifies its pinned bytes.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError(f"installation {policy_name} tmpfiles policy cannot be opened without following links")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise ValueError(f"installation {policy_name} tmpfiles policy is unavailable") from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != mode
                or not 0 < metadata.st_size <= maximum_bytes
            ):
                raise ValueError(f"installation {policy_name} tmpfiles policy metadata differs")
            raw = stream.read(maximum_bytes + 1)
            after = os.fstat(stream.fileno())
            before_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if (
                len(raw) != metadata.st_size
                or len(raw) > maximum_bytes
                or before_identity != after_identity
            ):
                raise ValueError(f"installation {policy_name} tmpfiles policy changed while it was read")
            return raw
    except OSError as exc:
        raise ValueError(f"installation {policy_name} tmpfiles policy could not be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_installation_systemd_tmpfiles() -> bytes:
    """Reuse the native policy reader with the existing systemd profile."""
    return _read_installation_tmpfiles(
        INSTALLATION_SYSTEMD_TMPFILES_PATH, 0o644, INSTALLATION_SYSTEMD_TMPFILES_MAX_BYTES, "systemd"
    )


def _read_installation_audit_tmpfiles() -> bytes:
    """Read only the fixed audit package policy, never audit records."""
    return _read_installation_tmpfiles(
        INSTALLATION_AUDIT_TMPFILES_PATH, 0o640, INSTALLATION_AUDIT_TMPFILES_MAX_BYTES, "audit"
    )


def verify_installation_journal_metadata(systemd_sha256: str) -> dict[str, bool]:
    """Verify only the native systemd-owned metadata on the journal directory.

    Args:
        systemd_sha256: Original checksum admitted from the ISO RPM manifest.

    The fixed systemd RPM ships an empty journal directory. Its pinned tmpfiles
    policy creates that directory as root:systemd-journal mode ``2755``. No
    journal children or contents are opened or inspected.
    """
    if systemd_sha256 != INSTALLATION_SYSTEMD_SHA256:
        raise ValueError("systemd runtime metadata profile is not admitted")
    raw = _read_installation_systemd_tmpfiles()
    if hashlib.sha256(raw).hexdigest() != INSTALLATION_SYSTEMD_TMPFILES_SHA256:
        raise ValueError("installation systemd tmpfiles policy checksum differs")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ValueError("installation systemd tmpfiles policy is not UTF-8") from exc
    journal_rows = [
        fields
        for line in lines
        if (fields := line.split())
        and len(fields) > 1
        and fields[0] == "z"
        and fields[1] == "/var/log/journal"
    ]
    if journal_rows != [INSTALLATION_SYSTEMD_JOURNAL_TMPFILES_ROW.split()]:
        raise ValueError("installation systemd journal tmpfiles policy differs")
    try:
        from grp import getgrnam

        journal_gid = getgrnam("systemd-journal").gr_gid
        metadata = INSTALLATION_SYSTEMD_JOURNAL_PATH.lstat()
    except (KeyError, OSError) as exc:
        raise ValueError("installation systemd journal directory metadata is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o2755
        or metadata.st_uid != 0
        or metadata.st_gid != journal_gid
    ):
        raise ValueError(
            "installation systemd journal directory metadata differs from native tmpfiles policy"
        )
    return {"runtime_journal_metadata_verified": True}


def verify_installation_audit_metadata(audit_sha256: str) -> dict[str, bool]:
    """Verify the audit directory's native root-only runtime permissions.

    Args:
        audit_sha256: Original audit RPM checksum admitted from the ISO manifest.

    The pinned native tmpfiles policy creates this packaged directory as
    root:root ``0700``. No audit children or record contents are inspected.
    """
    if audit_sha256 != INSTALLATION_AUDIT_SHA256:
        raise ValueError("audit runtime metadata profile is not admitted")
    raw = _read_installation_audit_tmpfiles()
    if hashlib.sha256(raw).hexdigest() != INSTALLATION_AUDIT_TMPFILES_SHA256:
        raise ValueError("installation audit tmpfiles policy checksum differs")
    if raw.decode("utf-8").splitlines() != [INSTALLATION_AUDIT_TMPFILES_ROW]:
        raise ValueError("installation audit tmpfiles policy differs")
    try:
        metadata = INSTALLATION_AUDIT_PATH.lstat()
    except OSError as exc:
        raise ValueError("installation audit directory metadata is unavailable") from exc
    if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != 0 or metadata.st_gid != 0):
        raise ValueError("installation audit directory metadata differs from native tmpfiles policy")
    return {"runtime_audit_metadata_verified": True}


def _verify_installation_sys_directory(profile: str, package_sha256: str) -> None:
    """Reuse the two admitted packages' root:sys initial-install metadata proof.

    Args:
        profile: Fixed native package profile, never an arbitrary path selector.
        package_sha256: Original package checksum admitted from the ISO.
    """
    profiles = {
        "rpcbind": (INSTALLATION_RPCBIND_SHA256, INSTALLATION_RPCBIND_PATH, 0o755),
        "openssh": (INSTALLATION_OPENSSH_SHA256, INSTALLATION_OPENSSH_PATH, 0o711),
    }
    if profile not in profiles or package_sha256 != profiles[profile][0]:
        raise ValueError("native directory runtime metadata profile is not admitted")
    _, directory, mode = profiles[profile]
    try:
        from grp import getgrnam

        sys_gid = getgrnam("sys").gr_gid
        metadata = directory.lstat()
    except (KeyError, OSError) as exc:
        raise ValueError("installation native directory metadata is unavailable") from exc
    if (sys_gid != 2 or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != 0 or metadata.st_gid != sys_gid):
        raise ValueError("installation directory metadata differs from native post-transaction policy")


def verify_installation_rpcbind_metadata(rpcbind_sha256: str) -> dict[str, bool]:
    """Verify the pinned RPC package's initial-install ownership policy.

    Args:
        rpcbind_sha256: Original rpcbind RPM checksum admitted from the ISO.

    The archive declares root:root mode ``0755``; its own initial-install
    script changes only ownership to root:sys. Photon's admitted filesystem
    declares sys as gid 2. No state files or directory children are read.
    """
    _verify_installation_sys_directory("rpcbind", rpcbind_sha256)
    return {"runtime_rpcbind_metadata_verified": True}


def verify_installation_openssh_metadata(openssh_sha256: str) -> dict[str, bool]:
    """Verify only the native privilege-separation directory, never SSH keys.

    Args:
        openssh_sha256: Original OpenSSH server RPM checksum admitted from the ISO.

    The archive declares root:root mode ``0711``. Its own initial-install
    script changes that directory to root:sys without changing permissions.
    """
    _verify_installation_sys_directory("openssh", openssh_sha256)
    return {"runtime_openssh_metadata_verified": True}


def _verified_installation_layout() -> dict:
    """Authenticate and reuse the installed-layout verifier before mount observation.

    Compile only the checksum-bound shared helper bytes already read through the
    root-owned no-follow policy reader; do not reopen an import pathname.
    """
    raw = _read_installation_tmpfiles(INSTALLATION_LAYOUT_HELPER_PATH, 0o644, 65536, "layout helper")
    if hashlib.sha256(raw).hexdigest() != INSTALLATION_LAYOUT_HELPER_SHA256:
        raise ValueError("installation layout helper checksum differs")
    scope = {"__name__": "_verified_installation_layout"}
    exec(compile(raw, str(INSTALLATION_LAYOUT_HELPER_PATH), "exec"), scope)
    if not scope["installation_profile"]():
        raise ValueError("installation profile is missing")
    return scope["verify_layout"]()


def verify_installation_efi_metadata(shim_sha256: str, grub_efi_sha256: str) -> dict[str, bool]:
    """Verify native VFAT metadata and immutable bytes for the three boot files.

    Args:
        shim_sha256: Original shim RPM checksum admitted from the ISO.
        grub_efi_sha256: Original GRUB EFI-image RPM checksum admitted from the ISO.

    VFAT derives permissions from mount masks and stores modification times in
    two-second units. Reuse recorded UUID mount checks, require the native masks,
    and independently verify all packaged byte sequences and rounded times.
    """
    if shim_sha256 != INSTALLATION_SHIM_SHA256 or grub_efi_sha256 != INSTALLATION_GRUB_EFI_SHA256:
        raise ValueError("EFI runtime metadata profile is not admitted")
    layout = _verified_installation_layout()
    if not any(item["target"] == "/boot/efi" and item["filesystem"] == "vfat" for item in layout["mounts"]):
        raise ValueError("installation EFI filesystem differs from recorded layout")
    mounts = _installation_mount_rows()
    rows = [row for row in mounts if row[0][4] == "/boot/efi"]
    if (len(rows) != 1 or rows[0][0][3] != "/" or rows[0][1][0] != "vfat"
            or any(row[0][4].startswith("/boot/efi/") for row in mounts)):
        raise ValueError("installation EFI mount identity differs")
    options = rows[0][1][2].split(",")
    for key, expected in (("fmask", "0022"), ("dmask", "0022")):
        if [item for item in options if item.startswith(key + "=")] != [key + "=" + expected]:
            raise ValueError("installation EFI mount permissions differ")
    root = INSTALLATION_EFI_PATH.lstat()
    if (not stat.S_ISDIR(root.st_mode) or stat.S_IMODE(root.st_mode) != 0o755
            or root.st_uid or root.st_gid):
        raise ValueError("installation EFI root metadata differs")
    for name, size, checksum, modified in INSTALLATION_EFI_FILES:
        path = INSTALLATION_EFI_PATH / name
        before = path.lstat()
        raw = _read_installation_tmpfiles(path, 0o755, size, "EFI file")
        metadata = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                         "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before, name) != getattr(metadata, name) for name in stable_fields)
                or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o755 or metadata.st_uid or metadata.st_gid
                or metadata.st_size != size or len(raw) != size or hashlib.sha256(raw).hexdigest() != checksum
                or metadata.st_dev != root.st_dev
                or metadata.st_mtime_ns != (modified // 2 * 2) * 1_000_000_000):
            raise ValueError("installation EFI bytes or native timestamp differ")
    return {"runtime_efi_metadata_verified": True}


def verify_installation_metadata(
    filesystem_sha256: str, systemd_sha256: str, audit_sha256: str, rpcbind_sha256: str,
    shim_sha256: str, grub_efi_sha256: str, openssh_sha256: str
) -> dict[str, bool]:
    """Reuse the admitted native profiles before or after package comparison.

    Args:
        filesystem_sha256: Original Photon filesystem RPM checksum.
        systemd_sha256: Original Photon systemd RPM checksum.
        audit_sha256: Original Photon audit RPM checksum.
        rpcbind_sha256: Original Photon rpcbind RPM checksum.
        shim_sha256: Original Photon shim RPM checksum.
        grub_efi_sha256: Original Photon GRUB EFI-image RPM checksum.
        openssh_sha256: Original Photon OpenSSH server RPM checksum.
    """
    result = verify_installation_runtime_metadata(filesystem_sha256)
    result.update(verify_installation_journal_metadata(systemd_sha256))
    result.update(verify_installation_audit_metadata(audit_sha256))
    result.update(verify_installation_rpcbind_metadata(rpcbind_sha256))
    result.update(verify_installation_openssh_metadata(openssh_sha256))
    result.update(verify_installation_efi_metadata(shim_sha256, grub_efi_sha256))
    return result


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Arguments to parse, or ``None`` for the process arguments.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os-release", type=Path, default=Path("/etc/os-release"))
    parser.add_argument(
        "--photon-release", type=Path, default=Path("/etc/photon-release")
    )
    parser.add_argument("--tdnf-config", type=Path, default=Path("/etc/tdnf/tdnf.conf"))
    parser.add_argument("--guest-platform", choices=("vmware", "none"), required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Photon package-state verification.

    Args:
        argv: Arguments to parse, or ``None`` for the process arguments.
    """

    args = parse_args(argv)
    try:
        distroverpkg = verify_photon_package_state(
            os_release_path=args.os_release,
            photon_release_path=args.photon_release,
            tdnf_config_path=args.tdnf_config,
            guest_platform=args.guest_platform,
            image_root=Path("/"),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"Photon package runtime verification failed: {exc}") from exc
    print(f"Photon package runtime verified with distroverpkg {distroverpkg}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
