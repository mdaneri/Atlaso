#!/usr/bin/env python3
"""Verify Photon release identity and package-manager runtime prerequisites."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable, Sequence
from contextlib import ExitStack
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
# Reviewed openssh-server-10.6p1-2.ph5 retains the native root:sys 0711 directory policy.
INSTALLATION_OPENSSH_SHA256 = "8701947e3a0ca692ad4dc19b51432e2030e04b54d1a3f124276c43ccbd016dc3"
INSTALLATION_OPENSSH_PATH = Path("/usr/share/empty.sshd")
INSTALLATION_OPENLDAP_SHA256 = "11b4af044b7418ba9af5cf6762e2cbe5add5b3463774d20f6be89b8ff98c47dc"
INSTALLATION_OPENLDAP_UNIT_PATH = Path("/usr/lib/systemd/system/slapd.service")
INSTALLATION_OPENLDAP_UNIT_SHA256 = "203aafa5cb6c16defe0fae0100bc89b9cbf65d666e7d73a9b510f8fb8b94c8cf"
INSTALLATION_SHIM_SHA256 = "e41e6109d7be89ae83da63ef8021ef9a0e053ecd4fe1f47ae73dd79270d688c7"
INSTALLATION_GRUB_EFI_SHA256 = "516e63a3c609abecf4a4bf3ef2661d4f1bed26729a612f73e0bfcb530727e91f"
INSTALLATION_LINUX_SHA256 = "e9fce63202ba573679b5c450a320d7cb6ad1d38ccb5d64ceceb917616a9a7191"
INSTALLATION_KMOD_SHA256 = "b7614a76f7a17b832e2158fe90413cf2af719b1d1e9d85bfae7195e4905a7850"
INSTALLATION_KMOD_BINARY_SHA256 = "ee872a0ddff939b69e87beec32090dc98d1882e9028f4bd5729b9a2b858aaaeb"
INSTALLATION_MODULE_ROOT = Path("/usr/lib/modules/6.12.114-1.ph5")
INSTALLATION_MODULE_RUN_ROOT = Path("/run")
INSTALLATION_KMOD_FILES = (
    ("/usr/bin/kmod", 171272, "954714d5862c7081a266babeac7d5dd859e7b0812224dad9a7b81957bf93c629"),
    ("/usr/lib/libkmod.so.2.5.1", 108880, "1326d9860cecc0c6daef966ada6bbf7963028987c7a0bff95ce4b62cb5b3ccb5"),
)
# Canonical original RPM header records across the complete admitted closure.
# Directory sizes normalize to zero; filesystem allocation sizes are not inputs.
INSTALLATION_MODULE_INPUT_COUNT = 1235
INSTALLATION_MODULE_INPUT_BYTES = 37958620
INSTALLATION_MODULE_INPUT_SHA256 = "27c70106fd4ae16b0de330b4200254c545f4991559815e64fdecf957bf6ca927"
INSTALLATION_MODULE_NAMESPACE_SHA256 = "4ac74c113a8e332683882d31856cc2b4799eb6f1f20f40fc45a23b52398b3ded"
INSTALLATION_MODULE_GENERATED = frozenset({
    "modules.dep", "modules.dep.bin", "modules.alias", "modules.alias.bin",
    "modules.softdep", "modules.weakdep", "modules.symbols", "modules.symbols.bin",
    "modules.builtin.bin", "modules.builtin.alias.bin", "modules.devname",
})
_INSTALLATION_STABLE_FIELDS = (
    "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
    "st_size", "st_mtime_ns", "st_ctime_ns",
)
INSTALLATION_MODULE_GENERATED_PATHS = frozenset(
    "/lib/modules/6.12.114-1.ph5/" + name for name in INSTALLATION_MODULE_GENERATED
)
INSTALLATION_LAYOUT_HELPER_PATH = Path(__file__).resolve().parents[3] / "scripts/installation/layout.py"
INSTALLATION_LAYOUT_HELPER_SHA256 = "1feb571697f3a1e592e3839bc303cd4c20cd8d40f7acd4e3d7df93449de99608"
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
    "iproute2",
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


def _verify_installation_runtime_mount(
    mounts: list[tuple[list[str], list[str]]], name: str, filesystem: str, mode: int
) -> None:
    """Require one native runtime mount with the admitted root metadata.

    Args:
        mounts: Bounded mount rows from the existing private reader.
        name: Fixed mount point selected by an installation profile.
        filesystem: Native filesystem required by that profile.
        mode: Expected native mount-point permission bits.
    """
    metadata = Path(name).lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != 0 or metadata.st_gid != 0):
        raise ValueError("installation runtime mount metadata differs")
    rows = [row for row in mounts if row[0][4] == name]
    if len(rows) != 1 or rows[0][0][3] != "/" or rows[0][1][0] != filesystem:
        raise ValueError("installation runtime mount identity differs")


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
        _verify_installation_runtime_mount(mounts, name, filesystem, mode)
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


def _read_installation_tmpfiles(
    path: Path, mode: int, maximum_bytes: int, policy_name: str, *, directory_fd: int | None = None,
    allow_empty: bool = False,
) -> bytes:
    """Read the admitted tmpfiles policy through a bounded no-follow handle.

    Args:
        path: Fixed public policy path selected by the package profile.
        mode: Native packaged permission bits for that policy.
        maximum_bytes: Maximum policy size admitted by the profile.
        policy_name: Fixed package name used in non-secret error categories.
        directory_fd: Optional pinned parent for descriptor-relative module reads.
        allow_empty: Admit empty native index output only when explicitly requested.

    This reads public package policy only. Root ownership, ordinary-file identity
    and stable metadata are checked before the caller verifies its pinned bytes.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError(f"installation {policy_name} tmpfiles policy cannot be opened without following links")
    try:
        descriptor = (os.open(path, os.O_RDONLY | nofollow) if directory_fd is None else
                      os.open(path, os.O_RDONLY | nofollow | os.O_NONBLOCK, dir_fd=directory_fd))
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
                or not (0 if allow_empty else 1) <= metadata.st_size <= maximum_bytes
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


def verify_installation_openldap_metadata(openldap_sha256: str) -> dict[str, bool]:
    """Prove the initial disabled LDAP service's volatile directory is absent.

    Args:
        openldap_sha256: Original OpenLDAP server RPM checksum admitted from the ISO.

    Reuse the bounded public policy reader and runtime mount validator. The
    native unit declares no RuntimeDirectory; Atlaso's existing LDAP helper
    creates /run/openldap when enabling LDAP. This profile applies only to the
    inactive, disabled initial service and reads no LDAP configuration or data.
    """
    if openldap_sha256 != INSTALLATION_OPENLDAP_SHA256:
        raise ValueError("OpenLDAP runtime metadata profile is not admitted")
    unit = _read_installation_tmpfiles(INSTALLATION_OPENLDAP_UNIT_PATH, 0o644, 4096, "OpenLDAP")
    if hashlib.sha256(unit).hexdigest() != INSTALLATION_OPENLDAP_UNIT_SHA256:
        raise ValueError("installation OpenLDAP unit differs from native policy")
    _verify_installation_runtime_mount(_installation_mount_rows(), "/run", "tmpfs", 0o755)
    try:
        parent, alias = Path("/var").lstat(), Path("/var/run").lstat()
        if (not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o755
                or parent.st_uid != 0 or parent.st_gid != 0
                or not stat.S_ISLNK(alias.st_mode) or alias.st_nlink != 1
                or alias.st_uid != 0 or alias.st_gid != 0
                or Path("/var/run").readlink().as_posix() != "../run"):
            raise ValueError("installation OpenLDAP runtime alias differs from native policy")
    except OSError as exc:
        raise ValueError("installation OpenLDAP runtime alias is unavailable") from exc
    for path in (Path("/run/openldap"), Path("/var/run/openldap")):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise ValueError("installation initial OpenLDAP runtime directory must be absent")
    try:
        completed = subprocess.run(
            ["/usr/bin/systemctl", "show", "slapd.service", "--no-pager", "--property=LoadState",
             "--property=ActiveState", "--property=SubState", "--property=UnitFileState"],
            check=False, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("installation OpenLDAP service state is unavailable") from exc
    if completed.returncode or completed.stderr or len(completed.stdout) > 2048:
        raise ValueError("installation OpenLDAP service state is unavailable")
    states = {}
    for row in completed.stdout.splitlines():
        key, separator, value = row.partition("=")
        if not separator or key in states:
            raise ValueError("installation OpenLDAP service state is malformed")
        states[key] = value
    if states != {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled"}:
        raise ValueError("installation OpenLDAP service is not in its initial disabled state")
    return {"runtime_openldap_metadata_verified": True}


def _installation_directory_names(descriptor: int, maximum: int) -> list[str]:
    """Enumerate a pinned directory without materializing unbounded names.

    Args:
        descriptor: Retained ordinary-directory descriptor.
        maximum: Maximum admitted immediate-entry count.
    """
    if os.scandir not in os.supports_fd:
        raise ValueError("installation descriptor enumeration is unavailable")
    names = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= maximum:
                raise ValueError("installation directory namespace exceeds its bound")
            names.append(entry.name)
    return sorted(names)


def _installation_directory_pin(path: Path, parent_fd: int | None, mode: int, device: int | None = None) -> int:
    """Retain an ordinary native directory through its admitted parent.

    Args:
        path: Fixed path or single relative component.
        parent_fd: Retained parent, or None for the initial absolute root.
        mode: Exact ordinary-directory permission bits.
        device: Optional filesystem identity required for scratch descendants.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
    original = (os.stat(path, follow_symlinks=False) if parent_fd is None else
                os.stat(path, dir_fd=parent_fd, follow_symlinks=False))
    descriptor = os.open(path, flags) if parent_fd is None else os.open(path, flags, dir_fd=parent_fd)
    try:
        metadata = os.fstat(descriptor)
        if (any(getattr(metadata, field) != getattr(original, field) for field in _INSTALLATION_STABLE_FIELDS)
                or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid or metadata.st_gid
                or stat.S_IMODE(metadata.st_mode) != mode
                or (device is not None and metadata.st_dev != device)):
            raise ValueError("installation native directory metadata differs")
    except (OSError, ValueError):
        os.close(descriptor)
        raise
    return descriptor


def _installation_module_snapshot(root_fd: int) -> tuple[dict[str, tuple], dict[str, bytes]]:
    """Measure the complete native module inputs through a retained directory.

    Args:
        root_fd: Already pinned, no-follow descriptor for the fixed module root.

    All paths are fixed package inputs. Unknown namespace entries change the
    aggregate rather than becoming exclusions. Only the eleven native root index
    files are returned separately for the later derivation proof. No contents or
    child names are emitted in errors or public reports.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (nofollow is None or directory is None or not hasattr(os, "O_NONBLOCK")
            or os.scandir not in os.supports_fd):
        raise ValueError("installation module descriptor traversal is unavailable")
    device = os.fstat(root_fd).st_dev
    records = []
    stamps = {}
    indexes = {}
    total = 0
    generated_bytes = 0
    admitted = None

    def stamp(metadata: os.stat_result) -> tuple:
        """Keep original identities and metadata for a complete stability check.

        Args:
            metadata: Metadata observed through the pinned parent or object.
        """
        return tuple(getattr(metadata, field) for field in _INSTALLATION_STABLE_FIELDS)

    def visit(descriptor: int, relative: str, depth: int, read_files: bool) -> None:
        """Inspect one pinned directory without following any child link.

        Args:
            descriptor: Retained ordinary-directory descriptor.
            relative: Public package-relative directory name.
            depth: Current bounded traversal depth.
            read_files: Read bytes only after the complete public namespace passes.
        """
        nonlocal total, generated_bytes
        before = os.fstat(descriptor)
        if (depth > 32 or not stat.S_ISDIR(before.st_mode) or before.st_uid or before.st_gid
                or stat.S_IMODE(before.st_mode) != 0o755 or before.st_dev != device):
            raise ValueError("installation module directory metadata differs")
        stamps[relative] = stamp(before)
        if admitted is not None and admitted.get(relative) != stamp(before):
            raise ValueError("installation module directory changed after admission")
        names = _installation_directory_names(descriptor, 2048 - len(stamps))
        for name in names:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", name):
                raise ValueError("installation module namespace differs")
            child = relative + "/" + name if relative else name
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if metadata.st_dev != device:
                raise ValueError("installation module filesystem differs")
            if admitted is not None and admitted.get(child) != stamp(metadata):
                raise ValueError("installation module entry changed after admission")
            if stat.S_ISDIR(metadata.st_mode):
                nested = os.open(name, os.O_RDONLY | nofollow | directory, dir_fd=descriptor)
                try:
                    if stamp(os.fstat(nested)) != stamp(metadata):
                        raise ValueError("installation module directory changed")
                    records.append([child, "d", stat.S_IMODE(metadata.st_mode), 0, "", "root", "root"])
                    visit(nested, child, depth + 1, read_files)
                finally:
                    os.close(nested)
            elif stat.S_ISREG(metadata.st_mode):
                if (metadata.st_nlink != 1 or metadata.st_uid or metadata.st_gid
                        or stat.S_IMODE(metadata.st_mode) != 0o644
                        or not (0 if not relative and name in INSTALLATION_MODULE_GENERATED else 1) <= metadata.st_size <= 8 * 1024 * 1024):
                    raise ValueError("installation module file metadata differs")
                if not relative and name in INSTALLATION_MODULE_GENERATED:
                    generated_bytes += metadata.st_size
                    if generated_bytes > 16 * 1024 * 1024:
                        raise ValueError("installation module indexes exceed their bound")
                data = _read_installation_tmpfiles(
                    Path(name), 0o644, 8 * 1024 * 1024, "module input", directory_fd=descriptor,
                    allow_empty=not relative and name in INSTALLATION_MODULE_GENERATED
                ) if read_files else b""
                stamps[child] = stamp(metadata)
                if not relative and name in INSTALLATION_MODULE_GENERATED:
                    indexes[name] = data
                else:
                    total += metadata.st_size
                    if total > 64 * 1024 * 1024:
                        raise ValueError("installation module inputs exceed their bound")
                    records.append([child, "f", stat.S_IMODE(metadata.st_mode), metadata.st_size,
                                    hashlib.sha256(data).hexdigest() if read_files else "", "root", "root"])
            else:
                raise ValueError("installation module entry type differs")
            if stamp(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != stamp(metadata):
                raise ValueError("installation module entry changed")
        if stamp(os.fstat(descriptor)) != stamp(before):
            raise ValueError("installation module directory changed")

    # Unknown/private additions are rejected from public names and metadata
    # before any file content is opened. The second pass retains those exact
    # identities and stamps, including parent-directory namespace changes.
    visit(root_fd, "", 0, False)
    digest = hashlib.sha256(json.dumps(sorted(records), separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    if (len(records) != INSTALLATION_MODULE_INPUT_COUNT or total != INSTALLATION_MODULE_INPUT_BYTES
            or digest != INSTALLATION_MODULE_NAMESPACE_SHA256 or set(indexes) != INSTALLATION_MODULE_GENERATED):
        raise ValueError("installation module namespace differs from original RPM inputs")
    admitted = dict(stamps)
    records.clear()
    stamps.clear()
    indexes.clear()
    total = 0
    generated_bytes = 0
    visit(root_fd, "", 0, True)
    digest = hashlib.sha256(json.dumps(sorted(records), separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    if (len(records) != INSTALLATION_MODULE_INPUT_COUNT or total != INSTALLATION_MODULE_INPUT_BYTES
            or digest != INSTALLATION_MODULE_INPUT_SHA256 or set(indexes) != INSTALLATION_MODULE_GENERATED):
        raise ValueError("installation module inputs differ from original RPM namespace")
    return stamps, indexes


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


def verify_installation_module_indexes() -> dict[str, bool]:
    """Derive native indexes from the complete original, immutable module inputs.

    The caller must first verify the admitted RPM package files and native
    metadata profiles. Only this fixed native derivation runs, with no inherited
    environment, external configuration or persistent output. Any mismatch fails;
    this function never repairs the installed module tree.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (nofollow is None or directory is None or not hasattr(os, "O_NONBLOCK")
            or os.scandir not in os.supports_fd):
        raise ValueError("installation native module pins are unavailable")
    layout = _verified_installation_layout()
    layout_pin = json.dumps(layout, sort_keys=True)
    recorded = {item["target"] for item in layout["mounts"]}
    ancestors = {"/usr", "/usr/bin", "/usr/lib", "/usr/lib/modules", str(INSTALLATION_MODULE_ROOT)}
    native_paths = {"/etc", "/usr/local", "/usr/local/lib", "/lib", "/lib64",
                    "/usr/lib/libkmod.so.2", *[name for name, _size, _checksum in INSTALLATION_KMOD_FILES]}
    config_paths = {base + "/depmod.d" for base in ("/etc", "/run", "/usr/local/lib", "/usr/lib", "/lib")}
    stage_name = ".atlaso-depmod-" + str(os.getpid())
    output = INSTALLATION_MODULE_RUN_ROOT / stage_name

    def mount_pin() -> tuple:
        """Revalidate native input and scratch mounts without following child data."""
        rows = _installation_mount_rows()
        for fields, _tail in rows:
            point = fields[4]
            if ((point in ancestors | native_paths and point not in recorded)
                    or any(point == name or point.startswith(name + "/") for name in config_paths)
                    or point.startswith(str(INSTALLATION_MODULE_ROOT) + "/")
                    or point == "/proc/" + str(os.getpid())
                    or point.startswith("/proc/" + str(os.getpid()) + "/")
                    or point == str(output) or point.startswith(str(output) + "/")):
                raise ValueError("installation module mount differs from recorded layout")
        _verify_installation_runtime_mount(rows, str(INSTALLATION_MODULE_RUN_ROOT), "tmpfs", 0o755)
        _verify_installation_runtime_mount(rows, "/proc", "proc", 0o555)
        relevant = ancestors | native_paths | {str(Path("/")), str(INSTALLATION_MODULE_RUN_ROOT), "/proc"}
        return tuple((tuple(fields), tuple(tail)) for fields, tail in rows if fields[4] in relevant)

    mounts = mount_pin()
    with ExitStack() as pins:
        descriptors = {}
        originals = {}
        for path in [Path("/"), Path("/usr"), Path("/usr/bin"), Path("/usr/lib"),
                     Path("/usr/lib/modules"), INSTALLATION_MODULE_ROOT]:
            fd = _installation_directory_pin(path if path == Path("/") else Path(path.name),
                                             None if path == Path("/") else descriptors[path.parent], 0o755)
            pins.callback(os.close, fd)
            metadata = os.fstat(fd)
            descriptors[path] = fd
            originals[path] = tuple(getattr(metadata, field) for field in _INSTALLATION_STABLE_FIELDS)
        missing = []
        for path in (Path("/etc"), INSTALLATION_MODULE_RUN_ROOT, Path("/usr/local"), Path("/usr/local/lib")):
            if path.parent not in descriptors:
                continue
            parent = descriptors[path.parent]
            try:
                fd = _installation_directory_pin(Path(path.name), parent, 0o755)
            except FileNotFoundError:
                if path in {Path("/etc"), INSTALLATION_MODULE_RUN_ROOT}:
                    raise ValueError("installation native required directory is missing") from None
                missing.append((path, parent))
                continue
            pins.callback(os.close, fd)
            descriptors[path] = fd
            originals[path] = tuple(getattr(os.fstat(fd), field) for field in _INSTALLATION_STABLE_FIELDS)
        aliases = {Path("/lib"): "usr/lib", Path("/lib64"): "usr/lib",
                   Path("/usr/lib/libkmod.so.2"): "libkmod.so.2.5.1"}
        alias_stamps = {}
        for path, target in aliases.items():
            parent = descriptors[path.parent]
            metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid or metadata.st_gid
                    or metadata.st_nlink != 1 or os.readlink(path.name, dir_fd=parent) != target):
                raise ValueError("installation native module alias differs")
            alias_stamps[path] = tuple(getattr(metadata, field) for field in _INSTALLATION_STABLE_FIELDS)
        # Refuse override contents without reading their names or configuration.
        configuration = []
        for base in (Path("/etc"), INSTALLATION_MODULE_RUN_ROOT, Path("/usr/local/lib"), Path("/usr/lib")):
            if base not in descriptors:
                continue
            path = base / "depmod.d"
            parent = descriptors[base]
            try:
                metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                missing.append((path, parent))
                continue
            fd = _installation_directory_pin(Path(path.name), parent, 0o755)
            pins.callback(os.close, fd)
            if (any(getattr(os.fstat(fd), field) != getattr(metadata, field) for field in _INSTALLATION_STABLE_FIELDS)
                    or _installation_directory_names(fd, 1)):
                raise ValueError("installation native depmod overrides are unsupported")
            configuration.append(fd)
            originals[path] = tuple(getattr(metadata, field) for field in _INSTALLATION_STABLE_FIELDS)
        binaries = {}
        for name, size, checksum in INSTALLATION_KMOD_FILES:
            path = Path(name)
            metadata = os.stat(path.name, dir_fd=descriptors[path.parent], follow_symlinks=False)
            binaries[path] = tuple(getattr(metadata, field) for field in _INSTALLATION_STABLE_FIELDS)
            raw = _read_installation_tmpfiles(path.relative_to(path.parent), 0o755, size,
                                             "native kmod", directory_fd=descriptors[path.parent])
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError("installation native kmod bytes differ")
        module_fd = descriptors[INSTALLATION_MODULE_ROOT]
        before, indexes = _installation_module_snapshot(module_fd)
        # Create exclusively through the verified RAM parent. On any failure,
        # leave this finite public scratch for the owning VM stop; never traverse
        # ambiguous state recursively during exception cleanup.
        run_fd = descriptors[INSTALLATION_MODULE_RUN_ROOT]
        device = os.fstat(run_fd).st_dev
        try:
            os.mkdir(stage_name, 0o700, dir_fd=run_fd)
        except FileExistsError:
            raise ValueError("installation native module scratch already exists") from None
        output_fd = _installation_directory_pin(Path(stage_name), run_fd, 0o700, device)
        pins.callback(os.close, output_fd)
        levels = [(output, output_fd)]
        parent = output_fd
        current = output
        for name in ("usr", "lib", "modules", INSTALLATION_MODULE_ROOT.name):
            os.mkdir(name, 0o700, dir_fd=parent)
            child = _installation_directory_pin(Path(name), parent, 0o700, device)
            pins.callback(os.close, child)
            current = current / name
            levels.append((current, child))
            parent = child
        generated_fd = parent
        # Native writes change only this owned leaf. Keep every ancestor's
        # original identity/metadata through execution and all comparisons.
        level_stamps = {path: tuple(getattr(os.fstat(fd), field) for field in _INSTALLATION_STABLE_FIELDS)
                        for path, fd in levels}
        if mount_pin() != mounts:
            raise ValueError("installation native mounts changed")
        try:
            result = subprocess.run(
                ["depmod", "-a", "-b", "/", "-m", "/usr/lib/modules",
                 "-o", "/proc/" + str(os.getpid()) + "/fd/" + str(output_fd), "-C", "/dev/null", INSTALLATION_MODULE_ROOT.name],
                executable="/usr/bin/kmod",
                cwd="/", env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=60, check=False, umask=0o022,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError("installation native module derivation failed") from None
        if result.returncode or result.stdout or result.stderr:
            raise ValueError("installation native module derivation failed")
        if mount_pin() != mounts:
            raise ValueError("installation native mounts changed")
        if set(_installation_directory_names(generated_fd, 11)) != INSTALLATION_MODULE_GENERATED:
            raise ValueError("installation native module output namespace differs")
        leaf_before = os.fstat(generated_fd)
        total_output = 0
        output_stamps = {}
        for name in INSTALLATION_MODULE_GENERATED:
            before_file = os.stat(name, dir_fd=generated_fd, follow_symlinks=False)
            output_stamps[name] = tuple(getattr(before_file, field) for field in _INSTALLATION_STABLE_FIELDS)
            total_output += before_file.st_size
            if before_file.st_dev != device or total_output > 16 * 1024 * 1024:
                raise ValueError("installation native module output bound differs")
            raw = _read_installation_tmpfiles(Path(name), 0o644, 8 * 1024 * 1024,
                                             "derived module index", directory_fd=generated_fd, allow_empty=True)
            after_file = os.stat(name, dir_fd=generated_fd, follow_symlinks=False)
            if (any(getattr(before_file, field) != getattr(after_file, field)
                    for field in _INSTALLATION_STABLE_FIELDS) or raw != indexes[name]):
                raise ValueError("installation native module index bytes or identity differ")
        if any(getattr(os.fstat(generated_fd), field) != getattr(leaf_before, field)
               for field in _INSTALLATION_STABLE_FIELDS):
            raise ValueError("installation native module output changed")
        after, unchanged = _installation_module_snapshot(module_fd)
        if after != before or unchanged != indexes:
            raise ValueError("installation native module inputs or outputs changed")
        for name, size, checksum in INSTALLATION_KMOD_FILES:
            path = Path(name)
            raw = _read_installation_tmpfiles(Path(path.name), 0o755, size, "native kmod",
                                             directory_fd=descriptors[path.parent])
            metadata = os.stat(path.name, dir_fd=descriptors[path.parent], follow_symlinks=False)
            if (len(raw) != size or hashlib.sha256(raw).hexdigest() != checksum
                    or tuple(getattr(metadata, field) for field in _INSTALLATION_STABLE_FIELDS) != binaries[path]):
                raise ValueError("installation native kmod changed")
        for path, parent in missing:
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("installation native configuration namespace changed")
        for fd in configuration:
            if _installation_directory_names(fd, 1):
                raise ValueError("installation native depmod configuration changed")
        for path, original in originals.items():
            current = path.lstat()
            # The owned scratch directory changes /run's namespace timestamps.
            # Its mount, object identity and ownership remain independently fixed.
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid") if path == INSTALLATION_MODULE_RUN_ROOT else _INSTALLATION_STABLE_FIELDS
            if any(getattr(current, field) != original[_INSTALLATION_STABLE_FIELDS.index(field)] for field in fields):
                raise ValueError("installation native directory changed")
        for path, original in alias_stamps.items():
            current = path.lstat()
            if tuple(getattr(current, field) for field in _INSTALLATION_STABLE_FIELDS) != original:
                raise ValueError("installation native module alias changed")
        if json.dumps(_verified_installation_layout(), sort_keys=True) != layout_pin or mount_pin() != mounts:
            raise ValueError("installation native layout or mounts changed")
        identity_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid")
        for index, (path, fd) in enumerate(levels):
            parent_fd = run_fd if index == 0 else levels[index - 1][1]
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            original = level_stamps[path]
            selected = identity_fields if fd == generated_fd else _INSTALLATION_STABLE_FIELDS
            if any(getattr(current, field) != original[_INSTALLATION_STABLE_FIELDS.index(field)]
                   for field in selected):
                raise ValueError("installation native module output ancestor changed")
        # Remove only the exact successfully verified files and then empty
        # creation-owned directories, always relative to retained parents.
        if set(_installation_directory_names(generated_fd, 11)) != INSTALLATION_MODULE_GENERATED:
            raise ValueError("installation native module cleanup namespace changed")
        for name in sorted(INSTALLATION_MODULE_GENERATED):
            current = os.stat(name, dir_fd=generated_fd, follow_symlinks=False)
            if tuple(getattr(current, field) for field in _INSTALLATION_STABLE_FIELDS) != output_stamps[name]:
                raise ValueError("installation native module cleanup file changed")
            os.unlink(name, dir_fd=generated_fd)
        for index in range(len(levels) - 1, -1, -1):
            path, fd = levels[index]
            parent_fd = run_fd if index == 0 else levels[index - 1][1]
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            original = level_stamps[path]
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
            if (_installation_directory_names(fd, 1)
                    or any(getattr(current, field) != original[_INSTALLATION_STABLE_FIELDS.index(field)]
                           for field in fields)):
                raise ValueError("installation native module cleanup directory changed")
            os.rmdir(path.name, dir_fd=parent_fd)
    return {"runtime_module_indexes_verified": True}


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
    filesystem_sha256: str = INSTALLATION_FILESYSTEM_SHA256,
    systemd_sha256: str = INSTALLATION_SYSTEMD_SHA256,
    audit_sha256: str = INSTALLATION_AUDIT_SHA256,
    rpcbind_sha256: str = INSTALLATION_RPCBIND_SHA256,
    shim_sha256: str = INSTALLATION_SHIM_SHA256,
    grub_efi_sha256: str = INSTALLATION_GRUB_EFI_SHA256,
    openssh_sha256: str = INSTALLATION_OPENSSH_SHA256,
    openldap_sha256: str = INSTALLATION_OPENLDAP_SHA256,
) -> dict[str, bool]:
    """Reuse the admitted native profiles before or after package comparison.

    Pinned defaults avoid transmitting duplicate constants after host media and
    helper admission. Explicit callers retain every mismatched-pin refusal.

    Args:
        filesystem_sha256: Original Photon filesystem RPM checksum.
        systemd_sha256: Original Photon systemd RPM checksum.
        audit_sha256: Original Photon audit RPM checksum.
        rpcbind_sha256: Original Photon rpcbind RPM checksum.
        shim_sha256: Original Photon shim RPM checksum.
        grub_efi_sha256: Original Photon GRUB EFI-image RPM checksum.
        openssh_sha256: Original Photon OpenSSH server RPM checksum.
        openldap_sha256: Original Photon OpenLDAP server RPM checksum.
    """
    result = verify_installation_runtime_metadata(filesystem_sha256)
    result.update(verify_installation_journal_metadata(systemd_sha256))
    result.update(verify_installation_audit_metadata(audit_sha256))
    result.update(verify_installation_rpcbind_metadata(rpcbind_sha256))
    result.update(verify_installation_openssh_metadata(openssh_sha256))
    result.update(verify_installation_openldap_metadata(openldap_sha256))
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
