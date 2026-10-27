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

    mounts = []
    for row in _read_installation_mountinfo().splitlines():
        before, separator, after = row.partition(" - ")
        fields, filesystem_fields = before.split(), after.split()
        if not separator or len(fields) < 6 or len(filesystem_fields) < 3:
            raise ValueError("installation runtime mount table is malformed")
        mounts.append((fields, filesystem_fields))
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
