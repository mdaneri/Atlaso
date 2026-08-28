#!/usr/bin/env python3
"""Verify Photon release identity and package-manager runtime prerequisites."""

from __future__ import annotations

import argparse
import configparser
import re
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

PACKAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:-]*\Z")
PHOTON_DEFAULT_DISTROVERPKG = "photon-release"
REQUIRED_RUNTIME_PACKAGES = ("photon-release", "rpm", "tdnf", "python3", "powershell")


def read_os_release(path: Path) -> dict[str, str]:
    """Return the bounded key/value fields from one os-release file."""

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
    """Return the exact package identity configured by TDNF."""

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
    """Require every named runtime RPM to remain installed."""

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


def verify_photon_package_state(
    *,
    os_release_path: Path,
    photon_release_path: Path,
    tdnf_config_path: Path,
    guest_platform: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Verify release files, TDNF identity, and required runtime RPMs."""

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
    return distroverpkg


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os-release", type=Path, default=Path("/etc/os-release"))
    parser.add_argument(
        "--photon-release", type=Path, default=Path("/etc/photon-release")
    )
    parser.add_argument("--tdnf-config", type=Path, default=Path("/etc/tdnf/tdnf.conf"))
    parser.add_argument("--guest-platform", choices=("vmware", "none"), required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Photon package-state verification."""

    args = parse_args(argv)
    try:
        distroverpkg = verify_photon_package_state(
            os_release_path=args.os_release,
            photon_release_path=args.photon_release,
            tdnf_config_path=args.tdnf_config,
            guest_platform=args.guest_platform,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"Photon package runtime verification failed: {exc}") from exc
    print(f"Photon package runtime verified with distroverpkg {distroverpkg}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
