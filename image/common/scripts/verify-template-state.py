#!/usr/bin/env python3
"""Reject reusable templates whose offline tools or deployment state were consumed."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
from pathlib import Path

STAGING = "var/lib/atlaso/first-boot-packages"
FORBIDDEN = (
    "var/lib/atlaso-privileged/guest-agent/guest-agent.applied",
    "var/lib/atlaso/vmware-ovf-customization.applied",
    "var/lib/atlaso/vmware-ovf-customization.pending",
    "var/lib/atlaso/vmware-no-ovf-initialization.applied",
    "var/lib/atlaso/vmware-ovf-initializing",
    "var/lib/atlaso/vmware-ovf-network-review.json",
    "var/lib/atlaso/vmware-ovf-network-correction.json",
    "var/lib/atlaso/first-boot-https.applied",
    "var/lib/atlaso/first-boot-development-root-ca-imported",
    "etc/machine-id",
    "var/lib/dbus/machine-id",
)


def verify_files(files: dict[str, bytes]) -> None:
    """Verify exact offline RPM inventory and both unconsumed provider closures.

    Args:
        files: Regular file bytes relative to the trusted staging directory.
    """
    if "SHA256SUMS" not in files:
        raise SystemExit(
            "Template guest-tool checksum manifest is missing; rebuild the template"
        )
    hashes = {}
    for line in files["SHA256SUMS"].decode("ascii").splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  ((?:hyperv|qemu)/[A-Za-z0-9_.+~-]+\.rpm)", line
        )
        if match is None or match[2] in hashes:
            raise SystemExit("Template guest-tool checksum manifest is invalid")
        hashes[match[2]] = match[1]
    if set(files) != set(hashes) | {"SHA256SUMS"}:
        raise SystemExit(
            "Template guest-tool inventory differs from its checksum manifest"
        )
    for prefix in ("hyperv/hyper-v-", "qemu/atlaso-qemu-guest-agent-"):
        if not any(name.startswith(prefix) for name in hashes):
            raise SystemExit(
                "Template is missing an offline guest agent; rebuild the template"
            )
    for name, digest in hashes.items():
        if hashlib.sha256(files[name]).hexdigest() != digest:
            raise SystemExit(f"Template guest-tool package changed: {name}")


def verify(root: Path) -> None:
    """Inspect a template filesystem without modifying first-boot state.

    Args:
        root: Template filesystem root; defaults to the provisioning guest root.
    """
    for name in FORBIDDEN:
        path = root / name
        if path.exists() or path.is_symlink():
            raise SystemExit(
                f"Template contains consumed deployment state: /{name}; rebuild it"
            )
    if list((root / "etc/ssh").glob("ssh_host_*")):
        raise SystemExit("Template contains generated SSH host identity")
    staging = root / STAGING
    if not staging.is_dir() or staging.is_symlink():
        raise SystemExit("Template offline guest-tool staging is missing or unsafe")
    files = {}
    directories = set()
    for path in (staging, *staging.rglob("*")):
        info = path.lstat()
        if info.st_uid != 0 or info.st_gid != 0:
            raise SystemExit("Template guest-tool staging must be root-owned")
        if stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700:
            if path != staging:
                directories.add(path.relative_to(staging).as_posix())
        elif (
            stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
        ):
            files[path.relative_to(staging).as_posix()] = path.read_bytes()
        else:
            raise SystemExit(
                "Template guest-tool staging has unsafe permissions or file types"
            )
    if directories != {"hyperv", "qemu"}:
        raise SystemExit("Template guest-tool staging has unexpected directories")
    verify_files(files)
    environment = (root / "etc/atlaso/atlaso.env").read_text()
    for name in (
        "ATLASO_SECRET_KEY",
        "ATLASO_SECRETS_KEY",
        "ATLASO_BOOTSTRAP_ADMIN_PASSWORD",
    ):
        matches = [
            line for line in environment.splitlines() if line.startswith(name + "=")
        ]
        if matches != [name + "=INITIALIZATION_REQUIRED"]:
            raise SystemExit("Template contains initialized application identity")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    verify(parser.parse_args().root)
