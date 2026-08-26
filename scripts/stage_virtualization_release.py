#!/usr/bin/env python3
"""Stage one exact validated Atlaso virtualization asset set for publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if not __package__:
    sys.path.insert(0, str(ROOT))

from scripts.publish_release import (  # noqa: E402
    MAXIMUM_GITHUB_ASSET_BYTES,
    verify_vmware_release_assets,
)

SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VMWARE_SUFFIXES = (".ova", ".ovf", ".mf", ".vmdk", "-provenance.json")
RELEASE_HELPERS = (
    ROOT / "scripts" / "virtualization" / "templates" / "import-atlaso-proxmox.sh",
    ROOT / "scripts" / "virtualization" / "templates" / "import-atlaso-kvm.sh",
    ROOT / "scripts" / "virtualization" / "validate_ova.py",
    ROOT / "scripts" / "virtualization" / "normalize_libvirt.py",
)


def _sha256(path: Path) -> str:
    """Return one file's SHA-256 digest."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ordinary_asset(path: Path, label: str) -> Path:
    """Return a bounded ordinary release asset path."""

    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} must be an ordinary file, not a symlink: {path}")
    size = path.stat().st_size
    if size <= 0 or size >= MAXIMUM_GITHUB_ASSET_BYTES:
        raise SystemExit(f"{label} is empty or exceeds the GitHub asset limit: {path.name}")
    return path.resolve(strict=True)


def _copy_exact(source: Path, destination: Path) -> None:
    """Copy one asset without replacing different existing bytes."""

    if destination.exists() or destination.is_symlink():
        if not destination.is_file() or destination.is_symlink() or _sha256(source) != _sha256(destination):
            raise SystemExit(f"release staging destination already contains different bytes: {destination.name}")
        return
    shutil.copy2(source, destination)
    if _sha256(source) != _sha256(destination):
        raise SystemExit(f"release staging copy verification failed: {destination.name}")


def stage(
    *,
    ova_directory: Path,
    hyperv_zip: Path,
    output: Path,
    version: str,
    commit: str,
) -> list[str]:
    """Validate and stage the complete virtualization release asset set."""

    if SEMVER_PATTERN.fullmatch(version) is None or COMMIT_PATTERN.fullmatch(commit) is None:
        raise SystemExit("version or source commit has an invalid release identity")
    if ova_directory.is_symlink() or not ova_directory.is_dir():
        raise SystemExit("OVA package source must be an ordinary directory")
    ova_root = ova_directory.resolve(strict=True)
    vmware_sources = sorted(
        path for path in ova_root.iterdir() if path.is_file() and path.name.lower().endswith(VMWARE_SUFFIXES)
    )
    vmware_names = {path.name for path in vmware_sources}
    verify_vmware_release_assets(
        ova_root,
        vmware_names,
        expected_version=version,
        expected_commit=commit,
    )
    expected_hyperv_name = f"atlaso-v{version}-hyperv-x86_64.zip"
    hyperv_source = _ordinary_asset(hyperv_zip, "Hyper-V package")
    if hyperv_source.name != expected_hyperv_name:
        raise SystemExit(f"Hyper-V package must be named {expected_hyperv_name}")
    sources = [*_ordinary_sources(vmware_sources), hyperv_source]
    sources.extend(_ordinary_asset(path, "virtualization import helper") for path in RELEASE_HELPERS)
    expected_names = {source.name for source in sources}
    if len(expected_names) != len(sources):
        raise SystemExit("virtualization release sources must have unique flat names")

    if output.exists() and (output.is_symlink() or not output.is_dir()):
        raise SystemExit("release staging output must be an ordinary directory")
    output.mkdir(parents=True, exist_ok=True)
    output_root = output.resolve(strict=True)
    if output_root == ova_root or ova_root in output_root.parents:
        raise SystemExit("release staging output cannot be the OVA source or its descendant")
    existing_names = {entry.name for entry in output_root.iterdir()}
    unexpected_names = sorted(existing_names - expected_names)
    if unexpected_names:
        raise SystemExit(f"release staging output contains unexpected assets: {unexpected_names}")
    for source in sources:
        _copy_exact(source, output_root / source.name)
    staged_names = {entry.name for entry in output_root.iterdir()}
    if staged_names != expected_names:
        raise SystemExit("release staging output does not contain the exact virtualization asset set")
    return sorted(expected_names)


def _ordinary_sources(paths: list[Path]) -> list[Path]:
    """Validate and return an ordered collection of ordinary source assets."""

    return [_ordinary_asset(path, "VMware OVA package asset") for path in paths]


def main(argv: list[str] | None = None) -> int:
    """Run the staging command-line interface."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ova-directory", type=Path, required=True)
    parser.add_argument("--hyperv-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)
    staged = stage(
        ova_directory=args.ova_directory,
        hyperv_zip=args.hyperv_zip,
        output=args.output,
        version=args.version,
        commit=args.commit,
    )
    print(json.dumps({"assets": staged, "count": len(staged)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
