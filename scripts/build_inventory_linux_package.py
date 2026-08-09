#!/usr/bin/env python3
"""Provide the build inventory linux package repository utility."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$")


def sha256(path: Path) -> str:
    """Return sha256.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def package_inventory_linux(source: Path, output: Path) -> Path:
    """Return package inventory linux.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    manifest_path = source / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Inventory Linux manifest is missing or invalid: {manifest_path}") from exc
    version = str(manifest.get("version") or "")
    if (
        manifest.get("kind") != "atlaso-inventory-linux"
        or manifest.get("schema_version") != 1
        or INVENTORY_VERSION_RE.fullmatch(version) is None
    ):
        raise SystemExit(
            "Inventory Linux manifest identity is invalid; version must use X.Y.Z+revision."
        )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise SystemExit("Inventory Linux manifest artifacts are invalid.")
    required = [manifest_path, source / "bzImage", source / "rootfs.cpio.gz"]
    for path in required:
        if not path.is_file():
            raise SystemExit(f"Inventory Linux package input is missing: {path}")
    for name in ("bzImage", "rootfs.cpio.gz"):
        expected = str(artifacts.get(name) or "").lower()
        if sha256(source / name) != expected:
            raise SystemExit(f"Inventory Linux artifact digest mismatch: {name}")
    legal_root = source / "legal-info"
    if not legal_root.is_dir():
        raise SystemExit(f"Inventory Linux legal metadata is missing: {legal_root}")

    output.mkdir(parents=True, exist_ok=True)
    package = output / f"atlaso-inventory-linux-{version}.zip"
    entries = required + sorted(path for path in legal_root.rglob("*") if path.is_file())
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in entries:
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return package


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser(description="Build the reproducible Atlaso Inventory Linux release package.")
    parser.add_argument("--source", type=Path, default=ROOT / "image/inventory-linux/output")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/inventory-linux")
    args = parser.parse_args()
    package = package_inventory_linux(args.source.resolve(), args.output.resolve())
    print(json.dumps({"package": str(package), "sha256": sha256(package)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
