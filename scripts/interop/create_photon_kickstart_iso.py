#!/usr/bin/env python3
"""Embed Atlaso kickstart and auto-install GRUB config into Photon ISO."""

from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path

GRUB_BOOT_CONFIG = """set default=0
set timeout=1

menuentry 'Install Atlaso Photon OS with kickstart' {
    linux /isolinux/vmlinuz root=/dev/ram0 loglevel=3 ks=cdrom:/photon-ks.json insecure_installation=1 photon.media=cdrom
    initrd /isolinux/initrd.img
}
"""

GRUB_CONFIG_TARGETS = (
    ("/BOOT/GRUB2/GRUB.CFG;1", "grub.cfg"),
    ("/EFI/BOOT/GRUB.CFG;1", "grub.cfg"),
)


def parse_args() -> argparse.Namespace:
    """Parse args.

    Returns:
        The parsed args.
    """
    parser = argparse.ArgumentParser(
        description="Create a Photon ISO with photon-ks.json and an auto-install GRUB entry embedded."
    )
    parser.add_argument("--source-iso", required=True, help="Original Photon ISO path.")
    parser.add_argument("--kickstart", required=True, help="Rendered photon-ks.json path.")
    parser.add_argument("--output", required=True, help="Output ISO path.")
    return parser.parse_args()


def iso_record_exists(iso, *, iso_path: str) -> bool:
    """Return iso record exists.

    Args:
        iso: Iso consumed by ISO record exists.
        iso_path: Filesystem path used for ISO.
    """
    try:
        iso.get_record(iso_path=iso_path)
    except Exception:
        return False
    return True


def remove_file_if_present(iso, *, iso_path: str, rr_name: str) -> None:
    """Remove file if present.

    Args:
        iso: Iso consumed by remove file if present.
        iso_path: Filesystem path used for ISO.
        rr_name: Rr name consumed by remove file if present.
    """
    rr_path = f"{iso_path.rsplit('/', 1)[0].lower()}/{rr_name}"
    for lookup in ({"iso_path": iso_path}, {"rr_path": rr_path}):
        try:
            iso.get_record(**lookup)
        except Exception:
            continue
        iso.rm_file(**lookup)
        return


def replace_text_file(iso, *, iso_path: str, rr_name: str, text: str) -> None:
    """Handle replace text file.

    Args:
        iso: Iso consumed by replace text file.
        iso_path: Filesystem path used for ISO.
        rr_name: Rr name consumed by replace text file.
        text: Text content consumed by the operation.


    Raises:
        ValueError: If an input value is invalid.
    """
    parent_iso_path = iso_path.rsplit("/", 1)[0]
    if not iso_record_exists(iso, iso_path=parent_iso_path):
        raise ValueError(f"ISO parent path is missing: {parent_iso_path}")

    remove_file_if_present(iso, iso_path=iso_path, rr_name=rr_name)
    payload = text.encode("utf-8")
    iso.add_fp(io.BytesIO(payload), len(payload), iso_path=iso_path, rr_name=rr_name)


def replace_grub_config(iso) -> str:
    """Return replace grub config.

    Args:
        iso: Iso consumed by replace grub config.


    Raises:
        RuntimeError: If the operation cannot be completed safely.
    """
    failures = []
    for iso_path, rr_name in GRUB_CONFIG_TARGETS:
        try:
            replace_text_file(iso, iso_path=iso_path, rr_name=rr_name, text=GRUB_BOOT_CONFIG)
        except Exception as exc:
            failures.append(f"{iso_path}: {exc}")
            continue
        return iso_path

    targets = ", ".join(iso_path for iso_path, _ in GRUB_CONFIG_TARGETS)
    detail = "; ".join(failures)
    raise RuntimeError(f"Could not embed Atlaso GRUB config. Tried: {targets}. {detail}")


def unlink_with_retry(path: Path) -> None:
    """Handle unlink with retry.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    for attempt in range(10):
        try:
            path.unlink()
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.5)


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    try:
        import pycdlib
    except ImportError:
        print("pycdlib is required. Install it with: python -m pip install pycdlib", file=sys.stderr)
        return 2

    args = parse_args()
    source_iso = Path(args.source_iso)
    kickstart = Path(args.kickstart)
    output = Path(args.output)

    if not source_iso.is_file():
        print(f"Source ISO not found: {source_iso}", file=sys.stderr)
        return 2
    if not kickstart.is_file():
        print(f"Kickstart file not found: {kickstart}", file=sys.stderr)
        return 2

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        unlink_with_retry(output)

    iso = pycdlib.PyCdlib()
    iso.open(str(source_iso))
    try:
        iso.add_file(str(kickstart), iso_path="/PHOTONKS.JSON;1", rr_name="photon-ks.json")
        grub_path = replace_grub_config(iso)
        iso.write(str(output))
    finally:
        iso.close()

    print(f"embedded GRUB auto-install config at {grub_path}", file=sys.stderr)
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
