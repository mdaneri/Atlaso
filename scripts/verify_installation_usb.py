#!/usr/bin/env python3
"""Read back an Atlaso ISO's USB layout and optionally compare a written device."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
from pathlib import Path
from typing import BinaryIO


def inspect_layout(image: Path) -> dict:
    """Check the disk EFI partition against the preserved optical boot catalog.

    Args:
        image: Already signature-verified, reconstructed Atlaso ISO.
    """
    import pycdlib

    size = image.stat().st_size
    if size < 32768 or size % 512:
        raise ValueError("installation image must contain complete 512-byte sectors")
    with image.open("rb") as stream:
        mbr = stream.read(512)
        if (mbr[510:] != b"\x55\xaa" or mbr[450] != 0x17 or mbr[466] != 0xEF
                or any(mbr[478:510]) or struct.unpack_from("<II", mbr, 454) != (0, size // 512)):
            raise ValueError("image has no supported ISO/EFI MBR disk map; rebuild USB-capable media")
        start, count = struct.unpack_from("<II", mbr, 470)
        if start < 64 or count < 1 or (start + count) * 512 > size:
            raise ValueError("EFI partition lies outside the ISO image")
        iso = pycdlib.PyCdlib()
        iso.open_fp(stream)
        try:
            catalog = iso.eltorito_boot_catalog
            if catalog is None:
                raise ValueError("installation image has no optical boot catalog")
            entries = [catalog.initial_entry] if catalog.validation_entry.platform_id == 0xEF else []
            entries += [entry for section in catalog.sections if section.platform_id == 0xEF
                        for entry in section.section_entries]
            if len(entries) != 1 or (start, count) != (entries[0].load_rba * 4, entries[0].sector_count):
                raise ValueError("USB EFI partition differs from the optical EFI boot image")
            if iso.interchange_level < 3:
                raise ValueError("installation image requires ISO9660 level 3 for large payloads")
        finally:
            iso.close()
        stream.seek(start * 512)
        fat = stream.read(512)
        sectors = struct.unpack_from("<H", fat, 19)[0] or struct.unpack_from("<I", fat, 32)[0]
        if fat[510:] != b"\x55\xaa" or struct.unpack_from("<H", fat, 11)[0] != 512 or sectors != count:
            raise ValueError("EFI partition has an invalid or truncated FAT boot sector")
    return {"layout": "MBR ISO9660 level 3 view and embedded EFI-system partition",
            "image_bytes": size, "minimum_device_bytes": size,
            "efi_start_sector": start, "efi_sectors": count}


def compare_prefix(image: BinaryIO, device: BinaryIO, length: int) -> str:
    """Compare exactly the image bytes, leaving all device content untouched.

    Args:
        image: Read-only stream of the authenticated ISO.
        device: Read-only stream of the explicitly selected whole USB device.
        length: Exact ISO length; unrelated trailing device capacity is ignored.
    """
    if length <= 0 or length % 512:
        raise ValueError("image length must be a positive multiple of 512 bytes")
    digest = hashlib.sha256()
    remaining = length
    while remaining:
        size = min(1024 * 1024, remaining)
        expected = image.read(size)
        actual = device.read(size)
        if len(expected) != size or actual != expected:
            raise ValueError("USB readback differs from the ISO or ended early; do not install")
        digest.update(expected)
        remaining -= size
    return digest.hexdigest()


def verify_written(image: Path, device: Path) -> str:
    """Open the selected device read-only and verify its complete image prefix.

    Args:
        image: Signature-verified reconstructed ISO on separate storage.
        device: Exact whole-device identity selected by the operator.
    """
    with image.open("rb", buffering=0) as source, device.open("rb", buffering=0) as target:
        before = os.fstat(source.fileno())
        other = os.fstat(target.fileno())
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) == (other.st_dev, other.st_ino):
            raise ValueError("ISO must be a separate regular file")
        result = compare_prefix(source, target, before.st_size)
        after = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("ISO changed during readback")
        return result


def main() -> None:
    """Inspect an ISO and optionally verify a USB without writing either input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True, help="Already signature-verified reconstructed Atlaso ISO")
    parser.add_argument("--device", type=Path, help="Explicit whole USB device; opened read-only")
    args = parser.parse_args()
    result = inspect_layout(args.image)
    if args.device:
        result["verified_prefix_sha256"] = verify_written(args.image, args.device)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
