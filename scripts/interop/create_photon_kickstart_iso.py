#!/usr/bin/env python3
"""Embed Atlaso kickstart and auto-install GRUB config into Photon ISO."""

from __future__ import annotations

import argparse
import io
import os
import sys
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


def open_pinned_output(path: Path):
    """Open a caller-pinned output without weakening its Windows delete lock.

    Args:
        path: Pre-created output path held by the PowerShell caller.

    Returns:
        A binary read/write stream that owns its newly opened handle.
    """
    if os.name != "nt":
        return path.open("r+b", buffering=0)

    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    generic_read = 0x80000000
    generic_write = 0x40000000
    share_read = 0x00000001
    share_write = 0x00000002
    share_delete = 0x00000004
    open_existing = 3
    normal = 0x00000080
    handle = create_file(
        str(path),
        generic_read | generic_write,
        share_read | share_write | share_delete,
        None,
        open_existing,
        normal,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDWR | os.O_BINARY)
    except Exception:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise
    return os.fdopen(descriptor, "r+b", buffering=0)


def open_pinned_input(path: Path):
    """Open a caller-pinned input with Windows delete sharing enabled.

    Args:
        path: Existing input path held by the PowerShell caller.

    Returns:
        A binary read stream that owns its newly opened handle.
    """
    if os.name != "nt":
        return path.open("rb", buffering=0)

    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    generic_read = 0x80000000
    share_read = 0x00000001
    share_write = 0x00000002
    share_delete = 0x00000004
    open_existing = 3
    normal = 0x00000080
    handle = create_file(
        str(path),
        generic_read,
        share_read | share_write | share_delete,
        None,
        open_existing,
        normal,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise
    return os.fdopen(descriptor, "rb", buffering=0)


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
    except Exception:  # noqa: BLE001 - pycdlib uses several exception classes for a missing record.
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
        except Exception:  # noqa: BLE001 - pycdlib uses several exception classes for a missing record.
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
        except Exception as exc:  # noqa: BLE001 - collect every pycdlib replacement failure for one report.
            failures.append(f"{iso_path}: {exc}")
            continue
        return iso_path

    targets = ", ".join(iso_path for iso_path, _ in GRUB_CONFIG_TARGETS)
    detail = "; ".join(failures)
    raise RuntimeError(f"Could not embed Atlaso GRUB config. Tried: {targets}. {detail}")


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

    if output.is_symlink() or not output.is_file():
        print("Output ISO must be a pre-created regular file.", file=sys.stderr)
        return 2

    iso = pycdlib.PyCdlib()
    iso.open(str(source_iso))
    try:
        # The caller's protective handle owns DELETE access. Open the kickstart
        # with compatible delete sharing and retain this exact stream until
        # pycdlib has consumed it during the final ISO write.
        with open_pinned_input(kickstart) as kickstart_stream:
            kickstart_size = os.fstat(kickstart_stream.fileno()).st_size
            iso.add_fp(
                kickstart_stream,
                kickstart_size,
                iso_path="/PHOTONKS.JSON;1",
                rr_name="photon-ks.json",
            )
            grub_path = replace_grub_config(iso)
            # The PowerShell caller creates and identity-pins this file before
            # launch. Truncate and write through that same directory entry instead
            # of unlinking it and silently replacing the pinned filesystem object.
            with open_pinned_output(output) as output_stream:
                output_stream.truncate(0)
                iso.write_fp(output_stream)
                output_stream.flush()
                os.fsync(output_stream.fileno())
    finally:
        iso.close()

    print(f"embedded GRUB auto-install config at {grub_path}", file=sys.stderr)
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
