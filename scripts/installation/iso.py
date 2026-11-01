"""Remaster the pinned Photon installer ISO with the Atlaso offline payload."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import stat
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from scripts.installation.manifest import (
    PHOTON_INSTALLER_SHA256 as PHOTON_INSTALLER_SHA256,
)
from scripts.installation.manifest import (
    SOURCE_ISO_SHA512 as SOURCE_ISO_SHA512,
)
from scripts.interop.create_photon_kickstart_iso import (
    open_pinned_input,
    open_pinned_output,
    remove_file_if_present,
    replace_text_file,
)

PHOTON_INSTALLER_PATH = "usr/lib/python3.11/site-packages/photon_installer/installer.py"
INITRD_ISO_PATH = "/ISOLINUX/INITRD.IMG;1"
BOOT_LAUNCHER_PATH = "usr/bin/bootphotoninstaller"
TRUST_KEY_PATH = "etc/atlaso-installer/trust.pem"
PAYLOAD_ISO_ROOT = "/ATLASO"
VOLUME_IDENTIFIER = b"ATLASO_INSTALLER".ljust(32, b" ")
_CHUNK_SIZE = 1024 * 1024
_CPIO_HEADER_SIZE = 110
_CPIO_MAGICS = {b"070701", b"070702"}
_GRUB_CONFIGS = (
    ("/BOOT/GRUB2/GRUB.CFG;1", "grub.cfg"),
    ("/EFI/BOOT/GRUB.CFG;1", "grub.cfg"),
)
_GRUB_CONFIG = """set default=0
set timeout=-1

menuentry 'Install Atlaso offline' {
    linux /isolinux/vmlinuz root=/dev/ram0 loglevel=3
    initrd /isolinux/initrd.img
}
"""
_DEVELOPMENT_GRUB_CONFIG = """set default=atlaso-graphical
set timeout=5

if serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1; then
    terminal_input console serial
    terminal_output console serial
fi

menuentry 'DEVELOPMENT ONLY - Install Atlaso offline - VM window (tty0)' --id=atlaso-graphical {
    linux /isolinux/vmlinuz root=/dev/ram0 loglevel=3 console=tty0
    initrd /isolinux/initrd.img
}

menuentry 'DEVELOPMENT ONLY - Install Atlaso offline - Serial (ttyS0, 115200)' --id=atlaso-serial {
    linux /isolinux/vmlinuz root=/dev/ram0 loglevel=3 console=ttyS0,115200n8
    initrd /isolinux/initrd.img
}
"""
_LAUNCHER = b"""#!/bin/sh
set -u

rescue() {
    printf '%s\\n' "$1"
    exec /bin/sh -i
}

if [ ! -r /sys/devices/virtual/tty/console/active ]; then
    rescue 'Could not identify the active installer console.'
fi
active_console=
IFS= read -r active_console < /sys/devices/virtual/tty/console/active || rescue 'Could not read the active console.'
case "$active_console" in
    tty0) console=/dev/tty1 ;;
    ttyS*)
        serial_suffix=${active_console#ttyS}
        case "$serial_suffix" in
            ''|*[!0-9]*) rescue 'The active serial console name is invalid.' ;;
        esac
        console=/dev/$active_console
        ;;
    *) rescue 'The active console is not supported by the Atlaso installer.' ;;
esac
if [ ! -c "$console" ] || [ "$(tty 2>/dev/null)" != "$console" ]; then
    rescue 'Start the Atlaso installer on the active console.'
fi
exec <"$console" >"$console" 2>&1
case "$active_console" in
    ttyS*) stty rows 25 cols 80 <"$console" 2>/dev/null || rescue 'Could not configure the serial installer console to 80 by 25.' ;;
esac

media=/mnt/atlaso-install
if ! mkdir -p "$media"; then
    rescue 'Could not prepare the read-only installation media mount.'
fi
if ! /usr/bin/python3 /etc/atlaso-installer/media.py --target "$media"; then
    rescue 'Could not discover exactly one safe read-only Atlaso installation medium.'
fi

if /usr/bin/unshare --net -- /usr/bin/python3 /etc/atlaso-installer/bootstrap.py --media "$media/atlaso"; then
    if ! umount "$media"; then
        rescue 'Installation completed, but the media could not be unmounted; reboot manually after inspection.'
    fi
    /sbin/reboot
    exec /bin/sh -i
else
    status=$?
    printf 'Atlaso installation cancelled or failed (status %s).\\n' "$status"
    exec /bin/sh -i
fi
"""


@dataclass(frozen=True)
class _CpioEntry:
    name: str
    mode: int
    ino: int
    raw: bytes
    is_trailer: bool = False


@dataclass
class _PinnedFile:
    path: Path
    relative: PurePosixPath | None
    stream: BinaryIO | None
    identity: tuple[int, int, int, int]
    mode: int
    digest: str
    hash_algorithm: str


class _FileSlice(io.RawIOBase):
    """Give PyCdlib an independent seekable view over one shared spool file."""

    def __init__(self, stream: BinaryIO, offset: int, length: int) -> None:
        """Initialize the object with its supplied stream and slice bounds.

        Args:
            stream: Open binary stream to read or hash.
            offset: Absolute or relative position within the stream.
            length: Number of bytes exposed by this slice."""
        super().__init__()
        self._stream = stream
        self._offset = offset
        self._length = length
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._stream.fileno()

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the cursor within this file slice.

        Args:
            offset: Absolute or relative position within the stream.
            whence: Reference point used to calculate the seek position."""
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._length + offset
        else:
            raise ValueError("invalid seek origin")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def readinto(self, buffer: bytearray | memoryview) -> int:
        """Read bytes from the file slice into a caller-provided buffer.

        Args:
            buffer: Writable byte buffer for reading the current slice."""
        if self.closed:
            raise ValueError("I/O operation on closed file slice")
        available = max(0, self._length - self._position)
        amount = min(len(buffer), available)
        if amount == 0:
            return 0
        self._stream.seek(self._offset + self._position)
        chunk = self._stream.read(amount)
        buffer[: len(chunk)] = chunk
        self._position += len(chunk)
        return len(chunk)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    """Return stable filesystem identity fields for change detection.

    Args:
        info: Stat metadata used to identify the filesystem object."""
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _stable_mode(mode: int) -> int:
    """Exclude Windows filename-derived execute bits from mode comparisons.

    Args:
        mode: Filesystem mode reported for a path or open descriptor.
    """
    # Windows stat infers execute bits from .exe/.bat/.cmd suffixes, whereas
    # fstat cannot inspect a filename. File type and read-only bits still match.
    return mode & ~0o111 if os.name == "nt" else mode


def _is_reparse(path: Path, info: os.stat_result) -> bool:
    """Check whether a path is a symbolic link or reparse point.

    Args:
        path: Filesystem path to the input or target.
        info: Stat metadata used to identify the filesystem object."""
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _checked_path(path: Path, *, final_kind: str) -> Path:
    """Validate an input path and return its absolute form.

    Args:
        path: Filesystem path to the input or target.
        final_kind: Required filesystem type for the final path component."""
    if ".." in Path(path).parts:
        raise ValueError("path ancestry must not contain parent traversal")
    absolute = Path(os.path.abspath(path))
    chain = list(reversed((absolute, *absolute.parents)))
    for index, item in enumerate(chain):
        info = item.lstat()
        if _is_reparse(item, info):
            raise ValueError(f"symbolic links and reparse points are not allowed: {item.name}")
        is_final = index == len(chain) - 1
        if not is_final and not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"path ancestry must be a directory: {item}")
    final = absolute.lstat()
    expected = stat.S_ISDIR(final.st_mode) if final_kind == "directory" else stat.S_ISREG(final.st_mode)
    if not expected:
        raise ValueError(f"path must be an ordinary {final_kind}: {absolute}")
    if final_kind == "file" and final.st_nlink != 1:
        raise ValueError(f"file must have exactly one hard link: {absolute.name}")
    return absolute


def _checked_new_path(path: Path) -> Path:
    """Validate a new output path without creating it.

    Args:
        path: Filesystem path to the input or target."""
    parent = _checked_path(path.parent, final_kind="directory")
    result = parent / path.name
    if not path.name or path.name in {".", ".."}:
        raise ValueError("output must name a file")
    if os.path.lexists(result):
        raise FileExistsError(result)
    return result


def _hash_stream(stream: BinaryIO, algorithm: str) -> str:
    """Hash an open input stream and restore its position.

    Args:
        stream: Open binary stream to read or hash.
        algorithm: Hash algorithm used to verify the stream."""
    stream.seek(0)
    digest = hashlib.new(algorithm)
    while chunk := stream.read(_CHUNK_SIZE):
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()


def _open_pinned(
    path: Path,
    *,
    relative: PurePosixPath | None = None,
    hash_algorithm: str = "sha256",
) -> _PinnedFile:
    """Open an ordinary file and record its verified identity and digest.

    Args:
        path: Filesystem path to the input or target.
        relative: Payload path relative to its root directory.
        hash_algorithm: Hash algorithm used to pin the file contents."""
    absolute = _checked_path(path, final_kind="file")
    before = absolute.lstat()
    stream = open_pinned_input(absolute)
    try:
        opened = os.fstat(stream.fileno())
        current = absolute.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _identity(opened) != _identity(before)
            or _identity(current) != _identity(before)
        ):
            raise ValueError(f"file changed while opening: {absolute.name}")
        return _PinnedFile(
            absolute,
            relative,
            stream,
            _identity(opened),
            opened.st_mode,
            _hash_stream(stream, hash_algorithm),
            hash_algorithm,
        )
    except Exception:
        stream.close()
        raise


def _verify_pinned(item: _PinnedFile) -> None:
    """Confirm that a pinned input still matches its recorded identity and digest.

    Args:
        item: Pinned file record whose identity and contents are checked."""
    current = item.path.lstat()
    if _identity(current) != item.identity or _stable_mode(current.st_mode) != _stable_mode(item.mode):
        raise ValueError(f"input changed during ISO assembly: {item.path.name}")
    if item.stream is not None:
        opened = os.fstat(item.stream.fileno())
        if _identity(opened) != item.identity or _stable_mode(opened.st_mode) != _stable_mode(item.mode):
            raise ValueError(f"input changed during ISO assembly: {item.path.name}")
        if _hash_stream(item.stream, item.hash_algorithm) != item.digest:
            raise ValueError(f"input changed during ISO assembly: {item.path.name}")
        return
    with open_pinned_input(item.path) as stream:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _identity(opened) != item.identity
            or _stable_mode(opened.st_mode) != _stable_mode(item.mode)
            or _identity(item.path.lstat()) != item.identity
            or _hash_stream(stream, item.hash_algorithm) != item.digest
        ):
            raise ValueError(f"input changed during ISO assembly: {item.path.name}")


def _payload_inventory(root: Path) -> tuple[list[Path], list[Path]]:
    """Enumerate ordinary payload files and directories.

    Args:
        root: Root directory containing the files being checked."""
    directories = [root]
    files: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
        for entry in entries:
            info = entry.lstat()
            if _is_reparse(entry, info):
                raise ValueError(f"payload contains a symbolic link or reparse point: {entry.name}")
            if stat.S_ISDIR(info.st_mode):
                directories.append(entry)
                pending.append(entry)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.append(entry)
            else:
                raise ValueError(f"payload contains a special or hard-linked file: {entry.name}")
    return directories, files


def _canonical_cpio_name(raw_name: bytes) -> str:
    """Validate and normalize a cpio archive entry name.

    Args:
        raw_name: Raw filename bytes read from the archive."""
    if not raw_name or raw_name.startswith(b"/") or b"\\" in raw_name:
        raise ValueError("initrd cpio contains an unsafe path")
    try:
        name = raw_name.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("initrd cpio path is not UTF-8") from exc
    if "\x00" in name or name.startswith("/"):
        raise ValueError("initrd cpio contains an unsafe path")
    while name.startswith("./"):
        name = name[2:]
    parts = name.rstrip("/").split("/")
    if name in {"", "."}:
        return "."
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("initrd cpio contains an unsafe path")
    return "/".join(parts)


def _parse_newc(archive: bytes) -> tuple[list[_CpioEntry], bytes, bytes]:
    """Parse and validate a single newc cpio archive.

    Args:
        archive: Newc cpio archive bytes to parse or rewrite."""
    entries: list[_CpioEntry] = []
    seen: set[str] = set()
    offset = 0
    magic: bytes | None = None
    while offset < len(archive):
        header_start = offset
        if len(archive) - offset < _CPIO_HEADER_SIZE:
            raise ValueError("initrd cpio header is truncated")
        entry_magic = archive[offset : offset + 6]
        if entry_magic not in _CPIO_MAGICS or magic is not None and entry_magic != magic:
            raise ValueError("initrd must contain one newc cpio archive")
        magic = entry_magic
        fields = []
        for start in range(offset + 6, offset + _CPIO_HEADER_SIZE, 8):
            value = archive[start : start + 8]
            try:
                fields.append(int(value, 16))
            except ValueError as exc:
                raise ValueError("initrd cpio header contains a non-hexadecimal field") from exc
        ino, mode = fields[0], fields[1]
        file_size, name_size = fields[6], fields[11]
        if name_size < 1:
            raise ValueError("initrd cpio filename is empty")
        name_start = offset + _CPIO_HEADER_SIZE
        name_end = name_start + name_size
        if name_end > len(archive) or archive[name_end - 1] != 0:
            raise ValueError("initrd cpio filename is truncated")
        raw_name = archive[name_start : name_end - 1]
        name = _canonical_cpio_name(raw_name)
        data_start = (name_end + 3) & ~3
        data_end = data_start + file_size
        record_end = (data_end + 3) & ~3
        if data_end > len(archive) or record_end > len(archive):
            raise ValueError("initrd cpio file data is truncated")
        raw = archive[header_start:record_end]
        trailer = name == "TRAILER!!!"
        if trailer:
            entries.append(_CpioEntry(name, mode, ino, raw, True))
            if any(archive[record_end:]):
                raise ValueError("initrd cpio has non-padding data after its trailer")
            return entries, magic, archive[record_end:]
        if name in seen:
            raise ValueError("initrd cpio contains duplicate paths")
        seen.add(name)
        if entry_magic == b"070702":
            checksum = fields[12]
            if checksum != sum(archive[data_start:data_end]) & 0xFFFFFFFF:
                raise ValueError("initrd cpio checksum is invalid")
        entries.append(_CpioEntry(name, mode, ino, raw))
        offset = record_end
    raise ValueError("initrd cpio trailer is missing")


def _newc_entry(magic: bytes, name: str, mode: int, ino: int, data: bytes = b"") -> bytes:
    """Encode one entry in the selected newc cpio format.

    Args:
        magic: Newc archive format marker used for the record.
        name: Entry name to encode in the archive.
        mode: Filesystem mode stored in the archive record.
        ino: Inode number stored in the archive record.
        data: File contents stored in the archive record."""
    encoded_name = name.encode("utf-8") + b"\x00"
    checksum = sum(data) & 0xFFFFFFFF if magic == b"070702" else 0
    fields = (
        ino,
        mode,
        0,
        0,
        1,
        0,
        len(data),
        0,
        0,
        0,
        0,
        len(encoded_name),
        checksum,
    )
    result = bytearray(magic + b"".join(f"{value:08x}".encode("ascii") for value in fields))
    result.extend(encoded_name)
    result.extend(b"\x00" * ((-len(result)) & 3))
    result.extend(data)
    result.extend(b"\x00" * ((-len(result)) & 3))
    return bytes(result)


def _rewrite_newc(archive: bytes, launcher: bytes, trust: bytes, *, bootstrap: bytes = b"", manifest_code: bytes = b"", development: bool = False) -> bytes:
    """Replace the initrd launcher and embed the trusted verifier.

    Args:
        archive: Newc cpio archive bytes to parse or rewrite.
        launcher: Trusted console launcher bytes embedded in the initrd.
        trust: Public trust key bytes embedded in the initrd.
        bootstrap: Trusted initrd bootstrap source to embed.
        manifest_code: Trusted manifest verifier source to embed.
        development: Embed an explicit public-test trust marker for VMware only."""
    entries, magic, padding = _parse_newc(archive)
    by_name = {entry.name: entry for entry in entries if not entry.is_trailer}
    required_unshare = by_name.get("usr/bin/unshare")
    if required_unshare is None or not stat.S_ISREG(required_unshare.mode) or not required_unshare.mode & 0o111:
        raise ValueError("pinned Photon initrd does not contain executable /usr/bin/unshare")
    if bootstrap:
        for name in ("cryptography/__init__.py", "cryptography/hazmat/primitives/asymmetric/ed25519.py"):
            dependency = by_name.get("usr/lib/python3.11/site-packages/" + name)
            if dependency is None or not stat.S_ISREG(dependency.mode):
                raise ValueError("pinned Photon initrd is missing its cryptography verifier")
    installer = by_name.get(PHOTON_INSTALLER_PATH)
    if installer is None or not stat.S_ISREG(installer.mode):
        raise ValueError("pinned Photon initrd installer is missing")
    installer_data = _cpio_data(installer.raw, magic)
    if hashlib.sha256(installer_data).hexdigest() != PHOTON_INSTALLER_SHA256:
        raise ValueError("Photon installer does not match the pinned 2.2 version")

    for directory in ("usr", "usr/bin", "etc", "etc/atlaso-installer"):
        existing = by_name.get(directory)
        if existing is not None and not stat.S_ISDIR(existing.mode):
            raise ValueError("initrd installer parent path is not a directory")

    replacements = {
        BOOT_LAUNCHER_PATH: (stat.S_IFREG | 0o755, launcher),
        TRUST_KEY_PATH: (stat.S_IFREG | 0o644, trust),
    }
    if development:
        from scripts.installation.manifest import DEVELOPMENT_KEY_ID

        replacements["etc/atlaso-installer/development"] = (stat.S_IFREG | 0o644, (DEVELOPMENT_KEY_ID + "\n").encode())
    if bootstrap and manifest_code:
        replacements["etc/atlaso-installer/bootstrap.py"] = (stat.S_IFREG | 0o644, bootstrap)
        replacements["etc/atlaso-installer/manifest.py"] = (stat.S_IFREG | 0o644, manifest_code)
        replacements["etc/atlaso-installer/media.py"] = (stat.S_IFREG | 0o644, Path(__file__).with_name("media.py").read_bytes())
    elif bootstrap or manifest_code:
        raise ValueError("both initrd bootstrap and manifest verifier are required")
    next_ino = max((entry.ino for entry in entries if not entry.is_trailer), default=0) + 1
    generated: dict[str, bytes] = {}
    for directory in ("usr", "usr/bin", "etc", "etc/atlaso-installer"):
        if directory not in by_name:
            generated[directory] = _newc_entry(magic, directory, stat.S_IFDIR | 0o755, next_ino)
            next_ino += 1
    for name, (mode, data) in replacements.items():
        generated[name] = _newc_entry(magic, name, mode, next_ino, data)
        next_ino += 1

    result = bytearray()
    emitted = set()
    for entry in entries:
        if entry.is_trailer:
            for name, raw in generated.items():
                if name not in by_name:
                    result.extend(raw)
                    emitted.add(name)
            result.extend(entry.raw)
            continue
        replacement = generated.get(entry.name)
        if replacement is not None:
            result.extend(replacement)
            emitted.add(entry.name)
        else:
            result.extend(entry.raw)
    if emitted != set(generated):
        raise ValueError("initrd cpio rewrite did not emit every Atlaso entry")
    result.extend(padding)
    return bytes(result)


def _cpio_data(raw: bytes, magic: bytes) -> bytes:
    """Extract file contents from a raw cpio record.

    Args:
        raw: Raw cpio record bytes to decode.
        magic: Newc archive format marker used for the record."""
    name_size = int(raw[94:102], 16)
    file_size = int(raw[54:62], 16)
    data_start = (_CPIO_HEADER_SIZE + name_size + 3) & ~3
    return raw[data_start : data_start + file_size]


def _iso_component(relative: PurePosixPath) -> str:
    """Create a stable short ISO identifier for a payload path.

    Args:
        relative: Payload path relative to its root directory."""
    return hashlib.sha256(relative.as_posix().encode("utf-8")).hexdigest()[:16].upper()


def _add_payload(iso, root: Path, pinned: list[_PinnedFile], spool: BinaryIO) -> None:
    """Stage and add the signed payload tree to the ISO.

    Args:
        iso: Open PyCdlib image being updated.
        root: Root directory containing the files being checked.
        pinned: Collection used to retain and verify pinned payload file identities.
        spool: Temporary binary stream holding staged payload bytes."""
    from scripts.interop.create_photon_kickstart_iso import iso_record_exists

    if iso_record_exists(iso, iso_path=PAYLOAD_ISO_ROOT):
        raise ValueError("source ISO already contains the Atlaso payload root")
    if not iso.rock_ridge:
        raise ValueError("source ISO does not support Rock Ridge payload paths")

    directories, files = _payload_inventory(root)
    expected = {
        PurePosixPath("payload-manifest.json"),
        PurePosixPath("payload-manifest.json.sig"),
        PurePosixPath("source/scripts/installation/installer.py"),
    }
    available = {PurePosixPath(path.relative_to(root).as_posix()) for path in files}
    if not expected <= available:
        raise ValueError("payload is missing its signed manifest or installer entry point")

    names: dict[PurePosixPath, str] = {}
    occupied: set[str] = set()
    for path in sorted((PurePosixPath(item.relative_to(root).as_posix()) for item in directories + files if item != root)):
        if len(path.name.encode("utf-8")) > 255:
            raise ValueError("payload Rock Ridge filename exceeds the supported limit")
        component = _iso_component(path)
        if component in occupied:
            raise ValueError("deterministic ISO payload name collision")
        occupied.add(component)
        names[path] = component

    file_slices: dict[PurePosixPath, tuple[_PinnedFile, _FileSlice]] = {}
    for path in sorted(files):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        pinned_file = _open_pinned(path, relative=relative)
        pinned.append(pinned_file)
        offset = spool.tell()
        copied_digest = hashlib.new(pinned_file.hash_algorithm)
        copied = 0
        while chunk := pinned_file.stream.read(_CHUNK_SIZE):
            spool.write(chunk)
            copied_digest.update(chunk)
            copied += len(chunk)
        if copied != pinned_file.identity[2] or copied_digest.hexdigest() != pinned_file.digest:
            raise ValueError(f"payload changed while staging: {path.name}")
        _verify_pinned(pinned_file)
        pinned_file.stream.close()
        pinned_file.stream = None
        file_slices[relative] = (pinned_file, _FileSlice(spool, offset, copied))

    iso.add_directory(iso_path=PAYLOAD_ISO_ROOT, rr_name="atlaso")
    directory_paths = [item for item in directories if item != root]
    for path in sorted(directory_paths, key=lambda item: (len(item.relative_to(root).parts), item.relative_to(root).as_posix())):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        parent_components = [names[PurePosixPath(*relative.parts[:index])] for index in range(1, len(relative.parts))]
        iso_path = PAYLOAD_ISO_ROOT + "/" + "/".join((*parent_components, names[relative]))
        iso.add_directory(iso_path=iso_path, rr_name=relative.name)

    for relative, (pinned_file, file_slice) in sorted(file_slices.items()):
        parent_components = [names[PurePosixPath(*relative.parts[:index])] for index in range(1, len(relative.parts))]
        iso_path = PAYLOAD_ISO_ROOT + "/" + "/".join((*parent_components, names[relative])) + ";1"
        iso.add_fp(
            file_slice,
            pinned_file.identity[2],
            iso_path=iso_path,
            rr_name=relative.name,
            file_mode=pinned_file.mode,
        )


def _create_exclusive_output(path: Path) -> tuple[BinaryIO, tuple[int, int]]:
    """Create an absent ISO output and retain its filesystem identity.

    Args:
        path: Filesystem path to the input or target."""
    with path.open("xb") as created:
        info = os.fstat(created.fileno())
        identity = (info.st_dev, info.st_ino)
    try:
        output_stream = open_pinned_output(path)
        opened = os.fstat(output_stream.fileno())
        current = path.lstat()
        if (
            (opened.st_dev, opened.st_ino) != identity
            or (current.st_dev, current.st_ino) != identity
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            output_stream.close()
            raise ValueError("exclusive ISO output changed while opening")
        return output_stream, identity
    except Exception:
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) == identity and stat.S_ISREG(current.st_mode) and current.st_nlink == 1:
                path.unlink()
        except FileNotFoundError:
            pass
        raise


def _remove_owned_output(path: Path, identity: tuple[int, int]) -> None:
    """Remove an incomplete ISO only when its identity still matches.

    Args:
        path: Filesystem path to the input or target.
        identity: Recorded device and inode identity used to confirm ownership."""
    try:
        current = path.lstat()
        if (current.st_dev, current.st_ino) == identity and stat.S_ISREG(current.st_mode) and current.st_nlink == 1:
            path.unlink()
    except FileNotFoundError:
        pass


def build_iso(
    source_iso: Path, payload_root: Path, output: Path, *, trust_key: Path,
    development: bool = False, serial_console: bool = False,
) -> None:
    """Create a new Atlaso offline installer ISO from the pinned Photon source.

    Args:
        source_iso: Pinned Photon installation ISO used as the remaster base.
        payload_root: Prepared signed Atlaso payload directory to embed.
        output: Destination path for the generated output.
        trust_key: Trusted public key used to verify signed metadata.
        development: Build an explicitly marked VMware-only test ISO.
        serial_console: Default a development ISO's console menu to serial.
    """
    if serial_console and not development:
        raise ValueError("serial console selection is restricted to development images")
    try:
        import pycdlib
    except ImportError as exc:
        raise RuntimeError("pycdlib is required to remaster the Photon installation ISO") from exc

    source = _checked_path(Path(source_iso), final_kind="file")
    payload = _checked_path(Path(payload_root), final_kind="directory")
    trust_path = _checked_path(Path(trust_key), final_kind="file")
    output_path = _checked_new_path(Path(output))
    if output_path == source or output_path == trust_path or payload in output_path.parents:
        raise ValueError("output must be distinct from all ISO inputs and outside the payload root")
    _, payload_files = _payload_inventory(payload)
    payload_bytes = sum(path.stat().st_size for path in payload_files)
    # Admit both spool/remaster peak and the later ordered release asset copy.
    required_bytes = 2 * (source.stat().st_size + payload_bytes) + 2 * 1024**3
    if payload_bytes > 16 * 1024**3 or shutil.disk_usage(output_path.parent).free < required_bytes:
        raise ValueError("insufficient capacity for installation ISO assembly and release assets")

    pinned: list[_PinnedFile] = []
    iso = pycdlib.PyCdlib()
    source_iso_stream: BinaryIO | None = None
    output_stream: BinaryIO | None = None
    payload_spool: BinaryIO | None = None
    output_identity: tuple[int, int] | None = None
    iso_opened = False
    try:
        source_file = _open_pinned(source, hash_algorithm="sha512")
        pinned.append(source_file)
        if source_file.digest != SOURCE_ISO_SHA512:
            raise ValueError("source ISO does not match the pinned Photon image")

        trust_file = _open_pinned(trust_path)
        pinned.append(trust_file)
        trust = trust_file.stream.read(1024 * 1024 + 1)
        trust_file.stream.seek(0)
        if (
            not trust
            or len(trust) > 1024 * 1024
            or b"PRIVATE KEY" in trust
            or b"-----BEGIN PUBLIC KEY-----" not in trust and b"-----BEGIN CERTIFICATE-----" not in trust
        ):
            raise ValueError("installer trust input must be a bounded public key")

        source_iso_stream = source.open("rb", buffering=0)
        opened_source = os.fstat(source_iso_stream.fileno())
        if _identity(opened_source) != source_file.identity:
            raise ValueError("source ISO changed after its pinned checksum was verified")
        iso.open_fp(source_iso_stream)
        iso_opened = True
        if iso.pvd is None or not iso.rock_ridge:
            raise ValueError("pinned Photon ISO must contain a primary volume and Rock Ridge support")
        if iso.interchange_level < 3 and source_file.identity[2] > 4 * 1024 * 1024 * 1024:
            raise ValueError("source ISO exceeds its declared ISO level capacity")

        initrd_buffer = io.BytesIO()
        iso.get_file_from_iso_fp(initrd_buffer, iso_path=INITRD_ISO_PATH)
        try:
            initrd = gzip.decompress(initrd_buffer.getvalue())
        except (OSError, EOFError) as exc:
            raise ValueError("pinned Photon initrd is not a valid gzip archive") from exc
        script_root = Path(__file__).resolve().parent
        rewritten = gzip.compress(
            _rewrite_newc(initrd, _LAUNCHER, trust, bootstrap=(script_root / "bootstrap.py").read_bytes(), manifest_code=(script_root / "manifest.py").read_bytes(), development=development),
            compresslevel=9, mtime=0,
        )
        remove_file_if_present(iso, iso_path=INITRD_ISO_PATH, rr_name="initrd.img")
        iso.add_fp(io.BytesIO(rewritten), len(rewritten), iso_path=INITRD_ISO_PATH, rr_name="initrd.img")

        from scripts.interop.create_photon_kickstart_iso import iso_record_exists

        grub_paths = [entry for entry in _GRUB_CONFIGS if iso_record_exists(iso, iso_path=entry[0])]
        if not grub_paths:
            raise ValueError("pinned Photon ISO has no supported GRUB configuration path")
        for iso_path, rr_name in grub_paths:
            grub = _GRUB_CONFIG
            if development:
                grub = _DEVELOPMENT_GRUB_CONFIG
                if serial_console:
                    grub = grub.replace("set default=atlaso-graphical", "set default=atlaso-serial")
            replace_text_file(iso, iso_path=iso_path, rr_name=rr_name, text=grub)

        iso.pvd.volume_identifier = VOLUME_IDENTIFIER
        if iso.joliet_vd is not None:
            iso.joliet_vd.volume_identifier = VOLUME_IDENTIFIER
        payload_spool = tempfile.TemporaryFile(mode="w+b", dir=output_path.parent)
        _add_payload(iso, payload, pinned, payload_spool)
        projected_size = source_file.identity[2] + len(rewritten) + sum(
            item.identity[2] for item in pinned if item.relative is not None
        ) + 16 * 1024 * 1024
        if iso.interchange_level < 3 and projected_size >= 4 * 1024 * 1024 * 1024:
            raise ValueError("payload would exceed the source ISO's interchange-level capacity")
        for item in pinned:
            _verify_pinned(item)

        output_stream, output_identity = _create_exclusive_output(output_path)
        iso.write_fp(output_stream)
        catalog = iso.eltorito_boot_catalog
        efi = ([catalog.initial_entry] if catalog.validation_entry.platform_id == 0xEF else [])
        efi += [entry for section in catalog.sections if section.platform_id == 0xEF
               for entry in section.section_entries]
        if len(efi) != 1:
            raise ValueError("pinned Photon ISO requires exactly one EFI boot image")
        # UEFI supports an MBR EFI-system partition. Map the same immutable FAT
        # image used by optical El Torito; the ISO9660 payload stays in place.
        # Partition 1 also exposes the whole ISO for GRUB/kernel discovery;
        # partition 2 intentionally aliases only its embedded FAT extent.
        # No BIOS code, secondary image format, extracted FAT32 payload or GPT
        # relocation is needed. The system area is outside the ISO descriptors.
        mbr = bytearray(512)
        struct.pack_into("<I", mbr, 440, 0x41544C53)
        struct.pack_into("<BBBBBBBBII", mbr, 446, 0, 0xFE, 0xFF, 0xFF, 0x17, 0xFE, 0xFF, 0xFF,
                         0, output_stream.seek(0, os.SEEK_END) // 512)
        struct.pack_into("<BBBBBBBBII", mbr, 462, 0, 0xFE, 0xFF, 0xFF, 0xEF, 0xFE, 0xFF, 0xFF,
                         efi[0].load_rba * 4, efi[0].sector_count)
        mbr[510:] = b"\x55\xaa"
        output_stream.seek(0)
        output_stream.write(mbr)
        output_stream.flush()
        os.fsync(output_stream.fileno())
        from scripts.verify_installation_usb import inspect_layout

        inspect_layout(output_path)
        for item in pinned:
            _verify_pinned(item)
    except Exception:
        if output_stream is not None:
            output_stream.close()
        if output_identity is not None:
            _remove_owned_output(output_path, output_identity)
        raise
    finally:
        if output_stream is not None and not output_stream.closed:
            output_stream.close()
        if iso_opened:
            iso.close()
        if payload_spool is not None:
            payload_spool.close()
        if source_iso_stream is not None:
            source_iso_stream.close()
        for item in pinned:
            if item.stream is not None:
                item.stream.close()


__all__ = ["build_iso"]
