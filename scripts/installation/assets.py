"""Deterministic, checksummed ISO asset splitting and reassembly."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import BinaryIO

GITHUB_ASSET_LIMIT = 2_147_483_648
MAX_PART_BYTES = 1_073_741_824
_CHUNK_BYTES = 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _safe_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or ":" in value
        or any(ord(character) < 32 for character in value)
        or any(character in '<>"|?*' for character in value)
        or value.endswith((" ", "."))
        or re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]", value.split(".")[0], re.IGNORECASE)
        or Path(value).name != value
        or Path(value).drive
    ):
        raise ValueError("asset names must be safe basenames")
    return value


def _is_reparse_point(path: Path, info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _check_path_chain(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    chain = list(reversed((absolute, *absolute.parents)))
    for item in chain:
        try:
            info = item.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"path ancestry does not exist: {item}") from exc
        if _is_reparse_point(item, info):
            raise ValueError(f"symbolic links and reparse points are not allowed: {item}")
        if item != absolute and not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"path ancestry is not a directory: {item}")
    return absolute


def _open_regular(path: Path) -> tuple[BinaryIO, os.stat_result]:
    absolute = _check_path_chain(path)
    info = absolute.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f"asset must be an ordinary single-link file: {absolute.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    stream = os.fdopen(descriptor, "rb")
    opened = os.fstat(stream.fileno())
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or _identity(opened) != _identity(info):
        stream.close()
        raise ValueError(f"asset changed while opening: {absolute.name}")
    return stream, opened


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    # Windows updates ctime when an open handle changes metadata precision.
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _digest_stream(stream: BinaryIO) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(_CHUNK_BYTES):
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _file_metadata(path: Path) -> tuple[os.stat_result, int, str]:
    with _open_regular(path)[0] as stream:
        before = os.fstat(stream.fileno())
        size, digest = _digest_stream(stream)
        after = os.fstat(stream.fileno())
    if _identity(before) != _identity(after) or size != after.st_size:
        raise ValueError(f"asset changed while reading: {path.name}")
    return after, size, digest


def _exclusive_output(path: Path) -> tuple[BinaryIO, tuple[int, int]]:
    absolute = _check_path_chain(path.parent) / path.name
    _safe_name(path.name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(absolute, flags, 0o666)
    stream = os.fdopen(descriptor, "wb")
    info = os.fstat(stream.fileno())
    return stream, (info.st_dev, info.st_ino)


def _remove_owned(path: Path, identity: tuple[int, int]) -> None:
    try:
        info = path.lstat()
        if (info.st_dev, info.st_ino) == identity and stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            path.unlink()
    except FileNotFoundError:
        pass


def _validate_manifest(manifest: object) -> tuple[str, int, str, list[dict[str, object]]]:
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "iso", "assets"}:
        raise ValueError("manifest must contain exactly schema, iso, and assets")
    if type(manifest["schema"]) is not int or manifest["schema"] != 1:
        raise ValueError("unsupported asset manifest schema")
    iso = manifest["iso"]
    assets = manifest["assets"]
    if not isinstance(iso, dict) or set(iso) != {"name", "size", "sha256"}:
        raise ValueError("manifest ISO entry is invalid")
    name = _safe_name(iso["name"])
    size = iso["size"]
    digest = iso["sha256"]
    if type(size) is not int or size < 0 or not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise ValueError("manifest ISO size or checksum is invalid")
    if not isinstance(assets, list) or not assets:
        raise ValueError("manifest assets must be a nonempty list")
    clean_assets: list[dict[str, object]] = []
    names: set[str] = set()
    for entry in assets:
        if not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"}:
            raise ValueError("manifest asset entry is invalid")
        asset_name = _safe_name(entry["name"])
        asset_size = entry["size"]
        asset_digest = entry["sha256"]
        if asset_name in names:
            raise ValueError("manifest contains duplicate asset names")
        names.add(asset_name)
        if (
            type(asset_size) is not int
            or asset_size < 0
            or not isinstance(asset_digest, str)
            or not _SHA256_RE.fullmatch(asset_digest)
        ):
            raise ValueError("manifest asset size or checksum is invalid")
        clean_assets.append({"name": asset_name, "size": asset_size, "sha256": asset_digest})

    if size < GITHUB_ASSET_LIMIT:
        if len(clean_assets) != 1 or clean_assets[0]["name"] != name or clean_assets[0]["size"] != size:
            raise ValueError("small ISO must have one matching asset")
    else:
        expected_names = [f"{name}.part{index:04d}" for index in range(1, len(clean_assets) + 1)]
        if [entry["name"] for entry in clean_assets] != expected_names:
            raise ValueError("split ISO assets must be consecutively numbered in order")
        if any(type(entry["size"]) is not int or not 0 < entry["size"] <= MAX_PART_BYTES for entry in clean_assets):
            raise ValueError("split ISO part sizes are invalid")
    if sum(int(entry["size"]) for entry in clean_assets) != size:
        raise ValueError("asset sizes do not match the ISO size")
    return name, size, digest, clean_assets


def split_iso(source: Path, destination: Path, *, part_bytes: int = MAX_PART_BYTES) -> dict[str, object]:
    """Copy an ISO into a single safe asset or ordered checksum-verified parts."""
    if type(part_bytes) is not int or not 1 <= part_bytes <= MAX_PART_BYTES:
        raise ValueError(f"part_bytes must be between 1 and {MAX_PART_BYTES}")
    source_path = Path(source)
    destination_path = _check_path_chain(Path(destination))
    if not stat.S_ISDIR(destination_path.lstat().st_mode):
        raise ValueError("destination must be an existing directory")
    _safe_name(source_path.name)
    source_info, source_size, source_digest = _file_metadata(source_path)
    if source_size < GITHUB_ASSET_LIMIT:
        specifications = [(source_path.name, 0, source_size)]
    else:
        specifications = []
        offset = 0
        index = 1
        while offset < source_size:
            size = min(part_bytes, source_size - offset)
            specifications.append((f"{source_path.name}.part{index:04d}", offset, size))
            offset += size
            index += 1

    created: list[tuple[Path, tuple[int, int]]] = []
    try:
        copied_digest = hashlib.sha256()
        copied_size = 0
        with _open_regular(source_path)[0] as input_stream:
            if _identity(os.fstat(input_stream.fileno())) != _identity(source_info):
                raise ValueError("source changed before copying")
            for asset_name, offset, expected_size in specifications:
                input_stream.seek(offset)
                asset_path = destination_path / asset_name
                output_stream, identity = _exclusive_output(asset_path)
                created.append((asset_path, identity))
                part_size = 0
                with output_stream:
                    remaining = expected_size
                    while remaining:
                        chunk = input_stream.read(min(_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise ValueError("source ended while copying")
                        output_stream.write(chunk)
                        copied_digest.update(chunk)
                        part_size += len(chunk)
                        copied_size += len(chunk)
                        remaining -= len(chunk)
                if part_size != expected_size:
                    raise ValueError("source changed while copying")
            after = os.fstat(input_stream.fileno())
        if _identity(after) != _identity(source_info) or copied_size != source_size or copied_digest.hexdigest() != source_digest:
            raise ValueError("source changed while copying")
        with_digest_entries = []
        for asset_name, _, expected_size in specifications:
            asset_path = destination_path / asset_name
            _, actual_size, actual_digest = _file_metadata(asset_path)
            if actual_size != expected_size:
                raise ValueError("created asset size changed during packaging")
            with_digest_entries.append({"name": asset_name, "size": actual_size, "sha256": actual_digest})
        return {
            "schema": 1,
            "iso": {"name": source_path.name, "size": source_size, "sha256": source_digest},
            "assets": with_digest_entries,
        }
    except Exception:
        for path, identity in reversed(created):
            _remove_owned(path, identity)
        raise


def _verify_asset(path: Path, entry: dict[str, object]) -> os.stat_result:
    info, size, digest = _file_metadata(path)
    if size != entry["size"] or digest != entry["sha256"]:
        raise ValueError(f"asset checksum or size mismatch: {path.name}")
    return info


def verify_and_reassemble(manifest: dict, asset_root: Path, output: Path) -> None:
    """Verify every declared asset, then exclusively create the reconstructed ISO."""
    _, expected_size, expected_digest, assets = _validate_manifest(manifest)
    root = _check_path_chain(Path(asset_root))
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("asset_root must be an existing directory")
    verified: list[tuple[Path, dict[str, object], os.stat_result]] = []
    for entry in assets:
        path = root / str(entry["name"])
        info = _verify_asset(path, entry)
        verified.append((path, entry, info))

    output_path = Path(output)
    if output_path.name == "":
        raise ValueError("output must name a file")
    created_identity: tuple[int, int] | None = None
    try:
        output_stream, created_identity = _exclusive_output(output_path)
        digest = hashlib.sha256()
        total = 0
        with output_stream:
            for source, entry, verified_info in verified:
                with _open_regular(source)[0] as input_stream:
                    if _identity(os.fstat(input_stream.fileno())) != _identity(verified_info):
                        raise ValueError(f"asset changed after verification: {source.name}")
                    part_size = 0
                    part_digest = hashlib.sha256()
                    while chunk := input_stream.read(_CHUNK_BYTES):
                        output_stream.write(chunk)
                        digest.update(chunk)
                        part_digest.update(chunk)
                        total += len(chunk)
                        part_size += len(chunk)
                    after = os.fstat(input_stream.fileno())
                if _identity(after) != _identity(verified_info) or part_size != entry["size"] or part_digest.hexdigest() != entry["sha256"]:
                    raise ValueError(f"asset changed while copying: {source.name}")
        if total != expected_size or digest.hexdigest() != expected_digest:
            raise ValueError("reassembled ISO checksum or size mismatch")
    except Exception:
        if created_identity is not None:
            _remove_owned(output_path, created_identity)
        raise
