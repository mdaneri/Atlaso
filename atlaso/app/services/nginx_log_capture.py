"""Replay cooperatively sealed Nginx generations into immutable producer rows.

The lifecycle collector owns sequencing and its exclusive lock. This layer never
deletes a raw generation or changes the operating system's retention policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from typing import Any, BinaryIO

from atlaso.app.services import producer_log_history
from atlaso.app.services.nginx_log_sealing import LOG_NAMES

BATCH_INPUT_BYTES = 192 * 1024
LINE_INPUT_BYTES = 64 * 1024


def _record_chunks(stream: BinaryIO, end: int) -> Iterator[bytes]:
    """Yield one previously bounded sealed record without materializing it.

    Args:
        stream: Authenticated sealed file positioned at the record's beginning.
        end: Exclusive offset established by the bounded physical-line scan.
    """
    while stream.tell() < end:
        chunk = stream.read(min(LINE_INPUT_BYTES, end - stream.tell()))
        if not chunk:
            raise ValueError("Sealed Nginx record ended before its capture boundary.")
        yield chunk


def _checkpoint(directory: Path, state: dict[str, Any]) -> None:
    """Persist receipt replay information before acknowledging an input offset.

    Args:
        directory: Private sealed generation directory.
        state: Metadata-only source offsets and pending receipt identities.
    """
    temporary = directory / "capture.pending"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, directory / "capture.json")
    if os.name == "posix":
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def capture_generation(store: Path, directory: Path) -> None:
    """Capture a complete sealed pair with durable idempotent batch receipts.

    A crash after append but before checkpoint publication replays exactly the
    same source/revision/input batch. The store receipt rejects changed retries
    and cannot let a duplicate footer change a newer private-key checkpoint.
    The caller must process generations in original order under its own lock.

    Args:
        store: Trusted initialized Nginx producer store with legacy import complete.
        directory: Trusted private directory whose generation is already sealed.
    """
    manifest_path, capture_path = directory / "manifest.json", directory / "capture.json"
    if directory.is_symlink() or manifest_path.is_symlink() or capture_path.is_symlink():
        raise ValueError("Linked Nginx generation state.")
    if manifest_path.stat().st_size > 4096 or (capture_path.exists() and capture_path.stat().st_size > 4096):
        raise ValueError("Oversized Nginx generation state.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("schema") != 1 or manifest.get("state") != "sealed" or
            set(manifest.get("files", {})) != set(LOG_NAMES)):
        raise ValueError("Nginx capture requires a complete sealed generation.")
    generation = producer_log_history.read_page(store, "nginx-access", limit=1).generation
    if capture_path.exists():
        state = json.loads(capture_path.read_text(encoding="utf-8"))
        if state.get("schema") != 1 or state.get("store_generation") != generation:
            raise ValueError("Nginx capture store changed during generation replay.")
    else:
        state = {"schema": 1, "store_generation": generation,
                 "files": {name: {"offset": 0, "pending": None} for name in LOG_NAMES}}
        _checkpoint(directory, state)
    for name in LOG_NAMES:
        source = "nginx-access" if name == "access.log" else "nginx-error"
        source_path = directory / name
        expected = manifest["files"][name]
        entry = state["files"][name]
        descriptor = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    [info.st_dev, info.st_ino] != expected["identity"] or info.st_size != expected["size"] or
                    hashlib.file_digest(stream, "sha256").hexdigest() != expected["sha256"]):
                raise ValueError("Nginx sealed generation identity or contents changed.")
            offset = entry["offset"]
            if type(offset) is not int or not 0 <= offset <= info.st_size:
                raise ValueError("Invalid Nginx capture offset.")
            stream.seek(offset)
            while offset < info.st_size:
                lines: list[str] = []
                oversized = False
                batch_start = offset
                while offset - batch_start < BATCH_INPUT_BYTES and len(lines) < 500:
                    raw = stream.readline(LINE_INPUT_BYTES + 1)
                    if not raw:
                        break
                    if len(raw) > LINE_INPUT_BYTES:
                        if lines:
                            stream.seek(offset)
                            break
                        # The oversized record receives its own receipt. Discover
                        # its physical boundary using bounded reads, then stream
                        # it under the store's checkpoint transaction below.
                        while not raw.endswith(b"\n"):
                            raw = stream.readline(LINE_INPUT_BYTES)
                            if not raw:
                                break
                        offset, oversized = stream.tell(), True
                        break
                    lines.append(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
                    offset = stream.tell()
                pending = entry["pending"]
                if pending is None:
                    with closing(sqlite3.connect(store.resolve().as_uri() + "?mode=ro", uri=True)) as db:
                        receipt = db.execute("SELECT revision FROM receipt WHERE source=? AND writer='service'",
                                             (source,)).fetchone()
                    pending = {"start": batch_start, "end": offset,
                               "revision": int(receipt[0]) + 1 if receipt else 1}
                    entry["pending"] = pending
                    _checkpoint(directory, state)
                if pending["start"] != batch_start or pending["end"] != offset:
                    raise ValueError("Nginx pending capture does not match its sealed input.")
                if oversized:
                    stream.seek(batch_start)
                    producer_log_history.append_stream(store, source, _record_chunks(stream, offset),
                                                       writer="service", revision=pending["revision"])
                else:
                    producer_log_history.append(store, source, lines, writer="service", revision=pending["revision"])
                entry["offset"], entry["pending"] = offset, None
                _checkpoint(directory, state)
            after = os.fstat(stream.fileno())
            if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                raise ValueError("Sealed Nginx input changed during capture.")
