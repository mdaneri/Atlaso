"""Bound temporary browser upload sessions without exposing incomplete artifacts."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from secrets import token_hex
from typing import BinaryIO, cast

CHUNK_BYTES = 8 * 1024**2
SESSION_SECONDS = 30 * 60
UPLOAD_ROOT = Path("/mnt/atlaso-vcf-offline-depot/.atlaso-uploads")


class UploadError(Exception):
    """Carry only a fixed public error and its HTTP status."""

    def __init__(self, status: int, message: str) -> None:
        """  init  .

        Args:
            status: HTTP status for the fixed protocol error.
            message: Fixed public protocol message without underlying exception details.
        """
        super().__init__(message)
        self.status = status


@dataclass
class UploadSession:
    """Hold process-local ownership and an unpublished upload handle."""

    owner: str
    target: str
    field: str
    filename: str
    size: int
    file: BinaryIO
    expires: float
    offset: int = 0
    claimed: bool = False


class UploadStore:
    """Serialize offset changes, reserve capacity, and expire abandoned handles.

    Small files stay in memory, including credential files. Large files use an
    anonymous, mode-0600 temporary file on the depot volume. Restart deliberately
    invalidates sessions and the OS closes their anonymous files.
    """

    def __init__(self) -> None:
        self.sessions: dict[str, UploadSession] = {}
        self.lock = threading.RLock()
        self.timer: threading.Timer | None = None

    def _sweep(self) -> None:
        """Close expired sessions even when no subsequent request arrives."""
        with self.lock:
            self.timer = None
            for key, session in list(self.sessions.items()):
                if not session.claimed and session.expires <= time.monotonic():
                    self.sessions.pop(key).file.close()
            if self.sessions:
                self._schedule()

    def _schedule(self) -> None:
        """Keep one bounded cleanup timer while sessions exist."""
        if self.timer is None:
            self.timer = threading.Timer(60, self._sweep)
            self.timer.daemon = True
            self.timer.start()

    def close(self) -> None:
        """Release all process-owned staging during application shutdown."""
        with self.lock:
            if self.timer:
                self.timer.cancel()
                self.timer = None
            for session in self.sessions.values():
                session.file.close()
            self.sessions.clear()

    def create(self, owner: str, target: str, field: str, filename: str, size: int) -> str:
        """Reserve bounded staging without creating any discoverable artifact.

        Args:
            owner: Authenticated browser-session identifier.
            target: Exact destination endpoint path bound to this file.
            field: Existing endpoint file-field name.
            filename: Original basename validated before publication.
            size: Declared total file length in bytes.
        """
        with self.lock:
            if (len(self.sessions) >= 16
                    or sum(s.owner == owner for s in self.sessions.values()) >= 4
                    or sum(s.size for s in self.sessions.values()) + size > 32 * 1024**3):
                raise UploadError(429, "Upload capacity is busy. Finish or cancel another upload first.")
            handle: BinaryIO
            if size <= 16 * 1024**2:
                handle = io.BytesIO()
            else:
                root = UPLOAD_ROOT
                if not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents)):
                    raise UploadError(503, "Upload staging is unavailable.")
                if not root.parent.is_dir():
                    raise UploadError(503, "The upload storage volume is unavailable.")
                root.mkdir(mode=0o700, exist_ok=True)
                if os.name == "posix" and root.stat().st_mode & 0o022:
                    raise UploadError(503, "Upload staging permissions are unsafe.")
                reserved = sum(s.size for s in self.sessions.values())
                if shutil.disk_usage(root).free < (reserved + size) * 2 + 64 * 1024**2:
                    raise UploadError(507, "Insufficient free space for upload and validation.")
                handle = cast(BinaryIO, tempfile.TemporaryFile(mode="w+b", dir=root))
            key = token_hex(24)
            self.sessions[key] = UploadSession(owner, target, field, filename, size, handle,
                                               time.monotonic() + SESSION_SECONDS)
            self._schedule()
            return key

    def get(self, key: str, owner: str) -> UploadSession:
        """Resolve an unexpired session without revealing another owner's state.

        Args:
            key: Opaque process-local upload identifier.
            owner: Authenticated browser-session identifier.
        """
        session = self.sessions.get(key)
        if session is None or session.claimed or session.owner != owner or session.expires <= time.monotonic():
            raise UploadError(404, "Upload expired or is unavailable. Select the file again.")
        return session

    def append(self, key: str, owner: str, offset: int, data: bytes, digest: str) -> int:
        """Accept exact-offset chunks and byte-identical retries atomically.

        Args:
            key: Opaque process-local upload identifier.
            owner: Authenticated browser-session identifier.
            offset: Expected contiguous byte offset.
            data: Bytes supplied by this test or upload chunk.
            digest: Expected hexadecimal SHA-256 digest of the chunk.
        """
        with self.lock:
            session = self.get(key, owner)
            if not data or len(data) > CHUNK_BYTES or hashlib.sha256(data).hexdigest() != digest:
                raise UploadError(400, "Invalid upload chunk or checksum.")
            if offset < 0 or offset + len(data) > session.size:
                raise UploadError(413, "Chunk exceeds the declared file size.")
            if offset < session.offset:
                session.file.seek(offset)
                if offset + len(data) > session.offset or session.file.read(len(data)) != data:
                    raise UploadError(409, "Upload offset conflict.")
            elif offset == session.offset:
                session.file.seek(offset)
                try:
                    session.file.write(data)
                    session.file.flush()
                except OSError:
                    session.file.truncate(offset)
                    raise
                session.offset += len(data)
            else:
                raise UploadError(409, "Upload offset conflict.")
            session.expires = time.monotonic() + SESSION_SECONDS
            return session.offset

    def claim(self, keys: list[str], owner: str, target: str) -> list[UploadSession]:
        """Consume complete sessions once, together, before endpoint validation.

        Args:
            keys: Upload identifiers to consume together.
            owner: Authenticated browser-session identifier.
            target: Exact destination endpoint path bound to this file.
        """
        with self.lock:
            if len(keys) != len(set(keys)):
                raise UploadError(400, "Duplicate upload session.")
            sessions = [self.get(key, owner) for key in keys]
            if any(s.target != target or s.offset != s.size for s in sessions):
                raise UploadError(409, "Upload is incomplete or belongs to another form.")
            for session in sessions:
                session.claimed = True
                session.file.seek(0)
            return sessions

    def release(self, keys: list[str]) -> None:
        """Release claimed capacity only after the consuming endpoint finishes.

        Args:
            keys: Upload identifiers to consume together.
        """
        with self.lock:
            for key in keys:
                session = self.sessions.pop(key, None)
                if session is not None:
                    session.file.close()

    def cancel(self, key: str, owner: str) -> None:
        """Close a session belonging to this browser session.

        Args:
            key: Opaque process-local upload identifier.
            owner: Authenticated browser-session identifier.
        """
        with self.lock:
            self.get(key, owner)
            self.sessions.pop(key).file.close()


upload_store = UploadStore()
