"""Read complete retained log history in authenticated, bounded pages."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import stat
import time
import zlib
from collections import OrderedDict
from contextlib import nullcontext
from pathlib import Path
from threading import RLock
from typing import Any

from itsdangerous import BadSignature, URLSafeSerializer

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.operational_logging import redact_operational_text

PAGE_LINES = 500
PAGE_BYTES = 1024 * 1024
LINE_BYTES = 64 * 1024


def _file_available(path: Path) -> bool:
    """Probe readable retained-file metadata without loading log contents.

    Args:
        path: Server-owned current log path and numbered rotation prefix.
    """
    try:
        candidates = [path] + [candidate for candidate in path.parent.glob(f"{path.name}.*")
                               if re.fullmatch(re.escape(path.name) + r"\.\d+(\.gz)?", candidate.name)]
        for candidate in candidates:
            if candidate.is_symlink():
                continue
            try:
                descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                try:
                    if stat.S_ISREG(os.fstat(descriptor).st_mode):
                        return True
                finally:
                    os.close(descriptor)
            except OSError:
                continue
    except OSError:
        pass
    return False


def source_availability() -> dict[str, Any]:
    """Return fixed-source metadata so disabled tabs can recover without reading history."""
    sources = [{"id": "app", "available": _file_available(get_settings().app_log_path)},
               {"id": "kms", "available": _file_available(Path("/var/log/atlaso/kmip/server.log"))}]
    result = SystemAdapter().read_log_history("availability", {})
    if not result.returncode:
        payload = json.loads(result.stdout)
        sources.extend(payload.get("sources", []))
    return {"sources": sources}


def source_page(source: str, *, cursor: str = "", tail: bool = False, limit: int = PAGE_LINES) -> dict[str, Any]:
    """Read one authorized fixed-source page and redact before transport.

    Args:
        source: Fixed source selected in the authenticated Logs viewer.
        cursor: Signed position belonging to this source.
        tail: Open the newest retained page when no cursor is supplied.
        limit: Selected bounded page size; total retained history is unchanged.
    """
    if source == "app":
        return file_page(get_settings().app_log_path, source=source, cursor=cursor, tail=tail, limit=limit)
    if source == "kms":
        return file_page(Path("/var/log/atlaso/kmip/server.log"), source=source, cursor=cursor, tail=tail, limit=limit)
    if source not in {"dnsmasq-dns", "dnsmasq-dhcp", "dnsmasq-tftp", "ldap", "ntp", "esx-storage", "nginx", "nginx-access", "nginx-error"}:
        raise ValueError("Unknown log source.")
    position = decode_cursor(cursor, source)
    if tail and not cursor:
        position["tail"] = True
    position["limit"] = max(1, min(PAGE_LINES, limit))
    result = SystemAdapter().read_log_history(source, position)
    if result.returncode:
        raise ValueError("Log history is temporarily unavailable. Your displayed page is preserved.")
    payload = json.loads(result.stdout)
    initial_private_key = not payload.get("reset") and payload.get("initial_private_key", position.get("private_key")) is True
    lines, private_key = redact_lines(payload["lines"], private_key=initial_private_key)
    if payload.get("line_private_keys") is not None:
        states = payload["line_private_keys"]
        if not isinstance(states, list) or len(states) != len(payload["lines"]) or any(type(state) is not bool for state in states):
            raise ValueError("Invalid classified log redaction state.")
        lines = []
        for line, state in zip(payload["lines"], states, strict=True):
            safe, private_key = redact_lines([line], private_key=state)
            lines.extend(safe)
    if type(payload.get("final_private_key")) is bool:
        private_key = payload["final_private_key"]
    previous_position = payload.get("previous_position")
    next_position = payload.get("file_position", payload.get("journal_position", {"journal_cursor": payload.get("journal_cursor", "")}))
    current = encode_cursor(source, **payload["current_position"], private_key=initial_private_key) if "current_position" in payload else cursor
    return {"source": source, "available": payload.get("available", True), "text": "\n".join(lines), "cursor": current,
            "next_cursor": encode_cursor(source, **next_position, private_key=private_key),
            "previous_cursor": encode_cursor(source, **previous_position) if previous_position else "",
            "has_more": payload["has_more"], "notice": "Retained history changed; reopened the oldest available file." if payload.get("reset") else "",
            "reset": payload.get("reset", False)}


def _serializer() -> URLSafeSerializer:
    """Bind opaque history positions to the appliance's signing key."""
    return URLSafeSerializer(get_settings().secret_key, salt="atlaso-log-history-v1")


def decode_cursor(cursor: str, source: str) -> dict[str, Any]:
    """Validate a source-bound position before using any file offset.

    Args:
        cursor: Opaque position previously returned by this appliance.
        source: Authorized source identity selected by the endpoint.
    """
    if not cursor:
        return {}
    if len(cursor) > 4096:
        raise ValueError("Invalid log history position.")
    try:
        value = _serializer().loads(cursor)
    except BadSignature as exc:
        raise ValueError("Invalid log history position. Open the log again.") from exc
    if not isinstance(value, dict) or value.get("source") != source:
        raise ValueError("Log history position belongs to another source.")
    return value


def encode_cursor(source: str, **position: Any) -> str:
    """Sign a position and redaction state for one authorized source.

    Args:
        source: Authorized source identity.
        **position: File or journal position and redaction state.
    """
    return str(_serializer().dumps({"source": source, **position}))


def redact_lines(lines: list[str], *, private_key: bool = False) -> tuple[list[str], bool]:
    """Carry private-key redaction across authenticated page boundaries.

    Args:
        lines: Complete source lines for this page.
        private_key: Whether the preceding page ended inside a private key.
    """
    output = []
    for line in lines:
        conceal = private_key
        for marker in re.finditer(r"-----(BEGIN|END) (?:(?!-----)[ -~])*?PRIVATE KEY-----", line):
            conceal = True
            private_key = marker.group(1) == "BEGIN"
        output.append("[redacted private key]" if conceal else redact_operational_text(line))
    return output, private_key


def _log_wire_size(line: str) -> int:
    """Measure a displayed line after JSON escaping, including its separator.

    Args:
        line: Decoded retained line before transport serialization.
    """
    return len(json.dumps(line, ensure_ascii=False).encode("utf-8")) + 1


def _tail_offset(handle: Any, *, compressed: bool, deadline: float, end: int | None = None, limit: int = 500) -> tuple[int, bool]:
    """Locate the newest bounded group without replaying pages to the client.

    Args:
        handle: Verified regular source stream.
        compressed: Whether seeking requires bounded decompression.
        deadline: Shared monotonic deadline for the request.
        end: Optional exclusive boundary for the preceding page.
        limit: Maximum physical lines in the selected group.
    """
    if compressed:
        data, total = b"", 0
        handle.seek(0)
        while end is None or total < end:
            chunk = handle.read(min(65536, end - total) if end is not None else 65536)
            if not chunk:
                break
            if time.monotonic() > deadline:
                raise ValueError("Archived tail scan exceeded its deadline; open from the beginning.")
            total += len(chunk)
            data = (data + chunk)[-1024 * 1024:]
    else:
        total = handle.seek(0, os.SEEK_END)
        if end is not None:
            total = min(total, end)
        handle.seek(max(0, total - 1024 * 1024))
        data = handle.read(min(total, 1024 * 1024))
    offset = total - len(data)
    if offset:
        boundary = data.find(b"\n")
        if boundary < 0:
            return (offset if end is not None else total), True
        if boundary == len(data) - 1:
            return offset, True
        offset += boundary + 1
        data = data[boundary + 1:]
    starts = [0] + [match.end() for match in re.finditer(b"\n", data) if match.end() < len(data)]
    selected_start, wire_bytes, boundary = len(data), 0, len(data)
    for start in reversed(starts[-limit:]):
        line = data[start:boundary]
        size = _log_wire_size(line.decode("utf-8", errors="replace").rstrip("\r\n")) if len(line) <= 65536 else 128
        if wire_bytes and wire_bytes + size > 1024 * 1024 - 16384:
            break
        selected_start = start
        wire_bytes += size
        boundary = start
    return offset + selected_start, False


class _TailScanPending(ValueError):
    """Signal that a bounded redaction scan saved progress for the next request."""


_TAIL_REDACTION_CACHE: OrderedDict[tuple[str, int, int], tuple[bool, bytes, bytes, int, int, Any]] = OrderedDict()
_TAIL_REDACTION_LOCK = RLock()



_PREFIX_VERIFICATION_CACHE: OrderedDict[tuple[Any, ...], tuple[int, Any]] = OrderedDict()


def _verify_retained_prefix(raw: Any, path: Path, offset: int, expected: bytes, *, deadline: float) -> bool:
    """Resume hashing a prefix only while its complete source version is unchanged.

    Args:
        raw: Verified regular file descriptor owned by the caller.
        path: Server-selected path binding this verification to its source.
        offset: Exclusive prefix boundary requiring authentication.
        expected: SHA-256 digest captured with the redaction checkpoint.
        deadline: Shared request deadline with rendering time reserved.
    """
    info = os.fstat(raw.fileno())
    version = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    if info.st_size < offset:
        return False
    key = (str(path), *version, offset, expected)
    with _TAIL_REDACTION_LOCK:
        saved = _PREFIX_VERIFICATION_CACHE.get(key)
        checked, verification = (saved[0], saved[1].copy()) if saved else (0, hashlib.sha256())
    raw.seek(checked)
    while checked < offset and time.monotonic() < deadline - 0.25:
        chunk = raw.read(min(65536, offset - checked))
        if not chunk:
            return False
        verification.update(chunk)
        checked += len(chunk)
    after = os.fstat(raw.fileno())
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != version:
        raise _TailScanPending("Retained history changed during verification; retrying against its new version.")
    with _TAIL_REDACTION_LOCK:
        _PREFIX_VERIFICATION_CACHE[key] = (checked, verification.copy())
        _PREFIX_VERIFICATION_CACHE.move_to_end(key)
        while len(_PREFIX_VERIFICATION_CACHE) > 32:
            _PREFIX_VERIFICATION_CACHE.popitem(last=False)
    if checked < offset:
        raise _TailScanPending("Verifying retained history; the next request resumes the saved hash.")
    return verification.digest() == expected

def _scan_pem_markers(chunk: bytes, carry: bytes = b"") -> tuple[bool | None, bytes]:
    """Track arbitrarily long PEM labels with only fixed-token parser state.

    Args:
        chunk: Next contiguous source fragment.
        carry: Prior parser mode and partial fixed token, never arbitrary label bytes.
    """
    starts = (b"-----BEGIN ", b"-----END ")
    endings = (b"PRIVATE KEY-----", b"-----")
    start_parts = sorted({token[:size] for token in starts for size in range(1, len(token))}, key=len, reverse=True)
    end_parts = sorted({token[:size] for token in endings for size in range(1, len(token))}, key=len, reverse=True)
    mode = carry[:1] or b"S"
    suffix = carry[1:]
    allowed = start_parts if mode == b"S" else end_parts
    if mode not in (b"S", b"B", b"E") or (suffix and suffix not in allowed):
        raise ValueError("Invalid private-key parser state.")
    data = suffix + chunk
    position = 0
    last = None
    start_pattern = re.compile(rb"-----(BEGIN|END) ")
    boundary_pattern = re.compile(rb"-----|[^ -~]")
    while True:
        if mode == b"S":
            match = start_pattern.search(data, position)
            if match is None:
                suffix = next((part for part in start_parts if data.endswith(part, position)), b"")
                return last, b"S" + suffix
            position = match.end()
            mode = b"B" if match.group(1) == b"BEGIN" else b"E"
        boundary = boundary_pattern.search(data, position)
        if boundary is None:
            suffix = next((part for part in end_parts if data.endswith(part, position)), b"")
            return last, mode + suffix
        start = boundary.start()
        if boundary.group() == b"-----" and data.endswith(b"PRIVATE KEY", position, start):
            last = mode == b"B"
            position = boundary.end()
        else:
            position = start if boundary.group() == b"-----" else boundary.end()
        mode = b"S"


def _tail_private_key(paths: list[Path], offset: int, *, deadline: float) -> bool:
    """Return completed private-key state at a retained byte boundary.

    Args:
        paths: Ordered retained source files.
        offset: Uncompressed boundary in the last source.
        deadline: Shared request deadline.
    """
    return _tail_marker_state(paths, offset, deadline=deadline)[0]


def _tail_marker_state(paths: list[Path], offset: int, *, deadline: float) -> tuple[bool, bytes]:
    """Recover redaction state using bounded, verified in-process checkpoints.

    Args:
        paths: Fixed retained files through the selected newest source.
        offset: Uncompressed byte boundary within the selected source.
        deadline: Shared monotonic deadline for the request.
    """
    if any(path.suffix == ".gz" for path in paths):
        return _compressed_tail_private_key(paths, offset, deadline=deadline)
    identities = [path.lstat() for path in paths]
    context = hashlib.sha256(repr([
        (str(path), info.st_dev, info.st_ino,
         info.st_size if index < len(paths) - 1 else None,
         info.st_mtime_ns if index < len(paths) - 1 else None)
        for index, (path, info) in enumerate(zip(paths, identities, strict=True))
    ]).encode()).hexdigest()
    stop = min(deadline - 0.25, time.monotonic() + 2)
    with _TAIL_REDACTION_LOCK:
        candidates = [key for key in _TAIL_REDACTION_CACHE if key[0] == context
                      and (key[1] < len(paths) - 1 or key[2] <= offset)]
        checkpoint = max(candidates, key=lambda key: key[1:]) if candidates else None
        cached = _TAIL_REDACTION_CACHE.get(checkpoint) if checkpoint else None
    opened, carry, start_index, start_offset = False, b"", 0, 0
    prefix_digest = hashlib.sha256()
    if checkpoint and cached:
        start_index, start_offset = checkpoint[1:]
        opened, carry, fingerprint, saved_size, saved_mtime, saved_digest = cached
        prefix_digest = saved_digest.copy()
        authenticated = False
        path = paths[start_index]
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as raw:
            if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
                raise ValueError("Retained log is not a regular file.")
            with (gzip.GzipFile(fileobj=raw) if path.suffix == ".gz" else nullcontext(raw)) as stream:
                prefix = stream.read(min(start_offset, 4096))
                stream.seek(max(0, start_offset - 128))
                anchor = stream.read(min(start_offset, 128))
                if identities[start_index].st_size >= start_offset:
                    if (identities[start_index].st_mtime_ns == saved_mtime and identities[start_index].st_size == saved_size):
                        authenticated = True
                    else:
                        authenticated = _verify_retained_prefix(raw, path, start_offset, saved_digest.digest(), deadline=deadline)
        if hashlib.sha256(prefix + anchor).digest() != fingerprint or not authenticated:
            with _TAIL_REDACTION_LOCK:
                for key in candidates:
                    _TAIL_REDACTION_CACHE.pop(key, None)
            opened, carry, start_index, start_offset = False, b"", 0, 0
            prefix_digest = hashlib.sha256()
    for index in range(start_index, len(paths)):
        if index != start_index:
            prefix_digest = hashlib.sha256()
        path = paths[index]
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as raw:
            if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
                raise ValueError("Retained log is not a regular file.")
            with (gzip.GzipFile(fileobj=raw) if path.suffix == ".gz" else nullcontext(raw)) as stream:
                prefix = stream.read(4096)
                stream.seek(start_offset if index == start_index else 0)
                while index < len(paths) - 1 or stream.tell() < offset:
                    chunk = stream.read(min(65536, offset - stream.tell()) if index == len(paths) - 1 else 65536)
                    if not chunk:
                        break
                    prefix_digest.update(chunk)
                    marker_state, carry = _scan_pem_markers(chunk, carry)
                    if marker_state is not None:
                        opened = marker_state
                    scanned = stream.tell()
                    # Only source fingerprints and bounded state remain in process memory.
                    if len(chunk) >= 128:
                        anchor = chunk[-128:]
                    else:
                        stream.seek(max(0, scanned - 128))
                        anchor = stream.read(min(scanned, 128))
                        stream.seek(scanned)
                    key = (context, index, scanned)
                    with _TAIL_REDACTION_LOCK:
                        _TAIL_REDACTION_CACHE[key] = (opened, carry, hashlib.sha256(prefix[:min(scanned, 4096)] + anchor).digest(),
                                                      identities[index].st_size, identities[index].st_mtime_ns, prefix_digest.copy())
                        _TAIL_REDACTION_CACHE.move_to_end(key)
                        while len(_TAIL_REDACTION_CACHE) > 128:
                            _TAIL_REDACTION_CACHE.popitem(last=False)
                    if time.monotonic() > stop and (index < len(paths) - 1 or scanned < offset):
                        raise _TailScanPending("Preparing retained history; the next request resumes this scan.")
    for path, before in zip(paths, identities, strict=True):
        after = path.lstat()
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) !=
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
            raise _TailScanPending("Retained history changed during preparation; retrying from verified state.")
    return opened, carry


_COMPRESSED_REDACTION_CACHE: OrderedDict[tuple[str, int, int], tuple[bool, bytes, Any, int, bytes, bool, Any, int, int]] = OrderedDict()


def _compressed_tail_private_key(paths: list[Path], offset: int, *, deadline: float) -> tuple[bool, bytes]:
    """Resume bounded decompression using immutable source-version checkpoints.

    Args:
        paths: Fixed retained files through the selected newest source.
        offset: Uncompressed byte boundary within the selected source.
        deadline: Shared monotonic deadline for the request.
    """
    identities = [path.lstat() for path in paths]
    versions = [(str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                for path, info in zip(paths, identities, strict=True)]
    context_versions: list[tuple[str, int, int, int | None, int | None]] = list(versions)
    if paths and paths[-1].suffix != ".gz":
        context_versions[-1] = (*versions[-1][:3], None, None)
    contexts = [hashlib.sha256(repr(context_versions[:index + 1]).encode()).hexdigest() for index in range(len(paths))]
    stop = min(deadline - 0.25, time.monotonic() + 2)
    opened, carry, start_index, expanded = False, b"", 0, 0
    decoder, raw_offset, pending, finished = None, 0, b"", False
    prefix_digest = hashlib.sha256()
    saved_size, saved_mtime = 0, 0
    with _TAIL_REDACTION_LOCK:
        candidates = [key for key in _COMPRESSED_REDACTION_CACHE
                      if key[1] < len(paths) and key[0] == contexts[key[1]]
                      and (key[1] < len(paths) - 1 or key[2] <= offset)]
        if candidates:
            key = max(candidates, key=lambda item: item[1:])
            opened, carry, saved_decoder, raw_offset, pending, finished, saved_digest, saved_size, saved_mtime = _COMPRESSED_REDACTION_CACHE[key]
            prefix_digest = saved_digest.copy()
            decoder = saved_decoder.copy() if saved_decoder is not None else None
            start_index, expanded = key[1:]
            _COMPRESSED_REDACTION_CACHE.move_to_end(key)
    if candidates and start_index == len(paths) - 1 and paths[-1].suffix != ".gz" and (
            identities[-1].st_size != saved_size or identities[-1].st_mtime_ns != saved_mtime):
        descriptor = os.open(paths[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as raw:
            if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
                raise ValueError("Retained log is not a regular file.")
            authenticated = _verify_retained_prefix(raw, paths[-1], expanded, prefix_digest.digest(), deadline=deadline)
        if not authenticated:
            with _TAIL_REDACTION_LOCK:
                for candidate in candidates:
                    if candidate[1] == len(paths) - 1:
                        _COMPRESSED_REDACTION_CACHE.pop(candidate, None)
            opened, carry, start_index, expanded = False, b"", 0, 0
            decoder, raw_offset, pending = None, 0, b""
            prefix_digest = hashlib.sha256()
        finished = False
    for index in range(start_index, len(paths)):
        path = paths[index]
        if index != start_index:
            decoder, raw_offset, pending, finished, expanded = None, 0, b"", False, 0
            prefix_digest = hashlib.sha256()
        compressed = path.suffix == ".gz"
        if compressed and decoder is None:
            decoder = zlib.decompressobj(31)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as raw:
            info = os.fstat(raw.fileno())
            if (not stat.S_ISREG(info.st_mode) or
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != versions[index][1:]):
                raise _TailScanPending("Retained history changed during preparation; retrying from verified state.")
            raw.seek(raw_offset)
            while not finished and (index < len(paths) - 1 or expanded < offset):
                count = min(65536, offset - expanded) if index == len(paths) - 1 else 65536
                if compressed:
                    assert decoder is not None
                    if not pending:
                        pending = raw.read(16384)
                        raw_offset += len(pending)
                    if not pending:
                        if not decoder.eof:
                            raise ValueError("Retained gzip history is incomplete.")
                        finished, chunk = True, b""
                    else:
                        if decoder.eof:
                            pending = pending.lstrip(b"\x00")
                            if pending:
                                decoder = zlib.decompressobj(31)
                        if pending:
                            try:
                                chunk = decoder.decompress(pending, count)
                            except zlib.error as exc:
                                raise ValueError("Retained gzip history is invalid.") from exc
                            pending = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
                        else:
                            chunk = b""
                else:
                    chunk = raw.read(count)
                    raw_offset += len(chunk)
                    finished = not chunk
                expanded += len(chunk)
                prefix_digest.update(chunk)
                marker_state, carry = _scan_pem_markers(chunk, carry)
                if marker_state is not None:
                    opened = marker_state
                key = (contexts[index], index, expanded)
                with _TAIL_REDACTION_LOCK:
                    _COMPRESSED_REDACTION_CACHE[key] = (opened, carry, decoder.copy() if decoder is not None else None,
                                                       raw_offset, pending, finished, prefix_digest.copy(),
                                                       identities[index].st_size, identities[index].st_mtime_ns)
                    _COMPRESSED_REDACTION_CACHE.move_to_end(key)
                    while len(_COMPRESSED_REDACTION_CACHE) > 32:
                        _COMPRESSED_REDACTION_CACHE.popitem(last=False)
                if time.monotonic() > stop and (index < len(paths) - 1 or (not finished and expanded < offset)):
                    raise _TailScanPending("Preparing retained history; the next request resumes this scan.")
    for path, before in zip(paths, identities, strict=True):
        after = path.lstat()
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) !=
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
            raise _TailScanPending("Retained history changed during preparation; retrying from verified state.")
    return opened, carry


def _history_window(handle: Any, offset: int, *, compressed: bool, deadline: float) -> bytes:
    """Read a bounded content window immediately before a retained byte position.

    Args:
        handle: Verified regular retained stream.
        offset: Uncompressed position whose preceding content must remain stable.
        compressed: Whether seeking needs bounded decompression.
        deadline: Shared request deadline.
    """
    length = min(offset, 4096)
    start = offset - length
    handle.seek(0 if compressed else start)
    remaining = start if compressed else 0
    while remaining:
        if time.monotonic() > deadline:
            raise ValueError("Retained history scan exceeded its deadline.")
        chunk = handle.read(min(65536, remaining))
        if not chunk:
            raise ValueError("Retained history position is unavailable.")
        remaining -= len(chunk)
    return bytes(handle.read(length))


def _history_anchor(handle: Any, offset: int, *, compressed: bool, deadline: float) -> dict[str, Any]:
    """Fingerprint the content immediately before a retained byte position.

    Args:
        handle: Verified regular retained stream.
        offset: Uncompressed position whose preceding content must remain stable.
        compressed: Whether seeking needs bounded decompression.
        deadline: Shared request deadline.
    """
    window = _history_window(handle, offset, compressed=compressed, deadline=deadline)
    return {"anchor_length": min(offset, 4096), "anchor": hashlib.sha256(window).hexdigest()}


_GZIP_WINDOW_BYTES = PAGE_BYTES + LINE_BYTES + 8192
_GZIP_WINDOW_CACHE: OrderedDict[tuple[Any, ...], tuple[int, bytes, bytes, Any, int, bytes, bool]] = OrderedDict()


class _GzipHistoryWindow:
    """Expose the prepared prefix and bounded page window at absolute offsets."""

    def __init__(self, expanded: int, window: bytes, prefix: bytes) -> None:
        """Bind immutable decompressed bytes for one page request.

        Args:
            expanded: Absolute end of the prepared window.
            window: Bounded bytes ending at the prepared boundary.
            prefix: First source bytes used for cursor authentication.
        """
        self.expanded = expanded
        self.window = window
        self.prefix = prefix
        self.position = 0

    def tell(self) -> int:
        """Return the absolute uncompressed position."""
        return self.position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Select an absolute position without replaying compressed bytes.

        Args:
            offset: Byte displacement from the selected origin.
            whence: Start, current position, or prepared end.
        """
        self.position = offset + (self.expanded if whence == os.SEEK_END else self.position if whence == os.SEEK_CUR else 0)
        if self.position < 0:
            raise ValueError("Invalid retained history position.")
        return self.position

    def read(self, count: int) -> bytes:
        """Read a bounded range from the prefix or prepared page window.

        Args:
            count: Maximum requested uncompressed byte count.
        """
        start = self.expanded - len(self.window)
        if self.position >= self.expanded:
            return b""
        if self.position >= start:
            data = self.window[self.position - start:self.position - start + count]
        elif self.position + count <= len(self.prefix):
            data = self.prefix[self.position:self.position + count]
        else:
            raise ValueError("Retained history range is outside its prepared window.")
        self.position += len(data)
        return data

    def readline(self, count: int) -> bytes:
        """Read one bounded physical entry from the prepared page.

        Args:
            count: Maximum physical-entry fragment size.
        """
        data = self.read(count)
        boundary = data.find(b"\n")
        if boundary >= 0:
            self.position -= len(data) - boundary - 1
            data = data[:boundary + 1]
        return data


def _prepare_gzip_window(raw: Any, path: Path, *, end: int | None, deadline: float) -> _GzipHistoryWindow:
    """Resume decompression to an immutable archive boundary within a time budget.

    Args:
        raw: Verified open regular archive descriptor owned by this request.
        path: Server-selected source path binding the cache identity.
        end: Exclusive uncompressed target, or None for the archive end.
        deadline: Shared request deadline, with time reserved for page rendering.
    """
    info = os.fstat(raw.fileno())
    identity = (str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    stop = min(deadline - 0.25, time.monotonic() + 2)
    with _TAIL_REDACTION_LOCK:
        candidates = [key for key in _GZIP_WINDOW_CACHE if key[:5] == identity and (end is None or key[5] <= end)]
        key = max(candidates, key=lambda item: item[5]) if candidates else None
        saved = _GZIP_WINDOW_CACHE.get(key) if key else None
        if saved:
            expanded, window, prefix, saved_decoder, raw_offset, pending, finished = saved
            decoder = saved_decoder.copy()
        else:
            expanded, window, prefix, raw_offset, pending, finished = 0, b"", b"", 0, b"", False
            decoder = zlib.decompressobj(31)
    raw.seek(raw_offset)
    while not finished and (end is None or expanded < end):
        if not pending:
            pending = raw.read(16384)
            raw_offset += len(pending)
        if not pending:
            if not decoder.eof:
                raise ValueError("Retained gzip history is incomplete.")
            finished = True
        else:
            if decoder.eof:
                pending = pending.lstrip(b"\x00")
                if pending:
                    decoder = zlib.decompressobj(31)
            if pending:
                try:
                    chunk = decoder.decompress(pending, min(65536, end - expanded) if end is not None else 65536)
                except zlib.error as exc:
                    raise ValueError("Retained gzip history is invalid.") from exc
                pending = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
                expanded += len(chunk)
                window = (window + chunk)[-_GZIP_WINDOW_BYTES:]
                prefix = (prefix + chunk[:max(0, 4096 - len(prefix))])[:4096]
        if time.monotonic() > stop:
            break
    after = os.fstat(raw.fileno())
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity[1:]:
        raise _TailScanPending("Retained archive changed during preparation; retrying.")
    with _TAIL_REDACTION_LOCK:
        key = (*identity, expanded)
        _GZIP_WINDOW_CACHE[key] = (expanded, window, prefix, decoder.copy(), raw_offset, pending, finished)
        _GZIP_WINDOW_CACHE.move_to_end(key)
        while len(_GZIP_WINDOW_CACHE) > 8:
            _GZIP_WINDOW_CACHE.popitem(last=False)
    if not finished and (end is None or expanded < end):
        raise _TailScanPending("Preparing archived history; the next request resumes this scan.")
    return _GzipHistoryWindow(expanded, window, prefix)

def file_page(path: Path, *, source: str, cursor: str = "", limit: int = PAGE_LINES,
              complete: bool = False, tail: bool = False) -> dict[str, Any]:
    """Read current and numbered retained rotations without a total-history cap.

    Args:
        path: Server-owned allowlisted current log path.
        source: Stable authorized identity, including during task archival.
        cursor: Signed file identity, position, and redaction state.
        limit: Per-page line count, bounded independently of total history.
        complete: Include a terminal task's final line without a newline.
        tail: Start at the newest bounded group while preserving earlier navigation.
    """
    deadline = time.monotonic() + 10
    position = decode_cursor(cursor, source)
    rotations = []
    for candidate in path.parent.glob(f"{path.name}.*"):
        match = re.fullmatch(re.escape(path.name) + r"\.(\d+)(\.gz)?", candidate.name)
        if match:
            rotations.append((int(match[1]), candidate))
    paths = [candidate for _, candidate in sorted(rotations, key=lambda item: item[0], reverse=True)]
    if path.exists():
        paths.append(path)
    if not paths:
        return {"text": "", "available": False, "has_more": False, "cursor": "", "next_cursor": "",
                "notice": "Log file has not been written yet.", "source": source}
    index = len(paths) - 1 if tail and not cursor else 0
    reset = False
    if position.get("generation"):
        for candidate_index, candidate in enumerate(paths):
            info = candidate.lstat()
            if f"{info.st_dev}:{info.st_ino}" == position["generation"]:
                index = candidate_index
                break
        else:
            index, position, reset = 0, {}, True
    backward = position.get("before") is True
    before_end = position.get("offset", 0) if backward else None
    if backward and before_end == 0 and index > 0:
        index -= 1
        before_end = None
    page_end = before_end if backward else position.get("page_end")
    selected = paths[index]
    if selected.is_symlink():
        raise ValueError("Linked log files are not supported.")
    descriptor = os.open(selected, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as raw:
        metadata = os.fstat(raw.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Log source is not a regular retained file.")
        compressed = selected.suffix == ".gz"
        offset = position.get("offset", 0)
        if type(offset) is not int or offset < 0:
            raise ValueError("Invalid log history position.")
        prepared: Any
        if compressed:
            target = (None if before_end is None else before_end + 1) if ((tail and not cursor) or backward) else offset + PAGE_BYTES + LINE_BYTES + 1
            try:
                prepared = _prepare_gzip_window(raw, selected, end=target, deadline=deadline)
            except _TailScanPending:
                return {"source": source, "text": "", "available": True, "has_more": False,
                        "cursor": cursor, "next_cursor": cursor, "pending": True,
                        "notice": "Preparing retained history; this continues automatically."}
        else:
            prepared = raw
        with nullcontext(prepared) as handle:
            generation = f"{metadata.st_dev}:{metadata.st_ino}"
            if (tail and not cursor) or backward:
                offset, oversized = _tail_offset(handle, compressed=False, deadline=deadline, end=before_end, limit=max(1, min(PAGE_LINES, limit)))
                try:
                    private_key, pem_state = _tail_marker_state(paths[:index + 1], offset, deadline=deadline)
                except _TailScanPending:
                    return {"source": source, "text": "", "available": True, "has_more": False,
                            "cursor": cursor, "next_cursor": cursor, "pending": True,
                            "notice": "Preparing retained history; this continues automatically."}
                position = {"oversized": oversized, "private_key": private_key, "pem_state": pem_state.decode("ascii")}
            if type(offset) is not int or offset < 0:
                raise ValueError("Invalid log history position.")
            prefix_length = position.get("prefix_length", 0)
            if type(prefix_length) is not int or not 0 <= prefix_length <= 4096:
                raise ValueError("Invalid log history position.")
            handle.seek(0)
            prefix = handle.read(prefix_length)
            anchor_length = position.get("anchor_length", 0)
            if type(anchor_length) is not int or not 0 <= anchor_length <= min(offset, 4096):
                raise ValueError("Invalid log history anchor.")
            anchor = _history_anchor(handle, offset, compressed=False, deadline=deadline) if anchor_length else {}
            if ((not compressed and offset > metadata.st_size) or
                    (prefix_length and hashlib.sha256(prefix).hexdigest() != position.get("prefix")) or
                    (anchor_length and anchor.get("anchor") != position.get("anchor"))):
                offset, position, reset = 0, {}, True
                if compressed:
                    try:
                        handle = _prepare_gzip_window(raw, selected, end=PAGE_BYTES + LINE_BYTES + 1, deadline=deadline)
                    except _TailScanPending:
                        return {"source": source, "text": "", "available": True, "has_more": False,
                                "cursor": cursor, "next_cursor": cursor, "pending": True,
                                "notice": "Preparing retained history; this continues automatically."}
            anchor = _history_anchor(handle, offset, compressed=False, deadline=deadline)
            handle.seek(offset)
            private_key = position.get("private_key") is True
            current = encode_cursor(source, generation=generation, offset=offset, private_key=private_key,
                                    oversized=position.get("oversized") is True, pem_state=position.get("pem_state", ""),
                                    prefix_length=prefix_length if position else 0,
                                    prefix=position.get("prefix", ""), page_end=page_end, **anchor)
            parser_state = position.get("pem_state", "") if not reset else ""
            if not isinstance(parser_state, str) or len(parser_state) > 16 or not parser_state.isascii():
                raise ValueError("Invalid private-key parser state.")
            _, marker_prefix = _scan_pem_markers(b"", parser_state.encode("ascii"))
            lines: list[str] = []
            if (tail and not cursor) or backward:
                if position.get("oversized") is True:
                    lines.append("[Oversized log entry omitted: reading retained history in bounded groups.]")
            wire_bytes = 0
            partial = False
            oversized = position.get("oversized") is True
            while len(lines) < max(1, min(PAGE_LINES, limit)) and handle.tell() - offset < PAGE_BYTES and (page_end is None or handle.tell() < page_end):
                start = handle.tell()
                line = handle.readline(min(LINE_BYTES + 1, page_end - start) if page_end is not None else LINE_BYTES + 1)
                if not line:
                    break
                if oversized or len(line) > LINE_BYTES:
                    if not oversized:
                        lines.append("[Oversized log entry omitted: exceeds 64 KiB; continuing with the next complete entry.]")
                    marker_state, marker_prefix = _scan_pem_markers(line, marker_prefix)
                    if marker_state is not None:
                        lines.append("-----BEGIN PRIVATE KEY-----" if marker_state else "-----END PRIVATE KEY-----")
                    oversized = not line.endswith(b"\n")
                    continue
                if not line.endswith(b"\n") and not (complete or selected != path):
                    handle.seek(start)
                    partial = True
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
                size = _log_wire_size(decoded)
                if wire_bytes + size > PAGE_BYTES - 16384:
                    handle.seek(start)
                    break
                wire_bytes += size
                marker_prefix = b""
                lines.append(decoded)
            next_offset = handle.tell()
            more = bool(handle.read(1)) and not partial
            handle.seek(0)
            prefix = handle.read(min(next_offset, 4096))
            next_position = {"generation": generation, "offset": next_offset, "oversized": oversized,
                             "pem_state": marker_prefix.decode("ascii"),
                             "prefix_length": len(prefix), "prefix": hashlib.sha256(prefix).hexdigest(),
                             **_history_anchor(handle, next_offset, compressed=False, deadline=deadline)}
    if not more and index + 1 < len(paths):
        following = paths[index + 1].lstat()
        next_position = {"generation": f"{following.st_dev}:{following.st_ino}", "offset": 0}
        more = True
    safe_lines, private_key = redact_lines(lines, private_key=private_key)
    return {"source": source, "text": "\n".join(safe_lines), "available": True,
            "cursor": current, "next_cursor": encode_cursor(source, **next_position, private_key=private_key),
            "previous_cursor": encode_cursor(source, generation=generation, offset=offset, before=True) if offset or index else "",
            "has_more": more, "size_bytes": metadata.st_size, "updated_at": metadata.st_mtime, "reset": reset,
            "notice": "Retained history changed; reopened the oldest available file." if reset else ""}


def _bounded_json_text(text: str, *, suffix: bool = False) -> str:
    """Select a character-safe prefix or suffix within the escaped text budget.

    Args:
        text: Bounded candidate retained text.
        suffix: Select the newest characters instead of the oldest.
    """
    budget = PAGE_BYTES - min(16384, PAGE_BYTES // 4)
    low, high = 0, min(len(text), budget)
    while low < high:
        count = (low + high + 1) // 2
        candidate = text[-count:] if suffix else text[:count]
        if _log_wire_size(candidate) <= budget:
            low = count
        else:
            high = count - 1
    return (text[-low:] if low else "") if suffix else text[:low]


def text_page(text: str, *, source: str, cursor: str = "", tail: bool = False) -> dict[str, Any]:
    """Page an already-redacted task projection without shortening its history.

    Args:
        text: Complete retained task projection after existing redaction.
        source: Stable task identity.
        cursor: Opaque source-bound character position.
        tail: Open the newest byte-bounded part of the retained projection.
    """
    position = decode_cursor(cursor, source)
    offset = position.get("offset", 0)
    if type(offset) is not int or offset < 0:
        raise ValueError("Invalid log history position.")
    before_end = offset if position.get("before") is True else (position.get("page_end") or len(text))
    if (tail and not cursor) or position.get("before") is True:
        suffix = _bounded_json_text(text[max(0, before_end - PAGE_BYTES):before_end], suffix=True)
        offset = before_end - len(suffix)
        if offset and "\n" in suffix:
            offset += suffix.index("\n") + 1
        position["prefix"] = hashlib.sha256(text[:offset].encode("utf-8")).hexdigest()
    fingerprint = hashlib.sha256(text[:offset].encode("utf-8")).hexdigest()
    reset = offset > len(text) or (offset > 0 and fingerprint != position.get("prefix"))
    if reset:
        offset = 0
    bounded = _bounded_json_text(text[offset:min(offset + PAGE_BYTES, before_end)])
    end = offset + len(bounded)
    if end < len(text):
        boundary = text.rfind("\n", offset, end)
        if boundary > offset:
            end = boundary + 1
    return {"source": source, "text": text[offset:end], "available": True,
            "cursor": encode_cursor(source, offset=offset, prefix=hashlib.sha256(text[:offset].encode("utf-8")).hexdigest(),
                                    page_end=before_end if position.get("before") or position.get("page_end") else None),
            "next_cursor": encode_cursor(source, offset=end, prefix=hashlib.sha256(text[:end].encode("utf-8")).hexdigest()),
            "previous_cursor": encode_cursor(source, offset=offset, before=True) if offset else "",
            "has_more": end < len(text), "reset": reset,
            "notice": "Task details changed; reopened the beginning of its retained log." if reset else ""}
