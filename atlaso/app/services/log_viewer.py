"""Read complete retained log history in authenticated, bounded pages."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import stat
import time
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
        if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
            private_key = True
        if private_key:
            output.append("[redacted private key]")
            if "-----END " in line and "PRIVATE KEY-----" in line:
                private_key = False
        else:
            output.append(redact_operational_text(line))
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


_TAIL_REDACTION_CACHE: OrderedDict[tuple[str, int, int], tuple[bool, bytes, bytes, int, int]] = OrderedDict()
_TAIL_REDACTION_LOCK = RLock()


def _tail_private_key(paths: list[Path], offset: int, *, deadline: float) -> bool:
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
    if checkpoint and cached:
        start_index, start_offset = checkpoint[1:]
        opened, carry, fingerprint, saved_size, saved_mtime = cached
        path = paths[start_index]
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as raw:
            if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
                raise ValueError("Retained log is not a regular file.")
            with (gzip.GzipFile(fileobj=raw) if path.suffix == ".gz" else nullcontext(raw)) as stream:
                prefix = stream.read(min(start_offset, 4096))
                stream.seek(max(0, start_offset - 128))
                anchor = stream.read(min(start_offset, 128))
        if (hashlib.sha256(prefix + anchor).digest() != fingerprint or
                (identities[start_index].st_mtime_ns != saved_mtime and identities[start_index].st_size <= saved_size)):
            with _TAIL_REDACTION_LOCK:
                for key in candidates:
                    _TAIL_REDACTION_CACHE.pop(key, None)
            opened, carry, start_index, start_offset = False, b"", 0, 0
    for index in range(start_index, len(paths)):
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
                    window = carry + chunk
                    for match in re.finditer(rb"-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----", window):
                        opened = match.group(1) == b"BEGIN"
                    carry = window[-128:]
                    scanned = stream.tell()
                    # Only source fingerprints and bounded state remain in process memory.
                    anchor = chunk[-128:] if len(chunk) >= 128 else window[-min(scanned, 128):]
                    key = (context, index, scanned)
                    with _TAIL_REDACTION_LOCK:
                        _TAIL_REDACTION_CACHE[key] = (opened, carry, hashlib.sha256(prefix[:min(scanned, 4096)] + anchor).digest(),
                                                      identities[index].st_size, identities[index].st_mtime_ns)
                        _TAIL_REDACTION_CACHE.move_to_end(key)
                        while len(_TAIL_REDACTION_CACHE) > 128:
                            _TAIL_REDACTION_CACHE.popitem(last=False)
                    if time.monotonic() > stop and (index < len(paths) - 1 or scanned < offset):
                        raise _TailScanPending("Preparing retained history; the next request resumes this scan.")
    return opened


def _compressed_tail_private_key(paths: list[Path], offset: int, *, deadline: float) -> bool:
    """Recover redaction state before a tail boundary without retaining source contents.

    Args:
        paths: Fixed retained files through the selected newest source.
        offset: Uncompressed byte boundary within the selected source.
        deadline: Shared monotonic deadline for the request.
    """
    opened = False
    carry = b""
    for index, path in enumerate(paths):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as raw:
            if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
                raise ValueError("Retained log is not a regular file.")
            with (gzip.GzipFile(fileobj=raw) if path.suffix == ".gz" else nullcontext(raw)) as stream:
                remaining = offset if index == len(paths) - 1 else None
                while remaining is None or remaining > 0:
                    if time.monotonic() > deadline:
                        raise ValueError("Tail redaction scan exceeded its deadline; open from the beginning.")
                    chunk = stream.read(min(65536, remaining) if remaining is not None else 65536)
                    if not chunk:
                        break
                    if remaining is not None:
                        remaining -= len(chunk)
                    window = carry + chunk
                    for match in re.finditer(rb"-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----", window):
                        opened = match.group(1) == b"BEGIN"
                    carry = window[-128:]
    return opened


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
        with (gzip.GzipFile(fileobj=raw) if compressed else nullcontext(raw)) as handle:
            generation = f"{metadata.st_dev}:{metadata.st_ino}"
            offset = position.get("offset", 0)
            if (tail and not cursor) or backward:
                offset, oversized = _tail_offset(handle, compressed=compressed, deadline=deadline, end=before_end, limit=max(1, min(PAGE_LINES, limit)))
                try:
                    private_key = _tail_private_key(paths[:index + 1], offset, deadline=deadline)
                except _TailScanPending:
                    return {"source": source, "text": "", "available": True, "has_more": False,
                            "cursor": cursor, "next_cursor": cursor, "notice": "Preparing retained history; this continues automatically."}
                position = {"oversized": oversized, "private_key": private_key}
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
            anchor = _history_anchor(handle, offset, compressed=compressed, deadline=deadline) if anchor_length else {}
            if ((not compressed and offset > metadata.st_size) or
                    (prefix_length and hashlib.sha256(prefix).hexdigest() != position.get("prefix")) or
                    (anchor_length and anchor.get("anchor") != position.get("anchor"))):
                offset, position, reset = 0, {}, True
            anchor = _history_anchor(handle, offset, compressed=compressed, deadline=deadline)
            handle.seek(0)
            remaining = offset if compressed else 0
            if not compressed:
                handle.seek(offset)
            while remaining:
                skipped = handle.read(min(65536, remaining))
                if not skipped or time.monotonic() > deadline:
                    raise ValueError("Retained history position is unavailable; reopen from the beginning.")
                remaining -= len(skipped)
            private_key = position.get("private_key") is True
            current = encode_cursor(source, generation=generation, offset=offset, private_key=private_key,
                                    oversized=position.get("oversized") is True,
                                    prefix_length=prefix_length if position else 0,
                                    prefix=position.get("prefix", ""), page_end=page_end, **anchor)
            marker_prefix = _history_window(handle, offset, compressed=compressed, deadline=deadline)[-128:]
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
                    window = marker_prefix + line
                    markers = list(re.finditer(rb"-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----", window))
                    if markers:
                        lines.append(markers[-1].group().decode("ascii"))
                    marker_prefix = window[-128:]
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
                             "prefix_length": len(prefix), "prefix": hashlib.sha256(prefix).hexdigest(),
                             **_history_anchor(handle, next_offset, compressed=compressed, deadline=deadline)}
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
