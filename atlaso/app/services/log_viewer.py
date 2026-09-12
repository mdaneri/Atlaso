"""Read complete retained log history in authenticated, bounded pages."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import stat
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from itsdangerous import BadSignature, URLSafeSerializer

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.operational_logging import redact_operational_text

PAGE_LINES = 500
PAGE_BYTES = 1024 * 1024
LINE_BYTES = 64 * 1024


def source_page(source: str, *, cursor: str = "", tail: bool = False) -> dict[str, Any]:
    """Read one authorized fixed-source page and redact before transport.

    Args:
        source: Fixed source selected in the authenticated Logs viewer.
        cursor: Signed position belonging to this source.
        tail: Open the newest retained page when no cursor is supplied.
    """
    if source == "app":
        return file_page(get_settings().app_log_path, source=source, cursor=cursor, tail=tail)
    if source == "kms":
        return file_page(Path("/var/log/atlaso/kmip/server.log"), source=source, cursor=cursor, tail=tail)
    if source not in {"dnsmasq-dns", "dnsmasq-dhcp", "dnsmasq-tftp", "ldap", "ntp", "esx-storage", "nginx", "nginx-access", "nginx-error"}:
        raise ValueError("Unknown log source.")
    position = decode_cursor(cursor, source)
    if tail and not cursor:
        position["tail"] = True
    result = SystemAdapter().read_log_history(source, position)
    if result.returncode:
        raise ValueError("Log history is temporarily unavailable. Your displayed page is preserved.")
    payload = json.loads(result.stdout)
    initial_private_key = not payload.get("reset") and payload.get("initial_private_key", position.get("private_key")) is True
    lines, private_key = redact_lines(payload["lines"], private_key=initial_private_key)
    if source.startswith("dnsmasq-"):
        category = source.removeprefix("dnsmasq-")
        lines = [line for line in lines if (
            "dhcp" if re.search(r"\bdnsmasq-dhcp(?:\[\d+\])?:", line)
            else "tftp" if re.search(r"\bdnsmasq-tftp(?:\[\d+\])?:", line) else "dns"
        ) == category]
    next_position = payload.get("file_position", payload.get("journal_position", {"journal_cursor": payload.get("journal_cursor", "")}))
    current = encode_cursor(source, **payload["current_position"], private_key=initial_private_key) if "current_position" in payload else cursor
    return {"source": source, "available": payload.get("available", True), "text": "\n".join(lines), "cursor": current,
            "next_cursor": encode_cursor(source, **next_position, private_key=private_key),
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


def _tail_offset(handle: Any, *, compressed: bool, deadline: float) -> tuple[int, bool]:
    """Locate the newest bounded group without replaying pages to the client.

    Args:
        handle: Verified regular source stream.
        compressed: Whether seeking requires bounded decompression.
        deadline: Shared monotonic deadline for the request.
    """
    if compressed:
        data, total = b"", 0
        handle.seek(0)
        while chunk := handle.read(65536):
            if time.monotonic() > deadline:
                raise ValueError("Archived tail scan exceeded its deadline; open from the beginning.")
            total += len(chunk)
            data = (data + chunk)[-1024 * 1024:]
    else:
        total = handle.seek(0, os.SEEK_END)
        handle.seek(max(0, total - 1024 * 1024))
        data = handle.read(1024 * 1024)
    offset = total - len(data)
    if offset:
        boundary = data.find(b"\n")
        if boundary < 0:
            return total, True
        offset += boundary + 1
        data = data[boundary + 1:]
    starts = [0] + [match.end() for match in re.finditer(b"\n", data) if match.end() < len(data)]
    if len(starts) > 500:
        offset += starts[-500]
    return offset, False


def _tail_private_key(paths: list[Path], offset: int, *, deadline: float) -> bool:
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


def _history_anchor(handle: Any, offset: int, *, compressed: bool, deadline: float) -> dict[str, Any]:
    """Fingerprint the content immediately before a retained byte position.

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
    window = handle.read(length)
    return {"anchor_length": length, "anchor": hashlib.sha256(window).hexdigest()}


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
            if tail and not cursor:
                offset, oversized = _tail_offset(handle, compressed=compressed, deadline=deadline)
                position = {"oversized": oversized, "private_key": _tail_private_key(paths[:index + 1], offset, deadline=deadline)}
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
                                    prefix=position.get("prefix", ""), **anchor)
            lines: list[str] = []
            partial = False
            oversized = position.get("oversized") is True
            while len(lines) < max(1, min(PAGE_LINES, limit)) and handle.tell() - offset < PAGE_BYTES:
                start = handle.tell()
                line = handle.readline(LINE_BYTES + 1)
                if not line:
                    break
                if oversized or len(line) > LINE_BYTES:
                    if not oversized:
                        if b"-----BEGIN " in line and b"PRIVATE KEY-----" in line:
                            lines.append("-----BEGIN PRIVATE KEY-----")
                        lines.append("[Oversized log entry omitted: exceeds 64 KiB; continuing with the next complete entry.]")
                    oversized = not line.endswith(b"\n")
                    continue
                if not line.endswith(b"\n") and not (complete or selected != path):
                    handle.seek(start)
                    partial = True
                    break
                lines.append(line.decode("utf-8", errors="replace").rstrip("\r\n"))
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
            "has_more": more, "size_bytes": metadata.st_size, "updated_at": metadata.st_mtime, "reset": reset,
            "notice": "Retained history changed; reopened the oldest available file." if reset else ""}


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
    if tail and not cursor:
        suffix = text[-PAGE_BYTES:].encode("utf-8")[-PAGE_BYTES:].decode("utf-8", errors="ignore")
        offset = len(text) - len(suffix)
        if offset and "\n" in suffix:
            offset += suffix.index("\n") + 1
        position["prefix"] = hashlib.sha256(text[:offset].encode("utf-8")).hexdigest()
    fingerprint = hashlib.sha256(text[:offset].encode("utf-8")).hexdigest()
    reset = offset > len(text) or (offset > 0 and fingerprint != position.get("prefix"))
    if reset:
        offset = 0
    bounded = text[offset:offset + PAGE_BYTES].encode("utf-8")[:PAGE_BYTES].decode("utf-8", errors="ignore")
    end = offset + len(bounded)
    if end < len(text):
        boundary = text.rfind("\n", offset, end)
        if boundary > offset:
            end = boundary + 1
    return {"source": source, "text": text[offset:end], "available": True,
            "cursor": encode_cursor(source, offset=offset, prefix=hashlib.sha256(text[:offset].encode("utf-8")).hexdigest()),
            "next_cursor": encode_cursor(source, offset=end, prefix=hashlib.sha256(text[:end].encode("utf-8")).hexdigest()),
            "has_more": end < len(text), "reset": reset,
            "notice": "Task details changed; reopened the beginning of its retained log." if reset else ""}
