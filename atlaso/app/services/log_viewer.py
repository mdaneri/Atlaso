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


def source_page(source: str, *, cursor: str = "") -> dict[str, Any]:
    """Read one authorized fixed-source page and redact before transport.

    Args:
        source: Fixed source selected in the authenticated Logs viewer.
        cursor: Signed position belonging to this source.
    """
    if source == "app":
        return file_page(get_settings().app_log_path, source=source, cursor=cursor)
    if source == "kms":
        return file_page(Path("/var/log/atlaso/kmip/server.log"), source=source, cursor=cursor)
    if source not in {"dnsmasq-dns", "dnsmasq-dhcp", "dnsmasq-tftp", "ldap", "ntp", "esx-storage", "nginx", "nginx-access", "nginx-error"}:
        raise ValueError("Unknown log source.")
    position = decode_cursor(cursor, source)
    result = SystemAdapter().read_log_history(source, position)
    if result.returncode:
        raise ValueError("Log history is temporarily unavailable. Your displayed page is preserved.")
    payload = json.loads(result.stdout)
    lines, private_key = redact_lines(payload["lines"], private_key=not payload.get("reset") and position.get("private_key") is True)
    if source.startswith("dnsmasq-"):
        category = source.removeprefix("dnsmasq-")
        lines = [line for line in lines if (
            "dhcp" if re.search(r"\bdnsmasq-dhcp(?:\[\d+\])?:", line)
            else "tftp" if re.search(r"\bdnsmasq-tftp(?:\[\d+\])?:", line) else "dns"
        ) == category]
    next_position = payload.get("file_position", {"journal_cursor": payload.get("journal_cursor", "")})
    current = encode_cursor(source, **payload["current_position"], private_key=not payload.get("reset") and position.get("private_key") is True) if "current_position" in payload else cursor
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


def file_page(path: Path, *, source: str, cursor: str = "", limit: int = PAGE_LINES,
              complete: bool = False) -> dict[str, Any]:
    """Read current and numbered retained rotations without a total-history cap.

    Args:
        path: Server-owned allowlisted current log path.
        source: Stable authorized identity, including during task archival.
        cursor: Signed file identity, position, and redaction state.
        limit: Per-page line count, bounded independently of total history.
        complete: Include a terminal task's final line without a newline.
    """
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
    index = 0
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
            if type(offset) is not int or offset < 0:
                raise ValueError("Invalid log history position.")
            prefix_length = position.get("prefix_length", 0)
            if type(prefix_length) is not int or not 0 <= prefix_length <= 4096:
                raise ValueError("Invalid log history position.")
            prefix = handle.read(prefix_length)
            if ((not compressed and offset > metadata.st_size) or
                    (prefix_length and hashlib.sha256(prefix).hexdigest() != position.get("prefix"))):
                offset, position, reset = 0, {}, True
            handle.seek(0)
            deadline = time.monotonic() + 10
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
                                    prefix_length=prefix_length if position else 0,
                                    prefix=position.get("prefix", ""))
            lines: list[str] = []
            partial = False
            while len(lines) < max(1, min(PAGE_LINES, limit)) and handle.tell() - offset < PAGE_BYTES:
                start = handle.tell()
                line = handle.readline(LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > LINE_BYTES:
                    raise ValueError("A log entry exceeds the safe page size; the complete page could not be displayed.")
                if not line.endswith(b"\n") and not (complete or selected != path):
                    handle.seek(start)
                    partial = True
                    break
                lines.append(line.decode("utf-8", errors="replace").rstrip("\r\n"))
            next_offset = handle.tell()
            more = bool(handle.read(1)) and not partial
            handle.seek(0)
            prefix = handle.read(min(next_offset, 4096))
            next_position = {"generation": generation, "offset": next_offset,
                             "prefix_length": len(prefix), "prefix": hashlib.sha256(prefix).hexdigest()}
    if not more and index + 1 < len(paths):
        following = paths[index + 1].lstat()
        next_position = {"generation": f"{following.st_dev}:{following.st_ino}", "offset": 0}
        more = True
    safe_lines, private_key = redact_lines(lines, private_key=private_key)
    return {"source": source, "text": "\n".join(safe_lines), "available": True,
            "cursor": current, "next_cursor": encode_cursor(source, **next_position, private_key=private_key),
            "has_more": more, "size_bytes": metadata.st_size, "updated_at": metadata.st_mtime, "reset": reset,
            "notice": "Retained history changed; reopened the oldest available file." if reset else ""}


def text_page(text: str, *, source: str, cursor: str = "") -> dict[str, Any]:
    """Page an already-redacted task projection without shortening its history.

    Args:
        text: Complete retained task projection after existing redaction.
        source: Stable task identity.
        cursor: Opaque source-bound character position.
    """
    position = decode_cursor(cursor, source)
    offset = position.get("offset", 0)
    if type(offset) is not int or offset < 0:
        raise ValueError("Invalid log history position.")
    fingerprint = hashlib.sha256(text[:offset].encode("utf-8")).hexdigest()
    reset = offset > len(text) or (offset > 0 and fingerprint != position.get("prefix"))
    if reset:
        offset = 0
    end = min(len(text), offset + PAGE_BYTES)
    if end < len(text):
        boundary = text.rfind("\n", offset, end)
        if boundary > offset:
            end = boundary + 1
    return {"source": source, "text": text[offset:end], "available": True,
            "cursor": encode_cursor(source, offset=offset, prefix=hashlib.sha256(text[:offset].encode("utf-8")).hexdigest()),
            "next_cursor": encode_cursor(source, offset=end, prefix=hashlib.sha256(text[:end].encode("utf-8")).hexdigest()),
            "has_more": end < len(text), "reset": reset,
            "notice": "Task details changed; reopened the beginning of its retained log." if reset else ""}
