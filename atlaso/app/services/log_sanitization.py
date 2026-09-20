"""Sanitize producer records without application settings or database imports."""

import hashlib
import json
import re

from atlaso.app.services.task_log_redaction import redact_task_value

SECRET_LINE_PATTERN = re.compile(
    r"(rootpw|password|passwd|token|secret|credential|private[_.-]?key|robot[_.-]?account|ca[_.-]?bundle[_.-]?pem|activation[_.-]?code|license|ipxe[_.-]?script|payload[_.-]?b64)",
    re.IGNORECASE,
)
PRIVATE_KEY_BEGIN_PATTERN = re.compile(r"-----BEGIN .*PRIVATE KEY-----")
PRIVATE_KEY_END_PATTERN = re.compile(r"-----END .*PRIVATE KEY-----")
JWT_PATH_SEGMENT_PATTERN = re.compile(r"(?<=/)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?=/|$)")
JSON_SECRET_FIELD_PATTERN = re.compile(r'^(\s*"[^"]+"\s*:\s*)(.*?)(,?)\s*$')
URL_USERINFO_PATTERN = re.compile(r"(https?://)[^/\s@]+@", re.IGNORECASE)
OIDC_QUERY_SECRET_PATTERN = re.compile(
    r"([?&](?:code|client_secret|id_token_hint|access_token)=)[^&\s]+",
    re.IGNORECASE,
)


def redact_operational_text(value: str | None) -> str:
    """Return redact operational text.

    Args:
        value: Candidate value consumed by redact operational text.
    """
    lines: list[str] = []
    in_private_key = False
    for line in (value or "").splitlines():
        if PRIVATE_KEY_BEGIN_PATTERN.search(line):
            lines.append("[redacted private key]")
            in_private_key = True
            continue
        if in_private_key:
            if PRIVATE_KEY_END_PATTERN.search(line):
                in_private_key = False
            continue
        if SECRET_LINE_PATTERN.search(line):
            json_match = JSON_SECRET_FIELD_PATTERN.match(line)
            if json_match:
                lines.append(f'{json_match.group(1)}"[redacted]"{json_match.group(3)}')
                continue
            separator = "=" if "=" in line else ":" if ":" in line else None
            if separator:
                prefix = line.split(separator, 1)[0].rstrip()
                lines.append(f"{prefix}{separator} [redacted]")
            else:
                lines.append("[redacted sensitive line]")
            continue
        redacted = URL_USERINFO_PATTERN.sub(r"\1[redacted]@", line)
        redacted = OIDC_QUERY_SECRET_PATTERN.sub(r"\1[redacted]", redacted)
        lines.append(JWT_PATH_SEGMENT_PATTERN.sub("[redacted-token]", redacted))
    return "\n".join(lines)


def _scan_pem_markers(chunk: bytes, carry: bytes = b"") -> tuple[bool | None, bytes]:
    """Match private-key labels with bounded resumable label fingerprints.

    Args:
        chunk: Next contiguous source fragment.
        carry: Parser tokens and fixed-size label fingerprints from the prior fragment.
    """
    starts = (b"-----BEGIN ", b"-----END ")
    endings = (b"PRIVATE KEY-----", b"-----")
    start_parts = sorted({token[:size] for token in starts for size in range(1, len(token))}, key=len, reverse=True)
    end_parts = sorted({token[:size] for token in endings for size in range(1, len(token))}, key=len, reverse=True)
    if carry.startswith(b"["):
        fields = json.loads(carry)
        if not isinstance(fields, list) or len(fields) != 5 or not all(isinstance(item, str) for item in fields):
            raise ValueError("Invalid private-key parser state.")
        mode, suffix_hex, digest_hex, pending_hex, active = fields
        suffix, digest, pending = bytes.fromhex(suffix_hex), bytes.fromhex(digest_hex), bytes.fromhex(pending_hex)
    else:
        mode, suffix = (carry[:1] or b"S").decode("ascii"), carry[1:]
        digest, pending, active = bytes(32), b"", ""
    allowed = start_parts if mode == "S" else end_parts
    if (mode not in ("S", "B", "E") or (suffix and suffix not in allowed) or len(digest) != 32 or len(pending) >= 16 or
            (active not in ("", "!") and (len(active) != 64 or any(char not in "0123456789abcdef" for char in active)))):
        raise ValueError("Invalid private-key parser state.")

    def absorb(value: bytes) -> None:
        """Hash canonical blocks independently of transport fragmentation.

        Args:
            value: Confirmed label bytes, excluding an unconsumed fixed-token suffix.
        """
        nonlocal digest, pending
        value = pending + value
        boundary = len(value) // 16 * 16
        for index in range(0, boundary, 16):
            digest = hashlib.sha256(b"pem-label-block" + digest + value[index:index + 16]).digest()
        pending = value[boundary:]

    data, position, last = suffix + chunk, 0, None
    start_pattern = re.compile(rb"-----(BEGIN|END) ")
    boundary_pattern = re.compile(rb"-----|[^ -~]")
    while True:
        if mode == "S":
            match = start_pattern.search(data, position)
            if match is None:
                suffix = next((part for part in start_parts if data.endswith(part, position)), b"")
                break
            position = match.end()
            mode = "B" if match.group(1) == b"BEGIN" else "E"
            digest, pending = bytes(32), b""
        boundary = boundary_pattern.search(data, position)
        if boundary is None:
            suffix = next((part for part in end_parts if data.endswith(part, position)), b"")
            absorb(data[position:len(data) - len(suffix)] if suffix else data[position:])
            break
        start = boundary.start()
        if boundary.group() == b"-----" and data.endswith(b"PRIVATE KEY", position, start):
            absorb(data[position:boundary.end()])
            label = hashlib.sha256(b"pem-label-final" + digest + pending).hexdigest()
            if mode == "B":
                active = label if not active else "!"
                last = True
            elif active == label:
                active, last = "", False
            elif active:
                last = True
            else:
                last = False
            position = boundary.end()
        else:
            position = start if boundary.group() == b"-----" else boundary.end()
        mode, digest, pending = "S", bytes(32), b""
    return last, json.dumps([mode, suffix.hex(), digest.hex(), pending.hex(), active], separators=(",", ":")).encode("ascii")


def _safe_lines(lines: list[str], private: bool = False, parser: dict[str, str] | None = None) -> tuple[list[str], bool]:
    """Sanitize complete lines while carrying an unfinished private key.

    Args:
        lines: Newly observed producer lines, before scalar sanitization.
        private: Whether an earlier committed fragment opened a key.
        parser: Finite marker state retained between committed fragments.
    """
    output = []
    parser = parser if parser is not None else {}
    carry = parser.get("carry", "").encode("ascii")
    if private and not carry.startswith(b"["):
        carry = json.dumps(["S", "", bytes(32).hex(), "", "!"]).encode("ascii")
    for value in lines:
        for line in str(value).splitlines() or [""]:
            private = private or parser.get("hold") == "1"
            marker, carry = _scan_pem_markers(line.encode("utf-8"), carry)
            concealed = private or marker is not None or (json.loads(carry)[0] != "S" or bool(json.loads(carry)[1]))
            output.append("[redacted private key]" if concealed else str(redact_task_value(line)))
            if marker is not None:
                private = marker
            if carry.startswith((b"B", b'["B",')) or parser.get("hold") == "1":
                private = True
    parser["carry"] = carry.decode("ascii")
    return output, private
