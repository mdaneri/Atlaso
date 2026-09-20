"""Bounded remote property editor; transmitted to VCF over confirmed SSH.

Only this module's fixed path, keys and service are writable. No configuration
contents or command stderr cross the SSH boundary. Also importable for tests.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

CONFIG_PATH = "/etc/vmware/vcf/domainmanager/application-prod.properties"
KEYS = {
    "esa": "vsan.esa.sddc.managed.disk.claim",
    "nic": "enable.speed.of.physical.nics.validation",
}
VALUES = {"esa": "true", "nic": "false"}
MAX_BYTES = 1024 * 1024


class PropertyError(ValueError):
    """Reject an ambiguous or unsafe remote configuration."""


def _lines(content: bytes) -> list[str]:
    """Split Java physical lines, preserving every unrelated byte."""
    return re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", content.decode("latin-1"))[:-1]


def _unescape(value: str) -> str:
    """Decode Java property escapes when identifying protected keys."""

    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("u") and len(token) == 5:
            return chr(int(token[1:], 16))
        return {"t": "\t", "r": "\r", "n": "\n", "f": "\f"}.get(token, token)

    return re.sub(r"\\(u[0-9a-fA-F]{4}|.)", replace, value)


def properties(
    content: bytes,
) -> tuple[dict[str, str | None], dict[str, tuple[int, int]]]:
    """Read only allowlisted booleans; reject duplicate and continued keys."""
    if len(content) > MAX_BYTES or b"\x00" in content:
        raise PropertyError("Configuration is oversized or malformed.")
    lines = _lines(content)
    values: dict[str, str | None] = dict.fromkeys(KEYS)
    locations: dict[str, tuple[int, int]] = {}
    index = 0
    while index < len(lines):
        start = index
        line = lines[index].rstrip("\r\n")
        index += 1
        if line.lstrip().startswith(("#", "!")):
            continue
        while (len(line) - len(line.rstrip("\\"))) % 2:
            if index == len(lines):
                raise PropertyError("Configuration has an incomplete continuation.")
            line = line[:-1] + lines[index].lstrip().rstrip("\r\n")
            index += 1
        match = re.match(r"\s*((?:\\.|[^\s:=])+)\s*(?:[=:]\s*)?(.*)$", line)
        if not match:
            continue
        key, value = _unescape(match[1]), _unescape(match[2]).strip()
        for identifier, allowed_key in KEYS.items():
            if key != allowed_key:
                continue
            if (
                identifier in locations
                or index != start + 1
                or value not in {"true", "false"}
            ):
                raise PropertyError(
                    "Managed properties are duplicated, continued, or not boolean."
                )
            locations[identifier] = (start, index)
            values[identifier] = value
    return values, locations


def edit_properties(content: bytes, desired: dict[str, str | None]) -> bytes:
    """Change only selected keys without appending duplicate properties."""
    current, locations = properties(content)
    if not desired or set(desired) - KEYS.keys():
        raise PropertyError("Choose one or both supported properties.")
    if any(value not in {None, "true", "false"} for value in desired.values()):
        raise PropertyError("Invalid property value.")
    lines = _lines(content)
    newline = "\r\n" if b"\r\n" in content else "\n"
    additions = []
    for identifier, value in desired.items():
        if value == current[identifier]:
            continue
        replacement = f"{KEYS[identifier]}={value}" if value is not None else ""
        if identifier in locations:
            start, _ = locations[identifier]
            ending = (
                "\r\n"
                if lines[start].endswith("\r\n")
                else "\n"
                if lines[start].endswith("\n")
                else "\r"
                if lines[start].endswith("\r")
                else ""
            )
            lines[start] = replacement + ending if replacement else ""
        elif replacement:
            # Prepend so an unrelated final line without a newline stays intact.
            additions.append(replacement + newline)
    result = ("".join(additions) + "".join(lines)).encode("latin-1")
    properties(result)
    return result


def read_configuration(path: Path) -> tuple[bytes, os.stat_result]:
    """Reject links and non-regular configuration before bounded reading."""
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise PropertyError("Configuration path contains a symbolic link.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PropertyError("Configuration must be an ordinary single-link file.")
        content = stream.read(MAX_BYTES + 1)
    properties(content)
    return content, info


def snapshot(content: bytes, info: os.stat_result) -> str:
    """Bind review to bytes, identity, ownership and permissions."""
    metadata = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    return hashlib.sha256(repr(metadata).encode() + content).hexdigest()


def active() -> bool:
    """Check only the required service, without returning its output."""
    return (
        subprocess.run(
            ["systemctl", "is-active", "--quiet", "domainmanager"],
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def operate(request: dict[str, Any]) -> dict[str, Any]:
    """Inspect or compare-and-replace fixed properties under a remote lock."""
    import fcntl

    # Remote execution is Linux-only; Windows imports only the pure editor tests.
    posix: Any = os
    locking: Any = fcntl

    if posix.geteuid() != 0:
        raise PropertyError(
            "SSH requires root or passwordless sudo for this operation."
        )
    if request.get("action") not in {"inspect", "write"}:
        raise PropertyError("Unsupported operation.")
    lock_fd = os.open(
        "/run/lock/atlaso-vcf-lab.lock",
        os.O_CREAT | os.O_RDWR | posix.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(lock_fd, "w") as lock:
        try:
            locking.flock(lock, locking.LOCK_EX | locking.LOCK_NB)
        except BlockingIOError as exc:
            raise PropertyError(
                "Another property operation is active on this appliance."
            ) from exc
        path = Path(CONFIG_PATH)
        content, info = read_configuration(path)
        values, _ = properties(content)
        result: dict[str, Any] = {
            "ok": True,
            "values": values,
            "revision": snapshot(content, info),
            "service_active": active(),
            "changed": False,
        }
        if request["action"] == "inspect":
            return result
        if request.get("revision") != result["revision"]:
            raise PropertyError(
                "Configuration changed after review. Inspect and review again."
            )
        updated = edit_properties(content, request.get("desired", {}))
        if updated == content:
            return result
        fd, temporary = tempfile.mkstemp(prefix=".atlaso-lab-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                posix.fchown(stream.fileno(), info.st_uid, info.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                stream.write(updated)
                stream.flush()
                os.fsync(stream.fileno())
            for attribute in posix.listxattr(path):
                posix.setxattr(temporary, attribute, posix.getxattr(path, attribute))
            latest, latest_info = read_configuration(path)
            if snapshot(latest, latest_info) != result["revision"]:
                raise PropertyError(
                    "Configuration changed during the operation; no changes written."
                )
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | posix.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            result["changed"] = True
            observed, observed_info = read_configuration(path)
            result.update(
                values=properties(observed)[0],
                revision=snapshot(observed, observed_info),
            )
            if observed != updated or any(
                result["values"][key] != value
                for key, value in request["desired"].items()
            ):
                raise PropertyError(
                    "Property readback failed; inspect the target before recovery."
                )
            if (
                observed_info.st_uid,
                observed_info.st_gid,
                stat.S_IMODE(observed_info.st_mode),
            ) != (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)):
                raise PropertyError(
                    "Configuration permission readback failed; inspect the target before recovery."
                )
            try:
                restart = subprocess.run(
                    ["systemctl", "restart", "domainmanager"],
                    timeout=90,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except subprocess.SubprocessError:
                result.update(
                    ok=False,
                    service_active=False,
                    error="Properties verified, but service restart timed out. Review target health or revert.",
                )
                return result
            deadline = time.monotonic() + 180
            while restart.returncode == 0 and time.monotonic() < deadline:
                if active():
                    result["service_active"] = True
                    return result
                time.sleep(3)
            result.update(
                ok=False,
                service_active=False,
                error="Properties changed, but domainmanager did not recover. Inspect the service and review a revert.",
            )
            return result
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main() -> None:
    """Return bounded structured evidence, never raw configuration or stderr."""
    try:
        request = json.loads(sys.stdin.buffer.readline(16385))
        result = operate(request)
    except PropertyError as exc:
        result = {"ok": False, "error": str(exc)}
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        result = {
            "ok": False,
            "error": "Remote operation failed. Changes may have occurred; inspect the target and review recovery.",
        }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
