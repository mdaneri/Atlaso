"""Bounded remote property editor; transmitted to VCF over confirmed SSH.

Only this module's fixed path, keys and service are writable. No configuration
contents or command stderr cross the SSH boundary. Also importable for tests.
"""

import base64
import hashlib
import json
import os
import re
import shlex
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
# Neither credential handling nor privileged execution may import caller files.
PYTHON_COMMAND = "cd / && exec /usr/bin/python3 -I -S -c "


class PropertyError(ValueError):
    """Reject an ambiguous or unsafe remote configuration."""


def _lines(content: bytes) -> list[str]:
    """Split Java physical lines, preserving every unrelated byte.

    Args:
        content: Original property-file bytes, never returned to the browser.
    """
    return re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", content.decode("latin-1"))[:-1]


def _unescape(value: str) -> str:
    """Decode Java property escapes when identifying protected keys.

    Args:
        value: Escaped Java property text to decode.
    """

    def replace(match: re.Match[str]) -> str:
        """Exercise replace.

        Args:
            match: Matched Java property escape sequence.
        """
        token = match.group(1)
        if token.startswith("u") and len(token) == 5:
            return chr(int(token[1:], 16))
        return {"t": "\t", "r": "\r", "n": "\n", "f": "\f"}.get(token, token)

    return re.sub(r"\\(u[0-9a-fA-F]{4}|.)", replace, value)


def properties(
    content: bytes,
) -> tuple[dict[str, str | None], dict[str, tuple[int, int]]]:
    """Read only allowlisted booleans; reject duplicate and continued keys.

    Args:
        content: Original property-file bytes, never returned to the browser.
    """
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
        # Scan once; escaped separators belong to the key.
        line = line.lstrip(" \t\f")
        end = 0
        while end < len(line):
            if line[end] == "\\":
                end += 2
            elif line[end] in " \t\f:=":
                break
            else:
                end += 1
        raw_value = line[end:].lstrip(" \t\f")
        if raw_value.startswith((":", "=")):
            raw_value = raw_value[1:].lstrip(" \t\f")
        key, value = _unescape(line[:end]), _unescape(raw_value).strip()
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
    """Change only selected keys without appending duplicate properties.

    Args:
        content: Original property-file bytes, never returned to the browser.
        desired: Allowlisted property values to apply, with None meaning removal.
    """
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
    """Reject links and non-regular configuration before bounded reading.

    Args:
        path: Fixed property-file path to inspect.
    """
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
    """Bind review to bytes, identity, ownership and permissions.

    Args:
        content: Original property-file bytes, never returned to the browser.
        info: Original file metadata bound into the review revision.
    """
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
    """Inspect or compare-and-replace fixed properties under a remote lock.

    Args:
        request: Bounded request carrying only allowed operation inputs.
    """
    import fcntl

    # Remote execution is Linux-only; Windows imports only the pure editor tests.
    posix: Any = os
    locking: Any = fcntl

    if request.get("action") not in {"inspect", "write"}:
        raise PropertyError("Unsupported operation.")
    if request["action"] == "inspect":
        # Inspection never creates a lock file or mutates the appliance. Try as
        # vcf first; only a permission refusal warrants the separate su boundary.
        content, info = read_configuration(Path(CONFIG_PATH))
        return {
            "ok": True,
            "values": properties(content)[0],
            "revision": snapshot(content, info),
            "service_active": active(),
            "changed": False,
        }
    if posix.geteuid() != 0:
        raise PermissionError("Root elevation is required for property writes.")
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
        if not result["service_active"] and request.get("recovery") is not True:
            raise PropertyError("domainmanager is inactive; ordinary apply is refused.")
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
            except (OSError, subprocess.SubprocessError):
                result.update(
                    ok=False,
                    service_active=False,
                    error="Properties verified, but service restart failed or timed out. Review target health or revert.",
                )
                return result
            deadline = time.monotonic() + 180
            while restart.returncode == 0 and time.monotonic() < deadline:
                try:
                    ready = active()
                except (OSError, subprocess.SubprocessError):
                    break
                if ready:
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


def elevated(
    command: str, password: str, *, authorize_write: bool = False
) -> dict[str, Any]:
    """Run the fixed editor through a private, unlogged, non-echoing su terminal.

    Args:
        command: Internally generated editor command containing no credentials.
        password: Separate root secret received through encrypted SSH stdin only.
        authorize_write: Require a durable Atlaso handoff before allowing mutation.
    """
    import pty
    import select
    import signal
    import termios

    posix: Any = os
    terminals: Any = termios
    pseudoterminals: Any = pty
    signals: Any = signal
    if (
        not password
        or len(password.encode()) > 1024
        or any(ord(char) < 32 or ord(char) == 127 for char in password)
    ):
        return {"elevation_error": "authentication"}
    if not Path("/usr/bin/su").is_file() and not Path("/bin/su").is_file():
        return {"elevation_error": "unavailable"}
    su = "/usr/bin/su" if Path("/usr/bin/su").is_file() else "/bin/su"
    pid, terminal = pseudoterminals.fork()
    if pid == 0:
        try:
            # The child owns the controlling terminal; turn echo off before su
            # starts. The parent checks it again immediately before secret input.
            settings = terminals.tcgetattr(0)
            settings[3] &= ~(terminals.ECHO | terminals.ECHONL)
            terminals.tcsetattr(0, terminals.TCSANOW, settings)
            posix.execve(
                su,
                [su, "-s", "/bin/sh", "-c", command, "root"],
                {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except (OSError, terminals.error):
            posix._exit(126)
    output = bytearray()
    sent = False
    ready = False
    reaped = False
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], 0.1)[0]:
                try:
                    data = os.read(terminal, 4096)
                except OSError:
                    data = b""
                if not data:
                    break
                output.extend(data)
                if len(output) > 32768:
                    return {"elevation_error": "execution"}
                if (
                    not sent
                    and bytes(output).rsplit(b"\n", 1)[-1].strip().lower()
                    == b"password:"
                ):
                    if terminals.tcgetattr(terminal)[3] & (
                        terminals.ECHO | terminals.ECHONL
                    ):
                        return {"elevation_error": "echo"}
                    os.write(terminal, password.encode() + b"\n")
                    password = ""
                    sent = True
                    output.clear()
                if b"ATLASO_ROOT_READY" in output and not ready:
                    ready = True
                    deadline = time.monotonic() + 310
                    if authorize_write:
                        print(json.dumps({"ready": True}), flush=True)
                        if not select.select([sys.stdin], [], [], 15)[0]:
                            return {"elevation_error": "timeout"}
                        if sys.stdin.buffer.readline(32) != b"ATLASO_APPLY\n":
                            return {"elevation_error": "execution"}
                        os.write(terminal, b"ATLASO_APPLY\n")
                marker = b"ATLASO_RESULT:"
                if marker in output:
                    result_line = bytes(output).split(marker, 1)[1].split(b"\n", 1)
                    if len(result_line) == 2:
                        result = json.loads(result_line[0])
                        if isinstance(result, dict) and ready:
                            return result
                        return {"elevation_error": "execution"}
            exited = 0
            if not reaped:
                exited, _ = posix.waitpid(pid, posix.WNOHANG)
            if exited:
                reaped = True
                # Drain a final ready chunk on the next iteration.
                if not select.select([terminal], [], [], 0)[0]:
                    break
        else:
            return {"elevation_error": "timeout"}
        return {"elevation_error": "execution" if ready else "authentication"}
    finally:
        password = ""
        output.clear()
        os.close(terminal)
        if not reaped:
            try:
                posix.kill(pid, signals.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            posix.waitpid(pid, posix.WNOHANG)


def safe_operate(request: dict[str, Any]) -> dict[str, Any]:
    """Return safe editor failures without a traceback or remote configuration.

    Args:
        request: Fixed property inspection or mutation request.
    """
    try:
        return operate(request)
    except PropertyError as exc:
        return {"ok": False, "error": str(exc), "phase": "property"}
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return {
            "ok": False,
            "phase": "property",
            "error": "Property operation failed; inspect the target before recovery.",
        }


def dispatch(envelope: dict[str, Any]) -> dict[str, Any]:
    """Keep readable inspection unprivileged; elevate only the fixed editor.

    Args:
        envelope: Request, editor source and transient root secret from SSH stdin.
    """
    request = envelope["request"]
    if request.get("action") == "inspect":
        try:
            return operate(request)
        except PermissionError:
            pass
    # Only source and the non-secret operation enter su's argv. No password is
    # inserted into this program, its arguments, a file, or a shell environment.
    source = base64.b64decode(envelope["editor"], validate=True).decode()
    program = (
        "import os,signal,sys;signal.alarm(300);"
        "assert os.geteuid()==0;print('ATLASO_ROOT_READY',flush=True);"
        + (
            "assert sys.stdin.readline()=='ATLASO_APPLY\\n';"
            if request.get("action") == "write"
            else ""
        )
        + f"exec(compile({source!r},'<atlaso-vcf-lab>','exec'),globals());"
        f"print('ATLASO_RESULT:'+json.dumps(safe_operate({request!r})),flush=True)"
    )
    # Suppress the module's stdin entrypoint inside the privileged interpreter.
    program = "__name__='atlaso_vcf_editor';" + program
    return elevated(
        PYTHON_COMMAND + shlex.quote(program),
        envelope["root_password"],
        authorize_write=request.get("action") == "write",
    )


def main() -> None:
    """Return bounded structured evidence, never raw configuration or stderr."""
    try:
        envelope = json.loads(sys.stdin.buffer.readline(131073))
        result = dispatch(envelope)
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
