#!/usr/bin/env python3
"""Bounded Linux RPM tool protocol for the Windows offline ISO refresh owner.

Uses only the standard library available in an existing Linux tool environment.
No tool is executed until the Windows owner durably records its original Linux
PID, birth and session and sends the matching release message. No installation,
credential handling or distribution configuration is performed here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import signal
import sys
import time
from pathlib import Path

TOOLS = {name: Path("/usr/bin") / name for name in ("rpm", "rpmkeys", "createrepo_c")}
MAX_OUTPUT = 4 * 1024**2


def birth(pid: int) -> str:
    """Read the kernel start tick of one exact Linux process.

    Args:
        pid: Exact Linux process identifier whose kernel birth tick is read.
    """
    return Path(f"/proc/{pid}/stat").read_text().rpartition(") ")[2].split()[19]


def live_group(group: int) -> list[int]:
    """Return every executing process in the original tool session/group.

    Args:
        group: Original Linux process group and session identifier to inspect.
    """
    result = []
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            fields = (path / "stat").read_text().rpartition(") ")[2].split()
        except FileNotFoundError:
            continue
        if fields[0] != "Z" and (int(fields[2]) == group or int(fields[3]) == group):
            result.append(int(path.name))
    return result


def stop_group(group: int, expected_birth: str | None = None) -> None:
    """Terminate only the original tool group and prove no executing members remain.

    Args:
        group: Original Linux process group and session identifier to inspect.
        expected_birth: Original group-leader start tick preventing unrelated PID-reuse cleanup.
    """
    end = time.monotonic() + 5
    while live_group(group):
        try:
            if expected_birth is not None and birth(group) != expected_birth:
                raise RuntimeError("native_tool_pid_reused_preserve_group")
        except FileNotFoundError:
            pass
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if time.monotonic() >= end:
            raise RuntimeError("native_tool_group_quiescence_unproven")
        time.sleep(0.02)


def emit(value: dict) -> None:
    """Emit one protocol message, never arbitrary tool or console bytes.

    Args:
        value: Bounded protocol record, never arbitrary console or credential text.
    """
    print(json.dumps(value, separators=(",", ":")), flush=True)


def execute(request: dict) -> int:
    """Execute one fixed native tool with an original, host-released child.

    Args:
        request: Bounded fixed-tool request with original task, source and deadline bindings.
    """
    name, arguments = request["tool"], request["arguments"]
    if name not in TOOLS or not isinstance(arguments, list) or len(arguments) > 2048:
        raise ValueError("native_tool_request_invalid")
    if any(not isinstance(arg, str) or "\0" in arg or len(arg) > 65536 for arg in arguments):
        raise ValueError("native_tool_arguments_invalid")
    executable = TOOLS[name]
    identity = executable.stat()
    tool_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    # Reserve cleanup time inside the caller's original deadline. A late WSL
    # startup cannot create a new effective command budget.
    remaining = min(120, request["deadline_epoch"] - time.time())
    if remaining < 7:
        raise ValueError("native_tool_original_deadline_expired")
    deadline = time.monotonic() + remaining - 6
    output_read, output_write = os.pipe()
    error_read, error_write = os.pipe()
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            for descriptor in (output_read, error_read, ready_read, release_write):
                os.close(descriptor)
            os.setsid()
            os.write(ready_write, b"1")
            os.close(ready_write)
            if os.read(release_read, 1) != b"1":
                os._exit(125)
            os.close(release_read)
            os.dup2(output_write, 1)
            os.dup2(error_write, 2)
            os.close(output_write)
            os.close(error_write)
            os.chdir(request["cwd"])
            # The independent native timeout survives even if the host launcher
            # or this supervisor dies before it can publish a completion record.
            os.execv("/usr/bin/timeout", ["/usr/bin/timeout", "--kill-after=5s",
                                        str(max(0.1, deadline - time.monotonic())) + "s",
                                        str(executable), *arguments])
        except BaseException:  # noqa: BLE001 - a forked child must exit instead of falling into its supervisor's code.
            os._exit(126)
    for descriptor in (output_write, error_write, ready_write, release_read):
        os.close(descriptor)
    released = False
    reaped = False
    original = None
    try:
        if os.read(ready_read, 1) != b"1":
            raise RuntimeError("native_tool_child_not_ready")
        original = {"schema": 1, "kind": "native-tool-original", "request_id": request["request_id"],
                    "task_id": request["task_id"], "source_commit": request["source_commit"],
                    "pid": pid, "start_ticks": birth(pid), "group": pid,
                    "tool": name, "tool_sha256": tool_hash,
                    "tool_identity": [identity.st_dev, identity.st_ino], "deadline_epoch": request["deadline_epoch"]}
        emit(original)
        release_raw = sys.stdin.buffer.readline(4097)
        if len(release_raw) > 4096 or json.loads(release_raw) != {"release": request["request_id"]}:
            raise RuntimeError("native_tool_release_not_admitted")
        if time.monotonic() >= deadline:
            raise RuntimeError("native_tool_original_deadline_expired")
        os.write(release_write, b"1")
        os.close(release_write)
        released = True
        chunks, size = [], 0
        selector = selectors.DefaultSelector()
        for descriptor, keep in ((output_read, True), (error_read, False), (sys.stdin.fileno(), False)):
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ, keep)
        status = None
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError("native_tool_timeout")
                for key, _ in selector.select(0.05):
                    data = os.read(key.fd, 8192)
                    if not data:
                        selector.unregister(key.fd)
                        if key.fd == sys.stdin.fileno() and status is None:
                            raise RuntimeError("native_tool_owner_disconnected")
                        continue
                    if key.fd == sys.stdin.fileno():
                        raise RuntimeError("native_tool_unexpected_owner_input")
                    size += len(data)
                    if size > MAX_OUTPUT:
                        raise RuntimeError("native_tool_output_limit")
                    if key.data:
                        chunks.append(data)
                if status is None:
                    waited, raw_status = os.waitpid(pid, os.WNOHANG)
                    if waited:
                        reaped = True
                        status = os.waitstatus_to_exitcode(raw_status)
                        stop_group(pid, original["start_ticks"])
                        selector.unregister(sys.stdin.fileno())
        finally:
            selector.close()
        stop_group(pid, original["start_ticks"])
        after = executable.stat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                identity.st_dev, identity.st_ino, identity.st_size, identity.st_mtime_ns):
            raise RuntimeError("native_tool_identity_changed")
        if hashlib.sha256(executable.read_bytes()).hexdigest() != tool_hash:
            raise RuntimeError("native_tool_bytes_changed")
        emit({"schema": 1, "kind": "native-tool-result", "request_id": request["request_id"],
              "pid": pid, "start_ticks": original["start_ticks"], "returncode": status,
              "whole_group_quiescent": True, "output": base64.b64encode(b"".join(chunks)).decode("ascii")})
        return 0
    finally:
        if not released:
            os.close(release_write)
        stop_group(pid, original["start_ticks"] if original else None)
        if not reaped:
            os.waitpid(pid, 0)
        for descriptor in (ready_read, output_read, error_read):
            os.close(descriptor)


def main() -> int:
    """Accept one bounded request and fail closed without emitting private errors."""
    raw = sys.stdin.buffer.readline(1024**2 + 1)
    if not raw or len(raw) > 1024**2:
        raise ValueError("native_tool_request_limit")
    return execute(json.loads(raw))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        emit({"kind": "native-tool-failure", "whole_group_quiescent": False})
        raise SystemExit(2) from None
