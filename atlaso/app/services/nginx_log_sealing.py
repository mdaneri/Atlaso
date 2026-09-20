"""Seal Nginx-owned log generations only after cooperative descriptor closure.

This primitive does not poll or rotate from a browser request. A privileged
lifecycle/collector caller supplies its prepared private generation directory.
Raw generations remain available for recovery and retain their original bytes.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

LOG_NAMES = ("access.log", "error.log")
MAX_PROCESSES = 4096
MAX_DESCRIPTORS = 65536


def _sync_directory(directory: Path) -> None:
    """Persist directory entry changes on the Linux appliance filesystem.

    Args:
        directory: Trusted source or retained generation directory.
    """
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _identity(path: Path) -> tuple[int, int]:
    """Read a single-link ordinary file identity without following a link.

    Args:
        path: Internal fixed log or retained generation path.
    """
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Nginx sealing requires an ordinary single-link file.")
    return info.st_dev, info.st_ino


def _persist(directory: Path, manifest: dict[str, Any]) -> None:
    """Durably publish recovery state before or after the corresponding action.

    Args:
        directory: Private task-owned generation directory.
        manifest: Metadata-only generation state.
    """
    temporary = directory / "manifest.pending"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, directory / "manifest.json")
    _sync_directory(directory)


def seal_generation(log_directory: Path, generation_directory: Path, *,
                    reopen: Callable[[], None],
                    writers_closed: Callable[[set[tuple[int, int]]], bool],
                    timeout: float = 10) -> dict[str, Any]:
    """Retain and seal one crash-recoverable pair of Nginx log files.

    The caller holds the collector's exclusive lifecycle lock and owns both
    directories. A failed reopen or closure proof preserves the unsealed files;
    retrying this same directory requests reopen again and completes the proof.
    No size-growth heuristic authenticates a mutable prefix.

    Args:
        log_directory: Trusted directory containing the two fixed current logs.
        generation_directory: Existing private directory unique to this generation.
        reopen: Checked Nginx master USR1 operation, never a shell command string.
        writers_closed: Full service process/descriptor proof for both old inodes.
        timeout: Maximum seconds to wait for cooperative descriptor closure.
    """
    if timeout <= 0 or timeout > 30:
        raise ValueError("Invalid Nginx seal deadline.")
    for directory in (log_directory, generation_directory):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("Nginx sealing requires prepared ordinary directories.")
    generation_info = generation_directory.stat()
    if generation_info.st_dev != log_directory.stat().st_dev:
        raise ValueError("Nginx sealing requires same-filesystem atomic retention.")
    if os.name == "posix":
        uid = int(importlib.import_module("os").geteuid())
        if generation_info.st_uid != uid or stat.S_IMODE(generation_info.st_mode) & 0o077:
            raise ValueError("Nginx generation requires a private collector-owned directory.")
    manifest_path = generation_directory / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("Linked Nginx generation manifest.")
    if manifest_path.exists():
        if manifest_path.stat().st_size > 4096:
            raise ValueError("Oversized Nginx generation manifest.")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict) or manifest.get("schema") != 1 or
                manifest.get("state") not in {"prepared", "sealed"} or
                set(manifest.get("files", {})) != set(LOG_NAMES)):
            raise ValueError("Invalid Nginx generation recovery state.")
    else:
        entries = list(generation_directory.iterdir())
        if entries and (len(entries) != 1 or entries[0].name != "manifest.pending"):
            raise ValueError("Nginx generation has unowned recovery contents.")
        if entries:
            # No rename occurs until the prepared manifest is durable. A crash
            # while writing its private temporary file can safely retry from
            # the still-current pair, without trusting partial JSON bytes.
            _identity(entries[0])
        files = {name: {"identity": list(_identity(log_directory / name))} for name in LOG_NAMES}
        manifest = {"schema": 1, "state": "prepared", "files": files}
        _persist(generation_directory, manifest)
    identities: set[tuple[int, int]] = set()
    for name in LOG_NAMES:
        expected = manifest["files"][name].get("identity")
        if (not isinstance(expected, list) or len(expected) != 2 or
                any(type(part) is not int or part < 0 for part in expected)):
            raise ValueError("Invalid Nginx generation identity.")
        identity = (expected[0], expected[1])
        current, retained = log_directory / name, generation_directory / name
        if retained.exists() or retained.is_symlink():
            if _identity(retained) != identity:
                raise ValueError("Retained Nginx generation identity changed.")
        else:
            if manifest["state"] == "sealed" or _identity(current) != identity:
                raise ValueError("Current Nginx generation identity changed.")
            os.rename(current, retained)
            if _identity(retained) != identity:
                raise ValueError("Nginx generation changed during retention.")
            _sync_directory(log_directory)
            _sync_directory(generation_directory)
        identities.add(identity)
    if manifest["state"] != "sealed":
        reopen()
        deadline = time.monotonic() + timeout
        while not writers_closed(identities):
            if time.monotonic() >= deadline:
                raise TimeoutError("Nginx has not closed its retained log descriptors.")
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    for name in LOG_NAMES:
        retained = generation_directory / name
        descriptor = os.open(retained, (os.O_RDWR if os.name == "nt" else os.O_RDONLY) |
                             getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino) not in identities or not stat.S_ISREG(before.st_mode):
                raise ValueError("Nginx generation descriptor changed.")
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("Nginx retained generation changed after closure.")
            if manifest["state"] == "sealed" and (
                    digest != manifest["files"][name].get("sha256") or
                    before.st_size != manifest["files"][name].get("size")):
                raise ValueError("Sealed Nginx generation contents changed.")
            manifest["files"][name].update(size=before.st_size, sha256=digest)
            os.fsync(stream.fileno())
    manifest["state"] = "sealed"
    _persist(generation_directory, manifest)
    return manifest


def _processes(cgroup: Path) -> dict[int, str]:
    """Pin the full bounded Nginx cgroup membership by process start time.

    Args:
        cgroup: Verified fixed Nginx service cgroup beneath the cgroup mount.
    """
    paths = [cgroup / "cgroup.procs"]
    for path in cgroup.rglob("cgroup.procs"):
        if path not in paths:
            paths.append(path)
        if len(paths) > 64:
            raise ValueError("Nginx cgroup hierarchy exceeds the seal bound.")
    processes: dict[int, str] = {}
    for path in paths:
        values = path.read_text(encoding="ascii").splitlines()
        if len(values) + len(processes) > MAX_PROCESSES:
            raise ValueError("Nginx process inventory exceeds the seal bound.")
        for value in values:
            if not value.isdecimal() or int(value) < 1:
                raise ValueError("Invalid Nginx cgroup process identity.")
            pid = int(value)
            # comm can include spaces and parentheses; fields after its final ')'
            # begin with field 3, making starttime (field 22) index 19.
            process_stat = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
            processes[pid] = process_stat.rsplit(")", 1)[1].split()[19]
    return processes


def nginx_writers_closed(identities: set[tuple[int, int]]) -> bool:
    """Prove no current Nginx process can continue writing either old inode.

    Args:
        identities: Device/inode identities retained by the sealing transaction.
    """
    cgroup = Path("/sys/fs/cgroup/system.slice/nginx.service")
    if not cgroup.is_dir() or cgroup.is_symlink():
        raise ValueError("The fixed Nginx cgroup is unavailable.")
    try:
        before = _processes(cgroup)
        if not before:
            return False  # Startup/restart races require a later populated proof.
        count = 0
        for pid in before:
            for descriptor in (Path("/proc") / str(pid) / "fd").iterdir():
                count += 1
                if count > MAX_DESCRIPTORS:
                    raise ValueError("Nginx descriptor inventory exceeds the seal bound.")
                try:
                    info = descriptor.stat()
                except FileNotFoundError:
                    # Client sockets can close throughout healthy traffic. A
                    # vanished descriptor is closed; worker identity/membership
                    # is independently revalidated after scanning all survivors.
                    continue
                if (info.st_dev, info.st_ino) in identities:
                    return False
        return before == _processes(cgroup)
    except (FileNotFoundError, ProcessLookupError):
        return False


def reopen_nginx_logs() -> None:
    """Ask only the existing Nginx master to reopen its normal file logs."""
    subprocess.run(["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=USR1",
                    "nginx.service"], check=True, timeout=10, capture_output=True)
