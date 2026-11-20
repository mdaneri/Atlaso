"""Standard-library workspace owner for the pinned SSH RPM tool transport.

Only newly created, task-bound data directories are managed. This program never
installs tools, changes a VM, handles credentials, or executes a native command.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

MAX_FILE = 512 * 1024**2
MAX_TOTAL = 16 * 1024**3
PARENT = Path("/var/tmp")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")


def stamp(value: os.stat_result) -> list[int]:
    """Return the identity and metadata used to reject concurrent replacement.

    Args:
        value: A no-follow filesystem observation.
    """
    return [value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def inventory(path: Path, *, include_digests: bool = True) -> list[dict]:
    """Inspect an ordinary owned tree through retained no-follow directory handles.

    Args:
        path: Exact directory beneath the admitted workspace.
        include_digests: Hash file contents only for export or final deletion.
    """
    rows: list[dict] = []
    total = 0

    def visit(fd: int, relative: str) -> None:
        """Inspect one directory without traversing links.

        Args:
            fd: Retained directory descriptor.
            relative: Workspace-relative public name.
        """
        nonlocal total
        before = os.fstat(fd)
        for name in sorted(os.listdir(fd)):
            if name in (".", "..") or "/" in name or "\\" in name or len(rows) >= 20000:
                raise ValueError("workspace_inventory_invalid")
            item = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if item.st_uid != os.getuid() or item.st_dev != before.st_dev:
                raise ValueError("workspace_owner_or_device_changed")
            child = relative + "/" + name if relative else name
            row = {"path": child, "stamp": stamp(item)}
            if stat.S_ISDIR(item.st_mode):
                nested = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if stamp(os.fstat(nested)) != stamp(item):
                        raise ValueError("workspace_directory_changed")
                    row["kind"] = "directory"
                    rows.append(row)
                    visit(nested, child)
                finally:
                    os.close(nested)
            elif stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and item.st_size <= MAX_FILE:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(descriptor, "rb") as stream:
                    if stamp(os.fstat(stream.fileno())) != stamp(item):
                        raise ValueError("workspace_file_changed")
                    digest = hashlib.file_digest(stream, "sha256").hexdigest() if include_digests else None
                    if stamp(os.fstat(stream.fileno())) != stamp(item):
                        raise ValueError("workspace_file_changed")
                total += item.st_size
                if total > MAX_TOTAL:
                    raise ValueError("workspace_size_limit")
                row.update(kind="file", size=item.st_size)
                if digest is not None:
                    row["sha256"] = digest
                rows.append(row)
            else:
                raise ValueError("workspace_link_or_special_file")
            if stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) != stamp(item):
                raise ValueError("workspace_entry_changed")
        if stamp(os.fstat(fd)) != stamp(before):
            raise ValueError("workspace_directory_changed")

    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(fd, "")
    finally:
        os.close(fd)
    return rows


def catalog_digest(rows: list[dict]) -> str:
    """Bind complete names and object stamps without rehashing cached public RPMs.

    Args:
        rows: Complete no-follow workspace inventory.
    """
    values = [{key: value for key, value in row.items() if key != "sha256"} for row in rows]
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inside(root: Path, relative: str) -> Path:
    """Resolve only ordinary descendants of the original workspace.

    Args:
        root: Original workspace root.
        relative: Lexically constrained relative path.
    """
    parts = relative.split("/")
    if not relative or any(part in ("", ".", "..") or "\\" in part or "\0" in part for part in parts):
        raise ValueError("workspace_path_invalid")
    current = root
    for part in parts:
        current /= part
        value = current.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid != os.getuid():
            raise ValueError("workspace_path_changed")
    return current


def execute(request: dict) -> dict:
    """Create, inspect, export or remove one exactly bound native workspace.

    Args:
        request: Bounded operation and independently retained root identity.
    """
    scope = request["scope"]
    if not re.fullmatch(r"[0-9a-f]{32}-[a-z]{3,16}", scope):
        raise ValueError("workspace_scope_invalid")
    root = PARENT / ("atlaso-rpm-" + scope)
    if not stat.S_ISDIR(PARENT.lstat().st_mode):
        raise ValueError("workspace_parent_must_be_ordinary")
    boot = BOOT_ID.read_text().strip()
    if request["operation"] == "create":
        root.mkdir(mode=0o700)
        parent_fd = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        value = root.lstat()
        original = {"path": str(root), "identity": [value.st_dev, value.st_ino], "boot_id": boot,
                    "uid": value.st_uid, "scope": scope, "task_id": request["task_id"],
                    "source_commit": request["source_commit"], "created_epoch": time.time()}
        with (root / "ownership.json").open("x") as stream:
            json.dump(original, stream)
            stream.flush()
            os.fsync(stream.fileno())
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        return original
    original = request["original"]
    value = root.lstat()
    if (original["path"] != str(root) or original["boot_id"] != boot or original["scope"] != scope
            or original["task_id"] != request["task_id"] or original["source_commit"] != request["source_commit"]
            or original["identity"] != [value.st_dev, value.st_ino]
            or not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700
            or value.st_uid != os.getuid() or original["uid"] != value.st_uid):
        raise ValueError("workspace_original_identity_changed")
    ownership = inside(root, "ownership.json")
    if json.loads(ownership.read_text()) != original:
        raise ValueError("workspace_ownership_changed")
    operation = request["operation"]
    if operation == "verify":
        return {"identity_verified": True, "observed_epoch": time.time()}
    if operation == "catalog":
        return {"sha256": catalog_digest(inventory(root, include_digests=False))}
    if operation == "files":
        result = {}
        for relative in request["paths"]:
            path = inside(root, relative)
            if path.is_dir():
                result[relative] = inventory(path)
            else:
                value = path.lstat()
                if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size > MAX_FILE:
                    raise ValueError("workspace_file_invalid")
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    if stamp(os.fstat(stream.fileno())) != stamp(value):
                        raise ValueError("workspace_file_changed")
                    checksum = hashlib.file_digest(stream, "sha256").hexdigest()
                    if stamp(os.fstat(stream.fileno())) != stamp(value):
                        raise ValueError("workspace_file_changed")
                result[relative] = [{"path": "", "kind": "file", "size": value.st_size,
                                     "sha256": checksum}]
        return result
    if operation == "remove":
        rows = inventory(root)
        if request["expected_catalog"] != catalog_digest(rows):
            raise ValueError("workspace_inventory_changed_before_release")
        # Never follow an unknown entry or remove a replacement. A failed
        # comparison preserves the remaining tree for explicit reconciliation.
        for row in sorted(rows, key=lambda item: item["path"].count("/"), reverse=True):
            path = inside(root, row["path"])
            current = path.lstat()
            expected = row["stamp"]
            if (current.st_dev, current.st_ino, current.st_mode, current.st_uid) != (
                    expected[0], expected[1], expected[2], expected[4]):
                raise ValueError("workspace_changed_before_release")
            if row["kind"] == "file":
                if stamp(current) != expected or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
                    raise ValueError("workspace_file_changed_before_release")
                path.unlink()
            else:
                path.rmdir()
        if [root.lstat().st_dev, root.lstat().st_ino] != original["identity"]:
            raise ValueError("workspace_root_changed_before_release")
        root.rmdir()
        return {"remote_root_absent": not os.path.lexists(root)}
    raise ValueError("workspace_operation_invalid")


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.readline(1024**2 + 1)
        if len(raw) > 1024**2:
            raise ValueError("workspace_request_limit")
        print(json.dumps({"result": execute(json.loads(raw))}), flush=True)
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"error": "native_workspace_refused"}), flush=True)
        raise SystemExit(2) from None
