"""Windows handle-bound removal of an independently owned generated output tree."""

from __future__ import annotations

import ctypes
import os
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path


class FileRefusal(RuntimeError):
    """Filesystem identity or platform cannot support checked deletion."""


@contextmanager
def cleanup_lock(root: Path, digest: str):
    """Serialize destructive runs for one canonical task identity across processes without waiting.

    Args:
        root: Root directory that bounds the filesystem operation.
        digest: Canonical task identity SHA-256 used to coordinate exclusive cleanup.
    """
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise FileRefusal("Invalid cleanup lock identity.")
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.WaitForSingleObject.restype = ctypes.c_uint32
        kernel.ReleaseMutex.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.CreateMutexW(None, False, f"Global\\Atlaso.CompletedTaskCleanup.{digest}")
        if not handle:
            raise FileRefusal("Cannot acquire cleanup coordination handle; preserve resources.")
        acquired = False
        try:
            acquired = kernel.WaitForSingleObject(handle, 0) in (0, 0x80)
            if not acquired:
                raise FileRefusal("Another cleanup controller owns this task; retry after it exits.")
            yield
        finally:
            if acquired:
                kernel.ReleaseMutex(handle)
            kernel.CloseHandle(handle)
    else:
        import fcntl

        # Keep the lock inode: unlinking it would let a later controller lock a different inode.
        descriptor = os.open(root / f".atlaso-cleanup-{digest}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise FileRefusal("Cleanup lock must be an ordinary single-link coordination file.")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise FileRefusal("Another cleanup controller owns this task; retry after it exits.") from exc
            yield
        finally:
            os.close(descriptor)


def sync_directory(path: Path) -> None:
    """Persist visible POSIX entries before trusting a recovered rename; Windows publishes write-through.

    Args:
        path: Filesystem path examined by this operation.
    """
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def publish_durable_file(source: Path, destination: Path) -> None:
    """Publish a flushed same-directory file and durably commit its directory entry.

    Args:
        source: Staged same-directory entry whose contents were already flushed.
        destination: Final path that must not replace an existing entry.
    """
    if source.parent != destination.parent or destination.exists():
        raise FileRefusal("Evidence publication requires a new name in the same directory.")
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        kernel.MoveFileExW.restype = ctypes.c_int
        # WRITE_THROUGH waits for the move to reach disk; omit replacement/copy flags.
        if not kernel.MoveFileExW(str(source), str(destination), 0x8):
            raise FileRefusal("Write-through evidence publication failed; reconcile pending evidence before retry.")
    else:
        source.rename(destination)
        sync_directory(destination.parent)


def ensure_durable_directory(path: Path) -> None:
    """Publish each newly created directory through its parent before trusting child journals.

    Args:
        path: Filesystem path examined by this operation.
    """
    pending = path.with_name(f".{path.name}.atlaso-cleanup-directory.pending")
    if pending.exists():
        raise FileRefusal("Pending evidence-directory publication requires independent reconciliation before retry.")
    if not path.exists():
        ensure_durable_directory(path.parent)
        pending.mkdir()
        publish_durable_file(pending, path)
    if not path.is_dir():
        raise FileRefusal("Evidence directory is not an ordinary directory.")
    if os.name != "nt" and path != path.parent:
        # Also repair durability on a retry after rename succeeded but parent fsync failed.
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def read_bounded_regular(path: Path, limit: int) -> bytes:
    """Read a small ordinary file without following its link or accepting growth/replacement.

    Args:
        path: Filesystem path examined by this operation.
        limit: Maximum permitted file size and number of bytes read.
    """
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise FileRefusal("Evidence input must be a bounded regular single-link file.")
    with ExitStack() as stack:
        if os.name == "nt":
            files = WindowsFiles()
            stack.enter_context(files.ancestors(path))
            stack.enter_context(files.opened(path))
            stream = stack.enter_context(path.open("rb"))
        else:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stream = stack.enter_context(os.fdopen(descriptor, "rb"))
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size > limit \
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise FileRefusal("Evidence input identity or size changed before reading.")
        payload = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(payload) > limit or len(payload) != opened.st_size \
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink) != \
                   (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, 1):
            raise FileRefusal("Evidence input changed during its bounded read.")
        return payload


class WindowsFiles:
    """Pin ancestors and delete only the exact no-follow object whose identity was checked."""

    def __init__(self) -> None:
        """Bind documented Win32 file APIs without compiling or staging helper files."""
        if os.name != "nt":
            raise FileRefusal("Generated-tree release requires Windows handle-bound deletion.")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                           ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        self.kernel.CreateFileW.restype = ctypes.c_void_p
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                         ctypes.c_void_p, ctypes.c_uint32]

    @contextmanager
    def opened(self, path: Path, *, delete: bool = False, directory: bool = False):
        """Deny replacement/writers while reading attributes or setting exact-object disposition.

        Args:
            path: Filesystem path examined by this operation.
            delete: Request deletion access while retaining the checked object handle.
            directory: Whether the handle must refer to a directory.
        """
        # READ_DATA/LIST_DIRECTORY makes the share restriction effective. OPEN_REPARSE_POINT
        # inspects the entry itself; BACKUP_SEMANTICS permits ordinary directory handles.
        handle = self.kernel.CreateFileW(str(path), 0x81 | (0x10000 if delete else 0),
                                         1, None, 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise FileRefusal("Cannot pin an ordinary inactive output entry; preserve it and retry after quiescence.")
        try:
            information = (ctypes.c_uint32 * 13)()
            if not self.kernel.GetFileInformationByHandle(handle, information):
                raise FileRefusal("Cannot read pinned filesystem identity.")
            attributes = information[0]
            if attributes & 0x400 or bool(attributes & 0x10) != directory:
                raise FileRefusal("Reparse point or entry type changed; preserve the tree.")
            if not directory and information[10] != 1:
                raise FileRefusal("Shared hard-linked output file is not eligible.")
            identity = (information[7], information[11], information[12])
            stamp = (information[5], information[6], information[8], information[9])
            yield handle, identity, stamp
        finally:
            self.kernel.CloseHandle(handle)

    @contextmanager
    def ancestors(self, path: Path):
        """Pin from volume root down so a checked ancestor cannot become a junction.

        Args:
            path: Filesystem path examined by this operation.
        """
        from contextlib import ExitStack

        with ExitStack() as stack:
            for parent in reversed(path.parents):
                stack.enter_context(self.opened(parent, directory=True))
            yield

    def snapshot(self, root: Path) -> dict[str, dict]:
        """Capture an exact ordinary tree without following links or allowing ancestor replacement.

        Args:
            root: Root directory that bounds the filesystem operation.
        """
        result: dict[str, dict] = {}

        def visit(path: Path) -> None:
            """Keep a parent pinned while enumerating and inspecting its children.

            Args:
                path: Filesystem path examined by this operation.
            """
            if len(result) >= 50000 or len(path.relative_to(root).parts) > 128:
                raise FileRefusal("Generated tree exceeds bounded inventory limits; split its owned resource inventory.")
            directory = path.is_dir()
            with self.opened(path, directory=directory) as (_, identity, stamp):
                result[str(path.relative_to(root))] = {"identity": list(identity), "stamp": list(stamp),
                                                       "directory": directory}
                if directory:
                    for child in sorted(path.iterdir()):
                        visit(child)

        with self.ancestors(root):
            visit(root)
        return result

    def remove(self, root: Path, expected: dict[str, dict]) -> None:
        """Delete children then empty directories through matching no-follow handles.

        Args:
            root: Root directory that bounds the filesystem operation.
            expected: Previously captured relative-path identity snapshot required before removal.
        """
        if self.snapshot(root) != expected:
            raise FileRefusal("Generated output changed after inspection; obtain a fresh preview.")
        for relative in sorted(expected, key=lambda value: len(Path(value).parts), reverse=True):
            path = root / relative
            entry = expected[relative]
            with self.ancestors(path), self.opened(path, delete=True, directory=entry["directory"]) as (handle, identity, stamp):
                if list(identity) != entry["identity"] or (not entry["directory"] and list(stamp) != entry["stamp"]):
                    raise FileRefusal("An output entry was replaced or changed; preserve remaining entries.")
                # The kernel rejects nonempty directories. A concurrently added child therefore
                # blocks completion instead of being swept into a recursive path-based deletion.
                disposition = ctypes.c_ubyte(1)
                if not self.kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), 1):
                    raise FileRefusal("Exact output deletion failed; preserve remaining entries and retry after inspection.")
            if path.exists():
                raise FileRefusal("Output absence verification failed.")
