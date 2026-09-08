"""Windows handle-bound removal of an independently owned generated output tree."""

from __future__ import annotations

import ctypes
import os
from contextlib import contextmanager
from pathlib import Path


class FileRefusal(RuntimeError):
    """Filesystem identity or platform cannot support checked deletion."""


def publish_durable_file(source: Path, destination: Path) -> None:
    """Publish a flushed same-directory file and durably commit its directory entry."""
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
        descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


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
        """Deny replacement/writers while reading attributes or setting exact-object disposition."""
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
        """Pin from volume root down so a checked ancestor cannot become a junction."""
        from contextlib import ExitStack

        with ExitStack() as stack:
            for parent in reversed(path.parents):
                stack.enter_context(self.opened(parent, directory=True))
            yield

    def snapshot(self, root: Path) -> dict[str, dict]:
        """Capture an exact ordinary tree without following links or allowing ancestor replacement."""
        result: dict[str, dict] = {}

        def visit(path: Path) -> None:
            """Keep a parent pinned while enumerating and inspecting its children."""
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
        """Delete children then empty directories through matching no-follow handles."""
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
