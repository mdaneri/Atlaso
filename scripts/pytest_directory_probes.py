"""Recognize the fixed harmless directory-release probe without adopting recovery state."""

from __future__ import annotations

import ctypes
import re
from pathlib import Path
from typing import Any

from scripts.completed_task_files import FileRefusal, WindowsFiles, read_bounded_regular


class PytestDirectoryProbeFiles(WindowsFiles):
    """Own explicitly selected synthetic directory probes inside a creation-bound pytest root."""

    def __init__(self, probe_roots: object) -> None:
        """Select only the known directory-gate fixture layout, with no caller-defined payloads.

        Args:
            probe_roots: One to sixteen exact relative probe-root strings from the resource inventory.
        """
        if not isinstance(probe_roots, list) or not 1 <= len(probe_roots) <= 16:
            raise FileRefusal("Supply a bounded explicit synthetic directory-probe inventory.")
        selected = []
        for value in probe_roots:
            parts = value.replace("\\", "/").split("/") if isinstance(value, str) else []
            if len(parts) != 4 or not re.fullmatch(r"pytest(?:-[a-z0-9_-]+)?", parts[0]) \
                    or not re.fullmatch(r"test_real_directory_gate_prune[0-9]+", parts[1]) \
                    or parts[2:] != ["worktree", ".atlaso-local"]:
                raise FileRefusal("Synthetic directory-probe path differs from the known pytest fixture layout.")
            selected.append(Path(*parts))
        if len(set(selected)) != len(selected):
            raise FileRefusal("Duplicate synthetic directory-probe roots are forbidden.")
        self.probe_roots = tuple(selected)
        super().__init__(allow_internal_symlinks=True)
        self.kernel.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.c_void_p, ctypes.c_void_p]
        self.kernel.ReadFile.restype = ctypes.c_int

    def probe_files(self, snapshot: dict[str, dict[str, Any]]) -> tuple[Path, ...]:
        """Refuse unknown recovery roots, extra entries, links, and altered probe entry types.

        Args:
            snapshot: Complete no-follow inventory of the outer creation-bound validation root.
        """
        nested = set()
        entries = {Path(name): entry for name, entry in snapshot.items()}
        for path in entries:
            for index, part in enumerate(path.parts):
                if part.casefold() == ".atlaso-local":
                    nested.add(Path(*path.parts[:index + 1]))
        if nested != set(self.probe_roots):
            raise FileRefusal("Unlisted or missing nested recovery root blocks synthetic probe cleanup.")
        files = []
        for probe in self.probe_roots:
            payload = probe / "result with spaces.txt"
            required = {probe: True, probe / "nested empty": True, payload: False}
            actual = {path for path in entries if path.is_relative_to(probe)}
            if actual != set(required) or any(entries[path].get("directory") is not directory
                                             or "link_sha256" in entries[path]
                                             for path, directory in required.items()):
                raise FileRefusal("Synthetic directory probe contains unknown entries, links, or entry types.")
            files.append(payload)
        return tuple(files)

    def snapshot(self, root: Path) -> dict[str, dict[str, Any]]:
        """Verify each selected probe's fixed literal while its ordinary file is pinned.

        Args:
            root: Originally receipted outer pytest output root.
        """
        snapshot = super().snapshot(root)
        for relative in self.probe_files(snapshot):
            path = root / relative
            with self.ancestors(path), self.opened(path) as (_handle, identity, stamp):
                entry = snapshot[str(relative)]
                if list(identity) != entry["identity"] or list(stamp) != entry["stamp"] \
                        or read_bounded_regular(path, 9) != b"generated":
                    raise FileRefusal("Synthetic directory-probe payload differs from the fixed test literal.")
        return snapshot

    def verify_pinned_contents(self, root: Path, expected: dict[str, dict[str, Any]], handles: dict[str, int]) -> None:
        """Recheck fixed bytes on the existing deletion handles before disposing any object.

        Args:
            root: Owned output root with all object handles already held.
            expected: Complete snapshot whose identities, types, and stamps were verified.
            handles: Fresh pinned handles, with no prior file-data reads and offsets at zero.
        """
        for relative in self.probe_files(expected):
            buffer = ctypes.create_string_buffer(10)
            count = ctypes.c_uint32()
            if not self.kernel.ReadFile(handles[str(relative)], buffer, 10, ctypes.byref(count), None) \
                    or count.value != 9 or buffer.raw[:count.value] != b"generated":
                raise FileRefusal("Synthetic probe payload changed before pinned release; preserve all output.")
