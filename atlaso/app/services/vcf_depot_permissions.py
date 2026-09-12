"""Keep published VCF depot content readable without changing private tool state."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def prepare_downloaded_depot_permissions(store_path: str) -> int:
    """Add public read/traverse bits to ordinary files and directories in PROD.

    Directory-relative descriptors prevent renamed or linked entries from redirecting
    permission changes outside the published tree. Linked and special files fail
    closed instead of changing another owner's data. Windows development hosts do
    not implement the appliance's POSIX permission model.

    Args:
        store_path: Absolute configured depot store directory.

    Returns:
        Number of entries whose permissions were changed.

    Raises:
        OSError: If published content cannot be safely inspected or repaired.
        ValueError: If the configured store path is not absolute.
    """
    if os.name != "posix":
        return 0
    store = Path(store_path)
    if not store.is_absolute() or ".." in store.parts:
        raise ValueError("The depot store must be an absolute path without parent traversal.")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open("/", directory_flags)
    changed = 0
    try:
        for part in store.parts[1:]:
            next_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        try:
            prod_fd = os.open("PROD", directory_flags, dir_fd=parent_fd)
        except FileNotFoundError:
            return 0
        try:
            def walk_error(error: OSError) -> None:
                """Make unreadable subtrees fail the task instead of disappearing.

                Args:
                    error: Filesystem traversal error.
                """
                raise error

            for _root, directories, files, root_fd in os.fwalk(".", dir_fd=prod_fd, follow_symlinks=False, onerror=walk_error):
                mode = stat.S_IMODE(os.fstat(root_fd).st_mode)
                if mode | 0o555 != mode:
                    os.fchmod(root_fd, mode | 0o555)
                    changed += 1
                for name in directories + files:
                    entry = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    if stat.S_ISDIR(entry.st_mode):
                        continue
                    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                        raise OSError("Published depot content contains a link or special file; permission repair refused.")
                    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
                    try:
                        opened = os.fstat(file_fd)
                        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                            raise OSError("Published depot content changed during permission repair.")
                        mode = stat.S_IMODE(opened.st_mode)
                        if mode | 0o444 != mode:
                            os.fchmod(file_fd, mode | 0o444)
                            changed += 1
                    finally:
                        os.close(file_fd)
        finally:
            os.close(prod_fd)
    finally:
        os.close(parent_fd)
    return changed
