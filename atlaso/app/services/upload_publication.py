"""Bind browser overwrite consent to the artifact observed before transfer."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_KEY = secrets.token_bytes(32)
_LOCK = threading.RLock()
CONFLICT = "The destination changed. Select the file again and confirm any overwrite."


class PublicationConflict(ValueError):
    """Reject a destination that no longer matches the operator's consent."""


def revision(path: Path) -> tuple[int, int, int, int, int] | None:
    """Read an ordinary artifact's identity without following symlinks.

    Args:
        path: Destination whose current revision is being checked.
    """
    if any(parent.is_symlink() for parent in path.parents):
        raise OSError("Unsafe upload destination")
    try:
        value = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(value.st_mode):
        raise OSError("Upload destination is not an ordinary file")
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


@dataclass(frozen=True)
class UploadPublication:
    """Retain the exact destination revision approved before accepting bytes."""

    path: Path
    expected: tuple[int, int, int, int, int] | None

    def token(self, owner: str) -> str:
        """Authenticate an overwrite challenge for this browser and revision.

        Args:
            owner: Authenticated browser session receiving the challenge.
        """
        payload = repr((owner, str(self.path.absolute()), self.expected)).encode()
        return hmac.new(_KEY, payload, hashlib.sha256).hexdigest()

    @contextmanager
    def publish(self, staged: Path, destination: Path, *, defer_cleanup: bool = False) -> Iterator[None]:
        """Publish validated bytes and restore the old artifact on audit failure.

        Args:
            staged: Private validated file retained until publication finishes.
            destination: Actual service destination, checked against admission.
            defer_cleanup: Let the caller remove private staging links through its worker cleanup.
        """
        with _LOCK:
            if destination.absolute() != self.path.absolute() or revision(destination) != self.expected:
                raise PublicationConflict(CONFLICT)
            backup = staged.with_name(staged.name + ".previous")
            replacement = staged.with_name(staged.name + ".publish")
            try:
                if self.expected is None:
                    try:
                        os.link(staged, destination)
                    except FileExistsError as exc:
                        raise PublicationConflict(CONFLICT) from exc
                else:
                    os.link(destination, backup)
                    # Creating the backup changes ctime, so compare the linked inode
                    # and original content metadata immediately before replacement.
                    current = revision(destination)
                    if current is None or current[:4] != self.expected[:4]:
                        raise PublicationConflict(CONFLICT)
                    os.link(staged, replacement)
                    os.replace(replacement, destination)
                try:
                    yield
                except BaseException:
                    if destination.exists() and os.path.samefile(staged, destination):
                        if self.expected is None:
                            destination.unlink()
                        else:
                            os.replace(backup, destination)
                    raise
            finally:
                if not defer_cleanup:
                    backup.unlink(missing_ok=True)
                    replacement.unlink(missing_ok=True)
