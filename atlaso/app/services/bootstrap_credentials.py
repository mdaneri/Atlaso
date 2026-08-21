"""Verify and persist the bootstrap administrator web credential."""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

BOOTSTRAP_ADMIN_PASSWORD_VERIFIER_PATH = Path(
    "/etc/atlaso/bootstrap-admin-password.hash"
)
BOOTSTRAP_ADMIN_PASSWORD_HASHER = PasswordHasher()
BOOTSTRAP_ADMIN_PASSWORD_VERIFIER_MAX_BYTES = 4096
ATLASO_SERVICE_USER = "atlaso"


def bootstrap_admin_password_matches(
    password: str,
    configured_password: str,
    *,
    verifier_path: Path | None = None,
) -> bool:
    """Return whether a supplied bootstrap password matches the active verifier.

    Args:
        password: Password supplied for the immediate authenticated operation.
        configured_password: Image-configured password used before a verifier exists.
        verifier_path: Optional verifier path override used by focused tests.
    """
    path = verifier_path or BOOTSTRAP_ADMIN_PASSWORD_VERIFIER_PATH
    if path.is_symlink():
        return False
    if not path.exists():
        return secrets.compare_digest(password, configured_password)
    try:
        if not path.is_file() or path.resolve() != path:
            return False
        if path.stat().st_size > BOOTSTRAP_ADMIN_PASSWORD_VERIFIER_MAX_BYTES:
            return False
        verifier = path.read_text(encoding="utf-8").strip()
        if not verifier:
            return False
        return bool(BOOTSTRAP_ADMIN_PASSWORD_HASHER.verify(verifier, password))
    except (
        InvalidHashError,
        OSError,
        UnicodeError,
        VerificationError,
        VerifyMismatchError,
    ):
        return False


def write_bootstrap_admin_password_verifier(
    password: str,
    *,
    verifier_path: Path | None = None,
) -> None:
    """Atomically persist a root-owned Argon2 bootstrap-password verifier.

    Args:
        password: New bootstrap administrator password to hash and persist.
        verifier_path: Optional verifier path override used by focused tests.
    """
    path = verifier_path or BOOTSTRAP_ADMIN_PASSWORD_VERIFIER_PATH
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.resolve() != path)):
        raise ValueError("Bootstrap administrator password verifier path is unsafe.")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(BOOTSTRAP_ADMIN_PASSWORD_HASHER.hash(password))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o640)
        if os.name == "posix":
            shutil.chown(temporary, user="root", group=ATLASO_SERVICE_USER)
        os.replace(temporary, path)
        if os.name == "posix":
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
