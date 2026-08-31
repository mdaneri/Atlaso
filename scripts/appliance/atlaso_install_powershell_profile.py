#!/usr/bin/env python3
"""Install Atlaso's global PowerShell profile into a reviewed package layout."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import uuid
from collections.abc import Collection
from pathlib import Path

SUPPORTED_POWERSHELL_BINARIES = frozenset(
    {
        Path("/usr/share/powershell/pwsh"),
        Path("/opt/microsoft/powershell/7/pwsh"),
    }
)


class ProfileInstallError(RuntimeError):
    """Report a bounded, non-secret profile installation failure."""


def _require_safe_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    """Require one root-owned directory without group or other write access.

    Args:
        path: Directory whose link, type, ownership, and mode are checked.
        expected_uid: Required numeric owner.
        expected_gid: Required numeric group.
    """

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProfileInstallError(
            f"PowerShell profile directory is unavailable: {path}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ProfileInstallError(
            f"PowerShell profile directory must be a canonical directory: {path}"
        )
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise ProfileInstallError(
            f"PowerShell profile directory must be owned by root: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ProfileInstallError(
            f"PowerShell profile directory must not be writable by group or other: {path}"
        )


def resolve_profile_root(
    pwsh_path: Path,
    *,
    supported_binaries: Collection[Path] = SUPPORTED_POWERSHELL_BINARIES,
    trusted_ancestor: Path = Path("/"),
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> Path:
    """Resolve and validate one supported PowerShell global-profile root.

    Args:
        pwsh_path: PowerShell command path selected by the package manager.
        supported_binaries: Canonical executable identities admitted by policy.
        trusted_ancestor: Highest directory checked for safe ancestry.
        expected_uid: Required numeric owner for the directory chain.
        expected_gid: Required numeric group for the directory chain.
    """

    try:
        resolved_binary = pwsh_path.resolve(strict=True)
    except OSError as exc:
        raise ProfileInstallError(
            f"PowerShell executable cannot be resolved safely: {pwsh_path}"
        ) from exc
    try:
        binary_metadata = resolved_binary.lstat()
    except OSError as exc:
        raise ProfileInstallError(
            f"PowerShell executable cannot be inspected safely: {resolved_binary}"
        ) from exc
    if not stat.S_ISREG(binary_metadata.st_mode):
        raise ProfileInstallError(
            f"PowerShell executable is not a regular file: {resolved_binary}"
        )
    if (
        binary_metadata.st_uid != expected_uid
        or binary_metadata.st_gid != expected_gid
        or stat.S_IMODE(binary_metadata.st_mode) & 0o022
        or not stat.S_IMODE(binary_metadata.st_mode) & 0o111
    ):
        raise ProfileInstallError(
            "PowerShell executable must be root-owned, executable, and non-writable "
            f"by group or other: {resolved_binary}"
        )
    # The allowlist names canonical filesystem identities, not paths whose
    # current symlink targets should be trusted implicitly.
    admitted = set(supported_binaries)
    if resolved_binary not in admitted:
        raise ProfileInstallError(
            "PowerShell resolved to an unsupported global profile directory: "
            f"{resolved_binary.parent}"
        )

    try:
        canonical_ancestor = trusted_ancestor.resolve(strict=True)
        relative_root = resolved_binary.parent.relative_to(canonical_ancestor)
    except (OSError, ValueError) as exc:
        raise ProfileInstallError(
            f"PowerShell profile directory escapes its trusted filesystem boundary: {resolved_binary.parent}"
        ) from exc

    current = canonical_ancestor
    _require_safe_directory(
        current, expected_uid=expected_uid, expected_gid=expected_gid
    )
    for component in relative_root.parts:
        current /= component
        _require_safe_directory(
            current, expected_uid=expected_uid, expected_gid=expected_gid
        )
    if current != resolved_binary.parent:
        raise ProfileInstallError(
            f"PowerShell profile directory is not canonical: {resolved_binary.parent}"
        )
    return current


def _validate_optional_profile_root(
    profile_root: Path,
    *,
    trusted_ancestor: Path,
    expected_uid: int,
    expected_gid: int,
) -> bool:
    """Validate an inactive supported root when its directory still exists.

    Args:
        profile_root: Inactive supported PowerShell package directory.
        trusted_ancestor: Highest directory checked for safe ancestry.
        expected_uid: Required numeric owner for the directory chain.
        expected_gid: Required numeric group for the directory chain.

    Returns:
        ``True`` when the complete canonical directory exists, otherwise ``False``.
    """

    try:
        canonical_ancestor = trusted_ancestor.resolve(strict=True)
        relative_root = profile_root.relative_to(canonical_ancestor)
    except (OSError, ValueError) as exc:
        raise ProfileInstallError(
            f"Inactive PowerShell profile directory escapes its trusted filesystem boundary: {profile_root}"
        ) from exc
    if any(component in {".", ".."} for component in relative_root.parts):
        raise ProfileInstallError(
            f"Inactive PowerShell profile directory escapes its trusted filesystem boundary: {profile_root}"
        )

    current = canonical_ancestor
    _require_safe_directory(
        current, expected_uid=expected_uid, expected_gid=expected_gid
    )
    for component in relative_root.parts:
        current /= component
        try:
            current.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ProfileInstallError(
                f"Inactive PowerShell profile directory is unavailable: {current}"
            ) from exc
        _require_safe_directory(
            current, expected_uid=expected_uid, expected_gid=expected_gid
        )
    if current != profile_root:
        raise ProfileInstallError(
            f"Inactive PowerShell profile directory is not canonical: {profile_root}"
        )
    return True


def _remove_inactive_profiles(
    active_root: Path,
    source_bytes: bytes,
    *,
    supported_binaries: Collection[Path],
    trusted_ancestor: Path,
    expected_uid: int,
    expected_gid: int,
) -> None:
    """Remove only exact Atlaso profiles from inactive reviewed layouts.

    Args:
        active_root: Canonical directory selected by the installed runtime.
        source_bytes: Exact Atlaso global-profile content.
        supported_binaries: Canonical executable identities admitted by policy.
        trusted_ancestor: Highest directory checked for safe ancestry.
        expected_uid: Required numeric owner for removable content.
        expected_gid: Required numeric group for removable content.
    """

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    verify_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
        verify_flags |= os.O_NOFOLLOW

    for supported_binary in sorted(set(supported_binaries), key=str):
        inactive_root = supported_binary.parent
        if inactive_root == active_root:
            continue
        if not _validate_optional_profile_root(
            inactive_root,
            trusted_ancestor=trusted_ancestor,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        ):
            continue

        directory_fd = os.open(inactive_root, directory_flags)
        try:
            try:
                profile_fd = os.open("profile.ps1", verify_flags, dir_fd=directory_fd)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ProfileInstallError(
                    f"Inactive PowerShell global profile is not Atlaso-owned: {inactive_root / 'profile.ps1'}"
                ) from exc
            try:
                metadata = os.fstat(profile_fd)
                content = os.read(profile_fd, len(source_bytes) + 1)
            finally:
                os.close(profile_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or content != source_bytes
            ):
                raise ProfileInstallError(
                    f"Inactive PowerShell global profile is not Atlaso-owned: {inactive_root / 'profile.ps1'}"
                )
            os.unlink("profile.ps1", dir_fd=directory_fd)
            os.fsync(directory_fd)
        except ProfileInstallError:
            raise
        except OSError as exc:
            raise ProfileInstallError(
                f"Inactive PowerShell global profile removal failed safely: {inactive_root / 'profile.ps1'}"
            ) from exc
        finally:
            os.close(directory_fd)


def install_global_profile(
    pwsh_path: Path,
    profile_source: Path,
    *,
    supported_binaries: Collection[Path] = SUPPORTED_POWERSHELL_BINARIES,
    trusted_ancestor: Path = Path("/"),
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> Path:
    """Atomically install and verify Atlaso's system-wide PowerShell profile.

    Args:
        pwsh_path: PowerShell command path selected by the package manager.
        profile_source: Canonical Atlaso profile source.
        supported_binaries: Canonical executable identities admitted by policy.
        trusted_ancestor: Highest directory checked for safe ancestry.
        expected_uid: Required numeric owner for installed content.
        expected_gid: Required numeric group for installed content.
    """

    profile_root = resolve_profile_root(
        pwsh_path,
        supported_binaries=supported_binaries,
        trusted_ancestor=trusted_ancestor,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        source_metadata = profile_source.lstat()
        source_bytes = profile_source.read_bytes()
    except OSError as exc:
        raise ProfileInstallError(
            f"Atlaso PowerShell profile source is unavailable: {profile_source}"
        ) from exc
    if (
        stat.S_ISLNK(source_metadata.st_mode)
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_uid != expected_uid
        or source_metadata.st_gid != expected_gid
        or stat.S_IMODE(source_metadata.st_mode) & 0o022
    ):
        raise ProfileInstallError(
            f"Atlaso PowerShell profile source has unsafe ownership or permissions: {profile_source}"
        )

    target_name = "profile.ps1"
    target_path = profile_root / target_name
    try:
        target_metadata = target_path.lstat()
    except FileNotFoundError:
        target_metadata = None
    except OSError as exc:
        raise ProfileInstallError(
            f"PowerShell global profile path cannot be inspected safely: {target_path}"
        ) from exc
    if target_metadata is not None and (
        stat.S_ISLNK(target_metadata.st_mode)
        or not stat.S_ISREG(target_metadata.st_mode)
    ):
        raise ProfileInstallError(
            f"PowerShell global profile path must be a regular file or absent: {target_path}"
        )

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(profile_root, directory_flags)
    temporary_name = f".atlaso-profile-{uuid.uuid4().hex}.tmp"
    temporary_fd: int | None = None
    try:
        temporary_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            temporary_flags |= os.O_NOFOLLOW
        temporary_fd = os.open(
            temporary_name,
            temporary_flags,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(temporary_fd, "wb", closefd=False) as handle:
            handle.write(source_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        fchown = getattr(os, "fchown", None)
        if fchown is None:
            raise ProfileInstallError(
                "PowerShell global profile installation requires POSIX ownership controls"
            )
        fchown(temporary_fd, expected_uid, expected_gid)
        os.fchmod(temporary_fd, 0o644)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        os.replace(
            temporary_name,
            target_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)

        verify_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            verify_flags |= os.O_NOFOLLOW
        verify_fd = os.open(target_name, verify_flags, dir_fd=directory_fd)
        try:
            installed_metadata = os.fstat(verify_fd)
            installed_bytes = os.read(verify_fd, len(source_bytes) + 1)
        finally:
            os.close(verify_fd)
        if (
            not stat.S_ISREG(installed_metadata.st_mode)
            or installed_metadata.st_uid != expected_uid
            or installed_metadata.st_gid != expected_gid
            or stat.S_IMODE(installed_metadata.st_mode) != 0o644
            or installed_bytes != source_bytes
        ):
            raise ProfileInstallError(
                f"PowerShell global profile verification failed: {target_path}"
            )
    except ProfileInstallError:
        raise
    except OSError as exc:
        raise ProfileInstallError(
            f"PowerShell global profile installation failed safely: {target_path}"
        ) from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)
    _remove_inactive_profiles(
        profile_root,
        source_bytes,
        supported_binaries=supported_binaries,
        trusted_ancestor=trusted_ancestor,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    return target_path


def main() -> int:
    """Install the canonical Atlaso PowerShell profile."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--pwsh-path", required=True, type=Path)
    parser.add_argument("--profile-source", required=True, type=Path)
    args = parser.parse_args()
    try:
        install_global_profile(args.pwsh_path, args.profile_source)
    except ProfileInstallError:
        # Command-line paths are operator-controlled and may disclose host or
        # staging identities. Keep detailed diagnostics inside the typed
        # exception for trusted callers, but emit only a bounded CLI failure.
        print("Atlaso PowerShell profile installation failed safely", file=sys.stderr)
        return 2
    # The resolved destination derives from operator-controlled command paths.
    # Successful installation is enough for this public CLI boundary; trusted
    # callers retain the exact returned path from install_global_profile().
    print("Installed Atlaso PowerShell global profile")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
