#!/usr/bin/env python3
"""Establish the trusted Photon 5 updates repository before package refresh."""

from __future__ import annotations

import argparse
import configparser
import os
import stat
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, ContextManager

REPOSITORY_SECTION = "photon-updates"
CANONICAL_BASEURL = (
    "https://packages.broadcom.com/photon/$releasever/"
    "photon_updates_$releasever_$basearch"
)
CANONICAL_METADATA_URL = (
    "https://packages.broadcom.com/photon/5.0/"
    "photon_updates_5.0_x86_64/repodata/repomd.xml"
)
CANONICAL_GPG_KEY_URI = "file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY-4096"
LEGACY_GPG_KEY_URIS = (
    "file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY "
    "file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY-4096"
)
DEFAULT_REPOSITORY_PATH = Path("/etc/yum.repos.d/photon-updates.repo")
DEFAULT_GPG_KEY_PATH = Path("/etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY-4096")
PROBE_TIMEOUT_SECONDS = 30
MAX_METADATA_BYTES = 2 * 1024 * 1024
TRUSTED_EXISTING_BASEURLS = {
    CANONICAL_BASEURL,
    (
        "https://packages-prod.broadcom.com/photon/$releasever/"
        "photon_updates_$releasever_$basearch"
    ),
    (
        "https://packages.vmware.com/photon/$releasever/"
        "photon_updates_$releasever_$basearch"
    ),
    (
        "https://packages.vmware.com/photon/updates/$releasever/"
        "photon_updates_$releasever_$basearch"
    ),
}


class PhotonRepositoryError(RuntimeError):
    """Raised when the Photon repository trust boundary cannot be proven."""


def _require_regular_trusted_file(path: Path, description: str) -> os.stat_result:
    """Return metadata for a safe existing repository trust file.

    Args:
        path: File whose type, ownership, and permissions must be checked.
        description: Stable description used in a sanitized failure message.

    Returns:
        The file's lstat result.

    Raises:
        PhotonRepositoryError: The file is absent, linked, or writable by an
            untrusted local account.
    """

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PhotonRepositoryError(f"{description} is unavailable: {path}") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise PhotonRepositoryError(f"{description} must be a regular file: {path}")
    if os.name == "posix":
        get_effective_uid = getattr(os, "get" + "euid")
        if metadata.st_uid != get_effective_uid():
            raise PhotonRepositoryError(
                f"{description} must be owned by the provisioning account: {path}"
            )
        if metadata.st_mode & 0o022:
            raise PhotonRepositoryError(
                f"{description} must not be writable by group or other: {path}"
            )
    return metadata


def _read_repository(repository_path: Path) -> configparser.ConfigParser:
    """Read and parse the stock Photon updates repository.

    Args:
        repository_path: Repository file to parse.

    Returns:
        The parsed configuration.

    Raises:
        PhotonRepositoryError: The file is not valid UTF-8 INI data.
    """

    try:
        source = repository_path.read_text(encoding="utf-8")
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(source)
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise PhotonRepositoryError(
            f"Photon updates repository is invalid: {repository_path}"
        ) from exc
    return parser


def _validate_repository(parser: configparser.ConfigParser, gpg_key_path: Path) -> None:
    """Validate the existing Photon updates repository trust settings.

    Args:
        parser: Parsed Photon repository configuration.
        gpg_key_path: Expected installed Photon RPM signing key.

    Raises:
        PhotonRepositoryError: The repository is not the trusted stock Photon
            updates definition.
    """

    if parser.sections() != [REPOSITORY_SECTION]:
        raise PhotonRepositoryError(
            "Photon updates repository must contain only [photon-updates]."
        )
    section = parser[REPOSITORY_SECTION]
    baseurl = section.get("baseurl", "").strip()
    if baseurl not in TRUSTED_EXISTING_BASEURLS:
        raise PhotonRepositoryError(
            "Photon updates repository base URL is not an approved Photon 5 layout."
        )
    if section.get("enabled", "").strip() != "1":
        raise PhotonRepositoryError("Photon updates repository must be enabled.")
    if section.get("gpgcheck", "").strip() != "1":
        raise PhotonRepositoryError(
            "Photon updates repository must enforce GPG checks."
        )
    if section.get("gpgkey", "").strip() not in {
        CANONICAL_GPG_KEY_URI,
        LEGACY_GPG_KEY_URIS,
    }:
        raise PhotonRepositoryError(
            "Photon updates repository must use the approved 4096-bit RPM signing key."
        )
    _require_regular_trusted_file(gpg_key_path, "Photon RPM signing key")


def _canonical_repository_text() -> str:
    """Return the canonical upstream Photon updates repository text.

    Returns:
        Canonical repository configuration with signed packages enabled.
    """

    return (
        f"[{REPOSITORY_SECTION}]\n"
        "name=VMware Photon Linux $releasever ($basearch) Updates\n"
        f"baseurl={CANONICAL_BASEURL}\n"
        f"gpgkey={CANONICAL_GPG_KEY_URI}\n"
        "gpgcheck=1\n"
        "enabled=1\n"
        "skip_if_unavailable=1\n"
    )


def _write_repository_atomic(
    repository_path: Path, source: str, metadata: os.stat_result
) -> bool:
    """Atomically replace a noncanonical repository file.

    Args:
        repository_path: Exact repository path to replace.
        source: Canonical UTF-8 repository text.
        metadata: Original file metadata whose mode and ownership are retained.

    Returns:
        ``True`` when the file changed, otherwise ``False``.
    """

    if repository_path.read_text(encoding="utf-8") == source:
        return False
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{repository_path.name}.", dir=repository_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(source)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, stat.S_IMODE(metadata.st_mode))
        if os.name == "posix":
            change_owner = getattr(os, "ch" + "own")
            change_owner(temporary_path, metadata.st_uid, metadata.st_gid)
        os.replace(temporary_path, repository_path)
        if os.name == "posix":
            directory_descriptor = os.open(repository_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        temporary_path.unlink(missing_ok=True)
    return True


def probe_repository_metadata(
    opener: Callable[..., ContextManager[Any]] = urllib.request.urlopen,
) -> None:
    """Require bounded valid metadata from the canonical Photon repository.

    Args:
        opener: HTTPS opener, injectable for focused tests.

    Raises:
        PhotonRepositoryError: The canonical endpoint is unreachable, redirects
            elsewhere, is oversized, or does not contain repository metadata.
    """

    request = urllib.request.Request(
        CANONICAL_METADATA_URL,
        headers={"User-Agent": "Atlaso-Photon-Image-Builder/1"},
    )
    try:
        with opener(request, timeout=PROBE_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            effective_url = response.geturl()
            payload = response.read(MAX_METADATA_BYTES + 1)
    except Exception as exc:
        raise PhotonRepositoryError(
            "Canonical Photon 5 updates metadata is unreachable."
        ) from exc
    if status != 200 or effective_url != CANONICAL_METADATA_URL:
        raise PhotonRepositoryError(
            "Canonical Photon 5 updates metadata did not return the approved endpoint."
        )
    if len(payload) > MAX_METADATA_BYTES:
        raise PhotonRepositoryError(
            "Photon repository metadata exceeds the safety limit."
        )
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise PhotonRepositoryError("Photon repository metadata is malformed.") from exc
    if root.tag.rsplit("}", 1)[-1] != "repomd":
        raise PhotonRepositoryError(
            "Photon repository metadata has an unexpected root."
        )


def configure_photon_updates_repository(
    repository_path: Path = DEFAULT_REPOSITORY_PATH,
    gpg_key_path: Path = DEFAULT_GPG_KEY_PATH,
    opener: Callable[..., ContextManager[Any]] = urllib.request.urlopen,
) -> bool:
    """Validate, probe, and canonicalize the Photon updates repository.

    Args:
        repository_path: Stock Photon updates repository file.
        gpg_key_path: Installed Photon 4096-bit RPM signing key.
        opener: HTTPS opener, injectable for focused tests.

    Returns:
        ``True`` when the repository file changed, otherwise ``False``.
    """

    metadata = _require_regular_trusted_file(
        repository_path, "Photon updates repository"
    )
    parser = _read_repository(repository_path)
    _validate_repository(parser, gpg_key_path)
    probe_repository_metadata(opener)
    canonical = _canonical_repository_text()
    return _write_repository_atomic(repository_path, canonical, metadata)


def main() -> int:
    """Configure the image-build Photon repository and report bounded status."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=DEFAULT_REPOSITORY_PATH)
    parser.add_argument("--gpg-key", type=Path, default=DEFAULT_GPG_KEY_PATH)
    args = parser.parse_args()
    try:
        changed = configure_photon_updates_repository(args.repository, args.gpg_key)
    except PhotonRepositoryError as exc:
        parser.exit(2, f"Photon repository preparation failed: {exc}\n")
    state = "updated" if changed else "already current"
    print(
        f"Photon 5 updates repository is {state} and reachable with GPG checks enabled."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
