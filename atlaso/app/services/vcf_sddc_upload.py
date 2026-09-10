"""Stream manually supplied OVAs into the canonical VCFDT component directory."""

from __future__ import annotations

import io
import logging
import os
import re
import tarfile
import tempfile
from collections.abc import AsyncIterable, Callable
from pathlib import Path
from typing import BinaryIO

from anyio import CancelScope, to_thread

from atlaso.app.services.upload_publication import (
    PublicationConflict,
    UploadPublication,
)
from atlaso.app.services.vcf_sddc_deployment import (
    MANIFEST_LINE,
    SDDC_MANAGER_OVA_ROOT,
    VcfSddcDeploymentError,
    inspect_ova,
    validate_ova_manifest,
)

logger = logging.getLogger(__name__)

SDDC_OVA_MAX_BYTES = 16 * 1024**3
OVA_MAX_MEMBERS = 4096
OVA_MAX_OVF_BYTES = 4 * 1024**2
OVA_MAX_METADATA_BYTES = 8 * 1024**2


class _MetadataReader(io.BufferedReader):
    """Bound tar header and extension allocations before parsing an archive."""

    remaining = OVA_MAX_METADATA_BYTES

    def read(self, size: int | None = -1) -> bytes:
        """Reject oversized metadata reads before allocating their buffers.

        Args:
            size: Requested tar metadata read length.
        """
        if size is None or size < 0 or size > self.remaining:
            raise ValueError("OVA metadata limit exceeded")
        data = super().read(size)
        self.remaining -= len(data)
        return data


def _check_ova_structure(path: Path) -> None:
    """Bound member count, extended headers and descriptors before discovery.

    Args:
        path: Private uncompressed OVA awaiting deployment-parser inspection.
    """
    with _MetadataReader(io.FileIO(path, "r")) as source:
        with tarfile.open(fileobj=source, mode="r:") as archive:
            logical_bytes = 0
            for count, member in enumerate(archive, 1):
                if member.size < 0 or member.size > SDDC_OVA_MAX_BYTES:
                    raise ValueError("OVA member size limit exceeded")
                logical_bytes += member.size
                if logical_bytes > SDDC_OVA_MAX_BYTES:
                    raise ValueError("OVA logical size limit exceeded")
                if count > OVA_MAX_MEMBERS:
                    raise ValueError("OVA member limit exceeded")
                if member.name.lower().endswith(".ovf") and member.size > OVA_MAX_OVF_BYTES:
                    raise ValueError("OVA descriptor limit exceeded")
                if member.name.lower().endswith(".mf") and member.size > 1024**2:
                    raise ValueError("OVA manifest limit exceeded")


def _flush_staged_file(target: BinaryIO) -> None:
    """Flush validated input to disk from a worker thread.

    Args:
        target: Open private staging file.
    """
    target.flush()
    os.fsync(target.fileno())

UPLOAD_ERROR_MESSAGES = {
    'invalid_filename': 'Choose a .ova filename using only letters, numbers, dots, hyphens, and underscores.',
    'storage_path': 'The SDDC Manager depot path is unavailable. Ask an administrator to check its storage.',
    'duplicate': 'An OVA with this filename already exists. Confirm overwrite in the upload dialog.',
    'oversized': 'The OVA exceeds the 16 GiB upload limit.',
    'empty': 'The OVA upload is empty. Choose a complete OVA file.',
    'invalid_ova': 'OVA validation failed. Choose the original complete SDDC Manager OVA with its OVF, disks, and valid manifest.',
    'storage_error': 'OVA upload could not be stored. Check depot free space and write access, then retry.',
    'audit_error': 'OVA upload could not be audited and was rolled back. Retry after database recovery.',
}



class SddcUploadError(ValueError):
    """Report a reviewed upload failure without exposing filesystem exceptions."""

    def __init__(self, code: str, status_code: int = 400) -> None:
        """  init  .

        Args:
            code: Fixed public error-message selector.
            status_code: HTTP status for the reviewed failure.
        """
        super().__init__(UPLOAD_ERROR_MESSAGES.get(code, UPLOAD_ERROR_MESSAGES["storage_error"]))
        self.code = code
        self.status_code = status_code


def validate_ova_filename(filename: str) -> None:
    """Reject unsupported names consistently before admission and storage.

    Args:
        filename: Original OVA basename supplied by the caller.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,195}\.ova", filename, re.IGNORECASE):
        raise SddcUploadError("invalid_filename")


def _validate_staged_ova(path: Path) -> None:
    """Validate descriptor and manifest before publication, off the event loop.

    Args:
        path: Private staged OVA to validate.
    """
    try:
        _check_ova_structure(path)
        descriptor = inspect_ova(path, root=path.parent)
        with tarfile.open(path, "r") as archive:
            manifest = archive.extractfile(descriptor.manifest_member)
            if manifest is None:
                raise ValueError("Missing manifest")
            content = manifest.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise ValueError("Oversized manifest")
            covered: set[str] = set()
            hashing_bytes = 0
            for line in content.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                match = MANIFEST_LINE.fullmatch(line.strip())
                if match is None:
                    raise ValueError("Unsupported manifest entry")
                member = archive.getmember(match.group(2))
                if not member.isfile() or member.name in covered:
                    raise ValueError("Duplicate or non-file manifest entry")
                covered.add(member.name)
                hashing_bytes += member.size
                if len(covered) > OVA_MAX_MEMBERS or hashing_bytes > SDDC_OVA_MAX_BYTES:
                    raise ValueError("OVA manifest work limit exceeded")
            if not {descriptor.ovf_member, *(str(item["href"]) for item in descriptor.files)} <= covered:
                raise ValueError("Incomplete manifest")
        validate_ova_manifest(descriptor)
    except (VcfSddcDeploymentError, OSError, tarfile.TarError, ValueError, KeyError, RecursionError) as exc:
        raise SddcUploadError(
            "invalid_ova"
        ) from exc


async def store_sddc_ova_upload(
    chunks: AsyncIterable[bytes],
    filename: str,
    *,
    root: Path = SDDC_MANAGER_OVA_ROOT,
    max_bytes: int = SDDC_OVA_MAX_BYTES,
    on_publish: Callable[[dict[str, str | int]], None] | None = None,
    publication: UploadPublication | None = None,
) -> dict[str, str | int]:
    """Publish a validated stream, replacing artifacts only with bound consent.

    Staging is a private sibling directory outside deployment discovery. A unique
    staging path isolates concurrent requests, and hard-link publication provides
    atomic create-if-absent semantics even if another upload wins the race.

    Args:
        chunks: Incoming bounded byte stream.
        filename: Original basename validated before publication.
        root: Canonical artifact directory on the depot volume.
        max_bytes: Maximum accepted file size in bytes.
        on_publish: Audit callback; failure removes only this upload's published hard link.
        publication: Browser consent bound to the destination's pre-upload revision.
    """
    validate_ova_filename(filename)
    destination = root / filename
    try:
        if not root.is_absolute() or any(part.is_symlink() for part in (root, *root.parents)):
            raise SddcUploadError("storage_path")
        root.mkdir(parents=True, exist_ok=True)
        if publication is None and os.path.lexists(destination):
            raise SddcUploadError("duplicate", 409)
        # Keeping staging on the depot volume avoids root-volume multipart spooling.
        staging = tempfile.TemporaryDirectory(prefix=".sddc-upload-", dir=root.parent)
        published = False
        try:
            staged = Path(staging.name) / filename
            total = 0
            target = await to_thread.run_sync(staged.open, "xb")
            try:
                async for chunk in chunks:
                    total += len(chunk)
                    if total > max_bytes:
                        raise SddcUploadError("oversized", 413)
                    await to_thread.run_sync(target.write, chunk)
                if not total:
                    raise SddcUploadError("empty")
                await to_thread.run_sync(_flush_staged_file, target)
            finally:
                with CancelScope(shield=True):
                    await to_thread.run_sync(target.close)
            await to_thread.run_sync(_validate_staged_ova, staged)
            staged.chmod(0o644)
            result: dict[str, str | int] = {
                "path": str(destination), "relative_path": filename, "filename": filename, "size_bytes": total,
            }
            with (publication or UploadPublication(destination, None)).publish(staged, destination):
                if on_publish is not None:
                    try:
                        on_publish(result)
                    except Exception as exc:
                        raise SddcUploadError("audit_error", 503) from exc
            published = True
        finally:
            with CancelScope(shield=True):
                try:
                    await to_thread.run_sync(staging.cleanup)
                except OSError:
                    if not published:
                        raise
                    logger.warning("Published OVA staging cleanup could not be completed.")
        return result
    except PublicationConflict as exc:
        raise SddcUploadError("duplicate", 409) from exc
    except OSError as exc:
        raise SddcUploadError("storage_error", 503) from exc
