"""Stream manually supplied OVAs into the canonical VCFDT component directory."""

from __future__ import annotations

import os
import re
import tarfile
import tempfile
from collections.abc import AsyncIterable
from pathlib import Path

from anyio import to_thread

from atlaso.app.services.vcf_sddc_deployment import (
    MANIFEST_LINE,
    SDDC_MANAGER_OVA_ROOT,
    VcfSddcDeploymentError,
    inspect_ova,
    validate_ova_manifest,
)

SDDC_OVA_MAX_BYTES = 16 * 1024**3


class SddcUploadError(ValueError):
    """Report a reviewed upload failure without exposing filesystem exceptions."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def _validate_staged_ova(path: Path) -> None:
    """Validate descriptor and manifest before publication, off the event loop."""
    try:
        descriptor = inspect_ova(path, root=path.parent)
        with tarfile.open(path, "r") as archive:
            manifest = archive.extractfile(descriptor.manifest_member)
            if manifest is None:
                raise ValueError("Missing manifest")
            content = manifest.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise ValueError("Oversized manifest")
            covered = {
                match.group(2) for line in content.decode("utf-8").splitlines()
                if (match := MANIFEST_LINE.fullmatch(line.strip()))
            }
            if not {descriptor.ovf_member, *(str(item["href"]) for item in descriptor.files)} <= covered:
                raise ValueError("Incomplete manifest")
        validate_ova_manifest(descriptor)
    except (VcfSddcDeploymentError, OSError, tarfile.TarError, ValueError, KeyError) as exc:
        raise SddcUploadError(
            "OVA validation failed. Choose the original complete SDDC Manager OVA with its OVF, disks, and valid manifest."
        ) from exc


async def store_sddc_ova_upload(
    chunks: AsyncIterable[bytes],
    filename: str,
    *,
    root: Path = SDDC_MANAGER_OVA_ROOT,
    max_bytes: int = SDDC_OVA_MAX_BYTES,
) -> dict[str, str | int]:
    """Publish a validated stream without replacing any existing depot artifact.

    Staging is a private sibling directory outside deployment discovery. A unique
    staging path isolates concurrent requests, and hard-link publication provides
    atomic create-if-absent semantics even if another upload wins the race.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,195}\.ova", filename, re.IGNORECASE):
        raise SddcUploadError("Choose a .ova filename using only letters, numbers, dots, hyphens, and underscores.")
    destination = root / filename
    try:
        if not root.is_absolute() or any(part.is_symlink() for part in (root, *root.parents)):
            raise SddcUploadError("The SDDC Manager depot path is unavailable. Ask an administrator to check its storage.")
        root.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(destination):
            raise SddcUploadError("An OVA with this filename already exists. Existing depot files are never replaced.", 409)
        # Keeping staging on the depot volume avoids root-volume multipart spooling.
        with tempfile.TemporaryDirectory(prefix=".sddc-upload-", dir=root.parent) as staging:
            staged = Path(staging) / filename
            total = 0
            with staged.open("xb") as target:
                async for chunk in chunks:
                    total += len(chunk)
                    if total > max_bytes:
                        raise SddcUploadError("The OVA exceeds the 16 GiB upload limit.", 413)
                    target.write(chunk)
                if not total:
                    raise SddcUploadError("The OVA upload is empty. Choose a complete OVA file.")
                target.flush()
                os.fsync(target.fileno())
            await to_thread.run_sync(_validate_staged_ova, staged)
            staged.chmod(0o644)
            try:
                os.link(staged, destination)
            except FileExistsError as exc:
                raise SddcUploadError("An OVA with this filename already exists. Existing depot files are never replaced.", 409) from exc
        return {"path": str(destination), "relative_path": filename, "filename": filename, "size_bytes": total}
    except OSError as exc:
        raise SddcUploadError("OVA upload could not be stored. Check depot free space and write access, then retry.", 503) from exc
