"""Desired storage for the SFTP receiver and VCF Offline Depot."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    EsxNfsShare,
    EsxStorageVolume,
    VcfBackupSettings,
    VcfOfflineDepotSettings,
)
from atlaso.app.services.esx_storage import reserved_mount_owner
from atlaso.app.services.network_objects import acquire_network_objects_write_lock

Role = Literal["backup", "depot"]
DEFAULT_PATHS = {"backup": "/mnt/atlaso-vcf-backups", "depot": "/mnt/atlaso-vcf-offline-depot"}
VOLUME_DIRECTORIES = {"backup": "vcf-backups", "depot": "vcf-offline-depot"}
STORAGE_COMMENT = "# Atlaso VCF storage: "
_SYSTEM_ROOTS = frozenset("bin boot dev etc home lib lib64 opt proc root run sbin sys tmp usr var".split())
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def _row(db: Session, role: Role) -> VcfBackupSettings | VcfOfflineDepotSettings | None:
    """Select the singleton for one service.

    Args:
        db: Active database session.
        role: Service that owns the assignment.
    """
    if role == "backup":
        return db.scalars(select(VcfBackupSettings)).one_or_none()
    return db.scalars(select(VcfOfflineDepotSettings)).one_or_none()


def _eligible_volumes(db: Session) -> list[EsxStorageVolume]:
    """Find registered disks with one usable mount and filesystem identity.

    Args:
        db: Active database session containing applied volume registrations.
    """
    volumes = db.scalars(select(EsxStorageVolume).where(
        EsxStorageVolume.applied.is_(True), EsxStorageVolume.state == "mounted",
    ).order_by(EsxStorageVolume.name)).all()
    uuid_counts = Counter(volume.filesystem_uuid for volume in volumes)
    return [
        volume for volume in volumes
        if _UUID.fullmatch(volume.filesystem_uuid)
        and uuid_counts[volume.filesystem_uuid] == 1
        and _data_volume_path(volume.mount_path)
        and volume.stable_device_id.startswith("/dev/disk/by-id/")
        and not reserved_mount_owner(volume.mount_path)
    ]


def _storage_path_syntax(value: str) -> bool:
    """Check absolute storage path components in a single pass.

    Args:
        value: Submitted or registered Linux path.
    """
    return value.startswith("/") and all(
        part and part[0] not in ".-" and part.isascii()
        and all(char.isalnum() or char in "_.-" for char in part)
        for part in value[1:].split("/")
    )


def _data_volume_path(value: str) -> bool:
    """Check whether a registered volume is outside protected system mounts.

    Args:
        value: Registered volume's absolute mount path.
    """
    if not _storage_path_syntax(value):
        return False
    path = PurePosixPath(value)
    return (
        (path.parts[1] not in _SYSTEM_ROOTS or path.is_relative_to("/var/srv"))
        and not path.is_relative_to("/srv/atlaso")
        and not path.is_relative_to("/var/srv/atlaso")
    )


def storage_options(db: Session, role: Role) -> list[dict[str, str]]:
    """List applied ext4 registrations with stable identities and safe mount paths.

    Args:
        db: Active database session.
        role: Service whose directory name is appended to each volume.
    """
    return [
        {
            "uuid": volume.filesystem_uuid, "name": volume.name, "mount_path": volume.mount_path,
            "storage_path": f"{volume.mount_path}/{VOLUME_DIRECTORIES[role]}",
        }
        for volume in _eligible_volumes(db)
        if len(volume.mount_path) + 1 + len(VOLUME_DIRECTORIES[role]) <= 240
    ]


def storage_settings(db: Session, role: Role) -> dict[str, str]:
    """Read the saved storage selection or the installed default.

    Args:
        db: Active database session.
        role: Service that owns the assignment.
    """
    settings = _row(db, role)
    if settings is None:
        return {"volume_uuid": "", "mount_path": DEFAULT_PATHS[role]}
    return {"volume_uuid": settings.storage_volume_uuid, "mount_path": settings.storage_volume_path or DEFAULT_PATHS[role]}


def _assignment(db: Session, role: Role, volume_uuid: str, mount_path: str | None = None) -> dict[str, str]:
    """Validate an assignment against the current volume and share registrations.

    Args:
        db: Active database session.
        role: Service that owns the assignment.
        volume_uuid: Selected registered filesystem UUID, or empty for installed storage.
        mount_path: Previously saved directory, or None to derive a new selection.
    """
    if not volume_uuid:
        if mount_path not in {None, "", DEFAULT_PATHS[role]}:
            raise ValueError("Select a registered volume to use a different storage path.")
        return {}
    matches = [volume for volume in _eligible_volumes(db) if volume.filesystem_uuid == volume_uuid]
    if len(matches) != 1:
        raise ValueError("The selected storage volume is unavailable. Apply its registration in Storage Volumes first.")
    volume = matches[0]
    if mount_path is None:
        mount_path = f"{volume.mount_path}/{VOLUME_DIRECTORIES[role]}"
    if len(mount_path) > 240 or not _storage_path_syntax(mount_path):
        raise ValueError("The storage directory is invalid or too long for the selected volume.")
    target = PurePosixPath(mount_path)
    volume_path = PurePosixPath(volume.mount_path)
    if target.parent != volume_path:
        raise ValueError("The storage directory must be directly under the selected volume's mount path.")
    other = storage_settings(db, "depot" if role == "backup" else "backup")
    if mount_path == other["mount_path"]:
        raise ValueError("The other VCF service already uses this storage directory.")
    for share in db.scalars(select(EsxNfsShare).where(EsxNfsShare.volume_id == volume.id)):
        share_path = volume_path / share.relative_path
        if target.is_relative_to(share_path) or share_path.is_relative_to(target):
            raise ValueError("This storage directory overlaps an ESX Storage share.")
    return {
        "uuid": volume_uuid, "path": mount_path, "volume_path": volume.mount_path,
        "device": volume.stable_device_id, "name": volume.name,
    }


def save_storage_assignment(db: Session, role: Role, volume_uuid: str) -> None:
    """Stage a selection within the caller's desired-state transaction.

    Args:
        db: Active database session owned by the caller.
        role: Service that owns the assignment.
        volume_uuid: Submitted filesystem UUID, or empty for installed storage.
    """
    acquire_network_objects_write_lock(db)
    assignment = _assignment(db, role, volume_uuid.strip())
    settings = _row(db, role)
    if settings is None:
        raise ValueError("The service settings are unavailable.")
    settings.storage_volume_uuid = assignment.get("uuid", "")
    settings.storage_volume_path = assignment.get("path", "")


def storage_assignment(db: Session, role: Role) -> dict[str, str]:
    """Bind a reviewed assignment to the exact current registration.

    Args:
        db: Active database session.
        role: Service that owns the assignment.
    """
    settings = storage_settings(db, role)
    return _assignment(db, role, settings["volume_uuid"], settings["mount_path"])


def storage_config_metadata(assignment: dict[str, str]) -> str:
    """Render constrained-helper metadata for a registered volume.

    Args:
        assignment: Validated registration identity, or empty for installed storage.
    """
    if not assignment:
        return ""
    identity = {key: assignment[key] for key in ("uuid", "path", "volume_path", "device")}
    return "\n" + STORAGE_COMMENT + json.dumps(identity, sort_keys=True) + "\n"


def storage_review(
    role: Role, previous: object, proposed: dict[str, str], *, enabled: bool,
) -> list[str]:
    """Describe storage changes in the existing Apply review.

    Args:
        role: Service that owns the assignment.
        previous: Assignment recorded in the applied baseline.
        proposed: Validated assignment in this Apply plan.
        enabled: Whether active service access could be interrupted.
    """
    current = previous if isinstance(previous, dict) else {}
    if current == proposed:
        return []
    default = DEFAULT_PATHS[role]
    before = f"{current.get('name', 'Installed storage')} at {current.get('path', default)}"
    after = f"{proposed.get('name', 'Installed storage')} at {proposed.get('path', default)}"
    interruption = "Active service access may be interrupted briefly." if enabled else "The service is disabled."
    return [
        f"Current storage: {before}",
        f"Proposed storage: {after}",
        "Existing files stay on their current storage. Apply does not copy or erase files.",
        interruption,
    ]
