"""Storage selections for the VCF appliance services."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Literal, TypedDict

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    EsxNfsShare,
    EsxStorageVolume,
    VcfBackupSettings,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
)
from atlaso.app.services.applied_service_dns import load_appliance_apply_baselines
from atlaso.app.services.esx_storage import reserved_mount_owner
from atlaso.app.services.network_objects import acquire_network_objects_write_lock

Role = Literal["backup", "depot", "registry"]
DEFAULT_PATHS = {
    "backup": "/mnt/atlaso-vcf-backups", "depot": "/mnt/atlaso-vcf-offline-depot", "registry": "/mnt/atlaso-vcf-registry",
}
VOLUME_DIRECTORIES = {"backup": "vcf-backups", "depot": "vcf-offline-depot", "registry": "vcf-registry"}
REGISTRY_STORAGE_UNIT = "vcf_private_registry_storage"
REGISTRY_STORAGE_CONFIG_PATH = "/var/lib/atlaso/apply/vcf-private-registry/atlaso-storage.conf"
STORAGE_UNITS: dict[Role, str] = {"backup": "vcf_backups", "depot": "vcf_offline_depot", "registry": REGISTRY_STORAGE_UNIT}
STORAGE_POLICIES = {"move", "leave", "delete"}
STORAGE_COMMENT = "# Atlaso VCF storage: "
STORAGE_CHANGE_COMMENT = "# Atlaso VCF storage change: "
STORAGE_IDENTITY_FIELDS = ("uuid", "path", "volume_path", "device")
DEFAULT_STORAGE_LABEL = "Appliance default"
_SYSTEM_ROOTS = frozenset("bin boot dev etc home lib lib64 opt proc root run sbin sys tmp usr var".split())
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


class StorageContext(TypedDict):
    """Fields shared by the three VCF storage wizard pages."""

    options: list[dict[str, str]]
    selection: dict[str, str]
    applied: dict[str, str]
    default_path: str


class StorageChange(TypedDict):
    """Review and execution identity for an actual backing-directory change."""

    action: str
    previous: dict[str, str]
    previous_path: str
    proposed_path: str
    confirmation: str


def storage_context(db: Session, role: Role) -> StorageContext:
    """Build the shared service volume picker and review state.

    Args:
        db: Active database session supplying the current storage registration.
        role: Service whose storage wizard will be rendered.
    """
    return {
        "options": storage_options(db, role),
        "selection": storage_settings(db, role),
        "applied": applied_storage_settings(db, role),
        "default_path": DEFAULT_PATHS[role],
    }


def _row(db: Session, role: Role) -> VcfBackupSettings | VcfOfflineDepotSettings | VcfPrivateRegistrySettings | None:
    """Select the singleton for one service.

    Args:
        db: Active database session.
        role: Service that owns the assignment.
    """
    if role == "backup":
        return db.scalars(select(VcfBackupSettings)).one_or_none()
    if role == "depot":
        return db.scalars(select(VcfOfflineDepotSettings)).one_or_none()
    return db.scalars(select(VcfPrivateRegistrySettings)).one_or_none()


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
    reserved_uuids = _other_service_volume_uuids(db, role)
    return [
        {
            "uuid": volume.filesystem_uuid, "name": volume.name, "mount_path": volume.mount_path,
            "storage_path": f"{volume.mount_path}/{VOLUME_DIRECTORIES[role]}",
        }
        for volume in _eligible_volumes(db)
        if volume.filesystem_uuid not in reserved_uuids
        and len(volume.mount_path) + 1 + len(VOLUME_DIRECTORIES[role]) <= 240
    ]


def storage_settings(db: Session, role: Role) -> dict[str, str]:
    """Read the saved storage selection or the installed default.

    Args:
        db: Active database session.
        role: Service that owns the assignment.
    """
    settings = _row(db, role)
    if settings is None:
        return {"volume_uuid": "", "mount_path": DEFAULT_PATHS[role], "migration_policy": "leave"}
    return {
        "volume_uuid": settings.storage_volume_uuid,
        "mount_path": settings.storage_volume_path or DEFAULT_PATHS[role],
        "migration_policy": settings.storage_migration_policy or "leave",
    }


def clear_applied_storage_policy(db: Session, role: Role, change: StorageChange, assignment: object) -> None:
    """Consume a completed choice without overwriting a newer saved assignment.

    Args:
        db: Active writer session holding Apply baseline admission.
        role: Service that applied a data action.
        change: Data action admitted in the completed task.
        assignment: Registered mount applied by that task, or its default.
    """
    row = _row(db, role)
    target = assignment if isinstance(assignment, dict) else {}
    if row is not None and (
        row.storage_volume_uuid,
        row.storage_volume_path,
        row.storage_migration_policy,
    ) == (target.get("uuid", ""), target.get("path", ""), change["action"]):
        row.storage_migration_policy = ""


def applied_storage_settings(db: Session, role: Role) -> dict[str, str]:
    """Read the last applied registration and directory for a service.

    Args:
        db: Active database session holding the shared Apply baseline.
        role: Service whose storage is displayed before a change.
    """
    baseline = load_appliance_apply_baselines(db, refresh=True).get(STORAGE_UNITS[role], {})
    marker = baseline.get("snapshot_marker")
    if not isinstance(marker, dict):
        return {"uuid": "", "path": DEFAULT_PATHS[role]}
    return {"uuid": str(marker.get("uuid") or ""), "path": str(marker.get("path") or DEFAULT_PATHS[role])}


def _other_service_volume_uuids(db: Session, role: Role) -> set[str]:
    """Keep the other service's current and proposed volumes reserved until Apply releases them.

    Args:
        db: Active database session containing desired settings and Apply baselines.
        role: Service requesting the volume.
    """
    baselines = load_appliance_apply_baselines(db, refresh=True)
    reserved: set[str] = set()
    for other_role, unit in STORAGE_UNITS.items():
        if other_role == role:
            continue
        row = _row(db, other_role)
        if row and row.storage_volume_uuid:
            reserved.add(row.storage_volume_uuid)
        marker = baselines.get(unit, {}).get("snapshot_marker")
        if isinstance(marker, dict) and isinstance(marker.get("uuid"), str):
            reserved.add(marker["uuid"])
    return reserved


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
    if any(mount_path == storage_settings(db, other)["mount_path"] for other in STORAGE_UNITS if other != role):
        raise ValueError("The other VCF service already uses this storage directory.")
    for share in db.scalars(select(EsxNfsShare).where(EsxNfsShare.volume_id == volume.id)):
        share_path = volume_path / share.relative_path
        if target.is_relative_to(share_path) or share_path.is_relative_to(target):
            raise ValueError("This storage directory overlaps an ESX Storage share.")
    return {
        "uuid": volume_uuid, "path": mount_path, "volume_path": volume.mount_path,
        "device": volume.stable_device_id, "name": volume.name,
    }


def save_storage_assignment(db: Session, role: Role, volume_uuid: str, migration_policy: str = "leave") -> None:
    """Stage a selection within the caller's desired-state transaction.

    Args:
        db: Active database session owned by the caller.
        role: Service that owns the assignment.
        volume_uuid: Submitted filesystem UUID, or empty for installed storage.
        migration_policy: Operator's requested handling for the previous storage data.
    """
    acquire_network_objects_write_lock(db)
    db.flush()
    if migration_policy not in STORAGE_POLICIES:
        raise ValueError("Choose Move, Leave, or Delete for the previous storage data.")
    volume_uuid = volume_uuid.strip()
    if volume_uuid and volume_uuid in _other_service_volume_uuids(db, role):
        raise ValueError("The other VCF service has already selected or applied this storage volume.")
    assignment = _assignment(db, role, volume_uuid)
    settings = _row(db, role)
    if settings is None:
        raise ValueError("The service settings are unavailable.")
    settings.storage_volume_uuid = assignment.get("uuid", "")
    settings.storage_volume_path = assignment.get("path", "")
    settings.storage_migration_policy = migration_policy


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
    identity = {key: assignment[key] for key in STORAGE_IDENTITY_FIELDS}
    return "\n" + STORAGE_COMMENT + json.dumps(identity, sort_keys=True) + "\n"


def storage_change(
    role: Role, previous: object, proposed: dict[str, str], action: str,
) -> StorageChange | None:
    """Describe the exact source, destination, and data action at review.

    Args:
        role: Consumer whose fixed default is used when no volume is assigned.
        previous: Assignment recorded in the last applied baseline.
        proposed: Validated desired assignment.
        action: Requested handling of data at the old location.
    """
    current = previous if isinstance(previous, dict) else {}
    previous_path = str(current.get("path") or DEFAULT_PATHS[role])
    proposed_path = proposed.get("path", DEFAULT_PATHS[role])
    if (current.get("uuid") or "", previous_path) == (proposed.get("uuid", ""), proposed_path):
        return None
    if action not in STORAGE_POLICIES:
        raise ValueError("Choose Move, Leave, or Delete for the previous storage data.")
    if current and not all(isinstance(current.get(key), str) for key in STORAGE_IDENTITY_FIELDS):
        raise ValueError("The applied storage record is incomplete. Verify the current mount before changing it.")
    return {
        "action": action,
        "previous": {key: current[key] for key in STORAGE_IDENTITY_FIELDS} if current else {},
        "previous_path": previous_path,
        "proposed_path": proposed_path,
        "confirmation": f"DELETE {previous_path}" if action == "delete" else "",
    }


def storage_change_metadata(change: StorageChange | None) -> str:
    """Serialize the exact data action admitted in the submitted Apply task.

    Args:
        change: Consented storage change, or no storage change for this unit.
    """
    if change is None:
        return ""
    request = {key: change[key] for key in ("action", "previous", "confirmation")}
    return "\n" + STORAGE_CHANGE_COMMENT + json.dumps(request, sort_keys=True) + "\n"


def verify_storage_confirmations(
    required: dict[str, str], submitted: list[str],
) -> None:
    """Require one exact deletion confirmation per selected storage change.

    Args:
        required: Selected component IDs mapped to their exact confirmation phrases.
        submitted: Repeated JSON-encoded form fields.
    """
    confirmations: dict[str, str] = {}
    if len(submitted) > len(STORAGE_UNITS):
        raise ValueError("Too many storage confirmations. Reopen Appliance Apply and try again.")
    for raw in submitted:
        try:
            item = json.loads(raw) if len(raw) <= 800 else None
        except ValueError:
            item = None
        if (
            not isinstance(item, dict)
            or set(item) != {"unit_id", "confirmation"}
            or not isinstance(item["unit_id"], str)
            or not isinstance(item["confirmation"], str)
            or item["unit_id"] in confirmations
            or item["unit_id"] not in required
        ):
            raise ValueError("A storage confirmation was invalid. Reopen Appliance Apply and try again.")
        confirmations[item["unit_id"]] = item["confirmation"]
    for unit_id, phrase in required.items():
        if confirmations.get(unit_id) != phrase:
            raise ValueError(f"Deleting previous storage files requires the exact confirmation {phrase!r}.")


def storage_review(
    role: Role, previous: object, proposed: dict[str, str], *, enabled: bool, action: str = "leave",
) -> list[str]:
    """Describe storage changes in the existing Apply review.

    Args:
        role: Service that owns the assignment.
        previous: Assignment recorded in the applied baseline.
        proposed: Validated assignment in this Apply plan.
        enabled: Whether active service access could be interrupted.
        action: Confirmed data handling to explain in Appliance Apply.
    """
    current = previous if isinstance(previous, dict) else {}
    if storage_change(role, current, proposed, action) is None:
        return []
    default = DEFAULT_PATHS[role]
    before = f"{current.get('name', DEFAULT_STORAGE_LABEL)} at {current.get('path', default)}"
    after = f"{proposed.get('name', DEFAULT_STORAGE_LABEL)} at {proposed.get('path', default)}"
    interruption = "Active service access may be interrupted briefly." if enabled else "The service is disabled."
    return [
        f"Current storage: {before}",
        f"Proposed storage: {after}",
        {
            "move": "Apply moves existing files to the proposed location before activating the new storage.",
            "leave": "Existing files stay on their current storage. Apply does not copy or erase files.",
            "delete": "Apply permanently deletes the previous files after the new storage is active.",
        }[action],
        interruption,
    ]
