"""Own ESX Storage API v1 transports."""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi import Path as ApiPath
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import EsxNfsShare, EsxStorageVolume, utcnow
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    EsxNfsShareCreate,
    EsxNfsShareResponse,
    EsxNfsShareUpdate,
    EsxStorageDiskResponse,
    EsxStorageSettingsUpdate,
    EsxStorageStatusResponse,
    EsxStorageVolumeCreate,
    EsxStorageVolumeResponse,
    EsxStorageVolumeUpdate,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.esx_storage import (
    ESX_STORAGE_MOUNT_ROOT,
    normalize_families,
    normalize_relative_path,
    parse_disk_inventory_output,
    select_inventory_candidate,
    storage_slug,
    validate_mounted_volume_path,
)
from atlaso.app.services.esx_storage import (
    split_lines as split_esx_storage_lines,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class EsxStorageApiDependencies:
    """Provide facade-owned ESX Storage API transport dependencies."""

    esx_share_response: Endpoint
    esx_storage_state: Endpoint
    get_esx_storage_settings: Endpoint
    reconcile_esx_storage_dns: Endpoint
    system_adapter_factory: Endpoint


@dataclass(frozen=True)
class EsxStorageApiRouter:
    """Return the API v1 router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: EsxStorageApiDependencies) -> EsxStorageApiRouter:
    """Build ESX Storage API v1 transports.

    Args:
        dependencies: Facade-provided transport dependencies.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)

    @router.get(
        "/esx-storage/status",
        response_model=EsxStorageStatusResponse,
        tags=["ESX Storage"],
        operation_id="getEsxStorageStatus",
    )
    def get_esx_storage_status(
        identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> EsxStorageStatusResponse:
        """Get Esx Storage Status.

        Requires the `read:esx-storage` API scope. This read-only operation does not change saved
        desired state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings, volumes, shares, _interfaces, manifest = (
            dependencies.esx_storage_state(db)
        )
        return EsxStorageStatusResponse(
            enabled=settings.enabled,
            hostname=settings.hostname,
            valid=not manifest["validation"]["errors"],
            validation_errors=manifest["validation"]["errors"],
            validation_warnings=manifest["validation"]["warnings"],
            volume_count=len(volumes),
            share_count=len(shares),
            active_share_count=len([row for row in shares if row.enabled]),
            dry_run=get_settings().dry_run_system_adapters,
        )

    @router.patch(
        "/esx-storage/status",
        response_model=EsxStorageStatusResponse,
        tags=["ESX Storage"],
        operation_id="updateEsxStorageSettings",
    )
    def update_esx_storage_settings(
        payload: EsxStorageSettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> EsxStorageStatusResponse:
        """Update Esx Storage Settings.

        Requires the `write:esx-storage` API scope. The request is evaluated without persisting desired
        state or mutating appliance runtime state.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        row = dependencies.get_esx_storage_settings(db)
        previous_hostname = row.hostname
        hostname = payload.hostname.strip().lower().rstrip(".")
        if "." not in hostname:
            raise HTTPException(
                status_code=422,
                detail="ESX Storage hostname must be a fully qualified DNS name.",
            )
        row.enabled = payload.enabled
        row.hostname = hostname
        row.updated_at = utcnow()
        dependencies.reconcile_esx_storage_dns(
            db, identity.username, previous_hostname=previous_hostname
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_esx_storage_settings",
            resource_type="esx_storage",
            resource_id=str(row.id),
        )
        return get_esx_storage_status(identity, db)

    @router.get(
        "/esx-storage/disks",
        response_model=list[EsxStorageDiskResponse],
        tags=["ESX Storage"],
        operation_id="getEsxStorageDisks",
    )
    def get_esx_storage_disks(
        identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> list[EsxStorageDiskResponse]:
        """Get Esx Storage Disks.

        Requires the `read:esx-storage` API scope. This read-only operation does not change saved
        desired state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        result = dependencies.system_adapter_factory().esx_storage_inventory()
        if result.returncode:
            raise HTTPException(
                status_code=503,
                detail=result.stderr or "ESX Storage disk inventory failed.",
            )
        claimed = set(
            db.execute(select(EsxStorageVolume.stable_device_id)).scalars().all()
        )
        try:
            entries = parse_disk_inventory_output(result.stdout, claimed_ids=claimed)
        except (json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="ESX Storage disk inventory returned invalid JSON.",
            ) from exc
        return [EsxStorageDiskResponse(**item) for item in entries]

    @router.get(
        "/esx-storage/volumes",
        response_model=list[EsxStorageVolumeResponse],
        tags=["ESX Storage"],
        operation_id="getEsxStorageVolumes",
    )
    def get_esx_storage_volumes(
        identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> list[EsxStorageVolumeResponse]:
        """Get Esx Storage Volumes.

        Requires the `read:esx-storage` API scope. This read-only operation does not change saved
        desired state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            EsxStorageVolumeResponse.model_validate(row)
            for row in db.execute(
                select(EsxStorageVolume).order_by(EsxStorageVolume.name)
            )
            .scalars()
            .all()
        ]

    @router.post(
        "/esx-storage/volumes",
        response_model=EsxStorageVolumeResponse,
        status_code=201,
        tags=["ESX Storage"],
        operation_id="createEsxStorageVolume",
    )
    def create_esx_storage_volume(
        payload: EsxStorageVolumeCreate,
        identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> EsxStorageVolumeResponse:
        """Create Esx Storage Volume.

        Requires the `write:esx-storage` API scope. The operation changes saved Atlaso application
        state; any appliance host enforcement remains subject to the documented apply or task boundary
        for the resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        name = payload.name.strip()
        if (
            payload.source_type == "blank_disk"
            and not payload.stable_device_id.startswith("/dev/disk/by-id/")
        ):
            raise HTTPException(
                status_code=422,
                detail="Blank disks require a stable /dev/disk/by-id identity.",
            )
        if payload.source_type == "mounted_ext4":
            try:
                validate_mounted_volume_path(payload.mount_path)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        candidate: dict[str, Any] = {}
        if not get_settings().dry_run_system_adapters:
            result = dependencies.system_adapter_factory(
                dry_run=False
            ).esx_storage_inventory()
            if result.returncode:
                raise HTTPException(
                    status_code=503,
                    detail=result.stderr or "ESX Storage disk inventory failed.",
                )
            try:
                inventory = parse_disk_inventory_output(
                    result.stdout,
                    claimed_ids=set(
                        db.execute(select(EsxStorageVolume.stable_device_id))
                        .scalars()
                        .all()
                    ),
                )
                candidate = select_inventory_candidate(
                    inventory,
                    source_type=payload.source_type,
                    stable_device_id=payload.stable_device_id,
                    mount_path=payload.mount_path,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        row = EsxStorageVolume(
            name=name,
            source_type=payload.source_type,
            stable_device_id=str(
                candidate.get("stable_device_id") or payload.stable_device_id
            ).strip(),
            device_path=str(candidate.get("device_path") or ""),
            device_model=str(candidate.get("model") or ""),
            device_serial=str(candidate.get("serial") or ""),
            device_wwn=str(candidate.get("wwn") or ""),
            capacity_bytes=int(candidate.get("size_bytes") or 0),
            filesystem_uuid=str(candidate.get("filesystem_uuid") or ""),
            filesystem_label=str(candidate.get("filesystem_label") or ""),
            mount_path=str(candidate.get("mount_path") or payload.mount_path).strip()
            or f"{ESX_STORAGE_MOUNT_ROOT}/{storage_slug(name)}",
            state="pending_format"
            if payload.source_type == "blank_disk"
            else "mounted",
            applied=False,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="The volume name or stable disk identity is already claimed.",
            ) from exc
        db.refresh(row)
        dependencies.reconcile_esx_storage_dns(db, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="create_esx_storage_volume",
            resource_type="esx_storage_volume",
            resource_id=str(row.id),
            detail=f"name={row.name} source_type={row.source_type}",
        )
        return EsxStorageVolumeResponse.model_validate(row)

    @router.patch(
        "/esx-storage/volumes/{volume_id}",
        response_model=EsxStorageVolumeResponse,
        tags=["ESX Storage"],
        operation_id="updateEsxStorageVolume",
    )
    def update_esx_storage_volume(
        volume_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the volume record addressed by this operation."
            ),
        ],
        payload: EsxStorageVolumeUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> EsxStorageVolumeResponse:
        """Update Esx Storage Volume.

        Requires the `write:esx-storage` API scope. The operation updates saved Atlaso state and does
        not bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            volume_id: Stable identifier of the associated volume resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        row = db.get(EsxStorageVolume, volume_id)
        if row is None:
            raise HTTPException(status_code=404, detail="ESX Storage volume not found.")
        if any(
            value is not None
            for value in [payload.stable_device_id, payload.mount_path]
        ):
            raise HTTPException(
                status_code=409,
                detail="Volume identity and mount path are immutable after the inventory-backed claim is created.",
            )
        if payload.name is not None:
            row.name = payload.name.strip()
        if payload.stable_device_id is not None:
            if (
                row.source_type == "blank_disk"
                and not payload.stable_device_id.startswith("/dev/disk/by-id/")
            ):
                raise HTTPException(
                    status_code=422,
                    detail="Blank disks require a stable /dev/disk/by-id identity.",
                )
            row.stable_device_id = payload.stable_device_id.strip()
        if payload.mount_path is not None:
            row.mount_path = payload.mount_path.strip()
        row.updated_at = utcnow()
        db.commit()
        db.refresh(row)
        dependencies.reconcile_esx_storage_dns(db, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_esx_storage_volume",
            resource_type="esx_storage_volume",
            resource_id=str(row.id),
        )
        return EsxStorageVolumeResponse.model_validate(row)

    @router.get(
        "/esx-storage/shares",
        response_model=list[EsxNfsShareResponse],
        tags=["ESX Storage"],
        operation_id="getEsxNfsShares",
    )
    def get_esx_nfs_shares(
        identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> list[EsxNfsShareResponse]:
        """Get Esx Nfs Shares.

        Requires the `read:esx-storage` API scope. This read-only operation does not change saved
        desired state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        _settings, _volumes, shares, _interfaces, manifest = (
            dependencies.esx_storage_state(db)
        )
        return [dependencies.esx_share_response(row, manifest) for row in shares]

    def apply_esx_share_payload(
        row: EsxNfsShare, payload: EsxNfsShareCreate | EsxNfsShareUpdate
    ) -> None:
        """Update esx share payload.

        Args:
            row: Persistent database row affected by the operation.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        values = payload.model_dump(exclude_unset=True)
        if "relative_path" in values:
            values["relative_path"] = normalize_relative_path(values["relative_path"])
        if "address_families" in values:
            families = normalize_families(values["address_families"])
            if not families:
                raise HTTPException(
                    status_code=422, detail="Enable IPv4, IPv6, or both."
                )
            values["address_families"] = "\n".join(families)
        if "ipv4_clients" in values:
            values["ipv4_clients"] = "\n".join(
                split_esx_storage_lines(values["ipv4_clients"])
            )
        if "ipv6_clients" in values:
            values["ipv6_clients"] = "\n".join(
                split_esx_storage_lines(values["ipv6_clients"])
            )
        for key, value in values.items():
            setattr(row, key, value)
        row.updated_at = utcnow()

    @router.post(
        "/esx-storage/shares",
        response_model=EsxNfsShareResponse,
        status_code=201,
        tags=["ESX Storage"],
        operation_id="createEsxNfsShare",
    )
    def create_esx_nfs_share(
        payload: EsxNfsShareCreate,
        identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> EsxNfsShareResponse:
        """Create Esx Nfs Share.

        Requires the `write:esx-storage` API scope. The operation changes saved Atlaso application
        state; any appliance host enforcement remains subject to the documented apply or task boundary
        for the resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        if db.get(EsxStorageVolume, payload.volume_id) is None:
            raise HTTPException(
                status_code=422, detail="Selected ESX Storage volume does not exist."
            )
        row = EsxNfsShare(
            datastore_name=payload.datastore_name, volume_id=payload.volume_id
        )
        apply_esx_share_payload(row, payload)
        db.add(row)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Datastore name already exists."
            ) from exc
        db.refresh(row)
        dependencies.reconcile_esx_storage_dns(db, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="create_esx_nfs_share",
            resource_type="esx_nfs_share",
            resource_id=str(row.id),
            detail=f"datastore={row.datastore_name}",
        )
        return dependencies.esx_share_response(
            row, dependencies.esx_storage_state(db)[4]
        )

    @router.patch(
        "/esx-storage/shares/{share_id}",
        response_model=EsxNfsShareResponse,
        tags=["ESX Storage"],
        operation_id="updateEsxNfsShare",
    )
    def update_esx_nfs_share(
        share_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the share record addressed by this operation."
            ),
        ],
        payload: EsxNfsShareUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> EsxNfsShareResponse:
        """Update Esx Nfs Share.

        Requires the `write:esx-storage` API scope. The operation updates saved Atlaso state and does
        not bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            share_id: Stable identifier of the associated share resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        row = db.get(EsxNfsShare, share_id)
        if row is None:
            raise HTTPException(
                status_code=404, detail="NFS datastore share not found."
            )
        if (
            payload.volume_id is not None
            and db.get(EsxStorageVolume, payload.volume_id) is None
        ):
            raise HTTPException(
                status_code=422, detail="Selected ESX Storage volume does not exist."
            )
        apply_esx_share_payload(row, payload)
        dependencies.reconcile_esx_storage_dns(db, identity.username)
        db.commit()
        db.refresh(row)
        record_audit(
            db,
            actor=identity.username,
            action="update_esx_nfs_share",
            resource_type="esx_nfs_share",
            resource_id=str(row.id),
            detail=f"datastore={row.datastore_name}",
        )
        return dependencies.esx_share_response(
            row, dependencies.esx_storage_state(db)[4]
        )

    @router.delete(
        "/esx-storage/shares/{share_id}",
        status_code=204,
        tags=["ESX Storage"],
        operation_id="deleteEsxNfsShare",
    )
    def delete_esx_nfs_share(
        share_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the share record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Esx Nfs Share.

        Requires the `write:esx-storage` API scope. Removal or revocation takes effect in Atlaso
        application state; appliance host changes remain subject to the documented apply boundary for
        the resource.

        Args:
            share_id: Stable identifier of the associated share resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        row = db.get(EsxNfsShare, share_id)
        if row is None:
            raise HTTPException(
                status_code=404, detail="NFS datastore share not found."
            )
        name = row.datastore_name
        db.delete(row)
        db.flush()
        dependencies.reconcile_esx_storage_dns(db, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_esx_nfs_share",
            resource_type="esx_nfs_share",
            resource_id=str(share_id),
            detail=f"datastore={name}; data preserved",
        )
        return Response(status_code=204)

    return EsxStorageApiRouter(
        router=router,
        endpoints={
            "get_esx_storage_status": get_esx_storage_status,
            "update_esx_storage_settings": update_esx_storage_settings,
            "get_esx_storage_disks": get_esx_storage_disks,
            "get_esx_storage_volumes": get_esx_storage_volumes,
            "create_esx_storage_volume": create_esx_storage_volume,
            "update_esx_storage_volume": update_esx_storage_volume,
            "get_esx_nfs_shares": get_esx_nfs_shares,
            "apply_esx_share_payload": apply_esx_share_payload,
            "create_esx_nfs_share": create_esx_nfs_share,
            "update_esx_nfs_share": update_esx_nfs_share,
            "delete_esx_nfs_share": delete_esx_nfs_share,
        },
    )
