"""Own ESX Storage management UI transports."""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import EsxNfsShare, EsxStorageVolume, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.esx_storage import (
    normalize_families as normalize_esx_storage_families,
)
from atlaso.app.services.esx_storage import (
    normalize_relative_path as normalize_esx_storage_relative_path,
)
from atlaso.app.services.esx_storage import (
    parse_disk_inventory_output as parse_esx_storage_disk_inventory_output,
)
from atlaso.app.services.esx_storage import (
    select_inventory_candidate as select_esx_storage_inventory_candidate,
)
from atlaso.app.services.esx_storage import (
    split_lines as split_esx_storage_lines,
)
from atlaso.app.services.esx_storage import (
    storage_slug as esx_storage_slug,
)
from atlaso.app.services.esx_storage import (
    validate_mounted_volume_path as validate_esx_storage_mounted_volume_path,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class EsxStorageUiDependencies:
    """Provide facade-owned ESX Storage transport dependencies."""

    appliance_apply_client_status: Endpoint
    appliance_apply_status: Endpoint
    ensure_dns_for_esx_storage: Endpoint
    esx_storage_context: Endpoint
    get_esx_storage_settings_row: Endpoint
    normalize_dns_hostname: Endpoint
    render: Endpoint
    require_management_ui_request: Endpoint
    system_adapter_factory: Endpoint
    verify_csrf: Endpoint


@dataclass(frozen=True)
class EsxStorageUiRouter:
    """Return the management router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: EsxStorageUiDependencies) -> EsxStorageUiRouter:
    """Build ESX Storage management UI transports.

    Args:
        dependencies: Facade-provided transport dependencies.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )

    def require_esx_storage_write(identity: Identity) -> None:
        """Handle require esx storage write.

        Args:
            identity: Authenticated identity authorizing the request.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not identity.can("write:esx-storage"):
            raise HTTPException(
                status_code=403, detail="ESX Storage write permission is required."
            )

    @router.get("/esx-storage", response_class=HTMLResponse, response_model=None)
    def esx_storage_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the esx storage page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        context = dependencies.esx_storage_context(db)
        return dependencies.render(
            request,
            "esx_storage.html",
            {
                "identity": identity,
                "esx_storage_can_write": identity.can("write:esx-storage"),
                **context,
                "appliance_apply_status": dependencies.appliance_apply_status(
                    db, "esx_storage"
                ),
            },
        )

    @router.post("/esx-storage/settings", response_model=None)
    def update_esx_storage_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        hostname: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update esx storage settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            hostname: DNS hostname of the target resource.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        require_esx_storage_write(identity)
        settings = dependencies.get_esx_storage_settings_row(db)
        previous_hostname = settings.hostname
        normalized_hostname = dependencies.normalize_dns_hostname(
            hostname.strip() or settings.hostname
        )
        if not normalized_hostname or "." not in normalized_hostname:
            raise HTTPException(
                status_code=400,
                detail="ESX Storage hostname must be a fully qualified DNS name.",
            )
        settings.enabled = enabled == "on"
        settings.hostname = normalized_hostname
        settings.updated_at = utcnow()
        dns_action = dependencies.ensure_dns_for_esx_storage(
            db, identity.username, previous_hostname=previous_hostname
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_esx_storage_settings",
            resource_type="esx_storage",
            resource_id=str(settings.id),
            detail=f"enabled={settings.enabled} hostname={settings.hostname}",
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = dependencies.esx_storage_context(db)
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": settings.updated_at.isoformat(),
                    "dns_record_action": dns_action,
                    "valid": not context["esx_storage_validation_errors"],
                    "validation_errors": context["esx_storage_validation_errors"],
                    "validation_warnings": context["esx_storage_validation_warnings"],
                    "config_preview": context["esx_storage_manifest_preview"],
                    "appliance_apply_status": dependencies.appliance_apply_client_status(
                        dependencies.appliance_apply_status(db, "esx_storage")
                    ),
                }
            )
        return RedirectResponse("/esx-storage", status_code=303)

    @router.post("/esx-storage/volumes", response_model=None)
    def create_esx_storage_volume_from_ui(
        request: Request,
        name: str = Form(...),
        source_type: str = Form("blank_disk"),
        stable_device_id: str = Form(""),
        mount_path: str = Form(""),
        device_model: str = Form(""),
        device_serial: str = Form(""),
        device_wwn: str = Form(""),
        capacity_bytes: int = Form(0),
        filesystem_uuid: str = Form(""),
        filesystem_label: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the create esx storage volume from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            source_type: Source type supplied by the caller.
            stable_device_id: Identifier of the stable device.
            mount_path: Filesystem path for the mount.
            device_model: Device model supplied by the caller.
            device_serial: Device serial supplied by the caller.
            device_wwn: Device wwn supplied by the caller.
            capacity_bytes: Capacity bytes supplied by the caller.
            filesystem_uuid: Filesystem uuid supplied by the caller.
            filesystem_label: Filesystem label supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        require_esx_storage_write(identity)
        normalized_name = name.strip()
        if source_type not in {"blank_disk", "mounted_ext4"}:
            raise HTTPException(
                status_code=400,
                detail="Volume source must be a blank disk or mounted ext4 volume.",
            )
        if source_type == "blank_disk" and not stable_device_id.startswith(
            "/dev/disk/by-id/"
        ):
            raise HTTPException(
                status_code=400,
                detail="Blank disks require a stable /dev/disk/by-id identity.",
            )
        if source_type == "mounted_ext4":
            try:
                validate_esx_storage_mounted_volume_path(mount_path)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        candidate: dict[str, Any] = {}
        if not get_settings().dry_run_system_adapters:
            inventory_result = dependencies.system_adapter_factory(
                dry_run=False
            ).esx_storage_inventory()
            if inventory_result.returncode:
                raise HTTPException(
                    status_code=503,
                    detail=inventory_result.stderr
                    or "ESX Storage disk inventory failed.",
                )
            try:
                inventory = parse_esx_storage_disk_inventory_output(
                    inventory_result.stdout,
                    claimed_ids=set(
                        db.execute(select(EsxStorageVolume.stable_device_id))
                        .scalars()
                        .all()
                    ),
                )
                candidate = select_esx_storage_inventory_candidate(
                    inventory,
                    source_type=source_type,
                    stable_device_id=stable_device_id,
                    mount_path=mount_path,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        row = EsxStorageVolume(
            name=normalized_name,
            source_type=source_type,
            stable_device_id=str(
                candidate.get("stable_device_id") or stable_device_id
            ).strip(),
            device_path=str(candidate.get("device_path") or ""),
            device_model=str(candidate.get("model") or device_model).strip(),
            device_serial=str(candidate.get("serial") or device_serial).strip(),
            device_wwn=str(candidate.get("wwn") or device_wwn).strip(),
            capacity_bytes=int(candidate.get("size_bytes") or max(capacity_bytes, 0)),
            filesystem_uuid=str(
                candidate.get("filesystem_uuid") or filesystem_uuid
            ).strip(),
            filesystem_label=str(
                candidate.get("filesystem_label") or filesystem_label
            ).strip(),
            mount_path=str(candidate.get("mount_path") or mount_path).strip()
            or f"/mnt/atlaso-esx-storage/{esx_storage_slug(normalized_name)}",
            state="pending_format" if source_type == "blank_disk" else "mounted",
            applied=False,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail="The volume name or stable device identity is already claimed.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_esx_storage_volume",
            resource_type="esx_storage_volume",
            resource_id=str(row.id),
            detail=f"name={row.name} source_type={row.source_type}",
        )
        return RedirectResponse("/esx-storage#storage-volumes", status_code=303)

    @router.post("/esx-storage/shares", response_model=None)
    def create_esx_nfs_share_from_ui(
        request: Request,
        datastore_name: str = Form(...),
        volume_id: int = Form(...),
        relative_path: str = Form(...),
        preferred_nfs_version: str = Form("4.1"),
        interface_name: str = Form(...),
        address_families: list[str] = Form(default_factory=list),
        ipv4_clients: str = Form(""),
        ipv6_clients: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the create esx nfs share from ui endpoint.

        Args:
            request: Incoming HTTP request.
            datastore_name: Datastore name supplied by the caller.
            volume_id: Identifier of the volume.
            relative_path: Filesystem path for the relative.
            preferred_nfs_version: Preferred nfs version supplied by the caller.
            interface_name: Linux interface name of the network target.
            address_families: Address families supplied by the caller.
            ipv4_clients: Ipv4 clients supplied by the caller.
            ipv6_clients: Ipv6 clients supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        require_esx_storage_write(identity)
        if db.get(EsxStorageVolume, volume_id) is None:
            raise HTTPException(
                status_code=400, detail="Selected storage volume does not exist."
            )
        if preferred_nfs_version not in {"3", "4.1"}:
            raise HTTPException(
                status_code=400, detail="Preferred NFS version must be 3 or 4.1."
            )
        families = normalize_esx_storage_families(address_families)
        if not families:
            raise HTTPException(status_code=400, detail="Select IPv4, IPv6, or both.")
        row = EsxNfsShare(
            datastore_name=datastore_name.strip(),
            volume_id=volume_id,
            relative_path=normalize_esx_storage_relative_path(relative_path),
            preferred_nfs_version=preferred_nfs_version,
            interface_name=interface_name.strip(),
            address_families="\n".join(families),
            ipv4_clients="\n".join(split_esx_storage_lines(ipv4_clients)),
            ipv6_clients="\n".join(split_esx_storage_lines(ipv6_clients)),
            enabled=enabled == "on",
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=400, detail="A datastore with this name already exists."
            ) from exc
        dependencies.ensure_dns_for_esx_storage(db, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="create_esx_nfs_share",
            resource_type="esx_nfs_share",
            resource_id=str(row.id),
            detail=f"datastore={row.datastore_name} families={','.join(families)}",
        )
        return RedirectResponse("/esx-storage#nfs-datastores", status_code=303)

    @router.post("/esx-storage/shares/{share_id}", response_model=None)
    def update_esx_nfs_share_from_ui(
        request: Request,
        share_id: int,
        datastore_name: str = Form(...),
        volume_id: int = Form(...),
        relative_path: str = Form(...),
        preferred_nfs_version: str = Form("4.1"),
        interface_name: str = Form(...),
        address_families: list[str] = Form(default_factory=list),
        ipv4_clients: str = Form(""),
        ipv6_clients: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the update esx nfs share from ui endpoint.

        Args:
            request: Incoming HTTP request.
            share_id: Identifier of the share.
            datastore_name: Datastore name supplied by the caller.
            volume_id: Identifier of the volume.
            relative_path: Filesystem path for the relative.
            preferred_nfs_version: Preferred nfs version supplied by the caller.
            interface_name: Linux interface name of the network target.
            address_families: Address families supplied by the caller.
            ipv4_clients: Ipv4 clients supplied by the caller.
            ipv6_clients: Ipv6 clients supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        require_esx_storage_write(identity)
        row = db.get(EsxNfsShare, share_id)
        if row is None:
            raise HTTPException(
                status_code=404, detail="NFS datastore share not found."
            )
        if db.get(EsxStorageVolume, volume_id) is None:
            raise HTTPException(
                status_code=400, detail="Selected storage volume does not exist."
            )
        if preferred_nfs_version not in {"3", "4.1"}:
            raise HTTPException(
                status_code=400, detail="Preferred NFS version must be 3 or 4.1."
            )
        families = normalize_esx_storage_families(address_families)
        if not families:
            raise HTTPException(status_code=400, detail="Select IPv4, IPv6, or both.")
        row.datastore_name = datastore_name.strip()
        row.volume_id = volume_id
        row.relative_path = normalize_esx_storage_relative_path(relative_path)
        row.preferred_nfs_version = preferred_nfs_version
        row.interface_name = interface_name.strip()
        row.address_families = "\n".join(families)
        row.ipv4_clients = "\n".join(split_esx_storage_lines(ipv4_clients))
        row.ipv6_clients = "\n".join(split_esx_storage_lines(ipv6_clients))
        row.enabled = enabled == "on"
        row.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=400, detail="A datastore with this name already exists."
            ) from exc
        dependencies.ensure_dns_for_esx_storage(db, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_esx_nfs_share",
            resource_type="esx_nfs_share",
            resource_id=str(row.id),
            detail=f"datastore={row.datastore_name} families={','.join(families)}",
        )
        return RedirectResponse("/esx-storage#nfs-datastores", status_code=303)

    @router.post("/esx-storage/shares/{share_id}/delete", response_model=None)
    def delete_esx_nfs_share_from_ui(
        request: Request,
        share_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete esx nfs share from ui endpoint.

        Args:
            request: Incoming HTTP request.
            share_id: Identifier of the share.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        require_esx_storage_write(identity)
        row = db.get(EsxNfsShare, share_id)
        if row is None:
            raise HTTPException(
                status_code=404, detail="NFS datastore share not found."
            )
        name = row.datastore_name
        db.delete(row)
        db.flush()
        dependencies.ensure_dns_for_esx_storage(db, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_esx_nfs_share",
            resource_type="esx_nfs_share",
            resource_id=str(share_id),
            detail=f"datastore={name}; underlying data preserved",
        )
        return RedirectResponse("/esx-storage#nfs-datastores", status_code=303)

    return EsxStorageUiRouter(
        router=router,
        endpoints={
            "require_esx_storage_write": require_esx_storage_write,
            "esx_storage_page": esx_storage_page,
            "update_esx_storage_settings_from_ui": update_esx_storage_settings_from_ui,
            "create_esx_storage_volume_from_ui": create_esx_storage_volume_from_ui,
            "create_esx_nfs_share_from_ui": create_esx_nfs_share_from_ui,
            "update_esx_nfs_share_from_ui": update_esx_nfs_share_from_ui,
            "delete_esx_nfs_share_from_ui": delete_esx_nfs_share_from_ui,
        },
    )
