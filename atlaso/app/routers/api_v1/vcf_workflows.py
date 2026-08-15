"""Own VCF workflow API v1 status transport handlers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import ServiceState, VcfRegistryBundle
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    ServiceStateResponse,
    VcfBackupStatusResponse,
    VcfOfflineDepotStatusResponse,
    VcfPrivateRegistryStatusResponse,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.vcf_backups import vcf_backup_settings_to_dict
from atlaso.app.services.vcf_private_registry import (
    validate_vcf_registry_state,
    vcf_registry_settings_to_dict,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class VcfWorkflowsApiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    build_vcf_offline_depot_status: Endpoint
    get_vcf_backup_settings: Endpoint
    get_vcf_private_registry_settings: Endpoint
    vcf_registry_ca_bundle_status: Endpoint


@dataclass(frozen=True)
class VcfWorkflowsApiRouters:
    """Return ordered status routers and compatibility endpoint exports."""

    backups_router: APIRouter
    offline_depot_router: APIRouter
    private_registry_router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_routers(
    dependencies: VcfWorkflowsApiDependencies,
) -> VcfWorkflowsApiRouters:
    """Build the segmented VCF workflows API v1 routers.

    Args:
        dependencies: Stable facade dependencies used by VCF status transports.
    """
    backups_router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    offline_depot_router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    private_registry_router = APIRouter(
        prefix="/api/v1", route_class=DocumentedAPIRoute
    )
    build_vcf_offline_depot_status = dependencies.build_vcf_offline_depot_status
    get_vcf_backup_settings = dependencies.get_vcf_backup_settings
    get_vcf_private_registry_settings = dependencies.get_vcf_private_registry_settings
    vcf_registry_ca_bundle_status = dependencies.vcf_registry_ca_bundle_status

    @backups_router.get(
        "/vcf-backups/status",
        response_model=VcfBackupStatusResponse,
        tags=["VCF Backups"],
        operation_id="getVcfBackupsStatus",
    )
    def get_vcf_backups_status(
        identity: Annotated[Identity, Depends(require_scope("read:vcf-backups"))],
        db: Session = Depends(get_db),
    ) -> VcfBackupStatusResponse:
        """Get Vcf Backups Status.

        Requires the `read:vcf-backups` API scope. This read-only operation does not change saved
        desired state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_vcf_backup_settings(db)
        row = db.execute(
            select(ServiceState).where(ServiceState.service == "vcf-backups")
        ).scalar_one_or_none()
        payload = vcf_backup_settings_to_dict(settings)
        return VcfBackupStatusResponse(
            enabled=settings.enabled,
            service=ServiceStateResponse.model_validate(row) if row else None,
            listen_interface=payload["listen_interface"],
            listen_address=payload["listen_address"],
            port=payload["port"],
            sftp_username=payload["sftp_username"] or None,
            storage_path=payload["storage_path"],
            remote_directory=payload["remote_directory"],
            config_path=payload["config_path"],
            dry_run=get_settings().dry_run_system_adapters,
        )

    @offline_depot_router.get(
        "/vcf-offline-depot/status",
        response_model=VcfOfflineDepotStatusResponse,
        tags=["VCF Offline Depot"],
        operation_id="getVcfOfflineDepotStatus",
    )
    def get_vcf_offline_depot_status(
        identity: Annotated[Identity, Depends(require_scope("read:repository"))],
        db: Session = Depends(get_db),
    ) -> VcfOfflineDepotStatusResponse:
        """Get Vcf Offline Depot Status.

        Requires the `read:repository` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return build_vcf_offline_depot_status(db)

    @private_registry_router.get(
        "/vcf-private-registry/status",
        response_model=VcfPrivateRegistryStatusResponse,
        tags=["VCF Private Registry"],
        operation_id="getVcfPrivateRegistryStatus",
    )
    def get_vcf_private_registry_status(
        identity: Annotated[Identity, Depends(require_scope("read:vcf-registry"))],
        db: Session = Depends(get_db),
    ) -> VcfPrivateRegistryStatusResponse:
        """Get Vcf Private Registry Status.

        Requires the `read:vcf-registry` API scope. This read-only operation does not change saved
        desired state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_vcf_private_registry_settings(db)
        bundles = (
            db.execute(select(VcfRegistryBundle).order_by(VcfRegistryBundle.name))
            .scalars()
            .all()
        )
        row = db.execute(
            select(ServiceState).where(ServiceState.service == "vcf-private-registry")
        ).scalar_one_or_none()
        ca_bundle_source, ca_bundle_available = vcf_registry_ca_bundle_status(db)
        validation_errors, _warnings = validate_vcf_registry_state(
            settings,
            bundles,
            ca_bundle_source=ca_bundle_source,
            ca_bundle_available=ca_bundle_available,
        )
        payload = vcf_registry_settings_to_dict(settings)
        return VcfPrivateRegistryStatusResponse(
            enabled=settings.enabled,
            service=ServiceStateResponse.model_validate(row) if row else None,
            hostname=str(payload["hostname"]),
            endpoint=str(payload["endpoint"]),
            listen_interface=str(payload["listen_interface"]),
            listen_address=str(payload["listen_address"]),
            port=int(payload["port"]),
            harbor_project=str(payload["harbor_project"]),
            storage_path=str(payload["storage_path"]),
            config_path=str(payload["config_path"]),
            bundle_count=len([bundle for bundle in bundles if bundle.enabled]),
            valid=not validation_errors,
            dry_run=get_settings().dry_run_system_adapters,
        )

    return VcfWorkflowsApiRouters(
        backups_router=backups_router,
        offline_depot_router=offline_depot_router,
        private_registry_router=private_registry_router,
        endpoints={
            "get_vcf_backups_status": get_vcf_backups_status,
            "get_vcf_offline_depot_status": get_vcf_offline_depot_status,
            "get_vcf_private_registry_status": get_vcf_private_registry_status,
        },
    )
