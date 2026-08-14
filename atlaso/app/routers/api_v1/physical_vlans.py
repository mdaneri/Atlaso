"""Own physical-interface and VLAN API v1 transport handlers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi import Path as ApiPath
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import PhysicalInterface, VlanInterface
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    PhysicalInterfaceResponse,
    PhysicalInterfaceUpdate,
    VlanCreate,
    VlanResponse,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.interface_updates import (
    PhysicalInterfaceUpdateError,
    update_physical_interface_desired_state,
)
from atlaso.app.services.networking import sync_host_physical_interfaces

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class PhysicalVlanApiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    refresh_interface_service_dns_aliases: Endpoint
    validate_vlan_api_payload: Endpoint


@dataclass(frozen=True)
class PhysicalVlanApiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: PhysicalVlanApiDependencies) -> PhysicalVlanApiRouter:
    """Build the physical-interface and VLAN API v1 router.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured domain router and its stable endpoint callables.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)

    @router.get(
        "/interfaces/physical",
        response_model=list[PhysicalInterfaceResponse],
        tags=["Interfaces"],
        operation_id="listPhysicalInterfaces",
    )
    def list_physical_interfaces(
        identity: Annotated[Identity, Depends(require_scope("read:interfaces"))],
        db: Session = Depends(get_db),
    ) -> list[PhysicalInterfaceResponse]:
        """List Physical Interfaces.

        Requires the `read:interfaces` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            PhysicalInterfaceResponse.model_validate(row)
            for row in db.execute(select(PhysicalInterface)).scalars().all()
        ]

    @router.get(
        "/interfaces/physical/{name}",
        response_model=PhysicalInterfaceResponse,
        tags=["Interfaces"],
        operation_id="getPhysicalInterface",
    )
    def get_physical_interface(
        name: Annotated[
            str,
            ApiPath(description="Stable name identifying the resource addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:interfaces"))],
        db: Session = Depends(get_db),
    ) -> PhysicalInterfaceResponse:
        """Get Physical Interface.

        Requires the `read:interfaces` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            name: Stable name identifying the resource or operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == name)
        ).scalar_one_or_none()
        if not interface:
            raise HTTPException(status_code=404, detail="Interface not found")
        return PhysicalInterfaceResponse.model_validate(interface)

    @router.patch(
        "/interfaces/physical/{name}",
        response_model=PhysicalInterfaceResponse,
        tags=["Interfaces"],
        operation_id="updatePhysicalInterface",
    )
    def update_physical_interface(
        name: Annotated[
            str,
            ApiPath(description="Stable name identifying the resource addressed by this operation."),
        ],
        payload: PhysicalInterfaceUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
        db: Session = Depends(get_db),
    ) -> PhysicalInterfaceResponse:
        """Update Physical Interface Desired State.

        Requires the `write:interfaces` API scope. This operation validates and saves the supplied
        physical-interface fields, then atomically reconciles dependent DNS, NTP/NTS, Certificate
        Authority, KMS, LDAP, VCF service, ESX Storage, Web Terminal, DHCP, and Network Boot bindings.
        If any dependent update fails, Atlaso rolls back the interface and every dependent row. The
        call changes desired state only; the global Appliance Apply workflow remains the
        host-enforcement boundary.

        Args:
            name: Stable name identifying the resource or operation.
            payload: Typed partial physical-interface desired-state update.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == name)
        ).scalar_one_or_none()
        if not interface:
            raise HTTPException(status_code=404, detail="Interface not found")
        try:
            result = update_physical_interface_desired_state(
                db,
                interface,
                payload.model_dump(exclude_unset=True),
                dns_refresher=dependencies.refresh_interface_service_dns_aliases,
            )
        except PhysicalInterfaceUpdateError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
        detail_parts: list[str] = []
        if result.dependent_updates:
            detail_parts.append(
                "Refreshed dependent desired-state addresses: "
                f"{', '.join(result.dependent_updates)}."
            )
        if result.preserved_dhcp_dns:
            detail_parts.append(
                "Preserved DHCP-provided DNS in desired state: "
                f"{', '.join(result.preserved_dhcp_dns)}."
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_interface",
            resource_type="interface",
            resource_id=name,
            detail=" ".join(detail_parts),
        )
        return PhysicalInterfaceResponse.model_validate(result.interface)

    @router.post(
        "/interfaces/physical/{name}/enable",
        response_model=PhysicalInterfaceResponse,
        tags=["Interfaces"],
        operation_id="enablePhysicalInterface",
    )
    def enable_physical_interface(
        name: Annotated[
            str,
            ApiPath(description="Stable name identifying the resource addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
        db: Session = Depends(get_db),
    ) -> PhysicalInterfaceResponse:
        """Enable Physical Interface.

        Requires the `write:interfaces` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            name: Stable name identifying the physical interface.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return update_physical_interface(
            name,
            PhysicalInterfaceUpdate.model_validate({"admin_state": "up"}),
            identity,
            db,
        )

    @router.post(
        "/interfaces/physical/{name}/disable",
        response_model=PhysicalInterfaceResponse,
        tags=["Interfaces"],
        operation_id="disablePhysicalInterface",
    )
    def disable_physical_interface(
        name: Annotated[
            str,
            ApiPath(description="Stable name identifying the resource addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
        db: Session = Depends(get_db),
    ) -> PhysicalInterfaceResponse:
        """Disable Physical Interface.

        Requires the `write:interfaces` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            name: Stable name identifying the physical interface.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return update_physical_interface(
            name,
            PhysicalInterfaceUpdate.model_validate({"admin_state": "down"}),
            identity,
            db,
        )

    @router.post(
        "/interfaces/refresh",
        response_model=list[PhysicalInterfaceResponse],
        tags=["Interfaces"],
        operation_id="refreshPhysicalInterfaces",
    )
    def refresh_physical_interfaces(
        identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
        db: Session = Depends(get_db),
    ) -> list[PhysicalInterfaceResponse]:
        """Refresh Physical Interfaces.

        Requires the `write:interfaces` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        interfaces, discovered_count = sync_host_physical_interfaces(db)
        record_audit(
            db,
            actor=identity.username,
            action="refresh_physical_interface_inventory",
            resource_type="interface",
            detail=f"{discovered_count} host interface{'s' if discovered_count != 1 else ''} discovered",
        )
        return [PhysicalInterfaceResponse.model_validate(row) for row in interfaces]

    @router.get(
        "/vlans",
        response_model=list[VlanResponse],
        tags=["VLANs"],
        operation_id="listVlans",
    )
    def list_vlans(
        identity: Annotated[Identity, Depends(require_scope("read:vlans"))],
        db: Session = Depends(get_db),
    ) -> list[VlanResponse]:
        """List Vlans.

        Requires the `read:vlans` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            VlanResponse.model_validate(row)
            for row in db.execute(select(VlanInterface)).scalars().all()
        ]

    @router.post(
        "/vlans",
        response_model=VlanResponse,
        status_code=201,
        tags=["VLANs"],
        operation_id="createVlan",
    )
    def create_vlan(
        payload: VlanCreate,
        identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
        db: Session = Depends(get_db),
    ) -> VlanResponse:
        """Create Vlan.

        Requires the `write:vlans` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated VLAN desired-state payload.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        values = dependencies.validate_vlan_api_payload(payload, db)
        vlan = VlanInterface(
            name=f"{values['parent_interface']}.{values['vlan_id']}",
            **values,
        )
        db.add(vlan)
        db.commit()
        db.refresh(vlan)
        record_audit(
            db,
            actor=identity.username,
            action="create_vlan",
            resource_type="vlan",
            resource_id=str(vlan.id),
        )
        return VlanResponse.model_validate(vlan)

    @router.get(
        "/vlans/{vlan_id}",
        response_model=VlanResponse,
        tags=["VLANs"],
        operation_id="getVlan",
    )
    def get_vlan(
        vlan_id: Annotated[
            int,
            ApiPath(description="Unique identifier of the vlan record addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:vlans"))],
        db: Session = Depends(get_db),
    ) -> VlanResponse:
        """Get Vlan.

        Requires the `read:vlans` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            vlan_id: Stable identifier of the VLAN record.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        vlan = db.get(VlanInterface, vlan_id)
        if not vlan:
            raise HTTPException(status_code=404, detail="VLAN not found")
        return VlanResponse.model_validate(vlan)

    @router.patch(
        "/vlans/{vlan_id}",
        response_model=VlanResponse,
        tags=["VLANs"],
        operation_id="updateVlan",
    )
    def update_vlan(
        vlan_id: Annotated[
            int,
            ApiPath(description="Unique identifier of the vlan record addressed by this operation."),
        ],
        payload: VlanCreate,
        identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
        db: Session = Depends(get_db),
    ) -> VlanResponse:
        """Update Vlan.

        Requires the `write:vlans` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            vlan_id: Stable identifier of the VLAN record.
            payload: Validated VLAN desired-state payload.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        vlan = db.get(VlanInterface, vlan_id)
        if not vlan:
            raise HTTPException(status_code=404, detail="VLAN not found")
        values = dependencies.validate_vlan_api_payload(payload, db)
        for key, value in values.items():
            setattr(vlan, key, value)
        vlan.name = f"{vlan.parent_interface}.{vlan.vlan_id}"
        db.commit()
        db.refresh(vlan)
        record_audit(
            db,
            actor=identity.username,
            action="update_vlan",
            resource_type="vlan",
            resource_id=str(vlan.id),
        )
        return VlanResponse.model_validate(vlan)

    @router.delete(
        "/vlans/{vlan_id}",
        status_code=204,
        tags=["VLANs"],
        operation_id="deleteVlan",
    )
    def delete_vlan(
        vlan_id: Annotated[
            int,
            ApiPath(description="Unique identifier of the vlan record addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Vlan.

        Requires the `write:vlans` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            vlan_id: Stable identifier of the VLAN record.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        vlan = db.get(VlanInterface, vlan_id)
        if not vlan:
            raise HTTPException(status_code=404, detail="VLAN not found")
        db.delete(vlan)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vlan",
            resource_type="vlan",
            resource_id=str(vlan_id),
        )
        return Response(status_code=204)

    @router.post(
        "/vlans/{vlan_id}/enable",
        response_model=VlanResponse,
        tags=["VLANs"],
        operation_id="enableVlan",
    )
    def enable_vlan(
        vlan_id: Annotated[
            int,
            ApiPath(description="Unique identifier of the vlan record addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
        db: Session = Depends(get_db),
    ) -> VlanResponse:
        """Enable Vlan.

        Requires the `write:vlans` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            vlan_id: Stable identifier of the VLAN record.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        vlan = db.get(VlanInterface, vlan_id)
        if not vlan:
            raise HTTPException(status_code=404, detail="VLAN not found")
        parent = db.execute(
            select(PhysicalInterface).where(
                PhysicalInterface.name == vlan.parent_interface
            )
        ).scalar_one_or_none()
        if parent and parent.oper_state == "missing":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{vlan.parent_interface} is missing from host inventory. Move the VLAN to an "
                    "available trunk parent before enabling it."
                ),
            )
        vlan.enabled = True
        db.commit()
        db.refresh(vlan)
        record_audit(
            db,
            actor=identity.username,
            action="enable_vlan",
            resource_type="vlan",
            resource_id=str(vlan.id),
        )
        return VlanResponse.model_validate(vlan)

    @router.post(
        "/vlans/{vlan_id}/disable",
        response_model=VlanResponse,
        tags=["VLANs"],
        operation_id="disableVlan",
    )
    def disable_vlan(
        vlan_id: Annotated[
            int,
            ApiPath(description="Unique identifier of the vlan record addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
        db: Session = Depends(get_db),
    ) -> VlanResponse:
        """Disable Vlan.

        Requires the `write:vlans` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            vlan_id: Stable identifier of the VLAN record.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        vlan = db.get(VlanInterface, vlan_id)
        if not vlan:
            raise HTTPException(status_code=404, detail="VLAN not found")
        vlan.enabled = False
        db.commit()
        db.refresh(vlan)
        record_audit(
            db,
            actor=identity.username,
            action="disable_vlan",
            resource_type="vlan",
            resource_id=str(vlan.id),
        )
        return VlanResponse.model_validate(vlan)

    @router.post(
        "/vlans/{vlan_id}/apply",
        response_model=VlanResponse,
        tags=["VLANs"],
        operation_id="applyVlan",
    )
    def apply_vlan(
        vlan_id: Annotated[
            int,
            ApiPath(description="Unique identifier of the vlan record addressed by this operation."),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
        db: Session = Depends(get_db),
    ) -> VlanResponse:
        """Apply Vlan.

        Requires the `write:vlans` API scope. The action runs through the endpoint's existing audited
        adapter or task boundary; inspect the returned state before treating the operation as complete.

        Args:
            vlan_id: Stable identifier of the VLAN record.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        vlan = get_vlan(vlan_id, identity, db)
        record_audit(
            db,
            actor=identity.username,
            action="apply_vlan_dry_run",
            resource_type="vlan",
            resource_id=str(vlan_id),
        )
        return vlan

    endpoints: dict[str, Endpoint] = {
        "list_physical_interfaces": list_physical_interfaces,
        "get_physical_interface": get_physical_interface,
        "update_physical_interface": update_physical_interface,
        "enable_physical_interface": enable_physical_interface,
        "disable_physical_interface": disable_physical_interface,
        "refresh_physical_interfaces": refresh_physical_interfaces,
        "list_vlans": list_vlans,
        "create_vlan": create_vlan,
        "get_vlan": get_vlan,
        "update_vlan": update_vlan,
        "delete_vlan": delete_vlan,
        "enable_vlan": enable_vlan,
        "disable_vlan": disable_vlan,
        "apply_vlan": apply_vlan,
    }
    return PhysicalVlanApiRouter(router=router, endpoints=endpoints)
