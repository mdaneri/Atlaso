"""Own physical-interface and VLAN management UI transport handlers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import PhysicalInterface, VlanInterface
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.interface_updates import (
    PhysicalInterfaceUpdateError,
    refresh_interface_dependent_addresses,
    update_physical_interface_desired_state,
)
from atlaso.app.services.networking import sync_host_physical_interfaces
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class PhysicalVlanUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    render: Callable[..., HTMLResponse]
    verify_csrf: Endpoint
    grid_saved_response: Callable[..., RedirectResponse | JSONResponse]
    grid_error_response: Callable[..., HTMLResponse | JSONResponse]
    network_context: Endpoint
    refresh_interface_service_dns_aliases: Endpoint
    validate_vlan_form_values: Endpoint
    vlan_form_validation_response: Callable[[Request, Response], Response | JSONResponse]
    appliance_apply_status: Endpoint
    vlan_interface_to_dict: Endpoint


@dataclass(frozen=True)
class PhysicalVlanUiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: PhysicalVlanUiDependencies) -> PhysicalVlanUiRouter:
    """Build the physical-interface and VLAN management UI router.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured domain router and its stable endpoint callables.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )

    @router.get("/physical-interfaces", response_class=HTMLResponse, response_model=None)
    def physical_interfaces_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the physical interfaces page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return dependencies.render(
            request,
            "physical_interfaces.html",
            {
                "identity": identity,
                **dependencies.network_context(db),
                "appliance_apply_status": dependencies.appliance_apply_status(db, "network"),
            },
        )

    @router.post("/physical-interfaces/refresh", response_model=None)
    def refresh_physical_interfaces_from_ui(
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the refresh physical interfaces from UI endpoint.

        Args:
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        dependencies.verify_csrf(request, csrf)
        _interfaces, discovered_count = sync_host_physical_interfaces(db)
        record_audit(
            db,
            actor=identity.username,
            action="refresh_physical_interface_inventory",
            resource_type="interface",
            detail=f"{discovered_count} host interface{'s' if discovered_count != 1 else ''} discovered",
        )
        return RedirectResponse("/physical-interfaces", status_code=303)

    @router.post("/physical-interfaces/{interface_id}/edit", response_model=None)
    def edit_physical_interface_from_ui(
        request: Request,
        interface_id: int,
        role: str = Form("unused"),
        mode: str = Form("unused"),
        ipv4_method: str = Form("static"),
        ip_cidr: str = Form(""),
        gateway: str | None = Form(None),
        ipv6_enabled: bool = Form(False),
        ipv6_cidr: str = Form(""),
        ipv6_gateway: str = Form(""),
        mtu: int = Form(1500),
        admin_state: str = Form("up"),
        access_management_ui_enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Update physical-interface desired state from the management UI.

        Args:
            request: Incoming HTTP request.
            interface_id: Identifier of the physical interface.
            role: Atlaso role used for authorization.
            mode: Operating mode selected for the workflow.
            ipv4_method: IPv4 address assignment method.
            ip_cidr: IPv4 network or address in CIDR notation.
            gateway: IPv4 gateway supplied by the caller.
            ipv6_enabled: Whether IPv6 desired state is enabled.
            ipv6_cidr: IPv6 network or address in CIDR notation.
            ipv6_gateway: IPv6 gateway supplied by the caller.
            mtu: Requested interface maximum transmission unit.
            admin_state: Requested administrative link state.
            access_management_ui_enabled: Whether the access interface exposes management UI.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        dependencies.verify_csrf(request, csrf)
        interface = db.get(PhysicalInterface, interface_id)
        if not interface:
            raise HTTPException(status_code=404, detail="Physical interface not found")
        changes = {
            "role": role,
            "mode": mode,
            "ipv4_method": ipv4_method,
            "ip_cidr": ip_cidr,
            "gateway": interface.gateway if gateway is None else gateway,
            "ipv6_enabled": bool(ipv6_enabled),
            "ipv6_cidr": ipv6_cidr,
            "ipv6_gateway": ipv6_gateway,
            "mtu": mtu,
            "admin_state": admin_state,
        }
        if access_management_ui_enabled is not None:
            changes["access_management_ui_enabled"] = access_management_ui_enabled == "on"
        try:
            result = update_physical_interface_desired_state(
                db,
                interface,
                changes,
                dns_refresher=dependencies.refresh_interface_service_dns_aliases,
            )
        except PhysicalInterfaceUpdateError as exc:
            return Response(exc.detail, status_code=exc.status_code, media_type="text/plain")
        detail_parts = []
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
            action="update_physical_interface",
            resource_type="interface",
            resource_id=result.interface.name,
            detail=" ".join(detail_parts),
        )
        return RedirectResponse("/physical-interfaces", status_code=303)

    @router.post("/physical-interfaces/{interface_id}/forget", response_model=None)
    def forget_missing_physical_interface_from_ui(
        request: Request,
        interface_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Forget a physical interface already marked missing from inventory.

        Args:
            request: Incoming HTTP request.
            interface_id: Identifier of the physical interface.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        dependencies.verify_csrf(request, csrf)
        interface = db.get(PhysicalInterface, interface_id)
        if not interface:
            raise HTTPException(status_code=404, detail="Physical interface not found")
        if interface.oper_state != "missing":
            return Response(
                "Only interfaces already marked missing from host inventory can be forgotten.",
                status_code=409,
                media_type="text/plain",
            )
        active_vlans = db.execute(
            select(VlanInterface).where(
                VlanInterface.parent_interface == interface.name,
                VlanInterface.enabled.is_(True),
            )
        ).scalars().all()
        if active_vlans:
            return Response(
                "Disable or move dependent VLAN interfaces before forgetting this missing interface.",
                status_code=409,
                media_type="text/plain",
            )
        disabled_vlans = db.execute(
            select(VlanInterface).where(VlanInterface.parent_interface == interface.name)
        ).scalars().all()
        old_name = interface.name
        try:
            dependent_updates = refresh_interface_dependent_addresses(
                db,
                old_name=old_name,
                new_name="",
                old_ip_cidr=interface.ip_cidr,
                old_ipv6_cidr=interface.ipv6_cidr,
                actor=None,
                dns_refresher=dependencies.refresh_interface_service_dns_aliases,
            )
            for vlan in disabled_vlans:
                db.delete(vlan)
            db.delete(interface)
            db.commit()
        except PhysicalInterfaceUpdateError as exc:
            db.rollback()
            return Response(exc.detail, status_code=exc.status_code, media_type="text/plain")
        details = [
            f"Forgot missing interface {old_name}; removed {len(disabled_vlans)} disabled dependent "
            f"VLAN row{'s' if len(disabled_vlans) != 1 else ''}."
        ]
        if dependent_updates:
            details.append(
                f"Refreshed dependent desired-state addresses: {', '.join(dependent_updates)}."
            )
        record_audit(
            db,
            actor=identity.username,
            action="forget_missing_physical_interface",
            resource_type="interface",
            resource_id=old_name,
            detail=" ".join(details),
        )
        return RedirectResponse("/physical-interfaces", status_code=303)

    @router.get("/vlan-interfaces", response_class=HTMLResponse, response_model=None)
    def vlan_interfaces_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the VLAN interfaces page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        return dependencies.render(
            request,
            "vlan_interfaces.html",
            {
                "identity": identity,
                **dependencies.network_context(db),
                "appliance_apply_status": dependencies.appliance_apply_status(db, "network"),
            },
        )

    @router.post("/vlan-interfaces", response_model=None)
    def create_vlan_interface_from_ui(
        request: Request,
        parent_interface: str = Form(...),
        vlan_id: str = Form(""),
        ip_cidr: str = Form(""),
        ipv6_cidr: str = Form(""),
        mtu: int = Form(1500),
        role: str = Form("access"),
        enabled: str | None = Form(None),
        access_management_ui_enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse | Response:
        """Create VLAN desired state from the management UI.

        Args:
            request: Incoming HTTP request.
            parent_interface: Parent physical interface name.
            vlan_id: Requested VLAN identifier.
            ip_cidr: IPv4 network or address in CIDR notation.
            ipv6_cidr: IPv6 network or address in CIDR notation.
            mtu: Requested interface maximum transmission unit.
            role: Requested VLAN role.
            enabled: Whether the VLAN is administratively enabled.
            access_management_ui_enabled: Whether the access VLAN exposes management UI.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        dependencies.verify_csrf(request, csrf)
        requested_enabled = enabled == "on"
        parsed = dependencies.validate_vlan_form_values(
            parent_interface, vlan_id, ip_cidr, ipv6_cidr, mtu, role, requested_enabled, db
        )
        if isinstance(parsed, Response):
            return dependencies.vlan_form_validation_response(request, parsed)
        parent_name, parsed_vlan_id, ip_value, ipv6_value, mtu_value, role_value, parent_missing = parsed
        management_ui_value = access_management_ui_enabled == "on"
        if management_ui_value and role_value != "access":
            return dependencies.vlan_form_validation_response(
                request,
                Response(
                    "Management UI exposure is available only for an access-role VLAN.",
                    status_code=422,
                    media_type="text/plain",
                ),
            )
        vlan = VlanInterface(
            name=f"{parent_name}.{parsed_vlan_id}",
            parent_interface=parent_name,
            vlan_id=parsed_vlan_id,
            ip_cidr=ip_value,
            ipv6_cidr=ipv6_value,
            mtu=mtu_value,
            role=role_value,
            enabled=requested_enabled and not parent_missing,
            access_management_ui_enabled=management_ui_value,
        )
        db.add(vlan)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return dependencies.grid_error_response(
                request,
                detail=f"VLAN {vlan.name} already exists.",
                status_code=409,
                template_name="vlan_interfaces.html",
                context={
                    "identity": identity,
                    **dependencies.network_context(db),
                    "form_error": f"VLAN {vlan.name} already exists.",
                },
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_vlan_interface",
            resource_type="vlan",
            resource_id=str(vlan.id),
        )
        return dependencies.grid_saved_response(
            request,
            redirect_url="/vlan-interfaces",
            resource_name="vlan",
            resource=dependencies.vlan_interface_to_dict(vlan, parent_missing=parent_missing),
        )

    @router.post("/vlan-interfaces/{vlan_id}/edit", response_model=None)
    def edit_vlan_interface_from_ui(
        request: Request,
        vlan_id: int,
        parent_interface: str = Form(...),
        vlan_id_value: str = Form("", alias="vlan_id"),
        ip_cidr: str = Form(""),
        ipv6_cidr: str = Form(""),
        mtu: int = Form(1500),
        role: str = Form("access"),
        enabled: str | None = Form(None),
        access_management_ui_enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse | Response:
        """Update VLAN desired state from the management UI.

        Args:
            request: Incoming HTTP request.
            vlan_id: Stable identifier of the VLAN record.
            parent_interface: Parent physical interface name.
            vlan_id_value: Requested VLAN identifier from the aliased form field.
            ip_cidr: IPv4 network or address in CIDR notation.
            ipv6_cidr: IPv6 network or address in CIDR notation.
            mtu: Requested interface maximum transmission unit.
            role: Requested VLAN role.
            enabled: Whether the VLAN is administratively enabled.
            access_management_ui_enabled: Whether the access VLAN exposes management UI.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        dependencies.verify_csrf(request, csrf)
        vlan = db.get(VlanInterface, vlan_id)
        if not vlan:
            raise HTTPException(status_code=404, detail="VLAN interface not found")
        requested_enabled = enabled == "on"
        parsed = dependencies.validate_vlan_form_values(
            parent_interface,
            vlan_id_value,
            ip_cidr,
            ipv6_cidr,
            mtu,
            role,
            requested_enabled,
            db,
        )
        if isinstance(parsed, Response):
            return dependencies.vlan_form_validation_response(request, parsed)
        parent_name, parsed_vlan_id, ip_value, ipv6_value, mtu_value, role_value, parent_missing = parsed
        management_ui_value = access_management_ui_enabled == "on"
        if management_ui_value and role_value != "access":
            return dependencies.vlan_form_validation_response(
                request,
                Response(
                    "Management UI exposure is available only for an access-role VLAN.",
                    status_code=422,
                    media_type="text/plain",
                ),
            )
        old_name = vlan.name
        old_ip_cidr = vlan.ip_cidr
        old_ipv6_cidr = vlan.ipv6_cidr
        vlan.parent_interface = parent_name
        vlan.vlan_id = parsed_vlan_id
        vlan.name = f"{vlan.parent_interface}.{vlan.vlan_id}"
        vlan.ip_cidr = ip_value
        vlan.ipv6_cidr = ipv6_value
        vlan.mtu = mtu_value
        vlan.role = role_value
        vlan.enabled = requested_enabled and not parent_missing
        vlan.access_management_ui_enabled = management_ui_value
        try:
            dependent_updates = refresh_interface_dependent_addresses(
                db,
                old_name=old_name,
                new_name=vlan.name,
                old_ip_cidr=old_ip_cidr,
                old_ipv6_cidr=old_ipv6_cidr,
                actor=None,
                dns_refresher=dependencies.refresh_interface_service_dns_aliases,
            )
            db.commit()
        except PhysicalInterfaceUpdateError as exc:
            db.rollback()
            return dependencies.vlan_form_validation_response(
                request,
                Response(exc.detail, status_code=exc.status_code, media_type="text/plain"),
            )
        except IntegrityError:
            db.rollback()
            return dependencies.grid_error_response(
                request,
                detail=f"VLAN {vlan.name} already exists.",
                status_code=409,
                template_name="vlan_interfaces.html",
                context={
                    "identity": identity,
                    **dependencies.network_context(db),
                    "form_error": f"VLAN {vlan.name} already exists.",
                },
            )
        detail = (
            f"Refreshed dependent desired-state addresses: {', '.join(dependent_updates)}."
            if dependent_updates
            else ""
        )
        record_audit(
            db,
            actor=identity.username,
            action="update_vlan_interface",
            resource_type="vlan",
            resource_id=str(vlan.id),
            detail=detail,
        )
        return dependencies.grid_saved_response(
            request,
            redirect_url="/vlan-interfaces",
            resource_name="vlan",
            resource=dependencies.vlan_interface_to_dict(vlan, parent_missing=parent_missing),
        )

    @router.post("/vlan-interfaces/{vlan_id}/delete", response_model=None)
    def delete_vlan_interface_from_ui(
        request: Request,
        vlan_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response | JSONResponse:
        """Delete VLAN desired state from the management UI.

        Args:
            request: Incoming HTTP request.
            vlan_id: Stable identifier of the VLAN record.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        dependencies.verify_csrf(request, csrf)
        vlan = db.get(VlanInterface, vlan_id)
        if not vlan:
            raise HTTPException(status_code=404, detail="VLAN interface not found")
        old_name = vlan.name
        old_ip_cidr = vlan.ip_cidr
        old_ipv6_cidr = vlan.ipv6_cidr
        try:
            db.delete(vlan)
            db.flush()
            dependent_updates = refresh_interface_dependent_addresses(
                db,
                old_name=old_name,
                new_name="",
                old_ip_cidr=old_ip_cidr,
                old_ipv6_cidr=old_ipv6_cidr,
                actor=None,
                dns_refresher=dependencies.refresh_interface_service_dns_aliases,
            )
            db.commit()
        except PhysicalInterfaceUpdateError as exc:
            db.rollback()
            return dependencies.vlan_form_validation_response(
                request,
                Response(exc.detail, status_code=exc.status_code, media_type="text/plain"),
            )
        details: list[str] = []
        if dependent_updates:
            details.append(
                f"Refreshed dependent desired-state addresses: {', '.join(dependent_updates)}."
            )
        record_audit(
            db,
            actor=identity.username,
            action="delete_vlan_interface",
            resource_type="vlan",
            resource_id=str(vlan_id),
            detail=" ".join(details),
        )
        return RedirectResponse("/vlan-interfaces", status_code=303)

    endpoints: dict[str, Endpoint] = {
        "physical_interfaces_page": physical_interfaces_page,
        "refresh_physical_interfaces_from_ui": refresh_physical_interfaces_from_ui,
        "edit_physical_interface_from_ui": edit_physical_interface_from_ui,
        "forget_missing_physical_interface_from_ui": forget_missing_physical_interface_from_ui,
        "vlan_interfaces_page": vlan_interfaces_page,
        "create_vlan_interface_from_ui": create_vlan_interface_from_ui,
        "edit_vlan_interface_from_ui": edit_vlan_interface_from_ui,
        "delete_vlan_interface_from_ui": delete_vlan_interface_from_ui,
    }
    return PhysicalVlanUiRouter(router=router, endpoints=endpoints)
