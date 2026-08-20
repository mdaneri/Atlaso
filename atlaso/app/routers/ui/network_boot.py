"""Own Network Boot and ESXi PXE management UI transport handlers."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import EsxiKickstart, EsxiPxeHost, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.esxi_pxe import (
    ESXI_PXE_DEFAULT_HOSTNAME,
    ESXI_PXE_HTTP_PORT,
    assign_kickstart_content,
    canonical_http_path,
    content_hash,
    custom_variable_definitions,
    decode_kickstart_upload,
    delete_custom_variable_definition,
    esxi_pxe_boot_settings,
    esxi_pxe_default_host_settings,
    generated_kickstart_path,
    host_to_dict,
    host_variables_json,
    kickstart_validation,
    normalize_host_mac,
    normalize_installer_iso_path,
    normalize_kickstart_content,
    normalize_kickstart_name,
    save_custom_variable_definition,
    save_esxi_pxe_boot_settings,
    save_esxi_pxe_default_host_settings,
    store_installer_iso_upload,
    strict_validation_enabled,
    sync_esxi_pxe_host_network_records,
    validate_kickstart_custom_references,
    validate_kickstart_vault_references,
)
from atlaso.app.services.network_boot import (
    remove_esxi_host_discovery_state,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class NetworkBootUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    appliance_apply_status: Endpoint
    ensure_dns_for_esxi_pxe: Endpoint
    esxi_kickstart_grid_payload: Endpoint
    esxi_pxe_context: Endpoint
    esxi_pxe_page_context: Endpoint
    grid_saved_response: Endpoint
    next_kickstart_copy_name: Endpoint
    parse_optional_esxi_kickstart_id: Endpoint
    render: Endpoint
    require_esxi_pxe_write: Endpoint
    resolve_service_bind_targets: Endpoint
    verify_csrf: Endpoint
    kickstart_reference_validation_error: str
    kickstart_upload_error: str


@dataclass(frozen=True)
class NetworkBootUiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: NetworkBootUiDependencies) -> NetworkBootUiRouter:
    """Build the Network Boot and ESXi PXE management UI router.

    Args:
        dependencies: Stable facade dependencies used by Network Boot transports.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    appliance_apply_status = dependencies.appliance_apply_status
    ensure_dns_for_esxi_pxe = dependencies.ensure_dns_for_esxi_pxe
    esxi_kickstart_grid_payload = dependencies.esxi_kickstart_grid_payload
    esxi_pxe_context = dependencies.esxi_pxe_context
    esxi_pxe_page_context = dependencies.esxi_pxe_page_context
    grid_saved_response = dependencies.grid_saved_response
    next_kickstart_copy_name = dependencies.next_kickstart_copy_name
    parse_optional_esxi_kickstart_id = dependencies.parse_optional_esxi_kickstart_id
    render = dependencies.render
    require_esxi_pxe_write = dependencies.require_esxi_pxe_write
    resolve_service_bind_targets = dependencies.resolve_service_bind_targets
    verify_csrf = dependencies.verify_csrf
    KICKSTART_REFERENCE_VALIDATION_ERROR = (
        dependencies.kickstart_reference_validation_error
    )
    KICKSTART_UPLOAD_ERROR = dependencies.kickstart_upload_error

    @router.get("/esxi-pxe", response_model=None)
    def esxi_pxe_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
    ) -> RedirectResponse:
        """Handle the esxi pxe page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.

        Returns:
            The endpoint response.
        """
        query = f"?{request.url.query}" if request.url.query else ""
        fragment = request.url.fragment
        suffix = f"#{fragment}" if fragment else ""
        return RedirectResponse(f"/network-boot{query}{suffix}", status_code=307)

    @router.get("/network-boot", response_class=HTMLResponse, response_model=None)
    def network_boot_page(
        request: Request,
        kickstart_id: int | None = None,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the network boot page endpoint.

        Args:
            request: Incoming HTTP request.
            kickstart_id: Identifier of the kickstart.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "esxi_pxe.html",
            {
                "identity": identity,
                **esxi_pxe_page_context(db, identity, selected_id=kickstart_id),
                "appliance_apply_status": appliance_apply_status(db, "esxi_pxe"),
            },
        )

    @router.post("/esxi-pxe/boot-settings", response_model=None)
    def update_esxi_pxe_boot_settings_from_ui(
        request: Request,
        enabled: bool = Form(False),
        hostname: str = Form(ESXI_PXE_DEFAULT_HOSTNAME),
        dhcp_scope_id: str = Form(""),
        dhcp_scope_ids: list[str] = Form(default=[]),
        listen_interfaces: list[str] = Form(default=[]),
        listen_addresses: list[str] = Form(default=[]),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        listen_interface: str = Form(""),
        listen_address: str = Form(""),
        tftp_root: str = Form(...),
        http_port: int = Form(ESXI_PXE_HTTP_PORT),
        bios_bootfile: str = Form(...),
        uefi_bootfile: str = Form(...),
        native_uefi_http_enabled: bool = Form(False),
        native_uefi_http_url: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the update esxi pxe boot settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            hostname: DNS hostname of the target resource.
            dhcp_scope_id: Identifier of the dhcp scope.
            dhcp_scope_ids: Dhcp scope ids supplied by the caller.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            listen_interface: Interface on which the service should listen.
            listen_address: Address on which the service should listen.
            tftp_root: Tftp root supplied by the caller.
            http_port: Http port supplied by the caller.
            bios_bootfile: Bios bootfile supplied by the caller.
            uefi_bootfile: Uefi bootfile supplied by the caller.
            native_uefi_http_enabled: Native uefi http enabled supplied by the caller.
            native_uefi_http_url: URL for the native uefi http.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        previous_boot = esxi_pxe_boot_settings(db)
        selected_interfaces, selected_addresses = resolve_service_bind_targets(
            db,
            [*listen_interfaces, listen_interface],
            [*listen_addresses, listen_address],
            current_interface=str(previous_boot.get("listen_interface") or ""),
            current_address=str(previous_boot.get("listen_address") or ""),
            listen_interfaces_present=listen_interfaces_present,
            listen_addresses_present=listen_addresses_present,
        )
        try:
            boot = save_esxi_pxe_boot_settings(
                db,
                enabled=enabled,
                hostname=hostname,
                listen_interface=selected_interfaces,
                listen_address=selected_addresses,
                dhcp_scope_id=dhcp_scope_id,
                dhcp_scope_ids=dhcp_scope_ids
                or ([dhcp_scope_id] if dhcp_scope_id else []),
                tftp_root=tftp_root,
                http_port=http_port,
                bios_bootfile=bios_bootfile,
                uefi_bootfile=uefi_bootfile,
                native_uefi_http_enabled=native_uefi_http_enabled,
                native_uefi_http_url=native_uefi_http_url,
            )
            dns_record_action = ensure_dns_for_esxi_pxe(
                db,
                boot,
                identity.username,
                previous_hostname=str(previous_boot.get("hostname") or ""),
            )
            db.commit()
        except ValueError as exc:
            db.rollback()
            return render(
                request,
                "esxi_pxe.html",
                {
                    "identity": identity,
                    **esxi_pxe_page_context(db, identity, error=str(exc)),
                    "appliance_apply_status": appliance_apply_status(db, "esxi_pxe"),
                },
                status_code=400,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_pxe_boot_settings",
            resource_type="esxi_pxe_boot",
            resource_id="default",
            detail=f"enabled={boot['enabled']} native_uefi_http_enabled={boot['native_uefi_http_enabled']} tftp_root={boot['tftp_root']} http_port={boot['http_port']}",
            request_id=request.state.request_id,
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = esxi_pxe_context(db)
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": utcnow().isoformat(),
                    "hostname": context["esxi_pxe_boot"]["hostname"],
                    "listen_address": context["esxi_pxe_primary_listen_address"],
                    "bind_label": context["esxi_pxe_bind_label"],
                    "dns_record_action": dns_record_action,
                    "validation_errors": context["esxi_pxe_validation_errors"],
                    "validation_warnings": context["esxi_pxe_validation_warnings"],
                }
            )
        return RedirectResponse("/esxi-pxe", status_code=303)

    @router.post("/esxi-pxe/kickstarts", response_model=None)
    def create_esxi_kickstart_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        content: str = Form(...),
        enabled: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the create esxi kickstart from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            content: Document or file content to process.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        try:
            kickstart = EsxiKickstart(
                name=normalize_kickstart_name(name),
                description=description or None,
                content="",
                content_hash="",
                enabled=enabled,
            )
            db.add(kickstart)
            db.flush()
            assign_kickstart_content(
                kickstart, content, max_bytes=get_settings().esxi_kickstart_max_bytes
            )
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
            db.commit()
        except (ValueError, IntegrityError) as exc:
            db.rollback()
            detail = (
                "A Kickstart with that name already exists."
                if isinstance(exc, IntegrityError)
                else KICKSTART_REFERENCE_VALIDATION_ERROR
            )
            if "application/json" in request.headers.get("accept", ""):
                return JSONResponse({"detail": detail}, status_code=400)
            return render(
                request,
                "esxi_pxe.html",
                {
                    "identity": identity,
                    **esxi_pxe_page_context(db, identity, error=detail),
                    "appliance_apply_status": appliance_apply_status(db, "esxi_pxe"),
                },
                status_code=400,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"name={kickstart.name} hash={kickstart.content_hash}",
            request_id=request.state.request_id,
        )
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse(
                {
                    "kickstart": esxi_kickstart_grid_payload(
                        kickstart, include_content=True
                    )
                }
            )
        return RedirectResponse(
            f"/esxi-pxe?kickstart_id={kickstart.id}", status_code=303
        )

    @router.post("/esxi-pxe/kickstarts/upload", response_model=None)
    async def upload_esxi_kickstart_from_ui(
        request: Request,
        kickstart_file: UploadFile = File(...),
        name: str = Form(""),
        description: str = Form(""),
        enabled: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the upload esxi kickstart from ui endpoint.

        Args:
            request: Incoming HTTP request.
            kickstart_file: Kickstart file supplied by the caller.
            name: Name of the target object.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        try:
            content = decode_kickstart_upload(
                await kickstart_file.read(),
                max_bytes=get_settings().esxi_kickstart_max_bytes,
            )
            kickstart = EsxiKickstart(
                name=normalize_kickstart_name(
                    name or Path(kickstart_file.filename or "uploaded-kickstart").stem
                ),
                description=description or None,
                content=content,
                content_hash=content_hash(content),
                rendered_content=content,
                enabled=enabled,
            )
            db.add(kickstart)
            db.flush()
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
            kickstart.http_path = canonical_http_path(
                kickstart.id, kickstart.content_hash
            )
            db.commit()
        except ValueError, IntegrityError:
            db.rollback()
            return render(
                request,
                "esxi_pxe.html",
                {
                    "identity": identity,
                    **esxi_pxe_page_context(db, identity, error=KICKSTART_UPLOAD_ERROR),
                    "appliance_apply_status": appliance_apply_status(db, "esxi_pxe"),
                },
                status_code=400,
            )
        record_audit(
            db,
            actor=identity.username,
            action="upload_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"name={kickstart.name} hash={kickstart.content_hash}",
            request_id=request.state.request_id,
        )
        return RedirectResponse(
            f"/esxi-pxe?kickstart_id={kickstart.id}", status_code=303
        )

    @router.post("/esxi-pxe/kickstarts/{kickstart_id}", response_model=None)
    def update_esxi_kickstart_from_ui(
        kickstart_id: int,
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        content: str = Form(...),
        enabled: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Handle the update esxi kickstart from ui endpoint.

        Args:
            kickstart_id: Identifier of the kickstart.
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            content: Document or file content to process.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        try:
            kickstart.name = normalize_kickstart_name(name)
            kickstart.description = description or None
            kickstart.enabled = enabled
            assign_kickstart_content(
                kickstart, content, max_bytes=get_settings().esxi_kickstart_max_bytes
            )
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
            db.add(kickstart)
            db.commit()
        except (ValueError, IntegrityError) as exc:
            db.rollback()
            detail = (
                "A Kickstart with that name already exists."
                if isinstance(exc, IntegrityError)
                else KICKSTART_REFERENCE_VALIDATION_ERROR
            )
            if "application/json" in request.headers.get("accept", ""):
                return JSONResponse({"detail": detail}, status_code=400)
            return render(
                request,
                "esxi_pxe.html",
                {
                    "identity": identity,
                    **esxi_pxe_page_context(
                        db, identity, selected_id=kickstart_id, error=detail
                    ),
                    "appliance_apply_status": appliance_apply_status(db, "esxi_pxe"),
                },
                status_code=400,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"name={kickstart.name} hash={kickstart.content_hash}",
            request_id=request.state.request_id,
        )
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse(
                {
                    "kickstart": esxi_kickstart_grid_payload(
                        kickstart, include_content=True
                    )
                }
            )
        return RedirectResponse(
            f"/esxi-pxe?kickstart_id={kickstart.id}", status_code=303
        )

    @router.post("/esxi-pxe/kickstarts/{kickstart_id}/duplicate", response_model=None)
    def duplicate_esxi_kickstart_from_ui(
        kickstart_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the duplicate esxi kickstart from ui endpoint.

        Args:
            kickstart_id: Identifier of the kickstart.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        source = db.get(EsxiKickstart, kickstart_id)
        if not source:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        duplicate = EsxiKickstart(
            name=next_kickstart_copy_name(db, source.name),
            description=source.description,
            content=source.content,
            content_hash=source.content_hash,
            rendered_content=source.rendered_content,
            enabled=source.enabled,
        )
        db.add(duplicate)
        db.flush()
        duplicate.http_path = canonical_http_path(duplicate.id, duplicate.content_hash)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="duplicate_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(duplicate.id),
            detail=f"source_id={source.id} name={duplicate.name}",
            request_id=request.state.request_id,
        )
        return RedirectResponse(
            f"/esxi-pxe?kickstart_id={duplicate.id}", status_code=303
        )

    @router.post("/esxi-pxe/kickstarts/{kickstart_id}/delete", response_model=None)
    def delete_esxi_kickstart_from_ui(
        kickstart_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete esxi kickstart from ui endpoint.

        Args:
            kickstart_id: Identifier of the kickstart.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        for host in (
            db.execute(
                select(EsxiPxeHost).where(EsxiPxeHost.kickstart_id == kickstart.id)
            )
            .scalars()
            .all()
        ):
            host.kickstart_id = None
            host.updated_at = utcnow()
            db.add(host)
        db.delete(kickstart)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart_id),
            request_id=request.state.request_id,
        )
        return RedirectResponse("/esxi-pxe", status_code=303)

    @router.post(
        "/esxi-pxe/kickstarts/{kickstart_id}/validate",
        response_class=HTMLResponse,
        response_model=None,
    )
    def validate_esxi_kickstart_from_ui(
        kickstart_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the validate esxi kickstart from ui endpoint.

        Args:
            kickstart_id: Identifier of the kickstart.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        errors, warnings = kickstart_validation(
            kickstart.content,
            strict=strict_validation_enabled(db),
            max_bytes=get_settings().esxi_kickstart_max_bytes,
        )
        try:
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
        except ValueError:
            errors.append(KICKSTART_REFERENCE_VALIDATION_ERROR)
        record_audit(
            db,
            actor=identity.username,
            action="validate_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"errors={len(errors)} warnings={len(warnings)}",
            request_id=request.state.request_id,
        )
        return render(
            request,
            "esxi_pxe.html",
            {
                "identity": identity,
                **esxi_pxe_page_context(
                    db,
                    identity,
                    selected_id=kickstart_id,
                    result={
                        "title": "Validation complete",
                        "message": f"{len(errors)} errors, {len(warnings)} warnings.",
                    },
                ),
                "appliance_apply_status": appliance_apply_status(db, "esxi_pxe"),
            },
        )

    @router.get("/esxi-pxe/kickstarts/{kickstart_id}/download", response_model=None)
    def download_esxi_kickstart_from_ui(
        kickstart_id: int,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download esxi kickstart from ui endpoint.

        Args:
            kickstart_id: Identifier of the kickstart.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        filename = (
            re.sub(r"[^A-Za-z0-9_.-]+", "-", kickstart.name).strip("-")
            or f"kickstart-{kickstart.id}"
        )
        return Response(
            kickstart.content,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}.cfg"'},
        )

    @router.post("/esxi-pxe/custom-variables", response_model=None)
    def create_esxi_custom_variable_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        default_value: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the create esxi custom variable from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            default_value: Default value supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        try:
            variable = save_custom_variable_definition(
                db,
                name=name,
                description=description,
                default_value=default_value,
            )
            db.commit()
        except ValueError:
            db.rollback()
            return JSONResponse(
                {"detail": "Custom variable definition is invalid."}, status_code=400
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_esxi_custom_variable",
            resource_type="esxi_custom_variable",
            resource_id=variable["name"],
            detail=f"name={variable['name']}",
            request_id=request.state.request_id,
        )
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"variable": variable})
        return RedirectResponse(
            "/esxi-pxe#esxi-pxe-custom-variables-panel", status_code=303
        )

    @router.post("/esxi-pxe/custom-variables/{variable_name}", response_model=None)
    def update_esxi_custom_variable_from_ui(
        variable_name: str,
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        default_value: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update esxi custom variable from ui endpoint.

        Args:
            variable_name: Variable name supplied by the caller.
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            default_value: Default value supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        if variable_name not in {
            item["name"] for item in custom_variable_definitions(db)
        }:
            raise HTTPException(status_code=404, detail="Custom variable not found")
        try:
            variable = save_custom_variable_definition(
                db,
                name=name,
                description=description,
                default_value=default_value,
                original_name=variable_name,
            )
            db.commit()
        except ValueError:
            db.rollback()
            return JSONResponse(
                {"detail": "Custom variable definition is invalid."}, status_code=400
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_custom_variable",
            resource_type="esxi_custom_variable",
            resource_id=variable["name"],
            detail=f"previous_name={variable_name} name={variable['name']}",
            request_id=request.state.request_id,
        )
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"variable": variable})
        return RedirectResponse(
            "/esxi-pxe#esxi-pxe-custom-variables-panel", status_code=303
        )

    @router.post(
        "/esxi-pxe/custom-variables/{variable_name}/delete", response_model=None
    )
    def delete_esxi_custom_variable_from_ui(
        variable_name: str,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the delete esxi custom variable from ui endpoint.

        Args:
            variable_name: Variable name supplied by the caller.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        if not delete_custom_variable_definition(db, variable_name):
            raise HTTPException(status_code=404, detail="Custom variable not found")
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_esxi_custom_variable",
            resource_type="esxi_custom_variable",
            resource_id=variable_name,
            request_id=request.state.request_id,
        )
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"deleted": variable_name})
        return RedirectResponse(
            "/esxi-pxe#esxi-pxe-custom-variables-panel", status_code=303
        )

    @router.post("/esxi-pxe/isos/upload", response_model=None)
    async def upload_esxi_installer_iso_from_ui(
        request: Request,
        iso_file: UploadFile = File(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the upload esxi installer iso from ui endpoint.

        Args:
            request: Incoming HTTP request.
            iso_file: Iso file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        wants_json = request.headers.get("X-Atlaso-Upload") == "1"
        try:
            iso = await store_installer_iso_upload(
                iso_file, max_bytes=get_settings().esxi_installer_iso_max_bytes
            )
        except ValueError as exc:
            status_code = 413 if "too large" in str(exc).lower() else 400
            if wants_json:
                # The upload service emits only reviewed, user-safe validation messages.
                # codeql[py/stack-trace-exposure]
                return JSONResponse(
                    {"status": "error", "detail": str(exc)}, status_code=status_code
                )
            return render(
                request,
                "esxi_pxe.html",
                {
                    "identity": identity,
                    **esxi_pxe_page_context(db, identity, error=str(exc)),
                    "appliance_apply_status": appliance_apply_status(db, "esxi_pxe"),
                },
                status_code=status_code,
            )
        upload_event = record_audit(
            db,
            actor=identity.username,
            action="upload_esxi_installer_iso",
            resource_type="esxi_installer_iso",
            resource_id=iso["relative_path"],
            detail=f"path={iso['path']} size={iso['size_bytes']}",
            request_id=request.state.request_id,
        )
        if wants_json:
            return JSONResponse(
                {
                    "status": "uploaded",
                    **iso,
                    "source": "uploaded",
                    "source_label": "Uploaded by user",
                    "source_at": upload_event.created_at.isoformat(),
                }
            )
        return RedirectResponse("/esxi-pxe#esxi-pxe-isos-panel", status_code=303)

    @router.post("/esxi-pxe/isos/delete", response_model=None)
    def delete_esxi_installer_iso_from_ui(
        request: Request,
        installer_iso_path: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete esxi installer iso from ui endpoint.

        Args:
            request: Incoming HTTP request.
            installer_iso_path: Filesystem path for the installer iso.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        try:
            normalized_path = normalize_installer_iso_path(installer_iso_path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        path = Path(normalized_path)
        # The normalizer resolves the path and proves containment beneath the managed ISO root.
        # codeql[py/path-injection]
        if not path.exists():
            raise HTTPException(status_code=404, detail="Installer ISO not found")
        # The same containment proof applies to the deletion sink below.
        # codeql[py/path-injection]
        path.unlink()
        cleared_hosts = 0
        for host in (
            db.execute(
                select(EsxiPxeHost).where(
                    EsxiPxeHost.installer_iso_path == normalized_path
                )
            )
            .scalars()
            .all()
        ):
            host.installer_iso_path = ""
            host.updated_at = utcnow()
            db.add(host)
            cleared_hosts += 1
        default_host = esxi_pxe_default_host_settings(db)
        cleared_default = default_host.get("installer_iso_path") == normalized_path
        if cleared_default:
            save_esxi_pxe_default_host_settings(
                db,
                enabled=bool(default_host.get("enabled")),
                kickstart_id=default_host.get("kickstart_id"),
                installer_iso_path="",
            )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_esxi_installer_iso",
            resource_type="esxi_installer_iso",
            resource_id=path.name,
            detail=f"path={normalized_path} cleared_hosts={cleared_hosts} cleared_default={cleared_default}",
            request_id=request.state.request_id,
        )
        return RedirectResponse("/esxi-pxe#esxi-pxe-isos-panel", status_code=303)

    @router.post(
        "/esxi-pxe/kickstarts/{kickstart_id}/import-filesystem", response_model=None
    )
    def import_esxi_kickstart_filesystem_copy(
        kickstart_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the import esxi kickstart filesystem copy endpoint.

        Args:
            kickstart_id: Identifier of the kickstart.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        path = generated_kickstart_path(kickstart.id, kickstart.content_hash)
        if not path.is_file():
            raise HTTPException(
                status_code=404, detail="Generated Kickstart file not found"
            )
        assign_kickstart_content(
            kickstart,
            normalize_kickstart_content(
                path.read_text(encoding="utf-8"),
                max_bytes=get_settings().esxi_kickstart_max_bytes,
            ),
            max_bytes=get_settings().esxi_kickstart_max_bytes,
        )
        db.add(kickstart)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="import_esxi_kickstart_from_filesystem",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"path={path} hash={kickstart.content_hash}",
            request_id=request.state.request_id,
        )
        return RedirectResponse(
            f"/esxi-pxe?kickstart_id={kickstart.id}", status_code=303
        )

    @router.post("/esxi-pxe/hosts", response_model=None)
    def create_esxi_pxe_host_from_ui(
        request: Request,
        hostname: str = Form(...),
        mac_address: str = Form(...),
        ip_address: str = Form(""),
        kickstart_id: str = Form(""),
        installer_iso_path: str = Form(""),
        variables: str = Form("{}"),
        enabled: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the create esxi pxe host from ui endpoint.

        Args:
            request: Incoming HTTP request.
            hostname: DNS hostname of the target resource.
            mac_address: MAC address identifying the host or interface.
            ip_address: Ip address supplied by the caller.
            kickstart_id: Identifier of the kickstart.
            installer_iso_path: Filesystem path for the installer iso.
            variables: Variables supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            ValueError: If an input value is invalid.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        normalized_kickstart_id = parse_optional_esxi_kickstart_id(db, kickstart_id)
        try:
            normalized_mac = normalize_host_mac(mac_address)
            if not normalized_mac:
                raise ValueError("ESXi PXE host MAC address is invalid.")
            normalized_iso_path = normalize_installer_iso_path(installer_iso_path)
            normalized_variables_json = host_variables_json(variables)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        host = EsxiPxeHost(
            hostname=hostname.strip(),
            mac_address=normalized_mac,
            ip_address=ip_address.strip(),
            kickstart_id=normalized_kickstart_id,
            installer_iso_path=normalized_iso_path,
            variables_json=normalized_variables_json,
            enabled=enabled,
        )
        db.add(host)
        try:
            db.flush()
            sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if "already exists" in str(exc) else 400,
                detail=str(exc),
            ) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"ESXi PXE host for {mac_address} already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_esxi_pxe_host",
            resource_type="esxi_pxe_host",
            resource_id=str(host.id),
            detail=f"kickstart_id={host.kickstart_id} installer_iso={host.installer_iso_path}",
            request_id=request.state.request_id,
        )
        return grid_saved_response(
            request,
            redirect_url="/network-boot#esxi-pxe-hosts-panel",
            resource_name="host",
            resource=host_to_dict(host),
        )

    @router.post("/esxi-pxe/hosts/{host_id}", response_model=None)
    def update_esxi_pxe_host_from_ui(
        host_id: int,
        request: Request,
        hostname: str = Form(...),
        mac_address: str = Form(...),
        ip_address: str = Form(""),
        kickstart_id: str = Form(""),
        installer_iso_path: str = Form(""),
        variables: str = Form("{}"),
        enabled: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update esxi pxe host from ui endpoint.

        Args:
            host_id: Identifier of the host.
            request: Incoming HTTP request.
            hostname: DNS hostname of the target resource.
            mac_address: MAC address identifying the host or interface.
            ip_address: Ip address supplied by the caller.
            kickstart_id: Identifier of the kickstart.
            installer_iso_path: Filesystem path for the installer iso.
            variables: Variables supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            ValueError: If an input value is invalid.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        host = db.get(EsxiPxeHost, host_id)
        if not host:
            raise HTTPException(status_code=404, detail="ESXi PXE host not found")
        normalized_kickstart_id = parse_optional_esxi_kickstart_id(db, kickstart_id)
        try:
            normalized_mac = normalize_host_mac(mac_address)
            if not normalized_mac:
                raise ValueError("ESXi PXE host MAC address is invalid.")
            normalized_iso_path = normalize_installer_iso_path(installer_iso_path)
            normalized_variables_json = host_variables_json(variables)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        host.hostname = hostname.strip()
        host.mac_address = normalized_mac
        host.ip_address = ip_address.strip()
        host.kickstart_id = normalized_kickstart_id
        host.installer_iso_path = normalized_iso_path
        host.variables_json = normalized_variables_json
        host.enabled = enabled
        host.updated_at = utcnow()
        db.add(host)
        try:
            db.flush()
            sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if "already exists" in str(exc) else 400,
                detail=str(exc),
            ) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"ESXi PXE host for {mac_address} already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_pxe_host",
            resource_type="esxi_pxe_host",
            resource_id=str(host.id),
            detail=f"kickstart_id={host.kickstart_id} installer_iso={host.installer_iso_path}",
            request_id=request.state.request_id,
        )
        return grid_saved_response(
            request,
            redirect_url="/network-boot#esxi-pxe-hosts-panel",
            resource_name="host",
            resource=host_to_dict(host),
        )

    @router.post("/esxi-pxe/default-host", response_model=None)
    def update_esxi_pxe_default_host_from_ui(
        request: Request,
        kickstart_id: str = Form(""),
        installer_iso_path: str = Form(""),
        enabled: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the update esxi pxe default host from ui endpoint.

        Args:
            request: Incoming HTTP request.
            kickstart_id: Identifier of the kickstart.
            installer_iso_path: Filesystem path for the installer iso.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        try:
            default_host = save_esxi_pxe_default_host_settings(
                db,
                enabled=enabled,
                kickstart_id=kickstart_id,
                installer_iso_path=installer_iso_path,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_pxe_default_host",
            resource_type="esxi_pxe_default_host",
            resource_id="default",
            detail=f"enabled={default_host['enabled']} kickstart_id={default_host['kickstart_id']} installer_iso={default_host['installer_iso_path']}",
            request_id=request.state.request_id,
        )
        return RedirectResponse("/esxi-pxe#esxi-pxe-hosts", status_code=303)

    @router.post("/esxi-pxe/hosts/{host_id}/delete", response_model=None)
    def delete_esxi_pxe_host_from_ui(
        host_id: int,
        request: Request,
        remove_discovered_host: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete esxi pxe host from ui endpoint.

        Args:
            host_id: Identifier of the host.
            request: Incoming HTTP request.
            remove_discovered_host: Also remove matching discovered-host inventory state.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        host = db.get(EsxiPxeHost, host_id)
        if not host:
            raise HTTPException(status_code=404, detail="ESXi PXE host not found")
        hostname = host.hostname
        removal_counts = {
            "discovered_hosts_removed": 0,
            "commands": 0,
            "sessions": 0,
            "reports": 0,
        }
        if remove_discovered_host:
            try:
                removal_counts = remove_esxi_host_discovery_state(db, host)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        host.ip_address = ""
        sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
        db.delete(host)
        record_audit(
            db,
            actor=identity.username,
            action="delete_esxi_pxe_host",
            resource_type="esxi_pxe_host",
            resource_id=str(host_id),
            detail=(
                f"hostname={hostname}; discovered_hosts_removed={removal_counts['discovered_hosts_removed']}; "
                f"reports={removal_counts['reports']}; sessions={removal_counts['sessions']}; "
                f"commands={removal_counts['commands']}"
            ),
            request_id=request.state.request_id,
        )
        return RedirectResponse("/esxi-pxe#esxi-pxe-hosts", status_code=303)

    return NetworkBootUiRouter(
        router=router,
        endpoints={
            "esxi_pxe_page": esxi_pxe_page,
            "network_boot_page": network_boot_page,
            "update_esxi_pxe_boot_settings_from_ui": update_esxi_pxe_boot_settings_from_ui,
            "create_esxi_kickstart_from_ui": create_esxi_kickstart_from_ui,
            "upload_esxi_kickstart_from_ui": upload_esxi_kickstart_from_ui,
            "update_esxi_kickstart_from_ui": update_esxi_kickstart_from_ui,
            "duplicate_esxi_kickstart_from_ui": duplicate_esxi_kickstart_from_ui,
            "delete_esxi_kickstart_from_ui": delete_esxi_kickstart_from_ui,
            "validate_esxi_kickstart_from_ui": validate_esxi_kickstart_from_ui,
            "download_esxi_kickstart_from_ui": download_esxi_kickstart_from_ui,
            "create_esxi_custom_variable_from_ui": create_esxi_custom_variable_from_ui,
            "update_esxi_custom_variable_from_ui": update_esxi_custom_variable_from_ui,
            "delete_esxi_custom_variable_from_ui": delete_esxi_custom_variable_from_ui,
            "upload_esxi_installer_iso_from_ui": upload_esxi_installer_iso_from_ui,
            "delete_esxi_installer_iso_from_ui": delete_esxi_installer_iso_from_ui,
            "import_esxi_kickstart_filesystem_copy": import_esxi_kickstart_filesystem_copy,
            "create_esxi_pxe_host_from_ui": create_esxi_pxe_host_from_ui,
            "update_esxi_pxe_host_from_ui": update_esxi_pxe_host_from_ui,
            "update_esxi_pxe_default_host_from_ui": update_esxi_pxe_default_host_from_ui,
            "delete_esxi_pxe_host_from_ui": delete_esxi_pxe_host_from_ui,
        },
    )
