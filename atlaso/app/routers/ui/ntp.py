"""Own NTP and NTS management UI transports."""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.dnsmasq import (
    join_servers,
    split_addresses,
    split_interfaces,
    split_servers,
)
from atlaso.app.services.ntp import (
    NTP_DEFAULT_HOSTNAME,
    NTP_STAGED_CONFIG_PATH,
    dump_ntp_upstream_sources,
    duplicate_ntp_upstream_source,
    join_allow_clients,
    split_allow_clients,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class NtpUiDependencies:
    """Provide facade-owned NTP transport dependencies."""

    ensure_ca_state: Endpoint
    get_ntp_settings_row: Endpoint
    normalize_dns_hostname: Endpoint
    ntp_context: Endpoint
    ntp_nts_certificate_paths: Endpoint
    ntpd_apply_status: Endpoint
    ntpd_capabilities_payload: Endpoint
    primary_listen_address: Endpoint
    primary_listen_interface: Endpoint
    remove_ntp_nts_certificate_rows: Endpoint
    render: Endpoint
    require_management_ui_request: Endpoint
    resolve_service_bind_targets: Endpoint
    system_adapter_factory: Endpoint
    verify_csrf: Endpoint


@dataclass(frozen=True)
class NtpUiRouter:
    """Return the management router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: NtpUiDependencies) -> NtpUiRouter:
    """Build NTP and NTS management UI transports.

    Args:
        dependencies: Facade-provided transport dependencies.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )

    @router.get("/ntp", response_class=HTMLResponse, response_model=None)
    def ntp_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the ntp page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        context = dependencies.ntp_context(db)
        return dependencies.render(
            request,
            "ntp.html",
            {
                "identity": identity,
                **context,
                "appliance_apply_status": dependencies.ntpd_apply_status(db, context),
            },
        )

    @router.get(
        "/ntp/source-health", response_class=JSONResponse, response_model=None
    )
    def ntp_source_health(
        identity: Identity = Depends(require_session_identity),
    ) -> JSONResponse:
        """Handle the ntp source health endpoint.

        Args:
            identity: Authenticated identity authorizing the request.

        Returns:
            The endpoint response.
        """
        result = dependencies.system_adapter_factory().read_ntpd_status()
        parsed_status: dict[str, Any] = {}
        if result.stdout:
            try:
                raw_status = json.loads(result.stdout)
            except json.JSONDecodeError:
                raw_status = {}
            if isinstance(raw_status, dict):
                parsed_status = raw_status
        return JSONResponse(
            {
                "ok": result.returncode == 0,
                "dry_run": result.dry_run,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "status": parsed_status,
            }
        )

    @router.post("/ntp/settings", response_model=None)
    def update_ntp_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        hostname: str = Form(NTP_DEFAULT_HOSTNAME),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_addresses: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        listen_interface: str = Form(""),
        listen_address: str = Form(""),
        port: int = Form(123),
        upstream_servers: str = Form(""),
        upstream_source: list[str] = Form(default_factory=list),
        upstream_sources_json: str = Form(""),
        upstream_enabled: list[str] = Form(default_factory=list),
        upstream_use_nts: list[str] = Form(default_factory=list),
        upstream_description: list[str] = Form(default_factory=list),
        allow_clients: str = Form("any"),
        nts_server_enabled: str | None = Form(None),
        nts_server_cert_path: str = Form(""),
        nts_server_key_path: str = Form(""),
        minsources: int | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update ntp settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            hostname: DNS hostname of the target resource.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            listen_interface: Interface on which the service should listen.
            listen_address: Address on which the service should listen.
            port: TCP or UDP port of the target service.
            upstream_servers: Upstream servers supplied by the caller.
            upstream_source: Upstream source supplied by the caller.
            upstream_sources_json: Upstream sources json supplied by the caller.
            upstream_enabled: Upstream enabled supplied by the caller.
            upstream_use_nts: Upstream use nts supplied by the caller.
            upstream_description: Upstream description supplied by the caller.
            allow_clients: Allow clients supplied by the caller.
            nts_server_enabled: Nts server enabled supplied by the caller.
            nts_server_cert_path: Filesystem path for the nts server cert.
            nts_server_key_path: Filesystem path for the nts server key.
            minsources: Minsources supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        settings = dependencies.get_ntp_settings_row(db)
        capability_result = (
            dependencies.system_adapter_factory().read_ntpd_capabilities()
        )
        ntp_capabilities = dependencies.ntpd_capabilities_payload(capability_result)
        ntp_nts_capability_known = "nts" in ntp_capabilities
        ntp_nts_supported = ntp_capabilities.get("nts") is True
        selected_interfaces, selected_addresses = (
            dependencies.resolve_service_bind_targets(
                db,
                [*listen_interfaces, listen_interface],
                [*listen_addresses, listen_address],
                current_interface=settings.listen_interface,
                current_address=settings.listen_address,
                listen_interfaces_present=listen_interfaces_present,
                listen_addresses_present=listen_addresses_present,
            )
        )
        settings.enabled = enabled == "on"
        settings.hostname = dependencies.normalize_dns_hostname(
            hostname.strip() or NTP_DEFAULT_HOSTNAME
        )
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses
        settings.port = port
        source_rows = []
        if upstream_sources_json.strip():
            try:
                parsed_sources = json.loads(upstream_sources_json)
            except json.JSONDecodeError:
                parsed_sources = []
            if isinstance(parsed_sources, list):
                for index, item in enumerate(parsed_sources, start=1):
                    if not isinstance(item, dict):
                        continue
                    source = str(item.get("source") or "").strip()
                    if not source:
                        continue
                    source_rows.append(
                        {
                            "id": str(item.get("id") or f"source-{index}"),
                            "source": source,
                            "enabled": bool(item.get("enabled", True)),
                            "use_nts": (
                                bool(item.get("use_nts", False))
                                if not ntp_nts_capability_known
                                else ntp_nts_supported
                                and bool(item.get("use_nts", False))
                            ),
                            "description": str(
                                item.get("description") or ""
                            ).strip(),
                        }
                    )
        if not source_rows:
            max_rows = max(len(upstream_source), len(upstream_description))
            enabled_indexes = {
                int(value) for value in upstream_enabled if str(value).isdigit()
            }
            nts_indexes = {
                int(value) for value in upstream_use_nts if str(value).isdigit()
            }
            for index in range(max_rows):
                source = (
                    upstream_source[index].strip()
                    if index < len(upstream_source)
                    else ""
                )
                if not source:
                    continue
                source_rows.append(
                    {
                        "id": f"source-{index + 1}",
                        "source": source,
                        "enabled": index in enabled_indexes,
                        "use_nts": (
                            index in nts_indexes
                            if not ntp_nts_capability_known
                            else ntp_nts_supported and index in nts_indexes
                        ),
                        "description": (
                            upstream_description[index].strip()
                            if index < len(upstream_description)
                            else ""
                        ),
                    }
                )
        if not source_rows:
            source_rows = [
                {
                    "id": f"source-{index}",
                    "source": server,
                    "enabled": True,
                    "use_nts": False,
                    "description": "",
                }
                for index, server in enumerate(
                    split_servers(upstream_servers), start=1
                )
            ]
        duplicate_source = duplicate_ntp_upstream_source(source_rows)
        if duplicate_source:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"NTP upstream source {duplicate_source} is duplicated. "
                    "Source names must be unique."
                ),
            )
        settings.upstream_sources_json = dump_ntp_upstream_sources(source_rows)
        settings.upstream_servers = join_servers(
            [
                str(row["source"])
                for row in source_rows
                if row.get("enabled")
            ]
        )
        settings.allow_clients = join_allow_clients(
            split_allow_clients(allow_clients)
        )
        settings.nts_server_enabled = (
            settings.nts_server_enabled
            if not ntp_nts_capability_known
            else ntp_nts_supported and nts_server_enabled == "on"
        )
        (
            _ntp_nts_cert_path,
            ntp_nts_key_path,
            ntp_nts_chain_path,
        ) = dependencies.ntp_nts_certificate_paths(settings)
        if settings.nts_server_enabled:
            settings.nts_server_cert_path = ntp_nts_chain_path
            settings.nts_server_key_path = ntp_nts_key_path
        else:
            settings.nts_server_cert_path = ""
            settings.nts_server_key_path = ""
            dependencies.remove_ntp_nts_certificate_rows(db)
        settings.nts_ke_port = 4460
        settings.minsources = minsources if minsources and minsources > 0 else None
        settings.config_path = NTP_STAGED_CONFIG_PATH
        settings.updated_at = utcnow()
        db.add(settings)
        db.commit()
        if settings.nts_server_enabled:
            dependencies.ensure_ca_state(db)
        record_audit(
            db,
            actor=identity.username,
            action="update_ntp_settings",
            resource_type="ntpd",
            resource_id=str(settings.id),
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = dependencies.ntp_context(db)
            saved_settings = context["ntp_settings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": saved_settings.updated_at.isoformat(),
                    "enabled": saved_settings.enabled,
                    "hostname": saved_settings.hostname,
                    "listen_interface": dependencies.primary_listen_interface(
                        saved_settings.listen_interface
                    ),
                    "listen_address": dependencies.primary_listen_address(
                        saved_settings.listen_address
                    ),
                    "listen_interfaces": split_interfaces(
                        saved_settings.listen_interface
                    ),
                    "listen_addresses": split_addresses(
                        saved_settings.listen_address
                    ),
                    "port": saved_settings.port,
                    "upstream_servers": context["ntp_settings_json"][
                        "upstream_servers"
                    ],
                    "upstream_sources": context["ntp_settings_json"][
                        "upstream_sources"
                    ],
                    "allow_clients": saved_settings.allow_clients,
                    "nts_server_enabled": saved_settings.nts_server_enabled,
                    "nts_server_cert_path": saved_settings.nts_server_cert_path,
                    "nts_server_key_path": saved_settings.nts_server_key_path,
                    "nts_ke_port": saved_settings.nts_ke_port,
                    "nts_supported": context["ntp_nts_supported"],
                    "nts_capability_known": context[
                        "ntp_nts_capability_known"
                    ],
                    "valid": not context["ntp_validation_errors"],
                    "validation_errors": context["ntp_validation_errors"],
                    "config_path": saved_settings.config_path,
                    "config_preview": context["ntp_config_preview"],
                }
            )
        return RedirectResponse("/ntp", status_code=303)

    return NtpUiRouter(
        router=router,
        endpoints={
            "ntp_page": ntp_page,
            "ntp_source_health": ntp_source_health,
            "update_ntp_settings_from_ui": update_ntp_settings_from_ui,
        },
    )
