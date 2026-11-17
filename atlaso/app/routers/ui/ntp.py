"""Own NTP and NTS management UI transports."""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import Job, JobStatus, JobStep, NtpSettings, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.dnsmasq import (
    join_servers,
    split_addresses,
    split_interfaces,
    split_servers,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.ntp import (
    NTP_STAGED_CONFIG_PATH,
    NTP_TIME_SOURCES,
    dump_ntp_upstream_sources,
    duplicate_ntp_upstream_source,
    join_allow_clients,
    normalize_ntp_source,
    ntp_time_mode,
    ntp_upstream_sources,
    parse_manual_time_utc,
    parse_ntp_source,
    split_allow_clients,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


def _check_ntp_apply_idle(db: Session) -> None:
    """Refuse time-state writes while a captured NTP Apply can still run."""
    active = db.scalar(select(Job.id).join(JobStep).where(
        Job.type == "appliance-apply",
        Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
        JobStep.component_key == "ntpd",
    ).limit(1))
    if active is not None:
        raise HTTPException(409, "Wait for the active NTP appliance Apply task to finish.")


def _clock_status(result: Any) -> dict[str, Any]:
    """Project the bounded native status object without raw probe output."""
    if result.returncode != 0 or result.dry_run:
        return {}
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _settings_sources(raw: str, *, prior: list[dict[str, object]], nts_supported: bool) -> list[dict[str, object]]:
    """Validate complete wizard rows and preserve NTS flags when editing is unavailable."""
    try:
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError
        existing = {row["id"]: row for row in prior}
        sources: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        for row in rows:
            row_id = row["id"]
            if not isinstance(row_id, str) or not row_id or row_id in seen_ids:
                raise ValueError
            seen_ids.add(row_id)
            host = normalize_ntp_source(row["source"])
            enabled = row["enabled"]
            use_nts = row["use_nts"]
            description = row["description"]
            if not isinstance(enabled, bool) or not isinstance(use_nts, bool) or not isinstance(description, str):
                raise ValueError
            if not nts_supported:
                previous = existing.get(row_id)
                preserved = previous is not None and previous["source"] == host and bool(previous["use_nts"])
                if use_nts and not preserved:
                    raise HTTPException(422, "NTS capability is unavailable for this source.")
                if previous and previous["use_nts"] and previous["source"] != host:
                    raise HTTPException(422, "Wait for NTS capability detection before changing this endpoint.")
                use_nts = preserved
            if use_nts and parse_ntp_source(host)[2]:
                raise HTTPException(422, "NTS sources require a DNS hostname.")
            sources.append({"id": row_id, "source": host, "enabled": enabled, "use_nts": use_nts,
                            "description": description.strip()})
    except (TypeError, KeyError, ValueError) as exc:
        raise HTTPException(422, "Each upstream must have a unique row ID and a valid NTP endpoint.") from exc
    if duplicate_ntp_upstream_source(sources):
        raise HTTPException(422, "NTP upstream source names must be unique.")
    return sources


@dataclass(frozen=True)
class NtpUiDependencies:
    """Provide facade-owned NTP transport dependencies."""

    ensure_ca_state: Endpoint
    ensure_dns_for_ntp: Endpoint
    get_ntp_settings_row: Endpoint
    normalize_dns_hostname: Endpoint
    ntp_context: Endpoint
    ntp_nts_certificate_paths: Endpoint
    invalidate_appliance_apply_status_projection: Endpoint
    ntpd_apply_status: Endpoint
    ntpd_capabilities_payload: Endpoint
    primary_listen_address: Endpoint
    primary_listen_interface: Endpoint
    remove_ntp_nts_certificate_rows: Endpoint
    render: Endpoint
    require_admin_identity: Endpoint
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
        context = dependencies.ntp_context(db, include_runtime_health=True)
        clock_status = context.get("ntp_clock_status")
        if not isinstance(clock_status, dict) or not clock_status:
            clock_status = {}
            raw_status = context.get("ntp_ntpq_status")
            if isinstance(raw_status, str):
                try:
                    parsed_status = json.loads(raw_status)
                except json.JSONDecodeError:
                    parsed_status = {}
                if isinstance(parsed_status, dict):
                    clock_status = parsed_status
        context["ntp_clock_status"] = clock_status
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

    def editable_time_settings(db: Session, revision: str) -> NtpSettings:
        acquire_network_objects_write_lock(db)
        settings = dependencies.get_ntp_settings_row(db)
        # Default row creation may commit.
        acquire_network_objects_write_lock(db)
        db.refresh(settings)
        _check_ntp_apply_idle(db)
        if settings.enabled:
            raise HTTPException(409, "NTP and NTS owns clock configuration while server mode is enabled.")
        if settings.updated_at.isoformat() != revision:
            raise HTTPException(409, "Time settings changed. Reload Settings and review the current values.")
        return settings

    @router.get("/settings/time/status", response_model=None)
    def settings_time_status(
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Observe wall-clock time and the applied authority without enforcing desired state."""
        context = dependencies.ntp_context(db, reconcile=False)
        settings = context["ntp_settings"]
        apply = dependencies.ntpd_apply_status(db, context)
        native = _clock_status(dependencies.system_adapter_factory().read_ntpd_status())
        desired = ntp_time_mode(settings)
        effective = native.get("mode")
        synchronization = native.get("synchronization")
        synchronization = synchronization if isinstance(synchronization, dict) else {}
        state = synchronization.get("state")
        pending = bool(apply["changed"]) or (
            isinstance(effective, str) and effective in NTP_TIME_SOURCES | {"ntp_server"} and effective != desired
        )
        transaction = native.get("transaction")
        if isinstance(transaction, dict) and transaction.get("pending") is True:
            pending = True
        return JSONResponse({
            "date_time": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "selected_source": settings.time_source,
            "desired_mode": desired,
            "effective_mode": effective if isinstance(effective, str) and effective in NTP_TIME_SOURCES | {"ntp_server"} else None,
            "synchronization": state if state in ("synchronized", "unsynchronized") else "unavailable",
            "detail": synchronization.get("detail", ""),
            "pending": pending,
            "validation_errors": context["ntp_validation_errors"],
            "server_enabled": settings.enabled,
            "manual_ready": native.get("manual_ready") is True and effective == desired == "manual",
            "revision": settings.updated_at.isoformat(),
        }, headers={"Cache-Control": "no-store"})

    @router.post("/settings/time", response_model=None)
    def save_time_settings(
        request: Request,
        csrf: str = Form(...),
        revision: str = Form(...),
        time_source: str = Form(...),
        upstream_sources_json: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Stage client source preferences in the canonical NTP settings row."""
        dependencies.require_admin_identity(identity)
        dependencies.verify_csrf(request, csrf)
        settings = editable_time_settings(db, revision)
        caps = dependencies.ntpd_capabilities_payload(dependencies.system_adapter_factory().read_ntpd_capabilities())
        if time_source not in NTP_TIME_SOURCES or (time_source == "vmware_tools" and caps.get("vmware_tools") is not True):
            raise HTTPException(422, "Select an available clock source.")
        rows = _settings_sources(upstream_sources_json, prior=ntp_upstream_sources(settings), nts_supported=caps.get("nts") is True)
        if time_source == "ntp_client" and not any(row["enabled"] for row in rows):
            raise HTTPException(422, "Enable at least one upstream source for NTP client mode.")
        if settings.time_source != time_source:
            settings.manual_time_utc = None
        settings.time_source = time_source
        settings.upstream_sources_json = dump_ntp_upstream_sources(rows)
        settings.upstream_servers = join_servers([str(row["source"]) for row in rows if row["enabled"]])
        settings.updated_at = utcnow()
        record_audit(db, actor=identity.username, action="update_appliance_time_settings", resource_type="ntpd", resource_id=str(settings.id))
        db.commit()
        db.refresh(settings)
        dependencies.invalidate_appliance_apply_status_projection()
        return JSONResponse({"status": "saved", "revision": settings.updated_at.isoformat(), "time_source": time_source})

    @router.post("/settings/time/clock", response_model=None)
    def stage_manual_clock(
        request: Request,
        csrf: str = Form(...),
        revision: str = Form(...),
        target_utc: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Stage an absolute clock target for the separate Appliance Apply review."""
        dependencies.require_admin_identity(identity)
        dependencies.verify_csrf(request, csrf)
        settings = editable_time_settings(db, revision)
        native = _clock_status(dependencies.system_adapter_factory().read_ntpd_status())
        if settings.time_source != "manual" or native.get("mode") != "manual" or native.get("manual_ready") is not True:
            raise HTTPException(409, "Apply Manual mode and verify automatic clock sources are off before staging a clock change.")
        try:
            target = parse_manual_time_utc(target_utc)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        settings.manual_time_utc = target
        settings.updated_at = utcnow()
        record_audit(db, actor=identity.username, action="stage_manual_clock_change", resource_type="ntpd",
                     resource_id=str(settings.id), detail=f"UTC target pending Appliance Apply: {target.isoformat()}")
        db.commit()
        dependencies.invalidate_appliance_apply_status_projection()
        return RedirectResponse(f"{MANAGEMENT_UI_ROOT}/settings#settings-time", status_code=303)

    @router.post("/ntp/settings", response_model=None)
    def update_ntp_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        time_source: str | None = Form(None),
        hostname: str = Form(""),
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
            time_source: Remembered clock source used when the NTP server is disabled.
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
        from atlaso.app.services.reverse_proxies import (
            validate_service_listener_sockets,
        )

        dependencies.verify_csrf(request, csrf)
        acquire_network_objects_write_lock(db)
        if time_source is not None and time_source not in NTP_TIME_SOURCES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Time source must be ntp_client, vmware_tools, or manual.",
            )
        settings = dependencies.get_ntp_settings_row(db)
        # Default-row readers may commit; reacquire before editing their result.
        acquire_network_objects_write_lock(db)
        db.refresh(settings)
        _check_ntp_apply_idle(db)
        if time_source == "manual" and settings.time_source != "manual":
            raise HTTPException(422, "Select Manual mode from Settings → Time.")
        previous_hostname = settings.hostname
        capability_result = (
            dependencies.system_adapter_factory().read_ntpd_capabilities()
        )
        ntp_capabilities = dependencies.ntpd_capabilities_payload(capability_result)
        ntp_nts_capability_known = "nts" in ntp_capabilities
        ntp_nts_supported = ntp_capabilities.get("nts") is True
        ntp_vmware_tools_capability_known = isinstance(
            ntp_capabilities.get("vmware_tools"), bool
        )
        ntp_vmware_tools_available = ntp_capabilities.get("vmware_tools") is True
        requested_server_mode = enabled == "on"
        requested_time_source = time_source or settings.time_source
        preserve_server_remembered_choice = (
            requested_server_mode
            and settings.time_source == "vmware_tools"
            and not ntp_vmware_tools_available
            and time_source in {None, "vmware_tools"}
        )
        if (
            requested_time_source == "vmware_tools"
            and not ntp_vmware_tools_available
            and not preserve_server_remembered_choice
        ):
            availability = (
                "unavailable"
                if ntp_vmware_tools_capability_known
                else "could not be verified"
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "VMware Tools time synchronization "
                    f"{availability}; select NTP client before saving this time-source choice."
                ),
            )
        if not requested_server_mode and time_source is not None and not preserve_server_remembered_choice:
            if settings.time_source != time_source:
                settings.manual_time_utc = None
            settings.time_source = time_source
        if requested_server_mode:
            settings.manual_time_utc = None
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
            hostname.strip() or settings.hostname
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
        settings.nts_ke_port = 4460
        try:
            validate_service_listener_sockets(db)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
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
        settings.minsources = minsources if minsources and minsources > 0 else None
        settings.config_path = NTP_STAGED_CONFIG_PATH
        settings.updated_at = utcnow()
        db.add(settings)
        dependencies.ensure_dns_for_ntp(
            db, settings, identity.username, previous_hostname=previous_hostname
        )
        db.commit()
        if settings.enabled and settings.nts_server_enabled:
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
                    "time_source": context["ntp_settings_json"]["time_source"],
                    "time_mode": context["ntp_settings_json"]["time_mode"],
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
            "settings_time_status": settings_time_status,
            "save_time_settings": save_time_settings,
            "stage_manual_clock": stage_manual_clock,
            "update_ntp_settings_from_ui": update_ntp_settings_from_ui,
        },
    )
