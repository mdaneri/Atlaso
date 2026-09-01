"""Own operational management UI transport handlers."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import EsxNfsShare, Job, JobStatus, Role, ServiceState, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.appliance_update import cancel_pending_appliance_update
from atlaso.app.services.ca import ca_service_state
from atlaso.app.services.esx_storage import (
    rpcbind_required as esx_storage_rpcbind_required,
)
from atlaso.app.services.esxi_pxe import (
    esxi_pxe_boot_settings,
    esxi_pxe_service_state_from_boot,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.routes_wan import save_routing_enabled_state
from atlaso.app.services.service_registry import (
    SERVICE_STATE_IDS,
    SERVICE_SYSTEMD_UNITS,
)
from atlaso.app.services.vcf_backups import vcf_backup_service_state
from atlaso.app.services.vcf_depot_downloads import (
    active_vcf_depot_download_jobs,
    active_vcf_depot_exclusive_job,
    cancel_pending_vcf_depot_download,
    vcf_depot_job_profile_id,
)
from atlaso.app.services.vcf_offline_depot import vcf_depot_service_state
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class OperationsUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    active_job_statuses: set[str]
    service_admin_cancellable_job_types: set[str]
    job_payload: Endpoint
    redact_task_value: Endpoint
    task_component_filter_options: Endpoint
    task_filter_clauses: Endpoint
    task_log_lines: Endpoint
    task_row: Endpoint
    audit_event_rows_context: Endpoint
    backing_systemd_unit_active: Endpoint
    get_ca_settings_row: Endpoint
    get_dhcp_settings_row: Endpoint
    get_dns_settings_row: Endpoint
    get_esx_storage_settings_row: Endpoint
    get_vcf_backup_settings_row: Endpoint
    get_vcf_offline_depot_settings_row: Endpoint
    log_sources_context: Endpoint
    logs_context: Endpoint
    normalized_log_line_count: Endpoint
    render: Endpoint
    vcf_depot_execution_conflict_detail: Endpoint
    vcf_depot_profile_start_states: Endpoint
    verify_csrf: Endpoint


@dataclass(frozen=True)
class OperationsUiRouter:
    """Return the configured router and compatibility exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: OperationsUiDependencies) -> OperationsUiRouter:
    """Build the operational management UI router.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured operational UI router and its stable endpoint callables.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    ACTIVE_JOB_STATUSES = dependencies.active_job_statuses
    SERVICE_ADMIN_CANCELLABLE_JOB_TYPES = (
        dependencies.service_admin_cancellable_job_types
    )
    _job_payload = dependencies.job_payload
    _redact_task_value = dependencies.redact_task_value
    _task_component_filter_options = dependencies.task_component_filter_options
    _task_filter_clauses = dependencies.task_filter_clauses
    _task_log_lines = dependencies.task_log_lines
    _task_row = dependencies.task_row
    audit_event_rows_context = dependencies.audit_event_rows_context
    backing_systemd_unit_active = dependencies.backing_systemd_unit_active
    get_ca_settings_row = dependencies.get_ca_settings_row
    get_dhcp_settings_row = dependencies.get_dhcp_settings_row
    get_dns_settings_row = dependencies.get_dns_settings_row
    get_esx_storage_settings_row = dependencies.get_esx_storage_settings_row
    get_vcf_backup_settings_row = dependencies.get_vcf_backup_settings_row
    get_vcf_offline_depot_settings_row = dependencies.get_vcf_offline_depot_settings_row
    log_sources_context = dependencies.log_sources_context
    logs_context = dependencies.logs_context
    normalized_log_line_count = dependencies.normalized_log_line_count
    render = dependencies.render
    vcf_depot_execution_conflict_detail = (
        dependencies.vcf_depot_execution_conflict_detail
    )
    vcf_depot_profile_start_states = dependencies.vcf_depot_profile_start_states
    verify_csrf = dependencies.verify_csrf

    def service_state_status_row(service: ServiceState) -> dict[str, object]:
        """Return service state status row.

        Args:
            service: Atlaso or host service affected by the operation.
        """
        row = {
            "id": service.id,
            "service": service.service,
            "display_name": service.display_name,
            "running": service.running,
            "enabled": service.enabled,
            "health": service.health,
            "detail": service.detail or "native host service",
        }
        unit = SERVICE_SYSTEMD_UNITS.get(service.service)
        if unit and not get_settings().dry_run_system_adapters:
            result = SystemAdapter().service_status(unit)
            if result.stdout:
                try:
                    status_payload = json.loads(result.stdout)
                except json.JSONDecodeError:
                    status_payload = {}
                active_state = str(status_payload.get("active") or "").strip()
                enabled_state = str(status_payload.get("enabled") or "").strip()
                if active_state:
                    row["running"] = active_state == "active"
                if enabled_state:
                    row["enabled"] = enabled_state in {"enabled", "enabled-runtime"}
                if row["running"] and row["enabled"]:
                    row["health"] = "healthy"
                elif row["running"] or row["enabled"]:
                    row["health"] = "degraded"
                else:
                    row["health"] = "disabled"
        return row

    def service_state_to_grid_row(service: ServiceState) -> dict[str, object]:
        """Return service state to grid row.

        Args:
            service: Atlaso or host service affected by the operation.
        """
        row = service_state_status_row(service)
        row.pop("health", None)
        return row

    def dnsmasq_backed_service_grid_row(
        service: ServiceState, enabled: bool
    ) -> dict[str, object]:
        """Return dnsmasq backed service grid row.

        Args:
            service: Atlaso or host service affected by the operation.
            enabled: Whether the associated resource or behavior is enabled.
        """
        row = service_state_to_grid_row(service)
        if not get_settings().dry_run_system_adapters:
            active = backing_systemd_unit_active("dnsmasq.service")
            if active is not None:
                row["running"] = active
        row["enabled"] = enabled
        row.pop("health", None)
        return row

    def esxi_pxe_service_grid_row(
        service: ServiceState, db: Session
    ) -> dict[str, object]:
        """Return esxi pxe service grid row.

        Args:
            service: Atlaso service affected by the operation.
            db: Active database session.
        """
        row = service_state_to_grid_row(service)
        row.update(esxi_pxe_service_state_from_boot(esxi_pxe_boot_settings(db)))
        row.pop("health", None)
        row["detail"] = "dnsmasq TFTP/DHCP boot options and PXE HTTP files"
        return row

    def ca_service_grid_row(service: ServiceState, db: Session) -> dict[str, object]:
        """Return ca service grid row.

        Args:
            service: Atlaso service affected by the operation.
            db: Active database session.
        """
        row = service_state_to_grid_row(service)
        row.update(ca_service_state(get_ca_settings_row(db)))
        row.pop("health", None)
        row["detail"] = service.detail or "Atlaso CA material and issued certificates"
        return row

    def vcf_backup_service_grid_row(
        service: ServiceState, db: Session
    ) -> dict[str, object]:
        """Return vcf backup service grid row.

        Args:
            service: Atlaso service affected by the operation.
            db: Active database session.
        """
        row = service_state_to_grid_row(service)
        settings = get_vcf_backup_settings_row(db)
        row.update(
            vcf_backup_service_state(
                settings, sshd_active=backing_systemd_unit_active("sshd.service")
            )
        )
        row.pop("health", None)
        row["detail"] = service.detail or "/mnt/atlaso-vcf-backups"
        return row

    def vcf_depot_service_grid_row(
        service: ServiceState, db: Session
    ) -> dict[str, object]:
        """Return vcf depot service grid row.

        Args:
            service: Atlaso service affected by the operation.
            db: Active database session.
        """
        row = service_state_to_grid_row(service)
        settings = get_vcf_offline_depot_settings_row(db)
        row.update(
            vcf_depot_service_state(
                settings, nginx_active=backing_systemd_unit_active("nginx.service")
            )
        )
        row.pop("health", None)
        row["detail"] = service.detail or "/mnt/atlaso-vcf-offline-depot"
        return row

    def esx_storage_service_grid_row(
        service: ServiceState, db: Session
    ) -> dict[str, object]:
        """Return esx storage service grid row.

        Args:
            service: Atlaso service affected by the operation.
            db: Active database session.
        """
        row = service_state_status_row(service)
        settings = get_esx_storage_settings_row(db)
        shares = (
            db.execute(select(EsxNfsShare).where(EsxNfsShare.enabled.is_(True)))
            .scalars()
            .all()
        )
        requires_rpcbind = esx_storage_rpcbind_required(shares)
        row["enabled"] = settings.enabled
        row["detail"] = "NFS 3 / 4.1 over equivalent IPv4 and IPv6 listeners"
        if not settings.enabled:
            row["running"] = False
            row["health"] = "disabled"
        elif (
            requires_rpcbind
            and not get_settings().dry_run_system_adapters
            and backing_systemd_unit_active("rpcbind.service") is not True
        ):
            row["running"] = False
            row["health"] = "degraded"
            row["detail"] += (
                "; rpcbind.service is required by an enabled NFS 3 share but is not active"
            )
        elif row.get("running"):
            row["health"] = "healthy"
        else:
            row["health"] = "degraded"
        return row

    def service_grid_row(
        service: ServiceState, db: Session, dns_enabled: bool, dhcp_enabled: bool
    ) -> dict[str, object]:
        """Return service grid row.

        Args:
            service: Atlaso service affected by the operation.
            db: Active database session.
            dns_enabled: Dns enabled supplied by the caller.
            dhcp_enabled: Dhcp enabled supplied by the caller.
        """
        if service.service == "dns":
            return dnsmasq_backed_service_grid_row(service, dns_enabled)
        if service.service == "dhcp":
            return dnsmasq_backed_service_grid_row(service, dhcp_enabled)
        if service.service == "esxi-pxe":
            return esxi_pxe_service_grid_row(service, db)
        if service.service == "ca":
            return ca_service_grid_row(service, db)
        if service.service == "vcf-backups":
            return vcf_backup_service_grid_row(service, db)
        if service.service == "repository":
            return vcf_depot_service_grid_row(service, db)
        if service.service == "esx-storage":
            return esx_storage_service_grid_row(service, db)
        return service_state_to_grid_row(service)

    def services_template_context(db: Session) -> dict[str, object]:
        """Return services template context.

        Args:
            db: Active database session.
        """
        dns_settings = get_dns_settings_row(db)
        dhcp_settings = get_dhcp_settings_row(db)
        rows = (
            db.execute(
                select(ServiceState)
                .where(ServiceState.service.in_(SERVICE_STATE_IDS))
                .order_by(ServiceState.display_name)
            )
            .scalars()
            .all()
        )
        service_rows = [
            service_grid_row(row, db, dns_settings.enabled, dhcp_settings.enabled)
            for row in rows
        ]
        system_adapter_dry_run = get_settings().dry_run_system_adapters
        return {
            "services": service_rows,
            "service_rows": service_rows,
            "system_adapter_dry_run": system_adapter_dry_run,
            "services_boundary_label": "dry-run" if system_adapter_dry_run else "live",
            "services_boundary_pill": "warn" if system_adapter_dry_run else "good",
        }

    @router.post("/services/{service}/{action}", response_model=None)
    def service_action_from_ui(
        service: str,
        action: str,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the service action from ui endpoint.

        Args:
            service: Atlaso service affected by the operation.
            action: Operation to perform on the target resource.
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
        if service not in SERVICE_STATE_IDS:
            raise HTTPException(
                status_code=404, detail="Service is not approved for control"
            )
        if action not in {"start", "stop", "restart", "enable", "disable"}:
            raise HTTPException(status_code=422, detail="Unsupported service action")
        if service == "routing" and action in {"start", "stop", "restart"}:
            raise HTTPException(
                status_code=422,
                detail="Routing runtime changes require Appliance Apply",
            )
        if service == "routing" and action in {"enable", "disable"}:
            if not identity.can("write:routes") or not identity.can("write:wan"):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Routing service actions require write:routes and write:wan permissions"
                    ),
                )
            acquire_network_objects_write_lock(db)
        row = db.execute(
            select(ServiceState).where(ServiceState.service == service)
        ).scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Service not found")
        if action == "enable":
            if service != "routing" or row.health != "unconfigured":
                row.enabled = True
            if service == "dns":
                get_dns_settings_row(db).enabled = True
            elif service == "dhcp":
                get_dhcp_settings_row(db).enabled = True
            elif service == "routing":
                save_routing_enabled_state(db, enabled=True)
        elif action == "disable":
            if service != "routing" or row.health != "unconfigured":
                row.enabled = False
            if service == "dns":
                get_dns_settings_row(db).enabled = False
            elif service == "dhcp":
                get_dhcp_settings_row(db).enabled = False
            elif service == "routing":
                save_routing_enabled_state(db, enabled=False)
        elif action in {"start", "restart"}:
            row.running = True
        elif action == "stop":
            row.running = False
        db.add(row)
        result = SystemAdapter().service_action(service, action)
        service_action_name = (
            f"{action}_service_dry_run"
            if get_settings().dry_run_system_adapters
            else f"{action}_service_intent"
        )
        record_audit(
            db,
            actor=identity.username,
            action=service_action_name,
            resource_type="service",
            resource_id=service,
            detail=" ".join(result.command),
        )
        return render(
            request,
            "services.html",
            {
                "identity": identity,
                **services_template_context(db),
                "service_action_result": {
                    "service": row.display_name,
                    "action": action,
                    "command": " ".join(result.command),
                    "dry_run": result.dry_run,
                },
            },
        )

    @router.get(
        "/services/{service}/logs", response_class=HTMLResponse, response_model=None
    )
    def service_logs_from_ui(
        service: str,
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the service logs from ui endpoint.

        Args:
            service: Atlaso service affected by the operation.
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if service not in SERVICE_STATE_IDS:
            raise HTTPException(status_code=404, detail="Log source is not approved")
        row = db.execute(
            select(ServiceState).where(ServiceState.service == service)
        ).scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Service not found")
        return render(
            request,
            "services.html",
            {
                "identity": identity,
                **services_template_context(db),
                "service_logs": {
                    "service": row.display_name,
                    "lines": [
                        f"dry-run log source for {service}",
                        "No host journal is read in development mode.",
                    ],
                },
            },
        )

    @router.get("/services", response_class=HTMLResponse, response_model=None)
    def services(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the services endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "services.html",
            {"identity": identity, **services_template_context(db)},
        )

    @router.get("/logs", response_class=HTMLResponse, response_model=None)
    def logs_page(
        request: Request,
        lines: int = Query(100),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the logs page endpoint.

        Args:
            request: Incoming HTTP request.
            lines: Lines supplied by the caller.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "logs.html",
            {
                "identity": identity,
                **logs_context(db, max_lines=lines),
            },
        )

    @router.get("/logs/data", response_class=JSONResponse, response_model=None)
    def logs_data(
        lines: int = Query(100),
        _identity: Identity = Depends(require_session_identity),
    ) -> JSONResponse:
        """Handle the logs data endpoint.

        Args:
            lines: Lines supplied by the caller.
            _identity: Authenticated identity supplied by the dependency layer.

        Returns:
            The endpoint response.
        """
        line_count = normalized_log_line_count(lines)
        return JSONResponse(
            {
                "line_count": line_count,
                "refreshed_at": utcnow().isoformat(),
                "sources": log_sources_context(max_lines=line_count),
            }
        )

    @router.get("/tasks", response_class=HTMLResponse, response_model=None)
    def tasks_page(
        request: Request,
        job_id: str = Query(""),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the tasks page endpoint.

        Args:
            request: Incoming HTTP request.
            job_id: Identifier of the job.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        jobs = (
            db.execute(
                select(Job)
                .options(selectinload(Job.steps))
                .order_by(desc(Job.created_at))
                .limit(500)
            )
            .scalars()
            .all()
        )
        task_rows = [_task_row(job, identity) for job in jobs]
        selected_job_id = (
            job_id if any(row["id"] == job_id for row in task_rows) else ""
        )
        return render(
            request,
            "tasks.html",
            {
                "identity": identity,
                "task_rows": task_rows,
                "task_component_filter_options": _task_component_filter_options(db),
                "selected_task_id": selected_job_id,
            },
        )

    @router.get("/tasks/status", response_class=JSONResponse, response_model=None)
    def tasks_status(
        job_id: str = Query(""),
        task_type: str = Query(""),
        filters: str = Query("[]"),
        page: int = Query(1, ge=1),
        size: int = Query(25, ge=1, le=100),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the tasks status endpoint.

        Args:
            job_id: Identifier of the job.
            task_type: Task type supplied by the caller.
            filters: Filters supplied by the caller.
            page: Page supplied by the caller.
            size: Size supplied by the caller.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        normalized_task_type = task_type.strip()
        if len(normalized_task_type) > 100:
            raise HTTPException(status_code=400, detail="Task type filter is too long.")
        scope_clauses = (
            [Job.type == normalized_task_type] if normalized_task_type else []
        )
        clauses = _task_filter_clauses(filters)
        total_count = int(
            db.scalar(select(func.count(Job.id)).where(*scope_clauses)) or 0
        )
        filtered_count = int(
            db.scalar(select(func.count(Job.id)).where(*scope_clauses, *clauses)) or 0
        )
        active_count = int(
            db.scalar(
                select(func.count(Job.id)).where(
                    *scope_clauses, Job.status.in_(ACTIVE_JOB_STATUSES)
                )
            )
            or 0
        )
        last_page = max(1, (filtered_count + size - 1) // size)
        effective_page = min(page, last_page)
        jobs = (
            db.execute(
                select(Job)
                .options(selectinload(Job.steps))
                .where(*scope_clauses, *clauses)
                .order_by(desc(Job.created_at))
                .offset((effective_page - 1) * size)
                .limit(size)
            )
            .scalars()
            .all()
        )
        rows = [_task_row(job, identity) for job in jobs]
        selected_job = (
            db.scalar(
                select(Job)
                .options(selectinload(Job.steps))
                .where(Job.id == job_id, *scope_clauses)
            )
            if job_id
            else None
        )
        selected = (
            _task_row(selected_job, identity) if selected_job is not None else None
        )
        active_downloads = (
            [
                {
                    "job_id": job.id,
                    "profile_id": vcf_depot_job_profile_id(job),
                    "status": job.status,
                }
                for job in active_vcf_depot_download_jobs(db)
            ]
            if normalized_task_type == "vcf-depot-download"
            else []
        )
        exclusive_job = (
            active_vcf_depot_exclusive_job(db)
            if normalized_task_type == "vcf-depot-download"
            else None
        )
        return JSONResponse(
            {
                "last_page": last_page,
                "data": rows,
                "tasks": rows,
                "selected_task": selected,
                "active_count": active_count,
                "filtered_count": filtered_count,
                "total_count": total_count,
                "active_downloads": active_downloads,
                "profile_start_states": (
                    vcf_depot_profile_start_states(db)
                    if normalized_task_type == "vcf-depot-download"
                    else []
                ),
                "active_exclusive_operation": (
                    {
                        "job_id": exclusive_job.id,
                        "status": exclusive_job.status,
                        "type": exclusive_job.type,
                        "detail": vcf_depot_execution_conflict_detail(exclusive_job),
                    }
                    if exclusive_job is not None
                    else None
                ),
                "server_time": utcnow().isoformat(),
            }
        )

    @router.get(
        "/tasks/{job_id}/status", response_class=JSONResponse, response_model=None
    )
    def task_status(
        job_id: str,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the task status endpoint.

        Args:
            job_id: Identifier of the job.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        job = db.scalar(
            select(Job).options(selectinload(Job.steps)).where(Job.id == job_id)
        )
        if job is None:
            raise HTTPException(status_code=404, detail="Task not found")
        return JSONResponse(
            {"task": _task_row(job, identity), "server_time": utcnow().isoformat()}
        )

    @router.get("/tasks/{job_id}/log", response_class=JSONResponse, response_model=None)
    def task_log(
        job_id: str,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the task log endpoint.

        Args:
            job_id: Identifier of the job.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        job = db.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Task not found")
        row = _task_row(job)
        return JSONResponse(
            {
                "job_id": job.id,
                "status": job.status,
                "title": f"{row['type_label']} log",
                "text": "\n".join(_task_log_lines(job, db)),
            }
        )

    @router.post(
        "/tasks/{job_id}/cancel", response_class=JSONResponse, response_model=None
    )
    def cancel_task_from_ui(
        job_id: str,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the cancel task from ui endpoint.

        Args:
            job_id: Identifier of the job.
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
        job = db.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Task not found")
        if not (
            identity.has_role(Role.ADMIN.value)
            or (
                identity.has_role(Role.SERVICE_ADMIN.value)
                and job.type in SERVICE_ADMIN_CANCELLABLE_JOB_TYPES
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator role required for this task type",
            )
        if job.status not in ACTIVE_JOB_STATUSES:
            return JSONResponse(
                {
                    "task": _task_row(job, identity),
                    "message": "Task is already finished.",
                }
            )
        if job.type == "pxe-media-sync" and job.status == JobStatus.RUNNING.value:
            try:
                config = json.loads(job.task_config_json or "{}")
            except json.JSONDecodeError:
                config = {}
            if config.get("source") == "delete":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A running Network Boot media deletion cannot be cancelled.",
                )
        if job.type == "appliance-update" and job.status == JobStatus.RUNNING.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "A running Appliance Update cannot be cancelled because host mutation "
                    "and update-only status recovery may already be in progress."
                ),
            )
        if job.type == "appliance-update" and job.status == JobStatus.PENDING.value:
            finished_at = utcnow()
            payload = _job_payload(job)
            payload["state"] = "cancelled"
            payload["cancelled_by"] = identity.username
            payload["cancelled_at"] = finished_at.isoformat()
            cancelled = cancel_pending_appliance_update(
                db,
                job.id,
                finished_at=finished_at,
                error="Task cancelled by operator.",
                result=json.dumps(_redact_task_value(payload), sort_keys=True),
            )
            if not cancelled:
                db.rollback()
                db.expire_all()
                current = db.get(Job, job.id)
                if current is None:
                    raise HTTPException(status_code=404, detail="Task not found")
                if current.status == JobStatus.RUNNING.value:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "A running Appliance Update cannot be cancelled because host mutation "
                            "and update-only status recovery may already be in progress."
                        ),
                    )
                return JSONResponse(
                    {
                        "task": _task_row(current, identity),
                        "message": "Task is already finished.",
                    }
                )
            db.commit()
            record_audit(
                db,
                actor=identity.username,
                action="cancel_task",
                resource_type="job",
                resource_id=job.id,
                detail=f"type={job.type}",
            )
            db.refresh(job)
            return JSONResponse(
                {
                    "task": _task_row(job, identity),
                    "message": "Task cancellation requested.",
                }
            )
        if job.type == "vcf-depot-software-id":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "A queued or running VCFDT Software Depot ID task cannot be cancelled because identity "
                    "replacement may already be in progress."
                ),
            )
        if job.type == "vcf-depot-download" and job.status == JobStatus.RUNNING.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "A running VCFDT profile download cannot be cancelled because the VCFDT process is still executing."
                ),
            )
        if job.type == "vcf-depot-download" and job.status == JobStatus.PENDING.value:
            finished_at = utcnow()
            payload = _job_payload(job)
            payload["state"] = "cancelled"
            payload["cancelled_by"] = identity.username
            payload["cancelled_at"] = finished_at.isoformat()
            cancelled = cancel_pending_vcf_depot_download(
                db,
                job.id,
                profile_id=int(
                    job.vcf_depot_profile_id or payload.get("profile_id") or 0
                ),
                profile_status_before_enqueue=str(
                    payload.get("profile_status_before_enqueue") or "planned"
                ),
                finished_at=finished_at,
                error="Task cancelled by operator.",
                result=json.dumps(_redact_task_value(payload), sort_keys=True),
            )
            if not cancelled:
                db.rollback()
                db.expire_all()
                current = db.get(Job, job.id)
                if current is None:
                    raise HTTPException(status_code=404, detail="Task not found")
                if current.status == JobStatus.RUNNING.value:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "A running VCFDT profile download cannot be cancelled because the VCFDT process "
                            "is still executing."
                        ),
                    )
                return JSONResponse(
                    {
                        "task": _task_row(current, identity),
                        "message": "Task is already finished.",
                    }
                )
            db.commit()
            record_audit(
                db,
                actor=identity.username,
                action="cancel_task",
                resource_type="job",
                resource_id=job.id,
                detail=f"type={job.type}",
            )
            db.refresh(job)
            return JSONResponse(
                {
                    "task": _task_row(job, identity),
                    "message": "Task cancellation requested.",
                }
            )
        if job.type == "appliance-apply":
            payload = _job_payload(job)
            if not payload.get("cancel_requested"):
                payload["state"] = "cancellation-requested"
                payload["cancel_requested"] = True
                payload["cancelled_by"] = identity.username
                payload["cancel_requested_at"] = utcnow().isoformat()
                job.result = json.dumps(_redact_task_value(payload), sort_keys=True)
                db.commit()
                record_audit(
                    db,
                    actor=identity.username,
                    action="request_cancel_task",
                    resource_type="job",
                    resource_id=job.id,
                    detail=f"type={job.type}",
                )
                db.refresh(job)
            return JSONResponse(
                {
                    "task": _task_row(job, identity),
                    "message": "Cancellation requested. The running component will finish before remaining components are skipped.",
                }
            )
        if job.type == "pxe-media-sync" and job.status == JobStatus.PENDING.value:
            try:
                config = json.loads(job.task_config_json or "{}")
            except json.JSONDecodeError:
                config = {}
            if config.get("source") == "upload":
                from atlaso.app.services.network_boot import cleanup_network_boot_upload

                cleanup_network_boot_upload(job.id)
        job.status = JobStatus.CANCELLED.value
        job.finished_at = utcnow()
        job.error = "Task cancelled by operator."
        payload = _job_payload(job)
        payload["state"] = "cancelled"
        payload["cancelled_by"] = identity.username
        payload["cancelled_at"] = job.finished_at.isoformat()
        job.result = json.dumps(_redact_task_value(payload), sort_keys=True)
        job.progress_percent = 100
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="cancel_task",
            resource_type="job",
            resource_id=job.id,
            detail=f"type={job.type}",
        )
        db.refresh(job)
        return JSONResponse(
            {
                "task": _task_row(job, identity),
                "message": "Task cancellation requested.",
            }
        )

    @router.get("/audit-log", response_class=HTMLResponse, response_model=None)
    def audit_log(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the audit log endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "audit.html",
            {
                "identity": identity,
                "audit_event_rows": audit_event_rows_context(db),
            },
        )

    return OperationsUiRouter(
        router=router,
        endpoints={
            "service_state_status_row": service_state_status_row,
            "service_state_to_grid_row": service_state_to_grid_row,
            "dnsmasq_backed_service_grid_row": dnsmasq_backed_service_grid_row,
            "esxi_pxe_service_grid_row": esxi_pxe_service_grid_row,
            "ca_service_grid_row": ca_service_grid_row,
            "vcf_backup_service_grid_row": vcf_backup_service_grid_row,
            "vcf_depot_service_grid_row": vcf_depot_service_grid_row,
            "esx_storage_service_grid_row": esx_storage_service_grid_row,
            "service_grid_row": service_grid_row,
            "services_template_context": services_template_context,
            "service_action_from_ui": service_action_from_ui,
            "service_logs_from_ui": service_logs_from_ui,
            "services": services,
            "logs_page": logs_page,
            "logs_data": logs_data,
            "tasks_page": tasks_page,
            "tasks_status": tasks_status,
            "task_status": task_status,
            "task_log": task_log,
            "cancel_task_from_ui": cancel_task_from_ui,
            "audit_log": audit_log,
        },
    )
