from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi import Path as ApiPath
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import AuditEvent, Job, JobStatus, ServiceState, utcnow
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    AuditEventResponse,
    JobResponse,
    ServiceActionResponse,
    ServiceStateResponse,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.network_boot import cleanup_network_boot_upload
from atlaso.app.services.service_registry import SERVICE_STATE_IDS

Endpoint = Callable[..., Any]
APPROVED_SERVICES = set(SERVICE_STATE_IDS) | {"vcf-offline-depot"}


@dataclass(frozen=True)
class OperationsApiDependencies:
    get_dhcp_settings_row: Endpoint
    get_dns_settings_row: Endpoint
    service_state_response: Endpoint


@dataclass(frozen=True)
class OperationsApiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: OperationsApiDependencies) -> OperationsApiRouter:
    """Build the extracted operational API router without importing its facade.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured operational API router and its stable endpoint callables.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    get_dhcp_settings_row = dependencies.get_dhcp_settings_row
    get_dns_settings_row = dependencies.get_dns_settings_row
    service_state_response = dependencies.service_state_response

    @router.get(
        "/services",
        response_model=list[ServiceStateResponse],
        tags=["Services"],
        operation_id="listServices",
    )
    def list_services(
        identity: Annotated[Identity, Depends(require_scope("read:services"))],
        db: Session = Depends(get_db),
    ) -> list[ServiceStateResponse]:
        """List Services.

        Requires the `read:services` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rows = (
            db.execute(
                select(ServiceState)
                .where(ServiceState.service.in_(SERVICE_STATE_IDS))
                .order_by(ServiceState.display_name)
            )
            .scalars()
            .all()
        )
        return [service_state_response(row, db) for row in rows]

    @router.get(
        "/services/{service}",
        response_model=ServiceStateResponse,
        tags=["Services"],
        operation_id="getService",
    )
    def get_service(
        service: Annotated[
            str,
            ApiPath(
                description="Path value for service, identifying the resource addressed by `/api/v1/services/{service}`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:services"))],
        db: Session = Depends(get_db),
    ) -> ServiceStateResponse:
        """Get Service.

        Requires the `read:services` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            service: Atlaso or host service affected by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        if service not in SERVICE_STATE_IDS:
            raise HTTPException(status_code=404, detail="Service not found")
        row = db.execute(
            select(ServiceState).where(ServiceState.service == service)
        ).scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Service not found")
        return service_state_response(row, db)

    def service_action(
        service: str, action: str, identity: Identity, db: Session
    ) -> ServiceActionResponse:
        """Return service action.

        Args:
            service: Atlaso service affected by the operation.
            action: Operation to perform on the target resource.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if service not in APPROVED_SERVICES:
            raise HTTPException(
                status_code=404, detail="Service is not approved for control"
            )
        if action not in {"start", "stop", "restart", "enable", "disable"}:
            raise HTTPException(status_code=422, detail="Unsupported service action")
        row = db.execute(
            select(ServiceState).where(ServiceState.service == service)
        ).scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Service not found")
        if action == "enable":
            row.enabled = True
            if service == "dns":
                get_dns_settings_row(db).enabled = True
            elif service == "dhcp":
                get_dhcp_settings_row(db).enabled = True
        elif action == "disable":
            row.enabled = False
            if service == "dns":
                get_dns_settings_row(db).enabled = False
            elif service == "dhcp":
                get_dhcp_settings_row(db).enabled = False
        elif action in {"start", "restart"}:
            row.running = True
        elif action == "stop":
            row.running = False
        db.add(row)
        result = SystemAdapter().service_action(service, action)
        record_audit(
            db,
            actor=identity.username,
            action=f"{action}_service_dry_run",
            resource_type="service",
            resource_id=service,
            detail=" ".join(result.command),
        )
        return ServiceActionResponse(
            service=service,
            action=action,
            dry_run=result.dry_run,
            command=result.command,
        )

    @router.post(
        "/services/{service}/start",
        response_model=ServiceActionResponse,
        tags=["Services"],
        operation_id="startService",
    )
    def start_service(
        service: Annotated[
            str,
            ApiPath(
                description="Path value for service, identifying the resource addressed by `/api/v1/services/{service}/start`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:services"))],
        db: Session = Depends(get_db),
    ) -> ServiceActionResponse:
        """Start Service.

        Requires the `write:services` API scope. The action runs through the endpoint's existing audited
        adapter or task boundary; inspect the returned state before treating the operation as complete.

        Args:
            service: Atlaso or host service affected by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return service_action(service, "start", identity, db)

    @router.post(
        "/services/{service}/stop",
        response_model=ServiceActionResponse,
        tags=["Services"],
        operation_id="stopService",
    )
    def stop_service(
        service: Annotated[
            str,
            ApiPath(
                description="Path value for service, identifying the resource addressed by `/api/v1/services/{service}/stop`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:services"))],
        db: Session = Depends(get_db),
    ) -> ServiceActionResponse:
        """Stop Service.

        Requires the `write:services` API scope. The action runs through the endpoint's existing audited
        adapter or task boundary; inspect the returned state before treating the operation as complete.

        Args:
            service: Atlaso or host service affected by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return service_action(service, "stop", identity, db)

    @router.post(
        "/services/{service}/restart",
        response_model=ServiceActionResponse,
        tags=["Services"],
        operation_id="restartService",
    )
    def restart_service(
        service: Annotated[
            str,
            ApiPath(
                description="Path value for service, identifying the resource addressed by `/api/v1/services/{service}/restart`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:services"))],
        db: Session = Depends(get_db),
    ) -> ServiceActionResponse:
        """Restart Service.

        Requires the `write:services` API scope. The action runs through the endpoint's existing audited
        adapter or task boundary; inspect the returned state before treating the operation as complete.

        Args:
            service: Atlaso or host service affected by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return service_action(service, "restart", identity, db)

    @router.post(
        "/services/{service}/enable",
        response_model=ServiceActionResponse,
        tags=["Services"],
        operation_id="enableService",
    )
    def enable_service(
        service: Annotated[
            str,
            ApiPath(
                description="Path value for service, identifying the resource addressed by `/api/v1/services/{service}/enable`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:services"))],
        db: Session = Depends(get_db),
    ) -> ServiceActionResponse:
        """Enable Service.

        Requires the `write:services` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            service: Atlaso or host service affected by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return service_action(service, "enable", identity, db)

    @router.post(
        "/services/{service}/disable",
        response_model=ServiceActionResponse,
        tags=["Services"],
        operation_id="disableService",
    )
    def disable_service(
        service: Annotated[
            str,
            ApiPath(
                description="Path value for service, identifying the resource addressed by `/api/v1/services/{service}/disable`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:services"))],
        db: Session = Depends(get_db),
    ) -> ServiceActionResponse:
        """Disable Service.

        Requires the `write:services` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            service: Atlaso or host service affected by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return service_action(service, "disable", identity, db)

    @router.get(
        "/services/{service}/logs",
        response_model=list[str],
        tags=["Services"],
        operation_id="getServiceLogs",
    )
    def get_service_logs(
        service: Annotated[
            str,
            ApiPath(
                description="Path value for service, identifying the resource addressed by `/api/v1/services/{service}/logs`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:logs"))],
    ) -> list[str]:
        """Get Service Logs.

        Requires the `read:logs` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            service: Atlaso or host service affected by the operation.
            identity: Authenticated identity authorizing the operation.
        """
        if service not in APPROVED_SERVICES:
            raise HTTPException(status_code=404, detail="Log source is not approved")
        return [
            f"dry-run log source for {service}",
            "No host journal is read in development mode.",
        ]

    @router.get(
        "/logs", response_model=list[str], tags=["Logs"], operation_id="listLogs"
    )
    def list_logs(
        identity: Annotated[Identity, Depends(require_scope("read:logs"))],
    ) -> list[str]:
        """List Logs.

        Requires the `read:logs` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
        """
        return [
            "system",
            "atlaso",
            "dnsmasq",
            "ldap",
            "ntp",
            "nginx",
            "openssh",
            "nftables",
        ]

    @router.get(
        "/logs/{source}",
        response_model=list[str],
        tags=["Logs"],
        operation_id="getLogSource",
    )
    def get_log_source(
        source: Annotated[
            str,
            ApiPath(
                description="Path value for source, identifying the resource addressed by `/api/v1/logs/{source}`."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:logs"))],
    ) -> list[str]:
        """Get Log Source.

        Requires the `read:logs` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            source: Source object or location from which data is obtained.
            identity: Authenticated identity authorizing the operation.
        """
        if source not in {
            "system",
            "atlaso",
            "dnsmasq",
            "ldap",
            "ntp",
            "nginx",
            "openssh",
            "nftables",
        }:
            raise HTTPException(status_code=404, detail="Log source is not approved")
        return [
            f"dry-run log source for {source}",
            "Host log streaming is not enabled in the MVP scaffold.",
        ]

    @router.get(
        "/audit",
        response_model=list[AuditEventResponse],
        tags=["Audit"],
        operation_id="listAuditEvents",
    )
    def list_audit_events(
        identity: Annotated[Identity, Depends(require_scope("read:audit"))],
        db: Session = Depends(get_db),
        user: Annotated[
            str | None,
            Query(
                description="Optional query value controlling user for this response."
            ),
        ] = None,
        action: Annotated[
            str | None,
            Query(
                description="Optional query value controlling action for this response."
            ),
        ] = None,
        resource_type: Annotated[
            str | None,
            Query(
                description="Optional query value controlling resource type for this response."
            ),
        ] = None,
        success: Annotated[
            bool | None,
            Query(
                description="Optional query value controlling success for this response."
            ),
        ] = None,
        start_time: Annotated[
            datetime | None,
            Query(
                description="Optional query value controlling start time for this response."
            ),
        ] = None,
        end_time: Annotated[
            datetime | None,
            Query(
                description="Optional query value controlling end time for this response."
            ),
        ] = None,
    ) -> list[AuditEventResponse]:
        """List Audit Events.

        Requires the `read:audit` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            user: User record or identity affected by the operation.
            action: Action consumed by list audit events.
            resource_type: Resource type consumed by list audit events.
            success: Success consumed by list audit events.
            start_time: Start time consumed by list audit events.
            end_time: End time consumed by list audit events.
        """
        query = select(AuditEvent)
        if user:
            query = query.where(AuditEvent.actor == user)
        if action:
            query = query.where(AuditEvent.action == action)
        if resource_type:
            query = query.where(AuditEvent.resource_type == resource_type)
        if success is not None:
            query = query.where(AuditEvent.success.is_(success))
        if start_time:
            query = query.where(AuditEvent.created_at >= start_time)
        if end_time:
            query = query.where(AuditEvent.created_at <= end_time)
        return [
            AuditEventResponse.model_validate(row)
            for row in db.execute(
                query.order_by(desc(AuditEvent.created_at)).limit(200)
            )
            .scalars()
            .all()
        ]

    @router.get(
        "/jobs",
        response_model=list[JobResponse],
        tags=["Jobs"],
        operation_id="listJobs",
    )
    def list_jobs(
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
    ) -> list[JobResponse]:
        """List Jobs.

        Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            JobResponse.model_validate(row)
            for row in db.execute(select(Job).order_by(desc(Job.created_at)))
            .scalars()
            .all()
        ]

    @router.post(
        "/jobs",
        response_model=JobResponse,
        status_code=202,
        tags=["Jobs"],
        operation_id="createJob",
    )
    def create_job(
        identity: Annotated[Identity, Depends(require_scope("admin:all"))],
        db: Session = Depends(get_db),
    ) -> JobResponse:
        """Create Job.

        Requires the `admin:all` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        job = Job(
            id=f"job_{uuid4().hex[:12]}",
            type="manual-placeholder",
            created_by=identity.username,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        record_audit(
            db,
            actor=identity.username,
            action="create_job",
            resource_type="job",
            resource_id=job.id,
        )
        return JobResponse.model_validate(job)

    @router.get(
        "/jobs/{job_id}",
        response_model=JobResponse,
        tags=["Jobs"],
        operation_id="getJob",
    )
    def get_job(
        job_id: Annotated[
            str,
            ApiPath(
                description="Unique identifier of the job record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
    ) -> JobResponse:
        """Get Job.

        Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            job_id: Stable identifier of the associated job resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        job = db.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return JobResponse.model_validate(job)

    @router.post(
        "/jobs/{job_id}/cancel",
        response_model=JobResponse,
        tags=["Jobs"],
        operation_id="cancelJob",
    )
    def cancel_job(
        job_id: Annotated[
            str,
            ApiPath(
                description="Unique identifier of the job record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("admin:all"))],
        db: Session = Depends(get_db),
    ) -> JobResponse:
        """Cancel Job.

        Requires the `admin:all` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            job_id: Stable identifier of the associated job resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        job = db.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
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
        if job.type == "pxe-media-sync" and job.status == "pending":
            try:
                config = json.loads(job.task_config_json or "{}")
            except json.JSONDecodeError:
                config = {}
            if config.get("source") == "upload":
                cleanup_network_boot_upload(job.id)
        job.status = "cancelled"
        job.finished_at = utcnow()
        db.commit()
        db.refresh(job)
        record_audit(
            db,
            actor=identity.username,
            action="cancel_job",
            resource_type="job",
            resource_id=job.id,
        )
        return JobResponse.model_validate(job)

    return OperationsApiRouter(
        router=router,
        endpoints={
            "list_services": list_services,
            "get_service": get_service,
            "service_action": service_action,
            "start_service": start_service,
            "stop_service": stop_service,
            "restart_service": restart_service,
            "enable_service": enable_service,
            "disable_service": disable_service,
            "get_service_logs": get_service_logs,
            "list_logs": list_logs,
            "get_log_source": get_log_source,
            "list_audit_events": list_audit_events,
            "list_jobs": list_jobs,
            "create_job": create_job,
            "get_job": get_job,
            "cancel_job": cancel_job,
        },
    )
