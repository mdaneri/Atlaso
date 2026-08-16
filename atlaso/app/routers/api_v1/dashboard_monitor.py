"""Own Dashboard and Monitor API v1 transport handlers."""

from __future__ import annotations

import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    AuditEvent,
    PhysicalInterface,
    ServiceState,
    WanPolicy,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    DashboardResponse,
    MonitorResponse,
    PhysicalInterfaceResponse,
    ServiceStateResponse,
    WanPolicyResponse,
)
from atlaso.app.security import Identity, require_scope

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class DashboardMonitorApiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    monitor_payload: Endpoint


@dataclass(frozen=True)
class DashboardMonitorApiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(
    dependencies: DashboardMonitorApiDependencies,
) -> DashboardMonitorApiRouter:
    """Build the Dashboard and Monitor API v1 router.

    Args:
        dependencies: Stable facade dependencies used by the extracted transports.

    Returns:
        Configured API v1 router and stable endpoint callables.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    monitor_payload = dependencies.monitor_payload

    @router.get(
        "/dashboard",
        response_model=DashboardResponse,
        tags=["Dashboard"],
        operation_id="getDashboard",
    )
    def get_dashboard(
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> DashboardResponse:
        """Get Dashboard.

        Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        services = (
            db.execute(select(ServiceState).order_by(ServiceState.display_name))
            .scalars()
            .all()
        )
        interfaces = (
            db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name))
            .scalars()
            .all()
        )
        policies = (
            db.execute(
                select(WanPolicy)
                .where(WanPolicy.enabled.is_(True))
                .order_by(WanPolicy.name)
            )
            .scalars()
            .all()
        )
        audit_events = (
            db.execute(
                select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(5)
            )
            .scalars()
            .all()
        )
        return DashboardResponse(
            appliance={
                "hostname": socket.gethostname(),
                "management_ip": "127.0.0.1",
                "uptime": "development session",
                "cpu_usage_percent": 12,
                "memory_usage_percent": 38,
            },
            service_health=[
                ServiceStateResponse.model_validate(service) for service in services
            ],
            interfaces=[
                PhysicalInterfaceResponse.model_validate(interface)
                for interface in interfaces
            ],
            active_wan_policies=[
                WanPolicyResponse.model_validate(policy) for policy in policies
            ],
            disk_usage={
                "root_percent": 41,
                "repository_percent": 3,
                "vcf_backup_percent": 1,
            },
            recent_audit_events=[
                {
                    "created_at": event.created_at.isoformat(),
                    "actor": event.actor,
                    "action": event.action,
                    "resource_type": event.resource_type,
                    "success": event.success,
                }
                for event in audit_events
            ],
        )

    @router.get(
        "/monitor",
        response_model=MonitorResponse,
        tags=["Monitor"],
        operation_id="getMonitor",
    )
    def get_monitor(
        identity: Annotated[Identity, Depends(require_scope("read:monitoring"))],
        db: Session = Depends(get_db),
        hours: int = Query(
            default=6,
            ge=1,
            le=24,
            description="Monitoring history window, in hours, from 1 through 24.",
        ),
    ) -> MonitorResponse:
        """Get Monitor.

        Requires the `read:monitoring` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            hours: Hours consumed by get monitor.
        """
        return MonitorResponse(**monitor_payload(db, hours=hours))

    endpoints = {
        endpoint.__name__: endpoint for endpoint in (get_dashboard, get_monitor)
    }
    return DashboardMonitorApiRouter(router=router, endpoints=endpoints)
