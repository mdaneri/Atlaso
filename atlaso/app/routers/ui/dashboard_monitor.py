"""Own Dashboard and Monitor management UI transports."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from atlaso.app.database import get_db
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services import monitor_runtime, monitor_update_comparison
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]
NO_STORE = {"Cache-Control": "no-store"}


@dataclass(frozen=True)
class DashboardMonitorUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    render: Endpoint
    dashboard_snapshot: Endpoint
    require_monitoring_read: Endpoint
    monitor_payload: Endpoint
    format_byte_rate: Endpoint
    utcnow: Endpoint


@dataclass(frozen=True)
class DashboardMonitorUiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(
    dependencies: DashboardMonitorUiDependencies,
) -> DashboardMonitorUiRouter:
    """Build the Dashboard and Monitor management UI router.

    Args:
        dependencies: Stable facade dependencies used by the extracted transports.

    Returns:
        Configured management router and stable endpoint callables.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    render = dependencies.render
    dashboard_snapshot = dependencies.dashboard_snapshot
    require_monitoring_read = dependencies.require_monitoring_read
    monitor_payload = dependencies.monitor_payload
    format_byte_rate = dependencies.format_byte_rate
    utcnow = dependencies.utcnow

    @router.get("/dashboard", response_class=HTMLResponse, response_model=None)
    def dashboard(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the dashboard endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        snapshot = dashboard_snapshot(db)
        return render(
            request,
            "dashboard.html",
            {
                "identity": identity,
                "dashboard": snapshot,
                "sidebar_pending_apply_count": snapshot["pending_changes"]["count"]
                + snapshot["pending_changes"]["invalid_count"],
            },
        )

    @router.get("/dashboard/data", response_class=JSONResponse, response_model=None)
    def dashboard_data(
        _identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the dashboard data endpoint.

        Args:
            _identity: Authenticated identity supplied by the dependency layer.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return JSONResponse(dashboard_snapshot(db))

    def require_network(identity: Identity = Depends(require_session_identity)) -> None:
        """Require the Monitor and routing read scopes.

        Args:
            identity: Authenticated identity for the requested network view.
        """
        require_monitoring_read(identity)
        if not identity.can("read:routes"):
            raise HTTPException(status_code=403, detail="Routing read access is required")

    def require_services(identity: Identity = Depends(require_session_identity)) -> None:
        """Require the Monitor and service read scopes.

        Args:
            identity: Authenticated identity for the requested service view.
        """
        require_monitoring_read(identity)
        if not identity.can("read:services"):
            raise HTTPException(status_code=403, detail="Service read access is required")

    @router.get("/monitor", response_class=HTMLResponse, response_model=None)
    def monitor_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
        view: Literal["overview", "network", "services"] = "overview",
        update: str = Query(default="", max_length=64),
    ) -> HTMLResponse:
        """Handle the monitor page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
            view: Monitor tab to open.
            update: Appliance Update task to compare in the Network tab.

        Returns:
            The endpoint response.
        """
        require_monitoring_read(identity)
        if view == "network":
            require_network(identity)
        elif view == "services":
            require_services(identity)
        initial_payload = monitor_payload(db, hours=6)
        network_rows = [
            {
                **row,
                "rx_rate_label": format_byte_rate(row.get("rx_bytes_per_sec")),
                "tx_rate_label": format_byte_rate(row.get("tx_bytes_per_sec")),
                "errors": int(row.get("rx_errors") or 0)
                + int(row.get("tx_errors") or 0),
                "drops": int(row.get("rx_dropped") or 0)
                + int(row.get("tx_dropped") or 0),
            }
            for row in initial_payload.get("networks", [])
        ]
        disk_rows = [
            {
                **row,
                "read_rate_label": format_byte_rate(row.get("read_bytes_per_sec")),
                "write_rate_label": format_byte_rate(row.get("write_bytes_per_sec")),
            }
            for row in initial_payload.get("disk_devices", [])
        ]
        return render(
            request,
            "monitor.html",
            {
                "identity": identity,
                "monitor_view": view,
                "monitor_update": update if view == "network" else "",
                "monitor_can_network": identity.can("read:routes"),
                "monitor_can_services": identity.can("read:services"),
                "monitor_initial_payload": initial_payload,
                "monitor_network_fallback_rows": network_rows,
                "monitor_disk_fallback_rows": disk_rows,
            },
        )

    @router.get("/monitor/data", response_class=JSONResponse, response_model=None)
    def monitor_data(
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
        hours: int = Query(default=6, ge=1, le=24),
    ) -> JSONResponse:
        """Handle the monitor data endpoint.

        Args:
            identity: Authenticated identity authorizing the request.
            db: Active database session.
            hours: Hours supplied by the caller.

        Returns:
            The endpoint response.
        """
        require_monitoring_read(identity)
        return JSONResponse(monitor_payload(db, hours=hours))

    @router.get("/monitor/network/data", dependencies=[Depends(require_network)], response_model=None)
    def monitor_network_data() -> JSONResponse:
        """Return a current, scoped network observation."""
        return JSONResponse(monitor_runtime.collect_network(), headers=NO_STORE)

    @router.get("/monitor/network/lookup", dependencies=[Depends(require_network)], response_model=None)
    def monitor_network_lookup(
        destination: Annotated[str, Query(min_length=1, max_length=64)],
        source: Annotated[str, Query(max_length=64)] = "",
        ingress: Annotated[str, Query(max_length=15)] = "",
    ) -> JSONResponse:
        """Return the kernel's route selection for one numeric tuple.

        Args:
            destination: Numeric destination address.
            source: Optional source address of the same family.
            ingress: Optional interface to simulate as the incoming link.
        """
        try:
            result = monitor_runtime.route_lookup(destination, source, ingress)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc), headers=NO_STORE) from exc
        return JSONResponse(result, headers=NO_STORE)

    @router.get("/monitor/network/updates/{job_id}", dependencies=[Depends(require_network)], response_model=None)
    def monitor_update_data(job_id: str, db: Session = Depends(get_db)) -> JSONResponse:
        """Return the comparison for one Appliance Update install task.

        Args:
            job_id: Appliance Update task identifier.
            db: Database session used to load the stored captures.
        """
        comparison = monitor_update_comparison.get_comparison(db, job_id)
        if comparison is None:
            raise HTTPException(status_code=404, detail="Update comparison not found", headers=NO_STORE)
        return JSONResponse(comparison, headers=NO_STORE)

    @router.get("/monitor/services/data", dependencies=[Depends(require_services)], response_model=None)
    def monitor_services_data() -> JSONResponse:
        """Return a current, scoped service and clock observation."""
        return JSONResponse(monitor_runtime.collect_services(), headers=NO_STORE)

    @router.get("/server-time", response_class=JSONResponse, response_model=None)
    def server_time(
        _identity: Identity = Depends(require_session_identity),
    ) -> JSONResponse:
        """Handle the server time endpoint.

        Args:
            _identity: Authenticated identity supplied by the dependency layer.

        Returns:
            The endpoint response.
        """
        now = utcnow()
        return JSONResponse(
            {
                "server_time": now.isoformat(),
                "label": now.strftime("Server %H:%M:%S UTC"),
            }
        )

    endpoints = {
        endpoint.__name__: endpoint
        for endpoint in (
            dashboard,
            dashboard_data,
            monitor_page,
            monitor_data,
            monitor_network_data,
            monitor_network_lookup,
            monitor_update_data,
            monitor_services_data,
            server_time,
        )
    }
    return DashboardMonitorUiRouter(router=router, endpoints=endpoints)
