from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from atlaso.app.database import get_db
from atlaso.app.security import Identity
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class ApplianceApplyUiDependencies:
    require_management_ui_request: Endpoint
    require_session_identity: Endpoint
    invalidate_observed_management_dhcp_dns: Endpoint
    appliance_apply_context: Endpoint
    appliance_apply_status_projection: Endpoint
    appliance_apply_client_status: Endpoint
    active_appliance_apply_job: Endpoint
    submit_appliance_apply: Endpoint
    task_row: Endpoint


@dataclass(frozen=True)
class ApplianceApplyUiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: ApplianceApplyUiDependencies) -> ApplianceApplyUiRouter:
    """Build the extracted Appliance Apply router without importing its facade.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured domain router and its stable endpoint callables.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )

    @router.get("/appliance-apply", response_class=RedirectResponse, response_model=None)
    def appliance_apply_page(
        _identity: Identity = Depends(dependencies.require_session_identity),
    ) -> RedirectResponse:
        """Handle the appliance apply page endpoint.

        Args:
            _identity: Authenticated identity supplied by the dependency layer.

        Returns:
            The endpoint response.
        """
        return RedirectResponse("/dashboard#appliance-apply-review", status_code=303)

    @router.get("/appliance-apply/review", response_class=JSONResponse, response_model=None)
    def appliance_apply_review(
        identity: Identity = Depends(dependencies.require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the appliance apply review endpoint.

        Args:
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        dependencies.invalidate_observed_management_dhcp_dns()
        context = dependencies.appliance_apply_context(db)
        units = [
            {
                "id": unit["id"],
                "label": unit["label"],
                "page_url": unit["page_url"],
                "summary": unit["summary"],
                "valid": unit["valid"],
                "validation_errors": unit["validation_errors"],
                "validation_warnings": unit["validation_warnings"],
                "connection_warnings": unit["connection_warnings"],
                "config_path": unit["config_path"],
                "config_preview": unit["config_preview"],
                "config_diff": unit["config_diff"],
                "has_baseline": unit["has_baseline"],
                "selected": unit["valid"],
                "format_volumes": [
                    {
                        "id": volume["id"],
                        "name": volume["name"],
                        "stable_device_id": volume["stable_device_id"],
                        "fingerprint": volume["fingerprint"],
                        "confirmation": f"FORMAT {volume['name']}",
                    }
                    for volume in unit.get("context", {}).get("esx_storage_manifest", {}).get("volumes", [])
                    if volume.get("requires_format")
                ],
            }
            for unit in context["changed_apply_units"]
        ]
        active_job = dependencies.active_appliance_apply_job(db)
        return JSONResponse(
            {
                "units": units,
                "pending_count": len(units),
                "active_task": dependencies.task_row(active_job, identity) if active_job is not None else None,
            }
        )

    @router.get("/appliance-apply/status", response_class=JSONResponse, response_model=None)
    def appliance_apply_status_api(
        refresh: bool = Query(False),
        identity: Identity = Depends(dependencies.require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the appliance apply status API endpoint.

        Args:
            refresh: Whether to replace the cached sidebar projection.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        projection = dependencies.appliance_apply_status_projection(db, refresh=refresh)
        pending_count = projection["pending_count"]
        active_job = dependencies.active_appliance_apply_job(db)
        units = [dependencies.appliance_apply_client_status(unit) for unit in projection["units"]]
        return JSONResponse(
            {
                "units": units,
                "pending_count": pending_count,
                "label": "Review appliance changes" if pending_count else "Appliance Apply",
                "detail": (
                    f"{pending_count} pending {'unit' if pending_count == 1 else 'units'}"
                    if pending_count
                    else "Desired state current"
                ),
                "badge": "pending" if pending_count else "current",
                "locked": active_job is not None,
                "active_task": dependencies.task_row(active_job, identity) if active_job is not None else None,
            }
        )

    @router.post("/appliance-apply", response_class=HTMLResponse, response_model=None)
    def submit_appliance_apply(
        request: Request,
        background_tasks: BackgroundTasks,
        selected_units: list[str] = Form(default=[]),
        format_confirmations: list[str] = Form(default=[]),
        refresh_vcf_depot_software_depot_id: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(dependencies.require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the submit appliance apply endpoint.

        Args:
            request: Incoming HTTP request.
            background_tasks: Background tasks supplied by the caller.
            selected_units: Selected units supplied by the caller.
            format_confirmations: Format confirmations supplied by the caller.
            refresh_vcf_depot_software_depot_id: Whether to refresh the VCFDT software depot identifier.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return cast(
            Response,
            dependencies.submit_appliance_apply(
                request=request,
                background_tasks=background_tasks,
                selected_units=selected_units,
                format_confirmations=format_confirmations,
                refresh_vcf_depot_software_depot_id=refresh_vcf_depot_software_depot_id,
                csrf=csrf,
                identity=identity,
                db=db,
            ),
        )

    endpoints: dict[str, Endpoint] = {
        "appliance_apply_page": appliance_apply_page,
        "appliance_apply_review": appliance_apply_review,
        "appliance_apply_status_api": appliance_apply_status_api,
        "submit_appliance_apply": submit_appliance_apply,
    }
    return ApplianceApplyUiRouter(router=router, endpoints=endpoints)
