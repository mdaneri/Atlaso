"""Own appliance power and Appliance Update management UI transports."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import get_db
from atlaso.app.models import Job, JobStatus, ManagedPackage, UpdateSource
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.appliance_update import (
    APPLIANCE_UPDATE_SETTINGS_KEY,
    DEFAULT_ATLASO_MANIFEST_URL,
    UPDATE_STREAMS,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class ApplianceMaintenanceUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    require_admin_identity: Endpoint
    verify_csrf: Endpoint
    render: Endpoint
    appliance_update_context: Endpoint
    appliance_update_availability_summary: Endpoint
    appliance_update_settings: Endpoint
    adapter_result_to_payload: Endpoint
    default_source_settings: Endpoint
    encrypt_secret: Endpoint
    get_settings: Endpoint
    managed_package_from_form: Endpoint
    record_audit: Endpoint
    render_update_manifest: Endpoint
    set_setting_value: Endpoint
    source_rows: Endpoint
    submit_appliance_update: Endpoint
    system_adapter: Endpoint
    update_settings_to_json: Endpoint
    update_source_payload: Endpoint
    update_source_settings: Endpoint
    utcnow: Endpoint
    validate_update_settings: Endpoint
    validate_update_source: Endpoint


@dataclass(frozen=True)
class ApplianceMaintenanceUiRouters:
    """Return the ordered maintenance routers and compatibility endpoint exports."""

    power_router: APIRouter
    update_router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_routers(
    dependencies: ApplianceMaintenanceUiDependencies,
) -> ApplianceMaintenanceUiRouters:
    """Build the segmented appliance-maintenance management routers.

    Args:
        dependencies: Stable facade dependencies used by the extracted transports.

    Returns:
        Configured power and update routers plus stable endpoint callables.
    """
    power_router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    update_router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    require_admin_identity = dependencies.require_admin_identity
    verify_csrf = dependencies.verify_csrf
    render = dependencies.render
    appliance_update_context = dependencies.appliance_update_context
    appliance_update_availability_summary = dependencies.appliance_update_availability_summary
    appliance_update_settings = dependencies.appliance_update_settings
    adapter_result_to_payload = dependencies.adapter_result_to_payload
    default_source_settings = dependencies.default_source_settings
    encrypt_secret = dependencies.encrypt_secret
    get_settings = dependencies.get_settings
    _managed_package_from_form = dependencies.managed_package_from_form
    record_audit = dependencies.record_audit
    render_update_manifest = dependencies.render_update_manifest
    set_setting_value = dependencies.set_setting_value
    source_rows = dependencies.source_rows
    submit_appliance_update = dependencies.submit_appliance_update
    SystemAdapter = dependencies.system_adapter
    update_settings_to_json = dependencies.update_settings_to_json
    update_source_payload = dependencies.update_source_payload
    update_source_settings = dependencies.update_source_settings
    utcnow = dependencies.utcnow
    validate_update_settings = dependencies.validate_update_settings
    validate_update_source = dependencies.validate_update_source

    @power_router.post("/appliance/power/{action}", response_model=None)
    def appliance_power_action(
        request: Request,
        action: str,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the appliance power action endpoint.

        Args:
            request: Incoming HTTP request.
            action: Operation to perform on the target resource.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        if action not in {"reboot", "shutdown"}:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Unknown appliance power action",
            )

        now = utcnow()
        job = Job(
            id=f"job_{uuid4().hex[:12]}",
            type=f"appliance-{action}",
            status=JobStatus.PENDING.value,
            created_by=identity.username,
            progress_percent=0,
        )
        db.add(job)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action=f"submit_appliance_{action}",
            resource_type="job",
            resource_id=job.id,
            detail=f"Confirmed appliance {action} task submitted.",
        )

        job.status = JobStatus.RUNNING.value
        job.started_at = now
        db.add(job)
        db.commit()
        try:
            result = SystemAdapter().schedule_appliance_power(action)
        except Exception as exc:  # noqa: BLE001 - normalize adapter boundary failures into a safe result.
            result = AdapterResult(
                command=["atlaso-helper", "appliance-power", action],
                returncode=1,
                stdout="",
                stderr=str(exc),
                dry_run=get_settings().dry_run_system_adapters,
            )

        succeeded = result.returncode == 0
        state = "failed"
        if succeeded:
            state = "dry-run recorded" if result.dry_run else "scheduled"
        payload = {
            "action": action,
            "state": state,
            "status": (
                JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value
            ),
            "success": succeeded,
            "scheduled": succeeded and not result.dry_run,
            "delay_seconds": 5,
            "dry_run": result.dry_run,
            "commands": [adapter_result_to_payload(result)],
        }
        job.status = payload["status"]
        job.finished_at = utcnow()
        job.progress_percent = 100
        job.result = json.dumps(payload, indent=2, sort_keys=True)
        job.error = None if succeeded else f"Appliance {action} scheduling failed."
        db.add(job)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action=f"schedule_appliance_{action}",
            resource_type="job",
            resource_id=job.id,
            detail=" ".join(result.command),
            success=succeeded,
        )
        return RedirectResponse(f"/tasks?job_id={job.id}", status_code=303)

    @update_router.get(
        "/appliance-update/availability",
        response_class=JSONResponse,
        response_model=None,
        include_in_schema=False,
    )
    def appliance_update_availability(
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Return sanitized browser-only update availability.

        Args:
            identity: Authenticated browser session identity.
            db: Active database session.
        """
        del identity
        return JSONResponse(
            appliance_update_availability_summary(db),
            headers={"Cache-Control": "no-store"},
        )

    @update_router.get(
        "/appliance-update", response_class=HTMLResponse, response_model=None
    )
    def appliance_update_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the appliance update page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "appliance_update.html",
            {"identity": identity, **appliance_update_context(db)},
        )

    @update_router.post("/appliance-update/settings", response_model=None)
    def update_appliance_update_settings(
        request: Request,
        photon_source: str = Form("configured Photon repositories"),
        atlaso_manifest_url: str = Form(DEFAULT_ATLASO_MANIFEST_URL),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update appliance update settings endpoint.

        Args:
            request: Incoming HTTP request.
            photon_source: Photon source supplied by the caller.
            atlaso_manifest_url: URL for the atlaso manifest.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        settings = {
            "photon_source": photon_source.strip()
            or "configured Photon repositories",
            "atlaso_manifest_url": atlaso_manifest_url.strip()
            or DEFAULT_ATLASO_MANIFEST_URL,
        }
        errors = validate_update_settings(settings)
        if errors:
            if request.headers.get("X-Atlaso-Autosave") == "1":
                return JSONResponse(
                    {"status": "error", "errors": errors}, status_code=422
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": " ".join(errors),
                },
                status_code=422,
            )
        set_setting_value(
            db,
            APPLIANCE_UPDATE_SETTINGS_KEY,
            update_settings_to_json(settings),
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_appliance_update_settings",
            resource_type="appliance_update",
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(
                {
                    "status": "saved",
                    "saved_at": utcnow().isoformat(),
                    "manifest_preview": render_update_manifest(
                        selected_streams=list(UPDATE_STREAMS),
                        settings=settings,
                        actor=identity.username,
                    ),
                }
            )
        return RedirectResponse("/appliance-update", status_code=303)

    @update_router.post(
        "/appliance-update/sources/{source_id}", response_model=None
    )
    def update_appliance_update_source(
        source_id: int,
        request: Request,
        name: str = Form(...),
        url: str = Form(""),
        priority: int = Form(50),
        enabled: str | None = Form(None),
        enabled_present: str | None = Form(None),
        trusted: str | None = Form(None),
        channel: str = Form("stable"),
        managed: str | None = Form(None),
        gpgcheck: str | None = Form(None),
        gpgkey: str = Form(""),
        tls_verify: str | None = Form(None),
        credential_username: str = Form(""),
        credential_secret: str = Form(""),
        clear_credential: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update appliance update source endpoint.

        Args:
            source_id: Identifier of the source.
            request: Incoming HTTP request.
            name: Name of the target object.
            url: URL of the target resource or service.
            priority: Ordering priority assigned to the item.
            enabled: Whether the requested behavior is enabled.
            enabled_present: Enabled present supplied by the caller.
            trusted: Trusted supplied by the caller.
            channel: Channel supplied by the caller.
            managed: Managed supplied by the caller.
            gpgcheck: Gpgcheck supplied by the caller.
            gpgkey: Gpgkey supplied by the caller.
            tls_verify: Tls verify supplied by the caller.
            credential_username: Credential username supplied by the caller.
            credential_secret: Credential secret supplied by the caller.
            clear_credential: Clear credential supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        wizard_request = request.headers.get("X-Atlaso-Wizard") == "1"
        source = db.get(UpdateSource, source_id)
        if source is None:
            raise HTTPException(status_code=404, detail="Update source not found.")
        source.name = name.strip()
        source.url = url.strip()
        source.priority = priority
        if enabled_present is not None:
            source.enabled = enabled == "on"
        settings = update_source_settings(source)
        if source.kind == "powershell":
            settings["trusted"] = trusted == "on"
        elif source.kind == "atlaso":
            settings["channel"] = channel.strip().lower()
        elif source.kind == "photon":
            settings.update(
                {
                    "managed": managed == "on",
                    "gpgcheck": gpgcheck == "on",
                    "gpgkey": gpgkey.strip(),
                    "tls_verify": tls_verify == "on",
                }
            )
        source.settings_json = json.dumps(settings, sort_keys=True)
        if clear_credential == "on":
            source.credential_encrypted = ""
        elif credential_secret:
            source.credential_encrypted = encrypt_secret(
                json.dumps(
                    {
                        "username": credential_username.strip(),
                        "secret": credential_secret,
                    }
                )
            )
        source.validation_status = "not_checked"
        source.validation_message = ""
        source.validated_at = None
        source.updated_at = utcnow()
        errors = validate_update_source(source)
        if not source.name:
            errors.insert(0, "Source name is required.")
        if errors:
            db.rollback()
            if wizard_request:
                return JSONResponse(
                    {
                        "status": "error",
                        "detail": " ".join(errors),
                        "errors": errors,
                    },
                    status_code=422,
                )
            if request.headers.get("X-Atlaso-Autosave") == "1":
                return JSONResponse(
                    {"status": "error", "errors": errors}, status_code=422
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": " ".join(errors),
                },
                status_code=422,
            )
        db.add(source)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            message = "A source with this name and type already exists."
            if wizard_request:
                return JSONResponse(
                    {"status": "error", "detail": message, "errors": [message]},
                    status_code=409,
                )
            if request.headers.get("X-Atlaso-Autosave") == "1":
                return JSONResponse(
                    {"status": "error", "errors": [message]}, status_code=409
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": message,
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_software_source",
            resource_type="update_source",
            resource_id=str(source.id),
            detail=f"kind={source.kind}; name={source.name}",
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(
                {"status": "saved", "saved_at": utcnow().isoformat()}
            )
        if wizard_request:
            return JSONResponse(
                {"status": "saved", "source": update_source_payload(source)}
            )
        return RedirectResponse("/appliance-update", status_code=303)

    @update_router.post("/appliance-update/sources", response_model=None)
    def create_appliance_update_source(
        request: Request,
        kind: str = Form(...),
        name: str = Form(...),
        url: str = Form(""),
        priority: int = Form(50),
        enabled: str | None = Form(None),
        trusted: str | None = Form(None),
        channel: str = Form("stable"),
        managed: str | None = Form(None),
        gpgcheck: str | None = Form(None),
        gpgkey: str = Form(""),
        tls_verify: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create appliance update source endpoint.

        Args:
            request: Incoming HTTP request.
            kind: Kind supplied by the caller.
            name: Name of the target object.
            url: URL of the target resource or service.
            priority: Ordering priority assigned to the item.
            enabled: Whether the requested behavior is enabled.
            trusted: Trusted supplied by the caller.
            channel: Channel supplied by the caller.
            managed: Managed supplied by the caller.
            gpgcheck: Gpgcheck supplied by the caller.
            gpgkey: Gpgkey supplied by the caller.
            tls_verify: Tls verify supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        wizard_request = request.headers.get("X-Atlaso-Wizard") == "1"
        normalized_kind = kind.strip().lower()
        settings = default_source_settings(normalized_kind)
        if normalized_kind == "powershell" and (
            wizard_request or trusted is not None
        ):
            settings["trusted"] = trusted == "on"
        elif normalized_kind == "atlaso":
            settings["channel"] = channel.strip().lower()
        elif normalized_kind == "photon" and wizard_request:
            settings.update(
                {
                    "managed": managed == "on",
                    "gpgcheck": gpgcheck == "on",
                    "gpgkey": gpgkey.strip(),
                    "tls_verify": tls_verify == "on",
                }
            )
        source = UpdateSource(
            kind=normalized_kind,
            name=name.strip(),
            url=url.strip(),
            priority=priority,
            enabled=enabled == "on",
            settings_json=json.dumps(settings, sort_keys=True),
        )
        errors = validate_update_source(source)
        if not source.name:
            errors.insert(0, "Source name is required.")
        if errors:
            if wizard_request:
                return JSONResponse(
                    {
                        "status": "error",
                        "detail": " ".join(errors),
                        "errors": errors,
                    },
                    status_code=422,
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": " ".join(errors),
                },
                status_code=422,
            )
        db.add(source)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            message = "A source with this name and type already exists."
            if wizard_request:
                return JSONResponse(
                    {"status": "error", "detail": message, "errors": [message]},
                    status_code=409,
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": message,
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_software_source",
            resource_type="update_source",
            resource_id=str(source.id),
            detail=f"kind={source.kind}; name={source.name}",
        )
        if wizard_request:
            return JSONResponse(
                {"status": "saved", "source": update_source_payload(source)}
            )
        return RedirectResponse(
            "/appliance-update#update-sources", status_code=303
        )

    @update_router.post(
        "/appliance-update/sources/{source_id}/delete", response_model=None
    )
    def delete_appliance_update_source(
        source_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete appliance update source endpoint.

        Args:
            source_id: Identifier of the source.
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
        require_admin_identity(identity)
        source = db.get(UpdateSource, source_id)
        if source is None:
            raise HTTPException(status_code=404, detail="Update source not found.")
        packages = (
            db.execute(
                select(ManagedPackage).where(ManagedPackage.source_id == source.id)
            )
            .scalars()
            .all()
        )
        if packages:
            names = ", ".join(package.name for package in packages)
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": (
                        "Reassign or delete packages using this source first: "
                        f"{names}."
                    ),
                },
                status_code=409,
            )
        name = source.name
        kind = source.kind
        db.delete(source)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_software_source",
            resource_type="update_source",
            resource_id=str(source_id),
            detail=f"kind={kind}; name={name}",
        )
        return RedirectResponse(
            "/appliance-update#update-sources", status_code=303
        )

    @update_router.post("/appliance-update/packages", response_model=None)
    def create_managed_update_package(
        request: Request,
        name: str = Form(...),
        source_id: int = Form(...),
        policy: str = Form("pinned"),
        target_version: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create managed update package endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            source_id: Identifier of the source.
            policy: Policy values to validate or enforce.
            target_version: Target version supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        wizard_request = request.headers.get("X-Atlaso-Wizard") == "1"
        package = ManagedPackage(
            ecosystem="powershell", name="", source_id=source_id
        )
        errors = _managed_package_from_form(
            package,
            name=name,
            source_id=source_id,
            policy=policy,
            target_version=target_version,
            enabled=enabled == "on",
            db=db,
        )
        if errors:
            if wizard_request:
                return JSONResponse(
                    {
                        "status": "error",
                        "detail": " ".join(errors),
                        "errors": errors,
                    },
                    status_code=422,
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": " ".join(errors),
                },
                status_code=422,
            )
        db.add(package)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            message = "This PowerShell module is already managed."
            if wizard_request:
                return JSONResponse(
                    {"status": "error", "detail": message, "errors": [message]},
                    status_code=409,
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": message,
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_managed_package",
            resource_type="managed_package",
            resource_id=str(package.id),
            detail=f"ecosystem=powershell; name={package.name}",
        )
        if wizard_request:
            return JSONResponse(
                {"status": "saved", "package": {"id": package.id}}
            )
        return RedirectResponse(
            "/appliance-update#managed-packages", status_code=303
        )

    @update_router.post(
        "/appliance-update/packages/{package_id}", response_model=None
    )
    def update_managed_update_package(
        package_id: int,
        request: Request,
        name: str = Form(...),
        source_id: int = Form(...),
        policy: str = Form("pinned"),
        target_version: str = Form(""),
        enabled: str | None = Form(None),
        enabled_present: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update managed update package endpoint.

        Args:
            package_id: Identifier of the package.
            request: Incoming HTTP request.
            name: Name of the target object.
            source_id: Identifier of the source.
            policy: Policy values to validate or enforce.
            target_version: Target version supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            enabled_present: Enabled present supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        wizard_request = request.headers.get("X-Atlaso-Wizard") == "1"
        package = db.get(ManagedPackage, package_id)
        if package is None or package.ecosystem != "powershell":
            raise HTTPException(
                status_code=404,
                detail="Managed PowerShell module not found.",
            )
        errors = _managed_package_from_form(
            package,
            name=name,
            source_id=source_id,
            policy=policy,
            target_version=target_version,
            enabled=(enabled == "on")
            if enabled_present is not None
            else package.enabled,
            db=db,
        )
        if errors:
            db.rollback()
            if wizard_request:
                return JSONResponse(
                    {
                        "status": "error",
                        "detail": " ".join(errors),
                        "errors": errors,
                    },
                    status_code=422,
                )
            if request.headers.get("X-Atlaso-Autosave") == "1":
                return JSONResponse(
                    {"status": "error", "errors": errors}, status_code=422
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": " ".join(errors),
                },
                status_code=422,
            )
        db.add(package)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            message = "This PowerShell module is already managed."
            if wizard_request:
                return JSONResponse(
                    {"status": "error", "detail": message, "errors": [message]},
                    status_code=409,
                )
            if request.headers.get("X-Atlaso-Autosave") == "1":
                return JSONResponse(
                    {"status": "error", "errors": [message]}, status_code=409
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": message,
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_managed_package",
            resource_type="managed_package",
            resource_id=str(package.id),
            detail=f"ecosystem=powershell; name={package.name}",
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(
                {"status": "saved", "saved_at": utcnow().isoformat()}
            )
        if wizard_request:
            return JSONResponse(
                {"status": "saved", "package": {"id": package.id}}
            )
        return RedirectResponse(
            "/appliance-update#managed-packages", status_code=303
        )

    @update_router.post(
        "/appliance-update/packages/{package_id}/delete", response_model=None
    )
    def delete_managed_update_package(
        package_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete managed update package endpoint.

        Args:
            package_id: Identifier of the package.
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
        require_admin_identity(identity)
        package = db.get(ManagedPackage, package_id)
        if package is None or package.ecosystem != "powershell":
            raise HTTPException(
                status_code=404,
                detail="Managed PowerShell module not found.",
            )
        name = package.name
        db.delete(package)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_managed_package",
            resource_type="managed_package",
            resource_id=str(package_id),
            detail=f"ecosystem=powershell; name={name}",
        )
        return RedirectResponse(
            "/appliance-update#managed-packages", status_code=303
        )

    @update_router.post("/appliance-update/source-sync", response_model=None)
    def sync_appliance_update_sources(
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse | JSONResponse:
        """Handle the sync appliance update sources endpoint.

        Args:
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        wants_json = "application/json" in request.headers.get("accept", "")
        errors = [
            error
            for source in source_rows(db)
            if source.enabled
            for error in validate_update_source(source)
        ]
        if errors:
            if wants_json:
                return JSONResponse(
                    {
                        "status": "error",
                        "errors": errors,
                        "detail": " ".join(errors),
                    },
                    status_code=422,
                )
            return render(
                request,
                "appliance_update.html",
                {
                    "identity": identity,
                    **appliance_update_context(db),
                    "update_error": " ".join(errors),
                },
                status_code=422,
            )
        settings = appliance_update_settings(db)
        task_config = {
            "selected_streams": [],
            "settings": settings,
            "mode": "source_sync",
        }
        job = Job(
            id=f"job_{uuid4().hex[:12]}",
            type="appliance-update",
            status=JobStatus.PENDING.value,
            created_by=identity.username,
            progress_percent=0,
            trigger="manual",
            task_config_json=json.dumps(task_config, sort_keys=True),
            result=json.dumps(
                {
                    "status": "pending",
                    "mode": "source_sync",
                    "selected_streams": [],
                },
                indent=2,
            ),
        )
        db.add(job)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="queue_update_source_sync",
            resource_type="job",
            resource_id=job.id,
        )
        if wants_json:
            return JSONResponse(
                {
                    "status": JobStatus.PENDING.value,
                    "job_id": job.id,
                    "mode": "source_sync",
                },
                status_code=202,
            )
        return render(
            request,
            "appliance_update.html",
            {
                "identity": identity,
                **appliance_update_context(db),
                "appliance_update_task": job,
                "appliance_update_task_result": {
                    "status": "pending",
                    "dry_run": get_settings().dry_run_system_adapters,
                },
                "appliance_update_failures": [],
            },
        )

    @update_router.post(
        "/appliance-update/check",
        response_class=HTMLResponse,
        response_model=None,
    )
    def check_appliance_update(
        request: Request,
        selected_streams: list[str] = Form(default=[]),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse | JSONResponse:
        """Handle the check appliance update endpoint.

        Args:
            request: Incoming HTTP request.
            selected_streams: Update streams selected for the job.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return submit_appliance_update(
            request=request,
            selected_streams=selected_streams,
            csrf=csrf,
            identity=identity,
            db=db,
            mode="check",
        )

    @update_router.post(
        "/appliance-update/run",
        response_class=HTMLResponse,
        response_model=None,
    )
    def run_appliance_update(
        request: Request,
        selected_streams: list[str] = Form(default=[]),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse | JSONResponse:
        """Handle the run appliance update endpoint.

        Args:
            request: Incoming HTTP request.
            selected_streams: Update streams selected for the job.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return submit_appliance_update(
            request=request,
            selected_streams=selected_streams,
            csrf=csrf,
            identity=identity,
            db=db,
            mode="run",
        )

    endpoints = {
        endpoint.__name__: endpoint
        for endpoint in (
            appliance_power_action,
            appliance_update_availability,
            appliance_update_page,
            update_appliance_update_settings,
            update_appliance_update_source,
            create_appliance_update_source,
            delete_appliance_update_source,
            create_managed_update_package,
            update_managed_update_package,
            delete_managed_update_package,
            sync_appliance_update_sources,
            check_appliance_update,
            run_appliance_update,
        )
    }
    return ApplianceMaintenanceUiRouters(
        power_router=power_router,
        update_router=update_router,
        endpoints=endpoints,
    )
