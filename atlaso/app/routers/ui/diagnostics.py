"""Serve administrator-only Maintenance diagnostic actions on the management plane."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import Job, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services import diagnostics
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT
from atlaso.diagnostics import EvidenceError, Options

NO_STORE = {"Cache-Control": "no-store, private", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}


def build_router(*, management: Callable[..., Any], admin: Callable[..., Any],
                 csrf: Callable[..., Any]) -> APIRouter:
    """Bind established management, current identity and CSRF enforcement.

    Args:
        management: Existing management-listener eligibility dependency.
        admin: Current administrator authorization check.
        csrf: Existing CSRF validation callback.
    """
    router = APIRouter(prefix=MANAGEMENT_UI_ROOT + "/backup-restore/diagnostics",
                       dependencies=[Depends(management)], include_in_schema=False)

    def authorized(identity: Identity = Depends(require_session_identity)) -> Identity:
        """Authorized.

        Args:
            identity: Currently authenticated session identity.
        """
        admin(identity)
        return identity

    def lookup(db: Session, bundle_id: str) -> Job:
        """Lookup.

        Args:
            db: Request or worker database session.
            bundle_id: Server-generated diagnostic bundle UUID.
        """
        try:
            return diagnostics.find_job(db, bundle_id)
        except LookupError as exc:
            raise HTTPException(404, "Bundle not found.") from exc

    @router.get("/data")
    def diagnostics_data(identity: Identity = Depends(authorized), db: Session = Depends(get_db)) -> JSONResponse:
        """List bounded administrator-visible bundles; reevaluate expiry every request.

        Args:
            identity: Currently authenticated session identity.
            db: Request or worker database session.
        """
        jobs = db.scalars(select(Job).where(Job.type == diagnostics.JOB_TYPE).order_by(Job.created_at.desc()).limit(100)).all()
        return JSONResponse({"bundles": [diagnostics.row(job) for job in jobs]}, headers=NO_STORE)

    @router.post("/create")
    async def diagnostics_create(request: Request, identity: Identity = Depends(authorized), db: Session = Depends(get_db)) -> JSONResponse:
        """Validate reviewed choices and queue an explicit observational task.

        Args:
            request: Incoming authenticated browser request.
            identity: Currently authenticated session identity.
            db: Request or worker database session.
        """
        form = await request.form()
        csrf(request, str(form.get("csrf", "")))
        try:
            options = Options.parse({"since": form.get("since"), "until": form.get("until"),
                "scopes": form.getlist("scopes"), "anonymize": form.get("anonymize") == "on",
                "detailed_logs": form.get("detailed_logs") == "on", "correlation_id": form.get("correlation_id"),
                "log_lines": form.get("log_lines", 500)})
            job = diagnostics.create(db, options, identity.username)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except (OSError, EvidenceError) as exc:
            raise HTTPException(503, "Diagnostic storage is unavailable. Check private spool permissions and free space.") from exc
        return JSONResponse({"id": job.id, "task_id": job.id}, status_code=202, headers=NO_STORE)

    @router.get("/{bundle_id}")
    def diagnostics_detail(bundle_id: str, identity: Identity = Depends(authorized), db: Session = Depends(get_db)) -> JSONResponse:
        """Show the sanitized contents and omission summary before manual sharing.

        Args:
            bundle_id: Server-generated diagnostic bundle UUID.
            identity: Currently authenticated session identity.
            db: Request or worker database session.
        """
        try:
            return JSONResponse(diagnostics.detail(lookup(db, bundle_id)), headers=NO_STORE)
        except (OSError, EvidenceError, ValueError) as exc:
            raise HTTPException(503, "Bundle evidence is unavailable.") from exc

    @router.get("/{bundle_id}/download")
    def diagnostics_download(bundle_id: str, identity: Identity = Depends(authorized), db: Session = Depends(get_db)) -> Response:
        """Read a bounded private archive only for a currently authorized administrator.

        Args:
            bundle_id: Server-generated diagnostic bundle UUID.
            identity: Currently authenticated session identity.
            db: Request or worker database session.
        """
        try:
            data = diagnostics.download(db, lookup(db, bundle_id), identity.username)
        except LookupError as exc:
            raise HTTPException(404, "Bundle is unavailable or expired.") from exc
        except (OSError, EvidenceError) as exc:
            raise HTTPException(503, "Bundle evidence is unavailable.") from exc
        return Response(data, media_type="application/zip", headers={**NO_STORE,
                        "Content-Disposition": f'attachment; filename="atlaso-diagnostics-{bundle_id}.zip"'})

    @router.post("/{bundle_id}/delete")
    async def diagnostics_delete(bundle_id: str, request: Request, identity: Identity = Depends(authorized), db: Session = Depends(get_db)) -> JSONResponse:
        """Delete only an owned terminal artifact after authenticated confirmation.

        Args:
            bundle_id: Server-generated diagnostic bundle UUID.
            request: Incoming authenticated browser request.
            identity: Currently authenticated session identity.
            db: Request or worker database session.
        """
        form = await request.form()
        csrf(request, str(form.get("csrf", "")))
        try:
            diagnostics.remove(db, lookup(db, bundle_id), actor=identity.username)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except (OSError, EvidenceError) as exc:
            raise HTTPException(503, "Bundle removal could not be verified; retry after checking storage.") from exc
        return JSONResponse({"status": "deleted"}, headers=NO_STORE)

    @router.post("/{bundle_id}/cancel")
    async def diagnostics_cancel(bundle_id: str, request: Request, identity: Identity = Depends(authorized), db: Session = Depends(get_db)) -> JSONResponse:
        """Request cooperative cancellation without allowing deletion during capture.

        Args:
            bundle_id: Server-generated diagnostic bundle UUID.
            request: Incoming authenticated browser request.
            identity: Currently authenticated session identity.
            db: Request or worker database session.
        """
        import json

        form = await request.form()
        csrf(request, str(form.get("csrf", "")))
        db.execute(text("UPDATE jobs SET progress_percent=progress_percent WHERE 1=0"))
        job = lookup(db, bundle_id)
        state = diagnostics.result(job)
        if job.status == "pending":
            job.status = "cancelled"
            job.finished_at = utcnow()
            job.progress_percent = 100
            state["bundle_status"] = "cancelled"
        elif job.status == "running":
            state["cancel_requested"] = True
        job.result = json.dumps(state)
        db.commit()
        record_audit(db, actor=identity.username, action="diagnostics.cancel", resource_type="diagnostic_bundle", resource_id=job.id)
        return JSONResponse(diagnostics.row(job), headers=NO_STORE)

    return router
