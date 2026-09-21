"""Admin-only VCF lab property transports within the VCF workflow router."""

import json
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import Job
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services import vcf_lab_overrides as lab


def register_routes(router: APIRouter, verify_csrf: Callable[..., Any]) -> None:
    """Register browser-only handlers with the existing management boundary.

    Args:
        router: Existing management UI router that owns these endpoints.
        verify_csrf: Management UI CSRF validator.
    """

    def require_admin(
        identity: Identity = Depends(require_session_identity),
    ) -> Identity:
        """Exercise require admin.

        Args:
            identity: Authenticated operator identity used for authorization.
        """
        if not identity.has_role("admin"):
            raise HTTPException(
                403, "Administrator access is required for VCF lab overrides."
            )
        return identity

    async def payload(request: Request) -> dict[str, Any]:
        """Exercise payload.

        Args:
            request: Incoming HTTP request used for body and CSRF validation.
        """
        verify_csrf(request, request.headers.get("X-CSRF-Token", ""))
        # Bound the body before parsing, including chunked requests.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                raise HTTPException(413, "Request exceeds the lab operation limit.")
        try:
            value = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except ValueError, TypeError:
            raise HTTPException(422, "Expected a lab operation object.") from None

    @router.post("/vcf-helper/lab-overrides/{operation}", include_in_schema=False)
    async def lab_operation(
        operation: str,
        request: Request,
        background_tasks: BackgroundTasks,
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Probe, inspect, review or queue an explicitly acknowledged operation.

        Args:
            operation: Allowlisted lab operation selected by the route.
            request: Incoming HTTP request used for body and CSRF validation.
            background_tasks: FastAPI task dispatcher for the durable worker.
            identity: Authenticated operator identity used for authorization.
            db: Database session for credential metadata and durable task state.
        """
        values = await payload(request)
        if operation not in {"probe", "inspect", "review", "execute"}:
            raise HTTPException(404, "Unknown lab operation.")
        try:
            if operation == "execute":
                if values.get("acknowledged") is not True:
                    raise lab.LabOverrideError(
                        "Explicit lab-only acknowledgement is required."
                    )
                job = lab.enqueue(db, identity.username, str(values.get("token", "")))
                record_audit(
                    db,
                    actor=identity.username,
                    action="queue_vcf_lab_overrides",
                    resource_type=lab.JOB_TYPE,
                    resource_id=job.id,
                )
                background_tasks.add_task(lab.run_job, job.id)
                return {
                    "job_id": job.id,
                    "status_url": f"{router.prefix}/vcf-helper/lab-overrides/tasks/{job.id}",
                }
            target = lab.target_from_values(db, values)
            if operation == "probe":
                return await run_in_threadpool(lab.probe, target)
            if values.get("confirmed") is not True:
                raise lab.LabOverrideError(
                    "Confirm both fingerprints before authentication."
                )
            record_audit(
                db,
                actor=identity.username,
                action="use_vcf_lab_credentials",
                resource_type=lab.JOB_TYPE,
                detail=json.dumps(
                    {
                        "target": target.host,
                        "api_entry_id": target.api_entry_id,
                        "ssh_entry_id": target.ssh_entry_id,
                        "root_entry_id": target.root_entry_id,
                        "operation": operation,
                    }
                ),
            )
            if operation == "inspect":
                return await run_in_threadpool(
                    lab.inspect_target,
                    db,
                    target,
                    str(values.get("tls_fingerprint", "")),
                    str(values.get("ssh_fingerprint", "")),
                )
            return await run_in_threadpool(
                lab.review, db, identity.username, target, values
            )
        except lab.LabOverrideError as exc:
            raise HTTPException(
                409 if operation == "execute" else 422, str(exc)
            ) from None

    @router.get("/vcf-helper/lab-overrides/history", include_in_schema=False)
    def lab_history(
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Return managed operation choices for review and revert.

        Args:
            identity: Authenticated operator identity used for authorization.
            db: Database session for credential metadata and durable task state.
        """
        return {"jobs": lab.history(db)}

    @router.get("/vcf-helper/lab-overrides/tasks/{job_id}", include_in_schema=False)
    def lab_task(
        job_id: str,
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Report property verification separately from service/API recovery.

        Args:
            job_id: Durable task identifier.
            identity: Authenticated operator identity used for authorization.
            db: Database session for credential metadata and durable task state.
        """
        job = db.get(Job, job_id)
        if job is None or job.type != lab.JOB_TYPE:
            raise HTTPException(404, "VCF lab task not found.")
        return {
            "id": job.id,
            "status": job.status,
            "error": job.error,
            "result": json.loads(job.result or "{}"),
        }
