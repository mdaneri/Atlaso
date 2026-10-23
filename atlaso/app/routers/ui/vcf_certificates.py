"""Browser-only transport for administrator VCF appliance certificate workflows."""

import json
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services import vcf_certificates as cert


def register_routes(router: APIRouter, verify_csrf: Callable[..., Any]) -> None:
    """Register administrator-only browser handlers on the VCF workflow router."""

    def require_admin(
        identity: Identity = Depends(require_session_identity),
    ) -> Identity:
        if not identity.has_role("admin"):
            raise HTTPException(403, "Administrator access is required.")
        return identity

    async def payload(request: Request) -> dict[str, Any]:
        verify_csrf(request, request.headers.get("X-CSRF-Token", ""))
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                raise HTTPException(
                    413, "Request exceeds the certificate operation limit."
                )
        try:
            value = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except ValueError, TypeError:
            raise HTTPException(
                422, "Expected a certificate operation object."
            ) from None

    @router.post(
        "/vcf-helper/appliance-certificates/{operation}", include_in_schema=False
    )
    async def certificate_operation(
        operation: str,
        request: Request,
        background_tasks: BackgroundTasks,
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        values = await payload(request)
        if operation not in {
            "probe",
            "inspect",
            "prepare",
            "review",
            "execute",
            "reconcile",
        }:
            raise HTTPException(404, "Unknown certificate operation.")
        try:
            result = await run_in_threadpool(
                cert.dispatch,
                db,
                identity.username,
                operation,
                values,
                background_tasks,
            )
            operation_id = result.get("operation_id", "")
            if operation_id:
                record_audit(
                    db,
                    actor=identity.username,
                    action=f"vcf_certificate_{operation}",
                    resource_type="vcf_appliance_certificate",
                    resource_id=str(operation_id),
                    detail=json.dumps({"operation": operation}),
                )
            return result
        except cert.CertificateOperationError as exc:
            raise HTTPException(
                409 if operation == "execute" else 422, str(exc)
            ) from None

    @router.get(
        "/vcf-helper/appliance-certificates/operations/{operation_id}",
        include_in_schema=False,
    )
    async def certificate_operation_status(
        operation_id: str,
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        try:
            return await run_in_threadpool(
                cert.operation_status, db, identity.username, operation_id
            )
        except cert.CertificateOperationError as exc:
            raise HTTPException(422, str(exc)) from None
