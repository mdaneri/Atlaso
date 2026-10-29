"""Browser-only transport for reviewed native VCF backup configuration."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services import vcf_backup_workflow as workflow

_ACTIONS = frozenset({"probe", "inspect", "review", "execute", "reconcile"})
_MAX_BODY = 65536


def register_routes(router: APIRouter, verify_csrf: Callable[..., Any]) -> None:
    """Register bounded, administrator-only backup workflow routes.

    Args:
        router: Existing management UI router receiving the handlers.
        verify_csrf: Shared session-bound CSRF verifier.
    """

    def require_admin(identity: Identity = Depends(require_session_identity)) -> Identity:
        """Require an administrator before exposing or mutating workflow state.

        Args:
            identity: Authenticated session identity to check for the administrator role.
        """
        if not identity.has_role("admin"):
            raise HTTPException(403, "Administrator access is required.")
        return identity

    async def payload(request: Request) -> dict[str, Any]:
        """Read one bounded JSON object after validating the browser CSRF token.

        Args:
            request: Browser request whose CSRF token and streamed JSON body are validated.
        """
        verify_csrf(request, request.headers.get("X-CSRF-Token", ""))
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > _MAX_BODY:
                raise HTTPException(413, "Request exceeds the VCF Backup operation limit.")
        try:
            value = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            raise HTTPException(422, "Expected a VCF Backup operation object.") from None
        if not isinstance(value, dict):
            raise HTTPException(422, "Expected a VCF Backup operation object.")
        return value

    @router.post("/vcf-helper/backups/{action}", include_in_schema=False)
    async def backup_action(
        action: str,
        request: Request,
        background_tasks: BackgroundTasks,
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Dispatch one explicit backup workflow action and record safe identifiers.

        Args:
            action: Allowlisted workflow operation selected by the route path.
            request: Browser request carrying the CSRF token and action payload.
            background_tasks: Response-scoped worker queue supplied by FastAPI.
            identity: Authenticated administrator identity for ownership and audit records.
            db: Database session used by the workflow and audit services.
        """
        if action not in _ACTIONS:
            raise HTTPException(404, "Unknown VCF Backup operation.")
        values = await payload(request)
        try:
            result = await run_in_threadpool(
                workflow.dispatch, db, identity.username, action, values, background_tasks
            )
            operation_id = str(result.get("operation_id", ""))
            if action not in {"probe"}:
                record_audit(
                    db,
                    actor=identity.username,
                    action=f"vcf_backup_{action}",
                    resource_type=workflow.JOB_TYPE,
                    resource_id=operation_id,
                    detail=json.dumps({"action": action}),
                )
            return result
        except workflow.BackupOperationError as exc:
            raise HTTPException(409 if action == "execute" else 422, str(exc)) from None

    @router.get("/vcf-helper/backups/operations", include_in_schema=False)
    async def backup_operations(
        limit: int = Query(default=25, ge=1, le=25),
        cursor: str | None = Query(default=None, max_length=2048),
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """List only the caller's admitted operations through a safe projection.

        Args:
            limit: Maximum number of operation rows requested for the page.
            cursor: Optional opaque continuation token for the caller's next page.
            identity: Authenticated administrator identity that owns the listed operations.
            db: Database session used to build the owner-bound projection.
        """
        try:
            return await run_in_threadpool(
                workflow.list_operations, db, identity.username, limit=limit, cursor=cursor
            )
        except workflow.BackupOperationError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.get("/vcf-helper/backups/operations/{operation_id}", include_in_schema=False)
    async def backup_operation_status(
        operation_id: str,
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Return the owner-bound public operation projection only.

        Args:
            operation_id: Opaque identifier of the operation requested for status.
            identity: Authenticated administrator identity that must own the operation.
            db: Database session used to load and project the operation.
        """
        try:
            return await run_in_threadpool(
                workflow.operation_status, db, identity.username, operation_id
            )
        except workflow.BackupOperationError as exc:
            raise HTTPException(422, str(exc)) from None
