"""Administrator browser transport for Atlaso-managed VCF certificate renewal."""

import json
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services import vcf_certificate_renewal as renewal

_ACTIONS = frozenset(
    {
        "probe",
        "save_connection",
        "inventory",
        "save_policy",
        "check",
        "prepare",
        "review",
        "execute",
        "reconcile",
    }
)


def register_routes(router: APIRouter, verify_csrf: Callable[..., Any]) -> None:
    """Register admin-only browser routes without changing the public API.

    Args:
        router: Existing VCF Helper router receiving the browser routes.
        verify_csrf: Shared verifier for the session-bound CSRF header.
    """

    def require_admin(
        identity: Identity = Depends(require_session_identity),
    ) -> Identity:
        """Require an administrator identity for all renewal state and actions.

        Args:
            identity: Authenticated administrator identity supplied by the session.
        """
        if not identity.has_role("admin"):
            raise HTTPException(403, "Administrator access is required.")
        return identity

    async def payload(request: Request) -> dict[str, Any]:
        """Read a bounded JSON object after validating the CSRF token.

        Args:
            request: Browser request whose body and CSRF header are checked.
        """
        verify_csrf(request, request.headers.get("X-CSRF-Token", ""))
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                raise HTTPException(413, "Request exceeds the renewal operation limit.")
        try:
            value = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            raise HTTPException(422, "Expected a renewal operation object.") from None
        if not isinstance(value, dict):
            raise HTTPException(422, "Expected a renewal operation object.")
        return value

    @router.get("/vcf-helper/certificate-renewals/state", include_in_schema=False)
    async def renewal_state(
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Return the safe, public-state projection for this administrator.

        Args:
            identity: Authenticated administrator identity supplied by the session.
            db: Database session used to read durable renewal state.
        """
        try:
            return await run_in_threadpool(renewal.state, db, identity.username)
        except renewal.RenewalError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.post(
        "/vcf-helper/certificate-renewals/{action}", include_in_schema=False
    )
    async def renewal_action(
        action: str,
        request: Request,
        identity: Identity = Depends(require_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Dispatch one bounded browser action and audit only safe identifiers.

        Args:
            action: Requested connection, inventory, policy, or renewal action.
            request: Browser request with a CSRF-protected bounded JSON object.
            identity: Authenticated administrator identity supplied by the session.
            db: Database session used by the renewal service and audit record.
        """
        if action not in _ACTIONS:
            raise HTTPException(404, "Unknown certificate renewal action.")
        values = await payload(request)
        try:
            result = await run_in_threadpool(
                renewal.dispatch, db, identity.username, action, values
            )
            resource_id = str(
                result.get("operation_id") or result.get("policy_id") or ""
            )
            if action not in {"probe", "inventory"}:
                record_audit(
                    db,
                    actor=identity.username,
                    action=f"vcf_certificate_renewal_{action}",
                    resource_type="vcf_certificate_renewal",
                    resource_id=resource_id,
                    detail=json.dumps({"action": action}),
                )
            return result
        except renewal.RenewalError as exc:
            status = 409 if action in {"review", "execute"} else 422
            raise HTTPException(status, str(exc)) from None
