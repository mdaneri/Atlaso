"""Own management transports for reverse-proxy desired state."""

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from atlaso.app.database import get_db
from atlaso.app.reverse_proxy_schemas import ReverseProxyCreate, response_for_proxy
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services import reverse_proxy_publication
from atlaso.app.services.reverse_proxies import delete_proxy, desired_rows, save_proxy
from atlaso.app.services.reverse_proxy_observation import observe_reverse_proxy_health
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

MAX_HEALTH_ITEMS = 512


def build_router(
    *,
    verify_csrf: Callable[[Request, str], None],
    require_management_ui_request: Callable[..., Any],
) -> APIRouter:
    """Build the session-, Firewall-scope-, and CSRF-protected UI router.

    Args:
        verify_csrf: Existing session-bound CSRF verifier.
        require_management_ui_request: Existing management-listener admission dependency.
    """
    router = APIRouter(
        prefix=f"{MANAGEMENT_UI_ROOT}/traffic-publishing/reverse-proxies",
        include_in_schema=False,
        dependencies=[Depends(require_management_ui_request)],
    )

    def authorize(identity: Identity, *, write: bool) -> None:
        """Enforce the existing Firewall read or write scope.

        Args:
            identity: Authenticated identity whose firewall scope is checked.
            write: Whether mutation permission is required.
        """
        permission = "write:firewall" if write else "read:firewall"
        if not identity.can(permission):
            operation = "write" if write else "read"
            raise HTTPException(403, f"Firewall {operation} permission is required")

    def collection_payload(db: Session) -> dict[str, Any]:
        """Build the bounded browser collection from publication-owned validation.

        Args:
            db: Caller-owned database session for proxy desired state.
        """
        context = reverse_proxy_publication.context(db)
        rows = [response_for_proxy(proxy).model_dump(mode="json") for proxy in desired_rows(db)]
        return {
            "items": rows,
            "listener_options": context["reverse_proxy_listener_options"],
            "validation_errors": context["reverse_proxy_validation_errors"],
            "validation_warnings": context["reverse_proxy_validation_warnings"],
            "config_preview": context["reverse_proxy_config_preview"],
            "config_path": context["reverse_proxy_config_path"],
        }

    def csrf(request: Request) -> None:
        """Verify the established browser header before parsing request JSON.

        Args:
            request: Incoming browser request carrying the payload and CSRF token.
        """
        verify_csrf(request, request.headers.get("X-CSRF-Token", ""))

    @router.get("/data")
    def data(identity: Identity = Depends(require_session_identity), db: Session = Depends(get_db)) -> JSONResponse:
        """Return complete reverse-proxy desired state and publication validation.

        Args:
            identity: Authenticated identity whose firewall scope is checked.
            db: Caller-owned database session for proxy desired state.
        """
        authorize(identity, write=False)
        return JSONResponse(collection_payload(db), headers={"Cache-Control": "no-store"})

    @router.get("/health")
    def health(identity: Identity = Depends(require_session_identity), db: Session = Depends(get_db)) -> JSONResponse:
        """Return bounded cached route health without probing upstreams per request.

        Args:
            identity: Authenticated identity whose firewall scope is checked.
            db: Caller-owned database session for proxy desired state.
        """
        authorize(identity, write=False)
        items = observe_reverse_proxy_health(db)[:MAX_HEALTH_ITEMS]
        return JSONResponse({"items": items}, headers={"Cache-Control": "no-store"})

    @router.post("/save")
    async def save(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Create or fully replace desired state without publishing host changes.

        Args:
            request: Incoming browser request carrying the payload and CSRF token.
            identity: Authenticated identity whose firewall scope is checked.
            db: Caller-owned database session for proxy desired state.
        """
        authorize(identity, write=True)
        csrf(request)
        try:
            raw = await request.json()
        except (ValueError, UnicodeDecodeError) as exc:
            raise HTTPException(422, "A valid JSON reverse-proxy record is required.") from exc
        if not isinstance(raw, dict):
            raise HTTPException(422, "A JSON object is required for a reverse-proxy record.")
        values = dict(raw)
        proxy_id = values.pop("id", None)
        if proxy_id is not None and (type(proxy_id) is not int or proxy_id < 1):
            raise HTTPException(422, "Reverse-proxy id must be a positive JSON integer.")
        try:
            payload = ReverseProxyCreate.model_validate(values)
            proxy = save_proxy(db, payload, actor=identity.username, proxy_id=proxy_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except (ValidationError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return JSONResponse(
            {"status": "saved", "item": response_for_proxy(proxy).model_dump(mode="json"), **collection_payload(db)},
            headers={"Cache-Control": "no-store"},
        )

    @router.post("/{proxy_id}/delete")
    def delete(
        proxy_id: int,
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Delete saved desired state; global Appliance Apply owns retirement.

        Args:
            proxy_id: Exact saved proxy identifier.
            request: Incoming browser request carrying the payload and CSRF token.
            identity: Authenticated identity whose firewall scope is checked.
            db: Caller-owned database session for proxy desired state.
        """
        authorize(identity, write=True)
        csrf(request)
        try:
            delete_proxy(db, proxy_id, actor=identity.username)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return JSONResponse({"status": "deleted", **collection_payload(db)}, headers={"Cache-Control": "no-store"})

    return router
