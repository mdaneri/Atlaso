"""Own session- and CSRF-protected port-forward desired-state transports."""

from collections.abc import Callable, Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from atlaso.app.database import get_db
from atlaso.app.port_forward_schemas import PortForwardCreate
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.port_forwarding import (
    delete_port_forward,
    observe_port_forwards,
    save_port_forward,
    set_port_forward_enabled,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT


def _form_payload(form: Mapping[str, Any]) -> PortForwardCreate:
    """Convert the browser form into the same strict complete API request.

    Args:
        form: Parsed form data; only schema fields and the CSRF token are admitted.
    """
    if set(form) - set(PortForwardCreate.model_fields) - {"csrf"}:
        raise ValueError("Unexpected port-forward form fields.")
    values: dict[str, Any] = {key: value for key, value in form.items() if key != "csrf"}
    for key in ("ip_family", "priority", "external_port_start", "external_port_end", "target_port_start", "target_port_end"):
        if key in values:
            values[key] = int(values[key])
    for key in ("enabled", "acknowledge_source_loss"):
        if form.get(key, "off") not in {"on", "off"}:
            raise ValueError("Port-forward switches require an explicit checked or unchecked state.")
        values[key] = form.get(key) == "on"
    return PortForwardCreate(**values)


def build_router(
    *, verify_csrf: Callable[[Request, str], None],
    context: Callable[[Session], dict[str, Any]],
    require_management_ui_request: Callable[..., Any],
) -> APIRouter:
    """Build a child router inside the management-gated Routes/WAN domain.

    Args:
        verify_csrf: Existing session-bound mutation verifier.
        context: Existing Traffic Publishing projection, without facade imports.
        require_management_ui_request: Applied management-listener admission dependency.
    """
    router = APIRouter(prefix=f"{MANAGEMENT_UI_ROOT}/traffic-publishing/port-forwards", include_in_schema=False,
                       dependencies=[Depends(require_management_ui_request)])

    def authorize(identity: Identity, *, write: bool) -> None:
        """Require the existing Firewall permission for every transport.

        Args:
            identity: Authenticated browser account.
            write: Whether this request changes desired state.
        """
        if not identity.can("write:firewall" if write else "read:firewall"):
            raise HTTPException(403, "Firewall write permission is required" if write else "Firewall read permission is required")

    def saved_response(request: Request, db: Session) -> JSONResponse | RedirectResponse:
        """Refresh validation and preview after a committed desired-state mutation.

        Args:
            request: Browser form or asynchronous grid request.
            db: Current saved intent.
        """
        if "application/json" in request.headers.get("accept", ""):
            current = context(db)
            return JSONResponse({"status": "saved", "rows": current["port_forward_rows"],
                                 "validation_errors": current["nat_validation_errors"],
                                 "config_preview": current["nat_config_preview"], "config_path": current["nat_config_path"]})
        return RedirectResponse(MANAGEMENT_UI_ROOT + "/traffic-publishing#port-forward-panel", status_code=303)

    async def write_form(request: Request, identity: Identity) -> Mapping[str, Any]:
        """Authorize a mutation and verify its session CSRF token before reads.

        Args:
            request: Submitted form request.
            identity: Authenticated browser account.
        """
        authorize(identity, write=True)
        form = await request.form()
        verify_csrf(request, str(form.get("csrf") or ""))
        return form

    async def save(request: Request, identity: Identity, db: Session, rule_id: int | None) -> JSONResponse | RedirectResponse:
        """Save a complete reviewed form through the atomic domain service.

        Args:
            request: Submitted complete rule.
            identity: Authorized Firewall writer.
            db: Desired-state transaction.
            rule_id: Existing row to replace, or None to create.
        """
        form = await write_form(request, identity)
        try:
            save_port_forward(db, _form_payload(form), actor=identity.username, rule_id=rule_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return saved_response(request, db)

    @router.get("/status")
    def status(identity: Identity = Depends(require_session_identity), db: Session = Depends(get_db)) -> JSONResponse:
        """Read bounded runtime counters and fresh wizard choices without mutation.

        Args:
            identity: Authenticated Firewall reader.
            db: Current desired configuration.
        """
        authorize(identity, write=False)
        current = context(db)
        return JSONResponse({"rules": [row.model_dump() for row in observe_port_forwards(db)],
                             "targets": current["wan_nat_targets"], "source_groups": current["wan_source_groups"]})

    @router.post("", response_model=None)
    async def create(request: Request, identity: Identity = Depends(require_session_identity), db: Session = Depends(get_db)) -> JSONResponse | RedirectResponse:
        """Create desired forwarding intent after session and CSRF verification.

        Args:
            request: Complete rule form.
            identity: Authenticated Firewall writer.
            db: Atomic desired-state transaction.
        """
        return await save(request, identity, db, None)

    @router.post("/{rule_id}/edit", response_model=None)
    async def edit(rule_id: int, request: Request, identity: Identity = Depends(require_session_identity), db: Session = Depends(get_db)) -> JSONResponse | RedirectResponse:
        """Replace an existing rule without applying it to the appliance.

        Args:
            rule_id: Exact saved rule.
            request: Complete reviewed replacement.
            identity: Authenticated Firewall writer.
            db: Atomic desired-state transaction.
        """
        return await save(request, identity, db, rule_id)

    @router.post("/{rule_id}/enabled", response_model=None)
    async def enabled(rule_id: int, request: Request, identity: Identity = Depends(require_session_identity), db: Session = Depends(get_db)) -> JSONResponse | RedirectResponse:
        """Change only the ordinary Enabled switch while preserving saved intent.

        Args:
            rule_id: Exact saved rule.
            request: Explicit enabled state and session CSRF token.
            identity: Authenticated Firewall writer.
            db: Locked desired-state transaction.
        """
        form = await write_form(request, identity)
        if form.get("enabled") not in {"on", "off"} or set(form) - {"csrf", "enabled"}:
            raise HTTPException(422, "Supply only the explicit Enabled state and CSRF token.")
        try:
            set_port_forward_enabled(db, rule_id, enabled=form.get("enabled") == "on", actor=identity.username)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return saved_response(request, db)

    @router.post("/{rule_id}/delete", response_model=None)
    async def delete(rule_id: int, request: Request, identity: Identity = Depends(require_session_identity), db: Session = Depends(get_db)) -> JSONResponse | RedirectResponse:
        """Delete desired intent; the global Apply transaction retires enforcement.

        Args:
            rule_id: Exact saved rule.
            request: Session-protected removal request.
            identity: Authenticated Firewall writer.
            db: Locked desired-state and audit transaction.
        """
        await write_form(request, identity)
        try:
            delete_port_forward(db, rule_id, actor=identity.username)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        return saved_response(request, db)

    return router
