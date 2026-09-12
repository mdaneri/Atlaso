"""Expose Firewall-scoped destination-translation desired-state operations."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.database import get_db
from atlaso.app.models import PortForward
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.port_forward_schemas import (
    PortForwardCreate,
    PortForwardResponse,
    PortForwardStatus,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.port_forwarding import (
    delete_port_forward as delete_saved_port_forward,
)
from atlaso.app.services.port_forwarding import (
    observe_port_forwards,
    save_port_forward,
)

router = APIRouter(prefix="/api/v1/traffic-publishing/port-forwards", route_class=DocumentedAPIRoute, tags=["NAT"])
RuleId = Annotated[int, Path(ge=1, description="Positive identifier of the saved port-forward resource.")]
Reader = Annotated[Identity, Depends(require_scope("read:firewall"))]
Writer = Annotated[Identity, Depends(require_scope("write:firewall"))]


@router.get("", response_model=list[PortForwardResponse], operation_id="listPortForwards")
def list_port_forwards(identity: Reader, db: Session = Depends(get_db)) -> list[PortForwardResponse]:
    """List managed port-forward desired state.

    Requires `read:firewall`. Returns at most 256 saved rules, including disabled
    and suspended intent. These records do not assert live activation. Global
    Appliance Apply is the only host-mutation boundary.

    Args:
        identity: Authorized Firewall reader.
        db: Saved rule transaction.
    """
    rows = db.scalars(select(PortForward).order_by(PortForward.priority, PortForward.name).limit(256))
    return [PortForwardResponse.model_validate(row) for row in rows]


@router.get("/status", response_model=list[PortForwardStatus], operation_id="getPortForwardStatus")
def get_port_forward_status(identity: Reader, db: Session = Depends(get_db)) -> list[PortForwardStatus]:
    """Observe applied port-forward state and nullable packet counters.

    Requires `read:firewall`. Uses one bounded read-only helper call and compares
    its captured applied records to current desired intent. Unavailable counters
    remain null, never fabricated zero. Does not apply, reset, recover, or probe
    credentials. Global Appliance Apply remains the host-mutation boundary.

    Args:
        identity: Authorized Firewall reader.
        db: Saved desired intent used for exact snapshot comparison.
    """
    return observe_port_forwards(db)


@router.get("/{rule_id}", response_model=PortForwardResponse, operation_id="getPortForward")
def get_port_forward(rule_id: RuleId, identity: Reader, db: Session = Depends(get_db)) -> PortForwardResponse:
    """Read one saved destination translation.

    Requires `read:firewall`. Returns desired intent without invoking the helper
    or changing runtime state. Missing resources return 404 ProblemDetails.
    Global Appliance Apply owns all subsequent host changes.

    Args:
        rule_id: Stable saved resource identifier.
        identity: Authorized Firewall reader.
        db: Saved desired-state session.
    """
    row = db.get(PortForward, rule_id)
    if row is None:
        raise HTTPException(404, "Port forward does not exist.")
    return PortForwardResponse.model_validate(row)


@router.post("", response_model=PortForwardResponse, status_code=201, operation_id="createPortForward")
def create_port_forward(payload: PortForwardCreate, identity: Writer, db: Session = Depends(get_db)) -> PortForwardResponse:
    """Create a reviewed port-forward rule without applying it.

    Requires `write:firewall`. Validates the complete family, listener, source,
    target, equal-length mapping and overlap under one transaction. Explicit
    reply masquerade requires acknowledgement of source visibility loss.
    Validation failures return 422 ProblemDetails; success saves desired state
    and audit together. Global Appliance Apply owns host mutation.

    Args:
        payload: Complete reviewed destination translation.
        identity: Authorized Firewall writer.
        db: Atomic desired-state and audit transaction.
    """
    try:
        row = save_port_forward(db, payload, actor=identity.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return PortForwardResponse.model_validate(row)


@router.put("/{rule_id}", response_model=PortForwardResponse, operation_id="replacePortForward")
def replace_port_forward(rule_id: RuleId, payload: PortForwardCreate, identity: Writer, db: Session = Depends(get_db)) -> PortForwardResponse:
    """Replace the complete reviewed intent of an existing port forward.

    Requires `write:firewall`. The full record is required so source and listener
    boundaries cannot be accidentally omitted. Revalidates overlap atomically;
    404 identifies an absent rule and 422 ProblemDetails identifies invalid
    intent. Global Appliance Apply is required to change the host.

    Args:
        rule_id: Existing destination translation identifier.
        payload: Complete replacement with source-loss acknowledgement when needed.
        identity: Authorized Firewall writer.
        db: Atomic desired-state transaction.
    """
    try:
        row = save_port_forward(db, payload, actor=identity.username, rule_id=rule_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return PortForwardResponse.model_validate(row)


@router.delete("/{rule_id}", status_code=204, operation_id="deletePortForward")
def delete_port_forward(rule_id: RuleId, identity: Writer, db: Session = Depends(get_db)) -> Response:
    """Delete a saved rule and audit the removal without mutating the host.

    Requires `write:firewall`. Missing rules return 404 ProblemDetails. Success
    returns no body; generated firewall admission and translation are removed
    only through the global Appliance Apply transaction.

    Args:
        rule_id: Exact destination translation to delete.
        identity: Authorized Firewall writer.
        db: Shared consumer-lock and audit transaction.
    """
    try:
        delete_saved_port_forward(db, rule_id, actor=identity.username)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return Response(status_code=204)
