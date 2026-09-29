"""Expose desired-state management for Routing Permissions."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import RoutingRule
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.routing_permission_schemas import (
    RoutingPermissionCreate,
    RoutingPermissionResponse,
)
from atlaso.app.schemas import ProblemDetails
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.routes_wan import ensure_routes_wan_settings
from atlaso.app.services.routing_permissions import (
    routing_permission_apply_state,
    routing_permission_rows,
    routing_permission_targets,
    validate_routing_permission,
)

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
RuleId = Annotated[str, Path(min_length=1, description="Saved routing permission identifier, or generated identifier that can be read but not changed.")]
Reader = Annotated[Identity, Depends(require_scope("read:routes"))]
Writer = Annotated[Identity, Depends(require_scope("write:routes"))]


def _permission_rows(db: Session) -> list[RoutingPermissionResponse]:
    """Build the explicit and generated desired-state projection."""
    settings = ensure_routes_wan_settings(db)
    targets = routing_permission_targets(db)
    rules = list(db.scalars(select(RoutingRule).order_by(RoutingRule.priority, RoutingRule.name)))
    apply_state = routing_permission_apply_state(db)
    rows = routing_permission_rows(targets, rules, settings.routing_enabled)
    return [RoutingPermissionResponse.model_validate({**row, "apply_state": apply_state}) for row in rows]


def _saved_rule(db: Session, rule_id: str) -> RoutingRule:
    """Resolve a persisted rule while rejecting generated identifiers."""
    if rule_id.startswith("generated:"):
        raise HTTPException(409, "Generated Routing Permissions are read-only.")
    if not rule_id.isdecimal() or int(rule_id) < 1:
        raise HTTPException(404, "Routing Permission does not exist.")
    rule = db.get(RoutingRule, int(rule_id))
    if rule is None:
        raise HTTPException(404, "Routing Permission does not exist.")
    return rule


def _validate(payload: RoutingPermissionCreate, db: Session) -> None:
    candidate = RoutingRule(**payload.model_dump())
    errors = validate_routing_permission(candidate, routing_permission_targets(db))
    if errors:
        raise HTTPException(422, "; ".join(errors))


@router.get(
    "/routing-permissions",
    response_model=list[RoutingPermissionResponse],
    tags=["Routes"],
    operation_id="listRoutingPermissions",
    summary="List Routing Permissions",
    responses={422: {"model": ProblemDetails, "description": "Invalid current saved state returned as ProblemDetails."}},
)
def list_routing_permissions(identity: Reader, db: Session = Depends(get_db)) -> list[RoutingPermissionResponse]:
    """Read explicit and generated Routing Permission intent.

    Requires `read:routes`. Includes both saved records and read-only generated
    route-role rows. This is desired-state projection only; enforcement changes
    require global Appliance Apply through the paired WAN and Firewall units.

    Args:
        identity: Authorized Routes reader.
        db: Database session containing permissions and interface targets.
    """
    return _permission_rows(db)


@router.post(
    "/routing-permissions",
    response_model=RoutingPermissionResponse,
    status_code=201,
    tags=["Routes"],
    operation_id="createRoutingPermission",
    summary="Create Routing Permission",
    responses={409: {"model": ProblemDetails, "description": "A permission name already exists."}, 422: {"model": ProblemDetails, "description": "Invalid permission intent returned as ProblemDetails."}},
)
def create_routing_permission(payload: RoutingPermissionCreate, identity: Writer, db: Session = Depends(get_db)) -> RoutingPermissionResponse:
    """Save one explicit permission without applying it to the appliance.

    Requires `write:routes`. Validates current interface targets while holding
    the shared network-object write lock, then commits desired state and its
    audit event together. Global Appliance Apply through the paired WAN and Firewall units owns host
    enforcement.

    Args:
        payload: Complete permission intent.
        identity: Authorized Routes writer.
        db: Desired-state and audit transaction.
    """
    acquire_network_objects_write_lock(db)
    _validate(payload, db)
    row = RoutingRule(**payload.model_dump())
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "A Routing Permission with that name already exists.") from exc
    record_audit(db, actor=identity.username, action="create_routing_permission", resource_type="routing_permission", resource_id=str(row.id))
    db.refresh(row)
    return RoutingPermissionResponse.model_validate(next(item for item in _permission_rows(db) if str(item.id) == str(row.id)))


@router.put(
    "/routing-permissions/{rule_id}",
    response_model=RoutingPermissionResponse,
    tags=["Routes"],
    operation_id="replaceRoutingPermission",
    summary="Replace Routing Permission",
    responses={404: {"model": ProblemDetails, "description": "The saved permission does not exist."}, 409: {"model": ProblemDetails, "description": "Generated permissions are read-only or the name is already used."}, 422: {"model": ProblemDetails, "description": "Invalid permission intent returned as ProblemDetails."}},
)
def replace_routing_permission(rule_id: RuleId, payload: RoutingPermissionCreate, identity: Writer, db: Session = Depends(get_db)) -> RoutingPermissionResponse:
    """Replace all desired fields of one explicit permission.

    Requires `write:routes`. A complete body prevents accidental loss of
    policy, family, or interface intent. Save and audit are one transaction;
    host state changes only through global Appliance Apply's paired WAN and Firewall units.

    Args:
        rule_id: Persisted permission identifier.
        payload: Complete replacement permission intent.
        identity: Authorized Routes writer.
        db: Desired-state and audit transaction.
    """
    acquire_network_objects_write_lock(db)
    row = _saved_rule(db, rule_id)
    _validate(payload, db)
    for field, value in payload.model_dump().items():
        setattr(row, field, value)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "A Routing Permission with that name already exists.") from exc
    record_audit(db, actor=identity.username, action="update_routing_permission", resource_type="routing_permission", resource_id=str(row.id))
    db.refresh(row)
    return RoutingPermissionResponse.model_validate(next(item for item in _permission_rows(db) if str(item.id) == str(row.id)))


@router.delete(
    "/routing-permissions/{rule_id}",
    status_code=204,
    tags=["Routes"],
    operation_id="deleteRoutingPermission",
    summary="Delete Routing Permission",
    responses={404: {"model": ProblemDetails, "description": "The saved permission does not exist."}, 409: {"model": ProblemDetails, "description": "Generated permissions are read-only."}},
)
def delete_routing_permission(rule_id: RuleId, identity: Writer, db: Session = Depends(get_db)) -> Response:
    """Delete saved permission intent without changing appliance state.

    Requires `write:routes`. Generated route-role permissions cannot be deleted.
    The deletion and audit are transactional; global Appliance Apply through
    the paired WAN and Firewall units removes the applied rule.

    Args:
        rule_id: Persisted permission identifier.
        identity: Authorized Routes writer.
        db: Desired-state and audit transaction.
    """
    acquire_network_objects_write_lock(db)
    row = _saved_rule(db, rule_id)
    db.delete(row)
    record_audit(db, actor=identity.username, action="delete_routing_permission", resource_type="routing_permission", resource_id=str(rule_id))
    return Response(status_code=204)
