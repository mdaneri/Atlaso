"""Implement audit behavior."""

from types import SimpleNamespace

from sqlalchemy.orm import Session

from atlaso.app.models import AuditEvent
from atlaso.app.operational_logging import log_audit_event


def record_audit(
    db: Session,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    success: bool = True,
    detail: str | None = None,
    request_id: str | None = None,
    emit_operational: bool = True,
) -> AuditEvent:
    """Persist audit.

    Args:
        db: Active database session.
        actor: Authenticated identity attributed to the audit record.
        action: Operation to perform on the target resource.
        resource_type: Resource type supplied by the caller.
        resource_id: Identifier of the resource.
        success: Success supplied by the caller.
        detail: Detail supplied by the caller.
        request_id: Identifier of the request.
        emit_operational: Emit operational supplied by the caller.

    Returns:
        The record audit result.
    """
    event = AuditEvent(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        success=success,
        detail=detail,
        request_id=request_id,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    if emit_operational:
        log_audit_event(event)
    return event


def finalize_audit(
    db: Session,
    event: AuditEvent,
    *,
    success: bool,
    detail: str,
    operational_outcome: str,
    delivered_count: int,
) -> AuditEvent:
    """Return finalize audit.

    Args:
        db: Active database session.
        event: Event being processed.
        success: Success supplied by the caller.
        detail: Detail supplied by the caller.
        operational_outcome: Operational outcome supplied by the caller.
        delivered_count: Delivered count supplied by the caller.
    """
    event.success = success
    event.detail = detail
    db.add(event)
    db.commit()
    db.refresh(event)
    log_audit_event(
        SimpleNamespace(
            actor=event.actor,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            success=event.success,
            request_id=event.request_id,
            detail=(
                f"outcome={operational_outcome}; "
                f"broadcasts_sent={max(0, int(delivered_count))}"
            ),
        )
    )
    return event
