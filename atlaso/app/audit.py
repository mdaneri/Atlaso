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
