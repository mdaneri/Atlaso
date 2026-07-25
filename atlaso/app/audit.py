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
    log_audit_event(event)
    return event
