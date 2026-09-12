"""Own task cancellation eligibility, durable requests, and verified dispositions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from atlaso.app.models import AuditEvent, Job, JobStatus, JobStep, Role, utcnow
from atlaso.app.security import Identity

ACTIVE = {JobStatus.PENDING.value, JobStatus.RUNNING.value}
PENDING_TYPES = {"appliance-update", "vcf-depot-download", "managed-script", "pxe-media-sync",
                 "diagnostic-bundle", "manual-placeholder"}
SERVICE_ADMIN_TYPES = {"pxe-media-sync"}


@dataclass(frozen=True)
class CancellationCapability:
    """Describe the currently audited stop contract for one task and caller."""

    can_cancel: bool
    reason: str
    confirmation: str = ""


class CancellationError(ValueError):
    """Carry a sanitized conflict or authorization failure to either transport."""

    def __init__(self, message: str, status_code: int = 409) -> None:
        """Record the safe response without exposing execution inputs.

        Args:
            message: Operator-facing explanation.
            status_code: Conflict or forbidden transport status.
        """
        super().__init__(message)
        self.status_code = status_code


def payload(value: str | None) -> dict[str, Any]:
    """Read existing task metadata without guessing malformed configuration.

    Args:
        value: Stored task result or configuration.
    """
    try:
        parsed = json.loads(value or "{}")
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def authorized(job: Job, identity: Identity, *, api: bool = False) -> bool:
    """Keep API scopes and browser task-role permissions distinct.

    Args:
        job: Persisted task being addressed.
        identity: Authenticated caller.
        api: Whether the request uses the scoped API contract.
    """
    if api:
        return identity.can("admin:all")
    return identity.has_role(Role.ADMIN.value) or (
        identity.has_role(Role.SERVICE_ADMIN.value) and job.type in SERVICE_ADMIN_TYPES
    )


def capability(job: Job, identity: Identity | None = None, *, api: bool = False) -> CancellationCapability:
    """Fail closed for unknown execution owners and unproven stop boundaries.

    Args:
        job: Current persisted task, never a browser-supplied capability.
        identity: Caller when rendering or accepting a user action.
        api: Apply API scope authorization instead of browser roles.
    """
    if identity is not None and not authorized(job, identity, api=api):
        return CancellationCapability(False, "You do not have permission to cancel this task.")
    if job.status not in ACTIVE:
        return CancellationCapability(False, "Task is already finished.")
    if job.cancel_requested_at is not None:
        reason = "Cancellation cleanup needs attention; the task has not been confirmed stopped." if job.cancel_outcome == "cleanup-required" else "Cancellation requested; waiting for a safe stop and cleanup."
        return CancellationCapability(False, reason)
    if payload(job.result).get("ownership_unresolved"):
        return CancellationCapability(False, "Helper ownership is unresolved; recovery must verify cleanup first.")
    if job.status == JobStatus.PENDING.value and job.type in PENDING_TYPES:
        return CancellationCapability(True, "Queued task has not been claimed.", "Prevent this queued task from starting and remove its owned staging, if any?")
    config = payload(job.task_config_json)
    if job.type == "appliance-update" and config.get("mode") == "check":
        from atlaso.app.services.appliance_update import UPDATE_STREAM_LABELS

        streams = config.get("selected_streams")
        if not isinstance(streams, list) or not streams or any(not isinstance(stream, str) or stream not in UPDATE_STREAM_LABELS for stream in streams):
            return CancellationCapability(False, "Check ownership metadata is incomplete; cancellation cannot be verified.")
        return CancellationCapability(True, "Stops after the current bounded check and credential cleanup.",
                                      "Request cancellation after the current check stops and cleans up? Remaining checks will be skipped; the current check can take up to six minutes to stop.")
    if job.type == "appliance-apply":
        return CancellationCapability(True, "Stops between components; completed changes remain applied.",
                                      "Finish the current component and its cleanup, then skip remaining components? Already applied changes are retained.")
    if job.type == "diagnostic-bundle":
        return CancellationCapability(False, "Running diagnostics has no verified descendant-process stop contract; collection must finish under its bounded owner.")
    if job.type == "pxe-media-sync" and config.get("source", job.network_boot_source) in {"download", "upload"}:
        return CancellationCapability(True, "Stops staged media work before committing the new version.",
                                      "Stop staged media work and restore the previous cache version? Cancellation waits for the current bounded transfer or extraction checkpoint and cleanup.")
    reasons = {
        "appliance-update": "Running installation or repository synchronization has no safe interruption contract.",
        "managed-script": "Running scripts may mutate local or remote systems; terminating the watcher cannot undo their work.",
        "vcf-depot-download": "The running VCFDT process has no verified task-owned stop and cleanup contract.",
        "vcf-depot-software-id": "VCFDT identity replacement must finish under its existing operation owner.",
        "vcf-sddc-manager-deploy": "Remote deployment can continue after its local watcher stops.",
        "vcf-offline-depot-target-config": "Remote configuration has no verified cancellation and rollback boundary.",
        "vcf-ca-trust": "Remote trust changes cannot be safely undone by stopping the local watcher.",
        "pxe-media-sync": "Running media deletion or an unrecognized media mode cannot be cancelled.",
    }
    return CancellationCapability(False, reasons.get(job.type, "This task type has no registered safe cancellation contract."))


def _audit(db: Session, job: Job, action: str, detail: str, *, success: bool = True) -> None:
    """Attach evidence to the same transaction as its lifecycle transition.

    Args:
        db: Transaction owning the transition.
        job: Exact task identity.
        action: Fixed cancellation audit action.
        detail: Sanitized disposition or cleanup evidence.
        success: Whether the recorded disposition succeeded.
    """
    db.add(AuditEvent(actor=job.cancel_requested_by or "system", action=action, resource_type="job",
                      resource_id=job.id, success=success, detail=detail))


def finish_stop(db: Session, job: Job, *, detail: str) -> bool:
    """Confirm cancellation only after the caller proved all owned work stopped.

    Args:
        db: Transaction owning the stopped task and child transitions.
        job: Refreshed task whose execution owner has completed cleanup.
        detail: Sanitized evidence for the verified stop.
    """
    if job.status not in ACTIVE or job.cancel_requested_at is None:
        return False
    now = utcnow()
    state = payload(job.result)
    state.update(state="cancelled", cancelled_by=job.cancel_requested_by, cancelled_at=now.isoformat())
    if job.type == "diagnostic-bundle":
        state["bundle_status"] = "cancelled"
    job.status = JobStatus.CANCELLED.value
    job.finished_at = now
    job.progress_percent = 100
    job.error = "Task stopped after operator cancellation and verified cleanup."
    job.result = json.dumps(state, sort_keys=True)
    job.cancel_completed_at = now
    job.cancel_outcome = "confirmed"
    for step in db.scalars(select(JobStep).where(JobStep.job_id == job.id, JobStep.status.in_(ACTIVE))):
        step.status = JobStatus.SKIPPED.value if step.status == JobStatus.PENDING.value else JobStatus.CANCELLED.value
        step.finished_at = now
        step.progress_percent = 100
        step.error = "Not continued after the parent's verified cancellation."
        step.result = json.dumps({"status": step.status, "success": False, "reason": "parent_cancelled"})
    _audit(db, job, "confirm_cancel_task", detail)
    return True


def finish_pending(db: Session, job: Job) -> None:
    """Release a reserved unclaimed task using its existing owned cleanup path.

    Args:
        db: Session holding the task's persisted cancellation reservation.
        job: Pending task excluded from worker claims by its request timestamp.
    """
    # Serialize retries as well as the first cleanup against other request sessions.
    locked = db.execute(update(Job).where(Job.id == job.id, Job.status == JobStatus.PENDING.value,
                                         Job.cancel_requested_at.is_not(None))
                        .values(cancel_outcome=Job.cancel_outcome))
    db.refresh(job)
    if getattr(locked, "rowcount", 0) != 1:
        db.rollback()
        return
    if job.type not in PENDING_TYPES:
        raise CancellationError("This pending cancellation requires its execution owner.")
    if job.type == "pxe-media-sync" and payload(job.task_config_json).get("source") == "upload":
        from atlaso.app.services.network_boot import cleanup_network_boot_upload

        try:
            cleanup_network_boot_upload(job.id)
        except (OSError, ValueError) as exc:
            job.cancel_outcome = "cleanup-required"
            job.error = "Cancellation staging cleanup failed; task remains unclaimed."
            _audit(db, job, "cancel_task_cleanup_failed", "Owned upload staging could not be released.", success=False)
            db.commit()
            raise CancellationError(job.error) from exc
    if job.type == "vcf-depot-download":
        from atlaso.app.models import VcfDepotDownloadProfile

        state = payload(job.result)
        restored = str(state.get("profile_status_before_enqueue") or "planned")
        if restored not in {"planned", "synced", "blocked"}:
            restored = "planned"
        db.execute(update(VcfDepotDownloadProfile).where(
            VcfDepotDownloadProfile.id == int(job.vcf_depot_profile_id or state.get("profile_id") or 0),
            VcfDepotDownloadProfile.status == "ready",
        ).values(status=restored, updated_at=utcnow()))
    finish_stop(db, job, detail="Pending claim was reserved; no worker started and owned staging was released.")
    db.commit()


def request(db: Session, job: Job, identity: Identity, *, api: bool = False) -> str:
    """Reserve a cancellation atomically against claims, stages, and completion.

    Args:
        db: Authenticated request session.
        job: Persisted task selected by server identity.
        identity: Authenticated request actor.
        api: Enforce API scope authorization.
    """
    if not authorized(job, identity, api=api):
        raise CancellationError("Administrator permission is required for this task type.", 403)
    db.refresh(job)
    if job.status not in ACTIVE:
        return "Task is already finished; its result was preserved."
    if job.cancel_requested_at is not None:
        if job.status == JobStatus.PENDING.value and job.type in PENDING_TYPES:
            finish_pending(db, job)
        return "Cancellation was already requested."
    contract = capability(job, identity, api=api)
    if not contract.can_cancel:
        raise CancellationError(contract.reason)
    changed = db.execute(update(Job).where(
        Job.id == job.id, Job.type == job.type, Job.status == job.status,
        Job.task_config_json == job.task_config_json, Job.result == job.result,
        Job.cancel_requested_at.is_(None),
    ).values(cancel_requested_at=utcnow(), cancel_requested_by=identity.username, cancel_outcome="requested"))
    if getattr(changed, "rowcount", 0) != 1:
        db.rollback()
        db.refresh(job)
        if job.status not in ACTIVE:
            return "Task finished before cancellation was accepted; its result was preserved."
        if job.cancel_requested_at is not None:
            return "Cancellation was already requested."
        raise CancellationError("The task changed before cancellation could be accepted. Refresh its current capability.")
    db.refresh(job)
    _audit(db, job, "request_cancel_task", contract.reason)
    db.commit()
    if job.status == JobStatus.PENDING.value and job.type in PENDING_TYPES:
        finish_pending(db, job)
    return "Task cancelled before execution." if job.status == JobStatus.CANCELLED.value else "Cancellation requested; waiting for a safe checkpoint and cleanup."


def reconcile_requests(db: Session) -> None:
    """Retry unclaimed cleanup and settle requests whose completion won the race.

    Args:
        db: Worker session for one bounded reconciliation pass.
    """
    jobs = db.scalars(select(Job).where(Job.cancel_requested_at.is_not(None), Job.cancel_completed_at.is_(None))
                      .order_by(Job.cancel_requested_at).limit(100)).all()
    for job in jobs:
        if job.status == JobStatus.PENDING.value and job.type in PENDING_TYPES:
            try:
                finish_pending(db, job)
            except CancellationError:
                continue
        elif job.status not in ACTIVE:
            job.cancel_completed_at = job.finished_at or utcnow()
            job.cancel_outcome = "confirmed" if job.status == JobStatus.CANCELLED.value else "completion-won"
            _audit(db, job, "settle_cancel_task", f"Final disposition: {job.status}; existing task result preserved.")
    db.commit()
