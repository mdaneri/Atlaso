"""Admit reviewed guest integration into the existing durable maintenance pipeline."""

from __future__ import annotations

import json
import re
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.models import AuditEvent, Job, JobStatus
from atlaso.app.services.appliance_update import (
    DEFAULT_UPDATE_SETTINGS,
    ensure_appliance_update_job_steps,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock


def guest_tools_observation(result: AdapterResult) -> dict[str, Any]:
    """Normalize bounded helper evidence without confusing a failed check with absence.

    Args:
        result: Read-only privileged provider/service observation.
    """
    unknown: dict[str, Any] = {
        "provider": "unknown", "state": "unknown", "version": "", "packages": [],
        "services": [], "available": False, "review_digest": "",
        "reason": "Guest-tools check failed. Review appliance helper availability and retry.",
        "reboot_impact": "Unknown until a successful check.",
    }
    if result.returncode or result.dry_run or len(result.stdout) > 1024 * 1024:
        return unknown
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return unknown
    if not isinstance(value, dict) or value.get("state") not in {"missing", "stopped", "healthy", "unsupported", "unknown"}:
        return unknown
    return {**unknown, **value}


def queue_guest_tools(
    db: Session, *, actor: str, provider: str, mode: str, review_digest: str = "",
) -> Job:
    """Queue one isolated guest-tools child with an atomic audit and immutable review.

    Args:
        db: Caller-owned task admission session.
        actor: Authenticated administrator attributed to the task.
        provider: Explicit compatible provider selected after observation.
        mode: Read-only check or explicitly confirmed run.
        review_digest: Digest of the exact helper plan reviewed by the operator.
    """
    if provider not in {"vmware", "hyperv", "qemu"} or mode not in {"check", "run"}:
        raise ValueError("Select the detected supported guest integration.")
    if mode == "run" and re.fullmatch(r"[0-9a-f]{64}", review_digest) is None:
        raise ValueError("Check and review guest tools before starting installation.")
    acquire_network_objects_write_lock(db)
    active = db.scalar(select(Job).where(
        Job.type.in_(["appliance-update", "appliance-apply"]), Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
    ))
    if active is not None:
        raise RuntimeError(f"Maintenance task {active.id} is already pending or running. Wait for it to finish.")
    settings: dict[str, Any] = {**DEFAULT_UPDATE_SETTINGS, "guest_tools": {
        "provider": provider, "review_digest": review_digest,
    }}
    config = {"schema_version": 2, "selected_streams": ["guest_tools"],
              "execution_order": ["guest_tools"], "status_transaction_id": uuid4().hex,
              "settings": settings, "mode": mode}
    job = Job(id=f"job_{uuid4().hex[:12]}", type="appliance-update", status=JobStatus.PENDING.value,
              created_by=actor, progress_percent=0, trigger="manual",
              task_config_json=json.dumps(config, sort_keys=True),
              result=json.dumps({"label": "Guest Tools", "mode": mode, "selected_streams": ["guest_tools"],
                                 "status": "pending", "success": False, "commands": [], "apply_started": False}))
    db.add(job)
    db.flush()
    ensure_appliance_update_job_steps(db, job=job, selected_streams=["guest_tools"])
    db.add(AuditEvent(actor=actor, action=f"queue_{mode}_guest_tools", resource_type="job", resource_id=job.id,
                      success=True, detail=f"provider={provider}; reviewed={mode == 'run'}"))
    db.commit()
    return job
