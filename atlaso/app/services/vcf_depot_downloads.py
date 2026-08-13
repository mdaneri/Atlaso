"""Implement vcf depot downloads service behavior."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.models import (
    Job,
    JobStatus,
    Schedule,
    VcfDepotAdmissionGate,
    VcfDepotDownloadProfile,
    utcnow,
)

VCF_DEPOT_JOB_TYPE = "vcf-depot-download"
ACTIVE_VCF_DEPOT_JOB_STATUSES = (JobStatus.PENDING.value, JobStatus.RUNNING.value)
VCF_DEPOT_TASK_LOG_DIR = "/var/lib/atlaso/vcfDownloadTool/task-logs"


class ActiveVcfDepotDownloadError(ValueError):
    """Report a active vcf depot download error.

    Attributes:
        active_job_id: Identifier of the associated active job.
    """
    def __init__(self, active_job_id: str, profile_id: int) -> None:
        """Initialize the active vcf depot download error.

        Args:
            active_job_id: Stable identifier of the associated active job resource.
            profile_id: Identifier of the duplicate VCFDT profile.
        """
        self.active_job_id = active_job_id
        self.profile_id = profile_id
        super().__init__(
            f"VCFDT task {active_job_id} is already queued or running for this profile. "
            "Wait for that profile task to finish before starting it again."
        )


class VcfDepotExclusiveOperationError(ValueError):
    """Report a Software Depot ID or Appliance Apply queue boundary conflict."""

    def __init__(self, active_job_id: str, operation_type: str) -> None:
        """Initialize the exclusive-operation conflict.

        Args:
            active_job_id: Stable identifier of the exclusive task.
            operation_type: Persisted task type holding the exclusive boundary.
        """
        self.active_job_id = active_job_id
        self.operation_type = operation_type
        super().__init__(
            f"VCFDT operation {active_job_id} ({operation_type}) is already pending or running. "
            "Wait for it to finish before queueing a profile download."
        )


class VcfDepotProfileUnavailableError(ValueError):
    """Report that a profile disappeared before its admission decision."""

    def __init__(self, profile_id: int) -> None:
        """Initialize the unavailable-profile conflict.

        Args:
            profile_id: Stable identifier of the unavailable profile.
        """
        self.profile_id = profile_id
        super().__init__(f"VCFDT download profile {profile_id} is no longer available.")


def vcf_depot_profile_id(task_config_json: str) -> int:
    """Return vcf depot profile id.

    Args:
        task_config_json: Task config json consumed by VCF depot profile identifier.
    """
    try:
        config = json.loads(task_config_json or "{}")
    except json.JSONDecodeError:
        return 0
    if not isinstance(config, dict):
        return 0
    try:
        return int(config.get("profile_id") or 0)
    except (TypeError, ValueError):
        return 0


def vcf_depot_schedules_for_profile(db: Session, profile_id: int) -> list[Schedule]:
    """Return vcf depot schedules for profile.

    Args:
        db: Active database session.
        profile_id: Identifier of the profile.
    """
    return [
        schedule
        for schedule in db.execute(
            select(Schedule)
            .where(Schedule.task_type == "vcf_depot_download")
            .order_by(Schedule.name)
        ).scalars()
        if vcf_depot_profile_id(schedule.task_config_json) == profile_id
    ]


def disable_vcf_depot_profile_schedules(db: Session, profile_id: int) -> list[Schedule]:
    """Return disable vcf depot profile schedules.

    Args:
        db: Active database session.
        profile_id: Identifier of the profile.
    """
    disabled: list[Schedule] = []
    now = utcnow()
    for schedule in vcf_depot_schedules_for_profile(db, profile_id):
        if schedule.enabled or schedule.next_run_at is not None:
            schedule.enabled = False
            schedule.next_run_at = None
            schedule.updated_at = now
            db.add(schedule)
            disabled.append(schedule)
    return disabled


def active_vcf_depot_operation_job(db: Session) -> Job | None:
    """Return active vcf depot operation job.

    Args:
        db: Active database session.
    """
    return db.scalars(
        select(Job)
        .where(
            Job.vcf_depot_operation.is_(True),
            Job.status.in_(ACTIVE_VCF_DEPOT_JOB_STATUSES),
        )
        .order_by(Job.created_at, Job.id)
        .limit(1)
    ).first()


def active_vcf_depot_exclusive_job(db: Session) -> Job | None:
    """Return the pending or running operation that excludes the download queue.

    Args:
        db: Active database session.
    """
    return db.scalars(
        select(Job)
        .where(
            Job.vcf_depot_operation.is_(True),
            Job.type != VCF_DEPOT_JOB_TYPE,
            Job.status.in_(ACTIVE_VCF_DEPOT_JOB_STATUSES),
        )
        .order_by(Job.created_at, Job.id)
        .limit(1)
    ).first()


def vcf_depot_job_profile_id(job: Job) -> int:
    """Return the stable VCFDT profile identifier recorded on a job.

    Args:
        job: VCFDT job being inspected.
    """
    if job.vcf_depot_profile_id:
        return int(job.vcf_depot_profile_id)
    return vcf_depot_profile_id(job.task_config_json)


def active_vcf_depot_download_jobs(db: Session) -> list[Job]:
    """Return every queued or running profile download in FIFO order.

    Args:
        db: Active database session.
    """
    return list(
        db.scalars(
            select(Job)
            .where(Job.type == VCF_DEPOT_JOB_TYPE, Job.status.in_(ACTIVE_VCF_DEPOT_JOB_STATUSES))
            .order_by(Job.created_at, Job.id)
        )
    )


def active_vcf_depot_download_job(db: Session, profile_id: int | None = None) -> Job | None:
    """Return active vcf depot download job.

    Args:
        db: Active database session.
        profile_id: Optional profile whose queued or running job should be returned.
    """
    jobs = active_vcf_depot_download_jobs(db)
    if profile_id is None:
        return jobs[0] if jobs else None
    return next((job for job in jobs if vcf_depot_job_profile_id(job) == profile_id), None)


def acquire_vcf_depot_admission_gate(db: Session) -> None:
    """Acquire the singleton database write gate for one admission decision.

    Args:
        db: Active database session.

    Raises:
        RuntimeError: If database initialization did not create the gate row.
    """
    acquired = db.execute(
        update(VcfDepotAdmissionGate)
        .where(VcfDepotAdmissionGate.id == 1)
        .values(generation=VcfDepotAdmissionGate.generation + 1)
    )
    if acquired.rowcount != 1:
        raise RuntimeError("The VCFDT admission gate is unavailable. Restart Atlaso and try again.")
    db.flush()


def cancel_pending_vcf_depot_download(
    db: Session,
    job_id: str,
    *,
    profile_id: int,
    profile_status_before_enqueue: str,
    finished_at: datetime,
    error: str,
    result: str,
) -> bool:
    """Cancel a profile download only while its claim state is still pending.

    Args:
        db: Active database session.
        job_id: Identifier of the queued profile download.
        profile_id: Identifier of the profile whose queued state is being restored.
        profile_status_before_enqueue: Durable status observed before queue admission.
        finished_at: Cancellation completion time.
        error: Durable cancellation message.
        result: Redacted durable task result.
    """
    cancelled = db.execute(
        update(Job)
        .where(
            Job.id == job_id,
            Job.type == VCF_DEPOT_JOB_TYPE,
            Job.status == JobStatus.PENDING.value,
        )
        .values(
            status=JobStatus.CANCELLED.value,
            finished_at=finished_at,
            error=error,
            result=result,
            progress_percent=100,
        )
    )
    if cancelled.rowcount != 1:
        return False
    restored_status = (
        profile_status_before_enqueue
        if profile_status_before_enqueue in {"planned", "synced", "blocked"}
        else "planned"
    )
    db.execute(
        update(VcfDepotDownloadProfile)
        .where(
            VcfDepotDownloadProfile.id == profile_id,
            VcfDepotDownloadProfile.status == "ready",
        )
        .values(status=restored_status, updated_at=finished_at)
    )
    return True


def lock_vcf_depot_profile_for_deletion(
    db: Session,
    profile_id: int,
) -> VcfDepotDownloadProfile:
    """Lock queue admission and return a profile only when no task uses it.

    Args:
        db: Active database session.
        profile_id: Identifier of the profile being deleted.

    Raises:
        ActiveVcfDepotDownloadError: If the profile has a queued or running task.
        VcfDepotProfileUnavailableError: If the profile no longer exists.
    """
    acquire_vcf_depot_admission_gate(db)
    profile = db.scalars(
        select(VcfDepotDownloadProfile).where(VcfDepotDownloadProfile.id == profile_id)
    ).first()
    if profile is None:
        raise VcfDepotProfileUnavailableError(profile_id)
    active = active_vcf_depot_download_job(db, profile_id)
    if active is not None:
        raise ActiveVcfDepotDownloadError(active.id, profile_id)
    return profile


def vcf_depot_task_log_reference(job_id: str, _profile_name: str = "") -> str:
    """Return vcf depot task log reference.

    Args:
        job_id: Stable identifier of the associated job resource.
        _profile_name: Profile name consumed by VCF depot task log reference.
    """
    return f"{VCF_DEPOT_TASK_LOG_DIR}/{job_id}.log"


def vcf_depot_initial_job_result(
    *,
    job_id: str,
    profile: VcfDepotDownloadProfile,
    trigger: str,
    schedule: Schedule | None,
    planned_for: datetime | None,
) -> dict[str, Any]:
    """Return vcf depot initial job result.

    Args:
        job_id: Identifier of the job.
        profile: Profile supplied by the caller.
        trigger: Trigger supplied by the caller.
        schedule: Schedule supplied by the caller.
        planned_for: Planned for supplied by the caller.
    """
    return {
        "profile_id": profile.id,
        "profile_name": profile.name,
        "profile_type": profile.profile_type,
        "profile_status_before_enqueue": profile.status,
        "trigger": trigger,
        "schedule_id": schedule.id if schedule is not None else None,
        "schedule_name": schedule.name if schedule is not None else "",
        "planned_for": planned_for.isoformat() if planned_for is not None else "",
        "log_path": vcf_depot_task_log_reference(job_id, profile.name),
    }


def enqueue_vcf_depot_download(
    db: Session,
    *,
    profile: VcfDepotDownloadProfile,
    actor: str,
    trigger: str,
    schedule: Schedule | None = None,
    planned_for: datetime | None = None,
    job_id: str | None = None,
) -> Job:
    """Return enqueue vcf depot download.

    Args:
        db: Active database session.
        profile: Profile supplied by the caller.
        actor: Authenticated identity attributed to the audit record.
        trigger: Trigger supplied by the caller.
        schedule: Schedule supplied by the caller.
        planned_for: Planned for supplied by the caller.
        job_id: Identifier of the job.

    Raises:
        ActiveVcfDepotDownloadError: If this profile already has a queued or running task.
        VcfDepotExclusiveOperationError: If an exclusive VCFDT operation is queued or running.
        VcfDepotProfileUnavailableError: If the profile was deleted before admission.
    """
    identifier = job_id or f"job_{uuid4().hex[:12]}"
    profile_id = int(profile.id or 0)
    acquire_vcf_depot_admission_gate(db)
    profile = db.scalars(
        select(VcfDepotDownloadProfile).where(VcfDepotDownloadProfile.id == profile_id)
    ).first()
    if profile is None:
        raise VcfDepotProfileUnavailableError(profile_id)
    exclusive = active_vcf_depot_exclusive_job(db)
    if exclusive is not None:
        raise VcfDepotExclusiveOperationError(exclusive.id, exclusive.type)
    job = Job(
        id=identifier,
        type=VCF_DEPOT_JOB_TYPE,
        status=JobStatus.PENDING.value,
        vcf_depot_operation=True,
        vcf_depot_profile_id=profile.id,
        created_by=actor,
        progress_percent=0,
        schedule_id=schedule.id if schedule is not None else None,
        trigger=trigger,
        planned_for=planned_for,
        task_config_json=json.dumps({"profile_id": profile.id}, sort_keys=True),
        result=json.dumps(
            vcf_depot_initial_job_result(
                job_id=identifier,
                profile=profile,
                trigger=trigger,
                schedule=schedule,
                planned_for=planned_for,
            ),
            indent=2,
            sort_keys=True,
        ),
    )
    try:
        with db.begin_nested():
            db.add(job)
            db.flush()
    except IntegrityError as exc:
        active = active_vcf_depot_download_job(db, profile.id)
        raise ActiveVcfDepotDownloadError(
            active.id if active is not None else "unknown",
            profile.id,
        ) from exc
    if profile.enabled:
        profile.status = "ready"
        profile.updated_at = utcnow()
        db.add(profile)
    return job
