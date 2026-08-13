"""Implement vcf depot downloads service behavior."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.models import Job, JobStatus, Schedule, VcfDepotDownloadProfile, utcnow

VCF_DEPOT_JOB_TYPE = "vcf-depot-download"
ACTIVE_VCF_DEPOT_JOB_STATUSES = (JobStatus.PENDING.value, JobStatus.RUNNING.value)
VCF_DEPOT_TASK_LOG_DIR = "/var/lib/atlaso/vcfDownloadTool/task-logs"


class ActiveVcfDepotDownloadError(ValueError):
    """Report a active vcf depot download error.

    Attributes:
        active_job_id: Identifier of the associated active job.
    """
    def __init__(self, active_job_id: str) -> None:
        """Initialize the active vcf depot download error.

        Args:
            active_job_id: Stable identifier of the associated active job resource.
        """
        self.active_job_id = active_job_id
        super().__init__(
            f"VCFDT task {active_job_id} is already active. Wait for it to finish before starting another VCFDT operation."
        )


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
        .order_by(desc(Job.created_at), desc(Job.id))
        .limit(1)
    ).first()


def active_vcf_depot_download_job(db: Session) -> Job | None:
    """Return active vcf depot download job.

    Args:
        db: Active database session.
    """
    return db.scalars(
        select(Job)
        .where(Job.type == VCF_DEPOT_JOB_TYPE, Job.status.in_(ACTIVE_VCF_DEPOT_JOB_STATUSES))
        .order_by(desc(Job.created_at), desc(Job.id))
        .limit(1)
    ).first()


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
        ActiveVcfDepotDownloadError: If the operation encounters an invalid state.
    """
    identifier = job_id or f"job_{uuid4().hex[:12]}"
    job = Job(
        id=identifier,
        type=VCF_DEPOT_JOB_TYPE,
        status=JobStatus.PENDING.value,
        vcf_depot_operation=True,
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
        active = active_vcf_depot_operation_job(db)
        raise ActiveVcfDepotDownloadError(active.id if active is not None else "unknown") from exc
    if profile.enabled:
        profile.status = "ready"
        profile.updated_at = utcnow()
        db.add(profile)
    return job
