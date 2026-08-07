from __future__ import annotations

import json
import re
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
    def __init__(self, active_job_id: str) -> None:
        self.active_job_id = active_job_id
        super().__init__(
            f"VCFDT task {active_job_id} is already active. Wait for it to finish before starting another download."
        )


def vcf_depot_profile_id(task_config_json: str) -> int:
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


def active_vcf_depot_download_job(db: Session) -> Job | None:
    return db.scalars(
        select(Job)
        .where(Job.type == VCF_DEPOT_JOB_TYPE, Job.status.in_(ACTIVE_VCF_DEPOT_JOB_STATUSES))
        .order_by(desc(Job.created_at), desc(Job.id))
        .limit(1)
    ).first()


def vcf_depot_task_log_reference(job_id: str, profile_name: str) -> str:
    profile_slug = re.sub(r"[^a-z0-9]+", "-", profile_name.lower()).strip("-") or "task"
    return f"{VCF_DEPOT_TASK_LOG_DIR}/{job_id}-{profile_slug}.log"


def vcf_depot_initial_job_result(
    *,
    job_id: str,
    profile: VcfDepotDownloadProfile,
    trigger: str,
    schedule: Schedule | None,
    planned_for: datetime | None,
) -> dict[str, Any]:
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
    identifier = job_id or f"job_{uuid4().hex[:12]}"
    job = Job(
        id=identifier,
        type=VCF_DEPOT_JOB_TYPE,
        status=JobStatus.PENDING.value,
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
        active = active_vcf_depot_download_job(db)
        raise ActiveVcfDepotDownloadError(active.id if active is not None else "unknown") from exc
    if profile.enabled:
        profile.status = "ready"
        profile.updated_at = utcnow()
        db.add(profile)
    return job
