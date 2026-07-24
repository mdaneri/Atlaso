from __future__ import annotations

import hashlib
import json
import shlex
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from labfoundry.app.models import (
    AutomationScript,
    AutomationScriptRevision,
    AuditEvent,
    Job,
    JobStatus,
    Schedule,
    utcnow,
)
from labfoundry.app.services.appliance_update import ensure_appliance_update_job_steps


SCHEDULE_TASK_TYPES = {
    "appliance_update_check",
    "appliance_update_install",
    "vcf_depot_download",
    "managed_script",
}
SCRIPT_INTERPRETERS = {"bash", "python", "powershell"}
SCHEDULE_JOB_TYPES = {
    "appliance_update_check": "appliance-update",
    "appliance_update_install": "appliance-update",
    "vcf_depot_download": "vcf-depot-download",
    "managed_script": "managed-script",
}
MAX_SCRIPT_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_SCRIPT_CONTENT_BYTES = 1024 * 1024
MAX_SCRIPT_ARGUMENTS = 64
MAX_SCRIPT_ARGUMENT_BYTES = 4096
MAX_SCRIPT_ARGUMENTS_BYTES = 16 * 1024


def json_object(raw_value: str, *, label: str = "configuration") -> dict[str, Any]:
    try:
        payload = json.loads(raw_value or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object.")
    return payload


def _parse_powershell_arguments(raw_value: str) -> list[str]:
    arguments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    token_started = False
    index = 0
    while index < len(raw_value):
        character = raw_value[index]
        if character == "`":
            index += 1
            if index >= len(raw_value):
                raise ValueError("A PowerShell continuation marker must be followed by another line or character.")
            escaped = raw_value[index]
            if escaped == "\r" and index + 1 < len(raw_value) and raw_value[index + 1] == "\n":
                index += 2
                continue
            if escaped == "\n":
                index += 1
                continue
            current.append(escaped)
            token_started = True
            index += 1
            continue
        if quote == "'" and character == "'" and index + 1 < len(raw_value) and raw_value[index + 1] == "'":
            current.append("'")
            token_started = True
            index += 2
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
                token_started = True
                index += 1
                continue
            if quote == character:
                quote = None
                index += 1
                continue
        if quote is None and character.isspace():
            if token_started:
                arguments.append("".join(current))
                current = []
                token_started = False
            index += 1
            continue
        current.append(character)
        token_started = True
        index += 1
    if quote is not None:
        raise ValueError("Managed script parameters contain an unterminated quote.")
    if token_started:
        arguments.append("".join(current))
    return arguments


def parse_script_arguments(raw_value: str, interpreter: str = "bash") -> list[str]:
    if interpreter == "powershell":
        arguments = _parse_powershell_arguments(raw_value)
    else:
        try:
            normalized_value = raw_value.replace("\\\r\n", "").replace("\\\n", "")
            arguments = shlex.split(normalized_value, posix=True)
        except ValueError as exc:
            raise ValueError(f"Managed script parameters are invalid: {exc}.") from exc
    if len(arguments) > MAX_SCRIPT_ARGUMENTS:
        raise ValueError(f"Managed scripts accept at most {MAX_SCRIPT_ARGUMENTS} arguments.")
    if any("\x00" in argument for argument in arguments):
        raise ValueError("Managed script arguments cannot contain null bytes.")
    if any(len(argument.encode("utf-8")) > MAX_SCRIPT_ARGUMENT_BYTES for argument in arguments):
        raise ValueError(f"Each managed script argument must be {MAX_SCRIPT_ARGUMENT_BYTES} bytes or smaller.")
    if sum(len(argument.encode("utf-8")) for argument in arguments) > MAX_SCRIPT_ARGUMENTS_BYTES:
        raise ValueError(f"Managed script arguments must total {MAX_SCRIPT_ARGUMENTS_BYTES} bytes or less.")
    return arguments


def _field_values(expression: str, minimum: int, maximum: int, *, sunday_alias: bool = False) -> set[int]:
    values: set[int] = set()
    for part in expression.split(","):
        part = part.strip()
        if not part:
            raise ValueError("Cron fields must not contain empty list items.")
        base, separator, step_value = part.partition("/")
        step = int(step_value) if separator else 1
        if step < 1:
            raise ValueError("Cron field steps must be positive integers.")
        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            start_text, end_text = base.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            start = end = int(base)
        if start < minimum or start > maximum or end < minimum or end > maximum or start > end:
            raise ValueError(f"Cron field value must be between {minimum} and {maximum}.")
        expanded = range(start, end + 1, step)
        values.update(0 if sunday_alias and value == 7 else value for value in expanded)
    return values


def parse_cron_expression(expression: str) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    fields = expression.split()
    if len(fields) != 5:
        raise ValueError("Cron expression must contain five fields: minute hour day month weekday.")
    minute = _field_values(fields[0], 0, 59)
    hour = _field_values(fields[1], 0, 23)
    day = _field_values(fields[2], 1, 31)
    month = _field_values(fields[3], 1, 12)
    weekday = _field_values(fields[4], 0, 7, sunday_alias=True)
    return minute, hour, day, month, weekday


def validate_schedule_values(
    *,
    task_type: str,
    task_config_json: str,
    schedule_kind: str,
    cron_expression: str,
    run_once_at: datetime | None,
    timezone_name: str,
) -> list[str]:
    errors: list[str] = []
    if task_type not in SCHEDULE_TASK_TYPES:
        errors.append("Choose a supported scheduled task type.")
    try:
        config = json_object(task_config_json, label="Task configuration")
    except ValueError as exc:
        errors.append(str(exc))
        config = {}
    if task_type in {"appliance_update_check", "appliance_update_install"}:
        streams = config.get("selected_streams")
        if not isinstance(streams, list) or not streams:
            errors.append("Appliance update schedules require selected_streams.")
        elif any(stream not in {"photon_os", "powershell_modules", "labfoundry_release"} for stream in streams):
            errors.append("Appliance update schedule contains a retired or unsupported stream.")
    elif task_type == "vcf_depot_download" and not isinstance(config.get("profile_id"), int):
        errors.append("VCF Offline Depot schedules require an integer profile_id.")
    elif task_type == "managed_script":
        if not isinstance(config.get("revision_id"), int):
            errors.append("Managed script schedules require an integer revision_id.")
        arguments = config.get("arguments", [])
        if not isinstance(arguments, list) or any(not isinstance(argument, str) for argument in arguments):
            errors.append("Managed script schedule arguments must be a list of strings.")
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        errors.append("Choose a valid IANA timezone.")
    if schedule_kind == "cron":
        try:
            parse_cron_expression(cron_expression)
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
    elif schedule_kind == "once":
        if run_once_at is None:
            errors.append("One-time schedules require a run date and time.")
    else:
        errors.append("Schedule kind must be cron or once.")
    return errors


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def next_cron_run(expression: str, timezone_name: str, *, after: datetime) -> datetime:
    minute, hour, day, month, weekday = parse_cron_expression(expression)
    zone = ZoneInfo(timezone_name)
    candidate = _aware_utc(after).replace(second=0, microsecond=0) + timedelta(minutes=1)
    deadline = candidate + timedelta(days=366 * 2)
    fields = expression.split()
    day_is_wildcard = fields[2] == "*"
    weekday_is_wildcard = fields[4] == "*"
    while candidate <= deadline:
        local = candidate.astimezone(zone)
        cron_weekday = (local.weekday() + 1) % 7
        day_matches = local.day in day
        weekday_matches = cron_weekday in weekday
        calendar_matches = (day_matches and weekday_matches) if day_is_wildcard or weekday_is_wildcard else (day_matches or weekday_matches)
        if local.minute in minute and local.hour in hour and local.month in month and calendar_matches:
            return candidate
        candidate += timedelta(minutes=1)
    raise ValueError("Cron expression does not produce a run within two years.")


def next_schedule_run(schedule: Schedule, *, after: datetime) -> datetime | None:
    if not schedule.enabled:
        return None
    if schedule.schedule_kind == "once":
        if schedule.run_once_at is None:
            return None
        run_at = _aware_utc(schedule.run_once_at)
        return run_at if run_at > _aware_utc(after) else None
    return next_cron_run(schedule.cron_expression, schedule.timezone_name, after=after)


def enabled_script_revision(db: Session, revision_id: int) -> AutomationScriptRevision | None:
    revision = db.get(AutomationScriptRevision, revision_id)
    return revision if revision is not None and revision.enabled else None


def create_script_revision(
    db: Session,
    *,
    script: AutomationScript,
    interpreter: str,
    content: str,
    timeout_seconds: int,
    actor: str,
) -> AutomationScriptRevision:
    if interpreter not in SCRIPT_INTERPRETERS:
        raise ValueError("Interpreter must be bash, python, or powershell.")
    if not content.strip():
        raise ValueError("Script content is required.")
    if len(content.encode("utf-8")) > MAX_SCRIPT_CONTENT_BYTES:
        raise ValueError("Script content must be 1 MiB or smaller.")
    if timeout_seconds < 1 or timeout_seconds > MAX_SCRIPT_TIMEOUT_SECONDS:
        raise ValueError("Script timeout must be between 1 second and 24 hours.")
    latest = db.execute(
        select(AutomationScriptRevision)
        .where(AutomationScriptRevision.script_id == script.id)
        .order_by(AutomationScriptRevision.revision.desc())
    ).scalars().first()
    revision = AutomationScriptRevision(
        script_id=script.id,
        revision=(latest.revision + 1) if latest else 1,
        interpreter=interpreter,
        content=content,
        content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        enabled=False,
        timeout_seconds=timeout_seconds,
        created_by=actor,
    )
    db.add(revision)
    return revision


def enqueue_schedule_now(db: Session, *, schedule: Schedule, actor: str, now: datetime | None = None) -> Job:
    current = _aware_utc(now or utcnow())
    active = db.execute(
        select(Job).where(
            Job.schedule_id == schedule.id,
            Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
        )
    ).scalars().first()
    if active is not None:
        raise ValueError(f"Schedule already has active task {active.id}.")
    config = json_object(schedule.task_config_json, label="Task configuration")
    if schedule.task_type == "appliance_update_check":
        config["mode"] = "check"
    elif schedule.task_type == "appliance_update_install":
        config["mode"] = "run"
    config["_schedule_id"] = schedule.id
    config["_schedule_name"] = schedule.name
    job = Job(
        id=f"job_schedule_{schedule.id}_{uuid4().hex[:12]}",
        type=SCHEDULE_JOB_TYPES[schedule.task_type],
        status=JobStatus.PENDING.value,
        created_by=actor,
        progress_percent=0,
        schedule_id=schedule.id,
        trigger="manual_schedule",
        planned_for=current,
        task_config_json=json.dumps(config, sort_keys=True),
        result=json.dumps({"schedule_id": schedule.id, "schedule_name": schedule.name, "trigger": "manual_schedule"}, indent=2),
    )
    db.add(job)
    db.flush()
    if job.type == "appliance-update":
        ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=[str(value) for value in config.get("selected_streams", [])],
        )
    schedule.last_run_at = current
    schedule.last_job_id = job.id
    schedule.updated_at = current
    db.add(schedule)
    db.add(
        AuditEvent(
            actor=actor,
            action="queue_schedule_now",
            resource_type="job",
            resource_id=job.id,
            detail=f"schedule_id={schedule.id}; task_type={schedule.task_type}",
        )
    )
    db.commit()
    return job


def enqueue_due_schedules(db: Session, *, now: datetime | None = None) -> list[Job]:
    current = _aware_utc(now or utcnow())
    due = db.execute(
        select(Schedule)
        .where(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None), Schedule.next_run_at <= current)
        .order_by(Schedule.next_run_at, Schedule.id)
    ).scalars().all()
    jobs: list[Job] = []
    for schedule in due:
        active = db.execute(
            select(Job).where(
                Job.schedule_id == schedule.id,
                Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
            )
        ).scalars().first()
        planned_for = schedule.next_run_at
        schedule.last_run_at = current
        if schedule.schedule_kind == "once":
            schedule.enabled = False
            schedule.next_run_at = None
        else:
            schedule.next_run_at = next_cron_run(schedule.cron_expression, schedule.timezone_name, after=current)
        schedule.updated_at = current
        if active is not None:
            db.add(
                AuditEvent(
                    actor=f"scheduler:{schedule.name}",
                    action="skip_scheduled_task",
                    resource_type="schedule",
                    resource_id=str(schedule.id),
                    success=False,
                    detail=f"active_job={active.id}; planned_for={planned_for.isoformat() if planned_for else ''}",
                )
            )
            continue
        config = json_object(schedule.task_config_json, label="Task configuration")
        if schedule.task_type == "appliance_update_check":
            config["mode"] = "check"
        elif schedule.task_type == "appliance_update_install":
            config["mode"] = "run"
        config["_schedule_id"] = schedule.id
        config["_schedule_name"] = schedule.name
        job = Job(
            id=f"job_schedule_{schedule.id}_{int(current.timestamp())}",
            type=SCHEDULE_JOB_TYPES[schedule.task_type],
            status=JobStatus.PENDING.value,
            created_by=f"scheduler:{schedule.name}",
            progress_percent=0,
            schedule_id=schedule.id,
            trigger="scheduled",
            planned_for=planned_for,
            task_config_json=json.dumps(config, sort_keys=True),
            result=json.dumps({"schedule_id": schedule.id, "schedule_name": schedule.name, "trigger": "scheduled"}, indent=2),
        )
        db.add(job)
        db.flush()
        if job.type == "appliance-update":
            ensure_appliance_update_job_steps(
                db,
                job=job,
                selected_streams=[str(value) for value in config.get("selected_streams", [])],
            )
        schedule.last_job_id = job.id
        db.add(
            AuditEvent(
                actor=f"scheduler:{schedule.name}",
                action="queue_scheduled_task",
                resource_type="job",
                resource_id=job.id,
                detail=f"schedule_id={schedule.id}; task_type={schedule.task_type}",
            )
        )
        jobs.append(job)
    db.commit()
    return jobs
