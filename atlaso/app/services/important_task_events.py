"""Project significant task transitions into the existing transactional history."""

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import literal, select
from sqlalchemy.engine import Connection

from atlaso.app.models import Job, JobStep
from atlaso.important_events import (
    COMPONENTS,
    EVENT_LIMIT,
    OUTCOMES,
    REASONS,
    STAGES,
    canonical_value,
    failure_reason,
    validate_event,
)


def _mapping(raw: Any) -> dict[str, Any]:
    """Decode a bounded producer object without retaining its arbitrary fields.

    Args:
        raw: Producer result JSON.
    """
    if not isinstance(raw, str) or len(raw) > 1024 * 1024:
        return {}
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _timestamp(value: datetime | None) -> str | None:
    """Format a persisted UTC timestamp, restoring UTC when SQLite drops tzinfo.

    Args:
        value: Persisted database timestamp.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat()


def execution_projection(payload: dict[str, Any], component: str) -> list[dict[str, Any]]:
    """Project bounded helper results and recovery separately, never raw streams.

    Args:
        payload: Producer-owned result mapping.
        component: Fixed component associated with the result.
    """
    output = []
    component = canonical_value(component, COMPONENTS) or "task"
    commands = payload.get("commands", [])
    if not isinstance(commands, list):
        commands = []
    for command in commands[:32]:
        if not isinstance(command, dict):
            continue
        code = command.get("returncode")
        if type(code) is not int or not -65536 <= code <= 65536:
            continue
        stage = canonical_value(command.get("stage"), STAGES)
        if stage is None:
            # Legacy command intent is inspected only to recognize fixed verbs.
            parts = command.get("command", [])
            stage = next((name for name in ("validation", "rollback", "recovery", "readiness", "cleanup")
                          if isinstance(parts, list) and {"validation": "validate"}.get(name, name) in parts[:8]), "execution")
        recorded_reason = canonical_value(command.get("reason_code"), REASONS.keys())
        reason = "none" if code == 0 else recorded_reason or failure_reason(command.get("stderr"), code)
        if stage == "validation" and code and reason == "helper_failed":
            reason = "validation_rejected"
        if stage == "rollback" and code:
            reason = "rollback_failed"
        output.append({"component": component, "stage": stage, "outcome": "succeeded" if code == 0 else "failed",
                       "reason": reason, "returncode": int(code)})
    for key, stage in (("network_transaction_recovery", "recovery"),
                       ("management_handoff_exception_recovery", "rollback")):
        recovery = payload.get(key)
        if isinstance(recovery, dict) and type(recovery.get("returncode")) is int:
            code = recovery["returncode"]
            if -65536 <= code <= 65536:
                output.append({"component": component, "stage": stage, "outcome": "failed" if code else "succeeded",
                               "reason": "rollback_failed" if code and stage == "rollback" else "cleanup_required" if code else "none",
                               "returncode": int(code)})
    return output


def capture_important_events(connection: Connection, job_id: str, previous: dict[str, Any],
                             state: dict[str, Any], *, result_changed: bool = True,
                             backfill: bool = False) -> list[dict[str, Any]]:
    """Retain transition evidence atomically with task state and sanitized chunks.

    Args:
        connection: Producer transaction holding the task row lock.
        job_id: Task owning these bounded records.
        previous: Prior sanitized checkpoint.
        state: New checkpoint updated in place.
        result_changed: Whether this transaction changed producer result evidence.
        backfill: Whether this capture initializes legacy history without transition timestamps.
    """
    columns: list[Any] = [column for column in Job.__table__.c if column.name != "result"]
    columns.append(Job.__table__.c.result if result_changed else literal(None).label("result"))
    job = connection.execute(select(*columns).where(Job.id == job_id)).mappings().one()
    payload = _mapping(job["result"])
    old_snapshots = previous.get("important_event_state", {})
    old_snapshots = old_snapshots if isinstance(old_snapshots, dict) else {}
    snapshots: dict[str, Any] = dict(old_snapshots)
    projections: list[tuple[str, dict[str, Any], str | None]] = []
    status = canonical_value(job["status"], OUTCOMES) or "failed"
    recorded_reason = canonical_value(payload.get("reason_code"), REASONS.keys())
    reason = ("none" if status not in {"failed", "cancelled", "partial-failure"}
              else recorded_reason if recorded_reason is not None
              else failure_reason(job["error"]))
    if status == "cancelled":
        reason = "cancelled"
    stage = "queued" if status == "pending" else "started" if status == "running" else "completed"
    task_at = _timestamp(job["created_at"] if stage == "queued" else
                         job["started_at"] if stage == "started" else job["finished_at"])
    projections.append(("task", {"component": "task", "stage": stage, "outcome": status, "reason": reason,
                                  "returncode": None}, task_at))
    if job["cancel_requested_at"]:
        completion_won = bool(job["cancel_completed_at"]) and job["cancel_outcome"] == "completion-won"
        projections.append(("cancellation", {"component": "task", "stage": "cancellation",
                            "outcome": status if completion_won else "cancelled" if job["cancel_completed_at"] else "running",
                            "reason": "completion_won" if completion_won else "cleanup_required" if job["cancel_outcome"] == "cleanup-required" else "cancelled",
                            "returncode": None}, _timestamp(job["cancel_completed_at"] or job["cancel_requested_at"])))
    if payload.get("state") == "cleanup-required":
        projections.append(("cleanup", {"component": "task", "stage": "cleanup", "outcome": "partial",
                                       "reason": "cleanup_required", "returncode": None}, None))
    columns = [column for column in JobStep.__table__.c if column.name != "result"]
    columns.append(JobStep.__table__.c.result if result_changed else literal(None).label("result"))
    rows = connection.execute(select(*columns).where(JobStep.job_id == job_id).order_by(JobStep.position).limit(100)).mappings()
    for row in rows:
        component = canonical_value(row["component_key"], COMPONENTS) or "task"
        step_status = canonical_value(row["status"], OUTCOMES) or "failed"
        step_reason = (failure_reason(row["error"]) if step_status in {"failed", "partial-failure"}
                       else "cancelled" if step_status == "cancelled" else "none")
        step_stage = "queued" if step_status == "pending" else "started" if step_status == "running" else "completed"
        step_at = _timestamp(row["created_at"] if step_stage == "queued" else
                             row["started_at"] if step_stage == "started" else row["finished_at"])
        projections.append((f"step:{row['position']}", {"component": component,
                            "stage": step_stage, "outcome": step_status, "reason": step_reason,
                            "returncode": None}, step_at))
        for index, result in enumerate(execution_projection(_mapping(row["result"]), component)):
            projections.append((f"step:{row['position']}:command:{index}", result, None))
    for index, result in enumerate(execution_projection(payload, "task")):
        projections.append((f"command:{index}", result, None))
    events = [event for value in previous.get("important_events", []) if (event := validate_event(value)) is not None]
    appended = []
    omitted = previous.get("important_events_omitted", 0)
    omitted = omitted if type(omitted) is int and omitted >= 0 else 0
    for key, projection, persisted_at in projections:
        snapshots[key] = projection
        if projection == old_snapshots.get(key):
            continue
        if backfill and persisted_at is None:
            # Result snapshots can identify an important stage, but cannot date
            # when it ran. Keep the state fingerprint and count omitted evidence.
            omitted += 1
            continue
        event_outcome = projection["outcome"]
        event_reason = projection["reason"]
        severity = (
            "ERROR"
            if event_outcome in {"failed", "partial-failure"}
            else "INFO"
            if event_outcome == "cancelled" and event_reason == "cancelled"
            else "INFO"
            if event_outcome in {"succeeded", "skipped", "no-op"} and event_reason == "completion_won"
            else "WARNING"
            if event_reason != "none"
            else "INFO"
        )
        event = {"schema": 1, "at": persisted_at if backfill else datetime.now(timezone.utc).isoformat(),
                 "severity": severity, **projection}
        if (safe := validate_event(event)) is not None:
            events.append(safe)
            appended.append(safe)
    while len(events) > EVENT_LIMIT:
        # Prefer dropping old successful stages; preserve original failures and recovery.
        index = next((i for i, item in enumerate(events) if item["severity"] == "INFO"), 0)
        events.pop(index)
        omitted += 1
    state.update(important_events=events, important_event_state=snapshots, important_events_omitted=omitted)
    return appended
