"""Capture task output transactionally and page its immutable character stream."""

import hashlib
import hmac
import json
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.models import AuditEvent, Job, TaskLogCheckpoint, TaskLogChunk
from atlaso.app.services import log_viewer
from atlaso.app.services.task_log_redaction import redact_task_value

CHUNK_CHARS = 16384


def _payload(value: str | None) -> dict[str, Any]:
    """Decode only mapping-shaped producer state.

    Args:
        value: Stored result or safe checkpoint JSON.
    """
    try:
        result = json.loads(value or "{}")
    except (ValueError, TypeError):
        return {}
    return result if isinstance(result, dict) else {}


def _safe_lines(lines: list[str], private: bool = False, parser: dict[str, str] | None = None) -> tuple[list[str], bool]:
    """Sanitize complete lines while carrying an unfinished private key.

    Args:
        lines: Newly observed producer lines, before scalar sanitization.
        private: Whether an earlier committed fragment opened a key.
        parser: Finite marker state retained between committed fragments.
    """
    output = []
    parser = parser if parser is not None else {}
    carry = parser.get("carry", "").encode("ascii")
    for value in lines:
        for line in str(value).splitlines() or [""]:
            marker, carry = log_viewer._scan_pem_markers(line.encode("utf-8"), carry)
            concealed = private or marker is not None or carry not in {b"", b"S"}
            output.append("[redacted private key]" if concealed else str(redact_task_value(line)))
            if marker is not None:
                private = marker
            if carry.startswith(b"B"):
                private = True
    parser["carry"] = carry.decode("ascii")
    return output, private


def _log_digest(lines: list[Any]) -> str:
    """Authenticate a producer prefix without persisting its raw contents.

    Args:
        lines: Cumulative producer log values.
    """
    encoded = json.dumps(lines, sort_keys=True, ensure_ascii=False).encode()
    return hmac.new(get_settings().secret_key.encode(), encoded, hashlib.sha256).hexdigest()


def _safe_value(value: Any, private: bool = False, key: str = "", parser: dict[str, str] | None = None) -> tuple[Any, bool]:
    """Sanitize nested result values before any checkpoint copy is persisted.

    Args:
        value: Original producer value.
        private: Unfinished key state within the result structure.
        key: Mapping key used by the established scalar secret policy.
        parser: Finite raw-value marker state shared by nested values.
    """
    parser = parser if parser is not None else {}
    if key and redact_task_value("", key=key) == "[redacted]":
        return "[redacted]", private
    if isinstance(value, dict):
        output = {}
        for item_key, item in value.items():
            output[str(item_key)], private = _safe_value(item, private, str(item_key), parser)
        return output, private
    if isinstance(value, list):
        items = []
        for item in value:
            safe, private = _safe_value(item, private, parser=parser)
            items.append(safe)
        return items, private
    if isinstance(value, str):
        lines, private = _safe_lines([value], private, parser)
        return "\n".join(lines), private
    return "[redacted private key]" if private else value, private


def capture_task_history(connection: Connection, job_id: str, audit_ids: tuple[int, ...] = ()) -> None:
    """Append result deltas and audit records inside the producer transaction.

    Args:
        connection: Producer-owned transactional connection.
        job_id: Task whose row serializes history writers.
        audit_ids: Newly flushed audit records; existing records are captured at initialization.
    """
    jobs, checkpoints, chunks = Job.__table__, TaskLogCheckpoint.__table__, TaskLogChunk.__table__
    locked = connection.execute(update(jobs).where(jobs.c.id == job_id).values(progress_percent=jobs.c.progress_percent))
    if locked.rowcount != 1:
        return
    job = connection.execute(select(jobs.c.result, jobs.c.error, jobs.c.status).where(jobs.c.id == job_id)).one()
    checkpoint = connection.execute(select(checkpoints).where(checkpoints.c.job_id == job_id)).mappings().first()
    previous = _payload(checkpoint["state_json"]) if checkpoint else {}
    end = int(checkpoint["end_offset"]) if checkpoint else 0
    result = _payload(job.result)
    result_parser = {"carry": previous.get("result_pem_state", "")}
    safe_result, result_private = _safe_value(
        {key: value for key, value in result.items() if key != "state" and (key != "log_lines" or not isinstance(value, list))},
        bool(previous.get("result_private")), parser=result_parser
    )
    old_result = previous.get("result", {})
    lines = []
    for key, value in safe_result.items():
        if key not in old_result or old_result[key] != value:
            rendered = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
            safe, _ = _safe_lines([f"{key}: {rendered}"])
            lines.extend(safe)
    for key in old_result.keys() - safe_result.keys():
        lines.append(f"{key}: [removed]")
    raw_logs = result.get("log_lines", [])
    raw_logs = raw_logs if isinstance(raw_logs, list) else []
    count = int(previous.get("log_count", 0))
    appending = count <= len(raw_logs) and _log_digest(raw_logs[:count]) == previous.get("log_digest")
    private = bool(previous.get("private"))
    log_parser = {"carry": previous.get("log_pem_state", "")}
    for value in raw_logs[count if appending else 0:]:
        if not isinstance(value, str):
            value, private = _safe_value(value, private, parser=log_parser)
            lines.append(str(value))
        else:
            safe_logs, private = _safe_lines([value], private, log_parser)
            lines.extend(safe_logs)
    error = _safe_value(job.error or "")[0] if job.status not in {"pending", "running"} else ""
    if error and error != previous.get("error"):
        safe, _ = _safe_lines([f"Error: {error}"])
        lines.extend(safe)
    audit = AuditEvent.__table__
    query = select(audit).where(audit.c.resource_type == "job", audit.c.resource_id == job_id)
    if checkpoint:
        query = query.where(audit.c.id.in_(audit_ids))
    audit_private = bool(previous.get("audit_private"))
    audit_parser = {"carry": previous.get("audit_pem_state", "")}
    for event in connection.execute(query.order_by(audit.c.id)).mappings():
        outcome = "success" if event["success"] else "failed"
        safe, audit_private = _safe_lines(
            [event["detail"] or ""], audit_private, audit_parser
        )
        prefix = str(redact_task_value(f"{event['created_at'].isoformat()} {event['action']} {outcome}"))
        lines.extend(f"{prefix} {line}" for line in safe)
    text = "".join(line + "\n" for line in lines)
    for start in range(0, len(text), CHUNK_CHARS):
        content = text[start:start + CHUNK_CHARS]
        connection.execute(chunks.insert().values(job_id=job_id, start_offset=end, end_offset=end + len(content), content=content))
        end += len(content)
    state = json.dumps({"result": safe_result, "log_count": len(raw_logs), "log_digest": _log_digest(raw_logs),
                        "log_pem_state": log_parser.get("carry", ""), "result_pem_state": result_parser.get("carry", ""),
                        "audit_pem_state": audit_parser.get("carry", ""),
                        "private": private, "result_private": result_private, "audit_private": audit_private, "error": error}, sort_keys=True)
    if checkpoint:
        connection.execute(update(checkpoints).where(checkpoints.c.job_id == job_id).values(state_json=state, end_offset=end))
    else:
        connection.execute(checkpoints.insert().values(job_id=job_id, state_json=state, end_offset=end))


def initialize_task_history(engine: Engine) -> None:
    """Initialize legacy task output before serving read-only history requests.

    Args:
        engine: Appliance database with current task columns and history tables.
    """
    after = ""
    while True:
        with engine.begin() as connection:
            ids = connection.execute(select(Job.id).where(Job.id > after).order_by(Job.id).limit(100)).scalars().all()
            for job_id in ids:
                capture_task_history(connection, job_id)
        if len(ids) < 100:
            break
        after = ids[-1]


def task_history_page(db: Session, job_id: str, *, cursor: str = "", tail: bool = False) -> dict[str, Any]:
    """Read a bounded immutable task window without rewriting producer state.

    Args:
        db: Read-only request session.
        job_id: Authorized task identifier.
        cursor: Signed character position in the immutable stream.
        tail: Open the latest retained window.
    """
    source = f"task:{job_id}"
    position = log_viewer.decode_cursor(cursor, source)
    reset = bool(cursor and position.get("history") != 1)
    if reset:
        position = {}
    offset = position.get("offset", 0)
    total = db.execute(select(TaskLogCheckpoint.end_offset).where(TaskLogCheckpoint.job_id == job_id)).scalar_one_or_none() or 0
    if type(offset) is not int or not 0 <= offset <= total:
        raise ValueError("Invalid task history position.")
    backward = position.get("before") is True or (tail and not cursor)
    end = offset if position.get("before") else position.get("page_end", total)
    if end is None:
        end = total
    if type(end) is not int or not offset <= end <= total:
        raise ValueError("Invalid task history boundary.")
    query = select(TaskLogChunk).where(TaskLogChunk.job_id == job_id, TaskLogChunk.start_offset < end)
    if backward:
        rows = db.execute(query.order_by(TaskLogChunk.start_offset.desc()).limit(65)).scalars().all()[::-1]
        start = rows[0].start_offset if rows else end
    else:
        rows = db.execute(query.where(TaskLogChunk.end_offset > offset).order_by(TaskLogChunk.start_offset).limit(65)).scalars().all()
        start = rows[0].start_offset if rows else offset
    text = "".join(row.content for row in rows)
    text = text[max(0, offset - start) if not backward else 0:max(0, end - start)]
    bounded = log_viewer._bounded_json_text(text, suffix=backward)
    physical_lines = bounded.splitlines(keepends=True)
    bounded = "".join(physical_lines[-500:] if backward else physical_lines[:500])
    if backward:
        offset = end - len(bounded)
    finish = offset + len(bounded)
    def encode(**values):
        """Bind an immutable character position to this task.

        Args:
            **values: Validated history position fields.
        """
        return log_viewer.encode_cursor(source, history=1, **values)
    return {"source": source, "available": True, "text": bounded,
            "cursor": encode(offset=offset, page_end=end if backward or position.get("page_end") else None),
            "next_cursor": encode(offset=finish), "previous_cursor": encode(offset=offset, before=True) if offset else "",
            "has_more": finish < total, "reset": reset,
            "notice": "Task history now uses stable entries; reopened the beginning." if reset else ""}
