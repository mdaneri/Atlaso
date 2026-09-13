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
    if private and not carry.startswith(b"["):
        carry = json.dumps(["S", "", bytes(32).hex(), "", "!"]).encode("ascii")
    for value in lines:
        for line in str(value).splitlines() or [""]:
            private = private or parser.get("hold") == "1"
            marker, carry = log_viewer._scan_pem_markers(line.encode("utf-8"), carry)
            concealed = private or marker is not None or (json.loads(carry)[0] != "S" or bool(json.loads(carry)[1]))
            output.append("[redacted private key]" if concealed else str(redact_task_value(line)))
            if marker is not None:
                private = marker
            if carry.startswith((b"B", b'["B",')) or parser.get("hold") == "1":
                private = True
    parser["carry"] = carry.decode("ascii")
    return output, private


def _log_digest(lines: list[Any]) -> str:
    """Authenticate producer values and nested field order without raw copies.

    Args:
        lines: Cumulative producer log values.
    """
    encoded = json.dumps(lines, ensure_ascii=False).encode()
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
        _, private = _safe_value(value, private, parser=parser)
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


def _merge_private_redaction(current: Any, snapshot: Any) -> Any:
    """Combine incremental and snapshot concealment without weakening either view.

    Args:
        current: Value sanitized in the newly appended stream context.
        snapshot: Same value sanitized by replaying the current result snapshot.
    """
    if isinstance(current, dict) and isinstance(snapshot, dict):
        return {key: _merge_private_redaction(value, snapshot[key]) for key, value in current.items()}
    if isinstance(current, list) and isinstance(snapshot, list):
        return [_merge_private_redaction(left, right) for left, right in zip(current, snapshot, strict=True)]
    if snapshot == "[redacted private key]" or current == "[redacted private key]":
        return "[redacted private key]"
    if isinstance(current, str) and isinstance(snapshot, str):
        left, right = current.splitlines(), snapshot.splitlines()
        if len(left) == len(right):
            return "\n".join("[redacted private key]" if "[redacted private key]" in (a, b) else a
                             for a, b in zip(left, right, strict=True))
    return current


def capture_task_history(
    connection: Connection, job_id: str, audit_ids: tuple[int, ...] = (), *,
    result_changed: bool = True, only_if_missing: bool = False,
) -> None:
    """Append result deltas and audit records inside the producer transaction.

    Args:
        connection: Producer-owned transactional connection.
        job_id: Task whose row serializes history writers.
        audit_ids: Newly flushed audit records; existing records are captured at initialization.
        result_changed: ORM result-change evidence; direct and Core callers default to full validation.
        only_if_missing: Recheck startup migration eligibility under the producer row lock.
    """
    jobs, checkpoints, chunks = Job.__table__, TaskLogCheckpoint.__table__, TaskLogChunk.__table__
    locked = connection.execute(update(jobs).where(jobs.c.id == job_id).values(progress_percent=jobs.c.progress_percent))
    if locked.rowcount != 1:
        return
    checkpoint = connection.execute(select(checkpoints).where(checkpoints.c.job_id == job_id)).mappings().first()
    if only_if_missing and checkpoint is not None:
        return
    job = connection.execute(select(jobs.c.result, jobs.c.error, jobs.c.status).where(jobs.c.id == job_id)).one()
    previous = _payload(checkpoint["state_json"]) if checkpoint else {}
    end = int(checkpoint["end_offset"]) if checkpoint else 0
    state = dict(previous)
    parser = {"carry": previous.get("stream_pem_state", "")}
    private = bool(previous.get("stream_private"))
    if "stream_pem_state" not in previous:
        active = [(previous.get(flag), previous.get(key, "")) for flag, key in (
            ("result_private", "result_pem_state"), ("private", "log_pem_state"), ("audit_private", "audit_pem_state"))]
        contexts = {carry for opened, carry in active if opened or (carry and carry not in {"S", ""} and
                    (not carry.startswith("[") or json.loads(carry)[0] != "S" or json.loads(carry)[1]))}
        if contexts:
            parser["carry"] = next(iter(contexts)) if len(contexts) == 1 else json.dumps(["S", "", bytes(32).hex(), "", "!"])
            private = any(opened for opened, _ in active) or len(contexts) > 1
    _, common_carry = log_viewer._scan_pem_markers(b"", parser["carry"].encode("ascii"))
    fields = json.loads(common_carry)
    active_label = fields[4] or ("!" if private and fields[0] == "S" and not fields[1] else "")
    common_carry = json.dumps(["S", "", bytes(32).hex(), "", active_label]).encode("ascii")
    partials = dict(previous.get("partial_pem_states", {}))
    if "partial_pem_states" not in previous:
        for channel, key in (("result", "result_pem_state"), ("log", "log_pem_state"), ("audit", "audit_pem_state")):
            carry = previous.get(key, "")
            if carry:
                _, normalized = log_viewer._scan_pem_markers(b"", carry.encode("ascii"))
                fields = json.loads(normalized)
                if fields[0] != "S" or fields[1]:
                    partials[channel] = normalized.decode("ascii")

    def enter_stream(channel: str) -> tuple[bool, dict[str, str]]:
        """Share completed key identity while preserving interrupted source fragments.

        Args:
            channel: Producer stream about to append changed output.
        """
        fields = json.loads(partials.get(channel, common_carry.decode("ascii")))
        fields[4] = active_label
        held = any(name != channel for name in partials)
        return bool(active_label) or held or fields[0] == "B", {
            "carry": json.dumps(fields, separators=(",", ":")), "hold": "1" if held else "0"}

    def leave_stream(channel: str, current: dict[str, str]) -> None:
        """Publish completed label identity and retain only bounded partial tokens.

        Args:
            channel: Producer stream just consumed.
            current: Parser state after its new values.
        """
        nonlocal active_label
        fields = json.loads(current["carry"])
        active_label = fields[4]
        if fields[0] != "S" or fields[1]:
            partials[channel] = current["carry"]
        else:
            partials.pop(channel, None)

    lines = []
    if result_changed or checkpoint is None:
        private, parser = enter_stream("result")
        result = _payload(job.result)
        old_result = previous.get("result", {})
        old_digests = previous.get("result_digests", {})
        raw_fields = {key: value for key, value in result.items()
                      if key != "state" and (key != "log_lines" or not isinstance(value, list))}
        result_digests = {key: _log_digest([key, value]) for key, value in raw_fields.items()}
        snapshot_parser: dict[str, str] = {}
        snapshot = None
        if result_digests != old_digests or list(raw_fields) != previous.get("result_order"):
            snapshot, _ = _safe_value(raw_fields, parser=snapshot_parser)
        safe_result = {}
        for key, raw_value in raw_fields.items():
            if key in old_result and old_digests.get(key) == result_digests[key]:
                value = old_result[key]
            else:
                value, private = _safe_value(raw_value, private, key, parser)
            if snapshot is not None:
                value = _merge_private_redaction(value, snapshot[key])
            safe_result[key] = value
            if key not in old_result or old_result[key] != value:
                rendered = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
                safe, _ = _safe_lines([f"{key}: {rendered}"])
                lines.extend(safe)
        for key in old_result.keys() - safe_result.keys():
            lines.append(f"{key}: [removed]")
        leave_stream("result", parser)
        if snapshot_parser.get("carry"):
            snapshot_fields = json.loads(snapshot_parser["carry"])
            label = snapshot_fields[4]
            if label:
                active_label = label if not active_label or active_label == label else "!"
            if snapshot_fields[0] != "S" or snapshot_fields[1]:
                partials["result"] = snapshot_parser["carry"]
        private, parser = enter_stream("log")
        raw_logs = result.get("log_lines", [])
        raw_logs = raw_logs if isinstance(raw_logs, list) else []
        count = int(previous.get("log_count", 0))
        appending = count <= len(raw_logs) and _log_digest(raw_logs[:count]) == previous.get("log_digest")
        for value in raw_logs[count if appending else 0:]:
            if not isinstance(value, str):
                value, private = _safe_value(value, private, parser=parser)
                lines.append(str(value))
            else:
                safe_logs, private = _safe_lines([value], private, parser)
                lines.extend(safe_logs)
        leave_stream("log", parser)
        state.update(result=safe_result, result_digests=result_digests, result_order=list(raw_fields),
                     log_count=len(raw_logs), log_digest=_log_digest(raw_logs))
    error = previous.get("error", "")
    raw_error = job.error or "" if job.status not in {"pending", "running"} else ""
    if raw_error and _log_digest([raw_error]) != previous.get("error_digest"):
        private, parser = enter_stream("error")
        error, private = _safe_value(raw_error, private, parser=parser)
        safe, _ = _safe_lines([f"Error: {error}"])
        lines.extend(safe)
        state["error_digest"] = _log_digest([raw_error])
        leave_stream("error", parser)
    audit = AuditEvent.__table__
    query = select(audit).where(audit.c.resource_type == "job", audit.c.resource_id == job_id)
    if checkpoint:
        query = query.where(audit.c.id.in_(audit_ids))
    private, parser = enter_stream("audit")
    for event in connection.execute(query.order_by(audit.c.id)).mappings():
        outcome = "success" if event["success"] else "failed"
        safe, private = _safe_lines([event["detail"] or ""], private, parser)
        prefix = str(redact_task_value(f"{event['created_at'].isoformat()} {event['action']} {outcome}"))
        lines.extend(f"{prefix} {line}" for line in safe)
    leave_stream("audit", parser)
    parser["carry"] = json.dumps(["S", "", bytes(32).hex(), "", active_label], separators=(",", ":"))
    private = bool(active_label)
    state["partial_pem_states"] = partials
    text = "".join(line + "\n" for line in lines)
    for start in range(0, len(text), CHUNK_CHARS):
        content = text[start:start + CHUNK_CHARS]
        connection.execute(chunks.insert().values(job_id=job_id, start_offset=end, end_offset=end + len(content), content=content))
        end += len(content)
    state.update(stream_pem_state=parser.get("carry", ""), stream_private=private, error=error)
    for key in ("log_pem_state", "result_pem_state", "audit_pem_state"):
        state[key] = partials.get(key.split("_")[0], parser.get("carry", ""))
    state.update(private=private, result_private=private, audit_private=private)
    state_json = json.dumps(state, sort_keys=True)
    if checkpoint:
        connection.execute(update(checkpoints).where(checkpoints.c.job_id == job_id).values(state_json=state_json, end_offset=end))
    else:
        connection.execute(checkpoints.insert().values(job_id=job_id, state_json=state_json, end_offset=end))


def initialize_task_history(engine: Engine) -> None:
    """Initialize legacy task output before serving read-only history requests.

    Args:
        engine: Appliance database with current task columns and history tables.
    """
    after = ""
    while True:
        with engine.begin() as connection:
            ids = connection.execute(select(Job.id).where(
                Job.id > after, ~select(TaskLogCheckpoint.job_id).where(TaskLogCheckpoint.job_id == Job.id).exists()
            ).order_by(Job.id).limit(100)).scalars().all()
            for job_id in ids:
                capture_task_history(connection, job_id, only_if_missing=True)
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
