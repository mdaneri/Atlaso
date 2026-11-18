"""Persist and compare bounded network snapshots around appliance updates."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.models import ApplianceUpdateNetworkSnapshot, Job

LOGGER = logging.getLogger(__name__)
SNAPSHOT_SECTIONS = ("routes", "rules", "interfaces", "forwarding")
SNAPSHOT_SECTION_LIMITS = {"routes": 1024, "rules": 512, "interfaces": 256, "forwarding": 4}
SNAPSHOT_SIZE_LIMIT = 1_048_576
SECTION_ROW_FIELDS = {
    "routes": (
        "family",
        "table",
        "destination",
        "gateway",
        "interface",
        "metric",
        "protocol",
        "type",
        "preferred_source",
        "source_prefix",
        "nexthop_id",
        "nexthops",
    ),
    "rules": (
        "family",
        "priority",
        "source",
        "destination",
        "ingress",
        "egress",
        "table",
        "action",
        "protocol",
        "selectors",
    ),
    "interfaces": (
        "interface",
        "carrier",
        "parent",
        "vlan",
        "addresses",
        "mtu",
    ),
    "forwarding": ("family", "enabled"),
}
SECTION_IDENTITIES = {
    "routes": ("family", "table", "destination", "type"),
    "rules": ("family", "priority"),
    "interfaces": ("interface",),
    "forwarding": ("family",),
}


def _capture_timestamp(value: Any) -> str:
    if isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            return timestamp.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()


def _project_snapshot(payload: Any) -> dict[str, Any]:
    """Keep only the bounded network fields consumed by the comparison view."""
    payload = payload if isinstance(payload, dict) else {}
    sections = payload.get("sections")
    sections = sections if isinstance(sections, dict) else {}
    projected_sections: dict[str, dict[str, Any]] = {}
    for section_name, fields in SECTION_ROW_FIELDS.items():
        section = sections.get(section_name)
        section = section if isinstance(section, dict) else {}
        state = section.get("state")
        if state not in {"ok", "partial", "unavailable"}:
            state = "unavailable"
        raw_rows = section.get("rows")
        raw_rows = raw_rows if isinstance(raw_rows, list) else []
        rows: list[dict[str, Any]] = []
        row_limit = SNAPSHOT_SECTION_LIMITS[section_name]
        for row in raw_rows[:row_limit]:
            if not isinstance(row, dict):
                continue
            projected = {
                key: row[key]
                for key in fields
                if key in row and (section_name != "interfaces" or key not in {"rx_errors", "tx_errors"})
            }
            for collection in ("addresses", "nexthops"):
                values = projected.get(collection)
                if isinstance(values, list):
                    projected[collection] = sorted(
                        values,
                        key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")),
                    )
            rows.append(projected)
        if len(raw_rows) > row_limit and state == "ok":
            state = "partial"
        projected_sections[section_name] = {"state": state, "rows": rows}
    projected_payload = {
        "captured_at": _capture_timestamp(payload.get("captured_at")),
        "sections": projected_sections,
    }
    serialized = json.dumps(projected_payload, sort_keys=True, separators=(",", ":"))
    while len(serialized.encode("utf-8")) > SNAPSHOT_SIZE_LIMIT:
        for section_name in reversed(SNAPSHOT_SECTIONS):
            rows = projected_sections[section_name]["rows"]
            if rows:
                rows.pop()
                if projected_sections[section_name]["state"] == "ok":
                    projected_sections[section_name]["state"] = "partial"
                break
        else:
            break
        serialized = json.dumps(projected_payload, sort_keys=True, separators=(",", ":"))
    return projected_payload


def capture_snapshot(db: Session, *, job: Job, phase: str) -> bool:
    """Capture and persist one immutable update network observation.

    Native discovery failures are recorded as unavailable sections and do not
    change Appliance Update task outcomes.
    """
    if phase not in {"before", "after"} or job.type != "appliance-update":
        return False
    try:
        config = json.loads(job.task_config_json or "{}")
    except (TypeError, ValueError):
        return False
    if not isinstance(config, dict) or config.get("mode") != "run":
        return False
    transaction_id = config.get("status_transaction_id")
    if not isinstance(transaction_id, str) or not transaction_id:
        return False

    existing = db.get(ApplianceUpdateNetworkSnapshot, (job.id, phase))
    if existing is not None:
        return existing.transaction_id == transaction_id
    if phase == "after":
        before = db.get(ApplianceUpdateNetworkSnapshot, (job.id, "before"))
        if before is None or before.transaction_id != transaction_id:
            return False

    try:
        from atlaso.app.services.monitor_runtime import collect_network

        snapshot = _project_snapshot(collect_network(include_neighbors=False))
    except Exception:  # noqa: BLE001 - observation failure must not fail the update.
        LOGGER.warning("Appliance Update network comparison capture failed for phase %s", phase)
        snapshot = _project_snapshot({})

    captured = ApplianceUpdateNetworkSnapshot(
        job_id=job.id,
        phase=phase,
        transaction_id=transaction_id,
        captured_at=datetime.fromisoformat(snapshot["captured_at"]),
        snapshot_json=json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
    )
    try:
        with db.begin_nested():
            db.add(captured)
            db.flush()
    except IntegrityError:
        existing = db.get(ApplianceUpdateNetworkSnapshot, (job.id, phase))
        return existing is not None and existing.transaction_id == transaction_id
    return True


def _snapshot_row(snapshot: ApplianceUpdateNetworkSnapshot | None) -> dict[str, Any]:
    if snapshot is None:
        return {
            "state": "unrecorded",
            "captured_at": None,
            "sections": _empty_sections("unrecorded"),
        }
    try:
        value = json.loads(snapshot.snapshot_json)
    except (TypeError, ValueError):
        return {
            "state": "unavailable",
            "captured_at": _capture_timestamp(snapshot.captured_at.isoformat()),
            "sections": _empty_sections(),
        }
    value = _project_snapshot(value)
    return {"state": "recorded", **value}


def _empty_sections(state: str = "unavailable") -> dict[str, dict[str, Any]]:
    return {
        name: {"state": state, "rows": []}
        for name in SNAPSHOT_SECTIONS
    }


def _row_identity(section: str, row: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for field in SECTION_IDENTITIES[section]:
        value = row.get(field)
        values.append(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return tuple(values)


def _compare_rows(
    section: str, before_rows: list[Any], after_rows: list[Any]
) -> dict[str, list[dict[str, Any]]]:
    before: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    after: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in before_rows:
        if isinstance(row, dict):
            before[_row_identity(section, row)].append(row)
    for row in after_rows:
        if isinstance(row, dict):
            after[_row_identity(section, row)].append(row)

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    for identity in sorted(before.keys() | after.keys()):
        old_rows = sorted(before.get(identity, []), key=lambda row: json.dumps(row, sort_keys=True))
        new_rows = sorted(after.get(identity, []), key=lambda row: json.dumps(row, sort_keys=True))
        new_by_value: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in new_rows:
            new_by_value[json.dumps(row, sort_keys=True, separators=(",", ":"))].append(row)
        old_remaining: list[dict[str, Any]] = []
        for row in old_rows:
            exact = new_by_value.get(json.dumps(row, sort_keys=True, separators=(",", ":")))
            if exact:
                exact.pop()
            else:
                old_remaining.append(row)
        new_remaining = [row for rows in new_by_value.values() for row in rows]
        if len(old_remaining) == len(new_remaining) == 1:
            changed.append({"before": old_remaining[0], "after": new_remaining[0]})
        else:
            removed.extend(old_remaining)
            added.extend(new_remaining)
    return {"added": added, "removed": removed, "changed": changed}


def get_comparison(db: Session, job_id: str) -> dict[str, Any] | None:
    """Return projected before/after observations and diffs for an install task."""
    job = db.get(Job, job_id)
    if job is None or job.type != "appliance-update":
        return None
    try:
        config = json.loads(job.task_config_json or "{}")
    except (TypeError, ValueError):
        return None
    if not isinstance(config, dict) or config.get("mode") != "run":
        return None
    transaction_id = config.get("status_transaction_id")
    rows = (
        db.scalars(
            select(ApplianceUpdateNetworkSnapshot).where(
                ApplianceUpdateNetworkSnapshot.job_id == job.id,
                ApplianceUpdateNetworkSnapshot.transaction_id == transaction_id,
            )
        ).all()
        if isinstance(transaction_id, str) and transaction_id
        else []
    )
    snapshots = {row.phase: row for row in rows if row.phase in {"before", "after"}}
    before = _snapshot_row(snapshots.get("before"))
    after = _snapshot_row(snapshots.get("after"))
    try:
        task_result = json.loads(job.result or "{}")
    except (TypeError, ValueError):
        task_result = {}
    task_success = task_result.get("success") if isinstance(task_result, dict) else None
    comparisons: dict[str, dict[str, Any]] = {}
    for section in SNAPSHOT_SECTIONS:
        old = before["sections"][section]
        new = after["sections"][section]
        state = (
            "unavailable"
            if old["state"] == "unavailable" or new["state"] == "unavailable"
            else "unrecorded"
            if old["state"] == "unrecorded" or new["state"] == "unrecorded"
            else "ok"
            if old["state"] == "ok" and new["state"] == "ok"
            else "partial"
        )
        diff = _compare_rows(section, old["rows"], new["rows"]) if state == "ok" else {
            "added": [],
            "removed": [],
            "changed": [],
        }
        comparisons[section] = {"state": state, **diff}
    return {
        "task_id": job.id,
        "state": (
            "unrecorded"
            if not snapshots
            else "complete"
            if before["state"] == "recorded"
            and after["state"] == "recorded"
            and all(section["state"] == "ok" for section in comparisons.values())
            else "partial"
        ),
        "outcome": {
            "status": job.status,
            "success": task_success if isinstance(task_success, bool) else None,
        },
        "phases": {"before": before, "after": after},
        "sections": comparisons,
    }
