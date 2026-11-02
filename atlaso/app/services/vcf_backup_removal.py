"""Reviewed removal of recorded initial-backup files, retaining audit evidence."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

from itsdangerous import BadData
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.models import Job, Setting, utcnow
from atlaso.app.services import vcf_backup_workflow as workflow
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.vcf_backup_native import NativeBackup
from atlaso.app.services.vcf_backup_receiver import (
    ReceiverSession,
    receiver_revision,
    require_receiver,
)


def _vcenter_destinations(native: NativeBackup, source: dict[str, Any], group: dict[str, Any]) -> list[dict[str, Any]]:
    """Allow a deleted scheduler only on the same recorded vCenter appliance.

    Args:
        native: Authenticated pinned vCenter adapter, used only for removal reads.
        source: Recorded appliance identity and originally inspected schedulers.
        group: Recorded backup whose files are being reviewed for removal.
    """
    reviewed = source["inventory"]
    original = [item for item in reviewed["groups"] if item["id"] == group["native_group_id"]]
    instance = original[0].get("native_identity", {}).get("instance_uuid") if len(original) == 1 else None
    latest = native.discover()
    groups = latest.get("groups")
    if (
        not isinstance(instance, str) or not instance or reviewed["identity"] != "vcenter:" + instance
        or any(latest.get(key) != reviewed.get(key) for key in ("identity", "version", "service"))
        or not isinstance(groups, list) or not groups
        or any(not isinstance(item, dict) or not isinstance(item.get("native_identity"), dict)
               or item["native_identity"].get("instance_uuid") != instance
               or not isinstance(item.get("current"), dict) for item in groups)
    ):
        raise workflow.BackupOperationError("The recorded vCenter appliance identity changed; stored files must be retained.")
    return [item["current"] for item in groups]


def _idle(db: Session, state: dict[str, Any]) -> None:
    """Refuse removal while configuration, recovery, or another removal is active.

    Args:
        db: Current admission session.
        state: Owner-bound historical operation.
    """
    job = db.get(Job, state.get("job_id", ""))
    if job is None or job.status in {"pending", "running"} or state["state"] not in {"succeeded", "reconciled"}:
        raise workflow.BackupOperationError("Finish or reconcile this backup operation before removing it.")
    if state.get("reconciliation_state") in {"queued", "running"} or state.get("removal_state") in {"removing", "removed"}:
        raise workflow.BackupOperationError("This operation is being checked or removed. Reload its status.")
    if db.scalar(select(Setting.id).where(Setting.key.like(workflow.LOCK_PREFIX + "%")).limit(1)) is not None:
        raise workflow.BackupOperationError("Another operation reserves a backup scheduler. Wait or finish recovery first.")


def _native_idle(db: Session, state: dict[str, Any], values: dict[str, Any]) -> None:
    """Check recorded native identity, terminal tasks, and disconnected destinations.

    Args:
        db: Session used to resolve recorded Vault references.
        state: Immutable native references and receiver directories.
        values: Invocation-local source credentials.
    """
    groups = [group for group in state.get("plan", []) if group.get("configuration_reference") is not None
              or group.get("backup_reference") is not None or group.get("checkpoint") != "reviewed"]
    if not groups:
        return
    inputs = workflow._recovery_source_inputs(db, state, values)
    reports = []
    for group in groups:
        source, credential = inputs[group["source_id"]]
        with workflow._native(source, credential, factory=NativeBackup) as native:
            native.login()
            if source["kind"] == "vcenter":
                destinations = _vcenter_destinations(native, source, group)
            else:
                workflow._current_native_identity(native, source)
                destinations = [native.current(group["native_group_id"])]
            for current in destinations:
                directory = current.get("directory")
                if current.get("host") and (not isinstance(directory, str) or not directory):
                    raise workflow.BackupOperationError("The native destination is ambiguous. Remove it in the native product first.")
                if current.get("host") and isinstance(directory, str):
                    target, root = PurePosixPath(directory), PurePosixPath(group["receiver_directory"])
                    if not target.is_absolute() or ".." in target.parts or "\\" in directory or any(ord(char) < 32 for char in directory):
                        raise workflow.BackupOperationError("The native destination is ambiguous. Remove it in the native product first.")
                    if target == root or target in root.parents or root in target.parents:
                        raise workflow.BackupOperationError("Remove this backup destination in the native product before deleting its stored files.")
            report: dict[str, Any] = {}
            reference = group.get("backup_reference")
            if reference is not None:
                status = native.vcenter_removal_task_status if source["kind"] == "vcenter" else native.backup_task_status
                report["native_backup"] = status(group["native_group_id"], reference.get("reference", reference))
            reference = group.get("configuration_reference")
            if reference is not None:
                if source["kind"] == "vcenter":
                    if (not isinstance(reference, dict) or reference.get("kind") not in (None, "vcenter")
                            or reference.get("group_id") not in (None, group["native_group_id"]) or reference.get("native_task_id") is not None):
                        raise workflow.BackupOperationError("The recorded vCenter configuration reference is ambiguous.")
                    report["native_configuration"] = {"state": "succeeded"}  # vCenter schedule writes are synchronous.
                else:
                    report["native_configuration"] = native.configuration_status(group["native_group_id"], reference)
            reports.append(report)
    if not workflow._native_tasks_terminal(groups, reports):
        raise workflow.BackupOperationError("A recorded native task is still running or unknown; its files cannot be removed.")


def _files(state: dict[str, Any]) -> dict[str, dict[str, list[int]]]:
    """Select only artifacts independently verified for this initial backup.

    Args:
        state: Durable historical artifact evidence.
    """
    result: dict[str, dict[str, list[int]]] = {}
    for group in state.get("plan", []):
        root = group["receiver_directory"]
        if not isinstance(root, str) or not root.startswith("/backups/vcf/") or len(PurePosixPath(root).parts) != 4:
            raise workflow.BackupOperationError("This operation has no safe Atlaso backup directory.")
        artifacts = result.setdefault(root, {})
        for item in group.get("artifacts", []):
            path, size, mtime = item.get("path"), item.get("bytes"), item.get("mtime")
            if (not isinstance(path, str) or PurePosixPath(root) not in PurePosixPath(path).parents
                    or any(part in {".", "..", ""} for part in path.split("/")[1:]) or "\\" in path
                    or any(ord(char) < 32 for char in path) or type(size) is not int or type(mtime) is not int
                    or size < 1 or mtime < 0):
                raise workflow.BackupOperationError("Recorded artifact ownership is incomplete; removal is unavailable.")
            if path in artifacts and artifacts[path] != [size, mtime]:
                raise workflow.BackupOperationError("Recorded artifact ownership is ambiguous.")
            artifacts[path] = [size, mtime]
    if not result:
        raise workflow.BackupOperationError("This operation has no recorded backup destinations.")
    return result


def _shared_files(db: Session, state: dict[str, Any], files: dict[str, dict[str, list[int]]]) -> None:
    """Preserve any artifact also referenced by another admitted operation.

    Args:
        db: Session containing historical operations from every owner.
        state: Operation being removed.
        files: Exact recorded paths selected for removal.
    """
    paths = {path for entries in files.values() for path in entries}
    rows = list(db.scalars(select(Setting).where(Setting.key.like(workflow.PREFIX + "%")).limit(1001)))
    if len(rows) > 1000:
        raise workflow.BackupOperationError("Backup history exceeds the bounded ownership check; removal is unavailable.")
    for row in rows:
        if row.key == workflow.PREFIX + state["operation_id"]:
            continue
        other = json.loads(row.value)
        if other.get("reconciliation_state") in {"queued", "running"}:
            raise workflow.BackupOperationError("Another backup operation is being checked. Wait before removing stored files.")
        if other.get("removal_state") == "removed":
            continue
        if any(item.get("path") in paths for group in other.get("plan", []) for item in group.get("artifacts", [])):
            raise workflow.BackupOperationError("Another operation references these backup files; removal is unavailable.")


def _snapshot(storage: ReceiverSession, files: dict[str, dict[str, list[int]]]) -> dict[str, dict[str, list[int]]]:
    """Refuse unrelated or changed files, including later incremental restore points.

    Args:
        storage: Authenticated pinned receiver session.
        files: Recorded initial-backup files permitted to be removed.
    """
    snapshot = {}
    for root, recorded in files.items():
        current = {path: list(detail) for path, detail in storage.manifest(root).items()}
        if any(path not in recorded or detail != recorded[path] for path, detail in current.items()):
            raise workflow.BackupOperationError(
                "The folder contains changed or additional backup files. Preserve its backup chain; automatic removal is unavailable."
            )
        snapshot[root] = current
    return snapshot


def dispatch(db: Session, actor: str, action: str, values: dict[str, Any]) -> dict[str, Any]:
    """Review or explicitly remove one owner's recorded initial backup.

    Args:
        db: Current owner-bound workflow session.
        actor: Enabled administrator requesting removal.
        action: Removal review or single-use confirmed removal.
        values: Operation identifier, review token, and invocation-local credentials.
    """
    workflow._actor(db, actor)
    row, state = workflow._state(db, actor, str(values.get("operation_id", "")))
    _idle(db, state)
    original = row.value
    receiver = require_receiver(db)
    if receiver_revision(receiver) != state["receiver"]:
        raise workflow.BackupOperationError("The applied backup receiver changed. Stored files cannot be removed from this operation.")
    files = _files(state)
    _shared_files(db, state, files)
    _native_idle(db, state, values)
    with ReceiverSession(receiver, workflow._secret(db, state["sftp_secret"])) as storage:
        snapshot = _snapshot(storage, files)
        if action == "removal-review":
            acquire_network_objects_write_lock(db)
            db.refresh(row)
            if row.value != original:
                raise workflow.BackupOperationError("This operation changed during removal review. Reload its status.")
            _idle(db, state)
            review: dict[str, Any] = {"nonce": uuid4().hex, "revision": workflow._revision(state), "files": snapshot}
            state["removal_review"] = review
            workflow._save(db, row, state)
            paths = sorted(path for entries in snapshot.values() for path in entries)
            token = workflow._serializer().dumps({"action": "remove", "actor": actor, "operation_id": state["operation_id"],
                                                  "review": workflow._digest(review)})
            return {"operation_id": state["operation_id"], "removal_token": token, "file_count": len(paths),
                    "total_bytes": sum(detail[0] for entries in snapshot.values() for detail in entries.values()), "paths": paths}
        try:
            token = workflow._serializer().loads(str(values.get("removal_token", "")), max_age=workflow.REVIEW_SECONDS)
        except BadData:
            raise workflow.BackupOperationError("Removal review expired or is invalid. Review again.") from None
        recorded_review = state.get("removal_review")
        if (values.get("confirmed") is not True or not isinstance(recorded_review, dict) or recorded_review.get("files") != snapshot
                or recorded_review.get("revision") != workflow._revision(state)
                or token != {"action": "remove", "actor": actor, "operation_id": state["operation_id"], "review": workflow._digest(recorded_review)}):
            raise workflow.BackupOperationError("The removal scope changed or was not confirmed. Review again.")
        acquire_network_objects_write_lock(db)
        db.refresh(row)
        if row.value != original:
            raise workflow.BackupOperationError("This operation changed during removal admission. Review again.")
        _idle(db, state)
        _shared_files(db, state, files)
        lease = "remove:" + state["operation_id"] + ":" + uuid4().hex
        db.add(Setting(key=workflow.LOCK_PREFIX + "global", value=lease))
        state.update(removal_state="removing", removal_lease=lease, removal_files=snapshot, removal_completed=[])
        state.pop("removal_review", None)
        workflow._save(db, row, state)  # Consume authorization before the first unlink.
        try:
            def completed(path: str) -> None:
                """Persist each completed unlink without changing historical backup success.

                Args:
                    path: Reviewed artifact just removed through pinned SFTP.
                """
                state["removal_completed"].append(path)
                workflow._save(db, row, state)

            for root, entries in snapshot.items():
                workflow._actor(db, actor)
                if receiver_revision(require_receiver(db)) != state["receiver"]:
                    raise workflow.BackupOperationError("The receiver changed during removal. Review remaining files again.")
                storage.remove_artifacts(root, entries, completed)
            if any(storage.manifest(root) for root in snapshot):
                raise workflow.BackupOperationError("Files appeared during removal. History was retained; review remaining files again.")
            state.update(removal_state="removed", removed_at=utcnow().isoformat())
        finally:
            if state["removal_state"] == "removing":
                state["removal_state"] = "failed"
            lock = db.scalar(select(Setting).where(Setting.key == workflow.LOCK_PREFIX + "global"))
            if lock is not None and lock.value == lease:
                db.delete(lock)
            workflow._save(db, row, state)
            record_audit(db, actor=actor, action="remove_vcf_backup_files", resource_type=workflow.JOB_TYPE,
                         resource_id=state["operation_id"], success=state["removal_state"] == "removed",
                         detail=workflow._json({"removed_files": len(state["removal_completed"])}), post_commit_best_effort=True)
            db.commit()
    return {"operation_id": state["operation_id"], "state": "removed", "removed_files": len(state["removal_completed"])}
