"""Manage private diagnostic artifacts and worker jobs with bounded retention."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import zipfile
from datetime import timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import or_, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.models import Job, JobStatus, utcnow
from atlaso.diagnostics import (
    TOTAL_LIMIT,
    Collector,
    EvidenceError,
    Options,
    ordinary_path,
    read_source,
    write_new,
)

JOB_TYPE = "diagnostic-bundle"
RETENTION = timedelta(hours=24)


def spool() -> Path:
    """Prepare the configured private root; never follow an existing link."""
    root = get_settings().diagnostics_spool_path.absolute()
    ordinary_path(root.parent)
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    ordinary_path(root)
    info = root.stat()
    effective_uid = getattr(os, "geteuid", lambda: -1)
    if not root.is_dir() or (os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != effective_uid())):
        raise EvidenceError("permission_denied")
    return root


def artifact_path(bundle_id: str) -> Path:
    """Bind the sole artifact filename to an exact server-generated UUID.

    Args:
        bundle_id: Server-generated diagnostic bundle UUID.
    """
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", bundle_id):
        raise ValueError("Invalid bundle identifier.")
    return spool() / (bundle_id + ".zip")


def expires_at(job: Job) -> Any:
    """Use aware timestamps even when SQLite returns a naive creation time.

    Args:
        job: Diagnostic job whose current lifecycle is being inspected.
    """
    return job.created_at.replace(tzinfo=timezone.utc) + RETENTION


def find_job(db: Session, bundle_id: str) -> Job:
    """Prevent artifact access through arbitrary paths or another task domain.

    Args:
        db: Request or worker database session.
        bundle_id: Server-generated diagnostic bundle UUID.
    """
    if not re.fullmatch(r"[0-9a-f-]{36}", bundle_id):
        raise LookupError("Bundle not found.")
    job = db.get(Job, bundle_id)
    if job is None or job.type != JOB_TYPE:
        raise LookupError("Bundle not found.")
    return job


def result(job: Job) -> dict[str, Any]:
    """Read only service-owned bundle lifecycle metadata.

    Args:
        job: Diagnostic job whose current lifecycle is being inspected.
    """
    try:
        value = json.loads(job.result or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def row(job: Job) -> dict[str, Any]:
    """Return safe grid metadata; collection identity mappings never reach this store.

    Args:
        job: Diagnostic job whose current lifecycle is being inspected.
    """
    config = json.loads(job.task_config_json or "{}")
    state = result(job)
    status = state.get("bundle_status", job.status)
    if status not in {"deleted", "expired"} and job.status != "succeeded":
        status = job.status
    if expires_at(job) <= utcnow() and status != "deleted":
        status = "expired"
    return {"id": job.id, "task_id": job.id, "created_at": job.created_at.isoformat(),
            "expires_at": expires_at(job).isoformat(), "status": status,
            "scope": config.get("scopes", []), "anonymize": config.get("anonymize", False),
            "size_bytes": state.get("size_bytes"), "summary": state.get("summary", ""),
            "omissions": state.get("omissions", []), "progress_percent": job.progress_percent,
            "selection": config}


def create(db: Session, options: Options, actor: str) -> Job:
    """Admit one bounded worker request without starting any source collection.

    Args:
        db: Request or worker database session.
        options: Validated capture selections shared by the UI and CLI.
        actor: Authenticated username recorded in the safe audit event.
    """
    from dataclasses import asdict

    root = spool()
    if shutil.disk_usage(root).free < TOTAL_LIMIT * 2:
        raise ValueError("Insufficient free space to collect a bundle.")
    # Serialize admission before the read on SQLite; a no-op write obtains its
    # reserved writer lock even when no diagnostic job has existed yet.
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        db.execute(text("UPDATE jobs SET progress_percent=progress_percent WHERE 1=0"))
    else:
        raise ValueError("Diagnostic bundle task admission currently requires the appliance SQLite database.")
    active = db.scalar(select(Job.id).where(Job.type == JOB_TYPE, Job.status.in_(["pending", "running"])).limit(1))
    if active:
        raise ValueError("A diagnostic bundle is already queued or collecting. Wait or cancel it first.")
    count = len(db.scalars(select(Job.id).where(Job.type == JOB_TYPE, Job.created_at > utcnow() - RETENTION).limit(32)).all())
    if count >= 32:
        raise ValueError("The daily diagnostic collection limit has been reached.")
    job = Job(id=str(uuid4()), type=JOB_TYPE, status=JobStatus.PENDING.value,
              created_by=actor, task_config_json=json.dumps(asdict(options)),
              result=json.dumps({"bundle_status": "pending"}))
    db.add(job)
    db.commit()
    record_audit(db, actor=actor, action="diagnostics.create", resource_type="diagnostic_bundle", resource_id=job.id)
    return job


def remove(db: Session, job: Job, *, actor: str, expired: bool = False) -> None:
    """Remove only an owned terminal artifact; never race an active writer.

    Args:
        db: Request or worker database session.
        job: Diagnostic job whose current lifecycle is being inspected.
        actor: Authenticated username recorded in the safe audit event.
        expired: Whether removal is automatic retention cleanup.
    """
    if job.status in {"pending", "running"}:
        raise ValueError("Cancel collection and wait for it to stop before deleting the bundle.")
    target = artifact_path(job.id)
    if target.exists() or target.is_symlink():
        ordinary_path(target)
        if target.stat().st_nlink != 1:
            raise EvidenceError("permission_denied")
        target.unlink()
    status = "expired" if expired else "deleted"
    job.result = json.dumps({"bundle_status": status})
    db.commit()
    record_audit(db, actor=actor, action="diagnostics." + ("expire" if expired else "delete"),
                 resource_type="diagnostic_bundle", resource_id=job.id)


def expire(db: Session) -> None:
    """Reconcile expired owned terminal bundles in one bounded worker pass.

    Args:
        db: Request or worker database session.
    """
    jobs = db.scalars(select(Job).where(Job.type == JOB_TYPE, Job.created_at <= utcnow() - RETENTION,
                                      or_(Job.result.is_(None), Job.result.notin_([json.dumps({"bundle_status": "expired"}), json.dumps({"bundle_status": "deleted"})])),
                                      Job.status.notin_(["pending", "running"])).order_by(Job.created_at.desc()).limit(128)).all()
    for job in jobs:
        if result(job).get("bundle_status") not in {"expired", "deleted"}:
            remove(db, job, actor="system", expired=True)


def download(db: Session, job: Job, actor: str) -> bytes:
    """Reauthorize lifecycle and expiry before reading a private non-static archive.

    Args:
        db: Request or worker database session.
        job: Diagnostic job whose current lifecycle is being inspected.
        actor: Authenticated username recorded in the safe audit event.
    """
    if expires_at(job) <= utcnow():
        if job.status not in {"pending", "running"}:
            remove(db, job, actor="system", expired=True)
        raise LookupError("Bundle has expired.")
    if result(job).get("bundle_status") not in {"ready", "ready_with_omissions"}:
        raise LookupError("Bundle is not available for download.")
    data = read_source(artifact_path(job.id), TOTAL_LIMIT + 1024 * 1024)
    record_audit(db, actor=actor, action="diagnostics.download", resource_type="diagnostic_bundle", resource_id=job.id)
    return data


def detail(job: Job) -> dict[str, Any]:
    """Inspect the sanitized manifest without exposing archive paths or raw source data.

    Args:
        job: Diagnostic job whose current lifecycle is being inspected.
    """
    item = row(job)
    if item["status"] in {"ready", "ready_with_omissions"}:
        data = read_source(artifact_path(job.id), TOTAL_LIMIT + 1024 * 1024)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.getinfo("manifest.json")
            if info.file_size > 262_144:
                raise EvidenceError("failed")
            item["manifest"] = json.loads(archive.read(info))
    return item


def run(job_id: str) -> None:
    """Execute the shared collector and publish only after cancellation is rechecked.

    Args:
        job_id: Diagnostic worker job UUID.
    """
    with SessionLocal() as db:
        job = find_job(db, job_id)
        options = Options.parse(json.loads(job.task_config_json))

    def cancelled() -> bool:
        with SessionLocal() as db:
            job = find_job(db, job_id)
            return job.status != "running" or bool(result(job).get("cancel_requested")) or expires_at(job) <= utcnow()

    def progress(percent: int, source: str) -> None:
        """Progress.

        Args:
            percent: Completed collection percentage.
            source: Fixed allowlisted collector identifier.
        """
        with SessionLocal() as db:
            job = find_job(db, job_id)
            job.progress_percent = percent
            db.commit()

    try:
        root = spool()
        if shutil.disk_usage(root).free < TOTAL_LIMIT * 2:
            raise EvidenceError("insufficient_space")
        url = make_url(get_settings().database_url)
        database = Path(url.database).absolute() if url.drivername == "sqlite" and url.database else Path("/nonexistent/unsupported-database")
        archive, manifest = Collector(options, database=database, cancelled=cancelled, progress=progress).capture(job_id)
        if cancelled():
            raise EvidenceError("cancelled")
        write_new(artifact_path(job_id), archive)
        with SessionLocal() as db:
            db.execute(text("UPDATE jobs SET progress_percent=progress_percent WHERE 1=0"))
            job = find_job(db, job_id)
            if result(job).get("cancel_requested") or job.status != "running" or expires_at(job) <= utcnow():
                artifact_path(job_id).unlink(missing_ok=True)
                job.status = "cancelled"
                job.result = json.dumps({"bundle_status": "cancelled"})
            else:
                job.status = "succeeded"
                job.progress_percent = 100
                job.result = json.dumps({"bundle_status": manifest["status"], "size_bytes": len(archive),
                    "summary": "Collection completed. Review the contents and omissions before manual sharing.",
                    "omissions": manifest["omissions"]})
            job.finished_at = utcnow()
            db.commit()
    except (EvidenceError, OSError, ValueError):
        # Never propagate raw source exceptions into the worker's generic logger.
        with SessionLocal() as db:
            job = find_job(db, job_id)
            job.status = "cancelled" if result(job).get("cancel_requested") or job.status == "cancelled" else "failed"
            job.finished_at = utcnow()
            job.error = "Collection stopped. Check available space, source availability and permissions, then retry."
            job.result = json.dumps({"bundle_status": job.status})
            db.commit()
