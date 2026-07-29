from __future__ import annotations

import json
import logging
import signal
import time
from pathlib import Path
from secrets import compare_digest
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal, init_db
from atlaso.app.models import AuditEvent, AutomationScriptRevision, Job, JobStatus, JobStep, Vault, utcnow
from atlaso.app.services.appliance_update import (
    APPLIANCE_UPDATE_EXECUTION_ORDER,
    APPLIANCE_UPDATE_FINALIZER_PATH,
    UPDATE_STREAM_LABELS,
    ensure_appliance_update_job_steps,
)
from atlaso.app.services.automation import enqueue_due_schedules, json_object
from atlaso.app.services.vaults import decrypted_vault_values, redact_secret_values, vault_scope_identity


LOGGER = logging.getLogger("atlaso.worker")
POLL_SECONDS = 5
AUTOMATION_STAGE_DIR = Path("/var/lib/atlaso/automation/scripts")
AUTOMATION_VAULT_STAGE_DIR = Path("/run/atlaso-automation-vaults")
WORKER_JOB_TYPES = {
    "appliance-update",
    "vcf-depot-download",
    "managed-script",
    "pxe-media-sync",
}
_stop_requested = False


def _request_stop(_signum: int, _frame: object) -> None:
    global _stop_requested
    _stop_requested = True


def _job_config(job: Job) -> dict[str, Any]:
    return json_object(job.task_config_json, label="Job configuration")


def claim_next_job(db: Session) -> Job | None:
    job = db.execute(
        select(Job)
        .where(Job.status == JobStatus.PENDING.value, Job.type.in_(WORKER_JOB_TYPES))
        .order_by(Job.created_at, Job.id)
    ).scalars().first()
    if job is None:
        return None
    job.status = JobStatus.RUNNING.value
    job.started_at = utcnow()
    job.progress_percent = max(1, int(job.progress_percent or 0))
    db.add(job)
    db.commit()
    return job


def _release_finalizer() -> dict[str, Any]:
    try:
        payload = json.loads(Path(APPLIANCE_UPDATE_FINALIZER_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def recover_interrupted_worker_jobs(db: Session) -> int:
    jobs = db.execute(
        select(Job).where(Job.type.in_(WORKER_JOB_TYPES), Job.status == JobStatus.RUNNING.value)
    ).scalars().all()
    now = utcnow()
    finalizer = _release_finalizer()
    for job in jobs:
        definitive = (
            finalizer
            if job.type == "appliance-update" and str(finalizer.get("job_id") or "") == job.id
            else {}
        )
        finalizer_status = str(definitive.get("status") or "")
        recovered = finalizer_status in {JobStatus.SUCCEEDED.value, JobStatus.FAILED.value}
        update_steps = list(job.steps) if job.type == "appliance-update" else []
        if update_steps:
            release_step = next(
                (step for step in update_steps if step.component_key == "atlaso_release"),
                None,
            )
            if recovered and release_step is not None:
                release_step.status = finalizer_status
                release_step.started_at = release_step.started_at or job.started_at or now
                release_step.finished_at = now
                release_step.progress_percent = 100
                release_step.error = (
                    None
                    if finalizer_status == JobStatus.SUCCEEDED.value
                    else str(definitive.get("error") or "The Atlaso release transaction failed.")
                )
                try:
                    release_result = json.loads(release_step.result or "{}")
                except json.JSONDecodeError:
                    release_result = {}
                release_result.update(
                    {
                        "status": finalizer_status,
                        "success": finalizer_status == JobStatus.SUCCEEDED.value,
                        "release_transaction": definitive,
                        "worker_recovery": "root_finalizer",
                    }
                )
                release_step.result = json.dumps(release_result, indent=2, sort_keys=True)
                db.add(release_step)
            for step in update_steps:
                if step is release_step and recovered:
                    continue
                if step.status == JobStatus.RUNNING.value:
                    step.status = JobStatus.FAILED.value
                    step.error = "The Atlaso worker restarted while this update stream was running."
                elif step.status == JobStatus.PENDING.value:
                    step.status = JobStatus.SKIPPED.value
                    step.error = "The update stream was not started because the Atlaso worker restarted."
                else:
                    continue
                step.finished_at = now
                step.progress_percent = 100
                try:
                    step_result = json.loads(step.result or "{}")
                except json.JSONDecodeError:
                    step_result = {}
                step_result.update(
                    {
                        "status": step.status,
                        "success": False,
                        "error": step.error,
                        "worker_recovery": "interrupted",
                    }
                )
                step.result = json.dumps(step_result, indent=2, sort_keys=True)
                db.add(step)
            all_steps_succeeded = bool(update_steps) and all(
                step.status == JobStatus.SUCCEEDED.value for step in update_steps
            )
            job.status = (
                JobStatus.SUCCEEDED.value
                if recovered and all_steps_succeeded
                else JobStatus.FAILED.value
            )
        else:
            job.status = finalizer_status if recovered else JobStatus.FAILED.value
        job.finished_at = now
        job.progress_percent = 100
        job.error = (
            None
            if job.status == JobStatus.SUCCEEDED.value
            else str(definitive.get("error") or "The Atlaso worker restarted while this task was running. The task was not rerun automatically.")
        )
        try:
            result = json.loads(job.result or "{}")
        except json.JSONDecodeError:
            result = {}
        result.update(
            {
                "status": job.status,
                "success": job.status == JobStatus.SUCCEEDED.value,
                "release_transaction": definitive,
                "worker_recovery": "root_finalizer" if recovered else "interrupted",
            }
        )
        if job.error:
            result["error"] = job.error
        job.result = json.dumps(result, indent=2, sort_keys=True)
        db.add(job)
    if jobs:
        db.commit()
    return len(jobs)


def _fail_job(db: Session, job: Job, exc: Exception) -> None:
    job.status = JobStatus.FAILED.value
    job.finished_at = utcnow()
    job.progress_percent = 100
    job.error = str(exc)
    try:
        result = json.loads(job.result or "{}")
    except json.JSONDecodeError:
        result = {}
    result.update({"status": JobStatus.FAILED.value, "success": False, "error": str(exc)})
    job.result = json.dumps(result, indent=2, sort_keys=True)
    db.add(job)
    db.commit()


def _appliance_update_result_error(result: dict[str, Any]) -> str:
    explicit = str(result.get("error") or "").strip()
    if explicit:
        return explicit
    for command in result.get("commands", []):
        if not isinstance(command, dict) or int(command.get("returncode") or 0) == 0:
            continue
        detail = str(command.get("stderr") or command.get("stdout") or "").strip()
        if detail:
            return detail[-2000:]
    return "This appliance update stream reported a failure."


def _set_appliance_update_step_running(job_id: str, stream: str, *, completed: int, total: int) -> None:
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        step = db.get(JobStep, f"{job_id}:{stream}")
        if job is None or step is None:
            return
        now = utcnow()
        step.status = JobStatus.RUNNING.value
        step.started_at = step.started_at or now
        step.progress_percent = max(1, int(step.progress_percent or 0))
        step.error = None
        job.progress_percent = max(int(job.progress_percent or 0), int((completed / max(total, 1)) * 90))
        db.add_all([job, step])
        db.commit()


def _complete_appliance_update_step(
    job_id: str,
    stream: str,
    *,
    result: dict[str, Any],
    completed: int,
    total: int,
) -> None:
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        step = db.get(JobStep, f"{job_id}:{stream}")
        if job is None or step is None:
            return
        now = utcnow()
        step.status = str(result.get("status") or JobStatus.FAILED.value)
        step.started_at = step.started_at or now
        step.finished_at = now
        step.progress_percent = 100
        step.result = json.dumps(result, indent=2, sort_keys=True)
        step.error = None if result.get("success") else _appliance_update_result_error(result)
        job.progress_percent = max(int(job.progress_percent or 0), int((completed / max(total, 1)) * 90))
        db.add_all([job, step])
        db.commit()


def _run_appliance_update(job_id: str) -> None:
    from atlaso.app.ui import (
        aggregate_appliance_update_results,
        appliance_update_exception_result,
        appliance_update_settings,
        complete_appliance_update_task,
        execute_appliance_update_job,
    )
    from atlaso.app.services.update_sources import update_source_credentials

    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None:
            return
        config = _job_config(job)
        selected = [str(value) for value in config.get("selected_streams", [])]
        settings = config.get("settings") if isinstance(config.get("settings"), dict) else appliance_update_settings(db)
        mode = str(config.get("mode") or "check")
        actor = job.created_by
        credentials = update_source_credentials(db)
        if mode != "source_sync":
            ensure_appliance_update_job_steps(db, job=job, selected_streams=selected)
            db.commit()
    if mode == "source_sync":
        try:
            update_result = execute_appliance_update_job(
                selected_stream_ids=selected,
                settings=settings,
                actor=actor,
                mode=mode,
                job_id=job_id,
                credentials=credentials,
            )
        except Exception as exc:  # noqa: BLE001 - workers must persist a terminal job state.
            LOGGER.exception("Appliance update source synchronization %s failed before helper completion", job_id)
            update_result = appliance_update_exception_result(
                selected_stream_ids=selected,
                settings=settings,
                actor=actor,
                mode=mode,
                exc=exc,
            )
    else:
        execution_streams = [stream for stream in APPLIANCE_UPDATE_EXECUTION_ORDER if stream in selected]
        stream_results: list[dict[str, Any]] = []
        earlier_failed = False
        for index, stream in enumerate(execution_streams, start=1):
            if mode == "run" and stream == "photon_os" and earlier_failed:
                skip_reason = "Photon OS was not started because an earlier selected update stream failed."
                stream_result = {
                    "unit_id": stream,
                    "label": UPDATE_STREAM_LABELS[stream],
                    "mode": mode,
                    "selected_streams": [stream],
                    "selected_labels": [UPDATE_STREAM_LABELS[stream]],
                    "status": JobStatus.SKIPPED.value,
                    "success": False,
                    "skipped": True,
                    "skip_reason": skip_reason,
                    "dry_run": False,
                    "restart_after_commit": False,
                    "commands": [],
                    "config_path": "",
                    "config_preview": "",
                    "error": skip_reason,
                }
            else:
                _set_appliance_update_step_running(
                    job_id,
                    stream,
                    completed=index - 1,
                    total=len(execution_streams),
                )
                try:
                    stream_result = execute_appliance_update_job(
                        selected_stream_ids=[stream],
                        settings=settings,
                        actor=actor,
                        mode=mode,
                        job_id=job_id,
                        credentials=credentials,
                    )
                except Exception as exc:  # noqa: BLE001 - each child step must reach a terminal state.
                    LOGGER.exception("Appliance update stream %s for job %s failed before helper completion", stream, job_id)
                    stream_result = appliance_update_exception_result(
                        selected_stream_ids=[stream],
                        settings=settings,
                        actor=actor,
                        mode=mode,
                        exc=exc,
                    )
            stream_results.append(stream_result)
            earlier_failed = earlier_failed or not bool(stream_result.get("success"))
            _complete_appliance_update_step(
                job_id,
                stream,
                result=stream_result,
                completed=index,
                total=len(execution_streams),
            )
        update_result = aggregate_appliance_update_results(
            selected_stream_ids=selected,
            settings=settings,
            actor=actor,
            mode=mode,
            stream_results=stream_results,
            job_id=job_id,
        )
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None:
            return
        complete_appliance_update_task(db, job=job, update_result=update_result)


def _automation_stage_path(job_id: str, interpreter: str) -> Path:
    suffix = {"bash": ".sh", "python": ".py", "powershell": ".ps1"}[interpreter]
    if get_settings().environment != "appliance":
        return Path("data") / "automation" / "scripts" / f"{job_id}{suffix}"
    return AUTOMATION_STAGE_DIR / f"{job_id}{suffix}"


def _automation_vault_stage_path(job_id: str) -> Path:
    if get_settings().environment != "appliance":
        return Path("data") / "automation" / "vaults" / f"{job_id}.json"
    return AUTOMATION_VAULT_STAGE_DIR / f"{job_id}.json"


def _run_managed_script(db: Session, job: Job) -> None:
    config = _job_config(job)
    revision_id = int(config.get("revision_id") or 0)
    revision = db.get(AutomationScriptRevision, revision_id)
    if revision is None or not revision.enabled:
        raise ValueError("The scheduled managed script revision is missing or disabled.")
    arguments = config.get("arguments", [])
    if not isinstance(arguments, list) or any(not isinstance(argument, str) for argument in arguments):
        raise ValueError("The scheduled managed script arguments are invalid.")
    stage_path = _automation_stage_path(job.id, revision.interpreter)
    stage_path.parent.mkdir(parents=True, exist_ok=True)
    stage_path.write_text(revision.content, encoding="utf-8")
    stage_path.chmod(0o640)
    vault_path: Path | None = None
    vault_values: dict[str, str] = {}
    try:
        vault_id = int(config.get("vault_id") or 0)
        if vault_id:
            vault = db.get(Vault, vault_id)
            if vault is None:
                raise ValueError("The managed script vault is missing.")
            expected_scope = str(config.get("vault_scope") or "")
            if not expected_scope or not compare_digest(expected_scope, vault_scope_identity(vault)):
                raise ValueError("The managed script vault no longer matches the vault selected when the job was queued.")
            vault_values = decrypted_vault_values(db, vault_id)
            vault_path = _automation_vault_stage_path(job.id)
            vault_path.parent.mkdir(parents=True, exist_ok=True)
            vault_path.write_text(
                json.dumps({"version": 1, "values": vault_values}, sort_keys=True),
                encoding="utf-8",
            )
            vault_path.chmod(0o600)
        result = SystemAdapter().run_automation_script(
            str(stage_path),
            revision.interpreter,
            revision.timeout_seconds,
            arguments,
            str(vault_path) if vault_path else "",
        )
    finally:
        stage_path.unlink(missing_ok=True)
        if vault_path:
            vault_path.unlink(missing_ok=True)
    stdout = redact_secret_values(result.stdout, vault_values)
    stderr = redact_secret_values(result.stderr, vault_values)
    payload = {
        "status": JobStatus.SUCCEEDED.value if result.returncode == 0 else JobStatus.FAILED.value,
        "success": result.returncode == 0,
        "revision_id": revision.id,
        "script_id": revision.script_id,
        "interpreter": revision.interpreter,
        "arguments_count": len(arguments),
        "content_sha256": revision.content_sha256,
        "dry_run": result.dry_run,
        "command": result.command,
        "returncode": result.returncode,
        "stdout": stdout[-8000:],
        "stderr": stderr[-8000:],
    }
    job.status = payload["status"]
    job.finished_at = utcnow()
    job.progress_percent = 100
    job.error = None if payload["success"] else (stderr[-2000:] or "Managed script failed.")
    job.result = json.dumps(payload, indent=2, sort_keys=True)
    db.add(job)
    db.add(
        AuditEvent(
            actor=job.created_by,
            action="execute_managed_script",
            resource_type="job",
            resource_id=job.id,
            success=bool(payload["success"]),
            detail=f"revision_id={revision.id}; sha256={revision.content_sha256}; returncode={result.returncode}",
        )
    )
    db.commit()


def _run_pxe_media_sync(db: Session, job: Job) -> None:
    from atlaso.app.services.network_boot import (
        media_to_dict,
        network_boot_upload_path,
        sync_network_boot_media,
    )

    config = _job_config(job)
    environment = str(config.get("environment") or "")
    source = str(config.get("source") or "download")
    upload_path = network_boot_upload_path(job.id) if source == "upload" else None
    try:
        media = sync_network_boot_media(
            db,
            environment_key=environment,
            uploaded_artifact=upload_path,
            uploaded_filename=str(config.get("filename") or ""),
        )
    finally:
        if upload_path is not None:
            upload_path.unlink(missing_ok=True)
            try:
                upload_path.parent.rmdir()
            except OSError:
                pass
    payload = {
        "status": JobStatus.SUCCEEDED.value,
        "success": True,
        "environment": environment,
        "source": source,
        "media": media_to_dict(media),
        "activation": "pending desired state; global appliance apply is required",
    }
    job.status = JobStatus.SUCCEEDED.value
    job.finished_at = utcnow()
    job.progress_percent = 100
    job.error = None
    job.result = json.dumps(payload, indent=2, sort_keys=True)
    db.add(job)
    db.add(
        AuditEvent(
            actor=job.created_by,
            action="sync_network_boot_media",
            resource_type="network_boot_media",
            resource_id=f"{environment}:{media.version}",
            success=True,
            detail=(
                f"sha256={media.artifact_sha256}; "
                f"verification={media.verification_method}"
            ),
        )
    )
    db.commit()


def run_worker_once() -> str | None:
    with SessionLocal() as db:
        enqueue_due_schedules(db)
        job = claim_next_job(db)
        if job is None:
            return None
        job_id = job.id
        job_type = job.type
    try:
        if job_type == "appliance-update":
            _run_appliance_update(job_id)
        elif job_type == "vcf-depot-download":
            from atlaso.app.ui import run_vcf_depot_download_job
            from atlaso.app.models import VcfDepotDownloadProfile

            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if job is None:
                    return job_id
                config = _job_config(job)
                if not config:
                    config = json_object(job.result or "{}", label="VCF job configuration")
                profile_id = int(config.get("profile_id") or 0)
                profile = db.get(VcfDepotDownloadProfile, profile_id)
                if profile is None or not profile.enabled:
                    raise ValueError("Enable the scheduled VCF Offline Depot profile before running it.")
            run_vcf_depot_download_job(job_id, profile_id)
        elif job_type == "managed-script":
            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if job is not None:
                    _run_managed_script(db, job)
        elif job_type == "pxe-media-sync":
            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if job is not None:
                    _run_pxe_media_sync(db, job)
        else:
            raise ValueError(f"No worker handler is registered for job type {job_type}.")
    except Exception as exc:  # noqa: BLE001 - the worker must survive individual job failures.
        LOGGER.exception("Job %s failed", job_id)
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if job is not None and job.status in {JobStatus.PENDING.value, JobStatus.RUNNING.value}:
                _fail_job(db, job, exc)
    return job_id


def main() -> int:
    global _stop_requested
    _stop_requested = False
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    init_db()
    with SessionLocal() as db:
        recovered = recover_interrupted_worker_jobs(db)
        if recovered:
            LOGGER.warning("Marked %s interrupted worker jobs failed", recovered)
    LOGGER.info("Atlaso worker started")
    while not _stop_requested:
        handled = run_worker_once()
        if handled is None:
            time.sleep(POLL_SECONDS)
    LOGGER.info("Atlaso worker stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
