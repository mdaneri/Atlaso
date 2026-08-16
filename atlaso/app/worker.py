"""Claim and execute durable background jobs outside the web process."""

from __future__ import annotations

import json
import logging
import os
import signal
import time
from pathlib import Path
from secrets import compare_digest
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso import __version__
from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.database import (
    SessionLocal,
    ensure_vcf_depot_running_operation_index,
    init_db,
)
from atlaso.app.models import (
    AuditEvent,
    AutomationScriptRevision,
    Job,
    JobStatus,
    JobStep,
    Vault,
    utcnow,
)
from atlaso.app.services.appliance_update import (
    APPLIANCE_UPDATE_EXECUTION_ORDER,
    APPLIANCE_UPDATE_FINALIZER_PATH,
    APPLIANCE_UPDATE_RESTART_GATE_PATH,
    ATLASO_CURRENT_RELEASE_PATH,
    UPDATE_STREAM_LABELS,
    ensure_appliance_update_job_steps,
    reconcile_release_success_finalizer,
)
from atlaso.app.services.automation import (
    enqueue_due_schedules,
    json_object,
    normalize_script_content,
)
from atlaso.app.services.network_boot import (
    cleanup_network_boot_upload,
    recover_interrupted_network_boot_media_swaps,
)
from atlaso.app.services.vaults import (
    decrypted_vault_values,
    redact_secret_values,
    vault_scope_identity,
)

LOGGER = logging.getLogger("atlaso.worker")
POLL_SECONDS = 5
AUTOMATION_STAGE_DIR = Path("/var/lib/atlaso/automation/scripts")
AUTOMATION_VAULT_STAGE_DIR = Path("/run/atlaso-automation-vaults")
WORKER_STARTUP_STATUS_PATH = Path("/var/lib/atlaso/worker-startup.json")
WORKER_JOB_TYPES = {
    "appliance-update",
    "vcf-depot-download",
    "managed-script",
    "pxe-media-sync",
}
_stop_requested = False


def _request_stop(_signum: int, _frame: object) -> None:
    """Handle request stop.

    Args:
        _signum: Signum consumed by request stop.
        _frame: Frame consumed by request stop.
    """
    global _stop_requested
    _stop_requested = True


def _job_config(job: Job) -> dict[str, Any]:
    """Return job config.

    Args:
        job: Background job record affected by the operation.
    """
    return json_object(job.task_config_json, label="Job configuration")


def claim_next_job(db: Session) -> Job | None:
    """Return claim next job.

    Args:
        db: Active database session.
    """
    ensure_vcf_depot_running_operation_index(db.get_bind())
    while True:
        running_vcf_operation = db.execute(
            select(Job.id)
            .where(
                Job.vcf_depot_operation.is_(True),
                Job.status == JobStatus.RUNNING.value,
            )
            .limit(1)
        ).scalar_one_or_none()
        pending_filter = [
            Job.status == JobStatus.PENDING.value,
            Job.type.in_(WORKER_JOB_TYPES),
        ]
        if running_vcf_operation is not None:
            pending_filter.append(Job.vcf_depot_operation.is_(False))
        candidate = db.execute(
            select(Job.id)
            .where(*pending_filter)
            .order_by(Job.created_at, Job.id)
            .limit(1)
        ).scalar_one_or_none()
        if candidate is None:
            return None
        started_at = utcnow()
        try:
            claimed = db.execute(
                update(Job)
                .where(Job.id == candidate, Job.status == JobStatus.PENDING.value)
                .values(
                    status=JobStatus.RUNNING.value,
                    started_at=started_at,
                    progress_percent=1,
                )
            )
        except IntegrityError:
            # The partial VCFDT runtime index keeps a second worker from
            # starting another queued profile while one VCFDT operation runs.
            db.rollback()
            continue
        if claimed.rowcount != 1:
            db.rollback()
            continue
        claimed_job = db.get(Job, candidate)
        db.commit()
        return claimed_job


def _release_finalizer() -> dict[str, Any]:
    """Return release finalizer."""
    try:
        payload = json.loads(Path(APPLIANCE_UPDATE_FINALIZER_PATH).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _worker_process_identity() -> tuple[str, str]:
    """Return the current boot ID and this worker's process-start ticks."""
    if os.name != "posix":
        return ("non-posix-test", "non-posix-test")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    process_stat = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
    start_ticks = process_stat.rsplit(")", 1)[1].split()[19]
    if not boot_id or not start_ticks:
        raise ValueError("worker process identity is incomplete")
    return (boot_id, start_ticks)


def _write_worker_startup_status() -> None:
    """Publish the running worker identity for release-activation proof."""
    finalizer = _release_finalizer()
    release_job_id = (
        str(finalizer.get("job_id") or "")
        if str(finalizer.get("status") or "") in {"restart_pending", "activation_committed"}
        else ""
    )
    try:
        current_release = str(ATLASO_CURRENT_RELEASE_PATH.resolve(strict=True))
        boot_id, start_ticks = _worker_process_identity()
        WORKER_STARTUP_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = WORKER_STARTUP_STATUS_PATH.with_name(f"startup.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "boot_id": boot_id,
                    "pid": os.getpid(),
                    "start_ticks": start_ticks,
                    "version": __version__.split("+", 1)[0],
                    "current_release": current_release,
                    "release_job_id": release_job_id,
                    "started_at": utcnow().isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o644)
        os.replace(temporary, WORKER_STARTUP_STATUS_PATH)
    except (OSError, ValueError, IndexError):
        LOGGER.exception("Could not publish the Atlaso worker startup identity")


def _wait_for_release_restart_finalizer(timeout_seconds: int = 90) -> bool:
    """Hold startup recovery until the root release transaction opens its gate.

    Args:
        timeout_seconds: Maximum time to wait for definitive transaction evidence.
    """
    deadline = time.monotonic() + timeout_seconds
    while True:
        observed_at = time.monotonic()
        finalizer = _release_finalizer()
        finalizer_status = str(finalizer.get("status") or "")
        recovery = finalizer.get("transaction_recovery")
        finalizer_pending = bool(
            finalizer_status
            in {
                "transaction_pending",
                "restart_pending",
                "rollback_pending",
                "activation_committed",
            }
            or (
                finalizer_status == JobStatus.FAILED.value
                and finalizer.get("rolled_back") is not True
                and isinstance(recovery, dict)
            )
        )
        gate_exists = APPLIANCE_UPDATE_RESTART_GATE_PATH.exists()
        if not gate_exists and not finalizer_pending:
            return True
        definitive = finalizer_status == JobStatus.SUCCEEDED.value or (
            finalizer_status == JobStatus.FAILED.value and finalizer.get("rolled_back") is True
        )
        if gate_exists and definitive:
            try:
                gate_job_id = APPLIANCE_UPDATE_RESTART_GATE_PATH.read_text(encoding="utf-8").strip()
            except OSError:
                gate_job_id = ""
            if gate_job_id and gate_job_id == str(finalizer.get("job_id") or ""):
                LOGGER.warning(
                    "Atlaso worker startup ignored a stale release gate backed by definitive transaction evidence"
                )
                return True
        owner = recovery.get("owner") if isinstance(recovery, dict) else None
        owner_alive = _release_transaction_owner_alive(owner)
        if not gate_exists and finalizer_pending and not owner_alive:
            LOGGER.error(
                "Atlaso worker startup found stale release transaction evidence that pre-start recovery did not resolve"
            )
            return False
        if gate_exists and finalizer_pending and owner_alive:
            deadline = observed_at + timeout_seconds
        elif observed_at >= deadline:
            return False
        time.sleep(1)


def _release_transaction_owner_alive(owner: object) -> bool:
    """Return whether provisional release evidence still names a live helper.

    Args:
        owner: Persisted boot, PID, and process-start identity.
    """
    if not isinstance(owner, dict):
        return False
    try:
        pid = int(owner.get("pid") or 0)
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        process_stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        start_ticks = process_stat.rsplit(")", 1)[1].split()[19]
    except (OSError, ValueError, IndexError):
        return False
    return bool(
        pid > 0
        and boot_id
        and boot_id == str(owner.get("boot_id") or "")
        and start_ticks == str(owner.get("start_ticks") or "")
    )


def _rollback_requires_worker_restart() -> bool:
    """Return whether startup recovered a rollback from a different release."""
    finalizer = _release_finalizer()
    previous_version = str(finalizer.get("previous_version") or "")
    return bool(
        str(finalizer.get("status") or "") == JobStatus.FAILED.value
        and finalizer.get("rolled_back") is True
        and previous_version
        and previous_version != __version__.split("+", 1)[0]
    )


def _complete_recovered_rollback_job() -> bool:
    """Complete the exact recovered release handoff before restoring the old worker.

    Returns:
        Whether the recovered Appliance Update parent is safe for the restored worker.
    """
    finalizer = _release_finalizer()
    job_id = str(finalizer.get("job_id") or "")
    if not job_id or not _rollback_requires_worker_restart():
        return False
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None or job.type != "appliance-update":
            return False
        status = job.status
    return status in {
        JobStatus.PENDING.value,
        JobStatus.SUCCEEDED.value,
        JobStatus.FAILED.value,
    }


def recover_release_rollback_handoff() -> int:
    """Run candidate-version recovery bookkeeping as a bounded one-shot process.

    Returns:
        Process status for the privileged pre-start recovery handoff.
    """
    init_db()
    with SessionLocal() as db:
        recovered = recover_interrupted_worker_jobs(db, release_finalizer_ready=True)
        if recovered:
            LOGGER.warning("Reconciled %s interrupted worker job(s)", recovered)
    try:
        completed = _complete_recovered_rollback_job()
    except Exception:  # noqa: BLE001 - pre-start recovery must fail closed on any bookkeeping error.
        LOGGER.exception("Candidate release recovery bookkeeping failed")
        return 1
    if not completed:
        LOGGER.error("Candidate release recovery did not terminalize its Appliance Update task")
        return 1
    return 0


def _recovered_appliance_update_step_result(
    job: Job,
    step: JobStep,
    *,
    status: str,
    definitive: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    """Build the normal per-stream result used by appliance-update completion.

    Args:
        job: Parent Appliance Update job being recovered.
        step: Child update stream being terminalized.
        status: Definitive child status to persist.
        definitive: Durable release transaction evidence for the release child.
        error: Sanitized terminal error for a failed or skipped child.
    """
    try:
        result = json.loads(step.result or "{}")
    except json.JSONDecodeError:
        result = {}
    if not isinstance(result, dict):
        result = {}
    config = _job_config(job)
    stream = step.component_key
    transaction = definitive if isinstance(definitive, dict) else {}
    commands = transaction.get("commands") if stream == "atlaso_release" else result.get("commands")
    if not isinstance(commands, list):
        commands = []
    success = status == JobStatus.SUCCEEDED.value
    result.update(
        {
            "unit_id": stream,
            "label": UPDATE_STREAM_LABELS.get(stream, stream),
            "mode": str(config.get("mode") or "run"),
            "selected_streams": [stream],
            "selected_labels": [UPDATE_STREAM_LABELS.get(stream, stream)],
            "status": status,
            "success": success,
            "dry_run": False,
            "restart_after_commit": False,
            "commands": [command for command in commands if isinstance(command, dict)],
            "config_path": "",
            "config_preview": "",
            "worker_recovery": "root_finalizer" if transaction else "interrupted",
        }
    )
    if transaction:
        result["release_transaction"] = transaction
    if error:
        result["error"] = error
    elif success:
        result.pop("error", None)
    return result


def recover_interrupted_worker_jobs(
    db: Session,
    *,
    release_finalizer_ready: bool = True,
) -> int:
    """Return recover interrupted worker jobs.

    Args:
        db: Active database session.
        release_finalizer_ready: Whether the runtime restart gate opened before recovery.
    """
    media_swaps = recover_interrupted_network_boot_media_swaps(db)
    if media_swaps:
        LOGGER.warning(
            "Recovered %s interrupted Network Boot media swap(s).",
            media_swaps,
        )
    jobs = db.execute(
        select(Job).where(Job.type.in_(WORKER_JOB_TYPES), Job.status == JobStatus.RUNNING.value)
    ).scalars().all()
    now = utcnow()
    finalizer = _release_finalizer() if release_finalizer_ready else {}
    if str(finalizer.get("status") or "") == JobStatus.SUCCEEDED.value:
        finalizer, startup_consistent = reconcile_release_success_finalizer(finalizer)
        if not startup_consistent:
            finalizer_job = db.get(Job, str(finalizer.get("job_id") or ""))
            if (
                finalizer_job is not None
                and finalizer_job.type == "appliance-update"
                and finalizer_job.status == JobStatus.SUCCEEDED.value
                and all(job.id != finalizer_job.id for job in jobs)
            ):
                jobs.append(finalizer_job)
    for job in jobs:
        if job.type == "pxe-media-sync":
            cleanup_network_boot_upload(job.id)
        definitive = (
            finalizer
            if job.type == "appliance-update" and str(finalizer.get("job_id") or "") == job.id
            else {}
        )
        if definitive:
            definitive, _startup_consistent = reconcile_release_success_finalizer(definitive)
        finalizer_status = str(definitive.get("status") or "")
        recovered = finalizer_status in {JobStatus.SUCCEEDED.value, JobStatus.FAILED.value}
        update_steps = list(job.steps) if job.type == "appliance-update" else []
        if update_steps:
            release_step = next(
                (step for step in update_steps if step.component_key == "atlaso_release"),
                None,
            )
            if recovered and release_step is not None:
                release_error = (
                    None
                    if finalizer_status == JobStatus.SUCCEEDED.value
                    else str(definitive.get("error") or "The Atlaso release transaction failed.")
                )
                release_result = _recovered_appliance_update_step_result(
                    job,
                    release_step,
                    status=finalizer_status,
                    definitive=definitive,
                    error=release_error or "",
                )
                _persist_appliance_update_step_completion(
                    db,
                    job,
                    release_step,
                    result=release_result,
                    completed=1,
                    total=len(update_steps),
                )
            remaining_steps = [step for step in update_steps if step is not release_step]
            release_handoff_complete = bool(
                recovered
                and release_step is not None
                and (
                    (
                        finalizer_status == JobStatus.SUCCEEDED.value
                        and release_step.status == JobStatus.SUCCEEDED.value
                    )
                    or (
                        finalizer_status == JobStatus.FAILED.value
                        and release_step.status == JobStatus.FAILED.value
                        and definitive.get("rolled_back") is True
                        and definitive.get("rollback_health") is True
                    )
                )
            )
            resume_pending_children = bool(
                release_handoff_complete
                and remaining_steps
                and any(step.status == JobStatus.PENDING.value for step in remaining_steps)
                and all(step.status != JobStatus.RUNNING.value for step in remaining_steps)
            )
            if resume_pending_children:
                job.status = JobStatus.PENDING.value
                job.finished_at = None
                completed_steps = sum(
                    step.status
                    in {
                        JobStatus.SUCCEEDED.value,
                        JobStatus.FAILED.value,
                        JobStatus.SKIPPED.value,
                    }
                    for step in update_steps
                )
                job.progress_percent = int((completed_steps / len(update_steps)) * 90)
                job.error = None
                try:
                    result = json.loads(job.result or "{}")
                except json.JSONDecodeError:
                    result = {}
                result.update(
                    {
                        "status": JobStatus.PENDING.value,
                        "success": False,
                        "release_transaction": definitive,
                        "worker_recovery": "release_handoff",
                    }
                )
                result.pop("error", None)
                job.result = json.dumps(result, indent=2, sort_keys=True)
                db.add(job)
                continue
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
                step_result = _recovered_appliance_update_step_result(
                    job,
                    step,
                    status=step.status,
                    error=step.error or "",
                )
                _persist_appliance_update_step_completion(
                    db,
                    job,
                    step,
                    result=step_result,
                    completed=int(step.position or 0) + 1,
                    total=len(update_steps),
                )
            all_steps_succeeded = bool(update_steps) and all(
                step.status == JobStatus.SUCCEEDED.value for step in update_steps
            )
            job.status = (
                JobStatus.SUCCEEDED.value
                if recovered and all_steps_succeeded
                else JobStatus.FAILED.value
            )
            if recovered:
                from atlaso.app.ui import (
                    aggregate_appliance_update_results,
                    complete_appliance_update_task,
                )

                config = _job_config(job)
                selected = [str(value) for value in config.get("selected_streams", [])]
                stream_results = []
                for step in update_steps:
                    try:
                        step_result = json.loads(step.result or "{}")
                    except json.JSONDecodeError:
                        step_result = {}
                    if isinstance(step_result, dict):
                        stream_results.append(step_result)
                update_result = aggregate_appliance_update_results(
                    selected_stream_ids=selected,
                    settings=config.get("settings") if isinstance(config.get("settings"), dict) else {},
                    actor=job.created_by,
                    mode=str(config.get("mode") or "run"),
                    stream_results=stream_results,
                    job_id=job.id,
                )
                if finalizer_status == JobStatus.FAILED.value:
                    update_result["error"] = str(
                        definitive.get("error") or "The Atlaso release transaction failed."
                    )
                complete_appliance_update_task(db, job=job, update_result=update_result)
                continue
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
    """Handle fail job.

    Args:
        db: Active database session.
        job: Job being processed.
        exc: Exception that caused the operation to fail.
    """
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
    """Return appliance update result error.

    Args:
        result: Operation result being inspected or returned.
    """
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
    """Update appliance update step running.

    Args:
        job_id: Stable identifier of the associated job resource.
        stream: Stream consumed by set appliance update step running.
        completed: Completed consumed by set appliance update step running.
        total: Total consumed by set appliance update step running.
    """
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
    """Handle complete appliance update step.

    Args:
        job_id: Identifier of the job.
        stream: Stream supplied by the caller.
        result: Operation result to summarize, validate, or persist.
        completed: Completed supplied by the caller.
        total: Total supplied by the caller.
    """
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        step = db.get(JobStep, f"{job_id}:{stream}")
        if job is None or step is None:
            return
        _persist_appliance_update_step_completion(
            db,
            job,
            step,
            result=result,
            completed=completed,
            total=total,
        )
        db.commit()


def _persist_appliance_update_step_completion(
    db: Session,
    job: Job,
    step: JobStep,
    *,
    result: dict[str, Any],
    completed: int,
    total: int,
) -> None:
    """Persist one child result through the shared completion bookkeeping.

    Args:
        db: Active database session.
        job: Parent Appliance Update job being updated.
        step: Child update stream reaching a terminal state.
        result: Complete stream result to persist.
        completed: Number of streams completed through this child.
        total: Total streams in the parent update.
    """
    now = utcnow()
    step.status = str(result.get("status") or JobStatus.FAILED.value)
    step.started_at = step.started_at or now
    step.finished_at = now
    step.progress_percent = 100
    step.result = json.dumps(result, indent=2, sort_keys=True)
    step.error = None if result.get("success") else _appliance_update_result_error(result)
    job.progress_percent = max(int(job.progress_percent or 0), int((completed / max(total, 1)) * 90))
    db.add_all([job, step])


def _run_appliance_update(job_id: str) -> None:
    """Run appliance update.

    Args:
        job_id: Stable identifier of the associated job resource.
    """
    from atlaso.app.services.update_sources import update_source_credentials
    from atlaso.app.ui import (
        aggregate_appliance_update_results,
        appliance_update_exception_result,
        appliance_update_settings,
        complete_appliance_update_task,
        execute_appliance_update_job,
    )

    terminal_stream_results: dict[str, dict[str, Any]] = {}
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
            steps = ensure_appliance_update_job_steps(db, job=job, selected_streams=selected)
            for step in steps:
                if step.status not in {
                    JobStatus.SUCCEEDED.value,
                    JobStatus.FAILED.value,
                    JobStatus.SKIPPED.value,
                }:
                    continue
                try:
                    parsed_result = json.loads(step.result or "{}")
                except json.JSONDecodeError:
                    parsed_result = {}
                if isinstance(parsed_result, dict) and str(parsed_result.get("status") or "") == step.status:
                    terminal_stream_results[step.component_key] = parsed_result
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
            if stream in terminal_stream_results:
                stream_result = terminal_stream_results[stream]
            elif mode == "run" and stream == "photon_os" and earlier_failed:
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
            if stream not in terminal_stream_results:
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
    """Return automation stage path.

    Args:
        job_id: Stable identifier of the associated job resource.
        interpreter: Interpreter consumed by automation stage path.
    """
    suffix = {"bash": ".sh", "python": ".py", "powershell": ".ps1"}[interpreter]
    if get_settings().environment != "appliance":
        return Path("data") / "automation" / "scripts" / f"{job_id}{suffix}"
    return AUTOMATION_STAGE_DIR / f"{job_id}{suffix}"


def _automation_vault_stage_path(job_id: str) -> Path:
    """Return automation vault stage path.

    Args:
        job_id: Stable identifier of the associated job resource.
    """
    if get_settings().environment != "appliance":
        return Path("data") / "automation" / "vaults" / f"{job_id}.json"
    return AUTOMATION_VAULT_STAGE_DIR / f"{job_id}.json"


def _run_managed_script(db: Session, job: Job) -> None:
    """Run managed script.

    Args:
        db: Active database session.
        job: Job being processed.

    Raises:
        ValueError: If an input value is invalid.
    """
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
    stage_path.write_text(normalize_script_content(revision.content, revision.interpreter), encoding="utf-8", newline="\n")
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
    """Run pxe media sync.

    Args:
        db: Active database session.
        job: Job being processed.

    Raises:
        NetworkBootMediaSyncCancelled: If the operation encounters an invalid state.
        RuntimeError: If the operation cannot be completed safely.
    """
    from atlaso.app.services.network_boot import (
        DeferredNetworkBootMediaSync,
        NetworkBootMediaSyncCancelled,
        media_to_dict,
        network_boot_upload_path,
        remove_inactive_network_boot_media,
        sync_network_boot_media,
    )

    config = _job_config(job)
    environment = str(config.get("environment") or "")
    source = str(config.get("source") or "download")
    upload_path = network_boot_upload_path(job.id) if source == "upload" else None

    if source == "delete":
        version = str(config.get("version") or "")
        try:
            removed = remove_inactive_network_boot_media(
                db,
                environment_key=environment,
                version=version,
                ignore_job_id=job.id,
            )
            payload = {
                "status": JobStatus.SUCCEEDED.value,
                "success": True,
                "environment": environment,
                "source": source,
                **removed,
            }
            completed = db.execute(
                update(Job)
                .where(
                    Job.id == job.id,
                    Job.status == JobStatus.RUNNING.value,
                )
                .values(
                    status=JobStatus.SUCCEEDED.value,
                    finished_at=utcnow(),
                    progress_percent=100,
                    error=None,
                    result=json.dumps(payload, indent=2, sort_keys=True),
                )
            )
            if completed.rowcount != 1:
                raise NetworkBootMediaSyncCancelled(
                    "Network Boot media deletion was cancelled before completion."
                )
            db.add(
                AuditEvent(
                    actor=job.created_by,
                    action="remove_network_boot_media",
                    resource_type="network_boot_media",
                    resource_id=f"{environment}:{version}",
                    success=True,
                    detail=(
                        "inactive immutable cache version removed; "
                        f"desired_version_cleared={removed['desired_version_cleared']}; "
                        f"staged_uploads_cleaned={removed['staged_uploads_cleaned']}"
                    ),
                )
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return

    def cancelled() -> bool:
        """Return cancelled."""
        status = db.execute(
            select(Job.status).where(Job.id == job.id)
        ).scalar_one()
        return status == JobStatus.CANCELLED.value

    filesystem_sync: DeferredNetworkBootMediaSync | None = None
    try:
        try:
            filesystem_sync = sync_network_boot_media(
                db,
                environment_key=environment,
                uploaded_artifact=upload_path,
                uploaded_filename=str(config.get("filename") or ""),
                cancelled=cancelled,
                defer_filesystem_commit=True,
            )
            if not isinstance(filesystem_sync, DeferredNetworkBootMediaSync):
                raise RuntimeError("Network Boot media sync did not defer its filesystem commit.")
        finally:
            if upload_path is not None:
                upload_path.unlink(missing_ok=True)
                try:
                    upload_path.parent.rmdir()
                except OSError:
                    pass
        media = filesystem_sync.media
        if cancelled():
            raise NetworkBootMediaSyncCancelled(
                "Network Boot media task was cancelled."
            )
        payload = {
            "status": JobStatus.SUCCEEDED.value,
            "success": True,
            "environment": environment,
            "source": source,
            "media": media_to_dict(media),
            "activation": "pending desired state; global appliance apply is required",
        }
        completed = db.execute(
            update(Job)
            .where(
                Job.id == job.id,
                Job.status == JobStatus.RUNNING.value,
            )
            .values(
                status=JobStatus.SUCCEEDED.value,
                finished_at=utcnow(),
                progress_percent=100,
                error=None,
                result=json.dumps(payload, indent=2, sort_keys=True),
            )
        )
        if completed.rowcount != 1:
            raise NetworkBootMediaSyncCancelled(
                "Network Boot media task was cancelled before completion."
            )
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
    except Exception:
        db.rollback()
        if filesystem_sync is not None:
            filesystem_sync.rollback_filesystem()
        raise
    filesystem_sync.commit_filesystem()


def run_worker_once() -> str | None:
    """Run worker once.

    Returns:
        The run worker once result.

    Raises:
        ValueError: If an input value is invalid.
    """
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

            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if job is None:
                    return job_id
                config = _job_config(job)
                if not config:
                    config = json_object(job.result or "{}", label="VCF job configuration")
                profile_id = int(config.get("profile_id") or 0)
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
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    global _stop_requested
    _stop_requested = False
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    init_db()
    _write_worker_startup_status()
    release_finalizer_ready = _wait_for_release_restart_finalizer()
    if not release_finalizer_ready:
        LOGGER.error("Atlaso worker startup stopped because the release restart gate did not open")
        return 1
    with SessionLocal() as db:
        recovered = recover_interrupted_worker_jobs(
            db,
            release_finalizer_ready=release_finalizer_ready,
        )
        if recovered:
            LOGGER.warning("Reconciled %s interrupted worker job(s)", recovered)
    if _rollback_requires_worker_restart():
        LOGGER.warning("Completing rollback bookkeeping before restoring the previous Atlaso worker")
        while not _stop_requested:
            try:
                if _complete_recovered_rollback_job():
                    break
            except Exception:  # noqa: BLE001 - retain candidate code until bookkeeping succeeds.
                LOGGER.exception("Candidate release recovery bookkeeping failed; retrying")
            time.sleep(POLL_SECONDS)
        LOGGER.warning("Restarting the worker through the restored Atlaso release after rollback recovery")
        return 1
    if not ensure_vcf_depot_running_operation_index():
        LOGGER.warning("Deferred the VCFDT runtime guard until identity-task startup recovery completes")
    LOGGER.info("Atlaso worker started")
    while not _stop_requested:
        handled = run_worker_once()
        if handled is None:
            time.sleep(POLL_SECONDS)
    LOGGER.info("Atlaso worker stopped")
    return 0


if __name__ == "__main__":
    if os.environ.get("ATLASO_RELEASE_RECOVERY_ONLY") == "1":
        raise SystemExit(recover_release_rollback_handoff())
    raise SystemExit(main())
