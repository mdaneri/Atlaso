"""Expose bounded Network Boot media, inventory, and host-control APIs."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict, deque
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Path as ApiPath, Query, Request, Response, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError
from sqlalchemy import delete, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import finalize_audit, record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    EsxiPxeHost,
    Job,
    JobStatus,
    NetworkBootDiscoveredHost,
    NetworkBootEnvironment,
    NetworkBootInventoryCommand,
    NetworkBootInventoryReport,
    NetworkBootInventorySession,
    NetworkBootMedia,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.security import Identity, require_api_or_session_scope
from atlaso.app.schemas import EsxiPxeHostCreate
from atlaso.app.services.esxi_pxe import (
    esxi_pxe_boot_settings,
    host_variables_json,
    normalize_installer_iso_path,
    normalize_pxe_mac,
    sync_esxi_pxe_host_network_records,
)
from atlaso.app.services.network_boot import (
    acknowledge_inventory_command,
    active_network_boot_media,
    available_network_boot_versions,
    NETWORK_BOOT_MEDIA_ROOT,
    NETWORK_BOOT_UPLOAD_MAX_BYTES,
    catalog_rows,
    claim_host_boot_override,
    esxi_host_assignments_by_mac,
    host_to_dict,
    inventory_session_for_token,
    issue_inventory_session,
    network_boot_upload_path,
    normalize_mac,
    poll_inventory_command,
    queue_reboot_command,
    render_network_boot_menu,
    report_identity,
    report_history,
    request_host_boot_override,
    send_wake_on_lan,
    set_environment_desired_state,
    store_inventory_report,
    touch_inventory_heartbeat,
    WakeOnLanDeliveryError,
    wake_on_lan_broadcast_targets,
)


router = APIRouter(
    prefix="/api/v1/network-boot",
    tags=["network-boot"],
    route_class=DocumentedAPIRoute,
)
public_router = APIRouter(tags=["network-boot-public"])
logger = logging.getLogger("uvicorn.error")
_rate_lock = threading.Lock()
_rate_windows: dict[str, deque[float]] = defaultdict(deque)
_MAX_RATE_LIMIT_KEYS = 4096
_MEDIA_ENVIRONMENT_ROOTS = {
    key: (NETWORK_BOOT_MEDIA_ROOT / key).resolve()
    for key in ("inventory", "memtest86plus", "shredos", "gparted", "clonezilla")
}
_MAX_MEDIA_FILES = 256


def _media_job_config(job: Job) -> dict[str, Any]:
    """Return media job config.

    Args:
        job: Background job record affected by the operation.
    """
    try:
        payload = json.loads(job.task_config_json or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _active_media_job(
    db: Session,
    *,
    environment_key: str,
    source: str,
) -> Job | None:
    """Return active media job.

    Args:
        db: Active database session.
        environment_key: Stable key identifying the Network Boot environment.
        source: Source path, address, or record to process.
    """
    active_jobs = db.execute(
        select(Job).where(
            Job.type == "pxe-media-sync",
            Job.status.in_((JobStatus.PENDING.value, JobStatus.RUNNING.value)),
        )
    ).scalars().all()
    for job in active_jobs:
        config = _media_job_config(job)
        if (
            str(config.get("environment") or "") == environment_key
            and str(config.get("source") or "download") == source
        ):
            return job
    return None


def _installed_media_directory(media: Any) -> Path | None:
    """Return installed media directory.

    Args:
        media: Media consumed by installed media directory.
    """
    environment_root = _MEDIA_ENVIRONMENT_ROOTS.get(media.environment_key)
    if environment_root is None or not environment_root.is_dir():
        return None
    try:
        for candidate in environment_root.iterdir():
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            resolved = candidate.resolve()
            if (
                resolved.is_relative_to(environment_root)
                and resolved.parent == environment_root
                and str(resolved) == media.installed_path
            ):
                return resolved
    except OSError:
        return None
    return None


def _allowlisted_media_file(
    root: Path,
    requested_path: str,
    allowed_paths: set[str],
) -> Path | None:
    """Return allowlisted media file.

    Args:
        root: Repository or filesystem root searched by the operation.
        requested_path: Filesystem path used for requested.
        allowed_paths: Allowed paths consumed by allowlisted media file.
    """
    normalized = requested_path.replace("\\", "/")
    parts = normalized.split("/")
    if (
        normalized not in allowed_paths
        or not normalized
        or normalized.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        return None
    try:
        for index, candidate in enumerate(root.rglob("*"), start=1):
            if index > _MAX_MEDIA_FILES:
                return None
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if (
                resolved.is_relative_to(root)
                and candidate.relative_to(root).as_posix() == normalized
            ):
                return resolved
    except OSError:
        return None
    return None


def _bounded_rate_limit(request: Request, *, bucket: str, limit: int, window: int = 60) -> None:
    """Handle bounded rate limit.

    Args:
        request: Incoming HTTP request.
        bucket: Bucket supplied by the caller.
        limit: Limit supplied by the caller.
        window: Window supplied by the caller.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    remote = request.client.host if request.client else "unknown"
    try:
        if ip_address(remote).is_loopback:
            forwarded = request.headers.get("X-Real-IP", "").strip()
            if forwarded:
                remote = str(ip_address(forwarded))
    except ValueError:
        remote = "unknown"
    key = f"{bucket}:{remote}"
    now = time.monotonic()
    with _rate_lock:
        cutoff = now - window
        for existing_key in list(_rate_windows):
            existing = _rate_windows[existing_key]
            while existing and existing[0] <= cutoff:
                existing.popleft()
            if not existing:
                del _rate_windows[existing_key]
        if key not in _rate_windows and len(_rate_windows) >= _MAX_RATE_LIMIT_KEYS:
            oldest_key = min(_rate_windows, key=lambda item: _rate_windows[item][-1])
            del _rate_windows[oldest_key]
        values = _rate_windows[key]
        if len(values) >= limit:
            raise HTTPException(status_code=429, detail="Network Boot request rate limit exceeded.")
        values.append(now)


def _bearer_token(request: Request) -> str:
    """Return bearer token.

    Args:
        request: Incoming HTTP request.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Inventory bearer token required.")
    return token


def _inventory_session(
    request: Request,
    db: Session,
    *,
    require_report: bool = False,
) -> NetworkBootInventorySession:
    """Return inventory session.

    Args:
        request: Incoming HTTP request.
        db: Active database session.
        require_report: Require report supplied by the caller.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    try:
        return inventory_session_for_token(
            db,
            _bearer_token(request),
            require_report=require_report,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.get("/environments")
def list_network_boot_environments(
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """List Network Boot environments.

    Uses the authentication posture documented for this endpoint. This read-only operation does not
    change saved desired state or appliance runtime state.

    Args:
        _identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return catalog_rows(db)


@router.get("/environments/available-versions")
def list_available_network_boot_versions(
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
) -> list[dict[str, str]]:
    """List downloadable Network Boot environment versions.

    Uses the authentication posture documented for this endpoint. This read-only operation does not
    change saved desired state or appliance runtime state.

    Args:
        _identity: Authenticated identity authorizing the operation.
    """
    return available_network_boot_versions()


@router.patch("/environments/{environment_key}")
def update_network_boot_environment(
    environment_key: Annotated[str, ApiPath(description='Stable environment key identifying the resource addressed by this operation.')],
    payload: dict[str, Any],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Update the desired state of a Network Boot environment.

    Uses the authentication posture documented for this endpoint. The operation updates saved Atlaso
    state and does not bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        environment_key: Filesystem path associated with environment key.
        payload: Validated request or task payload consumed by the operation.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if not isinstance(payload.get("enabled"), bool):
        raise HTTPException(status_code=422, detail="enabled must be a boolean.")
    try:
        state = set_environment_desired_state(
            db,
            environment_key=environment_key,
            enabled=payload["enabled"],
            desired_version=str(payload.get("desired_version") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="update_network_boot_environment",
        resource_type="network_boot_environment",
        resource_id=state.key,
        detail=f"enabled={state.enabled}; desired_version={state.desired_version}",
        request_id=request.state.request_id,
    )
    db.commit()
    return next(row for row in catalog_rows(db) if row["key"] == state.key)


@router.post("/environments/{environment_key}/sync", status_code=status.HTTP_202_ACCEPTED)
def sync_network_boot_environment(
    environment_key: Annotated[str, ApiPath(description='Stable environment key identifying the resource addressed by this operation.')],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Queue synchronization of a Network Boot environment.

    Uses the authentication posture documented for this endpoint. The action runs through the
    endpoint's existing audited adapter or task boundary; inspect the returned state before treating
    the operation as complete.

    Args:
        environment_key: Filesystem path associated with environment key.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = {row["key"]: row for row in catalog_rows(db)}
    if environment_key not in rows:
        raise HTTPException(
            status_code=422,
            detail="Select a downloadable Network Boot environment.",
        )
    duplicate = _active_media_job(
        db,
        environment_key=environment_key,
        source="download",
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Network Boot download task {duplicate.id} is already active "
                f"for {environment_key}."
            ),
        )
    job = Job(
        id=f"job_{uuid4().hex}",
        type="pxe-media-sync",
        status=JobStatus.PENDING.value,
        created_by=identity.username,
        progress_percent=0,
        task_config_json=json.dumps(
            {
                "environment": environment_key,
                "request_id": request.state.request_id,
                "source": "download",
            },
            sort_keys=True,
        ),
        network_boot_environment_key=environment_key,
        network_boot_source="download",
    )
    db.add(job)
    try:
        record_audit(
            db,
            actor=identity.username,
            action="queue_pxe_media_sync",
            resource_type="job",
            resource_id=job.id,
            detail=f"environment={environment_key}",
            request_id=request.state.request_id,
        )
    except IntegrityError as exc:
        db.rollback()
        duplicate = _active_media_job(
            db,
            environment_key=environment_key,
            source="download",
        )
        if duplicate is None:
            raise
        raise HTTPException(
            status_code=409,
            detail=(
                f"Network Boot download task {duplicate.id} is already active "
                f"for {environment_key}."
            ),
        ) from exc
    return {"job_id": job.id, "status": job.status, "environment": environment_key}


@router.post(
    "/environments/{environment_key}/upload",
    status_code=status.HTTP_202_ACCEPTED,
)
async def upload_network_boot_environment(
    environment_key: Annotated[str, ApiPath(description='Stable environment key identifying the resource addressed by this operation.')],
    request: Request,
    artifact: Annotated[UploadFile, File(description='Uploaded release artifact validated before it can enter Network Boot storage.')],
    identity: Annotated[
        Identity,
        Depends(require_api_or_session_scope("write:pxe")),
    ],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Upload and validate Network Boot environment media.

    Uses the authentication posture documented for this endpoint. The operation changes saved Atlaso
    application state; any appliance host enforcement remains subject to the documented apply or
    task boundary for the resource.

    Args:
        environment_key: Filesystem path associated with environment key.
        request: Incoming HTTP request carrying the operation context.
        artifact: Artifact consumed by upload network boot environment.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = {row["key"]: row for row in catalog_rows(db)}
    if environment_key not in rows:
        raise HTTPException(
            status_code=422,
            detail="Select an uploadable Network Boot environment.",
        )
    active = db.execute(
        select(Job).where(
            Job.type == "pxe-media-sync",
            Job.status.in_((JobStatus.PENDING.value, JobStatus.RUNNING.value)),
        )
    ).scalars().first()
    if active is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Network Boot media task {active.id} is already active.",
        )
    filename = Path(artifact.filename or "").name
    if not filename or len(filename) > 240:
        raise HTTPException(status_code=422, detail="Choose a named boot media file.")
    job_id = f"job_{uuid4().hex}"
    upload_path = network_boot_upload_path(job_id)
    total = 0
    try:
        upload_path.parent.mkdir(parents=True, mode=0o700, exist_ok=False)
        with upload_path.open("xb") as output:
            while chunk := await artifact.read(1024 * 1024):
                total += len(chunk)
                if total > NETWORK_BOOT_UPLOAD_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Network Boot media uploads are limited to 2 GiB.",
                    )
                output.write(chunk)
        if total == 0:
            raise HTTPException(status_code=422, detail="Uploaded boot media is empty.")
        upload_path.chmod(0o600)
        job = Job(
            id=job_id,
            type="pxe-media-sync",
            status=JobStatus.PENDING.value,
            created_by=identity.username,
            progress_percent=0,
            task_config_json=json.dumps(
                {
                    "environment": environment_key,
                    "request_id": request.state.request_id,
                    "source": "upload",
                    "filename": filename,
                },
                sort_keys=True,
            ),
        )
        db.add(job)
        record_audit(
            db,
            actor=identity.username,
            action="queue_pxe_media_upload",
            resource_type="job",
            resource_id=job.id,
            detail=f"environment={environment_key}; filename={filename}; bytes={total}",
            request_id=request.state.request_id,
        )
        db.commit()
    except Exception:
        upload_path.unlink(missing_ok=True)
        try:
            upload_path.parent.rmdir()
        except OSError:
            pass
        raise
    finally:
        await artifact.close()
    return {
        "job_id": job_id,
        "status": JobStatus.PENDING.value,
        "environment": environment_key,
        "filename": filename,
        "bytes": total,
    }


@router.delete(
    "/environments/{environment_key}/media/{version}",
    status_code=status.HTTP_202_ACCEPTED,
)
def remove_network_boot_media(
    environment_key: Annotated[str, ApiPath(description='Stable environment key identifying the resource addressed by this operation.')],
    version: Annotated[str, ApiPath(description='Path value for version, identifying the resource addressed by `/api/v1/network-boot/environments/{environment_key}/media/{version}`.')],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Queue removal of an inactive Network Boot media version.

    Uses the authentication posture documented for this endpoint. Removal or revocation takes effect
    in Atlaso application state; appliance host changes remain subject to the documented apply
    boundary for the resource.

    Args:
        environment_key: Filesystem path associated with environment key.
        version: Atlaso or artifact version being validated or produced.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if environment_key == "inventory":
        raise HTTPException(status_code=422, detail="Bundled Inventory Linux cannot be removed.")
    state = db.get(NetworkBootEnvironment, environment_key)
    media = db.execute(
        select(NetworkBootMedia).where(
            NetworkBootMedia.environment_key == environment_key,
            NetworkBootMedia.version == version,
        )
    ).scalar_one_or_none()
    if state is None or media is None:
        raise HTTPException(status_code=404, detail="Installed Network Boot media not found.")
    if version == state.active_version:
        raise HTTPException(
            status_code=409,
            detail="Apply a different active version or disable and apply this environment before removal.",
        )
    if state.enabled and version == state.desired_version:
        raise HTTPException(
            status_code=409,
            detail="Disable this environment before removing its desired media.",
        )
    environment_jobs = db.execute(
        select(Job).where(Job.type == "pxe-media-sync")
    ).scalars().all()
    matching_jobs: list[tuple[Job, dict[str, Any]]] = []
    for job in environment_jobs:
        try:
            config = json.loads(job.task_config_json or "{}")
        except json.JSONDecodeError:
            config = {}
        if config.get("environment") == environment_key:
            matching_jobs.append((job, config))
    if any(
        job.status in (JobStatus.PENDING.value, JobStatus.RUNNING.value)
        for job, _config in matching_jobs
    ):
        raise HTTPException(
            status_code=409,
            detail="Wait for the active Network Boot media task before cleaning this environment.",
        )
    if _installed_media_directory(media) is None:
        raise HTTPException(status_code=409, detail="Installed media path failed safety validation.")
    job = Job(
        id=f"job_{uuid4().hex}",
        type="pxe-media-sync",
        status=JobStatus.PENDING.value,
        created_by=identity.username,
        progress_percent=0,
        task_config_json=json.dumps(
            {
                "environment": environment_key,
                "request_id": request.state.request_id,
                "source": "delete",
                "version": version,
            },
            sort_keys=True,
        ),
        network_boot_environment_key=environment_key,
        network_boot_source="delete",
    )
    db.add(job)
    record_audit(
        db,
        actor=identity.username,
        action="queue_remove_network_boot_media",
        resource_type="job",
        resource_id=job.id,
        detail=f"environment={environment_key}; version={version}",
        request_id=request.state.request_id,
    )
    db.commit()
    return {
        "job_id": job.id,
        "status": job.status,
        "environment": environment_key,
        "version": version,
    }


@router.get("/hosts")
def list_discovered_hosts(
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """List hosts discovered through Atlaso Inventory Linux.

    Uses the authentication posture documented for this endpoint. This read-only operation does not
    change saved desired state or appliance runtime state.

    Args:
        _identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = db.execute(
        select(NetworkBootDiscoveredHost).order_by(
            desc(NetworkBootDiscoveredHost.last_seen_at),
            NetworkBootDiscoveredHost.id,
        )
    ).scalars().all()
    assignments_by_mac = esxi_host_assignments_by_mac(db)
    return [host_to_dict(db, row, assignments_by_mac=assignments_by_mac) for row in rows]


@router.get("/hosts/{host_id}")
def get_discovered_host(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get one discovered host and its current assignment state.

    Uses the authentication posture documented for this endpoint. This read-only operation does not
    change saved desired state or appliance runtime state.

    Args:
        host_id: Stable identifier of the associated host resource.
        _identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(NetworkBootDiscoveredHost, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    return host_to_dict(db, host, include_report=True)


@router.get("/hosts/{host_id}/history")
def get_discovered_host_history(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Get retained inventory-report history for a discovered host.

    Uses the authentication posture documented for this endpoint. This read-only operation does not
    change saved desired state or appliance runtime state.

    Args:
        host_id: Stable identifier of the associated host resource.
        _identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if db.get(NetworkBootDiscoveredHost, host_id) is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    return report_history(db, host_id)


@router.get("/hosts/{host_id}/reports/{report_id}/download")
def download_discovered_host_report(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    report_id: Annotated[int, ApiPath(description='Unique identifier of the report record addressed by this operation.')],
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> Response:
    """Download one retained discovered-host inventory report.

    Uses the authentication posture documented for this endpoint. This read-only operation does not
    change saved desired state or appliance runtime state.

    Args:
        host_id: Stable identifier of the associated host resource.
        report_id: Stable identifier of the associated report resource.
        _identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(NetworkBootDiscoveredHost, host_id)
    report = db.get(NetworkBootInventoryReport, report_id)
    if host is None or report is None or report.host_id != host.id:
        raise HTTPException(status_code=404, detail="Inventory report not found.")
    report_payload = json.loads(report.payload_json)
    identity_key, dmi_uuid, macs = report_identity(report_payload)
    system = report_payload["system"]
    cpu = report_payload["cpu"]
    memory = report_payload["memory"]
    exported = {
        "host": {
            "id": host.id,
            "identity_key": identity_key,
            "dmi_uuid": dmi_uuid,
            "boot_mac": report_payload["boot_mac"],
            "macs": macs,
            "manufacturer": system["manufacturer"],
            "product_name": system["product_name"],
            "serial_number": system["serial_number"],
            "cpu_model": cpu["model"],
            "total_memory_bytes": memory["total_bytes"],
            "disk_count": len(report_payload["disks"]),
            "interface_count": len(report_payload["interfaces"]),
        },
        "report_id": report.id,
        "received_at": report.received_at.isoformat(),
        "schema_version": report.schema_version,
        "report": report_payload,
    }
    filename = f"atlaso-inventory-host-{host.id}-report-{report.id}.json"
    return Response(
        json.dumps(exported, indent=2, sort_keys=True) + "\n",
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.delete("/hosts/{host_id}")
def remove_discovered_host(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Remove an unassigned discovered host and its retained reports.

    Uses the authentication posture documented for this endpoint. Removal or revocation takes effect
    in Atlaso application state; appliance host changes remain subject to the documented apply
    boundary for the resource.

    Args:
        host_id: Stable identifier of the associated host resource.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(NetworkBootDiscoveredHost, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    counts = {
        "commands": int(
            db.scalar(
                select(func.count(NetworkBootInventoryCommand.id)).where(
                    NetworkBootInventoryCommand.host_id == host.id
                )
            )
            or 0
        ),
        "sessions": int(
            db.scalar(
                select(func.count(NetworkBootInventorySession.id)).where(
                    NetworkBootInventorySession.host_id == host.id
                )
            )
            or 0
        ),
        "reports": int(
            db.scalar(
                select(func.count(NetworkBootInventoryReport.id)).where(
                    NetworkBootInventoryReport.host_id == host.id
                )
            )
            or 0
        ),
    }
    db.execute(
        delete(NetworkBootInventoryCommand).where(
            NetworkBootInventoryCommand.host_id == host.id
        )
    )
    db.execute(
        delete(NetworkBootInventorySession).where(
            NetworkBootInventorySession.host_id == host.id
        )
    )
    db.execute(
        delete(NetworkBootInventoryReport).where(
            NetworkBootInventoryReport.host_id == host.id
        )
    )
    db.delete(host)
    record_audit(
        db,
        actor=identity.username,
        action="remove_discovered_host",
        resource_type="network_boot_discovered_host",
        resource_id=str(host_id),
        detail=(
            f"reports={counts['reports']}; sessions={counts['sessions']}; "
            f"commands={counts['commands']}"
        ),
        request_id=request.state.request_id,
    )
    db.commit()
    return {"host_id": host_id, "removed": True, **counts}


def _wake_host(
    *,
    db: Session,
    request: Request,
    identity: Identity,
    mac_address: str,
    resource_type: str,
    resource_id: str,
) -> Any:
    """Return wake host.

    Args:
        db: Active database session.
        request: Incoming HTTP request.
        identity: Authenticated identity authorizing the request.
        mac_address: MAC address identifying the host or interface.
        resource_type: Resource type supplied by the caller.
        resource_id: Identifier of the resource.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    try:
        targets = wake_on_lan_broadcast_targets(db)
        display_mac = normalize_mac(mac_address, required=True)
    except ValueError as exc:
        record_audit(
            db,
            actor=identity.username,
            action="send_wake_on_lan",
            resource_type=resource_type,
            resource_id=resource_id,
            success=False,
            detail=str(exc),
            request_id=request.state.request_id,
        )
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit_event = record_audit(
        db,
        actor=identity.username,
        action="send_wake_on_lan",
        resource_type=resource_type,
        resource_id=resource_id,
        success=False,
        detail=(
            f"mac={display_mac}; broadcasts_planned={','.join(targets)}; "
            "udp_port=9; outcome=pending"
        ),
        request_id=request.state.request_id,
        emit_operational=False,
    )
    try:
        sent_targets = send_wake_on_lan(mac_address, targets)
    except WakeOnLanDeliveryError as exc:
        finalize_audit(
            db,
            audit_event,
            success=False,
            detail=(
                f"mac={display_mac}; broadcasts_sent={','.join(exc.sent_targets)}; "
                f"failed_broadcast={exc.failed_target}; udp_port=9; error={exc}"
            ),
            operational_outcome="packet_partially_sent",
            delivered_count=len(exc.sent_targets),
        )
        return JSONResponse(
            status_code=status.HTTP_207_MULTI_STATUS,
            content={
                "status": "packet_partially_sent",
                "mac_address": display_mac,
                "broadcast_targets": exc.sent_targets,
                "failed_broadcast_target": exc.failed_target,
                "message": (
                    "Wake-on-LAN reached only some broadcasts before a UDP send failed. "
                    "Do not retry automatically; host power-on is not confirmed."
                ),
            },
        )
    except (OSError, ValueError) as exc:
        finalize_audit(
            db,
            audit_event,
            success=False,
            detail=f"mac={display_mac}; broadcasts_sent=; udp_port=9; error={exc}",
            operational_outcome="packet_not_sent",
            delivered_count=0,
        )
        status_code = 409 if isinstance(exc, ValueError) else 503
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    finalize_audit(
        db,
        audit_event,
        success=True,
        detail=f"mac={display_mac}; broadcasts={','.join(sent_targets)}; udp_port=9",
        operational_outcome="packet_sent",
        delivered_count=len(sent_targets),
    )
    return {
        "status": "packet_sent",
        "mac_address": display_mac,
        "broadcast_targets": sent_targets,
        "message": "Wake-on-LAN packet sent; host power-on is not confirmed.",
    }


@router.post("/hosts/{host_id}/wake")
def wake_discovered_host(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Send one audited Wake-on-LAN packet for a discovered host.

    Uses the authentication posture documented for this endpoint. The action runs through the
    endpoint's existing audited adapter or task boundary; inspect the returned state before treating
    the operation as complete.

    Args:
        host_id: Stable identifier of the associated host resource.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(NetworkBootDiscoveredHost, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    return _wake_host(
        db=db,
        request=request,
        identity=identity,
        mac_address=host.boot_mac,
        resource_type="network_boot_discovered_host",
        resource_id=str(host.id),
    )


@router.post("/hosts/{host_id}/reboot", status_code=status.HTTP_202_ACCEPTED)
def reboot_discovered_host(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Queue an audited remote reboot for a discovered host.

    Uses the authentication posture documented for this endpoint. The action runs through the
    endpoint's existing audited adapter or task boundary; inspect the returned state before treating
    the operation as complete.

    Args:
        host_id: Stable identifier of the associated host resource.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(NetworkBootDiscoveredHost, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    try:
        command = queue_reboot_command(
            db,
            host=host,
            requested_by=identity.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="queue_inventory_reboot",
        resource_type="network_boot_inventory_command",
        resource_id=command.id,
        detail=f"host_id={host.id}",
        request_id=request.state.request_id,
    )
    db.commit()
    return {
        "id": command.id,
        "action": command.action,
        "status": command.status,
        "expires_at": command.expires_at.isoformat(),
    }


@router.get("/commands/{command_id}")
def get_inventory_command_status(
    command_id: Annotated[str, ApiPath(description='Unique identifier of the command record addressed by this operation.')],
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get the terminal status of an Inventory Linux command.

    Uses the authentication posture documented for this endpoint. This read-only operation does not
    change saved desired state or appliance runtime state.

    Args:
        command_id: Stable identifier of the associated command resource.
        _identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    command = db.get(NetworkBootInventoryCommand, command_id)
    if command is None:
        raise HTTPException(status_code=404, detail="Inventory command not found.")
    return {
        "id": command.id,
        "host_id": command.host_id,
        "action": command.action,
        "status": command.status,
        "created_at": command.created_at.isoformat(),
        "delivered_at": command.delivered_at.isoformat() if command.delivered_at else None,
        "acknowledged_at": (
            command.acknowledged_at.isoformat() if command.acknowledged_at else None
        ),
        "expires_at": command.expires_at.isoformat(),
    }


@router.post(
    "/esxi-hosts/{host_id}/wake",
)
def wake_esxi_host_reference(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Send one audited Wake-on-LAN packet for an ESXi Host Reference.

    Uses the authentication posture documented for this endpoint. The action runs through the
    endpoint's existing audited adapter or task boundary; inspect the returned state before treating
    the operation as complete.

    Args:
        host_id: Stable identifier of the associated host resource.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(EsxiPxeHost, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="ESXi host reference not found.")
    return _wake_host(
        db=db,
        request=request,
        identity=identity,
        mac_address=host.mac_address,
        resource_type="esxi_pxe_host",
        resource_id=str(host.id),
    )


@router.post(
    "/esxi-hosts/{host_id}/boot-inventory-once",
    status_code=status.HTTP_202_ACCEPTED,
)
def boot_esxi_host_into_inventory_once(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Request a one-time Inventory Linux boot for an ESXi Host Reference.

    Uses the authentication posture documented for this endpoint. The operation changes saved Atlaso
    application state; any appliance host enforcement remains subject to the documented apply or
    task boundary for the resource.

    Args:
        host_id: Stable identifier of the associated host resource.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(EsxiPxeHost, host_id)
    if host is None or not host.enabled:
        raise HTTPException(
            status_code=404,
            detail="Enabled ESXi host reference not found.",
        )
    inventory = db.execute(
        select(NetworkBootEnvironment).where(
            NetworkBootEnvironment.key == "inventory",
            NetworkBootEnvironment.active_version != "",
        )
    ).scalar_one_or_none()
    if inventory is None:
        raise HTTPException(
            status_code=409,
            detail="Atlaso Inventory Linux must be active before scheduling a utility boot.",
        )
    override = request_host_boot_override(
        db,
        host_id=host.id,
        mac_address=host.mac_address,
        environment_key="inventory",
        requested_by=identity.username,
    )
    record_audit(
        db,
        actor=identity.username,
        action="request_esxi_host_inventory_boot",
        resource_type="network_boot_host_boot_override",
        resource_id=str(host.id),
        detail=f"mac={host.mac_address}; expires_at={override.expires_at.isoformat()}",
        request_id=request.state.request_id,
    )
    db.commit()
    return {
        "host_id": host.id,
        "mac_address": host.mac_address,
        "environment_key": override.environment_key,
        "requested_at": override.requested_at.isoformat(),
        "expires_at": override.expires_at.isoformat(),
        "claimed_at": None,
    }


@router.post("/hosts/{host_id}/promote", status_code=status.HTTP_201_CREATED)
def promote_discovered_host(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    payload: dict[str, Any],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Promote a discovered host into an ESXi Host Reference.

    Uses the authentication posture documented for this endpoint. The operation changes saved Atlaso
    application state; any appliance host enforcement remains subject to the documented apply or
    task boundary for the resource.

    Args:
        host_id: Stable identifier of the associated host resource.
        payload: Validated request or task payload consumed by the operation.
        request: Incoming HTTP request carrying the operation context.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    discovered = db.get(NetworkBootDiscoveredHost, host_id)
    if discovered is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    required = {
        "hostname",
        "mac_address",
        "ip_address",
        "kickstart_id",
        "installer_iso_path",
        "variables",
        "enabled",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Promotion requires explicit review of {missing[0]}.",
        )
    if not isinstance(payload.get("enabled"), bool):
        raise HTTPException(status_code=422, detail="Promotion enabled state must be a boolean.")
    promotion_payload = dict(payload)
    if promotion_payload.get("kickstart_id") == "":
        promotion_payload["kickstart_id"] = None
    try:
        promotion = EsxiPxeHostCreate.model_validate(promotion_payload)
    except ValidationError as exc:
        error = exc.errors(include_url=False)[0]
        field = ".".join(str(part) for part in error.get("loc", ())) or "request"
        raise HTTPException(
            status_code=422,
            detail=f"Promotion {field} is invalid: {error['msg']}.",
        ) from exc
    mac_key = normalize_pxe_mac(promotion.mac_address)
    if not mac_key:
        raise HTTPException(status_code=422, detail="Promotion MAC is invalid.")
    mac_address = ":".join(mac_key.split("-")[1:])
    boot_mac_key = normalize_pxe_mac(discovered.boot_mac)
    boot_mac = ":".join(boot_mac_key.split("-")[1:]) if boot_mac_key else ""
    if mac_address != boot_mac:
        raise HTTPException(
            status_code=422,
            detail="Promotion MAC must match the discovered boot MAC.",
        )
    if db.execute(
        select(EsxiPxeHost).where(EsxiPxeHost.mac_address == mac_address)
    ).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="An ESXi profile already uses this MAC.")
    hostname = promotion.hostname.strip()
    if any(
        row.hostname.lower() == hostname.lower()
        for row in db.execute(select(EsxiPxeHost)).scalars().all()
    ):
        raise HTTPException(status_code=409, detail="An ESXi profile already uses this hostname.")
    try:
        host = EsxiPxeHost(
            hostname=hostname,
            mac_address=mac_address,
            ip_address=promotion.ip_address.strip(),
            kickstart_id=promotion.kickstart_id,
            installer_iso_path=normalize_installer_iso_path(
                promotion.installer_iso_path
            ),
            variables_json=host_variables_json(promotion.variables),
            enabled=promotion.enabled,
        )
        if not host.hostname:
            raise ValueError("Promotion hostname is required.")
        db.add(host)
        db.flush()
        sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
        record_audit(
            db,
            actor=identity.username,
            action="promote_inventory_host_to_esxi",
            resource_type="esxi_pxe_host",
            resource_id=str(host.id),
            detail=f"discovered_host_id={discovered.id}; mac={mac_address}",
            request_id=request.state.request_id,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="ESXi promotion conflicts with an existing profile.") from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "id": host.id,
        "hostname": host.hostname,
        "mac_address": host.mac_address,
        "enabled": host.enabled,
    }


@public_router.get("/pxe/boot.ipxe")
def network_boot_ipxe(
    request: Request,
    mac: str = "",
    firmware: str = "",
    db: Session = Depends(get_db),
) -> Response:
    """Handle the network boot ipxe endpoint.

    Args:
        request: Incoming HTTP request.
        mac: Mac supplied by the caller.
        firmware: Firmware supplied by the caller.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    _bounded_rate_limit(request, bucket="menu", limit=120)
    try:
        default_environment_key = claim_host_boot_override(
            db,
            mac_address=mac,
        )
        content = render_network_boot_menu(
            db,
            mac_address=mac,
            firmware=firmware,
            request_origin=f"{request.url.scheme}://{request.url.netloc}",
            default_environment_key=default_environment_key,
        )
        if default_environment_key:
            db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(
        content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


@public_router.get("/pxe/media/{environment_key}/{version}/{file_path:path}")
@public_router.head(
    "/pxe/media/{environment_key}/{version}/{file_path:path}",
    include_in_schema=False,
)
def network_boot_media_file(
    environment_key: str,
    version: str,
    file_path: str,
    db: Session = Depends(get_db),
) -> FileResponse:
    """Handle the network boot media file endpoint.

    Args:
        environment_key: Stable key identifying the Network Boot environment.
        version: Version identifier to validate or publish.
        file_path: Filesystem path for the file.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    media = active_network_boot_media(
        db,
        environment_key=environment_key,
        public_version=version,
    )
    if media is None:
        raise HTTPException(status_code=404, detail="Network Boot media is not active.")
    root = _installed_media_directory(media)
    if root is None:
        raise HTTPException(status_code=404, detail="Network Boot media file not found.")
    try:
        manifest = json.loads(media.manifest_json or "{}")
    except json.JSONDecodeError:
        manifest = {}
    allowed = set(manifest.get("files") or []) | {"manifest.json"}
    target = _allowlisted_media_file(root, file_path, allowed)
    if target is None:
        raise HTTPException(status_code=404, detail="Network Boot media file is not allowlisted.")
    return FileResponse(
        target,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "public, max-age=31536000, immutable",
            "X-Content-Type-Options": "nosniff",
        },
    )


@public_router.post("/pxe/inventory/sessions", status_code=status.HTTP_201_CREATED)
def create_inventory_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Handle the create inventory session endpoint.

    Args:
        request: Incoming HTTP request.
        response: HTTP response being constructed.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    _bounded_rate_limit(request, bucket="session", limit=30)
    try:
        session, token = issue_inventory_session(db)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {
        "session_id": session.id,
        "access_token": token,
        "token_type": "Bearer",
        "expires_at": session.expires_at.isoformat(),
        "heartbeat_interval_seconds": 10,
    }


@public_router.post("/pxe/inventory/report", status_code=status.HTTP_201_CREATED)
def submit_inventory_report(
    payload: dict[str, Any],
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Handle the submit inventory report endpoint.

    Args:
        payload: Validated request or operation payload.
        request: Incoming HTTP request.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    _bounded_rate_limit(request, bucket="report", limit=60)
    session = _inventory_session(request, db)
    try:
        host, report = store_inventory_report(
            db,
            session=session,
            payload=payload,
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        message = str(exc)
        logger.warning("Rejected Inventory Linux report: %s", message)
        if "occupied by live clients; retry later" in message:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=message,
            ) from exc
        code = 409 if "already submitted" in message or "does not match" in message else 422
        raise HTTPException(status_code=code, detail=message) from exc
    return {
        "host_id": host.id,
        "report_id": report.id,
        "identity_key": host.identity_key,
        "collision": bool(host.collision),
    }


@public_router.post("/pxe/inventory/heartbeat")
def inventory_heartbeat(
    payload: dict[str, Any],
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Handle the inventory heartbeat endpoint.

    Args:
        payload: Validated request or operation payload.
        request: Incoming HTTP request.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    _bounded_rate_limit(request, bucket="heartbeat", limit=360)
    session = _inventory_session(request, db, require_report=True)
    try:
        touch_inventory_heartbeat(
            session,
            identity_key=str(payload.get("identity_key") or ""),
        )
        db.add(session)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "online", "server_time": utcnow().isoformat()}


@public_router.get("/pxe/inventory/commands")
def inventory_commands(
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Handle the inventory commands endpoint.

    Args:
        request: Incoming HTTP request.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    _bounded_rate_limit(request, bucket="commands", limit=360)
    session = _inventory_session(request, db, require_report=True)
    command = poll_inventory_command(db, session=session)
    if command is not None:
        record_audit(
            db,
            actor="inventory-session",
            action="deliver_inventory_command",
            resource_type="network_boot_inventory_command",
            resource_id=command.id,
            detail=f"host_id={command.host_id}; action={command.action}",
            request_id=request.state.request_id,
        )
    db.commit()
    return {
        "command": (
            {
                "id": command.id,
                "action": command.action,
                "expires_at": command.expires_at.isoformat(),
            }
            if command
            else None
        )
    }


@public_router.post("/pxe/inventory/commands/{command_id}/acknowledge")
def acknowledge_inventory_command_route(
    command_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Handle the acknowledge inventory command route endpoint.

    Args:
        command_id: Identifier of the command.
        request: Incoming HTTP request.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    _bounded_rate_limit(request, bucket="ack", limit=120)
    session = _inventory_session(request, db, require_report=True)
    try:
        command = acknowledge_inventory_command(
            db,
            session=session,
            command_id=command_id,
        )
        record_audit(
            db,
            actor="inventory-session",
            action="acknowledge_inventory_command",
            resource_type="network_boot_inventory_command",
            resource_id=command.id,
            detail=f"host_id={command.host_id}; action={command.action}",
            request_id=request.state.request_id,
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": command.id, "status": command.status}
