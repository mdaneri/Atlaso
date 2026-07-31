from __future__ import annotations

import json
import logging
import shutil
import threading
import time
from collections import defaultdict, deque
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    EsxiPxeHost,
    Job,
    JobStatus,
    NetworkBootDiscoveredHost,
    NetworkBootEnvironment,
    NetworkBootInventoryCommand,
    NetworkBootInventorySession,
    NetworkBootMedia,
    utcnow,
)
from atlaso.app.security import Identity, require_api_or_session_scope
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
    NETWORK_BOOT_MEDIA_ROOT,
    NETWORK_BOOT_UPLOAD_MAX_BYTES,
    catalog_rows,
    claim_host_boot_override,
    cleanup_network_boot_upload,
    host_to_dict,
    inventory_session_for_token,
    issue_inventory_session,
    network_boot_upload_path,
    poll_inventory_command,
    queue_reboot_command,
    render_network_boot_menu,
    report_history,
    request_host_boot_override,
    set_environment_desired_state,
    store_inventory_report,
    touch_inventory_heartbeat,
)


router = APIRouter(prefix="/api/v1/network-boot", tags=["network-boot"])
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


def _installed_media_directory(media: Any) -> Path | None:
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
    return catalog_rows(db)


@router.patch("/environments/{environment_key}")
def update_network_boot_environment(
    environment_key: str,
    payload: dict[str, Any],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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
    environment_key: str,
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = {row["key"]: row for row in catalog_rows(db)}
    if environment_key not in rows:
        raise HTTPException(
            status_code=422,
            detail="Select a downloadable Network Boot environment.",
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
            },
            sort_keys=True,
        ),
    )
    db.add(job)
    record_audit(
        db,
        actor=identity.username,
        action="queue_pxe_media_sync",
        resource_type="job",
        resource_id=job.id,
        detail=f"environment={environment_key}",
        request_id=request.state.request_id,
    )
    db.commit()
    return {"job_id": job.id, "status": job.status, "environment": environment_key}


@router.post(
    "/environments/{environment_key}/upload",
    status_code=status.HTTP_202_ACCEPTED,
)
async def upload_network_boot_environment(
    environment_key: str,
    request: Request,
    artifact: Annotated[UploadFile, File()],
    identity: Annotated[
        Identity,
        Depends(require_api_or_session_scope("write:pxe")),
    ],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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


@router.delete("/environments/{environment_key}/media/{version}")
def remove_network_boot_media(
    environment_key: str,
    version: str,
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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
    if version in {state.desired_version, state.active_version}:
        raise HTTPException(
            status_code=409,
            detail="Select and apply a different version or disable this environment before removal.",
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
    target = _installed_media_directory(media)
    if target is None:
        raise HTTPException(status_code=409, detail="Installed media path failed safety validation.")
    shutil.rmtree(target)
    db.delete(media)
    cleaned_uploads = 0
    for job, config in matching_jobs:
        if config.get("source") != "upload":
            continue
        cleanup_network_boot_upload(job.id)
        cleaned_uploads += 1
    record_audit(
        db,
        actor=identity.username,
        action="remove_network_boot_media",
        resource_type="network_boot_media",
        resource_id=f"{environment_key}:{version}",
        detail=f"inactive immutable cache version removed; staged_uploads_cleaned={cleaned_uploads}",
        request_id=request.state.request_id,
    )
    db.commit()
    return {
        "environment": environment_key,
        "version": version,
        "removed": True,
        "staged_uploads_cleaned": cleaned_uploads,
    }


@router.get("/hosts")
def list_discovered_hosts(
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = db.execute(
        select(NetworkBootDiscoveredHost).order_by(
            desc(NetworkBootDiscoveredHost.last_seen_at),
            NetworkBootDiscoveredHost.id,
        )
    ).scalars().all()
    return [host_to_dict(db, row) for row in rows]


@router.get("/hosts/{host_id}")
def get_discovered_host(
    host_id: int,
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    host = db.get(NetworkBootDiscoveredHost, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    return host_to_dict(db, host, include_report=True)


@router.get("/hosts/{host_id}/history")
def get_discovered_host_history(
    host_id: int,
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    if db.get(NetworkBootDiscoveredHost, host_id) is None:
        raise HTTPException(status_code=404, detail="Discovered host not found.")
    return report_history(db, host_id)


@router.post("/hosts/{host_id}/reboot", status_code=status.HTTP_202_ACCEPTED)
def reboot_discovered_host(
    host_id: int,
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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
    command_id: str,
    _identity: Annotated[Identity, Depends(require_api_or_session_scope("read:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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
    "/esxi-hosts/{host_id}/boot-inventory-once",
    status_code=status.HTTP_202_ACCEPTED,
)
def boot_esxi_host_into_inventory_once(
    host_id: int,
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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
    host_id: int,
    payload: dict[str, Any],
    request: Request,
    identity: Annotated[Identity, Depends(require_api_or_session_scope("write:pxe"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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
    mac_address = str(payload.get("mac_address") or "").strip().lower().replace("-", ":")
    if mac_address not in set(json.loads(discovered.macs_json or "[]")):
        raise HTTPException(
            status_code=422,
            detail="Promotion MAC must be one of the discovered permanent or boot MACs.",
        )
    if not normalize_pxe_mac(mac_address):
        raise HTTPException(status_code=422, detail="Promotion MAC is invalid.")
    if db.execute(
        select(EsxiPxeHost).where(EsxiPxeHost.mac_address == mac_address)
    ).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="An ESXi profile already uses this MAC.")
    hostname = str(payload.get("hostname") or "").strip()
    if any(
        row.hostname.lower() == hostname.lower()
        for row in db.execute(select(EsxiPxeHost)).scalars().all()
    ):
        raise HTTPException(status_code=409, detail="An ESXi profile already uses this hostname.")
    if not isinstance(payload.get("enabled"), bool):
        raise HTTPException(status_code=422, detail="Promotion enabled state must be a boolean.")
    kickstart_id = payload.get("kickstart_id")
    try:
        host = EsxiPxeHost(
            hostname=hostname,
            mac_address=mac_address,
            ip_address=str(payload.get("ip_address") or "").strip(),
            kickstart_id=int(kickstart_id) if kickstart_id not in (None, "") else None,
            installer_iso_path=normalize_installer_iso_path(
                str(payload.get("installer_iso_path") or "")
            ),
            variables_json=host_variables_json(payload.get("variables")),
            enabled=payload["enabled"],
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
