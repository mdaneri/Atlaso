from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import io
import json
import logging
import re
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_urlsafe
from time import monotonic
from urllib.parse import urlparse

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal, get_db
from atlaso.app.models import ApplianceSettings, PhysicalInterface, User, VaultEntry, VlanInterface
from atlaso.app.secrets import decrypt_secret
from atlaso.app.security import (
    SESSION_APPLIANCE_INSTANCE_SESSION_KEY,
    ensure_appliance_instance_id,
    get_session_identity,
    require_session_identity,
)
from atlaso.app.services.appliance_settings import (
    management_interface_context,
    normalized_web_terminal_interfaces,
    web_terminal_addresses,
    web_terminal_interface_options,
    web_terminal_listener_interfaces,
)
from atlaso.app.services.vaults import vault_entry_uris


router = APIRouter()
LOGGER = logging.getLogger("atlaso.web_terminal")
WEB_TERMINAL_REQUEST_DIR = Path("/var/lib/atlaso/web-terminal/requests")
SSH_HOST_PUBLIC_KEY_PATH = Path("/etc/ssh/ssh_host_ed25519_key.pub")
TICKET_TTL_SECONDS = 30
IDLE_TIMEOUT_SECONDS = 15 * 60
MAX_SESSION_SECONDS = 60 * 60
MAX_GLOBAL_SESSIONS = 4
DETACHED_SESSION_SECONDS = 5 * 60
MAX_OUTSTANDING_TICKETS = 32
MAX_INPUT_BYTES = 16 * 1024
MAX_OUTPUT_BACKLOG = 1024 * 1024


@dataclass
class TerminalTicket:
    user_id: int
    username: str
    csrf_token: str
    browser_session_id: str
    takeover: bool
    expires_at: datetime
    remote_entry_id: int = 0
    remote_uri_index: int = 0
    remote_fingerprint: str = ""


@dataclass
class RemoteTerminalLaunch:
    user_id: int
    entry_id: int
    uri_index: int
    fingerprint: str
    expires_at: datetime


@dataclass
class ActiveTerminalSession:
    user_id: int
    username: str
    display_username: str
    target_key: str
    browser_session_id: str
    session_id: str
    transport: paramiko.Transport
    channel: paramiko.Channel
    started: float
    last_input: float
    detached_at: float | None = None
    websocket: WebSocket | None = None
    output: bytearray = field(default_factory=bytearray)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    close_reason: str = "shell exited"
    reader_task: asyncio.Task[None] | None = None


_ticket_lock = threading.Lock()
_tickets: dict[str, TerminalTicket] = {}
_remote_launches: dict[str, RemoteTerminalLaunch] = {}
_session_lock = threading.Lock()
_sessions: dict[tuple[int, str], ActiveTerminalSession] = {}
_pending_sessions: set[tuple[int, str]] = set()


def _ticket_digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _ssh_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


def _remote_entry_target(entry: VaultEntry, uri_index: int) -> tuple[str, int, str]:
    uris = vault_entry_uris(entry)
    if uri_index < 1 or uri_index > len(uris):
        raise ValueError("The selected vault URI does not exist.")
    parsed = urlparse(uris[uri_index - 1])
    if parsed.scheme not in {"ssh", "sftp"} or not parsed.hostname:
        raise ValueError("The selected vault URI is not an SSH or SFTP target.")
    if not entry.username:
        raise ValueError("Enter a username before opening an SSH or SFTP URI.")
    return parsed.hostname, parsed.port or 22, entry.username


def _probe_remote_ssh_host(hostname: str, port: int) -> str:
    sock = socket.create_connection((hostname, port), timeout=10)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=10)
        return _ssh_fingerprint(transport.get_remote_server_key())
    finally:
        transport.close()


def _terminal_replay_output(output: bytearray) -> bytes:
    # Replaying an old cursor-position query makes xterm answer it again into the
    # live shell, where PowerShell renders the response as text such as `12;40R`.
    return re.sub(rb"\x1b\[\??6n", b"", bytes(output))


def _settings_row(db: Session) -> ApplianceSettings:
    row = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    if row is None:
        row = ApplianceSettings()
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def _terminal_network_state(db: Session) -> tuple[ApplianceSettings, list[str], list[str], list[str]]:
    desired = _settings_row(db)
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    management = management_interface_context(interfaces)
    options = web_terminal_interface_options(interfaces, vlans)
    selected = web_terminal_listener_interfaces(
        normalized_web_terminal_interfaces(desired, management),
        options,
    )
    management_address = _normalized_listener(str(management.get("ip") or ""))
    management_addresses = [management_address] if management_address else []
    return desired, selected, web_terminal_addresses(selected, options), management_addresses


def _helper_applied() -> bool:
    result = SystemAdapter().web_terminal_status()
    if result.returncode != 0 or result.dry_run:
        return False
    for line in reversed(result.stdout.splitlines()):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "enabled" in payload:
            return bool(payload["enabled"])
    return False


def _normalized_listener(value: str) -> str:
    candidate = value.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def _request_uses_selected_listener(headers: object, server_host: str, allowed_addresses: list[str]) -> bool:
    if get_settings().environment != "appliance":
        return True
    try:
        if not ipaddress.ip_address(server_host).is_loopback:
            return False
    except ValueError:
        return False
    listener = _normalized_listener(headers.get("x-atlaso-listener-address", ""))  # type: ignore[attr-defined]
    return listener in allowed_addresses


def _request_is_https(headers: object, scheme: str) -> bool:
    if get_settings().environment != "appliance":
        return True
    return str(headers.get("x-forwarded-proto", scheme)).lower() == "https"  # type: ignore[attr-defined]


def _active_session_for_user(user_id: int) -> ActiveTerminalSession | None:
    with _session_lock:
        return next((session for (session_user_id, _browser_id), session in _sessions.items() if session_user_id == user_id), None)


def revoke_user_terminal_sessions(user_id: int, reason: str = "Web SSH access revoked") -> None:
    with _ticket_lock:
        stale_tickets = [digest for digest, ticket in _tickets.items() if ticket.user_id == user_id]
        for digest in stale_tickets:
            _tickets.pop(digest, None)
        stale_launches = [digest for digest, launch in _remote_launches.items() if launch.user_id == user_id]
        for digest in stale_launches:
            _remote_launches.pop(digest, None)
    with _session_lock:
        stale_keys = [key for key in _sessions if key[0] == user_id]
        sessions = [_sessions.pop(key) for key in stale_keys]
        _pending_sessions.difference_update({key for key in _pending_sessions if key[0] == user_id})
    for session in sessions:
        session.close_reason = reason
        try:
            session.channel.close()
        except Exception:
            pass
        try:
            session.transport.close()
        except Exception:
            pass


def _reserve_new_session(key: tuple[int, str]) -> bool:
    with _session_lock:
        if key in _sessions:
            return True
        if key in _pending_sessions or len(_sessions) + len(_pending_sessions) >= MAX_GLOBAL_SESSIONS:
            return False
        _pending_sessions.add(key)
        return True


def _release_session_reservation(key: tuple[int, str]) -> None:
    with _session_lock:
        _pending_sessions.discard(key)


def _user_has_terminal_permission(user: User | None) -> bool:
    return bool(
        user
        and user.enabled
        and user.web_terminal_access
        and (user.auth_provider or "local") == "local"
    )


def _user_can_access_terminal(user: User | None) -> bool:
    return bool(_user_has_terminal_permission(user) and (user.shell or "/sbin/nologin") != "/sbin/nologin")


def _terminal_page_context(
    request: Request,
    identity,
    db: Session,
) -> tuple[dict[str, object], bool]:
    user = db.get(User, int(identity.user_id))
    desired, selected, addresses, management_addresses = _terminal_network_state(db)
    if desired.web_terminal_enabled and not _user_has_terminal_permission(user):
        raise HTTPException(status_code=403, detail="Web SSH access is not enabled for this user")
    server_host = str((request.scope.get("server") or ("", 0))[0])
    page_addresses = addresses if desired.web_terminal_enabled else management_addresses
    if not _request_uses_selected_listener(request.headers, server_host, page_addresses):
        raise HTTPException(status_code=404, detail="Not found")
    public_listener = (
        _request_uses_selected_listener(request.headers, server_host, addresses)
        and not _request_uses_selected_listener(request.headers, server_host, management_addresses)
    )
    from atlaso.app.ui import appliance_apply_status, public_portal_links_context, render

    available = bool(
        get_settings().environment == "appliance"
        and desired.web_terminal_enabled
        and _user_can_access_terminal(user)
        and _request_is_https(request.headers, request.url.scheme)
        and _helper_applied()
    )
    reason = ""
    if not desired.web_terminal_enabled:
        reason = "Web terminal access is disabled in Appliance Settings."
    elif get_settings().environment != "appliance":
        reason = "Web terminal sessions are available only on a deployed appliance."
    elif not _user_can_access_terminal(user):
        reason = "Web SSH access requires an interactive local-user shell."
    elif not _request_is_https(request.headers, request.url.scheme):
        reason = "Web terminal access requires HTTPS."
    elif not available:
        reason = "Web terminal desired state has not been applied yet."
    context = {
        "identity": identity,
        "terminal_available": available,
        "terminal_unavailable_reason": reason,
        "terminal_interfaces": selected,
        "terminal_addresses": addresses,
        "terminal_public": public_listener,
    }
    return context, public_listener


@router.get("/terminal", response_class=HTMLResponse, response_model=None)
def terminal_page(
    request: Request,
    identity=Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    if identity is None:
        return RedirectResponse("/login?next=/terminal", status_code=303)
    context, public_listener = _terminal_page_context(request, identity, db)
    from atlaso.app.ui import appliance_apply_status, public_portal_links_context, render

    if public_listener:
        context.update(
            {
                "public_address_mode_switch": False,
                "public_logout_action": "/logout",
                "public_logout_next": "/terminal",
                **public_portal_links_context(db),
            }
        )
    else:
        context["appliance_apply_status"] = appliance_apply_status(db, "appliance_settings")
    return render(
        request,
        "public_terminal.html" if public_listener else "terminal.html",
        context,
    )


@router.get("/terminal/remote", response_class=HTMLResponse, response_model=None)
def remote_terminal_page(
    request: Request,
    identity=Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    if identity is None:
        return RedirectResponse("/login?next=/terminal/remote", status_code=303)
    if not identity.has_role("admin"):
        raise HTTPException(status_code=403, detail="Administrator role required")
    context, public_listener = _terminal_page_context(request, identity, db)
    if public_listener:
        raise HTTPException(status_code=404, detail="Not found")
    from atlaso.app.ui import render

    return render(request, "remote_terminal.html", context)


@router.post("/terminal/remote-launches", response_model=None)
async def create_remote_terminal_launch(
    request: Request,
    vault_id: int = Form(...),
    entry_id: int = Form(...),
    uri_index: int = Form(...),
    confirmed_fingerprint: str = Form(""),
    csrf: str = Form(...),
    identity=Depends(require_session_identity),
    db: Session = Depends(get_db),
) -> JSONResponse:
    if not identity.has_role("admin"):
        raise HTTPException(status_code=403, detail="Administrator role required")
    if not csrf or csrf != request.session.get("csrf_token"):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    user = db.get(User, int(identity.user_id))
    desired, _selected, addresses, _management_addresses = _terminal_network_state(db)
    server_host = str((request.scope.get("server") or ("", 0))[0])
    if (
        not _user_can_access_terminal(user)
        or not _request_uses_selected_listener(request.headers, server_host, addresses)
        or get_settings().environment != "appliance"
        or not desired.web_terminal_enabled
        or not _request_is_https(request.headers, request.url.scheme)
        or not _helper_applied()
    ):
        raise HTTPException(status_code=409, detail="Web terminal access is not applied and ready")
    entry = db.get(VaultEntry, entry_id)
    if entry is None or entry.vault_id != vault_id:
        raise HTTPException(status_code=404, detail="Vault entry not found.")
    try:
        hostname, port, _username = _remote_entry_target(entry, uri_index)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        fingerprint = await asyncio.to_thread(_probe_remote_ssh_host, hostname, port)
    except (OSError, paramiko.SSHException) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"The SSH target {hostname}:{port} is unavailable. Verify the address, port, and SSH service.",
        ) from exc
    target = f"{hostname}:{port}"
    if confirmed_fingerprint != fingerprint:
        return JSONResponse(
            {
                "error_code": "SSH_HOST_KEY_CONFIRMATION_REQUIRED",
                "target": target,
                "hostname": hostname,
                "fingerprint": fingerprint,
            },
            status_code=409,
            headers={"Cache-Control": "no-store"},
        )
    raw = token_urlsafe(36)
    now = datetime.now(timezone.utc)
    with _ticket_lock:
        stale_launches = [
            digest
            for digest, launch in _remote_launches.items()
            if launch.expires_at <= now
        ]
        for digest in stale_launches:
            _remote_launches.pop(digest, None)
        _remote_launches[_ticket_digest(raw)] = RemoteTerminalLaunch(
            user_id=int(identity.user_id),
            entry_id=entry.id,
            uri_index=uri_index,
            fingerprint=fingerprint,
            expires_at=now + timedelta(seconds=TICKET_TTL_SECONDS),
        )
    record_audit(
        db,
        actor=identity.username,
        action="vault_remote_terminal_launch",
        resource_type="vault_entry",
        resource_id=str(entry.id),
        detail=f"uri_index={uri_index}",
    )
    return JSONResponse(
        {
            "url": f"/terminal/remote#remote-launch={raw}",
            "target": hostname,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/terminal/tickets", response_model=None)
def create_terminal_ticket(
    request: Request,
    csrf: str = Form(...),
    browser_session_id: str = Form(...),
    takeover: bool = Form(False),
    remote_launch: str = Form(""),
    identity=Depends(require_session_identity),
    db: Session = Depends(get_db),
) -> JSONResponse:
    user = db.get(User, int(identity.user_id))
    if not _user_can_access_terminal(user):
        raise HTTPException(status_code=403, detail="Web SSH access is not enabled for this user")
    if not csrf or csrf != request.session.get("csrf_token"):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    browser_session_id = browser_session_id.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", browser_session_id):
        raise HTTPException(status_code=400, detail="Invalid browser terminal session identifier")
    desired, _selected, addresses, _management_addresses = _terminal_network_state(db)
    server_host = str((request.scope.get("server") or ("", 0))[0])
    if not _request_uses_selected_listener(request.headers, server_host, addresses):
        raise HTTPException(status_code=404, detail="Not found")
    if (
        get_settings().environment != "appliance"
        or not desired.web_terminal_enabled
        or not _request_is_https(request.headers, request.url.scheme)
        or not _helper_applied()
    ):
        raise HTTPException(status_code=409, detail="Web terminal access is not applied and ready")
    active_session = _active_session_for_user(int(identity.user_id))
    remote: RemoteTerminalLaunch | None = None
    if remote_launch:
        with _ticket_lock:
            remote = _remote_launches.pop(_ticket_digest(remote_launch), None)
        if (
            remote is None
            or remote.user_id != int(identity.user_id)
            or remote.expires_at <= datetime.now(timezone.utc)
        ):
            raise HTTPException(status_code=400, detail="The remote terminal launch is invalid or expired.")
        takeover = True
    if active_session is not None and active_session.browser_session_id != browser_session_id and not takeover:
        return JSONResponse(
            {
                "error_code": "TERMINAL_SESSION_ACTIVE",
                "detail": "This user already has an active web terminal session in another browser.",
            },
            status_code=409,
            headers={"Cache-Control": "no-store"},
        )
    raw = token_urlsafe(36)
    now = datetime.now(timezone.utc)
    with _ticket_lock:
        stale = [
            digest
            for digest, ticket in _tickets.items()
            if ticket.expires_at <= now
        ]
        for digest in stale:
            _tickets.pop(digest, None)
        if len(_tickets) >= MAX_OUTSTANDING_TICKETS:
            raise HTTPException(status_code=429, detail="Too many terminal tickets are pending")
        _tickets[_ticket_digest(raw)] = TerminalTicket(
            user_id=int(identity.user_id),
            username=identity.username,
            csrf_token=csrf,
            browser_session_id=browser_session_id,
            takeover=bool(takeover),
            expires_at=now + timedelta(seconds=TICKET_TTL_SECONDS),
            remote_entry_id=remote.entry_id if remote else 0,
            remote_uri_index=remote.uri_index if remote else 0,
            remote_fingerprint=remote.fingerprint if remote else "",
        )
    record_audit(db, actor=identity.username, action="web_terminal_ticket", resource_type="web_terminal")
    return JSONResponse(
        {"ticket": raw, "expires_in": TICKET_TTL_SECONDS, "websocket_path": "/terminal/ws"},
        headers={"Cache-Control": "no-store"},
    )


def _consume_ticket(raw: str, user_id: int, username: str, csrf_token: str) -> TerminalTicket | None:
    now = datetime.now(timezone.utc)
    with _ticket_lock:
        ticket = _tickets.pop(_ticket_digest(raw), None)
    return ticket if (
        ticket
        and ticket.expires_at > now
        and ticket.user_id == user_id
        and ticket.username == username
        and ticket.csrf_token == csrf_token
    ) else None


def _open_ssh_channel(username: str, session_id: str, cols: int, rows: int) -> tuple[paramiko.Transport, paramiko.Channel]:
    private_key = Ed25519PrivateKey.generate()
    private_text = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_text = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    WEB_TERMINAL_REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    request_path = WEB_TERMINAL_REQUEST_DIR / f"{session_id}.json"
    request_path.write_text(json.dumps({"username": username, "session_id": session_id, "public_key": public_text}), encoding="utf-8")
    request_path.chmod(0o600)
    result = SystemAdapter().sign_web_terminal_key(str(request_path))
    request_path.unlink(missing_ok=True)
    certificate = next((line.strip() for line in result.stdout.splitlines() if line.startswith("ssh-ed25519-cert-v01@openssh.com ")), "")
    if result.returncode != 0 or not certificate:
        raise RuntimeError(result.stderr.strip() or "The appliance did not issue a terminal certificate.")
    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(private_text))
    pkey.load_certificate(certificate)
    host_parts = SSH_HOST_PUBLIC_KEY_PATH.read_text(encoding="utf-8").strip().split()
    if len(host_parts) < 2 or host_parts[0] != "ssh-ed25519":
        raise RuntimeError("The appliance SSH Ed25519 host key is unavailable.")
    expected_host_key = paramiko.Ed25519Key(data=base64.b64decode(host_parts[1]))
    sock = socket.create_connection(("127.0.0.1", 22), timeout=10)
    transport = paramiko.Transport(sock)
    transport.get_security_options().key_types = ("ssh-ed25519",)
    transport.start_client(timeout=10)
    if transport.get_remote_server_key() != expected_host_key:
        transport.close()
        raise RuntimeError("The appliance SSH host key did not match the installed key.")
    transport.auth_publickey(username, pkey)
    channel = transport.open_session(timeout=10)
    channel.get_pty(term="xterm-256color", width=cols, height=rows)
    channel.invoke_shell()
    return transport, channel


def _open_remote_ssh_channel(
    entry_id: int,
    uri_index: int,
    expected_fingerprint: str,
    cols: int,
    rows: int,
) -> tuple[paramiko.Transport, paramiko.Channel, str]:
    with SessionLocal() as db:
        entry = db.get(VaultEntry, entry_id)
        if entry is None:
            raise RuntimeError("The vault entry no longer exists.")
        hostname, port, username = _remote_entry_target(entry, uri_index)
        password = decrypt_secret(entry.encrypted_value)
    sock = socket.create_connection((hostname, port), timeout=10)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=10)
        if _ssh_fingerprint(transport.get_remote_server_key()) != expected_fingerprint:
            raise RuntimeError("The remote SSH host key changed after confirmation.")
        transport.auth_password(username, password)
        channel = transport.open_session(timeout=10)
        channel.get_pty(term="xterm-256color", width=cols, height=rows)
        channel.invoke_shell()
        return transport, channel, f"{username}@{hostname}"
    except Exception:
        transport.close()
        raise


async def _detach_websocket(session: ActiveTerminalSession, websocket: WebSocket) -> None:
    async with session.send_lock:
        if session.websocket is websocket:
            session.websocket = None
            session.detached_at = monotonic()


async def _terminal_session_reader(session: ActiveTerminalSession) -> None:
    try:
        if hasattr(session.channel, "settimeout"):
            session.channel.settimeout(1.0)
        while not session.channel.closed:
            now = monotonic()
            if now - session.started >= MAX_SESSION_SECONDS:
                session.close_reason = "maximum lifetime"
                break
            if now - session.last_input >= IDLE_TIMEOUT_SECONDS:
                session.close_reason = "idle timeout"
                break
            if session.detached_at is not None and now - session.detached_at >= DETACHED_SESSION_SECONDS:
                session.close_reason = "reconnect timeout"
                break
            try:
                data = await asyncio.to_thread(session.channel.recv, 32768)
            except (socket.timeout, TimeoutError):
                continue
            if not data:
                break
            async with session.send_lock:
                session.output.extend(data)
                if len(session.output) > MAX_OUTPUT_BACKLOG:
                    del session.output[: len(session.output) - MAX_OUTPUT_BACKLOG]
                websocket = session.websocket
                if websocket is not None:
                    try:
                        await websocket.send_bytes(data)
                    except Exception:
                        if session.websocket is websocket:
                            session.websocket = None
                            session.detached_at = monotonic()
    except Exception:
        session.close_reason = "terminal error"
    finally:
        websocket = session.websocket
        session.websocket = None
        session.channel.close()
        session.transport.close()
        with _session_lock:
            for key, candidate in list(_sessions.items()):
                if candidate is session:
                    _sessions.pop(key, None)
        if websocket is not None:
            try:
                await websocket.send_json({"type": "closed", "reason": session.close_reason})
            except Exception:
                pass
            try:
                await websocket.close(code=1000)
            except Exception:
                pass
        with SessionLocal() as db:
            record_audit(
                db,
                actor=session.username,
                action="web_terminal_end",
                resource_type="web_terminal",
                resource_id=session.session_id,
                detail=f"duration_seconds={int(monotonic() - session.started)} reason={session.close_reason}",
            )


async def _terminate_terminal_session(session: ActiveTerminalSession, reason: str) -> None:
    session.close_reason = reason
    session.channel.close()
    session.transport.close()
    if session.reader_task is not None and session.reader_task is not asyncio.current_task():
        try:
            await asyncio.wait_for(asyncio.shield(session.reader_task), timeout=3)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass


async def _attach_terminal_session(session: ActiveTerminalSession, websocket: WebSocket, *, resumed: bool) -> None:
    previous: WebSocket | None = None
    async with session.send_lock:
        previous = session.websocket
        session.websocket = websocket
        session.detached_at = None
        await websocket.send_json(
            {
                "type": "ready",
                "username": session.display_username,
                "cols": 120,
                "rows": 32,
                "resumed": resumed,
            }
        )
        replay_output = _terminal_replay_output(session.output)
        if replay_output:
            await websocket.send_bytes(replay_output)
    if previous is not None and previous is not websocket:
        try:
            await previous.close(code=4410, reason="Terminal session reattached elsewhere")
        except Exception:
            pass


@router.websocket("/terminal/ws")
async def terminal_websocket(websocket: WebSocket) -> None:
    user_id = websocket.session.get("user_id")
    csrf_token = str(websocket.session.get("csrf_token") or "")
    with SessionLocal() as db:
        if not user_id or websocket.session.get(SESSION_APPLIANCE_INSTANCE_SESSION_KEY) != ensure_appliance_instance_id(db):
            await websocket.close(code=4401)
            return
        user = db.get(User, int(user_id))
        if not _user_can_access_terminal(user):
            await websocket.close(code=4403)
            return
        desired, _selected, addresses, _management_addresses = _terminal_network_state(db)
        server_host = str((websocket.scope.get("server") or ("", 0))[0])
        if not _request_uses_selected_listener(websocket.headers, server_host, addresses):
            await websocket.close(code=4404)
            return
        if (
            get_settings().environment != "appliance"
            or not desired.web_terminal_enabled
            or not _request_is_https(websocket.headers, websocket.url.scheme)
            or not _helper_applied()
        ):
            await websocket.close(code=4409)
            return
        origin = urlparse(websocket.headers.get("origin", ""))
        if origin.netloc and origin.netloc.lower() != websocket.headers.get("host", "").lower():
            await websocket.close(code=4403)
            return
        username = user.username
    await websocket.accept()
    session: ActiveTerminalSession | None = None
    session_id = ""
    try:
        auth_message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
        ticket = _consume_ticket(str(auth_message.get("ticket") or ""), int(user_id), username, csrf_token)
        if auth_message.get("type") != "authenticate" or ticket is None:
            await websocket.send_json({"type": "error", "message": "Terminal ticket is invalid or expired."})
            return
        key = (int(user_id), ticket.browser_session_id)
        target_key = (
            f"vault:{ticket.remote_entry_id}:{ticket.remote_uri_index}"
            if ticket.remote_entry_id
            else "appliance"
        )
        with _session_lock:
            session = _sessions.get(key)
            if session is not None and session.target_key != target_key:
                _sessions.pop(key, None)
        if session is not None and session.target_key != target_key:
            await _terminate_terminal_session(session, "terminal target changed")
            session = None
        resumed = session is not None
        active_session = _active_session_for_user(int(user_id))
        if active_session is not None and active_session is not session:
            if not ticket.takeover:
                await websocket.send_json({"type": "error", "message": "Another browser has the active terminal session."})
                return
            if active_session.target_key != target_key:
                old_key = (active_session.user_id, active_session.browser_session_id)
                with _session_lock:
                    if _sessions.get(old_key) is active_session:
                        _sessions.pop(old_key, None)
                await _terminate_terminal_session(active_session, "terminal target changed")
            else:
                old_key = (active_session.user_id, active_session.browser_session_id)
                with _session_lock:
                    if _sessions.get(old_key) is active_session:
                        _sessions.pop(old_key, None)
                    active_session.browser_session_id = ticket.browser_session_id
                    _sessions[key] = active_session
                session = active_session
                resumed = True
        if session is None:
            if not _reserve_new_session(key):
                await websocket.send_json({"type": "error", "message": "The appliance terminal session limit has been reached."})
                return
            try:
                session_id = token_urlsafe(18).replace("-", "_")
                display_username = username
                if ticket.remote_entry_id:
                    transport, channel, display_username = await asyncio.to_thread(
                        _open_remote_ssh_channel,
                        ticket.remote_entry_id,
                        ticket.remote_uri_index,
                        ticket.remote_fingerprint,
                        120,
                        32,
                    )
                else:
                    transport, channel = await asyncio.to_thread(_open_ssh_channel, username, session_id, 120, 32)
                now = monotonic()
                session = ActiveTerminalSession(
                    user_id=int(user_id),
                    username=username,
                    display_username=display_username,
                    target_key=target_key,
                    browser_session_id=ticket.browser_session_id,
                    session_id=session_id,
                    transport=transport,
                    channel=channel,
                    started=now,
                    last_input=now,
                )
                with _session_lock:
                    _sessions[key] = session
                with SessionLocal() as db:
                    record_audit(db, actor=username, action="web_terminal_start", resource_type="web_terminal", resource_id=session_id)
                session.reader_task = asyncio.create_task(_terminal_session_reader(session))
            finally:
                _release_session_reservation(key)
        await _attach_terminal_session(session, websocket, resumed=resumed)
        while not session.channel.closed and session.websocket is websocket:
            message = await websocket.receive_json()
            message_type = message.get("type")
            if message_type == "input":
                data = str(message.get("data") or "").encode("utf-8")
                if len(data) > MAX_INPUT_BYTES:
                    raise RuntimeError("Terminal input frame is too large.")
                await asyncio.to_thread(session.channel.sendall, data)
                session.last_input = monotonic()
            elif message_type == "resize":
                cols = max(20, min(300, int(message.get("cols") or 120)))
                rows = max(5, min(100, int(message.get("rows") or 32)))
                await asyncio.to_thread(session.channel.resize_pty, width=cols, height=rows)
            elif message_type == "ping":
                await websocket.send_json({"type": "pong"})
            elif message_type == "terminate":
                await _terminate_terminal_session(session, "operator disconnect")
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        LOGGER.exception(
            "Unable to start or reattach web terminal user=%s session_id=%s",
            username,
            session_id or "unassigned",
        )
        try:
            await websocket.send_json({"type": "error", "message": "The appliance terminal session could not be started or reattached."})
        except Exception:
            pass
    finally:
        if session is not None:
            await _detach_websocket(session, websocket)
        try:
            await websocket.close(code=1000)
        except Exception:
            pass
