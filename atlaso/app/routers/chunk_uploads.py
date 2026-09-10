"""Adapt bounded browser chunks to existing upload endpoint contracts."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.routing import APIRoute
from starlette.datastructures import FormData, UploadFile
from starlette.responses import Response

from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.security import (
    BROWSER_SESSION_ID_KEY,
    Identity,
    get_session_identity,
    require_session_identity,
)
from atlaso.app.services.chunk_uploads import CHUNK_BYTES, UploadError, upload_store
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

router = APIRouter(prefix=f"{MANAGEMENT_UI_ROOT}/uploads/chunks", include_in_schema=False)


def _policy(target: str, field: str, identity: Identity) -> int:
    """Admit only known upload fields with their existing authorization boundary.

    Args:
        target: Exact destination endpoint path bound to this file.
        field: Existing endpoint file-field name.
        identity: Current browser identity used for permission checks.
    """
    ui = target.removeprefix(MANAGEMENT_UI_ROOT)
    limit = 0
    allowed = False
    if target.startswith(MANAGEMENT_UI_ROOT + "/"):
        if ui == "/vcf-helper/sddc-manager/ovas/upload" and field == "ova_file":
            limit = 16 * 1024**3
            allowed = identity.has_role("admin") or identity.has_role("service-admin")
        elif ui == "/esxi-pxe/isos/upload" and field == "iso_file":
            limit = get_settings().esxi_installer_iso_max_bytes
            allowed = identity.can("write:esxi-pxe")
        elif ui == "/esxi-pxe/kickstarts/upload" and field == "kickstart_file":
            limit = 1024**2
            allowed = identity.can("write:esxi-pxe")
        elif ui in {"/backup-restore/ldap/import", "/ldap/recovery/import"} and field == "archive":
            limit = 1024**3
            allowed = identity.has_role("admin")
        elif ui == "/backup-restore/restore" and field == "archive_file":
            limit = 3_000_000
            allowed = identity.has_role("admin")
        elif ui == "/vcf-private-registry/settings" and field == "ca_bundle_file":
            limit = 1024**2
            allowed = identity.can("write:vcf-registry")
        else:
            fields = {
                "/vcf-offline-depot/settings": {"tool_archive_file", "download_token_file", "activation_code_file"},
                "/vcf-offline-depot/tool-package": {"tool_archive_file"},
                "/vcf-offline-depot/credentials": {"credential_file"},
                "/vcf-offline-depot/download-token": {"download_token_file"},
                "/vcf-offline-depot/activation-code": {"activation_code_file"},
                "/vcf-offline-depot/tool-configuration": {"download_token_file", "activation_code_file"},
            }
            if field in fields.get(ui, set()):
                limit = 2 * 1024**3 if field == "tool_archive_file" else 1024**2
                allowed = identity.can("write:repository")
    elif re.fullmatch(r"/api/v1/network-boot/environments/[a-z0-9_-]+/upload", target) and field == "artifact":
        limit = 2 * 1024**3
        allowed = identity.can("write:pxe")
    if not limit:
        raise HTTPException(400, "This form does not accept chunked uploads.")
    if not allowed:
        raise HTTPException(403, "Upload permission required.")
    return limit


def _owner(request: Request) -> str:
    """Bind every operation to an authenticated, CSRF-protected browser session.

    Args:
        request: Incoming authenticated browser request.
    """
    csrf = request.headers.get("X-CSRF-Token", "")
    owner = request.session.get(BROWSER_SESSION_ID_KEY)
    if not csrf or csrf != request.session.get("csrf_token") or not owner:
        raise HTTPException(403, "Invalid upload session or CSRF token.")
    return str(owner)


async def _body(request: Request, maximum: int) -> bytes:
    """Bound input while streaming, including requests without Content-Length.

    Args:
        request: Incoming authenticated browser request.
        maximum: Maximum buffered request size in bytes.
    """
    result = bytearray()
    async for chunk in request.stream():
        if len(result) + len(chunk) > maximum:
            raise HTTPException(413, "Upload request is too large.")
        result.extend(chunk)
    return bytes(result)


async def _json(request: Request) -> dict[str, Any]:
    """Parse only a small object envelope, never the uploaded file itself.

    Args:
        request: Incoming authenticated browser request.
    """
    try:
        value = json.loads(await _body(request, 1024**2))
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(400, "Invalid upload envelope.") from exc
    if not isinstance(value, dict):
        raise HTTPException(400, "Invalid upload envelope.")
    return value


async def _operation(function: Callable[..., Any], *args: Any) -> Any:
    """Keep disk operations off the event loop and return fixed storage errors.

    Args:
        function: Bounded synchronous storage operation.
        *args: Arguments forwarded to the storage operation or injected test callback.
    """
    try:
        return await anyio.to_thread.run_sync(function, *args)
    except UploadError as exc:
        messages = {
            400: "Invalid upload chunk or checksum.",
            404: "Upload expired or is unavailable. Select the file again.",
            409: "Upload offset conflict, incomplete file, or incorrect destination.",
            413: "Chunk exceeds the declared file size.",
            429: "Upload capacity is busy. Finish or cancel another upload first.",
            503: "Upload staging is unavailable. Check the depot volume and its permissions.",
            507: "Insufficient free space for upload and validation.",
        }
        raise HTTPException(exc.status, messages.get(exc.status, "Upload failed.")) from exc
    except OSError as exc:
        raise HTTPException(503, "Upload storage is unavailable. Retry the upload.") from exc


@router.post("")
async def create_upload(request: Request, identity: Identity = Depends(require_session_identity)) -> dict[str, Any]:
    """Reserve one file after session, CSRF, field, permission, and size checks.

    Args:
        request: Incoming authenticated browser request.
        identity: Current browser identity used for permission checks.
    """
    owner = _owner(request)
    body = await _json(request)
    target, field, filename, size = (body.get(name) for name in ("target", "field", "filename", "size"))
    if (not all(isinstance(value, str) for value in (target, field, filename))
            or not filename or len(filename) > 240 or any(c in filename for c in "\r\n\x00/\\")
            or not isinstance(size, int) or isinstance(size, bool) or size <= 0):
        raise HTTPException(400, "Choose a nonempty, named file.")
    limit = _policy(target, field, identity)
    if size > limit:
        raise HTTPException(413, "File exceeds this upload's size limit.")
    key = await _operation(upload_store.create, owner, target, field, filename, size)
    return {"id": key, "offset": 0, "chunk_bytes": CHUNK_BYTES}


@router.put("/data")
async def append_chunk(request: Request, identity: Identity = Depends(require_session_identity)) -> dict[str, int]:
    """Acknowledge the exact contiguous byte offset, including identical retries.

    Args:
        request: Incoming authenticated browser request.
        identity: Current browser identity used for permission checks.
    """
    owner = _owner(request)
    key = request.headers.get("X-Atlaso-Upload-Id", "")
    session = await _operation(upload_store.get, key, owner)
    _policy(session.target, session.field, identity)
    try:
        offset = int(request.headers.get("X-Atlaso-Upload-Offset", ""))
    except ValueError as exc:
        raise HTTPException(400, "Invalid upload offset.") from exc
    data = await _body(request, CHUNK_BYTES)
    offset = await _operation(upload_store.append, key, owner, offset, data,
                              request.headers.get("X-Atlaso-Chunk-SHA256", ""))
    return {"offset": offset}


@router.delete("/data", status_code=204)
async def cancel_upload(request: Request, identity: Identity = Depends(require_session_identity)) -> None:
    """Release this browser's abandoned file without touching published artifacts.

    Args:
        request: Incoming authenticated browser request.
        identity: Current browser identity used for permission checks.
    """
    await _operation(upload_store.cancel, request.headers.get("X-Atlaso-Upload-Id", ""), _owner(request))


class ChunkedUploadRoute(APIRoute):
    """Feed staged files to unchanged FastAPI form validators without re-spooling.

    The adapter is opt-in per request. Ordinary multipart API callers keep their
    original contract, and endpoint authorization and validation still run.
    """

    def get_route_handler(self) -> Callable:
        """Wrap only the bounded finalization envelope."""
        original = super().get_route_handler()

        async def handle(request: Request) -> Response:
            """Handle.

            Args:
                request: Incoming authenticated browser request.
            """
            if request.headers.get("X-Atlaso-Chunked") != "1":
                return await original(request)
            if request.method != "POST":
                raise HTTPException(405, "Upload finalization requires POST.")
            with SessionLocal() as db:
                identity = get_session_identity(request, db)
            if identity is None:
                raise HTTPException(401, "Authentication required.")
            owner = _owner(request)
            body = await _json(request)
            keys, fields = body.get("files"), body.get("fields", [])
            if (not isinstance(keys, list) or not 1 <= len(keys) <= 4
                    or not all(isinstance(key, str) for key in keys)
                    or not isinstance(fields, list) or len(fields) > 1000
                    or any(not isinstance(pair, list) or len(pair) != 2
                           or not all(isinstance(value, str) for value in pair) for pair in fields)):
                raise HTTPException(400, "Invalid upload envelope.")
            for key in keys:
                session = await _operation(upload_store.get, key, owner)
                _policy(request.url.path, session.field, identity)
            sessions = await _operation(upload_store.claim, keys, owner, request.url.path)
            try:
                # FastAPI calls Request.form(); pre-populating its form cache avoids
                # copying multi-GiB files through the multipart spool a second time.
                request._form = FormData([*map(tuple, fields), *(
                    (s.field, UploadFile(s.file, size=s.size, filename=s.filename)) for s in sessions
                )])
                if request.url.path.endswith("/vcf-helper/sddc-manager/ovas/upload"):
                    if len(sessions) != 1:
                        raise HTTPException(400, "Choose exactly one OVA.")
                    # The OVA handler deliberately accepts a raw byte stream.
                    async def receive() -> dict[str, Any]:
                        data = await anyio.to_thread.run_sync(sessions[0].file.read, CHUNK_BYTES)
                        return {"type": "http.request", "body": data, "more_body": bool(data)}
                    from urllib.parse import quote
                    scope = dict(request.scope)
                    scope["headers"] = [(k, v) for k, v in scope["headers"]
                                        if k not in {b"content-type", b"content-length", b"x-atlaso-filename"}]
                    scope["headers"] += [(b"content-type", b"application/octet-stream"),
                                         (b"x-atlaso-filename", quote(sessions[0].filename).encode())]
                    request = Request(scope, receive)
                return await original(request)
            finally:
                upload_store.release(keys)

        return handle
