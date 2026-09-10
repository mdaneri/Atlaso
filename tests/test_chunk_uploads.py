"""Verify retry, ownership, finalization, and bounded staging contracts."""

import hashlib
import io
import threading
import time
from functools import partial

import pytest

from atlaso.app.services.chunk_uploads import UploadError, UploadStore, upload_store
from atlaso.app.services.vcf_sddc_upload import store_sddc_ova_upload
from tests.routers.ui.helpers import login
from tests.test_vcf_sddc_deployment import write_ova

BASE = "/ui/management/uploads/chunks"
OVA = "/ui/management/vcf-helper/sddc-manager/ovas/upload"


@pytest.mark.parametrize("target,field,constant,filename", [
    (OVA, "ova_file", "vcf_sddc_upload.SDDC_MANAGER_OVA_ROOT", "existing.ova"),
    ("/ui/management/esxi-pxe/isos/upload", "iso_file", "esxi_pxe.ESXI_INSTALLER_ISO_ROOT", "existing.iso"),
    ("/ui/management/vcf-offline-depot/tool-package", "tool_archive_file",
     "vcf_offline_depot.VCF_DEPOT_UPLOAD_DIR", "vcf-download-tool-existing.tar.gz"),
])
def test_existing_media_requires_revision_bound_consent(client, tmp_path, monkeypatch, target, field, constant, filename):
    """Reserve no storage before confirmation and reject a stale warning token.

    Args:
        client: Isolated authenticated application client.
        tmp_path: Isolated destination directory.
        monkeypatch: Fixture replacing the canonical media root.
        target: Media endpoint under test.
        field: Corresponding browser file field.
        constant: Service constant that owns the destination.
        filename: Existing media basename.
    """
    monkeypatch.setattr("atlaso.app.services." + constant, tmp_path)
    destination = tmp_path / filename
    destination.write_bytes(b"original")
    login(client)
    page = client.get("/ui/management/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    headers = {"X-CSRF-Token": csrf}
    body = {"target": target, "field": field, "filename": filename, "size": 6}
    before = set(upload_store.sessions)
    warning = client.post(BASE, headers=headers, json=body)
    assert warning.status_code == 409
    assert warning.json()["code"] == "overwrite_required"
    assert set(upload_store.sessions) == before
    assert destination.read_bytes() == b"original"
    destination.write_bytes(b"newer file")
    stale = client.post(BASE, headers=headers, json={**body, "overwrite_token": warning.json()["overwrite_token"]})
    assert stale.status_code == 409
    confirmed = client.post(BASE, headers=headers, json={**body, "overwrite_token": stale.json()["overwrite_token"]})
    assert confirmed.status_code == 200
    key = confirmed.json()["id"]
    assert upload_store.sessions[key].publication.expected is not None
    assert destination.read_bytes() == b"newer file"
    client.delete(BASE + "/data", headers={**headers, "X-Atlaso-Upload-Id": key})


@pytest.mark.parametrize("filename", [" installer.iso", "installer.iso "])
@pytest.mark.parametrize("existing", [False, True])
def test_iso_consent_and_publication_share_canonical_filename(client, tmp_path, monkeypatch, filename, existing):
    """Trim ISO names consistently before warning and final publication.

    Args:
        client: Isolated application test client.
        tmp_path: Isolated media directory.
        monkeypatch: Fixture replacing the canonical ISO root.
        filename: Browser name containing surrounding whitespace.
        existing: Whether an overwrite confirmation is required.
    """
    root = tmp_path / "isos"
    root.mkdir()
    monkeypatch.setattr("atlaso.app.services.esxi_pxe.ESXI_INSTALLER_ISO_ROOT", root)
    destination = root / "installer.iso"
    if existing:
        destination.write_bytes(b"previous")
    login(client)
    page = client.get("/ui/management/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    headers = {"X-CSRF-Token": csrf}
    target = "/ui/management/esxi-pxe/isos/upload"
    envelope = {"target": target, "field": "iso_file", "filename": filename, "size": 6}
    response = client.post(BASE, headers=headers, json=envelope)
    if existing:
        assert response.status_code == 409
        assert destination.read_bytes() == b"previous"
        response = client.post(BASE, headers=headers,
                               json={**envelope, "overwrite_token": response.json()["overwrite_token"]})
    assert response.status_code == 200, response.text
    key = response.json()["id"]
    assert append(client, headers, key, 0, b"abcdef").status_code == 200
    result = client.post(target, headers={**headers, "X-Atlaso-Chunked": "1", "X-Atlaso-Upload": "1"},
                         json={"files": [key], "fields": [["csrf", csrf]]})
    assert result.status_code == 200, result.text
    assert result.json()["name"] == "installer.iso"
    assert destination.read_bytes() == b"abcdef"
    assert [p.name for p in root.iterdir()] == ["installer.iso"]


def test_chunk_admission_requires_destination_permissions():
    """Reject staging before bytes are accepted when destination scope is missing."""
    from fastapi import HTTPException

    from atlaso.app.routers.chunk_uploads import _policy
    from atlaso.app.security import Identity

    viewer = Identity("viewer", "viewer", {"read:repository"})
    for target, field in [(OVA, "ova_file"),
                          ("/ui/management/vcf-offline-depot/tool-package", "tool_archive_file"),
                          ("/ui/management/vcf-private-registry/settings", "ca_bundle_file")]:
        with pytest.raises(HTTPException) as error:
            _policy(target, field, viewer)
        assert error.value.status_code == 403


def test_store_retry_checksum_offset_and_claim():
    store = UploadStore()
    try:
        key = store.create("a", OVA, "ova_file", "test.ova", 6)
        digest = hashlib.sha256(b"abc").hexdigest()
        assert store.append(key, "a", 0, b"abc", digest) == 3
        assert store.append(key, "a", 0, b"abc", digest) == 3
        for owner, offset, data, checksum, status in [
            ("b", 0, b"abc", digest, 404),
            ("a", 4, b"abc", digest, 413),
            ("a", 2, b"abc", digest, 409),
            ("a", 3, b"abc", "wrong", 400),
        ]:
            with pytest.raises(UploadError) as error:
                store.append(key, owner, offset, data, checksum)
            assert error.value.status == status
        with pytest.raises(UploadError):
            store.claim([key], "a", OVA)
        store.append(key, "a", 3, b"abc", digest)
        with pytest.raises(UploadError):
            store.claim([key], "a", "/different")
        session = store.claim([key], "a", OVA)[0]
        assert session.file.read() == b"abcabc"
        with pytest.raises(UploadError):
            store.claim([key], "a", OVA)
        store.release([key])
        assert session.file.closed and not store.sessions
    finally:
        store.close()


def test_capacity_expiry_and_cancel():
    store = UploadStore()
    try:
        keys = [store.create("a", OVA, "ova_file", "test.ova", 1) for _ in range(4)]
        with pytest.raises(UploadError) as error:
            store.create("a", OVA, "ova_file", "test.ova", 1)
        assert error.value.status == 429
        handle = store.sessions[keys[0]].file
        store.sessions[keys[0]].expires = time.monotonic() - 1
        store._sweep()
        assert handle.closed
        store.cancel(keys[1], "a")
        assert keys[1] not in store.sessions
    finally:
        store.close()


def test_large_files_use_private_disk_staging_and_release_it(tmp_path, monkeypatch):
    """Exercise the large-media path independently of in-memory credential staging.

    Args:
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture isolating the storage volume from the appliance.
    """
    import atlaso.app.services.chunk_uploads as service
    root = tmp_path / "uploads"
    monkeypatch.setattr(service, "UPLOAD_ROOT", root)
    store = UploadStore()
    try:
        key = store.create("a", OVA, "ova_file", "test.ova", 17 * 1024**2)
        assert not isinstance(store.sessions[key].file, io.BytesIO)
        data = b"x" * 1024**2
        for offset in range(17):
            store.append(key, "a", offset * len(data), data, hashlib.sha256(data).hexdigest())
        session = store.claim([key], "a", OVA)[0]
        assert session.file.read(3) == b"xxx"
        store.release([key])
        assert session.file.closed
        assert list(root.iterdir()) == []
    finally:
        store.close()


def start(client, target=OVA, field="ova_file", filename="test.ova", size=6):
    """Create a session using the real authenticated browser and CSRF flow.

    Args:
        client: Isolated authenticated application test client.
        target: Exact destination endpoint path bound to this file.
        field: Existing endpoint file-field name.
        filename: Original basename validated before publication.
        size: Declared total file length in bytes.
    """
    login(client)
    page = client.get("/ui/management/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    headers = {"X-CSRF-Token": csrf}
    response = client.post(BASE, headers=headers, json={"target": target, "field": field,
                                                       "filename": filename, "size": size})
    assert response.status_code == 200, response.text
    return headers, response.json()["id"]


def append(client, headers, key, offset, data):
    """Send a chunk with its integrity and offset headers.

    Args:
        client: Isolated authenticated application test client.
        headers: Authenticated request headers including CSRF.
        key: Opaque process-local upload identifier.
        offset: Expected contiguous byte offset.
        data: Bytes supplied by this test or upload chunk.
    """
    return client.put(BASE + "/data", content=data, headers={**headers,
        "X-Atlaso-Upload-Id": key, "X-Atlaso-Upload-Offset": str(offset),
        "X-Atlaso-Chunk-SHA256": hashlib.sha256(data).hexdigest()})


def test_ova_chunks_reach_existing_validator_once(client, tmp_path, monkeypatch):
    """Test ova chunks reach existing validator once.

    Args:
        client: Isolated authenticated application test client.
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture replacing external dependencies with isolated test behavior.
    """
    import atlaso.app.routers.ui.vcf_workflows as routes
    root = tmp_path / "component"
    monkeypatch.setattr("atlaso.app.services.vcf_sddc_upload.SDDC_MANAGER_OVA_ROOT", root)
    monkeypatch.setattr(routes, "store_sddc_ova_upload", partial(store_sddc_ova_upload, root=root))
    source = tmp_path / "source.ova"
    write_ova(source)
    data = source.read_bytes()
    headers, key = start(client, size=len(data))
    split = len(data) // 2
    assert append(client, headers, key, 0, data[:split]).status_code == 200
    assert not root.exists()
    assert append(client, headers, key, 0, data[:split]).json()["offset"] == split
    assert append(client, headers, key, split, data[split:]).status_code == 200
    response = client.post(OVA, headers={**headers, "X-Atlaso-Chunked": "1"}, json={"files": [key]})
    assert response.status_code == 200, response.text
    assert (root / "test.ova").read_bytes() == data
    assert key not in upload_store.sessions
    assert client.post(OVA, headers={**headers, "X-Atlaso-Chunked": "1"}, json={"files": [key]}).status_code == 404
    envelope = {"target": OVA, "field": "ova_file", "filename": "test.ova", "size": len(data)}
    warning = client.post(BASE, headers=headers, json=envelope)
    assert warning.status_code == 409
    confirmation = client.post(BASE, headers=headers,
                               json={**envelope, "overwrite_token": warning.json()["overwrite_token"]})
    replacement = confirmation.json()["id"]
    assert append(client, headers, replacement, 0, data).status_code == 200
    result = client.post(OVA, headers={**headers, "X-Atlaso-Chunked": "1"}, json={"files": [replacement]})
    assert result.status_code == 200, result.text
    assert (root / "test.ova").read_bytes() == data


@pytest.mark.parametrize("target,field", [
    ("/ui/management/esxi-pxe/isos/upload", "iso_file"),
    ("/ui/management/vcf-offline-depot/tool-package", "tool_archive_file"),
    ("/ui/management/vcf-offline-depot/tool-configuration", "download_token_file"),
    ("/ui/management/backup-restore/restore", "archive_file"),
    ("/api/v1/network-boot/environments/inventory/upload", "artifact"),
])
def test_file_transport_preserves_endpoint_validation(client, target, field, tmp_path, monkeypatch):
    """Test file transport preserves endpoint validation.

    Args:
        client: Isolated authenticated application test client.
        target: Exact destination endpoint path bound to this file.
        field: Existing endpoint file-field name.
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture replacing external dependencies with isolated test behavior.
    """
    import atlaso.app.api.network_boot as network_routes
    import atlaso.app.routers.chunk_uploads as chunk_routes

    caller_threads = []
    release_threads = []
    original_json = chunk_routes._json
    original_release = upload_store.release

    async def observed_json(request):
        """Record the request event loop thread.

        Args:
            request: Incoming finalization envelope.
        """
        caller_threads.append(threading.get_ident())
        return await original_json(request)

    def observed_release(keys):
        """Record cleanup and close the real staged handles.

        Args:
            keys: Claimed upload identifiers to release.
        """
        release_threads.append(threading.get_ident())
        original_release(keys)

    monkeypatch.setattr(chunk_routes, "_json", observed_json)
    monkeypatch.setattr(upload_store, "release", observed_release)
    monkeypatch.setattr(network_routes, "network_boot_upload_path", lambda job_id: tmp_path / job_id / "artifact")
    monkeypatch.setattr("atlaso.app.services.esxi_pxe.ESXI_INSTALLER_ISO_ROOT", tmp_path / "isos")
    filename = {"iso_file": "installer.iso", "tool_archive_file": "vcf-download-tool-invalid.tar.gz"}.get(field, "invalid.bin")
    headers, key = start(client, target, field, filename)
    assert append(client, headers, key, 0, b"abcdef").status_code == 200
    response = client.post(target, headers={**headers, "X-Atlaso-Chunked": "1", "Accept": "application/json",
                                          "X-Atlaso-Upload": "1"},
                           json={"files": [key], "fields": [["csrf", headers["X-CSRF-Token"]]]})
    expected = {202} if target.startswith("/api/") else {200} if field == "iso_file" else {400, 422}
    assert response.status_code in expected, response.text
    assert len(release_threads) == 1
    assert release_threads[0] != caller_threads[-1]
    assert key not in upload_store.sessions


def test_admission_rejects_csrf_unknown_field_and_oversize(client):
    """Test admission rejects csrf unknown field and oversize.

    Args:
        client: Isolated authenticated application test client.
    """
    assert client.post(BASE, json={}, follow_redirects=False).status_code in {401, 303}
    headers, key = start(client)
    body = {"target": OVA, "field": "ova_file", "filename": "test.ova", "size": 1}
    assert client.post(BASE, json=body).status_code == 403
    assert client.post(BASE, headers=headers, json={**body, "field": "unknown"}).status_code == 400
    assert client.post(BASE, headers=headers, json={**body, "size": 17 * 1024**3}).status_code == 413
    assert client.delete(BASE + "/data", headers={**headers, "X-Atlaso-Upload-Id": key}).status_code == 204


def test_canceled_finalization_still_releases_staging(monkeypatch):
    """Close claimed staging off-loop even under an already canceled scope.

    Args:
        monkeypatch: Fixture isolating authentication and the upload store.
    """
    from contextlib import AsyncExitStack, nullcontext

    import anyio
    from fastapi import Request
    from starlette.responses import Response

    import atlaso.app.routers.chunk_uploads as routes

    store = UploadStore()
    key = store.create("owner", "/upload", "file", "test.bin", 1)
    store.append(key, "owner", 0, b"x", hashlib.sha256(b"x").hexdigest())
    staged = store.sessions[key].file
    released = []
    release = store.release

    def observed_release(keys):
        """Capture cleanup's worker thread before closing the staged handle.

        Args:
            keys: Claimed identifiers supplied by the route adapter.
        """
        released.append(threading.get_ident())
        release(keys)

    monkeypatch.setattr(routes, "upload_store", store)
    monkeypatch.setattr(store, "release", observed_release)
    monkeypatch.setattr(routes, "SessionLocal", lambda: nullcontext(None))
    monkeypatch.setattr(routes, "get_session_identity", lambda request, db: object())
    monkeypatch.setattr(routes, "_owner", lambda request: "owner")
    monkeypatch.setattr(routes, "_policy", lambda *args: None)

    async def exercise():
        """Cancel inside the wrapped endpoint and observe mandatory cleanup."""
        caller_thread = threading.get_ident()
        with anyio.CancelScope() as scope:
            async def endpoint():
                """Simulate cancellation after the staged file was claimed."""
                scope.cancel()
                await anyio.lowlevel.checkpoint()
                return Response()

            async def receive():
                """Supply the bounded finalization envelope."""
                return {"type": "http.request", "body": ('{"files":["' + key + '"]}').encode()}

            route = routes.ChunkedUploadRoute("/upload", endpoint, methods=["POST"])
            request = Request({"type": "http", "method": "POST", "path": "/upload",
                               "headers": [(b"x-atlaso-chunked", b"1")], "query_string": b""}, receive)
            async with AsyncExitStack() as stack:
                request.scope["fastapi_middleware_astack"] = stack
                request.scope["fastapi_inner_astack"] = stack
                request.scope["fastapi_function_astack"] = stack
                await route.get_route_handler()(request)
        assert scope.cancelled_caught
        assert len(released) == 1 and released[0] != caller_thread
        assert staged.closed and not store.sessions

    try:
        anyio.run(exercise)
    finally:
        store.close()


@pytest.mark.parametrize("filename", ["name with spaces.ova", "café.ova", "percent%20.ova", "a" * 197 + ".ova"])
def test_ova_filename_rejected_before_reservation(client, monkeypatch, filename):
    """Reject unsupported OVA names before allocating or accepting chunks.

    Args:
        client: Authenticated application test client.
        monkeypatch: Fixture preventing any storage reservation.
        filename: Invalid basename that passes generic transport checks.
    """
    from atlaso.app.services.vcf_sddc_upload import UPLOAD_ERROR_MESSAGES

    headers, key = start(client)
    client.delete(BASE + "/data", headers={**headers, "X-Atlaso-Upload-Id": key})

    def forbidden_create(*args, **kwargs):
        """Fail if invalid filenames reach storage admission.

        Args:
            *args: Ignored reservation arguments.
            **kwargs: Ignored reservation keyword arguments.
        """
        pytest.fail("Invalid OVA filename reached storage reservation")

    monkeypatch.setattr(upload_store, "create", forbidden_create)
    response = client.post(BASE, headers=headers, json={"target": OVA, "field": "ova_file",
                                                       "filename": filename, "size": 16 * 1024**3})
    assert response.status_code == 400
    assert response.json()["detail"] == UPLOAD_ERROR_MESSAGES["invalid_filename"]


@pytest.mark.parametrize("target", ["/vcf-offline-depot/settings", "/vcf-offline-depot/tool-package"])
@pytest.mark.parametrize("filename", ["renamed.tar.gz", "vcf-download-tool-with spaces.tar.gz"])
def test_vcfdt_filename_rejected_before_reservation(client, monkeypatch, target, filename):
    """Reject invalid tool names before allocating their potentially large storage.

    Args:
        client: Authenticated application client.
        monkeypatch: Fixture preventing storage allocation.
        target: Supported tool upload endpoint suffix.
        filename: Invalid archive basename.
    """
    headers, key = start(client)
    client.delete(BASE + "/data", headers={**headers, "X-Atlaso-Upload-Id": key})

    def forbidden_create(*args):
        """Reject any unexpected allocation.

        Args:
            *args: Storage admission arguments.
        """
        pytest.fail("Invalid VCFDT name reached storage reservation")

    monkeypatch.setattr(upload_store, "create", forbidden_create)
    response = client.post(BASE, headers=headers, json={
        "target": "/ui/management" + target, "field": "tool_archive_file",
        "filename": filename, "size": 2 * 1024**3,
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "Upload the VCF Download Tool file named vcf-download-tool-*.tar.gz."


@pytest.mark.parametrize("status", [201, 422])
def test_handle_close_failure_preserves_endpoint_result_and_releases_all(monkeypatch, status):
    """A failed first close must neither replace the result nor strand later files.

    Args:
        monkeypatch: Fixture isolating route identity and staged storage.
        status: Success or validation-failure status returned by the endpoint.
    """
    import io
    import json
    from contextlib import AsyncExitStack, nullcontext

    import anyio
    from fastapi import Request
    from starlette.responses import Response

    import atlaso.app.routers.chunk_uploads as routes

    class FailedClose(io.BytesIO):
        """Simulate a handle reporting a filesystem error during close."""

        def close(self):
            """Close the fixture and report the injected error."""
            super().close()
            raise OSError("private staging path")

    store = UploadStore()
    keys = [store.create("owner", "/upload", "file", "test.bin", 1) for _ in range(2)]
    for key in keys:
        store.append(key, "owner", 0, b"x", hashlib.sha256(b"x").hexdigest())
    store.sessions[keys[0]].file.close()
    store.sessions[keys[0]].file = FailedClose(b"x")
    handles = [store.sessions[key].file for key in keys]
    monkeypatch.setattr(routes, "upload_store", store)
    monkeypatch.setattr(routes, "SessionLocal", lambda: nullcontext(None))
    monkeypatch.setattr(routes, "get_session_identity", lambda request, db: object())
    monkeypatch.setattr(routes, "_owner", lambda request: "owner")
    monkeypatch.setattr(routes, "_policy", lambda *args: None)

    async def endpoint():
        """Return the original endpoint outcome after consuming staged data."""
        return Response(b"original outcome", status_code=status)

    async def receive():
        """Provide the finalization envelope for both staged files."""
        return {"type": "http.request", "body": json.dumps({"files": keys}).encode()}

    async def exercise():
        """Run the actual route adapter including its shielded worker cleanup."""
        route = routes.ChunkedUploadRoute("/upload", endpoint, methods=["POST"])
        request = Request({"type": "http", "method": "POST", "path": "/upload",
                           "headers": [(b"x-atlaso-chunked", b"1")], "query_string": b""}, receive)
        async with AsyncExitStack() as stack:
            for name in ("fastapi_middleware_astack", "fastapi_inner_astack", "fastapi_function_astack"):
                request.scope[name] = stack
            response = await route.get_route_handler()(request)
        assert response.status_code == status
        assert response.body == b"original outcome"
        assert all(handle.closed for handle in handles)
        assert not store.sessions

    try:
        anyio.run(exercise)
    finally:
        store.close()


@pytest.mark.parametrize("shutdown", [False, True])
def test_sweep_and_shutdown_continue_after_close_failure(monkeypatch, shutdown):
    """Failed closes cannot stop later cleanup or disable expiry scheduling.

    Args:
        monkeypatch: Fixture replacing timers with deterministic callbacks.
        shutdown: Whether to exercise shutdown or repeated expiry sweeps.
    """
    import atlaso.app.services.chunk_uploads as service

    timers = []

    class Timer:
        """Record scheduling without starting background threads."""

        def __init__(self, interval, callback):
            """Retain the scheduled callback.

            Args:
                interval: Requested sweep delay.
                callback: Expiry callback.
            """
            self.callback = callback
            self.canceled = False
            timers.append(self)

        def start(self):
            """Leave execution under the test's control."""

        def cancel(self):
            """Record shutdown cancellation."""
            self.canceled = True

    class FailedClose(io.BytesIO):
        """Close normally then simulate a filesystem error."""

        def close(self):
            """Report a failure after releasing this fixture's buffer."""
            super().close()
            raise OSError("staging close failed")

    monkeypatch.setattr(service.threading, "Timer", Timer)
    store = UploadStore()
    keys = [store.create("owner", OVA, "ova_file", "test.ova", 1) for _ in range(4)]
    store.sessions[keys[0]].file.close()
    store.sessions[keys[0]].file = FailedClose()
    handles = [store.sessions[key].file for key in keys]
    for key in keys[:2]:
        store.sessions[key].expires = 0
    store.sessions[keys[3]].claimed = True
    store.sessions[keys[3]].expires = 0
    try:
        if shutdown:
            store.close()
            assert timers[0].canceled and store.timer is None
            assert not store.sessions and all(handle.closed for handle in handles)
        else:
            timers[0].callback()
            assert all(handle.closed for handle in handles[:2])
            assert set(store.sessions) == set(keys[2:])
            assert not any(handle.closed for handle in handles[2:])
            assert len(timers) == 2 and store.timer is timers[1]
            key = store.create("owner", OVA, "ova_file", "new.ova", 1)
            store.cancel(key, "owner")
            store.sessions[keys[2]].expires = 0
            timers[1].callback()
            assert handles[2].closed and not handles[3].closed
            assert len(timers) == 3 and store.timer is timers[2]
    finally:
        store.close()
