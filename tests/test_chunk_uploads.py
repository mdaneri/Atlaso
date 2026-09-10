"""Verify retry, ownership, finalization, and bounded staging contracts."""

import hashlib
import io
import time
from functools import partial

import pytest

from atlaso.app.services.chunk_uploads import UploadError, UploadStore, upload_store
from atlaso.app.services.vcf_sddc_upload import store_sddc_ova_upload
from tests.routers.ui.helpers import login
from tests.test_vcf_sddc_deployment import write_ova

BASE = "/ui/management/uploads/chunks"
OVA = "/ui/management/vcf-helper/sddc-manager/ovas/upload"


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
    monkeypatch.setattr(network_routes, "network_boot_upload_path", lambda job_id: tmp_path / job_id / "artifact")
    headers, key = start(client, target, field, "invalid.bin")
    assert append(client, headers, key, 0, b"abcdef").status_code == 200
    response = client.post(target, headers={**headers, "X-Atlaso-Chunked": "1", "Accept": "application/json",
                                          "X-Atlaso-Upload": "1"},
                           json={"files": [key], "fields": [["csrf", headers["X-CSRF-Token"]]]})
    assert response.status_code in ({202} if target.startswith("/api/") else {400, 422}), response.text
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
