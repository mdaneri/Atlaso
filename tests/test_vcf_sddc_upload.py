"""Exercise manual OVA intake publication, validation, and admission boundaries."""

import asyncio
from functools import partial

import pytest

from atlaso.app.services.vcf_sddc_deployment import ova_inventory
from atlaso.app.services.vcf_sddc_upload import SddcUploadError, store_sddc_ova_upload
from tests.routers.ui.helpers import login
from tests.test_vcf_sddc_deployment import write_ova


async def chunks(data):
    """Supply several chunks to exercise streaming size accounting.

    Args:
        data: Bytes supplied by this test or upload chunk.
    """
    for offset in range(0, len(data), 1024):
        yield data[offset:offset + 1024]


def test_upload_publishes_into_vcfdt_layout_and_rejects_duplicates(tmp_path):
    """Test upload publishes into vcfdt layout and rejects duplicates.

    Args:
        tmp_path: Task-owned temporary directory supplied by pytest.
    """
    source = tmp_path / "original.ova"
    write_ova(source)
    root = tmp_path / "PROD" / "COMP" / "SDDC_MANAGER_VCF"
    result = asyncio.run(store_sddc_ova_upload(chunks(source.read_bytes()), source.name, root=root))
    assert result["relative_path"] == source.name
    assert (root / source.name).read_bytes() == source.read_bytes()
    assert ova_inventory(root=root)[0]["filename"] == source.name
    with pytest.raises(SddcUploadError) as error:
        asyncio.run(store_sddc_ova_upload(chunks(b"replacement"), source.name, root=root))
    assert error.value.status_code == 409
    assert (root / source.name).read_bytes() == source.read_bytes()
    assert not list(root.parent.glob(".sddc-upload-*"))


@pytest.mark.parametrize("name", ["../test.ova", "x/test.ova", "x\\test.ova", "test.iso", ".hidden.ova", "x%2Ftest.ova"])
def test_upload_rejects_unsafe_names_before_storage(tmp_path, name):
    """Test upload rejects unsafe names before storage.

    Args:
        tmp_path: Task-owned temporary directory supplied by pytest.
        name: Filename under validation.
    """
    root = tmp_path / "root"
    with pytest.raises(SddcUploadError):
        asyncio.run(store_sddc_ova_upload(chunks(b"invalid"), name, root=root))
    assert not root.exists()


@pytest.mark.parametrize("kind", ["empty", "invalid", "corrupt", "oversized", "disconnected"])
def test_failed_upload_never_enters_inventory(tmp_path, kind):
    """Test failed upload never enters inventory.

    Args:
        tmp_path: Task-owned temporary directory supplied by pytest.
        kind: Failure mode exercised by this test.
    """
    source = tmp_path / "source.ova"
    write_ova(source, corrupt_manifest=kind == "corrupt")
    data = source.read_bytes()
    if kind == "empty":
        data = b""
    elif kind == "invalid":
        data = b"not an OVA"
    root = tmp_path / "component"

    async def interrupted():
        yield data[:1024]
        assert ova_inventory(root=root) == []
        raise ConnectionError("disconnected")

    with pytest.raises((SddcUploadError, ConnectionError)):
        asyncio.run(store_sddc_ova_upload(
            interrupted() if kind == "disconnected" else chunks(data), "test.ova", root=root,
            max_bytes=100 if kind == "oversized" else 1024**2,
        ))
    assert ova_inventory(root=root) == []
    assert not list(root.parent.glob(".sddc-upload-*"))


def test_upload_atomic_publication_preserves_concurrent_winner(tmp_path, monkeypatch):
    """Test upload atomic publication preserves concurrent winner.

    Args:
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture replacing external dependencies with isolated test behavior.
    """
    import atlaso.app.services.vcf_sddc_upload as service

    source = tmp_path / "source.ova"
    write_ova(source)
    root = tmp_path / "component"
    actual_link = service.os.link

    def competing_link(staged, destination):
        """Competing link.

        Args:
            staged: Private source file for atomic publication.
            destination: Final artifact path used in the publication race test.
        """
        destination.write_bytes(b"winner")
        actual_link(staged, destination)

    monkeypatch.setattr(service.os, "link", competing_link)
    with pytest.raises(SddcUploadError) as error:
        asyncio.run(store_sddc_ova_upload(chunks(source.read_bytes()), "test.ova", root=root))
    assert error.value.status_code == 409
    assert (root / "test.ova").read_bytes() == b"winner"
    assert not list(root.parent.glob(".sddc-upload-*"))


def test_upload_route_checks_csrf_and_uses_canonical_service(client, tmp_path, monkeypatch):
    """Test upload route checks csrf and uses canonical service.

    Args:
        client: Isolated authenticated application test client.
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture replacing external dependencies with isolated test behavior.
    """
    import atlaso.app.routers.ui.vcf_workflows as routes

    root = tmp_path / "component"
    monkeypatch.setattr(routes, "store_sddc_ova_upload", partial(store_sddc_ova_upload, root=root))
    login(client)
    page = client.get("/ui/management/vcf-helper")
    assert "data-sddc-ova-upload-open" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    url = "/ui/management/vcf-helper/sddc-manager/ovas/upload"
    headers = {"Content-Type": "application/octet-stream", "X-Atlaso-Filename": "test.ova"}
    assert client.post(url, headers=headers, content=b"invalid").status_code == 403
    assert not root.exists()
    source = tmp_path / "source.ova"
    write_ova(source)
    headers["X-CSRF-Token"] = csrf
    response = client.post(url, headers=headers, content=source.read_bytes())
    assert response.status_code == 200, response.text
    assert response.json()["filename"] == "test.ova"
    assert ova_inventory(root=root)[0]["filename"] == "test.ova"


@pytest.mark.parametrize("role,expected", [("service-admin", 200), ("network-admin", 403), ("viewer", 403)])
def test_upload_route_enforces_roles_before_streaming(client, tmp_path, monkeypatch, role, expected):
    """Test upload route enforces roles before streaming.

    Args:
        client: Isolated authenticated application test client.
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture replacing external dependencies with isolated test behavior.
        role: Role whose upload permission is tested.
        expected: Expected HTTP admission status.
    """
    import atlaso.app.routers.ui.vcf_workflows as routes
    from atlaso.app.security import Identity, require_session_identity

    login(client)
    page = client.get("/ui/management/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    root = tmp_path / "component"
    monkeypatch.setattr(routes, "store_sddc_ova_upload", partial(store_sddc_ova_upload, root=root))
    source = tmp_path / "source.ova"
    write_ova(source)
    client.app.dependency_overrides[require_session_identity] = lambda: Identity("operator", role, set())
    try:
        response = client.post(
            "/ui/management/vcf-helper/sddc-manager/ovas/upload",
            headers={"Content-Type": "application/octet-stream", "X-Atlaso-Filename": "test.ova", "X-CSRF-Token": csrf},
            content=source.read_bytes(),
        )
        assert response.status_code == expected, response.text
        assert root.exists() == (expected == 200)
    finally:
        client.app.dependency_overrides.clear()


def test_upload_proxy_is_scoped_to_management_endpoint():
    from atlaso.app.services.public_services import _management_ui_proxy_locations

    text = "\n".join(_management_ui_proxy_locations("127.0.0.1", 8000))
    location = text.split("location = /ui/management/vcf-helper/sddc-manager/ovas/upload {", 1)[1].split("}", 1)[0]
    assert "client_max_body_size 16g;" in location
    assert "proxy_request_buffering off;" in location
    assert "proxy_http_version 1.1;" in location
    assert "proxy_set_header X-Atlaso-Listener-Address $server_addr;" in location


def test_storage_error_does_not_expose_underlying_exception(tmp_path, monkeypatch):
    """Test storage error does not expose underlying exception.

    Args:
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture replacing external dependencies with isolated test behavior.
    """
    import atlaso.app.services.vcf_sddc_upload as service

    root = tmp_path / "component"
    root.mkdir()

    def fail_staging(*args, **kwargs):
        """Fail staging.

        Args:
            *args: Arguments forwarded to the storage operation or injected test callback.
            **kwargs: Keyword arguments accepted by the injected test callback.
        """
        raise OSError("private filesystem diagnostics")

    monkeypatch.setattr(service.tempfile, "TemporaryDirectory", fail_staging)
    with pytest.raises(SddcUploadError) as error:
        asyncio.run(store_sddc_ova_upload(chunks(b"test"), "test.ova", root=root))
    assert error.value.code == "storage_error"
    assert "private" not in service.UPLOAD_ERROR_MESSAGES[error.value.code]


def test_audit_failure_rolls_back_published_ova(client, tmp_path, monkeypatch):
    """Test audit failure rolls back published ova.

    Args:
        client: Isolated authenticated application test client.
        tmp_path: Task-owned temporary directory supplied by pytest.
        monkeypatch: Fixture replacing external dependencies with isolated test behavior.
    """
    import atlaso.app.routers.ui.vcf_workflows as routes

    root = tmp_path / "component"
    monkeypatch.setattr(routes, "store_sddc_ova_upload", partial(store_sddc_ova_upload, root=root))
    login(client)
    page = client.get("/ui/management/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    def failed_audit(*args, **kwargs):
        """Failed audit.

        Args:
            *args: Arguments forwarded to the storage operation or injected test callback.
            **kwargs: Keyword arguments accepted by the injected test callback.
        """
        raise RuntimeError("private database failure")

    monkeypatch.setattr(routes, "record_audit", failed_audit)
    source = tmp_path / "source.ova"
    write_ova(source)
    response = client.post("/ui/management/vcf-helper/sddc-manager/ovas/upload", content=source.read_bytes(),
                           headers={"Content-Type": "application/octet-stream", "X-CSRF-Token": csrf,
                                    "X-Atlaso-Filename": "test.ova"})
    assert response.status_code == 503
    assert "rolled back" in response.json()["detail"]
    assert "private" not in response.text
    assert ova_inventory(root=root) == []
    assert not list(root.parent.glob(".sddc-upload-*"))
