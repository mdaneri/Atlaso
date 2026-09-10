"""Exercise manual OVA intake publication, validation, and admission boundaries."""

import asyncio
import io
import tarfile
import threading
from functools import partial

import pytest

from atlaso.app.services.vcf_sddc_deployment import ova_inventory
from atlaso.app.services.vcf_sddc_upload import SddcUploadError, store_sddc_ova_upload
from tests.routers.ui.helpers import login
from tests.test_vcf_sddc_deployment import write_ova


@pytest.mark.parametrize("kind", ["members", "descriptor", "manifest", "pax", "longname"])
def test_ova_metadata_limits_precede_deployment_parser(tmp_path, monkeypatch, kind):
    """Reject excessive metadata before the general parser allocates it.

    Args:
        tmp_path: Private test archive directory.
        monkeypatch: Fixture isolating parser entry and member-count limit.
        kind: Excessive archive structure under test.
    """
    import atlaso.app.services.vcf_sddc_upload as service
    path = tmp_path / "input.ova"
    if kind == "members":
        monkeypatch.setattr(service, "OVA_MAX_MEMBERS", 2)
        with tarfile.open(path, "w") as archive:
            for index in range(3):
                archive.addfile(tarfile.TarInfo(f"member-{index}"), io.BytesIO())
    else:
        member = tarfile.TarInfo("descriptor.ovf" if kind == "descriptor" else "manifest.mf")
        member.size = service.OVA_MAX_OVF_BYTES + 1 if kind == "descriptor" else 1024**2 + 1
        if kind in {"pax", "longname"}:
            member.type = tarfile.XHDTYPE if kind == "pax" else tarfile.GNUTYPE_LONGNAME
            member.size = service.OVA_MAX_METADATA_BYTES + 1
        path.write_bytes(member.tobuf() + b"\0" * 1024)

    def forbidden_parser(*args, **kwargs):
        """Prove the unrestricted parser is never reached.

        Args:
            *args: Ignored parser arguments.
            **kwargs: Ignored parser keyword arguments.
        """
        pytest.fail("Deployment parser reached before metadata limits")

    monkeypatch.setattr(service, "inspect_ova", forbidden_parser)
    with pytest.raises(SddcUploadError, match="validation"):
        service._validate_staged_ova(path)


def test_staging_writes_and_flush_run_outside_event_loop(tmp_path, monkeypatch):
    """Verify blocking file operations never execute on the async caller thread.

    Args:
        tmp_path: Private staging directory.
        monkeypatch: Fixture instrumenting staging writes and flush.
    """
    from pathlib import Path

    import atlaso.app.services.vcf_sddc_upload as service
    source = tmp_path / "source.ova"
    write_ova(source)
    data = source.read_bytes()
    caller = threading.get_ident()
    operations = []
    actual_open, actual_flush = Path.open, service._flush_staged_file

    class CheckedFile:
        """Record the worker identity at each blocking staging operation."""

        def __init__(self, wrapped):
            """Keep the real staging handle.

            Args:
                wrapped: File receiving staged bytes.
            """
            self.wrapped = wrapped

        def write(self, value):
            """Assert file writes use a worker.

            Args:
                value: Current upload chunk.
            """
            assert threading.get_ident() != caller
            operations.append("write")
            return self.wrapped.write(value)

        def close(self):
            assert threading.get_ident() != caller
            self.wrapped.close()

    def checked_open(path, mode="r", *args, **kwargs):
        """Wrap only the upload's writable staging handle.

        Args:
            path: File being opened.
            mode: Requested file mode.
            *args: Positional arguments for the underlying file.
            **kwargs: Keyword arguments for the underlying file.
        """
        result = actual_open(path, mode, *args, **kwargs)
        return CheckedFile(result) if mode == "xb" else result

    def checked_flush(target):
        """Assert fsync and buffered flush use the worker.

        Args:
            target: Wrapped upload staging handle.
        """
        assert threading.get_ident() != caller
        operations.append("flush")
        actual_flush(target.wrapped)

    monkeypatch.setattr(Path, "open", checked_open)
    monkeypatch.setattr(service, "_flush_staged_file", checked_flush)
    asyncio.run(store_sddc_ova_upload(chunks(data), "test.ova", root=tmp_path / "component"))
    assert "write" in operations and operations[-1] == "flush"


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
def test_failed_upload_never_enters_inventory(tmp_path, kind, monkeypatch):
    """Test failed upload never enters inventory.

    Args:
        tmp_path: Task-owned temporary directory supplied by pytest.
        kind: Failure mode exercised by this test.
        monkeypatch: Fixture observing private staging removal.
    """
    import atlaso.app.services.vcf_sddc_upload as service

    caller = threading.get_ident()
    cleanup_calls = []
    actual_cleanup = service.tempfile.TemporaryDirectory.cleanup

    def checked_cleanup(staging):
        """Observe real directory removal outside the request thread.

        Args:
            staging: Temporary directory holding the rejected OVA.
        """
        cleanup_calls.append(threading.get_ident())
        actual_cleanup(staging)

    monkeypatch.setattr(service.tempfile.TemporaryDirectory, "cleanup", checked_cleanup)
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
    assert len(cleanup_calls) == 1 and cleanup_calls[0] != caller


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


@pytest.mark.parametrize("failure", ["refresh", "operational_log"])
def test_post_commit_reporting_failure_preserves_published_ova(client, tmp_path, monkeypatch, failure):
    """Keep publication aligned with its durable success audit.

    Args:
        client: Isolated application client.
        tmp_path: Private upload destination.
        monkeypatch: Fixture injecting post-commit reporting failures.
        failure: Reporting stage that fails after the database commit.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    import atlaso.app.audit as audit
    import atlaso.app.routers.ui.vcf_workflows as routes
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent

    root = tmp_path / "component"
    monkeypatch.setattr(routes, "store_sddc_ova_upload", partial(store_sddc_ova_upload, root=root))
    login(client)
    page = client.get("/ui/management/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    actual_refresh = Session.refresh

    def failed_refresh(db, event, *args, **kwargs):
        """Fail only the committed upload audit refresh.

        Args:
            db: Active database session.
            event: Row being refreshed.
            *args: Extra refresh arguments.
            **kwargs: Extra refresh keyword arguments.
        """
        if isinstance(event, AuditEvent):
            raise RuntimeError("post-commit refresh failure")
        return actual_refresh(db, event, *args, **kwargs)

    def failed_log(event):
        """Simulate optional operational logging being unavailable.

        Args:
            event: Already committed audit event.
        """
        raise RuntimeError("post-commit logging failure")

    if failure == "refresh":
        monkeypatch.setattr(Session, "refresh", failed_refresh)
    else:
        monkeypatch.setattr(audit, "log_audit_event", failed_log)
    source = tmp_path / "source.ova"
    write_ova(source)
    response = client.post("/ui/management/vcf-helper/sddc-manager/ovas/upload", content=source.read_bytes(),
                           headers={"Content-Type": "application/octet-stream", "X-CSRF-Token": csrf,
                                    "X-Atlaso-Filename": "test.ova"})
    assert response.status_code == 200, response.text
    assert (root / "test.ova").read_bytes() == source.read_bytes()
    with SessionLocal() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "upload_vcf_sddc_ova"))
        assert event is not None and event.success


@pytest.mark.parametrize("sizes", [(1025,), (600, 600)])
def test_sparse_logical_sizes_are_bounded_before_hashing(tmp_path, monkeypatch, sizes):
    """Reject individual and aggregate sparse expansion before parser or hashing.

    Args:
        tmp_path: Isolated archive directory.
        monkeypatch: Fixture setting a small logical limit and guarding parsers.
        sizes: Logical sizes declared by physically tiny sparse disk members.
    """
    import atlaso.app.services.vcf_sddc_upload as service

    monkeypatch.setattr(service, "SDDC_OVA_MAX_BYTES", 1024)
    path = tmp_path / "sparse.ova"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for index, size in enumerate(sizes):
            member = tarfile.TarInfo(f"disk-{index}.vmdk")
            member.size = 1
            member.pax_headers = {"GNU.sparse.map": "0,1", "GNU.sparse.size": str(size)}
            archive.addfile(member, io.BytesIO(b"x"))
    with tarfile.open(path) as archive:
        members = list(archive)
        assert tuple(member.size for member in members) == sizes
        assert all(member.sparse == [(0, 1)] for member in members)

    def forbidden_parser(*args, **kwargs):
        """Ensure sparse expansion cannot reach discovery or hashing.

        Args:
            *args: Ignored validation arguments.
            **kwargs: Ignored validation keyword arguments.
        """
        pytest.fail("Sparse logical expansion reached parser or hashing")

    monkeypatch.setattr(service, "inspect_ova", forbidden_parser)
    monkeypatch.setattr(service, "validate_ova_manifest", forbidden_parser)
    with pytest.raises(SddcUploadError, match="validation"):
        service._validate_staged_ova(path)


@pytest.mark.parametrize("algorithm", ["SHA256", "SHA512"])
def test_duplicate_manifest_members_rejected_before_hashing(tmp_path, monkeypatch, algorithm):
    """Bound repeated hashing even when a duplicate uses another digest algorithm.

    Args:
        tmp_path: Private archive directory.
        monkeypatch: Fixture guarding manifest hashing.
        algorithm: Digest algorithm of the repeated member entry.
    """
    import atlaso.app.services.vcf_sddc_upload as service

    source = tmp_path / "source.ova"
    write_ova(source)
    path = tmp_path / "duplicate.ova"
    with tarfile.open(source) as original, tarfile.open(path, "w") as output:
        for member in original:
            body = original.extractfile(member).read()
            if member.name.endswith(".mf"):
                body += f"{algorithm}(disk.vmdk)= {'0' * (128 if algorithm == 'SHA512' else 64)}\n".encode()
                member.size = len(body)
            output.addfile(member, io.BytesIO(body))

    def forbidden_hash(*args, **kwargs):
        """Reject repeated work before the manifest validator starts.

        Args:
            *args: Ignored validator arguments.
            **kwargs: Ignored validator keyword arguments.
        """
        pytest.fail("Duplicate manifest reached hashing")

    monkeypatch.setattr(service, "validate_ova_manifest", forbidden_hash)
    with pytest.raises(SddcUploadError, match="validation"):
        service._validate_staged_ova(path)
