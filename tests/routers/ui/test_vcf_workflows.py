"""Test VCF workflow management UI transports."""

import pytest

from tests.routers.ui.helpers import login


def test_vcf_workflow_pages_keep_stable_transports(client):
    """Verify the extracted workflow pages keep their stable management routes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)

    helper = client.get("/vcf-helper")
    assert helper.status_code == 200
    assert 'action="/ui/management/vcf-helper/generated-fqdns"' in helper.text
    assert 'action="/ui/management/vcf-backups/settings"' in helper.text
    assert 'id="vcf-helper-backup-storage-status"' in helper.text

    trust = client.get("/vcf-trust")
    assert trust.status_code == 200
    assert 'action="/ui/management/vcf-trust/root-ca"' in trust.text

    depot = client.get("/vcf-offline-depot")
    assert depot.status_code == 200
    assert 'action="/ui/management/vcf-offline-depot/settings"' in depot.text
    assert 'id="vcf-depot-storage-status"' in depot.text
    assert "/vcf-offline-depot/profiles/" in depot.text

    registry = client.get("/vcf-private-registry")
    assert registry.status_code == 200
    assert 'action="/ui/management/vcf-private-registry/settings"' in registry.text

    backups = client.get("/vcf-backups")
    assert backups.status_code == 200
    assert 'action="/ui/management/vcf-backups/settings"' in backups.text
    assert 'id="vcf-backup-storage-status"' in backups.text


def test_legacy_https_repository_redirect_remains_stable(client):
    """Verify the legacy HTTPS repository bookmark keeps its stable redirect.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    response = client.get("/https-repository", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/management/https-repository"


def test_certificate_operator_cannot_render_vcf_helper_dns_inventory(client):
    """Verify certificate operators cannot render the VCF Helper DNS inventory.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.CERTIFICATE_OPERATOR.value
        admin.roles_json = roles_to_json([Role.CERTIFICATE_OPERATOR.value])
        db.commit()

    login(client)
    response = client.get("/vcf-helper")
    assert response.status_code == 403
    assert "Missing required scope: read:dns" in response.text


def test_vcf_backups_settings_badge_reflects_desired_state(client, monkeypatch):
    """Verify the VCF Backups badge reflects desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.config import get_settings

    login(client)
    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()

    page = client.get("/vcf-backups")

    assert page.status_code == 200
    settings_panel = page.text.split("<h2>SFTP Settings</h2>", 1)[1].split(
        "</form>", 1
    )[0]
    assert '<span class="status-pill muted">disabled</span>' in settings_panel
    assert '<span class="status-pill warn">dry-run</span>' not in page.text


@pytest.mark.parametrize(
    ("page_path", "settings_model", "assignment_path"),
    [
        ("/vcf-backups", "backup", "/mnt/atlaso-esx-storage/vcf/atlaso-vcf-backups"),
        ("/vcf-offline-depot", "depot", "/mnt/atlaso-esx-storage/vcf/atlaso-vcf-offline-depot"),
    ],
)
def test_service_storage_autosave_preserves_service_settings(
    client, page_path, settings_model, assignment_path
):
    """Verify storage autosave persists its assignment without resetting service settings.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        page_path: Page that provides the storage assignment form and CSRF token.
        settings_model: Service settings model selected by the test case.
        assignment_path: Direct child directory assigned under the registered volume.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        EsxStorageVolume,
        VcfBackupSettings,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.ui import appliance_apply_units

    login(client)
    page = client.get(page_path)
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    volume_uuid = "2cecf40a-b241-4b6a-8b1a-4d84d9b0eb61"
    settings_class = VcfBackupSettings if settings_model == "backup" else VcfOfflineDepotSettings

    with SessionLocal() as db:
        settings = db.execute(select(settings_class)).scalar_one()
        settings.enabled = True
        original_port = settings.port
        db.add(
            EsxStorageVolume(
                name="VCF Service Volume",
                source_type="mounted_ext4",
                stable_device_id="/dev/disk/by-id/ata-atlaso-vcf-service",
                filesystem_uuid=volume_uuid,
                mount_path="/mnt/atlaso-esx-storage/vcf",
                state="mounted",
                applied=True,
            )
        )
        db.commit()

    response = client.post(
        f"{page_path}/settings",
        data={
            "csrf": csrf,
            "storage_assignment_only": "1",
            "storage_volume_uuid": volume_uuid,
            "storage_volume_path": assignment_path,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["storage_volume_uuid"] == volume_uuid
    assert payload["storage_volume_path"] == assignment_path
    with SessionLocal() as db:
        settings = db.execute(select(settings_class)).scalar_one()
        assert settings.storage_volume_uuid == volume_uuid
        assert settings.storage_volume_path == assignment_path
        assert settings.enabled is True
        assert settings.port == original_port
        if settings_model == "backup":
            assert settings.storage_path == "/mnt/atlaso-vcf-backups"
        else:
            assert settings.depot_store_path == "/mnt/atlaso-vcf-offline-depot"
        unit_id = "vcf_backups" if settings_model == "backup" else "vcf_offline_depot"
        unit = next(item for item in appliance_apply_units(db, reconcile=False) if item["id"] == unit_id)
        assert unit["snapshot_marker"]["uuid"] == volume_uuid
        assert unit["changed"]
        assert f"Proposed storage: VCF Service Volume at {assignment_path}" in unit["summary"]
        assert any(line.startswith("Current storage: Installed storage at ") for line in unit["summary"])
        assert any("Existing files stay" in line for line in unit["summary"])

    other_page = "/vcf-offline-depot" if settings_model == "backup" else "/vcf-backups"
    conflict = client.post(
        f"{other_page}/settings",
        data={
            "csrf": csrf,
            "storage_assignment_only": "1",
            "storage_volume_uuid": volume_uuid,
            "storage_volume_path": assignment_path,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert conflict.status_code == 409
    assert "already uses this storage directory" in conflict.json()["detail"]


def test_vcf_offline_depot_upload_rejects_malformed_archive_before_saving(
    client, monkeypatch
):
    """Verify malformed VCFDT archives are rejected before persistence.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfOfflineDepotSettings

    monkeypatch.setattr(
        "atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None
    )
    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "hostname": "depot.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "csrf": csrf,
        },
        files={
            "tool_archive_file": (
                "vcf-download-tool-9.1.0.test.tar.gz",
                b"\x1f\x8b\x08\x00truncated",
                "application/gzip",
            ),
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 400
    assert "incomplete or invalid" in response.text
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert settings.tool_archive_path == ""
        assert settings.tool_version == ""


def test_vcf_trust_rejects_mismatched_confirmed_tls_fingerprint(client, monkeypatch):
    """Verify VCF Trust rejects a mismatched confirmed TLS fingerprint.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.ui import get_ca_settings_row

    login(client)
    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        ensure_root_ca_material(settings)
        db.commit()
    monkeypatch.setattr(
        "atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint",
        lambda _address, _port: "AA:BB",
    )
    csrf = (
        client.get("/vcf-helper")
        .text.split('name="csrf" value="', 1)[1]
        .split('"', 1)[0]
    )

    response = client.post(
        "/vcf-trust/root-ca",
        data={
            "address": "vcf-installer.example.test",
            "api_username": "administrator@vsphere.local",
            "api_password": "api-secret",
            "confirmed_tls_fingerprint": "CC:DD",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Trust": "1"},
    )

    assert response.status_code == 409
    assert response.json()["fingerprint"] == "AA:BB"


@pytest.mark.parametrize("stage", ["dns", "tcp", "tls", "tls_timeout"])
def test_vcf_trust_reports_connection_failure_stage(client, monkeypatch, stage):
    """Connection errors identify the failing stage before credentials are sent.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        stage: Connection stage whose failure is injected.
    """
    import socket
    import ssl

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.ui import get_ca_settings_row

    login(client)
    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        ensure_root_ca_material(settings)
        db.commit()
    def fail(_address, _port):
        """Inject an isolated pre-authentication connection failure.

        Args:
            _address: Target address ignored by the injected failure.
            _port: Target port ignored by the injected failure.
        """
        raise {
            "dns": socket.gaierror("name unavailable"),
            "tcp": ConnectionRefusedError("refused"),
            "tls": ssl.SSLError("handshake failed"),
            "tls_timeout": ssl.SSLError("TLS handshake timed out"),
        }[stage]
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint", fail)
    csrf = client.get("/vcf-helper").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/vcf-trust/root-ca", data={"address": "target.example.test",
                           "api_username": "admin", "api_password": "test-only", "csrf": csrf},
                           headers={"X-Atlaso-VCF-Trust": "1"})
    assert response.status_code == 422
    assert any(
        {
            "dns": "Unable to resolve",
            "tcp": "Unable to connect",
            "tls": "TLS handshake",
            "tls_timeout": "TLS handshake",
        }[stage]
        in error
        for error in response.json()["errors"]
    )


def test_tls_fingerprint_classifies_handshake_timeout(monkeypatch):
    """Translate a connected-socket timeout into a TLS-stage failure.

    Args:
        monkeypatch: Pytest fixture used to replace network dependencies.
    """
    import ssl

    from atlaso.app.services import vcf_sddc_deployment

    class ConnectedSocket:
        """Provide the context-manager contract used by the fingerprint helper."""

        def __enter__(self):
            """Return the connected socket placeholder."""
            return self

        def __exit__(self, *_args):
            """Close the placeholder without suppressing failures.

            Args:
                *_args: Context-manager exit arguments.
            """
            return False

    class TimeoutContext:
        """Fail only after TCP connection while starting the TLS handshake."""

        def wrap_socket(self, _socket, *, server_hostname):
            """Raise the timeout emitted by the standard TLS wrapper.

            Args:
                _socket: Connected socket placeholder.
                server_hostname: TLS server name supplied to the wrapper.
            """
            assert server_hostname == "target.example.test"
            raise TimeoutError("handshake timed out")

    monkeypatch.setattr(
        vcf_sddc_deployment.socket,
        "create_connection",
        lambda *_args, **_kwargs: ConnectedSocket(),
    )
    monkeypatch.setattr(
        vcf_sddc_deployment,
        "_fingerprint_tls_context",
        lambda: TimeoutContext(),
    )

    with pytest.raises(ssl.SSLError, match="TLS handshake timed out"):
        vcf_sddc_deployment.tls_sha256_fingerprint("target.example.test")


def test_tls_fingerprint_classifies_handshake_reset(monkeypatch):
    """Translate a connected-socket reset into a TLS-stage failure.

    Args:
        monkeypatch: Pytest fixture used to replace network dependencies.
    """
    import ssl

    from atlaso.app.services import vcf_sddc_deployment

    class ConnectedSocket:
        """Provide the context-manager contract used by the fingerprint helper."""

        def __enter__(self):
            """Return the connected socket placeholder."""
            return self

        def __exit__(self, *_args):
            """Close the placeholder without suppressing failures.

            Args:
                *_args: Context-manager exit arguments.
            """
            return False

    class ResetContext:
        """Fail only after TCP connection while starting the TLS handshake."""

        def wrap_socket(self, _socket, *, server_hostname):
            """Raise the reset emitted while negotiating TLS.

            Args:
                _socket: Connected socket placeholder.
                server_hostname: TLS server name supplied to the wrapper.
            """
            assert server_hostname == "target.example.test"
            raise ConnectionResetError("connection reset by peer")

    monkeypatch.setattr(
        vcf_sddc_deployment.socket,
        "create_connection",
        lambda *_args, **_kwargs: ConnectedSocket(),
    )
    monkeypatch.setattr(
        vcf_sddc_deployment,
        "_fingerprint_tls_context",
        lambda: ResetContext(),
    )

    with pytest.raises(ssl.SSLError, match="TLS handshake or certificate retrieval failed"):
        vcf_sddc_deployment.tls_sha256_fingerprint("target.example.test")
