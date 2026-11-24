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
    assert 'data-vcf-service-storage' not in helper.text

    trust = client.get("/vcf-trust")
    assert trust.status_code == 200
    assert 'action="/ui/management/vcf-trust/root-ca"' in trust.text

    depot = client.get("/vcf-offline-depot")
    assert depot.status_code == 200
    assert 'action="/ui/management/vcf-offline-depot/settings"' in depot.text
    assert 'id="vcf-service-storage-wizard"' in depot.text
    assert 'name="storage_volume_path"' not in depot.text
    assert "/vcf-offline-depot/profiles/" in depot.text

    registry = client.get("/vcf-private-registry")
    assert registry.status_code == 200
    assert 'action="/ui/management/vcf-private-registry/settings"' in registry.text
    assert 'id="vcf-service-storage-wizard"' in registry.text

    backups = client.get("/vcf-backups")
    assert backups.status_code == 200
    assert 'action="/ui/management/vcf-backups/settings"' in backups.text
    assert 'id="vcf-service-storage-wizard"' in backups.text
    assert 'name="storage_volume_path"' not in backups.text


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
        ("/vcf-backups", "backup", "/mnt/atlaso-esx-storage/vcf/vcf-backups"),
        ("/vcf-offline-depot", "depot", "/mnt/atlaso-esx-storage/vcf/vcf-offline-depot"),
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
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    page = client.get(page_path)
    assert page.status_code == 200
    assert 'name="storage_volume_path"' not in page.text
    assert 'Appliance default</option>' in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    volume_uuid = "2cecf40a-b241-4b6a-8b1a-4d84d9b0eb61"
    settings_class = VcfBackupSettings if settings_model == "backup" else VcfOfflineDepotSettings

    with SessionLocal() as db:
        settings = db.execute(select(settings_class)).scalar_one()
        settings.enabled = True
        settings.storage_volume_uuid = volume_uuid
        settings.storage_volume_path = "/mnt/atlaso-esx-storage/vcf/legacy-directory"
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

    selected_page = client.get(page_path)
    assert f'data-storage-path="{assignment_path}"' in selected_page.text
    assert 'aria-live="polite">/mnt/atlaso-esx-storage/vcf/legacy-directory</strong>' in selected_page.text
    response = client.post(
        f"{page_path}/settings",
        data={
            "csrf": csrf,
            "storage_assignment_only": "1",
            "storage_volume_uuid": volume_uuid,
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
        assert any(line.startswith("Current storage: Appliance default at ") for line in unit["summary"])
        assert any("Existing files stay" in line for line in unit["summary"])
        if settings_model == "backup":
            update_appliance_apply_baselines(db, [unit], {unit_id})
            db.commit()
            settings.enabled = False
            settings.storage_volume_uuid = "unavailable-volume"
            db.flush()
            disabled = next(item for item in appliance_apply_units(db, reconcile=False) if item["id"] == unit_id)
            assert disabled["valid"]
            assert disabled["snapshot_marker"] == unit["snapshot_marker"]
            assert "# Atlaso VCF Backup" in disabled["config_preview"]
            assert not any(line.startswith("Proposed storage:") for line in disabled["summary"])

    other_page = "/vcf-offline-depot" if settings_model == "backup" else "/vcf-backups"
    other = client.post(
        f"{other_page}/settings",
        data={
            "csrf": csrf,
            "storage_assignment_only": "1",
            "storage_volume_uuid": volume_uuid,
            "storage_volume_path": assignment_path,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert other.status_code == 409
    assert "other VCF service" in other.json()["detail"]
    choice = f'<option value="{volume_uuid}" data-storage-path='
    assert choice not in client.get(other_page).text
    assert choice not in client.get("/vcf-private-registry").text

    restored = client.post(
        f"{page_path}/settings",
        data={"csrf": csrf, "storage_assignment_only": "1", "storage_volume_uuid": ""},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert restored.status_code == 200
    assert restored.json()["storage_volume_path"] == (
        "/mnt/atlaso-vcf-backups" if settings_model == "backup" else "/mnt/atlaso-vcf-offline-depot"
    )
    if settings_model == "backup":
        assert choice not in client.get(other_page).text
        with SessionLocal() as db:
            unit = next(item for item in appliance_apply_units(db, reconcile=False) if item["id"] == unit_id)
            update_appliance_apply_baselines(db, [unit], {unit_id})
            db.commit()
    assert choice in client.get(other_page).text


@pytest.mark.parametrize(
    "page_path", ["/vcf-backups", "/vcf-offline-depot", "/vcf-private-registry"]
)
def test_vcf_services_render_the_same_storage_wizard(client, page_path):
    """Check that each service stages storage through the shared wizard.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        page_path: VCF service page that hosts the storage wizard.
    """
    login(client)
    page = client.get(page_path)
    assert page.status_code == 200
    assert 'aria-controls="vcf-service-storage-wizard"' in page.text
    wizard = page.text.split('<dialog id="vcf-service-storage-wizard"', 1)[1].split(
        "</dialog>", 1
    )[0]
    assert f'{page_path}/settings"' in wizard
    assert "data-autosave-form" not in wizard
    for step in ("volume", "data", "review"):
        assert f'data-atlaso-wizard-step="{step}"' in wizard
    for policy in ("move", "leave", "delete"):
        assert f'name="storage_migration_policy" value="{policy}"' in wizard


def test_registry_storage_wizard_saves_desired_state_and_reserves_volume(client):
    """Verify registry storage review and Apply independently of Harbor settings.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxStorageVolume, Job, VcfPrivateRegistrySettings
    from atlaso.app.services.applied_service_dns import load_appliance_apply_baselines
    from atlaso.app.services.vcf_service_storage import REGISTRY_STORAGE_UNIT

    login(client)
    page = client.get("/vcf-private-registry")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    uuid = "49b6850b-a8a2-4e62-878f-b9656f74fb5b"
    with SessionLocal() as db:
        registry = db.scalars(select(VcfPrivateRegistrySettings)).one()
        registry.harbor_project = "existing-project"
        db.add(
            EsxStorageVolume(
                name="Registry volume",
                source_type="mounted_ext4",
                stable_device_id="/dev/disk/by-id/ata-atlaso-registry",
                filesystem_uuid=uuid,
                mount_path="/mnt/atlaso-esx-storage/registry",
                state="mounted",
                applied=True,
            )
        )
        db.commit()

    response = client.post(
        "/vcf-private-registry/settings",
        data={
            "csrf": csrf,
            "storage_assignment_only": "1",
            "storage_volume_uuid": uuid,
            "storage_migration_policy": "move",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert response.status_code == 200
    assert response.json()["storage_volume_path"] == "/mnt/atlaso-esx-storage/registry/vcf-registry"
    with SessionLocal() as db:
        registry = db.scalars(select(VcfPrivateRegistrySettings)).one()
        assert registry.storage_migration_policy == "move"
        assert registry.storage_volume_uuid == uuid
        assert registry.storage_path == "/mnt/atlaso-vcf-registry"
        assert registry.harbor_project == "existing-project"
    for page_path in ("/vcf-backups", "/vcf-offline-depot"):
        assert f'<option value="{uuid}"' not in client.get(page_path).text

    reviewed = client.get("/appliance-apply/review", params={"selected_units": REGISTRY_STORAGE_UNIT}).json()
    move = next(unit for unit in reviewed["units"] if unit["id"] == REGISTRY_STORAGE_UNIT)
    assert move["valid"] and move["selected"]
    assert move["storage_change"]["action"] == "move"
    assert not any(unit["selected"] for unit in reviewed["units"] if unit["id"] == "vcf_private_registry")

    data = {
        "csrf": csrf,
        "selected_units": REGISTRY_STORAGE_UNIT,
        "requested_units": REGISTRY_STORAGE_UNIT,
        "reviewed_plan": reviewed["plan_token"],
    }
    headers = {"Accept": "application/json"}
    with SessionLocal() as db:
        registry = db.scalars(select(VcfPrivateRegistrySettings)).one()
        registry.storage_migration_policy = "delete"
        db.commit()
    stale = client.post("/appliance-apply", data=data, headers=headers)
    assert stale.status_code == 422
    assert "changed since review" in stale.json()["detail"]

    reviewed = client.get("/appliance-apply/review", params={"selected_units": REGISTRY_STORAGE_UNIT}).json()
    deletion = next(unit["storage_change"] for unit in reviewed["units"] if unit["id"] == REGISTRY_STORAGE_UNIT)
    assert deletion == {
        "action": "delete",
        "previous_path": "/mnt/atlaso-vcf-registry",
        "proposed_path": "/mnt/atlaso-esx-storage/registry/vcf-registry",
        "confirmation": "DELETE /mnt/atlaso-vcf-registry",
    }
    data["reviewed_plan"] = reviewed["plan_token"]
    missing = client.post("/appliance-apply", data=data, headers=headers)
    assert missing.status_code == 422
    assert "exact confirmation" in missing.json()["detail"]
    data["vcf_storage_confirmations"] = json.dumps({
        "unit_id": REGISTRY_STORAGE_UNIT,
        "confirmation": deletion["confirmation"],
    })
    submitted = client.post("/appliance-apply", data=data, headers=headers)
    assert submitted.status_code == 202, submitted.text
    with SessionLocal() as db:
        job = db.get(Job, submitted.json()["job_id"])
        assert job is not None and job.status == "succeeded"
        applied = load_appliance_apply_baselines(db)[REGISTRY_STORAGE_UNIT]
        assert applied["snapshot_marker"]["uuid"] == uuid
        assert applied["applied_job_id"] == job.id
        commands = json.loads(job.result)["units"][0]["commands"]
        assert commands[0]["command"][:3] == ["atlaso-helper", "vcf-storage", "apply-registry"]


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
