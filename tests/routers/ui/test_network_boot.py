"""Test Network Boot and ESXi PXE management UI transports."""

from tests.routers.api_v1.helpers import create_token
from tests.routers.ui.helpers import login


def create_api_token(client, scopes):
    """Return one raw API token for a mixed UI/API transport assertion."""
    return create_token(client, scopes)[0]


def test_esxi_custom_variable_errors_do_not_expose_exception_details(
    client, monkeypatch
):
    """Verify that esxi custom variable errors do not expose exception details.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.routers.ui.network_boot as ui_module

    login(client)
    page = client.get("/esxi-pxe")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/esxi-pxe/custom-variables",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "safe_name",
            "description": "",
            "default_value": "",
        },
    )
    assert created.status_code == 200

    def reject_definition(*_args, **_kwargs):
        """Handle reject definition.

        Args:
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.


        Raises:
            ValueError: If an input value is invalid.
        """
        raise ValueError("database details that must not reach the browser")

    monkeypatch.setattr(ui_module, "save_custom_variable_definition", reject_definition)
    create_error = client.post(
        "/esxi-pxe/custom-variables",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "another_name",
            "description": "",
            "default_value": "",
        },
    )
    update_error = client.post(
        "/esxi-pxe/custom-variables/safe_name",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "safe_name",
            "description": "",
            "default_value": "",
        },
    )

    assert create_error.status_code == 400
    assert update_error.status_code == 400
    assert create_error.json() == {"detail": "Custom variable definition is invalid."}
    assert update_error.json() == {"detail": "Custom variable definition is invalid."}
    assert "database details" not in create_error.text
    assert "database details" not in update_error.text


def test_esxi_pxe_autosave_validation_does_not_expose_exception_details(
    client, monkeypatch
):
    """Verify that esxi pxe autosave validation does not expose exception details.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.ui as ui_module

    login(client)
    page = client.get("/esxi-pxe")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/esxi-pxe/kickstarts",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "Safe validation",
            "description": "",
            "content": "network --bootproto=dhcp\nrootpw --iscrypted placeholder\n",
        },
    )
    assert created.status_code == 200

    def reject_references(*_args, **_kwargs):
        """Handle reject references.

        Args:
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.


        Raises:
            ValueError: If an input value is invalid.
        """
        raise ValueError("backend details that must not reach the browser")

    monkeypatch.setattr(
        ui_module, "validate_kickstart_custom_references", reject_references
    )
    response = client.post(
        "/esxi-pxe/boot-settings",
        headers={"X-Atlaso-Autosave": "1"},
        data={
            "csrf": csrf,
            "hostname": "esxi-pxe.atlaso.internal",
            "tftp_root": "/var/lib/atlaso/pxe/tftp",
            "http_port": "8080",
            "bios_bootfile": "undionly.kpxe",
            "uefi_bootfile": "snponly.efi",
        },
    )

    assert response.status_code == 200
    assert response.json()["validation_errors"] == [
        "Safe validation: Kickstart source is invalid. Review its variable and vault markers."
    ]
    assert "backend details" not in response.text


def test_esxi_kickstart_upload_does_not_expose_exception_details(client, monkeypatch):
    """Verify that esxi kickstart upload does not expose exception details.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.routers.ui.network_boot as ui_module

    login(client)
    page = client.get("/esxi-pxe")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    def reject_references(*_args, **_kwargs):
        """Handle reject references.

        Args:
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.


        Raises:
            ValueError: If an input value is invalid.
        """
        raise ValueError("backend upload details that must not reach the browser")

    monkeypatch.setattr(
        ui_module, "validate_kickstart_custom_references", reject_references
    )
    response = client.post(
        "/esxi-pxe/kickstarts/upload",
        data={
            "csrf": csrf,
            "name": "Safe upload",
            "description": "",
            "enabled": "false",
        },
        files={
            "kickstart_file": (
                "safe-upload.cfg",
                b"network --bootproto=dhcp\n",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400, response.text
    assert (
        "Kickstart upload is invalid. Review the file, name, and reference markers."
        in response.text
    )
    assert "backend upload details" not in response.text


def test_esxi_pxe_iso_upload_and_host_selection(client, monkeypatch, tmp_path):
    """Verify that esxi pxe iso upload and host selection.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import json
    from types import SimpleNamespace

    from sqlalchemy import select

    import atlaso.app.routers.ui.network_boot as ui_module
    import atlaso.app.services.esxi_pxe as esxi_pxe
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiPxeHost, Job

    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    monkeypatch.setattr(esxi_pxe, "ESXI_INSTALLER_ISO_ROOT", iso_root)

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    assert str(iso_root) in page.text
    boot_service = page.text.split("<h2>Boot Service</h2>", 1)[1].split(
        '<div class="panel wide-panel" data-esxi-kickstarts-panel>', 1
    )[0]
    assert boot_service.index("Bind target") < boot_service.index(
        "Installer ISO folder"
    )
    iso_panel = page.text.split('id="esxi-pxe-isos-panel"', 1)[1].split(
        'id="esxi-pxe-preview-panel"', 1
    )[0]
    assert "Installer ISO folder" not in iso_panel
    assert iso_root.is_dir()
    assert "data-esxi-iso-upload" in page.text
    assert "data-esxi-iso-upload-progress" in page.text
    assert 'id="esxi-iso-upload-dialog"' in page.text
    assert "Add ESX ISO" in page.text
    assert 'data-atlaso-wizard-step="file"' in page.text
    assert 'data-atlaso-wizard-step="review"' in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    uploaded = client.post(
        "/esxi-pxe/isos/upload",
        data={"csrf": csrf},
        files={
            "iso_file": (
                "VMware-VMvisor-Installer-8.0U3.iso",
                b"iso bytes",
                "application/octet-stream",
            )
        },
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    assert uploaded.headers["location"] == "/ui/management/esxi-pxe#esxi-pxe-isos-panel"
    iso_path = iso_root / "VMware-VMvisor-Installer-8.0U3.iso"
    assert iso_path.read_bytes() == b"iso bytes"

    ajax_upload = client.post(
        "/esxi-pxe/isos/upload",
        data={"csrf": csrf},
        files={
            "iso_file": (
                "Nested-ESXi.iso",
                b"ajax iso bytes",
                "application/octet-stream",
            )
        },
        headers={"X-Atlaso-Upload": "1"},
    )
    assert ajax_upload.status_code == 200
    assert ajax_upload.json()["status"] == "uploaded"
    assert ajax_upload.json()["relative_path"] == "Nested-ESXi.iso"
    assert ajax_upload.json()["source"] == "uploaded"
    assert ajax_upload.json()["source_label"] == "Uploaded by user"
    assert ajax_upload.json()["source_at"]
    assert ajax_upload.json()["esx_version"] == ""
    assert ajax_upload.json()["esx_build"] == ""

    original_get_settings = ui_module.get_settings
    monkeypatch.setattr(
        ui_module,
        "get_settings",
        lambda: SimpleNamespace(esxi_installer_iso_max_bytes=3),
    )
    too_large = client.post(
        "/esxi-pxe/isos/upload",
        data={"csrf": csrf},
        files={"iso_file": ("Too-Large.iso", b"too large", "application/octet-stream")},
        headers={"X-Atlaso-Upload": "1"},
    )
    assert too_large.status_code == 413
    assert too_large.json()["status"] == "error"
    assert "too large" in too_large.json()["detail"].lower()
    monkeypatch.setattr(ui_module, "get_settings", original_get_settings)

    vcfdt_iso_path = iso_root / "VCFDT-Downloaded.iso"
    vcfdt_iso_path.write_bytes(b"vcfdt iso bytes")
    refreshed = client.get("/esxi-pxe")
    assert "VMware-VMvisor-Installer-8.0U3.iso" in refreshed.text
    assert "ESX version" in refreshed.text
    assert "8.0U3" in refreshed.text
    assert "VCFDT-Downloaded.iso" in refreshed.text
    assert "Installer ISOs" in refreshed.text
    assert "Uploaded by user" in refreshed.text
    assert "Downloaded by VCFDT" in refreshed.text
    assert 'id="esxi-pxe-hosts-table"' in refreshed.text
    assert "Default / undefined MACs" in refreshed.text
    assert "host-create-form" not in refreshed.text
    csrf = refreshed.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    outside_iso_path = tmp_path / "Outside-Managed-Root.iso"
    outside_iso_path.write_bytes(b"outside managed root")
    rejected_delete = client.post(
        "/esxi-pxe/isos/delete",
        data={"csrf": csrf, "installer_iso_path": str(outside_iso_path)},
        follow_redirects=False,
    )
    assert rejected_delete.status_code == 400
    assert outside_iso_path.read_bytes() == b"outside managed root"
    vcfdt_delete = client.post(
        "/esxi-pxe/isos/delete",
        data={"csrf": csrf, "installer_iso_path": str(vcfdt_iso_path)},
        follow_redirects=False,
    )
    assert vcfdt_delete.status_code == 303
    assert (
        vcfdt_delete.headers["location"]
        == "/ui/management/esxi-pxe#esxi-pxe-isos-panel"
    )
    assert not vcfdt_iso_path.exists()
    host_response = client.post(
        "/esxi-pxe/hosts",
        data={
            "csrf": csrf,
            "hostname": "esxi-iso",
            "mac_address": "00:50:56:11:22:33",
            "installer_iso_path": str(iso_path),
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert host_response.status_code == 303
    host_page = client.get("/esxi-pxe")
    assert host_page.status_code == 200
    assert "data-hosts=" in host_page.text
    assert "esxi-iso" in host_page.text
    with SessionLocal() as db:
        host = db.execute(
            select(EsxiPxeHost).where(EsxiPxeHost.hostname == "esxi-iso")
        ).scalar_one()
        assert host.installer_iso_path == str(iso_path)
        host_id = host.id
    delete_response = client.post(
        "/esxi-pxe/isos/delete",
        data={"csrf": csrf, "installer_iso_path": str(iso_path)},
        follow_redirects=False,
    )
    assert delete_response.status_code == 303
    assert (
        delete_response.headers["location"]
        == "/ui/management/esxi-pxe#esxi-pxe-isos-panel"
    )
    assert not iso_path.exists()
    with SessionLocal() as db:
        host = db.get(EsxiPxeHost, host_id)
        assert host.installer_iso_path == ""
    iso_path.write_bytes(b"iso bytes restored")
    host_response = client.post(
        "/esxi-pxe/hosts/" + str(host_id),
        data={
            "csrf": csrf,
            "hostname": "esxi-iso",
            "mac_address": "00:50:56:11:22:33",
            "installer_iso_path": str(iso_path),
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert host_response.status_code == 303

    api_token = create_api_token(client, ["read:esxi-pxe"])
    api_isos = client.get(
        "/api/v1/esxi-pxe/isos", headers={"Authorization": f"Bearer {api_token}"}
    )
    assert api_isos.status_code == 200
    assert {row["relative_path"] for row in api_isos.json()} >= {
        "VMware-VMvisor-Installer-8.0U3.iso",
        "Nested-ESXi.iso",
    }
    api_isos_by_name = {row["name"]: row for row in api_isos.json()}
    assert (
        api_isos_by_name["VMware-VMvisor-Installer-8.0U3.iso"]["esx_version"] == "8.0U3"
    )
    assert api_isos_by_name["VMware-VMvisor-Installer-8.0U3.iso"]["esx_build"] == ""
    assert api_isos_by_name["Nested-ESXi.iso"]["esx_version"] == ""

    apply_page = client.get("/appliance-apply")
    apply_csrf = apply_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    applied = client.post(
        "/appliance-apply", data={"csrf": apply_csrf, "selected_units": "esxi_pxe"}
    )
    assert applied.status_code == 200
    with SessionLocal() as db:
        job = (
            db.execute(
                select(Job)
                .where(Job.type == "appliance-apply")
                .order_by(Job.created_at.desc())
            )
            .scalars()
            .first()
        )
        payload = json.loads(job.result or "{}")
        manifest = payload["units"][0]["config_preview"]
        manifest_payload = json.loads(manifest)
        assert "VMware-VMvisor-Installer-8.0U3.iso" in manifest
    assert manifest_payload["hosts"][0]["installer_iso_path"] == str(iso_path)


def test_esxi_pxe_host_reference_wizard_and_grid_responses(client):
    """Verify that esxi pxe host reference wizard and grid responses.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/network-boot")
    assert page.status_code == 200
    assert 'id="network-boot-promote-dialog"' in page.text
    assert 'id="esxi-boot-authorization-dialog"' in page.text
    assert "data-esxi-boot-authorization-form data-atlaso-wizard" in page.text
    assert 'name="boot_code"' in page.text
    assert 'autocomplete="one-time-code"' in page.text
    assert "data-esxi-host-wizard-title" in page.text
    assert 'name="host_source"' in page.text
    assert 'value="discovered">Discovered Network Boot host' in page.text
    assert 'value="manual">Manual host' in page.text
    assert 'name="discovered_host_id"' in page.text
    assert 'name="manual_mac_address"' in page.text
    assert "data-atlaso-resource-review" in page.text
    assert 'id="esxi-pxe-host-fallback-create"' in page.text
    assert 'id="esxi-host-variables-table"' in page.text
    assert "data-definitions=" in page.text
    assert 'name="variables" value="{}"' in page.text
    host_wizard = page.text.split('id="network-boot-promote-dialog"', 1)[1].split(
        "</dialog>", 1
    )[0]
    assert "Six hexadecimal octets; unicast addresses only." in host_wizard
    assert "IP address (optional — leave blank for DHCP)" in host_wizard
    assert "Boot MAC" in host_wizard
    assert "host-reference-enable-step" in host_wizard
    assert "Variables JSON" not in host_wizard
    assert "Custom Variables definition" in host_wizard
    assert "Default value" in host_wizard
    assert "Host override" in host_wizard
    assert "+ Add variable here" not in host_wizard
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    created = client.post(
        "/esxi-pxe/hosts",
        data={
            "csrf": csrf,
            "hostname": "esxi-wizard-01",
            "mac_address": "00:50:56:01:02:03",
            "ip_address": "",
            "variables": '{"rack":"r1"}',
            "enabled": "on",
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert created.status_code == 200, created.text
    created_host = created.json()["host"]
    assert created_host["hostname"] == "esxi-wizard-01"
    assert created_host["mac_address"] == "00:50:56:01:02:03"
    assert created_host["variables"] == {"rack": "r1"}
    assert created_host["enabled"] is True

    updated = client.post(
        f"/esxi-pxe/hosts/{created_host['id']}",
        data={
            "csrf": csrf,
            "hostname": "esxi-wizard-02",
            "mac_address": "00:50:56:01:02:03",
            "ip_address": "",
            "variables": "{}",
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["host"]["hostname"] == "esxi-wizard-02"
    assert updated.json()["host"]["enabled"] is False

    duplicate = client.post(
        "/esxi-pxe/hosts",
        data={
            "csrf": csrf,
            "hostname": "esxi-wizard-duplicate",
            "mac_address": "00:50:56:01:02:03",
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"]

    fallback = client.post(
        f"/esxi-pxe/hosts/{created_host['id']}",
        data={
            "csrf": csrf,
            "hostname": "esxi-wizard-fallback",
            "mac_address": "00:50:56:01:02:03",
            "ip_address": "",
            "variables": "{}",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert fallback.status_code == 303
    assert (
        fallback.headers["location"]
        == "/ui/management/network-boot#esxi-pxe-hosts-panel"
    )

    app_js = client.get("/static/app.js").text
    wizard_js = app_js.split("function initializeEsxiHostReferenceWizard()", 1)[
        1
    ].split("async function postEsxiHostAction", 1)[0]
    assert "eligibleDiscoveredHosts" in wizard_js
    assert "availableMacs" in wizard_js
    assert "return [host?.boot_mac]" in wizard_js
    assert "esxiDiscoveredHostIsRegistered(host, used)" in wizard_js
    assert 'const mac = host?.boot_mac || "no boot MAC"' in app_js
    assert "updateManualMacValidity" in wizard_js
    assert "normalizeEsxiHostMac" in wizard_js
    assert "discoveredSelectionSequence" in wizard_js
    assert "pendingDiscoveredSelection" in wizard_js
    assert "await pendingDiscoveredSelection" in wizard_js
    assert "form.elements.host_id.value !== discoveredHostSelect.value" in wizard_js
    assert 'mode === "edit"' in wizard_js
    assert 'mode === "promote"' in wizard_js
    assert 'pattern: "direct-edit"' in wizard_js
    assert "parseEsxiHostVariableRows" in wizard_js
    assert "enabledWasEdited" in wizard_js
    assert "installerIsoSelect.addEventListener" in wizard_js
    assert "window.location.reload()" not in wizard_js
    assert "networkBootDiscoveredHostRefresh?.refresh?.()" in wizard_js
    authorization_js = app_js.split(
        "function initializeEsxiBootAuthorizationWizard()", 1
    )[1].split("function esxiHostHasValidWakeMac", 1)[0]
    assert "window.AtlasoUiPatterns.createWizard" in authorization_js
    assert "boot_code: normalizeCode()" in authorization_js
    assert "Console code entered" in authorization_js
    assert "activeHost?.hostname" in authorization_js


def test_esxi_pxe_host_reference_wizard_respects_read_only_permissions(client):
    """Verify that esxi pxe host reference wizard respects read only permissions.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()

    login(client)
    page = client.get("/network-boot")
    assert page.status_code == 200
    assert 'id="network-boot-promote-dialog"' not in page.text
    assert 'id="esxi-boot-authorization-dialog"' not in page.text
    assert 'id="esxi-pxe-host-fallback-create"' not in page.text
    assert 'id="esxi-pxe-hosts-table"' in page.text
    assert 'data-can-write="false"' in page.text


def test_esxi_pxe_default_host_settings_update_existing_rows(
    client, monkeypatch, tmp_path
):
    """Verify that esxi pxe default host settings update existing rows.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.services.esxi_pxe as esxi_pxe
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, Setting

    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    iso_root.mkdir(parents=True)
    first_iso = iso_root / "First-ESXi.iso"
    second_iso = iso_root / "Second-ESXi.iso"
    first_iso.write_bytes(b"first")
    second_iso.write_bytes(b"second")
    monkeypatch.setattr(esxi_pxe, "ESXI_INSTALLER_ISO_ROOT", iso_root)

    with SessionLocal() as db:
        first_kickstart = EsxiKickstart(
            name="First",
            content="install",
            content_hash=esxi_pxe.content_hash("install"),
        )
        second_kickstart = EsxiKickstart(
            name="Second",
            content="install",
            content_hash=esxi_pxe.content_hash("install"),
        )
        db.add_all([first_kickstart, second_kickstart])
        db.flush()
        first_kickstart_id = first_kickstart.id
        second_kickstart_id = second_kickstart.id
        second_kickstart_hash = second_kickstart.content_hash

        first = esxi_pxe.save_esxi_pxe_default_host_settings(
            db,
            enabled=True,
            kickstart_id=first_kickstart_id,
            installer_iso_path=str(first_iso),
        )
        db.flush()
        second = esxi_pxe.save_esxi_pxe_default_host_settings(
            db,
            enabled=False,
            kickstart_id=second_kickstart_id,
            installer_iso_path=str(second_iso),
        )
        db.flush()

        rows = (
            db.execute(
                select(Setting).where(Setting.key.like("esxi_pxe.default_host.%"))
            )
            .scalars()
            .all()
        )
        manifest = json.loads(
            esxi_pxe.render_esxi_pxe_manifest([], [], default_host=second)
        )

    assert first["enabled"] is True
    assert first["kickstart_id"] == first_kickstart_id
    assert second["enabled"] is False
    assert second["kickstart_id"] == second_kickstart_id
    assert second["installer_iso_path"] == str(second_iso)
    assert manifest["default_host"] == {
        "enabled": False,
        "kickstart_id": second_kickstart_id,
        "kickstart_name": "Second",
        "kickstart_http_path": f"/pxe/esxi/ks/{second_kickstart_hash[:12]}.cfg",
        "installer_iso_path": str(second_iso),
        "installer_iso_name": "Second-ESXi.iso",
    }
    assert len(rows) == 3
    assert {row.key for row in rows} == {
        esxi_pxe.ESXI_PXE_DEFAULT_HOST_ENABLED_KEY,
        esxi_pxe.ESXI_PXE_DEFAULT_HOST_KICKSTART_ID_KEY,
        esxi_pxe.ESXI_PXE_DEFAULT_HOST_INSTALLER_ISO_KEY,
    }


def test_esxi_pxe_default_host_edit_marks_appliance_apply_pending(client):
    """Verify that esxi pxe default host edit marks appliance apply pending.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart
    from atlaso.app.services import esxi_pxe
    from atlaso.app.ui import (
        appliance_apply_status,
        appliance_apply_units,
        update_appliance_apply_baselines,
    )

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    with SessionLocal() as db:
        kickstart = EsxiKickstart(
            name="Baseline ESXi",
            content="install",
            content_hash=esxi_pxe.content_hash("install"),
        )
        db.add(kickstart)
        db.flush()
        kickstart_id = kickstart.id
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
    with SessionLocal() as db:
        assert appliance_apply_status(db, "esxi_pxe", refresh=True)["changed"] is False

    current = client.get("/appliance-apply/status")
    assert current.status_code == 200
    current_pending_count = current.json()["pending_count"]

    response = client.post(
        "/esxi-pxe/default-host",
        data={
            "csrf": csrf,
            "enabled": "on",
            "kickstart_id": str(kickstart_id),
            "installer_iso_path": "",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    pending = client.get("/appliance-apply/status")
    assert pending.status_code == 200
    assert pending.json()["pending_count"] > current_pending_count
    assert pending.json()["label"] == "Review appliance changes"
    with SessionLocal() as db:
        assert appliance_apply_status(db, "esxi_pxe", refresh=True)["changed"] is True


def test_network_boot_task_widget_contains_only_media_jobs(client):
    """Verify that network boot task widget contains only media jobs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    with SessionLocal() as db:
        db.add_all(
            [
                Job(
                    id="job_network_boot_widget",
                    type="pxe-media-sync",
                    status=JobStatus.SUCCEEDED.value,
                    created_by="admin",
                    progress_percent=100,
                ),
                Job(
                    id="job_unrelated_widget",
                    type="appliance-update",
                    status=JobStatus.SUCCEEDED.value,
                    created_by="admin",
                    progress_percent=100,
                ),
            ]
        )
        db.commit()

    page = client.get("/network-boot")

    assert page.status_code == 200
    assert "job_network_boot_widget" in page.text
    assert "job_unrelated_widget" not in page.text
    assert "The same task grid used by Tasks" in page.text
