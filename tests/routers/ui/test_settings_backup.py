"""Test Appliance Settings and Backup Restore management UI transports."""

from tests.routers.ui.helpers import login


def test_settings_backup_router_owns_exact_transport_set():
    """Keep Settings and Backup Restore route identities in established order."""
    from atlaso.app import ui

    assert [
        (route.path, tuple(sorted((route.methods or set()) - {"HEAD"})), route.name)
        for route in ui.settings_backup_router.routes
    ] == [
        (
            "/ui/management/backup-restore",
            ("GET",),
            "backup_restore_page",
        ),
        (
            "/ui/management/backup-restore/export",
            ("POST",),
            "export_backup_restore_archive",
        ),
        (
            "/ui/management/backup-restore/restore",
            ("POST",),
            "restore_backup_restore_archive",
        ),
        (
            "/ui/management/backup-restore/factory-reset",
            ("POST",),
            "factory_reset_backup_restore",
        ),
        ("/ui/management/settings", ("GET",), "settings_page"),
        ("/ui/management/settings", ("POST",), "update_settings_from_ui"),
        (
            "/ui/management/settings/vmware-ceip",
            ("POST",),
            "update_vmware_ceip_from_ui",
        ),
        (
            "/ui/management/settings/logging",
            ("POST",),
            "update_logging_settings_from_ui",
        ),
    ]


def test_backup_restore_transport_keeps_page_and_invalid_upload_contract(client):
    """Verify the extracted page and restore upload retain their HTTP contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/backup-restore")
    assert page.status_code == 200
    assert "Download settings backup" in page.text
    assert "Restore settings backup" in page.text
    assert "Factory reset appliance" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={"archive_file": ("invalid.json", b"not-json", "application/json")},
    )

    assert response.status_code == 400
    assert "Expecting value" in response.text


def test_settings_page_renders_autosave_validation_and_preview(client, monkeypatch):
    """Verify that settings page renders autosave validation and preview.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings

    monkeypatch.setattr(
        "atlaso.app.ui.socket.gethostname", lambda: "runtime.atlaso.internal"
    )

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        db.commit()

    response = client.get("/settings")

    assert response.status_code == 200
    assert 'action="/ui/management/settings"' in response.text
    assert (
        'data-autosave-status-id="appliance-settings-autosave-status"' in response.text
    )
    assert response.text.count('class="help-icon"') >= 2
    assert 'textarea name="external_dns_servers"' not in response.text
    assert 'input type="hidden" name="external_dns_servers"' in response.text
    assert "Appliance Settings has pending appliance changes" in response.text
    assert "Validation" in response.text
    assert "runtime.atlaso.internal" in response.text
    assert "core.atlaso.internal" in response.text
    assert "Management UI HTTPS" in response.text
    assert "Root SSH login" in response.text
    assert "VMware Product Preferences" in response.text
    assert "VMware CEIP participation" in response.text
    assert 'action="/ui/management/settings/vmware-ceip"' in response.text
    assert 'name="vmware_ceip_enabled"' in response.text
    assert "data-vmware-ceip-pill" in response.text
    assert "data-vmware-ceip-status" in response.text
    assert (
        'action="/ui/management/settings/vmware-ceip" method="post" data-autosave-form data-appliance-settings'
        in response.text
    )
    assert "Service DNS target names" in response.text
    assert response.text.count('class="settings-inline-field"') >= 2
    assert 'select name="service_dns_target_naming"' in response.text
    assert '<option value="ip" selected>IP address</option>' in response.text
    assert "Operational Logging" in response.text
    assert "External NTP servers" not in response.text
    assert 'textarea name="ntp_servers"' not in response.text
    assert 'action="/ui/management/settings/logging"' in response.text
    assert 'select name="level"' in response.text
    assert (
        'input class="switch-input" type="checkbox" name="syslog_enabled"'
        in response.text
    )
    assert "Syslog host" in response.text
    assert "data-appliance-settings-root-ssh" in response.text
    assert (
        "/var/lib/atlaso/apply/appliance-settings/atlaso-settings.json" in response.text
    )
    assert "resolver_mode" in response.text
    assert "root_ssh_enabled" in response.text
    assert "vmware_ceip_enabled" in response.text
    assert "data-config-preview-open" in response.text
    assert "data-appliance-settings-preview" in response.text
    assert 'class="validation-preview-source language-json"' in response.text
    assert 'class="settings-list validation-settings-list"' in response.text
    app_css = client.get("/static/app.css")
    assert ".validation-settings-list div" in app_css.text
    assert "grid-template-columns: minmax(0, 130px) minmax(0, 1fr);" in app_css.text
    assert "overflow-wrap: anywhere;" in app_css.text
    assert ".settings-inline-field" in app_css.text
    assert "grid-template-columns: 160px minmax(0, 1fr);" in app_css.text


def test_vmware_ceip_autosave_updates_global_policy_and_pending_preview(client):
    """Verify that vmware ceip autosave updates global policy and pending preview.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, AuditEvent

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/settings/vmware-ceip",
        data={"vmware_ceip_enabled": "on", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["vmware_ceip_enabled"] is True
    assert payload["fqdn"] == "core.atlaso.internal"
    assert payload["management_interface"]["name"] == "eth0"
    assert payload["resolver_mode"] in {"dhcp", "external", "local_dns"}
    assert '"vmware_ceip_enabled": true' in payload["config_preview"]
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        audit = db.execute(
            select(AuditEvent).where(AuditEvent.action == "update_vmware_ceip_policy")
        ).scalar_one()
        assert settings.vmware_ceip_enabled is True
        assert audit.detail == "enabled=true"

    status = client.get("/appliance-apply/status").json()
    unit = next(item for item in status["units"] if item["id"] == "appliance_settings")
    assert unit["changed"] is True
    updated_page = client.get("/settings")
    assert (
        'data-vmware-ceip-pill class="status-pill good">CEIP on</span>'
        in updated_page.text
    )
    assert "Appliance Settings has pending appliance changes" in updated_page.text


def test_logging_settings_autosave_updates_preferences(client):
    """Verify that logging settings autosave updates preferences.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Setting
    from atlaso.app.operational_logging import (
        LOGGING_LEVEL_KEY,
        LOGGING_SYSLOG_ENABLED_KEY,
        LOGGING_SYSLOG_FACILITY_KEY,
        LOGGING_SYSLOG_HOST_KEY,
        LOGGING_SYSLOG_LEVEL_KEY,
        LOGGING_SYSLOG_PORT_KEY,
        LOGGING_SYSLOG_PROTOCOL_KEY,
    )

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/settings/logging",
        data={
            "level": "DEBUG",
            "syslog_enabled": "on",
            "syslog_host": "127.0.0.1",
            "syslog_port": "5514",
            "syslog_protocol": "udp",
            "syslog_facility": "local4",
            "syslog_level": "WARNING",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["logging_preferences"]["level"] == "DEBUG"
    assert payload["logging_preferences"]["syslog_enabled"] is True
    assert payload["logging_preferences"]["syslog_host"] == "127.0.0.1"
    assert payload["logging_preferences"]["syslog_port"] == 5514
    assert payload["logging_preferences"]["syslog_protocol"] == "udp"
    assert payload["logging_preferences"]["syslog_facility"] == "local4"
    assert payload["logging_preferences"]["syslog_level"] == "WARNING"

    with SessionLocal() as db:
        values = {
            row.key: row.value for row in db.execute(select(Setting)).scalars().all()
        }
        assert values[LOGGING_LEVEL_KEY] == "DEBUG"
        assert values[LOGGING_SYSLOG_ENABLED_KEY] == "true"
        assert values[LOGGING_SYSLOG_HOST_KEY] == "127.0.0.1"
        assert values[LOGGING_SYSLOG_PORT_KEY] == "5514"
        assert values[LOGGING_SYSLOG_PROTOCOL_KEY] == "udp"
        assert values[LOGGING_SYSLOG_FACILITY_KEY] == "local4"
        assert values[LOGGING_SYSLOG_LEVEL_KEY] == "WARNING"
        event = db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "update_operational_logging_settings"
            )
        ).scalar_one()
        assert event.resource_type == "logging"


def test_logging_settings_requires_syslog_host_when_enabled(client):
    """Verify that logging settings requires syslog host when enabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/settings/logging",
        data={
            "level": "INFO",
            "syslog_enabled": "on",
            "syslog_host": "",
            "syslog_port": "514",
            "syslog_protocol": "udp",
            "syslog_facility": "local0",
            "syslog_level": "INFO",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 422
    assert (
        response.json()["message"]
        == "External syslog host is required when syslog forwarding is enabled."
    )


def test_settings_page_shows_external_dns_editor_when_local_dns_is_disabled(client):
    """Verify that settings page shows external dns editor when local dns is disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = False
        db.commit()

    response = client.get("/settings")

    assert response.status_code == 200
    assert "External DNS servers" in response.text
    assert 'textarea name="external_dns_servers"' in response.text
    assert "Local DNS is disabled. External DNS servers are required" in response.text


def test_settings_page_hides_ntp_editor_when_ntp_is_enabled(client):
    """Verify that settings page hides ntp editor when ntp is enabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NtpSettings

    login(client)
    with SessionLocal() as db:
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        ntp_settings.enabled = True
        db.add(ntp_settings)
        db.commit()

    response = client.get("/settings")

    assert response.status_code == 200
    assert "External NTP servers" not in response.text
    assert 'textarea name="ntp_servers"' not in response.text
    assert 'input type="hidden" name="ntp_servers"' not in response.text
    assert '  "ntp_servers": [' not in response.text
