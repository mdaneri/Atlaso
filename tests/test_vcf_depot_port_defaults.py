"""Test focused VCF Offline Depot default and compatibility behavior."""

import json
from copy import deepcopy

import pytest
from sqlalchemy import select

from atlaso.app.models import VCF_OFFLINE_DEPOT_DEFAULT_PORT, VcfOfflineDepotSettings
from atlaso.app.services.settings_archive import (
    export_settings_archive,
    restore_settings_archive,
)
from tests.routers.ui.helpers import login


@pytest.mark.parametrize("firewall_changed", [False, True])
def test_depot_apply_includes_changed_firewall(client, monkeypatch, firewall_changed):
    """Keep generated admission in the selected depot Apply operation.

    Args:
        client: Isolated HTTP application fixture.
        monkeypatch: Background execution replacement fixture.
        firewall_changed: Whether firewall configuration needs applying.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
    real_units = ui.appliance_apply_units

    def candidate_units(db, *, reconcile=True):
        """Set the independent component change state.

        Args:
            db: Active database session.
            reconcile: Whether desired state is reconciled.
        """
        units = real_units(db, reconcile=reconcile)
        for unit in units:
            if unit["id"] == "vcf_offline_depot":
                unit["changed"] = True
            if unit["id"] == "firewall":
                unit["changed"] = firewall_changed
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", candidate_units)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_offline_depot"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        payload = json.loads(job.result)
    assert ("firewall" in payload["selected_units"]) is firewall_changed
    if firewall_changed:
        assert "nat" in payload["selected_units"]


def test_fresh_seed_and_unpersisted_ui_defaults(client):
    """Use the new default both after seeding and before a UI row is persisted.

    Args:
        client: Isolated application/database fixture.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert settings.port == 8443
        db.delete(settings)
        db.commit()
        assert ui.get_vcf_offline_depot_settings_row(db, reconcile=False).port == 8443
        assert db.execute(select(VcfOfflineDepotSettings)).scalar_one_or_none() is None


@pytest.mark.parametrize("port", [443, 8443, 9443])
def test_api_read_preserves_saved_depot_port(client, port):
    """Read existing configuration without silently replacing its saved port.

    Args:
        client: Isolated application/database fixture.
        port: Existing configured port.
    """
    from atlaso.app.api.v1 import get_vcf_offline_depot_settings
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.port = port
        db.commit()
        assert get_vcf_offline_depot_settings(db).port == port


@pytest.mark.parametrize("host,port,expected", [
    ("depot.example", None, "depot.example:8443"),
    ("depot.example", 443, "depot.example"),
    ("depot.example", 9443, "depot.example:9443"),
    ("2001:db8::1", 8443, "[2001:db8::1]:8443"),
    ("[2001:db8::1]", 443, "[2001:db8::1]"),
])
def test_effective_depot_endpoint(host, port, expected):
    """Format standard, custom and IPv6 endpoint authorities consistently.

    Args:
        host: Depot DNS name or IP literal.
        port: Explicit port or an unpersisted default.
        expected: Expected authority for HTTPS URLs.
    """
    from atlaso.app.services.vcf_offline_depot import vcf_depot_endpoint

    assert vcf_depot_endpoint(VcfOfflineDepotSettings(hostname=host, port=port)) == expected


@pytest.mark.parametrize("port", [443, 8443, 9443])
def test_nginx_uses_selected_port_for_ipv4_and_ipv6(port):
    """Keep listener ports and published endpoint consistent for each selection.

    Args:
        port: Selected HTTPS port.
    """
    from atlaso.app.services.vcf_offline_depot import render_nginx_depot_config

    settings = VcfOfflineDepotSettings(
        enabled=True, hostname="depot.example", listen_address="192.0.2.1\n2001:db8::1",
        port=port, depot_store_path="/mnt/atlaso-vcf-offline-depot",
    )
    rendered = render_nginx_depot_config(settings)
    assert f"listen 192.0.2.1:{port} ssl;" in rendered
    assert f"listen [2001:db8::1]:{port} ssl;" in rendered
    authority = "depot.example" if port == 443 else f"depot.example:{port}"
    assert f"# VCF endpoint: https://{authority}/PROD/" in rendered


def test_vcf_offline_depot_model_default_port_is_8443():
    """Verify new default port value is 8443 for depot settings model."""
    assert VcfOfflineDepotSettings.__table__.c.port.default.arg == VCF_OFFLINE_DEPOT_DEFAULT_PORT


def test_vcf_offline_depot_archive_restore_defaults_missing_port_to_443(client):
    """Verify legacy archive restore uses 443 when depot port is omitted."""
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        client.get("/vcf-offline-depot")
        archive = export_settings_archive(db, actor="test")
        legacy_archive = deepcopy(archive)
        legacy_archive["data"]["vcf_offline_depot_settings"][0].pop("port", None)

        restore_settings_archive(db, legacy_archive)

        restored = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert restored.port == 443


def test_vcf_offline_depot_archive_restore_preserves_custom_port(client):
    """Verify archive restore preserves explicit custom port values."""
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        client.get("/vcf-offline-depot")
        archive = export_settings_archive(db, actor="test")
        custom_archive = deepcopy(archive)
        custom_archive["data"]["vcf_offline_depot_settings"][0]["port"] = 9443

        restore_settings_archive(db, custom_archive)

        restored = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert restored.port == 9443


def test_update_vcf_offline_depot_settings_omits_port_keeps_saved_value(client):
    """Verify omitted form port does not overwrite stored port."""
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.port = 9999
        db.commit()

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "csrf": csrf,
            "hostname": "depot.atlaso.internal",
            "listen_interface": "eth2",
            "listen_address": "192.168.50.1",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    with SessionLocal() as db:
        restored = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert restored.port == 9999


def test_update_vcf_offline_depot_settings_invalid_port_is_rejected(client):
    """Verify form parsing rejects non-integer port values."""
    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "csrf": csrf,
            "hostname": "depot.atlaso.internal",
            "listen_interface": "eth2",
            "listen_address": "192.168.50.1",
            "port": "https",
            "enabled": "on",
        },
    )

    assert response.status_code == 422
