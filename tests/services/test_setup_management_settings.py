"""Keep verified setup publication scoped to desired Settings and terminal identity."""

import json

import pytest


@pytest.fixture
def setup_publication(client, monkeypatch):
    """Model an independently admitted publication without seeding ordinary inventory.

    Args:
        client: Initialize the isolated appliance database.
        monkeypatch: Replace the separately tested root publication reader and CA availability.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        CaSettings,
        DnsSettings,
        PhysicalInterface,
    )
    from atlaso.app.services import dynamic_management

    with SessionLocal() as db:
        row = db.query(PhysicalInterface).filter_by(name="eth0").one()
        row.role, row.mode, row.admin_state, row.oper_state = "management", "access", "up", "up"
        row.ipv4_method, row.ip_cidr, row.host_ip_cidr = "dhcp", None, None
        row.host_ip_cidrs, row.ipv6_enabled = [], False
        settings = db.query(ApplianceSettings).one()
        settings.web_terminal_enabled, settings.management_https_enabled = True, True
        settings.web_terminal_interfaces_json, settings.external_dns_servers = '["eth0"]', ""
        db.query(DnsSettings).one().enabled = False
        db.query(CaSettings).one().enabled = True
        receipt = {"interface": "eth0", "mac": row.mac_address, "addresses": ["169.254.20.10"],
                   "apipa_addresses": ["169.254.20.10"]}
        db.commit()
    monkeypatch.setattr(dynamic_management, "read_publication", lambda _db: receipt)
    monkeypatch.setattr(ui, "ensure_ca_state", lambda _db, **_kwargs: [])
    monkeypatch.setattr(ui, "ca_managed_certificate_paths", lambda *_args: ("/public/leaf", "/public/key", "/public/chain"))
    monkeypatch.setattr(ui, "ca_certificate_available", lambda *_args: True)
    return receipt


@pytest.mark.parametrize("change", ["none", "moved", "static", "down", "missing", "mac"])
def test_settings_publication_requires_selected_desired_identity(setup_publication, change):
    """An applied old NIC cannot displace pending desired identity or static intent.

    Args:
        setup_publication: Fresh verified setup receipt bound to the original MAC.
        change: Desired identity or eligibility change since publication.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        old = db.query(PhysicalInterface).filter_by(name="eth0").one()
        if change == "moved":
            old.role = "unused"
            new = db.query(PhysicalInterface).filter_by(name="eth1").one_or_none()
            if new is None:
                new = PhysicalInterface(name="eth1", mac_address="02:00:00:00:10:88")
                db.add(new)
            new.role, new.mode, new.admin_state, new.oper_state = "management", "access", "up", "up"
            new.ipv4_method, new.ip_cidr, new.host_ip_cidr = "dhcp", None, None
            new.host_ip_cidrs, new.ipv6_enabled = [], False
        elif change == "static":
            old.ipv4_method, old.ip_cidr = "static", "192.0.2.50/24"
        elif change == "down":
            old.admin_state = "down"
        elif change == "missing":
            old.oper_state = "missing"
        elif change == "mac":
            old.mac_address = "02:00:00:00:10:99"
        db.commit()
        management = ui.appliance_settings_management_context(db)
        context = ui.appliance_settings_context(db, reconcile_dns=False)
        preview = json.loads(context["appliance_settings_config_preview"])
        expected = "169.254.20.10" if change == "none" else "192.0.2.50" if change == "static" else ""
        assert management["ip"] == expected
        assert preview["management_ip"] == expected
        if change == "moved":
            assert management["name"] == preview["management_interface"] == "eth1"
            assert preview["resolver_mode"] == "dhcp"
            assert preview["web_terminal_addresses"] == []
        assert old.host_ip_cidr is None and old.host_ip_cidrs == []


def test_verified_setup_projects_terminal_preview_and_api(setup_publication, monkeypatch):
    """Settings-specific terminal projection leaves generic service inventory empty.

    Args:
        setup_publication: Verified setup context for the selected dedicated NIC.
        monkeypatch: Model CA availability for the equivalent versioned response.
    """
    from atlaso.app import ui
    from atlaso.app.api import v1
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    monkeypatch.setattr(v1, "ca_managed_certificate_available", lambda *_args: (True, "/public/leaf", "/public/key"))
    with SessionLocal() as db:
        context = ui.appliance_settings_context(db, reconcile_dns=False)
        preview = json.loads(context["appliance_settings_config_preview"])
        assert context["appliance_settings_validation_errors"] == []
        assert preview["web_terminal_addresses"] == ["169.254.20.10"]
        assert context["web_terminal_addresses"] == ["169.254.20.10"]
        assert context["web_terminal_interface_options"][0]["name"] == "eth0"
        rows = db.query(PhysicalInterface).all()
        ordinary_options = ui.web_terminal_interface_options(rows, [])
        assert not any(option["name"] == "eth0" for option in ordinary_options)
        assert all("169.254.20.10" not in option["addresses"] for option in ordinary_options)
        assert not ui.management_dhcp_dns_context(rows, [])[0]["ip"]
        response = v1.appliance_settings_response(db, ui.get_settings())
        assert response.management_ip == "169.254.20.10"
        assert response.valid
        assert json.loads(response.config_preview)["web_terminal_addresses"] == ["169.254.20.10"]


def test_unrelated_settings_save_keeps_setup_terminal_valid(client, setup_publication):
    """The ordinary reviewed Settings form can save with Web Terminal already enabled.

    Args:
        client: Authenticated browser transport fixture.
        setup_publication: Verified APIPA-only management publication.
    """
    from tests.routers.ui.helpers import login

    login(client)
    page = client.get("/ui/management/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/ui/management/settings", headers={"X-Atlaso-Autosave": "1"}, data={
        "csrf": csrf, "fqdn": "core.atlaso.internal", "management_https_enabled": "on",
        "web_terminal_enabled": "on", "root_ssh_enabled": "on", "external_dns_servers": "",
    })
    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"], payload["validation_errors"]
    assert json.loads(payload["config_preview"])["web_terminal_addresses"] == ["169.254.20.10"]
