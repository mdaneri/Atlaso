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


def test_dual_stack_settings_matches_completed_apipa_handoff(setup_publication, monkeypatch):
    """Keep the completed Network projection and ordinary Settings snapshot identical.

    Args:
        setup_publication: Verified publication for the selected management NIC.
        monkeypatch: Isolate the observed DHCP DNS read from the test host.
    """
    from datetime import datetime, timezone

    from atlaso.app import appliance_console, ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface
    from atlaso.app.services import appliance_settings

    apipa = "169.254.20.10"
    ipv6 = "2001:db8::10"
    ipv6_cidr = ipv6 + "/64"
    job_id = "job_dual_stack_ipv4ll"
    monkeypatch.setattr(appliance_settings, "observed_management_dhcp_dns_servers", lambda _name: [])
    setup_publication.update(addresses=[ipv6], apipa_addresses=[])
    with SessionLocal() as db:
        interface = db.query(PhysicalInterface).filter_by(name="eth0").one()
        interface.ipv6_enabled = True
        interface.ipv6_cidr = interface.host_ipv6_cidr = ipv6_cidr
        interface.host_ipv6_cidrs = [ipv6_cidr]
        db.flush()
        captured, network_preview = appliance_console._captured_management_settings_unit(db)
        assert json.loads(captured["raw_config_preview"])["management_ip"] == ipv6

        observation = {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "complete": True,
            "links": [{
                "name": interface.name, "mac": interface.mac_address, "configured": True,
                "ethernet": True, "up": True, "carrier": True, "address_inventory_complete": True,
                "addresses": [
                    {"address": apipa, "cidr": apipa + "/16", "state": "assigned", "source": "IPv4LL", "scope": "link"},
                    {"address": ipv6, "cidr": ipv6_cidr, "state": "assigned", "source": "static", "scope": "global"},
                ],
            }],
        }
        db.add(Job(
            id=job_id, type="appliance-apply", status=JobStatus.SUCCEEDED.value, created_by="test",
            result=json.dumps({"units": [{"unit_id": "network", "management_handoff": {
                "candidate_addresses": [apipa, ipv6], "management_address_observation": observation,
            }}]}),
        ))
        db.commit()

    setup_publication.update(addresses=[ipv6, apipa], apipa_addresses=[apipa])
    with SessionLocal() as db:
        actual, _network = appliance_console._captured_management_settings_unit(db)
        preview = json.loads(actual["raw_config_preview"])
        assert preview["management_ip"] == apipa
        assert preview["management_ip_cidr"] == apipa + "/16"
        assert preview["web_terminal_addresses"] == [apipa, ipv6]
        rows = db.query(PhysicalInterface).all()
        ordinary, _dns = ui.management_dhcp_dns_context(rows, [])
        assert ordinary["addresses"] == [ipv6]

    native = {
        "network_job_id": job_id,
        "physical_interfaces": [{"name": "eth0", "ipv6_cidrs": [ipv6_cidr]}],
    }
    expected = appliance_console._post_handoff_settings_snapshot(
        job_id, captured, network_preview, captured["snapshot_hash"], native_observation=native,
    )
    assert expected == actual["snapshot_hash"]

    with SessionLocal() as db:
        interface = db.query(PhysicalInterface).filter_by(name="eth0").one()
        interface.host_ip_cidr = "192.0.2.20/24"
        db.flush()
        leased, _network = appliance_console._captured_management_settings_unit(db)
        preview = json.loads(leased["raw_config_preview"])
        assert preview["management_ip"] == "192.0.2.20"
        assert preview["web_terminal_addresses"] == ["192.0.2.20", ipv6]


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
