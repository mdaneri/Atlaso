"""Exercise DHCPv4 fallback intent and observations without mutating a network."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from atlaso.app.models import ApplianceSettings, PhysicalInterface
from atlaso.app.services.network_address_status import (
    ipv4_acquisition_status,
    row_status,
)
from atlaso.app.services.networking import render_network_config
from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("method", ["dhcp", "static"])
@pytest.mark.parametrize("ipv6", [True, False])
@pytest.mark.parametrize("enabled", [True, False])
def test_networkd_fallback_preserves_address_families(tmp_path, monkeypatch, method, ipv6, enabled):
    """Keep fallback independent of static IPv4 and IPv6 desired state.

    Args:
        tmp_path: Task-owned generated configuration directory.
        monkeypatch: Isolate preserved appliance network state.
        method: Requested IPv4 acquisition mode.
        ipv6: Whether IPv6 is enabled.
        enabled: Global fallback choice.
    """
    interface = PhysicalInterface(name="eth0", mac_address="02:00:00:00:10:77", role="management",
                                  mode="access", admin_state="up", oper_state="up", mtu=1500,
                                  ipv4_method=method, ip_cidr="192.168.50.10/24" if method == "static" else None,
                                  ipv6_enabled=ipv6, check_duplicate_ip_addresses=False)
    preview = render_network_config(interfaces=[interface], vlans=[], ipv4_link_local_fallback_enabled=enabled)
    path = tmp_path / "network.conf"
    path.write_text(preview)
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda *_args: {"DNS": [], "Domains": [], "Gateway": []})
    monkeypatch.setattr(helper.shutil, "which", lambda _name: None)
    files, _, _ = helper._systemd_networkd_files(path)
    rendered = files["00-atlaso-mgmt.network"]
    ipv4ll = enabled and method == "dhcp"
    expected = ("yes" if ipv6 else "ipv4") if ipv4ll else ("ipv6" if ipv6 else "no")
    assert f"LinkLocalAddressing={expected}\n" in rendered
    assert ("MaxAttempts=infinity" in rendered) == (method == "dhcp")
    assert ("Address=192.168.50.10/24" in rendered) == (method == "static")
    if ipv4ll:
        assert "ConfigureWithoutCarrier=no" in rendered
        assert "IPv4LLRoute=no" in rendered
        assert "SendDecline=no" in rendered  # IPv4LL still uses mandatory native ACD.
    assert all(line.startswith("Gateway=_") for line in rendered.splitlines() if line.startswith("Gateway="))
    assert "DNS=" not in rendered


@pytest.mark.parametrize("carrier,state,source,expected", [
    (False, "assigned", "IPv4LL", "no-carrier"),
    (True, "checking", "IPv4LL", "waiting-dhcp"),
    (True, "conflict", "IPv4LL", "waiting-dhcp"),
    (True, "assigned", "static", "waiting-dhcp"),
    (True, "assigned", "IPv4LL", "apipa"),
])
def test_acquisition_requires_carrier_and_native_source(carrier, state, source, expected):
    """A link-local address alone never proves a usable native fallback.

    Args:
        carrier: Current carrier observation.
        state: Native address state.
        source: Networkd address provenance.
        expected: Expected acquisition classification.
    """
    link = {"up": True, "carrier": carrier,
            "addresses": [{"address": "169.254.20.10", "state": state, "source": source}]}
    status = ipv4_acquisition_status(link, complete=True, dhcp4=True)
    assert status["ipv4_state"] == expected
    assert bool(status["ipv4ll_addresses"]) == (expected == "apipa")


def test_later_dhcp_lease_replaces_apipa_projection():
    """Prefer a proven lease even during native IPv4LL removal."""
    link = {"up": True, "carrier": True, "addresses": [
        {"address": "169.254.20.10", "state": "assigned", "source": "IPv4LL"},
        {"address": "192.168.50.10", "state": "assigned", "source": "DHCPv4"},
    ]}
    status = ipv4_acquisition_status(link, complete=True, dhcp4=True)
    assert status["ipv4_state"] == "dhcp-ready"
    assert status["ipv4ll_addresses"] == []


def test_ipv4ll_reselection_is_not_a_declined_dhcp_offer():
    """Retain conflict history without waiting for DHCP to validate a new fallback."""
    from atlaso.app.services.network_address_status import project_status
    from tests.test_network_address_status import observation, resource

    sample = observation(address="169.254.20.11", conflicts=[{
        "name": "eth0", "address": "169.254.20.10", "detected_at": "2026-10-01T00:00:00+00:00",
    }])
    sample["links"][0]["addresses"][0]["source"] = "IPv4LL"
    projected = project_status(sample, {}, [{**resource(), "desired": [], "dhcp4": True}])["rows"]["physical:1"]
    assert projected["state"] == "assigned"
    assert projected["ipv4_state"] == "apipa"
    assert projected["last_conflict"]["address"] == "169.254.20.10"


def test_stale_observation_withholds_fallback():
    """A retained address must not be advertised as current setup evidence."""
    old = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()
    status = row_status({"rows": {"physical:1": {"observed_at": old, "ipv4_state": "apipa",
                                                "ipv4ll_addresses": ["169.254.20.10"]}}}, "physical", 1)
    assert status["ipv4_state"] == "unknown"
    assert status["ipv4ll_addresses"] == []


def test_helper_rejects_mixed_per_interface_fallback_choices(tmp_path):
    """Keep the host boundary global even for malformed staged configuration.

    Args:
        tmp_path: Receipted task-owned staged Network fixture.
    """
    path = tmp_path / "mixed.conf"
    path.write_text("[physical_interfaces]\ninterface=eth0\n  ipv4_link_local_fallback_enabled=true\n"
                    "interface=eth1\n  ipv4_link_local_fallback_enabled=false\n")
    assert any("one global choice" in error for error in load_helper_module()._network_config_errors(path))


def test_upgrade_defaults_only_new_column(tmp_path):
    """Add the default once and retain an opt-out on subsequent schema startup.

    Args:
        tmp_path: Task-owned isolated legacy database directory.
    """
    from sqlalchemy import create_engine, text

    from atlaso.app.database import _reconcile_authentication_lifetime_columns

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE appliance_settings (id INTEGER PRIMARY KEY)"))
        connection.execute(text("INSERT INTO appliance_settings (id) VALUES (1)"))
        _reconcile_authentication_lifetime_columns(connection)
        assert connection.scalar(text("SELECT ipv4_link_local_fallback_enabled FROM appliance_settings")) == 1
        connection.execute(text("UPDATE appliance_settings SET ipv4_link_local_fallback_enabled = FALSE"))
        _reconcile_authentication_lifetime_columns(connection)
        assert connection.scalar(text("SELECT ipv4_link_local_fallback_enabled FROM appliance_settings")) == 0
    engine.dispose()


def test_first_boot_retry_preserves_applied_opt_out(tmp_path, monkeypatch):
    """Keep an applied false choice when an OVF customization envelope is retried.

    Args:
        tmp_path: Task-owned generated networkd and environment fixtures.
        monkeypatch: Replace appliance paths with isolated fixtures.
    """
    from tests.test_vmware_ovf_customization import load_customizer

    customizer = load_customizer()
    destination = tmp_path / "00-atlaso-mgmt.network"
    monkeypatch.setattr(customizer, "NETWORKD_PATH", destination)
    monkeypatch.setattr(customizer, "ENV_PATH", tmp_path / "atlaso.env")
    config = {"management_mode": "dhcp", "ipv6_mode": "disabled", "dns_servers": []}
    customizer.write_networkd_config({**config, "ipv4_link_local_fallback_enabled": False})
    for _ in range(2):
        customizer.write_networkd_config(config)
        rendered = destination.read_text()
        assert "LinkLocalAddressing=no" in rendered
        assert "DHCP=ipv4" in rendered
        assert "MaxAttempts=infinity" in rendered


def test_native_apply_accepts_only_owned_ready_ipv4ll(tmp_path, monkeypatch):
    """Use native provenance and carrier rather than accepting arbitrary link-local IPs.

    Args:
        tmp_path: Task-owned staged Network intent.
        monkeypatch: Supply sanitized observations without network operations.
    """
    helper = load_helper_module()
    path = tmp_path / "network.conf"
    path.write_text("[physical_interfaces]\ninterface=eth0\n  ipv4_method=dhcp\n  ipv6_enabled=false\n  admin_state=up\n")
    link = {"name": "eth0", "up": True, "carrier": True, "configured": True,
            "addresses": [{"address": "169.254.20.10", "cidr": "169.254.20.10/16", "source": "IPv4LL", "state": "assigned"}]}
    observation = {"complete": True, "links": [link], "conflicts": []}
    monkeypatch.setattr(helper, "_network_address_observation", lambda: observation)
    monkeypatch.setattr(helper, "_retain_network_conflicts", lambda *_args: None)
    assert helper._wait_network_addresses(path, attempts=1) == observation
    for field, value in (("carrier", False), ("up", False)):
        link[field] = value
        with pytest.raises(ValueError, match="Unable to verify"):
            helper._wait_network_addresses(path, attempts=1)
        link[field] = True
    link["addresses"][0]["source"] = "static"
    with pytest.raises(ValueError, match="Unable to verify"):
        helper._wait_network_addresses(path, attempts=1)


@pytest.mark.parametrize("enabled", [True, False])
def test_link_local_cannot_be_forwarded_even_with_firewall_disabled(enabled):
    """Enforce the link-local boundary before established-flow and routing allows.

    Args:
        enabled: Ordinary filtering desired state, independent of link-local isolation.
    """
    from atlaso.app.models import FirewallSettings
    from atlaso.app.services.firewall import render_nftables_config

    settings = FirewallSettings(enabled=enabled, default_input_policy="accept", default_forward_policy="accept",
                                default_output_policy="accept", allow_established=True)
    program = render_nftables_config(settings, [])
    assert "ip saddr 169.254.0.0/16 drop" in program
    assert "ip daddr 169.254.0.0/16 drop" in program
    helper = load_helper_module()
    assert helper._ipv4ll_preserve_forward_guard(program) == program
    rollback = helper._ipv4ll_preserve_forward_guard("flush ruleset\n")
    assert "ip saddr 169.254.0.0/16 drop" in rollback
    assert helper._ipv4ll_preserve_forward_guard(rollback) == rollback
    assert helper._ipv4ll_preserve_forward_guard("delete table inet unrelated\n") == "delete table inet unrelated\n"


@pytest.mark.parametrize("legacy", [False, True])
def test_global_opt_out_survives_archive_restore(client, legacy):
    """Restore an explicit false value without replacing it with the new default.

    Args:
        client: Isolated application/database fixture.
        legacy: Whether the archive predates the global setting.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        settings = db.scalar(select(ApplianceSettings))
        assert settings.ipv4_link_local_fallback_enabled is True
        settings.ipv4_link_local_fallback_enabled = False
        db.commit()
        archive = export_settings_archive(db, actor="test")
        assert archive["data"]["appliance_settings"][0]["ipv4_link_local_fallback_enabled"] is False
        if legacy:
            del archive["data"]["appliance_settings"][0]["ipv4_link_local_fallback_enabled"]
        restore_settings_archive(db, archive)
        assert db.scalar(select(ApplianceSettings)).ipv4_link_local_fallback_enabled is False


def test_global_ui_opt_out_is_desired_state_only(client):
    """Save a global opt-out and capture it in every Network Apply row.

    Args:
        client: Isolated authenticated application fixture.
    """
    from atlaso.app.database import SessionLocal
    from tests.routers.ui.helpers import login

    login(client)
    page = client.get("/ui/management/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/ui/management/physical-interfaces/link-local-fallback", data={"csrf": csrf}, follow_redirects=False)
    assert response.status_code == 303, response.text
    with SessionLocal() as db:
        from atlaso.app.ui import network_context

        assert db.scalar(select(ApplianceSettings)).ipv4_link_local_fallback_enabled is False
        preview = network_context(db)["network_config_preview"]
        assert "ipv4_link_local_fallback_enabled=false" in preview
        assert "ipv4_link_local_fallback_enabled=true" not in preview
