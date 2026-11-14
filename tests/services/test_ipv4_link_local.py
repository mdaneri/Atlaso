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


def _network_link_local_values(text):
    """Return only effective-setting assignments within Network sections.

    Args:
        text: Rendered public transitional configuration.
    """
    values = []
    section = ""
    for line in text.splitlines():
        if line.startswith("["):
            section = line
        elif section == "[Network]" and line.startswith("LinkLocalAddressing="):
            values.append(line.partition("=")[2])
    return values


@pytest.mark.parametrize("previous_policy", ["no", "ipv4", "ipv6", "yes"])
@pytest.mark.parametrize("candidate_policy", ["no", "ipv4", "ipv6", "yes"])
def test_handoff_unions_old_and_candidate_link_local_families(previous_policy, candidate_policy):
    """Keep both paths' required families in one effective transitional directive.

    Args:
        previous_policy: Previous networkd link-local family selection.
        candidate_policy: Candidate networkd link-local family selection.
    """
    helper = load_helper_module()
    previous = (
        "[Match]\nName=eth0\n[Network]\nAddress=192.0.2.10/24\n"
        f"LinkLocalAddressing={previous_policy}\nDNS=192.0.2.53\n"
        "[Address]\nAddress=fd00:1084:1077::10/64\nDuplicateAddressDetection=ipv6\n"
    )
    candidate = (
        "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n"
        f"LinkLocalAddressing={candidate_policy}\nIPv4LLRoute=no\nConfigureWithoutCarrier=no\n"
        "[DHCPv4]\nSendRelease=no\nMaxAttempts=infinity\n"
    )
    families = {"no": set(), "ipv4": {4}, "ipv6": {6}, "yes": {4, 6}}
    union = families[previous_policy] | families[candidate_policy]
    expected = "yes" if union == {4, 6} else "ipv4" if union == {4} else "ipv6" if union == {6} else "no"
    merged = helper._networkd_handoff_text(previous, candidate)
    assert _network_link_local_values(merged) == [expected]
    assert "Address=192.0.2.10/24" in merged
    assert "Address=fd00:1084:1077::10/64\nDuplicateAddressDetection=ipv6" in merged
    assert "DNS=192.0.2.53" in merged
    assert "DHCP=ipv4" in merged and "MaxAttempts=infinity" in merged
    assert "IPv4LLRoute=no" in merged and "ConfigureWithoutCarrier=no" in merged
    assert "Gateway=" not in merged


@pytest.mark.parametrize("ipv6", [False, True])
def test_installed_static_to_dhcp_holdover_preserves_fallback(tmp_path, monkeypatch, ipv6):
    """Exercise the real renderer and holdover installer without a native Apply.

    Args:
        tmp_path: Owned generated configuration, old snapshot and networkd output.
        monkeypatch: Isolate networkd output and all existing-state reads.
        ipv6: Whether the candidate also requires IPv6 link-local addressing.
    """
    helper = load_helper_module()
    interface = PhysicalInterface(name="eth0", mac_address="02:00:00:00:10:77", role="management",
                                  mode="access", admin_state="up", oper_state="up", mtu=1500,
                                  ipv4_method="dhcp", ipv6_enabled=ipv6, check_duplicate_ip_addresses=False)
    config = tmp_path / "network.conf"
    config.write_text(render_network_config(interfaces=[interface], vlans=[], ipv4_link_local_fallback_enabled=True), encoding="utf-8")
    old = tmp_path / "previous.network"
    old.write_text("[Match]\nName=eth0\n[Network]\nLinkLocalAddressing=no\n[Address]\nAddress=192.0.2.10/24\n", encoding="utf-8")
    output = tmp_path / "networkd"
    output.mkdir()
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", output)
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda *_args: {"DNS": [], "Domains": [], "Gateway": []})
    monkeypatch.setattr(helper.shutil, "which", lambda _name: None)
    state = {"previous_management_interfaces": ["eth0"], "snapshots": [{"path": str(output / "old.network"), "backup": str(old)}]}
    installed = helper._install_management_holdovers(state, {"network_config_path": str(config)})
    assert len(installed) == 1
    text = installed[0].read_text(encoding="utf-8")
    assert _network_link_local_values(text) == ["yes" if ipv6 else "ipv4"]
    assert "Address=192.0.2.10/24" in text
    assert "DHCP=ipv4" in text and "MaxAttempts=infinity" in text
    assert [line for line in text.splitlines() if line.startswith("Gateway=")] == ["Gateway=_dhcp4"] + (["Gateway=_ipv6ra"] if ipv6 else [])
    assert "DNS=" not in text


@pytest.mark.parametrize("previous,candidate,expected", [
    ("[Network]\nLinkLocalAddressing=no\nLinkLocalAddressing=ipv6\n", "[Network]\nLinkLocalAddressing=ipv4\n", ["yes"]),
    ("[Network]\nLinkLocalAddressing=ipv4\n[Network]\nLinkLocalAddressing=no\n", "[Network]\nLinkLocalAddressing=ipv6\n", ["ipv6"]),
    ("[Network]\nLinkLocalAddressing=ipv6\n", "[Network]\nLinkLocalAddressing=ipv4\n[Route]\nTable=100\n[Network]\nLinkLocalAddressing=no\n", ["ipv6"]),
    ("[Network]\nLinkLocalAddressing=no\n[Route]\nLinkLocalAddressing=yes\n", "[Network]\nLinkLocalAddressing=ipv6\n", ["ipv6"]),
    ("[Network]\nLinkLocalAddressing=no\n", "[Match]\nLinkLocalAddressing=invalid\n[Network]\nLinkLocalAddressing=no\n[Route]\nLinkLocalAddressing=yes\n", ["no"]),
    ("[Network]\n", "[Network]\n", []),
    ("[Network]\nLinkLocalAddressing=no\n", "[Network]\n", ["no"]),
    ("[Network]\n", "[Network]\nLinkLocalAddressing=ipv4\n", ["ipv4"]),
    ("[Network]\nLinkLocalAddressing=ipv6\n", "[Network]\n", ["ipv6"]),
])
def test_handoff_link_local_precedence_and_missing_settings(previous, candidate, expected):
    """Honor last Network assignments without inferring missing native defaults.

    Args:
        previous: Previous public configuration with explicit or missing policy.
        candidate: Candidate public configuration, possibly with repeated sections.
        expected: Single merged Network policy, or no invented assignment.
    """
    helper = load_helper_module()
    assert _network_link_local_values(helper._networkd_handoff_text(previous, candidate)) == expected


@pytest.mark.parametrize("unsupported_side", ["previous", "candidate"])
def test_handoff_refuses_unsupported_effective_link_local_policy(unsupported_side):
    """Refuse an unrecognized final policy rather than inventing reachability.

    Args:
        unsupported_side: Input whose final Network assignment is unsupported.
    """
    helper = load_helper_module()
    valid = "[Network]\nLinkLocalAddressing=ipv4\n"
    unsupported = "[Network]\nLinkLocalAddressing=no\n[Network]\nLinkLocalAddressing=unsupported\n"
    with pytest.raises(ValueError, match="link-local policy could not be preserved"):
        helper._networkd_handoff_text(unsupported if unsupported_side == "previous" else valid,
                                     unsupported if unsupported_side == "candidate" else valid)


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


@pytest.mark.parametrize("fallback", [True, False])
@pytest.mark.parametrize("ipv6_mode", ["disabled", "auto", "static"])
def test_first_boot_dynamic_routes_work_before_route_domain_apply(tmp_path, monkeypatch, fallback, ipv6_mode):
    """Keep same-subnet replies direct before any source-rule owner is installed.

    Args:
        tmp_path: Isolated networkd destination.
        monkeypatch: Replace appliance filesystem paths.
        fallback: Global IPv4LL choice, independent of DHCP route reachability.
        ipv6_mode: Initial disabled, SLAAC, or static IPv6 choice.
    """
    import configparser

    from tests.test_vmware_ovf_customization import load_customizer

    customizer = load_customizer()
    destination = tmp_path / "00-atlaso-mgmt.network"
    monkeypatch.setattr(customizer, "NETWORKD_PATH", destination)
    monkeypatch.setattr(customizer, "ENV_PATH", tmp_path / "atlaso.env")
    customizer.write_networkd_config({
        "management_mode": "dhcp", "ipv6_mode": ipv6_mode,
        "ipv6_cidr": "2001:db8:1::10/64", "ipv6_gateway": "fe80::1",
        "dns_servers": [], "ipv4_link_local_fallback_enabled": fallback,
    })
    parsed = configparser.ConfigParser(strict=False)
    parsed.read_string(destination.read_text())
    assert parsed["DHCPv4"]["RouteTable"] == "main"
    if ipv6_mode == "auto":
        assert parsed["IPv6AcceptRA"]["RouteTable"] == "main"
    assert parsed["DHCPv4"].getboolean("SendRelease") is False
    assert parsed["DHCPv4"]["MaxAttempts"] == "infinity"


@pytest.mark.parametrize("ipv6_mode", ["disabled", "auto", "static"])
@pytest.mark.parametrize("dns", [[], ["192.0.2.53"]])
def test_first_boot_opt_out_keeps_network_apply_address_requirements(tmp_path, monkeypatch, ipv6_mode, dns):
    """Recognize an opt-out from the real first-boot file without admitting other edits.

    Args:
        tmp_path: Task-owned first-boot and staged Network files.
        monkeypatch: Isolate preserved resolver state and networkd paths.
        ipv6_mode: First-boot IPv6 intent that the opt-out must preserve.
        dns: Configured resolver intent, or automatic resolver acquisition.
    """
    from tests.test_vmware_ovf_customization import load_customizer

    customizer = load_customizer()
    helper = load_helper_module()
    destination = tmp_path / "00-atlaso-mgmt.network"
    monkeypatch.setattr(customizer, "NETWORKD_PATH", destination)
    monkeypatch.setattr(customizer, "ENV_PATH", tmp_path / "atlaso.env")
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", tmp_path / "route-domains.json")
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", tmp_path / "route-domains.service")
    monkeypatch.setattr(helper, "_read_existing_management_network_values",
                        lambda *_args: {"DNS": dns, "Domains": [], "Gateway": []})
    ipv6_cidr = "2001:db8:1::10/64" if ipv6_mode == "static" else None
    ipv6_gateway = "fe80::1" if ipv6_mode == "static" else None
    customizer.write_networkd_config({
        "management_mode": "dhcp", "ipv6_mode": ipv6_mode,
        "ipv6_cidr": ipv6_cidr, "ipv6_gateway": ipv6_gateway,
        "dns_servers": dns, "ipv4_link_local_fallback_enabled": True,
    })
    interface = PhysicalInterface(name="eth0", mac_address="02:00:00:00:10:77", role="management",
                                  mode="access", admin_state="up", oper_state="up", mtu=1500,
                                  ipv4_method="dhcp", ipv6_enabled=ipv6_mode != "disabled",
                                  ipv6_cidr=ipv6_cidr, ipv6_gateway=ipv6_gateway,
                                  check_duplicate_ip_addresses=True)
    path = tmp_path / "candidate.conf"
    path.write_text(render_network_config(interfaces=[interface], vlans=[],
                                         ipv4_link_local_fallback_enabled=False))
    files, _, _ = helper._systemd_networkd_files(path)
    assert helper._ipv4ll_disable_only_links(path, files) == {"eth0"}
    bootstrap = destination.read_text()
    # Neither a different route table nor a pre-existing applied owner is the
    # known first-boot transition that may skip replacement-lease readiness.
    destination.write_text(bootstrap.replace("RouteTable=main", "RouteTable=200"))
    assert helper._ipv4ll_disable_only_links(path, files) == set()
    destination.write_text(bootstrap)
    helper.ROUTE_DOMAIN_CONFIG_PATH.write_text("{}")
    assert helper._ipv4ll_disable_only_links(path, files) == set()
    helper.ROUTE_DOMAIN_CONFIG_PATH.unlink()
    changed = {name: text.replace("DHCP=ipv4", "DHCP=no") for name, text in files.items()}
    assert helper._ipv4ll_disable_only_links(path, changed) == set()
    destination.write_text(destination.read_text().replace("DHCP=ipv4", "DHCP=no"))
    assert helper._ipv4ll_disable_only_links(path, files) == set()


def test_portable_image_opt_out_matches_network_apply(tmp_path, monkeypatch):
    """Run the portable image emitter without provisioning or touching a host network.

    Args:
        tmp_path: Task-owned emitted and candidate networkd files.
        monkeypatch: Isolate networkd and preserved resolver observations.
    """
    import os
    import shutil
    import subprocess
    from pathlib import Path

    shell = shutil.which("sh") or "C:/Program Files/Git/usr/bin/sh.exe"
    if not Path(shell).is_file():
        pytest.skip("POSIX shell is unavailable")
    source = (Path(__file__).resolve().parents[2] / "image/common/scripts/provision-atlaso.sh").read_text()
    body = source.split('log_step "configuring final appliance management network"\n', 1)[1]
    body = body.split("} >/etc/systemd/network/00-atlaso-mgmt.network", 1)[0] + "}\n"
    result = subprocess.run([shell], input="set -eu\n" + body, capture_output=True, text=True, check=True,
                            env={**os.environ, "ATLASO_MGMT_USES_DHCP": "true", "ATLASO_MGMT_INTERFACE": "eth0",
                                 "ATLASO_IPV4_LINK_LOCAL_FALLBACK_ENABLED": "true"}, timeout=10)
    (tmp_path / "00-atlaso-mgmt.network").write_text(result.stdout)
    interface = PhysicalInterface(name="eth0", mac_address="02:00:00:00:10:77", role="management",
                                  mode="access", admin_state="up", oper_state="up", mtu=1500,
                                  ipv4_method="dhcp", ipv6_enabled=True, check_duplicate_ip_addresses=True)
    path = tmp_path / "candidate.conf"
    path.write_text(render_network_config(interfaces=[interface], vlans=[],
                                         ipv4_link_local_fallback_enabled=False))
    helper = load_helper_module()
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(helper, "_read_existing_management_network_values",
                        lambda *_args: {"DNS": [], "Domains": [], "Gateway": []})
    files, _, _ = helper._systemd_networkd_files(path)
    assert helper._ipv4ll_disable_only_links(path, files) == {"eth0"}


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
