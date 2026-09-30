"""Exercise routing ownership when separate layer-two domains reuse a prefix."""

import shlex
import subprocess

import pytest

from atlaso.app.services.routes_wan import (
    RoutesWanSettings,
    _target_network_owners,
    render_wan_config,
)
from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("management_first", [False, True])
@pytest.mark.parametrize("reverse_labs", [False, True])
@pytest.mark.parametrize("duplicate", [False, True])
@pytest.mark.parametrize("routing_enabled", [False, True])
def test_ingress_preview_matches_helper_owned_rules(monkeypatch, management_first, reverse_labs, duplicate, routing_enabled):
    """Compare preview commands with actual helper rule generation and ordering.

    Args:
        monkeypatch: Replace only native observation and command execution.
        management_first: Whether management precedes lab targets.
        reverse_labs: Whether caller enumeration opposes interface-name order.
        duplicate: Whether a projected lab target appears twice.
        routing_enabled: Whether global Routing is desired.
    """
    helper = load_helper_module()
    management = {"name": "eth0", "routing_domain": "management", "ip_cidr": "192.0.2.10/24"}
    labs = [{"name": "eth1", "routing_domain": "lab", "ip_cidr": "192.0.2.20/24"},
            {"name": "eth2", "routing_domain": "lab", "ip_cidr": "", "ipv6_cidr": ""}]
    if reverse_labs:
        labs.reverse()
    if duplicate:
        labs.append(dict(labs[0]))
    targets = [management, *labs] if management_first else [*labs, management]
    preview = render_wan_config([], targets=targets, settings=RoutesWanSettings(
        routing_enabled=routing_enabled, nat_enabled=False, wan_simulation_enabled=False))
    commands = []
    monkeypatch.setattr(helper, "_snapshot_route_domain_rules", lambda: [])
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    desired = helper._route_domain_ingress_rules(["eth1", "eth2"]) if routing_enabled else []
    helper._restore_route_domain_rules(desired)
    shown = []
    for line in preview.splitlines():
        if line.startswith(("ip rule add iif ", "ip -6 rule add iif ")):
            command = shlex.split(line)
            if command[1] == "rule":
                command.insert(1, "-4")
            shown.append(command)
    assert shown == commands
    if routing_enabled:
        assert len(shown) == 8
        assert all("unreachable" in command for command in shown[:4])
        assert all(command[-2:] == ["protocol", "2"] for command in shown)
    else:
        assert "owned IPv4/IPv6 lab ingress lookups and terminal guards to an empty set" in preview
        assert "rule del priority" not in preview


@pytest.mark.parametrize("helper_side", [False, True])
@pytest.mark.parametrize("management_first", [False, True])
def test_connected_prefix_owner_is_scoped_to_routing_domain(helper_side, management_first):
    """Keep both domain routes regardless of interface enumeration order.

    Args:
        helper_side: Whether to exercise the privileged helper or application projection.
        management_first: Whether management appears before the overlapping lab interface.
    """
    targets = [
        {"name": "eth0", "routing_domain": "management", "ip_cidr": "192.0.2.10/24",
         "ipv6_cidr": "2001:db8:1::10/64"},
        {"name": "eth1", "routing_domain": "lab", "ip_cidr": "192.0.2.20/24",
         "ipv6_cidr": "2001:db8:1::20/64"},
    ]
    if not management_first:
        targets.reverse()
    # A duplicate inside the same routing domain still has one deterministic owner.
    targets.append({"name": "eth2", "routing_domain": "lab", "ip_cidr": "192.0.2.30/24",
                    "ipv6_cidr": "2001:db8:1::30/64"})
    owners = (load_helper_module()._target_network_owners if helper_side else _target_network_owners)(targets)
    for prefix in ("192.0.2.0/24", "2001:db8:1::/64"):
        assert targets[owners[("management", prefix)]]["name"] == "eth0"
        assert targets[owners[("lab", prefix)]]["name"] == "eth1"


def test_networkd_connected_routes_have_one_owner_per_domain(monkeypatch, tmp_path):
    """Networkd and WAN must not race duplicate same-domain connected routes.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
    helper = load_helper_module()
    physical = [
        {"name": "eth0", "role": "management", "mode": "access", "admin_state": "up",
         "ipv4_method": "static", "ip_cidr": "192.0.2.10/24", "ipv6_enabled": "true", "ipv6_cidr": "2001:db8::10/64"},
        {"name": "eth1", "role": "access", "mode": "access", "admin_state": "up",
         "ipv4_method": "static", "ip_cidr": "192.0.2.20/24", "ipv6_enabled": "true", "ipv6_cidr": "2001:db8::20/64"},
        {"name": "eth2", "role": "access", "mode": "access", "admin_state": "up",
         "ipv4_method": "static", "ip_cidr": "192.0.2.30/24", "ipv6_enabled": "true", "ipv6_cidr": "2001:db8::30/64"},
    ]
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: (physical, [], []))
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda _names=None: {"DNS": [], "Gateway": [], "Name": []})
    monkeypatch.setattr(helper, "_runtime_default_gateways_for_interface", lambda _name: [])
    files, _, _ = helper._systemd_networkd_files(tmp_path / "network.conf")
    for prefix in ("192.0.2.0/24", "2001:db8::/64"):
        assert f"Destination={prefix}" in files["00-atlaso-mgmt.network"]
        assert f"Destination={prefix}" in files[helper._networkd_managed_filename("eth1", "network")]
        assert f"Destination={prefix}" not in files[helper._networkd_managed_filename("eth2", "network")]
