"""Exercise routing ownership when separate layer-two domains reuse a prefix."""

import pytest

from atlaso.app.services.routes_wan import _target_network_owners
from tests.test_appliance_helper import load_helper_module


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
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda: {"DNS": [], "Gateway": [], "Name": []})
    monkeypatch.setattr(helper, "_runtime_default_gateways_for_interface", lambda _name: [])
    files, _, _ = helper._systemd_networkd_files(tmp_path / "network.conf")
    for prefix in ("192.0.2.0/24", "2001:db8::/64"):
        assert f"Destination={prefix}" in files["00-atlaso-mgmt.network"]
        assert f"Destination={prefix}" in files[helper._networkd_managed_filename("eth1", "network")]
        assert f"Destination={prefix}" not in files[helper._networkd_managed_filename("eth2", "network")]
