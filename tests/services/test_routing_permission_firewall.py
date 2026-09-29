"""Verify routing denials at the nftables enforcement and upgrade boundaries."""

import pytest
from sqlalchemy import create_engine, inspect, text

from atlaso.app.database import _reconcile_routing_permission_columns
from atlaso.app.models import (
    FirewallRule,
    FirewallSettings,
    PhysicalInterface,
    RoutingRule,
    VlanInterface,
)
from atlaso.app.services.firewall import (
    managed_routing_firewall_rules,
    render_nftables_config,
    validate_firewall_state,
)


def topology():
    """Return management, overlapping route networks and a dual-stack VLAN."""
    return [
        PhysicalInterface(name="mgmt", role="management", mode="access", ip_cidr="192.0.2.1/24"),
        PhysicalInterface(name="a", role="route", mode="access", ip_cidr="10.0.0.1/24", ipv6_cidr="2001:db8:a::1/64"),
        PhysicalInterface(name="b", role="route", mode="access", ip_cidr="10.0.1.1/24", ipv6_cidr="2001:db8:b::1/64"),
        PhysicalInterface(name="other", role="route", mode="access", ip_cidr="10.0.1.2/24"),
        PhysicalInterface(name="trunk", role="unused", mode="trunk"),
    ], [VlanInterface(name="trunk.20", parent_interface="trunk", vlan_id=20, enabled=True,
                      role="route", ip_cidr="10.20.0.1/24", ipv6_cidr="2001:db8:20::1/64")]


def settings():
    """Enable broad diagnostics and established traffic for precedence checks."""
    return FirewallSettings(enabled=True, allow_established=True, allow_icmp=True,
                            default_input_policy="drop", default_forward_policy="drop", default_output_policy="accept")


def test_deny_precedes_established_diagnostics_and_overlapping_accepts():
    """An exact directed denial must block even pre-existing connections."""
    interfaces, vlans = topology()
    deny = RoutingRule(id=41, name="Deny VLAN", enabled=True, source_interface="a",
                       destination_interface="trunk.20", policy="deny", ip_family=4, priority=999)
    allow = RoutingRule(id=42, name="Allow VLAN", enabled=True, source_interface="a",
                        destination_interface="trunk.20", policy="allow", ip_family=0, priority=0)
    broad = FirewallRule(name="Broad", direction="forward", action="accept", protocol="any",
                         source="any", destination="any", destination_port="", interface_name="",
                         enabled=True, priority=0)
    generated = managed_routing_firewall_rules(interfaces, vlans, [allow, deny])
    config = render_nftables_config(settings(), [broad], generated, replace_atlaso_service_rules=True)
    forward = config.split("chain forward {", 1)[1].split("chain output {", 1)[0]
    denial = 'oifname "trunk.20" iifname "a" ip saddr 10.0.0.0/24 ip daddr 10.20.0.0/24 drop comment "routing-41-deny-vlan"'
    assert denial in forward
    assert forward.index(denial) < forward.index("ct state established")
    assert forward.index(denial) < forward.index("Atlaso ICMP diagnostics")
    assert forward.index(denial) < forward.index('comment "Broad"')
    assert 'ip6 saddr 2001:db8:a::/64 ip6 daddr 2001:db8:20::/64 drop' not in forward
    assert 'oifname "other" iifname "a"' in forward
    assert 'oifname "a" iifname "trunk.20"' in forward
    assert 'comment "routing-41-deny-vlan"' not in config.split("chain forward {", 1)[0]


@pytest.mark.parametrize("policy", ["allow", "automatic"])
def test_operator_forward_drop_priority_precedes_routing_accepts(policy):
    """An operator restriction retains its ordinary lower-priority-first ordering.

    Args:
        policy: Explicit allow or inherited route-role authorization.
    """
    interfaces, vlans = topology()
    permission = RoutingRule(id=11, name="Allow path", enabled=True, source_interface="a", destination_interface="b",
                             policy=policy, ip_family=4, priority=100)
    drop = FirewallRule(name="Operator restriction", direction="forward", action="drop", protocol="tcp",
                        source="10.0.0.0/24", destination="10.0.1.0/24", destination_port="443",
                        interface_name="a", enabled=True, priority=0)
    generated = managed_routing_firewall_rules(interfaces, vlans, [permission])
    config = render_nftables_config(settings(), [drop], generated, replace_atlaso_service_rules=True)
    forward = config.split("chain forward {", 1)[1].split("chain output {", 1)[0]
    assert forward.index('comment "Operator restriction"') < forward.index('comment "route-a-to-b"')
    if policy == "allow":
        assert forward.index('comment "Operator restriction"') < forward.index('comment "routing-11-allow-path"')


@pytest.mark.parametrize("policy,expected", [("allow", True), ("automatic", False), ("deny", True)])
def test_automatic_revert_and_dual_stack_are_exact(policy, expected):
    """Inheritance removes only the override and retains route-role admission."""
    interfaces, vlans = topology()
    rule = RoutingRule(id=10, name="Override", enabled=True, source_interface="a", destination_interface="b",
                       policy=policy, ip_family=0, priority=100)
    generated = managed_routing_firewall_rules(interfaces, vlans, [rule])
    config = render_nftables_config(settings(), [], generated, replace_atlaso_service_rules=True)
    assert ('comment "routing-10-override"' in config) is expected
    assert 'ip saddr 10.0.0.0/24 ip daddr 10.0.1.0/24' in config
    assert 'ip6 saddr 2001:db8:a::/64 ip6 daddr 2001:db8:b::/64' in config
    assert 'comment "route-a-to-b"' in config


def test_suspension_keeps_management_isolation_and_disabled_firewall_rejects_deny():
    """Routing off suspends lab intent while management remains isolated."""
    interfaces, vlans = topology()
    rule = RoutingRule(id=10, name="Override", enabled=True, source_interface="a", destination_interface="b",
                       policy="deny", ip_family=0, priority=100)
    generated = managed_routing_firewall_rules(interfaces, vlans, [rule], routing_enabled=False)
    assert generated and all(item.routing_policy_phase == "isolation" for item in generated)
    generated = managed_routing_firewall_rules(interfaces, vlans, [rule])
    disabled = settings()
    disabled.enabled = False
    assert any("Enable Firewall" in error for error in validate_firewall_state(disabled, [], generated))


def test_upgrade_adds_defaults_without_losing_existing_permissions():
    """Serialized additive startup reconciliation is repeatable and preserves legacy data."""
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE routing_rules (id INTEGER PRIMARY KEY, name TEXT)"))
        connection.execute(text("INSERT INTO routing_rules VALUES (1, 'Legacy')"))
        _reconcile_routing_permission_columns(connection)
        _reconcile_routing_permission_columns(connection)
        assert {column["name"] for column in inspect(connection).get_columns("routing_rules")} >= {"policy", "ip_family"}
        assert connection.execute(text("SELECT name, policy, ip_family FROM routing_rules")).one() == ("Legacy", "allow", 0)


@pytest.mark.parametrize("destination_role", ["route", "access"])
@pytest.mark.parametrize("saved_automatic", [False, True])
def test_access_automatic_denial_is_enforced_with_accept_forward_policy(destination_role, saved_automatic):
    """Enforce Access defaults before established traffic and broad accepts.

    Args:
        destination_role: Other lab endpoint role.
        saved_automatic: Include a saved automatic permission or use defaults.
    """
    interfaces, vlans = topology()
    interfaces[1].role = "access"
    interfaces[2].role = destination_role
    permissions = [RoutingRule(name="Inherit", enabled=True, source_interface="a", destination_interface="b", policy="automatic", ip_family=4)] if saved_automatic else []
    generated = managed_routing_firewall_rules(interfaces, vlans, permissions)
    firewall = settings()
    firewall.default_forward_policy = "accept"
    broad = FirewallRule(name="Broad", direction="forward", action="accept", protocol="any", source="any", destination="any", destination_port="", interface_name="", enabled=True, priority=0)
    config = render_nftables_config(firewall, [broad], generated, replace_atlaso_service_rules=True)
    forward = config.split("chain forward {", 1)[1].split("chain output {", 1)[0]
    for version in (4, 6):
        marker = f'comment "routing-default-deny-a-to-b-ipv{version}"'
        assert marker in forward
        assert forward.index(marker) < forward.index("ct state established")
        assert forward.index(marker) < forward.index("Atlaso ICMP diagnostics")
        assert forward.index(marker) < forward.index('comment "Broad"')
    firewall.enabled = False
    assert any("Enable Firewall" in error for error in validate_firewall_state(firewall, [], generated))
    suspended = managed_routing_firewall_rules(interfaces, vlans, permissions, routing_enabled=False)
    assert not any(item.routing_policy_phase == "deny" for item in suspended)
    assert validate_firewall_state(firewall, [], suspended) == []


@pytest.mark.parametrize("enabled", [False, True])
def test_explicit_access_allow_suppresses_only_its_directed_family_default(enabled):
    """Preserve per-family allow precedence and independent reverse decisions.

    Args:
        enabled: Whether the explicit IPv4 allow is active.
    """
    interfaces, vlans = topology()
    interfaces[1].role = "access"
    allow = RoutingRule(id=50, name="Allow IPv4", enabled=enabled, source_interface="a", destination_interface="b", policy="allow", ip_family=4, priority=100)
    generated = managed_routing_firewall_rules(interfaces, vlans, [allow])
    names = {item.name for item in generated}
    assert ("routing-default-deny-a-to-b-ipv4" in names) is not enabled
    assert "routing-default-deny-a-to-b-ipv6" in names
    assert "routing-default-deny-b-to-a-ipv4" in names
    assert "routing-default-deny-b-to-a-ipv6" in names
    deny = RoutingRule(id=51, name="Deny IPv4", enabled=True, source_interface="a", destination_interface="b", policy="deny", ip_family=4, priority=999)
    config = render_nftables_config(settings(), [], managed_routing_firewall_rules(interfaces, vlans, [allow, deny]), replace_atlaso_service_rules=True)
    if enabled:
        assert config.index('comment "routing-51-deny-ipv4"') < config.index('comment "routing-50-allow-ipv4"')
