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
