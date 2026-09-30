"""Verify routing denials at the nftables enforcement and upgrade boundaries."""

from ipaddress import ip_network

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


def default_deny_name(rules: list[FirewallRule], source: str, destination: str, family: int) -> str:
    """Find one generated default denial by its exact directed family.

    Args:
        rules: Renderable firewall rules to search.
        source: Source interface in the directed pair.
        destination: Destination interface in the directed pair.
        family: Address family version to match.
    """
    return next(
        rule.name
        for rule in rules
        if rule.routing_policy_phase == "deny"
        and rule.interface_name == source
        and rule.routing_destination_interface == destination
        and ip_network(rule.source).version == family
    )


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


def test_long_permission_name_has_bounded_unique_nft_comment():
    """Maximum-length names still render distinct nftables comments."""
    interfaces, vlans = topology()
    first = RoutingRule(id=41, name="x" * 120, enabled=True, source_interface="a",
                        destination_interface="b", policy="deny", ip_family=4, priority=100)
    second = RoutingRule(id=42, name="x" * 119 + "y", enabled=True, source_interface="a",
                         destination_interface="b", policy="deny", ip_family=4, priority=101)
    generated = managed_routing_firewall_rules(interfaces, vlans, [first, second])
    names = [rule.name for rule in generated if rule.name.startswith("routing-")]
    assert len(names) == 2
    assert len(set(names)) == 2
    assert all(len(name.encode()) <= 128 for name in names)
    config = render_nftables_config(settings(), [], generated, replace_atlaso_service_rules=True)
    assert all(f'comment "{name}"' in config for name in names)


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
    """Inheritance removes only the override and retains route-role admission.

    Args:
        policy: Explicit policy or automatic inheritance under test.
        expected: Whether an explicit override should appear in the config.
    """
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
        marker = f'comment "{default_deny_name(generated, "a", "b", version)}"'
        assert marker in forward
        assert forward.index(marker) < forward.index("ct state established")
        assert forward.index(marker) < forward.index("Atlaso ICMP diagnostics")
        assert forward.index(marker) < forward.index('comment "Broad"')
    firewall.enabled = False
    assert any("Enable Firewall" in error for error in validate_firewall_state(firewall, [], generated))
    suspended = managed_routing_firewall_rules(interfaces, vlans, permissions, routing_enabled=False)
    assert not any(item.routing_policy_phase == "deny" for item in suspended)
    assert validate_firewall_state(firewall, [], suspended) == []


def test_access_default_deny_names_are_stable_and_unique_for_exact_directed_targets():
    """Keep generated Access denials distinct despite slug and pair-boundary collisions."""
    interface_names = ["lab-a", "lab.a", "Lab-a", "LAB-A", "a", "a-to-b", "b", "b-to-c", "c"]
    interfaces = [
        PhysicalInterface(
            name=name,
            role="access",
            mode="access",
            ip_cidr=f"10.{index}.0.1/24",
            ipv6_cidr=f"2001:db8:{index}::1/64",
        )
        for index, name in enumerate(interface_names, start=1)
    ]

    generated = managed_routing_firewall_rules(interfaces, [])
    repeated = managed_routing_firewall_rules(interfaces, [])
    generated_names = [rule.name for rule in generated]
    assert generated_names == [rule.name for rule in repeated]
    assert len(generated_names) == len(set(name.lower() for name in generated_names))

    names_by_identity = {}
    for rule in generated:
        family = ip_network(rule.source).version
        identity = (rule.interface_name, rule.routing_destination_interface, family)
        assert identity not in names_by_identity
        assert len(rule.name) <= 120
        assert rule.name.startswith(f"routing-default-deny-ipv{family}-")
        assert len(rule.name.rsplit("-", 1)[-1]) == 64
        names_by_identity[identity] = rule.name

    assert names_by_identity[("lab-a", "lab.a", 4)] != names_by_identity[("lab.a", "lab-a", 4)]
    assert names_by_identity[("lab-a", "lab.a", 4)] != names_by_identity[("LAB-A", "lab.a", 4)]
    assert names_by_identity[("a", "b-to-c", 4)] != names_by_identity[("a-to-b", "c", 4)]
    assert names_by_identity[("lab-a", "lab.a", 4)] != names_by_identity[("lab-a", "lab.a", 6)]
    assert validate_firewall_state(settings(), [], generated) == []


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
    identities = {
        (item.interface_name, item.routing_destination_interface, ip_network(item.source).version)
        for item in generated
        if item.routing_policy_phase == "deny"
    }
    assert (("a", "b", 4) in identities) is not enabled
    assert ("a", "b", 6) in identities
    assert ("b", "a", 4) in identities
    assert ("b", "a", 6) in identities
    deny = RoutingRule(id=51, name="Deny IPv4", enabled=True, source_interface="a", destination_interface="b", policy="deny", ip_family=4, priority=999)
    config = render_nftables_config(settings(), [], managed_routing_firewall_rules(interfaces, vlans, [allow, deny]), replace_atlaso_service_rules=True)
    if enabled:
        assert config.index('comment "routing-51-deny-ipv4"') < config.index('comment "routing-50-allow-ipv4"')
