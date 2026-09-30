"""Verify directed routing permission policy and family scoping."""

import pytest

from atlaso.app.models import RoutingRule
from atlaso.app.services.routes_wan import render_wan_config
from atlaso.app.services.routing_permissions import (
    routing_permission_rows,
    validate_routing_permission,
)


def target(name, role, ipv4="192.0.2.1/24", ipv6="2001:db8::1/64", **changes):
    """Build a configured lab interface or VLAN target.

    Args:
        name: Interface name used to identify the target.
        role: Routing role assigned to the target.
        ipv4: IPv4 interface address and prefix, when configured.
        ipv6: IPv6 interface address and prefix, when configured.
        **changes: Target fields replacing the fixture defaults.
    """
    return {
        "name": name,
        "role": role,
        "kind": "physical",
        "ip_cidr": ipv4,
        "ipv6_cidr": ipv6,
        "routing_domain": "lab",
        **changes,
    }


def rule(name, source, destination, policy="allow", ip_family=0, **changes):
    """Build one explicit directed permission.

    Args:
        name: Display name for the permission.
        source: Source interface name.
        destination: Destination interface name.
        policy: Requested allow, deny, or automatic policy.
        ip_family: Address family scope, with zero selecting both families.
        **changes: Rule fields replacing the fixture defaults.
    """
    values = {
        "name": name,
        "source_interface": source,
        "destination_interface": destination,
        "policy": policy,
        "ip_family": ip_family,
        "enabled": True,
    }
    values.update(changes)
    return RoutingRule(**values)


@pytest.mark.parametrize("separator", ["\r", "\r\n", "\v", "\f", "\x85", "\u2028", "\u2029"])
def test_render_wan_config_keeps_legacy_permission_text_on_one_line(separator):
    """Persisted text with any line separator cannot become a WAN record.

    Args:
        separator: Legacy line separator in saved text.
    """
    permission = rule(
        f"reviewed{separator}[routes]", "eth1", "eth2",
        description=f"reviewed{separator}[routes]{separator}route=Injected",
    )
    config = render_wan_config([], routing_rules=[permission])
    assert "routing=reviewed [routes]\n" in config
    assert "  description=reviewed [routes] route=Injected\n" in config
    assert config.count("route=Injected") == 1
    assert separator not in config


def explicit_row(rows, source, destination, family):
    """Find one explicit projected permission.

    Args:
        rows: Permission projections to search.
        source: Source interface in the directed pair.
        destination: Destination interface in the directed pair.
        family: Address family value to match.
    """
    return next(
        row
        for row in rows
        if not row["generated"]
        and row["source_interface"] == source
        and row["destination_interface"] == destination
        and row["ip_family"] == family
    )


def test_route_pairs_follow_automatic_default_and_access_requires_allow():
    """Route pairs inherit allow while Access pairs default to deny."""
    targets = [target("route-a", "route"), target("route-b", "route"), target("access-a", "access")]

    rows = routing_permission_rows(targets, [])

    generated = next(row for row in rows if row["source_interface"] == "route-a" and row["destination_interface"] == "route-b")
    assert generated["generated"] is True
    assert generated["policy"] == "automatic"
    assert generated["effective_action"] == "automatic allow"
    access_rule = rule("Access to route", "access-a", "route-a", policy="automatic")
    assert explicit_row(routing_permission_rows(targets, [access_rule]), "access-a", "route-a", 0)["effective_action"] == "automatic deny"
    access_rule.policy = "allow"
    assert explicit_row(routing_permission_rows(targets, [access_rule]), "access-a", "route-a", 0)["effective_action"] == "explicit allow"


def test_generated_permission_ids_distinguish_colon_partitioned_names():
    """Different directed pairs retain unique, stable grid identities."""
    targets = [target(name, "route") for name in ("a:b", "c", "a", "b:c")]
    rows = routing_permission_rows(targets, [])
    ids = {(row["source_interface"], row["destination_interface"]): row["id"] for row in rows if row["generated"]}
    assert len(ids) == len(set(ids.values()))
    assert ids[("a:b", "c")] != ids[("a", "b:c")]
    reversed_rows = routing_permission_rows(list(reversed(targets)), [])
    reversed_ids = {(row["source_interface"], row["destination_interface"]): row["id"]
                    for row in reversed_rows if row["generated"]}
    assert ids == reversed_ids


def test_deny_overrides_allow_for_same_direction_but_not_reverse_direction():
    """Conflicting policies resolve to deny only for their directed pair."""
    targets = [target("access-a", "access"), target("route-a", "route")]
    rules = [
        rule("Allow access to route", "access-a", "route-a", policy="allow"),
        rule("Deny access to route", "access-a", "route-a", policy="deny"),
        rule("Allow route to access", "route-a", "access-a", policy="allow"),
    ]

    rows = routing_permission_rows(targets, rules)

    assert explicit_row(rows, "access-a", "route-a", 0)["effective_action"] == "explicit deny"
    assert explicit_row(rows, "route-a", "access-a", 0)["effective_action"] == "explicit allow"


def test_family_scoping_and_global_routing_suspension():
    """An IPv4 override does not change IPv6, and Routing off suspends both."""
    targets = [target("access-a", "access"), target("route-a", "route")]
    rules = [rule("Deny IPv4", "access-a", "route-a", policy="deny", ip_family=4)]

    rows = routing_permission_rows(targets, rules)

    ipv4 = explicit_row(rows, "access-a", "route-a", 4)
    assert ipv4["source_networks"] == ["192.0.2.0/24"]
    assert ipv4["effective_action"] == "explicit deny"
    assert ipv4["family_effective_actions"] == {"4": "explicit deny"}
    suspended = routing_permission_rows(targets, rules, routing_enabled=False)
    assert explicit_row(suspended, "access-a", "route-a", 4)["effective_action"] == "suspended"


def test_generated_dual_stack_pair_explains_different_family_results():
    """A legitimate IPv4-only deny is distinct from an invalid scope."""
    targets = [target("route-a", "route"), target("route-b", "route")]
    rows = routing_permission_rows(targets, [rule("IPv4 deny", "route-a", "route-b", "deny", 4)])
    generated = next(row for row in rows if row["generated"] and row["source_interface"] == "route-a")
    assert generated["effective_action"] == "IPv4: explicit deny; IPv6: automatic allow"
    assert generated["family_effective_actions"] == {"4": "explicit deny", "6": "automatic allow"}


@pytest.mark.parametrize(
    "changes,fragment",
    [
        ({"policy": "permit"}, "policy must be automatic, allow, or deny"),
        ({"ip_family": 5}, "IP family must be 0 (both), 4, or 6"),
        ({"source_interface": "management"}, "protected management rules cannot be overridden"),
        ({"destination_interface": "access-a"}, "source and destination must be different"),
    ],
)
def test_invalid_policy_family_management_and_self_target_are_rejected(changes, fragment):
    """Reject unsupported values and protected or degenerate scopes.

    Args:
        changes: Invalid rule fields supplied by this parameterized case.
        fragment: Expected validation message fragment.
    """
    targets = [target("access-a", "access"), target("route-a", "route"),
               target("management", "management", routing_domain="management")]
    candidate = rule("Candidate", "access-a", "route-a", **changes)

    assert any(fragment in error for error in validate_routing_permission(candidate, targets))


def test_family_without_common_prefix_is_rejected():
    """Both endpoints must have prefixes in the selected family."""
    targets = [
        target("ipv4-only", "access", ipv6=""),
        target("ipv6-only", "route", ipv4="", ipv6="2001:db8::1/64"),
    ]
    candidate = rule("No common family", "ipv4-only", "ipv6-only")

    errors = validate_routing_permission(candidate, targets)

    assert any("common configured address family" in error for error in errors)


def test_disabled_stale_scope_can_be_retained_but_management_and_enums_stay_protected():
    """Disabling unavailable topology preserves intent without admitting unsafe policy."""
    candidate = rule("Stale", "gone", "route-a", "deny", 4, enabled=False)
    targets = [target("route-a", "route", ipv4="", ipv6="2001:db8::1/64"),
               target("management", "management", routing_domain="management")]
    assert validate_routing_permission(candidate, targets) == []
    candidate.enabled = True
    assert validate_routing_permission(candidate, targets)
    candidate.enabled = False
    candidate.source_interface = "management"
    assert any("protected management" in error for error in validate_routing_permission(candidate, targets))
    candidate.source_interface = "gone"
    candidate.policy = "permit"
    assert any("policy must" in error for error in validate_routing_permission(candidate, targets))


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("field", ["source_interface", "destination_interface"])
@pytest.mark.parametrize("name", ["", "gone\nrouting=Injected", "gone\rnext", "gone target", "gone=target", "x" * 81])
def test_interface_syntax_is_required_even_for_disabled_permissions(enabled, field, name):
    """Keep unavailable identities serializable regardless of activation state.

    Args:
        enabled: Proposed activation state.
        field: Endpoint being validated.
        name: Invalid interface identity.
    """
    candidate = rule("Dormant", "gone.10", "route-a", enabled=enabled)
    setattr(candidate, field, name)
    assert any("canonical interface name" in error for error in validate_routing_permission(candidate, [target("route-a", "route")]))


@pytest.mark.parametrize("name", ["gone.10", "missing-eth0", "vlan_10", "eth0:1"])
def test_disabled_permissions_accept_canonical_unavailable_names(name):
    """Retain valid dormant physical, alias and VLAN identities.

    Args:
        name: Canonical unavailable interface identity.
    """
    assert validate_routing_permission(rule("Dormant", name, "route-a", enabled=False), [target("route-a", "route")]) == []
