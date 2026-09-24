"""Test routes wan behavior."""

import pytest

from atlaso.app.models import NatRule, Route, RoutingRule, Setting, WanPolicy
from atlaso.app.services.routes_wan import (
    ROUTES_WAN_SETTING_KEYS,
    RoutesWanSettings,
    canonical_route_destination,
    default_route_family,
    ensure_routes_wan_settings,
    mirrored_management_default_routes,
    render_wan_config,
    route_to_dict,
    save_routes_wan_settings,
    validate_nat_source,
    validate_wan_state,
)


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("retirement", ["disabled", "removed", "routing-off"])
@pytest.mark.parametrize("metric,gateway_present", [(0, False), (100, False), (1024, False), (1024, True)])
@pytest.mark.parametrize("owns_prefix", [False, True])
def test_static_retirement_preview_preserves_connected_routes(family, retirement, metric, gateway_present, owns_prefix):
    """Match precise native retirement selectors for a connected destination.

    Args:
        family: Address family to render.
        retirement: Desired action that retires the static row.
        metric: Saved static route metric.
        gateway_present: Whether the row has a distinguishing next hop.
        owns_prefix: Whether this target owns the connected prefix in its domain.
    """
    prefix = "192.0.2.0/24" if family == 4 else "2001:db8::/64"
    address = "192.0.2.10/24" if family == 4 else "2001:db8::10/64"
    gateway = ("192.0.2.1" if family == 4 else "2001:db8::1") if gateway_present else ""
    route = Route(destination_cidr=prefix, interface_name="eth1", metric=metric,
                  gateway=gateway, enabled=retirement != "disabled")
    target = {"name": "eth1", "routing_domain": "lab", "ip_cidr" if family == 4 else "ipv6_cidr": address}
    targets = [target] if owns_prefix else [{**target, "name": "eth0"}, target]
    preview = render_wan_config([] if retirement == "removed" else [route], targets=targets,
                               removed_routes=[{"destination_cidr": prefix, "interface_name": "eth1",
                                                "metric": str(metric), "gateway": gateway}] if retirement == "removed" else [],
                               settings=RoutesWanSettings(retirement != "routing-off", False, False))
    command = f"ip {'-6 ' if family == 6 else ''}route del {prefix} dev eth1 table 200"
    alias = owns_prefix and not gateway and (metric == 0 or (family == 6 and metric == 1024))
    if not owns_prefix:
        assert command + "  #" in preview
    elif alias:
        assert command not in preview
        assert f"Retain Network-owned connected route {prefix}" in preview
    else:
        expected = command + f" metric {metric}" + (f" via {gateway}" if gateway else "")
        assert expected + "  #" in preview


def test_feature_settings_render_full_saved_intent_with_effective_gates():
    """Keep saved rows in the config while rendering only effective behavior."""
    policy = WanPolicy(name="Slow WAN", enabled=True, latency_ms=100)
    policy.id = 9
    route = Route(
        destination_cidr="10.20.0.0/24",
        interface_name="eth1",
        metric=100,
        enabled=True,
        wan_policy_id=9,
    )
    nat = NatRule(
        name="Lab NAT",
        source="10.20.0.0/24",
        outbound_interface="eth1",
        enabled=True,
    )

    config = render_wan_config(
        [route],
        [policy],
        [nat],
        targets=[
            {
                "name": "eth1",
                "kind": "physical",
                "role": "access",
                "ip_cidr": "192.0.2.10/24",
                "routing_domain": "lab",
                "route_allowed": True,
            }
        ],
        settings=RoutesWanSettings(
            routing_enabled=False,
            nat_enabled=True,
            wan_simulation_enabled=True,
        ),
    )

    assert "routing_enabled=false" in config
    assert "nat_enabled=" not in config
    assert "wan_simulation_enabled=true" in config
    assert "route=10.20.0.0/24" in config
    assert "nat=Lab NAT" not in config
    assert "policy=Slow WAN" in config
    assert "ip route replace 10.20.0.0/24" not in config
    assert "ip route replace 192.0.2.0/24 dev eth1 table 200" in config
    assert "rule add iif" not in config
    assert "owned IPv4/IPv6 lab ingress lookups and terminal guards to an empty set" in config
    assert "rule del priority" not in config
    assert "masquerade comment \"Lab NAT\"" not in config
    assert "nft -f /etc/atlaso/nftables.d/atlaso-nat.nft" not in config
    assert "tc qdisc replace dev eth1 root netem delay 100ms" in config
    assert "net.ipv4.ip_forward=0" in config
    assert "net.ipv6.conf.all.forwarding=0" in config


@pytest.mark.parametrize("routing_enabled", [False, True])
def test_wan_preview_orders_ingress_guards_before_enabling_forwarding(routing_enabled):
    """The captured preview follows the helper's enable and disable ordering.

    Args:
        routing_enabled: Whether lab routing is enabled in this case.
    """
    config = render_wan_config(
        [],
        settings=RoutesWanSettings(routing_enabled, False, False),
        applied_network_ingress=["eth1"],
    )
    lines = config.splitlines()
    forwarding = [
        lines.index(f"sysctl -w net.ipv4.ip_forward={int(routing_enabled)}  # global Routing switch"),
        lines.index(f"sysctl -w net.ipv6.conf.all.forwarding={int(routing_enabled)}  # global Routing switch"),
    ]
    if routing_enabled:
        guard = lines.index("ip rule add iif eth1 unreachable priority 2100 protocol 2")
        lookup = lines.index("ip rule add iif eth1 table 200 priority 2000 protocol 2")
        assert guard < lookup < min(forwarding)
    else:
        assert max(forwarding) < lines.index(
            "# Routing disabled: reconcile owned IPv4/IPv6 lab ingress lookups and terminal guards to an empty set."
        )
        assert "rule add iif eth1" not in config


def test_disabled_route_preview_guards_unknown_target_cleanup():
    """Preview dormant cleanup with the helper's live-link condition."""
    route = Route(
        destination_cidr="10.20.0.0/24",
        interface_name="missing_eth2",
        metric=100,
        enabled=True,
    )

    config = render_wan_config(
        [route],
        settings=RoutesWanSettings(False, False, False),
    )

    assert "route=10.20.0.0/24" in config
    assert (
        "if ip link show dev missing_eth2 >/dev/null 2>&1; then "
        "ip route del 10.20.0.0/24 dev missing_eth2 table 200; fi"
    ) in config
    assert "ip route replace 10.20.0.0/24" not in config
    assert (
        "if ip link show dev missing_eth2 >/dev/null 2>&1; then "
        "tc qdisc del dev missing_eth2 root; fi"
    ) in config


def test_disabled_route_preview_cleans_live_ineligible_target():
    """Keep cleanup visible when an omitted target exists but is ineligible."""
    route = Route(
        destination_cidr="10.20.0.0/24",
        interface_name="eth2",
        metric=100,
        enabled=True,
    )

    config = render_wan_config(
        [route],
        settings=RoutesWanSettings(False, False, False),
    )

    assert "ip route del 10.20.0.0/24 dev eth2 table 200" in config
    assert "tc qdisc del dev eth2 root" in config


def test_wan_preview_retains_guarded_omitted_target_cleanup():
    """Keep link-guarded target retirement stable across baseline convergence."""
    target = {
        "name": "eth2",
        "kind": "physical",
        "role": "access",
        "ip_cidr": "192.0.2.10/24",
        "routing_domain": "lab",
        "route_allowed": True,
    }
    previous = render_wan_config([], targets=[target])

    live = render_wan_config(
        [],
        previous_config_preview=previous,
        settings=RoutesWanSettings(False, False, False),
    )
    converged = render_wan_config(
        [],
        previous_config_preview=live,
        settings=RoutesWanSettings(False, False, False),
    )
    cleanup = (
        "if ip link show dev eth2 >/dev/null 2>&1; then "
        "ip route del 192.0.2.0/24 dev eth2 table 200; fi"
        "  # retired omitted or ineligible WAN target"
    )
    assert cleanup in live
    assert live == converged
    assert "[retired_targets]\ntarget=eth2\n  network=192.0.2.0/24" in live


def test_removed_route_preview_guards_unknown_target_cleanup():
    """Preview removed-route cleanup with the helper's live-link condition."""
    config = render_wan_config(
        [],
        removed_routes=[
            {
                "destination_cidr": "192.0.2.0/24",
                "interface_name": "missing-route-target",
            }
        ],
        settings=RoutesWanSettings(False, False, False),
    )

    assert "route=192.0.2.0/24" in config
    assert (
        "if ip link show dev missing-route-target >/dev/null 2>&1; then "
        "ip route del 192.0.2.0/24 dev missing-route-target table 200; fi"
    ) in config


def test_disabled_features_do_not_surface_inactive_row_validation_errors():
    """Do not block Apply on invalid resources whose global feature is off."""
    invalid_route = Route(
        destination_cidr="10.20.0.0/24",
        interface_name="eth1",
        metric=100,
        enabled=True,
    )
    invalid_nat = NatRule(
        name="",
        source="not-a-network",
        outbound_interface="missing",
        priority=-1,
        enabled=True,
    )
    invalid_policy = WanPolicy(name="", latency_ms=-1, jitter_ms=-1, enabled=True)

    assert validate_wan_state(
        [invalid_route],
        [invalid_policy],
        {"eth1"},
        [invalid_nat],
        set(),
        routing_enabled=False,
        nat_enabled=False,
        wan_simulation_enabled=False,
    ) == []
    assert validate_wan_state(
        [invalid_route],
        [invalid_policy],
        set(),
        [invalid_nat],
        set(),
        routing_enabled=True,
        nat_enabled=True,
        wan_simulation_enabled=True,
    )


def test_validate_wan_state_rejects_invalid_route_destinations_when_routing_off():
    """Reject malformed route destination CIDRs even while routing is disabled."""
    invalid_route = Route(
        destination_cidr="not-a-network",
        interface_name="eth1",
        metric=100,
        enabled=True,
    )

    assert validate_wan_state(
        [invalid_route],
        [],
        {"eth1"},
        routing_enabled=False,
        nat_enabled=False,
        wan_simulation_enabled=False,
    ) == ["Route not-a-network is not a valid destination CIDR."]


def test_disabled_routing_still_validates_active_management_default():
    """Validate a protected host default while ignoring dormant lab routes."""
    dormant_route = Route(
        destination_cidr="10.20.0.0/24",
        gateway="198.51.100.1",
        interface_name="eth2",
        metric=100,
        enabled=True,
    )
    management_default = Route(
        destination_cidr="0.0.0.0/0",
        gateway="198.51.100.1",
        interface_name="eth1",
        metric=100,
        enabled=True,
    )

    errors = validate_wan_state(
        [dormant_route, management_default],
        [],
        {"eth1", "eth2"},
        route_target_cidrs={
            "eth1": ("192.0.2.10/24", None),
            "eth2": ("203.0.113.10/24", None),
        },
        management_target_names={"eth1"},
        routing_enabled=False,
        nat_enabled=False,
        wan_simulation_enabled=False,
    )

    assert errors == [
        "Route 0.0.0.0/0: Route gateway 198.51.100.1 is not on-link for the selected target's configured IPv4 CIDR."
    ]


def test_fresh_settings_default_off_and_legacy_rows_infer_once(client):
    """Reconcile missing upgrade keys from effective legacy rows only once.

    Args:
        client: HTTP test client providing the isolated application database.
    """
    from sqlalchemy import delete, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        fresh = ensure_routes_wan_settings(db)
        assert fresh == RoutesWanSettings(False, False, False)

        for route_row in db.execute(select(Route)).scalars():
            route_row.enabled = False
        for nat_rule in db.execute(select(NatRule)).scalars():
            nat_rule.enabled = False
        for routing_rule in db.execute(select(RoutingRule)).scalars():
            routing_rule.enabled = False

        route_targets = db.execute(
            select(PhysicalInterface).order_by(PhysicalInterface.name)
        ).scalars().all()[:2]
        assert len(route_targets) == 2
        for interface in route_targets:
            interface.role = "route"
            interface.mode = "access"
            interface.admin_state = "up"
            interface.oper_state = "up"
            interface.ip_cidr = None
            interface.ipv6_cidr = None
        db.execute(delete(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS)))
        db.flush()
        assert ensure_routes_wan_settings(db).routing_enabled is False

        for index, interface in enumerate(route_targets, start=1):
            interface.mode = "trunk"
            interface.ip_cidr = f"192.0.{index}.10/24"
        db.execute(delete(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS)))
        db.flush()
        assert ensure_routes_wan_settings(db).routing_enabled is False

        for index, interface in enumerate(route_targets, start=1):
            interface.mode = "access"
            interface.admin_state = "down" if index == 1 else "up"
            interface.ip_cidr = f"192.0.{index}.10/24"
        db.execute(delete(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS)))
        db.flush()
        assert ensure_routes_wan_settings(db).routing_enabled is True

        db.execute(delete(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS)))
        route = db.execute(select(Route).order_by(Route.id)).scalars().first()
        nat = db.execute(select(NatRule).order_by(NatRule.id)).scalars().first()
        policy = db.execute(select(WanPolicy).order_by(WanPolicy.id)).scalars().first()
        assert route is not None and nat is not None and policy is not None
        route.enabled = False
        policy.enabled = True
        nat.enabled = True
        db.flush()

        nat_only = ensure_routes_wan_settings(db)
        assert nat_only == RoutesWanSettings(True, False, False)

        db.execute(delete(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS)))
        route.enabled = True
        route.wan_policy_id = policy.id
        db.flush()

        inferred = ensure_routes_wan_settings(db)
        assert inferred == RoutesWanSettings(True, False, True)
        route.enabled = False
        nat.enabled = False
        policy.enabled = False
        db.flush()

        assert ensure_routes_wan_settings(db) == inferred


def test_settings_archives_round_trip_explicit_and_infer_legacy_switches(client):
    """Round-trip current switches and derive them for an archive without keys.

    Args:
        client: HTTP test client providing the isolated application database.
    """
    from sqlalchemy import delete

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        factory_reset_desired_state,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        save_routes_wan_settings(
            db,
            routing_enabled=True,
            nat_enabled=False,
            wan_simulation_enabled=True,
        )
        db.commit()
        current_archive = export_settings_archive(db, actor="test")
        archived_keys = {
            row["key"]
            for row in current_archive["data"]["settings"]
        }
        assert ROUTES_WAN_SETTING_KEYS <= archived_keys

        db.execute(delete(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS)))
        db.commit()
        legacy_archive = export_settings_archive(db, actor="test")
        assert not ROUTES_WAN_SETTING_KEYS.intersection(
            {row["key"] for row in legacy_archive["data"]["settings"]}
        )

        factory_reset_desired_state(db)
        assert ensure_routes_wan_settings(db) == RoutesWanSettings(False, False, False)
        restore_settings_archive(db, current_archive)
        assert ensure_routes_wan_settings(db) == RoutesWanSettings(True, False, True)

        factory_reset_desired_state(db)
        restore_settings_archive(db, legacy_archive)
        assert ensure_routes_wan_settings(db) == RoutesWanSettings(True, False, True)


def test_default_route_helpers_and_renderer_use_canonical_semantics():
    """Canonicalize /0 values and render semantic default-route readback."""
    route = Route(
        destination_cidr="192.0.2.42/0",
        gateway="192.0.2.1",
        interface_name="eth1",
        metric=90,
        enabled=True,
    )

    assert canonical_route_destination(route.destination_cidr) == "0.0.0.0/0"
    assert default_route_family(route.destination_cidr) == 4
    assert route_to_dict(route)["destination_label"] == "Default route (IPv4)"
    config = render_wan_config([route])
    assert "route=0.0.0.0/0" in config
    assert "ip route replace 0.0.0.0/0 via 192.0.2.1 dev eth1 metric 90 table 200" in config


def test_flagged_management_default_route_also_preserves_host_default():
    """Render a migrated default into both lab policy and the host main table."""
    route = Route(
        destination_cidr="0.0.0.0/0",
        gateway="192.0.2.1",
        interface_name="eth1",
        metric=90,
        enabled=True,
    )

    config = render_wan_config(
        [route],
        targets=[
            {
                "name": "eth1",
                "kind": "physical",
                "role": "access",
                "ip_cidr": "192.0.2.10/24",
                "routing_domain": "lab",
                "route_allowed": True,
                "management_ui": True,
            }
        ],
    )

    assert "management_ui=true" in config
    assert "ip route replace 0.0.0.0/0 via 192.0.2.1 dev eth1 metric 90 table 200" in config
    assert (
        "ip route replace 0.0.0.0/0 via 192.0.2.1 dev eth1 metric 90"
        "  # flagged-management host default"
    ) in config
    assert mirrored_management_default_routes(config) == {
        ("0.0.0.0/0", "eth1", "192.0.2.1", "90")
    }


@pytest.mark.parametrize("family", [4, 6])
def test_modern_wan_preview_keeps_applied_network_ownership(family):
    """Pending prefixes and management flags cannot rewrite applied ownership.

    Args:
        family: Address family for connected and default routes.
    """
    old = "192.0.2.10/24" if family == 4 else "2001:db8:1::10/64"
    new = "198.51.100.10/24" if family == 4 else "2001:db8:2::10/64"
    prefix = "192.0.2.0/24" if family == 4 else "2001:db8:1::/64"
    new_prefix = "198.51.100.0/24" if family == 4 else "2001:db8:2::/64"
    destination = "0.0.0.0/0" if family == 4 else "::/0"
    gateway = "192.0.2.1" if family == 4 else "2001:db8:1::1"
    key = "ip_cidr" if family == 4 else "ipv6_cidr"
    applied = {"name": "eth1", "routing_domain": "lab", key: old, "management_ui": True}
    pending = {**applied, key: new, "management_ui": False}
    previous = render_wan_config([], targets=[applied])
    routes = [Route(destination_cidr=destination, interface_name="eth1", gateway=gateway, metric=90, enabled=True),
              Route(destination_cidr=prefix, interface_name="eth1", metric=100, enabled=False)]
    preview = render_wan_config(routes, targets=[pending], previous_config_preview=previous,
                               network_owned_targets=[applied], settings=RoutesWanSettings(False, False, False))
    family_flag = "-6 " if family == 6 else ""
    command = f"ip {family_flag}route replace {destination} via {gateway} dev eth1 metric 90"
    assert command + " table 200" in preview
    assert command + "  # flagged-management host default" in preview
    for connected in (prefix, new_prefix):
        assert f"ip {family_flag}route del {connected}" not in preview
        assert f"ip {family_flag}route replace {connected}" not in preview
    assert "after resolving native Network connected ownership" in preview
    assert "combined Apply uses the newly applied Network intent" in preview
    assert "older runtime intent without management eligibility requires Network reapply" in preview
    combined = render_wan_config(routes, targets=[pending], network_owned_targets=[pending],
                                 settings=RoutesWanSettings(False, False, False))
    assert command + " table 200" not in combined
    pending_flag_only = render_wan_config(routes, targets=[applied], network_owned_targets=[pending],
                                         settings=RoutesWanSettings(False, False, False))
    assert command + " table 200" not in pending_flag_only
    assert command + "  # flagged-management host default" not in pending_flag_only


@pytest.mark.parametrize("family", [4, 6])
def test_disabled_routing_preview_keeps_flagged_management_host_default(family):
    """Retain the management default in both main and source-selected tables.

    Args:
        family: Management default address family.
    """
    destination = "0.0.0.0/0" if family == 4 else "::/0"
    gateway = "192.0.2.1" if family == 4 else "2001:db8::1"
    route = Route(
        destination_cidr=destination,
        gateway=gateway,
        interface_name="eth1",
        metric=90,
        enabled=True,
    )
    config = render_wan_config(
        [route],
        targets=[
            {
                "name": "eth1",
                "kind": "physical",
                "role": "access",
                "ip_cidr": "192.0.2.10/24",
                "routing_domain": "lab",
                "route_allowed": True,
                "management_ui": True,
            }
        ],
        settings=RoutesWanSettings(False, False, False),
    )

    command = f"ip {'-6 ' if family == 6 else ''}route replace {destination} via {gateway} dev eth1 metric 90"
    assert command + " table 200" in config
    assert command + "  # flagged-management host default" in config
    assert f"route del {destination} dev eth1 table 200" not in config


def test_flagged_management_default_cleanup_uses_last_applied_mirroring():
    """Retire the host default after unflagging, disabling, or removing its route."""
    previous_route = Route(
        destination_cidr="0.0.0.0/0",
        gateway="192.0.2.1",
        interface_name="eth1",
        metric=90,
        enabled=True,
    )
    flagged_target = {
        "name": "eth1",
        "kind": "physical",
        "role": "access",
        "ip_cidr": "192.0.2.10/24",
        "routing_domain": "lab",
        "route_allowed": True,
        "management_ui": True,
    }
    unflagged_target = {**flagged_target, "management_ui": False}
    previous = render_wan_config([previous_route], targets=[flagged_target])

    retained = render_wan_config(
        [previous_route],
        targets=[unflagged_target],
        previous_config_preview=previous,
    )
    previous_route.enabled = False
    disabled = render_wan_config(
        [previous_route],
        targets=[unflagged_target],
        previous_config_preview=previous,
    )
    removed = render_wan_config(
        [],
        targets=[unflagged_target],
        removed_routes=[
            {
                "destination_cidr": "0.0.0.0/0",
                "gateway": "192.0.2.1",
                "interface_name": "eth1",
                "metric": "90",
            }
        ],
        previous_config_preview=previous,
    )

    assert (
        "ip route del 0.0.0.0/0 dev eth1"
        "  # retired flagged-management host default"
    ) in retained
    assert (
        "ip route del 0.0.0.0/0 dev eth1"
        "  # disabled flagged-management default"
    ) in disabled
    assert (
        "ip route del 0.0.0.0/0 dev eth1"
        "  # removed flagged-management default"
    ) in removed


def test_admin_down_access_interface_is_not_a_management_mirror_target(client):
    """Do not mirror a host default through an inactive physical listener.

    Args:
        client: HTTP test client providing the isolated application database.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.ui import wan_routing_targets

    with SessionLocal() as db:
        interface = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "down"
        interface.oper_state = "down"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.0.2.10/24"
        interface.access_management_ui_enabled = True
        db.commit()

        target = next(
            item for item in wan_routing_targets(db) if item["name"] == "eth2"
        )

    assert target["management_ui"] is False


def test_flagged_vlan_on_inactive_parent_is_not_a_management_wan_target(client):
    """Do not mirror a host default through a VLAN whose trunk parent is down.

    Args:
        client: HTTP test client providing the isolated application database.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface
    from atlaso.app.ui import wan_routing_targets

    with SessionLocal() as db:
        parent = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert parent is not None
        parent.role = "unused"
        parent.mode = "trunk"
        parent.admin_state = "down"
        parent.oper_state = "down"
        vlan = VlanInterface(
            name="eth2.521",
            parent_interface="eth2",
            vlan_id=521,
            ip_cidr="192.0.2.10/24",
            role="access",
            enabled=True,
            access_management_ui_enabled=True,
        )
        db.add(vlan)
        db.commit()

        target = next(
            item for item in wan_routing_targets(db) if item["name"] == vlan.name
        )

    assert target["management_ui"] is False


def test_removed_route_detection_compares_canonical_destinations():
    """Keep equivalent legacy baseline destinations during global Apply."""
    from atlaso.app.ui import removed_wan_route_entries

    current_preview = """[routes]
route=::/0
  gateway=2001:db8::1
  interface=eth1
  metric=90
"""
    baseline = {
        "config_preview": """[routes]
route=0:0:0:0:0:0:0:0/0
  gateway=2001:db8::1
  interface=eth1
  metric=90
"""
    }

    assert removed_wan_route_entries(current_preview, baseline) == []


def test_validate_wan_state_rejects_missing_and_duplicate_family_defaults():
    """Require next hops and permit at most one default per IP family."""
    routes = [
        Route(destination_cidr="0.0.0.0/0", gateway="", interface_name="eth1", metric=90, enabled=True),
        Route(destination_cidr="192.0.2.42/0", gateway="192.0.2.1", interface_name="eth1", metric=100, enabled=True),
        Route(destination_cidr="::/0", gateway="2001:db8::1", interface_name="eth1", metric=110, enabled=True),
    ]

    errors = validate_wan_state(routes, [], {"eth1"})

    assert any("Default IPv4 route" in error and "requires a gateway" in error for error in errors)
    assert any("Only one IPv4 default route" in error for error in errors)
    assert not any("Only one IPv6 default route" in error for error in errors)


def test_validate_wan_state_requires_gateway_reachability_on_selected_target():
    """Reject absent-family and off-link next hops while allowing IPv6 link-local gateways."""
    ipv6_default = Route(
        destination_cidr="::/0",
        gateway="2001:db8:20::fe",
        interface_name="eth1.20",
        metric=100,
        enabled=True,
    )

    absent_family_errors = validate_wan_state(
        [ipv6_default],
        [],
        {"eth1.20"},
        route_target_cidrs={"eth1.20": ("192.168.20.1/24", None)},
    )
    assert any("does not have a configured IPv6 CIDR" in error for error in absent_family_errors)

    ipv4_default = Route(
        destination_cidr="0.0.0.0/0",
        gateway="198.51.100.1",
        interface_name="eth1.20",
        metric=100,
        enabled=True,
    )
    off_link_errors = validate_wan_state(
        [ipv4_default],
        [],
        {"eth1.20"},
        route_target_cidrs={"eth1.20": ("192.168.20.1/24", None)},
    )
    assert any("is not on-link" in error for error in off_link_errors)

    ipv6_default.gateway = "fe80::1"
    assert validate_wan_state(
        [ipv6_default],
        [],
        {"eth1.20"},
        route_target_cidrs={"eth1.20": (None, "2001:db8:20::1/64")},
    ) == []


def test_render_wan_config_uses_ipv6_route_commands():
    """Verify that render wan config uses ipv6 route commands."""
    route = Route(
        destination_cidr="2001:db8:100::/64",
        gateway="2001:db8:50::fe",
        interface_name="eth2.50",
        metric=120,
        enabled=True,
    )

    config = render_wan_config(
        [route],
        targets=[
            {
                "name": "eth2.50",
                "kind": "vlan",
                "role": "route",
                "ip_cidr": "192.168.50.1/24",
                "ipv6_cidr": "2001:db8:50::1/64",
                "routing_domain": "lab",
                "route_allowed": True,
            }
        ],
    )

    assert "  ipv6_cidr=2001:db8:50::1/64" in config
    assert "  routing_domain=lab" in config
    assert "ip -6 rule add iif eth2.50 table 200 priority 2000 protocol 2" in config
    assert "ip -6 route replace 2001:db8:100::/64 via 2001:db8:50::fe dev eth2.50 metric 120 table 200" in config


@pytest.mark.parametrize("routing_enabled", [False, True])
def test_legacy_wan_preview_matches_source_rule_migration(routing_enabled):
    """Show the legacy cleanup and only the helper's owned source rules.

    Args:
        routing_enabled: Whether lab routing is enabled in this case.
    """
    targets = [
        {"name": "eth0", "routing_domain": "management", "ip_cidr": "192.0.2.10/24",
         "ipv6_cidr": "2001:db8:1::10/64", "gateway": "192.0.2.1", "ipv6_gateway": "fe80::1"},
        {"name": "eth1", "routing_domain": "lab", "ip_cidr": "198.51.100.10/24",
         "ipv6_cidr": "2001:db8:2::10/64"},
        {"name": "eth2", "routing_domain": "lab", "ip_cidr": "198.51.100.20/24"},
        {"name": "eth3", "routing_domain": "management", "ip_cidr": "203.0.113.10/24",
         "gateway": "198.51.100.1"},
    ]
    preview = render_wan_config(
        [], targets=targets, applied_network_ingress=[], network_owned_targets=None,
        settings=RoutesWanSettings(routing_enabled=routing_enabled),
    )
    commands = preview.splitlines()

    cleanup = [line for line in commands if line.startswith(("ip rule del priority ", "ip -6 rule del priority "))]
    assert len(cleanup) == 4 * 100
    assert "ip rule del priority 1000" in cleanup
    assert "ip -6 rule del priority 1099" in cleanup
    assert "ip rule del priority 2000" in cleanup
    assert "ip -6 rule del priority 2099" in cleanup
    source_rules = [line for line in commands if "rule add from " in line]
    expected = [
        "ip rule add from 192.0.2.0/24 table 100 priority 1000",
        "ip -6 rule add from 2001:db8:1::/64 table 100 priority 1000",
    ]
    if routing_enabled:
        expected += [
            "ip rule add from 198.51.100.0/24 table 200 priority 2001",
            "ip -6 rule add from 2001:db8:2::/64 table 200 priority 2001",
        ]
    assert source_rules == expected
    assert "Local source-address rules remain reconciled from applied Network intent." not in preview


def test_modern_wan_preview_does_not_show_legacy_source_rule_migration():
    """An empty modern ingress set is not a pre-migration Network baseline."""
    target = {"name": "eth0", "routing_domain": "management", "ip_cidr": "192.0.2.10/24",
              "gateway": "192.0.2.1"}
    preview = render_wan_config(
        [], targets=[target], applied_network_ingress=[], network_owned_targets=[target],
    )
    assert "rule del priority 1000" not in preview
    assert "rule add from " not in preview


def test_render_wan_config_keeps_management_and_lab_route_tables_separate():
    """Verify that render wan config keeps management and lab route tables separate."""
    config = render_wan_config(
        [Route(destination_cidr="0.0.0.0/0", gateway="172.20.0.254", interface_name="eth1", metric=100, enabled=True)],
        targets=[
            {
                "name": "eth0",
                "kind": "physical",
                "role": "management",
                "ip_cidr": "192.168.49.10/24",
                "ipv6_cidr": "",
                "gateway": "192.168.49.254",
                "routing_domain": "management",
                "route_allowed": False,
            },
            {
                "name": "eth1",
                "kind": "physical",
                "role": "route",
                "ip_cidr": "172.20.0.1/24",
                "ipv6_cidr": "",
                "routing_domain": "lab",
                "route_allowed": True,
            },
        ],
    )

    assert "management=100 atlaso_mgmt" in config
    assert "lab=200 atlaso_lab" in config
    assert "  gateway=192.168.49.254" in config
    assert "rule add from" not in config
    assert "ip route replace 192.168.49.0/24 dev eth0 table 100" in config
    assert "ip route replace default via 192.168.49.254 dev eth0\n" in config
    assert "ip route replace default via 192.168.49.254 dev eth0 table 100" in config
    assert "ip rule add iif eth1 table 200 priority 2000 protocol 2" in config
    assert "ip route replace 172.20.0.0/24 dev eth1 table 200" in config
    assert "ip route replace 0.0.0.0/0 via 172.20.0.254 dev eth1 metric 100 table 200" in config


def test_render_wan_config_emits_dual_stack_management_defaults_in_main_and_table_100():
    """Verify that render wan config emits dual stack management defaults in main and table 100."""
    config = render_wan_config(
        [],
        targets=[
            {
                "name": "eth0",
                "kind": "physical",
                "role": "management",
                "ip_cidr": "192.168.49.10/24",
                "ipv6_cidr": "2001:db8:49::10/64",
                "gateway": "192.168.49.254",
                "ipv6_gateway": "fe80::1",
                "routing_domain": "management",
                "route_allowed": False,
            }
        ],
    )

    assert "ip route replace default via 192.168.49.254 dev eth0\n" in config
    assert "ip route replace default via 192.168.49.254 dev eth0 table 100" in config
    assert "ip -6 route replace default via fe80::1 dev eth0\n" in config
    assert "ip -6 route replace default via fe80::1 dev eth0 table 100" in config


def test_render_wan_config_preserves_overlapping_prefixes_in_both_domains():
    """Keep identical management and access prefixes in their independent tables."""
    config = render_wan_config(
        [],
        targets=[
            {
                "name": "eth0",
                "kind": "physical",
                "role": "management",
                "ip_cidr": "192.168.1.10/24",
                "ipv6_cidr": "",
                "gateway": "192.168.1.1",
                "routing_domain": "management",
                "route_allowed": False,
            },
            {
                "name": "eth1.1",
                "kind": "vlan",
                "role": "access",
                "ip_cidr": "192.168.1.20/24",
                "ipv6_cidr": "",
                "routing_domain": "lab",
                "route_allowed": True,
            },
        ],
    )

    assert "rule add from" not in config
    assert "ip route replace 192.168.1.0/24 dev eth0 table 100" in config
    assert "ip rule add from 192.168.1.0/24 table 200" not in config
    assert "ip route replace 192.168.1.0/24 dev eth1.1 table 200" in config
    assert "ip rule add iif eth1.1 table 200 priority 2000 protocol 2" in config
    assert "ip -6 rule add iif eth1.1 table 200 priority 2000 protocol 2" in config


def test_render_wan_config_keeps_gatewayless_management_connected_route():
    """Keep gatewayless management peers reachable through the dedicated table."""
    config = render_wan_config(
        [],
        targets=[
            {
                "name": "eth0",
                "kind": "physical",
                "role": "management",
                "ip_cidr": "192.168.1.10/24",
                "ipv6_cidr": "",
                "gateway": "",
                "routing_domain": "management",
                "route_allowed": False,
            }
        ],
    )

    assert "ip rule add from 192.168.1.0/24 table 100" not in config
    assert "ip route replace 192.168.1.0/24 dev eth0 table 100" in config
    assert "route replace default" not in config


def test_validate_wan_state_rejects_ipv6_nat_sources_and_gateway_family_mismatch():
    """Verify that validate wan state rejects ipv6 nat sources and gateway family mismatch."""
    groups = [
        {"id": "any", "name": "Any", "entries": ["any"]},
        {"id": "custom:dual", "name": "Dual", "entries": ["192.168.50.0/24", "2001:db8:50::/64"]},
    ]
    nat = NatRule(name="dual source", source="group:custom:dual", outbound_interface="eth2.50", masquerade=True, priority=100, enabled=True)
    route = Route(destination_cidr="2001:db8:100::/64", gateway="192.168.50.254", interface_name="eth2.50", metric=100, enabled=True)

    errors = validate_wan_state([route], [], {"eth2.50"}, [nat], {"eth2.50"}, groups)

    assert any("same IP family" in error for error in errors)
    assert any("NAT v1 supports IPv4 source CIDRs only" in error for error in errors)
    assert any("NAT v1 supports IPv4 source CIDRs only" in error for error in validate_nat_source("group:custom:dual", {"custom:dual"}, groups))


def test_validate_wan_state_rejects_management_routing_rule_targets():
    """Verify that validate wan state rejects management routing rule targets."""
    rule = RoutingRule(name="mgmt transit", source_interface="eth0", destination_interface="eth1", priority=100, enabled=True)

    errors = validate_wan_state([], [], {"eth1"}, [], {"eth1"}, [], [rule], {"eth1"})

    assert any("source must be a non-management" in error for error in errors)
