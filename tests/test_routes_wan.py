"""Test routes wan behavior."""

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
    assert "nat_enabled=true" in config
    assert "effective_nat_enabled=false" in config
    assert "wan_simulation_enabled=true" in config
    assert "route=10.20.0.0/24" in config
    assert "nat=Lab NAT" in config
    assert "policy=Slow WAN" in config
    assert "ip route replace 10.20.0.0/24" not in config
    assert "masquerade comment \"Lab NAT\"" not in config
    assert "tc qdisc replace dev eth1 root netem delay 100ms" in config
    assert "net.ipv4.ip_forward=0" in config
    assert "net.ipv6.conf.all.forwarding=0" in config


def test_disabled_features_do_not_surface_inactive_row_validation_errors():
    """Do not block Apply on invalid resources whose global feature is off."""
    invalid_route = Route(
        destination_cidr="not-a-network",
        interface_name="missing",
        metric=-1,
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
        set(),
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


def test_fresh_settings_default_off_and_legacy_rows_infer_once(client):
    """Reconcile missing upgrade keys from effective legacy rows only once.

    Args:
        client: HTTP test client providing the isolated application database.
    """
    from sqlalchemy import delete, select

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        fresh = ensure_routes_wan_settings(db)
        assert fresh == RoutesWanSettings(False, False, False)

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
        assert nat_only == RoutesWanSettings(True, True, False)

        db.execute(delete(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS)))
        route.enabled = True
        route.wan_policy_id = policy.id
        db.flush()

        inferred = ensure_routes_wan_settings(db)
        assert inferred == RoutesWanSettings(True, True, True)
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
        assert ensure_routes_wan_settings(db) == RoutesWanSettings(True, True, True)


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
    assert "ip -6 rule add from 2001:db8:50::/64 table 200 priority 2000" in config
    assert "ip -6 route replace 2001:db8:100::/64 via 2001:db8:50::fe dev eth2.50 metric 120 table 200" in config


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
    assert "ip rule add from 192.168.49.0/24 table 100 priority 1000" in config
    assert "ip route replace 192.168.49.0/24 dev eth0 table 100" in config
    assert "ip route replace default via 192.168.49.254 dev eth0\n" in config
    assert "ip route replace default via 192.168.49.254 dev eth0 table 100" in config
    assert "ip rule add from 172.20.0.0/24 table 200 priority 2001" in config
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


def test_render_wan_config_gives_management_ownership_of_duplicate_vlan_network():
    """Verify that render wan config gives management ownership of duplicate vlan network."""
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

    assert "ip rule add from 192.168.1.0/24 table 100 priority 1000" in config
    assert "ip route replace 192.168.1.0/24 dev eth0 table 100" in config
    assert "ip rule add from 192.168.1.0/24 table 200" not in config
    assert "ip route replace 192.168.1.0/24 dev eth1.1 table 200" not in config
    assert "# 192.168.1.0/24 on eth1.1 reuses the subnet owned by eth0; no duplicate policy route generated" in config


def test_render_wan_config_keeps_gatewayless_management_on_main_table():
    """Verify that render wan config keeps gatewayless management on main table."""
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
    assert "ip route replace 192.168.1.0/24 dev eth0 table 100" not in config
    assert "# 192.168.1.0/24 on eth0 has no management default gateway; the main routing table remains authoritative" in config


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
