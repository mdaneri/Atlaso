"""Verify NAT ingress boundaries across desired state, rendering, and upgrade."""

import pytest
from sqlalchemy import create_engine, inspect, text

from atlaso.app.models import NatRule, PhysicalInterface, VlanInterface
from atlaso.app.services.routes_wan import (
    RoutesWanSettings,
    nat_eligible_target_names,
    render_wan_config,
    validate_nat_ingress,
    validate_wan_state,
)
from tests.test_appliance_helper import load_helper_module


def target(name, **changes):
    """Build an explicitly eligible IPv4 lab target.

    Args:
        name: Interface name for the eligible target fixture.
        **changes: Additional target metadata for the scenario.
    """
    return dict(name=name, role="access", kind="physical", ip_cidr="192.0.2.1/24",
                routing_domain="lab", route_allowed=True, nat_allowed=True, **changes)


def test_saved_nat_physical_identity_is_bounded():
    """Preserve provenance without allowing line-oriented configuration injection."""
    metadata = dict(nat_physical_interface="eth2", nat_physical_mac="00:11:22:33:44:55")
    rendered = render_wan_config([], targets=[target("eth2", **metadata)])
    assert "  nat_physical_interface=eth2\n" in rendered
    assert "  nat_physical_mac=00:11:22:33:44:55\n" in rendered
    for field in metadata:
        with pytest.raises(ValueError, match="identity is invalid"):
            render_wan_config([], targets=[target("eth2", **{**metadata, field: "eth2\ninjected=true"})])


@pytest.mark.parametrize("source,expression", [("any", ""), ("10.0.0.0/24", "ip saddr 10.0.0.0/24 ")])
def test_both_renderers_require_ingress_and_preserve_address_scope(source, expression):
    """An iifname match excludes local output and every unselected ingress.

    Args:
        source: Source selector exercised by both renderers.
        expression: Expected nftables source-address predicate.
    """
    rule = NatRule(name="Scoped", inbound_interfaces=["eth3", "eth2"], source=source,
                   outbound_interface="eth1", enabled=True, masquerade=True, priority=100)
    config = render_wan_config([], nat_rules=[rule], targets=[target(n) for n in ["eth1", "eth2", "eth3"]],
                               settings=RoutesWanSettings(True, True, False))
    expected = 'iifname { "eth2", "eth3" } ' + expression + 'oifname "eth1" masquerade'
    assert expected in config
    helper = load_helper_module()
    rendered = helper._render_wan_nat_config([dict(name="Scoped", enabled="true", inbound_interfaces="eth3,eth2",
                                                 outbound_interface="eth1", source=source)])
    assert expected in rendered


def test_legacy_scope_is_retained_but_cannot_render_or_validate():
    """No upgrade or disabled-rule path invents ingress membership."""
    rule = NatRule(name="Legacy", source="any", outbound_interface="eth1", enabled=True,
                   masquerade=True, priority=100)
    assert any("explicit review" in error for error in validate_wan_state([], [], {"eth1"}, [rule], {"eth1"}))
    config = render_wan_config([], nat_rules=[rule], targets=[target("eth1")], settings=RoutesWanSettings(True, True, False))
    assert "inbound_interfaces=" in config
    assert 'oifname "eth1" masquerade' not in config
    with pytest.raises(ValueError, match="explicit inbound"):
        load_helper_module()._render_wan_nat_config([dict(name="Legacy", outbound_interface="eth1")])
    rule.enabled = False
    assert not validate_wan_state([], [], {"eth1"}, [rule], {"eth1"})


def test_ingress_rejects_empty_management_duplicates_and_outbound():
    """Require a reviewed set of distinct eligible ingress targets."""
    eligible = {"eth1", "eth2"}
    for inbound in [[], ["eth0"], ["eth1"], ["eth2", "eth2"], "eth2", [None]]:
        assert validate_nat_ingress(inbound, "eth1", eligible)
    assert not validate_nat_ingress(["eth2"], "eth1", eligible)


def test_eligibility_tracks_parent_state_and_preserves_flagged_access():
    """Down, missing, trunk, unused, and dedicated management cannot enter NAT."""
    physical = PhysicalInterface(name="eth2", role="access", mode="access", admin_state="up",
                                 oper_state="up", ip_cidr="192.0.2.1/24", access_management_ui_enabled=True)
    parent = PhysicalInterface(name="eth1", role="access", mode="trunk", admin_state="up", oper_state="up")
    vlan = VlanInterface(name="eth1.20", parent_interface="eth1", role="route", enabled=True, ip_cidr="10.0.0.1/24")
    assert nat_eligible_target_names([physical, parent], [vlan]) == {"eth2", "eth1.20"}
    for field, value in [("admin_state", "down"), ("oper_state", "missing"), ("role", "management"), ("role", "unused"), ("mode", "trunk")]:
        previous = getattr(physical, field)
        setattr(physical, field, value)
        assert "eth2" not in nat_eligible_target_names([physical, parent], [vlan])
        setattr(physical, field, previous)
    parent.admin_state = "down"
    assert nat_eligible_target_names([physical, parent], [vlan]) == {"eth2"}
    assert nat_eligible_target_names([physical], [vlan]) == {"eth2"}


def test_database_upgrade_retains_enabled_legacy_rule(tmp_path, monkeypatch):
    """Adding the nullable-free ingress column preserves the legacy rule unchanged.

    Args:
        tmp_path: Isolated directory for the legacy database.
        monkeypatch: Fixture replacing the application database engine.
    """
    import atlaso.app.database as database

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE nat_rules (id INTEGER PRIMARY KEY, name TEXT, enabled BOOLEAN)"))
        connection.execute(text("INSERT INTO nat_rules VALUES (1, 'Legacy', 1)"))
    monkeypatch.setattr(database, "engine", engine)
    database.init_db()
    with engine.connect() as connection:
        assert "inbound_interfaces" in {column["name"] for column in inspect(connection).get_columns("nat_rules")}
        assert connection.execute(text("SELECT name, enabled, inbound_interfaces FROM nat_rules")).one() == ("Legacy", 1, "[]")
    engine.dispose()


def test_concurrent_nat_column_upgrade(tmp_path):
    """Both startup processes can upgrade the same legacy NAT table.

    Args:
        tmp_path: Isolated directory for the shared legacy database.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from atlaso.app import database

    engine = create_engine(f"sqlite:///{tmp_path / 'concurrent-nat.db'}", connect_args={"timeout": 10})
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE nat_rules (id INTEGER PRIMARY KEY, name TEXT, enabled BOOLEAN)"))
        connection.execute(text("INSERT INTO nat_rules VALUES (1, 'Legacy', 1)"))
    ready = Barrier(2)

    def upgrade():
        """Race two independent service connections at the schema boundary."""
        ready.wait()
        database._create_database_schema(engine)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(upgrade) for _ in range(2)]
        for future in futures:
            future.result()
    with engine.connect() as connection:
        assert connection.execute(text("SELECT name, enabled, inbound_interfaces FROM nat_rules")).one() == ("Legacy", 1, "[]")
    engine.dispose()


@pytest.mark.parametrize("bad", ["eth2\nfield=value", "eth2\rfield=value", "eth2,eth3", 'eth2"', "eth2;", "a" * 81, "", "eth2\x00"])
def test_disabled_ingress_syntax_never_reaches_config(bad):
    """Dormant rows retain unavailable identities, never malformed configuration text.

    Args:
        bad: Malformed interface name that must never reach configuration text.
    """
    assert validate_nat_ingress([bad], "eth1", set(), required=False, check_availability=False)
    assert not validate_nat_ingress(["missing_155d011d14.22"], "eth1", set(), required=False, check_availability=False)
    rule = NatRule(name="Dormant", source="any", outbound_interface="eth1", inbound_interfaces=[bad],
                   enabled=False, masquerade=True, priority=100)
    with pytest.raises(ValueError, match="canonical interface"):
        render_wan_config([], nat_rules=[rule], settings=RoutesWanSettings(False, False, False))


def test_safe_invalid_or_legacy_boundaries_remain_reviewable():
    """Syntax guards leave safe legacy and semantic errors visible for explicit review."""
    for inbound, outbound in [([], ""), (["eth2"], "eth2"), (["missing_155d011d14.22"], "eth1")]:
        rule = NatRule(name="Review", source="any", inbound_interfaces=inbound, outbound_interface=outbound,
                       enabled=False, masquerade=True, priority=100)
        config = render_wan_config([], nat_rules=[rule], settings=RoutesWanSettings(False, False, False))
        assert "nat=Review" in config
        assert "masquerade comment" not in config
