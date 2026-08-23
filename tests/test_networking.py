"""Test networking behavior."""

import json
import logging

import pytest

from atlaso.app.models import (
    ApplianceSettings,
    AuditEvent,
    CaSettings,
    DhcpScope,
    DhcpSettings,
    DnsSettings,
    Job,
    KmsSettings,
    NatRule,
    PhysicalInterface,
    Route,
    RoutingRule,
    Setting,
    VlanInterface,
)
from atlaso.app.services import appliance_settings as appliance_settings_service
from atlaso.app.services.appliance_settings import (
    management_dhcp_dns_context,
    management_ui_context,
)
from atlaso.app.services.networking import (
    NETWORK_INVENTORY_CLEANUP_WARNING_KEY,
    NETWORK_ROLES,
    HostPhysicalInterface,
    is_canonical_network_role,
    normalize_interface_role,
    parse_linux_ip_interfaces,
    reconcile_host_physical_interfaces,
    render_network_config,
    sync_host_physical_interfaces,
    validate_network_state,
)


def test_wan_is_not_an_interface_role_alias():
    """Verify that wan is not an interface role alias."""
    assert normalize_interface_role("wan") == "unused"


@pytest.mark.parametrize("legacy_role", ["services", "storage"])
def test_retired_network_roles_normalize_only_for_persisted_compatibility(legacy_role):
    """Verify retired stored roles map to access but are not valid new role values.

    Args:
        legacy_role: Retired stored role covered by bounded compatibility.
    """
    assert normalize_interface_role(legacy_role) == "access"
    assert is_canonical_network_role(legacy_role) is False
    assert NETWORK_ROLES == ["management", "access", "route", "unused"]


def test_parse_linux_ip_interfaces_skips_loopback_and_vlans():
    """Verify that parse linux ip interfaces skips loopback and vlans."""
    payload = json.dumps(
        [
            {"ifname": "lo", "link_type": "loopback", "address": "00:00:00:00:00:00"},
            {
                "ifname": "eth0",
                "link_type": "ether",
                "address": "00:15:5d:aa:bb:01",
                "mtu": 1500,
                "operstate": "UP",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "addr_info": [{"family": "inet", "local": "192.168.49.22", "prefixlen": 24, "scope": "global"}],
            },
            {
                "ifname": "eth0.20",
                "link_type": "ether",
                "linkinfo": {"info_kind": "vlan"},
                "address": "00:15:5d:aa:bb:01",
                "mtu": 1500,
                "operstate": "UP",
                "flags": ["UP"],
                "addr_info": [{"family": "inet", "local": "192.168.20.1", "prefixlen": 24, "scope": "global"}],
            },
        ]
    )

    interfaces = parse_linux_ip_interfaces(payload)

    assert [interface.name for interface in interfaces] == ["eth0"]
    assert interfaces[0].host_ip_cidr == "192.168.49.22/24"
    assert interfaces[0].host_mtu == 1500
    assert interfaces[0].host_admin_state == "up"


def test_reconcile_host_inventory_replaces_seed_but_preserves_user_desired_state():
    """Verify that reconcile host inventory replaces seed but preserves user desired state."""
    seed = PhysicalInterface(
        name="eth0",
        mac_address="old",
        ip_cidr="192.168.49.1/24",
        mtu=1500,
        admin_state="up",
        role="management",
        mode="access",
        inventory_source="seed",
        desired_state_source="seed",
    )
    user_owned = PhysicalInterface(
        name="eth1",
        mac_address="00:15:5d:aa:bb:02",
        ip_cidr="192.168.50.1/24",
        mtu=9000,
        admin_state="down",
        role="access",
        mode="access",
        inventory_source="host",
        desired_state_source="user",
    )

    reconciled = reconcile_host_physical_interfaces(
        [seed, user_owned],
        [
            HostPhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="192.168.49.22/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            ),
            HostPhysicalInterface(
                name="eth1",
                mac_address="00:15:5d:aa:bb:02",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            ),
        ],
    )

    by_name = {interface.name: interface for interface in reconciled}
    assert by_name["eth0"].inventory_source == "host"
    assert by_name["eth0"].ip_cidr == "192.168.49.22/24"
    assert by_name["eth0"].host_ip_cidr == "192.168.49.22/24"
    assert by_name["eth1"].ip_cidr == "192.168.50.1/24"
    assert by_name["eth1"].mtu == 9000
    assert by_name["eth1"].admin_state == "down"
    assert by_name["eth1"].host_mtu == 1500


def test_reconcile_host_inventory_keeps_seed_non_management_down():
    """Verify that reconcile host inventory keeps seed non management down."""
    reconciled = reconcile_host_physical_interfaces(
        [],
        [
            HostPhysicalInterface(
                name="eth1",
                mac_address="00:15:5d:aa:bb:02",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="192.168.50.22/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            )
        ],
    )

    assert len(reconciled) == 1
    assert reconciled[0].name == "eth1"
    assert reconciled[0].host_ip_cidr == "192.168.50.22/24"
    assert reconciled[0].ip_cidr is None
    assert reconciled[0].admin_state == "down"


def test_reconcile_host_inventory_tracks_renumbered_nics_by_mac():
    """Verify that reconcile host inventory tracks renumbered nics by mac."""
    removed = PhysicalInterface(
        name="eth1",
        mac_address="00:15:5d:01:1d:14",
        ip_cidr=None,
        mtu=1500,
        admin_state="up",
        role="access",
        mode="trunk",
        inventory_source="host",
        desired_state_source="user",
    )
    survivor = PhysicalInterface(
        name="eth2",
        mac_address="00:15:5d:01:1d:15",
        ip_cidr="192.168.20.1/24",
        mtu=1500,
        admin_state="up",
        role="access",
        mode="access",
        inventory_source="host",
        desired_state_source="user",
    )
    renames: dict[str, str] = {}

    reconciled = reconcile_host_physical_interfaces(
        [removed, survivor],
        [
            HostPhysicalInterface(
                name="eth1",
                mac_address="00:15:5d:01:1d:15",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="192.168.20.1/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            )
        ],
        renames=renames,
    )

    by_mac = {interface.mac_address: interface for interface in reconciled}
    assert by_mac["00:15:5d:01:1d:15"].name == "eth1"
    assert by_mac["00:15:5d:01:1d:15"].ip_cidr == "192.168.20.1/24"
    assert by_mac["00:15:5d:01:1d:15"].mode == "access"
    assert by_mac["00:15:5d:01:1d:14"].name.startswith("missing_")
    assert by_mac["00:15:5d:01:1d:14"].oper_state == "missing"
    assert renames["eth2"] == "eth1"
    assert renames["eth1"].startswith("missing_")


def test_sync_host_inventory_cleans_removed_nic_bindings_and_retargets_survivors(monkeypatch, tmp_path, caplog):
    """Verify that sync host inventory cleans removed nic bindings and retargets survivors.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        caplog: Pytest fixture used to capture emitted log records.
    """
    from sqlalchemy import select

    import atlaso.app.database as database
    from atlaso.app.config import get_settings

    db_path = tmp_path / "atlaso-renumber.db"
    monkeypatch.setenv("ATLASO_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ATLASO_SECRET_KEY", "test-secret-key-with-enough-length")
    monkeypatch.setenv("ATLASO_BOOTSTRAP_ADMIN_PASSWORD", "atlaso-admin")
    get_settings.cache_clear()
    database.engine.dispose()
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal.configure(bind=database.engine)
    database.init_db()

    def fake_discover():
        """Return fake discover."""
        return [
            HostPhysicalInterface(
                name="eth1",
                mac_address="00:15:5d:01:1d:15",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="192.168.20.1/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            )
        ]

    monkeypatch.setattr("atlaso.app.services.networking.discover_host_physical_interfaces", fake_discover)

    with database.SessionLocal() as db:
        db.add_all(
            [
                PhysicalInterface(
                    name="eth1",
                    mac_address="00:15:5d:01:1d:14",
                    role="access",
                    mode="trunk",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth2",
                    mac_address="00:15:5d:01:1d:15",
                    role="management",
                    mode="access",
                    ipv4_method="dhcp",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                Setting(
                    key="appliance_apply.baselines.v1",
                    value=json.dumps(
                        {
                            "network": {
                                "config_preview": "\n".join(
                                    [
                                        "[physical_interfaces]",
                                        "interface=eth1",
                                        "role=management",
                                        "mode=access",
                                        "admin_state=up",
                                        "ipv4_method=dhcp",
                                        "ip_cidr=",
                                        "ipv6_enabled=false",
                                        "ipv6_cidr=",
                                        "interface=eth2",
                                        "role=management",
                                        "mode=access",
                                        "admin_state=up",
                                        "ipv4_method=dhcp",
                                        "ip_cidr=",
                                        "ipv6_enabled=false",
                                        "ipv6_cidr=",
                                    ]
                                )
                            }
                        }
                    ),
                ),
                VlanInterface(parent_interface="eth1", name="eth1.22", vlan_id=22, ip_cidr="192.168.22.1/24"),
                VlanInterface(parent_interface="eth2", name="eth2.50", vlan_id=50, ip_cidr="192.168.50.1/24"),
                Route(destination_cidr="10.50.0.0/24", interface_name="eth2.50"),
                Route(destination_cidr="10.22.0.0/24", interface_name="eth1.22"),
                NatRule(name="removed outbound", source="192.168.22.0/24", outbound_interface="eth1.22"),
                RoutingRule(name="removed route permission", source_interface="eth1.22", destination_interface="eth2.50"),
                RoutingRule(name="survivor route permission", source_interface="eth2.50", destination_interface="eth2"),
                DhcpSettings(enabled=True),
                DhcpScope(name="removed-zone", interface_name="eth1.22", site_address="192.168.22.1", range_expression="192.168.22.100-200"),
                DnsSettings(enabled=True, listen_interface="eth1.22\neth2.50", listen_address="192.168.22.1\n192.168.50.1"),
                CaSettings(enabled=True, listen_interface="eth1.22", listen_address="192.168.22.1\n10.0.0.99"),
                KmsSettings(enabled=True, listen_interface="eth1.22", listen_address="192.168.22.1"),
            ]
        )
        db.commit()

        with caplog.at_level(logging.WARNING, logger="atlaso.networking"):
            sync_host_physical_interfaces(db)

        survivor = db.execute(select(PhysicalInterface).where(PhysicalInterface.mac_address == "00:15:5d:01:1d:15")).scalar_one()
        removed = db.execute(select(PhysicalInterface).where(PhysicalInterface.mac_address == "00:15:5d:01:1d:14")).scalar_one()
        assert survivor.name == "eth1"
        assert survivor.ip_cidr is None
        assert removed.name.startswith("missing_")
        assert removed.oper_state == "missing"
        assert removed.mode == "unused"
        assert removed.admin_state == "down"
        assert removed.ip_cidr is None
        survivor_vlan = db.execute(select(VlanInterface).where(VlanInterface.vlan_id == 50)).scalar_one()
        removed_vlan = db.execute(select(VlanInterface).where(VlanInterface.vlan_id == 22)).scalar_one()
        assert survivor_vlan.parent_interface == "eth1"
        assert survivor_vlan.name == "eth1.50"
        assert removed_vlan.parent_interface == removed.name
        assert removed_vlan.name == f"{removed.name}.22"
        assert removed_vlan.enabled is False
        survivor_route = db.execute(select(Route).where(Route.destination_cidr == "10.50.0.0/24")).scalar_one()
        removed_route = db.execute(select(Route).where(Route.destination_cidr == "10.22.0.0/24")).scalar_one()
        assert survivor_route.interface_name == "eth1.50"
        assert survivor_route.enabled is True
        assert removed_route.interface_name == f"{removed.name}.22"
        assert removed_route.enabled is False
        nat_rule = db.execute(select(NatRule).where(NatRule.name == "removed outbound")).scalar_one()
        assert nat_rule.enabled is False
        assert nat_rule.outbound_interface == ""
        removed_routing_rule = db.execute(select(RoutingRule).where(RoutingRule.name == "removed route permission")).scalar_one()
        assert removed_routing_rule.enabled is False
        assert removed_routing_rule.source_interface == f"{removed.name}.22"
        assert removed_routing_rule.destination_interface == "eth1.50"
        survivor_routing_rule = db.execute(select(RoutingRule).where(RoutingRule.name == "survivor route permission")).scalar_one()
        assert survivor_routing_rule.enabled is True
        assert survivor_routing_rule.source_interface == "eth1.50"
        assert survivor_routing_rule.destination_interface == "eth1"
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        assert dhcp_settings.enabled is False
        dhcp_scope = db.execute(select(DhcpScope).where(DhcpScope.name == "removed-zone")).scalar_one()
        assert dhcp_scope.enabled is False
        assert dhcp_scope.interface_name == ""
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        assert dns_settings.listen_interface == "eth1.50"
        assert dns_settings.listen_address == "192.168.50.1"
        assert dns_settings.enabled is True
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        assert ca_settings.listen_interface == ""
        assert ca_settings.listen_address == "10.0.0.99"
        assert ca_settings.enabled is True
        kms_settings = db.execute(select(KmsSettings)).scalar_one()
        assert kms_settings.listen_interface == ""
        assert kms_settings.listen_address == ""
        assert kms_settings.enabled is False
        rendered = render_network_config(interfaces=[survivor, removed], vlans=[survivor_vlan, removed_vlan])
        assert removed.name not in rendered
        assert removed_vlan.name not in rendered
        warning = db.execute(select(Setting).where(Setting.key == NETWORK_INVENTORY_CLEANUP_WARNING_KEY)).scalar_one()
        assert "Missing physical interface cleanup" in warning.value
        audit = db.execute(select(AuditEvent).where(AuditEvent.action == "cleanup_missing_physical_interface_bindings")).scalar_one()
        assert "disabled VLAN eth1.22" in (audit.detail or "")
        assert "disabled KMS / KMIP" in (audit.detail or "")
        assert "Missing physical interface cleanup" in caplog.text
        from atlaso.app.services.management_bindings import applied_management_bindings

        assert applied_management_bindings(db) == [
            {
                "interface": "eth1",
                "role": "management",
                "address": "192.168.20.1",
                "management_ui": "true",
            }
        ]

        monkeypatch.setattr(
            "atlaso.app.services.networking.discover_host_physical_interfaces",
            lambda: [
                fake_discover()[0],
                HostPhysicalInterface(
                    name="eth3",
                    mac_address="00:15:5d:01:1d:14",
                    driver="hv_netvsc",
                    speed="10000 Mbps",
                    host_ip_cidr="192.168.30.1/24",
                    host_mtu=1500,
                    host_admin_state="up",
                    oper_state="up",
                ),
            ],
        )
        sync_host_physical_interfaces(db)
        assert applied_management_bindings(db) == [
            {
                "interface": "eth3",
                "role": "management",
                "address": "192.168.30.1",
                "management_ui": "true",
            },
            {
                "interface": "eth1",
                "role": "management",
                "address": "192.168.20.1",
                "management_ui": "true",
            },
        ]

    get_settings.cache_clear()


def test_sync_host_inventory_commits_two_nic_name_swap(monkeypatch, tmp_path):
    """Verify that sync host inventory commits two nic name swap.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    import atlaso.app.database as database
    from atlaso.app.config import get_settings

    db_path = tmp_path / "atlaso-swap.db"
    monkeypatch.setenv("ATLASO_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ATLASO_SECRET_KEY", "test-secret-key-with-enough-length")
    monkeypatch.setenv("ATLASO_BOOTSTRAP_ADMIN_PASSWORD", "atlaso-admin")
    get_settings.cache_clear()
    database.engine.dispose()
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal.configure(bind=database.engine)
    database.init_db()

    mac_a = "00:15:5d:01:1d:14"
    mac_b = "00:15:5d:01:1d:15"

    def fake_discover():
        """Return fake discover."""
        return [
            HostPhysicalInterface(
                name="eth1",
                mac_address=mac_b,
                driver="vmxnet3",
                speed="10000 Mbps",
                host_ip_cidr="10.0.10.1/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            ),
            HostPhysicalInterface(
                name="eth2",
                mac_address=mac_a,
                driver="vmxnet3",
                speed="10000 Mbps",
                host_ip_cidr=None,
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            ),
        ]

    monkeypatch.setattr("atlaso.app.services.networking.discover_host_physical_interfaces", fake_discover)

    with database.SessionLocal() as db:
        db.add_all(
            [
                PhysicalInterface(
                    name="eth1",
                    mac_address=mac_a,
                    role="access",
                    mode="trunk",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth2",
                    mac_address=mac_b,
                    role="access",
                    mode="access",
                    ip_cidr="10.0.10.1/24",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                VlanInterface(parent_interface="eth2", name="eth2.50", vlan_id=50, ip_cidr="192.168.50.1/24"),
                Route(destination_cidr="10.50.0.0/24", interface_name="eth2.50"),
            ]
        )
        db.commit()

        sync_host_physical_interfaces(db)

        nic_a = db.execute(select(PhysicalInterface).where(PhysicalInterface.mac_address == mac_a)).scalar_one()
        nic_b = db.execute(select(PhysicalInterface).where(PhysicalInterface.mac_address == mac_b)).scalar_one()
        assert nic_a.name == "eth2"
        assert nic_a.oper_state == "up"
        assert nic_b.name == "eth1"
        assert nic_b.host_ip_cidr == "10.0.10.1/24"
        vlan = db.execute(select(VlanInterface).where(VlanInterface.vlan_id == 50)).scalar_one()
        assert vlan.parent_interface == "eth1"
        assert vlan.name == "eth1.50"
        route = db.execute(select(Route).where(Route.destination_cidr == "10.50.0.0/24")).scalar_one()
        assert route.interface_name == "eth1.50"
        assert db.execute(select(Setting).where(Setting.key == NETWORK_INVENTORY_CLEANUP_WARNING_KEY)).scalar_one_or_none() is None

    get_settings.cache_clear()


def test_startup_host_inventory_refreshes_appliance_seed_without_apply_job(monkeypatch, tmp_path):
    """Verify that startup host inventory refreshes appliance seed without apply job.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    import atlaso.app.database as database
    from atlaso.app.config import get_settings
    from atlaso.app.main import refresh_startup_host_inventory
    from atlaso.app.seed import seed_initial_data

    db_path = tmp_path / "atlaso-startup.db"
    monkeypatch.setenv("ATLASO_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ATLASO_SECRET_KEY", "test-secret-key-with-enough-length")
    monkeypatch.setenv("ATLASO_BOOTSTRAP_ADMIN_PASSWORD", "atlaso-admin")
    get_settings.cache_clear()

    database.engine.dispose()
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal.configure(bind=database.engine)
    database.init_db()

    def fake_discover():
        """Return fake discover."""
        return [
            HostPhysicalInterface(
                name="ens192",
                mac_address="00:15:5d:aa:bb:cc",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="192.168.49.22/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            )
        ]

    monkeypatch.setattr("atlaso.app.services.networking.discover_host_physical_interfaces", fake_discover)

    with database.SessionLocal() as db:
        seed_initial_data(db, include_examples=False)
        refresh_startup_host_inventory(db, environment="appliance")
        interface = db.execute(select(PhysicalInterface)).scalar_one()
        assert interface.name == "ens192"
        assert interface.inventory_source == "host"
        assert interface.desired_state_source == "seed"
        assert interface.ip_cidr is None
        assert interface.admin_state == "down"
        assert db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one_or_none() is None

    get_settings.cache_clear()


def test_appliance_seed_preserves_ovf_auto_ipv6_and_root_ssh(monkeypatch, tmp_path):
    """Verify that appliance seed preserves ovf auto ipv6 and root ssh.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    import atlaso.app.database as database
    from atlaso.app.config import get_settings
    from atlaso.app.seed import seed_initial_data

    db_path = tmp_path / "atlaso-ovf-seed.db"
    monkeypatch.setenv("ATLASO_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ATLASO_SECRET_KEY", "test-secret-key-with-enough-length")
    monkeypatch.setenv("ATLASO_BOOTSTRAP_ADMIN_PASSWORD", "atlaso-admin")
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_CIDR", "dhcp")
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED", "true")
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_IPV6_CIDR", "")
    monkeypatch.setenv("ATLASO_APPLIANCE_ROOT_SSH_ENABLED", "true")
    get_settings.cache_clear()
    database.engine.dispose()
    database.engine = database.create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    database.SessionLocal.configure(bind=database.engine)
    database.init_db()

    with database.SessionLocal() as db:
        seed_initial_data(db, include_examples=False, appliance_mode=True)
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert interface.ipv4_method == "dhcp"
        assert interface.ipv6_enabled is True
        assert interface.ipv6_cidr is None
        assert appliance_settings.root_ssh_enabled is True

    get_settings.cache_clear()


def test_render_network_config_includes_physical_roles_for_networkd_apply():
    """Verify that render network config includes physical roles for networkd apply."""
    config = render_network_config(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ip_cidr="192.168.49.1/24",
                role="management",
                mode="access",
            )
        ],
        vlans=[],
    )

    assert "interface=eth0" in config
    assert "  role=management" in config
    assert "  ipv4_method=static" in config


def test_render_network_config_includes_management_dhcp_method():
    """Verify that render network config includes management dhcp method."""
    config = render_network_config(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ipv4_method="dhcp",
                role="management",
                mode="access",
            )
        ],
        vlans=[],
    )

    assert "interface=eth0" in config
    assert "  role=management" in config
    assert "  ipv4_method=dhcp" in config
    assert "  ip_cidr=" in config


def test_render_network_config_persists_automatic_ipv6_state():
    """Verify that render network config persists automatic ipv6 state."""
    config = render_network_config(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ipv4_method="dhcp",
                ipv6_enabled=True,
                ipv6_cidr=None,
                role="management",
                mode="access",
            )
        ],
        vlans=[],
    )

    assert "  ipv6_enabled=true" in config
    assert "  ipv6_cidr=" in config


def test_render_network_config_persists_optional_management_ipv6_gateway():
    """Verify that render network config persists optional management ipv6 gateway."""
    config = render_network_config(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ip_cidr="192.168.49.10/24",
                ipv6_enabled=True,
                ipv6_cidr="2001:db8:49::10/64",
                ipv6_gateway="fe80::1",
                role="management",
                mode="access",
            )
        ],
        vlans=[],
    )

    assert "  ipv6_gateway=fe80::1" in config


def test_validate_network_state_rejects_ipv6_cidr_while_disabled():
    """Verify that validate network state rejects ipv6 cidr while disabled."""
    errors = validate_network_state(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ip_cidr="192.168.49.1/24",
                ipv6_enabled=False,
                ipv6_cidr="fd00:49::1/64",
                role="management",
                mode="access",
                mtu=1500,
            )
        ],
        vlans=[],
    )

    assert "Interface eth0 cannot set an IPv6 CIDR while IPv6 is disabled." in errors


@pytest.mark.parametrize(
    ("gateway", "message"),
    [
        ("192.168.49.1", "wrong IP family"),
        ("2001:db8:50::1", "not link-local or on-link"),
        ("2001:db8:49::10", "cannot equal"),
    ],
)
def test_validate_network_state_rejects_invalid_management_ipv6_gateway(gateway, message):
    """Verify that validate network state rejects invalid management ipv6 gateway.

    Args:
        gateway: Gateway supplied to the test scenario.
        message: Human-readable message associated with the operation.
    """
    errors = validate_network_state(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ip_cidr="192.168.49.10/24",
                ipv6_enabled=True,
                ipv6_cidr="2001:db8:49::10/64",
                ipv6_gateway=gateway,
                role="management",
                mode="access",
                mtu=1500,
                admin_state="up",
            )
        ],
        vlans=[],
    )

    assert any(message in error for error in errors)


def test_validate_network_state_accepts_link_local_management_ipv6_gateway():
    """Verify that validate network state accepts link local management ipv6 gateway."""
    errors = validate_network_state(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ip_cidr="192.168.49.10/24",
                ipv6_enabled=True,
                ipv6_cidr="2001:db8:49::10/64",
                ipv6_gateway="fe80::1",
                role="management",
                mode="access",
                mtu=1500,
                admin_state="up",
            )
        ],
        vlans=[],
    )

    assert errors == []


def test_validate_network_state_rejects_static_management_without_ipv4():
    """Verify that validate network state rejects static management without ipv4."""
    errors = validate_network_state(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ipv4_method="static",
                role="management",
                mode="access",
                mtu=1500,
            )
        ],
        vlans=[],
    )

    assert "Interface eth0 must set an IPv4 CIDR when IPv4 method is static." in errors


def test_validate_network_state_allows_management_role_on_non_eth0_interface():
    """Verify that a dedicated management role is not tied to eth0."""
    errors = validate_network_state(
        interfaces=[
            PhysicalInterface(
                name="eth1",
                mac_address="00:15:5d:aa:bb:01",
                ip_cidr="192.168.49.1/24",
                role="management",
                mode="access",
                mtu=1500,
                admin_state="up",
            )
        ],
        vlans=[],
    )

    assert errors == []


def test_validate_network_state_allows_flagged_access_without_dedicated_management():
    """Verify that an access interface can be the only management browser path."""
    errors = validate_network_state(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                mac_address="00:15:5d:aa:bb:01",
                ip_cidr="192.168.49.1/24",
                role="access",
                mode="access",
                access_management_ui_enabled=True,
                admin_state="up",
                oper_state="up",
                mtu=1500,
            )
        ],
        vlans=[],
    )

    assert errors == []


def test_validate_network_state_rejects_flagged_access_without_usable_address():
    """Verify that a flag cannot satisfy lockout protection without a usable listener address."""
    for ip_cidr in (None, "169.254.10.20/16"):
        errors = validate_network_state(
            interfaces=[
                PhysicalInterface(
                    name="eth0",
                    mac_address="00:15:5d:aa:bb:01",
                    ip_cidr=ip_cidr,
                    role="access",
                    mode="access",
                    access_management_ui_enabled=True,
                    admin_state="up",
                    oper_state="up",
                    mtu=1500,
                )
            ],
            vlans=[],
        )

        assert (
            "Interface eth0 can expose the management UI only when it has a usable non-link-local address."
            in errors
        )
        assert (
            "Network desired state must keep a management interface or enable the management UI on at least one access interface."
            in errors
        )


def test_validate_network_state_rejects_flagged_access_vlan_with_only_link_local_address():
    """Verify that a link-local-only access VLAN cannot be the management browser path."""
    errors = validate_network_state(
        interfaces=[
            PhysicalInterface(
                name="eth1",
                mac_address="00:15:5d:aa:bb:02",
                role="access",
                mode="trunk",
                admin_state="up",
                oper_state="up",
                mtu=1500,
            )
        ],
        vlans=[
            VlanInterface(
                name="eth1.20",
                parent_interface="eth1",
                vlan_id=20,
                ip_cidr="169.254.20.1/16",
                role="access",
                enabled=True,
                mtu=1500,
                access_management_ui_enabled=True,
            )
        ],
    )

    assert "VLAN eth1.20 can expose the management UI only when it has a usable non-link-local address." in errors
    assert (
        "Network desired state must keep a management interface or enable the management UI on at least one access interface."
        in errors
    )


def test_management_ui_context_prefers_dedicated_then_flagged_eth0_then_vlan(monkeypatch):
    """Verify deterministic appliance identity selection across management UI listeners.

    Args:
        monkeypatch: Pytest fixture used to replace DHCP DNS observation.
    """
    dedicated = PhysicalInterface(
        name="eth2",
        ip_cidr="192.168.52.1/24",
        role="management",
        mode="access",
        admin_state="up",
        oper_state="up",
    )
    flagged_eth1 = PhysicalInterface(
        name="eth1",
        ip_cidr="192.168.51.1/24",
        role="access",
        mode="access",
        access_management_ui_enabled=True,
        admin_state="up",
        oper_state="up",
    )
    flagged_eth0 = PhysicalInterface(
        name="eth0",
        host_ip_cidr="192.168.50.25/24",
        ipv4_method="dhcp",
        role="access",
        mode="access",
        access_management_ui_enabled=True,
        admin_state="up",
        oper_state="up",
    )
    flagged_vlan = VlanInterface(
        name="eth1.20",
        parent_interface="eth1",
        vlan_id=20,
        ip_cidr="192.168.20.1/24",
        role="access",
        enabled=True,
        access_management_ui_enabled=True,
    )

    assert management_ui_context(
        [flagged_eth1, dedicated, flagged_eth0],
        [flagged_vlan],
    )["name"] == "eth2"
    assert management_ui_context(
        [flagged_eth1, flagged_eth0],
        [flagged_vlan],
    )["name"] == "eth0"
    assert management_ui_context([flagged_eth1, flagged_eth0], [flagged_vlan])["ipv4_method"] == "dhcp"
    assert management_ui_context([], [flagged_vlan])["name"] == "eth1.20"
    monkeypatch.setattr(
        appliance_settings_service,
        "observed_management_dhcp_dns_servers",
        lambda interface_name: ["192.0.2.53"] if interface_name == "eth0" else [],
    )
    dhcp_context, dhcp_servers = management_dhcp_dns_context(
        [flagged_eth1, flagged_eth0],
        [flagged_vlan],
    )
    assert dhcp_context["name"] == "eth0"
    assert dhcp_servers == ["192.0.2.53"]
    assert management_dhcp_dns_context([], [flagged_vlan])[0]["name"] == "eth1.20"


def test_validate_network_state_rejects_lockout_and_non_access_flag():
    """Verify that the flag cannot be used outside an effective access listener."""
    interface = PhysicalInterface(
        name="eth1",
        mac_address="00:15:5d:aa:bb:02",
        ip_cidr="192.168.50.1/24",
        role="unused",
        mode="access",
        access_management_ui_enabled=True,
        admin_state="up",
        oper_state="up",
        mtu=1500,
    )

    errors = validate_network_state(interfaces=[interface], vlans=[])

    assert "Interface eth1 can expose the management UI only when its role and link type are access." in errors
    assert "Network desired state must keep a management interface or enable the management UI on at least one access interface." in errors


def test_render_network_config_includes_dual_stack_physical_and_vlan_cidrs():
    """Verify that render network config includes dual stack physical and vlan cidrs."""
    config = render_network_config(
        interfaces=[
            PhysicalInterface(
                name="eth1",
                mac_address="00:15:5d:aa:bb:02",
                ip_cidr="192.168.50.1/24",
                ipv6_enabled=True,
                ipv6_cidr="2001:db8:50::1/64",
                role="access",
                mode="trunk",
            )
        ],
        vlans=[
            VlanInterface(
                name="eth1.20",
                parent_interface="eth1",
                vlan_id=20,
                ip_cidr="192.168.20.1/24",
                ipv6_cidr="2001:db8:20::1/64",
                enabled=True,
            )
        ],
    )

    assert "interface=eth1" in config
    assert "  ip_cidr=192.168.50.1/24" in config
    assert "  ipv6_cidr=2001:db8:50::1/64" in config
    assert "vlan=eth1.20" in config
    assert "  ip_cidr=192.168.20.1/24" in config
    assert "  ipv6_cidr=2001:db8:20::1/64" in config
