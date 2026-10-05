"""Regression coverage for generated DNS across startup NIC renames."""

import pytest
from sqlalchemy import select

from tests.routers.ui.helpers import login


@pytest.mark.parametrize("legacy_ownership", [False, True], ids=["current", "legacy"])
def test_startup_mac_rename_projects_dhcp_dns_move_through_applied_nic_alias(
    client, monkeypatch, legacy_ownership
):
    """Resolve applied listener provenance after startup renames a DHCP NIC by MAC.

    Args:
        client: Seeded application client used to initialize the database.
        monkeypatch: Replace only native host discovery.
        legacy_ownership: Omit captured DNS ownership to exercise startup migration.
    """
    from atlaso.app import main, ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        NtpSettings,
        PhysicalInterface,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.services.networking import HostPhysicalInterface
    from atlaso.app.ui import (
        appliance_apply_units,
        load_appliance_apply_baselines,
        network_generated_dns_unit,
        save_appliance_apply_baselines,
        update_appliance_apply_baselines,
    )
    from tests.routers.ui.test_generated_dns_apply import (
        _prepare_service_address_baseline,
    )

    login(client)
    with SessionLocal() as db:
        management, access = _prepare_service_address_baseline(db, ui)
        access.ipv4_method = "dhcp"
        access.ip_cidr = None
        access.host_ip_cidr = "192.0.2.10/24"
        access.admin_state = "up"
        access.desired_state_source = "user"
        access.ipv6_cidr = None
        access.host_ipv6_cidr = "2001:db8::10/64"
        for model in (CaSettings, NtpSettings, VcfOfflineDepotSettings):
            settings = db.scalar(select(model))
            settings.listen_interface = access.name
            settings.listen_address = "192.0.2.10\n2001:db8::10"
        management_host = HostPhysicalInterface(
            name=management.name,
            mac_address=management.mac_address,
            driver="test",
            speed="1000 Mbps",
            host_ip_cidr=management.host_ip_cidr or management.ip_cidr,
            host_mtu=1500,
            host_admin_state="up",
            oper_state="up",
            host_ipv6_cidr=management.host_ipv6_cidr or management.ipv6_cidr,
        )
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = load_appliance_apply_baselines(db)
        applied_records = baselines["dnsmasq"]["service_dns_records"]
        assert any(row.get("source_interface") == "eth9" for row in applied_records)
        if legacy_ownership:
            baselines["dnsmasq"].pop("service_dns_records")
        save_appliance_apply_baselines(db, baselines)
        db.commit()

    monkeypatch.setattr(
        "atlaso.app.services.networking.discover_host_physical_interfaces",
        lambda **kwargs: [
            HostPhysicalInterface(
                name="ens192",
                mac_address="02:00:00:00:00:19",
                driver="test",
                speed="1000 Mbps",
                host_ip_cidr="192.0.2.11/24", host_dhcp_ip_cidr="192.0.2.11/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
                host_ipv6_cidr="2001:db8::11/64",
                host_dynamic_ipv6_cidr="2001:db8::11/64",
                host_dynamic_ipv6_cidrs=("2001:db8::11/64",),
            ),
            management_host,
        ],
    )

    with SessionLocal() as db:
        main.refresh_startup_host_inventory(db, environment="appliance")

    with SessionLocal() as db:
        renamed = db.scalar(select(PhysicalInterface).where(PhysicalInterface.mac_address == "02:00:00:00:00:19"))
        assert renamed is not None
        assert renamed.name == "ens192"
        assert renamed.host_ip_cidr == "192.0.2.11/24"
        assert renamed.host_ipv6_cidr == "2001:db8::11/64"
        baselines = load_appliance_apply_baselines(db)
        assert baselines["network"]["physical_interface_aliases"]["eth9"] == "ens192"
        assert any(
            row["address"] == "192.0.2.10" and row.get("source_interface") == "eth9"
            for row in baselines["dnsmasq"]["service_dns_records"]
        )

        units = {unit["id"]: unit for unit in appliance_apply_units(db)}
        projected = network_generated_dns_unit(db, units)
        assert projected is not None
        assert projected["validation_errors"] == []
        preview = projected["raw_config_preview"]
        owned_descriptions = {
            "Created from Certificate Authority portal endpoint.",
            "Created from NTP/NTS endpoint.",
            "Created from VCF Offline Depot endpoint.",
        }
        old_records = [row for row in applied_records if row["description"] in owned_descriptions]
        for row in old_records:
            if row["record_type"] not in {"A", "AAAA"}:
                continue
            directive = f"{'cname' if row['record_type'] == 'CNAME' else 'host-record'}={row['hostname']},{row['address']}"
            assert directive not in preview
        assert "host-record=operator-shared.example.internal,192.0.2.10" in preview
        assert "host-record=operator-shared.example.internal,2001:db8::10" in preview
        assert "192.0.2.11" in preview
        assert "2001:db8::11" in preview
        assert projected["generated_dns_only"] is True
        assert all(move["interface"] == "ens192" for move in projected["listener_address_moves"])


def test_applied_alias_chains_through_missing_startup_inventory(client, monkeypatch):
    """Keep the original applied name resolvable through a missing-to-live pass.

    Args:
        client: Seeded application client used to initialize the database.
        monkeypatch: Replace native host discovery across two startup sessions.
    """
    from atlaso.app import main
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.networking import HostPhysicalInterface
    from tests.routers.ui.test_generated_dns_apply import (
        _prepare_service_address_baseline,
    )

    login(client)
    with SessionLocal() as db:
        import atlaso.app.ui as ui

        _management, access = _prepare_service_address_baseline(db, ui)
        access.ipv4_method = "dhcp"
        access.ip_cidr = None
        access.host_ip_cidr = "192.0.2.10/24"
        access.admin_state = "up"
        access.inventory_source = "host"
        access.desired_state_source = "user"
        db.flush()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()

    monkeypatch.setattr("atlaso.app.services.networking.discover_host_physical_interfaces", lambda **kwargs: [])
    with SessionLocal() as db:
        main.refresh_startup_host_inventory(db, environment="appliance")
    with SessionLocal() as db:
        missing = db.scalar(select(PhysicalInterface).where(PhysicalInterface.mac_address == "02:00:00:00:00:19"))
        assert missing is not None and missing.name.startswith("missing_")

    monkeypatch.setattr(
        "atlaso.app.services.networking.discover_host_physical_interfaces",
        lambda **kwargs: [HostPhysicalInterface(
            name="ens192", mac_address="02:00:00:00:00:19", driver="test", speed="1000 Mbps",
            host_ip_cidr="192.0.2.11/24", host_dhcp_ip_cidr="192.0.2.11/24", host_mtu=1500, host_admin_state="up", oper_state="up",
        )],
    )
    with SessionLocal() as db:
        main.refresh_startup_host_inventory(db, environment="appliance")
    with SessionLocal() as db:
        aliases = ui.load_appliance_apply_baselines(db)["network"]["physical_interface_aliases"]
        assert aliases["eth9"] == "ens192"
        assert set(aliases.values()) == {"ens192"}
