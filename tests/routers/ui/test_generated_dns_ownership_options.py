"""Regression coverage for generated DNS ownership and bind eligibility."""

import ipaddress

import pytest

from tests.routers.ui.helpers import login
from tests.routers.ui.test_generated_dns_apply import _prepare_service_address_baseline


@pytest.mark.parametrize("ptr_enabled", [False, True])
def test_network_projection_moves_only_unprotected_authoritative_ptr(client, ptr_enabled):
    """Disabled PTR rows do not block generated moves; enabled rows remain owned by operators.

    Args:
        client: Isolated authenticated application client.
        ptr_enabled: Whether the explicit PTR row is published.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord
    from atlaso.app.services.service_dns_defaults import CA_PORTAL_DNS_DESCRIPTION

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        old_address = "192.0.2.10"
        new_address = "192.0.2.11"
        old_owner = ipaddress.ip_address(old_address).reverse_pointer
        new_owner = ipaddress.ip_address(new_address).reverse_pointer
        db.add(DnsRecord(
            hostname=old_owner,
            record_type="PTR",
            address="operator.example.internal",
            description="Operator reverse mapping",
            enabled=ptr_enabled,
        ))
        db.flush()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = ui.load_appliance_apply_baselines(db)
        prior_dns = baselines["dnsmasq"]["config_preview"]
        baselines["dnsmasq"]["config_preview"] = (
            prior_dns + f"\nlisten-address={old_address}\n"
            f"ptr-record={old_owner},ns1.atlaso.internal\n"
        )
        ui.save_appliance_apply_baselines(db, baselines)
        ca_record = next(
            row for row in ui.load_appliance_apply_baselines(db)["dnsmasq"]["service_dns_records"]
            if row["description"] == CA_PORTAL_DNS_DESCRIPTION
            and row["record_type"] == "A" and row["address"] == old_address
        )
        assert ca_record["generated_ptr"] == ("false" if ptr_enabled else "true")
        assert f"ptr-record={old_owner},ns1.atlaso.internal" in ui.load_appliance_apply_baselines(db)["dnsmasq"]["config_preview"]
        desired_dns = next(unit for unit in ui.appliance_apply_units(db) if unit["id"] == "dnsmasq")
        desired_ca = next(
            row for row in ui.owned_service_dns_records(db, desired_dns["raw_config_preview"])
            if row["description"] == CA_PORTAL_DNS_DESCRIPTION
            and row["record_type"] == "A" and row["address"] == old_address
        )
        assert desired_ca["generated_ptr"] == ("false" if ptr_enabled else "true")
        access.ip_cidr = f"{new_address}/24"
        access.ipv6_cidr = "2001:db8::11/64"
        ui.refresh_interface_service_dns_aliases(db)
        db.flush()

        current_units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        projected = ui.network_generated_dns_unit(db, current_units)
        assert projected is not None
        config = projected["raw_config_preview"]
        old_generated = f"ptr-record={old_owner},ns1.atlaso.internal"
        new_generated = f"ptr-record={new_owner},ns1.atlaso.internal"
        operator_ptr = f"ptr-record={old_owner},operator.example.internal"

        if ptr_enabled:
            assert operator_ptr in config
            assert old_generated in config
            assert new_generated not in config
        else:
            assert operator_ptr not in config
            assert old_generated not in config
            assert new_generated in config


def test_service_bind_options_exclude_down_dynamic_physical_interfaces(client):
    """Observed DHCP/SLAAC addresses become bind choices only while the link is up.

    Args:
        client: Seeded application client used to initialize the test database.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        interface = PhysicalInterface(
            name="eth-dynamic-test",
            mac_address="02:00:00:00:00:76",
            role="access",
            mode="access",
            admin_state="down",
            oper_state="up",
            ipv4_method="dhcp",
            host_ip_cidr="192.0.2.76/24",
            ipv6_enabled=True,
            host_ipv6_cidr="2001:db8::76/64",
        )
        db.add(interface)
        db.flush()

        down_options = {row["name"]: row for row in ui.service_bind_options(db)}
        assert "eth-dynamic-test" not in down_options

        interface.admin_state = "up"
        db.flush()
        up_options = {row["name"]: row for row in ui.service_bind_options(db)}
        assert up_options["eth-dynamic-test"]["addresses"] == ["192.0.2.76", "2001:db8::76"]
