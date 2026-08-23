"""Test physical-interface and VLAN API v1 transport behavior."""

import pytest

from tests.routers.api_v1.helpers import create_token


def test_physical_interface_api_persists_optional_ipv6_enabled_state(client):
    """Verify that physical interface api persists optional ipv6 enabled state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:interfaces", "write:interfaces"])
    headers = {"Authorization": f"Bearer {token}"}
    interfaces = client.get("/api/v1/interfaces/physical", headers=headers)
    assert interfaces.status_code == 200, interfaces.text
    management = next(row for row in interfaces.json() if row["role"] == "management")

    enabled = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv6_enabled": True, "ipv6_cidr": ""},
    )
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["ipv6_enabled"] is True
    assert enabled.json()["ipv6_cidr"] == ""

    preserved = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"mtu": 1500},
    )
    assert preserved.status_code == 200, preserved.text
    assert preserved.json()["ipv6_enabled"] is True

    static_ipv6 = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv6_cidr": "2001:db8:49::10/64", "ipv6_gateway": "fe80::1"},
    )
    assert static_ipv6.status_code == 200, static_ipv6.text
    assert static_ipv6.json()["ipv6_cidr"] == "2001:db8:49::10/64"
    assert static_ipv6.json()["ipv6_gateway"] == "fe80::1"

    off_link_ipv6_gateway = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv6_gateway": "2001:db8:50::1"},
    )
    assert off_link_ipv6_gateway.status_code == 422

    automatic_ipv6 = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv6_cidr": ""},
    )
    assert automatic_ipv6.status_code == 200, automatic_ipv6.text
    assert automatic_ipv6.json()["ipv6_gateway"] is None

    contradictory = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv6_enabled": False, "ipv6_cidr": "fd00:10::1/64"},
    )
    assert contradictory.status_code == 422

    disabled = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv6_enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["ipv6_cidr"] is None
    assert disabled.json()["ipv6_gateway"] is None

    wrong_type = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv6_enabled": "false"},
    )
    assert wrong_type.status_code == 422

    gateway = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv4_method": "static", "ip_cidr": "192.168.49.1/24", "gateway": "192.168.49.254"},
    )
    assert gateway.status_code == 200, gateway.text
    assert gateway.json()["gateway"] == "192.168.49.254"

    off_link_gateway = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"gateway": "192.168.50.254"},
    )
    assert off_link_gateway.status_code == 422


def test_physical_interface_api_rejects_explicit_null_role(client):
    """Verify PATCH omission remains valid while an explicit null role is rejected.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:interfaces", "write:interfaces"])
    headers = {"Authorization": f"Bearer {token}"}
    interfaces = client.get("/api/v1/interfaces/physical", headers=headers)
    assert interfaces.status_code == 200, interfaces.text
    management = next(row for row in interfaces.json() if row["role"] == "management")

    rejected = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"role": None},
    )

    assert rejected.status_code == 422, rejected.text
    refreshed = client.get("/api/v1/interfaces/physical", headers=headers)
    assert refreshed.status_code == 200, refreshed.text
    unchanged = next(row for row in refreshed.json() if row["name"] == management["name"])
    assert unchanged["role"] == "management"


def test_physical_interface_api_enforces_access_only_management_ui_flag(client):
    """Verify the API preserves management access during role conversion and rejects invalid flag use.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    token, _metadata = create_token(client, scopes=["read:interfaces", "write:interfaces"])
    headers = {"Authorization": f"Bearer {token}"}
    interfaces = client.get("/api/v1/interfaces/physical", headers=headers).json()
    management = next(row for row in interfaces if row["role"] == "management")
    rejected_multicast = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"role": "access", "ipv4_method": "static", "ip_cidr": "224.0.0.1/24"},
    )
    assert rejected_multicast.status_code == 422, rejected_multicast.text
    assert "At least one complete management listener must remain" in rejected_multicast.text
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == management["name"])
        ).scalar_one()
        interface.ipv6_enabled = True
        interface.ipv6_cidr = "fd00:469::1/64"
        db.commit()
    rejected_static = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"ipv4_method": "static", "ip_cidr": ""},
    )
    assert rejected_static.status_code == 422, rejected_static.text
    assert "At least one complete management listener must remain" in rejected_static.text
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == management["name"])
        ).scalar_one()
        interface.ipv4_method = "static"
        interface.ip_cidr = None
        interface.host_ip_cidr = "192.168.49.1/24"
        db.add(interface)
        db.commit()

    converted = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"role": "access", "ipv4_method": "static", "ip_cidr": ""},
    )
    assert converted.status_code == 200, converted.text
    assert converted.json()["access_management_ui_enabled"] is True
    assert converted.json()["ip_cidr"] == "192.168.49.1/24"

    final_listener = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"access_management_ui_enabled": False},
    )
    assert final_listener.status_code == 422, final_listener.text
    assert "At least one complete management listener must remain" in final_listener.text

    invalid = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"role": "unused", "access_management_ui_enabled": True},
    )
    assert invalid.status_code == 422

    reverted = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"role": "management", "access_management_ui_enabled": True},
    )
    assert reverted.status_code == 200, reverted.text
    assert reverted.json()["access_management_ui_enabled"] is False


@pytest.mark.parametrize("retired_role", ["services", "storage"])
def test_interface_apis_reject_retired_network_roles(client, retired_role):
    """Verify new physical-interface and VLAN requests accept only canonical roles.

    Args:
        client: Authenticated-capable application test client fixture.
        retired_role: Retired role that new API requests must reject.
    """
    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces", "write:vlans"],
    )
    headers = {"Authorization": f"Bearer {token}"}
    interfaces = client.get("/api/v1/interfaces/physical", headers=headers).json()
    physical = next(row for row in interfaces if row["role"] == "access" and row["mode"] == "access")

    physical_response = client.patch(
        f"/api/v1/interfaces/physical/{physical['name']}",
        headers=headers,
        json={"role": retired_role},
    )
    vlan_response = client.post(
        "/api/v1/vlans",
        headers=headers,
        json={
            "parent_interface": "eth1",
            "vlan_id": 333,
            "ip_cidr": "192.0.2.1/24",
            "role": retired_role,
        },
    )

    assert physical_response.status_code == 422
    assert vlan_response.status_code == 422


def test_vlan_api_preserves_case_insensitive_canonical_roles(client):
    """Verify VLAN create and update normalize recognized role capitalization.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        parent = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        parent.mode = "trunk"
        db.commit()

    token, _metadata = create_token(client, scopes=["write:vlans"])
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/api/v1/vlans",
        headers=headers,
        json={
            "parent_interface": "eth2",
            "vlan_id": 334,
            "ip_cidr": "192.0.2.1/24",
            "role": "Access",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["role"] == "access"

    updated = client.patch(
        f"/api/v1/vlans/{created.json()['id']}",
        headers=headers,
        json={
            "parent_interface": "eth2",
            "vlan_id": 334,
            "ip_cidr": "192.0.2.1/24",
            "role": "ROUTE",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["role"] == "route"


def test_vlan_api_rejects_removing_final_management_listener(client):
    """Keep the final flagged management VLAN intact across API mutations.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    with SessionLocal() as db:
        for interface in db.execute(select(PhysicalInterface)).scalars().all():
            interface.role = "unused"
            interface.access_management_ui_enabled = False
        parent = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth1")
        ).scalar_one()
        parent.mode = "trunk"
        parent.admin_state = "up"
        parent.oper_state = "up"
        vlan = VlanInterface(
            name="eth1.469",
            parent_interface="eth1",
            vlan_id=469,
            ip_cidr="192.168.69.1/24",
            role="access",
            enabled=True,
            access_management_ui_enabled=True,
        )
        db.add(vlan)
        db.commit()
        vlan_id = vlan.id

    token, _metadata = create_token(client, scopes=["write:vlans"])
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "parent_interface": "eth1",
        "vlan_id": 469,
        "ip_cidr": "192.168.69.1/24",
        "role": "access",
        "enabled": True,
        "access_management_ui_enabled": False,
    }
    updated = client.patch(f"/api/v1/vlans/{vlan_id}", headers=headers, json=payload)
    disabled = client.post(f"/api/v1/vlans/{vlan_id}/disable", headers=headers)
    deleted = client.delete(f"/api/v1/vlans/{vlan_id}", headers=headers)

    for response in (updated, disabled, deleted):
        assert response.status_code == 422, response.text
        assert "At least one complete management listener must remain" in response.text
    with SessionLocal() as db:
        preserved = db.get(VlanInterface, vlan_id)
        assert preserved is not None
        assert preserved.enabled is True
        assert preserved.access_management_ui_enabled is True


def test_physical_interface_api_atomically_refreshes_ipv4_and_ipv6_dependencies(client):
    """Verify the typed API update keeps service, DHCP, and Network Boot addresses aligned.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        DhcpReservation,
        DhcpScope,
        DnsRecord,
        DnsSettings,
        EsxiPxeHost,
        NtpSettings,
        OidcProviderSettings,
        PhysicalInterface,
    )
    from atlaso.app.services.esxi_pxe import (
        esxi_pxe_boot_settings,
        save_esxi_pxe_boot_settings,
    )
    from atlaso.app.services.oidc import OIDC_DNS_RECORD_DESCRIPTION

    old_ipv4 = "192.168.50.1"
    old_ipv6 = "fd00:50::1"
    new_ipv4 = "192.168.60.1"
    new_ipv6 = "fd00:60::1"
    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        primary_pxe_interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth1")
        ).scalar_one()
        primary_pxe_interface.role = "access"
        primary_pxe_interface.mode = "access"
        primary_pxe_interface.admin_state = "up"
        primary_pxe_interface.oper_state = "up"
        primary_pxe_interface.ip_cidr = "10.10.0.1/24"
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ip_cidr = f"{old_ipv4}/24"
        interface.ipv6_enabled = True
        interface.ipv6_cidr = f"{old_ipv6}/64"
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.enabled = True
        dns.listen_interface = interface.name
        dns.listen_address = f"{old_ipv4}\n{old_ipv6}"
        ntp = db.execute(select(NtpSettings)).scalar_one()
        ntp.enabled = True
        ntp.listen_interface = interface.name
        ntp.listen_address = f"{old_ipv4}\n{old_ipv6}"
        oidc = db.execute(select(OidcProviderSettings)).scalar_one_or_none()
        if oidc is None:
            oidc = OidcProviderSettings()
            db.add(oidc)
        oidc.enabled = True
        oidc.listen_interface = interface.name
        oidc.listen_address = f"{old_ipv4}\n{old_ipv6}"
        db.add_all(
            [
                DhcpScope(
                    name="api-ipv4-dependency",
                    address_family="ipv4",
                    interface_name=interface.name,
                    site_address="192.168.50.254",
                    prefix_length=24,
                    range_expression="192.168.50.100-192.168.50.120",
                    dns_server="192.168.50.53",
                    ntp_server="192.168.50.54",
                ),
                DhcpScope(
                    name="api-ipv6-dependency",
                    address_family="ipv6",
                    interface_name=interface.name,
                    site_address=old_ipv6,
                    prefix_length=64,
                    range_expression="fd00:50::100-fd00:50::120",
                    dns_server=old_ipv6,
                    ntp_server=old_ipv6,
                ),
            ]
        )
        reservation = DhcpReservation(
            hostname="reserved.atlaso.internal",
            mac_address="02:00:00:00:31:50",
            ip_address="192.168.50.10",
            description="Operator reservation note.",
            enabled=True,
        )
        db.add(reservation)
        db.flush()
        db.add(
            DnsRecord(
                hostname=reservation.hostname,
                record_type="A",
                address=reservation.ip_address,
                description=f"Created from DHCP reservation for {reservation.mac_address}.",
                enabled=True,
            )
        )
        db.add(
            DnsRecord(
                hostname="operator-owned.atlaso.internal",
                record_type="A",
                address=reservation.ip_address,
                description=reservation.description,
                enabled=True,
            )
        )
        managed_host = EsxiPxeHost(
            hostname="managed-esxi.atlaso.internal",
            mac_address="02:00:00:00:31:51",
            ip_address="192.168.50.11",
            enabled=True,
        )
        db.add(managed_host)
        db.flush()
        managed_description = f"Managed by ESXi PXE host {managed_host.id}."
        db.add_all(
            [
                DhcpReservation(
                    hostname=managed_host.hostname,
                    mac_address=managed_host.mac_address,
                    ip_address=managed_host.ip_address,
                    description=managed_description,
                    enabled=True,
                ),
                DnsRecord(
                    hostname=managed_host.hostname,
                    record_type="A",
                    address=managed_host.ip_address,
                    description=managed_description,
                    enabled=True,
                ),
            ]
        )
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname="pxe.atlaso.internal",
            listen_interface=f"{primary_pxe_interface.name}\n{interface.name}",
            listen_address="10.10.0.1\n192.168.50.254",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url="http://192.168.50.254:8080/pxe/boot.ipxe",
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "ip_cidr": f"{new_ipv4}/24",
            "ipv6_enabled": True,
            "ipv6_cidr": f"{new_ipv6}/64",
        },
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        dns = db.execute(select(DnsSettings)).scalar_one()
        ntp = db.execute(select(NtpSettings)).scalar_one()
        oidc = db.execute(select(OidcProviderSettings)).scalar_one()
        oidc_dns_addresses = set(
            db.execute(
                select(DnsRecord.address).where(
                    DnsRecord.description == OIDC_DNS_RECORD_DESCRIPTION,
                    DnsRecord.record_type.in_(["A", "AAAA"]),
                )
            ).scalars()
        )
        scopes = {
            scope.name: scope
            for scope in db.execute(
                select(DhcpScope).where(
                    DhcpScope.name.in_(["api-ipv4-dependency", "api-ipv6-dependency"])
                )
            ).scalars()
        }
        reservation = db.execute(
            select(DhcpReservation).where(
                DhcpReservation.mac_address == "02:00:00:00:31:50"
            )
        ).scalar_one()
        reservation_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "reserved.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one()
        managed_host = db.execute(
            select(EsxiPxeHost).where(
                EsxiPxeHost.mac_address == "02:00:00:00:31:51"
            )
        ).scalar_one()
        managed_reservation = db.execute(
            select(DhcpReservation).where(
                DhcpReservation.mac_address == "02:00:00:00:31:51"
            )
        ).scalar_one()
        managed_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "managed-esxi.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one()
        operator_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "operator-owned.atlaso.internal"
            )
        ).scalar_one()
        boot = esxi_pxe_boot_settings(db)
        audit = db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "update_interface")
            .order_by(AuditEvent.id.desc())
        ).scalars().first()

        assert interface.ip_cidr == f"{new_ipv4}/24"
        assert interface.ipv6_cidr == f"{new_ipv6}/64"
        assert dns.listen_interface == "eth2"
        assert dns.listen_address == f"{new_ipv4}\n{new_ipv6}"
        assert ntp.listen_interface == "eth2"
        assert ntp.listen_address == f"{new_ipv4}\n{new_ipv6}"
        assert oidc.listen_interface == "eth2"
        assert oidc.listen_address == f"{new_ipv4}\n{new_ipv6}"
        assert oidc_dns_addresses == {new_ipv4, new_ipv6}
        assert scopes["api-ipv4-dependency"].site_address == new_ipv4
        assert scopes["api-ipv4-dependency"].range_expression == "192.168.60.100-192.168.60.120"
        assert scopes["api-ipv4-dependency"].dns_server == "192.168.60.53"
        assert scopes["api-ipv4-dependency"].ntp_server == "192.168.60.54"
        assert scopes["api-ipv6-dependency"].site_address == new_ipv6
        assert scopes["api-ipv6-dependency"].range_expression == "fd00:60::100-fd00:60::120"
        assert scopes["api-ipv6-dependency"].dns_server == new_ipv6
        assert scopes["api-ipv6-dependency"].ntp_server == new_ipv6
        assert reservation.ip_address == "192.168.60.10"
        assert reservation_record.address == "192.168.60.10"
        assert managed_host.ip_address == "192.168.60.11"
        assert managed_reservation.ip_address == "192.168.60.11"
        assert managed_record.address == "192.168.60.11"
        assert operator_record.address == "192.168.50.10"
        assert boot["listen_interface"] == "eth1\neth2"
        assert boot["listen_address"] == f"10.10.0.1\n{new_ipv4}\n{new_ipv6}"
        assert new_ipv4 in boot["native_uefi_http_url"]
        assert "192.168.50.254" not in boot["native_uefi_http_url"]
        assert audit is not None
        assert "DNS" in (audit.detail or "")
        assert "NTP / NTS" in (audit.detail or "")
        assert "OIDC" in (audit.detail or "")
        assert "DHCP" in (audit.detail or "")
        assert "ESXi PXE" in (audit.detail or "")


def test_physical_interface_api_rejects_ambiguous_reservation_scope_move(client):
    """Verify overlapping changed scopes cannot choose a reservation move implicitly.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpReservation, DhcpScope, PhysicalInterface

    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ip_cidr = "192.168.70.1/24"
        db.add_all(
            [
                DhcpScope(
                    name="overlap-a",
                    address_family="ipv4",
                    interface_name=interface.name,
                    site_address="192.168.70.1",
                    prefix_length=24,
                    range_expression="192.168.70.100-192.168.70.110",
                    dns_server="192.168.70.1",
                ),
                DhcpScope(
                    name="overlap-b",
                    address_family="ipv4",
                    interface_name=interface.name,
                    site_address="192.168.70.1",
                    prefix_length=24,
                    range_expression="192.168.70.120-192.168.70.130",
                    dns_server="192.168.70.1",
                ),
                DhcpReservation(
                    hostname="ambiguous.atlaso.internal",
                    mac_address="02:00:00:00:31:70",
                    ip_address="192.168.70.10",
                    enabled=True,
                ),
            ]
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_cidr": "192.168.80.1/24"},
    )

    assert response.status_code == 422
    assert "cannot be mapped unambiguously" in response.text
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        reservation = db.execute(
            select(DhcpReservation).where(
                DhcpReservation.mac_address == "02:00:00:00:31:70"
            )
        ).scalar_one()
        assert interface.ip_cidr == "192.168.70.1/24"
        assert reservation.ip_address == "192.168.70.10"


def test_physical_interface_api_rejects_inconsistent_esxi_reservation_owner(client):
    """Verify an editable marker cannot redirect a rebase into an unrelated ESXi host.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DhcpReservation,
        DhcpScope,
        EsxiPxeHost,
        PhysicalInterface,
    )

    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ip_cidr = "192.168.71.1/24"
        host = EsxiPxeHost(
            hostname="owned-esxi.atlaso.internal",
            mac_address="02:00:00:00:31:71",
            ip_address="192.168.71.10",
            enabled=True,
        )
        db.add(host)
        db.flush()
        db.add_all(
            [
                DhcpScope(
                    name="esxi-owner-scope",
                    interface_name=interface.name,
                    site_address="192.168.71.1",
                    prefix_length=24,
                    range_expression="192.168.71.100-192.168.71.120",
                    dns_server="192.168.71.1",
                ),
                DhcpReservation(
                    hostname="unrelated.atlaso.internal",
                    mac_address="02:00:00:00:31:72",
                    ip_address="192.168.71.11",
                    description=f"Managed by ESXi PXE host {host.id}.",
                    enabled=True,
                ),
            ]
        )
        db.commit()
        host_id = host.id

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_cidr": "192.168.81.1/24"},
    )

    assert response.status_code == 422
    assert "inconsistent ESXi PXE ownership marker" in response.text
    with SessionLocal() as db:
        assert db.get(EsxiPxeHost, host_id).ip_address == "192.168.71.10"
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        assert interface.ip_cidr == "192.168.71.1/24"


def test_physical_interface_api_rejects_reservation_dns_collision(client):
    """Verify a rebased generated DNS record cannot collide with an existing row.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DhcpReservation,
        DhcpScope,
        DnsRecord,
        PhysicalInterface,
    )

    mac_address = "02:00:00:00:31:73"
    hostname = "collision.atlaso.internal"
    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ip_cidr = "192.168.73.1/24"
        db.add_all(
            [
                DhcpScope(
                    name="dns-collision-scope",
                    interface_name=interface.name,
                    site_address="192.168.73.1",
                    prefix_length=24,
                    range_expression="192.168.73.100-192.168.73.120",
                    dns_server="192.168.73.1",
                ),
                DhcpReservation(
                    hostname=hostname,
                    mac_address=mac_address,
                    ip_address="192.168.73.10",
                    enabled=True,
                ),
                DnsRecord(
                    hostname=hostname,
                    record_type="A",
                    address="192.168.73.10",
                    description=f"Created from DHCP reservation for {mac_address}.",
                    enabled=True,
                ),
                DnsRecord(
                    hostname=hostname,
                    record_type="A",
                    address="192.168.83.10",
                    description="Operator-owned destination record.",
                    enabled=True,
                ),
            ]
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_cidr": "192.168.83.1/24"},
    )

    assert response.status_code == 422
    assert "destination address already exists" in response.text
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        reservation = db.execute(
            select(DhcpReservation).where(DhcpReservation.mac_address == mac_address)
        ).scalar_one()
        assert interface.ip_cidr == "192.168.73.1/24"
        assert reservation.ip_address == "192.168.73.10"


def test_physical_interface_api_rebuilds_pxe_url_for_ipv6_to_ipv4_fallback(client):
    """Verify removing IPv6 rebuilds the PXE URL without IPv4 literal brackets.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, PhysicalInterface
    from atlaso.app.services.esxi_pxe import (
        esxi_pxe_boot_settings,
        save_esxi_pxe_boot_settings,
    )

    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ip_cidr = "192.168.52.1/24"
        interface.ipv6_enabled = True
        interface.ipv6_cidr = "fd00:52::1/64"
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname="pxe.atlaso.internal",
            listen_interface=interface.name,
            listen_address="192.168.52.1\nfd00:52::1",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url="http://[fd00:52::1]:8080/pxe/boot.ipxe",
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"ipv6_enabled": False},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        boot = esxi_pxe_boot_settings(db)
        assert boot["listen_address"] == "192.168.52.1"
        assert boot["native_uefi_http_url"] == "http://192.168.52.1:8080/pxe/boot.ipxe"


def test_physical_interface_api_preserves_partial_transition_compatibility(client):
    """Verify controlling-field-only PATCH requests clear fields they make inapplicable.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        interface.role = "management"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.167.10/24"
        interface.gateway = "192.168.167.2"
        interface.ipv6_enabled = True
        interface.ipv6_cidr = "fd00:167::10/64"
        interface.ipv6_gateway = "fd00:167::2"
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    headers = {"Authorization": f"Bearer {token}"}
    disable_ipv6 = client.patch(
        "/api/v1/interfaces/physical/eth0",
        headers=headers,
        json={"ipv6_enabled": False},
    )
    assert disable_ipv6.status_code == 200, disable_ipv6.text
    assert disable_ipv6.json()["ipv6_enabled"] is False
    assert disable_ipv6.json()["ipv6_cidr"] is None
    assert disable_ipv6.json()["ipv6_gateway"] is None

    enable_dhcp = client.patch(
        "/api/v1/interfaces/physical/eth0",
        headers=headers,
        json={"ipv4_method": "dhcp"},
    )
    assert enable_dhcp.status_code == 200, enable_dhcp.text
    assert enable_dhcp.json()["ipv4_method"] == "dhcp"
    assert enable_dhcp.json()["ip_cidr"] is None
    assert enable_dhcp.json()["gateway"] is None


def test_physical_interface_api_normalizes_compatible_enum_spellings(client):
    """Verify compatible case and legacy mode spellings remain accepted by PATCH.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    headers = {"Authorization": f"Bearer {token}"}
    normalized = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers=headers,
        json={"role": "Access", "mode": "Routed", "ipv4_method": "Static"},
    )
    assert normalized.status_code == 200, normalized.text
    assert normalized.json()["role"] == "access"
    assert normalized.json()["mode"] == "access"
    assert normalized.json()["ipv4_method"] == "static"


def test_physical_interface_api_rejects_dhcp_range_that_cannot_fit(client):
    """Verify a prefix shrink rolls back when a dependent DHCP range cannot be rebased.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, PhysicalInterface

    scope_name = "api-prefix-shrink-dependency"
    with SessionLocal() as db:
        db.execute(select(DhcpSettings)).scalar_one().enabled = True
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        db.add(
            DhcpScope(
                name=scope_name,
                address_family="ipv4",
                interface_name=interface.name,
                site_address="192.168.50.1",
                prefix_length=24,
                range_expression="192.168.50.100-192.168.50.120",
                dns_server="192.168.50.1",
                ntp_server="192.168.50.1",
            )
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_cidr": "192.168.60.1/28"},
    )

    assert response.status_code == 422, response.text
    assert "cannot fit" in response.json()["detail"]
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == scope_name)).scalar_one()
        assert interface.ip_cidr == "192.168.50.1/24"
        assert scope.site_address == "192.168.50.1"
        assert scope.prefix_length == 24
        assert scope.range_expression == "192.168.50.100-192.168.50.120"


def test_physical_interface_api_rebases_ranges_within_retained_scope_prefix(client):
    """Verify a custom DHCP prefix remains internally valid after interface readdressing.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, PhysicalInterface

    scope_name = "api-retained-prefix-dependency"
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        db.add(
            DhcpScope(
                name=scope_name,
                address_family="ipv4",
                interface_name=interface.name,
                site_address="192.168.50.1",
                prefix_length=25,
                range_expression="192.168.50.100-192.168.50.120",
                dns_server="192.168.50.1",
                ntp_server="192.168.50.1",
                enabled=True,
            )
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_cidr": "192.168.60.1/16"},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == scope_name)).scalar_one()
        assert scope.site_address == "192.168.60.1"
        assert scope.prefix_length == 25
        assert scope.range_expression == "192.168.60.100-192.168.60.120"


def test_physical_interface_api_preserves_unchanged_dhcp_timestamp(client):
    """Verify an unrelated interface edit does not dirty a bound DHCP row.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from datetime import datetime, timezone

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DnsSettings, NtpSettings, PhysicalInterface

    scope_name = "api-unchanged-timestamp-dependency"
    original_updated_at = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        db.add(
            DhcpScope(
                name=scope_name,
                address_family="ipv4",
                interface_name=interface.name,
                site_address="192.168.50.254",
                prefix_length=24,
                range_expression="192.168.50.100-192.168.50.120",
                dns_server="192.168.50.53",
                ntp_server="192.168.50.123",
                enabled=True,
                updated_at=original_updated_at,
            )
        )
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.enabled = True
        dns.listen_interface = interface.name
        dns.listen_address = "192.168.50.1"
        ntp = db.execute(select(NtpSettings)).scalar_one()
        ntp.enabled = True
        ntp.listen_interface = interface.name
        ntp.listen_address = "192.168.50.1"
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"mtu": 1600},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == scope_name)).scalar_one()
        assert scope.site_address == "192.168.50.254"
        assert scope.dns_server == "192.168.50.53"
        assert scope.ntp_server == "192.168.50.123"
        assert scope.updated_at.replace(tzinfo=timezone.utc) == original_updated_at


def test_physical_interface_api_removes_ineligible_multi_selection_and_blocks_final_disable(client):
    """Verify service selections follow eligibility and reject loss of their final address.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        DhcpScope,
        DnsSettings,
        NtpSettings,
        OidcProviderSettings,
        PhysicalInterface,
        VcfBackupSettings,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

    with SessionLocal() as db:
        eth1 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth1")
        ).scalar_one()
        eth2 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        for interface, cidr in ((eth1, "192.168.40.1/24"), (eth2, "192.168.50.1/24")):
            interface.role = "access"
            interface.mode = "access"
            interface.ipv4_method = "static"
            interface.ip_cidr = cidr
            interface.admin_state = "up"
        for scope in db.execute(select(DhcpScope)).scalars().all():
            scope.enabled = False
        for model in (
            NtpSettings,
            OidcProviderSettings,
            VcfBackupSettings,
            VcfOfflineDepotSettings,
            VcfPrivateRegistrySettings,
        ):
            for settings in db.execute(select(model)).scalars().all():
                settings.enabled = False
        ca = db.execute(select(CaSettings)).scalar_one()
        ca.enabled = False
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.enabled = True
        dns.listen_interface = "eth1\neth2"
        dns.listen_address = "192.168.40.1\n192.168.50.1"
        save_esxi_pxe_boot_settings(
            db,
            enabled=False,
            hostname="pxe.atlaso.internal",
            listen_interface="eth2",
            listen_address="192.168.50.1",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    headers = {"Authorization": f"Bearer {token}"}
    trunk = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers=headers,
        json={"mode": "trunk"},
    )
    assert trunk.status_code == 200, trunk.text
    with SessionLocal() as db:
        dns = db.execute(select(DnsSettings)).scalar_one()
        assert dns.listen_interface == "eth1"
        assert dns.listen_address == "192.168.40.1"
        eth2 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        eth2.role = "access"
        eth2.mode = "access"
        eth2.ip_cidr = "192.168.50.1/24"
        eth2.admin_state = "up"
        dns.enabled = False
        oidc = db.execute(select(OidcProviderSettings)).scalar_one_or_none()
        if oidc is None:
            oidc = OidcProviderSettings()
            db.add(oidc)
        oidc.enabled = True
        oidc.listen_interface = "eth2"
        oidc.listen_address = "192.168.50.1"
        db.commit()

    disabled = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers=headers,
        json={"admin_state": "down"},
    )
    assert disabled.status_code == 422, disabled.text
    assert "Enabled OIDC" in disabled.json()["detail"]
    with SessionLocal() as db:
        eth2 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        oidc = db.execute(select(OidcProviderSettings)).scalar_one()
        assert eth2.admin_state == "up"
        assert oidc.listen_interface == "eth2"
        assert oidc.listen_address == "192.168.50.1"


def test_physical_interface_api_rejects_active_service_listener_removal(client):
    """Verify an enabled service blocks removal of its final interface listen address.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DnsSettings, PhysicalInterface
    from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        for scope in db.execute(
            select(DhcpScope).where(DhcpScope.interface_name == interface.name)
        ).scalars().all():
            scope.enabled = False
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.enabled = True
        dns.listen_interface = interface.name
        dns.listen_address = "192.168.50.1"
        save_esxi_pxe_boot_settings(
            db,
            enabled=False,
            hostname="pxe.atlaso.internal",
            listen_interface=interface.name,
            listen_address="192.168.50.1",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "trunk"},
    )

    assert response.status_code == 422, response.text
    assert "Enabled DNS" in response.json()["detail"]
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        dns = db.execute(select(DnsSettings)).scalar_one()
        assert interface.mode == "access"
        assert interface.ip_cidr == "192.168.50.1/24"
        assert dns.listen_interface == "eth2"
        assert dns.listen_address == "192.168.50.1"


def test_physical_interface_api_clears_ca_portal_without_disabling_custody(client):
    """Verify loss of the CA portal interface retains internal CA enablement.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        DhcpScope,
        DnsSettings,
        NtpSettings,
        OidcProviderSettings,
        PhysicalInterface,
        VcfBackupSettings,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        for scope in db.execute(
            select(DhcpScope).where(DhcpScope.interface_name == interface.name)
        ).scalars().all():
            scope.enabled = False
        for model in (
            DnsSettings,
            NtpSettings,
            OidcProviderSettings,
            VcfBackupSettings,
            VcfOfflineDepotSettings,
            VcfPrivateRegistrySettings,
        ):
            for settings in db.execute(select(model)).scalars().all():
                settings.enabled = False
        ca = db.execute(select(CaSettings)).scalar_one()
        ca.enabled = True
        ca.listen_interface = interface.name
        ca.listen_address = "192.168.50.1"
        save_esxi_pxe_boot_settings(
            db,
            enabled=False,
            hostname="pxe.atlaso.internal",
            listen_interface=interface.name,
            listen_address="192.168.50.1",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "trunk"},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        ca = db.execute(select(CaSettings)).scalar_one()
        assert ca.enabled is True
        assert ca.listen_interface == ""
        assert ca.listen_address == ""


def test_physical_interface_api_rejects_address_removal_with_enabled_dependents(client):
    """Verify enabled DHCP and PXE bindings block removal of their interface addresses.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, PhysicalInterface
    from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

    scope_name = "api-address-removal-dependency"
    with SessionLocal() as db:
        db.execute(select(DhcpSettings)).scalar_one().enabled = True
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        interface.ipv6_enabled = True
        interface.ipv6_cidr = "fd00:50::1/64"
        db.add(
            DhcpScope(
                name=scope_name,
                address_family="ipv6",
                interface_name=interface.name,
                site_address="fd00:50::1",
                prefix_length=64,
                range_expression="fd00:50::100-fd00:50::120",
                dns_server="fd00:50::1",
                ntp_server="fd00:50::1",
                enabled=True,
            )
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    headers = {"Authorization": f"Bearer {token}"}
    dhcp_rejected = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers=headers,
        json={"ipv6_enabled": False},
    )
    assert dhcp_rejected.status_code == 422, dhcp_rejected.text
    assert "DHCP scope" in dhcp_rejected.json()["detail"]
    assert "Disable or move" in dhcp_rejected.json()["detail"]

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        db.execute(select(DhcpScope).where(DhcpScope.name == scope_name)).scalar_one()
        assert interface.ipv6_enabled is True
        assert interface.ipv6_cidr == "fd00:50::1/64"
        for bound_scope in db.execute(
            select(DhcpScope).where(DhcpScope.interface_name == interface.name)
        ).scalars().all():
            bound_scope.enabled = False
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname="pxe.atlaso.internal",
            listen_interface=interface.name,
            listen_address="192.168.50.1",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
        )
        db.commit()

    pxe_rejected = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers=headers,
        json={"mode": "trunk"},
    )
    assert pxe_rejected.status_code == 422, pxe_rejected.text
    assert "ESXi PXE" in pxe_rejected.json()["detail"]
    assert "Disable or move" in pxe_rejected.json()["detail"]

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        assert interface.mode == "access"
        assert interface.ip_cidr == "192.168.50.1/24"
        assert interface.ipv6_cidr == "fd00:50::1/64"


def test_physical_interface_api_rejects_required_esx_storage_family_removal(client):
    """Verify an enabled datastore blocks removal of its selected address family.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DhcpScope,
        EsxNfsShare,
        EsxStorageVolume,
        PhysicalInterface,
    )

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        interface.ipv6_enabled = True
        interface.ipv6_cidr = "fd00:50::1/64"
        interface.admin_state = "up"
        for scope in db.execute(select(DhcpScope)).scalars().all():
            scope.enabled = False
        for share in db.execute(select(EsxNfsShare)).scalars().all():
            share.enabled = False
        volume = EsxStorageVolume(
            name="api-esx-family-volume",
            source_type="mounted_ext4",
            stable_device_id="api-esx-family-volume",
            mount_path="/mnt/api-esx-family-volume",
            state="ready",
        )
        db.add(volume)
        db.flush()
        db.add(
            EsxNfsShare(
                datastore_name="api-ipv6-datastore",
                volume_id=volume.id,
                relative_path="datastore",
                interface_name=interface.name,
                address_families="ipv6",
                ipv6_clients="fd00:50::/64",
                enabled=True,
            )
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"ipv6_enabled": False},
    )

    assert response.status_code == 422, response.text
    assert "ESX Storage datastore api-ipv6-datastore" in response.json()["detail"]
    assert "IPV6" in response.json()["detail"]
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        share = db.execute(
            select(EsxNfsShare).where(
                EsxNfsShare.datastore_name == "api-ipv6-datastore"
            )
        ).scalar_one()
        assert interface.ipv6_enabled is True
        assert interface.ipv6_cidr == "fd00:50::1/64"
        assert share.interface_name == "eth2"


def test_physical_interface_api_ignores_scope_dependency_when_dhcp_disabled(client):
    """Verify globally disabled DHCP leaves enabled scope rows dormant.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ip_cidr = "192.168.58.1/24"
        interface.admin_state = "up"
        settings = db.execute(select(DhcpSettings)).scalar_one()
        settings.enabled = False
        db.add(
            DhcpScope(
                name="dormant-enabled-scope",
                interface_name=interface.name,
                site_address="192.168.58.1",
                prefix_length=24,
                range_expression="192.168.58.100-192.168.58.120",
                dns_server="192.168.58.1",
                enabled=True,
            )
        )
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"admin_state": "down"},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        scope = db.execute(
            select(DhcpScope).where(DhcpScope.name == "dormant-enabled-scope")
        ).scalar_one()
        assert interface.admin_state == "down"
        assert scope.enabled is True
        assert scope.interface_name == "eth2"


def test_physical_interface_api_ignores_inactive_legacy_dhcp_binding(client):
    """Verify real DHCP scopes make compatibility binding fields inactive.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, PhysicalInterface

    with SessionLocal() as db:
        eth1 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth1")
        ).scalar_one()
        eth2 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        for interface, cidr in ((eth1, "192.168.40.1/24"), (eth2, "192.168.50.1/24")):
            interface.role = "access"
            interface.mode = "access"
            interface.ipv4_method = "static"
            interface.ip_cidr = cidr
            interface.admin_state = "up"
        for scope in db.execute(select(DhcpScope)).scalars().all():
            scope.enabled = False
        db.add(
            DhcpScope(
                name="api-real-dhcp-scope",
                address_family="ipv4",
                interface_name="eth1",
                site_address="192.168.40.1",
                prefix_length=24,
                range_expression="192.168.40.100-192.168.40.120",
                dns_server="192.168.40.1",
                enabled=True,
            )
        )
        legacy = db.execute(select(DhcpSettings)).scalar_one()
        legacy.enabled = True
        legacy.interface_name = "eth2"
        legacy.site_address = "192.168.50.1"
        legacy.prefix_length = 24
        legacy.range_expression = "192.168.50.100-192.168.50.120"
        legacy.dns_server = "192.168.50.1"
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"admin_state": "down"},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        eth2 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        legacy = db.execute(select(DhcpSettings)).scalar_one()
        real_scope = db.execute(
            select(DhcpScope).where(DhcpScope.name == "api-real-dhcp-scope")
        ).scalar_one()
        assert eth2.admin_state == "down"
        assert legacy.interface_name == "eth2"
        assert legacy.site_address == "192.168.50.1"
        assert real_scope.interface_name == "eth1"
        assert real_scope.site_address == "192.168.40.1"


def test_physical_interface_api_prunes_unavailable_web_terminal_selection(client):
    """Verify Web Terminal drops an additional interface that becomes unavailable.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        AuditEvent,
        DhcpScope,
        EsxNfsShare,
        PhysicalInterface,
    )
    from atlaso.app.services.appliance_settings import web_terminal_interfaces_from_json

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        interface.admin_state = "up"
        for scope in db.execute(select(DhcpScope)).scalars().all():
            scope.enabled = False
        for share in db.execute(select(EsxNfsShare)).scalars().all():
            share.enabled = False
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = '["eth0", "eth2"]'
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"admin_state": "down"},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        audit = db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "update_interface")
            .order_by(AuditEvent.id.desc())
        ).scalars().first()
        assert interface.admin_state == "down"
        assert web_terminal_interfaces_from_json(
            settings.web_terminal_interfaces_json
        ) == ["eth0"]
        assert audit is not None
        assert "Appliance Settings" in (audit.detail or "")


def test_physical_interface_api_rejects_child_vlan_listener_on_parent_disable(client):
    """Verify a child VLAN service binding blocks disabling its physical parent.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DhcpScope,
        EsxNfsShare,
        OidcProviderSettings,
        PhysicalInterface,
        VlanInterface,
    )

    vlan_name = "eth2.377"
    with SessionLocal() as db:
        parent = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        parent.role = "unused"
        parent.mode = "trunk"
        parent.ipv4_method = "static"
        parent.ip_cidr = None
        parent.ipv6_enabled = False
        parent.ipv6_cidr = None
        parent.admin_state = "up"
        for scope in db.execute(select(DhcpScope)).scalars().all():
            scope.enabled = False
        for share in db.execute(select(EsxNfsShare)).scalars().all():
            share.enabled = False
        db.add(
            VlanInterface(
                name=vlan_name,
                parent_interface=parent.name,
                vlan_id=377,
                ip_cidr="192.168.77.1/24",
                role="access",
                enabled=True,
            )
        )
        oidc = db.execute(select(OidcProviderSettings)).scalar_one_or_none()
        if oidc is None:
            oidc = OidcProviderSettings()
            db.add(oidc)
        oidc.enabled = True
        oidc.listen_interface = vlan_name
        oidc.listen_address = "192.168.77.1"
        db.commit()

    token, _metadata = create_token(
        client,
        scopes=["read:interfaces", "write:interfaces"],
    )
    response = client.patch(
        "/api/v1/interfaces/physical/eth2",
        headers={"Authorization": f"Bearer {token}"},
        json={"admin_state": "down"},
    )

    assert response.status_code == 422, response.text
    assert "Enabled OIDC" in response.json()["detail"]
    with SessionLocal() as db:
        parent = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        oidc = db.execute(select(OidcProviderSettings)).scalar_one()
        assert parent.admin_state == "up"
        assert oidc.listen_interface == vlan_name
        assert oidc.listen_address == "192.168.77.1"
