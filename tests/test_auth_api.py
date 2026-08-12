"""Test auth api behavior."""

from datetime import datetime, timedelta, timezone


def create_token(client, scopes=None):
    """Create token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Normalized authorization scopes granted or required by the operation.


    Returns:
        The created token.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "test token", "scopes": scopes or ["read:dashboard", "read:wan", "write:wan", "read:audit"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["raw_token"]
    return body["raw_token"], body["token"]


def test_unauthenticated_api_requests_are_rejected(client):
    """Verify that unauthenticated api requests are rejected.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 401
    assert response.json()["error_code"] == "HTTP_ERROR"


def test_appliance_version_api_is_unauthenticated(client, monkeypatch):
    """Verify that appliance version api is unauthenticated.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.api.v1 as api_v1

    monkeypatch.setattr(api_v1, "__version__", "0.9.87+g0123456789ab")
    monkeypatch.setattr(api_v1, "__build_git_commit__", "0123456789abcdef0123456789abcdef01234567")
    monkeypatch.setattr(api_v1, "__build_time_utc__", "2026-08-09T20:15:00Z")

    response = client.get("/api/v1/version")

    assert response.status_code == 200
    assert response.json() == {
        "version": "0.9.87+g0123456789ab",
        "base_version": "0.9.87",
        "git_commit": "0123456789abcdef0123456789abcdef01234567",
        "built_at": "2026-08-09T20:15:00Z",
    }


def test_invalid_jwt_is_rejected(client):
    """Verify that invalid jwt is rejected.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    response = client.get("/api/v1/dashboard", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401


def test_api_login_creates_token_and_me_works(client):
    """Verify that api login creates token and me works.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, metadata = create_token(client)
    assert metadata["name"] == "test token"
    assert "raw_token" not in metadata

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
    assert response.json()["auth_type"] == "bearer"


def test_api_token_is_shown_only_once_in_list(client):
    """Verify that api token is shown only once in list.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client)
    response = client.get("/api/v1/api-tokens", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()
    assert "raw_token" not in response.text


def test_settings_api_updates_root_ssh_desired_state(client):
    """Verify that settings api updates root ssh desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])

    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "appliance_fqdn": "api.atlaso.internal",
            "management_https_enabled": False,
            "root_ssh_enabled": True,
            "external_dns_servers": ["1.1.1.1", "9.9.9.9"],
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["appliance_fqdn"] == "api.atlaso.internal"
    assert payload["root_ssh_enabled"] is True
    assert '"root_ssh_enabled": true' in payload["config_preview"]


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


def test_physical_interface_api_enforces_access_only_management_ui_flag(client):
    """Verify the API preserves management access during role conversion and rejects invalid flag use.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    token, _metadata = create_token(client, scopes=["read:interfaces", "write:interfaces"])
    headers = {"Authorization": f"Bearer {token}"}
    interfaces = client.get("/api/v1/interfaces/physical", headers=headers).json()
    management = next(row for row in interfaces if row["role"] == "management")

    converted = client.patch(
        f"/api/v1/interfaces/physical/{management['name']}",
        headers=headers,
        json={"role": "access", "ipv4_method": "static", "ip_cidr": "192.168.49.1/24"},
    )
    assert converted.status_code == 200, converted.text
    assert converted.json()["access_management_ui_enabled"] is True

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


def test_physical_interface_api_atomically_refreshes_ipv4_and_ipv6_dependencies(client):
    """Verify the typed API update keeps service, DHCP, and Network Boot addresses aligned.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        DhcpScope,
        DnsRecord,
        DnsSettings,
        NtpSettings,
        OidcProviderSettings,
        PhysicalInterface,
    )
    from atlaso.app.services.esxi_pxe import esxi_pxe_boot_settings, save_esxi_pxe_boot_settings
    from atlaso.app.services.oidc import OIDC_DNS_RECORD_DESCRIPTION

    old_ipv4 = "192.168.50.1"
    old_ipv6 = "fd00:50::1"
    new_ipv4 = "192.168.60.1"
    new_ipv6 = "fd00:60::1"
    with SessionLocal() as db:
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
                    site_address=old_ipv4,
                    prefix_length=24,
                    range_expression="192.168.50.100-192.168.50.120",
                    dns_server=old_ipv4,
                    ntp_server=old_ipv4,
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
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname="pxe.atlaso.internal",
            listen_interface=interface.name,
            listen_address=f"{old_ipv4}\n{old_ipv6}",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url=f"http://{old_ipv4}:8080/pxe/boot.ipxe",
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
        assert scopes["api-ipv4-dependency"].dns_server == new_ipv4
        assert scopes["api-ipv4-dependency"].ntp_server == new_ipv4
        assert scopes["api-ipv6-dependency"].site_address == new_ipv6
        assert scopes["api-ipv6-dependency"].range_expression == "fd00:60::100-fd00:60::120"
        assert scopes["api-ipv6-dependency"].dns_server == new_ipv6
        assert scopes["api-ipv6-dependency"].ntp_server == new_ipv6
        assert boot["listen_interface"] == "eth2"
        # Network Boot remains IPv4-only; the IPv6 DHCP dependency is reconciled separately.
        assert boot["listen_address"] == new_ipv4
        assert new_ipv4 in boot["native_uefi_http_url"]
        assert old_ipv4 not in boot["native_uefi_http_url"]
        assert audit is not None
        assert "DNS" in (audit.detail or "")
        assert "NTP / NTS" in (audit.detail or "")
        assert "OIDC" in (audit.detail or "")
        assert "DHCP" in (audit.detail or "")
        assert "ESXi PXE" in (audit.detail or "")


def test_physical_interface_update_rolls_back_interface_and_dependents(client, monkeypatch):
    """Verify a dependent refresh failure leaves every desired-state row unchanged.

    Args:
        client: Authenticated-capable application test client fixture.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, PhysicalInterface
    from atlaso.app.services import interface_updates

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ip_cidr = "192.168.50.1/24"
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.listen_interface = "eth2"
        dns.listen_address = "192.168.50.1"
        db.commit()

        def fail_after_dependent_mutation(session, **_kwargs):
            dependent_dns = session.execute(select(DnsSettings)).scalar_one()
            dependent_dns.listen_address = "192.168.60.1"
            session.add(dependent_dns)
            raise RuntimeError("injected dependent failure")

        monkeypatch.setattr(
            interface_updates,
            "refresh_interface_dependent_addresses",
            fail_after_dependent_mutation,
        )
        with pytest.raises(RuntimeError, match="injected dependent failure"):
            interface_updates.update_physical_interface_desired_state(
                db,
                interface,
                {"ip_cidr": "192.168.60.1/24"},
            )

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        dns = db.execute(select(DnsSettings)).scalar_one()
        assert interface.ip_cidr == "192.168.50.1/24"
        assert dns.listen_address == "192.168.50.1"


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


def test_physical_interface_api_normalizes_legacy_enum_spellings(client):
    """Verify recognized enum spellings accepted by the legacy PATCH remain compatible.

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

    for legacy_role in ("services", "storage"):
        response = client.patch(
            "/api/v1/interfaces/physical/eth2",
            headers=headers,
            json={"role": legacy_role},
        )
        assert response.status_code == 200, response.text
        assert response.json()["role"] == legacy_role


def test_physical_interface_api_rejects_dhcp_range_that_cannot_fit(client):
    """Verify a prefix shrink rolls back when a dependent DHCP range cannot be rebased.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, PhysicalInterface

    scope_name = "api-prefix-shrink-dependency"
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
    from atlaso.app.models import DhcpScope, PhysicalInterface

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
                site_address="192.168.50.1",
                prefix_length=24,
                range_expression="192.168.50.100-192.168.50.120",
                dns_server="192.168.50.1",
                ntp_server="192.168.50.1",
                enabled=True,
                updated_at=original_updated_at,
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
        json={"mtu": 1600},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == scope_name)).scalar_one()
        assert scope.updated_at.replace(tzinfo=timezone.utc) == original_updated_at


def test_physical_interface_api_rejects_address_removal_with_enabled_dependents(client):
    """Verify enabled DHCP and PXE bindings block removal of their interface addresses.

    Args:
        client: Authenticated-capable application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, PhysicalInterface
    from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

    scope_name = "api-address-removal-dependency"
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
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == scope_name)).scalar_one()
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


def test_scope_restrictions_are_enforced(client):
    """Verify that scope restrictions are enforced.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:dashboard"])
    response = client.post(
        "/api/v1/wan/policies",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Nope"},
    )
    assert response.status_code == 403

    monitor = client.get("/api/v1/monitor", headers={"Authorization": f"Bearer {token}"})
    assert monitor.status_code == 403


def test_monitor_api_requires_monitoring_scope(client):
    """Verify that monitor api requires monitoring scope.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:monitoring"])

    response = client.get("/api/v1/monitor?hours=24", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["window_hours"] == 24
    assert "summary" in payload
    assert "virtualization" in payload
    assert "cpu" in payload
    assert "disk_devices" in payload


def test_sufficient_scopes_allow_wan_policy_creation_and_audit(client):
    """Verify that sufficient scopes allow wan policy creation and audit.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:dashboard", "read:wan", "write:wan", "read:audit"])
    response = client.post(
        "/api/v1/wan/policies",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Slow WAN", "latency_ms": 100, "jitter_ms": 10, "packet_loss_percent": 0.5, "bandwidth_mbit": 100},
    )
    assert response.status_code == 201, response.text
    assert response.json()["name"] == "Slow WAN"

    audit = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert audit.status_code == 200
    assert any(event["action"] == "create_wan_policy" for event in audit.json())


def test_api_rejects_route_wan_mode(client):
    """Verify that api rejects route wan mode.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:routes", "write:routes"])
    response = client.post(
        "/api/v1/routes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "destination_cidr": "10.22.0.0/24",
            "interface_name": "eth1.20",
            "metric": 100,
            "enabled": True,
            "wan_mode": "route",
        },
    )

    assert response.status_code == 422
    assert response.json()["error_code"] == "VALIDATION_ERROR"


def test_api_allows_nat_on_access_interface(client):
    """Verify that api allows nat on access interface.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:wan", "write:wan"])
    response = client.post(
        "/api/v1/nat/rules",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Access NAT",
            "source": "192.168.50.0/24",
            "outbound_interface": "eth2",
            "masquerade": True,
            "priority": 120,
            "enabled": True,
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["outbound_interface"] == "eth2"


def test_revoked_token_is_rejected(client):
    """Verify that revoked token is rejected.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, metadata = create_token(client, scopes=["read:dashboard"])
    revoke = client.post(f"/api/v1/api-tokens/{metadata['id']}/revoke", headers={"Authorization": f"Bearer {token}"})
    assert revoke.status_code == 200

    response = client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_expired_token_request_is_rejected(client):
    """Verify that expired token request is rejected.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    expires = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "expired", "expires_at": expires, "scopes": ["read:dashboard"]},
    )
    assert response.status_code == 422
