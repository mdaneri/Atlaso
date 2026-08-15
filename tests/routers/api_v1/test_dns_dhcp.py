"""Test DNS/DHCP API v1 transport behavior."""


def create_token(client, scopes):
    """Create token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Normalized authorization scopes granted or required by the operation.


    Returns:
        The created token.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "dns dhcp test token", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_dns_api_requires_scope_and_returns_config_preview(client):
    """Verify that dns api requires scope and returns config preview.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token = create_token(client, ["read:dashboard"])
    denied = client.get(
        "/api/v1/dns/status", headers={"Authorization": f"Bearer {token}"}
    )
    assert denied.status_code == 403

    dns_token = create_token(client, ["read:dns", "write:dns"])
    status = client.get(
        "/api/v1/dns/status", headers={"Authorization": f"Bearer {dns_token}"}
    )
    assert status.status_code == 200
    assert status.json()["domain"] == "atlaso.internal"

    created = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "api.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.30",
        },
    )
    assert created.status_code == 201, created.text
    same_owner_different_value = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "API.atlaso.internal",
            "record_type": "a",
            "address": "192.168.50.31",
        },
    )
    assert same_owner_different_value.status_code == 201, (
        same_owner_different_value.text
    )
    duplicate = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "API.atlaso.internal",
            "record_type": "a",
            "address": "192.168.50.30",
        },
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"]

    wrong_family = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "wrong-family.atlaso.internal",
            "record_type": "A",
            "address": "2001:db8::30",
        },
    )
    assert wrong_family.status_code == 422
    assert "IPv4" in wrong_family.json()["detail"]

    cname = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "alias.atlaso.internal",
            "record_type": "CNAME",
            "address": "api.atlaso.internal",
        },
    )
    assert cname.status_code == 201, cname.text
    assert cname.json()["record_type"] == "CNAME"

    forwarder_settings = client.patch(
        "/api/v1/dns/settings",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "conditional_forwarders": [
                {"domain": "sddc.internal", "server": "192.168.10.10"}
            ]
        },
    )
    assert forwarder_settings.status_code == 200
    assert forwarder_settings.json()["conditional_forwarders"] == [
        {"domain": "sddc.internal", "server": "192.168.10.10"}
    ]

    validation = client.post(
        "/api/v1/dns/validate", headers={"Authorization": f"Bearer {dns_token}"}
    )
    assert validation.status_code == 200
    assert validation.json()["valid"] is True
    assert validation.json()["warnings"] == []
    assert "api.atlaso.internal" in validation.json()["config_preview"]
    assert (
        "cname=alias.atlaso.internal,api.atlaso.internal"
        in validation.json()["config_preview"]
    )
    assert "server=/sddc.internal/192.168.10.10" in validation.json()["config_preview"]

    settings = client.patch(
        "/api/v1/dns/settings",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"domain": "vcf.local"},
    )
    assert settings.status_code == 200
    local_validation = client.post(
        "/api/v1/dns/validate", headers={"Authorization": f"Bearer {dns_token}"}
    )
    assert local_validation.status_code == 200
    assert "vcf.local" in local_validation.json()["warnings"][0]
    assert "RFC 6762" in local_validation.json()["warnings"][0]
    assert "ICANN/IANA" in local_validation.json()["warnings"][0]
    assert ".internal" in local_validation.json()["warnings"][0]

    updated = client.patch(
        f"/api/v1/dns/records/{created.json()['id']}",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "api-renamed.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.32",
            "description": "updated through API",
            "enabled": False,
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["hostname"] == "api-renamed.atlaso.internal"
    assert updated.json()["address"] == "192.168.50.32"
    assert updated.json()["enabled"] is False


def test_dns_api_exposes_read_only_authoritative_settings_and_advances_serial(client):
    """Verify that dns api exposes read only authoritative settings and advances serial.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dns_token = create_token(client, ["read:dns", "write:dns"])
    headers = {"Authorization": f"Bearer {dns_token}"}
    initial = client.get("/api/v1/dns/settings", headers=headers)
    assert initial.status_code == 200
    initial_body = initial.json()
    initial_serial = initial_body["authoritative_serial"]

    assert initial_body["authoritative_server"] == "ns1.atlaso.internal"
    assert initial_body["authoritative_contact"] == "hostmaster.atlaso.internal"
    assert initial_body["authoritative_ttl"] == 3600
    assert initial_body["authoritative_refresh"] == 1200
    assert initial_body["authoritative_retry"] == 180
    assert initial_body["authoritative_expire"] == 1209600

    created = client.post(
        "/api/v1/dns/records",
        headers=headers,
        json={
            "hostname": "serial.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.88",
        },
    )
    assert created.status_code == 201, created.text
    after_create = client.get("/api/v1/dns/settings", headers=headers).json()[
        "authoritative_serial"
    ]
    assert after_create > initial_serial

    updated = client.patch(
        f"/api/v1/dns/records/{created.json()['id']}",
        headers=headers,
        json={
            "hostname": "serial.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.89",
        },
    )
    assert updated.status_code == 200, updated.text
    after_update = client.get("/api/v1/dns/settings", headers=headers).json()[
        "authoritative_serial"
    ]
    assert after_update > after_create

    schema = client.get("/openapi.json").json()["components"]["schemas"]
    assert "authoritative_serial" in schema["DnsSettingsResponse"]["properties"]
    assert "authoritative_serial" not in schema["DnsSettingsUpdate"]["properties"]


def test_dns_api_update_rejects_duplicate_record(client):
    """Verify that dns api update rejects duplicate record.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dns_token = create_token(client, ["read:dns", "write:dns"])
    first = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "first.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.50",
        },
    )
    second = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "second.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.51",
        },
    )
    assert first.status_code == 201
    assert second.status_code == 201

    duplicate = client.patch(
        f"/api/v1/dns/records/{second.json()['id']}",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "FIRST.atlaso.internal",
            "record_type": "a",
            "address": "192.168.50.50",
        },
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"]

    allowed = client.patch(
        f"/api/v1/dns/records/{second.json()['id']}",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "FIRST.atlaso.internal",
            "record_type": "a",
            "address": "192.168.50.52",
        },
    )
    assert allowed.status_code == 200, allowed.text


def test_dns_hosts_import_replaces_existing_records(client):
    """Verify that dns hosts import replaces existing records.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dns_token = create_token(client, ["read:dns", "write:dns"])
    response = client.post(
        "/api/v1/dns/records/import",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "replace_existing": True,
            "hosts_text": "192.168.50.70 imported.atlaso.internal imported-alias\n",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["imported_count"] == 2
    hostnames = {record["hostname"] for record in body["records"]}
    assert hostnames == {"imported-alias", "imported.atlaso.internal"}

    validation = client.post(
        "/api/v1/dns/validate", headers={"Authorization": f"Bearer {dns_token}"}
    )
    assert "imported.atlaso.internal" in validation.json()["config_preview"]
    assert "core.atlaso.internal" not in validation.json()["config_preview"]


def test_dhcp_api_scope_and_reservations(client):
    """Verify that dhcp api scope and reservations.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dhcp_token = create_token(client, ["read:dhcp", "write:dhcp", "read:dns"])
    status = client.get(
        "/api/v1/dhcp/status", headers={"Authorization": f"Bearer {dhcp_token}"}
    )
    assert status.status_code == 200
    assert status.json()["interface_name"] == "eth2"

    reservation = client.post(
        "/api/v1/dhcp/reservations",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "hostname": "api-client",
            "mac_address": "02:15:5d:00:20:30",
            "ip_address": "192.168.50.130",
        },
    )
    assert reservation.status_code == 201, reservation.text
    assert reservation.json()["hostname"] == "api-client.atlaso.internal"
    dns_records = client.get(
        "/api/v1/dns/records", headers={"Authorization": f"Bearer {dhcp_token}"}
    )
    assert any(
        record["hostname"] == "api-client.atlaso.internal"
        for record in dns_records.json()
    )

    scopes = client.get(
        "/api/v1/dhcp/scopes", headers={"Authorization": f"Bearer {dhcp_token}"}
    )
    assert scopes.status_code == 200
    assert scopes.json()[0]["name"] == "SiteA"
    assert scopes.json()[0]["range_expression"] == "192.168.50.100-192.168.50.200"
    family_change = client.patch(
        f"/api/v1/dhcp/scopes/{scopes.json()[0]['id']}",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "name": "SiteA",
            "address_family": "ipv6",
            "interface_name": "eth2",
            "site_address": "fd00:50::1",
            "prefix_length": 64,
            "range_expression": "fd00:50::100-fd00:50::200",
            "lease_time": "12h",
            "domain_name": "atlaso.internal",
            "dns_server": "fd00:50::1",
            "ntp_server": "fd00:50::1",
            "enabled": True,
        },
    )
    assert family_change.status_code == 409
    assert (
        family_change.json()["detail"]
        == "DHCP IP zone family cannot be changed after it is created"
    )

    created_scope = client.post(
        "/api/v1/dhcp/scopes",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "name": "SiteB",
            "interface_name": "eth2",
            "site_address": "192.168.60.1",
            "prefix_length": 24,
            "range_expression": "192.168.60.100-192.168.60.200",
            "lease_time": "8h",
            "domain_name": "siteb.internal",
            "dns_server": "192.168.60.1",
            "ntp_server": "192.168.60.1",
            "enabled": True,
        },
    )
    assert created_scope.status_code == 201, created_scope.text
    created_option = client.post(
        "/api/v1/dhcp/options",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "scope_id": created_scope.json()["id"],
            "option_code": "ntp-server",
            "value": "192.168.60.1",
            "enabled": True,
        },
    )
    assert created_option.status_code == 201, created_option.text
    assert created_option.json()["scope_id"] == created_scope.json()["id"]
    options = client.get(
        "/api/v1/dhcp/options", headers={"Authorization": f"Bearer {dhcp_token}"}
    )
    assert any(option["option_code"] == "ntp-server" for option in options.json())
    leases = client.get(
        "/api/v1/dhcp/leases", headers={"Authorization": f"Bearer {dhcp_token}"}
    )
    assert leases.status_code == 200
    assert leases.json()[0]["hostname"] == "api-client.atlaso.internal"
    scopes = client.get(
        "/api/v1/dhcp/scopes", headers={"Authorization": f"Bearer {dhcp_token}"}
    )
    assert {scope["name"] for scope in scopes.json()} == {"SiteA", "SiteB"}


def test_dhcp_api_leases_reflect_helper_output(client, monkeypatch):
    """Verify that dhcp api leases reflect helper output.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult

    def fake_read_dhcp_leases(self):
        """Return fake read dhcp leases."""
        return AdapterResult(
            command=[
                "sudo",
                "-n",
                "/opt/atlaso/bin/atlaso-helper",
                "dnsmasq",
                "leases",
                "--real",
            ],
            dry_run=False,
            stdout="1893456000 02:15:5d:00:20:40 192.168.50.140 live-client.atlaso.internal *\n",
        )

    monkeypatch.setattr(
        "atlaso.app.api.v1.SystemAdapter.read_dhcp_leases", fake_read_dhcp_leases
    )
    dhcp_token = create_token(client, ["read:dhcp"])

    leases = client.get(
        "/api/v1/dhcp/leases", headers={"Authorization": f"Bearer {dhcp_token}"}
    )

    assert leases.status_code == 200
    assert leases.json() == [
        {
            "expires_at": "2030-01-01T00:00:00Z",
            "mac_address": "02:15:5d:00:20:40",
            "ip_address": "192.168.50.140",
            "hostname": "live-client.atlaso.internal",
            "client_id": "",
            "status": "active",
        }
    ]
