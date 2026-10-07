"""Test DNS/DHCP API v1 transport behavior."""


def test_dhcp_availability_opt_out_survives_omitted_api_field(client):
    """Old API clients cannot silently re-enable an explicit opt-out.

    Args:
        client: HTTP test client with isolated appliance state.
    """
    token = create_token(client, ["read:dhcp", "write:dhcp"])
    headers = {"Authorization": f"Bearer {token}"}
    current = client.get("/api/v1/dhcp/settings", headers=headers).json()
    assert current["check_ip_availability"] is True
    current["check_ip_availability"] = False
    saved = client.patch("/api/v1/dhcp/settings", headers=headers, json=current)
    assert saved.status_code == 200, saved.text
    assert saved.json()["check_ip_availability"] is False
    current.pop("check_ip_availability")
    saved = client.patch("/api/v1/dhcp/settings", headers=headers, json=current)
    assert saved.status_code == 200, saved.text
    assert saved.json()["check_ip_availability"] is False


def test_pool_verification_requires_scopes_and_rejects_unapplied_identity(client):
    """Permission checks precede reading evidence or queueing network work.

    Args:
        client: HTTP test client with isolated appliance state.
    """
    token = create_token(client, ["read:dhcp", "write:dhcp"])
    headers = {"Authorization": f"Bearer {token}"}
    scope_id = client.get("/api/v1/dhcp/scopes", headers=headers).json()[0]["id"]
    path = f"/api/v1/dhcp/scopes/{scope_id}/verification"
    denied = create_token(client, ["read:dashboard"])
    denied_headers = {"Authorization": f"Bearer {denied}"}
    assert client.get(path, headers=denied_headers).status_code == 403
    assert client.post(path, headers=denied_headers).status_code == 403
    report = client.get(path, headers=headers)
    assert report.status_code == 200 and report.json()["state"] == "unknown"
    assert report.json()["observations"] == []
    assert client.post(path, headers=headers).status_code == 409
    assert client.get("/api/v1/dhcp/scopes/999999/verification", headers=headers).status_code == 404


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


def test_reverse_proxy_owned_dns_records_reject_independent_crud_and_imports(client):
    """Keep proxy-owned DNS records under their reverse-proxy desired-state owner.

    Args:
        client: HTTP test client with isolated appliance state.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord
    from atlaso.app.services.reverse_proxy_publication import DNS_OWNER_PREFIX

    token = create_token(client, ["read:dns", "write:dns"])
    headers = {"Authorization": f"Bearer {token}"}
    with SessionLocal() as db:
        record = DnsRecord(
            hostname="proxy.atlaso.internal",
            record_type="A",
            address="192.168.50.77",
            record_data_json='{"address":"192.168.50.77"}',
            description=f"{DNS_OWNER_PREFIX}17",
            enabled=True,
        )
        unrelated = DnsRecord(
            hostname="ordinary.atlaso.internal",
            record_type="A",
            address="192.168.50.76",
            record_data_json='{"address":"192.168.50.76"}',
            description="Operator-owned DNS record",
            enabled=True,
        )
        db.add_all([record, unrelated])
        db.commit()
        record_id = record.id
        unrelated_id = unrelated.id

    updated = client.patch(
        f"/api/v1/dns/records/{record_id}",
        headers=headers,
        json={
            "hostname": "renamed.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.78",
            "description": "ordinary DNS edit",
            "enabled": False,
        },
    )
    deleted = client.delete(f"/api/v1/dns/records/{record_id}", headers=headers)
    assert updated.status_code == 409
    assert "Reverse Proxies" in updated.json()["detail"]
    assert deleted.status_code == 409
    assert "Reverse Proxies" in deleted.json()["detail"]

    additional_type = client.post(
        "/api/v1/dns/records",
        headers=headers,
        json={
            "hostname": "proxy.atlaso.internal",
            "record_type": "AAAA",
            "address": "2001:db8::78",
            "description": "Operator-owned conflicting alias",
        },
    )
    renamed = client.patch(
        f"/api/v1/dns/records/{unrelated_id}",
        headers=headers,
        json={
            "hostname": "proxy.atlaso.internal",
            "record_type": "AAAA",
            "address": "2001:db8::79",
            "description": "Operator-owned renamed alias",
            "enabled": True,
        },
    )
    assert additional_type.status_code == 409
    assert renamed.status_code == 409

    spoofed = client.post(
        "/api/v1/dns/records",
        headers=headers,
        json={
            "hostname": "spoof.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.79",
            "description": f"{DNS_OWNER_PREFIX}99",
        },
    )
    assert spoofed.status_code == 422

    replacement = client.post(
        "/api/v1/dns/records/import",
        headers=headers,
        json={"replace_existing": True, "hosts_text": "192.168.50.80 imported.atlaso.internal\n"},
    )
    overwrite = client.post(
        "/api/v1/dns/records/import",
        headers=headers,
        json={"replace_existing": False, "hosts_text": "192.168.50.78 proxy.atlaso.internal\n"},
    )
    unrelated_import = client.post(
        "/api/v1/dns/records/import",
        headers=headers,
        json={"replace_existing": False, "hosts_text": "192.168.50.80 unrelated.atlaso.internal\n"},
    )
    assert replacement.status_code == 409
    assert "Reverse Proxies" in replacement.json()["detail"]
    assert overwrite.status_code == 409
    assert "Reverse Proxies" in overwrite.json()["detail"]
    assert unrelated_import.status_code == 200, unrelated_import.text

    with SessionLocal() as db:
        preserved = db.get(DnsRecord, record_id)
        assert preserved is not None
        assert preserved.hostname == "proxy.atlaso.internal"
        assert preserved.address == "192.168.50.77"
        assert preserved.enabled is True
        unrelated_after = db.get(DnsRecord, unrelated_id)
        assert unrelated_after is not None
        assert unrelated_after.hostname == "ordinary.atlaso.internal"


def test_dns_settings_reconcile_reverse_proxy_records_atomically(client):
    """DNS enablement removes and restores owner records without touching operator rows.

    Args:
        client: HTTP test client with isolated appliance state.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DnsRecord,
        DnsSettings,
        ReverseProxy,
        ReverseProxyRoute,
    )
    from atlaso.app.services.reverse_proxy_publication import DNS_OWNER_PREFIX

    with SessionLocal() as db:
        settings = db.scalar(select(DnsSettings))
        assert settings is not None
        settings.enabled = True
        settings.authoritative = True
        settings.domain = "atlaso.internal"
        proxy = ReverseProxy(
            name="Managed proxy",
            hostname="proxy.atlaso.internal",
            scheme="https",
            port=8443,
            enabled=True,
            managed_dns=True,
            listeners=[{"interface": "eth2", "address": "192.168.50.1"}],
            routes=[
                ReverseProxyRoute(
                    position=0,
                    path_prefix="/",
                    upstream_scheme="http",
                    upstream_host="10.10.20.30",
                    upstream_port=8080,
                )
            ],
        )
        operator_record = DnsRecord(
            hostname="operator.atlaso.internal",
            record_type="A",
            address="192.168.50.99",
            record_data_json='{"address":"192.168.50.99"}',
            description="Operator-owned DNS record",
            enabled=True,
        )
        proxy_record = DnsRecord(
            hostname="proxy.atlaso.internal",
            record_type="A",
            address="192.168.50.1",
            record_data_json='{"address":"192.168.50.1"}',
            description=f"{DNS_OWNER_PREFIX}1",
            enabled=True,
        )
        db.add_all([proxy, operator_record, proxy_record])
        db.commit()
        operator_id = operator_record.id

    token = create_token(client, ["read:dns", "write:dns"])
    headers = {"Authorization": f"Bearer {token}"}
    disabled = client.patch("/api/v1/dns/settings", headers=headers, json={"enabled": False})
    assert disabled.status_code == 200, disabled.text
    with SessionLocal() as db:
        assert db.scalar(select(DnsRecord).where(DnsRecord.description.startswith(DNS_OWNER_PREFIX))) is None
        operator_after_disable = db.get(DnsRecord, operator_id)
        assert operator_after_disable is not None
        assert operator_after_disable.description == "Operator-owned DNS record"
        assert operator_after_disable.address == "192.168.50.99"

    enabled = client.patch("/api/v1/dns/settings", headers=headers, json={"enabled": True})
    assert enabled.status_code == 200, enabled.text
    with SessionLocal() as db:
        owner_record = db.scalar(select(DnsRecord).where(DnsRecord.description.startswith(DNS_OWNER_PREFIX)))
        operator_after_enable = db.get(DnsRecord, operator_id)
        assert owner_record is not None
        assert owner_record.hostname == "proxy.atlaso.internal"
        assert owner_record.address == "192.168.50.1"
        assert operator_after_enable is not None
        assert operator_after_enable.description == "Operator-owned DNS record"
        assert operator_after_enable.address == "192.168.50.99"


def test_dns_settings_owner_conflict_rolls_back_saved_settings(client):
    """Reject conflicting generated DNS and preserve the old settings and operator row.

    Args:
        client: HTTP test client with isolated appliance state.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DnsRecord,
        DnsSettings,
        ReverseProxy,
        ReverseProxyRoute,
    )

    with SessionLocal() as db:
        settings = db.scalar(select(DnsSettings))
        assert settings is not None
        settings.enabled = False
        settings.authoritative = True
        settings.domain = "atlaso.internal"
        db.add(
            ReverseProxy(
                name="Conflicting proxy",
                hostname="collision.atlaso.internal",
                scheme="https",
                port=8443,
                enabled=True,
                managed_dns=True,
                listeners=[{"interface": "eth2", "address": "192.168.50.1"}],
                routes=[ReverseProxyRoute(
                    position=0,
                    path_prefix="/",
                    upstream_scheme="http",
                    upstream_host="10.10.20.30",
                    upstream_port=8080,
                )],
            )
        )
        operator = DnsRecord(
            hostname="collision.atlaso.internal",
            record_type="A",
            address="192.168.50.88",
            record_data_json='{"address":"192.168.50.88"}',
            description="Operator-owned conflict",
            enabled=True,
        )
        db.add(operator)
        db.commit()
        operator_id = operator.id

    token = create_token(client, ["read:dns", "write:dns"])
    response = client.patch(
        "/api/v1/dns/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"enabled": True},
    )

    assert response.status_code == 409
    assert "operator" in response.json()["detail"].lower()
    with SessionLocal() as db:
        settings = db.scalar(select(DnsSettings))
        operator_after = db.get(DnsRecord, operator_id)
        assert settings is not None
        assert settings.enabled is False
        assert operator_after is not None
        assert operator_after.address == "192.168.50.88"


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
            "dns_server": "192.168.1.250",
            "ntp_server": "192.168.1.250",
            "enabled": True,
        },
    )
    assert created_scope.status_code == 201, created_scope.text
    assert created_scope.json()["dns_server"] == "192.168.1.250"
    assert created_scope.json()["ntp_server"] == "192.168.1.250"
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
