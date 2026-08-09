from datetime import datetime, timedelta, timezone


def create_token(client, scopes=None):
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "test token", "scopes": scopes or ["read:dashboard", "read:wan", "write:wan", "read:audit"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["raw_token"]
    return body["raw_token"], body["token"]


def test_unauthenticated_api_requests_are_rejected(client):
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 401
    assert response.json()["error_code"] == "HTTP_ERROR"


def test_appliance_version_api_is_unauthenticated(client, monkeypatch):
    import atlaso.app.api.v1 as api_v1

    monkeypatch.setattr(
        api_v1,
        "current_version_info",
        lambda: {
            "version": "0.9.87+g0123456789ab",
            "base_version": "0.9.87",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "built_at": "2026-08-09T20:15:00Z",
            "platform": "excluded",
        },
    )

    response = client.get("/api/v1/version")

    assert response.status_code == 200
    assert response.json() == {
        "version": "0.9.87+g0123456789ab",
        "base_version": "0.9.87",
        "git_commit": "0123456789abcdef0123456789abcdef01234567",
        "built_at": "2026-08-09T20:15:00Z",
    }


def test_invalid_jwt_is_rejected(client):
    response = client.get("/api/v1/dashboard", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401


def test_api_login_creates_token_and_me_works(client):
    token, metadata = create_token(client)
    assert metadata["name"] == "test token"
    assert "raw_token" not in metadata

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
    assert response.json()["auth_type"] == "bearer"


def test_api_token_is_shown_only_once_in_list(client):
    token, _metadata = create_token(client)
    response = client.get("/api/v1/api-tokens", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()
    assert "raw_token" not in response.text


def test_settings_api_updates_root_ssh_desired_state(client):
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


def test_scope_restrictions_are_enforced(client):
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
    token, metadata = create_token(client, scopes=["read:dashboard"])
    revoke = client.post(f"/api/v1/api-tokens/{metadata['id']}/revoke", headers={"Authorization": f"Bearer {token}"})
    assert revoke.status_code == 200

    response = client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_expired_token_request_is_rejected(client):
    expires = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "expired", "expires_at": expires, "scopes": ["read:dashboard"]},
    )
    assert response.status_code == 422
