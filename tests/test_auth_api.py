"""Test auth api behavior."""

from datetime import datetime, timedelta, timezone

from tests.routers.api_v1.helpers import create_token


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
