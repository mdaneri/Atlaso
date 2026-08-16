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
