"""Test extracted current-identity and API-token transports."""

from tests.routers.api_v1.helpers import create_token


def test_identity_api_router_owns_exact_transport_set():
    """Keep the bounded API v1 route set in the identity domain module."""
    from atlaso.app.api import v1

    assert {
        (route.path, tuple(sorted(route.methods or ())), route.name, route.operation_id)
        for route in v1.identity_router.routes
    } == {
        ("/api/v1/auth/me", ("GET",), "get_me", "getCurrentIdentity"),
        ("/api/v1/api-tokens", ("GET",), "list_api_tokens", "listApiTokens"),
        ("/api/v1/api-tokens", ("POST",), "create_api_token", "createApiToken"),
        ("/api/v1/api-tokens/{token_id}", ("GET",), "get_api_token", "getApiToken"),
        (
            "/api/v1/api-tokens/{token_id}",
            ("DELETE",),
            "delete_api_token",
            "deleteApiToken",
        ),
        (
            "/api/v1/api-tokens/{token_id}/revoke",
            ("POST",),
            "revoke_api_token",
            "revokeApiToken",
        ),
    }


def test_api_login_creates_token_and_me_works(client):
    """Verify that api login creates token and me works.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, metadata = create_token(client)
    assert metadata["name"] == "test token"
    assert "raw_token" not in metadata

    response = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
    assert response.json()["auth_type"] == "bearer"


def test_api_token_is_shown_only_once_in_list(client):
    """Verify that api token is shown only once in list.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client)
    response = client.get(
        "/api/v1/api-tokens", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()
    assert "raw_token" not in response.text


def test_revoked_token_is_rejected(client):
    """Verify that revoked token is rejected.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, metadata = create_token(client, scopes=["read:dashboard"])
    revoke = client.post(
        f"/api/v1/api-tokens/{metadata['id']}/revoke",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert revoke.status_code == 200

    response = client.get(
        "/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
