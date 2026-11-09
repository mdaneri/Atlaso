"""Test extracted current-identity and API-token transports."""

import pytest

from atlaso.app.database import SessionLocal
from atlaso.app.models import ApiToken, AuditEvent, User
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


@pytest.mark.parametrize(
    "caller_scopes, requested_scopes",
    [
        (["read:dashboard"], ["admin:all"]),
        (["read:dashboard", "write:wan"], ["write:services"]),
        (["read:dashboard"], ["read:dashboard"]),
        (["read:dashboard"], []),
    ],
)
def test_restricted_bearer_cannot_issue_tokens(client, caller_scopes, requested_scopes):
    """Deny new credentials from restricted bearers before token or audit creation.

    Args:
        client: Isolated HTTP client exercising the real issuance dependency.
        caller_scopes: Permissions granted to the administrator-owned caller token.
        requested_scopes: Broader, equal, or empty permissions requested for a child.
    """
    token, _metadata = create_token(client, scopes=caller_scopes)
    with SessionLocal() as db:
        token_count = db.query(ApiToken).count()
        audit_count = db.query(AuditEvent).filter_by(action="create_api_token").count()

    response = client.post(
        "/api/v1/api-tokens",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "delegation-denied", "scopes": requested_scopes},
    )

    assert response.status_code == 403
    with SessionLocal() as db:
        assert db.query(ApiToken).count() == token_count
        assert db.query(AuditEvent).filter_by(action="create_api_token").count() == audit_count


def test_admin_bearer_can_issue_a_usable_scoped_token(client):
    """Preserve explicit administrator issuance and the resulting scope limits.

    Args:
        client: Isolated HTTP client exercising token creation and authentication.
    """
    token, _metadata = create_token(client, scopes=["admin:all"])
    response = client.post(
        "/api/v1/api-tokens",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "authorized-integration", "scopes": ["read:dashboard"]},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["token"]["scopes"] == ["read:dashboard"]
    assert "raw_token" not in body["token"]
    child_headers = {"Authorization": f"Bearer {body['raw_token']}"}
    assert client.get("/api/v1/dashboard", headers=child_headers).status_code == 200
    assert client.get("/api/v1/monitor", headers=child_headers).status_code == 403


def test_admin_bearer_issuance_keeps_current_owner_role_ceiling(client):
    """Retain the shared service's current role check after transport admission.

    Args:
        client: Isolated HTTP client with a role change after credential issuance.
    """
    token, _metadata = create_token(client, scopes=["admin:all"])
    with SessionLocal() as db:
        user = db.query(User).filter_by(username="admin").one()
        user.role = "viewer"
        user.roles_json = '["viewer"]'
        db.commit()
    response = client.post(
        "/api/v1/api-tokens",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "role-ceiling-denied", "scopes": ["admin:all"]},
    )
    assert response.status_code == 403
