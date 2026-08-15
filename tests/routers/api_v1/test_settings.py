"""Test Appliance Settings API v1 transports."""

from tests.routers.api_v1.helpers import create_token


def test_settings_api_router_owns_exact_transport_set():
    """Keep Settings API route identities and operation IDs exact."""
    from atlaso.app.api import v1

    assert [
        (
            route.path,
            tuple(sorted((route.methods or set()) - {"HEAD"})),
            route.name,
            route.operation_id,
        )
        for route in v1.settings_router.routes
    ] == [
        ("/api/v1/settings", ("GET",), "get_app_settings", "getSettings"),
        ("/api/v1/settings", ("PATCH",), "update_app_settings", "updateSettings"),
    ]


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


def test_settings_api_retains_read_and_admin_scope_boundaries(client):
    """Verify the extracted Settings operations keep their distinct scopes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    read_token, _metadata = create_token(client, scopes=["read:dashboard"])
    headers = {"Authorization": f"Bearer {read_token}"}

    assert client.get("/api/v1/settings", headers=headers).status_code == 200
    assert (
        client.patch(
            "/api/v1/settings",
            headers=headers,
            json={
                "appliance_fqdn": "api.atlaso.internal",
                "management_https_enabled": False,
                "root_ssh_enabled": False,
                "external_dns_servers": [],
            },
        ).status_code
        == 403
    )
