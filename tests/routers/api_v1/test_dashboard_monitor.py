"""Test Dashboard and Monitor API v1 transports."""

from tests.routers.api_v1.helpers import create_token


def test_dashboard_monitor_api_router_owns_exact_transport_set():
    """Keep Dashboard and Monitor API identities and operation IDs exact."""
    from atlaso.app.api import v1

    assert [
        (
            route.path,
            tuple(sorted((route.methods or set()) - {"HEAD"})),
            route.name,
            route.operation_id,
        )
        for route in v1.dashboard_monitor_router.routes
    ] == [
        ("/api/v1/dashboard", ("GET",), "get_dashboard", "getDashboard"),
        ("/api/v1/monitor", ("GET",), "get_monitor", "getMonitor"),
    ]


def test_dashboard_api_keeps_public_response_contract(client):
    """Verify the public Dashboard response remains separate from private UI data.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:dashboard"])
    response = client.get(
        "/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert set(response.json()) == {
        "appliance",
        "service_health",
        "interfaces",
        "active_wan_policies",
        "disk_usage",
        "recent_audit_events",
    }


def test_monitor_api_requires_monitoring_scope(client):
    """Verify that Monitor API keeps its scope and history-window contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dashboard_token, _metadata = create_token(client, scopes=["read:dashboard"])
    assert (
        client.get(
            "/api/v1/monitor",
            headers={"Authorization": f"Bearer {dashboard_token}"},
        ).status_code
        == 403
    )

    token, _metadata = create_token(client, scopes=["read:monitoring"])
    response = client.get(
        "/api/v1/monitor?hours=24",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["window_hours"] == 24
    assert "summary" in payload
    assert "virtualization" in payload
    assert "cpu" in payload
    assert "disk_devices" in payload
