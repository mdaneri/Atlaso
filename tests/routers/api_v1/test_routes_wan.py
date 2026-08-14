"""Test Routes/WAN API v1 transport behavior."""

from tests.routers.api_v1.helpers import create_token


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
