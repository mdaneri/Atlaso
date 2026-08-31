"""Test Routes/WAN API v1 transport behavior."""

from tests.routers.api_v1.helpers import create_token


def test_routes_wan_settings_require_both_scopes_and_preserve_rows(client):
    """Save global feature intent while preserving all Routes and WAN rows.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import func, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, NatRule, Route, WanPolicy

    read_routes_token, _ = create_token(client, scopes=["read:routes"])
    denied = client.get(
        "/api/v1/routes-wan/settings",
        headers={"Authorization": f"Bearer {read_routes_token}"},
    )
    assert denied.status_code == 403
    assert "read:wan" in denied.text

    token, _ = create_token(
        client,
        scopes=["read:routes", "read:wan", "write:routes", "write:wan"],
    )
    headers = {"Authorization": f"Bearer {token}"}
    initial = client.get("/api/v1/routes-wan/settings", headers=headers)
    assert initial.status_code == 200
    assert initial.json() == {
        "routing_enabled": False,
        "nat_enabled": False,
        "wan_simulation_enabled": False,
        "effective_nat_enabled": False,
    }

    with SessionLocal() as db:
        before = (
            db.scalar(select(func.count(Route.id))),
            db.scalar(select(func.count(NatRule.id))),
            db.scalar(select(func.count(WanPolicy.id))),
        )

    suspended = client.put(
        "/api/v1/routes-wan/settings",
        headers=headers,
        json={
            "routing_enabled": False,
            "nat_enabled": True,
            "wan_simulation_enabled": True,
        },
    )
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["nat_enabled"] is True
    assert suspended.json()["effective_nat_enabled"] is False

    enabled = client.put(
        "/api/v1/routes-wan/settings",
        headers=headers,
        json={
            "routing_enabled": True,
            "nat_enabled": True,
            "wan_simulation_enabled": True,
        },
    )
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["effective_nat_enabled"] is True

    with SessionLocal() as db:
        after = (
            db.scalar(select(func.count(Route.id))),
            db.scalar(select(func.count(NatRule.id))),
            db.scalar(select(func.count(WanPolicy.id))),
        )
        assert after == before
        assert db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "update_routes_wan_settings"
            )
        ) == 2


def test_routes_wan_settings_put_requires_both_write_scopes(client):
    """Reject a settings mutation when either write scope is absent.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _ = create_token(
        client,
        scopes=["read:routes", "read:wan", "write:routes"],
    )
    response = client.put(
        "/api/v1/routes-wan/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "routing_enabled": True,
            "nat_enabled": False,
            "wan_simulation_enabled": False,
        },
    )
    assert response.status_code == 403
    assert "write:wan" in response.text


def test_routes_wan_settings_put_preserves_unconfigured_routing_service(client):
    """Keep restored Routing runtime state unchanged until Appliance Apply.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ServiceState

    with SessionLocal() as db:
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "routing")
        ).scalar_one()
        service.enabled = False
        service.running = False
        service.health = "unconfigured"
        db.commit()

    token, _ = create_token(
        client,
        scopes=["read:routes", "read:wan", "write:routes", "write:wan"],
    )
    response = client.put(
        "/api/v1/routes-wan/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "routing_enabled": True,
            "nat_enabled": True,
            "wan_simulation_enabled": True,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["routing_enabled"] is True
    with SessionLocal() as db:
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "routing")
        ).scalar_one()
        assert service.enabled is False
        assert service.running is False
        assert service.health == "unconfigured"


def test_wan_status_reports_only_effective_feature_state(client):
    """Exclude preserved NAT and policy rows while their feature is inactive.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import delete

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NatRule, Route, WanPolicy
    from atlaso.app.services.routes_wan import save_routes_wan_settings

    with SessionLocal() as db:
        db.execute(delete(Route))
        db.execute(delete(NatRule))
        db.execute(delete(WanPolicy))
        policy = WanPolicy(name="Status WAN", enabled=True, latency_ms=25)
        db.add(policy)
        db.flush()
        db.add(
            Route(
                destination_cidr="203.0.113.0/24",
                interface_name="eth1.20",
                enabled=True,
                wan_policy_id=policy.id,
            )
        )
        db.add(
            NatRule(
                name="Status NAT",
                source="192.168.20.0/24",
                outbound_interface="eth2",
                enabled=True,
            )
        )
        save_routes_wan_settings(
            db,
            routing_enabled=False,
            nat_enabled=True,
            wan_simulation_enabled=False,
        )
        db.commit()

    token, _ = create_token(client, scopes=["read:wan"])
    headers = {"Authorization": f"Bearer {token}"}
    disabled = client.get("/api/v1/wan/status", headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["active_policy_count"] == 0
    assert disabled.json()["managed_interfaces"] == []

    with SessionLocal() as db:
        save_routes_wan_settings(
            db,
            routing_enabled=False,
            nat_enabled=True,
            wan_simulation_enabled=True,
        )
        db.commit()

    simulation_only = client.get("/api/v1/wan/status", headers=headers)
    assert simulation_only.json()["active_policy_count"] == 1
    assert simulation_only.json()["managed_interfaces"] == ["eth1.20"]

    with SessionLocal() as db:
        save_routes_wan_settings(
            db,
            routing_enabled=True,
            nat_enabled=True,
            wan_simulation_enabled=True,
        )
        db.commit()

    all_enabled = client.get("/api/v1/wan/status", headers=headers)
    assert all_enabled.json()["active_policy_count"] == 1
    assert all_enabled.json()["managed_interfaces"] == ["eth1.20", "eth2"]


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


def test_api_default_route_contract_and_canonical_readback(client):
    """Preserve /0 API compatibility while enforcing default-route invariants.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:routes", "write:routes"])
    headers = {"Authorization": f"Bearer {token}"}
    base = {
        "interface_name": "eth1.20",
        "metric": 100,
        "enabled": True,
        "wan_mode": "interface",
    }

    direct = client.post(
        "/api/v1/routes",
        headers=headers,
        json={**base, "destination_cidr": "10.55.0.42/24", "gateway": None},
    )
    assert direct.status_code == 201, direct.text
    assert direct.json()["destination_cidr"] == "10.55.0.0/24"
    assert direct.json()["gateway"] is None

    missing_gateway = client.post(
        "/api/v1/routes",
        headers=headers,
        json={**base, "destination_cidr": "0.0.0.0/0", "gateway": None},
    )
    assert missing_gateway.status_code == 422
    assert "requires a gateway" in missing_gateway.text

    mismatch = client.post(
        "/api/v1/routes",
        headers=headers,
        json={**base, "destination_cidr": "::/0", "gateway": "192.0.2.1"},
    )
    assert mismatch.status_code == 422
    assert "family must match" in mismatch.text

    off_link = client.post(
        "/api/v1/routes",
        headers=headers,
        json={**base, "destination_cidr": "0.0.0.0/0", "gateway": "198.51.100.1"},
    )
    assert off_link.status_code == 422
    assert "is not on-link" in off_link.text

    created = client.post(
        "/api/v1/routes",
        headers=headers,
        json={**base, "destination_cidr": "192.0.2.42/0", "gateway": "192.168.20.254"},
    )
    assert created.status_code == 201, created.text
    route_id = created.json()["id"]
    assert created.json()["destination_cidr"] == "0.0.0.0/0"

    readback = client.get(f"/api/v1/routes/{route_id}", headers=headers)
    assert readback.status_code == 200
    assert readback.json()["destination_cidr"] == "0.0.0.0/0"

    duplicate = client.post(
        "/api/v1/routes",
        headers=headers,
        json={**base, "destination_cidr": "0.0.0.0/0", "gateway": "192.168.20.253"},
    )
    assert duplicate.status_code == 422
    assert "Only one IPv4 default route" in duplicate.text

    target_mismatch = client.patch(
        f"/api/v1/routes/{route_id}",
        headers=headers,
        json={**base, "destination_cidr": "2001:db8::99/0", "gateway": "2001:db8::1"},
    )
    assert target_mismatch.status_code == 422
    assert "does not have a configured IPv6 CIDR" in target_mismatch.text

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VlanInterface

    with SessionLocal() as db:
        target = db.execute(select(VlanInterface).where(VlanInterface.name == "eth1.20")).scalar_one()
        target.ipv6_cidr = "2001:db8:20::1/64"
        db.commit()

    updated = client.patch(
        f"/api/v1/routes/{route_id}",
        headers=headers,
        json={**base, "destination_cidr": "2001:db8::99/0", "gateway": "fe80::1"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["destination_cidr"] == "::/0"
