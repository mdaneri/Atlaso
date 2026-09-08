"""Verify canonical source translation and legacy API compatibility."""

from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import PhysicalInterface
from tests.routers.api_v1.helpers import create_token


def test_canonical_settings_own_nat_without_routing_authority(client):
    """Firewall-scoped NAT writes share legacy state without enabling Routing.

    Args:
        client: Authenticated transport fixture.
    """
    token, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    response = client.put("/api/v1/traffic-publishing/settings", headers=headers, json={"nat_enabled": True})
    assert response.status_code == 200, response.text
    assert response.json() == {"nat_enabled": True, "routing_enabled": False,
                               "effective_nat_enabled": False, "suspended": True}
    assert client.get("/api/v1/traffic-publishing/settings", headers=headers).json() == response.json()
    assert client.put("/api/v1/routes-wan/settings", headers=headers, json={"routing_enabled": True}).status_code == 403
    legacy_token, _ = create_token(client, scopes=["read:routes", "write:routes", "read:wan", "write:wan"])
    legacy = {"Authorization": f"Bearer {legacy_token}"}
    assert client.get("/api/v1/routes-wan/settings", headers=legacy).json()["nat_enabled"]
    assert client.get("/api/v1/traffic-publishing/settings", headers=legacy).status_code == 403
    updated = client.put("/api/v1/routes-wan/settings", headers=legacy,
                         json={"routing_enabled": True, "nat_enabled": False, "wan_simulation_enabled": False})
    assert updated.status_code == 200
    assert client.get("/api/v1/traffic-publishing/settings", headers=headers).json() == {
        "nat_enabled": False, "routing_enabled": True, "effective_nat_enabled": False, "suspended": False}


def test_ipv6_snat_api_preserves_additive_fields_for_legacy_edits(client):
    """Persist NAT66 and preserve its family/mode when older clients omit them.

    Args:
        client: Isolated API fixture with two explicit access interfaces.
    """
    with SessionLocal() as db:
        for name, address in (("eth2", "2001:db8:2::1/64"), ("eth3", "2001:db8:3::1/64")):
            row = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == name))
            if row is None:
                row = PhysicalInterface(name=name, mac_address="00:11:22:33:44:33")
                db.add(row)
            row.mode, row.role, row.admin_state, row.oper_state = "access", "access", "up", "up"
            row.ipv6_cidr = address
        db.commit()
    token, _ = create_token(client, scopes=["read:wan", "write:wan"])
    headers = {"Authorization": f"Bearer {token}"}
    body = {"name": "NAT66", "source": "2001:db8:2::/64", "enabled": True,
            "inbound_interfaces": ["eth2"], "outbound_interface": "eth3", "ip_family": 6,
            "translation_mode": "snat", "translated_address": "2001:db8:3::1"}
    response = client.post("/api/v1/nat/rules", headers=headers, json=body)
    assert response.status_code == 201, response.text
    path = f"/api/v1/nat/rules/{response.json()['id']}"
    legacy_body = {key: value for key, value in body.items()
                   if key not in {"inbound_interfaces", "ip_family", "translation_mode", "translated_address"}}
    edited = client.patch(path, headers=headers, json=legacy_body)
    assert edited.status_code == 200, edited.text
    for key in ("inbound_interfaces", "ip_family", "translation_mode", "translated_address"):
        assert edited.json()[key] == body[key]
    assert edited.json()["masquerade"] is False
    for changed in ({"translated_address": "2001:db8:3::99"}, {"source": "192.0.2.0/24"},
                    {"inbound_interfaces": ["eth0"]}, {"ip_family": 4}):
        assert client.patch(path, headers=headers, json={**body, **changed}).status_code == 422
    assert client.get(path, headers=headers).json()["translated_address"] == body["translated_address"]
