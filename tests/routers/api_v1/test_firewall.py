"""Test Firewall API v1 transport behavior."""

from tests.routers.api_v1.helpers import create_token


def test_firewall_api_preserves_settings_rule_and_validation_transports(client):
    """Exercise the existing Firewall API desired-state transport contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(
        client,
        scopes=["read:firewall", "write:firewall"],
    )
    headers = {"Authorization": f"Bearer {token}"}

    settings = client.get("/api/v1/firewall/settings", headers=headers)
    assert settings.status_code == 200, settings.text
    settings_payload = settings.json()
    updated_settings = client.patch(
        "/api/v1/firewall/settings",
        headers=headers,
        json={
            **settings_payload,
            "enabled": True,
            "log_dropped": True,
        },
    )
    assert updated_settings.status_code == 200, updated_settings.text
    assert updated_settings.json()["enabled"] is True
    assert updated_settings.json()["log_dropped"] is True

    rule_payload = {
        "name": "api-router-firewall",
        "direction": "input",
        "action": "accept",
        "protocol": "tcp",
        "source": "any",
        "destination": "any",
        "destination_port": "443",
        "interface_name": "eth2",
        "priority": 125,
        "enabled": True,
        "description": "Focused API transport coverage",
    }
    created = client.post(
        "/api/v1/firewall/rules",
        headers=headers,
        json=rule_payload,
    )
    assert created.status_code == 200, created.text
    rule_id = created.json()["id"]

    listed = client.get("/api/v1/firewall/rules", headers=headers)
    assert listed.status_code == 200, listed.text
    assert any(rule["id"] == rule_id for rule in listed.json())

    updated = client.patch(
        f"/api/v1/firewall/rules/{rule_id}",
        headers=headers,
        json={**rule_payload, "priority": 126},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["priority"] == 126

    validation = client.get("/api/v1/firewall/validate", headers=headers)
    assert validation.status_code == 200, validation.text
    assert validation.json()["valid"] is True
    assert "table inet atlaso" in validation.json()["config_preview"]

    deleted = client.delete(
        f"/api/v1/firewall/rules/{rule_id}",
        headers=headers,
    )
    assert deleted.status_code == 200, deleted.text
    assert deleted.json() == {"deleted": True}


def test_firewall_api_preserves_read_write_scope_boundaries(client):
    """Require write scope for Firewall desired-state mutation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["read:firewall"])
    headers = {"Authorization": f"Bearer {token}"}

    status = client.get("/api/v1/firewall/status", headers=headers)
    assert status.status_code == 200, status.text

    rejected = client.post(
        "/api/v1/firewall/rules",
        headers=headers,
        json={
            "name": "forbidden-firewall-rule",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "any",
            "destination": "any",
            "destination_port": "443",
            "interface_name": "eth2",
            "priority": 130,
            "enabled": True,
            "description": "Must not persist",
        },
    )
    assert rejected.status_code == 403


def test_flagged_management_listener_preview_matches_ui_and_api(client):
    """Keep flagged physical and VLAN management rules identical across previews.

    Args:
        client: HTTP test client used to initialize isolated application state.
    """
    from sqlalchemy import select

    from atlaso.app.api.v1 import firewall_validation_payload
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface
    from atlaso.app.ui import firewall_context

    with SessionLocal() as db:
        physical = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        physical.role = "access"
        physical.mode = "access"
        physical.ip_cidr = "192.0.2.10/24"
        physical.access_management_ui_enabled = True
        vlan = db.execute(
            select(VlanInterface).where(VlanInterface.name == "eth1.20")
        ).scalar_one()
        vlan.ip_cidr = "198.51.100.10/24"
        vlan.role = "access"
        vlan.enabled = True
        vlan.access_management_ui_enabled = True
        db.commit()

        ui_preview = firewall_context(db, reconcile=False)["firewall_config_preview"]
        _settings, _rules, api_preview, errors = firewall_validation_payload(db)

    ui_management_rules = sorted(
        line.strip()
        for line in ui_preview.splitlines()
        if 'comment "management-ui-' in line
    )
    api_management_rules = sorted(
        line.strip()
        for line in api_preview.splitlines()
        if 'comment "management-ui-' in line
    )
    assert errors == []
    assert ui_management_rules == api_management_rules
    assert any(
        'iifname "eth0" tcp dport { 22, 80, 443 } accept comment "management-ui-eth0"'
        in line
        for line in ui_management_rules
    )
    assert any(
        'iifname "eth1.20" tcp dport { 22, 80, 443 } accept comment "management-ui-eth1.20"'
        in line
        for line in ui_management_rules
    )
