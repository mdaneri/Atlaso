"""Test Firewall API v1 transport behavior."""

import pytest

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


@pytest.mark.parametrize("valid_note, invalid_note", [("a" * 1000, "x" * 1001), ("\U0001f600" * 500, "\U0001f600" * 501), ("a" * 998 + "\U0001f600", "a" * 999 + "\U0001f600"), ("a" * 997 + "\r\nb", "a" * 998 + "\r\nb")], ids=["ascii", "non-bmp", "mixed", "literal-crlf"])
def test_firewall_description_write_limit_preserves_legacy_reads(client, valid_note, invalid_note):
    """Reject oversized writes without losing existing or legacy operator notes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        valid_note: Note at the browser-compatible write boundary.
        invalid_note: Note exceeding the browser-compatible write boundary.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import FirewallRule

    token, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"name": "bounded-api-note", "description": valid_note}
    oversized = {**payload, "description": invalid_note}
    assert client.post("/api/v1/firewall/rules", headers=headers, json=oversized).status_code == 422
    created = client.post("/api/v1/firewall/rules", headers=headers, json=payload)
    assert created.status_code == 200, created.text
    rule_id = created.json()["id"]
    assert created.json()["description"] == payload["description"]
    endpoint = f"/api/v1/firewall/rules/{rule_id}"
    assert client.patch(endpoint, headers=headers, json=oversized).status_code == 422
    with SessionLocal() as db:
        rule = db.get(FirewallRule, rule_id)
        assert rule.description == payload["description"]
        rule.description = "legacy" * 200
        db.commit()
    listed = client.get("/api/v1/firewall/rules", headers=headers)
    assert listed.status_code == 200, listed.text
    assert next(row for row in listed.json() if row["id"] == rule_id)["description"] == "legacy" * 200
    updated = client.patch(endpoint, headers=headers, json=payload)
    assert updated.status_code == 200, updated.text
    assert updated.json()["description"] == payload["description"]
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    note_schema = schemas["FirewallRuleCreate"]["properties"]["description"]
    assert note_schema["x-maxLengthUtf16CodeUnits"] == 1000
    assert "maxLength" not in note_schema
    assert all("maxLength" not in item for item in note_schema["anyOf"])


@pytest.mark.parametrize("policy", ["automatic", "deny"])
def test_legacy_firewall_apply_preserves_routing_denials_when_disabled(client, monkeypatch, policy):
    """Reject invalid compatibility applies before applying or recording success.

    Args:
        client: Isolated application HTTP client.
        monkeypatch: Track the dry-run adapter apply boundary.
        policy: Automatic Access isolation or an explicit route-pair deny.
    """
    from sqlalchemy import select

    from atlaso.app.adapters.system import SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        FirewallSettings,
        PhysicalInterface,
        RoutingRule,
    )
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    token, _ = create_token(client, scopes=["write:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    with SessionLocal() as db:
        db.scalar(select(FirewallSettings)).enabled = False
        for name, role, cidr in (("guard-a", "access" if policy == "automatic" else "route", "10.85.1.1/24"), ("guard-b", "route", "10.85.2.1/24")):
            db.add(PhysicalInterface(name=name, role=role, mode="access", ip_cidr=cidr, mac_address="02:00:00:00:85:11" if name == "guard-a" else "02:00:00:00:85:12"))
        db.add(RoutingRule(name="Protected forwarding", enabled=True, source_interface="guard-a", destination_interface="guard-b", policy=policy, ip_family=4))
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
    calls = []
    original_apply = SystemAdapter.apply_firewall_config

    def track_apply(adapter, config_path):
        """Record calls while preserving the existing dry-run behavior."""
        calls.append(config_path)
        return original_apply(adapter, config_path)

    monkeypatch.setattr(SystemAdapter, "apply_firewall_config", track_apply)
    rejected = client.post("/api/v1/firewall/apply", headers=headers)
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["valid"] is False
    assert rejected.json()["reloaded"] is False
    assert any("Enable Firewall" in error for error in rejected.json()["errors"])
    assert calls == []
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "apply_firewall_dry_run")) is None
        save_routes_wan_settings(db, routing_enabled=False, nat_enabled=False, wan_simulation_enabled=False)
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"wan", "firewall"})
        db.commit()
    accepted = client.post("/api/v1/firewall/apply", headers=headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["valid"] is True
    assert len(calls) == 1
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "apply_firewall_dry_run")) is not None


@pytest.mark.parametrize("change", ["deny", "allow", "disable", "delete", "routing-off", "topology"])
def test_legacy_firewall_apply_rejects_pending_routing_intent(client, monkeypatch, change):
    """Never publish valid pending routing intent through the unpaired legacy route.

    Args:
        client: Isolated application HTTP client.
        monkeypatch: Track the adapter publication boundary.
        change: Valid desired-state edit requiring paired application.
    """
    from sqlalchemy import select

    from atlaso.app.adapters.system import SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        FirewallSettings,
        PhysicalInterface,
        RoutingRule,
        Setting,
    )
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.services.routing_permissions import routing_permission_apply_state
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    token, _ = create_token(client, scopes=["write:firewall", "read:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    with SessionLocal() as db:
        db.scalar(select(FirewallSettings)).enabled = True
        for name, cidr, mac in (("pair-a", "10.86.1.1/24", "02:00:00:00:86:11"), ("pair-b", "10.86.2.1/24", "02:00:00:00:86:12")):
            db.add(PhysicalInterface(name=name, role="route", mode="access", ip_cidr=cidr, mac_address=mac))
        rule = RoutingRule(name="Paired forwarding", enabled=True, source_interface="pair-a", destination_interface="pair-b", policy="automatic", ip_family=4)
        db.add(rule)
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"wan", "firewall"})
        db.commit()
        assert routing_permission_apply_state(db) == "applied"
        if change in {"deny", "allow"}:
            rule.policy = change
        elif change == "disable":
            rule.enabled = False
        elif change == "delete":
            db.delete(rule)
        elif change == "routing-off":
            save_routes_wan_settings(db, routing_enabled=False, nat_enabled=False, wan_simulation_enabled=False)
        else:
            db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "pair-a")).ip_cidr = "10.86.3.1/24"
        db.commit()
        assert routing_permission_apply_state(db) == "pending"
        baseline_before = db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).value

    calls = []
    original_apply = SystemAdapter.apply_firewall_config

    def track_apply(adapter, config_path):
        """Track publication without changing the dry-run adapter contract."""
        calls.append(config_path)
        return original_apply(adapter, config_path)

    monkeypatch.setattr(SystemAdapter, "apply_firewall_config", track_apply)
    validation = client.get("/api/v1/firewall/validate", headers=headers)
    assert validation.status_code == 200, validation.text
    assert validation.json()["valid"] is True
    rejected = client.post("/api/v1/firewall/apply", headers=headers)
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["valid"] is False
    assert rejected.json()["reloaded"] is False
    assert any("global Appliance Apply" in error for error in rejected.json()["errors"])
    assert calls == []
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "apply_firewall_dry_run")) is None
        assert db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).value == baseline_before
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"wan", "firewall"})
        db.commit()
        assert routing_permission_apply_state(db) == "applied"
        baseline_applied = db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).value
    accepted = client.post("/api/v1/firewall/apply", headers=headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["valid"] is True
    assert len(calls) == 1
    with SessionLocal() as db:
        assert db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).value == baseline_applied
