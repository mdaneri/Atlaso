"""Bind routing permission Apply state to executed paired snapshots."""

import json

import pytest

from tests.routers.ui.helpers import login


@pytest.mark.parametrize("selected", ["wan", "firewall"])
def test_routing_permission_apply_captures_both_units(client, selected):
    """Selecting either enforcement owner captures WAN and Firewall together.

    Args:
        client: Isolated application client with dry-run system adapters.
        selected: Operator-selected enforcement unit.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, RoutingRule
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.services.routing_permissions import routing_permission_apply_state
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        for name, cidr in (("route-a", "10.60.0.1/24"), ("route-b", "10.61.0.1/24")):
            db.add(PhysicalInterface(name=name, mac_address="02:00:00:00:85:01" if name == "route-a" else "02:00:00:00:85:02", mode="access", role="route", admin_state="up",
                                     oper_state="up", ip_cidr=cidr))
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        assert routing_permission_apply_state(db) == "applied"
        db.add(RoutingRule(name="Apply denial", enabled=True, source_interface="route-a", destination_interface="route-b",
                           policy="deny", ip_family=4))
        db.commit()
        assert routing_permission_apply_state(db) == "pending"

    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": [selected]},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result)
        assert {"wan", "firewall"} <= set(payload["selected_units"])
        assert job.status == "succeeded", job.error
        assert routing_permission_apply_state(db) == "applied"
        rule = db.scalar(select(RoutingRule).where(RoutingRule.name == "Apply denial"))
        rule.policy = "automatic"
        db.commit()
        assert routing_permission_apply_state(db) == "pending"


def test_one_baseline_or_stale_snapshot_cannot_claim_applied(client):
    """A newer edit remains pending when an older captured snapshot finishes.

    Args:
        client: Isolated application database fixture.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import RoutingRule
    from atlaso.app.services.routing_permissions import routing_permission_apply_state
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"wan"})
        db.commit()
        assert routing_permission_apply_state(db) == "pending"
        db.add(RoutingRule(name="New intent", source_interface="eth2", destination_interface="eth1.20",
                           policy="deny", ip_family=4, enabled=True))
        db.commit()
        update_appliance_apply_baselines(db, units, {"wan", "firewall"})
        db.commit()
        assert routing_permission_apply_state(db) == "pending"


def test_access_only_topology_change_requires_paired_apply(client):
    """Access defaults remain paired even without an explicit permission row.

    Args:
        client: Isolated application client with dry-run system adapters.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.services.routing_permissions import (
        routing_permission_apply_state,
        routing_permission_fingerprint,
    )
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        first = PhysicalInterface(name="access-a", mac_address="02:00:00:00:85:11", mode="access", role="access",
                                  admin_state="up", oper_state="up", ip_cidr="10.85.1.1/24")
        db.add(first)
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        assert routing_permission_apply_state(db) == "applied"
        original = routing_permission_fingerprint(db)

        first.ip_cidr = "10.85.2.1/24"
        db.commit()
        assert routing_permission_fingerprint(db) != original
        assert routing_permission_apply_state(db) == "pending"
        first.ip_cidr = "10.85.1.1/24"
        db.add(PhysicalInterface(name="access-b", mac_address="02:00:00:00:85:12", mode="access", role="access",
                                 admin_state="up", oper_state="up", ip_cidr="10.85.3.1/24"))
        db.commit()
        assert routing_permission_fingerprint(db) != original
        second = routing_permission_fingerprint(db)
        first.ipv6_cidr = "2001:db8:85::1/64"
        first.ipv6_enabled = True
        db.commit()
        assert routing_permission_fingerprint(db) != second
        units = appliance_apply_units(db)
        assert not {unit["id"]: unit["validation_errors"] for unit in units if unit["id"] in {"network", "wan", "firewall", "nat"} and unit["validation_errors"]}

    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result)
        assert {"network", "wan", "firewall"} <= set(payload["selected_units"])
        assert job.status == "succeeded", job.error
        assert routing_permission_apply_state(db) == "applied"


def test_routing_shutdown_stops_wan_before_removing_access_drops(client, monkeypatch):
    """A failed WAN shutdown cannot publish the permissive Firewall snapshot.

    Args:
        client: Isolated application client with dry-run system adapters.
        monkeypatch: Inject a WAN failure and observe Firewall publication.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        for index in (1, 2):
            db.add(PhysicalInterface(name=f"access-{index}", mac_address=f"02:00:00:00:86:0{index}",
                                     mode="access", role="access", admin_state="up", oper_state="up",
                                     ip_cidr=f"10.86.{index}.1/24"))
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        save_routes_wan_settings(db, routing_enabled=False, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()

    firewall_calls = []

    def fail_wan(_adapter, _path):
        return AdapterResult(command=["wan", "apply"], dry_run=True, stderr="injected WAN failure", returncode=1)

    def record_firewall(_adapter, path):
        firewall_calls.append(path)
        return AdapterResult(command=["firewall", "apply"], dry_run=True)

    monkeypatch.setattr(SystemAdapter, "apply_wan_config", fail_wan)
    monkeypatch.setattr(SystemAdapter, "apply_firewall_config", record_firewall)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "wan"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result)
        assert payload["management_handoff"] is False
        assert payload["selected_units"].index("wan") < payload["selected_units"].index("firewall")
        assert job.status == "failed"
        assert firewall_calls == []
