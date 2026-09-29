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


@pytest.mark.parametrize("selected", ["network", "wan", "firewall"])
def test_access_only_topology_change_requires_paired_apply(client, selected):
    """Access defaults remain paired even without an explicit permission row.

    Args:
        client: Isolated application client with dry-run system adapters.
        selected: Operator-selected publication unit.
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
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": selected},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result)
        assert {"network", "wan", "firewall"} <= set(payload["selected_units"])
        assert payload["routing_publishing_network"] is True
        assert job.status == "succeeded", job.error
        assert routing_permission_apply_state(db) == "applied"


def test_apply_rejects_enabled_permission_after_endpoint_loses_forwarding_role(client):
    """A role edit cannot silently retire a saved deny while Routing is active.

    Args:
        client: Isolated application client with dry-run adapters.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, RoutingRule
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.ui import (
        appliance_apply_units,
        routes_wan_context,
        update_appliance_apply_baselines,
    )

    login(client)
    with SessionLocal() as db:
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.add(RoutingRule(name="Retained denial", enabled=True, source_interface="eth2",
                           destination_interface="eth1.20", policy="deny", ip_family=4))
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        endpoint = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert endpoint is not None
        endpoint.role = "unused"
        db.commit()
        errors = routes_wan_context(db)["routing_validation_errors"]
        assert any("Retained denial source must be" in error for error in errors)

    csrf = client.get("/routes-wan").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "firewall"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 422, response.text


def test_nat_only_selection_pairs_new_access_endpoint_with_firewall(client):
    """NAT dependency expansion cannot activate Access topology under stale policy.

    Args:
        client: Isolated application client.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.services.routing_permissions import routing_permission_apply_state
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        db.add(PhysicalInterface(name="nat-access-a", mac_address="02:00:00:00:85:41", mode="access",
                                 role="access", admin_state="up", oper_state="up", ip_cidr="10.85.41.1/24"))
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=True, wan_simulation_enabled=False)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        db.add(PhysicalInterface(name="nat-access-b", mac_address="02:00:00:00:85:42", mode="access",
                                 role="access", admin_state="up", oper_state="up", ip_cidr="10.85.42.1/24"))
        db.commit()
        assert routing_permission_apply_state(db) == "pending"
        assert next(unit for unit in appliance_apply_units(db) if unit["id"] == "network")["changed"]

    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "nat"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result)
        assert {"network", "wan", "firewall", "nat"} <= set(payload["selected_units"])
        assert payload["routing_publishing_pair"] is True
        assert job.status == "succeeded", job.error
        assert routing_permission_apply_state(db) == "applied"


def test_routing_permission_change_waits_for_forwarding_off_during_management_handoff(client, monkeypatch):
    """A handoff must not expose a new Access link under old forwarding policy.

    Args:
        client: Isolated application client with dry-run system adapters.
        monkeypatch: Force the changed Network unit through protected management handoff.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        access = PhysicalInterface(name="access-a", mac_address="02:00:00:00:85:31", mode="access",
                                   role="access", admin_state="up", oper_state="up", ip_cidr="10.85.31.1/24")
        db.add(access)
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
        update_appliance_apply_baselines(db, appliance_apply_units(db), {"network", "wan", "firewall", "nat"})
        db.commit()
        access.ip_cidr = "10.85.32.1/24"
        db.commit()

    original_units = ui.appliance_apply_units

    def handoff_units(db, **kwargs):
        """Mark only the pending Network change as management-affecting.

        Args:
            db: Session used to build Apply units.
            **kwargs: Options forwarded to the unit builder.
        """
        units = original_units(db, **kwargs)
        next(unit for unit in units if unit["id"] == "network")["management_handoff_required"] = True
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", handoff_units)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 422, response.text
    assert "Disable Routing" in response.json()["detail"]


def test_access_network_apply_failure_does_not_publish_network_standalone(client, monkeypatch):
    """A failed routing group retains the previous Network baseline and runtime.

    Args:
        client: Isolated application client with dry-run adapters.
        monkeypatch: Inject group failure and detect independent Network apply.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.services.routing_permissions import routing_permission_apply_state
    from atlaso.app.ui import (
        appliance_apply_units,
        load_appliance_apply_baselines,
        update_appliance_apply_baselines,
    )

    login(client)
    with SessionLocal() as db:
        db.add(PhysicalInterface(name="access-a", mac_address="02:00:00:00:85:21", mode="access", role="access",
                                 admin_state="up", oper_state="up", ip_cidr="10.85.21.1/24"))
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        original_network = load_appliance_apply_baselines(db)["network"]
        db.add(PhysicalInterface(name="access-b", mac_address="02:00:00:00:85:22", mode="access", role="access",
                                 admin_state="up", oper_state="up", ip_cidr="10.85.22.1/24"))
        db.commit()
        assert routing_permission_apply_state(db) == "pending"

    grouped = []
    independent = []

    def fail_group(_adapter, job_id, nat_path, firewall_path, wan_path, wan_rollback_path, network_path):
        """Reject one captured four-unit helper invocation.

        Args:
            _adapter: Dry-run system adapter.
            job_id: Global Apply task owner.
            nat_path: Captured translation stage.
            firewall_path: Captured Firewall stage.
            wan_path: Captured WAN candidate.
            wan_rollback_path: Last-applied WAN stage.
            network_path: Captured Network candidate.
        """
        grouped.append((job_id, nat_path, firewall_path, wan_path, wan_rollback_path, network_path))
        return AdapterResult(command=["nat", "apply-publishing"], dry_run=True,
                             stderr="injected four-unit failure", returncode=1)

    def record_network(_adapter, path):
        """Detect any independent Network publication.

        Args:
            _adapter: Dry-run system adapter.
            path: Staged Network configuration.
        """
        independent.append(path)
        return AdapterResult(command=["network", "apply"], dry_run=True)

    monkeypatch.setattr(SystemAdapter, "apply_traffic_publishing", fail_group)
    monkeypatch.setattr(SystemAdapter, "apply_network_config", record_network)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result)
        assert payload["routing_publishing_network"] is True
        assert {"network", "wan", "firewall", "nat"} <= set(payload["selected_units"])
        assert job.status == "failed"
        assert len(grouped) == 1 and independent == []
        assert load_appliance_apply_baselines(db)["network"] == original_network
        assert routing_permission_apply_state(db) == "pending"


@pytest.mark.parametrize("routing_disabled", [False, True])
def test_routing_permission_pair_fails_as_one_group(client, monkeypatch, routing_disabled):
    """A failed permission publication cannot advance either applied owner.

    Args:
        client: Isolated application client with dry-run system adapters.
        monkeypatch: Inject a coupled helper failure and observe unit calls.
        routing_disabled: Disable Routing or relax an Access deny while enabled.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, RoutingRule
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from atlaso.app.services.routing_permissions import routing_permission_apply_state
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        for index in (1, 2):
            db.add(PhysicalInterface(name=f"access-{index}", mac_address=f"02:00:00:00:86:0{index}",
                                     mode="access", role="access", admin_state="up", oper_state="up",
                                     ip_cidr=f"10.86.{index}.1/24"))
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        permission = RoutingRule(name="Access deny", enabled=True, source_interface="access-1",
                                 destination_interface="access-2", policy="deny", ip_family=4)
        db.add(permission)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        if routing_disabled:
            save_routes_wan_settings(db, routing_enabled=False, nat_enabled=False, wan_simulation_enabled=False)
        else:
            permission.policy = "allow"
        db.commit()
        assert routing_permission_apply_state(db) == "pending"

    coupled_calls = []
    independent_calls = []

    def fail_coupled(_adapter, job_id, nat_path, firewall_path, wan_path, wan_rollback_path):
        """Fail one captured group after observing its exact five arguments.

        Args:
            _adapter: Dry-run host adapter.
            job_id: Exact Apply owner.
            nat_path: Captured translation stage.
            firewall_path: Captured Firewall stage.
            wan_path: Captured WAN stage.
            wan_rollback_path: Last-applied WAN rollback stage.
        """
        coupled_calls.append((job_id, nat_path, firewall_path, wan_path, wan_rollback_path))
        return AdapterResult(command=["nat", "apply-publishing"], dry_run=True,
                             stderr="injected coupled failure", returncode=1)

    def record_independent(_adapter, path):
        """Detect any independent WAN or Firewall publication.

        Args:
            _adapter: Dry-run host adapter.
            path: Independent staged configuration.
        """
        independent_calls.append(path)
        return AdapterResult(command=["independent", "apply"], dry_run=True)

    monkeypatch.setattr(SystemAdapter, "apply_traffic_publishing", fail_coupled)
    monkeypatch.setattr(SystemAdapter, "apply_wan_config", record_independent)
    monkeypatch.setattr(SystemAdapter, "apply_firewall_config", record_independent)
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
        assert payload["routing_publishing_pair"] is True
        assert payload["selected_units"].index("wan") < payload["selected_units"].index("firewall")
        assert job.status == "failed"
        assert len(coupled_calls) == 1
        assert independent_calls == []
        assert routing_permission_apply_state(db) == "pending"
