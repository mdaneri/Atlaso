"""Test Appliance Apply management UI transport behavior."""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from tests.routers.ui.helpers import login


@pytest.mark.parametrize("baseline_kind", ["missing", "legacy", "modern"])
@pytest.mark.parametrize("selection", ["wan", "nat"])
@pytest.mark.parametrize("invalid_network", [False, True])
def test_initial_wan_submission_includes_network_dependency(client, monkeypatch, baseline_kind, selection, invalid_network, handoff=False):
    """Expand fresh WAN dependencies before validation without coupling upgrades.

    Args:
        client: Isolated HTTP application fixture.
        monkeypatch: Keep jobs pending and inject controlled unit validation.
        baseline_kind: Saved Network baseline migration state.
        selection: Direct WAN selection or NAT that adds WAN transitively.
        invalid_network: Whether the Network dependency has a validation error.
        handoff: Whether Network requires the protected management transaction.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        baselines = ui.load_appliance_apply_baselines(db)
        baselines.pop("network", None)
        if baseline_kind != "missing":
            preview = "[physical_interfaces]\n"
            if baseline_kind == "modern":
                preview = "# Network runtime revision: exact-source-routing-v1.\n" + preview
            baselines["network"] = {"snapshot_hash": "prior-network", "config_preview": preview}
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()
        units = ui.appliance_apply_units(db)
        count_before = db.query(Job).count()
    for unit in units:
        if unit["id"] == "network":
            # Test the fresh dependency independently of NAT's changed-state rule.
            unit["changed"] = False
            unit["management_handoff_required"] = handoff
            unit["management_default_mirror_change"] = False
            unit["validation_errors"] = ["invalid Network dependency"] if invalid_network else []
        elif unit["id"] == "wan":
            unit["changed"] = True
            unit["validation_errors"] = []
        elif unit["id"] == "nat":
            unit["context"]["traffic_publishing_settings"] = SimpleNamespace(effective_nat_enabled=selection == "nat")
            unit["context"]["port_forward_effective"] = False
            unit["validation_errors"] = []
    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db: units)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": selection},
                           headers={"Accept": "application/json"})
    blocked = baseline_kind == "missing" and invalid_network
    assert response.status_code == (422 if blocked else 202)
    with SessionLocal() as db:
        assert db.query(Job).count() == count_before + (0 if blocked else 1)
        if not blocked:
            job = db.get(Job, response.json()["job_id"])
            payload = json.loads(job.result)
            selected = payload["selected_units"]
            assert payload["management_handoff"] is handoff
            if handoff:
                assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS).issubset(selected)
            assert ("network" in selected) is (baseline_kind == "missing")
            assert "wan" in selected
            if baseline_kind == "missing":
                assert selected.index("network") < selected.index("wan")


def test_initial_wan_dependency_expands_protected_management_handoff(client, monkeypatch):
    """Compute protected handoff after adding the initial Network dependency.

    Args:
        client: Isolated HTTP application fixture.
        monkeypatch: Replace host execution and the Network handoff requirement.
    """
    test_initial_wan_submission_includes_network_dependency(client, monkeypatch, "missing", "wan", False, handoff=True)


@pytest.mark.parametrize("baseline_kind", ["modern", "legacy", "missing"])
def test_wan_review_uses_applied_network_ingress_with_pending_network(client, baseline_kind):
    """Keep WAN-only selectors on applied intent and label combined Apply correctly.

    Args:
        client: Isolated application database fixture.
        baseline_kind: Applied Network migration state to project.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.routes_wan import save_routes_wan_settings

    with SessionLocal() as db:
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        baseline_preview = "[physical_interfaces]\ninterface=eth9\n  role=access\n  mode=access\n  admin_state=up\n"
        baseline_preview += "  ip_cidr=192.0.2.10/24\n  ipv6_enabled=true\n  ipv6_cidr=2001:db8:1::10/64\n"
        baseline_preview += "interface=eth8\n  role=route\n  mode=access\n  admin_state=down\n"
        baseline_preview += "interface=eth7\n  role=access\n  mode=trunk\n  admin_state=up\n"
        baseline_preview += "interface=eth6\n  role=management\n  mode=access\n  admin_state=up\n"
        if baseline_kind == "modern":
            baseline_preview = "# Network runtime revision: exact-source-routing-v1.\n" + baseline_preview
        baselines = ui.load_appliance_apply_baselines(db)
        baselines.pop("network", None)
        if baseline_kind != "missing":
            baselines["network"] = {"config_preview": baseline_preview, "snapshot_hash": "prior-network"}
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()
        page = ui.routes_wan_context(db)
        units = ui.appliance_apply_units(db)
        assert next(unit for unit in units if unit["id"] == "network")["changed"]
        wan = next(unit for unit in units if unit["id"] == "wan")
        candidate = wan["network_candidate_variant"]["config_preview"]
        candidate_names = set(ui.wan_network_ingress_from_preview(
            next(unit for unit in units if unit["id"] == "network")["config_preview"]
        ))
        candidate_commands = [line for line in candidate.splitlines() if "rule add iif " in line]
        assert len(candidate_commands) == 4 * len(candidate_names)
        assert {line.split(" iif ", 1)[1].split()[0] for line in candidate_commands} == candidate_names
        assert "candidate Network intent applied before WAN" in candidate
        for preview in (page["wan_config_preview"], wan["config_preview"]):
            commands = [line for line in preview.splitlines() if "rule add iif " in line]
            if baseline_kind == "missing":
                network = next(unit for unit in units if unit["id"] == "network")
                names = set(ui.wan_network_ingress_from_preview(network["config_preview"]))
                assert len(commands) == 4 * len(names)
                assert {line.split(" iif ", 1)[1].split()[0] for line in commands} == names
                assert "Initial WAN Apply automatically includes Network first" in preview
                assert "pre-migration baselines" not in preview
            else:
                assert len(commands) == (4 if baseline_kind == "modern" else 0)
                assert all(" iif eth9 " in line for line in commands)
                assert "not pending Network edits" in preview
                assert "If Network is applied first in the same task" in preview
                if baseline_kind == "modern":
                    assert "Connected routes and dedicated-management defaults are maintained by Network" in preview
                    assert "route replace 192.0.2.0/24" not in preview
                    assert "route del 192.0.2.0/24" not in preview
                    assert "route replace 2001:db8:1::/64" not in preview
                    assert "route del 2001:db8:1::/64" not in preview
                if baseline_kind == "legacy":
                    assert "pre-migration baselines retain legacy WAN handling" in preview


def test_combined_wan_rejects_candidate_ingress_over_capacity(client, monkeypatch):
    """Combined Apply refuses a newly enabled Routing window before Network runs.

    Args:
        client: Authenticated API test client.
        monkeypatch: Replace host execution with bounded test observations.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.routes_wan import save_routes_wan_settings

    login(client)
    with SessionLocal() as db:
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False,
                                 wan_simulation_enabled=False)
        monkeypatch.setattr(ui, "wan_network_ingress_from_preview",
                            lambda _preview: [f"lab{index}" for index in range(101)])
        units = ui.appliance_apply_units(db)
        wan = next(unit for unit in units if unit["id"] == "wan")
        combined = ui.appliance_apply_units_for_selection(units, {"network", "wan"})
        selected_wan = next(unit for unit in combined if unit["id"] == "wan")
        assert selected_wan is wan["network_candidate_variant"]
        assert any("ingress rule capacity" in error for error in selected_wan["validation_errors"])

    review = client.get("/appliance-apply/review")
    assert review.status_code == 200
    review_wan = next(unit for unit in review.json()["units"] if unit["id"] == "wan")
    assert review_wan["valid"] is True
    assert review_wan["network_candidate_valid"] is False
    assert review_wan["forces_network_selection"] is True
    assert any("ingress rule capacity" in error
               for error in review_wan["network_candidate_validation_errors"])


def test_network_only_rejects_ingress_over_applied_routing_capacity(client, monkeypatch):
    """Network alone cannot overflow the already-applied Routing window.

    Args:
        client: Authenticated API test client.
        monkeypatch: Replace candidate ingress with a bounded oversized set.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings

    login(client)
    with SessionLocal() as db:
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False,
                                 wan_simulation_enabled=False)
        applied = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, applied, {unit["id"] for unit in applied})
        interface = db.query(PhysicalInterface).first()
        assert interface is not None
        interface.mtu = 1400
        db.commit()
    monkeypatch.setattr(ui, "wan_network_ingress_from_preview",
                        lambda _preview: [f"lab{index}" for index in range(101)])
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        network = next(unit for unit in units if unit["id"] == "network")
        assert any("applied Routing & WAN ingress rule capacity" in error
                   for error in network["validation_errors"])
        selected = ui.appliance_apply_units_for_selection(units, {"network"})
        assert selected is units

    review = client.get("/appliance-apply/review")
    assert review.status_code == 200
    review_network = next(unit for unit in review.json()["units"] if unit["id"] == "network")
    assert review_network["valid"] is False
    assert any("applied Routing & WAN ingress rule capacity" in error
               for error in review_network["validation_errors"])
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        count_before = db.query(Job).count()
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 422, response.text
    with SessionLocal() as db:
        assert db.query(Job).count() == count_before


def test_fresh_wan_ingress_matches_helper_for_mixed_network_links(client, tmp_path):
    """Project active addressless links without admitting down or unused targets.

    Args:
        client: Isolated application database fixture.
        tmp_path: Owned test directory for the helper's read-only Network input.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings
    from tests.test_appliance_helper import load_helper_module

    with SessionLocal() as db:
        for interface in db.query(PhysicalInterface):
            interface.role = "unused"
        for vlan in db.query(VlanInterface):
            vlan.enabled = False
        for name, role, mode, state, address in [
            ("active", "access", "access", "up", "192.0.2.10/24"),
            ("dynamic", "route", "access", "up", ""),
            ("down", "access", "access", "down", "192.0.3.10/24"),
            ("unused", "unused", "access", "up", "192.0.4.10/24"),
            ("trunk", "access", "trunk", "up", ""),
            ("mgmt", "management", "access", "up", "192.0.5.10/24"),
        ]:
            db.add(PhysicalInterface(name=name, role=role, mode=mode, admin_state=state,
                                     mac_address="02:00:00:00:00:01", driver="vmxnet3", speed="1 Gbps",
                                     ipv4_method="static" if address else "dhcp", ip_cidr=address,
                                     ipv6_enabled=True))
        db.add(VlanInterface(name="trunk.42", parent_interface="trunk", vlan_id=42,
                             role="route", enabled=True, ip_cidr="", ipv6_cidr=""))
        db.add(VlanInterface(name="trunk.43", parent_interface="trunk", vlan_id=43,
                             role="access", enabled=False, ip_cidr="192.0.6.10/24"))
        baselines = ui.load_appliance_apply_baselines(db)
        baselines.pop("network", None)
        ui.save_appliance_apply_baselines(db, baselines)
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        db.commit()
        page = ui.routes_wan_context(db)
        units = ui.appliance_apply_units(db)
        network = next(unit for unit in units if unit["id"] == "network")
        config_path = tmp_path / "network.conf"
        config_path.write_text(network["config_preview"], encoding="utf-8")
        expected = load_helper_module()._route_domain_ingress_interfaces(config_path)
        assert expected == ["active", "dynamic", "trunk.42"]
        wan = next(unit for unit in units if unit["id"] == "wan")
        for preview in (page["wan_config_preview"], wan["config_preview"]):
            commands = [line for line in preview.splitlines() if "rule add iif " in line]
            assert len(commands) == 4 * len(expected)
            assert {line.split(" iif ", 1)[1].split()[0] for line in commands} == set(expected)
            assert "Initial WAN Apply automatically includes Network first" in preview


@pytest.mark.parametrize("apply_succeeds", [False, True])
def test_network_runtime_revision_requires_successful_upgrade_apply(client, monkeypatch, apply_succeeds):
    """Offer unchanged legacy Network intent until its revised runtime is applied.

    Args:
        client: Isolated application database fixture.
        monkeypatch: Replace only the privileged execution boundary.
        apply_succeeds: Whether the simulated Network execution succeeds.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    marker = "# Network runtime revision: exact-source-routing-v1.\n"
    with SessionLocal() as db:
        unit = next(item for item in ui.appliance_apply_units(db) if item["id"] == "network")
        assert marker in unit["config_preview"]
        legacy_preview = unit["config_preview"].replace(marker, "")
        legacy_hash = ui.appliance_snapshot_hash({
            "unit_id": "network", "summary": unit["summary"], "config_path": unit["config_path"],
            "config_preview": legacy_preview, "snapshot_marker": None,
        })
        legacy_unit = {**unit, "snapshot_hash": legacy_hash, "config_preview": legacy_preview}
        ui.update_appliance_apply_baselines(db, [legacy_unit], {"network"})
        db.add(Job(id="previous-apply", type="appliance-apply", status=JobStatus.SUCCEEDED.value,
                   created_by="admin", result="{}"))
        db.commit()
        context = ui.appliance_apply_context(db)
        assert context["initial_apply_required"] is False
        pending = next(item for item in context["review_apply_units"] if item["id"] == "network")
        assert pending["changed"] and pending["valid"] and pending["has_baseline"]
        assert pending["config_preview"].replace(marker, "") == legacy_preview
        assert pending["management_handoff_required"] is False
        job = Job(id="network-revision-upgrade", type="appliance-apply", status=JobStatus.PENDING.value,
                  created_by="admin", result=json.dumps({"selected_units": ["network"],
                  "captured_units": [{"unit_id": "network", "snapshot_hash": pending["snapshot_hash"]}]}))
        db.add(job)
        db.add(JobStep(id="network-revision-upgrade:network", job=job, component_key="network",
                       label="Network", position=1, status=JobStatus.PENDING.value, result="{}"))
        db.commit()

    executed = []

    def execute(candidate, **_kwargs):
        """Return a controlled result without executing host operations.

        Args:
            candidate: Real Network unit approved by the ordinary review flow.
            **_kwargs: Production execution options.
        """
        executed.append(candidate["snapshot_hash"])
        return {"unit_id": "network", "label": "Network", "success": apply_succeeds,
                "status": JobStatus.SUCCEEDED.value if apply_succeeds else JobStatus.FAILED.value,
                "dry_run": True, "commands": []}

    monkeypatch.setattr(ui, "execute_appliance_apply_unit", execute)
    ui.run_appliance_apply_job("network-revision-upgrade")
    assert executed == [unit["snapshot_hash"]]
    with SessionLocal() as db:
        completed = db.get(Job, "network-revision-upgrade")
        assert completed.status == (JobStatus.SUCCEEDED.value if apply_succeeds else JobStatus.FAILED.value)
        baseline = ui.load_appliance_apply_baselines(db)["network"]
        assert baseline["snapshot_hash"] == (unit["snapshot_hash"] if apply_succeeds else legacy_hash)
        assert baseline["config_preview"] == (unit["config_preview"] if apply_succeeds else legacy_preview)
        context = ui.appliance_apply_context(db)
        assert any(item["id"] == "network" for item in context["review_apply_units"]) is (not apply_succeeds)
        current = next(item for item in context["apply_units"] if item["id"] == "network")
        assert current["changed"] is (not apply_succeeds)


@pytest.mark.parametrize("enabled_default", [False, True])
def test_legacy_flagged_default_network_revision_couples_wan_handoff(client, monkeypatch, enabled_default):
    """A Network-only migration preserves the flagged listener's off-subnet reply route.

    Args:
        client: Authenticated test client.
        monkeypatch: Pytest fixture replacing external dependencies.
        enabled_default: Whether the default route is enabled.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route

    login(client)
    marker = "# Network runtime revision: exact-source-routing-v1.\n"
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.10/24"
        interface.access_management_ui_enabled = True
        db.add(Route(destination_cidr="0.0.0.0/0", gateway="192.168.50.1",
                     interface_name="eth2", enabled=enabled_default))
        db.commit()
        units = ui.appliance_apply_units(db)
        assert not next(unit for unit in units if unit["id"] == "network")["management_domain_migration_required"]
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = ui.load_appliance_apply_baselines(db)
        assert marker in baselines["network"]["config_preview"]
        baselines["network"]["config_preview"] = baselines["network"]["config_preview"].replace(marker, "")
        baselines["network"]["snapshot_hash"] = "legacy-network-revision"
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()
        refreshed = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert refreshed["network"]["changed"]
        assert not refreshed["network"]["management_handoff_required"]
        assert refreshed["network"]["management_domain_migration_required"] is enabled_default

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        payload = json.loads(db.get(Job, response.json()["job_id"]).result)
    assert payload["management_handoff"] is enabled_default
    if enabled_default:
        assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) | {"wan"} <= set(payload["management_handoff_units"])
        assert "wan" in payload["selected_units"]
    else:
        assert "wan" not in payload["selected_units"]


@pytest.mark.parametrize("commit_fails", [False, True])
@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_network_apply_acknowledges_only_durable_executed_baseline(client, monkeypatch, commit_fails, cleanup_fails):
    """Bind runtime acknowledgement to the executed snapshot and database commit.

    Args:
        client: Isolated application database fixture.
        monkeypatch: Replace host operations and inject the commit failure.
        commit_fails: Fail the baseline transaction after its flag was assigned.
        cleanup_fails: Inject a transient post-commit helper failure.
    """
    from sqlalchemy.orm import Session

    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    unit = {
        "id": "network", "label": "Network", "snapshot_hash": "executed",
        "summary": [], "validation_errors": [], "validation_warnings": [],
        "config_path": "/etc/atlaso/network.conf", "config_preview": "executed\n", "config_diff": "",
    }
    with SessionLocal() as db:
        job = Job(id="network-commit-test", type="appliance-apply", status=JobStatus.PENDING.value,
                  created_by="admin", result=json.dumps({"selected_units": ["network"],
                  "captured_units": [{"unit_id": "network", "snapshot_hash": "executed"}]}))
        db.add(job)
        db.add(JobStep(id="network-commit-test:network", job=job, component_key="network", label="Network",
                       position=1, status=JobStatus.PENDING.value, result="{}"))
        db.commit()

    executed = False
    acknowledgements = []

    class Adapter:
        """Inspect the committed database before allowing helper acknowledgement."""

        dry_run = False

        def __init__(self, **_kwargs):
            """Accept production options.

            Args:
                **_kwargs: Unused host adapter configuration.
            """

        def reconcile_network_transaction(self, job_id, *, committed=False):
            """Read durable evidence in a separate database session.

            Args:
                job_id: Transaction-owning task.
                committed: Requested helper disposition.
            """
            with SessionLocal() as verify_db:
                payload = json.loads(verify_db.get(Job, job_id).result)
                baseline = ui.load_appliance_apply_baselines(verify_db).get("network", {})
                assert payload["network_application_committed"] is committed
                assert (baseline.get("snapshot_hash") == "executed") is committed
            acknowledgements.append(committed)
            return AdapterResult(command=["network", "reconcile"],
                                 returncode=2 if cleanup_fails and len(acknowledgements) == 1 else 0,
                                 dry_run=False)

    def execute(candidate, **_kwargs):
        """Verify pending ownership was persisted before host mutation.

        Args:
            candidate: Captured Network intent with task binding.
            **_kwargs: Production execution options.
        """
        nonlocal executed
        assert candidate["network_transaction_job_id"] == "network-commit-test"
        with SessionLocal() as verify_db:
            payload = json.loads(verify_db.get(Job, "network-commit-test").result)
            assert payload["network_runtime_commit_pending"] is True
            assert payload["network_application_committed"] is False
        executed = True
        return {**unit, "unit_id": "network", "success": True,
                "status": JobStatus.SUCCEEDED.value, "dry_run": False, "commands": []}

    original_commit = Session.commit
    injected = False

    def commit(db):
        """Fail only the transaction attempting to record the applied baseline.

        Args:
            db: Active database session.
        """
        nonlocal injected
        if commit_fails and not injected:
            for item in db.dirty:
                if isinstance(item, Job) and json.loads(item.result).get("network_application_committed") is True:
                    injected = True
                    raise RuntimeError("injected baseline commit failure")
        return original_commit(db)

    monkeypatch.setattr(ui, "SystemAdapter", Adapter)
    monkeypatch.setattr(ui, "execute_appliance_apply_unit", execute)
    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: [
        {**unit, "snapshot_hash": "newer-desired", "config_preview": "newer\n"} if executed else unit,
    ])
    monkeypatch.setattr(Session, "commit", commit)
    ui.run_appliance_apply_job("network-commit-test")
    assert acknowledgements == [not commit_fails]
    assert injected is commit_fails
    with SessionLocal() as db:
        completed = db.get(Job, "network-commit-test")
        if cleanup_fails:
            assert completed.status == JobStatus.RUNNING.value
            assert ui.active_appliance_apply_job(db).id == completed.id
            assert ui.retry_network_transaction_cleanup(db) == 1
            assert acknowledgements == [not commit_fails, not commit_fails]
            baseline = ui.load_appliance_apply_baselines(db).get("network", {})
            assert (baseline.get("snapshot_hash") == "executed") is (not commit_fails)
            assert ui.active_appliance_apply_job(db) is None
        assert completed.status == (JobStatus.FAILED.value if commit_fails or cleanup_fails else JobStatus.SUCCEEDED.value)
        assert json.loads(completed.result)["network_runtime_commit_pending"] is False


def test_interrupted_network_apply_uses_durable_application_commit(client, monkeypatch):
    """Recover uncommitted work, acknowledge committed work, and retain failed ownership.

    Args:
        client: Isolated application database fixture.
        monkeypatch: Replace privileged recovery calls with recorded results.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    calls = []

    class RecoveryAdapter:
        """Record whether the database committed the executed candidate."""

        def __init__(self, **_kwargs):
            """Accept adapter configuration.

            Args:
                **_kwargs: Production options unused by this recorder.
            """

        def reconcile_network_transaction(self, job_id, *, committed=False):
            """Return success except when the original helper still owns its lock.

            Args:
                job_id: Exact task owning the helper marker.
                committed: Whether its executed baseline is durable.
            """
            calls.append((job_id, committed))
            return AdapterResult(command=["network", "reconcile", job_id], dry_run=False,
                                 returncode=2 if job_id == "network-busy" else 0)

    monkeypatch.setattr(ui, "SystemAdapter", RecoveryAdapter)
    with SessionLocal() as db:
        for name, committed in (("network-interrupted", False), ("network-committed", True), ("network-busy", False)):
            db.add(Job(id=name, type="appliance-apply", status=JobStatus.FAILED.value, created_by="admin",
                       result=json.dumps({"network_runtime_commit_pending": True,
                                          "network_application_committed": committed})))
        db.commit()
        assert ui.active_appliance_apply_job(db) is not None
        assert ui.recover_interrupted_appliance_apply_jobs(db) == 3
        assert set(calls) == {("network-interrupted", False), ("network-committed", True), ("network-busy", False)}
        for name in ("network-interrupted", "network-committed"):
            assert json.loads(db.get(Job, name).result)["network_runtime_commit_pending"] is False
        busy = db.get(Job, "network-busy")
        assert busy.status == JobStatus.RUNNING.value
        assert json.loads(busy.result)["network_runtime_commit_pending"] is True
        assert ui.active_appliance_apply_job(db).id == "network-busy"


@pytest.mark.parametrize("committed", [False, True])
def test_network_cleanup_worker_retries_without_restart(client, monkeypatch, committed):
    """Release abandoned ownership only after helper recovery succeeds.

    Args:
        client: Application database fixture.
        monkeypatch: Substitute a transiently unavailable helper.
        committed: Durable candidate commit authority, independent of step status.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    calls = []

    class Adapter:
        """Fail the first cleanup pass and succeed on the next worker cycle."""

        def __init__(self, **_kwargs):
            """Accept production options.

            Args:
                **_kwargs: Unused host options.
            """

        def reconcile_network_transaction(self, job_id, *, committed=False):
            """Record exact persisted disposition on every retry.

            Args:
                job_id: Transaction owner.
                committed: Durable application commit flag.
            """
            calls.append((job_id, committed))
            return AdapterResult(command=["network", "reconcile"], dry_run=False,
                                 returncode=2 if len(calls) == 1 else 0)

    monkeypatch.setattr(ui, "SystemAdapter", Adapter)
    with SessionLocal() as db:
        job = Job(id="cleanup-retry", type="appliance-apply", status=JobStatus.RUNNING.value, created_by="admin",
                  result=json.dumps({"state": "running", "network_runtime_commit_pending": True,
                                     "network_application_committed": committed}))
        db.add(job)
        db.add(JobStep(id="cleanup-retry:remaining", job=job, component_key="dns", label="DNS",
                       position=2, status=JobStatus.PENDING.value, result="{}"))
        db.commit()
        assert ui.retry_network_transaction_cleanup(db) == 0
        assert calls == []  # The worker must never reconcile a live Apply runner.
        payload = json.loads(job.result)
        payload["state"] = "cleanup-required"
        job.result = json.dumps(payload)
        db.commit()
        assert ui.retry_network_transaction_cleanup(db) == 0
        assert ui.active_appliance_apply_job(db).id == job.id
        assert json.loads(job.result)["network_runtime_commit_pending"] is True
        assert job.finished_at is None
        from sqlalchemy import select

        from atlaso.app.models import TaskLogChunk

        chunks = db.scalars(select(TaskLogChunk).where(TaskLogChunk.job_id == job.id)).all()
        assert any("network_transaction_recovery" in chunk.content for chunk in chunks)
        assert ui.retry_network_transaction_cleanup(db) == 1
        assert calls == [(job.id, committed), (job.id, committed)]
        assert json.loads(job.result)["network_runtime_commit_pending"] is False
        assert json.loads(job.result)["network_application_committed"] is committed
        assert job.status == JobStatus.FAILED.value
        assert job.steps[0].status == "skipped"
        assert ui.active_appliance_apply_job(db) is None
        assert ui.retry_network_transaction_cleanup(db) == 0
        assert len(calls) == 2


def test_management_path_signature_covers_dedicated_and_flagged_access_transitions():
    """Detect every supported management-listener topology change."""
    from atlaso.app.ui import management_handoff_required, network_management_paths

    dedicated = """[physical_interfaces]
interface=eth0
  role=management
  mode=access
  admin_state=up
  ipv4_method=static
  ip_cidr=192.0.2.10/24
  gateway=192.0.2.1
interface=eth1
  role=access
  mode=access
  admin_state=up
  access_management_ui_enabled=false
  ip_cidr=198.51.100.10/24
"""
    flagged = dedicated.replace("role=management", "role=access", 1).replace(
        "access_management_ui_enabled=false",
        "access_management_ui_enabled=true",
    )

    assert network_management_paths(dedicated) == [
        {
            "kind": "physical",
            "name": "eth0",
            "parent": "",
            "parent_admin_state": "",
            "check_duplicate_ip_addresses": "false",
            "role": "management",
            "mtu": "",
            "ipv4_method": "static",
            "ip_cidr": "192.0.2.10/24",
            "gateway": "192.0.2.1",
            "ipv6_enabled": "",
            "ipv6_cidr": "",
            "ipv6_gateway": "",
        }
    ]
    assert network_management_paths(flagged) == [
        {
            "kind": "physical",
            "name": "eth1",
            "parent": "",
            "parent_admin_state": "",
            "check_duplicate_ip_addresses": "false",
            "role": "access",
            "mtu": "",
            "ipv4_method": "",
            "ip_cidr": "198.51.100.10/24",
            "gateway": "",
            "ipv6_enabled": "",
            "ipv6_cidr": "",
            "ipv6_gateway": "",
        }
    ]
    assert management_handoff_required(
        {"raw_config_preview": flagged},
        {"config_preview": dedicated},
    )
    assert not management_handoff_required(
        {"raw_config_preview": dedicated},
        {"config_preview": dedicated},
    )
    checked = dedicated.replace("role=management", "role=management\n  check_duplicate_ip_addresses=true")
    assert network_management_paths(checked)[0]["check_duplicate_ip_addresses"] == "true"
    assert management_handoff_required(
        {"raw_config_preview": checked}, {"config_preview": dedicated},
    )


def test_management_gateway_route_migration_couples_only_unapplied_default():
    """Detect the exact default route created from a removed management gateway."""
    from atlaso.app.ui import (
        management_gateway_route_migrations,
        wan_rollback_config_preview,
    )

    previous_network = """[physical_interfaces]
interface=eth0
role=management
mode=access
admin_state=up
ipv4_method=static
ip_cidr=192.0.2.10/24
gateway=192.0.2.1
ipv6_enabled=false
ipv6_cidr=
ipv6_gateway=
"""
    candidate_network = previous_network.replace(
        "role=management", "role=access"
    ).replace(
        "gateway=192.0.2.1",
        "gateway=\naccess_management_ui_enabled=true",
    )
    previous_wan = """[targets]
target=eth0
role=access
ip_cidr=192.0.2.10/24
management_ui=false
[routes]
[removed_routes]
[routing_rules]
[nat_rules]
[wan_policies]
"""
    candidate_wan = previous_wan.replace(
        "management_ui=false",
        "management_ui=true",
    ).replace(
        "[routes]",
        "[routes]\nroute=0.0.0.0/0\ngateway=192.0.2.1\ninterface=eth0\nmetric=100\nenabled=true",
    )
    migrations = management_gateway_route_migrations(
        {"raw_config_preview": candidate_network},
        {"config_preview": previous_network},
        {"raw_config_preview": candidate_wan},
        {"config_preview": previous_wan},
    )

    assert migrations == [
        {
            "family": "4",
            "destination_cidr": "0.0.0.0/0",
            "gateway": "192.0.2.1",
            "interface": "eth0",
        }
    ]
    assert management_gateway_route_migrations(
        {
            "raw_config_preview": candidate_network.replace(
                "access_management_ui_enabled=true",
                "access_management_ui_enabled=false",
            )
        },
        {"config_preview": previous_network},
        {"raw_config_preview": candidate_wan},
        {"config_preview": previous_wan},
    ) == migrations
    rollback = wan_rollback_config_preview(
        candidate_wan, {"config_preview": previous_wan}
    )
    assert "[removed_routes]" in rollback
    assert "route=0.0.0.0/0" in rollback
    assert "interface=eth0" in rollback
    assert "[removed_main_defaults]" in rollback
    assert "route=0.0.0.0/0" in rollback
    assert (
        management_gateway_route_migrations(
            {"raw_config_preview": candidate_network},
            {"config_preview": previous_network},
            {"raw_config_preview": candidate_wan},
            {"config_preview": candidate_wan},
        )
        == []
    )


def test_wan_rollback_removes_new_mirror_without_removing_retained_lab_route():
    """Encode host-only cleanup when an existing lab default becomes mirrored."""
    from atlaso.app.ui import wan_rollback_config_preview

    baseline = """[targets]
target=eth0
role=access
ip_cidr=192.0.2.10/24
management_ui=false
[routes]
route=0.0.0.0/0
gateway=192.0.2.1
interface=eth0
metric=100
enabled=true
[removed_routes]
[routing_rules]
[nat_rules]
[wan_policies]
"""
    candidate = baseline.replace("management_ui=false", "management_ui=true")

    rollback = wan_rollback_config_preview(
        candidate,
        {"config_preview": baseline},
    )

    assert rollback.count("route=0.0.0.0/0") == 2
    assert "[removed_routes]" in rollback
    assert "[removed_main_defaults]" in rollback


def test_wan_rollback_removes_superseded_mirrored_default_metric():
    """Encode the exact candidate metric variant before restoring the baseline."""
    from atlaso.app.ui import wan_rollback_config_preview

    baseline = """[targets]
target=eth0
role=access
ip_cidr=192.0.2.10/24
management_ui=true
[routes]
route=0.0.0.0/0
gateway=192.0.2.1
interface=eth0
metric=100
enabled=true
[removed_routes]
[routing_rules]
[nat_rules]
[wan_policies]
"""
    candidate = baseline.replace("metric=100", "metric=50")

    rollback = wan_rollback_config_preview(
        candidate,
        {"config_preview": baseline},
    )

    cleanup = rollback.split("[removed_main_defaults]", 1)[1]
    assert "route=0.0.0.0/0" in cleanup
    assert "gateway=192.0.2.1" in cleanup
    assert "interface=eth0" in cleanup
    assert "metric=50" in cleanup


def test_appliance_settings_stages_flagged_access_resolver_interface(client):
    """Bind resolver staging to the effective flagged-access listener.

    Args:
        client: HTTP test client used to initialize an isolated database.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "198.51.100.10/24"
        interface.access_management_ui_enabled = True
        db.commit()

        context = ui.appliance_settings_context(db, reconcile_dns=False)

    preview = json.loads(context["appliance_settings_config_preview"])
    assert context["management_interface"]["name"] == "eth0"
    assert preview["management_interface"] == "eth0"
    assert preview["management_ip"] == "198.51.100.10"


def test_appliance_settings_uses_last_applied_dns_state_for_resolver(client):
    """Keep loopback DNS pending until the DNS/DHCP unit is applied.

    Args:
        client: HTTP test client used to initialize an isolated database.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings

    assert ui.applied_local_dns_enabled({"summary": ["DNS enabled"]}) is True
    assert ui.applied_local_dns_enabled({"summary": ["DNS disabled"]}) is False

    with SessionLocal() as db:
        dns_settings = db.query(DnsSettings).one()
        dns_settings.enabled = True
        db.commit()
        ui.save_appliance_apply_baselines(
            db,
            {"dnsmasq": {"summary": ["DNS disabled"], "dns_enabled": False}},
        )
        db.commit()

        pending_context = ui.appliance_settings_context(db, reconcile_dns=False)
        pending_preview = json.loads(pending_context["appliance_settings_config_preview"])
        assert pending_context["local_dns_enabled"] is False
        assert pending_preview["resolver_mode"] != "local_dns"
        assert pending_preview["resolver_servers"] != ["127.0.0.1"]

        ui.save_appliance_apply_baselines(
            db,
            {"dnsmasq": {"summary": ["DNS enabled"], "dns_enabled": True}},
        )
        db.commit()
        applied_context = ui.appliance_settings_context(db, reconcile_dns=False)
        applied_preview = json.loads(applied_context["appliance_settings_config_preview"])
        assert applied_context["local_dns_enabled"] is True
        assert applied_preview["resolver_mode"] == "local_dns"
        assert applied_preview["resolver_servers"] == ["127.0.0.1"]

        dns_settings.enabled = False
        db.commit()
        disabling_context = ui.appliance_settings_context(db, reconcile_dns=False)
        disabling_preview = json.loads(disabling_context["appliance_settings_config_preview"])

    assert disabling_context["local_dns_enabled"] is False
    assert disabling_preview["resolver_mode"] != "local_dns"
    assert disabling_preview["resolver_servers"] != ["127.0.0.1"]


def test_pending_dhcp_management_does_not_require_external_dns(client):
    """Keep pending dedicated DHCP resolver ahead of a usable Access fallback.

    Args:
        client: Authenticated test client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsSettings, PhysicalInterface

    with SessionLocal() as db:
        interface = db.query(PhysicalInterface).filter_by(name="eth0").one()
        settings = db.query(ApplianceSettings).one()
        dns = db.query(DnsSettings).one()
        interface.role = "management"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "dhcp"
        interface.ip_cidr = None
        interface.host_ip_cidr = None
        fallback = db.query(PhysicalInterface).filter_by(name="eth1").one_or_none()
        if fallback is None:
            fallback = PhysicalInterface(name="eth1", mac_address="02:00:00:00:00:02")
            db.add(fallback)
        fallback.role = "access"
        fallback.mode = "access"
        fallback.admin_state = "up"
        fallback.oper_state = "up"
        fallback.ip_cidr = "192.0.2.25/24"
        fallback.access_management_ui_enabled = True
        settings.web_terminal_enabled = True
        settings.management_https_enabled = True
        settings.external_dns_servers = ""
        dns.enabled = False
        db.commit()

        context = ui.appliance_settings_context(db, reconcile_dns=False)

    assert context["management_interface"]["name"] == "eth0"
    assert context["management_interface"]["ip"] == ""
    assert context["appliance_settings_resolver_mode"] == "dhcp"
    preview = json.loads(context["appliance_settings_config_preview"])
    assert preview["management_interface"] == "eth0"
    assert preview["resolver_mode"] == "dhcp"
    assert not any(
        error.startswith("External DNS servers are required")
        for error in context["appliance_settings_validation_errors"]
    )
    assert not any(
        error.startswith("Web terminal interfaces are unavailable or have no address: eth0")
        for error in context["appliance_settings_validation_errors"]
    )



def test_local_dns_enable_applies_listener_before_host_resolver(client):
    """Require explicit Settings selection before activating the resolver.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, Job

    login(client)
    with SessionLocal() as db:
        dns = db.query(DnsSettings).one()
        dns.enabled = False
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.add(Job(id="dns-enable-previous-apply", type="appliance-apply", status="succeeded", created_by="admin"))
        dns.enabled = True
        db.commit()
    review = client.get("/appliance-apply/review")
    assert review.status_code == 200
    settings_review = next(unit for unit in review.json()["units"] if unit["id"] == "appliance_settings")
    assert settings_review["requires_dns_selection"] is True
    assert json.loads(settings_review["config_preview"])["resolver_servers"] == ["127.0.0.1"]
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "dnsmasq"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 422
    assert "Select Appliance Settings" in response.json()["detail"]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": ["dnsmasq", "appliance_settings"]},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        payload = json.loads(job.result)
        assert payload["selected_units"] == ["dnsmasq", "appliance_settings"]
        settings = next(unit for unit in payload["captured_units"] if unit["unit_id"] == "appliance_settings")
        assert json.loads(settings["config_preview"])["resolver_servers"] == ["127.0.0.1"]


@pytest.mark.parametrize("previous_apply", [False, True])
def test_dns_activation_review_projects_local_resolver_for_existing_settings_row(client, previous_apply):
    """Initial and independently changed Settings rows show the executed resolver preview.

    Args:
        client: Isolated client for this scenario.
        previous_apply: Whether Appliance Settings was previously applied.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsSettings, Job

    login(client)
    with SessionLocal() as db:
        dns = db.query(DnsSettings).one()
        dns.enabled = False
        db.commit()
        if previous_apply:
            units = ui.appliance_apply_units(db)
            ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
            db.add(Job(id="dns-review-previous-apply", type="appliance-apply", status="succeeded", created_by="admin"))
        dns.enabled = True
        if previous_apply:
            settings = db.query(ApplianceSettings).one()
            settings.root_ssh_enabled = not settings.root_ssh_enabled
        db.commit()

    review = client.get("/appliance-apply/review")
    assert review.status_code == 200
    settings_rows = [unit for unit in review.json()["units"] if unit["id"] == "appliance_settings"]
    assert len(settings_rows) == 1
    assert json.loads(settings_rows[0]["config_preview"])["resolver_servers"] == ["127.0.0.1"]
    assert settings_rows[0]["requires_dns_selection"] is False

    if previous_apply:
        csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        response = client.post(
            "/appliance-apply",
            data={"csrf": csrf, "selected_units": ["dnsmasq", "appliance_settings"]},
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 202
        with SessionLocal() as db:
            job = db.get(Job, response.json()["job_id"])
            captured = next(unit for unit in json.loads(job.result)["captured_units"] if unit["unit_id"] == "appliance_settings")
            assert captured["config_preview"] == settings_rows[0]["config_preview"]


def test_dns_change_keeps_unrelated_settings_pending_when_resolver_is_already_local(
    client,
):
    """Do not expand an ordinary DNS apply after local resolver activation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsSettings, Job

    login(client)
    with SessionLocal() as db:
        dns = db.query(DnsSettings).one()
        dns.enabled = True
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()

        settings = db.query(ApplianceSettings).one()
        settings.root_ssh_enabled = not settings.root_ssh_enabled
        dns.cache_size = int(dns.cache_size or 1000) + 1
        db.commit()

    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "dnsmasq"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["selected_units"] == ["dnsmasq"]


@pytest.mark.parametrize("ca_changed", [False, True])
def test_management_https_applies_pending_ca_before_settings(client, monkeypatch, ca_changed):
    """HTTPS activation installs its certificate even if CA preview is unchanged.

    Args:
        client: Isolated client for this scenario.
        monkeypatch: Replace external behavior for this scenario.
        ca_changed: Whether the CA unit has pending changes.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaSettings, Job

    login(client)
    with SessionLocal() as db:
        settings = db.query(ApplianceSettings).one()
        db.query(CaSettings).one().enabled = True
        db.commit()
        baseline_units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, baseline_units, {unit["id"] for unit in baseline_units})
        settings.management_https_enabled = True
        db.commit()
        ui.ca_context(db)
    real_units = ui.appliance_apply_units

    def units_with_pending_ca(db, *, reconcile=True, applying_dns=False):
        """Units with pending ca.

        Args:
            db: Current database session.
            reconcile: Whether to reconcile current inventory.
            applying_dns: Whether DNS is included in the apply selection.
        """
        units = real_units(db, reconcile=reconcile, applying_dns=applying_dns)
        next(unit for unit in units if unit["id"] == "ca")["changed"] = ca_changed
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", units_with_pending_ca)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "appliance_settings"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        selected = json.loads(job.result or "{}")["selected_units"]
    assert selected.index("ca") < selected.index("appliance_settings")


def test_applied_https_does_not_reselect_unrelated_pending_ca(client, monkeypatch):
    """A later Settings edit must honor an operator's unchecked CA row.

    Args:
        client: Isolated client for this scenario.
        monkeypatch: Replace external behavior for this scenario.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaSettings, Job

    login(client)
    with SessionLocal() as db:
        settings = db.query(ApplianceSettings).one()
        settings.management_https_enabled = True
        db.query(CaSettings).one().enabled = True
        db.commit()
        ui.ca_context(db)
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        settings.root_ssh_enabled = not settings.root_ssh_enabled
        db.commit()

    real_units = ui.appliance_apply_units

    def units_with_pending_ca(db, *, reconcile=True, applying_dns=False):
        """Units with pending ca.

        Args:
            db: Current database session.
            reconcile: Whether to reconcile current inventory.
            applying_dns: Whether DNS is included in the apply selection.
        """
        units = real_units(db, reconcile=reconcile, applying_dns=applying_dns)
        ca_unit = next(unit for unit in units if unit["id"] == "ca")
        ca_preview = json.loads(ca_unit["config_preview"])
        management_certificate = next(
            certificate for certificate in ca_preview["certificates"]
            if certificate.get("managed_owner") == "appliance:https"
        )
        management_certificate["fingerprint"] = "replacement-ca-leaf"
        ca_unit["config_preview"] = json.dumps(ca_preview)
        ca_unit["changed"] = True
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", units_with_pending_ca)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "appliance_settings"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        selected = json.loads(job.result or "{}")["selected_units"]
    assert "ca" not in selected


def test_management_https_hostname_change_applies_new_ca_certificate_first(client, monkeypatch):
    """An already-enabled HTTPS listener still needs its newly issued certificate installed first.

    Args:
        client: Isolated client for this scenario.
        monkeypatch: Replace external behavior for this scenario.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaSettings, Job

    login(client)
    with SessionLocal() as db:
        settings = db.query(ApplianceSettings).one()
        settings.management_https_enabled = True
        db.query(CaSettings).one().enabled = True
        db.commit()
        ui.ca_context(db)
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        settings.fqdn = "new-management.atlaso.internal"
        db.commit()
        ui.ca_context(db)

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "appliance_settings"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        selected = json.loads(job.result or "{}")["selected_units"]
    assert selected.index("ca") < selected.index("appliance_settings")


def test_local_dns_disable_forces_resolver_move_before_dns_stop(client):
    """Move the resolver before an applied local DNS listener is disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, Job
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        dns_settings = db.query(DnsSettings).one()
        dns_settings.enabled = True
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"appliance_settings"})
        dns_settings.enabled = False
        db.commit()
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["dnsmasq", "appliance_settings"]},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["selected_units"] == ["appliance_settings", "dnsmasq"]
    assert [unit["unit_id"] for unit in payload["captured_units"]] == [
        "appliance_settings",
        "dnsmasq",
    ]


def test_local_dns_disable_retry_accepts_already_applied_external_resolver(client):
    """A failed DNS step can retry after Settings committed the resolver move.

    Args:
        client: Isolated client for this scenario.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, Job
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        dns_settings = db.query(DnsSettings).one()
        dns_settings.enabled = True
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        dns_settings.enabled = False
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"appliance_settings"})
        db.commit()
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "dnsmasq"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["selected_units"] == ["dnsmasq"]


def test_management_handoff_keeps_dns_shutdown_after_resolver_move(client):
    """Bundle local DNS shutdown with a protected management-address change.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, Job, PhysicalInterface
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        dns_settings = db.query(DnsSettings).one()
        dns_settings.enabled = True
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.22/24"
        dns_settings.enabled = False
        db.commit()
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network", "dnsmasq", "appliance_settings"]},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert "dnsmasq" in payload["management_handoff_units"]
    assert payload["selected_units"].index("appliance_settings") < payload["selected_units"].index("dnsmasq")


def test_management_handoff_leaves_unselected_dns_record_pending(client, monkeypatch):
    """A Network handoff must not submit a separately staged DNS record.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to isolate background execution.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, DnsSettings, Job, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        dns_settings = db.query(DnsSettings).one()
        dns_settings.enabled = True
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.22/24"
        db.add(DnsRecord(hostname="pending.atlaso.internal", record_type="A", address="192.168.12.44"))
        db.commit()
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
        pending = next(unit for unit in ui.appliance_apply_units(db) if unit["id"] == "dnsmasq")
    assert payload["management_handoff"] is True
    assert "dnsmasq" not in payload["selected_units"]
    assert "dnsmasq" not in payload["management_handoff_units"]
    assert "dnsmasq" in {unit["unit_id"] for unit in payload["skipped_changed_units"]}
    assert pending["changed"] is True


def test_ldap_dependency_dns_disable_includes_resolver_move(client, monkeypatch):
    """Move the resolver when LDAP dependency expansion selects DNS shutdown.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to isolate background execution.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, Job

    login(client)
    with SessionLocal() as db:
        dns = db.query(DnsSettings).one()
        dns.enabled = True
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        dns.enabled = False
        db.commit()

    real_units = ui.appliance_apply_units

    def units_with_ldap_dependency(db, **kwargs):
        """Mark LDAP active so its changed DNS dependency is selected.

        Args:
            db: Active database session used to build apply units.
            **kwargs: Additional appliance apply unit options.
        """
        units = real_units(db, **kwargs)
        unit_map = {unit["id"]: unit for unit in units}
        unit_map["ldap"]["context"]["ldap_organizations"] = [object()]
        unit_map["ldap"]["changed"] = True
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", units_with_ldap_dependency)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["ldap", "appliance_settings"]},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert "dnsmasq" in payload["selected_units"]
    assert payload["selected_units"].index("appliance_settings") < payload["selected_units"].index("dnsmasq")
    settings = next(
        unit
        for unit in payload["captured_units"]
        if unit["unit_id"] == "appliance_settings"
    )
    assert json.loads(settings["config_preview"])["resolver_servers"] != ["127.0.0.1"]


def test_management_handoff_fails_closed_without_network_baseline():
    """Require the handoff path when no known-good baseline can identify the old listener."""
    from atlaso.app.ui import management_handoff_required

    network_unit = {
        "raw_config_preview": """[physical_interfaces]
interface=eth1
  role=management
  mode=access
  admin_state=up
  ipv4_method=static
  ip_cidr=198.51.100.10/24
"""
    }

    assert management_handoff_required(network_unit, None)


def test_management_handoff_detects_ipv6_router_advertisement_toggle():
    """Treat SLAAC enablement as a management listener topology change."""
    from atlaso.app.ui import management_handoff_required

    previous = """[physical_interfaces]
interface=eth0
  role=management
  mode=access
  admin_state=up
  ipv4_method=static
  ip_cidr=192.0.2.10/24
  ipv6_enabled=false
"""
    candidate = previous.replace("ipv6_enabled=false", "ipv6_enabled=true")

    assert management_handoff_required(
        {"raw_config_preview": candidate},
        {"config_preview": previous},
    )


def test_management_handoff_detects_flagged_access_vlan_mtu_change():
    """Treat a management-listener VLAN MTU change as a handoff boundary."""
    from atlaso.app.ui import management_handoff_required, network_management_paths

    previous = """[vlan_interfaces]
vlan=eth1.20
  parent=eth1
  role=access
  admin_state=up
  access_management_ui_enabled=true
  mtu=1500
  ipv4_method=static
  ip_cidr=192.0.2.20/24
"""
    candidate = previous.replace("mtu=1500", "mtu=9000")

    assert management_handoff_required(
        {"raw_config_preview": candidate},
        {"config_preview": previous},
    )

    assert network_management_paths(previous.replace("admin_state=up", "enabled=false")) == []


def test_management_handoff_detects_flagged_access_vlan_parent_admin_down():
    """Protect a management VLAN when its trunk parent is disabled."""
    from atlaso.app.ui import management_handoff_required, network_management_paths

    previous = """[physical_interfaces]
interface=eth1
  role=access
  mode=trunk
  admin_state=up
[vlan_interfaces]
vlan=eth1.20
  parent=eth1
  role=access
  admin_state=up
  access_management_ui_enabled=true
  mtu=1500
  ipv4_method=static
  ip_cidr=192.0.2.20/24
"""
    candidate = previous.replace("admin_state=up", "admin_state=down", 1)

    previous_paths = network_management_paths(previous)
    candidate_paths = network_management_paths(candidate)
    assert previous_paths[0]["parent_admin_state"] == "up"
    assert candidate_paths[0]["parent_admin_state"] == "down"
    assert management_handoff_required(
        {"raw_config_preview": candidate},
        {"config_preview": previous},
    )


@pytest.mark.parametrize("failure_target", ["ca", "manifest"])
def test_management_handoff_staging_failure_removes_private_ca_payload(
    monkeypatch,
    tmp_path,
    failure_target,
):
    """Remove the transient private-key payload on every staging failure.

    Args:
        monkeypatch: Pytest fixture used to inject the staging failure.
        tmp_path: Temporary root containing the secret and manifest payloads.
        failure_target: Staging operation that fails after the CA file is written.
    """
    from atlaso.app import ui

    class UnusedAdapter:
        """Reject helper calls because staging must fail first."""

        dry_run = False

        def validate_management_handoff(self, _manifest_path):
            """Fail if staging unexpectedly reaches helper validation.

            Args:
                _manifest_path: Staged manifest that must not reach validation.
            """
            raise AssertionError("helper validation must not run after staging failure")

    unit_defaults = {
        "label": "Management handoff component",
        "summary": "Apply the management handoff component.",
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "",
        "config_preview": "",
        "config_diff": "",
        "raw_config_preview": "",
    }
    units = {
        unit_id: {**unit_defaults, "id": unit_id}
        for unit_id in ui.MANAGEMENT_HANDOFF_UNIT_IDS
    }
    units["network"]["previous_management_paths"] = []
    units["network"]["removed_vlan_interfaces"] = []
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": []}
    ca_path = tmp_path / "atlaso-ca.json"
    manifest_path = tmp_path / "atlaso-management-handoff.json"
    monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(ca_path))
    monkeypatch.setattr(ui, "MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db: {"appliance_settings": {}})
    monkeypatch.setattr(ui, "network_config_with_removed_vlans", lambda preview, _removed: preview)
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "private-key-payload")

    def stage_config(target, content):
        """Write the CA payload, then inject the selected staging failure.

        Args:
            target: Canonical staged configuration path.
            content: Rendered staged configuration content.
        """
        if str(target) == str(ca_path):
            ca_path.write_text(content, encoding="utf-8")
            if failure_target == "ca":
                raise OSError("CA staging interrupted")
        if str(target) == str(manifest_path):
            raise OSError("manifest staging interrupted")
        return str(target)

    monkeypatch.setattr(ui, "stage_appliance_apply_config", stage_config)

    with pytest.raises(OSError, match="staging interrupted"):
        ui.execute_management_handoff(
            units,
            job_id="job_secret_cleanup_435",
            adapter=UnusedAdapter(),
            db=object(),
        )

    assert not ca_path.exists()
    assert not manifest_path.exists()


def test_management_handoff_timeout_stops_and_recovers_indeterminate_helper(monkeypatch):
    """Recover the fixed helper unit when the adapter wait times out.

    Args:
        monkeypatch: Pytest fixture used to isolate staging and helper execution.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult

    class TimeoutAdapter:
        """Return an indeterminate apply result followed by proven rollback."""

        dry_run = False

        def __init__(self):
            """Initialize the recorded helper actions."""
            self.actions: list[str] = []

        def validate_management_handoff(self, manifest_path):
            """Accept the staged manifest.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            self.actions.append("validate")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "validate", manifest_path],
                dry_run=False,
                returncode=0,
            )

        def apply_management_handoff(self, manifest_path):
            """Return the adapter timeout used for indeterminate execution.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            self.actions.append("apply")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "apply", manifest_path],
                dry_run=False,
                stderr="management handoff helper wait timed out",
                returncode=124,
            )

        def recover_management_handoff(self):
            """Return bounded proof that the surviving helper was rolled back."""
            self.actions.append("recover")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "recover"],
                dry_run=False,
                stdout=json.dumps(
                    {
                        "management_handoff": "rolled back after interruption",
                        "rolled_back": True,
                        "failing_layer": "interruption serialization",
                    }
                ),
                returncode=0,
            )

    unit_defaults = {
        "label": "Management handoff component",
        "summary": "Apply the management handoff component.",
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "",
        "config_preview": "",
        "config_diff": "",
        "raw_config_preview": "",
    }
    units = {
        unit_id: {**unit_defaults, "id": unit_id}
        for unit_id in (*ui.MANAGEMENT_HANDOFF_UNIT_IDS, "dnsmasq")
    }
    units["network"]["previous_management_paths"] = [
        {
            "name": "eth0.20",
            "parent": "eth0",
            "ip_cidr": "192.0.2.10/24",
            "ipv6_cidr": "",
        }
    ]
    units["network"]["removed_vlan_interfaces"] = []
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": []}
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db: {"appliance_settings": {}})
    staged: dict[str, str] = {}

    def stage_config(target, content):
        """Capture staged handoff content by target path.

        Args:
            target: Canonical staged configuration path.
            content: Rendered staged configuration content.

        Returns:
            The unchanged target path.
        """
        staged[str(target)] = content
        return target

    monkeypatch.setattr(ui, "stage_appliance_apply_config", stage_config)
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
    adapter = TimeoutAdapter()

    group, results = ui.execute_management_handoff(
        units,
        job_id="job_timeout435",
        adapter=adapter,
        db=object(),
        include_dnsmasq=True,
    )

    assert adapter.actions == ["validate", "apply", "recover"]
    assert group["success"] is False
    assert group["rollback_proven"] is True
    assert group["management_handoff"]["management_handoff"] == "rolled back"
    assert group["management_handoff"]["failing_layer"] == "handoff helper wait"
    assert all(result["rolled_back"] is True for result in results)
    manifest = json.loads(staged[str(ui.MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH)])
    assert manifest["dnsmasq_config_path"] == str(ui.DNSMASQ_STAGED_CONFIG_PATH)
    assert {result["unit_id"] for result in results} == {
        *ui.MANAGEMENT_HANDOFF_UNIT_IDS,
        "dnsmasq",
    }
    assert manifest["previous_management_interfaces"] == ["eth0.20"]
    assert manifest["previous_management_parent_interfaces"] == ["eth0"]
    assert manifest["previous_management_paths"] == [
        {
            "name": "eth0.20",
            "ipv4_method": "",
            "ipv6_enabled": "",
            "ipv6_cidr": "",
        }
    ]


def test_management_handoff_preserves_newer_routing_desired_state(client, monkeypatch, tmp_path):
    """Preserve newer Routing desired state after a bundled WAN apply.

    Args:
        client: HTTP test client used to initialize an isolated database.
        monkeypatch: Pytest fixture used to isolate staging and helper execution.
        tmp_path: Temporary root used for staged handoff paths.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ServiceState

    class SuccessfulAdapter:
        """Return successful non-dry-run handoff results."""

        dry_run = False

        def validate_management_handoff(self, manifest_path):
            """Accept the staged handoff manifest.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "validate", manifest_path],
                dry_run=False,
                returncode=0,
            )

        def apply_management_handoff(self, manifest_path):
            """Apply the staged handoff manifest successfully.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "apply", manifest_path],
                dry_run=False,
                returncode=0,
            )

    unit_defaults = {
        "label": "Management handoff component",
        "summary": "Apply the management handoff component.",
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "",
        "config_preview": "",
        "config_diff": "",
        "raw_config_preview": "",
    }
    units = {
        unit_id: {**unit_defaults, "id": unit_id}
        for unit_id in (*ui.MANAGEMENT_HANDOFF_UNIT_IDS, "wan")
    }
    units["network"]["previous_management_paths"] = []
    units["network"]["removed_vlan_interfaces"] = []
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": []}
    units["wan"]["config_path"] = str(tmp_path / "wan.json")
    units["wan"]["context"] = {
        "routes_wan_settings": SimpleNamespace(routing_enabled=True)
    }
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db: {})
    monkeypatch.setattr(
        ui,
        "stage_appliance_apply_config",
        lambda target, _content: str(tmp_path / str(target).replace(":", "").replace("/", "_").replace("\\", "_")),
    )
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
    monkeypatch.setattr(ui, "wan_rollback_config_preview", lambda *_args, **_kwargs: "")
    lock_events: list[str] = []
    monkeypatch.setattr(
        ui,
        "acquire_network_objects_write_lock",
        lambda _db: lock_events.append("routing-sync"),
    )

    with SessionLocal() as db:
        routing_service = db.execute(
            select(ServiceState).where(ServiceState.service == "routing")
        ).scalar_one()
        routing_service.enabled = False
        routing_service.running = False
        routing_service.health = "disabled"
        db.flush()

        group, _results = ui.execute_management_handoff(
            units,
            job_id="job_routing_runtime_sync",
            adapter=SuccessfulAdapter(),
            db=db,
            include_wan=True,
        )

        assert group["success"] is True
        assert lock_events == ["routing-sync"]
        assert routing_service.enabled is False
        assert routing_service.running is True
        assert routing_service.health == "healthy"


def test_management_handoff_settings_baseline_ignores_only_applied_front_door_fields():
    """Keep unrelated Appliance Settings pending after the management transaction."""
    from atlaso.app.ui import management_handoff_completes_appliance_settings

    previous = {
        "fqdn": "atlaso.example",
        "resolver_mode": "dhcp",
        "resolver_servers": [],
        "local_dns_enabled": False,
        "management_interface": "eth0",
        "management_ip": "192.0.2.10",
        "management_https_enabled": True,
        "root_ssh_enabled": False,
    }
    baseline = {"config_preview": json.dumps(previous)}
    management_only = {
        **previous,
        "resolver_mode": "local_dns",
        "resolver_servers": ["127.0.0.1"],
        "local_dns_enabled": True,
        "management_interface": "eth1",
        "management_ip": "198.51.100.10",
    }

    assert management_handoff_completes_appliance_settings(json.dumps(management_only), baseline)
    assert not management_handoff_completes_appliance_settings(
        json.dumps({**management_only, "root_ssh_enabled": True}),
        baseline,
    )


def test_appliance_apply_router_owns_exact_transport_set():
    """Keep the extracted route identities and response classes exact."""
    from atlaso.app import ui

    assert [
        (
            route.path,
            tuple(sorted((route.methods or set()) - {"HEAD"})),
            route.name,
            route.response_class.__name__,
        )
        for route in ui.appliance_apply_router.routes
    ] == [
        (
            "/ui/management/appliance-apply",
            ("GET",),
            "appliance_apply_page",
            "RedirectResponse",
        ),
        (
            "/ui/management/appliance-apply/review",
            ("GET",),
            "appliance_apply_review",
            "JSONResponse",
        ),
        (
            "/ui/management/appliance-apply/status",
            ("GET",),
            "appliance_apply_status_api",
            "JSONResponse",
        ),
        (
            "/ui/management/appliance-apply",
            ("POST",),
            "submit_appliance_apply",
            "HTMLResponse",
        ),
    ]


def test_appliance_apply_status_tolerates_duplicate_managed_certificate_owners(client):
    """Verify that status tolerates duplicate managed certificate owners.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate

    login(client)
    with SessionLocal() as db:
        db.add_all(
            [
                CaCertificate(
                    common_name="older-kms.atlaso.internal",
                    managed_owner="kms:server",
                    status="planned",
                ),
                CaCertificate(
                    common_name="newer-kms.atlaso.internal",
                    managed_owner="kms:server",
                    status="issued",
                    certificate_pem="test-certificate",
                    private_key_encrypted="test-encrypted-key",
                ),
            ]
        )
        db.commit()

    response = client.get("/appliance-apply/status")

    assert response.status_code == 200
    assert response.json()["units"]


def test_appliance_apply_status_uses_lightweight_projection(client, monkeypatch):
    """Verify ordinary status polling never runs apply-time reconciliation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui

    login(client)
    original = ui.appliance_apply_units
    monkeypatch.setattr(ui, "_appliance_apply_status_cache", None)
    reconcile_values = []

    def tracked_units(db, *, reconcile=True):
        """Track reconciliation selection.

        Args:
            db: Active database session.
            reconcile: Whether dependent desired state should be reconciled.
        """
        reconcile_values.append(reconcile)
        return original(db, reconcile=reconcile)

    monkeypatch.setattr(ui, "appliance_apply_units", tracked_units)
    first = client.get("/appliance-apply/status")
    second = client.get("/appliance-apply/status")
    users_page = client.get("/users")
    refreshed = client.get("/appliance-apply/status?refresh=true")

    assert first.status_code == 200
    assert second.status_code == 200
    assert users_page.status_code == 200
    assert refreshed.status_code == 200
    assert first.json().keys() == second.json().keys()
    assert reconcile_values == [False, False]


def test_appliance_apply_status_preserves_planned_management_restart_context(client, monkeypatch):
    """Keep durable reconnect context available before the management front door restarts.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    observed_at = datetime(2026, 8, 20, 19, 30, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(ui, "utcnow", lambda: observed_at)
    login(client)
    with SessionLocal() as db:
        job = Job(
            id="job_planned_management_restart",
            type="appliance-apply",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            progress_percent=50,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": {
                        "kind": "planned_service_restart",
                        "restart_delay_seconds": 3,
                        "grace_seconds": 15,
                    },
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=datetime(2026, 8, 20, 19, 30, 0),
                result="{}",
            )
        )
        db.add(
            JobStep(
                id=f"{job.id}:firewall",
                job=job,
                component_key="firewall",
                label="Firewall",
                position=2,
                status=JobStatus.RUNNING.value,
                progress_percent=50,
                result="{}",
            )
        )
        db.commit()

    response = client.get("/appliance-apply/status")

    assert response.status_code == 200
    task = response.json()["active_task"]
    assert task["id"] == "job_planned_management_restart"
    assert task["result"]["management_status_transition"] == {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    assert task["management_restart_window"] == {
        "restart_delay_remaining_ms": 2000,
        "remaining_ms": 17000,
    }
    assert [(step["component_key"], step["status"]) for step in task["_children"]] == [
        ("appliance_settings", "succeeded"),
        ("firewall", "running"),
    ]
    assert task["_children"][0]["finished_at"] == "2026-08-20T19:30:00+00:00"


def test_appliance_apply_status_retains_terminal_planned_restart_lock(client, monkeypatch):
    """Keep a settings-only task and the mutation lock through its restart window.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    observed_at = datetime(2026, 8, 20, 20, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(ui, "utcnow", lambda: observed_at)
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    transition = {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    with SessionLocal() as db:
        job = Job(
            id="job_terminal_management_restart",
            type="appliance-apply",
            status=JobStatus.SUCCEEDED.value,
            created_by="admin",
            progress_percent=100,
            finished_at=observed_at,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": transition,
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=observed_at,
                result="{}",
            )
        )
        db.commit()

    retained = client.get("/appliance-apply/status?refresh=true")
    assert retained.status_code == 200
    assert retained.json()["locked"] is True
    assert retained.json()["active_task"]["id"] == "job_terminal_management_restart"
    assert retained.json()["active_task"]["status"] == JobStatus.SUCCEEDED.value
    assert retained.json()["active_task"]["mutation_locked"] is True
    assert retained.json()["active_task"]["management_restart_window"] == {
        "restart_delay_remaining_ms": 3000,
        "remaining_ms": 18000,
    }

    blocked = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
    )
    assert blocked.status_code == 423
    assert blocked.json()["job_id"] == "job_terminal_management_restart"

    monkeypatch.setattr(ui, "utcnow", lambda: observed_at + timedelta(seconds=19))
    released = client.get("/appliance-apply/status?refresh=true")
    assert released.status_code == 200
    assert released.json()["locked"] is False
    assert released.json()["active_task"] is None


@pytest.mark.parametrize("terminal_status", ["failed", "cancelled"])
def test_appliance_apply_status_retains_non_successful_terminal_restart_lock(
    client,
    monkeypatch,
    terminal_status,
):
    """Retain every terminal master carrying a valid confirmed restart.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        terminal_status: Terminal master status exercised by the regression.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    observed_at = datetime(2026, 8, 20, 20, 45, tzinfo=timezone.utc)
    monkeypatch.setattr(ui, "utcnow", lambda: observed_at)
    login(client)
    with SessionLocal() as db:
        job = Job(
            id=f"job_terminal_management_restart_{terminal_status}",
            type="appliance-apply",
            status=terminal_status,
            created_by="admin",
            progress_percent=100,
            finished_at=observed_at,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": {
                        "kind": "planned_service_restart",
                        "restart_delay_seconds": 3,
                        "grace_seconds": 15,
                    },
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=observed_at,
                result="{}",
            )
        )
        db.commit()

    retained = client.get("/appliance-apply/status?refresh=true")
    assert retained.status_code == 200
    assert retained.json()["locked"] is True
    assert retained.json()["active_task"]["status"] == terminal_status
    assert retained.json()["active_task"]["mutation_locked"] is True


def test_appliance_apply_transition_context_requires_helper_confirmation():
    """Mark only a real helper-confirmed Appliance Settings restart as planned."""
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.ui import appliance_settings_management_status_transition

    confirmed = AdapterResult(
        command=["atlaso-helper", "appliance-settings", "apply"],
        dry_run=False,
        stdout=json.dumps(
            {
                "appliance_settings": "apply complete",
                "management_status_transition": {
                    "kind": "planned_service_restart",
                    "restart_delay_seconds": 3,
                },
            }
        ),
    )
    assert appliance_settings_management_status_transition([confirmed]) == {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=False, stdout='{"appliance_settings":"apply complete"}')]
    ) is None
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=True, stdout=confirmed.stdout)]
    ) is None
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=False, stdout=confirmed.stdout, returncode=1)]
    ) is None


def test_appliance_apply_job_persists_helper_confirmed_transition(client, monkeypatch):
    """Persist confirmed restart context before the helper's delayed restart fires.

    Args:
        client: HTTP test client used to initialize an isolated database.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    transition = {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    unit = {
        "id": "appliance_settings",
        "label": "Appliance Settings",
        "snapshot_hash": "captured-settings",
        "summary": ["Apply settings"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "/etc/atlaso/atlaso-settings.json",
        "config_preview": "{}\n",
        "config_diff": "",
    }
    with SessionLocal() as db:
        job = Job(
            id="job_confirmed_management_restart",
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "captured_units": [
                        {
                            "unit_id": "appliance_settings",
                            "snapshot_hash": "captured-settings",
                        }
                    ],
                    "units": [],
                    "dry_run": False,
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.PENDING.value,
                result="{}",
            )
        )
        db.commit()

    unit_projection_calls = 0
    durable_before_reconciliation = False

    def appliance_apply_units_with_durable_probe(_db, reconcile=True):
        """Verify confirmed restart state before post-helper reconciliation.

        Args:
            _db: Active job database session.
            reconcile: Whether to reconcile current host observations.
        """
        nonlocal unit_projection_calls, durable_before_reconciliation
        unit_projection_calls += 1
        if unit_projection_calls == 2:
            with SessionLocal() as verification_db:
                persisted = verification_db.get(Job, "job_confirmed_management_restart")
                assert persisted is not None
                persisted_step = verification_db.get(
                    JobStep,
                    "job_confirmed_management_restart:appliance_settings",
                )
                durable_before_reconciliation = (
                    json.loads(persisted.result or "{}").get("management_status_transition") == transition
                    and persisted_step is not None
                    and persisted_step.status == JobStatus.SUCCEEDED.value
                    and persisted_step.finished_at is not None
                )
        return [unit]

    monkeypatch.setattr(ui, "appliance_apply_units", appliance_apply_units_with_durable_probe)
    monkeypatch.setattr(
        ui,
        "execute_appliance_apply_unit",
        lambda _unit, **_kwargs: {
            **unit,
            "unit_id": "appliance_settings",
            "success": True,
            "status": JobStatus.SUCCEEDED.value,
            "dry_run": False,
            "commands": [],
            "management_status_transition": transition,
        },
    )

    ui.run_appliance_apply_job("job_confirmed_management_restart")

    with SessionLocal() as db:
        completed = db.get(Job, "job_confirmed_management_restart")
        assert completed is not None
        assert completed.status == JobStatus.SUCCEEDED.value
        assert json.loads(completed.result or "{}")["management_status_transition"] == transition
    assert durable_before_reconciliation is True


def test_appliance_apply_review_returns_management_address_connection_warning(client):
    """Verify review returns the management-address connection warning.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.20/24"
        db.commit()

    review = client.get("/appliance-apply/review")

    assert review.status_code == 200
    network = next(unit for unit in review.json()["units"] if unit["id"] == "network")
    assert len(network["connection_warnings"]) == 1
    assert "from 192.168.49.1/24 to 192.168.49.20/24" in network["connection_warnings"][0]


@pytest.mark.parametrize("network_selected", [False, True])
def test_wan_apply_preview_uses_selected_network_ownership(client, monkeypatch, network_selected):
    """Review and submitted WAN snapshot agree on applied versus candidate Network.

    Args:
        client: Isolated HTTP application fixture.
        monkeypatch: Keep the submitted task pending for snapshot inspection.
        network_selected: Whether Network is explicitly selected in the request.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route

    login(client)
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.10/24"
        interface.access_management_ui_enabled = True
        db.add(Route(destination_cidr="0.0.0.0/0", gateway="192.168.50.1",
                     interface_name="eth2", enabled=True))
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        interface.access_management_ui_enabled = False
        db.commit()
        wan = next(unit for unit in ui.appliance_apply_units(db) if unit["id"] == "wan")
        candidate = wan["network_candidate_variant"]
        assert wan["config_preview"] != candidate["config_preview"]

    review = client.get("/appliance-apply/review")
    assert review.status_code == 200
    review_wan = next(unit for unit in review.json()["units"] if unit["id"] == "wan")
    assert review_wan["config_preview"] == wan["config_preview"]
    assert review_wan["network_candidate_preview"] == candidate["config_preview"]

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    selection = ["wan", "network"] if network_selected else ["wan"]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": selection},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        payload = json.loads(db.get(Job, response.json()["job_id"]).result)
    expected = candidate if "network" in payload["selected_units"] else wan
    captured = next(unit for unit in payload["captured_units"] if unit["unit_id"] == "wan")
    assert captured["snapshot_hash"] == expected["snapshot_hash"]
    assert captured["config_preview"] == expected["config_preview"]


@pytest.mark.parametrize("scenario", ["changed_address", "unrelated_network_edit", "invalid_network",
                                       "disabled_route", "routing_off", "activate_trunk",
                                       "activate_admin_down", "activate_unused", "change_domain",
                                       "enable_management_listener"])
@pytest.mark.parametrize("gateway_present", [True, False], ids=["gateway", "direct"])
def test_wan_gateway_target_address_requires_network_apply(client, monkeypatch, scenario, gateway_present):
    """A pending route's new target prefix or routing owner requires Network first.

    Args:
        client: Isolated HTTP application fixture.
        monkeypatch: Keep submitted jobs pending and inject invalid Network state.
        scenario: Address or ownership dependency, unrelated edit, or inactive route.
        gateway_present: Whether the route uses a gateway or only its target link.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route
    from atlaso.app.services.routes_wan import save_routes_wan_settings

    login(client)
    with SessionLocal() as db:
        db.query(Route).delete()
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert interface is not None
        interface.role = "unused" if scenario == "activate_unused" else (
            "management" if scenario == "change_domain" else "access"
        )
        interface.mode = "trunk" if scenario == "activate_trunk" else "access"
        interface.admin_state = "down" if scenario == "activate_admin_down" else "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.0.2.10/24"
        route = Route(destination_cidr="0.0.0.0/0" if scenario == "enable_management_listener" and gateway_present
                      else "198.51.100.0/24", gateway="192.0.2.1" if gateway_present else None,
                      interface_name="eth2", enabled=True)
        db.add(route)
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        if scenario == "enable_management_listener":
            interface.access_management_ui_enabled = True
        elif scenario.startswith("activate_") or scenario == "change_domain":
            interface.role = "access"
            interface.mode = "access"
            interface.admin_state = "up"
            if not gateway_present:
                route.destination_cidr = "198.51.101.0/24"
        elif scenario == "unrelated_network_edit":
            interface.mtu = 1400
            if gateway_present:
                route.gateway = "192.0.2.2"
            else:
                route.destination_cidr = "198.51.101.0/24"
        else:
            interface.ip_cidr = "192.0.3.10/24"
            if gateway_present:
                route.gateway = "192.0.3.1"
            else:
                route.destination_cidr = "198.51.101.0/24"
            if scenario == "disabled_route":
                route.enabled = False
            elif scenario == "routing_off":
                save_routes_wan_settings(db, routing_enabled=False, nat_enabled=False,
                                         wan_simulation_enabled=False)
        db.commit()
        units = ui.appliance_apply_units(db)
        network = next(unit for unit in units if unit["id"] == "network")
        wan = next(unit for unit in units if unit["id"] == "wan")
        expected_dependency = scenario in {"changed_address", "invalid_network", "activate_trunk",
                                           "activate_admin_down", "activate_unused", "change_domain",
                                           "enable_management_listener"}
        assert network["changed"]
        assert wan["network_address_dependency"] is expected_dependency
        assert wan["changed"]
        if scenario == "invalid_network":
            network["validation_errors"] = ["invalid Network dependency"]
        count_before = db.query(Job).count()

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db: units)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "wan"},
                           headers={"Accept": "application/json"})
    assert response.status_code == (422 if scenario == "invalid_network" else 202), response.text
    with SessionLocal() as db:
        assert db.query(Job).count() == count_before + (0 if scenario == "invalid_network" else 1)
        if scenario == "invalid_network":
            return
        payload = json.loads(db.get(Job, response.json()["job_id"]).result)
    selected = payload["selected_units"]
    assert ("network" in selected) is expected_dependency
    assert "wan" in selected
    if expected_dependency:
        assert selected.index("network") < selected.index("wan")
    captured = next(unit for unit in payload["captured_units"] if unit["unit_id"] == "wan")
    expected_wan = wan["network_candidate_variant"] if expected_dependency else wan
    assert captured["config_preview"] == expected_wan["config_preview"]


def test_network_only_ingress_reconciliation_does_not_leave_wan_pending(client):
    """Network-owned ingress changes do not create an independent WAN Apply.

    Args:
        client: Isolated HTTP application fixture.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.routes_wan import save_routes_wan_settings

    with SessionLocal() as db:
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "down"
        db.commit()
        units = ui.appliance_apply_units(db)
        applied = ui.appliance_apply_units_for_selection(
            units, {unit["id"] for unit in units}
        )
        ui.update_appliance_apply_baselines(db, applied, {unit["id"] for unit in applied})
        interface.admin_state = "up"
        db.commit()
        before = ui.appliance_apply_units(db)
        assert next(unit for unit in before if unit["id"] == "network")["changed"]
        wan_before = next(unit for unit in before if unit["id"] == "wan")
        assert not wan_before["changed"]
        assert not wan_before["network_candidate_variant"]["changed"]
        ui.update_appliance_apply_baselines(db, before, {"network"})
        after = ui.appliance_apply_units(db)
        assert not next(unit for unit in after if unit["id"] == "network")["changed"]
        assert not next(unit for unit in after if unit["id"] == "wan")["changed"]


def test_management_move_leaves_unselected_dns_enablement_pending(client):
    """Bundle required handoff units without applying pending DNS enablement.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, Job, PhysicalInterface
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        dns = db.query(DnsSettings).one()
        dns.enabled = False
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.21/24"
        dns.enabled = True
        db.commit()
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
        assert payload["management_handoff"] is True
        assert set(payload["management_handoff_units"]) == {
            "ca",
            "network",
            "firewall",
            "appliance_settings",
            "public_services",
        }
        assert "dnsmasq" not in payload["selected_units"]
        assert "dnsmasq" in {unit["unit_id"] for unit in payload["skipped_changed_units"]}
        settings = next(
            unit
            for unit in payload["captured_units"]
            if unit["unit_id"] == "appliance_settings"
        )
        resolver = json.loads(settings["config_preview"])
        assert resolver["resolver_mode"] != "local_dns"
        assert resolver["resolver_servers"] != ["127.0.0.1"]
        assert all(
            unit["management_handoff"]["management_handoff"] == "committed"
            for unit in payload["units"]
            if unit["unit_id"] in payload["management_handoff_units"]
        )


@pytest.mark.parametrize("listener_change", ["unflag", "admin_down"])
def test_mirror_changing_listener_edit_forces_wan_into_handoff(
    client,
    listener_change,
):
    """Execute host-default cleanup in every protected listener handoff.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        listener_change: Applied-listener mutation exercised by the scenario.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.10/24"
        interface.access_management_ui_enabled = True
        db.add(
            Route(
                destination_cidr="0.0.0.0/0",
                gateway="192.168.50.1",
                interface_name="eth2",
                enabled=True,
            )
        )
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        if listener_change == "unflag":
            interface.access_management_ui_enabled = False
        else:
            interface.admin_state = "down"
        db.commit()
        invalid = {
            unit["id"]: unit["validation_errors"]
            for unit in appliance_apply_units(db)
            if unit["validation_errors"]
        }
        assert invalid == {}

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert set(payload["management_handoff_units"]) == {
        "ca",
        "network",
        "firewall",
        "appliance_settings",
        "public_services",
        "wan",
    }
    assert "wan" in payload["selected_units"]
    assert any(unit["unit_id"] == "wan" for unit in payload["units"])


def test_modern_flagged_listener_enable_forces_candidate_wan_handoff(client, monkeypatch):
    """A Network-only selection must install the new listener's default mirror.

    Args:
        client: HTTP test client used to submit the applied-state change.
        monkeypatch: Prevent asynchronous execution while inspecting the queued job.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route

    login(client)
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.10/24"
        interface.access_management_ui_enabled = False
        db.add(Route(destination_cidr="0.0.0.0/0", gateway="192.168.50.1",
                     interface_name="eth2", enabled=True))
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        assert "# Network runtime revision: exact-source-routing-v1." in ui.load_appliance_apply_baselines(db)["network"]["config_preview"]
        interface.access_management_ui_enabled = True
        db.commit()
        current = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert current["network"]["management_default_mirror_change"] is True
        assert current["network"]["management_domain_migration_required"] is False
        assert current["wan"]["network_candidate_variant"]["changed"] is True

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        payload = json.loads(db.get(Job, response.json()["job_id"]).result)
    assert payload["management_handoff"] is True
    assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) | {"wan"} <= set(payload["management_handoff_units"])
    assert "wan" in payload["selected_units"]


@pytest.mark.parametrize("route_change", ["gateway", "metric", "disable", "remove"])
def test_standalone_mirrored_default_edit_starts_management_handoff(
    client,
    route_change,
):
    """Protect every host-default mutation submitted from Routes & WAN.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        route_change: Mirrored-default mutation exercised by the scenario.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.10/24"
        interface.access_management_ui_enabled = True
        route = Route(
            destination_cidr="0.0.0.0/0",
            gateway="192.168.50.1",
            interface_name="eth2",
            metric=100,
            enabled=True,
        )
        db.add(route)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        if route_change == "gateway":
            route.gateway = "192.168.50.2"
        elif route_change == "metric":
            route.metric = 200
        elif route_change == "disable":
            route.enabled = False
        else:
            db.delete(route)
        db.commit()

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "wan"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert set(payload["management_handoff_units"]) == {
        "ca",
        "network",
        "firewall",
        "appliance_settings",
        "public_services",
        "wan",
    }
    assert any(unit["unit_id"] == "wan" for unit in payload["units"])


def test_selected_wan_change_executes_inside_existing_management_handoff(client):
    """Apply a captured non-mirror WAN edit with the protected Network change.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        )
        access = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert management is not None
        assert access is not None
        management.ip_cidr = "192.168.49.21/24"
        access.role = "access"
        access.mode = "access"
        access.admin_state = "up"
        access.oper_state = "up"
        access.ipv4_method = "static"
        access.ip_cidr = "192.168.50.10/24"
        db.add(
            Route(
                destination_cidr="203.0.113.0/24",
                gateway="192.168.50.1",
                interface_name="eth2",
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network", "wan"]},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert "wan" in payload["management_handoff_units"]
    assert any(unit["unit_id"] == "wan" for unit in payload["units"])


@pytest.mark.parametrize("initially_enabled", [False, True])
def test_ntp_apply_includes_generated_dns_after_ntp(client, monkeypatch, initially_enabled):
    """NTP enable and disable capture only their owned DNS delta after NTP.

    Args:
        client: HTTP test client.
        monkeypatch: Pytest fixture used to replace dependencies.
        initially_enabled: Whether NTP starts enabled.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, NtpSettings, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        settings = db.scalar(select(NtpSettings))
        assert interface is not None and settings is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ip_cidr = "192.168.49.20/24"
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.49.20"
        settings.enabled = initially_enabled
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        settings.enabled = not initially_enabled
        db.commit()
        changed = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert ui.ntp_owned_dns_is_only_pending_change(db, changed["dnsmasq"])

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "ntpd"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        selected = json.loads(job.result or "{}")["selected_units"]
    assert selected.index("ntpd") < selected.index("dnsmasq")


@pytest.mark.parametrize(
    ("initially_enabled", "selected_id"),
    [(True, "dnsmasq"), (False, "dnsmasq"), (False, "ntpd"),
     (False, ["dnsmasq", "ntpd"])],
)
def test_ntp_and_unrelated_dns_changes_keep_explicit_selection(
    client, monkeypatch, initially_enabled, selected_id,
):
    """A manual DNS edit must not silently expand the operator's Apply selection.

    Args:
        client: HTTP test client.
        monkeypatch: Pytest fixture used to replace dependencies.
        initially_enabled: Whether NTP starts enabled.
        selected_id: Apply unit or units selected by the operator.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job, NtpSettings, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        settings = db.scalar(select(NtpSettings))
        assert interface is not None and settings is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ip_cidr = "192.168.49.20/24"
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.49.20"
        settings.enabled = initially_enabled
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        settings.enabled = not initially_enabled
        db.add(DnsRecord(
            hostname="manual.example.internal", record_type="A", address="192.0.2.77",
            description="Operator", enabled=True,
        ))
        db.commit()
        changed = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert not ui.ntp_owned_dns_is_only_pending_change(db, changed["dnsmasq"])

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": selected_id},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        selected = json.loads(job.result or "{}")["selected_units"]
    assert selected == ([selected_id] if isinstance(selected_id, str) else selected_id)


def test_ntp_apply_does_not_select_manual_ptr_to_its_target(client, monkeypatch):
    """A manual reverse owner stays outside NTP's generated DNS dependency.

    Args:
        client: Isolated client for this scenario.
        monkeypatch: Replace external behavior for this scenario.
    """
    from ipaddress import ip_address

    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job, NtpSettings, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        settings = db.scalar(select(NtpSettings))
        assert interface is not None and settings is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ip_cidr = "192.168.49.20/24"
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.49.20"
        settings.enabled = False
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        settings.enabled = True
        db.add(DnsRecord(
            hostname=ip_address("192.0.2.77").reverse_pointer,
            record_type="PTR",
            address=ui.service_target_hostname(settings.hostname, "service"),
            description="Operator",
            enabled=True,
        ))
        db.commit()
        changed = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert not ui.ntp_owned_dns_is_only_pending_change(db, changed["dnsmasq"])

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "ntpd"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        selected = json.loads(job.result or "{}")["selected_units"]
    assert "dnsmasq" not in selected


def test_management_move_rechecks_handoff_after_ldap_dependency_expansion(client, monkeypatch):
    """Protect a Firewall unit added indirectly by the LDAP dependency closure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to isolate background execution.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.22/24"
        db.commit()

    real_units = ui.appliance_apply_units

    def units_with_ldap_firewall_dependency(db, *, reconcile=True):
        """Mark LDAP active and its generated Firewall dependency changed.

        Args:
            db: Active database session.
            reconcile: Whether desired-state dependencies should be reconciled.

        Returns:
            Appliance Apply units with the indirect LDAP dependency active.
        """
        units = real_units(db, reconcile=reconcile)
        unit_map = {unit["id"]: unit for unit in units}
        unit_map["ldap"]["context"]["ldap_organizations"] = [object()]
        unit_map["ldap"]["changed"] = True
        unit_map["firewall"]["changed"] = True
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", units_with_ldap_firewall_dependency)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "ldap"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert set(payload["management_handoff_units"]) == {
        "ca",
        "network",
        "firewall",
        "appliance_settings",
        "public_services",
    }
    assert "ldap" in payload["selected_units"]


def test_management_handoff_baselines_exact_applied_snapshot(client, monkeypatch):
    """Leave a desired-state edit saved during readiness pending.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to inject a concurrent desired-state edit.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.21/24"
        db.commit()

    original_execute = ui.execute_management_handoff

    def execute_with_concurrent_edit(*args, **kwargs):
        """Apply the captured candidate, then save a newer desired address.

        Args:
            *args: Positional arguments forwarded to the production executor.
            **kwargs: Keyword arguments forwarded to the production executor.

        Returns:
            The production management-handoff result.
        """
        result = original_execute(*args, **kwargs)
        with SessionLocal() as edit_db:
            management = edit_db.scalar(
                select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
            )
            assert management is not None
            management.ip_cidr = "192.168.49.22/24"
            edit_db.commit()
        return result

    monkeypatch.setattr(ui, "execute_management_handoff", execute_with_concurrent_edit)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        assert job.status == JobStatus.SUCCEEDED.value
        payload = json.loads(job.result or "{}")
        captured = next(
            unit for unit in payload["captured_units"] if unit["unit_id"] == "network"
        )
        baseline = ui.load_appliance_apply_baselines(db)["network"]
        current = next(
            unit
            for unit in ui.appliance_apply_units(db, reconcile=False)
            if unit["id"] == "network"
        )
        assert baseline["snapshot_hash"] == captured["snapshot_hash"]
        assert baseline["config_preview"] == captured["config_preview"]
        assert current["snapshot_hash"] != baseline["snapshot_hash"]
        assert current["changed"] is True


def test_management_handoff_persists_helper_confirmed_dynamic_address(client, monkeypatch):
    """Publish a DHCP listener binding from the address probed by the handoff helper.

    Args:
        client: HTTP test client providing an isolated database.
        monkeypatch: Pytest fixture used to provide the post-handoff host observation.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.management_bindings import applied_management_bindings
    from atlaso.app.services.networking import HostPhysicalInterface

    config_preview = """\
[physical_interfaces]
interface=eth0
role=management
mode=access
admin_state=up
ipv4_method=dhcp
ip_cidr=
ipv6_enabled=false
ipv6_cidr=
"""
    observed = HostPhysicalInterface(
        name="eth0",
        mac_address="00:15:5d:01:01:01",
        driver="vmxnet3",
        speed="10000 Mbps",
        host_ip_cidr="192.168.167.134/24",
        host_mtu=1500,
        host_admin_state="up",
        oper_state="up",
    )
    monkeypatch.setattr(ui, "discover_host_physical_interfaces", lambda: [observed])

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert interface is not None
        interface.role = "management"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.ipv4_method = "dhcp"
        interface.ip_cidr = None
        interface.host_ip_cidr = "192.168.49.10/24"
        ui.refresh_management_handoff_dynamic_observations(
            db,
            config_preview,
            {"candidate_addresses": ["192.168.167.134"]},
        )
        ui.save_appliance_apply_baselines(
            db,
            {"network": {"config_preview": config_preview}},
        )
        db.commit()

    with SessionLocal() as db:
        assert applied_management_bindings(db) == [
            {
                "interface": "eth0",
                "role": "management",
                "address": "192.168.167.134",
                "management_ui": "true",
            }
        ]


def test_management_handoff_staging_failure_clears_unstarted_runtime_lock(client, monkeypatch):
    """Do not retain the Apply lock when the helper proves no transaction began.

    Args:
        client: HTTP test client providing an isolated database.
        monkeypatch: Pytest fixture used to fail before privileged helper execution.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.21/24"
        db.commit()

    original_run = ui.run_appliance_apply_job
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        ui,
        "execute_management_handoff",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("staging failed")),
    )
    no_transaction = AdapterResult(
        command=["atlaso-helper", "management-handoff", "recover"],
        dry_run=False,
        stdout=json.dumps(
            {
                "management_handoff": "no interrupted transaction",
                "rolled_back": False,
            }
        ),
        returncode=0,
    )
    monkeypatch.setattr(
        ui,
        "reconcile_management_handoff_exception",
        lambda *_args, **_kwargs: (
            no_transaction,
            ui.management_handoff_result_evidence(no_transaction),
        ),
    )
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        job.created_by = "console:root"
        db.commit()
    original_run(response.json()["job_id"], force_real=True)
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        assert job.status == JobStatus.FAILED.value
        payload = json.loads(job.result or "{}")
        assert "management_handoff_runtime_commit_pending" not in payload
        assert "management_handoff_application_committed" not in payload
        recovery = payload["management_handoff_exception_recovery"]["evidence"]
        assert recovery["management_handoff"] == "no interrupted transaction"
        assert "no runtime rollback was necessary" in (job.error or "")
        assert ui.active_appliance_apply_job(db) is None


def test_interrupted_handoff_reconciles_application_commit_without_false_rollback(client, monkeypatch):
    """Acknowledge a committed baseline and distinguish a missing rollback marker.

    Args:
        client: HTTP test client providing an isolated database.
        monkeypatch: Pytest fixture used to replace privileged helper calls.
    """
    import atlaso.app.ui as ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    recovery_calls: list[str] = []

    class RecoveryAdapter:
        """Return deterministic commit and no-marker recovery evidence."""

        def __init__(self, **_kwargs):
            """Accept the production adapter construction contract.

            Args:
                **_kwargs: Adapter options ignored by this test double.
            """

        def acknowledge_management_handoff(self, job_id):
            """Return an idempotent acknowledgement for the committed task.

            Args:
                job_id: Appliance Apply task being acknowledged.
            """
            recovery_calls.append(f"acknowledge:{job_id}")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "acknowledge", job_id],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "already committed", "job_id": job_id}),
                returncode=0,
            )

        def recover_management_handoff(self):
            """Return a successful command that explicitly performed no rollback."""
            recovery_calls.append("recover")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "recover"],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "no interrupted transaction", "rolled_back": False}),
                returncode=0,
            )

    monkeypatch.setattr(ui, "SystemAdapter", RecoveryAdapter)
    with SessionLocal() as db:
        db.add(
            Job(
                id="handoff-committed",
                type="appliance-apply",
                status=JobStatus.FAILED.value,
                created_by="admin",
                progress_percent=80,
                result=json.dumps(
                    {
                        "management_handoff": True,
                        "management_handoff_runtime_commit_pending": True,
                        "management_handoff_application_committed": True,
                    }
                ),
            )
        )
        db.commit()

        active = ui.active_appliance_apply_job(db)
        assert active is not None and active.id == "handoff-committed"
        db.add(
            Job(
                id="handoff-no-marker",
                type="appliance-apply",
                status=JobStatus.PENDING.value,
                created_by="admin",
                progress_percent=20,
                result=json.dumps(
                    {
                        "management_handoff": True,
                        "management_handoff_runtime_commit_pending": True,
                    }
                ),
            )
        )
        db.commit()
        db.add(
            Job(
                id="handoff-unproven",
                type="appliance-apply",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=10,
                result=json.dumps({"management_handoff": True}),
            )
        )
        db.commit()
        assert ui.recover_interrupted_appliance_apply_jobs(db) == 3

        committed = db.get(Job, "handoff-committed")
        missing = db.get(Job, "handoff-no-marker")
        unproven = db.get(Job, "handoff-unproven")
        assert committed is not None and missing is not None and unproven is not None
        committed_payload = json.loads(committed.result or "{}")
        missing_payload = json.loads(missing.result or "{}")
        unproven_payload = json.loads(unproven.result or "{}")
        assert committed_payload["management_handoff_runtime_committed"] is True
        assert committed_payload["management_handoff_runtime_commit_pending"] is False
        assert "management_handoff_application_committed" not in committed_payload
        assert "candidate management path remains active" in (committed.error or "")
        assert "before the privileged management handoff transaction began" in (missing.error or "")
        assert "rolled back" not in (missing.error or "").lower()
        assert "management_handoff_runtime_commit_pending" not in missing_payload
        assert "management_handoff_application_committed" not in missing_payload
        assert unproven_payload["management_handoff_runtime_commit_pending"] is True
        assert "management_handoff_application_committed" not in unproven_payload
        retained_lock = ui.active_appliance_apply_job(db)
        assert retained_lock is not None
        assert retained_lock.id == "handoff-unproven"
        assert recovery_calls == ["acknowledge:handoff-committed", "recover", "recover"]


def test_management_handoff_exception_reconciliation_selects_transaction_boundary():
    """Roll back before the application commit and acknowledge after it."""
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.ui import reconcile_management_handoff_exception

    class RecoveryAdapter:
        """Record which retained helper reconciliation path was selected."""

        def __init__(self):
            """Initialize the recorded helper calls."""
            self.calls: list[str] = []

        def recover_management_handoff(self):
            """Return bounded rollback evidence."""
            self.calls.append("recover")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "recover"],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "rolled back", "rolled_back": True}),
                returncode=0,
            )

        def acknowledge_management_handoff(self, job_id):
            """Return bounded committed-candidate evidence.

            Args:
                job_id: Appliance Apply task being acknowledged.
            """
            self.calls.append(f"acknowledge:{job_id}")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "acknowledge", job_id],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "committed", "job_id": job_id}),
                returncode=0,
            )

    adapter = RecoveryAdapter()
    rollback, rollback_evidence = reconcile_management_handoff_exception(
        adapter,
        "job-before-commit",
        application_committed=False,
    )
    acknowledgement, acknowledgement_evidence = reconcile_management_handoff_exception(
        adapter,
        "job-after-commit",
        application_committed=True,
    )

    assert rollback.returncode == 0
    assert rollback_evidence["rolled_back"] is True
    assert acknowledgement.returncode == 0
    assert acknowledgement_evidence["management_handoff"] == "committed"
    assert adapter.calls == ["recover", "acknowledge:job-after-commit"]


@pytest.mark.parametrize("existing_baseline", [False, True])
def test_appliance_apply_json_submission_returns_master_with_live_child_status(client, existing_baseline):
    """Verify JSON submission returns the master and live child status.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        existing_baseline: Whether Network has already been successfully applied.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    if existing_baseline:
        with SessionLocal() as db:
            ui.update_appliance_apply_baselines(db, ui.appliance_apply_units(db), {"network"})
            db.commit()
    expected_components = ["wan", "nat"] if existing_baseline else [
        "appliance_settings", "network", "firewall", "wan", "nat", "ca", "public_services",
    ]
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "wan"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["job_id"].startswith("job_")
    assert payload["status_url"] == f"/tasks/{payload['job_id']}/status"
    assert payload["task"]["type"] == "appliance-apply"
    assert [(step["component_key"], step["status"]) for step in payload["task"]["_children"]] == [
        (component, "pending") for component in expected_components
    ]

    status_response = client.get(payload["status_url"])
    assert status_response.status_code == 200
    task = status_response.json()["task"]
    assert task["status"] == "succeeded"
    assert [(step["component_key"], step["status"]) for step in task["_children"]] == [
        (component, "succeeded") for component in expected_components
    ]


def test_appliance_apply_rejects_submission_while_another_task_is_active(client):
    """Verify submission rejects another active Appliance Apply task.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_active_apply",
                type="appliance-apply",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=25,
                result="{}",
            )
        )
        db.commit()

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
    )

    assert response.status_code == 423
    assert response.json()["job_id"] == "job_active_apply"
    assert "Changes are locked" in response.json()["detail"]
    with SessionLocal() as db:
        jobs = db.scalars(select(Job).where(Job.type == "appliance-apply")).all()
        assert [job.id for job in jobs] == ["job_active_apply"]
