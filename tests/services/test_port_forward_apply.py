"""Verify the database decision for paired Firewall and NAT publication."""

import json

import pytest

from atlaso.app import ui
from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.database import SessionLocal
from atlaso.app.models import Job


@pytest.mark.parametrize("management_move", [False, True])
def test_global_submission_publishes_captured_port_forward_pair(client, management_move):
    """The real submission and task runner keep Firewall/NAT baselines together.

    Args:
        client: Isolated application with dry-run host adapters.
        management_move: Include the pair in a protected management handoff.
    """
    from sqlalchemy import select

    from atlaso.app.models import PhysicalInterface, PortForward
    from tests.routers.ui.helpers import login
    from tests.services.test_port_forwarding import payload

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        ui.set_setting_value(db, "routes_wan.routing_enabled", "true")
        db.commit()
        before = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, before, {unit["id"] for unit in before})
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
        if management_move:
            management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
            management.ip_cidr = "192.168.49.21/24"
        db.commit()
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "nat"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        result = json.loads(job.result)
        assert job.status == "succeeded", result
        if management_move:
            assert result["management_handoff"] is True
            assert "nat" in result["management_handoff_units"]
        else:
            assert result["traffic_publishing_pair"] is True
            assert result["traffic_publishing_runtime_commit_pending"] is False
            assert [unit["unit_id"] for unit in result["units"]] == ["firewall", "nat"]
        baselines = ui.load_appliance_apply_baselines(db)
        assert "Atlaso port forward" in baselines["firewall"]["config_preview"]
        assert "[port_forwards]" in baselines["nat"]["config_preview"]
        captured_nat = next(unit for unit in result["captured_units"] if unit["unit_id"] == "nat")
        assert baselines["nat"]["snapshot_hash"] == captured_nat["snapshot_hash"]


@pytest.fixture()
def publication(client, monkeypatch):
    """Create a global task without permitting any host staging.

    Args:
        client: Isolated database and application lifecycle.
        monkeypatch: Substitute only the filesystem staging boundary.
    """
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda path, content: path)
    with SessionLocal() as db:
        job = Job(id="job_123456789abc", type="appliance-apply", status="running", created_by="admin", result="{}")
        db.add(job)
        db.commit()
        units = [{
            "id": key, "label": key, "snapshot_hash": f"captured-{key}", "summary": f"captured {key}",
            "config_path": f"/var/lib/atlaso/apply/{key}/candidate", "raw_config_preview": f"captured {key}",
            "config_preview": f"captured {key}", "config_diff": "", "validation_errors": [], "validation_warnings": [],
        } for key in ("firewall", "nat")]
        yield db, job, units


def test_acknowledgement_observes_both_durable_captured_baselines(publication, monkeypatch):
    """The helper cannot receive ACK while either baseline is uncommitted.

    Args:
        publication: Global task with two captured units.
        monkeypatch: Inspect the durable database at helper boundaries.
    """
    db, job, units = publication
    actions = []

    def helper(self, group, action, *args, **kwargs):
        """Read through a separate session at the acknowledgement boundary.

        Args:
            self: Real-mode adapter with a substituted host boundary.
            group: Constrained helper group.
            action: Publication phase.
            *args: Non-secret task identity and managed paths.
            **kwargs: Bounded execution options.
        """
        actions.append(action)
        if action == "acknowledge-publishing":
            with SessionLocal() as observed:
                baselines = ui.load_appliance_apply_baselines(observed)
                assert baselines["firewall"]["snapshot_hash"] == "captured-firewall"
                assert baselines["nat"]["snapshot_hash"] == "captured-nat"
                assert json.loads(observed.get(Job, job.id).result)["traffic_publishing_application_committed"] is True
        return AdapterResult([group, action], dry_run=False)

    monkeypatch.setattr(SystemAdapter, "_helper_result", helper)
    results = ui.execute_traffic_publishing_pair(db, job, units, adapter=SystemAdapter(dry_run=False))
    assert all(result["success"] for result in results)
    assert actions == ["validate-publishing", "apply-publishing", "acknowledge-publishing"]
    assert json.loads(job.result)["traffic_publishing_runtime_commit_pending"] is False


@pytest.mark.parametrize("failure", ["publication", "baseline", "acknowledgement"])
def test_pair_failure_preserves_the_correct_commit_decision(publication, monkeypatch, failure):
    """Failures before commit roll back; failures after commit retain forward recovery.

    Args:
        publication: Global task with captured units.
        monkeypatch: Inject one failure at a transaction boundary.
        failure: Publication, baseline persistence, or acknowledgement failure.
    """
    db, job, units = publication
    before = ui.load_appliance_apply_baselines(db)
    actions = []

    def helper(self, group, action, *args, **kwargs):
        """Fail only the selected host phase.

        Args:
            self: Adapter whose host boundary is replaced.
            group: Constrained helper group.
            action: Current transaction phase.
            *args: Admitted helper arguments.
            **kwargs: Bounded execution options.
        """
        actions.append(action)
        failed = ((failure == "publication" and action == "apply-publishing")
                  or (failure == "acknowledgement" and action == "acknowledge-publishing"))
        return AdapterResult([group, action], dry_run=False, returncode=int(failed))

    monkeypatch.setattr(SystemAdapter, "_helper_result", helper)
    if failure == "baseline":
        def fail_baseline(*args, **kwargs):
            """Simulate unsuccessful baseline persistence.

            Args:
                *args: Captured baseline inputs.
                **kwargs: Persistence options.
            """
            raise RuntimeError("injected baseline failure")

        monkeypatch.setattr(ui, "update_appliance_apply_baselines", fail_baseline)
        with pytest.raises(RuntimeError, match="baseline failure"):
            ui.execute_traffic_publishing_pair(db, job, units, adapter=SystemAdapter(dry_run=False))
    else:
        results = ui.execute_traffic_publishing_pair(db, job, units, adapter=SystemAdapter(dry_run=False))
        assert not any(result["success"] for result in results)
    if failure != "acknowledgement":
        assert ui.load_appliance_apply_baselines(db) == before
        assert actions[-1] == "recover-publishing"
        assert "acknowledge-publishing" not in actions
    else:
        assert ui.load_appliance_apply_baselines(db)["nat"]["snapshot_hash"] == "captured-nat"
        assert "recover-publishing" not in actions
        job.status = "failed"
        db.commit()
        assert ui.active_appliance_apply_job(db).id == job.id
