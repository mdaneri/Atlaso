"""Keep proven unadmitted deployment conflicts distinct from uncertain ownership."""

import json
import subprocess

import pytest


@pytest.mark.parametrize("code,payload,retry", [
    (73, {"status": "deployment-busy", "mutation_started": False}, True),
    (75, {"status": "deployment-busy", "mutation_started": False}, False),
    (73, {"status": "deployment-busy", "mutation_started": True}, False),
    (73, {}, False),
])
def test_adapter_requires_explicit_unadmitted_conflict(monkeypatch, code, payload, retry):
    """Only the dedicated return code plus no-mutation proof permits retry.

    Args:
        monkeypatch: Replace the subprocess boundary only.
        code: Helper or systemd transport exit status.
        payload: Final helper JSON record.
        retry: Whether this exact proof is safe to defer.
    """
    from atlaso.app.adapters.system import ApplianceUpdateDeploymentBusy, SystemAdapter

    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(
        command, code, json.dumps(payload) + "\n", "",
    ))
    adapter = SystemAdapter(dry_run=False)
    if retry:
        with pytest.raises(ApplianceUpdateDeploymentBusy):
            adapter.check_appliance_update_config("/fixture/update.json")
    else:
        assert adapter.check_appliance_update_config("/fixture/update.json").returncode == code


@pytest.mark.parametrize("mode,phase", [
    ("check", "check"), ("source_sync", "sync-sources"),
    ("run", "status-publish"), ("run", "check"), ("run", "apply"),
])
def test_busy_update_stays_queued_and_retries_same_task(client, monkeypatch, tmp_path, mode, phase):
    """Exercise helper transport through worker bookkeeping and a later queue claim.

    Args:
        client: Fresh application/database fixture.
        monkeypatch: Replace privileged subprocesses and staging with isolated fixtures.
        tmp_path: Receipted task output root.
        mode: Check, installation or source synchronization.
        phase: Admission point that conflicts with deployment.
    """
    from atlaso.app import ui, worker
    from atlaso.app.adapters.system import SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services import diagnostics, update_sources

    job_id = "job_112345abcdef"
    monkeypatch.setattr(update_sources, "update_source_credentials", lambda db: {})
    monkeypatch.setattr(ui, "SystemAdapter", lambda: SystemAdapter(dry_run=False))
    monkeypatch.setattr(worker, "SystemAdapter", lambda: SystemAdapter(dry_run=False))
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda *_args: str(tmp_path / "update.json"))
    monkeypatch.setattr(worker, "_reconcile_appliance_update_status_surface", lambda: True)
    monkeypatch.setattr(worker, "enqueue_due_schedules", lambda db: None)
    monkeypatch.setattr(diagnostics, "expire", lambda db: None)
    calls = []
    original_run = subprocess.run

    def invoke(command, **kwargs):
        """Return actual adapter input with only the selected phase refused.

        Args:
            command: Exact privileged helper command produced by SystemAdapter.
            **kwargs: Bounded subprocess options.
        """
        if command[0] == "git":
            return original_run(command, **kwargs)
        action = command[command.index("appliance-update") + 1]
        calls.append(action)
        busy = action == phase
        return subprocess.CompletedProcess(
            command, 73 if busy else 0,
            json.dumps({"status": "deployment-busy", "mutation_started": False} if busy else {"checks": {}}) + "\n", "",
        )

    monkeypatch.setattr(subprocess, "run", invoke)
    with SessionLocal() as db:
        db.add(Job(id=job_id, type="appliance-update", status="pending", created_by="admin",
                   task_config_json=json.dumps({"mode": mode, "selected_streams": ["photon_os"],
                                                "execution_order": ["photon_os"], "settings": {},
                                                "schema_version": 2, "status_transaction_id": "a" * 32})))
        db.commit()
    assert worker.run_worker_once() is None
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.status == "pending"
        assert job.error is None and job.cancel_outcome != "cleanup-required"
        result = json.loads(job.result)
        assert result["state"] == "waiting-deployment" and result["retryable"] is True
        assert result.get("ownership_unresolved") is not True
        assert result["apply_started"] is False
        assert all(step.status == "pending" for step in job.steps)
        assert all(not json.loads(step.result or "{}").get("apply_started") for step in job.steps)
    assert phase in calls
    assert "apply" not in calls or phase == "apply"
    resumed = []

    def success(**kwargs):
        """Model successful privileged work after the deployment released its lock.

        Args:
            **kwargs: Stored task identity, mode and streams used by the worker.
        """
        resumed.append(kwargs["job_id"])
        return {"unit_id": "photon_os", "mode": mode, "success": True,
                "status": "succeeded", "dry_run": True, "commands": [],
                "selected_streams": ["photon_os"], "restart_after_commit": False}

    monkeypatch.setattr(ui, "execute_appliance_update_job", success)
    monkeypatch.setattr(worker, "_publish_appliance_update_status", lambda *args, **kwargs: True)
    assert worker.run_worker_once() == job_id
    assert resumed == [job_id]
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.status == "succeeded" and job.error is None
        assert all(step.status == "succeeded" for step in job.steps)


def test_retry_preserves_completed_children_and_uncertain_ownership(client, monkeypatch):
    """Reset only unadmitted running work; retain terminal and cleanup-required state.

    Args:
        client: Fresh application/database fixture.
        monkeypatch: Replace only the admitted runner with a proven contention result.
    """
    from atlaso.app import worker
    from atlaso.app.adapters.system import ApplianceUpdateDeploymentBusy
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    def busy(_job_id):
        """Signal that this attempt made no mutation.

        Args:
            _job_id: Stored update task being retried.
        """
        raise ApplianceUpdateDeploymentBusy()

    monkeypatch.setattr(worker, "_run_appliance_update_admitted", busy)
    with SessionLocal() as db:
        for suffix, cleanup in (("a", False), ("b", True), ("c", False), ("d", False)):
            job = Job(id="job_" + suffix * 12, type="appliance-update", status="running", created_by="admin",
                      cancel_outcome="cleanup-required" if cleanup else None,
                      result=json.dumps({"retained": "evidence", "ownership_unresolved": suffix == "c"}))
            db.add(job)
            steps = ensure_appliance_update_job_steps(
                db, job=job, selected_streams=["photon_os", "powershell_modules"],
                execution_order=["photon_os", "powershell_modules"],
            )
            steps[0].status = "succeeded"
            steps[0].result = '{"status":"succeeded","apply_started":true,"retained":"terminal"}'
            steps[1].status = "running"
            steps[1].result = json.dumps({"apply_started": True, "ownership_unresolved": suffix == "d"})
        db.commit()
    for suffix in ("a", "b", "c", "d"):
        worker._run_appliance_update("job_" + suffix * 12)
    with SessionLocal() as db:
        retried = db.get(Job, "job_" + "a" * 12)
        assert retried.status == "pending"
        assert retried.steps[0].result == '{"status":"succeeded","apply_started":true,"retained":"terminal"}'
        assert retried.steps[1].status == "pending"
        assert json.loads(retried.result)["apply_started"] is True
        assert json.loads(retried.result)["retained"] == "evidence"
        retained = db.get(Job, "job_" + "b" * 12)
        assert retained.status == "running" and retained.cancel_outcome == "cleanup-required"
        assert retained.steps[1].status == "running"
        for suffix in ("c", "d"):
            uncertain = db.get(Job, "job_" + suffix * 12)
            assert uncertain.status == "running" and uncertain.steps[1].status == "running"


def test_busy_status_reconciliation_defers_without_claiming_jobs(client, monkeypatch):
    """A terminal front-door retry must not fail a task or admit another job.

    Args:
        client: Fresh application/database fixture.
        monkeypatch: Isolate only the reconciliation admission conflict.
    """
    from atlaso.app import worker
    from atlaso.app.adapters.system import ApplianceUpdateDeploymentBusy
    from atlaso.app.services import diagnostics

    def busy():
        """Simulate unadmitted status restoration during wheel deployment."""
        raise ApplianceUpdateDeploymentBusy()

    monkeypatch.setattr(worker, "_reconcile_appliance_update_status_surface", busy)
    monkeypatch.setattr(diagnostics, "expire", lambda db: None)
    claimed = []
    monkeypatch.setattr(worker, "claim_next_job", lambda db: claimed.append(True))
    assert worker.run_worker_once() is None
    assert not claimed


def test_busy_quiescence_does_not_prove_prior_helper_stopped(monkeypatch):
    """Unadmitted cleanup retains the previous helper's ownership safeguards.

    Args:
        monkeypatch: Replace the cleanup adapter with the proven admission conflict.
    """
    from atlaso.app import worker
    from atlaso.app.adapters.system import ApplianceUpdateDeploymentBusy, SystemAdapter

    def busy(*args):
        """Refuse cleanup before inspecting or stopping its prior owner.

        Args:
            *args: Prior task and stream identity.
        """
        raise ApplianceUpdateDeploymentBusy()

    monkeypatch.setattr(SystemAdapter, "quiesce_appliance_update_action", busy)
    assert worker._quiesce_appliance_update_action("job_112345abcdef", "photon_os") is False
