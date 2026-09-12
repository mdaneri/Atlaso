"""Bound update checks without releasing unverified helper ownership."""

import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def helper(monkeypatch):
    """Load the helper with privileged filesystem preparation replaced.

    Args:
        monkeypatch: Test-local replacement of host operations.
    """
    path = Path(__file__).resolve().parents[1] / "scripts/appliance/atlaso-helper"
    loader = importlib.machinery.SourceFileLoader("deadline_helper", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    monkeypatch.setattr(module, "_privileged_powershell_environment", lambda: {
        "HOME": "/unused", "XDG_CACHE_HOME": "/unused/cache",
        "XDG_CONFIG_HOME": "/unused/config", "XDG_DATA_HOME": "/unused/data",
    })
    return module


@pytest.mark.parametrize("outcome", ["success", "timeout", "cleanup-failure"])
def test_check_deadline_keeps_process_tree_and_cleanup_owned(helper, monkeypatch, tmp_path, outcome):
    """Exercise the deadline and cleanup ordering without running systemd.

    Args:
        helper: Isolated helper module.
        monkeypatch: Test-local command replacement.
        tmp_path: Temporary manifest directory.
        outcome: Completion or failure to simulate.
    """
    manifest = tmp_path / "check.json"
    manifest.write_text(json.dumps({"job_id": "job_012345abcdef", "selected_streams": ["photon_os"]}))
    events = []

    def run(command, *, timeout=None):
        """Capture the owning command and simulate a stalled transport.

        Args:
            command: Complete helper command.
            timeout: Transport deadline.
        """
        events.append("run")
        assert "--property=RuntimeMaxSec=300" in command
        assert "--property=TimeoutStopSec=30" in command
        assert "--property=KillMode=control-group" in command
        assert "--property=SendSIGKILL=yes" in command
        assert timeout == 360
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(command, timeout)
        return subprocess.CompletedProcess(command, 0, "", "")

    def quiesce(unit, *, bounded=False):
        """Require exact task ownership before releasing transient credentials.

        Args:
            unit: Unit selected for verification.
            bounded: Whether systemctl itself is bounded.
        """
        events.append("quiesce")
        assert unit == helper._appliance_update_action_unit_name("job_012345abcdef", "photon_os") + ".service"
        assert bounded
        if outcome == "cleanup-failure":
            raise ValueError("not stopped")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_quiesce_appliance_update_unit", quiesce)
    monkeypatch.setattr(helper, "_cleanup_stale_photon_repository_views", lambda **kwargs: events.append("credentials"))
    result = helper._run_real_action_with_systemd("appliance-update", "check", [str(manifest)])
    assert result == {"success": 0, "timeout": 124, "cleanup-failure": 75}[outcome]
    assert events == (["run", "quiesce"] if outcome == "cleanup-failure" else ["run", "quiesce", "credentials"])


def test_install_has_no_check_deadline(helper, monkeypatch):
    """Never apply a read-only check deadline to package mutation.

    Args:
        helper: Isolated helper module.
        monkeypatch: Test-local command replacement.
    """
    commands = []
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command) or subprocess.CompletedProcess(command, 0, "", ""))
    assert helper._run_real_action_with_systemd("appliance-update", "apply", ["/missing/config"]) == 0
    assert not any("RuntimeMaxSec" in item for item in commands[0])


def test_check_cleanup_preserves_other_owners(helper, monkeypatch, tmp_path):
    """Release only this stopped check's credential view, never foreign state.

    Args:
        helper: Isolated helper module.
        monkeypatch: Test-local process and path replacement.
        tmp_path: Private synthetic runtime root.
    """
    owner = "atlaso-helper-action-" + "a" * 32
    own = tmp_path / f"atlaso-tdnf-repositories-100-200-{owner}-test"
    foreign = tmp_path / "atlaso-tdnf-repositories-101-201-other-test"
    for directory in (own, foreign):
        directory.mkdir(mode=0o700)
    monkeypatch.setattr(helper, "_photon_repository_runtime_root", lambda: tmp_path)
    monkeypatch.setattr(helper, "_process_start_identity", lambda pid: "200")
    with pytest.raises(ValueError, match="live owner"):
        helper._cleanup_stale_photon_repository_views(check_owner=owner)
    assert own.exists() and foreign.exists()
    monkeypatch.setattr(helper, "_process_start_identity", lambda pid: "")
    helper._cleanup_stale_photon_repository_views(check_owner=owner)
    assert not own.exists()
    assert foreign.exists()


def test_unverified_check_retains_parent_child_and_blocks_queue(client, monkeypatch):
    """Do not run another child or queued job while the previous owner may live.

    Args:
        client: Isolated database/application fixture.
        monkeypatch: Replacement of privileged work and status probes.
    """
    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services import diagnostics, update_sources

    calls = []
    monkeypatch.setattr(update_sources, "update_source_credentials", lambda db: {})
    monkeypatch.setattr(ui, "execute_appliance_update_job", lambda **kwargs: calls.append(kwargs["selected_stream_ids"]) or {"ownership_unresolved": True})
    monkeypatch.setattr(worker, "_reconcile_appliance_update_status_surface", lambda: True)
    monkeypatch.setattr(diagnostics, "expire", lambda db: None)
    with SessionLocal() as db:
        db.add(Job(id="job_012345abcdef", type="appliance-update", status="running", created_by="admin",
                   task_config_json=json.dumps({"mode": "check", "selected_streams": ["photon_os", "powershell_modules"],
                                                "execution_order": ["photon_os", "powershell_modules"]})))
        db.add(Job(id="queued-script", type="managed-script", status="pending", created_by="admin"))
        db.commit()
    worker._run_appliance_update("job_012345abcdef")
    assert calls == [["photon_os"]]
    assert worker.run_worker_once() is None
    with SessionLocal() as db:
        parent = db.get(Job, "job_012345abcdef")
        assert parent.status == "running"
        assert json.loads(parent.result)["state"] == "cleanup-required"
        assert [step.status for step in parent.steps] == ["running", "pending"]
        assert db.get(Job, "queued-script").status == "pending"


def test_stopped_failed_check_finishes_other_streams_and_releases_queue(client, monkeypatch):
    """A proven stopped timeout is terminal, so later checks and jobs can run.

    Args:
        client: Isolated database/application fixture.
        monkeypatch: Replacement of privileged checks and worker admission.
    """
    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services import diagnostics, update_sources

    calls = []

    def execute(**kwargs):
        """Simulate one timed-out check followed by an independent check.

        Args:
            **kwargs: Worker-selected stream and mode.
        """
        stream = kwargs["selected_stream_ids"][0]
        calls.append(stream)
        success = stream != "photon_os"
        return {"unit_id": stream, "mode": "check", "success": success,
                "status": "succeeded" if success else "failed", "commands": [],
                "dry_run": True, "restart_after_commit": False,
                "error": "Check deadline exceeded; helper stopped." if not success else ""}

    monkeypatch.setattr(update_sources, "update_source_credentials", lambda db: {})
    monkeypatch.setattr(ui, "execute_appliance_update_job", execute)
    monkeypatch.setattr(worker, "_reconcile_appliance_update_status_surface", lambda: True)
    monkeypatch.setattr(diagnostics, "expire", lambda db: None)
    with SessionLocal() as db:
        db.add(Job(id="job_112345abcdef", type="appliance-update", status="running", created_by="admin",
                   task_config_json=json.dumps({"mode": "check", "selected_streams": ["photon_os", "powershell_modules"],
                                                "execution_order": ["photon_os", "powershell_modules"]})))
        db.commit()
    worker._run_appliance_update("job_112345abcdef")
    with SessionLocal() as db:
        parent = db.get(Job, "job_112345abcdef")
        assert parent.status == "failed"
        assert [step.status for step in parent.steps] == ["failed", "succeeded"]
    assert calls == ["photon_os", "powershell_modules"]
    claimed = []
    monkeypatch.setattr(worker, "enqueue_due_schedules", lambda db: None)
    monkeypatch.setattr(worker, "claim_next_job", lambda db: claimed.append(True))
    assert worker.run_worker_once() is None
    assert claimed == [True]
