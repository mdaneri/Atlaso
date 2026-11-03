"""Verify guest maintenance admission stays explicit, compatible and durable."""

import json

import pytest
from sqlalchemy import select

from tests.routers.ui.helpers import login


def test_guest_tools_check_is_audited_maintenance_and_serialized(client):
    """A check queues a single child without invoking install or losing its audit.

    Args:
        client: Isolated management client and task database.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job

    login(client)
    page = client.get("/ui/management/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    url = "/ui/management/settings/hardware/guest-tools/check"
    assert client.post(url, data={"csrf": "invalid", "provider": "vmware"}).status_code == 403
    response = client.post(url, data={"csrf": csrf, "provider": "vmware"}, headers={"accept": "application/json"})
    assert response.status_code == 202
    observed = client.get("/ui/management/settings/hardware/status").json()
    assert observed["maintenance_task"]["job_id"] == response.json()["job_id"]
    assert observed["maintenance_task"]["status"] == "pending"
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert json.loads(job.task_config_json)["mode"] == "check"
        assert [step.component_key for step in job.steps] == ["guest_tools"]
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "queue_check_guest_tools")) is not None
    assert client.post(url, data={"csrf": csrf, "provider": "vmware"}).status_code == 409


def test_guest_tools_install_requires_exact_live_review(client, monkeypatch):
    """Only an explicit matching live plan can create a mutation task.

    Args:
        client: Isolated authenticated browser.
        monkeypatch: Read-only helper result replacement.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter

    login(client)
    page = client.get("/ui/management/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    payload = {"provider": "vmware", "state": "missing", "available": True, "review_digest": "a" * 64}
    monkeypatch.setattr(SystemAdapter, "guest_tools_status", lambda self: AdapterResult(
        command=["atlaso-helper"], returncode=0, stdout=json.dumps(payload), stderr="", dry_run=False,
    ))
    url = "/ui/management/settings/hardware/guest-tools/install"
    data = {"csrf": csrf, "provider": "vmware", "review_digest": "b" * 64, "confirmed": "yes"}
    assert client.post(url, data=data).status_code == 409
    data["review_digest"] = "a" * 64
    data["confirmed"] = ""
    assert client.post(url, data=data).status_code == 409
    data["confirmed"] = "yes"
    response = client.post(url, data=data, headers={"accept": "application/json"})
    assert response.status_code == 202


def test_hardware_status_is_private_read_only_and_never_queues(client, monkeypatch):
    """Hardware discovery may observe packages but never schedules maintenance.

    Args:
        client: Isolated management client.
        monkeypatch: Safe hardware/helper observation replacements.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.routers.ui import settings_backup

    login(client)
    monkeypatch.setattr(settings_backup, "hardware_inventory", lambda: {"status": "available", "disks": [], "interfaces": []})
    monkeypatch.setattr(SystemAdapter, "guest_tools_status", lambda self: AdapterResult(
        command=["atlaso-helper"], returncode=1, stdout="", stderr="unavailable", dry_run=False,
    ))
    response = client.get("/ui/management/settings/hardware/status")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["guest_tools"]["state"] == "unknown"
    with SessionLocal() as db:
        assert db.scalar(select(Job)) is None


def test_guest_tools_child_executes_and_terminal_evidence_survives_worker_pass(client, monkeypatch):
    """The Hardware task uses the existing durable child execution and completion path.

    Args:
        client: Isolated appliance application and task database.
        monkeypatch: Bounded helper execution replacement.
    """
    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.guest_tools import queue_guest_tools

    client.get("/ui/management/login")
    calls = []

    def execute(**kwargs):
        """Return a successful read-only provider check.

        Args:
            **kwargs: Exact stored child execution contract.
        """
        calls.append(kwargs["selected_stream_ids"])
        assert kwargs["settings"]["guest_tools"]["provider"] == "qemu"
        return {"unit_id": "guest_tools", "label": "Guest Tools", "mode": "check", "selected_streams": ["guest_tools"],
                "status": "succeeded", "success": True, "dry_run": False, "apply_started": False,
                "commands": [], "restart_after_commit": False, "guest_tools": {"state": "healthy"}}

    monkeypatch.setattr(ui, "execute_appliance_update_job", execute)
    with SessionLocal() as db:
        job_id = queue_guest_tools(db, actor="admin", provider="qemu", mode="check").id
    assert worker.run_worker_once() == job_id
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.status == "succeeded"
        assert len(job.steps) == 1
        assert job.steps[0].status == "succeeded"
        assert json.loads(job.steps[0].result)["guest_tools"]["state"] == "healthy"
    assert worker.run_worker_once() is None
    assert calls == [["guest_tools"]]


@pytest.mark.parametrize("commands", [[], [{"success": True}]])
def test_failed_guest_tools_helper_fails_child_parent_and_audit(client, monkeypatch, capsys, commands):
    """Carry verification failures through the CLI, executor, worker and audit.

    Args:
        client: Isolated application and task database.
        monkeypatch: Safe helper and staging boundary replacements.
        capsys: Captured helper JSON output.
        commands: Empty admission failure or successful commands with failed verification.
    """
    from atlaso.app import ui, worker
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job
    from atlaso.app.services.guest_tools import queue_guest_tools
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    failed = {"status": "failed", "commands": commands, "error": "Guest-tools verification failed."}
    monkeypatch.setattr(helper, "_validate_appliance_update_config_path", lambda path: path)
    monkeypatch.setattr(helper, "_load_appliance_update_config", lambda path: {})
    monkeypatch.setattr(helper, "_load_appliance_update_credentials", lambda args: {})
    monkeypatch.setattr(helper, "_appliance_update_config_errors", lambda *args, **kwargs: [])
    monkeypatch.setattr(helper, "_apply_appliance_update", lambda *args: failed)
    returncode = helper._handle_appliance_update_locked("apply", ["synthetic-config"])
    stdout = capsys.readouterr().out
    monkeypatch.setattr(SystemAdapter, "check_appliance_update_config", lambda *args: AdapterResult(
        command=["synthetic-check"], returncode=0, stdout='{"checks":{}}', dry_run=False,
    ))
    monkeypatch.setattr(SystemAdapter, "apply_appliance_update_config", lambda *args: AdapterResult(
        command=["synthetic-apply"], returncode=returncode, stdout=stdout, dry_run=False,
    ))
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda *args: "synthetic-config")
    client.get("/ui/management/login")
    with SessionLocal() as db:
        job_id = queue_guest_tools(db, actor="admin", provider="vmware", mode="run", review_digest="a" * 64).id
    assert worker.run_worker_once() == job_id
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.status == "failed"
        assert job.steps[0].status == "failed"
        result = json.loads(job.steps[0].result)
        assert result["apply_started"] is True
        assert result["commands"][-1]["returncode"] == 1
        assert json.loads(result["commands"][-1]["stdout"])["status"] == "failed"
        audits = db.scalars(select(AuditEvent).where(AuditEvent.resource_id == job_id)).all()
        assert any(not event.success for event in audits)
