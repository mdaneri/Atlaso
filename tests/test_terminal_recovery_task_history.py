"""Verify console recovery preserves terminal task history and runtime ownership."""

import json
from datetime import datetime

import pytest


@pytest.mark.parametrize("status", ["failed", "cancelled"])
@pytest.mark.parametrize("kind", ["network", "management_handoff"])
@pytest.mark.parametrize("recovered", [True, False])
def test_console_terminal_recovery_preserves_task_history(client, monkeypatch, status, kind, recovered):
    """Retry recovery through console admission without rewriting terminal history.

    Args:
        client: Initialized application with an isolated database.
        monkeypatch: Fixture replacing privileged native recovery calls.
        status: Original terminal task disposition.
        kind: Runtime transaction retaining ownership of console admission.
        recovered: Whether native recovery proves the previous configuration ready.
    """
    from atlaso.app import appliance_console, ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    finished = datetime(2026, 10, 22, 16, 55)
    pending_key = f"{kind}_runtime_commit_pending"
    with SessionLocal() as db:
        db.add(Job(id="job_terminal_history", type="appliance-apply", status=status, created_by="admin",
                   finished_at=finished, result=json.dumps({"state": status, pending_key: True})))
        db.commit()
    calls = []

    def reconcile(self, job_id, *, committed=False):
        """Return exact-owner Network recovery evidence.

        Args:
            job_id: Exact retained transaction owner.
            committed: Whether application baseline publication completed.
        """
        calls.append((job_id, committed))
        return AdapterResult(command=["network", "recover"], dry_run=False, returncode=0 if recovered else 1)

    def recover(self, *, startup=False):
        """Return management rollback evidence through the coordinator.

        Args:
            startup: Whether recovery is the startup admission phase.
        """
        calls.append(startup)
        return AdapterResult(command=["management-handoff", "recover"], dry_run=False,
                             stdout=json.dumps({"management_handoff": "rolled_back", "rolled_back": recovered}),
                             returncode=0 if recovered else 1)

    monkeypatch.setattr(ui.SystemAdapter, "reconcile_network_transaction", reconcile)
    monkeypatch.setattr(ui.SystemAdapter, "recover_management_handoff", recover)
    for _attempt in range(2):
        if recovered:
            appliance_console._ensure_no_active_apply()
        else:
            with pytest.raises(appliance_console.ConsoleOperationError, match="still owns runtime recovery"):
                appliance_console._ensure_no_active_apply()
        with SessionLocal() as db:
            job = db.get(Job, "job_terminal_history")
            payload = json.loads(job.result)
            assert job.status == status
            assert job.finished_at == finished
            assert payload["state"] == status
            assert ui._task_row(job)["state"] == status
            assert bool(payload.get(pending_key)) is (not recovered)
            assert payload.get("interrupted") is not True
    assert len(calls) == (1 if recovered else 2)
