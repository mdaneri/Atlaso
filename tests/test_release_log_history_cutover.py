"""Verify forward-only release cutover and exact worker identity revalidation."""

import json
import subprocess

import pytest

from tests.test_appliance_update import load_helper_module


def test_forward_completion_rejects_provisional_transaction_without_mutation(monkeypatch):
    """The migration entry cannot turn a rollback-capable transaction into a commit.

    Args:
        monkeypatch: Fixture guarding all history mutation boundaries.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_complete_release_log_history", lambda *args: pytest.fail("Not committed"))
    monkeypatch.setattr(helper, "_write_release_finalizer", lambda *args: pytest.fail("Cannot promote status"))
    result = helper._complete_committed_release_activation({"status": "restart_pending", "job_id": "job-history"})
    assert result["status"] == "restart_pending"
    assert not result["success"] and not result["allow_worker"]


@pytest.mark.parametrize("failure", ["", "app", "external", "worker"])
def test_committed_history_dispatches_independent_units_and_reproves_worker(tmp_path, monkeypatch, failure):
    """Keep stopping/restarting producers outside their owning helper cgroup.

    Args:
        tmp_path: Isolated candidate release path.
        monkeypatch: Fixture substituting systemd calls and process identity proof.
        failure: Migration or worker proof failure injected at its actual boundary.
    """
    helper = load_helper_module()
    commands = []
    identity = []

    def run(command, **kwargs):
        """Record the independent invocation and inject one failed subprocess.

        Args:
            command: Fixed root-owned transient service invocation.
            **kwargs: Bounded command execution options.
        """
        commands.append(command)
        module = command[command.index("-m") + 1]
        failed = ((failure == "app" and module.endswith("app_history_cutover"))
                  or (failure == "external" and module.endswith("external_history_lifecycle")))
        assert kwargs["timeout"] == 660
        return subprocess.CompletedProcess(command, int(failed), "synthetic untrusted stdout", "synthetic stderr")

    def worker(**kwargs):
        """Prove the current candidate worker after any intentional restart.

        Args:
            **kwargs: Complete expected job/release/version identity.
        """
        identity.append(kwargs)
        return {"success": failure != "worker", "worker_pid": 73, "worker_start_ticks": "1234"}

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_wait_for_worker_activation", worker)
    result, evidence = helper._complete_release_log_history(tmp_path, {"version": "0.9.359"}, "job-history")
    assert result["success"] is (not failure)
    assert len(commands) == (1 if failure == "app" else 2)
    for command in commands:
        assert command[0] == "systemd-run"
        assert "--wait" in command and "--collect" in command
        assert command[command.index("-I") - 1] == str(tmp_path / ".venv/bin/python")
    assert "--if-needed" in commands[0]
    assert "--already-stopped" not in commands[0]
    assert "synthetic" not in json.dumps(evidence)
    if failure not in {"app", "external"}:
        assert identity == [{"expected_version": "0.9.359", "expected_release": tmp_path,
                             "expected_job_id": "job-history", "previous_pid": 0}]
    else:
        assert not identity


@pytest.mark.parametrize("failed", [False, True])
def test_history_cutover_stays_behind_committed_maintenance_and_gate(tmp_path, monkeypatch, failed):
    """Never roll back committed capture or open the front door after migration failure.

    Args:
        tmp_path: Isolated candidate receipt and restart gate.
        monkeypatch: Fixture substituting system operations.
        failed: Whether the independently executed migration fails.
    """
    helper = load_helper_module()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / ".release-manifest.json").write_text('{"version":"0.9.359"}', encoding="utf-8")
    gate = tmp_path / "gate"
    gate.write_text("job-history", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_RESTART_GATE_PATH", gate)
    monkeypatch.setattr(helper, "_active_release_root", lambda: candidate)
    monkeypatch.setattr(helper, "_validated_release_recovery_context", lambda parsed: {"candidate": candidate})
    events = []
    finalizers = []

    def maintenance(enabled):
        """Observe whether migration runs while front-door writes remain excluded.

        Args:
            enabled: Requested maintenance state.
        """
        events.append(("maintenance", enabled))
        return {"success": True}

    def migrate(*args):
        """Record the migration boundary before internal and host-facing readiness.

        Args:
            *args: Validated candidate, receipt and job identity.
        """
        assert events[-1] == ("maintenance", True)
        assert gate.read_text() == "job-history"
        events.append(("migration", not failed))
        return {"success": not failed, "worker_restart": {"worker_pid": 73}}, []

    monkeypatch.setattr(helper, "_set_release_maintenance", maintenance)
    monkeypatch.setattr(helper, "_complete_release_log_history", migrate)
    monkeypatch.setattr(helper, "_sync_release_activation", lambda: {"success": True})
    monkeypatch.setattr(helper, "_release_activation_verification", lambda *args, **kwargs: ({"success": True}, []))
    monkeypatch.setattr(helper, "_write_release_finalizer", lambda payload: finalizers.append(payload.copy()))
    monkeypatch.setattr(helper, "_write_update_info", lambda payload: None)
    monkeypatch.setattr(helper, "_set_release_restart_gate", lambda enabled: events.append(("gate", enabled)))
    monkeypatch.setattr(helper, "_restore_sqlite_backup", lambda *args: pytest.fail("Committed state must never roll back"))
    result = helper._complete_committed_release_activation({
        "status": "activation_committed", "job_id": "job-history", "commands": [],
    })
    assert result["success"] is (not failed)
    if failed:
        assert result["status"] == "activation_committed" and result["rolled_back"] is False
        assert ("maintenance", False) not in events
        assert ("gate", False) not in events
    else:
        assert [item["status"] for item in finalizers] == ["activation_committed", "succeeded"]
        assert finalizers[0]["producer_history"]["success"]
        assert finalizers[0]["worker_restart"]["worker_pid"] == 73
        assert events.index(("migration", True)) < events.index(("maintenance", False))
        assert events[-1] == ("gate", False)
