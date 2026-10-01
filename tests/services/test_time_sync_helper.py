"""Focused adapter contract tests for host clock ownership commands."""

import json
import subprocess

from atlaso.app.adapters.system import AdapterResult, SystemAdapter


def test_ntpd_adapter_uses_bounded_apply_and_reconcile_commands(monkeypatch):
    calls = []

    def helper(self, group, action, *args, **kwargs):
        calls.append((group, action, args, kwargs))
        return AdapterResult(command=[group, action, *args], dry_run=False)

    monkeypatch.setattr(SystemAdapter, "_helper_result", helper)
    adapter = SystemAdapter(dry_run=False)

    adapter.apply_ntpd_config("/tmp/ntp.conf")
    adapter.reconcile_ntpd_time()

    assert calls[0][0:3] == ("ntpd", "apply", ("/tmp/ntp.conf",))
    assert calls[0][3]["timeout_seconds"] == 360
    assert calls[1][0:3] == ("ntpd", "reconcile", ())
    assert calls[1][3]["timeout_seconds"] == 180


def test_ntpd_apply_allows_helper_rollback_after_original_timeout_window(monkeypatch):
    """Let a completed helper rollback reach the adapter instead of timing out."""
    elapsed_seconds = 200
    observed = {}

    def run(command, **kwargs):
        observed["timeout"] = kwargs["timeout"]
        if elapsed_seconds > kwargs["timeout"]:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(
            command,
            1,
            stdout=json.dumps(
                {"ok": False, "rolled_back": True, "clock_source": "ntp_client"}
            ),
            stderr="candidate clock did not synchronize",
        )

    monkeypatch.setattr("atlaso.app.adapters.system.subprocess.run", run)

    result = SystemAdapter(dry_run=False).apply_ntpd_config("/etc/ntp.conf")

    assert elapsed_seconds > 150
    assert observed["timeout"] == 360
    assert result.returncode == 1
    assert result.returncode != 124
    assert json.loads(result.stdout) == {
        "ok": False,
        "rolled_back": True,
        "clock_source": "ntp_client",
    }


def test_ntpd_status_adapter_is_privileged_and_bounded(monkeypatch):
    calls = []

    def helper(self, group, action, *args, **kwargs):
        calls.append((group, action, args, kwargs))
        return AdapterResult(command=[group, action, *args], dry_run=False)

    monkeypatch.setattr(SystemAdapter, "_helper_result", helper)
    result = SystemAdapter(dry_run=False).read_ntpd_status()

    assert calls == [("ntpd", "status", (), {"dry_run_message": "dry-run: NTPsec status command recorded", "timeout_seconds": 12})]
    assert result.command == ["ntpd", "status"]


def test_ntpd_dry_run_status_never_claims_host_health():
    result = SystemAdapter(dry_run=True).read_ntpd_status()
    payload = json.loads(result.stdout)

    assert result.dry_run is True
    assert payload["mode"] == "unavailable"
    assert payload["synchronization"]["state"] == "unavailable"
    assert payload["synchronization"]["healthy"] is None
    assert "leap_none" not in payload["variables"]["stdout"]
