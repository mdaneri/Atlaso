"""Focused adapter contract tests for host clock ownership commands."""

import json

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
    assert calls[0][3]["timeout_seconds"] == 150
    assert calls[1][0:3] == ("ntpd", "reconcile", ())
    assert calls[1][3]["timeout_seconds"] == 90


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
