"""Verify applied clock-source reconciliation at appliance startup."""

from unittest.mock import Mock

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.main import reconcile_startup_time_source


def test_development_startup_does_not_mutate_host(monkeypatch):
    """Exercise test development startup does not mutate host.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    factory = Mock()
    monkeypatch.setattr("atlaso.app.adapters.system.SystemAdapter", factory)
    reconcile_startup_time_source(environment="development")
    factory.assert_not_called()


def test_appliance_startup_reconciles_applied_state(monkeypatch):
    """Exercise test appliance startup reconciles applied state.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    adapter = Mock(spec=SystemAdapter)
    adapter.dry_run = False
    adapter.reconcile_ntpd_time.return_value = AdapterResult(
        command=["atlaso-helper", "ntpd", "reconcile"], dry_run=False,
    )
    monkeypatch.setattr("atlaso.app.adapters.system.SystemAdapter", lambda: adapter)
    reconcile_startup_time_source(environment="appliance")
    adapter.reconcile_ntpd_time.assert_called_once_with()


def test_reconciliation_failure_keeps_management_available(monkeypatch, caplog):
    """Exercise test reconciliation failure keeps management available.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        caplog: Capture startup diagnostics when reconciliation fails.
    """
    adapter = Mock(spec=SystemAdapter)
    adapter.dry_run = False
    adapter.reconcile_ntpd_time.return_value = AdapterResult(
        command=["atlaso-helper", "ntpd", "reconcile"], dry_run=False,
        returncode=2, stderr="conflicting host time mechanism",
    )
    monkeypatch.setattr("atlaso.app.adapters.system.SystemAdapter", lambda: adapter)
    reconcile_startup_time_source(environment="appliance")
    assert "time-source reconciliation needs attention" in caplog.text
    assert "conflicting host time mechanism" not in caplog.text


def test_dry_run_startup_does_not_call_privileged_helper(monkeypatch):
    """Exercise test dry run startup does not call privileged helper.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    adapter = Mock(spec=SystemAdapter)
    adapter.dry_run = True
    monkeypatch.setattr("atlaso.app.adapters.system.SystemAdapter", lambda: adapter)
    reconcile_startup_time_source(environment="appliance")
    adapter.reconcile_ntpd_time.assert_not_called()
