"""Fail-closed behavior when no Atlaso-owned clock configuration is provable."""

import pytest

from tests.test_appliance_helper import load_helper_module


def test_reconcile_stops_known_controllers_when_applied_config_is_missing(
    monkeypatch, tmp_path
):
    """Exercise test reconcile stops known controllers when applied config is missing.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", tmp_path / "missing.conf")
    monkeypatch.setattr(helper, "_ntpd_recover_interrupted_apply", lambda: None)
    calls = []
    monkeypatch.setattr(helper, "_ntpd_fail_closed_stop", lambda: calls.append("stop") or [])

    result = helper._ntpd_reconcile_applied()

    assert calls == ["stop"]
    assert result["managed"] is False
    assert result["mode"] == "unmanaged"
    assert "known controllers were stopped" in result["detail"]


def test_reconcile_preserves_unowned_vendor_config_while_stopping_controllers(
    monkeypatch, tmp_path
):
    """Exercise test reconcile preserves unowned vendor config while stopping controllers.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = load_helper_module()
    config = tmp_path / "ntp.conf"
    original = b"server vendor.example iburst\n"
    config.write_bytes(original)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    monkeypatch.setattr(helper, "_ntpd_recover_interrupted_apply", lambda: None)
    monkeypatch.setattr(helper, "_ntpd_config_managed", lambda _path: False)
    calls = []
    monkeypatch.setattr(helper, "_ntpd_fail_closed_stop", lambda: calls.append("stop") or [])

    result = helper._ntpd_reconcile_applied()

    assert calls == ["stop"]
    assert result["managed"] is False
    assert config.read_bytes() == original


def test_reconcile_reports_failed_fail_closed_cleanup(monkeypatch, tmp_path):
    """Exercise test reconcile reports failed fail closed cleanup.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", tmp_path / "missing.conf")
    monkeypatch.setattr(helper, "_ntpd_recover_interrupted_apply", lambda: None)
    monkeypatch.setattr(
        helper, "_ntpd_fail_closed_stop", lambda: ["ntpd.service could not be stopped"]
    )

    with pytest.raises(RuntimeError, match="Unable to fail closed"):
        helper._ntpd_reconcile_applied()


def _prepare_missing_config_guard(monkeypatch, tmp_path):
    """Exercise  prepare missing config guard.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", tmp_path / "missing.conf")
    monkeypatch.setattr(helper, "_ntpd_recover_interrupted_apply", lambda **_kwargs: None)
    monkeypatch.setattr(helper, "_ntpd_read_transaction", lambda: None)
    monkeypatch.setattr(helper, "_ntpd_config_managed", lambda _path: False)
    return helper


def test_boot_guard_fails_closed_when_applied_config_is_missing(monkeypatch, tmp_path):
    """Exercise test boot guard fails closed when applied config is missing.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = _prepare_missing_config_guard(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(helper, "_ntpd_fail_closed_stop", lambda: calls.append("stop") or [])

    assert helper._ntpd_guard("boot") == 0
    assert calls == ["stop"]


def test_guard_preserves_a_proven_live_first_apply_candidate(monkeypatch, tmp_path):
    """Exercise test guard preserves a proven live first apply candidate.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = _prepare_missing_config_guard(monkeypatch, tmp_path)
    monkeypatch.setattr(helper, "_ntpd_read_transaction", lambda: {"owner": "live-owner"})
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    monkeypatch.setattr(
        helper,
        "_ntpd_fail_closed_stop",
        lambda: pytest.fail("A live Apply candidate must not be stopped."),
    )

    assert helper._ntpd_guard("boot") == 0
    # An ntpd start without a ready managed candidate remains blocked, without
    # synchronously stopping the service whose ExecStartPre is running.
    assert helper._ntpd_guard("pre-ntpd") == 1


def test_pre_ntpd_guard_disables_its_start_without_stopping_itself(monkeypatch, tmp_path):
    """Exercise test pre ntpd guard disables its start without stopping itself.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = _prepare_missing_config_guard(monkeypatch, tmp_path)
    commands = []
    stopped = []
    cleanup = []
    monkeypatch.setattr(
        helper,
        "_ntpd_run_checked",
        lambda command, _description: commands.append(command),
    )
    monkeypatch.setattr(
        helper, "_ntpd_service_state", lambda _unit: {"enabled": False}
    )
    monkeypatch.setattr(
        helper, "_ntpd_stop_service", lambda unit: stopped.append(unit)
    )
    monkeypatch.setattr(
        helper, "_ntpd_client_packet_guard", lambda mode: cleanup.append(("guard", mode))
    )
    monkeypatch.setattr(
        helper,
        "_ntpd_set_vmware_timesync",
        lambda enabled: cleanup.append(("vmware", enabled)),
    )

    assert helper._ntpd_guard("pre-ntpd") == 1
    assert commands == [["systemctl", "disable", "ntpd.service"]]
    assert "ntpd.service" not in stopped
    assert stopped == ["chronyd.service", "systemd-timesyncd.service"]
    assert cleanup == [("guard", "disabled"), ("vmware", False)]


def test_legacy_pre_ntpd_guard_refuses_start_without_stopping_itself(
    monkeypatch, tmp_path
):
    """Exercise test legacy pre ntpd guard refuses start without stopping itself.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = load_helper_module()
    config = tmp_path / "ntp.conf"
    config.write_text("server legacy.example iburst\n", encoding="utf-8")
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    monkeypatch.setattr(helper, "_ntpd_recover_interrupted_apply", lambda **_kwargs: None)
    monkeypatch.setattr(helper, "_ntpd_read_transaction", lambda: None)
    monkeypatch.setattr(helper, "_ntpd_config_managed", lambda _path: True)
    monkeypatch.setattr(helper, "_ntpd_applied_time_mode", lambda _path: "unmanaged")
    commands = []
    stopped = []
    cleanup = []
    monkeypatch.setattr(
        helper,
        "_ntpd_run_checked",
        lambda command, _description: commands.append(command),
    )
    monkeypatch.setattr(
        helper, "_ntpd_service_state", lambda _unit: {"enabled": False}
    )
    monkeypatch.setattr(
        helper, "_ntpd_stop_service", lambda unit: stopped.append(unit)
    )
    monkeypatch.setattr(
        helper, "_ntpd_client_packet_guard", lambda mode: cleanup.append(("guard", mode))
    )
    monkeypatch.setattr(
        helper,
        "_ntpd_set_vmware_timesync",
        lambda enabled: cleanup.append(("vmware", enabled)),
    )

    assert helper._ntpd_guard("pre-ntpd") == 1
    assert commands == [["systemctl", "disable", "ntpd.service"]]
    assert "ntpd.service" not in stopped
    assert stopped == ["chronyd.service", "systemd-timesyncd.service"]
    assert cleanup == [("guard", "disabled"), ("vmware", False)]


def test_installed_boot_guard_runs_without_ntp_conf(monkeypatch, tmp_path):
    """Exercise test installed boot guard runs without ntp conf.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
    """
    helper = load_helper_module()
    guard_unit = tmp_path / "atlaso-time-sync-guard.service"
    monkeypatch.setattr(helper, "NTP_GUARD_SERVICE_PATH", guard_unit)
    monkeypatch.setattr(helper, "NTP_NTPD_DROPIN_PATH", tmp_path / "ntpd.conf")
    monkeypatch.setattr(helper, "NTP_VMTOOLS_DROPIN_PATH", tmp_path / "vmtools.conf")
    monkeypatch.setattr(helper, "FIREWALL_SERVICE_PATH", tmp_path / "firewall.service")
    monkeypatch.setattr(helper, "_ntpd_run_checked", lambda *_args, **_kwargs: None)

    helper._ntpd_install_guards()

    unit = guard_unit.read_text(encoding="utf-8")
    assert "ExecStart=/opt/atlaso/bin/atlaso-helper ntpd guard boot --real" in unit
    assert "ConditionPathExists=/etc/ntp.conf" not in unit
