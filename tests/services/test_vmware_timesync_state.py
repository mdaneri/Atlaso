"""Focused VMware Tools clock-controller state contracts."""

import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


def _configure_state_probe(monkeypatch, *, returncode, stdout, service_state):
    """Exercise  configure state probe.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        returncode: Simulated VMware toolbox process exit status.
        stdout: Simulated VMware toolbox time-sync output.
        service_state: Observed vmtoolsd activity and persistent enablement.
    """
    helper = load_helper_module()
    monkeypatch.setattr(
        helper.shutil, "which", lambda _command: "/usr/bin/vmware-toolbox-cmd"
    )
    monkeypatch.setattr(
        helper,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], returncode, stdout, ""
        ),
    )
    monkeypatch.setattr(
        helper, "_ntpd_service_state", lambda _unit: service_state.copy()
    )
    return helper


def test_disabled_periodic_sync_is_inactive_even_when_vmtoolsd_is_running(monkeypatch):
    """Exercise test disabled periodic sync is inactive even when vmtoolsd is running.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    helper = _configure_state_probe(
        monkeypatch,
        returncode=69,
        stdout="Disabled\n",
        service_state={"active": True, "enabled": True, "detail": "active; enabled"},
    )

    state = helper._ntpd_vmware_timesync_state()

    assert state["periodic_enabled"] is False
    assert state["active"] is False
    assert state["enabled"] is False


def test_periodic_sync_active_but_tools_service_disabled_is_not_healthy(monkeypatch):
    """Exercise test periodic sync active but tools service disabled is not healthy.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    helper = _configure_state_probe(
        monkeypatch,
        returncode=0,
        stdout="Enabled\n",
        service_state={"active": True, "enabled": False, "detail": "active; disabled"},
    )

    state = helper._ntpd_vmware_timesync_state()

    assert state["periodic_enabled"] is True
    assert state["active"] is True
    assert state["enabled"] is False


def test_unknown_physical_service_state_never_claims_periodic_sync_active(monkeypatch):
    """Exercise test unknown physical service state never claims periodic sync active.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    helper = _configure_state_probe(
        monkeypatch,
        returncode=0,
        stdout="Enabled\n",
        service_state={"active": None, "enabled": True, "detail": "active state unavailable"},
    )

    state = helper._ntpd_vmware_timesync_state()

    assert state["periodic_enabled"] is True
    assert state["active"] is None
    assert state["enabled"] is True


@pytest.mark.parametrize(
    ("returncode", "stdout", "expected"),
    [
        (69, "Disabled\n", False),
        (0, "enabled\n", True),
        (1, "state unavailable\n", None),
    ],
)
def test_periodic_flag_is_exposed_as_tri_state(
    monkeypatch, returncode, stdout, expected
):
    """Exercise test periodic flag is exposed as tri state.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        returncode: Simulated VMware toolbox process exit status.
        stdout: Simulated VMware toolbox time-sync output.
        expected: Expected normalized result for the injected service observation.
    """
    helper = _configure_state_probe(
        monkeypatch,
        returncode=returncode,
        stdout=stdout,
        service_state={"active": True, "enabled": True, "detail": "active; enabled"},
    )

    state = helper._ntpd_vmware_timesync_state()

    assert state["periodic_enabled"] is expected
    if expected is None:
        assert state["active"] is None
        assert state["enabled"] is None


@pytest.mark.parametrize(
    ("enabled", "status", "should_raise"),
    [
        (False, {"periodic_enabled": False, "active": False}, False),
        # An inactive vmtoolsd service alone cannot prove the periodic flag
        # was disabled; this was the false-success regression.
        (False, {"periodic_enabled": True, "active": False}, True),
        # Enabling periodic sync must also prove vmtoolsd is active.
        (True, {"periodic_enabled": True, "active": None}, True),
        (True, {"periodic_enabled": True, "active": True}, False),
    ],
)
def test_setter_verifies_raw_periodic_flag_and_effective_activation(
    monkeypatch, enabled, status, should_raise
):
    """Exercise test setter verifies raw periodic flag and effective activation.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        enabled: Requested VMware periodic synchronization setting.
        status: Observed raw periodic flag and effective Tools service activity.
        should_raise: Whether the supplied observation must fail setter verification.
    """
    helper = load_helper_module()
    monkeypatch.setattr(
        helper.shutil, "which", lambda _command: "/usr/bin/vmware-toolbox-cmd"
    )
    commands = []
    monkeypatch.setattr(
        helper,
        "_ntpd_run_checked",
        lambda command, _description: commands.append(command),
    )
    monkeypatch.setattr(helper, "_ntpd_vmware_timesync_state", lambda: status)

    if should_raise:
        with pytest.raises(RuntimeError, match="could not be verified"):
            helper._ntpd_set_vmware_timesync(enabled)
    else:
        helper._ntpd_set_vmware_timesync(enabled)

    assert commands == [
        ["/usr/bin/vmware-toolbox-cmd", "timesync", "enable" if enabled else "disable"]
    ]


def test_service_hook_can_set_periodic_flag_before_vmtoolsd_is_active(monkeypatch):
    """Lifecycle hooks verify the raw setting while systemd changes vmtoolsd.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    helper = load_helper_module()
    monkeypatch.setattr(
        helper.shutil, "which", lambda _command: "/usr/bin/vmware-toolbox-cmd"
    )
    monkeypatch.setattr(helper, "_ntpd_run_checked", lambda *_args: None)
    monkeypatch.setattr(
        helper,
        "_ntpd_vmware_timesync_state",
        lambda: {"periodic_enabled": True, "active": False, "enabled": False},
    )

    helper._ntpd_set_vmware_timesync(True, require_active=False)

    with pytest.raises(RuntimeError, match="could not be verified"):
        helper._ntpd_set_vmware_timesync(True)


@pytest.mark.parametrize("mode", ["ntp_client", "vmware_tools"])
def test_post_vmtoolsd_hook_uses_transition_aware_verification(
    monkeypatch, tmp_path, mode
):
    """Both hook branches verify the setting without requiring service activity.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
        tmp_path: Isolated filesystem fixture for applied configuration and evidence.
        mode: Selected appliance clock mode under test.
    """
    helper = load_helper_module()
    config = tmp_path / "ntp.conf"
    config.write_text(
        f"# Atlaso NTP enabled: {'true' if mode == 'ntp_client' else 'false'}\n"
        f"# Atlaso time mode: {mode}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    monkeypatch.setattr(helper, "_ntpd_config_managed", lambda _path: True)
    monkeypatch.setattr(helper, "_ntpd_applied_time_mode", lambda _path: mode)
    monkeypatch.setattr(helper, "_ntpd_recover_interrupted_apply", lambda **_kwargs: None)
    monkeypatch.setattr(helper, "_ntpd_stop_service", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_ntpd_client_packet_guard", lambda _mode: None)
    monkeypatch.setattr(helper, "_ntpd_run_checked", lambda *_args, **_kwargs: None)
    setter_calls = []

    def set_timesync(enabled, *, require_active=True):
        """Exercise set timesync.

        Args:
            enabled: Requested VMware periodic synchronization setting.
            require_active: Whether the setter must verify vmtoolsd is running.
        """
        setter_calls.append((enabled, require_active))

    monkeypatch.setattr(helper, "_ntpd_set_vmware_timesync", set_timesync)

    assert helper._ntpd_guard("post-vmtoolsd") == 0
    assert setter_calls == [(mode == "vmware_tools", False)]


def test_service_hook_still_rejects_unverified_periodic_flag(monkeypatch):
    """Exercise test service hook still rejects unverified periodic flag.

    Args:
        monkeypatch: Replace host operations with controlled test observations.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda _command: "/usr/bin/vmware-toolbox-cmd")
    monkeypatch.setattr(helper, "_ntpd_run_checked", lambda *_args: None)
    monkeypatch.setattr(
        helper,
        "_ntpd_vmware_timesync_state",
        lambda: {"periodic_enabled": False, "active": False, "enabled": False},
    )

    with pytest.raises(RuntimeError, match="could not be verified"):
        helper._ntpd_set_vmware_timesync(True, require_active=False)
