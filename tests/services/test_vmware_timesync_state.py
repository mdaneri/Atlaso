"""Focused VMware Tools clock-controller state contracts."""

import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


def _configure_state_probe(monkeypatch, *, returncode, stdout, service_state):
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
