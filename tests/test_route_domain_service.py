"""Verify routing watcher rollback preserves boot policy before restoring files."""

import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("enabled,active", [(False, False), (True, True), (False, True)])
def test_watcher_rollback_restores_original_runtime_and_boot_policy(monkeypatch, tmp_path, enabled, active):
    """Restore a previously disabled service without implicitly enabling it.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
        enabled: Original systemd boot-enable state to restore.
        active: Original systemd runtime state to restore.
    """
    helper = load_helper_module()
    unit = tmp_path / "atlaso-route-domains.service"
    unit.write_text("candidate")
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", unit)
    calls = []
    monkeypatch.setattr(helper, "_run", lambda command: calls.append(command) or subprocess.CompletedProcess(command, 0))
    monkeypatch.setattr(helper, "_reconcile_route_domains", lambda: calls.append(["reconcile"]))
    state = {"previous_route_domain_service": {"enabled": enabled, "active": active}}
    helper._stop_route_domains_for_restore(state)
    unit.write_text("restored")
    helper._restore_route_domains(state)
    assert calls[0] == ["systemctl", "stop", unit.name]
    assert (["systemctl", "disable", unit.name] in calls) is not enabled
    assert (["systemctl", "enable", unit.name] in calls) is enabled
    assert (["systemctl", "start", unit.name] in calls) is active
    if active:
        assert calls.index(["reconcile"]) < calls.index(["systemctl", "start", unit.name])


def test_failed_watcher_stop_leaves_handoff_network_files_untouched(monkeypatch, tmp_path):
    """A quiesce failure must retain every artifact needed for retry.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
    helper = load_helper_module()
    unit = tmp_path / "atlaso-route-domains.service"
    unit.write_text("candidate unit")
    network = tmp_path / "00-atlaso-mgmt.network"
    network.write_text("candidate network")
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", unit)
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", network)
    calls = []
    monkeypatch.setattr(helper, "_run", lambda command: calls.append(command) or subprocess.CompletedProcess(command, 1))
    with pytest.raises(ValueError, match="could not stop"):
        helper._restore_management_handoff({})
    assert network.read_text() == "candidate network"
    assert unit.read_text() == "candidate unit"
    assert calls == [["systemctl", "stop", unit.name]]


def test_first_apply_rollback_removes_boot_link_before_unit_removal(monkeypatch, tmp_path):
    """An absent prior service must not leave an enabled dangling unit.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
    helper = load_helper_module()
    unit = tmp_path / "atlaso-route-domains.service"
    unit.write_text("candidate")
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", unit)
    calls = []
    monkeypatch.setattr(helper, "_run", lambda command: calls.append((command, unit.exists())) or subprocess.CompletedProcess(command, 0))
    monkeypatch.setattr(helper, "_reconcile_route_domains", lambda: None)
    helper._stop_route_domains_for_restore({})
    unit.unlink()
    helper._restore_route_domains({})
    assert calls == [
        (["systemctl", "stop", unit.name], True),
        (["systemctl", "disable", unit.name], True),
        (["systemctl", "daemon-reload"], False),
    ]


def test_factory_reset_quiesces_old_domain_before_flushing_routes(monkeypatch, tmp_path):
    """A watcher cannot repopulate pre-reset rules during factory activation.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
    helper = load_helper_module()
    unit = tmp_path / "atlaso-route-domains.service"
    unit.write_text("unit")
    intent = tmp_path / "route-domains.json"
    intent.write_text('{"schema":1,"interfaces":[]}')
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", unit)
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", intent)
    monkeypatch.setattr(helper, "_factory_reset_runtime_cleanup_is_admitted", lambda: True)
    monkeypatch.setattr(helper.shutil, "which", lambda command: command)
    monkeypatch.setattr(helper, "_factory_reset_managed_vlan_names", lambda: [])
    monkeypatch.setattr(helper, "_factory_reset_wan_route_interfaces", lambda: [])
    monkeypatch.setattr(helper, "_factory_reset_root_netem_interfaces", lambda _interfaces: [])
    monkeypatch.setattr(helper, "_reset_factory_port_forward_runtime", lambda: None)
    monkeypatch.setattr(helper, "_clear_factory_network_conflicts", lambda: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda _path: None)
    operations = []
    monkeypatch.setattr(helper, "_run", lambda command: operations.append(command) or subprocess.CompletedProcess(command, 0, "", ""))

    def reconcile():
        """Require absent intent before the old exact-source rules are retired."""
        assert not intent.exists()
        operations.append(["reconcile"])

    monkeypatch.setattr(helper, "_reconcile_route_domains", reconcile)
    monkeypatch.setattr(helper, "_restore_route_domain_rules", lambda rows: operations.append(["retire-ingress", rows]))
    assert helper._reset_factory_network_runtime() == 0
    assert operations[:3] == [
        ["systemctl", "stop", unit.name], ["systemctl", "disable", unit.name], ["reconcile"],
    ]
    assert operations[3] == ["retire-ingress", []]
    assert operations[4][-1] == "--transition-stop"
    assert operations[5][:4] == ["ip", "route", "flush", "table"]
