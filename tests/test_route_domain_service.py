"""Verify routing watcher rollback preserves boot policy before restoring files."""

import json
import subprocess

import pytest

from atlaso import route_domains
from tests.test_appliance_helper import load_helper_module


@pytest.fixture
def route_domain_install(monkeypatch, tmp_path):
    """Prepare a same-interface table-100 to table-200 migration boundary.

    Args:
        monkeypatch: Replace native observations and activation commands.
        tmp_path: Isolated candidate files and published intent.
    """
    helper = load_helper_module()
    candidate = tmp_path / "candidate-network.conf"
    candidate.write_text(
        "# Network identity pins: reviewed-mac-v1.\n"
        "[physical_interfaces]\ninterface=eth0\n  mac=02:00:00:00:00:01\n",
        encoding="utf-8",
    )
    intent_path = tmp_path / "route-domains.json"
    service_path = tmp_path / "atlaso-route-domains.service"
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", intent_path)
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", service_path)
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: (
        [{"name": "eth0", "mac": "02:00:00:00:00:01", "role": "access",
          "mode": "access", "admin_state": "up"}], [], [],
    ))
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda: {"Name": []})
    inventory = [{"ifname": "eth0", "address": "02:00:00:00:00:01", "addr_info": [
        {"scope": "global", "local": "192.0.2.10"},
    ]}]
    monkeypatch.setattr(helper, "_network_observation_command", lambda command:
                        subprocess.CompletedProcess(command, 0, json.dumps(inventory), ""))
    events = []

    def publish_intent(intent, path):
        """Write the same candidate payload observed by route-domain reconciliation.

        Args:
            intent: Reviewed applied intent being published.
            path: Candidate intent path.
        """
        path.write_text(json.dumps(intent), encoding="utf-8")
        events.append("intent-published")

    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", publish_intent)
    monkeypatch.setattr(helper, "_fsync_file", lambda _path: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda _path: None)
    existing_rules = {
        route_domains.Rule(5000, "192.0.2.10", 100),
        route_domains.Rule(5001, "192.0.2.10", None),
    }

    def observed_rule_rows():
        """Project the synthetic kernel rules into the native iproute2 shape."""
        rows = []
        for rule in existing_rules:
            row = {
                "priority": rule.priority,
                "src": str(rule.source),
                "srclen": 32 if rule.family == 4 else 128,
                "iif": "lo",
                "protocol": str(route_domains.PROTOCOL),
            }
            if rule.table is None:
                row["action"] = "unreachable"
            else:
                row["table"] = str(rule.table)
            rows.append(row)
        return rows

    def read_native(arguments):
        """Return synthetic native addresses and the currently installed rules.

        Args:
            arguments: Read-only iproute2 query made by the route-domain module.
        """
        if arguments == ["address", "show"]:
            return inventory
        if arguments in (["-4", "rule", "show"], ["-6", "rule", "show"]):
            return observed_rule_rows() if arguments[0] == "-4" else []
        raise AssertionError(f"unexpected route-domain observation: {arguments!r}")

    monkeypatch.setattr(route_domains, "read_native", read_native)

    def apply_rule(command):
        """Apply the real planner's exact rule mutation to the synthetic kernel state.

        Args:
            command: Canonical route-domain rule command emitted by the planner.
        """
        table = int(command[-1]) if command[-2] == "table" else None
        rule = route_domains.Rule(int(command[5]), command[7].split("/", maxsplit=1)[0], table)
        if command[3] == "add":
            existing_rules.add(rule)
        else:
            existing_rules.remove(rule)
        events.append(("rule", command[3], rule))

    monkeypatch.setattr(route_domains, "run_ip", apply_rule)

    def run(command):
        """Run the real source planner and route-domain prestart checks.

        Args:
            command: Privileged helper systemd or route-domain command.
        """
        if command[-2:] == ["atlaso.route_domains", "--once"]:
            events.append("reconcile-start")
            intent = route_domains.parse_intent(json.loads(intent_path.read_text(encoding="utf-8")))
            sources, incomplete = route_domains.source_tables(intent, inventory)
            assert not incomplete
            assert sources == {"192.0.2.10": 200}
            desired = route_domains.plan_rules(sources, existing_rules)
            route_domains.apply_rules(desired, existing_rules)
            events.append("reconciled")
            return subprocess.CompletedProcess(command, 0, "", "")
        events.append(tuple(command))
        if command in (["systemctl", "enable", "--now", service_path.name],
                       ["systemctl", "restart", service_path.name]):
            # ExecStartPre --transition-start seeds candidate bindings before --once.
            events.append("transition-start")
            try:
                route_domains._seed_transition_sources_locked([{
                    "name": "eth0", "mac": "02:00:00:00:00:01", "table": 200,
                }])
            except route_domains.ReconcileError:
                return subprocess.CompletedProcess(command, 1, "", "")
            events.append("transition-start-ready")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    return helper, candidate, intent_path, service_path, events, existing_rules


@pytest.mark.parametrize("previous,started", [(False, False), (False, True), (True, False), (True, True)])
def test_rollback_restores_captured_guard_even_before_forward_activation(monkeypatch, previous, started):
    """Rollback reconciliation cannot introduce or remove a preexisting guard.

    Args:
        monkeypatch: Canonical guard mutation boundary.
        previous: Independently captured native guard state.
        started: Forward handoff activation progress before the failure.
    """
    helper = load_helper_module()
    calls = []
    monkeypatch.setattr(helper, "_transition_source_guard", calls.append)
    helper._restore_transition_source_guard({
        "previous_source_transition_guard": previous,
        "source_transition_guard": started,
        "previous_route_domain_service": {"active": False},
    })
    assert calls == [previous]


@pytest.mark.parametrize("previous,active", [(None, False), ("false", False), (False, True)])
def test_rollback_refuses_invalid_captured_guard_without_mutation(monkeypatch, previous, active):
    """Malformed or contradictory journal state cannot retire the isolation guard.

    Args:
        monkeypatch: Guard retirement boundary.
        previous: Invalid captured value, or contradictory absent guard.
        active: Whether the old routing watcher was running.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_transition_source_guard", lambda *_args: pytest.fail("unproven guard mutation"))
    with pytest.raises(ValueError):
        helper._restore_transition_source_guard({
            "previous_source_transition_guard": previous,
            "previous_route_domain_service": {"active": active},
        })


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


def test_source_migration_reconciles_before_route_domain_service_activation(route_domain_install):
    """Published candidate intent migrates existing sources before ExecStartPre.

    Args:
        route_domain_install: Same-interface native source migration harness.
    """
    helper, candidate, intent_path, service_path, events, active_rules = route_domain_install

    helper._install_route_domain_intent(candidate)

    published = json.loads(intent_path.read_text(encoding="utf-8"))
    assert published["interfaces"] == [{
        "name": "eth0", "mac": "02:00:00:00:00:01", "table": 200, "management_ui": False,
    }]
    assert events.index("intent-published") < events.index("reconcile-start") < events.index("reconciled")
    enable = ("systemctl", "enable", "--now", service_path.name)
    restart = ("systemctl", "restart", service_path.name)
    assert events.index("reconciled") < events.index(("systemctl", "daemon-reload")) < events.index(enable)
    assert events.index(enable) < events.index(restart)
    assert route_domains.Rule(5000, "192.0.2.10", 200) in active_rules
    assert route_domains.Rule(5000, "192.0.2.10", 100) not in active_rules


def test_route_domain_reconcile_failure_prevents_service_activation(monkeypatch, route_domain_install):
    """A reconciliation failure prevents systemd from activating the candidate.

    Args:
        monkeypatch: Replace reconciliation with a deterministic failure.
        route_domain_install: Candidate paths and command recorder.
    """
    helper, candidate, intent_path, service_path, events, _active_rules = route_domain_install

    def fail_reconciliation():
        """Represent an ownership/conflict refusal from the route-domain reconciler."""
        events.append("reconcile-failed")
        raise ValueError("routing-domain source reconciliation failed")

    monkeypatch.setattr(helper, "_reconcile_route_domains", fail_reconciliation)
    with pytest.raises(ValueError, match="routing-domain source reconciliation failed"):
        helper._install_route_domain_intent(candidate)

    assert intent_path.is_file()
    assert service_path.is_file()
    assert events == ["intent-published", "reconcile-failed"]
