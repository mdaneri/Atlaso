"""Regression coverage for WAN defaults during Network Apply."""

import json
import subprocess
from contextlib import nullcontext

import pytest

from tests.test_appliance_helper import load_helper_module

WAN_CONFIG = """[targets]
target=eth0
management_ui=true

[routes]
route=0.0.0.0/0
interface=eth0
gateway=192.0.2.1
metric=100
route=::/0
interface=eth0
gateway=2001:db8::1
metric=100
"""


@pytest.mark.parametrize("rollback", [False, True])
def test_network_apply_transaction_recovers_last_applied_defaults(monkeypatch, tmp_path, rollback):
    """Network activation and rollback restore captured defaults before completion.

    Args:
        monkeypatch: Replace native observations and durable host paths.
        tmp_path: Isolate the Network transaction and WAN intent files.
        rollback: Simulate a candidate failure after networkd removes both defaults.
    """
    helper = load_helper_module()
    networkd = tmp_path / "networkd"
    networkd.mkdir()
    transaction_dir = tmp_path / "transaction"
    transaction_dir.mkdir()
    wan_path = tmp_path / "atlaso-wan.conf"
    wan_path.write_text(WAN_CONFIG, encoding="utf-8")
    for name, path in {
        "NETWORKD_CONFIG_DIR": networkd,
        "NETWORKD_MGMT_CONFIG_PATH": networkd / "00-atlaso-mgmt.network",
        "NETWORK_TRANSACTION_DIR": transaction_dir,
        "ROUTE_DOMAIN_CONFIG_PATH": transaction_dir / "route-domains.json",
        "ROUTE_DOMAIN_SERVICE_PATH": transaction_dir / "route-domains.service",
        "WAN_RUNTIME_CONFIG_PATH": wan_path,
    }.items():
        monkeypatch.setattr(helper, name, path)

    live = [
        {"table": table, "dst": "default", "dev": "eth0", "gateway": "192.0.2.1",
         "protocol": "boot", "metric": 100}
        for table in ("main", "200")
    ]
    live.extend(
        {"table": table, "dst": "default", "dev": "eth0", "gateway": "2001:db8::1",
         "protocol": "boot", "metric": 100}
        for table in ("main", "200")
    )
    additions = []
    expected_routes = {(row['table'], row['gateway']) for row in live}

    def observe(command, **_kwargs):
        """Return configured link state or the current default routes.

        Args:
            command: Native observation command.
            **_kwargs: Unused bounded-command options.
        """
        if command[0] == "networkctl":
            output = {"Interfaces": [{"Name": "eth0", "AdministrativeState": "configured"}]}
        elif "-4" in command:
            output = [route for route in live if ":" not in route["gateway"]]
        else:
            output = [route for route in live if ":" in route["gateway"]]
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    def run(command, **_kwargs):
        """Record exact route additions and update the simulated route table.

        Args:
            command: Native command under test.
            **_kwargs: Unused bounded-command options.
        """
        if command[:4] in (["ip", "-4", "route", "add"], ["ip", "-6", "route", "add"]):
            additions.append(command)
            table = command[command.index("table") + 1]
            gateway = command[command.index("via") + 1]
            live.append({"table": "main" if table == "254" else table, "dst": "default", "dev": "eth0",
                         "gateway": gateway, "protocol": "boot", "metric": 100})
        return subprocess.CompletedProcess(command, 0, "", "")

    state = {}
    monkeypatch.setattr(helper, "_network_observation_command", observe)
    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(helper, "_applied_wan_network_state", lambda: {
        "management_ui": {"eth0": True},
        "prefixes": {("eth0", "192.0.2.0/24"), ("eth0", "2001:db8::/64")},
    })
    monkeypatch.setattr(helper, "_network_transaction_state", lambda: state)
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write",
                        lambda value, _path: state.update(value))
    monkeypatch.setattr(helper, "_preflight_route_domains", lambda: None)
    monkeypatch.setattr(helper, "_preflight_route_domain_capacity", lambda _path: None)
    monkeypatch.setattr(helper, "_ipv4ll_disable_only_links", lambda *_args: set())
    monkeypatch.setattr(helper, "_ipv4ll_policy_only_links", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(helper, "_management_handoff_candidate_links", lambda *_args, **_kwargs: ([], [], {}))
    monkeypatch.setattr(helper, "_systemd_networkd_files", lambda _path: ({}, [], []))
    monkeypatch.setattr(helper, "_snapshot_route_domain_service", lambda: {"active": False})
    monkeypatch.setattr(helper, "_snapshot_route_domain_rules", lambda: [])
    monkeypatch.setattr(helper, "_snapshot_transition_source_guard", lambda: False)
    monkeypatch.setattr(helper, "_fsync_file", lambda *_args: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda *_args: None)

    def finish(_state, phase):
        """Record completed rollback only once both routes have returned.

        Args:
            _state: Durable state for the finishing transaction.
            phase: Terminal rollback state.
        """
        assert {(row["table"], row["gateway"]) for row in live} == expected_routes
        state["phase"] = phase
        return True

    monkeypatch.setattr(helper, "_finish_network_transaction", finish)
    if rollback:
        monkeypatch.setattr(helper, "_stop_route_domains_for_restore", lambda _state: None)
        monkeypatch.setattr(helper, "_restore_management_handoff_links", lambda *_args: None)
        monkeypatch.setattr(helper, "_restored_legacy_route_baseline", lambda _state: False)
        monkeypatch.setattr(helper, "_restore_route_domains", lambda _state: None)
        monkeypatch.setattr(helper, "_restore_route_domain_rules", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(helper, "_retire_transition_routes", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(helper, "_restore_transition_source_guard", lambda _state: None)

    config_path = tmp_path / "network.conf"
    config_path.write_text("# atlaso-network-task: test\n", encoding="utf-8")
    outcome = pytest.raises(ValueError, match="previous network configuration restored") if rollback else nullcontext()
    with outcome, helper._network_apply_transaction(config_path):
        assert state["previous_wan_defaults"] == {
            "eth0": [[4, 254, "192.0.2.1", 100], [4, 200, "192.0.2.1", 100],
                     [6, 254, "2001:db8::1", 100], [6, 200, "2001:db8::1", 100]]
        }
        live.clear()
        if rollback:
            raise ValueError("candidate failed after reconfiguration")

    assert len(additions) == 4
    assert {(row["table"], row["gateway"]) for row in live} == expected_routes
    assert state["phase"] == ("rolled-back" if rollback else "awaiting-commit")


def test_network_wan_recovery_does_not_restore_ineligible_candidate(monkeypatch, tmp_path):
    """A changed Network candidate cannot inherit the old interface default.

    Args:
        monkeypatch: Replace applied-state reads and observe recovery attempts.
        tmp_path: Isolate the last-applied WAN configuration.
    """
    helper = load_helper_module()
    wan_path = tmp_path / "atlaso-wan.conf"
    wan_path.write_text(WAN_CONFIG, encoding="utf-8")
    monkeypatch.setattr(helper, "WAN_RUNTIME_CONFIG_PATH", wan_path)
    monkeypatch.setattr(helper, "_applied_wan_network_state", lambda: {
        "management_ui": {"eth0": False}, "prefixes": set(),
    })
    restored = []
    monkeypatch.setattr(helper, "_restore_resolver_wan_defaults",
                        lambda name, routes: restored.append((name, routes)))

    helper._restore_network_wan_defaults(
        {"previous_wan_defaults": {"eth0": [[4, 254, "192.0.2.1", 100],
                                               [4, 200, "192.0.2.1", 100]]}},
        candidate=True,
    )

    assert restored == []
