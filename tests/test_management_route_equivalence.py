"""Regress retained WAN defaults without admitting foreign route replacements."""

import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.fixture(scope="module")
def helper():
    """Load the large helper once; monkeypatch restores each test's boundaries."""
    return load_helper_module()


@pytest.mark.parametrize("table", [100, 200])
@pytest.mark.parametrize("destination,gateway", [("0.0.0.0/0", "192.0.2.1"), ("::/0", "fe80::1")])
@pytest.mark.parametrize("protocol", ["boot", 3, "3"])
def test_repeated_apply_preserves_exact_legacy_wan_default(helper, monkeypatch, tmp_path, table, destination, gateway, protocol):
    """A proven unchanged old route needs no temporary replacement or deletion.

    Args:
        helper: Isolated helper module.
        monkeypatch: Isolate native inventory and mutation.
        tmp_path: Owned validation marker location.
        table: Dedicated or Access-management domain.
        destination: Canonical family default.
        gateway: Captured old gateway.
        protocol: Native named or numeric boot protocol.
    """
    route = {"destination": destination, "gateway": gateway, "metric": 100, "scope": "global",
             "table": table, "preferred_source": "", "preference": "medium", "holdover_metric": 201}
    evidence = {"eth0": {"mac": "02:00:00:00:00:01", "table": table,
                         "cidrs": ["192.0.2.10/24" if table == 100 else "192.0.2.254/24"], "routes": [route]}}
    observed = {"dst": "default", "gateway": gateway, "metric": 100, "protocol": protocol,
                "dev": "eth0", "table": table}
    monkeypatch.setattr(helper, "_snapshot_management_handoff_routing", lambda *_args: evidence)
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: [observed])
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: None)
    monkeypatch.setattr(helper, "_run", lambda *_args: pytest.fail("equivalent route must remain untouched"))
    for _ in range(2):
        state = {"previous_management_routing": evidence}
        helper._seed_transition_routes(state, [{"name": "eth0", "table": table}], tmp_path / "state.json")
        assert state["transition_seed_routes"] == []


@pytest.mark.parametrize("protocol", [2, "2", 4, "4", 9, "9", 16, "16"])
def test_numeric_networkd_successor_protocols(helper, protocol):
    """Native protocol numbers have the same meaning as networkd protocol names.

    Args:
        helper: Isolated helper module.
        protocol: Kernel, static, RA, or DHCP native protocol identifier.
    """
    row = {"name": "eth0", "table": 100, "destination": "0.0.0.0/0", "gateway": "192.0.2.1",
           "metric": 100, "holdover_metric": 201, "seed_metric": 202}
    observed = {"dev": "eth0", "dst": "default", "gateway": "192.0.2.1", "protocol": protocol, "metric": 100}
    assert helper._transition_route_successor(row, observed, {202})


@pytest.mark.parametrize("change", [
    {"gateway": "192.0.2.2"}, {"metric": 101}, {"protocol": 99}, {"dev": "eth1"},
    {"flags": ["linkdown"]}, {"type": "blackhole"}, {"nhid": 7},
    {"from": "192.0.2.0/24"}, {"prefsrc": "192.0.2.99"}, {"metric": 202}, {"metric": True},
])
def test_boot_protocol_does_not_authorize_changed_or_foreign_successor(helper, change):
    """Boot is admitted only with the exact usable, captured old route key.

    Args:
        helper: Isolated helper module.
        change: Foreign ownership, alternate path, or unusable route evidence.
    """
    row = {"name": "eth0", "table": 200, "destination": "0.0.0.0/0", "gateway": "192.0.2.1",
           "metric": 100, "holdover_metric": 201, "seed_metric": 202}
    observed = {"dev": "eth0", "dst": "default", "gateway": "192.0.2.1", "protocol": "boot", "metric": 100}
    assert not helper._transition_route_successor(row, {**observed, **change}, {202})


@pytest.mark.parametrize("table", [100, 200])
@pytest.mark.parametrize("destination,gateway,foreign_gateway", [
    ("0.0.0.0/0", "192.0.2.1", "192.0.2.2"), ("::/0", "fe80::1", "fe80::2"),
])
def test_conflict_reports_pair_without_journaling_or_mutating(helper, monkeypatch, tmp_path, table,
                                                           destination, gateway, foreign_gateway):
    """A conflicting operator route stays intact and gets actionable evidence.

    Args:
        helper: Isolated helper module.
        monkeypatch: Replace native observation and fail unexpected mutation.
        tmp_path: Owned marker location.
        table: Dedicated or Access-management table.
        destination: Family default.
        gateway: Captured old gateway.
        foreign_gateway: Conflicting current gateway.
    """
    route = {"destination": destination, "gateway": gateway, "metric": 100, "scope": "global",
             "table": table, "preferred_source": "", "preference": "medium", "holdover_metric": 201,
             "protocol": "boot"}
    evidence = {"eth0": {"mac": "02:00:00:00:00:01", "table": table, "routes": [route]}}
    monkeypatch.setattr(helper, "_snapshot_management_handoff_routing", lambda *_args: evidence)
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: [{
        "dev": "eth0", "dst": "default", "gateway": foreign_gateway, "metric": 100, "protocol": "boot"}])
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: pytest.fail("must not journal"))
    monkeypatch.setattr(helper, "_run", lambda *_args: pytest.fail("must preserve operator route"))
    with pytest.raises(helper.ManagementRouteConflict) as raised:
        helper._seed_transition_routes({"previous_management_routing": evidence}, [{"name": "eth0", "table": table}],
                                       tmp_path / "state.json")
    assert raised.value.route_conflict == {
        "interface": "eth0", "family": 6 if ":" in destination else 4, "table": table,
        "condition": "gateway_mismatch",
        "expected": {"destination": destination, "gateway": gateway, "metric": 100, "protocol": "boot"},
        "observed": {"destination": destination, "gateway": foreign_gateway, "metric": 100, "protocol": "boot"},
    }


@pytest.mark.parametrize("qdisc_code,expected", [(2, 0), (1, 1)])
def test_wan_boot_route_and_absent_qdisc_cleanup_are_independent(helper, monkeypatch, capsys, qdisc_code, expected):
    """Reproduce WAN boot-route commands and classify the qdisc cleanup outcome.

    Args:
        helper: Isolated helper module.
        monkeypatch: Replace command availability and execution.
        capsys: Capture native cleanup diagnostics.
        qdisc_code: Native root-qdisc deletion status.
        expected: Existing WAN operation status for that cleanup result.
    """
    parsed = {"targets": [{"name": "eth0", "management_ui": "true"}],
              "routes": [{"destination_cidr": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "eth0",
                          "metric": "100", "enabled": "true"}],
              "removed_routes": [], "removed_main_defaults": [], "wan_policies": [],
              "feature_settings": [{"routing_enabled": "true", "wan_simulation_enabled": "false"}]}
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "native")
    monkeypatch.setattr(helper, "_applied_wan_network_state", lambda: None)
    commands = []

    def run(command):
        """Model route replacement and native absent-qdisc cleanup separately.

        Args:
            command: Fixed command built by the WAN producer.
        """
        commands.append(command)
        if command[0] == "tc":
            return subprocess.CompletedProcess(command, qdisc_code, "", "Cannot delete qdisc with handle of zero.\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    assert helper._apply_wan_routes_and_qdiscs(parsed) == expected
    routes = [command for command in commands if command[0] == "ip"]
    assert len(routes) == 2
    assert all("proto" not in command for command in routes)
    assert routes[0][-2:] == ["table", "200"]
    assert "table" not in routes[1]
    assert "Cannot delete qdisc with handle of zero." in capsys.readouterr().err


@pytest.mark.parametrize("table", [100, 200])
@pytest.mark.parametrize("destination,gateway", [("0.0.0.0/0", "192.0.2.1"), ("::/0", "fe80::1")])
@pytest.mark.parametrize("require_replacement", [True, False])
def test_seed_retirement_keeps_captured_boot_default(helper, monkeypatch, tmp_path, table,
                                                   destination, gateway, require_replacement):
    """Completion and rollback retire only the journaled temporary seed.

    Args:
        helper: Isolated helper module.
        monkeypatch: Replace native route inventory and mutation.
        tmp_path: Owned marker location.
        table: Dedicated or Access-management routing domain.
        destination: Captured default route destination.
        gateway: Captured gateway.
        require_replacement: Completion readiness versus rollback retirement.
    """
    route = {"destination": destination, "gateway": gateway, "metric": 100, "scope": "global",
             "table": table, "preferred_source": "", "preference": "medium", "holdover_metric": 201}
    seed = {"name": "eth0", **route, "seed_metric": 202}
    evidence = {"eth0": {"mac": "02:00:00:00:00:01", "table": table, "routes": [route]}}
    state = {"previous_management_routing": evidence, "transition_seed_routes": [seed]}
    original = {"dev": "eth0", "dst": "default", "gateway": gateway, "protocol": "boot", "metric": 100}
    observed = [original, {**original, "protocol": "kernel", "metric": 202}]
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: observed)
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: None)
    commands = []
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    helper._retire_transition_routes(state, tmp_path / "state.json", require_replacement=require_replacement)
    assert state["transition_seed_routes"] == []
    assert len(commands) == 1
    assert commands[0][3] == "del"
    assert commands[0][-2:] == ["metric", "202"]
    assert original in observed
