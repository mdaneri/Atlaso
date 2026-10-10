"""Regress retained WAN defaults without admitting foreign route replacements."""

import json
import subprocess
from contextlib import contextmanager
from ipaddress import ip_network

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.fixture(scope="module")
def helper():
    """Load the large helper once; monkeypatch restores each test's boundaries."""
    return load_helper_module()


@pytest.fixture(params=["kernel", "boot"])
def native_route_inventory(helper, monkeypatch, request):
    """Provide a bounded iproute2 observer with selector-bound owner omissions.

    Args:
        helper: Isolated helper module.
        monkeypatch: Restore native observation and mutation boundaries.
        request: Connected route protocol reported by the native inventory.
    """
    routes = {
        4: [
            {"dst": "192.0.2.0/24", "table": "main", "scope": "link", "metric": 0,
             "protocol": request.param},
            {"dst": "default", "table": "main", "gateway": "192.0.2.1", "metric": 100,
             "protocol": "boot"},
        ],
        6: [
            {"dst": "2001:db8:1::/64", "table": "main", "scope": "link", "metric": 0,
             "protocol": request.param},
            {"dst": "default", "table": "main", "gateway": "fe80::1", "metric": 100,
             "protocol": "boot"},
        ],
    }
    table_routes = {(family, table): [] for family in (4, 6) for table in (100, 200)}
    commands = []

    def observe(command):
        """Return native-style JSON rows for the selected interface and table.

        Args:
            command: Native observation command built by the helper.
        """
        commands.append(command)
        if command[1:4] == ["-j", "address", "show"]:
            return subprocess.CompletedProcess(command, 0, json.dumps([{
                "ifname": "eth0", "address": "02:00:00:00:00:01", "addr_info": [
                    {"local": "192.0.2.10", "prefixlen": 24, "scope": "global"},
                    {"local": "2001:db8:1::10", "prefixlen": 64, "scope": "global"},
                ],
            }]), "")
        if "route" not in command:
            return subprocess.CompletedProcess(command, 0, "[]", "")

        family = 4 if "-4" in command else 6
        table_index = command.index("table") + 1
        table = command[table_index]
        detailed = "-details" in command
        if table == "all":
            rows = routes[family]
        else:
            rows = table_routes[(family, int(table))]
        native_rows = []
        for row in rows:
            native = {key: value for key, value in row.items() if key != "dev"}
            if not detailed and native.get("protocol") == "boot":
                native.pop("protocol", None)
            native_rows.append(native)
        return subprocess.CompletedProcess(command, 0, json.dumps(native_rows), "")

    def run(command):
        """Apply only the fixed route additions and deletions under test.

        Args:
            command: Native route mutation command built by the helper.
        """
        commands.append(command)
        family = 4 if "-4" in command else 6
        table = int(command[command.index("table") + 1])
        action = command[3]
        destination = command[4]
        metric = int(command[command.index("metric") + 1])
        gateway = command[command.index("via") + 1] if "via" in command else ""
        row = {"dst": destination, "gateway": gateway, "metric": metric, "protocol": "kernel"}
        if action == "add":
            table_routes[(family, table)].append(row)
        else:
            table_routes[(family, table)] = [
                candidate for candidate in table_routes[(family, table)]
                if not (candidate.get("dst") == destination and candidate.get("metric") == metric)
            ]
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_network_observation_command", observe)
    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: None)

    def install_successors(table, evidence, protocol="boot"):
        """Install native routes representing the original usable paths.

        Args:
            table: Management or lab routing table under observation.
            evidence: Snapshot captured before the route transition.
            protocol: Native route protocol reported for successor rows.
        """
        for route in evidence["eth0"]["routes"]:
            table_routes[(ip_network(route["destination"]).version, table)].append({
                "dst": "default" if ip_network(route["destination"]).prefixlen == 0 else route["destination"],
                "gateway": route["gateway"], "metric": route["metric"], "protocol": protocol,
            })

    def install_holdovers(table, evidence):
        """Install the observed DHCP/RA replacements required by route readiness.

        Args:
            table: Management or lab routing table under observation.
            evidence: Snapshot captured before the route transition.
        """
        for route in evidence["eth0"]["routes"]:
            family = ip_network(route["destination"]).version
            table_routes[(family, table)].append({
                "dst": "default" if ip_network(route["destination"]).prefixlen == 0 else route["destination"],
                "gateway": route["gateway"], "metric": route["holdover_metric"],
                "protocol": "dhcp" if family == 4 else "ra",
            })

    return {"commands": commands, "connected_protocol": request.param, "install_holdovers": install_holdovers,
            "install_successors": install_successors, "table_routes": table_routes}


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
    {"gateway": "192.0.2.2"}, {"metric": 101}, {"protocol": 99}, {"protocol": "unknown"},
    {"dev": "eth1"},
    {"flags": ["linkdown"]}, {"type": "blackhole"}, {"nhid": 7},
    {"from": "192.0.2.0/24"}, {"prefsrc": "192.0.2.99"},
    {"multipath": [{"gateway": "192.0.2.1"}]}, {"metric": 202}, {"metric": True},
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


@pytest.mark.parametrize("table", [100, 200])
def test_native_details_capture_seed_and_retire_routes_with_omitted_owner_fields(
    helper, native_route_inventory, tmp_path, table,
):
    """Detailed native inventory preserves boot routes through table-bound retirement.

    Args:
        helper: Isolated helper module.
        native_route_inventory: Native-style observer omitting selector-bound fields.
        tmp_path: Isolated transition marker location.
        table: Management or lab routing domain selected for the interface.
    """
    marker = tmp_path / "state.json"
    state = {}
    bindings = [{"name": "eth0", "table": table}]

    helper._seed_transition_routes(state, bindings, marker)
    evidence = state["previous_management_routing"]
    assert {ip_network(route["destination"]).version for route in evidence["eth0"]["routes"]} == {4, 6}
    assert {route["protocol"] for route in evidence["eth0"]["routes"]} == {
        "boot", native_route_inventory["connected_protocol"],
    }
    assert len(state["transition_seed_routes"]) == 4

    native_route_inventory["install_holdovers"](table, evidence)
    helper._wait_management_handoff_routes({"previous_management_routing": evidence}, attempts=1)
    native_route_inventory["install_successors"](table, evidence)
    seed_metrics = {row["seed_metric"] for row in state["transition_seed_routes"]}
    helper._retire_transition_routes(state, marker, require_replacement=True)

    assert state["transition_seed_routes"] == []
    selected_rows = [row for (family, observed_table), rows in native_route_inventory["table_routes"].items()
                     if observed_table == table for row in rows]
    assert selected_rows
    assert not seed_metrics.intersection(row["metric"] for row in selected_rows)
    assert all(not rows for (_family, observed_table), rows in native_route_inventory["table_routes"].items()
               if observed_table != table)
    route_reads = [command for command in native_route_inventory["commands"] if "route" in command and "show" in command]
    assert route_reads
    assert all("-details" in command for command in route_reads)
    assert all(command[-2:] == ["dev", "eth0"] for command in route_reads)
    assert {command[command.index("table") + 1] for command in route_reads} >= {"all", str(table)}


@pytest.mark.parametrize("rollback_failed", [False, True])
def test_ordinary_network_apply_preserves_conflict_pair_after_transaction_unwind(helper, monkeypatch, tmp_path, capsys,
                                                                              rollback_failed):
    """Ordinary Network Apply retains typed evidence after its transaction exits.

    Args:
        helper: Loaded appliance helper.
        monkeypatch: Scoped native-operation replacements.
        tmp_path: Isolated staged configuration directory.
        capsys: Helper output capture fixture.
        rollback_failed: Whether transaction restoration reports failure.
    """
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.services.important_task_events import execution_projection
    from atlaso.app.ui import adapter_result_to_payload

    config = tmp_path / "network.conf"
    row = {"name": "eth0", "table": 100, "destination": "0.0.0.0/0", "gateway": "192.0.2.1",
           "metric": 100, "protocol": "boot"}
    conflict = helper.ManagementRouteConflict(row, {"dst": "default", "gateway": "192.0.2.2",
                                                   "metric": 100, "protocol": "boot"})
    events = []

    @contextmanager
    def transaction(_path):
        """Model transaction exception propagation before helper serialization.

        Args:
            _path: Staged configuration path.
        """
        try:
            yield
        except helper.ManagementRouteConflict as exc:
            events.append("unwound")
            disposition = "network rollback incomplete" if rollback_failed else "previous network configuration restored"
            raise ValueError(f"{exc}; {disposition}") from exc

    def seed(*_args):
        """Reject the observed foreign route.

        Args:
            *_args: Transition seed call arguments.
        """
        raise conflict

    monkeypatch.setattr(helper, "_validate_network_config_path", lambda _path: config)
    monkeypatch.setattr(helper, "_network_config_errors", lambda _path: [])
    monkeypatch.setattr(helper, "_network_identity_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_network_detection_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_route_domain_ingress_desired_rules", lambda _path: [])
    monkeypatch.setattr(helper, "_ordinary_network_old_management_bindings", lambda _path: [{"name": "eth0"}])
    monkeypatch.setattr(helper, "_network_apply_transaction", transaction)
    monkeypatch.setattr(helper, "_removed_vlan_source_holds", lambda _path: [])
    monkeypatch.setattr(helper, "_network_transaction_state", lambda: {})
    monkeypatch.setattr(helper, "_seed_transition_routes", seed)
    monkeypatch.setattr(helper, "_stage_candidate_ingress_guards", lambda _path: pytest.fail("activation began"))
    assert helper._handle_network_locked("apply", [str(config)]) == 2
    assert events == ["unwound"]
    stderr = capsys.readouterr().err
    evidence = json.loads(stderr)
    assert evidence["route_conflict"] == conflict.route_conflict
    assert ("network rollback incomplete" in evidence["error"]) is rollback_failed
    command = adapter_result_to_payload(AdapterResult(
        command=["atlaso-helper", "network", "apply", str(config)], dry_run=False, returncode=2, stderr=stderr,
    ))
    projected = execution_projection({"commands": [command]}, "network")
    assert projected[0]["reason"] == "management_route_conflict"
    assert projected[0]["route_conflict"] == conflict.route_conflict
