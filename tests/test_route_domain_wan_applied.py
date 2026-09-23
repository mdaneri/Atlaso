"""Require WAN to preserve applied Network ownership despite pending edits."""

import copy
import io
import json
import subprocess
from contextlib import nullcontext, redirect_stdout

import pytest

from atlaso import route_domains
from tests.test_appliance_helper import load_helper_module


@pytest.fixture(scope="module")
def helper():
    """Load the privileged helper once; every test restores its native boundaries."""
    return load_helper_module()


@pytest.fixture
def modern(helper, monkeypatch, tmp_path):
    """Install an admitted synthetic native snapshot and capture only mutations.

    Args:
        helper: Loaded privileged helper.
        monkeypatch: Reversible native command boundaries.
        tmp_path: Owned validation directory.
    """
    interface = {"name": "eth1", "mac": "02:00:00:00:00:01", "table": 200, "management_ui": True}
    state = {"intent": {"interfaces": [interface], "held_addresses": []}, "incomplete": False,
             "sources": {"192.0.2.10": 200, "2001:db8::10": 200},
             "addresses": [{"ifname": "eth1", "address": interface["mac"], "addr_info": [
                 {"local": "192.0.2.10", "prefixlen": 24}, {"local": "2001:db8::10", "prefixlen": 64}]}],
             "routes": {"4": [{"dst": "192.0.2.0/24", "dev": "eth1", "table": 200, "protocol": "4"}],
                        "6": [{"dst": "2001:db8::/64", "dev": "eth1", "table": 200,
                               "metric": 1024, "protocol": "4"}]}}
    path = tmp_path / "route-domains.json"
    path.write_text(json.dumps({"schema": 1, "interfaces": [interface]}))
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", path)
    monkeypatch.setattr(helper, "WAN_SYSCTL_PATH", tmp_path / "wan.sysctl")
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "native")
    commands = []

    def observe(command, *, timeout):
        """Supply canonical-module output without executing Linux observations.

        Args:
            command: Fixed isolated installed-core observation command.
            timeout: Whole-observation deadline.
        """
        assert command[:4] == ["/opt/atlaso/.venv/bin/python", "-I", "-c", command[3]]
        compile(command[3], "wan-native-observation", "exec")
        assert timeout <= 60
        return subprocess.CompletedProcess(command, 0, json.dumps(state), "")

    monkeypatch.setattr(helper, "_network_observation_command", observe)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    return state, commands


def wan_input():
    """Return disabled forwarding with pending desired prefixes and UI unflagging."""
    return {"targets": [{"name": "eth1", "ip_cidr": "198.51.100.10/24", "ipv6_cidr": "2001:db8:1::10/64",
                         "routing_domain": "lab", "management_ui": "false"}],
            "retired_targets": [{"name": "eth1", "network": "192.0.2.0/24"}],
            "routes": [], "removed_routes": [], "removed_main_defaults": [], "nat_rules": [],
            "routing_rules": [], "wan_policies": [], "feature_settings": [{"routing_enabled": "false",
                  "nat_enabled": "false", "wan_simulation_enabled": "false"}]}


@pytest.mark.parametrize("family", [4, 6])
def test_flagged_default_keeps_reply_table_with_forwarding_off(helper, modern, family):
    """Applied flag retains both host and guarded reply defaults, not forwarding.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted snapshot and captured mutations.
        family: Default route address family.
    """
    _state, commands = modern
    parsed = wan_input()
    destination, gateway = ("0.0.0.0/0", "192.0.2.1") if family == 4 else ("::/0", "2001:db8::1")
    parsed["routes"] = [{"destination_cidr": destination, "gateway": gateway, "interface": "eth1", "enabled": "true", "metric": "100"}]
    assert helper._apply_wan_forwarding(parsed) == 0
    assert helper._apply_wan_target_routes(parsed) == 0
    assert helper._apply_wan_routes_and_qdiscs(parsed) == 0
    base = ["ip", *(["-6"] if family == 6 else []), "route", "replace", destination, "via", gateway, "dev", "eth1", "metric", "100"]
    assert base in commands and base + ["table", "200"] in commands
    assert ["sysctl", "-w", "net.ipv4.ip_forward=0"] in commands
    assert ["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"] in commands
    assert not any("rule" in command for command in commands)


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("combined", [False, True])
def test_connected_cleanup_uses_current_applied_snapshot(helper, modern, family, combined):
    """WAN-only leaves old prefixes; combined Apply follows newly activated Network.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted snapshot and captured mutations.
        family: Connected route address family.
        combined: Whether Network already published the candidate prefix.
    """
    state, commands = modern
    parsed = wan_input()
    old, new, source, replacement = (("192.0.2.0/24", "198.51.100.0/24", "192.0.2.10", "198.51.100.10") if family == 4
                                    else ("2001:db8::/64", "2001:db8:1::/64", "2001:db8::10", "2001:db8:1::10"))
    if combined:
        state["sources"].pop(source)
        state["sources"][replacement] = 200
        state["addresses"][0]["addr_info"][0 if family == 4 else 1]["local"] = replacement
        state["routes"][str(family)][0]["dst"] = new
    parsed["removed_routes"] = [{"destination_cidr": old, "interface": "eth1", "gateway": "", "metric": "0"}]
    assert helper._apply_wan_target_routes(parsed, copy.deepcopy(parsed)) == 0
    assert commands == []
    assert helper._apply_wan_routes_and_qdiscs(parsed) == 0
    route_commands = [row for row in commands if "route" in row]
    assert bool(route_commands) is combined
    if combined:
        assert len(route_commands) == 1 and "del" in route_commands[0] and old in route_commands[0]


def test_held_old_interface_keeps_connected_route(helper, modern):
    """A previous interface held outside candidate intent remains protected.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted snapshot and captured mutations.
    """
    state, commands = modern
    interface = state["intent"]["interfaces"].pop()
    state["intent"]["held_addresses"] = [{"interface": interface, "address": "192.0.2.10"}]
    parsed = wan_input()
    parsed["removed_routes"] = [{"destination_cidr": "192.0.2.0/24", "interface": "eth1", "metric": "0"}]
    assert helper._apply_wan_routes_and_qdiscs(parsed) == 0
    assert not any("route" in command for command in commands)


@pytest.mark.parametrize("failure", ["missing-flag", "identity", "off-link"])
def test_unproven_applied_default_rejects_before_routes(helper, modern, failure):
    """Older eligibility or invalid native ownership cannot authorize a default.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted snapshot and captured mutations.
        failure: Applied admission prerequisite to invalidate.
    """
    state, commands = modern
    if failure == "missing-flag":
        state["intent"]["interfaces"][0].pop("management_ui")
    if failure == "identity":
        state["incomplete"] = True
    parsed = wan_input()
    parsed["routes"] = [{"destination_cidr": "0.0.0.0/0", "interface": "eth1", "enabled": "true",
                         "gateway": "198.51.100.1" if failure == "off-link" else "192.0.2.1"}]
    with pytest.raises(ValueError):
        helper._apply_wan_routes_and_qdiscs(parsed)
    assert commands == []


@pytest.mark.parametrize("flag", [True, False, None, "true", 1])
def test_applied_management_flag_is_optional_but_strict(flag):
    """Existing schema-1 rows remain readable without accepting non-Boolean flags.

    Args:
        flag: Optional eligibility value presented to the canonical parser.
    """
    row = {"name": "eth1", "mac": "02:00:00:00:00:01", "table": 200}
    if flag is not None:
        row["management_ui"] = flag
    if flag is None or type(flag) is bool:
        assert route_domains.parse_interface(row).management_ui is flag
    else:
        with pytest.raises(route_domains.ReconcileError):
            route_domains.parse_interface(row)


def test_installed_core_projection_serializes_held_identity(helper, modern, monkeypatch):
    """Execute the fixed projection with real canonical parsing and source binding.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted snapshot and captured mutations.
        monkeypatch: Reversible core native observation boundaries.
    """
    state, _commands = modern
    held = {"name": "eth1", "mac": "02:00:00:00:00:01", "table": 200, "address": "192.0.2.10"}
    admitted = route_domains.parse_intent({"schema": 1, "interfaces": [], "held_addresses": [held]})
    monkeypatch.setattr(route_domains, "read_intent", lambda: admitted)
    monkeypatch.setattr(route_domains, "reconciliation_lock", nullcontext)
    def read_native(arguments):
        """Return table 200 plus an unrelated main-table route for the projection."""
        if arguments == ["address", "show"]:
            return state["addresses"]
        assert arguments[-2:] == ["table", "all"]
        return [*state["routes"][arguments[0][-1]],
                {"dst": "default", "table": "main", "dev": "eth0"}]

    monkeypatch.setattr(route_domains, "read_native", read_native)

    def execute(command, *, timeout):
        """Run fixed source in-process with isolated mocked core observations.

        Args:
            command: Installed Python argument vector containing the fixed program.
            timeout: Bound supplied to production subprocess observation.
        """
        assert timeout <= 60
        output = io.StringIO()
        with redirect_stdout(output):
            exec(command[3], {})
        return subprocess.CompletedProcess(command, 0, output.getvalue(), "")

    monkeypatch.setattr(helper, "_network_observation_command", execute)
    observed = helper._applied_wan_network_state()
    assert observed["connected"] == {("eth1", "192.0.2.0/24"): {0}}
    assert observed["management_ui"] == {"eth1": None}


def test_wan_projection_reports_bounded_failed_stage(helper, modern, monkeypatch):
    """A failed isolated ownership read identifies its stage without raw stderr.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted applied-intent fixture.
        monkeypatch: Reversible native observation boundary.
    """
    _state, _commands = modern
    monkeypatch.setattr(helper, "_network_observation_command", lambda command, *, timeout:
                        subprocess.CompletedProcess(command, 1, '{"stage":"addresses","reason":"ReconcileError"}', ""))

    with pytest.raises(ValueError, match=r"observation failed at addresses \(ReconcileError\)"):
        helper._applied_wan_network_state()


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("gateway", [False, True])
def test_enabled_static_cannot_replace_connected_identity(helper, modern, family, gateway):
    """Native collisions reject before earlier statics; redundant aliases are skipped.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted snapshot and captured mutations.
        family: Connected route address family.
        gateway: Whether the colliding route changes the connected next hop.
    """
    _state, commands = modern
    parsed = wan_input()
    parsed["feature_settings"][0]["routing_enabled"] = "true"
    network, next_hop, metric = ("192.0.2.0/24", "192.0.2.1", "0") if family == 4 else ("2001:db8::/64", "2001:db8::1", "1024")
    parsed["routes"] = [{"destination_cidr": network, "interface": "eth1", "metric": metric,
                         "gateway": next_hop if gateway else "", "enabled": "true"}]
    if gateway:
        parsed["routes"].insert(0, {"destination_cidr": "203.0.113.0/24", "interface": "eth1", "enabled": "true", "metric": "100"})
        with pytest.raises(ValueError, match="Network-owned"):
            helper._apply_wan_routes_and_qdiscs(parsed)
        assert commands == []
    else:
        assert helper._apply_wan_routes_and_qdiscs(parsed) == 0
        assert not any("route" in command for command in commands)
