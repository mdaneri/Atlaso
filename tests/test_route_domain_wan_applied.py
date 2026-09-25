"""Require WAN to preserve applied Network ownership despite pending edits."""

import copy
import io
import ipaddress
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
def test_transition_guard_is_exact_and_rejects_foreign_priority(family):
    """Only the owned local-origin terminal guard may occupy priority 6004.

    Args:
        family: IPv4 or IPv6 address family under test.
    """
    canonical = {"priority": route_domains.TRANSITION_PRIORITY, "src": "all", "srclen": 0, "iif": "lo",
                 "action": "unreachable", "protocol": "2"}
    assert route_domains.transition_guard_present([canonical], family)
    assert not route_domains.transition_guard_present([], family)
    for changed in ({"iif": "eth1"}, {"action": "to_tbl", "table": "200"}, {"protocol": "4"}):
        with pytest.raises(route_domains.ReconcileError):
            route_domains.transition_guard_present([{**canonical, **changed}], family)


@pytest.mark.parametrize("family", [4, 6])
def test_terminal_exemptions_admit_only_unbound_and_link_local_main_lookup(family):
    """The escape slots cannot admit a global source or a foreign table.

    Args:
        family: IPv4 or IPv6 rule family under test.
    """
    for offset, prefix in enumerate(route_domains.TRANSITION_EXEMPTIONS[family]):
        network = ipaddress.ip_network(prefix)
        canonical = {"priority": 6000 + offset, "src": str(network.network_address),
                     "srclen": network.prefixlen, "iif": "lo", "table": "254", "protocol": "2"}
        assert route_domains.transition_exemptions_present([canonical], family) == {6000 + offset}
        for changed in ({"src": "192.0.2.1" if family == 4 else "2001:db8::1"},
                        {"table": "200"}, {"iif": "eth0"}):
            with pytest.raises(route_domains.ReconcileError):
                route_domains.transition_exemptions_present([{**canonical, **changed}], family)
    destination = ipaddress.ip_network(route_domains.TRANSITION_DESTINATION_EXEMPTIONS[family])
    canonical_destination = {"priority": 6003, "dst": str(destination.network_address),
                             "dstlen": destination.prefixlen, "iif": "lo", "table": "254", "protocol": "2"}
    assert route_domains.transition_exemptions_present([canonical_destination], family) == {6003}
    for changed in ({"dst": "192.0.2.1" if family == 4 else "2001:db8::1"},
                    {"table": "200"}, {"iif": "eth0"}):
        with pytest.raises(route_domains.ReconcileError):
            route_domains.transition_exemptions_present([{**canonical_destination, **changed}], family)


def test_held_source_inventory_uses_source_rule_capacity():
    """A dual-stack removal may hold more addresses than interface records."""
    owner = {"name": "eth1", "mac": "02:00:00:00:00:01", "table": 200}
    holds = [
        {**owner, "address": address}
        for index in range(1, 130)
        for address in (f"10.0.0.{index}", f"2001:db8::{index}")
    ]
    parsed = route_domains.parse_intent({"schema": 1, "interfaces": [], "held_addresses": holds})
    assert len(parsed.held_addresses) == 258
    too_many = [{**owner, "address": f"2001:db8::{index:x}"} for index in range(1, 1002)]
    with pytest.raises(route_domains.ReconcileError, match="invalid routing-domain inventory"):
        route_domains.parse_intent({"schema": 1, "interfaces": [], "held_addresses": too_many})


def test_transition_guard_brackets_both_families_after_source_slots(monkeypatch):
    """Dynamic sources remain blocked until synchronous rules have been installed.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    commands = []
    occupied = {4: set(), 6: set()}
    monkeypatch.setattr(route_domains, "reconciliation_lock", nullcontext)

    def read_native(args):
        """Return controlled native observations for this test.

        Args:
            args: Native observation arguments.
        """
        family = int(args[0][1:])
        rows = []
        for priority in occupied[family]:
            if priority == route_domains.TRANSITION_PRIORITY:
                rows.append({"priority": priority, "src": "all", "srclen": 0,
                             "iif": "lo", "action": "unreachable", "protocol": "2"})
            elif priority == 6003:
                network = ipaddress.ip_network(route_domains.TRANSITION_DESTINATION_EXEMPTIONS[family])
                rows.append({"priority": priority, "dst": str(network.network_address),
                             "dstlen": network.prefixlen, "iif": "lo", "table": "254", "protocol": "2"})
            else:
                network = ipaddress.ip_network(route_domains.TRANSITION_EXEMPTIONS[family][priority - 6000])
                rows.append({"priority": priority, "src": str(network.network_address),
                             "srclen": network.prefixlen, "iif": "lo", "table": "254", "protocol": "2"})
        return rows

    def run_ip(command):
        """Record the policy-rule command without host mutation.

        Args:
            command: Native command being recorded.
        """
        family = int(command[1][1:])
        priority = int(command[command.index("priority") + 1])
        if command[3] == "add":
            occupied[family].add(priority)
        else:
            occupied[family].remove(priority)
        commands.append(command)
        return ""

    monkeypatch.setattr(route_domains, "read_native", read_native)
    monkeypatch.setattr(route_domains, "run_ip", run_ip)
    monkeypatch.setattr(route_domains, "read_intent", lambda: route_domains.Intent(()))
    route_domains.transition_guard(True)
    assert occupied == {4: {6000, 6001, 6002, 6003, 6004}, 6: {6000, 6001, 6002, 6003, 6004}}
    route_domains.transition_guard(False)
    assert occupied == {4: set(), 6: set()}
    assert [(cmd[1], cmd[3], cmd[cmd.index("priority") + 1]) for cmd in commands] == [
        (family, action, str(priority))
        for action, priorities in (("add", (6004, 6000, 6001, 6002, 6003)),
                                   ("del", (6000, 6001, 6002, 6003, 6004)))
        for family in ("-4", "-6")
        for priority in priorities]


def test_owned_terminal_guard_is_admitted_by_new_network_transaction(monkeypatch):
    """The persistent local-origin guard remains through later Network Applies.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    monkeypatch.setattr(route_domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(route_domains, "read_native", lambda _args: [{
        "priority": route_domains.TRANSITION_PRIORITY, "src": "all", "srclen": 0, "iif": "lo",
        "action": "unreachable", "protocol": "2"}])
    route_domains.preflight()


def test_removed_vlan_sources_remain_bound_until_link_retirement():
    """A deferred VLAN preserves its old exact source pair until the link is gone."""
    intent = route_domains.parse_intent({"schema": 1, "interfaces": [
        {"name": "eth1.120", "mac": "02:00:00:00:01:20", "table": 200}], "held_addresses": []})
    inventory = [{"ifname": "eth1.120", "address": "02:00:00:00:01:20", "addr_info": [
        {"local": "192.0.2.20", "prefixlen": 24},
        {"local": "2001:db8::20", "prefixlen": 64, "flags": []}]}]
    holds = route_domains.removed_interface_holds(intent, inventory, {"eth1.120"})
    assert holds == [{"name": "eth1.120", "mac": "02:00:00:00:01:20", "address": source, "table": 200}
                     for source in ("192.0.2.20", "2001:db8::20")]
    transitional = route_domains.parse_intent({"schema": 1, "interfaces": [], "held_addresses": holds})
    assert route_domains.source_tables(transitional, inventory) == (
        {"192.0.2.20": 200, "2001:db8::20": 200}, False)
    assert route_domains.source_tables(transitional, [])[0] == {}
    with pytest.raises(route_domains.ReconcileError, match="identity unavailable"):
        route_domains.removed_interface_holds(intent, [{**inventory[0], "address": "02:00:00:00:02:20"}],
                                              {"eth1.120"})


def test_first_migration_removed_vlan_uses_proven_legacy_source():
    """A marker-free VLAN removal derives its hold from native identity and old rules."""
    removed = [{"name": "eth1.120", "parent": "eth1", "vlan_id": "120"}]
    inventory = [{"ifname": "eth1.120", "address": "02:00:00:00:01:20",
                  "addr_info": [{"local": "192.0.2.20", "flags": []}]}]
    links = [{"ifname": "eth1", "ifindex": 5},
             {"ifname": "eth1.120", "ifindex": 7, "link_index": 5,
              "address": "02:00:00:00:01:20",
              "linkinfo": {"info_kind": "vlan", "info_data": {"id": 120}}}]
    rules = [{"family": 4, "priority": 2000, "table": 200,
              "source": "192.0.2.0/24", "incoming_interface": "", "protocol": 4}]

    intent = route_domains.legacy_removed_vlan_intent(removed, inventory, links, rules)
    assert route_domains.removed_interface_holds(intent, inventory, {"eth1.120"}) == [
        {"name": "eth1.120", "mac": "02:00:00:00:01:20", "address": "192.0.2.20", "table": 200}]
    assert route_domains.legacy_removed_vlan_intent(removed, [], [links[0]], rules).interfaces == ()
    with pytest.raises(route_domains.ReconcileError, match="identity unavailable"):
        route_domains.legacy_removed_vlan_intent(removed, inventory,
                                                 [links[0], {**links[1], "link_index": 9}], rules)
    with pytest.raises(route_domains.ReconcileError, match="unproven routing domain"):
        route_domains.legacy_removed_vlan_intent(removed, inventory, links, [])
    with pytest.raises(route_domains.ReconcileError, match="unproven routing domain"):
        route_domains.legacy_removed_vlan_intent(removed, inventory, links,
                                                 [*rules, {**rules[0], "table": 100}])


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
        """Return table 200 plus an unrelated main-table route for the projection.

        Args:
            arguments: Command arguments under test.
        """
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


def test_same_address_handoff_requires_candidate_default_before_source_switch(helper, modern, tmp_path):
    """Only an exact held old source may stage a usable Access default.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted native routing snapshot.
        tmp_path: Owned candidate WAN configuration directory.
    """
    state, _commands = modern
    old_interface = {"name": "eth1", "mac": "02:00:00:00:00:01", "table": 100}
    state["intent"]["held_addresses"] = [{"interface": old_interface, "address": "192.0.2.10"}]
    state["sources"]["192.0.2.10"] = 100
    previous = {"previous_management_routing": {"eth1": {
        "table": 100, "mac": old_interface["mac"], "cidrs": ["192.0.2.10/24"],
        "routes": [{"destination": "0.0.0.0/0", "gateway": "192.0.2.1"}],
    }}}

    assert ("eth1", "192.0.2.0/24") not in helper._applied_wan_network_state()["prefixes"]
    with pytest.raises(ValueError, match="candidate IPv4 default is not ready"):
        helper._verify_management_handoff_migrated_defaults(previous)

    state["routes"]["4"].append({"dst": "default", "dev": "eth1", "table": 200,
                                  "gateway": "192.0.2.1", "metric": 100})
    helper._verify_management_handoff_migrated_defaults(previous)

    candidate = tmp_path / "candidate-wan.conf"
    candidate.write_text("[routes]\nroute=0.0.0.0/0\n  interface=eth1\n"
                         "  gateway=192.0.2.2\n  metric=100\n  enabled=true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="candidate IPv4 default is not ready"):
        helper._verify_management_handoff_migrated_defaults(previous, {"wan_config_path": str(candidate)})
    state["routes"]["4"][-1]["gateway"] = "192.0.2.2"
    helper._verify_management_handoff_migrated_defaults(previous, {"wan_config_path": str(candidate)})

    state["routes"]["4"][-1]["gateway"] = "198.51.100.1"
    with pytest.raises(ValueError, match="candidate IPv4 default is not ready"):
        helper._verify_management_handoff_migrated_defaults(previous)

    state["intent"]["held_addresses"][0]["interface"]["mac"] = "02:00:00:00:00:02"
    assert ("eth1", "192.0.2.0/24") not in helper._applied_wan_network_state(
        include_handoff_held_sources=True,
    )["prefixes"]


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


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("gateway", [False, True])
def test_nonowner_static_cannot_replace_connected_identity(helper, modern, family, gateway):
    """A route on another lab link cannot replace the table-wide prefix owner.

    Args:
        helper: Loaded privileged helper.
        modern: Admitted snapshot and captured mutations.
        family: Connected route address family.
        gateway: Whether the conflicting route has a next hop.
    """
    state, commands = modern
    parsed = wan_input()
    parsed["feature_settings"][0]["routing_enabled"] = "true"
    parsed["targets"].append({"name": "eth2", "routing_domain": "lab"})
    state["intent"]["interfaces"].append({"name": "eth2", "mac": "02:00:00:00:00:02",
                                           "table": 200, "management_ui": False})
    state["addresses"].append({"ifname": "eth2", "address": "02:00:00:00:00:02",
                               "addr_info": [{"local": "192.0.2.20", "prefixlen": 24},
                                             {"local": "2001:db8::20", "prefixlen": 64}]})
    state["sources"].update({"192.0.2.20": 200, "2001:db8::20": 200})
    network, next_hop, metric = (("192.0.2.0/24", "192.0.2.1", "0") if family == 4 else
                                 ("2001:db8::/64", "2001:db8::1", "1024"))
    parsed["routes"] = [
        {"destination_cidr": "203.0.113.0/24", "interface": "eth2", "enabled": "true", "metric": "100"},
        {"destination_cidr": network, "interface": "eth2", "gateway": next_hop if gateway else "",
         "enabled": "true", "metric": metric},
    ]
    with pytest.raises(ValueError, match="Network-owned connected route"):
        helper._apply_wan_routes_and_qdiscs(parsed)
    assert commands == []
