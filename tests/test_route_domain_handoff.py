"""Verify held DHCP/RA route evidence and guarded source-domain activation."""

import json
import subprocess
from pathlib import Path

import pytest

from tests.test_appliance_helper import load_helper_module


def test_held_management_link_becoming_lab_gets_guard_before_lookup(monkeypatch, tmp_path):
    """Candidate ingress cannot reach main while its old listener is held.

    Args:
        monkeypatch: Isolated native and configuration boundary replacements.
        tmp_path: Disposable candidate Network configuration location.
    """
    helper = load_helper_module()
    network = tmp_path / "candidate-network.conf"
    network.write_text("candidate\n", encoding="utf-8")
    wan = tmp_path / "applied-wan.conf"
    wan.write_text("[feature_settings]\nrouting_enabled=true\n", encoding="utf-8")
    monkeypatch.setattr(helper, "WAN_RUNTIME_CONFIG_PATH", wan)
    monkeypatch.setattr(helper, "_wan_config_errors", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helper, "_parse_wan_config", lambda _path: {"feature_settings": [{"routing_enabled": "true"}]})
    monkeypatch.setattr(helper, "_wan_feature_settings", lambda _parsed: {"routing_enabled": True})
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([
        {"name": "eth0", "role": "access", "mode": "access", "admin_state": "up"},
        {"name": "eth1", "role": "route", "mode": "access", "admin_state": "up"},
    ], [], []))

    desired = helper._route_domain_ingress_desired_rules(
        network, held_management_interfaces={"eth0"},
    )
    assert {(row["family"], row["table"]) for row in desired if row["incoming_interface"] == "eth0"} == {
        (4, None), (6, None),
    }
    assert {(row["family"], row["table"]) for row in desired if row["incoming_interface"] == "eth1"} == {
        (4, 200), (4, None), (6, 200), (6, None),
    }
    commands = []
    monkeypatch.setattr(helper, "_snapshot_route_domain_rules", lambda: [])
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    helper._stage_candidate_ingress_guards(network, held_management_interfaces={"eth0"})
    assert {command[5] for command in commands} == {"eth0", "eth1"}
    assert all("unreachable" in command for command in commands)


def test_removed_vlan_capture_accepts_dual_stack_holds_above_interface_limit(monkeypatch, tmp_path):
    """The readback bound admits every source from an admitted bulk removal.

    Args:
        monkeypatch: Isolated native inventory replacement.
        tmp_path: Disposable candidate Network configuration location.
    """
    helper = load_helper_module()
    network = tmp_path / "candidate-network.conf"
    network.write_text("candidate\n", encoding="utf-8")
    holds = [{"name": "eth1.120", "mac": "02:00:00:00:01:20", "table": 200,
              "address": f"2001:db8::{index:x}"} for index in range(1, 259)]
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([], [], [{"name": "eth1.120"}]))
    monkeypatch.setattr(helper, "_network_observation_command", lambda _command, **_kwargs:
                        subprocess.CompletedProcess([], 0, json.dumps(holds), ""))

    assert len(helper._removed_vlan_source_holds(network)) == 258


def observe_snapshot(helper, monkeypatch, *, v4_routes=None, v6_routes=None, addresses=None, nexthops=None):
    """Provide bounded native route/address snapshots without touching the host.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        v4_routes: Observed IPv4 routes for the previous management path.
        v6_routes: Observed IPv6 routes for the previous management path.
        addresses: Assigned native address records.
        nexthops: Observed native next-hop rows.
    """
    if addresses is None:
        addresses = [{"local": "192.0.2.10", "prefixlen": 24, "scope": "global"},
                     {"local": "2001:db8::10", "prefixlen": 64, "scope": "global"}]
    if v4_routes is None:
        v4_routes = [{"dst": "192.0.2.0/24", "dev": "eth0", "scope": "link", "protocol": "kernel"},
                     {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "metric": 1024, "protocol": "dhcp"}]
    if v6_routes is None:
        v6_routes = [{"dst": "2001:db8::/64", "dev": "eth0", "metric": 256, "protocol": "ra"},
                     {"dst": "default", "dev": "eth0", "gateway": "fe80::1", "metric": 1024, "protocol": "ra"}]
    if nexthops is None:
        nexthops = {}
    commands = []

    def observation(command):
        """Return only the exact interface or family requested by the helper.

        Args:
            command: Native command being recorded or simulated.
        """
        commands.append(command)
        if "nexthop" in command:
            rows = nexthops.get(int(command[-1]), [])
        elif "address" in command:
            rows = [{"ifname": "eth0", "address": "02:00:00:00:00:01", "addr_info": addresses}]
        else:
            rows = v4_routes if "-4" in command else v6_routes
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    monkeypatch.setattr(helper, "_network_observation_command", observation)
    return commands


def test_legacy_dhcp_and_ra_routes_gain_disjoint_standby_metrics(monkeypatch):
    """Native main-only routes can support old source rules in table100.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    helper = load_helper_module()
    commands = observe_snapshot(helper, monkeypatch)
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})["eth0"]
    assert evidence["cidrs"] == ["192.0.2.10/24", "2001:db8::10/64"]
    assert evidence["table"] == 100
    assert evidence["mac"] == "02:00:00:00:00:01"
    assert len(evidence["routes"]) == 4
    assert all(route["holdover_metric"] == route["metric"] + 1025 for route in evidence["routes"])
    assert min(route["holdover_metric"] for route in evidence["routes"]) > max(route["metric"] for route in evidence["routes"])
    assert all(command[-2:] == ["dev", "eth0"] for command in commands)
    held = helper._management_handoff_held_addresses({"previous_management_routing": {"eth0": evidence}})
    assert {row["address"] for row in held} == {"192.0.2.10", "2001:db8::10"}
    assert all(row["table"] == 100 for row in held)


def test_transition_route_observation_accepts_empty_numeric_table(monkeypatch):
    """An absent table is empty, while the all-table query still detects peers.

    Args:
        monkeypatch: Replace the native route observation with bounded JSON.
    """
    helper = load_helper_module()
    commands = []

    def observe(command):
        """Return a main-table route while recording the queried table.

        Args:
            command: Native route inventory command.
        """
        commands.append(command)
        if "100" in command:
            return subprocess.CompletedProcess(command, 2, "", "")
        rows = [{"dst": "192.0.2.0/24", "dev": "eth0", "protocol": "kernel"}]
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    monkeypatch.setattr(helper, "_network_observation_command", observe)
    assert helper._transition_route_rows("eth0", 4, 100) == []
    assert commands == [
        ["ip", "-j", "-4", "route", "show", "table", "100", "dev", "eth0"],
        ["ip", "-j", "-4", "route", "show", "table", "all", "dev", "eth0"],
    ]


def test_transition_route_observation_binds_omitted_json_table_and_device(monkeypatch):
    """A numeric table selector proves owner fields omitted from route JSON.

    Args:
        monkeypatch: Replace the native route observation with bounded JSON.
    """
    helper = load_helper_module()
    commands = []

    def observe(command):
        """Return a held route with omitted table and device fields.

        Args:
            command: Numeric-table inventory command.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps([{
            "dst": "default", "gateway": "192.0.2.1", "metric": 1, "protocol": "boot",
        }]), "")

    monkeypatch.setattr(helper, "_network_observation_command", observe)
    rows = helper._transition_route_rows("eth0", 4, 100)
    assert rows == [{"dst": "default", "gateway": "192.0.2.1", "metric": 1,
                     "protocol": "boot", "dev": "eth0", "table": 100}]
    assert commands == [["ip", "-j", "-4", "route", "show", "table", "100", "dev", "eth0"]]


@pytest.mark.parametrize("destination,gateway,source", [
    ("192.0.2.0/24", "", "192.0.2.10"),
    ("0.0.0.0/0", "192.0.2.1", "192.0.2.10"),
    ("::/0", "fe80::1", "2001:db8::10"),
])
def test_transition_seeds_missing_old_route_before_source_guard_and_retires_after_replacement(
    monkeypatch, tmp_path, destination, gateway, source,
):
    """An absent table-100 route gets a journaled standby before exact rules.

    Args:
        monkeypatch: Isolated native route operations.
        tmp_path: Task-owned transaction marker location.
        destination: Connected or default route copied from the old path.
        gateway: Proven old next hop, if any.
        source: Assigned old address used by the route.
    """
    helper = load_helper_module()
    family = 6 if ":" in destination else 4
    route = {"destination": destination, "gateway": gateway, "metric": 0,
             "scope": "link" if not gateway else "global", "table": 100,
             "preferred_source": source if not gateway else "", "preference": "medium",
             "holdover_metric": 1}
    evidence = {"eth0": {"mac": "02:00:00:00:00:01", "table": 100,
                         "cidrs": [f"{source}/64" if family == 6 else f"{source}/24"],
                         "routes": [route]}}
    state = {"previous_management_routing": evidence}
    observed = []
    events = []
    marker = tmp_path / "state.json"
    monkeypatch.setattr(helper, "_snapshot_management_handoff_routing", lambda *_args: evidence)
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: list(observed))
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write",
                        lambda _state, _marker: events.append("journal"))

    def run(command):
        """Model only exact route addition and deletion, recording their order.

        Args:
            command: Route command being simulated.
        """
        events.append(command[3])
        if command[3] == "add":
            observed.append({"dst": destination, "dev": "eth0", "gateway": gateway,
                             "metric": 2, "protocol": 2})
        else:
            observed.clear()
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], marker)
    assert events == ["journal", "add"]
    assert state["transition_seed_routes"][0]["seed_metric"] == 2
    assert "table" in helper._transition_route_command("add", state["transition_seed_routes"][0])
    # Networkd later installs the connected/default path at its own metric.
    observed.append({"dst": destination, "dev": "eth0", "gateway": gateway,
                     "metric": 1, "protocol": "static"})
    helper._retire_transition_routes(state, marker, require_replacement=True)
    assert events == ["journal", "add", "del", "journal"]
    assert state["transition_seed_routes"] == []


def test_transition_route_seed_refuses_changed_old_route_before_any_mutation(monkeypatch, tmp_path):
    """A stale snapshot cannot authorize a route and then a source-rule guard.

    Args:
        monkeypatch: Pytest fixture for replacing helper operations.
        tmp_path: Pytest fixture for the transition marker location.
    """
    helper = load_helper_module()
    evidence = {"eth0": {"mac": "02:00:00:00:00:01", "table": 100, "cidrs": ["192.0.2.10/24"],
                         "routes": [{"destination": "192.0.2.0/24", "gateway": "", "metric": 0,
                                     "scope": "link", "table": 100, "preferred_source": "192.0.2.10",
                                     "preference": "medium", "holdover_metric": 1}]}}
    state = {"previous_management_routing": evidence}
    monkeypatch.setattr(helper, "_snapshot_management_handoff_routing", lambda *_args: {})
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write",
                        lambda *_args: pytest.fail("stale routing was journaled"))
    monkeypatch.setattr(helper, "_run", lambda *_args: pytest.fail("stale routing was mutated"))
    with pytest.raises(ValueError, match="changed before transition"):
        helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], tmp_path / "state.json")


@pytest.mark.parametrize("successor,old_address_present,allowed", [
    ({"dst": "default", "dev": "eth0", "gateway": "192.0.2.1",
      "metric": 1, "protocol": "boot"}, True, True),
    ({"dst": "default", "dev": "eth0", "gateway": "192.0.2.2",
      "metric": 1024, "protocol": "dhcp"}, True, True),
    ({"dst": "198.51.100.0/24", "dev": "eth0", "metric": 1024,
      "protocol": "dhcp"}, True, False),
    (None, False, True),
])
def test_transition_retirement_requires_successor_or_disappeared_old_source(
    monkeypatch, tmp_path, successor, old_address_present, allowed,
):
    """A changed gateway is valid, but an unrelated route cannot replace old reachability.

    Args:
        monkeypatch: Pytest fixture for replacing helper operations.
        tmp_path: Pytest fixture for the transition marker location.
        successor: Candidate successor route for the old destination.
        old_address_present: Whether the old source remains on the link.
        allowed: Whether retirement is expected to succeed.
    """
    helper = load_helper_module()
    route = {"destination": "0.0.0.0/0", "gateway": "192.0.2.1", "metric": 0,
             "scope": "global", "table": 100, "preferred_source": "",
             "preference": "medium", "holdover_metric": 1}
    evidence = {"eth0": {"mac": "02:00:00:00:00:01", "table": 100,
                         "cidrs": ["192.0.2.10/24"], "routes": [route]}}
    seeded = {"name": "eth0", **route, "seed_metric": 2}
    state = {"previous_management_routing": evidence, "transition_seed_routes": [seeded]}
    observed = [{"dst": "default", "dev": "eth0", "gateway": "192.0.2.1",
                 "metric": 2, "protocol": "kernel"}]
    if successor:
        observed.append(successor)
    commands = []
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: observed)
    monkeypatch.setattr(helper, "_network_observation_command", lambda _command:
                        subprocess.CompletedProcess([], 0, json.dumps([{
                            "ifname": "eth0", "address": "02:00:00:00:00:01",
                            "addr_info": [{"local": "192.0.2.10" if old_address_present else "198.51.100.10"}],
                        }]), ""))
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: None)
    if allowed:
        helper._retire_transition_routes(state, tmp_path / "state.json",
                                         require_replacement=True, allow_disappeared_source=True)
        assert len(commands) == 1
        assert state["transition_seed_routes"] == []
    else:
        with pytest.raises(ValueError, match="replacement management route is not ready"):
            helper._retire_transition_routes(state, tmp_path / "state.json",
                                             require_replacement=True, allow_disappeared_source=True)
        assert commands == []


def test_transition_retirement_refuses_missing_seed_without_replacement(monkeypatch, tmp_path):
    """A vanished seed does not prove that the old source has a safe route.

    Args:
        monkeypatch: Replace native observations with a missing route table.
        tmp_path: Task-owned transaction marker location.
    """
    helper = load_helper_module()
    route = {"destination": "192.0.2.0/24", "gateway": "", "metric": 0,
             "scope": "link", "table": 100, "preferred_source": "192.0.2.10",
             "preference": "medium", "holdover_metric": 1}
    evidence = {"eth0": {"mac": "02:00:00:00:00:01", "table": 100,
                         "cidrs": ["192.0.2.10/24"], "routes": [route]}}
    state = {"previous_management_routing": evidence,
             "transition_seed_routes": [{"name": "eth0", **route, "seed_metric": 2}]}
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: [])
    monkeypatch.setattr(helper, "_run", lambda *_args: pytest.fail("missing seed was mutated"))
    with pytest.raises(ValueError, match="replacement management route is not ready"):
        helper._retire_transition_routes(state, tmp_path / "state.json", require_replacement=True)
    assert state["transition_seed_routes"]


def test_transition_retirement_waits_for_final_route_without_weakening_proof(monkeypatch, tmp_path):
    """A late RA successor may settle, while an unrelated error must fail immediately."""
    helper = load_helper_module()
    attempts = []

    def retire(_state, _marker, **kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            raise ValueError("replacement management route is not ready (family=6)")

    monkeypatch.setattr(helper, "_retire_transition_routes", retire)
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    helper._wait_and_retire_transition_routes({}, tmp_path / "state.json", attempts=2)
    assert attempts == [
        {"require_replacement": True, "allow_disappeared_source": True},
        {"require_replacement": True, "allow_disappeared_source": True},
    ]

    attempts.clear()
    monkeypatch.setattr(helper, "_retire_transition_routes", lambda *_args, **_kwargs:
                        (_ for _ in ()).throw(ValueError("transition route seed ownership is invalid")))
    with pytest.raises(ValueError, match="ownership is invalid"):
        helper._wait_and_retire_transition_routes({}, tmp_path / "state.json", attempts=2)


def test_snapshot_never_invents_gateway_or_ipv6_onlink_prefix(monkeypatch):
    """An RA prefix without the on-link flag must retain only observed routes.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    helper = load_helper_module()
    observe_snapshot(helper, monkeypatch,
                     v4_routes=[{"dst": "192.0.2.0/24", "dev": "eth0", "scope": "link"}],
                     v6_routes=[{"dst": "default", "dev": "eth0", "gateway": "fe80::1", "metric": 1024}])
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})["eth0"]
    assert len(evidence["routes"]) == 2
    assert not any(row["destination"] == "2001:db8::/64" for row in evidence["routes"])
    assert not any(row["destination"] == "0.0.0.0/0" for row in evidence["routes"])


def test_snapshot_ignores_other_domains_local_routes_and_duplicate_native_copies(monkeypatch):
    """Only the old device's main/old-domain unicast routes enter its holdover.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    helper = load_helper_module()
    route = {"dst": "192.0.2.0/24", "dev": "eth0", "scope": "link"}
    observe_snapshot(helper, monkeypatch, v4_routes=[route, {**route, "table": 100},
                     {"dst": "198.51.100.0/24", "dev": "eth0", "table": 200},
                     {"dst": "203.0.113.0/24", "dev": "eth1"},
                     {"dst": "192.0.2.10", "dev": "eth0", "table": "local", "type": "local"}])
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})["eth0"]
    assert [row["destination"] for row in evidence["routes"] if ":" not in row["destination"]] == ["192.0.2.0/24"]


def test_device_filtered_snapshot_accepts_omitted_dev_but_rejects_explicit_other_dev(monkeypatch):
    """An omitted JSON device is allowed only because the native query filters by it.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    helper = load_helper_module()
    commands = observe_snapshot(
        helper, monkeypatch,
        v4_routes=[{"dst": "192.0.2.0/24", "scope": "link"},
                   {"dst": "203.0.113.0/24", "dev": "eth1"}],
        v6_routes=[],
        addresses=[{"local": "192.0.2.10", "prefixlen": 24, "scope": "global"}],
    )
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})["eth0"]
    assert [route["destination"] for route in evidence["routes"]] == ["192.0.2.0/24"]
    assert all(command[-2:] == ["dev", "eth0"] for command in commands)


def test_snapshot_resolves_single_ipv6_nexthop_on_previous_device(monkeypatch):
    """A native nexthop ID may represent the RA gateway held during Apply.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    helper = load_helper_module()
    commands = observe_snapshot(
        helper, monkeypatch,
        v6_routes=[{"dst": "default", "nhid": 7, "metric": 1024, "protocol": "ra"}],
        nexthops={7: [{"id": 7, "dev": "eth0", "gateway": "fe80::1"}]},
    )
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})["eth0"]
    assert any(route["gateway"] == "fe80::1" and route["destination"] == "::/0"
               for route in evidence["routes"])
    assert ["ip", "-j", "nexthop", "show", "id", "7"] in commands


@pytest.mark.parametrize("nexthop", [
    {"id": 7, "dev": "eth1", "gateway": "fe80::1"},
    {"id": 7, "dev": "eth0", "group": [{"id": 8}]},
    {"id": 7, "dev": "eth0", "blackhole": None},
])
def test_snapshot_refuses_unsupported_ipv6_nexthop(monkeypatch, nexthop):
    """An unresolved or non-single-device nexthop cannot authorize holdover.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
        nexthop: Native next-hop row under test.
    """
    helper = load_helper_module()
    observe_snapshot(helper, monkeypatch,
                     v6_routes=[{"dst": "default", "nhid": 7, "metric": 1024}],
                     nexthops={7: [nexthop]})
    with pytest.raises(ValueError, match="nexthop cannot be preserved"):
        helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})


@pytest.mark.parametrize("bad_route", [
    {"metric": 0xFFFFFFFF}, {"metric": -1}, {"metric": True},
    {"nhid": 12}, {"multipath": [{"gateway": "192.0.2.1"}]}, {"from": "192.0.2.10/32"},
    {"gateway": "2001:db8::1"},
])
def test_snapshot_refuses_unrepresentable_routes_before_mutation(monkeypatch, bad_route):
    """Overflow and unsupported route semantics cannot silently alter the old path.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        bad_route: Unsupported native route shape that must be rejected.
    """
    helper = load_helper_module()
    route = {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", **bad_route}
    observe_snapshot(helper, monkeypatch, v4_routes=[route])
    with pytest.raises(ValueError):
        helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})


@pytest.mark.parametrize("address", [
    {"local": "192.0.2.10", "scope": "global"},
    {"local": "192.0.2.10", "prefixlen": 24, "scope": "global", "tentative": True},
    {"local": "192.0.2.10", "prefixlen": 24, "scope": "global", "flags": ["dadfailed"]},
])
def test_snapshot_requires_assigned_prefix_complete_old_addresses(monkeypatch, address):
    """Tentative or prefix-less addresses cannot authorize new held routing rules.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        address: Native address record used to test prefix completeness.
    """
    helper = load_helper_module()
    observe_snapshot(helper, monkeypatch, addresses=[address])
    with pytest.raises(ValueError):
        helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})


def test_holdover_renders_snapshotted_standby_routes_without_changing_candidate_domain(monkeypatch):
    """The old DHCP path keeps table100 alongside the candidate lab table200.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    helper = load_helper_module()
    observe_snapshot(helper, monkeypatch)
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})["eth0"]
    previous = "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n[DHCPv4]\nSendRelease=no\n"
    candidate = "[Match]\nName=eth0\n[Network]\n[Address]\nAddress=198.51.100.10/24\n[Route]\nDestination=198.51.100.0/24\nTable=200\n"
    text = helper._networkd_handoff_text(previous, candidate, held_routes=evidence["routes"])
    assert "DHCP=ipv4" in text
    assert "Table=200" in text
    assert "Destination=192.0.2.0/24\nTable=100\nMetric=1025\nScope=link" in text
    assert "Destination=0.0.0.0/0\nTable=100\nMetric=2049\nGateway=192.0.2.1\nGatewayOnLink=yes" in text
    assert "Destination=::/0\nTable=100\nMetric=2049\nGateway=fe80::1\nGatewayOnLink=yes" in text


@pytest.mark.parametrize("include_dev", [True, False])
def test_route_readiness_requires_standby_copy_not_merely_previous_native_route(monkeypatch, include_dev):
    """Existing native route presence cannot race standby installation.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        include_dev: Whether the native route observation includes a device.
    """
    helper = load_helper_module()
    observe_snapshot(helper, monkeypatch, v6_routes=[], addresses=[{"local": "192.0.2.10", "prefixlen": 24, "scope": "global"}])
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})
    snapshots = [
        [{"dst": "192.0.2.0/24", "dev": "eth0"}, {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "metric": 1024}],
        [{"dst": "192.0.2.0/24", "dev": "eth0", "metric": 1025},
         {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "metric": 2049}],
    ]
    if not include_dev:
        snapshots = [[{key: value for key, value in row.items() if key != "dev"} for row in rows]
                     for rows in snapshots]
    snapshots = iter(snapshots)
    commands = []
    monkeypatch.setattr(helper, "_network_observation_command", lambda command: commands.append(command) or
                        subprocess.CompletedProcess(command, 0, json.dumps(next(snapshots)), ""))
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    helper._wait_management_handoff_routes({"previous_management_routing": evidence}, attempts=2)
    assert len(commands) == 2
    assert all(command[-4:] == ["table", "100", "dev", "eth0"] for command in commands)


def test_missing_standby_route_blocks_activation(monkeypatch):
    """Do not publish source selectors that would choose an empty old table.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    helper = load_helper_module()
    observe_snapshot(helper, monkeypatch)
    state = {"previous_management_routing": helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})}
    monkeypatch.setattr(helper, "_network_observation_command", lambda command: subprocess.CompletedProcess(command, 0, "[]", ""))
    with pytest.raises(ValueError, match="did not become ready"):
        helper._wait_management_handoff_routes(state, attempts=1)


@pytest.mark.parametrize("destination,native_destination", [
    ("192.168.167.2/32", "192.168.167.2"),
    ("2001:db8::2/128", "2001:0db8:0:0:0:0:0:2"),
    ("0.0.0.0/0", "default"),
    ("::/0", "default"),
])
def test_route_readiness_normalizes_native_host_and_default_destinations(monkeypatch, destination, native_destination):
    """iproute2 omits host prefix lengths and prints both family defaults alike.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        destination: Desired canonical route destination.
        native_destination: Equivalent destination spelling returned by iproute2.
    """
    helper = load_helper_module()
    route = {"destination": destination, "gateway": "", "holdover_metric": 1025,
             "table": 100, "scope": "link", "preferred_source": "", "preference": "medium"}
    evidence = {"eth0": {"table": 100, "routes": [route]}}
    native = [{"dst": native_destination, "dev": "eth0", "metric": 1025}]
    monkeypatch.setattr(helper, "_network_observation_command", lambda command:
                        subprocess.CompletedProcess(command, 0, json.dumps(native), ""))
    helper._wait_management_handoff_routes({"previous_management_routing": evidence}, attempts=1)
    rendered = helper._networkd_handoff_text("[Match]\nName=eth0\n[Network]\n", "[Match]\nName=eth0\n[Network]\n", held_routes=[route])
    assert f"Destination={destination}\nTable=100\nMetric=1025\n" in rendered


def test_candidate_reconfiguration_waits_routes_without_installing_source_rules(monkeypatch):
    """Source intent is deferred until the caller proves candidate address readiness.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    helper = load_helper_module()
    calls = []
    monkeypatch.setattr(helper, "_install_systemd_networkd_files", lambda *_args, **_kwargs: (0, [], [], []))
    monkeypatch.setattr(helper, "_apply_vlan_interfaces", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([{"name": "eth1", "role": "management"}], [], []))
    monkeypatch.setattr(helper, "_link_exists", lambda _name: True)
    monkeypatch.setattr(helper, "_run", lambda command: calls.append(command) or subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(helper, "_wait_management_handoff_routes", lambda _state: calls.append("routes-ready"))
    monkeypatch.setattr(helper, "_install_route_domain_intent", lambda *_args, **_kwargs: pytest.fail("source activation ran too early"))
    helper._apply_management_candidate_network(Path("candidate.conf"), {"previous_management_interfaces": ["eth0"]})
    assert calls == [["networkctl", "reconfigure", "eth0"], ["networkctl", "reconfigure", "eth1"], "routes-ready"]


@pytest.mark.parametrize("management_ui", [False, True])
def test_candidate_new_address_never_becomes_a_held_old_source(monkeypatch, tmp_path, management_ui):
    """Publishing after DHCP/RA acquisition uses only immutable pre-mutation holds.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
        management_ui: Validated candidate access-listener eligibility to publish.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", tmp_path / "route-domains.json")
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", tmp_path / "route-domains.service")
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([{"name": "eth0", "role": "access",
                        "access_management_ui_enabled": str(management_ui).lower()}], [], []))
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda: {"Name": ["eth0"]})
    inventory = [{"ifname": "eth0", "address": "02:00:00:00:00:01", "addr_info": [
        {"scope": "global", "local": "192.0.2.10"}, {"scope": "global", "local": "198.51.100.10"}]}]
    monkeypatch.setattr(helper, "_network_observation_command", lambda command: subprocess.CompletedProcess(command, 0, json.dumps(inventory), ""))
    commands = []
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command) or subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(helper, "_fsync_file", lambda _path: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda _path: None)
    published = []
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda value, _path: published.append(value))
    old = {"name": "eth0", "mac": "02:00:00:00:00:01", "address": "192.0.2.10", "table": 100}
    helper._install_route_domain_intent(Path("candidate.conf"), held_addresses=[old])
    assert published[0]["held_addresses"] == [old]
    assert published[0]["interfaces"] == [{"name": "eth0", "mac": "02:00:00:00:00:01", "table": 200, "management_ui": management_ui}]
    unit = (tmp_path / "route-domains.service").read_text(encoding="utf-8")
    assert "DefaultDependencies=no" in unit
    assert "Before=systemd-networkd.service" in unit
    assert unit.index("ExecStartPre=/opt/atlaso/.venv/bin/python -I -m atlaso.route_domains --transition-start") < unit.index(
        "ExecStartPre=/opt/atlaso/.venv/bin/python -I -m atlaso.route_domains --once")
    assert commands[:3] == [["systemctl", "daemon-reload"],
                            ["systemctl", "enable", "--now", "route-domains.service"],
                            ["systemctl", "restart", "route-domains.service"]]
