"""Verify held DHCP/RA route evidence and guarded source-domain activation."""

import json
import subprocess
from pathlib import Path

import pytest

from tests.test_appliance_helper import load_helper_module


def observe_snapshot(helper, monkeypatch, *, v4_routes=None, v6_routes=None, addresses=None):
    """Provide bounded native route/address snapshots without touching the host.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        v4_routes: Observed IPv4 routes for the previous management path.
        v6_routes: Observed IPv6 routes for the previous management path.
        addresses: Assigned native address records.
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
    commands = []

    def observation(command):
        """Return only the exact interface or family requested by the helper.

        Args:
            command: Native command being recorded or simulated.
        """
        commands.append(command)
        if "address" in command:
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


def test_route_readiness_requires_standby_copy_not_merely_previous_native_route(monkeypatch):
    """Existing native route presence cannot race standby installation.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    helper = load_helper_module()
    observe_snapshot(helper, monkeypatch, v6_routes=[], addresses=[{"local": "192.0.2.10", "prefixlen": 24, "scope": "global"}])
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})
    snapshots = iter([
        [{"dst": "192.0.2.0/24", "dev": "eth0"}, {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "metric": 1024}],
        [{"dst": "192.0.2.0/24", "dev": "eth0", "metric": 1025},
         {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1", "metric": 2049}],
    ])
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


def test_candidate_new_address_never_becomes_a_held_old_source(monkeypatch, tmp_path):
    """Publishing after DHCP/RA acquisition uses only immutable pre-mutation holds.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", tmp_path / "route-domains.json")
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", tmp_path / "route-domains.service")
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([{"name": "eth0", "role": "access"}], [], []))
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda: {"Name": ["eth0"]})
    inventory = [{"ifname": "eth0", "address": "02:00:00:00:00:01", "addr_info": [
        {"scope": "global", "local": "192.0.2.10"}, {"scope": "global", "local": "198.51.100.10"}]}]
    monkeypatch.setattr(helper, "_network_observation_command", lambda command: subprocess.CompletedProcess(command, 0, json.dumps(inventory), ""))
    monkeypatch.setattr(helper, "_run", lambda command: subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(helper, "_fsync_file", lambda _path: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda _path: None)
    published = []
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda value, _path: published.append(value))
    old = {"name": "eth0", "mac": "02:00:00:00:00:01", "address": "192.0.2.10", "table": 100}
    helper._install_route_domain_intent(Path("candidate.conf"), held_addresses=[old])
    assert published[0]["held_addresses"] == [old]
    assert published[0]["interfaces"] == [{"name": "eth0", "mac": "02:00:00:00:00:01", "table": 200}]
