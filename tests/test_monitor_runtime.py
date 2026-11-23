"""Exercise Monitor's bounded native observations and trusted projections."""

import json
import time

import pytest

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.services import monitor_runtime as runtime
from atlaso.monitor_native import (
    ObservationUnavailable,
    collect_listeners,
    listener_endpoint,
)


@pytest.mark.parametrize("origin_status", ["complete", "incomplete", "timeout"])
def test_network_projects_forwarding_domains_addresses_and_neighbors(monkeypatch, origin_status):
    """Keep table identity, observed gateway states, and address origin distinct.

    Args:
        monkeypatch: Fixture that substitutes native observations.
        origin_status: Address-origin outcome to simulate.
    """
    data = {
        ("-4", "route", "show", "table", "all"): [
            {"dst": "default", "table": "main", "gateway": "192.0.2.1", "dev": "eth0", "protocol": "16"},
            {"dst": "default", "table": "200", "gateway": "192.0.2.1", "dev": "eth1"},
        ],
        ("-6", "route", "show", "table", "all"): [
            {"dst": "default", "table": "100", "nexthops": [{"gateway": "fe80::1", "dev": "eth0", "weight": 2}]},
        ],
        ("-4", "rule", "show"): [
            {"priority": 120, "src": "192.0.2.2", "iif": "lo", "type": "7"},
            {"priority": 100, "src": "192.0.2.0", "srclen": 24, "iif": "lo", "table": "100"},
        ],
        ("-6", "rule", "show"): [],
        ("-4", "neigh", "show"): [{"dst": "192.0.2.1", "dev": "eth0", "state": ["FAILED"]}],
        ("-6", "neigh", "show"): [{"dst": "fe80::1", "dev": "eth0", "state": ["STALE"]}],
        ("-statistics", "address", "show"): [
            {"ifname": "eth0", "ifindex": 2, "address": "00:11:22:33:44:55", "flags": ["UP", "LOWER_UP"],
             "mtu": 1500, "stats64": {"rx": {"errors": 3}, "tx": {"errors": 0}},
             "addr_info": [{"local": "192.0.2.2", "prefixlen": 24}]},
            {"ifname": "eth0.100", "ifindex": 3, "link_index": 2, "flags": ["UP"], "mtu": 1450,
             "linkinfo": {"info_kind": "vlan", "info_data": {"id": 100}},
             "addr_info": [{"local": "fe80::2", "prefixlen": 64}]},
        ],
    }

    def observe(command, argv, deadline):
        """Return a fixture for the requested native operation.

        Args:
            command: Native executable name.
            argv: Native command arguments.
            deadline: Monotonic deadline for the read.
        """
        assert command == "ip"
        assert argv[:3] == ["-N", "-j", "-details"]
        return 0, json.dumps(data[tuple(argv[3:])])

    def helper(_self, *, timeout_seconds):
        """Return the selected address-status outcome.

        Args:
            _self: Adapter instance whose method was replaced.
            timeout_seconds: Time budget for observing address origins.
        """
        assert 0 < timeout_seconds <= 3
        if origin_status == "timeout":
            return AdapterResult([], False, returncode=124)
        return AdapterResult([], False, json.dumps({
            "complete": origin_status == "complete",
            "links": [{"name": "eth0", "ifindex": 2, "mac": "00:11:22:33:44:55",
                       "addresses": [{"address": "192.0.2.2", "source": "DHCPv4", "state": "assigned"}]}],
        }))

    adapter = SystemAdapter(dry_run=False)
    monkeypatch.setattr(runtime, "SystemAdapter", lambda: adapter)
    monkeypatch.setattr(SystemAdapter, "read_network_address_status", helper)
    monkeypatch.setattr(runtime, "run_native", observe)
    monkeypatch.setattr(runtime.Path, "read_text", lambda self, **_kw: "0" if self.name == "ip_forward" else "1")
    payload = runtime.collect_network()["sections"]
    assert [(row["family"], row["table"]) for row in payload["routes"]["rows"]] == [(4, 254), (4, 200), (6, 100)]
    assert payload["routes"]["rows"][0]["protocol"] == "dhcp"
    assert payload["routes"]["rows"][2]["nexthops"][0]["weight"] == 2
    assert [row["action"] for row in payload["rules"]["rows"]] == ["lookup", "unreachable"]
    assert payload["rules"]["rows"][0]["source"] == "192.0.2.0/24"
    assert [row["state"] for row in payload["neighbors"]["rows"]] == ["FAILED", "No entry observed", "STALE"]
    physical, vlan = payload["interfaces"]["rows"]
    assert physical["carrier"] and physical["rx_errors"] == 3
    expected_origin = "DHCPv4" if origin_status == "complete" else None
    assert physical["addresses"] == [{"address": "192.0.2.2", "prefix": 24, "origin": expected_origin}]
    assert payload["interfaces"]["state"] == ("ok" if origin_status == "complete" else "partial")
    assert (vlan["parent"], vlan["vlan"], vlan["carrier"]) == ("eth0", 100, False)
    assert payload["forwarding"]["rows"] == [{"family": 4, "enabled": False}, {"family": 6, "enabled": True}]


def test_native_catch_all_rules_keep_dual_stack_observation_complete(monkeypatch):
    """Preserve explicit zero-length catch-all selectors for both IP families.

    Args:
        monkeypatch: Fixture that supplies native rule output.
    """
    monkeypatch.setattr(runtime, "run_native", lambda *_args: (
        0, '[{"priority": 100, "src": "all", "srclen": 0, "dst": "all", "dstlen": 0, "table": "100"}]',
    ))

    result = runtime._dual_stack(["rule", "show"], runtime._rule, time.monotonic() + 3)

    assert result["state"] == "ok"
    assert [(row["family"], row["source"], row["destination"]) for row in result["rows"]] == [
        (4, "all", "all"),
        (6, "all", "all"),
    ]


def test_partial_native_families_do_not_claim_empty(monkeypatch):
    """A timed-out family leaves the remaining route data explicitly partial.

    Args:
        monkeypatch: Fixture that substitutes native observations.
    """
    def observe(command, argv, _deadline):
        """Return IPv4 data and simulate an IPv6 timeout.

        Args:
            command: Native executable name.
            argv: Native command arguments.
            _deadline: Unused monotonic deadline.
        """
        assert command == "ip"
        if "-6" in argv:
            raise ObservationUnavailable
        return 0, '[{"dst":"192.0.2.0/24","dev":"eth0"}]'

    monkeypatch.setattr(runtime, "run_native", observe)
    result = runtime._dual_stack(["route", "show"], runtime._route, time.monotonic() + 3)
    assert result["state"] == "partial"
    assert result["rows"][0]["destination"] == "192.0.2.0/24"


def test_route_lookup_passes_only_numeric_destinations_and_validated_selectors(monkeypatch):
    """Exercise local and forwarded kernel lookup arguments and negative outcomes.

    Args:
        monkeypatch: Fixture that substitutes the kernel lookup.
    """

    monkeypatch.setattr(runtime, "SystemAdapter", lambda: SystemAdapter(dry_run=False))
    calls = []

    def observe(command, argv, _deadline, *, input_data):
        """Return the result associated with the fixed lookup command.

        Args:
            command: Native executable name.
            argv: Native command arguments.
            _deadline: Unused monotonic deadline.
            input_data: Validated lookup line passed to the command.
        """
        calls.append(([command, *argv], input_data))
        if input_data == b"route get fibmatch 203.0.113.1\n":
            return 2, "RTNETLINK answers: Network is unreachable"
        table, interface = ("200", "eth2") if b" iif " in input_data else ("100", "eth0")
        return 0, json.dumps([{"dst": "default", "table": table, "dev": interface, "gateway": "192.0.2.1"}])

    monkeypatch.setattr(runtime, "run_native", observe)
    for fields in (
        ("example.com", "", ""), ("192.0.2.2", "::1", ""), ("192.0.2.2", "", "eth0;id"),
        ("192.0.2.2\n", "", ""), ("192.0.2.2", "", "eth0\neth1"), ("fe80::1%eth0", "", ""),
    ):
        with pytest.raises(ValueError):
            runtime.route_lookup(*fields)
    assert calls == []
    assert runtime.route_lookup("192.0.2.2", "192.0.2.4", "")["rows"][0]["table"] == 100
    assert runtime.route_lookup("192.0.2.2", "192.0.2.4", "eth1")["rows"][0]["table"] == 200
    assert calls[1] == (
        ["ip", "-N", "-j", "-details", "-4", "-batch", "-"],
        b"route get fibmatch 192.0.2.2 from 192.0.2.4 iif eth1\n",
    )
    assert runtime.route_lookup("203.0.113.1", "", "")["state"] == "unreachable"


def test_services_and_clock_keep_incomplete_listener_and_pending_clock_evidence(monkeypatch):
    """Observe inactive services without inferring listeners or clock synchronization.

    Args:
        monkeypatch: Fixture that substitutes service and clock observations.
    """

    adapter = SystemAdapter(dry_run=False)
    monkeypatch.setattr(runtime, "SystemAdapter", lambda: adapter)
    monkeypatch.setattr(runtime, "_service_properties", lambda: {
        "atlaso.service": {"ActiveState": "active", "ActiveEnterTimestampMonotonic": "1000000", "NRestarts": "2"},
        "slapd.service": {"ActiveState": "inactive", "NRestarts": "0"},
    })
    monkeypatch.setattr(adapter, "read_monitor_listeners", lambda: AdapterResult([], False, json.dumps({
        "state": "partial", "rows": [{"unit": "atlaso.service", "protocol": "tcp", "address": "127.0.0.1", "port": 8000}],
    })))
    monkeypatch.setattr(adapter, "read_ntpd_status", lambda: AdapterResult([], False, json.dumps({
        "mode": "ntp_client", "synchronization": {"state": "synchronized", "raw_output": "not a projection"},
        "transaction": {"pending": True},
    })))
    sections = runtime.collect_services()["sections"]
    assert sections["services"]["state"] == "partial"
    rows = {row["unit"]: row for row in sections["services"]["rows"]}
    assert rows["atlaso.service"]["restarts"] == 2
    assert rows["atlaso.service"]["listeners"] == [{"protocol": "tcp", "address": "127.0.0.1", "port": 8000}]
    assert rows["slapd.service"]["state"] == "inactive"
    assert rows["slapd.service"]["listeners"] is None
    assert sections["clock"]["rows"] == [{"source": "ntp_client", "synchronization": "unverified", "pending": True}]


def test_listener_capture_requires_socket_and_cgroup_ownership(monkeypatch):
    """Expose attribution only for an exact kernel-owned socket in a packaged unit.

    Args:
        monkeypatch: Fixture that substitutes socket and ownership observations.
    """
    from atlaso import monitor_native

    def observe(command, args, _deadline):
        """Return IPv4 socket records for the ownership check.

        Args:
            command: Native executable name.
            args: Native socket inventory arguments.
            _deadline: Unused monotonic deadline.
        """
        assert command == "ss"
        if "-4" in args:
            return 0, (
                'tcp LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* users:(("python",pid=12,fd=4)) ino:42\n'
                'udp UNCONN 0 0 127.0.0.1:123 0.0.0.0:* users:(("ntpd",pid=21,fd=6)) ino:84'
            )
        return 0, ""

    monkeypatch.setattr(monitor_native, "run_native", observe)
    monkeypatch.setattr(monitor_native, "socket_unit",
                        lambda *args: "/system.slice/atlaso.service" if args == ("12", "4", "42") else None)
    assert collect_listeners() == {
        "state": "partial",
        "rows": [{"unit": "atlaso.service", "protocol": "tcp", "address": "127.0.0.1", "port": 8000}],
    }
    assert listener_endpoint("[fe80::1%eth0]:53", 6) == ("fe80::1%eth0", 53)
