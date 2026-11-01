"""Focused checks for retired-address and trusted-peer readbacks."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_retirement as retirement  # noqa: E402 - Local interop module import.

RETIRED = "192.0.2.40"
ACTIVE = "192.0.2.41"


class Session:
    def __init__(self, outputs: dict[str, bytes] | None = None) -> None:
        """Create a fake guest session with command-specific output.

        Args:
            outputs: Mapping of supported guest commands to their public output.
        """
        self.outputs = outputs or {}
        self.commands: list[str] = []

    def command(self, command: str) -> bytes:
        """Return configured output for a read-only guest command.

        Args:
            command: Exact command requested by the retirement verifier.
        """
        self.commands.append(command)
        if command not in self.outputs:
            raise RuntimeError("remote details must not leak")
        return self.outputs[command]


class Peer(Session):
    def __init__(self, retired: bool = False, active: bool = True) -> None:
        """Create a peer whose probes model retired and active addresses.

        Args:
            retired: Whether the retired address should accept TCP connections.
            active: Whether the active address should accept TCP connections.
        """
        super().__init__()
        self.results = {RETIRED: retired, ACTIVE: active}
        self.probes: list[tuple[str, int]] = []

    def tcp_reachable(self, address: str, port: int) -> bool:
        """Record a probe and return its configured reachability result.

        Args:
            address: IPv4 address being probed.
            port: TCP port being probed.
        """
        self.probes.append((address, port))
        return self.results[address]


def _json(value: Any) -> bytes:
    """Encode a value as UTF-8 JSON bytes for guest readback fixtures.

    Args:
        value: JSON-compatible value to encode.
    """
    return json.dumps(value).encode("utf-8")


def _plan() -> dict[str, Any]:
    return {
        "schema": 1,
        "task_id": "certificate-retirement-test",
        "repository": "mdaneri/Atlaso",
        "pr": 1074,
        "source_commit": "a" * 40,
    }


def _appliance(**changes: bytes) -> Session:
    """Build a guest session with normal address, listener, route, and rule output.

    Args:
        **changes: Command outputs that replace the normal fixture values.
    """
    outputs = {
        "ip -j -4 addr show": _json([
            {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
            {"ifname": "eth0", "addr_info": [{"family": "inet", "local": ACTIVE, "prefixlen": 24}]},
        ]),
        "ss -H -lnt": b"LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n",
        "ip -j -4 route show table all": _json([
            {"dst": "192.0.2.0/24", "dev": "eth0", "src": ACTIVE},
            {"dst": "default", "gateway": "192.0.2.1"},
        ]),
        "ip -j -4 rule show": _json([
            {"priority": 0, "src": "all", "table": "local"},
        ]),
    }
    outputs.update(changes)
    return Session(outputs)


def test_retirement_accepts_connected_subnet_and_requires_active_same_path() -> None:
    peer = Peer()
    appliance = _appliance()

    evidence = retirement.verify_retired_address(_plan(), peer, appliance, RETIRED, ACTIVE)

    assert evidence["kind"] == "certificate-address-retirement"
    assert evidence["retired_address_present"] is False
    assert evidence["retired_listener_count"] == 0
    assert evidence["retired_route_reference_count"] == 0
    assert evidence["retired_rule_reference_count"] == 0
    assert evidence["peer_retired_tcp_reachable"] is False
    assert evidence["peer_active_tcp_reachable"] is True
    assert peer.probes == [(RETIRED, 443), (ACTIVE, 443)]
    assert "ip -j -4 addr show" in appliance.commands
    assert "ss -H -lnt" in appliance.commands
    assert "ip -j -4 route show table all" in appliance.commands
    assert "ip -j -4 rule show" in appliance.commands


@pytest.mark.parametrize(
    ("command", "value", "reason"),
    [
        (
            "ip -j -4 addr show",
            [{"ifname": "eth1", "addr_info": [{"family": "inet", "local": RETIRED}]}],
            "retired_address_still_owned",
        ),
        (
            "ss -H -lnt",
            b"LISTEN 0 64 192.0.2.40:443 0.0.0.0:*\n",
            "retired_address_still_owned",
        ),
        (
            "ss -H -lnt",
            b"LISTEN 0 64 [::ffff:192.0.2.40]:443 [::]:*\n",
            "retired_address_still_owned",
        ),
        (
            "ip -j -4 route show table all",
            [{"dst": "192.0.2.40/32", "dev": "eth0"}],
            "retired_address_still_owned",
        ),
        (
            "ip -j -4 route show table all",
            [{"dst": "default", "src": RETIRED}],
            "retired_address_still_owned",
        ),
        (
            "ip -j -4 rule show",
            [{"priority": 99, "src": RETIRED}],
            "retired_address_still_owned",
        ),
        (
            "ip -j -4 rule show",
            [{"priority": 99, "src": "all", "dst": RETIRED}],
            "retired_address_still_owned",
        ),
        (
            "ip -j -4 rule show",
            [{"priority": 99, "src": RETIRED, "srclen": 32}],
            "retired_address_still_owned",
        ),
        (
            "ip -j -4 rule show",
            [{"priority": 99, "src": "all", "dst": RETIRED, "dstlen": 32}],
            "retired_address_still_owned",
        ),
    ],
)
def test_retirement_refuses_leftover_address_listener_route_or_rule(
    command: str, value: Any, reason: str,
) -> None:
    """Reject a retired address found in any guest-owned network state.

    Args:
        command: Guest command whose output contains the leftover reference.
        value: Synthetic output value for that command.
        reason: Expected refusal marker from the verifier.
    """
    outputs = {}
    if command == "ss -H -lnt":
        outputs[command] = value
    else:
        outputs[command] = _json(value)
    appliance = _appliance(**outputs)

    with pytest.raises(retirement.Refusal, match=reason):
        retirement.verify_retired_address(_plan(), Peer(), appliance, RETIRED, ACTIVE)


def test_retirement_accepts_native_iprule_wildcards_and_subnet_selectors() -> None:
    rules = [
        {"priority": 0, "src": "all", "table": "local"},
        {"priority": 100, "src": "192.0.2.0", "srclen": 24, "table": 100},
        {"priority": 101, "src": "0", "srclen": 0, "table": "main"},
        {"priority": 102, "src": "all", "dst": "0.0.0.0", "dstlen": 0},
    ]

    assert retirement._rule_facts(rules, RETIRED) == 0


@pytest.mark.parametrize(
    "rule",
    [
        {"priority": 99},
        {"priority": 99, "src": "all", "srclen": "0"},
        {"priority": 99, "src": "all", "srclen": True},
        {"priority": 99, "src": "192.0.2.0", "srclen": 33},
        {"priority": 99, "src": "192.0.2.0", "srclen": -1},
        {"priority": 99, "src": "192.0.2.0", "srclen": 24.0},
        {"priority": 99, "dstlen": 24},
        {"priority": 99, "dstlen": "0"},
        {"priority": 99, "src": "all", "srclen": 1},
        {"priority": 99, "src": RETIRED, "from": RETIRED},
        {"priority": 99, "src": "2001:db8::1"},
    ],
)
def test_retirement_refuses_malformed_native_iprule_selectors(rule: dict[str, Any]) -> None:
    """Reject malformed source or destination selectors in native ip-rule data.

    Args:
        rule: Synthetic native ip-rule record with an invalid selector.
    """
    with pytest.raises(retirement.Refusal, match="retirement_rule_readback_invalid"):
        retirement._rule_facts([rule], RETIRED)


def test_retirement_refuses_transport_failure_instead_of_treating_it_as_closed() -> None:
    class BrokenPeer(Peer):
        def tcp_reachable(self, address: str, port: int) -> bool:
            """Raise a transport failure instead of reporting reachability.

            Args:
                address: IPv4 address requested by the retirement verifier.
                port: TCP port requested by the retirement verifier.
            """
            raise RuntimeError("transport failure detail")

    with pytest.raises(retirement.Refusal, match="retirement_tcp_probe_failed") as error:
        retirement.verify_retired_address(_plan(), BrokenPeer(), _appliance(), RETIRED, ACTIVE)

    assert str(error.value) == "retirement_tcp_probe_failed"


def test_retirement_requires_active_address_reachable_from_same_peer() -> None:
    with pytest.raises(retirement.Refusal, match="active_address_unreachable"):
        retirement.verify_retired_address(_plan(), Peer(active=False), _appliance(), RETIRED, ACTIVE)


def test_retirement_refuses_a_still_reachable_retired_address() -> None:
    with pytest.raises(retirement.Refusal, match="retired_address_still_reachable"):
        retirement.verify_retired_address(_plan(), Peer(retired=True), _appliance(), RETIRED, ACTIVE)


def test_retirement_refuses_bad_guest_output_without_echoing_it() -> None:
    appliance = _appliance(**{"ip -j -4 addr show": b"host secret output"})

    with pytest.raises(retirement.Refusal, match="retirement_address_readback_invalid") as error:
        retirement.verify_retired_address(_plan(), Peer(), appliance, RETIRED, ACTIVE)

    assert str(error.value) == "retirement_address_readback_invalid"


def test_retirement_rejects_invalid_plan_and_same_addresses() -> None:
    with pytest.raises(retirement.Refusal, match="retirement_plan_invalid"):
        retirement.verify_retired_address({}, Peer(), _appliance(), RETIRED, ACTIVE)
    with pytest.raises(retirement.Refusal, match="retirement_addresses_must_differ"):
        retirement.verify_retired_address(_plan(), Peer(), _appliance(), RETIRED, RETIRED)


def _isolated_peer(
    *, ipv4: bytes = b"0\n", ipv6: bytes = b"0\n", links: Any | None = None,
) -> Session:
    """Build peer output for forwarding and bridge-isolation checks.

    Args:
        ipv4: Value returned for the IPv4 forwarding sysctl.
        ipv6: Value returned for the IPv6 forwarding sysctl.
        links: Optional replacement JSON link inventory.
    """
    return Session({
        "cat /proc/sys/net/ipv4/ip_forward": ipv4,
        "cat /proc/sys/net/ipv6/conf/all/forwarding": ipv6,
        "ip -j link show": _json(links if links is not None else [
            {"ifname": "lo", "flags": ["LOOPBACK"]},
            {"ifname": "eth0", "flags": ["BROADCAST", "UP"]},
        ]),
    })


def test_peer_isolation_accepts_forwarding_disabled_unbridged_links() -> None:
    peer = _isolated_peer()

    evidence = retirement.verify_peer_isolation(peer)

    assert evidence["ipv4_forwarding_enabled"] is False
    assert evidence["ipv6_forwarding_enabled"] is False
    assert evidence["bridge_membership_detected"] is False
    assert evidence["interface_count"] == 2


@pytest.mark.parametrize(
    ("peer", "reason"),
    [
        (_isolated_peer(ipv4=b"1\n"), "peer_forwarding_enabled"),
        (_isolated_peer(ipv6=b"1\n"), "peer_forwarding_enabled"),
        (_isolated_peer(links=[{"ifname": "eth0", "master": "br0"}]), "peer_bridge_membership_detected"),
        (_isolated_peer(links=[{"ifname": "br0", "linkinfo": {"info_kind": "bridge"}}]), "peer_bridge_membership_detected"),
    ],
)
def test_peer_isolation_refuses_forwarding_or_bridging(peer: Session, reason: str) -> None:
    """Reject peer forwarding or bridge membership in the isolated test LAN.

    Args:
        peer: Synthetic peer session with the isolation defect.
        reason: Expected refusal marker for that defect.
    """
    with pytest.raises(retirement.Refusal, match=reason):
        retirement.verify_peer_isolation(peer)
