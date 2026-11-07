"""Pure planning contracts for future dual-stack certificate native tests.

These validators neither execute a test nor authenticate native observations.
They do not admit a VM, topology, certificate, enforcement source, or proof kind.
Callers still need original receipts, source/boot bindings, a supported raw
producer, and independent execution admission. The legacy IPv4 fixture is separate.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class ContractRefusal(ValueError):
    """Fixed, non-secret reason that prevents use of a planning input."""


@dataclass(frozen=True)
class PlannedStep:
    """An expected interface state, never an observation or execution receipt."""

    name: str
    ipv4_cidr: str
    ipv6_cidr: str | None


_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
_ALLOWED_FLAGS = frozenset({"permanent", "noprefixroute"})
_OBSERVATION_FIELDS = frozenset({
    "schema", "kind", "interface", "mac", "operstate", "carrier", "family", "address",
    "prefixlen", "source", "flags", "dad_state", "valid_lifetime", "preferred_lifetime",
})


def _network(value: Any, family: int) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse one explicitly declared, canonical family-specific fixture prefix.

    Args:
        value: Declared fixture prefix, without an interface zone.
        family: Required numeric IP family.
    """
    if not isinstance(value, str) or "%" in value:
        raise ContractRefusal("fixture_prefix_invalid")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ContractRefusal("fixture_prefix_invalid") from None
    if (network.version != family or network.prefixlen == 0
            or network.is_multicast or network.is_unspecified
            or network.is_loopback or network.is_link_local):
        raise ContractRefusal("fixture_prefix_invalid")
    return network


def _usable(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject unusable or scope-ambiguous fixture endpoints.

    Args:
        address: Parsed numeric address.
    """
    return not (
        address.is_unspecified or address.is_multicast or address.is_loopback
        or address.is_link_local or address.is_reserved
        or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
    )


def _interface(
    value: Any, network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface:
    """Normalize a static host CIDR inside its exact declared fixture prefix.

    Args:
        value: Static host CIDR.
        network: Explicit fixture prefix; this is not address-control authority.
    """
    if not isinstance(value, str) or "%" in value:
        raise ContractRefusal("fixture_address_invalid")
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError:
        raise ContractRefusal("fixture_address_invalid") from None
    if (interface.version != network.version or interface.network != network
            or not _usable(interface.ip) or interface.ip == network.network_address
            or isinstance(network, ipaddress.IPv4Network)
            and interface.ip == network.broadcast_address):
        raise ContractRefusal("fixture_address_invalid")
    return interface


def plan_steps(
    *, ipv4_network: str, ipv6_network: str, main_ipv4: str, main_ipv6: str,
    candidate_ipv4: str, candidate_ipv6: str, peer_ipv4: str, peer_ipv6: str,
) -> tuple[PlannedStep, ...]:
    """Derive reciprocal family transitions from distinct declared static hosts.

    This describes expected states only. Exact original-state restoration needs
    a separately admitted original snapshot and a known transaction outcome.

    Args:
        ipv4_network: Explicit IPv4 fixture prefix.
        ipv6_network: Explicit IPv6 fixture prefix.
        main_ipv4: Baseline main IPv4 host CIDR.
        main_ipv6: Baseline main IPv6 host CIDR.
        candidate_ipv4: Replacement main IPv4 host CIDR.
        candidate_ipv6: Replacement main IPv6 host CIDR.
        peer_ipv4: Peer IPv4 host CIDR.
        peer_ipv6: Peer IPv6 host CIDR.
    """
    network4 = _network(ipv4_network, 4)
    network6 = _network(ipv6_network, 6)
    hosts4 = tuple(_interface(value, network4) for value in (
        main_ipv4, candidate_ipv4, peer_ipv4,
    ))
    hosts6 = tuple(_interface(value, network6) for value in (
        main_ipv6, candidate_ipv6, peer_ipv6,
    ))
    if len({host.ip for host in hosts4}) != 3 or len({host.ip for host in hosts6}) != 3:
        raise ContractRefusal("fixture_addresses_must_differ")
    base4, next4 = str(hosts4[0]), str(hosts4[1])
    base6, next6 = str(hosts6[0]), str(hosts6[1])
    return (
        PlannedStep("active_ipv4", base4, None),
        PlannedStep("add_ipv6", base4, base6),
        PlannedStep("replace_ipv4", next4, base6),
        PlannedStep("restore_ipv4", base4, base6),
        PlannedStep("replace_ipv6", base4, next6),
        PlannedStep("restore_ipv6", base4, base6),
    )


def _mac(value: Any) -> str:
    """Normalize a nonzero unicast MAC without echoing malformed input.

    Args:
        value: Expected or observed normalized MAC string.
    """
    if not isinstance(value, str) or _MAC.fullmatch(value) is None:
        raise ContractRefusal("static_observation_invalid")
    octets = bytes.fromhex(value.replace(":", ""))
    if not any(octets) or octets[0] & 1:
        raise ContractRefusal("static_observation_invalid")
    return value.lower()


def _lifetime(value: Any) -> float:
    """Parse a usable normalized kernel lifetime, excluding booleans.

    Args:
        value: Positive unsigned 32-bit seconds or the exact string forever.
    """
    if value == "forever":
        return float("inf")
    if type(value) is not int or not 0 < value <= 4_294_967_295:
        raise ContractRefusal("static_observation_invalid")
    return float(value)


def validate_static_observation(
    observation: Mapping[str, Any], *, expected_interface: str,
    expected_mac: str, expected_cidr: str,
) -> None:
    """Check normalized fixture facts without authenticating their producer.

    The source=static field is a consistency claim, not proof of provenance.
    Raw producer authentication, source/boot/MAC ownership, complete inventories,
    DAD observation, freshness, and address enforcement remain external gates.

    Args:
        observation: Exact normalized contract fields, not raw native IP JSON.
        expected_interface: Admitted interface name.
        expected_mac: Admitted interface MAC.
        expected_cidr: Expected static host address and prefix.
    """
    if (not isinstance(observation, Mapping)
            or set(observation) != _OBSERVATION_FIELDS
            or type(observation["schema"]) is not int or observation["schema"] != 1
            or observation["kind"] != "static-fixture-observation"
            or not isinstance(expected_interface, str)
            or _INTERFACE.fullmatch(expected_interface) is None
            or observation["interface"] != expected_interface
            or observation["operstate"] != "UP" or observation["carrier"] is not True
            or observation["source"] != "static"):
        raise ContractRefusal("static_observation_invalid")
    if _mac(observation["mac"]) != _mac(expected_mac):
        raise ContractRefusal("static_observation_invalid")
    if not isinstance(expected_cidr, str) or "%" in expected_cidr:
        raise ContractRefusal("static_observation_invalid")
    try:
        expected = ipaddress.ip_interface(expected_cidr)
        network = _network(str(expected.network), expected.version)
        expected = _interface(expected_cidr, network)
    except ValueError:
        raise ContractRefusal("static_observation_invalid") from None
    if (type(observation["family"]) is not int
            or observation["family"] != expected.version
            or observation["dad_state"] != ("complete" if expected.version == 6 else "not_applicable")
            or type(observation["prefixlen"]) is not int
            or observation["prefixlen"] != expected.network.prefixlen
            or not isinstance(observation["address"], str)
            or "%" in observation["address"]):
        raise ContractRefusal("static_observation_invalid")
    try:
        address = ipaddress.ip_address(observation["address"])
    except ValueError:
        raise ContractRefusal("static_observation_invalid") from None
    if address != expected.ip:
        raise ContractRefusal("static_observation_invalid")
    flags = observation["flags"]
    if (not isinstance(flags, list) or len(flags) > len(_ALLOWED_FLAGS)
            or any(not isinstance(flag, str) or flag not in _ALLOWED_FLAGS for flag in flags)
            or len(set(flags)) != len(flags)):
        raise ContractRefusal("static_observation_invalid")
    valid = _lifetime(observation["valid_lifetime"])
    preferred = _lifetime(observation["preferred_lifetime"])
    if preferred > valid:
        raise ContractRefusal("static_observation_invalid")
