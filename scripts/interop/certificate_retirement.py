"""Read-only proof that a retired IPv4 address is absent from an appliance."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any


class Refusal(Exception):
    """Fixed, non-secret reason that prevents a retirement claim."""


_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _identity(plan: Any) -> dict[str, Any]:
    if (not isinstance(plan, dict) or plan.get("schema") != 1
            or not isinstance(plan.get("task_id"), str) or not plan["task_id"]
            or plan.get("repository") != "mdaneri/Atlaso"
            or not isinstance(plan.get("pr"), int) or isinstance(plan.get("pr"), bool) or plan["pr"] <= 0
            or not isinstance(plan.get("source_commit"), str)
            or _COMMIT.fullmatch(plan["source_commit"]) is None):
        raise Refusal("retirement_plan_invalid")
    return {
        "task_id": plan["task_id"],
        "repository": plan["repository"],
        "pr": plan["pr"],
        "source_commit": plan["source_commit"],
    }


def _ipv4(value: Any, reason: str) -> str:
    if not isinstance(value, str):
        raise Refusal(reason)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise Refusal(reason) from None
    if not isinstance(address, ipaddress.IPv4Address) or address.is_unspecified or address.is_multicast:
        raise Refusal(reason)
    return str(address)


def _json_output(session: Any, command: str, refusal: str) -> Any:
    invalid = refusal.removesuffix("_failed") + "_invalid"
    try:
        output = session.command(command)
    except Exception:  # noqa: BLE001 - Session implementations use transport-specific failures.
        raise Refusal(refusal) from None
    if not isinstance(output, bytes) or len(output) > 65_536:
        raise Refusal(invalid)
    try:
        value = json.loads(output)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise Refusal(invalid) from None
    return value


def _address_facts(value: Any, retired: str) -> bool:
    if not isinstance(value, list):
        raise Refusal("retirement_address_readback_invalid")
    for interface in value:
        if not isinstance(interface, dict) or not isinstance(interface.get("addr_info", []), list):
            raise Refusal("retirement_address_readback_invalid")
        for address in interface.get("addr_info", []):
            if not isinstance(address, dict):
                raise Refusal("retirement_address_readback_invalid")
            local = address.get("local")
            if local is not None and _ipv4(local, "retirement_address_readback_invalid") == retired:
                return True
    return False


def _listener_count(output: bytes, retired: str) -> int:
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Refusal("retirement_listener_readback_invalid") from None
    count = 0
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] != "LISTEN":
            raise Refusal("retirement_listener_readback_invalid")
        local = fields[3]
        host, separator, _port = local.rpartition(":")
        if not separator or not host:
            raise Refusal("retirement_listener_readback_invalid")
        address_text = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            # Wildcard and abstract socket notation are not bindings to the
            # retired IPv4 address. Reject other unrecognized endpoint forms.
            if host not in {"*", "0.0.0.0", "[::]", "::"}:
                raise Refusal("retirement_listener_readback_invalid") from None
            continue
        if (isinstance(address, ipaddress.IPv4Address) and str(address) == retired
                or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
                and str(address.ipv4_mapped) == retired):
            count += 1
    return count


def _read_listeners(session: Any, retired: str) -> int:
    try:
        output = session.command("ss -H -lnt")
    except Exception:  # noqa: BLE001 - Session implementations use transport-specific failures.
        raise Refusal("retirement_listener_readback_failed") from None
    if not isinstance(output, bytes) or len(output) > 65_536:
        raise Refusal("retirement_listener_readback_invalid")
    return _listener_count(output, retired)


def _route_facts(value: Any, retired: str) -> int:
    if not isinstance(value, list):
        raise Refusal("retirement_route_readback_invalid")
    count = 0
    for route in value:
        if not isinstance(route, dict):
            raise Refusal("retirement_route_readback_invalid")
        destination = route.get("dst")
        if destination is not None and destination != "default":
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except (ValueError, TypeError):
                raise Refusal("retirement_route_readback_invalid") from None
            if (isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 32
                    and str(network.network_address) == retired):
                count += 1
        for key in ("src", "prefsrc"):
            source = route.get(key)
            if source is not None and _ipv4(source, "retirement_route_readback_invalid") == retired:
                count += 1
    return count


def _rule_facts(value: Any, retired: str) -> int:
    if not isinstance(value, list):
        raise Refusal("retirement_rule_readback_invalid")
    count = 0
    for rule in value:
        if not isinstance(rule, dict):
            raise Refusal("retirement_rule_readback_invalid")
        for key in ("from", "to"):
            selector = rule.get(key)
            if selector in (None, "all"):
                continue
            try:
                network = ipaddress.ip_network(selector, strict=False)
            except (ValueError, TypeError):
                raise Refusal("retirement_rule_readback_invalid") from None
            if (isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 32
                    and str(network.network_address) == retired):
                count += 1
    return count


def verify_retired_address(
    plan: dict[str, Any], peer: Any, appliance: Any, retired_address: str, active_address: str,
) -> dict[str, Any]:
    """Read back address retirement and probe both endpoints from the peer.

    Args:
        plan: Positive task, repository, PR, and source identity.
        peer: Pinned peer exposing ``tcp_reachable(address, port)``.
        appliance: Pinned appliance session exposing bounded ``command``.
        retired_address: IPv4 address expected to be retired.
        active_address: IPv4 address expected to remain reachable.
    """
    identity = _identity(plan)
    retired = _ipv4(retired_address, "retirement_address_invalid")
    active = _ipv4(active_address, "retirement_address_invalid")
    if retired == active:
        raise Refusal("retirement_addresses_must_differ")

    addresses = _json_output(appliance, "ip -j -4 addr show", "retirement_address_readback_failed")
    retired_present = _address_facts(addresses, retired)
    listeners = _read_listeners(appliance, retired)
    routes = _json_output(
        appliance, "ip -j -4 route show table all", "retirement_route_readback_failed",
    )
    retired_routes = _route_facts(routes, retired)
    rules = _json_output(appliance, "ip -j -4 rule show", "retirement_rule_readback_failed")
    retired_rules = _rule_facts(rules, retired)
    if retired_present or listeners or retired_routes or retired_rules:
        raise Refusal("retired_address_still_owned")

    try:
        retired_reachable = peer.tcp_reachable(retired, 443)
        active_reachable = peer.tcp_reachable(active, 443)
    except Exception:  # noqa: BLE001 - Peer transport has a stable wrapper but flexible test doubles.
        raise Refusal("retirement_tcp_probe_failed") from None
    if not isinstance(retired_reachable, bool) or not isinstance(active_reachable, bool):
        raise Refusal("retirement_tcp_probe_invalid")
    if retired_reachable:
        raise Refusal("retired_address_still_reachable")
    if not active_reachable:
        raise Refusal("active_address_unreachable")

    return {
        "schema": 1,
        "kind": "certificate-address-retirement",
        **identity,
        "retired_ipv4": retired,
        "active_ipv4": active,
        "retired_address_present": False,
        "retired_listener_count": listeners,
        "retired_route_reference_count": retired_routes,
        "retired_rule_reference_count": retired_rules,
        "peer_retired_tcp_reachable": retired_reachable,
        "peer_active_tcp_reachable": active_reachable,
    }


def verify_peer_isolation(peer: Any) -> dict[str, Any]:
    """Confirm the peer has forwarding disabled and is not a bridge member.

    Args:
        peer: Pinned peer exposing bounded ``command``.
    """
    try:
        ipv4 = peer.command("cat /proc/sys/net/ipv4/ip_forward")
        ipv6 = peer.command("cat /proc/sys/net/ipv6/conf/all/forwarding")
    except Exception:  # noqa: BLE001 - Session implementations use transport-specific failures.
        raise Refusal("peer_forwarding_readback_failed") from None
    if not isinstance(ipv4, bytes) or not isinstance(ipv6, bytes) or len(ipv4) > 16 or len(ipv6) > 16:
        raise Refusal("peer_forwarding_readback_invalid")
    if ipv4.strip() != b"0" or ipv6.strip() != b"0":
        raise Refusal("peer_forwarding_enabled")
    links = _json_output(peer, "ip -j link show", "peer_link_readback_failed")
    if not isinstance(links, list) or not links:
        raise Refusal("peer_link_readback_invalid")
    for link in links:
        if not isinstance(link, dict) or not isinstance(link.get("ifname"), str) or not link["ifname"]:
            raise Refusal("peer_link_readback_invalid")
        linkinfo = link.get("linkinfo", {})
        if not isinstance(linkinfo, dict):
            raise Refusal("peer_link_readback_invalid")
        if "master" in link or linkinfo.get("info_kind") == "bridge":
            raise Refusal("peer_bridge_membership_detected")
    return {
        "schema": 1,
        "kind": "certificate-peer-isolation",
        "ipv4_forwarding_enabled": False,
        "ipv6_forwarding_enabled": False,
        "bridge_membership_detected": False,
        "interface_count": len(links),
    }
