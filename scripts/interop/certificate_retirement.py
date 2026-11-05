"""Read-only proof that a retired IPv4 address is absent from an appliance."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import Any

from certificate_peer_transport import PeerTcpProbePending, PeerTransportRefusal


class Refusal(Exception):
    """Fixed, non-secret reason that prevents a retirement claim."""

    def __init__(self, reason: str, *, observations: list[dict[str, Any]] | None = None):
        """Retain only fixed public probe outcomes alongside the refusal.

        Args:
            reason: Fixed refusal identifier.
            observations: Bounded native observer outcomes, without response text.
        """
        super().__init__(reason)
        self.observations = observations or []


_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _identity(plan: Any) -> dict[str, Any]:
    """Validate and return the public task identity used in a retirement result.

    Args:
        plan: Plan mapping carrying the task, repository, PR, and source commit.
    """
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
    """Normalize a usable IPv4 address or raise its caller-selected refusal.

    Args:
        value: Address value read from a plan or native observation.
        reason: Fixed refusal identifier to use when the value is invalid.
    """
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
    """Read and parse one bounded JSON response from a pinned guest session.

    Args:
        session: Pinned session that executes the read-only command.
        command: Fixed command returning a JSON document.
        refusal: Fixed refusal identifier for command transport failure.
    """
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
    """Report whether any native interface owns the retired IPv4 address.

    Args:
        value: Parsed output from the guest's IPv4 address inventory.
        retired: Canonical retired IPv4 address.
    """
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
    """Count listeners bound to a retired IPv4 address.

    Args:
        output: Bounded text output from the native listener inventory.
        retired: Canonical retired IPv4 address.
    """
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
        if "%" in address_text:
            address_text, interface = address_text.split("%", 1)
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface) is None:
                raise Refusal("retirement_listener_readback_invalid")
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
    """Read and count listener bindings through the pinned appliance session.

    Args:
        session: Pinned appliance session exposing bounded guest commands.
        retired: Canonical retired IPv4 address.
    """
    try:
        output = session.command("ss -H -lnt")
    except Exception:  # noqa: BLE001 - Session implementations use transport-specific failures.
        raise Refusal("retirement_listener_readback_failed") from None
    if not isinstance(output, bytes) or len(output) > 65_536:
        raise Refusal("retirement_listener_readback_invalid")
    return _listener_count(output, retired)


def _route_facts(value: Any, retired: str) -> int:
    """Count exact route references to or from a retired IPv4 address.

    Args:
        value: Parsed output from the guest's full IPv4 route table.
        retired: Canonical retired IPv4 address.
    """
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


def _rule_selector_is_retired(rule: dict[str, Any], key: str, retired: str) -> bool:
    """Check whether one native policy-rule selector names the retired address.

    Args:
        rule: Parsed policy rule from the guest's complete IPv4 rule inventory.
        key: Selector field to inspect, either source or destination.
        retired: Canonical retired IPv4 address.
    """
    length_key = f"{key}len"
    if key not in rule:
        if key == "dst" and length_key not in rule:
            return False
        if key == "dst" and type(rule[length_key]) is int and rule[length_key] == 0:
            return False
        raise Refusal("retirement_rule_readback_invalid")

    selector = rule[key]
    if not isinstance(selector, str) or not selector:
        raise Refusal("retirement_rule_readback_invalid")
    if selector == "all":
        if length_key in rule:
            length = rule[length_key]
            if type(length) is not int or length != 0:
                raise Refusal("retirement_rule_readback_invalid")
        return False

    if length_key in rule:
        prefix_length = rule[length_key]
        if type(prefix_length) is not int or not 0 <= prefix_length <= 32:
            raise Refusal("retirement_rule_readback_invalid")
    else:
        prefix_length = 32
    try:
        address = ipaddress.IPv4Address("0.0.0.0" if selector == "0" else selector)
    except ValueError:
        raise Refusal("retirement_rule_readback_invalid") from None
    return prefix_length == 32 and str(address) == retired


def _rule_facts(value: Any, retired: str) -> int:
    """Count policy rules that select the retired IPv4 address.

    Args:
        value: Parsed output from the guest's complete IPv4 rule inventory.
        retired: Canonical retired IPv4 address.
    """
    if not isinstance(value, list):
        raise Refusal("retirement_rule_readback_invalid")
    count = 0
    for rule in value:
        if not isinstance(rule, dict) or "from" in rule or "to" in rule:
            raise Refusal("retirement_rule_readback_invalid")
        count += int(_rule_selector_is_retired(rule, "src", retired))
        count += int(_rule_selector_is_retired(rule, "dst", retired))
    return count


def _retired_native_absence(appliance: Any, retired: str) -> dict[str, Any]:
    """Require fresh native absence before each TCP observation.

    Args:
        appliance: Pinned appliance session exposing bounded read-only commands.
        retired: Exact retired IPv4 address.
    """
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
    return {
        "retired_address_present": False,
        "retired_listener_count": listeners,
        "retired_route_reference_count": retired_routes,
        "retired_rule_reference_count": retired_rules,
    }


def verify_retired_address(
    plan: dict[str, Any], peer: Any, appliance: Any, retired_address: str, active_address: str,
) -> dict[str, Any]:
    """Require native absence and an explicit live-peer TCP nonacceptance.

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
    deadline = time.monotonic() + 30
    observations: list[dict[str, Any]] = []
    for attempt in range(1, 4):
        if deadline - time.monotonic() < 8:
            raise Refusal("retirement_tcp_probe_failed", observations=observations)
        try:
            native = _retired_native_absence(appliance, retired)
        except Refusal as exc:
            exc.observations = observations.copy()
            raise
        if deadline - time.monotonic() < 8:
            raise Refusal("retirement_tcp_probe_failed", observations=observations)
        pending = False
        try:
            retired_reachable = peer.tcp_reachable(retired, 443)
        except PeerTcpProbePending:
            # A channel-open deadline has no TCP outcome. Require positive
            # active-path proof before another read-only native observation.
            retired_reachable = None
            pending = True
        except Exception as exc:  # noqa: BLE001 - Transport-specific errors remain inconclusive.
            category = getattr(exc, "probe_failure", "unclassified") if isinstance(exc, PeerTransportRefusal) else "unclassified"
            if category not in {"administrative_denial", "channel_failure", "ssh_failure", "transport_failure"}:
                category = "unclassified"
            observations.append({"attempt": attempt, "retired_ipv4": retired,
                                 "outcome": "tcp_probe_unproven", "failure_category": category})
            raise Refusal("retirement_tcp_probe_failed", observations=observations) from None
        observation: dict[str, Any] = {
            "attempt": attempt, "retired_ipv4": retired,
            "outcome": "channel_open_pending" if pending else (
                "tcp_acceptance" if retired_reachable is True else (
                    "explicit_tcp_nonacceptance" if retired_reachable is False else "invalid_tcp_result"
                )
            ),
        }
        observations.append(observation)
        if deadline - time.monotonic() < 8:
            raise Refusal("retirement_tcp_probe_failed", observations=observations)
        try:
            active_reachable = peer.tcp_reachable(active, 443)
        except Exception:  # noqa: BLE001 - Unknown active-path outcomes cannot authorize another observation.
            raise Refusal("retirement_tcp_probe_failed", observations=observations) from None
        observation["active_tcp_reachable"] = active_reachable if isinstance(active_reachable, bool) else None
        if not isinstance(active_reachable, bool) or not (pending or isinstance(retired_reachable, bool)):
            raise Refusal("retirement_tcp_probe_invalid", observations=observations)
        if retired_reachable is True:
            raise Refusal("retired_address_still_reachable", observations=observations)
        if not active_reachable:
            raise Refusal("active_address_unreachable", observations=observations)
        if pending:
            continue
        return {
            "schema": 1,
            "kind": "certificate-address-retirement",
            **identity,
            "retired_ipv4": retired,
            "active_ipv4": active,
            **native,
            "peer_retired_tcp_reachable": False,
            "peer_active_tcp_reachable": active_reachable,
            "tcp_observations": observations,
        }
    raise Refusal("retirement_tcp_probe_failed", observations=observations)


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


def verify_peer_tunnel_scope(peer: Any, addresses: list[str]) -> dict[str, Any]:
    """Verify the effective SSH policy before an address-changing Apply.

    Args:
        peer: Pinned peer exposing bounded ``command``.
        addresses: DHCP, static baseline, and candidate appliance addresses.
    """
    normalized = [_ipv4(value, "peer_tunnel_addresses_invalid") for value in addresses]
    if len(normalized) != 3 or len(set(normalized)) != 3:
        raise Refusal("peer_tunnel_addresses_invalid")
    expected = {f"{address}:{port}" for address in normalized for port in (22, 443)}
    # Evaluate Match rules for the actual authenticated user and source too.
    command = ('sudo -n sshd -T -C "user=$(id -un),host=${SSH_CONNECTION%% *},addr=${SSH_CONNECTION%% *}" '
               "| grep -E '^(disableforwarding|allowtcpforwarding|permitopen|gatewayports|allowagentforwarding|x11forwarding) '")
    try:
        output = peer.command(command)
    except Exception:  # noqa: BLE001 - Do not expose remote configuration or transport diagnostics.
        raise Refusal("peer_tunnel_policy_readback_failed") from None
    if not isinstance(output, bytes) or len(output) > 4096:
        raise Refusal("peer_tunnel_policy_invalid")
    try:
        rows = [line.split() for line in output.decode("ascii").splitlines()]
    except UnicodeDecodeError:
        raise Refusal("peer_tunnel_policy_invalid") from None
    settings = {row[0]: row[1:] for row in rows if len(row) >= 2}
    fixed = {"disableforwarding": ["no"], "allowtcpforwarding": ["local"], "gatewayports": ["no"],
             "allowagentforwarding": ["no"], "x11forwarding": ["no"]}
    permitted = settings.get("permitopen", [])
    if (len(rows) != 6 or len(settings) != 6 or any(settings.get(key) != value for key, value in fixed.items())
            or len(permitted) != 6 or set(permitted) != expected):
        raise Refusal("peer_tunnel_policy_invalid")
    return {"kind": "certificate-peer-ssh-scope", "local_forwarding_only": True,
            "permitted_destinations": sorted(expected), "gateway_listeners_enabled": False}
