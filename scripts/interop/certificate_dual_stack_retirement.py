"""Pure complete-inventory consistency checks, never native retirement acceptance.

Only the explicitly supported iproute2 JSON forms are interpreted. Unknown or
indirect state refuses; a zero count does not authenticate a producer, establish
handoff-route ownership, prove peer TCP nonacceptance or enforce LAN membership.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

from scripts.interop.certificate_dual_stack_channel import validate_public_payload
from scripts.interop.certificate_dual_stack_contract import plan_tls_numeric_endpoint
from scripts.interop.certificate_dual_stack_guest import GuestRefusal, public_bytes
from scripts.interop.certificate_dual_stack_inventory import (
    address_inventory,
    listener_inventory,
)

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
MAX_ROWS = 8192
LINK_KEYS = frozenset({"ifindex", "ifname", "address", "broadcast", "flags", "mtu", "qdisc",
                       "operstate", "linkmode", "group", "txqlen", "link_type", "altnames", "master", "link_index"})
LINK_FLAGS = frozenset({"LOOPBACK", "BROADCAST", "MULTICAST", "UP", "LOWER_UP", "DORMANT", "POINTOPOINT",
                        "NOARP", "PROMISC", "ALLMULTI", "MASTER", "SLAVE", "RUNNING", "ECHO", "DEBUG",
                        "NOTRAILERS", "PORTSEL", "AUTOMEDIA", "DYNAMIC"})
ADDRESS_FLAGS = frozenset({"permanent", "secondary", "dynamic", "temporary", "tentative", "dadfailed",
                           "deprecated", "noprefixroute", "mngtmpaddr", "stable-privacy", "optimistic",
                           "home", "nodad", "autojoin"})
ADDRESS_KEYS = ADDRESS_FLAGS | {"family", "local", "prefixlen", "scope", "label", "broadcast", "flags",
                                "valid_life_time", "preferred_life_time"}
ROUTE_KEYS = frozenset({"dst", "from", "src", "prefsrc", "gateway", "via", "dev", "table", "protocol",
                        "scope", "type", "metric", "flags", "pref", "tos", "nexthops"})
HOP_KEYS = frozenset({"gateway", "via", "dev", "weight", "flags"})
RULE_KEYS = frozenset({"priority", "src", "srclen", "dst", "dstlen", "table", "protocol", "iif", "oif",
                       "action", "fwmark", "fwmask", "suppress_prefixlength", "suppress_ifgroup"})
ROUTE_FLAGS = frozenset({"onlink", "pervasive", "linkdown", "dead", "offload", "trap", "notify"})


def _uint(value: Any, maximum: int = 4_294_967_295) -> bool:
    """Require an exact bounded unsigned JSON integer, excluding boolean aliases.

    Args:
        value: Public primitive to inspect.
        maximum: Explicit maximum for its native field.
    """
    return type(value) is int and 0 <= value <= maximum


def _shape(value: Any, allowed: set[str] | frozenset[str], required: set[str], reason: str) -> None:
    """Refuse unknown or missing semantics before interpreting any supported row.

    Args:
        value: Complete public JSON row.
        allowed: Supported exact field names.
        required: Members always emitted by the supported form.
        reason: Fixed non-secret refusal.
    """
    if not isinstance(value, dict) or not required <= value.keys() <= allowed:
        raise GuestRefusal(reason)


def _host(value: Any, family: int) -> Address:
    """Read one numeric unscoped host without hostname or prefix coercion.

    Args:
        value: Public numeric field.
        family: Producer-declared numeric family.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or "%" in value or "/" in value:
        raise GuestRefusal("retirement_numeric_field_invalid")
    try:
        result = ipaddress.ip_address(value)
    except ValueError:
        raise GuestRefusal("retirement_numeric_field_invalid") from None
    if result.version != family:
        raise GuestRefusal("retirement_numeric_family_changed")
    return result


def _prefix(value: Any, family: int) -> Network | None:
    """Parse canonical native host/prefix forms without treating coverage as ownership.

    Args:
        value: Numeric route destination/source or explicit default.
        family: Route inventory family.
    """
    if value == "default":
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 80 or "%" in value:
        raise GuestRefusal("retirement_prefix_invalid")
    if value.startswith("0/"):
        value = ("0.0.0.0" if family == 4 else "::") + value[1:]
    try:
        result = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise GuestRefusal("retirement_prefix_invalid") from None
    if result.version != family:
        raise GuestRefusal("retirement_numeric_family_changed")
    return result


def _matches(value: Address, target: Address) -> bool:
    """Keep mapped IPv4 references visible in an IPv6 producer.

    Args:
        value: Parsed address from any complete producer.
        target: Explicit retired numeric host.
    """
    return value == target or isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped == target


def _prefix_reference(value: Network | None, target: Address) -> int:
    """Count only exact host references, never generic default/subnet coverage.

    Args:
        value: Parsed native selector or default.
        target: Retired numeric host.
    """
    return int(value is not None and value.prefixlen == value.max_prefixlen and _matches(value.network_address, target))


def _metadata(row: dict[str, Any], family: int) -> None:
    """Validate supported routing metadata without inventing missing table defaults.

    Args:
        row: Already shape-checked route, nexthop or rule.
        family: Exact native producer family.
    """
    for key in ("dev", "iif", "oif"):
        if key in row and (not isinstance(row[key], str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", row[key]) is None):
            raise GuestRefusal("retirement_metadata_invalid")
    for key in ("table", "protocol", "scope"):
        if key in row and not (_uint(row[key]) or isinstance(row[key], str)
                               and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", row[key]) is not None):
            raise GuestRefusal("retirement_metadata_invalid")
    for key in ("metric", "priority", "suppress_ifgroup"):
        if key in row and not _uint(row[key]):
            raise GuestRefusal("retirement_metadata_invalid")
    if "weight" in row and (not _uint(row["weight"], 256) or row["weight"] < 1):
        raise GuestRefusal("retirement_metadata_invalid")
    if "suppress_prefixlength" in row and not _uint(row["suppress_prefixlength"], 32 if family == 4 else 128):
        raise GuestRefusal("retirement_metadata_invalid")
    for key in ("fwmark", "fwmask", "tos"):
        if key in row and not (_uint(row[key], 255 if key == "tos" else 4_294_967_295)
                               or isinstance(row[key], str) and re.fullmatch(r"0x[0-9a-fA-F]{1,8}", row[key]) is not None
                               and _uint(int(row[key], 16), 255 if key == "tos" else 4_294_967_295)):
            raise GuestRefusal("retirement_metadata_invalid")
    if "flags" in row and (not isinstance(row["flags"], list)
                           or any(not isinstance(flag, str) or flag not in ROUTE_FLAGS for flag in row["flags"])):
        raise GuestRefusal("retirement_metadata_invalid")
    if "pref" in row and row["pref"] not in ("low", "medium", "high"):
        raise GuestRefusal("retirement_metadata_invalid")
    if "type" in row and row["type"] not in ("unicast", "local", "broadcast", "multicast", "anycast",
                                             "throw", "unreachable", "prohibit", "blackhole"):
        raise GuestRefusal("retirement_metadata_invalid")
    if "action" in row and row["action"] not in ("lookup", "unreachable", "prohibit", "blackhole"):
        raise GuestRefusal("retirement_metadata_invalid")


def _hop(row: dict[str, Any], family: int, target: Address) -> int:
    """Inspect every explicit gateway, including typed cross-family via objects.

    Args:
        row: Supported route or nexthop row.
        family: Route producer family.
        target: Retired host to count.
    """
    count = int("gateway" in row and _matches(_host(row["gateway"], family), target))
    if "via" in row:
        via = row["via"]
        _shape(via, {"family", "host"}, {"family", "host"}, "retirement_via_invalid")
        if not isinstance(via["family"], str) or via["family"] not in {"inet", "inet6"}:
            raise GuestRefusal("retirement_via_invalid")
        count += int(_matches(_host(via["host"], 4 if via["family"] == "inet" else 6), target))
    return count


def _route(row: dict[str, Any], family: int, target: Address) -> tuple[int, int]:
    """Inspect one all-table route and every bounded nested nexthop without filtering.

    Args:
        row: Complete native route dictionary.
        family: Producer-declared family.
        target: Exact retired host.
    """
    _shape(row, ROUTE_KEYS, {"dst"}, "retirement_route_unsupported")
    _metadata(row, family)
    if "src" in row and "from" in row:
        raise GuestRefusal("retirement_route_unsupported")
    count = _prefix_reference(_prefix(row["dst"], family), target) + _hop(row, family, target)
    for key in ("src", "from"):
        if key in row:
            count += _prefix_reference(_prefix(row[key], family), target)
    if "prefsrc" in row:
        count += int(_matches(_host(row["prefsrc"], family), target))
    hops = row.get("nexthops", [])
    if "nexthops" in row and (not isinstance(hops, list) or not 1 <= len(hops) <= 256):
        raise GuestRefusal("retirement_nexthops_invalid")
    for hop in hops:
        _shape(hop, HOP_KEYS, {"dev"}, "retirement_nexthops_invalid")
        _metadata(hop, family)
        count += _hop(hop, family, target)
    return count, len(hops)


def _rule_selector(row: dict[str, Any], key: str, family: int) -> Network | None:
    """Interpret native numeric rule fields with independent exact typed lengths.

    Args:
        row: Shape-checked complete policy-rule row.
        key: Source or destination selector.
        family: Producer-declared family.
    """
    length_key = key + "len"
    maximum = 32 if family == 4 else 128
    length = row.get(length_key)
    if length_key in row and not _uint(length, maximum):
        raise GuestRefusal("retirement_rule_selector_invalid")
    if key not in row:
        if key != "dst" or length_key in row and length != 0:
            raise GuestRefusal("retirement_rule_selector_invalid")
        return None
    if row[key] == "all":
        if length_key in row and length != 0:
            raise GuestRefusal("retirement_rule_selector_invalid")
        return None
    value = row[key]
    if value == "0":
        value = "0.0.0.0" if family == 4 else "::"
    numeric = _host(value, family)
    prefix = maximum if length_key not in row else length
    return _prefix(f"{numeric}/{prefix}", family)


def _rule(row: dict[str, Any], family: int, target: Address) -> int:
    """Inspect supported complete rule selectors without interpreting broad coverage as ownership.

    Args:
        row: Native rule dictionary, with no from/to or inverted aliases.
        family: Producer-declared family.
        target: Exact retired host.
    """
    _shape(row, RULE_KEYS, {"priority", "src"}, "retirement_rule_unsupported")
    _metadata(row, family)
    return sum(_prefix_reference(_rule_selector(row, key, family), target) for key in ("src", "dst"))


def _address_rows(payload: dict[str, Any], target: Address) -> int:
    """Refuse unsupported link/address metadata so hidden peers cannot become absence.

    Args:
        payload: Already complete native inventory payload.
        target: Retired numeric host, also compared with numeric broadcast fields.
    """
    count = 0
    for name in ("links", "addresses"):
        for row in payload["observations"][name]["raw"]:
            _shape(row, LINK_KEYS | ({"addr_info"} if name == "addresses" else set()),
                   {"ifindex", "ifname", "address"}, "retirement_address_state_unsupported")
            for key in ("address", "broadcast"):
                if key in row and (not isinstance(row[key], str)
                                   or re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", row[key]) is None):
                    raise GuestRefusal("retirement_address_metadata_invalid")
            for key in ("mtu", "txqlen", "link_index"):
                if key in row and not _uint(row[key]):
                    raise GuestRefusal("retirement_address_metadata_invalid")
            for key in ("qdisc", "operstate", "linkmode", "group", "link_type", "master"):
                if key in row and (not isinstance(row[key], str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", row[key]) is None):
                    raise GuestRefusal("retirement_address_metadata_invalid")
            if "flags" in row and (not isinstance(row["flags"], list)
                                   or any(not isinstance(flag, str) or flag not in LINK_FLAGS for flag in row["flags"])):
                raise GuestRefusal("retirement_address_metadata_invalid")
            if "altnames" in row and (not isinstance(row["altnames"], list) or len(row["altnames"]) > 64
                                      or any(not isinstance(v, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", v) is None for v in row["altnames"])):
                raise GuestRefusal("retirement_address_metadata_invalid")
            if name == "addresses":
                for info in row["addr_info"]:
                    _shape(info, ADDRESS_KEYS, {"family", "local", "prefixlen"}, "retirement_address_state_unsupported")
                    for key in ADDRESS_FLAGS:
                        if key in info and type(info[key]) is not bool:
                            raise GuestRefusal("retirement_address_metadata_invalid")
                    if "flags" in info and (not isinstance(info["flags"], list) or any(
                            not isinstance(flag, str) or flag not in ADDRESS_FLAGS for flag in info["flags"])):
                        raise GuestRefusal("retirement_address_metadata_invalid")
                    for key in ("valid_life_time", "preferred_life_time"):
                        if key in info and not (_uint(info[key]) or info[key] == "forever"):
                            raise GuestRefusal("retirement_address_metadata_invalid")
                    for key in ("scope", "label"):
                        if key in info and (not isinstance(info[key], str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", info[key]) is None):
                            raise GuestRefusal("retirement_address_metadata_invalid")
                    if "broadcast" in info:
                        if info["family"] != "inet":
                            raise GuestRefusal("retirement_address_metadata_invalid")
                        count += int(_matches(_host(info["broadcast"], 4), target))
    return count


def retirement_consistency(
    payload: dict[str, Any], *, boot_id: str, family: int, address: str, port: int,
) -> dict[str, Any]:
    """Require supported complete inventories with no exact retired-host references.

    The digest covers canonical public_bytes(payload), not original producer bytes.
    Broad routes/rules covering the target are not proof of ownership or retirement.
    Keep original bytes and independently admit owned handoff-route absence, native
    producers, terminal Apply and positive peer path/TCP nonacceptance separately.

    Args:
        payload: Complete retained seven-producer observation, never mutated here.
        boot_id: Independently retained original guest boot identity.
        family: Exact numeric retired-host family, four or six.
        address: Usable unscoped numeric host from the admitted test plan.
        port: Explicit management TCP port; wildcard listeners remain unknown.
    """
    endpoint = plan_tls_numeric_endpoint(address, family=family, port=port)
    target = ipaddress.ip_address(endpoint.address)
    validate_public_payload(payload)
    if payload["kind"] != "dual-stack-native-raw-observation":
        raise GuestRefusal("complete_native_inventory_required")
    digest = hashlib.sha256(public_bytes(payload)).hexdigest()
    for name in ("links", "addresses", "routes4", "routes6", "rules4", "rules6", "listeners"):
        raw = payload["observations"][name]["raw"]
        if not isinstance(raw, list) or len(raw) > MAX_ROWS:
            raise GuestRefusal("complete_native_inventory_required")
    addresses = address_inventory(payload, boot_id=boot_id)
    references = sum(_matches(_host(row["address"], row["family"]), target) for row in addresses)
    references += _address_rows(payload, target)
    hop_count = 0
    for current in (4, 6):
        for row in payload["observations"][f"routes{current}"]["raw"]:
            count, hops = _route(row, current, target)
            references += count
            hop_count += hops
        for row in payload["observations"][f"rules{current}"]["raw"]:
            references += _rule(row, current, target)
    listeners = listener_inventory(payload)
    for listener in listeners:
        if listener.port == port:
            if listener.wildcard:
                raise GuestRefusal("retirement_listener_scope_unknown")
            references += int(listener.address is not None and _matches(ipaddress.ip_address(listener.address), target))
    if references:
        raise GuestRefusal("retired_address_still_referenced")
    return {
        "consistency_only": True, "test_only": True, "formal_acceptance": False, "native_acceptance": False,
        "exact_address_references_absent": True, "family": family, "address": endpoint.address, "port": port,
        "boot_id": boot_id, "monotonic_ns": payload["monotonic_ns"], "payload_sha256": digest,
        "inventory_rows": {name: len(row["raw"]) for name, row in payload["observations"].items()},
        "nexthop_rows": hop_count, "requires_authenticated_producer": True,
        "requires_owned_handoff_route_admission": True, "requires_positive_path_and_tcp_nonacceptance": True,
    }
