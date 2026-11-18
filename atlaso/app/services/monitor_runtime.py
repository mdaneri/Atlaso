"""Collect and project read-only runtime observations for the Monitor UI."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv6Address, ip_address, ip_network
from pathlib import Path
from typing import Any

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.monitor_native import (
    MAX_OUTPUT,
    MAX_ROWS,
    SERVICE_UNITS,
    ObservationUnavailable,
    run_native,
)

Row = dict[str, Any]
Section = dict[str, Any]
TABLE_IDS = {"unspec": 0, "default": 253, "main": 254, "local": 255}
ROUTE_TYPES = {
    1: "unicast", 2: "local", 3: "broadcast", 4: "anycast", 5: "multicast",
    6: "blackhole", 7: "unreachable", 8: "prohibit", 9: "throw", 10: "nat", 11: "xresolve",
}
RULE_ACTIONS = {1: "lookup", 2: "goto", 3: "nop", 6: "blackhole", 7: "unreachable", 8: "prohibit"}
PROTOCOL_NAMES = {0: "unspec", 1: "redirect", 2: "kernel", 3: "boot", 4: "static", 9: "ra", 16: "dhcp"}
ADDRESS_ORIGINS = {"DHCPv4", "DHCPv6", "IPv4LL", "NDisc", "static", "IPv6LL"}
NEIGHBOR_STATES = {"NONE", "INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT"}
SERVICE_STATES = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"}
CLOCK_MODES = {"ntp_client", "ntp_server", "vmware_tools", "manual", "unverified"}


def _dict(value: Any) -> Row:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int | None:
    if type(value) is int and 0 <= value < 1 << 64:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        return _int(int(value))
    return None


def _items(value: Any) -> list[Row]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _token(value: Any) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"[\w.:@/+-]{1,80}", value, re.ASCII) else None


def _address(value: Any, family: int | None = None) -> str | None:
    if not isinstance(value, str) or len(value) > 96:
        return None
    try:
        parsed = ip_address(value)
        if isinstance(parsed, IPv6Address) and parsed.scope_id and not _token(parsed.scope_id):
            return None
        return str(parsed) if family is None or family == parsed.version else None
    except ValueError:
        return None


def _prefix(value: Any, family: int) -> str | None:
    if value == "default":
        return "default"
    if not isinstance(value, str):
        return None
    parsed_address = _address(value, family)
    if parsed_address:
        return parsed_address
    try:
        network = ip_network(value, strict=False)
        return str(network) if network.version == family else None
    except ValueError:
        return None


def _table(value: Any) -> int | str | None:
    if isinstance(value, str) and value in TABLE_IDS:
        return TABLE_IDS[value]
    number = _int(value)
    return number if number is not None else _token(value)


def _native_label(value: Any, labels: dict[int, str]) -> str | None:
    number = _int(value)
    if number is not None:
        return labels.get(number, str(number))
    return _token(value)


def _next_hop(row: Row, family: int) -> Row:
    via = _dict(row.get("via"))
    return {
        "gateway": _address(row.get("gateway"), family) or _address(via.get("addr") or via.get("host")),
        "interface": _token(row.get("dev")),
        "weight": _int(row.get("weight")),
    }


def _route(row: Row, family: int) -> Row | None:
    destination = _prefix(row.get("dst"), family) or ("default" if "dst" not in row else None)
    table = _table(row.get("table", 254))
    if not destination or table is None:
        return None
    path = _next_hop(row, family)
    nexthops = row.get("nexthops", [])
    if not isinstance(nexthops, list) or len(nexthops) > MAX_ROWS or any(not isinstance(hop, dict) for hop in nexthops):
        return None
    return {
        "family": family, "table": table, "destination": destination,
        "gateway": path["gateway"], "interface": path["interface"], "metric": _int(row.get("metric")),
        "protocol": _native_label(row.get("protocol"), PROTOCOL_NAMES),
        "type": _native_label(row.get("type", "unicast"), ROUTE_TYPES),
        "preferred_source": _address(row.get("prefsrc"), family),
        "source_prefix": _prefix(row.get("from"), family),
        "nexthop_id": _int(row.get("nhid")), "nexthops": [_next_hop(hop, family) for hop in nexthops],
    }


def _rule_prefix(row: Row, field: str, family: int) -> str:
    value = row.get(field)
    length = _int(row.get(f"{field}len"))
    if value == "0":
        value = "0.0.0.0" if family == 4 else "::"
    if length is not None and isinstance(value, str):
        return _prefix(f"{value}/{length}", family) or "unavailable"
    return _prefix(value, family) or ("all" if value in (None, "all") else "unavailable")


def _rule(row: Row, family: int) -> Row | None:
    priority = _int(row.get("priority", 0))
    if priority is None:
        return None
    table = _table(row.get("table"))
    action = _native_label(row.get("type", row.get("action")), RULE_ACTIONS)
    if action is None and table is not None:
        action = "lookup"
    if action is None:
        action = next((needle for needle in ("goto", "nop", "masquerade") if needle in row), None)
    if action is None and "l3mdev" in row:
        action = "lookup"
    if action is None:
        return None
    selectors: list[str] = []
    if "not" in row:
        selectors.append("not")
    for key in ("tos", "fwmark", "fwmask", "uidrange", "uid_start", "uid_end", "ipproto",
                "sport", "sport_start", "sport_end", "sport_mask", "dport", "dport_start", "dport_end",
                "dport_mask", "l3mdev", "suppress_prefixlen", "suppress_prefixlength", "suppress_ifgroup",
                "tun_id", "goto", "flow_from", "flow_to", "nat_gateway", "masquerade",
                "iif_detached", "oif_detached", "unresolved", "dscp", "dscp_mask", "flowlabel", "flowlabel_mask"):
        value = row.get(key)
        if isinstance(value, dict):
            first = _int(value.get("start"))
            last = _int(value.get("end"))
            value = f"{first}-{last}" if first is not None and last is not None else None
        if key in row and (value is True or value is None):
            selectors.append(key)
        elif (selector := _token(str(value) if value is not None else None)) is not None:
            selectors.append(f"{key} {selector}")
    source = _rule_prefix(row, "src", family)
    destination = _rule_prefix(row, "dst", family)
    if "unavailable" in (source, destination):
        return None
    return {
        "family": family, "priority": priority, "source": source,
        "destination": destination, "ingress": _token(row.get("iif")),
        "egress": _token(row.get("oif")), "table": table, "action": action, "selectors": ", ".join(selectors),
    }


def _neighbor(row: Row, family: int) -> Row | None:
    address = _address(row.get("dst"), family)
    interface = _token(row.get("dev"))
    if not address or not interface:
        return None
    states = row.get("state", [])
    states = states if isinstance(states, list) else [states]
    return {
        "family": family, "address": address, "interface": interface,
        "state": ", ".join(state for state in states if isinstance(state, str) and state in NEIGHBOR_STATES) or "Unknown",
    }


def _section(rows: list[Row], state: str = "ok") -> Section:
    return {"state": state, "rows": rows}


def _ip_arguments(*args: str) -> list[str]:
    return ["ip", "-N", "-j", "-details", *args]


def _json_rows(args: list[str], deadline: float) -> list[Any]:
    code, output = run_native(args, deadline)
    if code:
        raise ObservationUnavailable
    decoded = json.loads(output)
    if not isinstance(decoded, list):
        raise ObservationUnavailable
    return decoded


def _dual_stack(arguments: list[str], project: Callable[[Row, int], Row | None], deadline: float) -> Section:
    rows: list[Row] = []
    complete = 0
    partial = False
    for family in (4, 6):
        try:
            native = _json_rows(_ip_arguments(f"-{family}", *arguments), deadline)
        except ValueError:
            partial = True
            continue
        complete += 1
        partial |= len(native) > MAX_ROWS
        for item in native[:MAX_ROWS]:
            row = project(_dict(item), family) if isinstance(item, dict) else None
            if row is None:
                partial = True
            else:
                rows.append(row)
    if not complete:
        return _section([], "unavailable")
    return _section(rows, "partial" if partial else "ok")


def _helper_object(result: AdapterResult) -> Row:
    if result.returncode or result.dry_run or len(result.stdout) > MAX_OUTPUT:
        return {}
    try:
        return _dict(json.loads(result.stdout))
    except ValueError:
        return {}


def _observed_origins(adapter: SystemAdapter, deadline: float) -> dict[tuple[int, str, str, str], str]:
    remaining = min(deadline - time.monotonic(), 3)
    if remaining <= 0.05:
        return {}
    payload = _helper_object(adapter.read_network_address_status(timeout_seconds=remaining))
    if payload.get("complete") is not True:
        return {}
    origins = {}
    for link in _items(payload.get("links")):
        name, index, mac = _token(link.get("name")), _int(link.get("ifindex")), _token(link.get("mac"))
        if not (name and index and mac):
            continue
        for row in _items(link.get("addresses")):
            origin = "DHCPv4" if row.get("dhcp4_lease") is True else row.get("source")
            address = _address(row.get("address"))
            if address and isinstance(origin, str) and origin in ADDRESS_ORIGINS and row.get("state") == "assigned":
                origins[index, name, mac.lower(), address] = origin
    return origins


def _interfaces(adapter: SystemAdapter, deadline: float) -> Section:
    try:
        native = _json_rows(_ip_arguments("-statistics", "address", "show"), deadline)
    except ValueError:
        return _section([], "unavailable")
    origins = _observed_origins(adapter, deadline)
    names = {_int(row.get("ifindex")): _token(row.get("ifname")) for row in map(_dict, native[:MAX_ROWS])}
    partial = len(native) > MAX_ROWS
    rows = []
    for link in map(_dict, native[:MAX_ROWS]):
        name = _token(link.get("ifname"))
        index = _int(link.get("ifindex"))
        if not name or index is None:
            partial = True
            continue
        if name == "lo":
            continue
        mac = _token(link.get("address")) or ""
        addresses = []
        raw_addresses = link.get("addr_info", [])
        if not isinstance(raw_addresses, list):
            raw_addresses = []
            partial = True
        partial |= len(raw_addresses) > MAX_ROWS
        for row in map(_dict, raw_addresses[:MAX_ROWS]):
            address = _address(row.get("local"))
            prefix = _int(row.get("prefixlen"))
            if address is None or prefix is None or prefix > ip_address(address).max_prefixlen:
                partial = True
                continue
            origin = origins.get((index, name, mac.lower(), address))
            if origin is None and ip_address(address).is_link_local:
                origin = "Link-local"
            addresses.append({"address": address, "prefix": prefix, "origin": origin})
        link_info = _dict(link.get("linkinfo"))
        vlan = link_info.get("info_kind") == "vlan"
        flags = link.get("flags")
        stats = _dict(link.get("stats64") or link.get("stats"))
        rows.append({
            "interface": name, "carrier": ("LOWER_UP" in flags if isinstance(flags, list) else None),
            "parent": (_token(link.get("link")) or names.get(_int(link.get("link_index")))) if vlan else None,
            "vlan": _int(_dict(link_info.get("info_data")).get("id")) if vlan else None,
            "addresses": addresses, "mtu": _int(link.get("mtu")),
            "rx_errors": _int(_dict(stats.get("rx")).get("errors")),
            "tx_errors": _int(_dict(stats.get("tx")).get("errors")),
        })
    return _section(rows, "partial" if partial else "ok")


def _forwarding() -> Section:
    rows: list[Row] = []
    for family, filename in ((4, "ipv4/ip_forward"), (6, "ipv6/conf/all/forwarding")):
        try:
            value = (Path("/proc/sys/net") / filename).read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            value = ""
        rows.append({"family": family, "enabled": value == "1" if value in {"0", "1"} else None})
    missing = sum(row["enabled"] is None for row in rows)
    return _section(rows, ("ok", "partial", "unavailable")[missing])


def _gateway_neighbors(routes: Section, deadline: float) -> Section:
    if routes["state"] == "unavailable":
        return _section([], "unavailable")
    gateways = set()
    for route in routes["rows"]:
        for hop in (route, *route["nexthops"]):
            if hop["gateway"] and hop["interface"]:
                family = ip_address(hop["gateway"]).version
                gateways.add((family, hop["gateway"], hop["interface"]))
    if not gateways:
        return _section([], routes["state"])
    neighbors = _dual_stack(["neigh", "show"], _neighbor, deadline)
    if neighbors["state"] == "unavailable":
        return neighbors
    observed = {(row["family"], row["address"], row["interface"]): row["state"] for row in neighbors["rows"]}
    rows = [
        {"family": family, "address": address, "interface": interface,
         "state": observed.get((family, address, interface),
                               "No entry observed" if neighbors["state"] == "ok" else "Unavailable")}
        for family, address, interface in sorted(gateways)
    ]
    return _section(rows, "partial" if routes["state"] == "partial" else neighbors["state"])


def collect_network(*, include_neighbors: bool = True) -> dict[str, Any]:
    """Read kernel network state without invoking any configuration handlers."""
    captured_at = datetime.now(UTC).isoformat()
    adapter = SystemAdapter()
    if adapter.dry_run:
        keys = ["routes", "rules", "interfaces", "forwarding"]
        if include_neighbors:
            keys.append("neighbors")
        return {"captured_at": captured_at, "sections": {key: _section([], "unavailable") for key in keys}}
    deadline = time.monotonic() + 8
    routes = _dual_stack(["route", "show", "table", "all"], _route, deadline)
    rules = _dual_stack(["rule", "show"], _rule, deadline)
    rules["rows"].sort(key=lambda row: (row["family"], row["priority"]))
    sections = {"routes": routes, "rules": rules, "forwarding": _forwarding()}
    if include_neighbors:
        sections["neighbors"] = _gateway_neighbors(routes, deadline)
    sections["interfaces"] = _interfaces(adapter, deadline)
    return {"captured_at": captured_at, "sections": sections}


def route_lookup(destination: str, source: str, ingress: str) -> Section:
    """Run a single validated kernel route lookup without sending traffic."""
    if "%" in destination or "%" in source:
        raise ValueError("Use numeric addresses without zone suffixes.")
    target = _address(destination)
    if not target:
        raise ValueError("Enter an IPv4 or IPv6 destination address.")
    family = ip_address(target).version
    origin = _address(source, family) if source else None
    if source and origin is None:
        raise ValueError("Use a source address in the destination's address family.")
    if ingress and not re.fullmatch(r"[0-9A-Za-z_.:-]{1,15}", ingress):
        raise ValueError("Select a valid ingress interface.")
    if SystemAdapter().dry_run:
        return _section([], "unavailable")
    deadline = time.monotonic() + 3
    arguments = _ip_arguments(f"-{family}", "route", "get", "fibmatch", target)
    if origin:
        arguments.extend(("from", origin))
    if ingress:
        arguments.extend(("iif", ingress))
    try:
        code, output = run_native(arguments, deadline)
        if code:
            if "Network is unreachable" in output or "No route to host" in output:
                return _section([], "unreachable")
            return _section([], "unavailable")
        native = json.loads(output)
    except ValueError:
        return _section([], "unavailable")
    if not isinstance(native, list) or not 0 < len(native) <= MAX_ROWS:
        return _section([], "unavailable")
    routes = [route for row in native if isinstance(row, dict) and (route := _route(row, family)) is not None]
    if not routes or len(routes) != len(native):
        return _section([], "unavailable")
    return _section(routes)


def _service_properties() -> dict[str, dict[str, str]]:
    props = "Id,LoadState,ActiveState,ActiveEnterTimestampMonotonic,NRestarts"
    try:
        code, output = run_native(
            ["systemctl", "show", "--no-pager", f"--property={props}", *SERVICE_UNITS],
            time.monotonic() + 3,
        )
    except ObservationUnavailable:
        return {}
    if code not in {0, 1}:
        return {}
    records = {}
    for block in output.strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if fields.get("Id") in SERVICE_UNITS:
            records[fields["Id"]] = fields
    return records


def _services(adapter: SystemAdapter) -> Section:
    properties = _service_properties()
    if not properties:
        return _section([], "unavailable")
    native = _helper_object(adapter.read_monitor_listeners())
    listeners: dict[str, list[Row]] = {}
    listener_state = native.get("state")
    for row in _items(native.get("rows")):
        unit, protocol = row.get("unit"), row.get("protocol")
        address, port = _address(row.get("address")), _int(row.get("port"))
        if isinstance(unit, str) and unit in SERVICE_UNITS and protocol in ("tcp", "udp") and address and port:
            listeners.setdefault(unit, []).append({"protocol": protocol, "address": address, "port": port})
    rows = []
    for unit, (name, url) in SERVICE_UNITS.items():
        props = properties.get(unit, {})
        state = props.get("ActiveState")
        started = _int(props.get("ActiveEnterTimestampMonotonic"))
        status = state if state in SERVICE_STATES else "unavailable"
        rows.append({
            "name": name, "unit": unit, "state": "not installed" if props.get("LoadState") == "not-found" else status,
            "uptime_seconds": max(0, int(time.monotonic() - started / 1_000_000)) if started and state == "active" else None,
            "restarts": _int(props.get("NRestarts")), "url": url,
            "listeners": listeners.get(unit, [] if listener_state == "ok" else None),
        })
    return _section(rows, "ok" if listener_state == "ok" and len(properties) == len(SERVICE_UNITS) else "partial")


def _clock(adapter: SystemAdapter) -> Section:
    payload = _helper_object(adapter.read_ntpd_status())
    if not payload:
        return _section([], "unavailable")
    mode = payload.get("mode")
    observed = _dict(payload.get("synchronization")).get("state")
    transaction = _dict(payload.get("transaction"))
    pending = transaction.get("pending") is True
    source = mode if isinstance(mode, str) and mode in CLOCK_MODES else None
    synchronization = observed if observed in ("synchronized", "unsynchronized") else "unavailable"
    if pending or source == "unverified":
        synchronization = "unverified"
    return _section([{"source": source, "synchronization": synchronization, "pending": pending}],
                    "ok" if source and synchronization != "unavailable" else "partial")


def collect_services() -> dict[str, Any]:
    """Read the packaged services and managed clock authority."""
    captured_at = datetime.now(UTC).isoformat()
    adapter = SystemAdapter()
    sections = ({"services": _section([], "unavailable"), "clock": _section([], "unavailable")}
                if adapter.dry_run else {"services": _services(adapter), "clock": _clock(adapter)})
    return {"captured_at": captured_at, "sections": sections}
