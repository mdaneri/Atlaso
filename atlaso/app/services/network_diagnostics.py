"""Run bounded, operator-requested appliance network checks."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address
from threading import BoundedSemaphore
from typing import Literal

from atlaso.app.config import get_settings
from atlaso.monitor_native import ObservationUnavailable, run_native

Check = Literal["ping", "traceroute", "dns"]
Family = Literal["auto", "4", "6"]
Address = IPv4Address | IPv6Address

PING_COUNT = 3
MAX_HOPS = 12
MAX_ANSWERS = 32
MAX_SOURCES = 256
_RUN_SLOTS = BoundedSemaphore(2)
_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
_INTERFACE = re.compile(r"[a-zA-Z0-9_.:-]{1,15}")
_PING_REPLY = re.compile(
    r"^\d+ bytes from ([0-9a-fA-F:.]+): icmp_seq=(\d+)\b.*?\btime([=<])(\d+(?:\.\d+)?) ms",
    re.MULTILINE,
)
_PING_LOSS = re.compile(r"^([0-9]+) packets transmitted, ([0-9]+) received,[^\n]*?([0-9.]+)% packet loss", re.MULTILINE)
_PING_RTT = re.compile(r"^(?:rtt|round-trip) min/avg/max/\w+ = ([0-9.]+)/([0-9.]+)/([0-9.]+)/[0-9.]+ ms", re.MULTILINE)
_TRACE_HOP = re.compile(
    r"^\s*(\d+)\s+(\*|([0-9a-fA-F:.]+)(?:%[a-zA-Z0-9_.:-]{1,15})?\s+"
    r"(\d+(?:\.\d+)?) ms(?:\s+(![A-Z0-9]+))?)\s*$",
)


@dataclass(frozen=True)
class Source:
    """An eligible address assigned to one live local interface."""

    address: str
    interface: str


@dataclass(frozen=True)
class ResultRow:
    """A projected reply, hop, or resolved address."""

    number: int
    address: str = ""
    rtt: str = ""
    status: str = ""


@dataclass(frozen=True)
class Result:
    """The outcome and bounded, display-safe evidence for one check."""

    state: str
    message: str
    target: str = ""
    source: str = ""
    rows: list[ResultRow] = field(default_factory=list)


def _probe_address(value: str) -> Address | None:
    """Accept unicast addresses that can be passed as numeric probe arguments."""
    try:
        address = ip_address(value)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast or value == "255.255.255.255":
        return None
    if isinstance(address, IPv6Address) and (address.scope_id or address.is_link_local or address.ipv4_mapped):
        return None
    return address


def _valid_hostname(value: str) -> bool:
    """Check hostname labels before sending a single query to the system resolver."""
    name = value.removesuffix(".")
    labels = name.split(".")
    return (
        0 < len(name) <= 253
        and all(_LABEL.fullmatch(label) for label in labels)
        and not all(label.isdecimal() for label in labels)
    )


def local_sources() -> list[Source]:
    """Read usable, unambiguous source options from the running kernel."""
    if get_settings().dry_run_system_adapters:
        raise ObservationUnavailable
    code, output = run_native("ip", ["-j", "address", "show", "up"], time.monotonic() + 2)
    if code:
        raise ObservationUnavailable
    links = json.loads(output)
    if not isinstance(links, list):
        raise ObservationUnavailable
    addresses: dict[str, set[str]] = {}
    for link in links:
        if not isinstance(link, dict) or not _INTERFACE.fullmatch(str(link.get("ifname", ""))):
            continue
        interface = link["ifname"]
        entries = link.get("addr_info", [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("tentative") or entry.get("dadfailed"):
                continue
            address = _probe_address(str(entry.get("local", "")))
            if address is not None:
                addresses.setdefault(str(address), set()).add(interface)
    return [
        Source(address, next(iter(interfaces)))
        for address, interfaces in sorted(addresses.items())
        if len(interfaces) == 1
    ]


def _resolve(hostname: str, family: int | None) -> list[Address]:
    """Use the appliance resolver once and keep its numeric results in preference order."""
    code, output = run_native("getent", ["-A", "ahosts", hostname], time.monotonic() + 3)
    if code == 2:
        return []
    if code:
        raise ObservationUnavailable
    answers: dict[Address, None] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[1] != "STREAM":
            continue
        try:
            address = ip_address(fields[0])
        except ValueError:
            continue
        if family is None or address.version == family:
            answers[address] = None
        if len(answers) == MAX_ANSWERS:
            break
    return list(answers)


def _route_source(check: Check, target: Address, source: Address | None) -> str:
    """Find the route and source address for a single numeric destination."""
    query = ["-j", f"-{target.version}", "route", "get", str(target)]
    if source is not None:
        query.extend(("from", str(source)))
    protocol = "udp" if check == "traceroute" else "icmp" if target.version == 4 else "ipv6-icmp"
    query.extend(("ipproto", protocol))
    code, output = run_native("ip", query, time.monotonic() + 2)
    if code:
        if "Network is unreachable" in output or "No route to host" in output:
            return ""
        raise ObservationUnavailable
    routes = json.loads(output)
    if not isinstance(routes, list) or len(routes) != 1 or not isinstance(routes[0], dict):
        raise ObservationUnavailable
    route = routes[0]
    if route.get("type") == "broadcast":
        return ""
    selected = source or _probe_address(str(route.get("prefsrc", "")))
    if selected is None or selected.version != target.version:
        raise ObservationUnavailable
    return str(selected)


def _ping(target: Address, source: str) -> Result:
    """Send three Echo Requests and project replies and aggregate statistics."""
    code, output = run_native(
        "ping", [f"-{target.version}", "-n", "-c", str(PING_COUNT), "-w", "6", "-I", source, str(target)],
        time.monotonic() + 8,
    )
    loss = _PING_LOSS.search(output)
    if code not in (0, 1) or not loss:
        raise ObservationUnavailable
    sent, received, percent = loss.groups()
    rows = [
        ResultRow(int(number), str(address), ("<" if operator == "<" else "") + rtt, "Reply")
        for value, number, operator, rtt in _PING_REPLY.findall(output)[:PING_COUNT]
        if (address := _probe_address(value)) is not None
    ]
    message = f"{received} of {sent} probes replied · {percent}% loss."
    timings = _PING_RTT.search(output)
    if timings:
        minimum, average, maximum = timings.groups()
        message += f" Round-trip min/avg/max: {minimum}/{average}/{maximum} ms."
    return Result("reply" if int(received) else "no_reply", message, str(target), source, rows)


def _traceroute(target: Address, source: str) -> Result:
    """Send one UDP probe per hop and preserve explicit hop timeouts."""
    code, output = run_native(
        "traceroute", [f"-{target.version}", "-n", "-m", str(MAX_HOPS), "-q", "1", "-N", "1", "-w", "1",
                       "-s", source, str(target)],
        time.monotonic() + MAX_HOPS + 3,
    )
    if code:
        raise ObservationUnavailable
    rows: list[ResultRow] = []
    reached = False
    for line in output.splitlines():
        match = _TRACE_HOP.fullmatch(line)
        if not match:
            continue
        hop, probe, address, rtt, error = match.groups()
        if int(hop) != len(rows) + 1 or len(rows) == MAX_HOPS:
            raise ObservationUnavailable
        if probe == "*":
            rows.append(ResultRow(int(hop), status="Timed out"))
            continue
        parsed = ip_address(address)
        reached |= parsed == target and not error
        rows.append(ResultRow(int(hop), str(parsed), rtt, f"ICMP {error}" if error else "Reply"))
    if not rows:
        raise ObservationUnavailable
    if reached:
        return Result("reply", "Destination reached.", str(target), source, rows)
    if any(row.address for row in rows):
        return Result("partial", "Hops replied, but the destination did not respond.", str(target), source, rows)
    return Result("no_reply", "No hops replied within the probe limits.", str(target), source, rows)


def run_check(check: Check, target_value: str, source_value: str, family: Family) -> Result:
    """Validate and run one explicitly requested check without retaining its results."""
    target_value = target_value.strip()
    source_value = source_value.strip()
    target = _probe_address(target_value)
    hostname = _valid_hostname(target_value)
    if check == "dns" and not hostname:
        return Result("invalid_target", "Enter a hostname for DNS lookup.")
    if target is None and not hostname:
        return Result("invalid_target", "Enter a unicast IPv4 address, IPv6 address without a zone, or hostname.")
    source = _probe_address(source_value) if source_value else None
    if source_value and (source is None or check == "dns"):
        return Result("invalid_source", "Select a local source address for Ping or Traceroute.")
    version = None if family == "auto" else int(family)
    if source and version and source.version != version:
        return Result("invalid_source", "The selected source belongs to a different address family.")
    version = version or (source.version if source else None)
    if target and version and target.version != version:
        return Result("invalid_target", "The destination and selected address family must match.")
    if get_settings().dry_run_system_adapters:
        return Result("unavailable", "Network diagnostics are unavailable in dry-run mode.")
    if not _RUN_SLOTS.acquire(blocking=False):
        return Result("busy", "The appliance is running other network checks. Try again shortly.")
    try:
        return _run_check(check, target_value, target, source, version)
    except (ValueError, OSError):
        return Result("unavailable", "The appliance could not complete this diagnostic.")
    finally:
        _RUN_SLOTS.release()


def _run_check(
    check: Check, target_value: str, target: Address | None, source: Address | None, version: int | None,
) -> Result:
    """Verify live source ownership, resolve if necessary, and dispatch a single probe."""
    if source and not any(option.address == str(source) for option in local_sources()):
        return Result("invalid_source", "The selected source is no longer assigned to an eligible local interface.")
    if target is None:
        answers = _resolve(target_value, version)
        if not answers:
            return Result("resolution_failed", "The appliance resolver returned no address in the requested family.")
        if check == "dns":
            rows = [ResultRow(number, str(answer), status=f"IPv{answer.version}") for number, answer in enumerate(answers, 1)]
            return Result("resolved", "Name resolved using the appliance resolver.", rows=rows)
        target = next((answer for answer in answers if _probe_address(str(answer)) is not None), None)
        if target is None:
            return Result("invalid_target", "The hostname resolved without a supported unicast destination.")
    selected = _route_source(check, target, source)
    if not selected:
        return Result("unreachable", "No unicast route is available for this destination and source.", str(target))
    if check == "ping":
        return _ping(target, selected)
    return _traceroute(target, selected)
