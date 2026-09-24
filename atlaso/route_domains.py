"""Maintain local-source routing rules from applied, identity-bound network intent.

Routes remain owned by networkd and WAN Apply. This service only owns canonical
protocol-2 source pairs in priorities 5000--5999 and terminal/exemption rules
in 6000--6004. The kernel
protocol deliberately exempts these rules from systemd-networkd v257's foreign
rule cleanup without changing its global policy. It does not confer ownership
of kernel rules outside these slots. The service never consumes desired state.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib
import ipaddress
import json
import os
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INTENT_PATH = Path("/etc/atlaso/route-domains.json")
LOCK_PATH = Path("/run/atlaso-route-domains.lock")
IP_COMMAND = "/usr/sbin/ip"
PROTOCOL = 2
PRIORITY_START = 5000
PRIORITY_END = 6000
TRANSITION_PRIORITY = 6004
TRANSITION_EXEMPTIONS = {
    4: ("0.0.0.0/32", "169.254.0.0/16", "127.0.0.0/8"),
    6: ("::/128", "fe80::/10", "::1/128"),
}
TRANSITION_DESTINATION_EXEMPTIONS = {4: "169.254.0.0/16", 6: "fe80::/10"}
MAX_HELD_ADDRESSES = PRIORITY_END - PRIORITY_START
MAX_JSON_BYTES = 2_000_000
RESCAN_SECONDS = 10.0
LOCK_SECONDS = 30.0
INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
MAC_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")


class ReconcileError(RuntimeError):
    """A bounded, sanitized refusal to change unproven routing state."""


def linux_attribute(owner: Any, name: str) -> Any:
    """Require Linux primitives while allowing pure planner tests on Windows.

    Args:
        owner: Module or object exposing the required Linux primitive.
        name: Exact native attribute or interface name.
    """
    try:
        return getattr(owner, name)
    except AttributeError as exc:
        raise ReconcileError("required Linux routing primitive unavailable") from exc


@dataclass(frozen=True)
class Interface:
    """Applied ownership of one physical or VLAN interface."""

    name: str
    mac: str
    table: int
    management_ui: bool | None = None


@dataclass(frozen=True)
class HeldAddress:
    """Old source ownership retained by a protected management handoff."""

    interface: Interface
    address: str


@dataclass(frozen=True)
class Intent:
    """Validated immutable applied routing-domain intent."""

    interfaces: tuple[Interface, ...]
    held_addresses: tuple[HeldAddress, ...] = ()


@dataclass(frozen=True)
class Rule:
    """One exactly owned source lookup or adjacent unreachable guard."""

    priority: int
    source: str
    table: int | None

    @property
    def family(self) -> int:
        """Return the IP version of this exact source."""
        return ipaddress.ip_address(self.source).version

    @property
    def slot(self) -> int:
        """Return the even priority shared by the source's rule pair."""
        return self.priority - self.priority % 2


def usable_address(value: Any) -> str:
    """Validate a unicast host address, including private and deprecated IPs.

    Args:
        value: Untrusted value being validated.
    """
    if not isinstance(value, str) or "%" in value:
        raise ReconcileError("invalid source address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ReconcileError("invalid source address") from exc
    if address.is_unspecified or address.is_multicast or address.is_link_local or address.is_loopback:
        raise ReconcileError("unusable source address")
    return str(address)


def parse_interface(row: Any) -> Interface:
    """Require a safe exact interface name, unicast MAC, and known table.

    Args:
        row: Interface ownership record.
    """
    if not isinstance(row, dict) or set(row) not in ({"name", "mac", "table"}, {"name", "mac", "table", "management_ui"}):
        raise ReconcileError("invalid interface intent")
    name, mac, table = row["name"], row["mac"], row["table"]
    if not isinstance(name, str) or not INTERFACE_PATTERN.fullmatch(name) or name in {".", "..", "lo"}:
        raise ReconcileError("invalid interface name")
    if not isinstance(mac, str):
        raise ReconcileError("invalid interface identity")
    mac = mac.lower()
    if not MAC_PATTERN.fullmatch(mac) or mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
        raise ReconcileError("invalid interface identity")
    if type(table) is not int or table not in {100, 200}:
        raise ReconcileError("invalid routing table")
    if "management_ui" in row and type(row["management_ui"]) is not bool:
        raise ReconcileError("invalid applied management UI eligibility")
    return Interface(name, mac, table, row.get("management_ui"))


def parse_intent(value: Any) -> Intent:
    """Validate schema-1 applied intent and optional handoff ownership holds.

    Args:
        value: Untrusted value being validated.
    """
    if not isinstance(value, dict) or set(value) - {"schema", "interfaces", "held_addresses"}:
        raise ReconcileError("invalid routing-domain intent")
    if type(value.get("schema")) is not int or value["schema"] != 1:
        raise ReconcileError("unsupported routing-domain schema")
    rows, holds = value.get("interfaces"), value.get("held_addresses", [])
    if (not isinstance(rows, list) or len(rows) > 256 or not isinstance(holds, list)
            or len(holds) > MAX_HELD_ADDRESSES):
        raise ReconcileError("invalid routing-domain inventory")
    interfaces = tuple(parse_interface(row) for row in rows)
    if len({row.name for row in interfaces}) != len(interfaces):
        raise ReconcileError("duplicate interface intent")
    held_addresses = []
    for row in holds:
        if not isinstance(row, dict) or set(row) != {"name", "mac", "address", "table"}:
            raise ReconcileError("invalid held address")
        interface = parse_interface({key: row[key] for key in ("name", "mac", "table")})
        held_addresses.append(HeldAddress(interface, usable_address(row["address"])))
    if len({(row.interface.name, row.address) for row in held_addresses}) != len(held_addresses):
        raise ReconcileError("duplicate held address")
    return Intent(interfaces, tuple(held_addresses))


def read_intent() -> Intent:
    """Read one atomic root-owned intent file without following symlinks."""
    try:
        descriptor = os.open(INTENT_PATH, os.O_RDONLY | linux_attribute(os, "O_NOFOLLOW"))
    except FileNotFoundError:
        return Intent(())
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or metadata.st_mode & 0o022:
            raise ReconcileError("unsafe routing-domain intent ownership")
        data = handle.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ReconcileError("routing-domain intent is oversized")
    try:
        return parse_intent(json.loads(data))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReconcileError("invalid routing-domain JSON") from exc


def source_tables(intent: Intent, inventory: Any) -> tuple[dict[str, int | None], bool]:
    """Resolve assigned sources; ambiguous cross-domain addresses get guards only.

    Args:
        intent: Validated applied routing ownership and handoff holds.
        inventory: Native link and assigned-address inventory.
    """
    if not isinstance(inventory, list) or len(inventory) > 4096:
        raise ReconcileError("invalid native address inventory")
    links: dict[str, dict[str, Any]] = {}
    for link in inventory:
        if not isinstance(link, dict) or not isinstance(link.get("ifname"), str):
            raise ReconcileError("invalid native link inventory")
        if link["ifname"] in links:
            raise ReconcileError("ambiguous native link inventory")
        links[link["ifname"]] = link
    holds = {(row.interface.name, row.address): row for row in intent.held_addresses}
    owners = {(row.name, row.mac): row for row in intent.interfaces}
    for row in intent.held_addresses:
        owners.setdefault((row.interface.name, row.interface.mac), row.interface)
    sources: dict[str, set[int]] = {}
    incomplete = False
    for interface in owners.values():
        link = links.get(interface.name)
        if link is None or str(link.get("address", "")).lower() != interface.mac:
            incomplete = True
            continue
        entries = link.get("addr_info")
        if not isinstance(entries, list) or len(entries) > 4096:
            raise ReconcileError("invalid native addresses")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ReconcileError("invalid native address")
            flags = entry.get("flags", [])
            if not isinstance(flags, list):
                raise ReconcileError("invalid native address flags")
            if any(entry.get(flag) or flag in flags for flag in ("tentative", "dadfailed")):
                continue
            if entry.get("valid_life_time") == 0:
                continue
            try:
                source = usable_address(entry.get("local"))
            except ReconcileError:
                continue
            hold = holds.get((interface.name, source))
            if hold is not None and hold.interface.mac == interface.mac:
                table = hold.interface.table
            elif interface not in intent.interfaces:
                continue
            else:
                table = interface.table
            sources.setdefault(source, set()).add(table)
    return {source: next(iter(tables)) if len(tables) == 1 else None for source, tables in sources.items()}, incomplete


def removed_interface_holds(intent: Intent, inventory: Any, names: set[str]) -> list[dict[str, str | int]]:
    """Retain proven old sources while a deferred VLAN link is still present.

    Args:
        intent: Applied routing-domain interface intent.
        inventory: Observed native interface and address inventory.
        names: Interface names selected for inspection.
    """
    if len(names) > 256 or any(not isinstance(name, str) or not INTERFACE_PATTERN.fullmatch(name) for name in names):
        raise ReconcileError("invalid removed interface names")
    if (not isinstance(inventory, list) or len(inventory) > 4096
            or any(not isinstance(link, dict) or not isinstance(link.get("ifname"), str)
                   for link in inventory)):
        raise ReconcileError("invalid native address inventory")
    present = {link["ifname"] for link in inventory}
    absent = names - present
    # A selected VLAN already removed with its parent has no live source to
    # preserve. Other missing links still make the old snapshot incomplete.
    effective = Intent(
        tuple(row for row in intent.interfaces if row.name not in absent),
        tuple(row for row in intent.held_addresses if row.interface.name not in absent),
    )
    sources, incomplete = source_tables(effective, inventory)
    if incomplete or any(table is None for table in sources.values()):
        raise ReconcileError("old source identity unavailable")
    owners = {row.name: row for row in intent.interfaces if row.name in names}
    holds: list[dict[str, str | int]] = []
    for link in inventory:
        name = link["ifname"]
        if name not in names:
            continue
        entries = link.get("addr_info")
        if not isinstance(entries, list):
            raise ReconcileError("invalid removed interface addresses")
        owner = owners.get(name)
        if owner is None or str(link.get("address", "")).lower() != owner.mac:
            raise ReconcileError("removed interface has unproven source ownership")
        for entry in entries:
            flags = entry.get("flags", [])
            if any(entry.get(flag) or flag in flags for flag in ("tentative", "dadfailed")):
                continue
            if entry.get("valid_life_time") == 0:
                continue
            try:
                source = usable_address(entry.get("local"))
            except ReconcileError:
                continue
            if sources.get(source) != owner.table:
                raise ReconcileError("removed source has ambiguous ownership")
            holds.append({"name": name, "mac": owner.mac, "address": source, "table": owner.table})
    return holds


def owned_rules(rows: Any, family: int) -> set[Rule]:
    """Reject occupied ranges or tagged rules outside the canonical owned form.

    Args:
        rows: Native policy rule records.
        family: IP version, either 4 or 6.
    """
    if not isinstance(rows, list) or len(rows) > 16384:
        raise ReconcileError("invalid native policy rules")
    rules: set[Rule] = set()
    priorities: set[int] = set()
    for row in rows:
        if not isinstance(row, dict) or type(row.get("priority")) is not int:
            raise ReconcileError("invalid native policy rule")
        priority = row["priority"]
        owned = str(row.get("protocol")) == str(PROTOCOL)
        within = PRIORITY_START <= priority < PRIORITY_END
        if not within:
            continue
        if not owned:
            raise ReconcileError("routing-domain priority ownership conflict")
        allowed = {"priority", "src", "srclen", "iif", "table", "action", "protocol"}
        if set(row) - allowed or row.get("iif") != "lo":
            raise ReconcileError("noncanonical owned policy rule")
        source = usable_address(row.get("src"))
        if ipaddress.ip_address(source).version != family or row.get("srclen", 32 if family == 4 else 128) != (32 if family == 4 else 128):
            raise ReconcileError("noncanonical owned source prefix")
        # Numeric iproute2 dumps use FR_ACT_UNREACHABLE (7) on Photon.
        if row.get("action") in ("unreachable", "7") and "table" not in row:
            table = None
        elif "action" not in row and str(row.get("table")) in {"100", "200"}:
            table = int(row["table"])
        else:
            raise ReconcileError("noncanonical owned policy action")
        if priority % 2 != (1 if table is None else 0) or priority in priorities:
            raise ReconcileError("ambiguous owned policy priority")
        priorities.add(priority)
        rules.add(Rule(priority, source, table))
    return rules


def plan_rules(sources: dict[str, int | None], existing: set[Rule]) -> set[Rule]:
    """Allocate stable paired priorities without reusing stale occupied slots.

    Args:
        sources: Exact assigned source addresses mapped to their owning table or quarantine.
        existing: Previously observed owned policy rules.
    """
    slots: dict[tuple[int, str], int] = {}
    occupied: dict[tuple[int, int], str] = {}
    for rule in existing:
        key = (rule.family, rule.source)
        location = (rule.family, rule.slot)
        if key in slots and slots[key] != rule.slot or location in occupied and occupied[location] != rule.source:
            raise ReconcileError("ambiguous source rule allocation")
        slots[key], occupied[location] = rule.slot, rule.source
    desired: set[Rule] = set()
    for source, table in sorted(sources.items()):
        family = ipaddress.ip_address(source).version
        key = (family, source)
        slot = slots.get(key)
        if slot is None:
            capacity = (PRIORITY_END - PRIORITY_START) // 2
            start = int.from_bytes(hashlib.sha256(source.encode("ascii")).digest()[:4], "big") % capacity
            slot = next((PRIORITY_START + 2 * ((start + step) % capacity) for step in range(capacity)
                         if (family, PRIORITY_START + 2 * ((start + step) % capacity)) not in occupied), None)
            if slot is None:
                raise ReconcileError("routing-domain priority capacity exhausted")
            occupied[(family, slot)] = source
        desired.add(Rule(slot + 1, source, None))
        if table is not None:
            desired.add(Rule(slot, source, table))
    return desired


def rule_command(action: str, rule: Rule) -> list[str]:
    """Build an exact tagged argv without shell interpolation or broad deletion.

    Args:
        action: Native policy action under test or requested rule operation.
        rule: Exact source lookup or unreachable guard.
    """
    prefix = 32 if rule.family == 4 else 128
    command = [IP_COMMAND, f"-{rule.family}", "rule", action, "priority", str(rule.priority),
               "from", f"{rule.source}/{prefix}", "iif", "lo", "protocol", str(PROTOCOL)]
    return command + (["unreachable"] if rule.table is None else ["table", str(rule.table)])


def run_ip(arguments: list[str]) -> str:
    """Execute fixed ip argv with bounded runtime and captured-output memory.

    Args:
        arguments: Native command argument vector.
    """
    try:
        with subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
            if process.stdout is None:
                raise ReconcileError("native policy command output unavailable")
            output = bytearray()
            deadline = time.monotonic() + 10
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ReconcileError("native policy command timed out")
                    ready, _, _ = select.select([process.stdout], [], [], remaining)
                    if not ready:
                        raise ReconcileError("native policy command timed out")
                    block = os.read(process.stdout.fileno(), 65536)
                    if not block:
                        break
                    output.extend(block)
                    if len(output) > MAX_JSON_BYTES:
                        raise ReconcileError("native policy response exceeded limit")
                if process.wait(timeout=max(0.01, deadline - time.monotonic())):
                    raise ReconcileError("native policy command failed")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReconcileError("native policy command unavailable or timed out") from exc
    try:
        return output.decode("utf-8")
    except UnicodeError as exc:
        raise ReconcileError("invalid native policy response encoding") from exc


def read_native(arguments: list[str]) -> Any:
    """Admit one bounded JSON response from numeric iproute2 output.

    Args:
        arguments: Native command argument vector.
    """
    try:
        # iproute2 omits protocol=kernel unless detailed output is requested.
        return json.loads(run_ip([IP_COMMAND, "-N", "-j", "-details", *arguments]))
    except json.JSONDecodeError as exc:
        raise ReconcileError("invalid native policy JSON") from exc


def apply_rules(desired: set[Rule], existing: set[Rule]) -> None:
    """Install guards first, preserve working rules, then retire exact stale state.

    Args:
        desired: Target set of owned source rules.
        existing: Previously observed owned policy rules.
    """
    def sort_key(rule: Rule) -> tuple[int, int, str, int]:
        """Order independent commands deterministically for bounded recovery.

        Args:
            rule: Exact source lookup or unreachable guard.
        """
        return rule.family, rule.priority, rule.source, rule.table or 0
    # Ensure even partial prior executions have guards before changing lookups.
    guards = {Rule(rule.slot + 1, rule.source, None) for rule in existing | desired}
    for rule in sorted(guards - existing, key=sort_key):
        run_ip(rule_command("add", rule))
    desired_sources = {rule.source for rule in desired}
    changing = {rule for rule in existing - desired if rule.table is not None and rule.source in desired_sources}
    # Table changes and ambiguous sources must never have parallel active lookups.
    for rule in sorted(changing, key=sort_key):
        run_ip(rule_command("del", rule))
    for rule in sorted(desired - existing - guards, key=sort_key):
        run_ip(rule_command("add", rule))
    for rule in sorted(existing - desired - changing, key=lambda rule: (rule.table is None, *sort_key(rule))):
        run_ip(rule_command("del", rule))
    for rule in sorted(guards - existing - desired, key=sort_key):
        run_ip(rule_command("del", rule))


def migrate_legacy_sources(rows: Any) -> None:
    """Replace journaled legacy source selectors before candidate activation.

    Args:
        rows: Helper-admitted legacy rules from the durable pre-Apply snapshot.
    """
    if not isinstance(rows, list) or len(rows) > 400:
        raise ReconcileError("invalid legacy source rules")
    selectors: list[tuple[int, int, int, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    seen: set[tuple[int, int]] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "family", "priority", "table", "source", "incoming_interface", "protocol",
        }:
            raise ReconcileError("invalid legacy source rule")
        family, priority, table, protocol = (row[key] for key in ("family", "priority", "table", "protocol"))
        if (type(family) is not int or family not in {4, 6} or type(priority) is not int
                or type(table) is not int or type(protocol) is not int or protocol not in {0, 2, 3, 4}
                or row["incoming_interface"] != "" or not isinstance(row["source"], str)):
            raise ReconcileError("invalid legacy source selector")
        expected = 100 if 1000 <= priority < 1100 else 200 if 2000 <= priority < 2100 else None
        if table != expected or (family, priority) in seen:
            raise ReconcileError("foreign or ambiguous legacy source rule")
        try:
            network = ipaddress.ip_network(row["source"], strict=True)
        except ValueError as exc:
            raise ReconcileError("invalid legacy source prefix") from exc
        if network.version != family or str(network) != row["source"] or network.prefixlen == 0:
            raise ReconcileError("invalid legacy source prefix")
        seen.add((family, priority))
        selectors.append((priority, table, protocol, network))
    if not selectors:
        return
    selectors.sort(key=lambda item: item[0])
    with reconciliation_lock():
        try:
            service = subprocess.run(["systemctl", "is-active", "atlaso-route-domains.service"],
                                     check=False, capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReconcileError("legacy source watcher status unavailable") from exc
        if service.returncode not in {0, 3, 4}:
            raise ReconcileError("legacy source watcher status unavailable")
        active = service.returncode == 0
        inventory = read_native(["address", "show"])
        if not isinstance(inventory, list) or len(inventory) > 4096:
            raise ReconcileError("invalid legacy source inventory")
        existing = owned_rules(read_native(["-4", "rule", "show"]), 4)
        existing |= owned_rules(read_native(["-6", "rule", "show"]), 6)
        sources: dict[str, int | None] = {
            rule.source: rule.table for rule in existing if rule.table is not None
        }
        for rule in existing:
            sources.setdefault(rule.source, None)
        seen_links: set[str] = set()
        for link in inventory:
            if not isinstance(link, dict) or not isinstance(link.get("ifname"), str) or link["ifname"] in seen_links:
                raise ReconcileError("ambiguous legacy source link")
            seen_links.add(link["ifname"])
            entries = link.get("addr_info")
            if not isinstance(entries, list) or len(entries) > 4096:
                raise ReconcileError("invalid legacy source addresses")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ReconcileError("invalid legacy source address")
                if entry.get("scope") not in ("global", 0) or entry.get("valid_life_time") == 0:
                    continue
                flags = entry.get("flags", [])
                if not isinstance(flags, list):
                    raise ReconcileError("invalid legacy source flags")
                if any(entry.get(flag) or flag in flags for flag in ("tentative", "dadfailed")):
                    continue
                source = usable_address(entry.get("local"))
                address = ipaddress.ip_address(source)
                match = next((item for item in selectors if item[3].version == address.version
                              and address in item[3]), None)
                if match is None:
                    continue
                table = match[1]
                if source in sources and sources[source] != table:
                    raise ReconcileError("legacy source conflicts with canonical ownership")
                if active and sources.get(source) != table:
                    raise ReconcileError("active watcher cannot preserve legacy source ownership")
                sources[source] = table
        apply_rules(plan_rules(sources, existing), existing)
        for priority, table, protocol, network in selectors:
            run_ip([IP_COMMAND, f"-{network.version}", "rule", "del", "from", str(network),
                    "table", str(table), "priority", str(priority), "protocol", str(protocol)])


@contextmanager
def reconciliation_lock() -> Iterator[None]:
    """Serialize snapshots and mutations while allowing bounded synchronous Apply."""
    fcntl = importlib.import_module("fcntl")

    descriptor = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | linux_attribute(os, "O_NOFOLLOW"), 0o600)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise ReconcileError("unsafe routing-domain lock")
        deadline = time.monotonic() + LOCK_SECONDS
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ReconcileError("routing-domain lock timed out") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def preflight() -> None:
    """Reject foreign source-rule ownership before Network starts a transaction."""
    with reconciliation_lock():
        for family in (4, 6):
            rows = read_native([f"-{family}", "rule", "show"])
            owned_rules(rows, family)
            transition_guard_present(rows, family)
            transition_exemptions_present(rows, family)


def preflight_capacity(candidate_addresses: list[str]) -> None:
    """Reserve rule slots for live, old, and candidate static sources before Apply."""
    if not isinstance(candidate_addresses, list) or len(candidate_addresses) > 512:
        raise ReconcileError("invalid candidate source inventory")
    candidates = {usable_address(address) for address in candidate_addresses}
    with reconciliation_lock():
        existing: set[Rule] = set()
        for family in (4, 6):
            rows = read_native([f"-{family}", "rule", "show"])
            existing.update(owned_rules(rows, family))
            transition_guard_present(rows, family)
            transition_exemptions_present(rows, family)
        # A removed VLAN can already be absent. Count its remaining old rules;
        # the removal-specific identity check decides whether Apply may proceed.
        live, _incomplete = source_tables(read_intent(), read_native(["address", "show"]))
        reserved = {rule.source for rule in existing} | set(live) | candidates
        plan_rules({source: None for source in reserved}, existing)


def transition_guard_present(rows: Any, family: int) -> bool:
    """Admit only our exact persistent local-origin terminal rule.

    Args:
        rows: Observed native policy rule rows.
        family: IPv4 or IPv6 address family under test.
    """
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReconcileError("invalid native policy rules")
    matches = [row for row in rows if row.get("priority") == TRANSITION_PRIORITY]
    if len(matches) > 1:
        raise ReconcileError("ambiguous routing-domain transition priority")
    if not matches:
        return False
    row = matches[0]
    source = "0.0.0.0" if family == 4 else "::"
    if (set(row) - {"priority", "src", "srclen", "iif", "action", "protocol"}
            or row.get("src", "all") not in {"all", source}
            or row.get("srclen", 0) != 0 or row.get("iif") != "lo"
            or row.get("action") not in {"unreachable", "7"}
            or str(row.get("protocol")) not in {str(PROTOCOL), "kernel"}):
        raise ReconcileError("routing-domain transition priority ownership conflict")
    return True


def transition_exemptions_present(rows: Any, family: int) -> set[int]:
    """Admit only main-table escape rules for unbound and link-local sources."""
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReconcileError("invalid native policy rules")
    present: set[int] = set()
    for offset, prefix in enumerate(TRANSITION_EXEMPTIONS[family]):
        priority = PRIORITY_END + offset
        matches = [row for row in rows if row.get("priority") == priority]
        if len(matches) > 1:
            raise ReconcileError("ambiguous routing-domain exemption priority")
        if not matches:
            continue
        row = matches[0]
        network = ipaddress.ip_network(prefix)
        if (set(row) - {"priority", "src", "srclen", "iif", "table", "protocol"}
                or row.get("src") != str(network.network_address)
                or row.get("srclen", 32 if family == 4 else 128) != network.prefixlen
                or row.get("iif") != "lo"
                or str(row.get("table")) not in {"254", "main"}
                or str(row.get("protocol")) not in {str(PROTOCOL), "kernel"}):
            raise ReconcileError("routing-domain exemption priority ownership conflict")
        present.add(priority)
    priority = PRIORITY_END + len(TRANSITION_EXEMPTIONS[family])
    matches = [row for row in rows if row.get("priority") == priority]
    if len(matches) > 1:
        raise ReconcileError("ambiguous routing-domain exemption priority")
    if matches:
        row = matches[0]
        network = ipaddress.ip_network(TRANSITION_DESTINATION_EXEMPTIONS[family])
        if (set(row) - {"priority", "src", "srclen", "dst", "dstlen", "iif", "table", "protocol"}
                or row.get("src", "all") not in {"all", "0.0.0.0" if family == 4 else "::"}
                or row.get("srclen", 0) != 0
                or row.get("dst") != str(network.network_address)
                or row.get("dstlen") != network.prefixlen
                or row.get("iif") != "lo"
                or str(row.get("table")) not in {"254", "main"}
                or str(row.get("protocol")) not in {str(PROTOCOL), "kernel"}):
            raise ReconcileError("routing-domain exemption priority ownership conflict")
        present.add(priority)
    return present


def _seed_transition_sources_locked(bindings: Any, *, allow_absent: bool = False) -> None:
    """Install exact live lookups before a transition guard can cut off old paths."""
    if (not isinstance(bindings, list) or len(bindings) > 256 or any(
        not isinstance(row, dict) or set(row) != {"name", "table"}
        or not isinstance(row["name"], str) or not INTERFACE_PATTERN.fullmatch(row["name"])
        or row["name"] in {"lo", ".", ".."} or type(row["table"]) is not int
        or row["table"] not in {100, 200} for row in bindings
    )):
        raise ReconcileError("invalid transition source bindings")
    names = [row["name"] for row in bindings]
    if len(names) != len(set(names)):
        raise ReconcileError("ambiguous transition source bindings")
    inventory = read_native(["address", "show"])
    if not isinstance(inventory, list) or len(inventory) > 4096:
        raise ReconcileError("invalid transition source inventory")
    by_name: dict[str, dict[str, Any]] = {}
    for link in inventory:
        if not isinstance(link, dict) or not isinstance(link.get("ifname"), str) or link["ifname"] in by_name:
            raise ReconcileError("ambiguous transition source inventory")
        by_name[link["ifname"]] = link
    owners = []
    for binding in bindings:
        link = by_name.get(binding["name"])
        if link is None and allow_absent:
            continue
        if link is None:
            raise ReconcileError("previous management source identity unavailable")
        owners.append(parse_interface({"name": binding["name"], "mac": link.get("address"),
                                       "table": binding["table"]}))
    sources, incomplete = source_tables(Intent(tuple(owners)), inventory)
    if incomplete or any(table is None for table in sources.values()):
        raise ReconcileError("previous management source identity unavailable")
    for source in sources:
        appearances = 0
        for link in inventory:
            entries = link.get("addr_info")
            if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                raise ReconcileError("invalid transition source addresses")
            for entry in entries:
                if entry.get("valid_life_time") == 0:
                    continue
                try:
                    observed_source = usable_address(entry.get("local"))
                except ReconcileError:
                    continue
                appearances += observed_source == source
        if appearances != 1:
            raise ReconcileError("ambiguous previous management source")
    existing = owned_rules(read_native(["-4", "rule", "show"]), 4)
    existing |= owned_rules(read_native(["-6", "rule", "show"]), 6)
    current: dict[str, int | None] = {
        rule.source: rule.table for rule in existing if rule.table is not None
    }
    for rule in existing:
        if rule.table is None and rule.source not in current:
            current[rule.source] = None
    for source, table in sources.items():
        if source in current and current[source] != table:
            raise ReconcileError("previous management source ownership conflicts with live rules")
        current[source] = table
    desired = plan_rules(current, existing)
    # Old replies still use main until their exact lookup is present. Add
    # lookups before their adjacent guards; do not retire any old rule here.
    for rule in sorted((desired - existing), key=lambda row: (row.table is None, row.family, row.priority)):
        run_ip(rule_command("add", rule))


def transition_guard(enable: bool, seed_interfaces: Any = None) -> None:
    """Maintain an exact local-origin guard across address changes.

    Args:
        enable: Whether to install the owned guard.
        seed_interfaces: Previous live interface domains to route before the guard.
    """
    with reconciliation_lock():
        if enable:
            bindings = seed_interfaces
            if bindings is None:
                # Boot starts the unit before networkd, but a persisted intent
                # can still identify addresses already present on its links.
                bindings = [{"name": row.name, "table": row.table}
                            for row in read_intent().interfaces]
            if bindings:
                _seed_transition_sources_locked(bindings, allow_absent=seed_interfaces is None)
        for family in (4, 6):
            _set_guard_locked(family, enable)


def _set_guard_locked(family: int, enable: bool) -> None:
    """Change only the owned terminal guard while holding the reconciliation lock.

    Args:
        family: IPv4 or IPv6 address family under test.
        enable: Whether to install the owned guard.
    """
    rows = read_native([f"-{family}", "rule", "show"])
    owned_rules(rows, family)
    present = transition_guard_present(rows, family)
    exemptions = transition_exemptions_present(rows, family)
    guard = [IP_COMMAND, f"-{family}", "rule", "priority", str(TRANSITION_PRIORITY),
             "from", "all", "iif", "lo", "protocol", str(PROTOCOL), "unreachable"]
    if enable and not present:
        # Install the catch-all first; a newly acquired global source must
        # never fall through while the narrow exceptions are being installed.
        run_ip(guard[:3] + ["add"] + guard[3:])
    for offset, prefix in enumerate(TRANSITION_EXEMPTIONS[family]):
        priority = PRIORITY_END + offset
        if (priority in exemptions) != enable:
            command = [IP_COMMAND, f"-{family}", "rule", "add" if enable else "del",
                       "priority", str(priority), "from", prefix, "iif", "lo",
                       "protocol", str(PROTOCOL), "table", "main"]
            run_ip(command)
    destination_priority = PRIORITY_END + len(TRANSITION_EXEMPTIONS[family])
    if (destination_priority in exemptions) != enable:
        command = [IP_COMMAND, f"-{family}", "rule", "add" if enable else "del",
                   "priority", str(destination_priority), "to", TRANSITION_DESTINATION_EXEMPTIONS[family],
                   "iif", "lo", "protocol", str(PROTOCOL), "table", "main"]
        run_ip(command)
    if not enable and present:
        run_ip(guard[:3] + ["del"] + guard[3:])


def reconcile() -> None:
    """Re-read applied intent and native state under the shared mutation lock."""
    with reconciliation_lock():
        # Keep unclassified DHCP/SLAAC sources out of main even between the
        # kernel's address event and this process's next netlink rescan.
        for family in (4, 6):
            _set_guard_locked(family, True)
        intent = read_intent()
        sources, incomplete = source_tables(intent, read_native(["address", "show"]))
        existing = owned_rules(read_native(["-4", "rule", "show"]), 4)
        existing |= owned_rules(read_native(["-6", "rule", "show"]), 6)
        if incomplete:
            # Missing identity is not proof that an old source disappeared.
            # Keep its guard instead of exposing an unproven replacement to
            # ordinary main-table fallback. A later complete snapshot retires it.
            for source in {rule.source for rule in existing}:
                previous_tables = {rule.table for rule in existing if rule.source == source and rule.table is not None}
                if sources.get(source) not in previous_tables:
                    sources[source] = None
        apply_rules(plan_rules(sources, existing), existing)
        if incomplete or any(table is None for table in sources.values()):
            raise ReconcileError("interface identity unavailable or duplicate source quarantined")


def event_requires_rescan(data: bytes, truncated: bool = False) -> bool:
    """Rescan after link/address events, malformed datagrams, or netlink loss.

    Args:
        data: Received netlink datagram bytes.
        truncated: Whether the receive operation reported a truncated datagram.
    """
    if truncated or not data:
        return True
    offset = 0
    while offset < len(data):
        if len(data) - offset < 16:
            return True
        length, kind, _flags, _sequence, _pid = struct.unpack_from("=IHHII", data, offset)
        if length < 16 or offset + length > len(data):
            return True
        if kind in {2, 4, 16, 17, 20, 21}:  # ERROR, OVERRUN, NEW/DEL LINK, NEW/DEL ADDR
            return True
        offset += (length + 3) & ~3
    return False


def monitor() -> None:
    """Subscribe before the initial snapshot and periodically repair event loss."""
    with socket.socket(linux_attribute(socket, "AF_NETLINK"), socket.SOCK_RAW, linux_attribute(socket, "NETLINK_ROUTE")) as events:
        events.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1_048_576)
        events.bind((0, 1 | 0x10 | 0x100))  # LINK, IPv4 address, IPv6 address
        pending = True
        deadline = time.monotonic()
        previous_error = ""
        while True:
            if pending or time.monotonic() >= deadline:
                try:
                    reconcile()
                    previous_error = ""
                except (ReconcileError, OSError) as exc:
                    message = str(exc) if isinstance(exc, ReconcileError) else "routing-domain system operation failed"
                    if message != previous_error:
                        print(message, file=sys.stderr, flush=True)
                    previous_error = message
                deadline = time.monotonic() + RESCAN_SECONDS
                pending = False
            ready, _, _ = select.select([events], [], [], max(0, deadline - time.monotonic()))
            if ready:
                try:
                    data, _ancillary, flags, _sender = linux_attribute(events, "recvmsg")(262_144)
                    pending = event_requires_rescan(data, bool(flags & socket.MSG_TRUNC))
                except OSError as exc:
                    if exc.errno != errno.ENOBUFS:
                        raise
                    pending = True


def main() -> int:
    """Run a synchronous Apply reconciliation or the privileged event monitor."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Reconcile once for protected Apply readiness")
    mode.add_argument("--preflight", action="store_true", help="Check source-rule ownership without changing rules or intent")
    mode.add_argument("--transition-start", action="store_true", help="Install persistent local-origin guard")
    mode.add_argument("--transition-start-seeded", action="store_true", help="Seed proven old sources before the guard")
    mode.add_argument("--transition-stop", action="store_true", help="Retire local-origin guard during rollback or reset")
    mode.add_argument("--migrate-legacy", action="store_true", help="Retire journaled legacy source rules before activation")
    arguments = parser.parse_args()
    try:
        if linux_attribute(os, "geteuid")() != 0:
            raise ReconcileError("routing-domain reconciliation requires root")
        if arguments.preflight:
            preflight()
        elif arguments.transition_start:
            transition_guard(True)
        elif arguments.transition_start_seeded:
            payload = sys.stdin.read(MAX_JSON_BYTES + 1)
            if len(payload) > MAX_JSON_BYTES:
                raise ReconcileError("transition source bindings are oversized")
            try:
                transition_guard(True, json.loads(payload))
            except json.JSONDecodeError as exc:
                raise ReconcileError("invalid transition source bindings") from exc
        elif arguments.transition_stop:
            transition_guard(False)
        elif arguments.migrate_legacy:
            payload = sys.stdin.read(MAX_JSON_BYTES + 1)
            if len(payload) > MAX_JSON_BYTES:
                raise ReconcileError("legacy source snapshot is oversized")
            try:
                migrate_legacy_sources(json.loads(payload))
            except json.JSONDecodeError as exc:
                raise ReconcileError("invalid legacy source snapshot") from exc
        elif arguments.once:
            reconcile()
        else:
            monitor()
    except (ReconcileError, OSError) as exc:
        print(str(exc) if isinstance(exc, ReconcileError) else "routing-domain system operation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
