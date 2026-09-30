"""Fail-closed contracts for an isolated routing-overlap lifecycle fixture.

These helpers have no provider or guest side effects. The canonical wrapper must
supply independently observed VMX and guest NIC mappings before using the returned
configuration. They do not admit a caller-authored descriptor as ownership proof.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any


class OverlapPrerequisiteError(ValueError):
    """Reject incomplete or conflicting fixture admission evidence."""


@dataclass(frozen=True)
class FixtureOwner:
    """Independent task identity retained by the canonical controller."""

    task_id: str
    repository: str
    source_commit: str
    pr: int
    lab_root: str


@dataclass(frozen=True)
class FixtureLink:
    """One provider adapter matched to exactly one guest interface."""

    role: str
    adapter: int
    interface: str
    mac: str
    network_type: str
    network_id: str


@dataclass(frozen=True)
class AdmittedTopology:
    """Frozen private test links and independent control links."""

    owner: FixtureOwner
    management_segment: str
    lab_segment: str
    links: tuple[FixtureLink, ...]
    ipv4_prefix: str
    ipv6_prefix: str

    def link(self, role: str, adapter: int) -> FixtureLink:
        """Return an already admitted adapter.

        Args:
            role: Canonical VM role.
            adapter: Exact VMX ethernet index.
        """
        return next(link for link in self.links if (link.role, link.adapter) == (role, adapter))


def _same_owner(receipt: dict[str, Any], owner: FixtureOwner) -> bool:
    """Compare receipt ownership with the independent controller identity.

    Args:
        receipt: Parsed immutable creation receipt.
        owner: Identity supplied independently from the receipt.
    """
    return all(receipt.get(key) == getattr(owner, key)
               for key in ("task_id", "repository", "source_commit", "pr", "lab_root"))


def _mac(value: Any) -> str:
    """Admit only a unicast six-octet Ethernet identity.

    Args:
        value: Provider or guest MAC observation.
    """
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        raise OverlapPrerequisiteError("invalid adapter MAC identity")
    if int(value[:2], 16) & 1 or value.lower() == "00:00:00:00:00:00":
        raise OverlapPrerequisiteError("adapter MAC must be nonzero unicast")
    return value.lower()


def admit_topology(
    owner: FixtureOwner,
    segments: dict[str, dict[str, str]],
    receipt_bytes: dict[str, bytes],
    provider_nics: list[dict[str, Any]],
    guest_links: list[dict[str, Any]],
    *,
    control_network: str,
    control_prefixes: list[str],
    ipv4_prefix: str = "192.0.2.0/24",
    ipv6_prefix: str = "fd74:1::/64",
) -> AdmittedTopology:
    """Require owned receipts and independent provider/guest topology agreement.

    Args:
        owner: Canonical task/PR identity, not derived from receipt contents.
        segments: Management/lab names, provider IDs, and independently retained receipt digests.
        receipt_bytes: Original receipt bytes read under the wrapper's no-write pins.
        provider_nics: Enabled VMX adapters independently read under provider/file pins.
        guest_links: Live guest interface/MAC observations from bounded guest operations.
        control_network: Independently selected existing VMnet for client control only.
        control_prefixes: Observed prefixes on the host control network.
        ipv4_prefix: Shared private test IPv4 prefix.
        ipv6_prefix: Shared private test IPv6 /64.

    Returns:
        Frozen admitted topology, suitable for guest configuration rendering.

    Raises:
        OverlapPrerequisiteError: If any identity or isolation prerequisite is unproven.
    """
    if (not owner.task_id or owner.repository != "mdaneri/Atlaso" or type(owner.pr) is not int
            or owner.pr <= 0 or not re.fullmatch(r"[0-9a-f]{40}", owner.source_commit) or not owner.lab_root):
        raise OverlapPrerequisiteError("invalid independent fixture ownership")
    if not re.fullmatch(r"VMnet[0-9]+", control_network) or not control_prefixes:
        raise OverlapPrerequisiteError("control network identity and prefixes are required")
    try:
        v4 = ipaddress.ip_network(ipv4_prefix, strict=True)
        v6 = ipaddress.ip_network(ipv6_prefix, strict=True)
        controls = [ipaddress.ip_network(prefix, strict=False) for prefix in control_prefixes]
    except ValueError as exc:
        raise OverlapPrerequisiteError("invalid fixture prefix") from exc
    if v4.version != 4 or v4.prefixlen != 24 or v6.version != 6 or v6.prefixlen != 64:
        raise OverlapPrerequisiteError("fixture requires an IPv4 /24 and IPv6 /64")
    if not v4.is_private or not v6.is_private or any(
        test.overlaps(control) for test in (v4, v6) for control in controls if test.version == control.version
    ):
        raise OverlapPrerequisiteError("private test prefixes must be separate from control addressing")
    if set(segments) != {"management", "lab"} or set(receipt_bytes) != set(segments):
        raise OverlapPrerequisiteError("exactly two owned segment receipts are required")
    ids: dict[str, str] = {}
    names: set[str] = set()
    for purpose, segment in segments.items():
        raw = receipt_bytes[purpose]
        digest = segment.get("receipt_sha256", "")
        if (not raw or len(raw) > 65536 or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or hashlib.sha256(raw).hexdigest() != digest):
            raise OverlapPrerequisiteError("segment creation receipt digest mismatch")
        try:
            receipt = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OverlapPrerequisiteError("segment receipt is not valid JSON") from exc
        if (not isinstance(receipt, dict) or receipt.get("schema") != 1 or not _same_owner(receipt, owner)
                or not re.fullmatch(r"[0-9a-f]{32}", str(receipt.get("creation_id", "")))):
            raise OverlapPrerequisiteError("segment creation receipt ownership mismatch")
        segment_id, name = segment.get("id", ""), segment.get("name", "")
        if (not re.fullmatch(r"52(?: [0-9a-f]{2}){7}-[0-9a-f]{2}(?: [0-9a-f]{2}){7}", segment_id)
                or receipt.get("pvn_id") != segment_id or receipt.get("name") != name
                or not name.startswith(f"Atlaso-PR-{owner.pr}-") or name in names or segment_id in ids.values()):
            raise OverlapPrerequisiteError("segments must have distinct canonical owned identities")
        names.add(name)
        ids[purpose] = segment_id
    expected = {
        ("appliance", 0): ("pvn", ids["management"]),
        ("appliance", 1): ("pvn", ids["lab"]),
        ("client-a", 0): ("custom", control_network),
        ("client-a", 1): ("pvn", ids["management"]),
        ("client-b", 0): ("custom", control_network),
        ("client-b", 1): ("pvn", ids["lab"]),
    }
    if len(provider_nics) != len(expected):
        raise OverlapPrerequisiteError("unexpected or missing enabled provider adapter")
    links: list[FixtureLink] = []
    seen: set[tuple[str, int]] = set()
    macs: set[str] = set()
    for nic in provider_nics:
        role, adapter = nic.get("role"), nic.get("adapter")
        key = (role, adapter)
        if type(adapter) is not int or key in seen or key not in expected:
            raise OverlapPrerequisiteError("ambiguous provider adapter identity")
        network = (nic.get("network_type"), nic.get("network_id"))
        if network != expected[key]:
            raise OverlapPrerequisiteError("provider adapter is outside the isolated topology")
        mac = _mac(nic.get("mac"))
        if mac in macs:
            raise OverlapPrerequisiteError("duplicate provider adapter MAC")
        matches = [row for row in guest_links if row.get("role") == role and _mac(row.get("mac")) == mac]
        if len(matches) != 1:
            raise OverlapPrerequisiteError("provider adapter lacks one exact guest NIC match")
        interface = matches[0].get("interface", "")
        if (not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", interface)
                or interface == "lo" or any(link.role == role and link.interface == interface for link in links)):
            raise OverlapPrerequisiteError("invalid or duplicate guest interface identity")
        links.append(FixtureLink(role, adapter, interface, mac, network[0], network[1]))
        seen.add(key)
        macs.add(mac)
    if len(guest_links) != len(links):
        raise OverlapPrerequisiteError("unmatched guest interface in isolated topology")
    return AdmittedTopology(owner, ids["management"], ids["lab"], tuple(links), str(v4), str(v6))


def server_configuration(topology: AdmittedTopology) -> dict[str, str]:
    """Render private-interface DHCP/RA configuration without executing anything.

    Args:
        topology: Provider/guest topology admitted by the canonical wrapper.

    Returns:
        Public server configuration plus fixed guest address metadata.
    """
    private = topology.link("client-a", 1)
    control = topology.link("client-a", 0)
    appliance = topology.link("appliance", 0)
    v4 = ipaddress.ip_network(topology.ipv4_prefix)
    gateway, address = str(v4.network_address + 1), str(v4.network_address + 10)
    dnsmasq = "\n".join([
        "port=0", "bind-interfaces", f"interface={private.interface}", f"except-interface={control.interface}",
        "no-resolv", "no-hosts", "dhcp-authoritative", "dhcp-ignore=tag:!fixture",
        f"dhcp-range={address},{address},{v4.netmask},2m",
        f"dhcp-host=set:fixture,{appliance.mac},{address},2m", f"dhcp-option=3,{gateway}",
        "dhcp-option=6", "dhcp-leasefile=/run/atlaso-routing-overlap/leases", "",
    ])
    radvd = (f"interface {private.interface} {{\n  AdvSendAdvert on;\n  MinRtrAdvInterval 3;\n"
             "  MaxRtrAdvInterval 10;\n  AdvDefaultLifetime 30;\n"
             f"  prefix {topology.ipv6_prefix} {{\n    AdvOnLink on;\n    AdvAutonomous on;\n"
             "    AdvValidLifetime 60;\n    AdvPreferredLifetime 30;\n  };\n};\n")
    return {"dnsmasq": dnsmasq, "radvd": radvd, "gateway": gateway, "appliance_address": address,
            "private_interface": private.interface, "control_interface": control.interface}


def verify_source_rules(
    addresses: dict[str, int], rules: dict[int, list[dict[str, Any]]],
) -> dict[str, int]:
    """Require exact-address lookup and terminal isolation rules for every source.

    Args:
        addresses: Observed admitted interface addresses mapped to expected table 100/200.
        rules: Complete native ``ip -j -N -4/-6 rule show`` observations.

    Returns:
        Exact sources whose lookup and unreachable fallback were both observed.

    Raises:
        OverlapPrerequisiteError: If a source rule is absent, broad, or lacks its fallback.
    """
    if set(rules) != {4, 6} or not addresses:
        raise OverlapPrerequisiteError("complete dual-family rule observations are required")
    for family in (4, 6):
        terminal = [row for row in rules[family] if row.get("priority") == 6004]
        if (len(terminal) != 1 or terminal[0].get("src", "all") not in
                {"all", "0.0.0.0" if family == 4 else "::"}
                or terminal[0].get("srclen", 0) != 0
                or terminal[0].get("iif") != "lo"
                or terminal[0].get("action") not in {"unreachable", "7", 7}
                or str(terminal[0].get("protocol")) != "2"):
            raise OverlapPrerequisiteError("persistent local-source guard is absent or ambiguous")
        exceptions = (("0.0.0.0/32", "169.254.0.0/16", "127.0.0.0/8") if family == 4
                      else ("::/128", "fe80::/10", "::1/128"))
        for offset, prefix in enumerate(exceptions):
            network = ipaddress.ip_network(prefix)
            matches = [row for row in rules[family] if row.get("priority") == 6000 + offset]
            if (len(matches) != 1 or matches[0].get("src") != str(network.network_address)
                    or matches[0].get("srclen", network.max_prefixlen) != network.prefixlen
                    or matches[0].get("iif") != "lo"
                    or str(matches[0].get("table")) != "254"
                    or str(matches[0].get("protocol")) != "2"):
                raise OverlapPrerequisiteError("unbound/link-local source escape is absent or ambiguous")
        destination = ipaddress.ip_network("169.254.0.0/16" if family == 4 else "fe80::/10")
        matches = [row for row in rules[family] if row.get("priority") == 6003]
        if (len(matches) != 1 or matches[0].get("dst") != str(destination.network_address)
                or matches[0].get("dstlen") != destination.prefixlen
                or matches[0].get("iif") != "lo"
                or str(matches[0].get("table")) != "254"
                or str(matches[0].get("protocol")) != "2"):
            raise OverlapPrerequisiteError("unbound link-local destination escape is absent or ambiguous")
    verified = {}
    for value, table in addresses.items():
        address = ipaddress.ip_address(value)
        if table not in {100, 200}:
            raise OverlapPrerequisiteError("unknown fixture source table")
        prefix = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
        matching = []
        for row in rules[address.version]:
            source = row.get("src", "all")
            if source == "all":
                continue
            try:
                network = ipaddress.ip_network(
                    source if "/" in source else f"{source}/{row.get('srclen', address.max_prefixlen)}", strict=False,
                )
            except (ValueError, TypeError) as exc:
                raise OverlapPrerequisiteError("invalid native source rule observation") from exc
            if (network == prefix and row.get("iif") == "lo"
                    and str(row.get("protocol")) == "2"
                    and type(row.get("priority")) is int and 5000 <= row["priority"] < 6000):
                matching.append(row)
        lookups = [row for row in matching if str(row.get("table")) == str(table)
                   and row.get("action", "to_tbl") in {"to_tbl", 1, "1"}]
        fallbacks = [row for row in matching if row.get("action") in {"unreachable", 7, "7"}]
        if (len(lookups) != 1 or len(fallbacks) != 1
                or type(lookups[0].get("priority")) is not int
                or type(fallbacks[0].get("priority")) is not int
                or lookups[0]["priority"] >= fallbacks[0]["priority"]):
            raise OverlapPrerequisiteError(f"source {address} lacks exact table lookup and unreachable fallback")
        verified[str(address)] = table
    return verified


def verify_expired_sources(
    expired: list[str], current_addresses: list[str], rules: dict[int, list[dict[str, Any]]],
) -> None:
    """Require expired addresses and their exact source rules to disappear.

    Args:
        expired: Previously proven acquired DHCP/SLAAC addresses.
        current_addresses: Complete current admitted-interface address observation.
        rules: Complete native rule observations for both families after expiry.

    Raises:
        OverlapPrerequisiteError: If any expired source remains or evidence is incomplete.
    """
    if not expired or set(rules) != {4, 6}:
        raise OverlapPrerequisiteError("expiry requires previous addresses and complete dual-family rules")
    active = {ipaddress.ip_address(value) for value in current_addresses}
    for value in expired:
        address = ipaddress.ip_address(value)
        if address in active:
            raise OverlapPrerequisiteError("expired address remains active")
        for row in rules[address.version]:
            source = row.get("src", "all")
            if source == "all":
                continue
            try:
                parsed = ipaddress.ip_interface(source).ip
            except ValueError as exc:
                raise OverlapPrerequisiteError("invalid native source rule observation") from exc
            if parsed == address:
                raise OverlapPrerequisiteError("expired source rule remains installed")


def verify_route_selection(source: str, table: int, interface: str, routes: list[dict[str, Any]]) -> None:
    """Require the kernel's source-specific route lookup to select its own domain.

    Args:
        source: Address supplied to the fixed ``ip -j -N route get ... from`` probe.
        table: Expected management or lab table.
        interface: Independently admitted guest NIC.
        routes: Successful native route-get JSON, not a rendered desired route.

    Raises:
        OverlapPrerequisiteError: If lookup selected another table, source, or device.
    """
    address = ipaddress.ip_address(source)
    if table not in {100, 200} or len(routes) != 1:
        raise OverlapPrerequisiteError("source route lookup must return one domain-owned route")
    route = routes[0]
    observed_source = route.get("from", route.get("prefsrc", route.get("src")))
    if (str(route.get("table")) != str(table) or route.get("dev") != interface
            or observed_source is None or ipaddress.ip_address(observed_source) != address
            or route.get("type", "unicast") != "unicast"):
        raise OverlapPrerequisiteError("kernel route lookup escaped its expected source domain")
