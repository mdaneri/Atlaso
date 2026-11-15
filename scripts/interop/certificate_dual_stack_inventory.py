"""Conservative family-aware interpretation of complete TEST_ONLY guest reads.

This module authenticates no producer and provides no address-control admission.
The original full seven-command payload must remain in the controller journal;
normalized facts never replace raw routes, rules, or original source/boot proof.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from scripts.interop.certificate_dual_stack_channel import validate_public_payload
from scripts.interop.certificate_dual_stack_contract import (
    ListenerEndpoint,
    parse_listener_endpoint,
    validate_static_observation,
)
from scripts.interop.certificate_dual_stack_guest import GuestRefusal


def _rows(payload: dict[str, Any], name: str) -> list[dict[str, Any]]:
    """Require complete object rows without dropping malformed inventory entries.

    Args:
        payload: Complete action-schema-validated native payload.
        name: One fixed JSON inventory producer name.
    """
    rows = payload["observations"][name]["raw"]
    if not all(isinstance(row, dict) for row in rows):
        raise GuestRefusal("native_inventory_row_invalid")
    return list(rows)


def _index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Require distinct positive link indexes and unambiguous interface names.

    Args:
        rows: Complete link or address inventory rows.
    """
    result: dict[str, dict[str, Any]] = {}
    indexes: set[int] = set()
    for row in rows:
        name = row.get("ifname")
        index = row.get("ifindex")
        if (not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) is None
                or type(index) is not int or index <= 0 or index in indexes or name in result):
            raise GuestRefusal("native_interface_inventory_ambiguous")
        indexes.add(index)
        result[name] = row
    return result


def address_inventory(payload: dict[str, Any], *, boot_id: str) -> list[dict[str, Any]]:
    """Preserve every address from a complete link/address snapshot of one boot.

    A missing/mismatched interface, unknown family, malformed address or prefix
    refuses the entire interpretation. There is no filtering to the expected NIC.

    Args:
        payload: Complete original seven-producer public payload.
        boot_id: Original controller-admitted guest boot identity.
    """
    validate_public_payload(payload)
    if payload["kind"] != "dual-stack-native-raw-observation" or payload["boot_id"] != boot_id:
        raise GuestRefusal("original_native_boot_required")
    links = _index(_rows(payload, "links"))
    addresses = _index(_rows(payload, "addresses"))
    if not links or set(links) != set(addresses):
        raise GuestRefusal("complete_interface_inventory_required")
    result = []
    for name, row in addresses.items():
        link = links[name]
        if row["ifindex"] != link["ifindex"] or row.get("address") != link.get("address"):
            raise GuestRefusal("native_interface_identity_changed")
        infos = row.get("addr_info")
        if not isinstance(infos, list):
            raise GuestRefusal("native_address_inventory_invalid")
        seen: set[tuple[int, str, int]] = set()
        for info in infos:
            if not isinstance(info, dict):
                raise GuestRefusal("native_address_inventory_invalid")
            family_name = info.get("family")
            family = {"inet": 4, "inet6": 6}.get(family_name) if isinstance(family_name, str) else None
            local, prefix = info.get("local"), info.get("prefixlen")
            if family is None or not isinstance(local, str) or "%" in local or type(prefix) is not int:
                raise GuestRefusal("native_address_inventory_invalid")
            try:
                address = ipaddress.ip_address(local)
            except ValueError:
                raise GuestRefusal("native_address_inventory_invalid") from None
            if address.version != family or not 0 <= prefix <= address.max_prefixlen:
                raise GuestRefusal("native_address_inventory_invalid")
            key = family, str(address), prefix
            if key in seen:
                raise GuestRefusal("native_address_inventory_ambiguous")
            seen.add(key)
            result.append({"interface": name, "ifindex": row["ifindex"], "mac": row.get("address"),
                           "family": family, "address": str(address), "prefixlen": prefix,
                           "raw": info})
    return result


def listener_inventory(payload: dict[str, Any]) -> list[ListenerEndpoint]:
    """Parse every complete numeric ss listening row, retaining wildcard/mapped facts.

    Args:
        payload: Complete original seven-producer public payload.
    """
    validate_public_payload(payload)
    if payload["kind"] != "dual-stack-native-raw-observation":
        raise GuestRefusal("complete_native_inventory_required")
    result = []
    for line in payload["observations"]["listeners"]["raw"]:
        if not isinstance(line, str) or len(line) > 4_096:
            raise GuestRefusal("complete_listener_inventory_required")
        parts = line.split()
        if (len(parts) != 5 or parts[0] != "LISTEN" or not parts[1].isdigit()
                or not parts[2].isdigit()):
            raise GuestRefusal("complete_listener_inventory_required")
        result.append(parse_listener_endpoint(parts[3]))
    return result


def static_address_consistency(
    payload: dict[str, Any], *, boot_id: str, interface: str, mac: str, cidrs: list[str],
) -> list[dict[str, Any]]:
    """Check native address facts against separately authenticated static intent.

    Missing dynamic flags do not prove assignment provenance. Callers need the
    normal-UI desired readback and original runtime admission independently.
    This returns consistency facts only, never formal or execution acceptance.

    Args:
        payload: Original complete seven-command native payload.
        boot_id: Original admitted boot identity.
        interface: Original admitted interface name.
        mac: Original admitted canonical MAC address.
        cidrs: Explicit expected static host CIDRs for both applicable families.
    """
    all_addresses = address_inventory(payload, boot_id=boot_id)
    links = _index(_rows(payload, "links"))
    link = links.get(interface)
    if (link is None or link.get("address") != mac or link.get("operstate") != "UP"
            or not isinstance(link.get("flags"), list) or "LOWER_UP" not in link["flags"]):
        raise GuestRefusal("active_native_interface_required")
    expected = [ipaddress.ip_interface(value) for value in cidrs]
    if not expected or len({item.version for item in expected}) != len(expected):
        raise GuestRefusal("distinct_expected_address_families_required")
    facts = []
    for item in expected:
        matches = [row for row in all_addresses if row["family"] == item.version
                   and row["address"] == str(item.ip)]
        if len(matches) != 1 or matches[0]["interface"] != interface:
            raise GuestRefusal("static_address_missing_or_duplicated")
        match = matches[0]
        raw = match["raw"]
        flags = raw.get("flags", [])
        if (not isinstance(flags, list) or any(not isinstance(flag, str) for flag in flags)
                or any(flag in raw and (type(raw[flag]) is not bool or raw[flag]) for flag in (
                    "dynamic", "temporary", "tentative", "dadfailed", "deprecated", "secondary"))
                or any(flag not in {"permanent", "noprefixroute"} for flag in flags)
                or raw.get("scope") != "global"):
            raise GuestRefusal("static_address_not_ready")
        observation = {
            "schema": 1, "kind": "static-fixture-observation", "interface": interface,
            "mac": mac, "operstate": "UP", "carrier": True, "family": item.version,
            "address": match["address"], "prefixlen": match["prefixlen"], "source": "static",
            "flags": flags, "dad_state": "complete" if item.version == 6 else "not_applicable",
            "valid_lifetime": raw.get("valid_life_time"),
            "preferred_lifetime": raw.get("preferred_life_time"),
        }
        validate_static_observation(observation, expected_interface=interface,
                                    expected_mac=mac, expected_cidr=str(item))
        facts.append({"observation": observation, "static_consistency_only": True,
                      "test_only": True, "formal_acceptance": False})
    # Do not discard unrecognized route/rule rows while retaining normalized addresses.
    for name in ("routes4", "routes6", "rules4", "rules6"):
        _rows(payload, name)
    listener_inventory(payload)
    return facts
