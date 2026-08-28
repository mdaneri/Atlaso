"""Select one QEMU guest-agent IPv4 bound to the provider management MAC."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from typing import Any

MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2})$")


class ManagementAddressError(RuntimeError):
    """Report unusable or ambiguous management adapter evidence."""


def normalize_mac(value: str) -> str:
    """Return a canonical lowercase colon-delimited MAC address.

    Args:
        value: Provider or QGA MAC address text.
    """

    candidate = value.strip().lower()
    if not MAC_PATTERN.fullmatch(candidate):
        raise ManagementAddressError("Management adapter evidence contains a malformed MAC address.")
    compact = candidate.replace(":", "").replace("-", "")
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _usable_ipv4(value: Any) -> str | None:
    """Return canonical usable IPv4 text or None for an ineligible value.

    Args:
        value: QGA IP address value.
    """

    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address) or (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        return None
    return str(address)


def select_management_ipv4(
    interfaces: Any,
    *,
    management_mac: str,
    service_mac: str,
) -> str:
    """Return the unique usable IPv4 on the exact management interface.

    Args:
        interfaces: QGA ``guest-network-get-interfaces`` result array.
        management_mac: Provider-side management adapter MAC.
        service_mac: Provider-side services adapter MAC.
    """

    expected_management = normalize_mac(management_mac)
    expected_service = normalize_mac(service_mac)
    if expected_management == expected_service:
        raise ManagementAddressError("Management and services adapter MAC addresses must be distinct.")
    if not isinstance(interfaces, list):
        raise ManagementAddressError("QGA network interface evidence is not an array.")

    matching: dict[str, list[dict[str, Any]]] = {
        expected_management: [],
        expected_service: [],
    }
    for interface in interfaces:
        if not isinstance(interface, dict):
            raise ManagementAddressError("QGA network interface evidence contains a malformed row.")
        hardware_address = interface.get("hardware-address")
        if not isinstance(hardware_address, str):
            continue
        try:
            normalized = normalize_mac(hardware_address)
        except ManagementAddressError:
            continue
        if normalized in matching:
            matching[normalized].append(interface)

    if len(matching[expected_management]) != 1 or len(matching[expected_service]) != 1:
        raise ManagementAddressError(
            "QGA must report exactly one interface for each provider-bound adapter MAC."
        )
    addresses = sorted(
        {
            selected
            for item in matching[expected_management][0].get("ip-addresses", [])
            if isinstance(item, dict) and item.get("ip-address-type") == "ipv4"
            if (selected := _usable_ipv4(item.get("ip-address"))) is not None
        }
    )
    if len(addresses) != 1:
        raise ManagementAddressError(
            "The provider-bound QGA management interface must report exactly one usable IPv4 address."
        )
    service_addresses = {
        selected
        for item in matching[expected_service][0].get("ip-addresses", [])
        if isinstance(item, dict) and item.get("ip-address-type") == "ipv4"
        if (selected := _usable_ipv4(item.get("ip-address"))) is not None
    }
    if addresses[0] in service_addresses:
        raise ManagementAddressError(
            "The provider-bound management IPv4 address is also reported by the services interface."
        )
    return addresses[0]


def main(argv: list[str] | None = None) -> int:
    """Read QGA JSON from stdin and print its provider-bound management IPv4.

    Args:
        argv: Optional command-line argument sequence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--management-mac", required=True)
    parser.add_argument("--service-mac", required=True)
    args = parser.parse_args(argv)
    try:
        interfaces = json.load(sys.stdin)
        address = select_management_ipv4(
            interfaces,
            management_mac=args.management_mac,
            service_mac=args.service_mac,
        )
    except (json.JSONDecodeError, ManagementAddressError) as exc:
        parser.error(str(exc))
    print(address)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
