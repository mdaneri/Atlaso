"""Focused provider-bound management address selection tests."""

from __future__ import annotations

import pytest

from scripts.virtualization.select_management_ipv4 import (
    ManagementAddressError,
    select_management_ipv4,
)

MANAGEMENT_MAC = "52:54:00:11:22:33"
SERVICE_MAC = "52:54:00:44:55:66"


def _interface(mac: str, *addresses: str) -> dict[str, object]:
    """Return one QGA network fixture.

    Args:
        mac: Interface hardware address.
        addresses: IPv4 values to publish on the fixture.
    """

    return {
        "name": f"fixture-{mac[-2:]}",
        "hardware-address": mac,
        "ip-addresses": [
            {"ip-address-type": "ipv4", "ip-address": address}
            for address in addresses
        ],
    }


def test_services_first_qga_fixture_selects_management_ipv4() -> None:
    """QGA enumeration order cannot redirect a probe to the services NIC."""

    interfaces = [
        _interface(SERVICE_MAC, "198.51.100.20"),
        _interface(MANAGEMENT_MAC, "192.0.2.20"),
    ]
    assert (
        select_management_ipv4(
            interfaces,
            management_mac=MANAGEMENT_MAC,
            service_mac=SERVICE_MAC,
        )
        == "192.0.2.20"
    )


@pytest.mark.parametrize(
    "interfaces",
    [
        [_interface(SERVICE_MAC, "198.51.100.20")],
        [
            _interface(SERVICE_MAC, "198.51.100.20"),
            _interface(MANAGEMENT_MAC, "192.0.2.20"),
            _interface(MANAGEMENT_MAC, "192.0.2.21"),
        ],
        [
            _interface(SERVICE_MAC, "198.51.100.20"),
            _interface(MANAGEMENT_MAC, "192.0.2.20", "192.0.2.21"),
        ],
        [
            _interface(SERVICE_MAC, "192.0.2.20"),
            _interface(MANAGEMENT_MAC, "192.0.2.20"),
        ],
        [
            _interface("52:54:00:aa:bb:cc", "192.0.2.20"),
            _interface(SERVICE_MAC, "198.51.100.20"),
        ],
    ],
)
def test_qga_management_selection_fails_closed_on_missing_duplicate_or_mismatch(
    interfaces: list[dict[str, object]],
) -> None:
    """Incomplete or ambiguous MAC/address evidence never yields a probe target.

    Args:
        interfaces: QGA fixture under test.
    """

    with pytest.raises(ManagementAddressError):
        select_management_ipv4(
            interfaces,
            management_mac=MANAGEMENT_MAC,
            service_mac=SERVICE_MAC,
        )


def test_qga_management_selection_rejects_ineligible_addresses() -> None:
    """Loopback and link-local values cannot become host-facing probe targets."""

    interfaces = [
        _interface(SERVICE_MAC, "198.51.100.20"),
        _interface(MANAGEMENT_MAC, "127.0.0.1", "169.254.10.20"),
    ]
    with pytest.raises(ManagementAddressError, match="exactly one usable"):
        select_management_ipv4(
            interfaces,
            management_mac=MANAGEMENT_MAC,
            service_mac=SERVICE_MAC,
        )
