"""Select a receipt-bound baseline for ordinary certificate acceptance."""

from __future__ import annotations

import ipaddress
from typing import Any


def baseline_mode(plan: dict[str, Any]) -> str:
    """Validate the explicit ordinary CA baseline mode.

    Args:
        plan: Receipt-bound certificate acceptance plan.

    Returns:
        ``static`` for the legacy default or ``dhcp`` for the ordinary CA case.

    Raises:
        ValueError: If the mode or its scenario binding is invalid.
    """
    mode = plan.get("ordinary_ca_baseline_mode", "static")
    if type(mode) is not str or mode not in {"static", "dhcp"}:
        raise ValueError("ordinary_ca_baseline_mode_invalid")
    if mode == "dhcp" and (
        plan.get("trust_model") != "trusted-host"
        or plan.get("scenario") != "ordinary-ca-rotation"
    ):
        raise ValueError("ordinary_ca_baseline_mode_invalid")
    return mode


def baseline_address(plan: dict[str, Any], fixture: dict[str, Any] | None = None) -> str:
    """Select the original static baseline or admitted DHCP lease address.

    Args:
        plan: Receipt-bound bootstrap or native acceptance plan.
        fixture: Optional admitted original ISO fixture containing its fixed lease.

    Returns:
        Canonical IPv4 address for the existing management baseline.

    Raises:
        ValueError: If the selected address is invalid or disagrees with the original fixture.
    """
    mode = baseline_mode(plan)
    if mode == "dhcp":
        value = plan.get("current_address")
        if fixture is not None and value != fixture.get("lease_address"):
            raise ValueError("ordinary_ca_dhcp_lease_mismatch")
    else:
        value = plan.get("baseline_address")
        peer_value = plan.get("peer_transport", {}).get("baseline_address")
        if value is None:
            value = peer_value
        elif peer_value is not None and str(value) != str(peer_value):
            raise ValueError("ordinary_ca_static_baseline_mismatch")
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError("ordinary_ca_baseline_address_invalid") from None
    return str(address)
