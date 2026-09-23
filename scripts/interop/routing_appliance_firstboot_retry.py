"""Submit the private fixture's unchanged DHCP review after native address readback.

This runs only inside the task-owned appliance clone. It never reads or prints
first-boot access credentials and refuses any unexpected network intent.
"""

from __future__ import annotations

import json
import subprocess


def eligible_review(review: object, addresses: object) -> bool:
    """Admit only the expected transient DHCP review with its assigned address.

    Args:
        review: Console's bounded first-boot network review object.
        addresses: Native ``ip -j`` address observation for the fixture link.
    """
    if review is None or not isinstance(addresses, list):
        return False
    if (getattr(review, "error", "") != "Native management addresses did not activate; review conflicts and network connectivity."
            or getattr(review, "ipv4_method", "") != "dhcp"
            or getattr(review, "ipv6_mode", "") != "disabled"
            or any(getattr(review, name, "") for name in ("ipv4_cidr", "gateway", "ipv6_cidr", "ipv6_gateway"))):
        return False
    return any(
        isinstance(link, dict) and link.get("ifname") == "eth0"
        and any(isinstance(addr, dict) and addr.get("family") == "inet"
                and addr.get("local") == "192.0.2.10" for addr in link.get("addr_info", []))
        for link in addresses
    )


def main() -> int:
    """Retry only the unchanged fixture review after actual DHCP assignment."""
    from atlaso.app.appliance_console import (  # noqa: PLC0415 - guest-only runtime import
        ConsoleOperationError,
        load_first_boot_network_review,
        submit_first_boot_network_correction,
    )

    try:
        review = load_first_boot_network_review()
        observed = subprocess.run(  # noqa: S603 - fixed native read-only command
            ["ip", "-j", "-4", "addr", "show", "dev", "eth0"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if observed.returncode or len(observed.stdout) > 8192:
            return 2
        if not eligible_review(review, json.loads(observed.stdout)):
            return 2
        submit_first_boot_network_correction(
            "dhcp", "", "", "disabled", "", "", ",".join(review.dns_servers),
        )
        return 0
    except (ConsoleOperationError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
