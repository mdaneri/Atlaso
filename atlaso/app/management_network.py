"""Validate management-network values shared by appliance entry points."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address, ip_interface


class ManagementNetworkValidationError(ValueError):
    """Report an invalid or internally inconsistent management network."""


@dataclass(frozen=True)
class ManagementNetworkValues:
    """Represent one normalized management-network configuration."""

    ipv4_method: str
    ipv4_cidr: str
    ipv4_gateway: str
    ipv6_mode: str
    ipv6_cidr: str
    ipv6_gateway: str
    dns_servers: tuple[str, ...]


def validate_ipv4_management_values(
    ipv4_method: str,
    ipv4_cidr: str,
    gateway: str,
    *,
    require_static_gateway: bool = False,
) -> tuple[str, str, str]:
    """Validate and normalize the management IPv4 relationship.

    Args:
        ipv4_method: Address-assignment method to validate.
        ipv4_cidr: Static IPv4 address and prefix, when configured.
        gateway: Static IPv4 gateway, when configured.
        require_static_gateway: Whether static IPv4 must include a gateway.

    Returns:
        The normalized method, CIDR, and gateway.
    """
    method = ipv4_method.strip().lower()
    cidr_value = ipv4_cidr.strip()
    gateway_value = gateway.strip()
    if method not in {"dhcp", "static"}:
        raise ManagementNetworkValidationError("Management IPv4 method must be DHCP or static.")
    if method == "dhcp":
        if cidr_value or gateway_value:
            raise ManagementNetworkValidationError(
                "DHCP management networking cannot include a static address or gateway."
            )
        return method, "", ""
    if not cidr_value:
        raise ManagementNetworkValidationError(
            "A static management IPv4 configuration requires an address and prefix."
        )
    try:
        parsed_interface = ip_interface(cidr_value)
    except ValueError as exc:
        raise ManagementNetworkValidationError(
            "Management IPv4 must be an IPv4 CIDR such as 192.168.49.1/24."
        ) from exc
    if parsed_interface.version != 4:
        raise ManagementNetworkValidationError("Management IP must use IPv4.")
    if parsed_interface.network.prefixlen <= 30 and parsed_interface.ip in {
        parsed_interface.network.network_address,
        parsed_interface.network.broadcast_address,
    }:
        raise ManagementNetworkValidationError(
            "Management IPv4 address must be a usable host address for the configured prefix."
        )
    if require_static_gateway and not gateway_value:
        raise ManagementNetworkValidationError(
            "A static management IPv4 configuration requires an IPv4 gateway."
        )
    if gateway_value:
        try:
            parsed_gateway = ip_address(gateway_value)
        except ValueError as exc:
            raise ManagementNetworkValidationError(
                "Management gateway must be a valid IPv4 address."
            ) from exc
        if parsed_gateway.version != 4 or parsed_gateway not in parsed_interface.network:
            raise ManagementNetworkValidationError(
                "Management gateway must be an on-link IPv4 address for the configured prefix."
            )
        if parsed_gateway == parsed_interface.ip:
            raise ManagementNetworkValidationError(
                "Management gateway cannot equal the management IPv4 address."
            )
        if parsed_interface.network.prefixlen <= 30 and parsed_gateway in {
            parsed_interface.network.network_address,
            parsed_interface.network.broadcast_address,
        }:
            raise ManagementNetworkValidationError(
                "Management gateway must be a usable host IPv4 address for the configured prefix."
            )
        gateway_value = str(parsed_gateway)
    return method, str(parsed_interface), gateway_value


def validate_ipv6_management_values(
    ipv6_mode: str,
    ipv6_cidr: str,
    ipv6_gateway: str,
) -> tuple[str, str, str]:
    """Validate and normalize the management IPv6 relationship.

    Args:
        ipv6_mode: IPv6 assignment mode to validate.
        ipv6_cidr: Static IPv6 address and prefix, when configured.
        ipv6_gateway: Static IPv6 gateway, when configured.

    Returns:
        The normalized mode, CIDR, and gateway.
    """
    mode = ipv6_mode.strip().lower()
    if mode == "auto":
        mode = "automatic"
    cidr_value = ipv6_cidr.strip()
    gateway_value = ipv6_gateway.strip()
    if mode not in {"disabled", "automatic", "static"}:
        raise ManagementNetworkValidationError(
            "Management IPv6 mode must be disabled, automatic, or static."
        )
    if mode != "static":
        if cidr_value or gateway_value:
            raise ManagementNetworkValidationError(
                "Disabled or automatic IPv6 cannot include a static address or gateway."
            )
        return mode, "", ""
    if not cidr_value:
        raise ManagementNetworkValidationError(
            "A static management IPv6 configuration requires an address and prefix."
        )
    try:
        parsed_interface = ip_interface(cidr_value)
    except ValueError as exc:
        raise ManagementNetworkValidationError(
            "Management IPv6 must be an IPv6 CIDR such as fd00:49::1/64."
        ) from exc
    if parsed_interface.version != 6:
        raise ManagementNetworkValidationError("Management IPv6 CIDR must use IPv6.")
    if gateway_value:
        try:
            parsed_gateway = ip_address(gateway_value)
        except ValueError as exc:
            raise ManagementNetworkValidationError(
                "Management IPv6 gateway must be a valid IPv6 address."
            ) from exc
        if parsed_gateway.version != 6:
            raise ManagementNetworkValidationError("Management IPv6 gateway must use IPv6.")
        if not parsed_gateway.is_link_local and parsed_gateway not in parsed_interface.network:
            raise ManagementNetworkValidationError(
                "Management IPv6 gateway must be link-local or on-link for the configured prefix."
            )
        if parsed_gateway == parsed_interface.ip:
            raise ManagementNetworkValidationError(
                "Management IPv6 gateway cannot equal the management IPv6 address."
            )
        gateway_value = str(parsed_gateway)
    return mode, str(parsed_interface), gateway_value


def validate_management_dns_servers(raw: str, *, required: bool = False) -> tuple[str, ...]:
    """Validate and normalize management DNS server addresses.

    Args:
        raw: Delimited DNS server addresses to validate.
        required: Whether at least one DNS server is required.

    Returns:
        The normalized DNS server addresses.
    """
    servers = tuple(item for item in re.split(r"[\s,;]+", raw.strip()) if item)
    if required and not servers:
        raise ManagementNetworkValidationError("At least one DNS server is required.")
    normalized: list[str] = []
    for server in servers:
        try:
            normalized.append(str(ip_address(server)))
        except ValueError as exc:
            raise ManagementNetworkValidationError(
                f"DNS server {server} must be an IPv4 or IPv6 address."
            ) from exc
    return tuple(normalized)


def validate_management_network(
    *,
    ipv4_method: str,
    ipv4_cidr: str,
    ipv4_gateway: str,
    ipv6_mode: str,
    ipv6_cidr: str,
    ipv6_gateway: str,
    dns_servers: str,
    require_static_ipv4_gateway: bool = False,
    require_dns: bool = False,
) -> ManagementNetworkValues:
    """Validate and normalize a complete management-network form.

    Args:
        ipv4_method: Address-assignment method to validate.
        ipv4_cidr: Static IPv4 address and prefix, when configured.
        ipv4_gateway: Static IPv4 gateway, when configured.
        ipv6_mode: IPv6 assignment mode to validate.
        ipv6_cidr: Static IPv6 address and prefix, when configured.
        ipv6_gateway: Static IPv6 gateway, when configured.
        dns_servers: Delimited DNS server addresses to validate.
        require_static_ipv4_gateway: Whether static IPv4 must include a gateway.
        require_dns: Whether at least one DNS server is required.

    Returns:
        The normalized complete management-network values.
    """
    method, normalized_cidr, normalized_gateway = validate_ipv4_management_values(
        ipv4_method,
        ipv4_cidr,
        ipv4_gateway,
        require_static_gateway=require_static_ipv4_gateway,
    )
    mode, normalized_ipv6_cidr, normalized_ipv6_gateway = validate_ipv6_management_values(
        ipv6_mode,
        ipv6_cidr,
        ipv6_gateway,
    )
    normalized_dns = validate_management_dns_servers(dns_servers, required=require_dns)
    return ManagementNetworkValues(
        ipv4_method=method,
        ipv4_cidr=normalized_cidr,
        ipv4_gateway=normalized_gateway,
        ipv6_mode=mode,
        ipv6_cidr=normalized_ipv6_cidr,
        ipv6_gateway=normalized_ipv6_gateway,
        dns_servers=normalized_dns,
    )
