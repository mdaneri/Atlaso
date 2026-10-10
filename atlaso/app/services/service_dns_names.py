"""Project canonical service DNS target identities without UI dependencies."""

import hashlib
import re
from ipaddress import ip_address

from atlaso.app.services.dnsmasq import split_addresses, split_interfaces


def service_dns_target_token(strategy: str, interface_name: str, address: str) -> str:
    """Return service dns target token.

    Args:
        strategy: Strategy consumed by service DNS target token.
        interface_name: Host network-interface name affected by the operation.
        address: Network address contacted or validated by the operation.
    """
    if strategy == "ip":
        try:
            parsed = ip_address(address)
        except ValueError:
            return re.sub(r"[^a-z0-9]+", "-", address.strip().lower()).strip("-") or "address"
        if parsed.version == 4:
            return str(parsed).replace(".", "-")
        return "-".join(format(int(group, 16), "x") for group in parsed.exploded.split(":"))
    safe_interface = re.sub(r"[^a-z0-9]+", "-", interface_name.strip().lower()).strip("-")
    return safe_interface or "interface"


def service_target_hostname(hostname: str, target_token: str) -> str:
    """Return service target hostname.

    Args:
        hostname: DNS hostname contacted, validated, or configured by the operation.
        target_token: Target token consumed by service target hostname.
    """
    normalized = hostname.strip().strip(".").lower()
    if "." not in normalized:
        return normalized
    label, domain = normalized.split(".", 1)
    safe_token = re.sub(r"[^a-z0-9]+", "-", target_token.strip().lower()).strip("-") or "target"
    suffix = f"-{safe_token}"
    if len(label) + len(suffix) <= 63:
        target_label = f"{label}{suffix}"
    else:
        digest = hashlib.sha1(f"{label}{suffix}".encode("utf-8")).hexdigest()[:8]
        hash_suffix = f"-{digest}"
        max_label_len = 63 - len(suffix) - len(hash_suffix)
        if max_label_len >= 1:
            target_label = f"{label[:max_label_len].rstrip('-')}{suffix}{hash_suffix}"
        else:
            target_label = f"{safe_token[: max(1, 63 - len(hash_suffix))].rstrip('-')}{hash_suffix}"
    return f"{target_label}.{domain}"


def service_alias_names(hostname: str, listen_interface: str | None, listen_address: str | None,
                        naming_strategy: str, *, shared_target_token: str | None = None) -> set[str]:
    """Reserve selected service targets, including temporarily unavailable bindings.

    Args:
        hostname: Canonical service endpoint hostname.
        listen_interface: Selected service interface names.
        listen_address: Selected service addresses.
        naming_strategy: Canonical appliance target naming strategy.
        shared_target_token: Stable shared target token used by NTP publication.
    """
    names: set[str] = set()
    for interface in split_interfaces(listen_interface):
        for address in split_addresses(listen_address):
            try:
                parsed = ip_address(address)
            except ValueError:
                continue
            token = shared_target_token or service_dns_target_token(naming_strategy, interface, str(parsed))
            names.add(service_target_hostname(hostname, token))
    return names


def storage_alias_names(hostname: str, interface_name: str, addresses: list[str],
                        address_families: str, naming_strategy: str) -> set[str]:
    """Project ESX Storage target names using its canonical renderer helpers.

    Args:
        hostname: Storage service endpoint hostname.
        interface_name: Selected storage interface name.
        addresses: Selected interface addresses.
        address_families: Selected storage address families.
        naming_strategy: Canonical appliance target naming strategy.
    """
    from atlaso.app.services.esx_storage import (
        normalize_families,
        target_hostname,
        target_token,
    )

    try:
        families = normalize_families(address_families)
        return {target_hostname(hostname, target_token(address, naming_strategy, interface_name))
                for address in addresses if ("ipv6" if ":" in address else "ipv4") in families}
    except ValueError:
        return set()
