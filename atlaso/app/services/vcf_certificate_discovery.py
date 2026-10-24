"""Pure product, identity, health, and topology checks for VCF appliances."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

from cryptography import x509


@dataclass(frozen=True)
class ApplianceNames:
    """Canonical names discovered from the existing appliance certificate.

    Attributes:
        common_name: Certificate subject common name.
        dns_names: Existing DNS SANs, including the required PNID hostname.
        ip_addresses: Existing IP SANs.
    """

    common_name: str
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]


def _product_text(value: Any) -> str:
    """Normalize a native product description without accepting structured values.

    Args:
        value: Candidate native value to normalize or validate.
    """
    if isinstance(value, str):
        return value.casefold()
    if isinstance(value, dict):
        return " ".join(
            str(item).casefold()
            for item in value.values()
            if isinstance(item, (str, int, float))
        )
    return ""


def supported_version(product: str, info: dict[str, Any]) -> bool:
    """Return whether native identity data identifies a supported product version.

    Args:
        product: Detected appliance product identifier.
        info: Public native discovery metadata.
    """
    product = product.casefold()
    if product == "sddc":
        if not isinstance(info, dict) or not isinstance(info.get("role"), str):
            return False
        if info["role"].casefold() != "sddcmanager":
            return False
        version = info.get("version")
        if not isinstance(version, (str, int, float)):
            return False
        match = re.match(r"^\s*(\d+)(?:\.\d+)*(?:[-+].*)?\s*$", str(version))
        return bool(match and int(match.group(1)) == 9)
    if product not in {"srm", "vcenter"}:
        return False
    identity = _product_text(info)
    if product == "srm" and not any(
        label in identity
        for label in (
            "protection and recovery appliance",
            "siterecoverymanager",
            "site recovery manager",
        )
    ):
        return False
    if product == "vcenter" and not any(
        label in identity
        for label in ("vcenter server appliance", "vcenter server", "vmware vcenter")
    ):
        return False
    version_keys = (
        ("appliance_version", "version", "product_version", "build_version")
        if product == "srm"
        else ("version", "product_version", "build_version")
    )
    version = next(
        (
            str(info[key])
            for key in version_keys
            if isinstance(info.get(key), (str, int, float))
        ),
        "",
    )
    match = re.match(
        r"^\s*(\d+)(?:\.\d+)*(?:\s+build\s+\d+)?(?:[-+].*)?\s*$", version, re.IGNORECASE
    )
    return bool(match and int(match.group(1)) >= 8)


def names_from_certificate(
    cert: x509.Certificate, product: str, identity_hostname: str
) -> ApplianceNames:
    """Preserve certificate DNS/IP SANs and require the native appliance PNID.

    Args:
        cert: Parsed public appliance certificate.
        product: Detected appliance product identifier.
        identity_hostname: Native appliance hostname used to validate certificate identity.
    """
    normalized_product = product.casefold()
    if (
        normalized_product not in {"srm", "vcenter", "sddc"}
        or not identity_hostname
        or identity_hostname != identity_hostname.strip()
    ):
        raise ValueError("Appliance identity hostname is invalid.")
    if normalized_product == "sddc":
        try:
            ip_address(identity_hostname)
        except ValueError:
            labels = identity_hostname.rstrip(".").split(".")
            if (
                len(labels) < 2
                or any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    or not re.fullmatch(r"[A-Za-z0-9-]+", label)
                    for label in labels
                )
                or identity_hostname.casefold() in {"localhost", "localhost.localdomain"}
            ):
                raise ValueError(
                    "SDDC Manager identity must be a valid DNS FQDN."
                ) from None
        else:
            raise ValueError("SDDC Manager identity must be a DNS FQDN.")
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError(
            "Current certificate has no subject alternative names."
        ) from exc
    dns_values = san.get_values_for_type(x509.DNSName)
    ip_values = san.get_values_for_type(x509.IPAddress)
    dns_names = {value for value in dns_values if value.casefold() not in {"localhost", "localhost.localdomain"}}
    ip_names = {str(value) for value in ip_values if not value.is_loopback}
    try:
        parsed = ip_address(identity_hostname)
    except ValueError:
        parsed = None
    if parsed is not None:
        ip_names.add(str(parsed))
        if normalized_product == "vcenter":
            dns_names.add(str(parsed))
    else:
        dns_names.add(identity_hostname)
    common_name = identity_hostname
    return ApplianceNames(
        common_name, tuple(sorted(dns_names, key=str.casefold)), tuple(sorted(ip_names))
    )


def healthy_services(
    product: str, health: Any, baseline: set[str] | dict[str, Any] | None = None
) -> bool:
    """Check native health, automatic services, and any previously running services.

    Args:
        product: Detected appliance product identifier.
        health: Native service health response.
        baseline: Previously accepted service inventory used for comparison.
    """
    if product.casefold() == "vcenter":
        if isinstance(health, str):
            return health.casefold() == "green"
        if isinstance(health, dict):
            value = health.get("value", health.get("status"))
            return isinstance(value, str) and value.casefold() == "green"
        return False
    if product.casefold() == "sddc":
        if not isinstance(health, dict) or not isinstance(health.get("list"), list):
            return False
        services = health["list"]
        if not services:
            return False
        service_ids: set[str] = set()
        for item in services:
            if not isinstance(item, dict):
                return False
            service_id = item.get("id")
            status = item.get("status")
            if (
                not isinstance(service_id, str)
                or not service_id.strip()
                or service_id in service_ids
                or not isinstance(status, str)
                or status.upper() not in {"UP", "RUNNING", "ACTIVE"}
            ):
                return False
            service_ids.add(service_id)
        required: set[str] = set()
        if isinstance(baseline, set):
            required = set(baseline)
        elif isinstance(baseline, dict):
            baseline_services = baseline.get("list")
            if not isinstance(baseline_services, list):
                return False
            for item in baseline_services:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    return False
                required.add(item["id"])
        elif baseline is not None:
            return False
        return required <= service_ids
    if product.casefold() != "srm" or not isinstance(health, (list, dict)):
        return False
    services = health.get("list") if isinstance(health, dict) else health
    if isinstance(health, dict) and isinstance(health.get("_meta"), dict):
        meta = health["_meta"]
        links = meta.get("links")
        total, offset, limit = meta.get("total"), meta.get("offset"), meta.get("limit")
        if (
            not isinstance(services, list)
            or not isinstance(links, dict)
            or links.get("next") is not None
            or not all(isinstance(value, int) for value in (total, offset, limit))
            or offset != 0
            or total != len(services)
            or total > limit
        ):
            return False
    if not isinstance(services, list):
        return False
    required = set(baseline) if isinstance(baseline, set) else set()
    if isinstance(baseline, dict) and isinstance(baseline.get("list"), list):
        required.update(
            item["id"]
            for item in baseline["list"]
            if isinstance(item, dict)
            and item.get("is_running") is True
            and isinstance(item.get("id"), str)
        )
    found: dict[str, tuple[str, bool]] = {}
    for item in services:
        if not isinstance(item, dict):
            continue
        service_id = item.get("id", item.get("service_name"))
        startup = item.get("startup_type")
        running = item.get("is_running")
        if running is None and isinstance(item.get("service_status"), str):
            running = item["service_status"].casefold() == "running"
        if (
            isinstance(service_id, str)
            and isinstance(startup, str)
            and isinstance(running, bool)
        ):
            found[service_id] = (startup.casefold(), running)
    for item in services:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("startup_type"), str)
            or item["startup_type"].casefold() != "automatic"
        ):
            continue
        service_id = item.get("id", item.get("service_name"))
        if isinstance(service_id, str):
            required.add(service_id)
    return bool(required) and all(
        name in found
        and found[name][1]
        and (found[name][0] == "automatic" or name in required)
        for name in required
    )


def standalone_vcenter(vcha_info: Any, registrations: Any) -> bool:
    """Allow only explicitly unconfigured VCHA with exactly one registered node.

    Broadcom's vSphere Automation SDK defines ConfigState.NOTCONFIGURED as the
    state for an appliance without a VCHA cluster. Unknown/missing states fail closed.

    Args:
        vcha_info: Native vCenter High Availability configuration.
        registrations: Native Lookup Service registration inventory.
    """
    if not isinstance(vcha_info, dict):
        return False
    state = vcha_info.get("config_state")
    normalized = (
        re.sub(r"[_\s-]", "", state).casefold() if isinstance(state, str) else ""
    )
    if normalized != "notconfigured" or not isinstance(registrations, list):
        return False
    if len(registrations) != 1 or not isinstance(registrations[0], dict):
        return False
    registration = registrations[0]
    return all(
        isinstance(registration.get(key), str) and bool(registration[key].strip())
        for key in ("node_id", "service_id")
    ) and bool(registration.get("endpoints"))
