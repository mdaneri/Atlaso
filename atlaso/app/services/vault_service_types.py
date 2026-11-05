"""Classify vault services from explicit component metadata, without reading secrets."""

from __future__ import annotations

import re
from ipaddress import ip_address
from urllib.parse import urlsplit

VAULT_SERVICE_TYPE_LABELS: dict[str, str] = {
    "unknown": "Unknown",
    "esx": "ESX",
    "vcenter": "vCenter",
    "sddc_manager": "SDDC Manager",
    "nsx": "NSX",
    "operations": "Operations",
    "automation": "Automation",
    "operations_collector": "Operations Collector",
    "services_runtime": "Services Runtime",
    "lifecycle_manager": "Lifecycle Manager",
    "log_insight": "Log Insight",
    "identity_manager": "Identity Manager",
    "load_balancer": "NSX Advanced Load Balancer",
    "vxrail_manager": "VxRail Manager",
    "psc": "Platform Services Controller",
    "backup": "Backup",
}

_RESOURCE_SERVICE_TYPES: dict[str, str] = {
    "ESX": "esx", "ESXI": "esx", "ESX_HOST": "esx", "HOST": "esx", "VCENTER": "vcenter", "PSC": "psc",
    "SDDC_MANAGER": "sddc_manager",
    "NSX": "nsx", "NSX_MANAGER": "nsx", "NSX_CONTROLLER": "nsx", "NSX_EDGE": "nsx",
    "NSXT_MANAGER": "nsx", "NSXT_EDGE": "nsx",
    "VROPS": "operations", "VCF_OPERATIONS": "operations",
    "VRA": "automation", "VCF_AUTOMATION": "automation",
    "VROPS_COLLECTOR": "operations_collector", "VCF_OPERATIONS_COLLECTOR": "operations_collector",
    "VSP": "services_runtime", "VCF_SERVICES_RUNTIME": "services_runtime",
    "VRLI": "log_insight", "WSA": "identity_manager", "VRSLCM": "lifecycle_manager",
    "VXRAIL_MANAGER": "vxrail_manager", "NSX_ALB": "load_balancer", "BACKUP": "backup",
}

_DEPLOYMENT_SERVICE_TYPES: dict[str, str] = {
    "hostspec": "esx", "hostspecs": "esx", "hosts": "esx", "esx": "esx", "esxi": "esx",
    "vcenterspec": "vcenter", "sddcmanagerspec": "sddc_manager", "nsxtspec": "nsx",
    "vcfoperationsspec": "operations", "vcfautomationspec": "automation",
    "vcfoperationscollectorspec": "operations_collector", "vspclusterspec": "services_runtime",
    "vropsspec": "operations", "vraspec": "automation", "vrlispec": "log_insight",
    "vrslcmspec": "lifecycle_manager", "wsaspec": "identity_manager",
}


def normalize_vault_service_type(value: str) -> str:
    """Validate a stored or operator-selected service identifier.

    Args:
        value: Canonical service identifier, with empty legacy inputs treated as unknown.

    Raises:
        ValueError: If the supplied service is unsupported.
    """
    service_type = value.strip().lower() or "unknown"
    if service_type not in VAULT_SERVICE_TYPE_LABELS:
        raise ValueError("Choose a supported vault service.")
    return service_type


def vault_service_from_resource(resource_type: str) -> str:
    """Map an explicit vendor resource type to a vault service.

    Args:
        resource_type: Resource type reported by the credential API.
    """
    return _RESOURCE_SERVICE_TYPES.get(resource_type.strip().upper(), "unknown")


def vault_service_from_deployment_path(path: tuple[str, ...]) -> str:
    """Map a top-level component container in a deployment password path.

    Args:
        path: Component and password-field path supplied by the deployment specification.
    """
    # Later path segments can be hostnames or other resource-provided labels.
    # Only a known specification container establishes the owning service.
    return _DEPLOYMENT_SERVICE_TYPES.get(path[0].lower(), "unknown") if path else "unknown"


def legacy_vault_service_type(*, source_type: str, secret_type: str, description: str) -> str:
    """Recover service labels only from Atlaso's known historical import descriptions.

    Args:
        source_type: Persisted import source type.
        secret_type: Persisted broad password category.
        description: Existing non-secret entry description.
    """
    if secret_type == "esx_password":
        return "esx"
    if source_type == "sddc_manager":
        match = re.match(r"^Imported SDDC Manager ([A-Z_]+) credential for ", description)
        return vault_service_from_resource(match.group(1)) if match else "unknown"
    if source_type == "vcf_installer":
        for prefix in ("Imported VCF Installer password from ", "Deployment-time password from "):
            if description.startswith(prefix):
                path = description.removeprefix(prefix).split(";", 1)[0].removesuffix(".")
                return vault_service_from_deployment_path(tuple(path.split(".")))
    return "unknown"


def vault_entry_display_name(*, key: str, service_type: str, username: str, uris: tuple[str, ...]) -> str:
    """Build an imported entry's readable name without changing its stable key.

    Args:
        key: Exact stable key retained for scripts and credential matching.
        service_type: Explicit service metadata, never inferred from a hostname.
        username: Non-secret account name.
        uris: Credential-free endpoint associations in operator-defined order.
    """
    host = ""
    for uri in uris:
        try:
            endpoint = urlsplit(uri)
            if endpoint.scheme not in {"http", "https", "ssh", "sftp"} or endpoint.username or endpoint.password:
                continue
            candidate_host = endpoint.hostname or ""
        except ValueError:
            continue
        if candidate_host:
            try:
                host = str(ip_address(candidate_host))
            except ValueError:
                host = candidate_host.rstrip(".").split(".", 1)[0]
            break
    # Display names are deliberately not identifiers: two domains may share a
    # short hostname. Full URIs, account details and the stable key remain available.
    def segment(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:48]

    host_label, account_label = segment(host), segment(username)
    if not host_label and not account_label:
        return key
    service = service_type if service_type in VAULT_SERVICE_TYPE_LABELS else "unknown"
    return ".".join(part for part in (service, host_label, account_label) if part)
