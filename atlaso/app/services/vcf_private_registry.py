"""Implement vcf private registry service behavior."""

from __future__ import annotations

import re
from ipaddress import ip_address

from atlaso.app.models import VcfPrivateRegistrySettings, VcfRegistryBundle
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces


VCF_REGISTRY_DEFAULT_STORAGE_PATH = "/mnt/atlaso-vcf-registry"
VCF_REGISTRY_DEFAULT_CONFIG_PATH = "/etc/atlaso/harbor/harbor.yml"
VCF_REGISTRY_DEFAULT_PROJECT = "vcf-supervisor-services"
VCF_REGISTRY_DEFAULT_HOSTNAME = "registry.atlaso.internal"
VCF_REGISTRY_UPLOADED_CA_BUNDLE_PATH = "/etc/atlaso/harbor/uploaded-ca-bundle.pem"
VCF_REGISTRY_UPLOADED_CA_BUNDLE_NAME_KEY = "vcf_registry_uploaded_ca_bundle_name"
VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY = "vcf_registry_uploaded_ca_bundle_pem"

PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,118}[a-z0-9]$")
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{1,251}[A-Za-z0-9]$")
STATUS_VALUES = {"planned", "ready", "relocated", "blocked"}


def vcf_registry_endpoint(settings: VcfPrivateRegistrySettings) -> str:
    """Return vcf registry endpoint."""
    port = settings.port or 443
    if port == 443:
        return settings.hostname.strip()
    return f"{settings.hostname.strip()}:{port}"


def default_target_reference(settings: VcfPrivateRegistrySettings, source_reference: str) -> str:
    """Return default target reference."""
    source = source_reference.strip()
    if not source:
        return ""
    image_name = source.split("/")[-1].split("@", 1)[0].split(":", 1)[0]
    image_name = image_name or "supervisor-service-bundle"
    return f"{vcf_registry_endpoint(settings)}/{settings.harbor_project.strip()}/{image_name}"


def vcf_registry_settings_to_dict(settings: VcfPrivateRegistrySettings) -> dict[str, object]:
    """Return vcf registry settings to dict."""
    return {
        "id": settings.id,
        "enabled": settings.enabled,
        "hostname": settings.hostname,
        "listen_interface": settings.listen_interface,
        "listen_address": settings.listen_address,
        "port": settings.port,
        "endpoint": vcf_registry_endpoint(settings),
        "harbor_project": settings.harbor_project,
        "storage_path": settings.storage_path,
        "config_path": settings.config_path,
        "ca_bundle_path": settings.ca_bundle_path,
        "server_certificate": settings.server_certificate,
        "robot_account": settings.robot_account,
        "relocation_dry_run": settings.relocation_dry_run,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else "",
    }


def vcf_registry_bundle_to_dict(bundle: VcfRegistryBundle) -> dict[str, object]:
    """Return vcf registry bundle to dict."""
    return {
        "id": bundle.id,
        "name": bundle.name,
        "source_reference": bundle.source_reference,
        "target_reference": bundle.target_reference,
        "enabled": bundle.enabled,
        "status": bundle.status,
        "notes": bundle.notes or "",
        "created_at": bundle.created_at.isoformat() if bundle.created_at else "",
        "updated_at": bundle.updated_at.isoformat() if bundle.updated_at else "",
    }


def render_harbor_config(settings: VcfPrivateRegistrySettings) -> str:
    """Render harbor config.

    Returns:
        The rendered harbor config.
    """
    storage_path = settings.storage_path or VCF_REGISTRY_DEFAULT_STORAGE_PATH
    config_port = settings.port or 443
    certificate_name = settings.server_certificate or settings.hostname or VCF_REGISTRY_DEFAULT_HOSTNAME
    project = settings.harbor_project or VCF_REGISTRY_DEFAULT_PROJECT
    robot_account = settings.robot_account or f"robot${project}"
    ca_bundle_path = settings.ca_bundle_path or "/etc/atlaso/ca/ca-bundle.pem"
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "# Dry-run preview of desired Harbor registry endpoint for VCF Supervisor Services.",
        f"hostname: {settings.hostname}",
        f"http:",
        f"  port: 80",
        f"https:",
        f"  port: {config_port}",
        f"  certificate: /etc/atlaso/harbor/certs/{certificate_name}.crt",
        f"  private_key: /etc/atlaso/harbor/certs/{certificate_name}.key",
        f"harbor_admin_password: <provisioned-by-atlaso-helper>",
        f"data_volume: {storage_path}",
        f"external_url: https://{vcf_registry_endpoint(settings)}",
        "",
        "# Atlaso helper creates or updates this Harbor project and robot account.",
        f"atlaso_project: {project}",
        f"atlaso_robot_account: {robot_account}",
        f"atlaso_ca_bundle: {ca_bundle_path}",
        f"atlaso_listen_interface: {settings.listen_interface}",
        f"atlaso_listen_address: {settings.listen_address}",
        f"atlaso_listen_interfaces: {split_interfaces(settings.listen_interface)}",
        f"atlaso_listen_addresses: {split_addresses(settings.listen_address)}",
    ]
    return "\n".join(lines).strip() + "\n"


def render_imgpkg_relocation_preview(settings: VcfPrivateRegistrySettings, bundles: list[VcfRegistryBundle]) -> str:
    """Render imgpkg relocation preview.

    Returns:
        The rendered imgpkg relocation preview.
    """
    enabled_bundles = [bundle for bundle in bundles if bundle.enabled]
    if not enabled_bundles:
        return "# No enabled Supervisor Service bundles are staged for relocation.\n"

    lines = [
        "# Dry-run preview. Credentials are supplied by the appliance helper and are not rendered here.",
        f"# Private registry: {vcf_registry_endpoint(settings)}",
        f"# Harbor project: {settings.harbor_project}",
    ]
    for bundle in enabled_bundles:
        source = bundle.source_reference.strip()
        target = bundle.target_reference.strip() or default_target_reference(settings, source)
        lines.extend(
            [
                "",
                f"# {bundle.name}",
                f"imgpkg copy -b {source} --to-repo {target}",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def validate_vcf_registry_state(
    settings: VcfPrivateRegistrySettings,
    bundles: list[VcfRegistryBundle],
    interface_names: set[str] | None = None,
    managed_dns_names: set[str] | None = None,
    ca_bundle_source: str = "local-ca",
    ca_bundle_available: bool = True,
) -> tuple[list[str], list[str]]:
    """Validate vcf registry state.

    Args:
        settings: Desired or runtime settings consumed by the operation.
        bundles: Bundles supplied by the caller.
        interface_names: Interface names supplied by the caller.
        managed_dns_names: Managed dns names supplied by the caller.
        ca_bundle_source: Ca bundle source supplied by the caller.
        ca_bundle_available: Ca bundle available supplied by the caller.

    Returns:
        The validate vcf registry state result.
    """
    errors: list[str] = []
    warnings: list[str] = []

    hostname = settings.hostname.strip()
    if not hostname or not HOSTNAME_PATTERN.match(hostname) or "." not in hostname:
        errors.append("Registry hostname must be a fully qualified DNS name.")
    if hostname.endswith(".local"):
        warnings.append("Avoid .local for VCF labs; use atlaso.internal or another non-.local internal domain.")
    if settings.enabled and managed_dns_names is not None and hostname.lower() not in managed_dns_names:
        warnings.append(f"Registry hostname {hostname} is not present in managed DNS records.")
    if settings.enabled:
        listen_interfaces = split_interfaces(settings.listen_interface)
        listen_addresses = split_addresses(settings.listen_address)
        if not listen_interfaces:
            errors.append("Listen interface is required.")
        elif interface_names is not None:
            for interface in listen_interfaces:
                if interface not in interface_names:
                    errors.append(f"Listen interface {interface} is not configured as an access physical or VLAN interface with an IP address.")
        if not listen_addresses:
            errors.append("Listen address is required.")
        for address in listen_addresses:
            try:
                ip_address(address)
            except ValueError:
                errors.append(f"Listen address {address} is not a valid IP address.")
    port = settings.port or 443
    if port < 1 or port > 65535:
        errors.append("Registry HTTPS port must be between 1 and 65535.")
    if not settings.harbor_project.strip() or not PROJECT_PATTERN.match(settings.harbor_project.strip()):
        errors.append("Harbor project must use lowercase letters, numbers, dots, underscores, or hyphens.")
    for path_label, path_value in [
        ("Registry storage path", settings.storage_path),
        ("Harbor config path", settings.config_path),
        ("CA bundle path", settings.ca_bundle_path),
    ]:
        if not path_value.startswith("/"):
            errors.append(f"{path_label} must be an absolute Linux path.")
    if not settings.server_certificate.strip():
        errors.append("Server certificate name is required.")
    if not settings.robot_account.strip():
        errors.append("Robot account name is required.")
    if settings.enabled and ca_bundle_source == "uploaded" and not ca_bundle_available:
        errors.append("Upload a CA bundle or enable the local CA before submitting VCF Private Registry through global appliance apply.")

    seen_names: set[str] = set()
    for bundle in bundles:
        name = bundle.name.strip()
        if not name:
            errors.append("Every Supervisor Service bundle needs a name.")
        elif name.lower() in seen_names:
            errors.append(f"Supervisor Service bundle {name} is duplicated.")
        seen_names.add(name.lower())
        status = bundle.status or "planned"
        target_reference = bundle.target_reference or ""
        if status not in STATUS_VALUES:
            errors.append(f"Supervisor Service bundle {name or bundle.id} has unsupported status {status}.")
        if bundle.enabled and not bundle.source_reference.strip():
            errors.append(f"Supervisor Service bundle {name or bundle.id} needs a source reference before relocation.")
        if bundle.enabled and not (target_reference.strip() or default_target_reference(settings, bundle.source_reference)):
            errors.append(f"Supervisor Service bundle {name or bundle.id} needs a target reference.")

    return errors, warnings
