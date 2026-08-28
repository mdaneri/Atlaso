"""Implement public services service behavior."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from atlaso.app.models import (
    CaSettings,
    OidcProviderSettings,
    PhysicalInterface,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
)
from atlaso.app.services.ca import CA_DEFAULT_PORTAL_HOSTNAME
from atlaso.app.services.dnsmasq import split_addresses
from atlaso.app.services.esxi_pxe import ESXI_PXE_DEFAULT_HOSTNAME
from atlaso.app.services.networking import normalize_interface_role
from atlaso.app.services.nginx import format_nginx_listen
from atlaso.app.services.vcf_offline_depot import (
    VCF_DEPOT_DEFAULT_HOSTNAME,
    VCF_DEPOT_DEFAULT_STORE_PATH,
    VCF_DEPOT_HTPASSWD_PATH,
)
from atlaso.app.services.vcf_private_registry import (
    VCF_REGISTRY_DEFAULT_HOSTNAME,
    vcf_registry_endpoint,
)

PUBLIC_SERVICES_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/public-services/atlaso-public-services.conf"
PUBLIC_SERVICES_NGINX_SITE_PATH = "/etc/atlaso/nginx/sites.d/public-services.conf"
PUBLIC_SERVICES_HTTP_PORT = 80
PUBLIC_SERVICES_UPSTREAM_HOST = "127.0.0.1"
PUBLIC_SERVICES_UPSTREAM_PORT = 8000
ESXI_PXE_HTTP_BASE = "/var/lib/atlaso/pxe/http/esxi"


def public_service_interface_entries(interfaces: list[PhysicalInterface], vlans: list[VlanInterface]) -> list[dict[str, Any]]:
    """Return public service interface entries.

    Args:
        interfaces: Interfaces consumed by public service interface entries.
        vlans: Vlans consumed by public service interface entries.
    """
    entries: list[dict[str, Any]] = []
    for interface in interfaces:
        if interface.oper_state == "missing":
            continue
        entries.extend(_entries_for_target(interface.name, interface.role, interface.ip_cidr, interface.ipv6_cidr))
    for vlan in vlans:
        if not vlan.enabled:
            continue
        entries.extend(_entries_for_target(vlan.name, vlan.role, vlan.ip_cidr, vlan.ipv6_cidr))
    return entries


def public_services_for_address(
    address: str,
    *,
    ca_settings: CaSettings,
    esxi_pxe_boot: dict[str, Any] | None,
    vcf_depot_settings: VcfOfflineDepotSettings,
    vcf_registry_settings: VcfPrivateRegistrySettings,
    oidc_settings: OidcProviderSettings | None = None,
) -> list[dict[str, Any]]:
    """Return public services for address.

    Args:
        address: Network address of the target service or interface.
        ca_settings: Ca settings supplied by the caller.
        esxi_pxe_boot: Esxi pxe boot supplied by the caller.
        vcf_depot_settings: Vcf depot settings supplied by the caller.
        vcf_registry_settings: Vcf registry settings supplied by the caller.
        oidc_settings: Oidc settings supplied by the caller.
    """
    normalized = _normalize_address(address)
    services: list[dict[str, Any]] = []
    if (
        oidc_settings
        and oidc_settings.enabled
        and normalized in _normalized_addresses(oidc_settings.listen_address)
    ):
        services.append(
            {
                "id": "oidc",
                "name": "OpenID Connect",
                "summary": "Authorization Code identity provider",
                "href": "/identity/.well-known/openid-configuration",
                "secondary_href": "",
                "secondary_label": "",
                "status": "enabled",
                "pill": "good",
                "scheme": "https",
                "port": int(oidc_settings.port or 443),
                "dns_names": _service_dns_names(oidc_settings.hostname),
            }
        )
    if ca_settings.enabled and normalized in _normalized_addresses(ca_settings.listen_address):
        services.append(
            {
                "id": "ca",
                "name": "Certificate Authority",
                "summary": "Trust material and certificate requests",
                "href": "/ca",
                "secondary_href": "",
                "secondary_label": "",
                "status": "available" if ca_settings.root_certificate_pem else "configured",
                "pill": "good" if ca_settings.root_certificate_pem else "warn",
                "scheme": "https",
                "port": 443,
                "dns_names": _service_dns_names(ca_settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME),
            }
        )
    boot = esxi_pxe_boot or {}
    if boot.get("enabled") and normalized in _normalized_addresses(str(boot.get("listen_address") or "")):
        services.append(
            {
                "id": "esxi_pxe",
                "name": "ESXi PXE",
                "summary": "HTTP boot files and Kickstart content",
                "href": "/pxe/esxi/",
                "secondary_href": "",
                "secondary_label": "",
                "status": "enabled",
                "pill": "good",
                "scheme": "http",
                "port": int(boot.get("http_port") or 8080),
                "dns_names": _service_dns_names(str(boot.get("hostname") or ESXI_PXE_DEFAULT_HOSTNAME)),
            }
        )
    if vcf_depot_settings.enabled and normalized in _normalized_addresses(vcf_depot_settings.listen_address):
        services.append(
            {
                "id": "vcf_offline_depot",
                "name": "VCF Offline Depot",
                "summary": "Static Broadcom depot mirror",
                "href": "/PROD/",
                "secondary_href": "",
                "secondary_label": "",
                "status": "enabled",
                "pill": "good",
                "scheme": "https",
                "port": int(vcf_depot_settings.port or 443),
                "allow_unauthenticated_access": bool(vcf_depot_settings.allow_unauthenticated_access),
                "http_username": vcf_depot_settings.http_user.username if vcf_depot_settings.http_user else "",
                "dns_names": _service_dns_names(vcf_depot_settings.hostname or VCF_DEPOT_DEFAULT_HOSTNAME),
            }
        )
    if vcf_registry_settings.enabled and normalized in _normalized_addresses(vcf_registry_settings.listen_address):
        services.append(
            {
                "id": "vcf_private_registry",
                "name": "VCF Private Registry",
                "summary": "Canonical Harbor registry endpoint",
                "href": f"https://{vcf_registry_endpoint(vcf_registry_settings)}",
                "secondary_href": "",
                "secondary_label": "",
                "status": "link only",
                "pill": "muted",
                "scheme": "https",
                "port": int(vcf_registry_settings.port or 443),
                "dns_names": _service_dns_names(vcf_registry_settings.hostname or VCF_REGISTRY_DEFAULT_HOSTNAME),
            }
        )
    return services


def public_service_entries(
    *,
    interfaces: list[PhysicalInterface],
    vlans: list[VlanInterface],
    ca_settings: CaSettings,
    esxi_pxe_boot: dict[str, Any] | None,
    vcf_depot_settings: VcfOfflineDepotSettings,
    vcf_registry_settings: VcfPrivateRegistrySettings,
    oidc_settings: OidcProviderSettings | None = None,
) -> list[dict[str, Any]]:
    """Return public service entries.

    Args:
        interfaces: Interfaces available to or selected by the operation.
        vlans: VLAN desired-state rows available to the operation.
        ca_settings: Ca settings supplied by the caller.
        esxi_pxe_boot: Esxi pxe boot supplied by the caller.
        vcf_depot_settings: Vcf depot settings supplied by the caller.
        vcf_registry_settings: Vcf registry settings supplied by the caller.
        oidc_settings: Oidc settings supplied by the caller.
    """
    entries: list[dict[str, Any]] = []
    for entry in public_service_interface_entries(interfaces, vlans):
        if entry["role"] == "management":
            continue
        entries.append(
            {
                **entry,
                "services": public_services_for_address(
                    entry["address"],
                    ca_settings=ca_settings,
                    esxi_pxe_boot=esxi_pxe_boot,
                    vcf_depot_settings=vcf_depot_settings,
                    vcf_registry_settings=vcf_registry_settings,
                    oidc_settings=oidc_settings,
                ),
            }
        )
    return entries


def render_public_services_nginx_config(
    entries: list[dict[str, Any]],
    *,
    upstream_host: str = PUBLIC_SERVICES_UPSTREAM_HOST,
    upstream_port: int = PUBLIC_SERVICES_UPSTREAM_PORT,
    http_port: int = PUBLIC_SERVICES_HTTP_PORT,
    https_port: int = 443,
    ca_certificate_path: str = "",
    ca_key_path: str = "",
    depot_store_path: str = VCF_DEPOT_DEFAULT_STORE_PATH,
    esxi_http_base: str = ESXI_PXE_HTTP_BASE,
    terminal_certificate_path: str = "",
    terminal_key_path: str = "",
    oidc_certificate_path: str = "",
    oidc_key_path: str = "",
    management_certificate_path: str = "",
    management_key_path: str = "",
) -> str:
    """Render public services nginx config.

    Args:
        entries: Entries supplied by the caller.
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        http_port: Http port supplied by the caller.
        https_port: Https port supplied by the caller.
        ca_certificate_path: Filesystem path for the ca certificate.
        ca_key_path: Filesystem path for the ca key.
        depot_store_path: Filesystem path for the depot store.
        esxi_http_base: Esxi http base supplied by the caller.
        terminal_certificate_path: Filesystem path for the terminal certificate.
        terminal_key_path: Filesystem path for the terminal key.
        oidc_certificate_path: Filesystem path for the oidc certificate.
        oidc_key_path: Filesystem path for the oidc key.
        management_certificate_path: Filesystem path for the appliance management certificate.
        management_key_path: Filesystem path for the appliance management private key.

    Returns:
        The rendered public services nginx config.
    """
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "# IP-scoped public service front door for non-management interfaces.",
    ]
    for entry in sorted(entries, key=lambda item: (str(item.get("interface") or ""), str(item.get("address") or ""))):
        address = str(entry.get("address") or "").strip()
        service_rows = entry.get("services") or []
        services = {str(service.get("id")) for service in service_rows}
        terminal_enabled = bool(entry.get("web_terminal"))
        management_ui_enabled = bool(
            entry.get("management_ui")
            and management_certificate_path
            and management_key_path
        )
        ip_scoped_https_emitted = False
        if not address:
            continue
        ca_service = next((service for service in service_rows if str(service.get("id")) == "ca"), None)
        oidc_service = next((service for service in service_rows if str(service.get("id")) == "oidc"), None)
        if oidc_service:
            hostnames = _service_dns_names(*(oidc_service.get("dns_names") or []))
            oidc_port = _service_port(oidc_service, https_port)
            lines.extend(
                _oidc_https_server_lines(
                    address,
                    hostnames[0] if hostnames else "",
                    certificate_path=oidc_certificate_path,
                    key_path=oidc_key_path,
                    upstream_host=upstream_host,
                    upstream_port=upstream_port,
                    https_port=oidc_port,
                    management_ui=management_ui_enabled and oidc_port == https_port,
                )
            )
        if ca_service:
            hostname = _service_dns_names(*(ca_service.get("dns_names") or []))
            lines.extend(
                _ca_https_server_lines(
                    address,
                    hostname[0] if hostname else CA_DEFAULT_PORTAL_HOSTNAME,
                    ca_certificate_path=ca_certificate_path,
                    ca_key_path=ca_key_path,
                    upstream_host=upstream_host,
                    upstream_port=upstream_port,
                    https_port=https_port,
                    management_ui=management_ui_enabled,
                )
            )
            depot_service = next((service for service in service_rows if str(service.get("id")) == "vcf_offline_depot"), None)
            if depot_service and _service_port(depot_service, https_port) == https_port:
                lines.extend(
                    _ip_scoped_https_server_lines(
                        address,
                        ca_certificate_path=ca_certificate_path,
                        ca_key_path=ca_key_path,
                        upstream_host=upstream_host,
                        upstream_port=upstream_port,
                        https_port=https_port,
                        depot_store_path=depot_store_path,
                        depot_auth_required=not bool(depot_service.get("allow_unauthenticated_access")),
                        depot_http_username=str(depot_service.get("http_username") or ""),
                        web_terminal=terminal_enabled,
                        management_ui=management_ui_enabled,
                        management_certificate_path=management_certificate_path,
                        management_key_path=management_key_path,
                    )
                )
                ip_scoped_https_emitted = True
                terminal_enabled = False
        if terminal_enabled:
            lines.extend(
                _terminal_https_server_lines(
                    address,
                    certificate_path=terminal_certificate_path,
                    key_path=terminal_key_path,
                    upstream_host=upstream_host,
                    upstream_port=upstream_port,
                    https_port=https_port,
                    management_ui=management_ui_enabled,
                    management_certificate_path=management_certificate_path,
                    management_key_path=management_key_path,
                )
            )
            ip_scoped_https_emitted = True
        if management_ui_enabled and not ip_scoped_https_emitted:
            lines.extend(
                _management_https_server_lines(
                    address,
                    certificate_path=management_certificate_path,
                    key_path=management_key_path,
                    upstream_host=upstream_host,
                    upstream_port=upstream_port,
                    https_port=https_port,
                )
            )
        if "esxi_pxe" in services:
            lines.extend(_esxi_pxe_http_server_lines(address, upstream_host, upstream_port, http_port, esxi_http_base))
    return "\n".join(lines).strip() + "\n"


def _oidc_https_server_lines(
    address: str,
    hostname: str,
    *,
    certificate_path: str,
    key_path: str,
    upstream_host: str,
    upstream_port: int,
    https_port: int,
    management_ui: bool = False,
) -> list[str]:
    """Return oidc https server lines.

    Args:
        address: Network address of the target service or interface.
        hostname: DNS hostname of the target resource.
        certificate_path: Filesystem path for the certificate.
        key_path: Filesystem path for the key.
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        https_port: Https port supplied by the caller.
        management_ui: Whether the management front door is cohosted on this access address and port.
    """
    return [
        "",
        "server {",
        "  # OIDC HTTPS front door.",
        f"  listen {format_nginx_listen(address, https_port)} ssl;",
        f"  server_name {hostname};",
        f"  ssl_certificate {certificate_path};",
        f"  ssl_certificate_key {key_path};",
        "",
        *_proxy_location("^~ /identity/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_management_or_not_found_location(management_ui, upstream_host, upstream_port),
        "}",
    ]


def _ca_https_server_lines(
    address: str,
    hostname: str,
    *,
    ca_certificate_path: str,
    ca_key_path: str,
    upstream_host: str,
    upstream_port: int,
    https_port: int,
    management_ui: bool = False,
) -> list[str]:
    """Return ca https server lines.

    Args:
        address: Network address of the target service or interface.
        hostname: DNS hostname of the target resource.
        ca_certificate_path: Filesystem path for the ca certificate.
        ca_key_path: Filesystem path for the ca key.
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        https_port: Https port supplied by the caller.
        management_ui: Whether the management front door is cohosted on this access address.
    """
    return [
        "",
        "server {",
        "  # CA portal HTTPS front door.",
        f"  listen {format_nginx_listen(address, https_port)} ssl;",
        f"  server_name {hostname};",
        f"  ssl_certificate {ca_certificate_path};",
        f"  ssl_certificate_key {ca_key_path};",
        "  client_max_body_size 1g;",
        "",
        *_proxy_location("= /", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /ui/public", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /ui/public/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /ca", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /ca/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /requests", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /requests/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /static/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /favicon.ico", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_management_or_not_found_location(management_ui, upstream_host, upstream_port),
        "}",
    ]


def _ip_scoped_https_server_lines(
    address: str,
    *,
    ca_certificate_path: str,
    ca_key_path: str,
    upstream_host: str,
    upstream_port: int,
    https_port: int,
    depot_store_path: str,
    depot_auth_required: bool,
    depot_http_username: str,
    web_terminal: bool = False,
    management_ui: bool = False,
    management_certificate_path: str = "",
    management_key_path: str = "",
) -> list[str]:
    """Return ip scoped https server lines.

    Args:
        address: Network address of the target service or interface.
        ca_certificate_path: Filesystem path for the ca certificate.
        ca_key_path: Filesystem path for the ca key.
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        https_port: Https port supplied by the caller.
        depot_store_path: Filesystem path for the depot store.
        depot_auth_required: Depot auth required supplied by the caller.
        depot_http_username: Depot http username supplied by the caller.
        web_terminal: Web terminal supplied by the caller.
        management_ui: Whether the management namespace is cohosted on this access address.
        management_certificate_path: Filesystem path for the appliance management certificate.
        management_key_path: Filesystem path for the appliance management private key.
    """
    return [
        "",
        "server {",
        "  # IP-scoped HTTPS public services front door.",
        f"  listen {format_nginx_listen(address, https_port)} ssl;",
        f"  server_name {_nginx_server_name(address)};",
        f"  ssl_certificate {management_certificate_path if management_ui else ca_certificate_path};",
        f"  ssl_certificate_key {management_key_path if management_ui else ca_key_path};",
        "  client_max_body_size 1g;",
        "",
        *_proxy_location("= /", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /ui/public", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /ui/public/", upstream_host, upstream_port, forwarded_proto="https"),
        *(_management_ui_proxy_locations(upstream_host, upstream_port) if management_ui else []),
        "",
        *_proxy_location("= /ca", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /ca/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /requests", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /requests/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /static/", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /favicon.ico", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_depot_https_location_lines(
            upstream_host,
            upstream_port,
            depot_store_path=depot_store_path,
            auth_required=depot_auth_required,
            http_username=depot_http_username,
        ),
        *(["", *_terminal_proxy_locations(upstream_host, upstream_port, include_static=False)] if web_terminal else []),
        "",
        *_management_or_not_found_location(management_ui, upstream_host, upstream_port),
        "}",
    ]


def _terminal_proxy_locations(upstream_host: str, upstream_port: int, *, include_static: bool = True) -> list[str]:
    """Return terminal proxy locations.

    Args:
        upstream_host: Upstream host consumed by terminal proxy locations.
        upstream_port: Upstream port consumed by terminal proxy locations.
        include_static: Whether include static applies to the operation.
    """
    paths = ["= /login", "= /logout", "= /terminal", "= /terminal/tickets"]
    if include_static:
        paths.append("^~ /static/")
    lines: list[str] = []
    for path in paths:
        lines.extend([*_proxy_location(path, upstream_host, upstream_port, forwarded_proto="https"), ""])
    lines.extend(
        _proxy_location(
            "= /terminal/ws",
            upstream_host,
            upstream_port,
            forwarded_proto="https",
            extra_directives=["    proxy_set_header Upgrade $http_upgrade;", '    proxy_set_header Connection "upgrade";'],
        )
    )
    return lines


def _terminal_https_server_lines(
    address: str,
    *,
    certificate_path: str,
    key_path: str,
    upstream_host: str,
    upstream_port: int,
    https_port: int,
    management_ui: bool = False,
    management_certificate_path: str = "",
    management_key_path: str = "",
) -> list[str]:
    """Return terminal https server lines.

    Args:
        address: Network address of the target service or interface.
        certificate_path: Filesystem path for the certificate.
        key_path: Filesystem path for the key.
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        https_port: Https port supplied by the caller.
        management_ui: Whether the management namespace is cohosted on this access address.
        management_certificate_path: Filesystem path for the appliance management certificate.
        management_key_path: Filesystem path for the appliance management private key.
    """
    return [
        "",
        "server {",
        "  # Terminal-only HTTPS front door.",
        f"  listen {format_nginx_listen(address, https_port)} ssl;",
        f"  server_name {_nginx_server_name(address)};",
        f"  ssl_certificate {management_certificate_path if management_ui else certificate_path};",
        f"  ssl_certificate_key {management_key_path if management_ui else key_path};",
        "",
        *_proxy_location("= /", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /ui/public", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("^~ /ui/public/", upstream_host, upstream_port, forwarded_proto="https"),
        *(_management_ui_proxy_locations(upstream_host, upstream_port) if management_ui else []),
        "",
        *_proxy_location("= /favicon.ico", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_terminal_proxy_locations(upstream_host, upstream_port),
        "",
        *_management_or_not_found_location(management_ui, upstream_host, upstream_port),
        "}",
    ]


def _management_https_server_lines(
    address: str,
    *,
    certificate_path: str,
    key_path: str,
    upstream_host: str,
    upstream_port: int,
    https_port: int,
) -> list[str]:
    """Return the IP-scoped management front door for a flagged access address.

    Args:
        address: Network address of the flagged access interface.
        certificate_path: Filesystem path for the appliance management certificate.
        key_path: Filesystem path for the appliance management private key.
        upstream_host: Atlaso application host receiving proxied requests.
        upstream_port: Atlaso application port receiving proxied requests.
        https_port: HTTPS port for the management listener.
    """
    return [
        "",
        "server {",
        "  # IP-scoped management HTTPS front door.",
        f"  listen {format_nginx_listen(address, https_port)} ssl;",
        f"  server_name {_nginx_server_name(address)};",
        f"  ssl_certificate {certificate_path};",
        f"  ssl_certificate_key {key_path};",
        "  client_max_body_size 1g;",
        "",
        *_proxy_location(
            "= /terminal/ws",
            upstream_host,
            upstream_port,
            forwarded_proto="https",
            extra_directives=[
                "    proxy_set_header Upgrade $http_upgrade;",
                '    proxy_set_header Connection "upgrade";',
            ],
        ),
        *_management_ui_proxy_locations(upstream_host, upstream_port),
        "",
        *_proxy_location("/", upstream_host, upstream_port, forwarded_proto="https"),
        "}",
    ]


def _management_or_not_found_location(
    management_ui: bool,
    upstream_host: str,
    upstream_port: int,
) -> list[str]:
    """Return a complete management fallback or a closed public-service fallback.

    Args:
        management_ui: Whether the listener exposes the management front door.
        upstream_host: Atlaso application host receiving proxied requests.
        upstream_port: Atlaso application port receiving proxied requests.
    """
    if management_ui:
        return _proxy_location("/", upstream_host, upstream_port, forwarded_proto="https")
    return ["  location / {", "    return 404;", "  }"]


def _management_ui_proxy_locations(upstream_host: str, upstream_port: int) -> list[str]:
    """Return proxy locations for a management UI cohosted on an access listener.

    Args:
        upstream_host: Atlaso application host receiving proxied browser requests.
        upstream_port: Atlaso application port receiving proxied browser requests.
    """
    return [
        "",
        *_proxy_location("= /ui/management", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location(
            "= /ui/management/terminal/ws",
            upstream_host,
            upstream_port,
            forwarded_proto="https",
            extra_directives=[
                "    proxy_set_header Upgrade $http_upgrade;",
                '    proxy_set_header Connection "upgrade";',
            ],
        ),
        "",
        *_proxy_location("^~ /ui/management/", upstream_host, upstream_port, forwarded_proto="https"),
    ]


def _depot_https_location_lines(
    upstream_host: str,
    upstream_port: int,
    *,
    depot_store_path: str,
    auth_required: bool,
    http_username: str,
) -> list[str]:
    """Return depot https location lines.

    Args:
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        depot_store_path: Filesystem path for the depot store.
        auth_required: Auth required supplied by the caller.
        http_username: Http username supplied by the caller.
    """
    return [
        f"  # Atlaso VCF Offline Depot user: {http_username}" if auth_required else "  # Atlaso VCF Offline Depot unauthenticated access: true",
        "  location = /PROD {",
        "    return 301 /PROD/;",
        "  }",
        "",
        *_proxy_location("= /PROD/login", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /PROD/logout", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        "  location = /_atlaso_depot_auth {",
        "    internal;",
        f"    proxy_pass http://{upstream_host}:{upstream_port}/PROD/auth-check;",
        "    proxy_pass_request_body off;",
        "    proxy_set_header Content-Length \"\";",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Original-URI $request_uri;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /_atlaso_depot_login {",
        "    internal;",
        f"    proxy_pass http://{upstream_host}:{upstream_port}/PROD/auth-failure;",
        "    proxy_pass_request_body off;",
        "    proxy_set_header Content-Length \"\";",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Original-URI $request_uri;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /PROD/ {",
        *(
            [
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {VCF_DEPOT_HTPASSWD_PATH};",
                "    auth_request /_atlaso_depot_auth;",
                "    error_page 401 = /_atlaso_depot_login;",
            ]
            if auth_required
            else []
        ),
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_http_version 1.1;",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "    proxy_set_header X-Atlaso-Depot-Basic-User $remote_user;",
        "  }",
        "",
        "  location ~ ^/PROD/.*/$ {",
        *(
            [
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {VCF_DEPOT_HTPASSWD_PATH};",
                "    auth_request /_atlaso_depot_auth;",
                "    error_page 401 = /_atlaso_depot_login;",
            ]
            if auth_required
            else []
        ),
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_http_version 1.1;",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "    proxy_set_header X-Atlaso-Depot-Basic-User $remote_user;",
        "  }",
        "",
        "  location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {",
        *(
            [
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {VCF_DEPOT_HTPASSWD_PATH};",
                "    auth_request /_atlaso_depot_auth;",
                "    error_page 401 = /_atlaso_depot_login;",
            ]
            if auth_required
            else []
        ),
        f"    alias {depot_store_path.rstrip('/')}/PROD/$1;",
        "    sendfile on;",
        "    tcp_nopush on;",
        "    directio 8m;",
        "    autoindex off;",
        "    types { }",
        "    default_type application/octet-stream;",
        "  }",
    ]


def _esxi_pxe_http_server_lines(address: str, upstream_host: str, upstream_port: int, http_port: int, esxi_http_base: str) -> list[str]:
    """Return esxi pxe http server lines.

    Args:
        address: Network address of the target service or interface.
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        http_port: Http port supplied by the caller.
        esxi_http_base: Esxi http base supplied by the caller.
    """
    return [
        "",
        "server {",
        f"  listen {format_nginx_listen(address, http_port)};",
        f"  server_name {_nginx_server_name(address)};",
        "  client_max_body_size 1g;",
        "",
        *_proxy_location("= /pxe/boot.ipxe", upstream_host, upstream_port, preserve_host_port=True),
        "",
        *_proxy_location(
            "/pxe/inventory/",
            upstream_host,
            upstream_port,
            extra_directives=["    client_max_body_size 256k;"],
            preserve_host_port=True,
        ),
        "",
        *_proxy_location("/pxe/media/", upstream_host, upstream_port, preserve_host_port=True),
        "",
        *_proxy_location(
            "/pxe/esxi/ks/",
            upstream_host,
            upstream_port,
            extra_directives=["    access_log off;"],
            preserve_host_port=True,
        ),
        "",
        *_proxy_location(
            "/pxe/esxi/claim/",
            upstream_host,
            upstream_port,
            extra_directives=["    access_log off;"],
            preserve_host_port=True,
        ),
        "",
        *_proxy_location("= /pxe/esxi/boot.ipxe", upstream_host, upstream_port, preserve_host_port=True),
        "",
        "  location = /pxe/esxi {",
        "    return 301 /pxe/esxi/;",
        "  }",
        "",
        "  location = /pxe/esxi/ {",
        "    default_type text/plain;",
        '    return 200 "Atlaso ESXi PXE HTTP root\\n";',
        "  }",
        "",
        "  location /pxe/esxi/attempts/ {",
        "    access_log off;",
        f"    alias {esxi_http_base.rstrip('/')}/attempts/;",
        "    autoindex off;",
        "  }",
        "",
        "  location /pxe/esxi/ {",
        f"    alias {esxi_http_base.rstrip('/')}/;",
        "    autoindex off;",
        "  }",
        "",
        "  location / {",
        "    return 404;",
        "  }",
        "}",
    ]


def _entries_for_target(name: str, role: str, *cidrs: str | None) -> list[dict[str, str]]:
    """Return entries for target.

    Args:
        name: Stable name identifying the resource or operation.
        role: Role consumed by entries for target.
        *cidrs: Additional positional arguments accepted by the callable.
    """
    entries: list[dict[str, str]] = []
    normalized_role = normalize_interface_role(role)
    for cidr in cidrs:
        address = _address_from_cidr(cidr)
        if not address:
            continue
        entries.append({"interface": name, "role": normalized_role, "address": address})
    return entries


def _address_from_cidr(value: str | None) -> str:
    """Return address from cidr.

    Args:
        value: Candidate value consumed by address from CIDR.
    """
    if not value:
        return ""
    try:
        return str(ip_address(str(value).split("/", 1)[0].strip())).lower()
    except ValueError:
        return ""


def _normalize_address(value: str) -> str:
    """Normalize address.

    Args:
        value: Candidate value consumed by normalize address.


    Returns:
        The normalize address result.
    """
    try:
        return str(ip_address(value.strip().strip("[]"))).lower()
    except ValueError:
        return value.strip().strip("[]").lower()


def _normalized_addresses(value: str | None) -> set[str]:
    """Return normalized addresses.

    Args:
        value: Candidate value consumed by normalized addresses.
    """
    return {_normalize_address(address) for address in split_addresses(value)}


def _service_dns_names(*values: str | None) -> list[str]:
    """Return service dns names.

    Args:
        *values: Additional positional arguments accepted by the callable.
    """
    names: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = (value or "").strip().strip(".").lower()
        if not candidate or candidate in seen:
            continue
        names.append(candidate)
        seen.add(candidate)
    return names


def _service_port(service: dict[str, Any], default: int) -> int:
    """Return service port.

    Args:
        service: Atlaso or host service affected by the operation.
        default: Default consumed by service port.
    """
    try:
        return int(service.get("port") or default)
    except (TypeError, ValueError):
        return default


def _nginx_server_name(address: str) -> str:
    """Return nginx server name.

    Args:
        address: Network address contacted or validated by the operation.
    """
    normalized = _normalize_address(address)
    try:
        parsed = ip_address(normalized)
    except ValueError:
        return "_"
    return f"_ {normalized}" if parsed.version == 4 else "_"


def _proxy_location(
    path: str,
    upstream_host: str,
    upstream_port: int,
    *,
    forwarded_proto: str = "http",
    extra_directives: list[str] | None = None,
    preserve_host_port: bool = False,
) -> list[str]:
    """Return proxy location.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        upstream_host: Hostname or address of the upstream service.
        upstream_port: Port of the upstream service.
        forwarded_proto: Forwarded proto supplied by the caller.
        extra_directives: Extra directives supplied by the caller.
        preserve_host_port: Preserve host port supplied by the caller.
    """
    return [
        f"  location {path} {{",
        *(extra_directives or []),
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_http_version 1.1;",
        f"    proxy_set_header Host {'$http_host' if preserve_host_port else '$host'};",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        f"    proxy_set_header X-Forwarded-Proto {forwarded_proto};",
        "    proxy_set_header X-Atlaso-Listener-Address $server_addr;",
        "  }",
    ]
