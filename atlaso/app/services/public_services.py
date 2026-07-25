from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from atlaso.app.models import CaSettings, PhysicalInterface, VcfOfflineDepotSettings, VcfPrivateRegistrySettings, VlanInterface
from atlaso.app.services.ca import CA_DEFAULT_PORTAL_HOSTNAME
from atlaso.app.services.dnsmasq import split_addresses
from atlaso.app.services.esxi_pxe import ESXI_PXE_DEFAULT_HOSTNAME
from atlaso.app.services.networking import normalize_interface_role
from atlaso.app.services.nginx import format_nginx_listen
from atlaso.app.services.vcf_offline_depot import (
    VCF_DEPOT_DEFAULT_HOSTNAME,
    VCF_DEPOT_DEFAULT_STORE_PATH,
    VCF_DEPOT_HTPASSWD_PATH,
    vcf_depot_endpoint,
)
from atlaso.app.services.vcf_private_registry import VCF_REGISTRY_DEFAULT_HOSTNAME, vcf_registry_endpoint


PUBLIC_SERVICES_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/public-services/atlaso-public-services.conf"
PUBLIC_SERVICES_NGINX_SITE_PATH = "/etc/atlaso/nginx/sites.d/public-services.conf"
PUBLIC_SERVICES_HTTP_PORT = 80
PUBLIC_SERVICES_UPSTREAM_HOST = "127.0.0.1"
PUBLIC_SERVICES_UPSTREAM_PORT = 8000
ESXI_PXE_HTTP_BASE = "/var/lib/atlaso/pxe/http/esxi"


def public_service_interface_entries(interfaces: list[PhysicalInterface], vlans: list[VlanInterface]) -> list[dict[str, Any]]:
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
) -> list[dict[str, Any]]:
    normalized = _normalize_address(address)
    services: list[dict[str, Any]] = []
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
) -> list[dict[str, Any]]:
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
) -> str:
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "# IP-scoped public service front door for non-management interfaces.",
    ]
    for entry in sorted(entries, key=lambda item: (str(item.get("interface") or ""), str(item.get("address") or ""))):
        address = str(entry.get("address") or "").strip()
        service_rows = entry.get("services") or []
        services = {str(service.get("id")) for service in service_rows}
        terminal_enabled = bool(entry.get("web_terminal"))
        if not address:
            continue
        ca_service = next((service for service in service_rows if str(service.get("id")) == "ca"), None)
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
                    )
                )
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
                )
            )
        if "esxi_pxe" in services:
            lines.extend(_esxi_pxe_http_server_lines(address, upstream_host, upstream_port, http_port, esxi_http_base))
    return "\n".join(lines).strip() + "\n"


def _ca_https_server_lines(
    address: str,
    hostname: str,
    *,
    ca_certificate_path: str,
    ca_key_path: str,
    upstream_host: str,
    upstream_port: int,
    https_port: int,
) -> list[str]:
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
        *_proxy_location("= /manifest.webmanifest", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /service-worker.js", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        "  location / {",
        "    return 404;",
        "  }",
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
) -> list[str]:
    return [
        "",
        "server {",
        "  # IP-scoped HTTPS public services front door.",
        f"  listen {format_nginx_listen(address, https_port)} ssl;",
        f"  server_name {_nginx_server_name(address)};",
        f"  ssl_certificate {ca_certificate_path};",
        f"  ssl_certificate_key {ca_key_path};",
        "  client_max_body_size 1g;",
        "",
        *_proxy_location("= /", upstream_host, upstream_port, forwarded_proto="https"),
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
        *_proxy_location("= /manifest.webmanifest", upstream_host, upstream_port, forwarded_proto="https"),
        "",
        *_proxy_location("= /service-worker.js", upstream_host, upstream_port, forwarded_proto="https"),
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
        "  location / {",
        "    return 404;",
        "  }",
        "}",
    ]


def _terminal_proxy_locations(upstream_host: str, upstream_port: int, *, include_static: bool = True) -> list[str]:
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
) -> list[str]:
    return [
        "",
        "server {",
        "  # Terminal-only HTTPS front door.",
        f"  listen {format_nginx_listen(address, https_port)} ssl;",
        f"  server_name {_nginx_server_name(address)};",
        f"  ssl_certificate {certificate_path};",
        f"  ssl_certificate_key {key_path};",
        *_terminal_proxy_locations(upstream_host, upstream_port),
        "",
        "  location / { return 404; }",
        "}",
    ]


def _depot_https_location_lines(
    upstream_host: str,
    upstream_port: int,
    *,
    depot_store_path: str,
    auth_required: bool,
    http_username: str,
) -> list[str]:
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
    return [
        "",
        "server {",
        f"  listen {format_nginx_listen(address, http_port)};",
        f"  server_name {_nginx_server_name(address)};",
        "  client_max_body_size 1g;",
        "",
        *_proxy_location("/pxe/esxi/ks/", upstream_host, upstream_port),
        "",
        *_proxy_location("= /pxe/esxi/boot.ipxe", upstream_host, upstream_port),
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
    entries: list[dict[str, str]] = []
    normalized_role = normalize_interface_role(role)
    for cidr in cidrs:
        address = _address_from_cidr(cidr)
        if not address:
            continue
        entries.append({"interface": name, "role": normalized_role, "address": address})
    return entries


def _address_from_cidr(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(ip_address(str(value).split("/", 1)[0].strip())).lower()
    except ValueError:
        return ""


def _normalize_address(value: str) -> str:
    try:
        return str(ip_address(value.strip().strip("[]"))).lower()
    except ValueError:
        return value.strip().strip("[]").lower()


def _normalized_addresses(value: str | None) -> set[str]:
    return {_normalize_address(address) for address in split_addresses(value)}


def _service_dns_names(*values: str | None) -> list[str]:
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
    try:
        return int(service.get("port") or default)
    except (TypeError, ValueError):
        return default


def _nginx_server_name(address: str) -> str:
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
) -> list[str]:
    return [
        f"  location {path} {{",
        *(extra_directives or []),
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_http_version 1.1;",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        f"    proxy_set_header X-Forwarded-Proto {forwarded_proto};",
        "    proxy_set_header X-Atlaso-Listener-Address $server_addr;",
        "  }",
    ]
