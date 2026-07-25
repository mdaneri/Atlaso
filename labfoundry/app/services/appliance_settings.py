import json
import re
import subprocess
from ipaddress import ip_address, ip_interface
from typing import Any

from labfoundry.app.models import ApplianceSettings, PhysicalInterface, VlanInterface
from labfoundry.app.services.dnsmasq import split_servers
from labfoundry.app.services.networking import normalize_interface_mode, normalize_interface_role, normalize_ipv4_method


APPLIANCE_SETTINGS_DEFAULT_FQDN = "labfoundry.labfoundry.internal"
APPLIANCE_SETTINGS_DEFAULT_EXTERNAL_DNS_SERVERS = "1.1.1.1\n9.9.9.9"
APPLIANCE_SETTINGS_STAGED_CONFIG_PATH = "/var/lib/labfoundry/apply/appliance-settings/labfoundry-settings.json"
APPLIANCE_DNS_RECORD_DESCRIPTION = "LabFoundry app-owned appliance FQDN record."
SERVICE_DNS_TARGET_NAMING_CHOICES = ("ip", "interface")
SERVICE_DNS_TARGET_NAMING_DEFAULT = "ip"
RESOLVER_MODE_LOCAL_DNS = "local_dns"
RESOLVER_MODE_EXTERNAL = "external"
RESOLVER_MODE_DHCP = "dhcp"
MANAGEMENT_UI_PORT = 8000
MANAGEMENT_UI_PUBLIC_HTTP_PORT = 80
MANAGEMENT_UI_PUBLIC_HTTPS_PORT = 443
MANAGEMENT_UI_UPSTREAM_HOST = "127.0.0.1"

HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def appliance_settings_to_dict(settings: ApplianceSettings) -> dict[str, Any]:
    return {
        "id": settings.id,
        "fqdn": settings.fqdn,
        "management_https_enabled": settings.management_https_enabled,
        "web_terminal_enabled": settings.web_terminal_enabled,
        "web_terminal_interfaces": web_terminal_interfaces_from_json(settings.web_terminal_interfaces_json),
        "root_ssh_enabled": settings.root_ssh_enabled,
        "vmware_ceip_enabled": settings.vmware_ceip_enabled,
        "service_dns_target_naming": normalize_service_dns_target_naming(settings.service_dns_target_naming),
        "external_dns_servers": split_servers(settings.external_dns_servers),
        "config_path": settings.config_path,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else "",
    }


def web_terminal_interfaces_from_json(value: str | None) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    result: list[str] = []
    for item in parsed:
        name = str(item or "").strip()
        if name and name not in result:
            result.append(name)
    return result


def web_terminal_interfaces_to_json(values: list[str]) -> str:
    normalized: list[str] = []
    for value in values:
        name = str(value or "").strip()
        if name and name not in normalized:
            normalized.append(name)
    return json.dumps(normalized)


def web_terminal_interface_options(
    interfaces: list[PhysicalInterface],
    vlans: list[VlanInterface],
) -> list[dict[str, Any]]:
    options: list[dict[str, Any]] = []
    parents = {interface.name: interface for interface in interfaces}
    management_name = management_interface_context(interfaces).get("name", "")
    for interface in interfaces:
        role = normalize_interface_role(interface.role)
        mode = normalize_interface_mode(interface.mode)
        ipv4_cidr = interface.host_ip_cidr if normalize_ipv4_method(interface.ipv4_method) == "dhcp" else interface.ip_cidr
        addresses = _interface_addresses(ipv4_cidr, interface.ipv6_cidr)
        if interface.oper_state == "missing" or interface.admin_state != "up" or role == "unused" or mode == "trunk" or not addresses:
            continue
        options.append(
            {
                "name": interface.name,
                "kind": "physical",
                "role": role,
                "addresses": addresses,
                "web_terminal_allowed": role != "management" or interface.name == management_name,
                "label": f"{interface.name} - {role} / {' / '.join(addresses)}",
            }
        )
    for vlan in vlans:
        parent = parents.get(vlan.parent_interface)
        role = normalize_interface_role(vlan.role)
        addresses = _interface_addresses(vlan.ip_cidr, vlan.ipv6_cidr)
        if (
            not vlan.enabled
            or role == "unused"
            or not addresses
            or parent is None
            or parent.oper_state == "missing"
            or parent.admin_state != "up"
        ):
            continue
        options.append(
            {
                "name": vlan.name,
                "kind": "vlan",
                "role": role,
                "addresses": addresses,
                "web_terminal_allowed": role != "management",
                "label": f"{vlan.name} - VLAN {vlan.vlan_id} on {vlan.parent_interface} / {role} / {' / '.join(addresses)}",
            }
        )
    return options


def normalized_web_terminal_interfaces(settings: ApplianceSettings, management_interface: dict[str, str]) -> list[str]:
    selected = web_terminal_interfaces_from_json(settings.web_terminal_interfaces_json)
    management_name = str(management_interface.get("name") or "")
    if settings.web_terminal_enabled and management_name:
        selected = [management_name, *[name for name in selected if name != management_name]]
    return selected


def web_terminal_addresses(selected: list[str], options: list[dict[str, Any]]) -> list[str]:
    by_name = {str(option["name"]): option for option in options}
    addresses: list[str] = []
    for name in selected:
        for address in by_name.get(name, {}).get("addresses", []):
            if address and address not in addresses:
                addresses.append(address)
    return addresses


def web_terminal_listener_interfaces(
    selected: list[str],
    options: list[dict[str, Any]],
) -> list[str]:
    by_name = {str(option.get("name") or ""): option for option in options}
    return [
        name
        for name in selected
        if name in by_name and bool(by_name[name].get("web_terminal_allowed", True))
    ]


def _interface_addresses(ipv4_cidr: str | None, ipv6_cidr: str | None) -> list[str]:
    result: list[str] = []
    for value in (ipv4_cidr, ipv6_cidr):
        if not value:
            continue
        try:
            address = str(ip_interface(value).ip)
        except ValueError:
            continue
        if address not in result:
            result.append(address)
    return result


def normalize_fqdn(value: str) -> str:
    return value.strip().strip(".").lower()


def normalize_multiline_values(value: str) -> str:
    return "\n".join(split_servers(value))


def normalize_service_dns_target_naming(value: str | None) -> str:
    normalized = (value or "").strip().lower().replace("_", "-")
    if normalized in SERVICE_DNS_TARGET_NAMING_CHOICES:
        return normalized
    return SERVICE_DNS_TARGET_NAMING_DEFAULT


def is_app_owned_appliance_dns_record(description: str | None) -> bool:
    return APPLIANCE_DNS_RECORD_DESCRIPTION in (description or "")


def resolver_mode_for_settings(
    *,
    local_dns_enabled: bool,
    management_interface: dict[str, str],
    external_servers: list[str],
) -> str:
    if local_dns_enabled:
        return RESOLVER_MODE_LOCAL_DNS
    if not external_servers and management_interface.get("ipv4_method") == "dhcp":
        return RESOLVER_MODE_DHCP
    return RESOLVER_MODE_EXTERNAL


def parse_resolvectl_dns_servers(output: str) -> list[str]:
    servers: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        for token in re.split(r"[\s,]+", line.strip()):
            candidate = token.strip("[](),;")
            if not candidate:
                continue
            candidate = candidate.split("#", 1)[0].split("%", 1)[0]
            try:
                parsed = ip_address(candidate)
            except ValueError:
                continue
            if parsed.is_loopback:
                continue
            server = str(parsed)
            if server in seen:
                continue
            seen.add(server)
            servers.append(server)
    return servers


def observed_management_dhcp_dns_servers(interface_name: str) -> list[str]:
    if not interface_name:
        return []
    try:
        result = subprocess.run(
            ["resolvectl", "dns", interface_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    return parse_resolvectl_dns_servers(result.stdout)


def management_dhcp_dns_context(interfaces: list[PhysicalInterface]) -> tuple[dict[str, str], list[str]]:
    management = management_interface_context(interfaces)
    if management.get("ipv4_method") != "dhcp":
        return management, []
    servers = []
    seen: set[str] = set()
    for server in observed_management_dhcp_dns_servers(management.get("name", "")):
        try:
            parsed = ip_address(server)
        except ValueError:
            continue
        if parsed.is_loopback:
            continue
        normalized = str(parsed)
        if normalized in seen:
            continue
        seen.add(normalized)
        servers.append(normalized)
    return management, servers


def management_interface_context(interfaces: list[PhysicalInterface]) -> dict[str, Any]:
    candidates = [interface for interface in interfaces if interface.role == "management"] + [
        interface for interface in interfaces if interface.name == "eth0"
    ]
    seen: set[str] = set()
    for interface in candidates:
        if interface.name in seen:
            continue
        seen.add(interface.name)
        ipv4_cidr = interface.host_ip_cidr if normalize_ipv4_method(interface.ipv4_method) == "dhcp" else interface.ip_cidr
        ipv6_cidr = (interface.ipv6_cidr or interface.host_ipv6_cidr) if interface.ipv6_enabled else None
        addresses: list[str] = []
        for candidate_cidr in (ipv4_cidr, ipv6_cidr):
            if not candidate_cidr:
                continue
            try:
                parsed = ip_interface(candidate_cidr)
            except ValueError:
                continue
            if parsed.ip.is_link_local:
                continue
            address = str(parsed.ip)
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            continue
        return {
            "name": interface.name,
            "ip": addresses[0],
            "ip_cidr": ipv4_cidr or ipv6_cidr or "",
            "ipv4_cidr": ipv4_cidr or "",
            "ipv6_cidr": ipv6_cidr or "",
            "addresses": addresses,
            "ipv4_method": normalize_ipv4_method(interface.ipv4_method),
        }
    return {"name": "", "ip": "", "ip_cidr": "", "ipv4_cidr": "", "ipv6_cidr": "", "addresses": [], "ipv4_method": "static"}


def validate_appliance_settings(
    settings: ApplianceSettings,
    *,
    local_dns_enabled: bool,
    management_interface: dict[str, str],
    dns_record_conflict: bool = False,
    ca_enabled: bool = False,
    management_https_cert_available: bool = False,
    web_terminal_options: list[dict[str, Any]] | None = None,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    fqdn = normalize_fqdn(settings.fqdn)
    if not fqdn:
        errors.append("Appliance FQDN is required.")
    elif not HOSTNAME_PATTERN.fullmatch(fqdn):
        errors.append("Appliance FQDN must be a valid fully qualified DNS name.")

    external_servers = split_servers(settings.external_dns_servers)
    resolver_mode = resolver_mode_for_settings(
        local_dns_enabled=local_dns_enabled,
        management_interface=management_interface,
        external_servers=external_servers,
    )
    if resolver_mode == RESOLVER_MODE_EXTERNAL and not external_servers:
        errors.append("External DNS servers are required when local DNS is disabled.")
    for server in external_servers:
        try:
            ip_address(server)
        except ValueError:
            errors.append(f"External DNS server {server} must be a valid IPv4 or IPv6 address.")

    if local_dns_enabled and not management_interface.get("ip"):
        errors.append("Local DNS registration requires a management interface or eth0 with a valid IP CIDR.")
    if dns_record_conflict:
        errors.append("The appliance FQDN already has a user-owned DNS A/AAAA record. Rename it or remove that record before autosave can manage the appliance record.")
    if settings.management_https_enabled:
        if not ca_enabled:
            errors.append("Management UI HTTPS requires the local LabFoundry CA to be enabled.")
        elif not management_https_cert_available:
            errors.append("Management UI HTTPS requires an issued CA-managed appliance HTTPS certificate. Apply the CA unit first.")
    selected_terminal_interfaces = normalized_web_terminal_interfaces(settings, management_interface)
    terminal_options = web_terminal_options or []
    options_by_name = {str(option.get("name") or ""): option for option in terminal_options}
    option_names = set(options_by_name)
    if settings.web_terminal_enabled:
        if not settings.management_https_enabled:
            errors.append("Web terminal access requires Management UI HTTPS.")
        management_name = str(management_interface.get("name") or "")
        if not management_name or management_name not in selected_terminal_interfaces:
            errors.append("Web terminal access requires the management interface.")
        missing = [name for name in selected_terminal_interfaces if name not in option_names]
        if missing:
            errors.append(f"Web terminal interfaces are unavailable or have no address: {', '.join(missing)}.")
        disallowed = [
            name
            for name in selected_terminal_interfaces
            if name in option_names
            and not bool(options_by_name[name].get("web_terminal_allowed", True))
        ]
        if disallowed:
            errors.append(f"Additional Web terminal interfaces cannot use the management role: {', '.join(disallowed)}.")
    if not settings.config_path.startswith("/"):
        errors.append("Appliance settings config path must be absolute.")
    raw_target_naming = (settings.service_dns_target_naming or "").strip().lower().replace("_", "-")
    if raw_target_naming and raw_target_naming not in SERVICE_DNS_TARGET_NAMING_CHOICES:
        errors.append("Service DNS target names must be generated from either IP addresses or interface names.")
    if local_dns_enabled:
        warnings.append("Local DNS is enabled, so appliance resolver apply will point management DNS at 127.0.0.1.")
    elif resolver_mode == RESOLVER_MODE_DHCP:
        warnings.append("Management IPv4 uses DHCP and no external DNS servers are set, so appliance resolver apply will keep DHCP-provided DNS.")
    return errors, warnings


def appliance_settings_preview_payload(
    settings: ApplianceSettings,
    *,
    local_dns_enabled: bool,
    management_interface: dict[str, str],
    management_https_cert_path: str = "",
    management_https_key_path: str = "",
    web_terminal_options: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    external_servers = split_servers(settings.external_dns_servers)
    resolver_mode = resolver_mode_for_settings(
        local_dns_enabled=local_dns_enabled,
        management_interface=management_interface,
        external_servers=external_servers,
    )
    resolver_servers = ["127.0.0.1"] if local_dns_enabled else external_servers
    selected_terminal_interfaces = normalized_web_terminal_interfaces(settings, management_interface)
    payload = {
        "fqdn": normalize_fqdn(settings.fqdn),
        "resolver_mode": resolver_mode,
        "resolver_servers": resolver_servers,
        "local_dns_enabled": local_dns_enabled,
        "management_interface": management_interface.get("name", ""),
        "management_ip": management_interface.get("ip", ""),
        "management_ip_cidr": management_interface.get("ip_cidr", ""),
        "management_https_enabled": bool(settings.management_https_enabled),
        "web_terminal_enabled": bool(settings.web_terminal_enabled),
        "web_terminal_interfaces": selected_terminal_interfaces,
        "web_terminal_addresses": web_terminal_addresses(selected_terminal_interfaces, web_terminal_options or []),
        "root_ssh_enabled": bool(settings.root_ssh_enabled),
        "vmware_ceip_enabled": bool(settings.vmware_ceip_enabled),
        "service_dns_target_naming": normalize_service_dns_target_naming(settings.service_dns_target_naming),
        "management_http_port": MANAGEMENT_UI_PORT,
        "management_public_http_port": MANAGEMENT_UI_PUBLIC_HTTP_PORT,
        "management_public_https_port": MANAGEMENT_UI_PUBLIC_HTTPS_PORT,
        "management_upstream_host": MANAGEMENT_UI_UPSTREAM_HOST,
        "management_upstream_port": MANAGEMENT_UI_PORT,
        "management_https_cert_path": management_https_cert_path if settings.management_https_enabled else "",
        "management_https_key_path": management_https_key_path if settings.management_https_enabled else "",
    }
    return payload


def render_appliance_settings_config(
    settings: ApplianceSettings,
    *,
    local_dns_enabled: bool,
    management_interface: dict[str, str],
    management_https_cert_path: str = "",
    management_https_key_path: str = "",
    web_terminal_options: list[dict[str, Any]] | None = None,
) -> str:
    payload = appliance_settings_preview_payload(
        settings,
        local_dns_enabled=local_dns_enabled,
        management_interface=management_interface,
        management_https_cert_path=management_https_cert_path,
        management_https_key_path=management_https_key_path,
        web_terminal_options=web_terminal_options,
    )
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
