from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import DhcpReservation, DhcpScope, DnsRecord, EsxiKickstart, EsxiPxeHost, Setting, utcnow
from atlaso.app.services.dnsmasq import reservation_dns_record

ESXI_PXE_UNIT_ID = "esxi_pxe"
ESXI_PXE_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/esxi-pxe/atlaso-esxi-pxe.json"
ESXI_PXE_SCHEMA_VERSION = 2
ESXI_PXE_HTTP_BASE = Path("/var/lib/atlaso/pxe/http/esxi")
ESXI_KICKSTART_HTTP_ROOT = Path("/var/lib/atlaso/pxe/http/esxi/ks")
ESXI_KICKSTART_HTTP_PREFIX = "/pxe/esxi/ks"
ESXI_PXE_IMAGE_HTTP_ROOT = Path("/var/lib/atlaso/pxe/http/esxi/images")
ESXI_PXE_IMAGE_HTTP_PREFIX = "/pxe/esxi/images"
ESXI_IPXE_HTTP_SCRIPT_PATH = ESXI_PXE_HTTP_BASE / "boot.ipxe"
ESXI_TFTP_ROOT = Path("/var/lib/atlaso/pxe/tftp")
ESXI_INSTALLER_ISO_ROOT = Path("/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST")
ESXI_PXE_STRICT_VALIDATION_KEY = "esxi_pxe.strict_kickstart_validation"
ESXI_PXE_BOOT_ENABLED_KEY = "esxi_pxe.boot.enabled"
ESXI_PXE_HOSTNAME_KEY = "esxi_pxe.boot.hostname"
ESXI_PXE_DHCP_SCOPE_ID_KEY = "esxi_pxe.boot.dhcp_scope_id"
ESXI_PXE_DHCP_SCOPE_IDS_KEY = "esxi_pxe.boot.dhcp_scope_ids"
ESXI_PXE_LISTEN_INTERFACE_KEY = "esxi_pxe.boot.listen_interface"
ESXI_PXE_LISTEN_ADDRESS_KEY = "esxi_pxe.boot.listen_address"
ESXI_PXE_TFTP_ROOT_KEY = "esxi_pxe.boot.tftp_root"
ESXI_PXE_HTTP_PORT_KEY = "esxi_pxe.boot.http_port"
ESXI_PXE_BIOS_BOOTFILE_KEY = "esxi_pxe.boot.bios_bootfile"
ESXI_PXE_UEFI_BOOTFILE_KEY = "esxi_pxe.boot.uefi_bootfile"
ESXI_PXE_NATIVE_UEFI_HTTP_ENABLED_KEY = "esxi_pxe.boot.native_uefi_http_enabled"
ESXI_PXE_NATIVE_UEFI_HTTP_URL_KEY = "esxi_pxe.boot.native_uefi_http_url"
ESXI_PXE_IPXE_SCRIPT_KEY = "esxi_pxe.boot.ipxe_script"
ESXI_PXE_DEFAULT_HOST_ENABLED_KEY = "esxi_pxe.default_host.enabled"
ESXI_PXE_DEFAULT_HOST_KICKSTART_ID_KEY = "esxi_pxe.default_host.kickstart_id"
ESXI_PXE_DEFAULT_HOST_INSTALLER_ISO_KEY = "esxi_pxe.default_host.installer_iso_path"
ESXI_PXE_IPXE_SCRIPT_NAME = "esxi.ipxe"
ESXI_PXE_DEFAULT_HOSTNAME = "esxi-pxe.atlaso.internal"
ESXI_PXE_HTTP_PORT = 8080
ESXI_PXE_BIOS_BOOTFILE = "undionly.kpxe"
ESXI_PXE_UEFI_BOOTFILE = "snponly.efi"
ESXI_PXE_BIOS_SECOND_STAGE_BOOTFILE = "pxelinux.0"
ESXI_PXE_UEFI_SECOND_STAGE_BOOTFILE = "mboot.efi"
ESXI_PXE_NATIVE_UEFI_BOOTFILE = "mboot.efi"
ESXI_PXE_DNS_RECORD_DESCRIPTION = "Created from ESXi PXE boot endpoint."
ESXI_PXE_HOST_MANAGED_DESCRIPTION_PREFIX = "Managed by ESXi PXE host "
ESXI_KICKSTART_HASH_PATH_LENGTH = 12
DEFAULT_ESXI_KICKSTART_NAME = "ESXi install"
DEFAULT_ESXI_KICKSTART_CONTENT = """#
# Sample scripted installation file
#

# Accept the VMware End User License Agreement
vmaccepteula

# Set the root password for the DCUI and Tech Support Mode
rootpw vmware01!

# Install on the first local disk available on machine
install --firstdisk --overwritevmfs
# In case your system has DPUs, you can also specify a PCI slot:
# install --firstdisk --overwritevmfs --dpupcislots=<PCIeSlotID>

# Set the network to DHCP on the first network adapter
network --bootproto=dhcp --device=vmnic0

# A sample post-install script
%post --interpreter=python --ignorefailure=true
import time
stampFile = open('/finished.stamp', mode='w')
stampFile.write(time.asctime())
"""
SECRET_KEYWORD_PATTERN = re.compile(r"(rootpw|password|passwd|token|secret|key|license|activation|credential)", re.IGNORECASE)
UNSUPPORTED_TEMPLATE_PATTERN = re.compile(r"({[%#].*?[}%]}|\$\{[^}]+\})")
KICKSTART_VARIABLE_PATTERN = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\}\}")
KICKSTART_TEMPLATE_EXPRESSION_PATTERN = re.compile(r"\{\{\s*(.*?)\s*\}\}")
CUSTOM_VARIABLE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_ISO_UPLOAD_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]*\.iso$", re.IGNORECASE)


def normalize_kickstart_name(value: str) -> str:
    name = re.sub(r"\s+", " ", (value or "").strip())
    if not name:
        raise ValueError("Kickstart name is required.")
    if len(name) > 120:
        raise ValueError("Kickstart name must be 120 characters or fewer.")
    return name


def normalize_kickstart_content(value: str, *, max_bytes: int) -> str:
    text = (value or "").replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("\ufeff"):
        text = text[1:]
    if not text.strip():
        raise ValueError("Kickstart content is required.")
    size = len(text.encode("utf-8"))
    if size > max_bytes:
        raise ValueError(f"Kickstart content is too large. Limit is {max_bytes} bytes.")
    if not text.endswith("\n"):
        text += "\n"
    return text


def decode_kickstart_upload(raw: bytes, *, max_bytes: int) -> str:
    if len(raw) > max_bytes:
        raise ValueError(f"Kickstart upload is too large. Limit is {max_bytes} bytes.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Kickstart upload must be valid UTF-8 text.") from exc
    return normalize_kickstart_content(text, max_bytes=max_bytes)


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def kickstart_http_stem(kickstart_id: int, content_hash_value: str | None = None) -> str:
    normalized_hash = (content_hash_value or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{12,}", normalized_hash):
        return normalized_hash[:ESXI_KICKSTART_HASH_PATH_LENGTH]
    return str(kickstart_id)


def canonical_http_path(kickstart_id: int, content_hash_value: str | None = None) -> str:
    return f"{ESXI_KICKSTART_HTTP_PREFIX}/{kickstart_http_stem(kickstart_id, content_hash_value)}.cfg"


def generated_kickstart_path(kickstart_id: int, content_hash_value: str | None = None) -> Path:
    return ESXI_KICKSTART_HTTP_ROOT / f"{kickstart_http_stem(kickstart_id, content_hash_value)}.cfg"


def kickstart_url(base_url: str, http_path: str) -> str:
    if not base_url or not http_path:
        return ""
    filename = Path(http_path).name
    if not filename:
        return ""
    return f"{base_url}/ks/{filename}"


def host_kickstart_url(base_url: str, http_path: str, mac_key: str) -> str:
    url = kickstart_url(base_url, http_path)
    return f"{url}?mac={mac_key}" if url and mac_key and mac_key != "default" else url


def kickstart_requires_host_context(content: str) -> bool:
    names, invalid = kickstart_template_variables(content)
    return bool(names or invalid)


def normalize_host_variables(value: Any) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("Host variables must be a JSON object.") from exc
    if not isinstance(value, dict):
        raise ValueError("Host variables must be a JSON object.")
    normalized: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key or "").strip()
        if key.startswith("custom."):
            key = key.removeprefix("custom.")
        if key.startswith(("host.", "dhcp.", "pxe.")):
            raise ValueError(f"Host variable {raw_key} cannot override built-in variables.")
        if not CUSTOM_VARIABLE_NAME_PATTERN.fullmatch(key):
            raise ValueError(f"Host variable {raw_key} must use letters, numbers, and underscores.")
        if len(key) > 80:
            raise ValueError(f"Host variable {key} is too long.")
        if raw_value is None:
            normalized[key] = ""
        elif isinstance(raw_value, (str, int, float, bool)):
            normalized[key] = str(raw_value)
        else:
            raise ValueError(f"Host variable {key} value must be a string.")
        if len(normalized[key]) > 2048:
            raise ValueError(f"Host variable {key} value is too long.")
    if len(normalized) > 64:
        raise ValueError("Host variables are limited to 64 entries.")
    return dict(sorted(normalized.items()))


def host_variables_json(value: Any) -> str:
    return json.dumps(normalize_host_variables(value), sort_keys=True)


def host_variables(host: EsxiPxeHost) -> dict[str, str]:
    try:
        return normalize_host_variables(host.variables_json or "{}")
    except ValueError:
        return {}


def kickstart_template_variables(content: str) -> tuple[set[str], list[str]]:
    names = set(KICKSTART_VARIABLE_PATTERN.findall(content or ""))
    invalid = [
        match.group(1).strip()
        for match in KICKSTART_TEMPLATE_EXPRESSION_PATTERN.finditer(content or "")
        if not KICKSTART_VARIABLE_PATTERN.fullmatch(match.group(0))
    ]
    return names, invalid


def kickstart_has_variables(content: str) -> bool:
    names, invalid = kickstart_template_variables(content)
    return bool(names or invalid)


def ensure_installer_iso_root() -> Path:
    ESXI_INSTALLER_ISO_ROOT.mkdir(parents=True, exist_ok=True)
    return ESXI_INSTALLER_ISO_ROOT


def installer_iso_root_path() -> str:
    return str(ESXI_INSTALLER_ISO_ROOT)


def default_ipxe_script() -> str:
    return "\n".join(
        [
            "#!ipxe",
            "echo Atlaso now generates ESXi PXE boot artifacts during global appliance apply.",
            "echo Legacy custom iPXE script storage is preserved for settings compatibility only.",
            "shell",
            "",
        ]
    )


def tftp_ipxe_chain_script() -> str:
    return "\n".join(
        [
            "#!ipxe",
            "dhcp",
            "chain http://${next-server}/pxe/esxi/boot.ipxe || shell",
            "",
        ]
    )


def _ordered_unique(values) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def primary_boot_address(boot: dict[str, Any]) -> str:
    for line in str(boot.get("listen_address") or "").replace(",", "\n").splitlines():
        address = line.strip()
        if address:
            return address
    return ""


def esxi_http_base_url(boot: dict[str, Any]) -> str:
    address = primary_boot_address(boot)
    port = int(boot.get("http_port") or ESXI_PXE_HTTP_PORT)
    host = f"[{address}]" if ":" in address and not address.startswith("[") else address
    return f"http://{host}:{port}/pxe/esxi" if address else ""


def effective_native_uefi_http_url(boot: dict[str, Any]) -> str:
    configured = str(boot.get("native_uefi_http_url") or "").strip()
    if configured:
        return configured
    base_url = esxi_http_base_url(boot)
    return f"{base_url}/{ESXI_PXE_NATIVE_UEFI_BOOTFILE}" if base_url else ""


def esxi_pxe_service_state_from_boot(boot: dict[str, Any]) -> dict[str, Any]:
    enabled = bool(boot.get("enabled"))
    has_scope = bool(boot.get("dhcp_scope_ids") or boot.get("dhcp_scope_id"))
    has_address = bool(primary_boot_address(boot))
    running = enabled and has_scope and has_address
    if running:
        health = "healthy"
        label = "live"
        pill = "good"
    elif enabled:
        health = "degraded"
        label = "enabled"
        pill = "warn"
    else:
        health = "disabled"
        label = "disabled"
        pill = "muted"
    return {
        "running": running,
        "enabled": enabled,
        "health": health,
        "label": label,
        "pill": pill,
    }


def selected_dhcp_scope_payload(scope: DhcpScope) -> dict[str, Any]:
    return {
        "id": scope.id,
        "name": scope.name,
        "address_family": _dhcp_scope_address_family(scope),
        "interface_name": scope.interface_name,
        "site_address": scope.site_address,
        "prefix_length": scope.prefix_length,
        "domain_name": scope.domain_name,
        "dns_server": scope.dns_server,
        "ntp_server": scope.ntp_server,
        "gateway": scope.site_address,
    }


def _scope_network(scope: dict[str, Any]) -> Any:
    try:
        return ip_network(f"{scope.get('site_address')}/{scope.get('prefix_length')}", strict=False)
    except ValueError:
        return None


def _dhcp_scope_for_host(host: EsxiPxeHost, boot_settings: dict[str, Any]) -> dict[str, Any]:
    scopes = [scope for scope in boot_settings.get("dhcp_scopes") or [] if isinstance(scope, dict)]
    host_ip = str(host.ip_address or "").strip()
    if host_ip:
        try:
            address = ip_address(host_ip)
        except ValueError:
            address = None
        if address is not None:
            for scope in scopes:
                network = _scope_network(scope)
                if network is not None and address in network:
                    return scope
    return scopes[0] if scopes else {}


def kickstart_variable_values(
    host: EsxiPxeHost,
    boot_settings: dict[str, Any],
    vault_values: dict[str, str] | None = None,
) -> dict[str, str]:
    mac_key = normalize_pxe_mac(host.mac_address)
    scope = _dhcp_scope_for_host(host, boot_settings)
    network = _scope_network(scope)
    dns_servers = str(scope.get("dns_server") or "").replace(",", "\n")
    ntp_servers = str(scope.get("ntp_server") or "").replace(",", "\n")
    values = {
        "host.hostname": host.hostname or "",
        "host.mac": mac_key,
        "host.ip_address": host.ip_address or "",
        "dhcp.gateway": str(scope.get("gateway") or scope.get("site_address") or ""),
        "dhcp.netmask": str(network.netmask) if network is not None and network.version == 4 else "",
        "dhcp.prefix": str(scope.get("prefix_length") or ""),
        "dhcp.dns_servers": " ".join(item.strip() for item in dns_servers.splitlines() if item.strip()),
        "dhcp.ntp_servers": " ".join(item.strip() for item in ntp_servers.splitlines() if item.strip()),
        "dhcp.domain": str(scope.get("domain_name") or ""),
        "pxe.http_base_url": esxi_http_base_url(boot_settings),
    }
    for key, value in host_variables(host).items():
        values[f"custom.{key}"] = value
    for key, value in (vault_values or {}).items():
        values[f"vault.{key}"] = value
    return values


def render_kickstart_for_host(
    content: str,
    host: EsxiPxeHost,
    boot_settings: dict[str, Any],
    vault_values: dict[str, str] | None = None,
) -> str:
    names, invalid = kickstart_template_variables(content)
    if invalid:
        raise ValueError(f"Kickstart contains invalid variable marker: {invalid[0]}")
    values = kickstart_variable_values(host, boot_settings, vault_values)
    missing = sorted(name for name in names if name not in values)
    if missing:
        raise ValueError(f"Kickstart variable {missing[0]} is not defined for host {host.hostname or host.mac_address}.")

    def replace(match: re.Match[str]) -> str:
        return values[match.group(1)]

    return KICKSTART_VARIABLE_PATTERN.sub(replace, content)


def kickstart_template_validation_errors(
    kickstarts: list[EsxiKickstart],
    hosts: list[EsxiPxeHost],
    boot_settings: dict[str, Any],
    default_host: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    kickstart_by_id = {row.id: row for row in kickstarts if row.id is not None}
    for row in kickstarts:
        names, invalid = kickstart_template_variables(row.content)
        for marker in invalid:
            errors.append(f"{row.name}: variable marker {{{{{marker}}}}} is invalid.")
        if any(not name.startswith(("host.", "dhcp.", "pxe.", "custom.", "vault.")) for name in names):
            bad = sorted(name for name in names if not name.startswith(("host.", "dhcp.", "pxe.", "custom.", "vault.")))[0]
            errors.append(f"{row.name}: variable {bad} must use host., dhcp., pxe., custom., or vault.")
    default_kickstart_id = (default_host or {}).get("kickstart_id")
    default_kickstart = kickstart_by_id.get(int(default_kickstart_id)) if default_kickstart_id else None
    if default_host and default_host.get("enabled") and default_host.get("installer_iso_path") and default_kickstart:
        errors.append(f"Default ESXi PXE profile cannot use Kickstart {default_kickstart.name}; dynamic Kickstart rendering requires a defined host MAC.")
    for host in hosts:
        if host.enabled is False or not host.kickstart_id:
            continue
        kickstart = kickstart_by_id.get(host.kickstart_id)
        if not kickstart or not kickstart.enabled:
            continue
        try:
            normalize_host_variables(host.variables_json or "{}")
            marker_names = kickstart_template_variables(kickstart.content)[0]
            validation_vault_values = {
                name.removeprefix("vault."): "__atlaso_vault_value__"
                for name in marker_names
                if name.startswith("vault.")
            }
            render_kickstart_for_host(kickstart.content, host, boot_settings, validation_vault_values)
        except ValueError as exc:
            errors.append(str(exc))
    return list(dict.fromkeys(errors))


def esxi_pxe_boot_settings(db: Session) -> dict[str, Any]:
    rows = {row.key: row.value for row in db.execute(select(Setting).where(Setting.key.like("esxi_pxe.boot.%"))).scalars().all()}
    enabled = rows.get(ESXI_PXE_BOOT_ENABLED_KEY, "false").strip().lower() in {"1", "true", "yes", "on"}
    native_uefi_http_enabled = rows.get(ESXI_PXE_NATIVE_UEFI_HTTP_ENABLED_KEY, "true").strip().lower() in {"1", "true", "yes", "on"}
    dhcp_scopes = _selected_dhcp_scopes(
        db,
        rows.get(ESXI_PXE_DHCP_SCOPE_IDS_KEY),
        rows.get(ESXI_PXE_DHCP_SCOPE_ID_KEY),
        rows.get(ESXI_PXE_LISTEN_INTERFACE_KEY, ""),
        rows.get(ESXI_PXE_LISTEN_ADDRESS_KEY, ""),
    )
    dhcp_scope = dhcp_scopes[0] if dhcp_scopes else None
    listen_interface = rows.get(ESXI_PXE_LISTEN_INTERFACE_KEY, "").strip()
    listen_address = rows.get(ESXI_PXE_LISTEN_ADDRESS_KEY, "").strip()
    if dhcp_scopes:
        listen_interface = "\n".join(_ordered_unique(scope.interface_name.strip() for scope in dhcp_scopes if scope.interface_name.strip()))
        listen_address = "\n".join(_ordered_unique(scope.site_address.strip() for scope in dhcp_scopes if scope.site_address.strip()))
    settings = {
        "enabled": enabled,
        "hostname": rows.get(ESXI_PXE_HOSTNAME_KEY, ESXI_PXE_DEFAULT_HOSTNAME).strip() or ESXI_PXE_DEFAULT_HOSTNAME,
        "dhcp_scope_id": dhcp_scope.id if dhcp_scope is not None else None,
        "dhcp_scope_name": dhcp_scope.name if dhcp_scope is not None else "",
        "dhcp_scope_ids": [scope.id for scope in dhcp_scopes],
        "dhcp_scope_names": [scope.name for scope in dhcp_scopes],
        "dhcp_scopes": [selected_dhcp_scope_payload(scope) for scope in dhcp_scopes],
        "listen_interface": listen_interface,
        "listen_address": listen_address,
        "tftp_root": rows.get(ESXI_PXE_TFTP_ROOT_KEY, ESXI_TFTP_ROOT.as_posix()).strip() or ESXI_TFTP_ROOT.as_posix(),
        "http_port": _normalize_http_port(rows.get(ESXI_PXE_HTTP_PORT_KEY, str(ESXI_PXE_HTTP_PORT))),
        "bios_bootfile": _bootfile_setting(rows.get(ESXI_PXE_BIOS_BOOTFILE_KEY), default=ESXI_PXE_BIOS_BOOTFILE, legacy_defaults={"pxelinux.0"}),
        "uefi_bootfile": _bootfile_setting(rows.get(ESXI_PXE_UEFI_BOOTFILE_KEY), default=ESXI_PXE_UEFI_BOOTFILE, legacy_defaults={"bootx64.efi", "mboot.efi"}),
        "bios_second_stage_bootfile": ESXI_PXE_BIOS_SECOND_STAGE_BOOTFILE,
        "uefi_second_stage_bootfile": ESXI_PXE_UEFI_SECOND_STAGE_BOOTFILE,
        "native_uefi_bootfile": ESXI_PXE_NATIVE_UEFI_BOOTFILE,
        "native_uefi_http_enabled": native_uefi_http_enabled,
        "native_uefi_http_url": rows.get(ESXI_PXE_NATIVE_UEFI_HTTP_URL_KEY, "").strip(),
        "ipxe_script_name": ESXI_PXE_IPXE_SCRIPT_NAME,
        "ipxe_script": rows.get(ESXI_PXE_IPXE_SCRIPT_KEY, default_ipxe_script()),
        "tftp_ipxe_script": tftp_ipxe_chain_script(),
        "http_ipxe_path": "/pxe/esxi/boot.ipxe",
        "http_ipxe_generated_path": ESXI_IPXE_HTTP_SCRIPT_PATH.as_posix(),
    }
    settings["http_base_url"] = esxi_http_base_url(settings)
    settings["effective_native_uefi_http_url"] = effective_native_uefi_http_url(settings)
    settings["host_bootfiles"] = [
        {
            "mac_address": host.mac_address.strip().lower(),
            "mac_key": normalize_pxe_mac(host.mac_address),
            "tag": dnsmasq_host_tag_for_pxe_mac(host.mac_address),
            "uefi_second_stage_bootfile": f"{normalize_pxe_mac(host.mac_address)}/{settings['uefi_second_stage_bootfile']}",
            "native_uefi_http_url": f"{settings['http_base_url']}/{normalize_pxe_mac(host.mac_address)}/{settings['native_uefi_bootfile']}" if settings.get("http_base_url") else "",
        }
        for host in db.execute(select(EsxiPxeHost).order_by(EsxiPxeHost.hostname)).scalars().all()
        if host.enabled is not False and host.installer_iso_path and normalize_pxe_mac(host.mac_address)
    ]
    return settings


def save_esxi_pxe_boot_settings(
    db: Session,
    *,
    enabled: bool,
    hostname: str,
    listen_interface: str,
    listen_address: str,
    tftp_root: str,
    bios_bootfile: str,
    uefi_bootfile: str,
    dhcp_scope_id: int | str | None = None,
    dhcp_scope_ids: list[int | str] | tuple[int | str, ...] | None = None,
    http_port: int | str = ESXI_PXE_HTTP_PORT,
    ipxe_script: str | None = None,
    native_uefi_http_enabled: bool = False,
    native_uefi_http_url: str = "",
) -> dict[str, Any]:
    normalized_scopes = _normalize_dhcp_scope_selections(db, dhcp_scope_ids if dhcp_scope_ids is not None else [dhcp_scope_id] if dhcp_scope_id else [])
    if normalized_scopes:
        listen_interface = "\n".join(_ordered_unique(scope.interface_name.strip() for scope in normalized_scopes if scope.interface_name.strip()))
        listen_address = "\n".join(_ordered_unique(scope.site_address.strip() for scope in normalized_scopes if scope.site_address.strip()))
    normalized_scope_id = normalized_scopes[0].id if normalized_scopes else None
    settings = {
        ESXI_PXE_BOOT_ENABLED_KEY: "true" if enabled else "false",
        ESXI_PXE_HOSTNAME_KEY: _normalize_hostname(hostname),
        ESXI_PXE_DHCP_SCOPE_ID_KEY: str(normalized_scope_id or ""),
        ESXI_PXE_DHCP_SCOPE_IDS_KEY: "\n".join(str(scope.id) for scope in normalized_scopes),
        ESXI_PXE_LISTEN_INTERFACE_KEY: _normalize_multiline_values(listen_interface),
        ESXI_PXE_LISTEN_ADDRESS_KEY: _normalize_multiline_values(listen_address),
        ESXI_PXE_TFTP_ROOT_KEY: _normalize_tftp_root(tftp_root),
        ESXI_PXE_HTTP_PORT_KEY: str(_normalize_http_port(http_port)),
        ESXI_PXE_BIOS_BOOTFILE_KEY: _normalize_bootfile(bios_bootfile, default=ESXI_PXE_BIOS_BOOTFILE),
        ESXI_PXE_UEFI_BOOTFILE_KEY: _normalize_bootfile(uefi_bootfile, default=ESXI_PXE_UEFI_BOOTFILE),
        ESXI_PXE_NATIVE_UEFI_HTTP_ENABLED_KEY: "true" if native_uefi_http_enabled else "false",
        ESXI_PXE_NATIVE_UEFI_HTTP_URL_KEY: _normalize_native_uefi_http_url(native_uefi_http_url),
    }
    if ipxe_script is not None:
        settings[ESXI_PXE_IPXE_SCRIPT_KEY] = _normalize_ipxe_script(ipxe_script)
    existing = {row.key: row for row in db.execute(select(Setting).where(Setting.key.in_(settings))).scalars().all()}
    for key, value in settings.items():
        row = existing.get(key)
        if row is None:
            db.add(Setting(key=key, value=value))
        else:
            row.value = value
    db.flush()
    return esxi_pxe_boot_settings(db)


def _selected_dhcp_scope(db: Session, raw_scope_id: str | None, listen_interface: str, listen_address: str) -> DhcpScope | None:
    scope_id = (raw_scope_id or "").strip()
    if scope_id.isdigit():
        scope = db.get(DhcpScope, int(scope_id))
        if scope is not None and scope.enabled is not False and _dhcp_scope_address_family(scope) == "ipv4":
            return scope
    interface = next((item.strip() for item in (listen_interface or "").splitlines() if item.strip()), "")
    address = next((item.strip() for item in (listen_address or "").splitlines() if item.strip()), "")
    if not interface and not address:
        return None
    query = select(DhcpScope).order_by(DhcpScope.name)
    for scope in db.execute(query).scalars().all():
        if scope.enabled is False:
            continue
        if _dhcp_scope_address_family(scope) != "ipv4":
            continue
        if address and scope.site_address.strip() != address:
            continue
        if interface and scope.interface_name.strip() != interface:
            continue
        return scope
    return None


def _selected_dhcp_scopes(
    db: Session,
    raw_scope_ids: str | None,
    raw_scope_id: str | None,
    listen_interface: str,
    listen_address: str,
) -> list[DhcpScope]:
    try:
        scopes = _normalize_dhcp_scope_selections(db, (raw_scope_ids or "").replace(",", "\n").splitlines(), allow_empty=True)
    except ValueError:
        scopes = []
    if scopes:
        return scopes
    legacy_scope = _selected_dhcp_scope(db, raw_scope_id, listen_interface, listen_address)
    return [legacy_scope] if legacy_scope is not None else []


def _normalize_dhcp_scope_selection(db: Session, raw_scope_id: int | str | None) -> tuple[int | None, str, str]:
    value = str(raw_scope_id or "").strip()
    if not value:
        return None, "", ""
    if not value.isdigit():
        raise ValueError("ESXi PXE DHCP zone must be a valid DHCP IP zone.")
    scope = db.get(DhcpScope, int(value))
    if scope is None or scope.enabled is False:
        raise ValueError("ESXi PXE DHCP zone must be an enabled DHCP IP zone.")
    if _dhcp_scope_address_family(scope) != "ipv4":
        raise ValueError("ESXi PXE DHCP zone must be an IPv4 DHCP IP zone.")
    return scope.id, scope.interface_name.strip(), scope.site_address.strip()


def _normalize_dhcp_scope_selections(db: Session, raw_scope_ids: list[int | str] | tuple[int | str, ...], *, allow_empty: bool = False) -> list[DhcpScope]:
    scopes: list[DhcpScope] = []
    seen: set[int] = set()
    for raw_scope_id in raw_scope_ids:
        value = str(raw_scope_id or "").strip()
        if not value:
            continue
        if not value.isdigit():
            raise ValueError("ESXi PXE DHCP zones must be valid DHCP IP zones.")
        scope = db.get(DhcpScope, int(value))
        if scope is None or scope.enabled is False:
            raise ValueError("ESXi PXE DHCP zones must be enabled DHCP IP zones.")
        if _dhcp_scope_address_family(scope) != "ipv4":
            raise ValueError("ESXi PXE DHCP zones must be IPv4 DHCP IP zones.")
        if scope.id not in seen:
            scopes.append(scope)
            seen.add(scope.id)
    if not scopes and not allow_empty:
        return []
    return scopes


def _dhcp_scope_address_family(scope: DhcpScope) -> str:
    family = str(getattr(scope, "address_family", "") or "").strip().lower()
    if family in {"ipv4", "ipv6"}:
        return family
    try:
        return "ipv6" if ip_address(scope.site_address).version == 6 else "ipv4"
    except ValueError:
        return "ipv4"


def _normalize_hostname(value: str) -> str:
    hostname = (value or "").strip().strip(".").lower() or ESXI_PXE_DEFAULT_HOSTNAME
    if len(hostname) > 253 or "." not in hostname:
        raise ValueError("ESXi PXE hostname must be a fully qualified DNS name.")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", hostname):
        raise ValueError("ESXi PXE hostname must be a valid DNS name.")
    return hostname


def _normalize_multiline_values(value: str) -> str:
    values = []
    for item in (value or "").replace(",", "\n").splitlines():
        normalized = item.strip()
        if normalized and normalized not in values:
            values.append(normalized)
    return "\n".join(values)


def _normalize_tftp_root(value: str) -> str:
    root = ((value or "").strip() or ESXI_TFTP_ROOT.as_posix()).replace("\\", "/")
    if not root.startswith("/"):
        raise ValueError("TFTP root must be an absolute path.")
    return root


def _normalize_http_port(value: int | str | None) -> int:
    try:
        port = int(value or ESXI_PXE_HTTP_PORT)
    except (TypeError, ValueError) as exc:
        raise ValueError("ESXi PXE HTTP port must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("ESXi PXE HTTP port must be between 1 and 65535.")
    return port


def _bootfile_setting(value: str | None, *, default: str, legacy_defaults: set[str]) -> str:
    name = (value or "").strip()
    if not name or name.lower() in {item.lower() for item in legacy_defaults}:
        return default
    return name


def _normalize_bootfile(value: str, *, default: str) -> str:
    name = (value or "").strip() or default
    if "/" in name or "\\" in name or name.startswith(".") or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("PXE boot filenames must be simple filenames.")
    return name


def _normalize_native_uefi_http_url(value: str) -> str:
    url = (value or "").strip()
    if not url:
        return ""
    if not re.fullmatch(r"https?://[^\s\"'<>]+", url):
        raise ValueError("Native UEFI HTTP boot URL must be an absolute HTTP or HTTPS URL.")
    return url


def _managed_host_description(host_id: int) -> str:
    return f"{ESXI_PXE_HOST_MANAGED_DESCRIPTION_PREFIX}{host_id}."


def _is_managed_by_esxi_host(row: DhcpReservation | DnsRecord, host_id: int) -> bool:
    return (row.description or "").strip() == _managed_host_description(host_id)


def _remove_managed_esxi_host_network_records(db: Session, host_id: int) -> None:
    marker = _managed_host_description(host_id)
    for reservation in db.execute(select(DhcpReservation).where(DhcpReservation.description == marker)).scalars().all():
        db.delete(reservation)
    for record in db.execute(select(DnsRecord).where(DnsRecord.description == marker)).scalars().all():
        db.delete(record)


def sync_esxi_pxe_host_network_records(db: Session, host: EsxiPxeHost, boot_settings: dict[str, Any]) -> None:
    if host.id is None:
        db.flush()
    if host.id is None:
        raise ValueError("ESXi PXE host must be saved before creating DHCP reservations.")

    marker = _managed_host_description(host.id)
    ip_value = (host.ip_address or "").strip()
    if host.enabled is False or not ip_value:
        _remove_managed_esxi_host_network_records(db, host.id)
        return

    mac_address = host.mac_address.strip().lower()
    if not normalize_pxe_mac(mac_address):
        raise ValueError("ESXi PXE host IP reservations require a concrete MAC address.")

    try:
        reserved_ip = ip_address(ip_value)
    except ValueError as exc:
        raise ValueError("ESXi PXE host IP address must be a valid IP address.") from exc

    selected_scopes = [
        scope
        for scope in db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
        if scope.enabled is not False and scope.id in set(boot_settings.get("dhcp_scope_ids") or [])
    ]
    if not selected_scopes:
        raise ValueError("ESXi PXE host IP reservations require at least one selected ESXi PXE DHCP zone.")
    if not any(reserved_ip in ip_network(f"{scope.site_address}/{scope.prefix_length}", strict=False) for scope in selected_scopes):
        raise ValueError("ESXi PXE host IP address must be inside a selected ESXi PXE DHCP zone.")

    for reservation in db.execute(select(DhcpReservation)).scalars().all():
        if reservation.mac_address.strip().lower() == mac_address and not _is_managed_by_esxi_host(reservation, host.id):
            raise ValueError(f"DHCP reservation already exists for MAC address {host.mac_address}.")

    stale_reservations = [
        reservation
        for reservation in db.execute(select(DhcpReservation).where(DhcpReservation.description == marker)).scalars().all()
        if reservation.mac_address.strip().lower() != mac_address
    ]
    for reservation in stale_reservations:
        db.delete(reservation)
    db.flush()

    reservation = db.execute(select(DhcpReservation).where(DhcpReservation.description == marker)).scalar_one_or_none()
    if reservation is None:
        reservation = DhcpReservation(description=marker)
    reservation.hostname = host.hostname.strip()
    reservation.mac_address = mac_address
    reservation.ip_address = str(reserved_ip)
    reservation.enabled = bool(host.enabled)
    reservation.description = marker
    db.add(reservation)
    db.flush()

    record_values = reservation_dns_record(reservation, selected_scopes)
    if record_values is None:
        raise ValueError("ESXi PXE host IP address must map to a selected DHCP zone DNS domain.")
    hostname, record_type, address = record_values
    reservation.hostname = hostname

    for record in db.execute(select(DnsRecord).where(DnsRecord.hostname == hostname, DnsRecord.record_type == record_type)).scalars().all():
        if not _is_managed_by_esxi_host(record, host.id):
            raise ValueError(f"DNS record already exists for {hostname} {record_type}.")

    for record in db.execute(select(DnsRecord).where(DnsRecord.description == marker)).scalars().all():
        if record.hostname != hostname or record.record_type != record_type:
            db.delete(record)
    db.flush()

    record = db.execute(select(DnsRecord).where(DnsRecord.description == marker, DnsRecord.hostname == hostname, DnsRecord.record_type == record_type)).scalar_one_or_none()
    if record is None:
        record = DnsRecord(description=marker)
    record.hostname = hostname
    record.record_type = record_type
    record.address = address
    record.enabled = True
    record.description = marker
    db.add(record)


def _normalize_ipxe_script(value: str) -> str:
    script = (value or "").replace("\r\n", "\n").replace("\r", "\n")
    if not script.strip():
        script = default_ipxe_script()
    if not script.startswith("#!ipxe"):
        raise ValueError("iPXE script must start with #!ipxe.")
    if not script.endswith("\n"):
        script += "\n"
    return script


def normalize_pxe_mac(value: str) -> str:
    raw = (value or "").strip().lower().replace("-", ":")
    if "." in raw and ":" not in raw:
        raw = raw.replace(".", "")
    octets = re.findall(r"[0-9a-f]{2}", raw)
    if len(octets) == 7 and octets[0] == "01":
        return "01-" + "-".join(octets[1:])
    if len(octets) != 6:
        return ""
    return "01-" + "-".join(octets)


def normalize_host_mac(value: str) -> str:
    mac_key = normalize_pxe_mac(value)
    if not mac_key:
        return ""
    return ":".join(mac_key.split("-")[1:])


def dnsmasq_host_tag_for_pxe_mac(value: str) -> str:
    mac_key = normalize_pxe_mac(value)
    if not mac_key:
        return ""
    return "esxi-" + "".join(mac_key.split("-")[1:])


def installer_image_key(path: str) -> str:
    selected = Path(path)
    stem = selected.stem or "esx-installer"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-._").lower() or "esx-installer"
    digest = hashlib.sha1(str(selected).encode("utf-8")).hexdigest()[:10]
    return f"{slug}-{digest}"


def safe_installer_iso_name(filename: str) -> str:
    name = Path(filename or "").name.strip()
    if not SAFE_ISO_UPLOAD_PATTERN.fullmatch(name):
        raise ValueError("Upload an ESXi installer ISO with a safe .iso filename.")
    return name


def installer_iso_inventory() -> list[dict[str, Any]]:
    root = ensure_installer_iso_root()
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.iso"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        stat = path.stat()
        rows.append(
            {
                "name": path.name,
                "path": str(path),
                "relative_path": path.relative_to(root).as_posix(),
                "size_bytes": stat.st_size,
                "updated_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            }
        )
    return rows


def normalize_installer_iso_path(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    root = ensure_installer_iso_root().resolve()
    path = Path(raw)
    if not path.is_absolute():
        path = root / raw
    resolved = path.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"Installer ISO must be under {root}.")
    if resolved.suffix.lower() != ".iso":
        raise ValueError("Installer ISO must be a .iso file.")
    if not resolved.is_file():
        raise ValueError(f"Installer ISO does not exist: {resolved}")
    return str(resolved)


async def store_installer_iso_upload(upload_file: Any, *, max_bytes: int) -> dict[str, Any]:
    root = ensure_installer_iso_root()
    filename = safe_installer_iso_name(upload_file.filename or "")
    destination = root / filename
    temp_path = root / f".{filename}.uploading"
    total = 0
    try:
        with temp_path.open("wb") as handle:
            while True:
                chunk = await upload_file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"Installer ISO upload is too large. Limit is {max_bytes} bytes.")
                handle.write(chunk)
        if total == 0:
            raise ValueError("Installer ISO upload is empty.")
        shutil.move(str(temp_path), destination)
        destination.chmod(0o644)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    stat = destination.stat()
    return {
        "name": destination.name,
        "path": str(destination),
        "relative_path": destination.relative_to(root).as_posix(),
        "size_bytes": stat.st_size,
        "updated_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
    }


def assign_kickstart_content(kickstart: EsxiKickstart, content: str, *, max_bytes: int) -> None:
    normalized = normalize_kickstart_content(content, max_bytes=max_bytes)
    kickstart.content = normalized
    kickstart.content_hash = content_hash(normalized)
    kickstart.rendered_content = normalized
    kickstart.http_path = canonical_http_path(kickstart.id, kickstart.content_hash) if kickstart.id else kickstart.http_path
    kickstart.updated_at = utcnow()


def redacted_kickstart_preview(content: str) -> str:
    lines: list[str] = []
    for raw_line in (content or "").splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        lower = stripped.lower()
        if lower.startswith("rootpw") or SECRET_KEYWORD_PATTERN.search(stripped):
            indent = line[: len(line) - len(line.lstrip())]
            command = stripped.split(None, 1)[0]
            if "=" in stripped and not lower.startswith("rootpw"):
                prefix = line.split("=", 1)[0].rstrip()
                lines.append(f"{prefix}= ********")
            else:
                lines.append(f"{indent}{command} ********")
            continue
        lines.append(line)
    return "\n".join(lines)


def redacted_host_variables(values: dict[str, str]) -> dict[str, str]:
    return {key: "[redacted]" if SECRET_KEYWORD_PATTERN.search(key) else value for key, value in values.items()}


def kickstart_validation(content: str, *, strict: bool, max_bytes: int) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        normalized = normalize_kickstart_content(content, max_bytes=max_bytes)
    except ValueError as exc:
        return [str(exc)], []

    lines = [line.strip() for line in normalized.splitlines()]
    directive_text = "\n".join(lines).lower()
    checks = [
        ("rootpw", any(line.startswith("rootpw") for line in lines), "missing rootpw"),
        ("install or upgrade", bool(re.search(r"(?m)^(install|upgrade)(\s|$)", directive_text)), "missing install or upgrade directive"),
        ("network", any(line.startswith("network") for line in lines), "missing network directive"),
        ("reboot", any(line.startswith("reboot") for line in lines), "missing reboot directive"),
        ("%firstboot", any(line.startswith("%firstboot") for line in lines), "missing firstboot section"),
    ]
    missing = [message for _label, present, message in checks if not present]
    if strict:
        errors.extend(missing)
    else:
        warnings.extend(missing)

    install_directive_lines = [
        index
        for index, line in enumerate(lines, start=1)
        if re.match(r"^(install|upgrade)(\s|$)", line.lower())
    ]
    if len(install_directive_lines) > 1:
        joined_lines = ", ".join(str(line) for line in install_directive_lines)
        errors.append(f"multiple install/upgrade directives on lines {joined_lines}; ESXi allows only one.")

    for line in lines:
        if SECRET_KEYWORD_PATTERN.search(line) and not line.startswith("#"):
            warnings.append("contains plaintext password or secret-looking value")
            break
    if UNSUPPORTED_TEMPLATE_PATTERN.search(normalized):
        warnings.append("contains unsupported template variable")
    return errors, list(dict.fromkeys(warnings))


def strict_validation_enabled(db: Session) -> bool:
    row = db.execute(select(Setting).where(Setting.key == ESXI_PXE_STRICT_VALIDATION_KEY)).scalar_one_or_none()
    return bool(row and row.value.strip().lower() in {"1", "true", "yes", "on"})


def filesystem_hash(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def kickstart_drift_state(kickstart: EsxiKickstart) -> str:
    path = generated_kickstart_path(kickstart.id, kickstart.content_hash)
    disk_hash = filesystem_hash(path)
    if not kickstart.rendered_hash and disk_hash is None:
        return "not_rendered"
    if kickstart.rendered_hash and disk_hash is None:
        return "filesystem_missing"
    if kickstart.rendered_hash and kickstart.content_hash != kickstart.rendered_hash:
        return "database_changed_pending_apply"
    if disk_hash != kickstart.content_hash:
        return "filesystem_modified"
    return "in_sync"


def kickstart_to_dict(kickstart: EsxiKickstart, *, include_content: bool = False) -> dict[str, Any]:
    payload = {
        "id": kickstart.id,
        "name": kickstart.name,
        "description": kickstart.description or "",
        "content_hash": kickstart.content_hash,
        "rendered_hash": kickstart.rendered_hash or "",
        "http_path": canonical_http_path(kickstart.id, kickstart.content_hash),
        "enabled": kickstart.enabled,
        "created_at": kickstart.created_at,
        "updated_at": kickstart.updated_at,
        "last_rendered_at": kickstart.last_rendered_at,
        "last_applied_at": kickstart.last_applied_at,
        "redacted_preview": redacted_kickstart_preview(kickstart.content),
        "drift_state": kickstart_drift_state(kickstart),
    }
    if include_content:
        payload["content"] = kickstart.content
    return payload


def host_to_dict(host: EsxiPxeHost) -> dict[str, Any]:
    iso_path = host.installer_iso_path or ""
    return {
        "id": host.id,
        "hostname": host.hostname,
        "mac_address": host.mac_address,
        "ip_address": host.ip_address or "",
        "kickstart_id": host.kickstart_id,
        "kickstart_name": host.kickstart.name if host.kickstart else "",
        "installer_iso_path": iso_path,
        "installer_iso_name": Path(iso_path).name if iso_path else "",
        "variables": host_variables(host),
        "variables_json": json.dumps(host_variables(host), sort_keys=True),
        "enabled": host.enabled,
        "created_at": host.created_at.isoformat() if host.created_at else "",
        "updated_at": host.updated_at.isoformat() if host.updated_at else "",
    }


def esxi_pxe_default_host_settings(db: Session) -> dict[str, Any]:
    rows = {row.key: row.value for row in db.execute(select(Setting).where(Setting.key.like("esxi_pxe.default_host.%"))).scalars().all()}
    kickstart_id = rows.get(ESXI_PXE_DEFAULT_HOST_KICKSTART_ID_KEY, "").strip()
    kickstart = db.get(EsxiKickstart, int(kickstart_id)) if kickstart_id.isdigit() else None
    iso_path = rows.get(ESXI_PXE_DEFAULT_HOST_INSTALLER_ISO_KEY, "").strip()
    return {
        "enabled": rows.get(ESXI_PXE_DEFAULT_HOST_ENABLED_KEY, "false").strip().lower() in {"1", "true", "yes", "on"},
        "kickstart_id": kickstart.id if kickstart is not None else None,
        "kickstart_name": kickstart.name if kickstart is not None else "",
        "kickstart_http_path": canonical_http_path(kickstart.id, kickstart.content_hash) if kickstart is not None else "",
        "installer_iso_path": iso_path,
        "installer_iso_name": Path(iso_path).name if iso_path else "",
    }


def save_esxi_pxe_default_host_settings(
    db: Session,
    *,
    enabled: bool,
    kickstart_id: int | str | None = None,
    installer_iso_path: str = "",
) -> dict[str, Any]:
    kickstart_value = str(kickstart_id or "").strip()
    if kickstart_value and not kickstart_value.isdigit():
        raise ValueError("Default ESXi PXE Kickstart is invalid.")
    normalized_kickstart_id = int(kickstart_value) if kickstart_value else None
    if normalized_kickstart_id and db.get(EsxiKickstart, normalized_kickstart_id) is None:
        raise ValueError("Default ESXi PXE Kickstart does not exist.")
    normalized_iso_path = normalize_installer_iso_path(installer_iso_path)
    settings = {
        ESXI_PXE_DEFAULT_HOST_ENABLED_KEY: "true" if enabled else "false",
        ESXI_PXE_DEFAULT_HOST_KICKSTART_ID_KEY: str(normalized_kickstart_id or ""),
        ESXI_PXE_DEFAULT_HOST_INSTALLER_ISO_KEY: normalized_iso_path,
    }
    for key, value in settings.items():
        row = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
        if row is None:
            row = Setting(key=key, value=value)
        else:
            row.value = value
        db.add(row)
    db.flush()
    return esxi_pxe_default_host_settings(db)


def default_host_to_dict(default_host: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "default",
        "hostname": "Default / undefined MACs",
        "mac_address": "*",
        "ip_address": "",
        "kickstart_id": default_host.get("kickstart_id"),
        "kickstart_name": default_host.get("kickstart_name") or "",
        "kickstart_http_path": default_host.get("kickstart_http_path") or "",
        "installer_iso_path": default_host.get("installer_iso_path") or "",
        "installer_iso_name": default_host.get("installer_iso_name") or "",
        "enabled": bool(default_host.get("enabled")),
        "is_default": True,
    }


def _esxi_pxe_artifact(
    *,
    host_id: int | None,
    hostname: str,
    mac_address: str,
    ip_address: str = "",
    mac_key: str,
    iso_path: str,
    kickstart_id: int | None,
    boot_settings: dict[str, Any],
    kickstart_http_path: str = "",
    kickstart_host_context_required: bool = True,
    is_default: bool = False,
) -> dict[str, Any]:
    base_url = esxi_http_base_url(boot_settings)
    image_key = installer_image_key(iso_path)
    image_http_path = f"{ESXI_PXE_IMAGE_HTTP_PREFIX}/{image_key}"
    kickstart_path = kickstart_http_path or (canonical_http_path(kickstart_id) if kickstart_id else "")
    if is_default:
        pxelinux_config_path = str(ESXI_TFTP_ROOT / "pxelinux.cfg" / "default")
        uefi_tftp_boot_cfg_path = str(ESXI_TFTP_ROOT / "boot.cfg")
        http_boot_cfg_path = str(ESXI_PXE_HTTP_BASE / "boot.cfg")
    else:
        pxelinux_config_path = str(ESXI_TFTP_ROOT / "pxelinux.cfg" / mac_key) if mac_key else ""
        uefi_tftp_boot_cfg_path = str(ESXI_TFTP_ROOT / mac_key / "boot.cfg") if mac_key else ""
        http_boot_cfg_path = str(ESXI_PXE_HTTP_BASE / mac_key / "boot.cfg") if mac_key else ""
    return {
        "host_id": host_id,
        "hostname": hostname,
        "mac_address": mac_address,
        "ip_address": ip_address,
        "mac_key": mac_key,
        "is_default": is_default,
        "image_key": image_key,
        "installer_iso_path": iso_path,
        "installer_iso_name": Path(iso_path).name if iso_path else "",
        "image_http_path": image_http_path,
        "image_http_url": f"{base_url}/images/{image_key}" if base_url else "",
        "image_generated_path": str(ESXI_PXE_IMAGE_HTTP_ROOT / image_key),
        "kickstart_id": kickstart_id,
        "kickstart_http_path": kickstart_path,
        "kickstart_url": host_kickstart_url(base_url, kickstart_path, mac_key) if (not is_default and kickstart_host_context_required) else kickstart_url(base_url, kickstart_path),
        "pxelinux_config_path": pxelinux_config_path,
        "uefi_tftp_boot_cfg_path": uefi_tftp_boot_cfg_path,
        "http_boot_cfg_path": http_boot_cfg_path,
    }


def esxi_pxe_host_artifacts(
    hosts: list[EsxiPxeHost],
    boot_settings: dict[str, Any],
    default_host: dict[str, Any] | None = None,
    kickstart_paths: dict[int, str] | None = None,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    paths = kickstart_paths or {}
    if default_host and default_host.get("enabled") and default_host.get("installer_iso_path"):
        default_kickstart_id = default_host.get("kickstart_id")
        default_kickstart_path = paths.get(int(default_kickstart_id)) if default_kickstart_id else ""
        artifacts.append(
            _esxi_pxe_artifact(
                host_id=None,
                hostname="Default / undefined MACs",
                mac_address="*",
                ip_address="",
                mac_key="default",
                iso_path=str(default_host.get("installer_iso_path") or ""),
                kickstart_id=default_kickstart_id,
                kickstart_http_path=default_kickstart_path or str(default_host.get("kickstart_http_path") or ""),
                boot_settings=boot_settings,
                is_default=True,
            )
        )
    for host in hosts:
        if host.enabled is False:
            continue
        iso_path = host.installer_iso_path or ""
        if not iso_path:
            continue
        mac_key = normalize_pxe_mac(host.mac_address)
        kickstart_path = ""
        if host.kickstart_id:
            kickstart_path = paths.get(host.kickstart_id, "")
            if not kickstart_path and host.kickstart is not None:
                kickstart_path = canonical_http_path(host.kickstart_id, host.kickstart.content_hash)
        requires_host_context = kickstart_requires_host_context(host.kickstart.content) if host.kickstart is not None else True
        artifacts.append(
            _esxi_pxe_artifact(
                host_id=host.id,
                hostname=host.hostname,
                mac_address=host.mac_address,
                ip_address=host.ip_address or "",
                mac_key=mac_key,
                iso_path=iso_path,
                kickstart_id=host.kickstart_id,
                kickstart_http_path=kickstart_path,
                kickstart_host_context_required=requires_host_context,
                boot_settings=boot_settings,
            )
        )
    return artifacts


def render_esxi_pxe_manifest(kickstarts: list[EsxiKickstart], hosts: list[EsxiPxeHost], boot_settings: dict[str, Any] | None = None, default_host: dict[str, Any] | None = None) -> str:
    iso_error = ""
    try:
        installer_isos = installer_iso_inventory()
    except OSError as exc:
        installer_isos = []
        iso_error = str(exc)
    boot = boot_settings or {
        "enabled": False,
        "hostname": ESXI_PXE_DEFAULT_HOSTNAME,
        "dhcp_scope_id": None,
        "dhcp_scope_name": "",
        "dhcp_scope_ids": [],
        "dhcp_scope_names": [],
        "dhcp_scopes": [],
        "listen_interface": "",
        "listen_address": "",
        "tftp_root": ESXI_TFTP_ROOT.as_posix(),
        "http_port": ESXI_PXE_HTTP_PORT,
        "bios_bootfile": ESXI_PXE_BIOS_BOOTFILE,
        "uefi_bootfile": ESXI_PXE_UEFI_BOOTFILE,
        "bios_second_stage_bootfile": ESXI_PXE_BIOS_SECOND_STAGE_BOOTFILE,
        "uefi_second_stage_bootfile": ESXI_PXE_UEFI_SECOND_STAGE_BOOTFILE,
        "native_uefi_bootfile": ESXI_PXE_NATIVE_UEFI_BOOTFILE,
        "native_uefi_http_enabled": True,
        "native_uefi_http_url": "",
        "ipxe_script_name": ESXI_PXE_IPXE_SCRIPT_NAME,
        "ipxe_script": default_ipxe_script(),
        "tftp_ipxe_script": tftp_ipxe_chain_script(),
        "http_ipxe_path": "/pxe/esxi/boot.ipxe",
        "http_ipxe_generated_path": ESXI_IPXE_HTTP_SCRIPT_PATH.as_posix(),
    }
    boot = dict(boot)
    boot["http_base_url"] = esxi_http_base_url(boot)
    boot["effective_native_uefi_http_url"] = effective_native_uefi_http_url(boot)
    boot_manifest_keys = {
        "enabled",
        "hostname",
        "dhcp_scope_id",
        "dhcp_scope_name",
        "dhcp_scope_ids",
        "dhcp_scope_names",
        "dhcp_scopes",
        "listen_interface",
        "listen_address",
        "tftp_root",
        "http_port",
        "http_base_url",
        "bios_bootfile",
        "uefi_bootfile",
        "bios_second_stage_bootfile",
        "uefi_second_stage_bootfile",
        "native_uefi_bootfile",
        "native_uefi_http_enabled",
        "native_uefi_http_url",
        "effective_native_uefi_http_url",
        "ipxe_script_name",
        "ipxe_script",
        "tftp_ipxe_script",
        "http_ipxe_path",
        "http_ipxe_generated_path",
    }
    boot_manifest = {key: boot.get(key) for key in boot_manifest_keys}
    kickstart_paths = {row.id: canonical_http_path(row.id, row.content_hash) for row in kickstarts if row.id is not None}
    artifacts = esxi_pxe_host_artifacts(hosts, boot, default_host, kickstart_paths=kickstart_paths)
    payload = {
        "kind": "atlaso-esxi-pxe",
        "schema_version": ESXI_PXE_SCHEMA_VERSION,
        "http_root": str(ESXI_KICKSTART_HTTP_ROOT),
        "http_base": str(ESXI_PXE_HTTP_BASE),
        "image_http_root": str(ESXI_PXE_IMAGE_HTTP_ROOT),
        "installer_iso_root": str(ESXI_INSTALLER_ISO_ROOT),
        "installer_isos": installer_isos,
        "installer_iso_error": iso_error,
        "boot": boot_manifest,
        "kickstarts": [
            {
                "id": row.id,
                "name": row.name,
                "enabled": row.enabled,
                "content": row.rendered_content if row.rendered_content is not None else row.content,
                "content_hash": row.content_hash,
                "http_path": canonical_http_path(row.id, row.content_hash),
                "generated_path": str(generated_kickstart_path(row.id, row.content_hash)),
            }
            for row in kickstarts
        ],
        "hosts": [
            {
                "id": host.id,
                "hostname": host.hostname,
                "mac_address": host.mac_address,
                "ip_address": host.ip_address or "",
                "kickstart_id": host.kickstart_id,
                "installer_iso_path": host.installer_iso_path or "",
                "installer_iso_name": Path(host.installer_iso_path).name if host.installer_iso_path else "",
                "variables": host_variables(host),
                "enabled": host.enabled,
            }
            for host in hosts
        ],
        "default_host": {
            "enabled": bool((default_host or {}).get("enabled")),
            "kickstart_id": (default_host or {}).get("kickstart_id"),
            "kickstart_name": (default_host or {}).get("kickstart_name") or "",
            "kickstart_http_path": (default_host or {}).get("kickstart_http_path") or "",
            "installer_iso_path": (default_host or {}).get("installer_iso_path") or "",
            "installer_iso_name": (default_host or {}).get("installer_iso_name") or "",
        },
        "artifacts": artifacts,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_esxi_pxe_preview(kickstarts: list[EsxiKickstart], hosts: list[EsxiPxeHost], boot_settings: dict[str, Any] | None = None, default_host: dict[str, Any] | None = None) -> str:
    payload = json.loads(render_esxi_pxe_manifest(kickstarts, hosts, boot_settings, default_host))
    for row in payload["kickstarts"]:
        row["content"] = redacted_kickstart_preview(str(row["content"]))
    for host in payload.get("hosts", []):
        if isinstance(host.get("variables"), dict):
            host["variables"] = redacted_host_variables(host["variables"])
    return json.dumps(payload, indent=2, sort_keys=True)


def mark_kickstarts_applied(kickstarts: list[EsxiKickstart]) -> None:
    timestamp = utcnow()
    for row in kickstarts:
        rendered = row.rendered_content if row.rendered_content is not None else row.content
        row.rendered_hash = content_hash(rendered)
        row.last_rendered_at = timestamp
        row.last_applied_at = timestamp
        row.http_path = canonical_http_path(row.id, row.rendered_hash or row.content_hash)
