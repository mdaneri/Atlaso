#!/usr/bin/env python3
"""Apply Atlaso VMware OVF deployment properties on first boot."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from ipaddress import ip_interface
import xml.etree.ElementTree as ET

from atlaso.app.management_network import ManagementNetworkValidationError, validate_management_network


PROPERTY_PREFIX = "atlaso."
PROPERTY_MANAGEMENT_MODE = f"{PROPERTY_PREFIX}management_mode"
PROPERTY_CIDR = f"{PROPERTY_PREFIX}cidr"
PROPERTY_GATEWAY = f"{PROPERTY_PREFIX}gateway"
PROPERTY_IPV6_ENABLED = f"{PROPERTY_PREFIX}ipv6_enabled"
PROPERTY_IPV6_CIDR = f"{PROPERTY_PREFIX}ipv6_cidr"
PROPERTY_IPV6_GATEWAY = f"{PROPERTY_PREFIX}ipv6_gateway"
PROPERTY_FQDN = f"{PROPERTY_PREFIX}fqdn"
PROPERTY_DNS = f"{PROPERTY_PREFIX}dns_servers"
PROPERTY_ADMIN_PASSWORD = f"{PROPERTY_PREFIX}admin_password"
PROPERTY_ROOT_PASSWORD = f"{PROPERTY_PREFIX}root_password"
PROPERTY_ROOT_SSH_ENABLED = f"{PROPERTY_PREFIX}root_ssh_enabled"
MINIMUM_PASSWORD_LENGTH = 12
REQUIRED_PROPERTIES = {
    PROPERTY_FQDN,
    PROPERTY_ADMIN_PASSWORD,
    PROPERTY_ROOT_PASSWORD,
}

ENV_PATH = Path("/etc/atlaso/atlaso.env")
NETWORKD_PATH = Path("/etc/systemd/network/00-atlaso-mgmt.network")
RESOLV_CONF_PATH = Path("/etc/resolv.conf")
NGINX_MANAGEMENT_PATH = Path("/etc/atlaso/nginx/sites.d/management.conf")
FIREWALL_CONFIG_PATH = Path("/etc/atlaso/nftables.d/atlaso.nft")
SSHD_ROOT_LOGIN_CONFIG_PATH = Path("/etc/ssh/sshd_config.d/atlaso-root-login.conf")
MARKER_PATH = Path("/var/lib/atlaso/vmware-ovf-customization.applied")
INITIALIZATION_LOCK_PATH = Path("/var/lib/atlaso/vmware-ovf-initializing")
NETWORK_REVIEW_PATH = Path("/var/lib/atlaso/vmware-ovf-network-review.json")
NETWORK_CORRECTION_PATH = Path("/var/lib/atlaso/vmware-ovf-network-correction.json")
LOG_PATH = Path("/var/log/atlaso/vmware-ovf-customize.log")
DEFAULT_INTERFACE = "eth0"
NETWORK_REVIEW_POLL_SECONDS = 1.0
FQDN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class OvfCustomizationError(ValueError):
    """Report a ovf customization error."""
    pass


class OvfManagementNetworkError(OvfCustomizationError):
    """Report recoverable OVF management-network validation failure."""

    pass


def utc_now() -> str:
    """Return utc now."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def log(message: str) -> None:
    """Handle log.

    Args:
        message: Human-readable message associated with the operation.
    """
    line = f"{utc_now()} {message}\n"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass
    print(message)


def attr_value(element: ET.Element, local_name: str) -> str:
    """Return attr value.

    Args:
        element: Element consumed by attr value.
        local_name: Local name consumed by attr value.
    """
    for key, value in element.attrib.items():
        if key == local_name or key.endswith(f"}}{local_name}"):
            return value
    return ""


def parse_ovf_environment(xml_text: str) -> dict[str, str]:
    """Parse ovf environment.

    Args:
        xml_text: Candidate xml text to parse.


    Returns:
        The parsed ovf environment.
    """
    if not xml_text.strip():
        return {}
    root = ET.fromstring(xml_text)
    properties: dict[str, str] = {}
    for element in root.iter():
        if not element.tag.endswith("Property"):
            continue
        key = attr_value(element, "key")
        if not key.startswith(PROPERTY_PREFIX):
            continue
        properties[key] = attr_value(element, "value").strip()
    return properties


def validate_fqdn(value: str) -> str:
    """Validate fqdn.

    Args:
        value: Candidate value consumed by validate FQDN.


    Returns:
        The validate fqdn result.

    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    fqdn = value.strip().lower().rstrip(".")
    if not fqdn or "." not in fqdn or not FQDN_PATTERN.match(fqdn):
        raise OvfCustomizationError("atlaso.fqdn must be a fully qualified DNS name")
    if fqdn.endswith(".local"):
        raise OvfCustomizationError("atlaso.fqdn must not use .local")
    return fqdn


def parse_boolean_property(properties: dict[str, str], key: str, *, default: bool = False) -> bool:
    """Parse boolean property.

    Args:
        properties: Candidate properties to parse.
        key: Stable key identifying the setting, secret, or mapping entry.
        default: Whether default applies to the operation.


    Returns:
        The parsed boolean property.

    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    value = properties.get(key, "").strip().lower()
    if not value:
        return default
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise OvfCustomizationError(f"{key} must be true or false")


def validate_non_network_properties(properties: dict[str, str]) -> dict[str, object]:
    """Validate OVF fields that the network-only console flow cannot correct.

    Args:
        properties: Candidate OVF properties to validate.

    Returns:
        The validated non-network customization values.

    Raises:
        OvfCustomizationError: If a non-network property is invalid.
    """
    missing = sorted(key for key in REQUIRED_PROPERTIES if not properties.get(key, "").strip())
    if missing:
        raise OvfCustomizationError(f"Missing required OVF properties: {', '.join(missing)}")
    for password_key in (PROPERTY_ADMIN_PASSWORD, PROPERTY_ROOT_PASSWORD):
        if len(properties[password_key]) < MINIMUM_PASSWORD_LENGTH:
            raise OvfCustomizationError(
                f"{password_key} must be at least {MINIMUM_PASSWORD_LENGTH} characters"
            )
    return {
        "fqdn": validate_fqdn(properties[PROPERTY_FQDN]),
        "admin_password": properties[PROPERTY_ADMIN_PASSWORD],
        "root_password": properties[PROPERTY_ROOT_PASSWORD],
        "root_ssh_enabled": parse_boolean_property(properties, PROPERTY_ROOT_SSH_ENABLED),
    }


def validate_properties(
    properties: dict[str, str],
    *,
    non_network: dict[str, object] | None = None,
) -> dict[str, object]:
    """Validate properties.

    Args:
        properties: Candidate properties to validate.
        non_network: Previously validated non-network values, when available.


    Returns:
        The validate properties result.

    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    validated_non_network = non_network or validate_non_network_properties(properties)

    _legacy_management_mode = properties.get(PROPERTY_MANAGEMENT_MODE, "").strip().lower()
    # Kept parse-compatible for existing deployment automation; address presence now owns IPv4 behavior.
    cidr_value = properties.get(PROPERTY_CIDR, "").strip()
    gateway_value = properties.get(PROPERTY_GATEWAY, "").strip()
    management_mode = "static" if cidr_value or gateway_value else "dhcp"

    try:
        ipv6_enabled = parse_boolean_property(properties, PROPERTY_IPV6_ENABLED)
    except OvfCustomizationError as exc:
        raise OvfManagementNetworkError(str(exc)) from exc
    ipv6_cidr_value = properties.get(PROPERTY_IPV6_CIDR, "").strip()
    ipv6_gateway_value = properties.get(PROPERTY_IPV6_GATEWAY, "").strip()
    ipv6_mode = (
        "static"
        if ipv6_cidr_value or ipv6_gateway_value
        else ("automatic" if ipv6_enabled else "disabled")
    )

    try:
        network = validate_management_network(
            ipv4_method=management_mode,
            ipv4_cidr=cidr_value,
            ipv4_gateway=gateway_value,
            ipv6_mode=ipv6_mode if ipv6_enabled else "disabled",
            ipv6_cidr=ipv6_cidr_value,
            ipv6_gateway=ipv6_gateway_value,
            dns_servers=properties.get(PROPERTY_DNS, ""),
            require_static_ipv4_gateway=True,
        )
    except ManagementNetworkValidationError as exc:
        raise OvfManagementNetworkError(str(exc)) from exc

    management_source_cidr = (
        str(ip_interface(network.ipv4_cidr).network) if network.ipv4_cidr else ""
    )
    management_source_ipv6_cidr = (
        str(ip_interface(network.ipv6_cidr).network) if network.ipv6_cidr else ""
    )
    return {
        "management_mode": network.ipv4_method,
        "cidr": network.ipv4_cidr or "dhcp",
        "gateway": network.ipv4_gateway,
        "ipv6_enabled": ipv6_enabled,
        "ipv6_mode": "auto" if network.ipv6_mode == "automatic" else network.ipv6_mode,
        "ipv6_cidr": network.ipv6_cidr,
        "ipv6_gateway": network.ipv6_gateway,
        "fqdn": validated_non_network["fqdn"],
        "dns_servers": list(network.dns_servers),
        "admin_password": validated_non_network["admin_password"],
        "root_password": validated_non_network["root_password"],
        "root_ssh_enabled": validated_non_network["root_ssh_enabled"],
        "management_source_cidr": management_source_cidr,
        "management_source_ipv6_cidr": management_source_ipv6_cidr,
    }


def _bounded_review_value(value: object, limit: int = 512) -> str:
    """Return one bounded non-secret OVF value for local console review.

    Args:
        value: Candidate scalar review value.
        limit: Maximum returned character count.

    Returns:
        The bounded display value.
    """
    return str(value or "").strip()[:limit]


def network_review_state(properties: dict[str, str], error: str) -> dict[str, object]:
    """Build the non-secret first-boot network review state.

    Args:
        properties: Original OVF properties containing deployment values.
        error: Safe management-network validation message.

    Returns:
        A bounded non-secret review document.
    """
    cidr = _bounded_review_value(properties.get(PROPERTY_CIDR, ""))
    gateway = _bounded_review_value(properties.get(PROPERTY_GATEWAY, ""))
    ipv6_cidr = _bounded_review_value(properties.get(PROPERTY_IPV6_CIDR, ""))
    ipv6_gateway = _bounded_review_value(properties.get(PROPERTY_IPV6_GATEWAY, ""))
    ipv6_enabled = properties.get(PROPERTY_IPV6_ENABLED, "").strip().lower() in {
        "true",
        "1",
        "yes",
        "on",
    }
    return {
        "version": 1,
        "state": "network_review",
        "error": _bounded_review_value(error, 1024),
        "ipv4_method": "static" if cidr or gateway else "dhcp",
        "ipv4_cidr": cidr,
        "ipv4_gateway": gateway,
        "ipv6_mode": (
            "static"
            if ipv6_cidr or ipv6_gateway
            else ("automatic" if ipv6_enabled else "disabled")
        ),
        "ipv6_cidr": ipv6_cidr,
        "ipv6_gateway": ipv6_gateway,
        "dns_servers": _bounded_review_value(properties.get(PROPERTY_DNS, "")),
        "fqdn": _bounded_review_value(properties.get(PROPERTY_FQDN, ""), 253),
        "updated_at": utc_now(),
    }


def write_json_atomic(path: Path, payload: dict[str, object], *, mode: int = 0o640) -> None:
    """Persist bounded JSON without exposing a partially written state file.

    Args:
        path: Destination path for the JSON document.
        payload: JSON-compatible document to persist.
        mode: Filesystem mode for the completed document.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_network_review(properties: dict[str, str], error: str) -> None:
    """Persist recoverable, non-secret first-boot review state.

    Args:
        properties: Original or corrected OVF properties requiring review.
        error: Safe management-network validation or recovery message.
    """
    write_json_atomic(NETWORK_REVIEW_PATH, network_review_state(properties, error))


def read_network_correction() -> dict[str, str] | None:
    """Read one console-supplied, non-secret management-network correction."""
    if not NETWORK_CORRECTION_PATH.exists():
        return None
    try:
        payload = json.loads(NETWORK_CORRECTION_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OvfManagementNetworkError("The console network correction could not be read; review it again.") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise OvfManagementNetworkError("The console network correction has an unsupported format.")
    allowed = {
        "ipv4_method",
        "ipv4_cidr",
        "ipv4_gateway",
        "ipv6_mode",
        "ipv6_cidr",
        "ipv6_gateway",
        "dns_servers",
    }
    unexpected = sorted(set(payload) - allowed - {"version"})
    if unexpected:
        raise OvfManagementNetworkError(
            "The console network correction contains unsupported fields; review it again."
        )
    return {key: _bounded_review_value(payload.get(key, "")) for key in allowed}


def properties_with_network_correction(
    properties: dict[str, str], correction: dict[str, str]
) -> dict[str, str]:
    """Merge only the allowlisted network fields into the original OVF properties.

    Args:
        properties: Original OVF properties, including in-memory credentials.
        correction: Validated allowlisted console network fields.

    Returns:
        The OVF properties with only management-network values replaced.
    """
    corrected = dict(properties)
    ipv4_method = correction.get("ipv4_method", "").strip().lower()
    if ipv4_method == "dhcp":
        corrected.pop(PROPERTY_CIDR, None)
        corrected.pop(PROPERTY_GATEWAY, None)
    else:
        corrected[PROPERTY_CIDR] = correction.get("ipv4_cidr", "")
        corrected[PROPERTY_GATEWAY] = correction.get("ipv4_gateway", "")
    ipv6_mode = correction.get("ipv6_mode", "").strip().lower()
    corrected[PROPERTY_IPV6_ENABLED] = "true" if ipv6_mode != "disabled" else "false"
    if ipv6_mode == "static":
        corrected[PROPERTY_IPV6_CIDR] = correction.get("ipv6_cidr", "")
        corrected[PROPERTY_IPV6_GATEWAY] = correction.get("ipv6_gateway", "")
    else:
        corrected.pop(PROPERTY_IPV6_CIDR, None)
        corrected.pop(PROPERTY_IPV6_GATEWAY, None)
    corrected[PROPERTY_DNS] = correction.get("dns_servers", "")
    return corrected


def clear_network_review() -> None:
    """Remove the non-secret first-boot review handshake."""
    NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
    NETWORK_REVIEW_PATH.unlink(missing_ok=True)


def complete_first_boot_initialization() -> None:
    """Unlock tty1 after success or recover cleanup from an applied marker."""
    clear_network_review()
    INITIALIZATION_LOCK_PATH.unlink(missing_ok=True)


def wait_for_network_review(properties: dict[str, str], error: str) -> int:
    """Wait visibly for tty1 to provide a valid first-boot network correction.

    Args:
        properties: Original OVF properties retained in process memory.
        error: Initial safe management-network validation message.

    Returns:
        Zero after corrected customization succeeds.
    """
    write_network_review(properties, error)
    log("VMware OVF management network requires review on the Atlaso tty1 console.")
    while True:
        try:
            correction = read_network_correction()
        except OvfManagementNetworkError as exc:
            write_network_review(properties, str(exc))
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            time.sleep(NETWORK_REVIEW_POLL_SECONDS)
            continue
        if correction is None:
            time.sleep(NETWORK_REVIEW_POLL_SECONDS)
            continue
        corrected_properties = properties_with_network_correction(properties, correction)
        try:
            config = validate_properties(corrected_properties)
        except OvfManagementNetworkError as exc:
            write_network_review(corrected_properties, str(exc))
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            continue
        except OvfCustomizationError as exc:
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            log(
                "VMware OVF customization stopped after an uncorrectable console validation: "
                f"{type(exc).__name__}"
            )
            return 2
        try:
            summary = apply_customization(config)
        except OvfCustomizationError as exc:
            write_network_review(
                corrected_properties,
                "The corrected management network validated, but first-time initialization did not finish. "
                "Resolve the condition reported in the customization log, then submit the network review again.",
            )
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            log(f"VMware OVF customization could not finish after console correction: {type(exc).__name__}")
            continue
        except (OSError, subprocess.CalledProcessError) as exc:
            write_network_review(
                corrected_properties,
                "The corrected management network could not be applied. Review the values and retry.",
            )
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            log(f"VMware OVF customization could not apply the console correction: {type(exc).__name__}")
            continue
        complete_first_boot_initialization()
        log("Applied corrected Atlaso VMware OVF customization: " + json.dumps(summary, sort_keys=True))
        return 0


def redacted_summary(config: dict[str, object]) -> dict[str, object]:
    """Return redacted summary.

    Args:
        config: Validated configuration consumed by the operation.
    """
    return {
        "applied_at": utc_now(),
        "management_mode": config["management_mode"],
        "cidr": config["cidr"],
        "gateway": config["gateway"],
        "ipv6_enabled": config["ipv6_enabled"],
        "ipv6_mode": config["ipv6_mode"],
        "ipv6_cidr": config["ipv6_cidr"],
        "ipv6_gateway": config["ipv6_gateway"],
        "fqdn": config["fqdn"],
        "dns_server_count": len(config["dns_servers"]),
        "admin_password_set": bool(config["admin_password"]),
        "root_password_set": bool(config["root_password"]),
        "root_ssh_enabled": config["root_ssh_enabled"],
    }


def read_ovf_environment() -> str:
    """Return ovf environment."""
    commands = [
        ["vmware-rpctool", "info-get guestinfo.ovfEnv"],
        ["vmtoolsd", "--cmd", "info-get guestinfo.ovfEnv"],
    ]
    for command in commands:
        if shutil.which(command[0]) is None:
            continue
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    return ""


def quote_env_value(value: object) -> str:
    """Return quote env value.

    Args:
        value: Candidate value consumed by quote env value.
    """
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def generate_secret_key() -> str:
    """Build secret key.

    Returns:
        The generate secret key result.
    """
    return secrets.token_urlsafe(48)


def read_env_file(path: Path) -> dict[str, str]:
    """Return env file.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def write_env_file(path: Path, updates: dict[str, object]) -> None:
    """Persist env file.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        updates: Updates supplied by the caller.
    """
    values = read_env_file(path)
    values.update({key: str(value) for key, value in updates.items()})
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{key}={quote_env_value(values[key])}" for key in sorted(values)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o640)
    try:
        shutil.chown(path, user="root", group="atlaso")
    except (LookupError, PermissionError):
        pass


def write_networkd_config(config: dict[str, object]) -> None:
    """Persist networkd config.

    Args:
        config: Validated configuration consumed by the operation.
    """
    lines = ["[Match]", f"Name={DEFAULT_INTERFACE}", "", "[Network]"]
    if config["management_mode"] == "dhcp":
        lines.append("DHCP=ipv4")
    else:
        lines.append(f"Address={config['cidr']}")
        lines.append(f"Gateway={config['gateway']}")
    if config["ipv6_mode"] == "disabled":
        lines.extend(["IPv6AcceptRA=no", "LinkLocalAddressing=no"])
    elif config["ipv6_mode"] == "auto":
        lines.extend(["IPv6AcceptRA=yes", "LinkLocalAddressing=ipv6"])
    else:
        lines.extend(["IPv6AcceptRA=no", "LinkLocalAddressing=ipv6", f"Address={config['ipv6_cidr']}"])
        if config["ipv6_gateway"]:
            lines.append(f"Gateway={config['ipv6_gateway']}")
    lines.extend(f"DNS={server}" for server in config["dns_servers"])
    content = "\n".join(lines).strip() + "\n"
    NETWORKD_PATH.parent.mkdir(parents=True, exist_ok=True)
    NETWORKD_PATH.write_text(content, encoding="utf-8")
    os.chmod(NETWORKD_PATH, 0o644)


def write_resolv_conf(config: dict[str, object]) -> None:
    """Persist resolv conf.

    Args:
        config: Validated configuration consumed by the operation.
    """
    if not config["dns_servers"]:
        return
    RESOLV_CONF_PATH.write_text("".join(f"nameserver {server}\n" for server in config["dns_servers"]), encoding="utf-8")
    os.chmod(RESOLV_CONF_PATH, 0o644)


def write_nginx_management_server_name(config: dict[str, object]) -> None:
    """Persist nginx management server name.

    Args:
        config: Validated configuration consumed by the operation.
    """
    if not NGINX_MANAGEMENT_PATH.exists():
        return
    text = NGINX_MANAGEMENT_PATH.read_text(encoding="utf-8")
    text = re.sub(r"server_name\s+[^;]+;", f"server_name {config['fqdn']} _;", text, count=1)
    NGINX_MANAGEMENT_PATH.write_text(text, encoding="utf-8")
    os.chmod(NGINX_MANAGEMENT_PATH, 0o644)


def write_initial_firewall_config(config: dict[str, object]) -> None:
    """Persist initial firewall config.

    Args:
        config: Validated configuration consumed by the operation.
    """
    management_rules = []
    source_cidr = str(config["management_source_cidr"])
    management_rules.append(
        f'ip saddr {source_cidr} tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv4 management access"'
        if source_cidr
        else f'iifname "{DEFAULT_INTERFACE}" meta nfproto ipv4 tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv4 management access"'
    )
    if config["ipv6_mode"] == "auto":
        management_rules.append(
            f'iifname "{DEFAULT_INTERFACE}" meta nfproto ipv6 tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv6 management access"'
        )
    elif config["ipv6_mode"] == "static":
        management_rules.append(
            f'ip6 saddr {config["management_source_ipv6_cidr"]} tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv6 management access"'
        )
    rendered_management_rules = "\n    ".join(management_rules)
    content = f"""# Managed by Atlaso. Local changes may be overwritten.
# nftables firewall state for Photon OS appliance images.
flush ruleset
table inet atlaso {{
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname "lo" accept comment "Atlaso loopback"
    ct state established,related accept comment "Atlaso established traffic"
    {rendered_management_rules}
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state established,related accept comment "Atlaso established traffic"
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }}
  chain output {{
    type filter hook output priority filter; policy accept;
    ct state established,related accept comment "Atlaso established traffic"
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }}
}}
"""
    FIREWALL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIREWALL_CONFIG_PATH.write_text(content, encoding="utf-8")
    os.chmod(FIREWALL_CONFIG_PATH, 0o644)


def set_password(username: str, password: str) -> None:
    """Update password.

    Args:
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
    """
    subprocess.run(["chpasswd"], input=f"{username}:{password}\n", text=True, check=True)


def set_hostname(fqdn: str) -> None:
    """Update hostname.

    Args:
        fqdn: Fqdn consumed by set hostname.
    """
    hostnamectl = shutil.which("hostnamectl")
    if hostnamectl:
        subprocess.run([hostnamectl, "set-hostname", fqdn], check=True)
        return
    Path("/etc/hostname").write_text(f"{fqdn}\n", encoding="utf-8")
    hostname = shutil.which("hostname")
    if hostname:
        subprocess.run([hostname, fqdn], check=True)


def configure_root_ssh(enabled: bool) -> None:
    """Update root ssh.

    Args:
        enabled: Whether the associated resource or behavior is enabled.


    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    SSHD_ROOT_LOGIN_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    previous = SSHD_ROOT_LOGIN_CONFIG_PATH.read_text(encoding="utf-8") if SSHD_ROOT_LOGIN_CONFIG_PATH.exists() else None
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten by Appliance Settings apply.",
        f"PermitRootLogin {'yes' if enabled else 'no'}",
    ]
    if enabled:
        lines.extend(["PasswordAuthentication yes", "KbdInteractiveAuthentication yes"])
    SSHD_ROOT_LOGIN_CONFIG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(SSHD_ROOT_LOGIN_CONFIG_PATH, 0o644)
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    try:
        subprocess.run([sshd, "-t"], check=True, text=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        if previous is None:
            SSHD_ROOT_LOGIN_CONFIG_PATH.unlink(missing_ok=True)
        else:
            SSHD_ROOT_LOGIN_CONFIG_PATH.write_text(previous, encoding="utf-8")
            os.chmod(SSHD_ROOT_LOGIN_CONFIG_PATH, 0o644)
        raise OvfCustomizationError("Photon sshd configuration validation failed") from exc


def apply_customization(config: dict[str, object], *, dry_run: bool = False) -> dict[str, object]:
    """Update customization.

    Args:
        config: Validated configuration consumed by the operation.
        dry_run: Whether to report planned actions without mutating host state.


    Returns:
        The apply customization result.
    """
    summary = redacted_summary(config)
    if dry_run:
        return summary

    write_networkd_config(config)
    write_resolv_conf(config)
    write_nginx_management_server_name(config)
    write_initial_firewall_config(config)
    set_hostname(str(config["fqdn"]))
    set_password("root", str(config["root_password"]))
    configure_root_ssh(bool(config["root_ssh_enabled"]))
    bootstrap_user = read_env_file(ENV_PATH).get("ATLASO_BOOTSTRAP_ADMIN_USERNAME", "admin").strip('"') or "admin"
    set_password(bootstrap_user, str(config["admin_password"]))
    write_env_file(
        ENV_PATH,
        {
            "ATLASO_BOOTSTRAP_ADMIN_PASSWORD": config["admin_password"],
            "ATLASO_SECRET_KEY": generate_secret_key(),
            "ATLASO_SECRETS_KEY": generate_secret_key(),
            "ATLASO_APPLIANCE_FQDN": config["fqdn"],
            "ATLASO_APPLIANCE_MANAGEMENT_CIDR": config["cidr"],
            "ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED": str(config["ipv6_enabled"]).lower(),
            "ATLASO_APPLIANCE_MANAGEMENT_IPV6_CIDR": config["ipv6_cidr"],
            "ATLASO_APPLIANCE_MANAGEMENT_IPV6_GATEWAY": config["ipv6_gateway"],
            "ATLASO_APPLIANCE_ROOT_SSH_ENABLED": str(config["root_ssh_enabled"]).lower(),
            "ATLASO_APPLIANCE_EXTERNAL_DNS_SERVERS": ",".join(config["dns_servers"]),
            "ATLASO_MANAGEMENT_SOURCE_CIDR": config["management_source_cidr"],
        },
    )
    write_json_atomic(MARKER_PATH, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Command-line arguments to parse, or ``None`` to use the process arguments.


    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser(description="Apply Atlaso VMware OVF deployment properties.")
    parser.add_argument("--ovf-env-file", default="", help="Read OVF environment XML from a file instead of VMware Tools.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the redacted summary without changing the host.")
    args = parser.parse_args(argv)

    if MARKER_PATH.exists() and not args.dry_run:
        complete_first_boot_initialization()
        log("VMware OVF customization already applied; leaving appliance state unchanged.")
        return 0

    xml_text = Path(args.ovf_env_file).read_text(encoding="utf-8") if args.ovf_env_file else read_ovf_environment()
    properties = parse_ovf_environment(xml_text)
    if not properties:
        if not args.dry_run:
            complete_first_boot_initialization()
        log("No Atlaso VMware OVF properties found; using image defaults.")
        return 0

    try:
        non_network = validate_non_network_properties(properties)
        config = validate_properties(properties, non_network=non_network)
    except OvfManagementNetworkError as exc:
        if args.dry_run:
            log(f"VMware OVF customization failed validation: {exc}")
            return 2
        return wait_for_network_review(properties, str(exc))
    except (OvfCustomizationError, ET.ParseError) as exc:
        log(f"VMware OVF customization failed validation: {exc}")
        return 2

    try:
        summary = apply_customization(config, dry_run=args.dry_run)
    except (OvfCustomizationError, OSError, subprocess.CalledProcessError) as exc:
        log(f"VMware OVF customization could not finish after validation: {type(exc).__name__}")
        if args.dry_run:
            return 2
        return wait_for_network_review(
            properties,
            "The management network validated, but first-time initialization did not finish. "
            "Resolve the condition reported in the customization log, then submit the network review to retry.",
        )

    if not args.dry_run:
        complete_first_boot_initialization()
    log("Applied Atlaso VMware OVF customization: " + json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
