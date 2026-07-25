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
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, ip_address
import xml.etree.ElementTree as ET


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
LOG_PATH = Path("/var/log/atlaso/vmware-ovf-customize.log")
DEFAULT_INTERFACE = "eth0"
FQDN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class OvfCustomizationError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def log(message: str) -> None:
    line = f"{utc_now()} {message}\n"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass
    print(message)


def attr_value(element: ET.Element, local_name: str) -> str:
    for key, value in element.attrib.items():
        if key == local_name or key.endswith(f"}}{local_name}"):
            return value
    return ""


def parse_ovf_environment(xml_text: str) -> dict[str, str]:
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


def split_list(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\s,;]+", value or "") if item.strip()]


def validate_fqdn(value: str) -> str:
    fqdn = value.strip().lower().rstrip(".")
    if not fqdn or "." not in fqdn or not FQDN_PATTERN.match(fqdn):
        raise OvfCustomizationError("atlaso.fqdn must be a fully qualified DNS name")
    if fqdn.endswith(".local"):
        raise OvfCustomizationError("atlaso.fqdn must not use .local")
    return fqdn


def validate_dns_servers(value: str, *, required: bool = False) -> list[str]:
    servers = split_list(value)
    if required and not servers:
        raise OvfCustomizationError("atlaso.dns_servers must include at least one DNS server")
    for server in servers:
        try:
            ip_address(server)
        except ValueError as exc:
            raise OvfCustomizationError(f"DNS server must be an IP address: {server}") from exc
    return servers


def parse_boolean_property(properties: dict[str, str], key: str, *, default: bool = False) -> bool:
    value = properties.get(key, "").strip().lower()
    if not value:
        return default
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise OvfCustomizationError(f"{key} must be true or false")


def validate_properties(properties: dict[str, str]) -> dict[str, object]:
    missing = sorted(key for key in REQUIRED_PROPERTIES if not properties.get(key, "").strip())
    if missing:
        raise OvfCustomizationError(f"Missing required OVF properties: {', '.join(missing)}")
    for password_key in (PROPERTY_ADMIN_PASSWORD, PROPERTY_ROOT_PASSWORD):
        if len(properties[password_key]) < MINIMUM_PASSWORD_LENGTH:
            raise OvfCustomizationError(
                f"{password_key} must be at least {MINIMUM_PASSWORD_LENGTH} characters"
            )

    _legacy_management_mode = properties.get(PROPERTY_MANAGEMENT_MODE, "").strip().lower()
    # Kept parse-compatible for existing deployment automation; address presence now owns IPv4 behavior.
    cidr: IPv4Interface | None = None
    gateway: IPv4Address | None = None
    cidr_value = properties.get(PROPERTY_CIDR, "").strip()
    gateway_value = properties.get(PROPERTY_GATEWAY, "").strip()
    management_mode = "static" if cidr_value else "dhcp"
    if cidr_value:
        if not gateway_value:
            raise OvfCustomizationError("atlaso.gateway is required when atlaso.cidr is supplied")
        try:
            cidr = IPv4Interface(cidr_value)
        except ValueError as exc:
            raise OvfCustomizationError("atlaso.cidr must be an IPv4 CIDR such as 192.168.10.10/24") from exc

        try:
            gateway = IPv4Address(gateway_value)
        except ValueError as exc:
            raise OvfCustomizationError("atlaso.gateway must be an IPv4 address") from exc
    elif gateway_value:
        raise OvfCustomizationError("atlaso.gateway cannot be supplied without atlaso.cidr")

    ipv6_enabled = parse_boolean_property(properties, PROPERTY_IPV6_ENABLED)
    ipv6_cidr_value = properties.get(PROPERTY_IPV6_CIDR, "").strip()
    ipv6_gateway_value = properties.get(PROPERTY_IPV6_GATEWAY, "").strip()
    ipv6_cidr: IPv6Interface | None = None
    ipv6_gateway: IPv6Address | None = None
    if not ipv6_enabled and (ipv6_cidr_value or ipv6_gateway_value):
        raise OvfCustomizationError("IPv6 CIDR and gateway require atlaso.ipv6_enabled=true")
    if ipv6_enabled and ipv6_cidr_value:
        try:
            ipv6_cidr = IPv6Interface(ipv6_cidr_value)
        except ValueError as exc:
            raise OvfCustomizationError("atlaso.ipv6_cidr must be an IPv6 CIDR such as fd00:10::10/64") from exc
        if ipv6_gateway_value:
            try:
                ipv6_gateway = IPv6Address(ipv6_gateway_value)
            except ValueError as exc:
                raise OvfCustomizationError("atlaso.ipv6_gateway must be an IPv6 address") from exc
            if not ipv6_gateway.is_link_local and ipv6_gateway not in ipv6_cidr.network:
                raise OvfCustomizationError("atlaso.ipv6_gateway must be link-local or on-link for atlaso.ipv6_cidr")
            if ipv6_gateway == ipv6_cidr.ip:
                raise OvfCustomizationError("atlaso.ipv6_gateway cannot equal the management IPv6 address")
    elif ipv6_gateway_value:
        raise OvfCustomizationError("atlaso.ipv6_gateway cannot be supplied without atlaso.ipv6_cidr")

    fqdn = validate_fqdn(properties[PROPERTY_FQDN])
    dns_servers = validate_dns_servers(properties.get(PROPERTY_DNS, ""))
    return {
        "management_mode": management_mode,
        "cidr": str(cidr) if cidr else "dhcp",
        "gateway": str(gateway) if gateway else "",
        "ipv6_enabled": ipv6_enabled,
        "ipv6_mode": "static" if ipv6_cidr else ("auto" if ipv6_enabled else "disabled"),
        "ipv6_cidr": str(ipv6_cidr) if ipv6_cidr else "",
        "ipv6_gateway": str(ipv6_gateway) if ipv6_gateway else "",
        "fqdn": fqdn,
        "dns_servers": dns_servers,
        "admin_password": properties[PROPERTY_ADMIN_PASSWORD],
        "root_password": properties[PROPERTY_ROOT_PASSWORD],
        "root_ssh_enabled": parse_boolean_property(properties, PROPERTY_ROOT_SSH_ENABLED),
        "management_source_cidr": str(cidr.network) if cidr else "",
        "management_source_ipv6_cidr": str(ipv6_cidr.network) if ipv6_cidr else "",
    }


def redacted_summary(config: dict[str, object]) -> dict[str, object]:
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
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def generate_secret_key() -> str:
    return secrets.token_urlsafe(48)


def read_env_file(path: Path) -> dict[str, str]:
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
    if not config["dns_servers"]:
        return
    RESOLV_CONF_PATH.write_text("".join(f"nameserver {server}\n" for server in config["dns_servers"]), encoding="utf-8")
    os.chmod(RESOLV_CONF_PATH, 0o644)


def write_nginx_management_server_name(config: dict[str, object]) -> None:
    if not NGINX_MANAGEMENT_PATH.exists():
        return
    text = NGINX_MANAGEMENT_PATH.read_text(encoding="utf-8")
    text = re.sub(r"server_name\s+[^;]+;", f"server_name {config['fqdn']} _;", text, count=1)
    NGINX_MANAGEMENT_PATH.write_text(text, encoding="utf-8")
    os.chmod(NGINX_MANAGEMENT_PATH, 0o644)


def write_initial_firewall_config(config: dict[str, object]) -> None:
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
    subprocess.run(["chpasswd"], input=f"{username}:{password}\n", text=True, check=True)


def set_hostname(fqdn: str) -> None:
    hostnamectl = shutil.which("hostnamectl")
    if hostnamectl:
        subprocess.run([hostnamectl, "set-hostname", fqdn], check=True)
        return
    Path("/etc/hostname").write_text(f"{fqdn}\n", encoding="utf-8")
    hostname = shutil.which("hostname")
    if hostname:
        subprocess.run([hostname, fqdn], check=True)


def configure_root_ssh(enabled: bool) -> None:
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
    MARKER_PATH.parent.mkdir(parents=True, exist_ok=True)
    MARKER_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(MARKER_PATH, 0o640)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply Atlaso VMware OVF deployment properties.")
    parser.add_argument("--ovf-env-file", default="", help="Read OVF environment XML from a file instead of VMware Tools.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the redacted summary without changing the host.")
    args = parser.parse_args(argv)

    if MARKER_PATH.exists() and not args.dry_run:
        log("VMware OVF customization already applied; leaving appliance state unchanged.")
        return 0

    xml_text = Path(args.ovf_env_file).read_text(encoding="utf-8") if args.ovf_env_file else read_ovf_environment()
    properties = parse_ovf_environment(xml_text)
    if not properties:
        log("No Atlaso VMware OVF properties found; using image defaults.")
        return 0

    try:
        config = validate_properties(properties)
        summary = apply_customization(config, dry_run=args.dry_run)
    except (OvfCustomizationError, ET.ParseError) as exc:
        log(f"VMware OVF customization failed validation: {exc}")
        return 2
    except subprocess.CalledProcessError as exc:
        log(f"VMware OVF customization command failed: {exc.cmd} exit_code={exc.returncode}")
        return exc.returncode or 1

    log("Applied Atlaso VMware OVF customization: " + json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
