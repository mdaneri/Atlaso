"""Implement ntp service behavior."""

from __future__ import annotations

import json
import re
from ipaddress import ip_address, ip_network
from pathlib import PurePosixPath

from atlaso.app.models import NtpSettings
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces, split_servers

NTP_DEFAULT_HOSTNAME = "ntp.atlaso.internal"
NTP_DEFAULT_UPSTREAM_SOURCE_ROWS: list[dict[str, object]] = [
    {
        "id": "cloudflare-nts",
        "source": "time.cloudflare.com",
        "enabled": True,
        "use_nts": True,
        "description": "Cloudflare public NTS",
    },
    {
        "id": "netnod-nts",
        "source": "nts.netnod.se",
        "enabled": True,
        "use_nts": True,
        "description": "Netnod public NTS",
    },
    {
        "id": "ptb-germany-nts",
        "source": "ptbtime1.ptb.de",
        "enabled": False,
        "use_nts": True,
        "description": "PTB Germany public NTS",
    },
    {
        "id": "pool-0-ntp",
        "source": "0.pool.ntp.org",
        "enabled": False,
        "use_nts": False,
        "description": "NTP Pool rotating server set 0",
    },
    {
        "id": "pool-1-ntp",
        "source": "1.pool.ntp.org",
        "enabled": False,
        "use_nts": False,
        "description": "NTP Pool rotating server set 1",
    },
    {
        "id": "pool-2-ntp",
        "source": "2.pool.ntp.org",
        "enabled": False,
        "use_nts": False,
        "description": "NTP Pool rotating server set 2 (IPv4/IPv6)",
    },
    {
        "id": "pool-3-ntp",
        "source": "3.pool.ntp.org",
        "enabled": False,
        "use_nts": False,
        "description": "NTP Pool rotating server set 3",
    },
    {
        "id": "google-ntp",
        "source": "time.google.com",
        "enabled": False,
        "use_nts": False,
        "description": "Google public NTP (leap smear; do not mix time scales)",
    },
    {
        "id": "nist-ntp",
        "source": "time.nist.gov",
        "enabled": False,
        "use_nts": False,
        "description": "NIST Internet Time Service",
    },
    {
        "id": "meta-ntp",
        "source": "time.facebook.com",
        "enabled": False,
        "use_nts": False,
        "description": "Meta public NTP",
    },
]
NTP_DEFAULT_UPSTREAM_SERVERS = "\n".join(
    str(source["source"]) for source in NTP_DEFAULT_UPSTREAM_SOURCE_ROWS if bool(source["enabled"])
)
NTP_DEFAULT_NTS_KE_PORT = 4460
NTP_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf"
NTP_EFFECTIVE_CONFIG_PATH = "/etc/ntp.conf"
NTP_DRIFT_PATH = "/var/lib/ntp/ntp.drift"
NTP_NTS_COOKIE_PATH = "/var/lib/ntp/nts-keys"

HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
BRACKETED_SOURCE_PATTERN = re.compile(r"^\[([^\]]+)\](?::(\d+))?$")


def parse_ntp_source(value: str) -> tuple[str, int | None, bool]:
    """Parse ntp source.

    Args:
        value: Candidate value consumed by parse NTP source.


    Returns:
        The parsed ntp source.

    Raises:
        ValueError: If an input value is invalid.
    """
    source = str(value or "").strip()
    if not source:
        raise ValueError("source is empty")
    host = source
    port: int | None = None
    bracketed = BRACKETED_SOURCE_PATTERN.fullmatch(source)
    if bracketed:
        host = bracketed.group(1)
        port = int(bracketed.group(2)) if bracketed.group(2) else None
        try:
            if ip_address(host).version != 6:
                raise ValueError
        except ValueError as exc:
            raise ValueError("bracketed source must contain a valid IPv6 address") from exc
    else:
        try:
            parsed_address = ip_address(source)
        except ValueError:
            parsed_address = None
            if source.count(":") == 1:
                possible_host, possible_port = source.rsplit(":", 1)
                if possible_port.isdigit():
                    host = possible_host
                    port = int(possible_port)
            try:
                parsed_address = ip_address(host)
            except ValueError:
                parsed_address = None
        if parsed_address is not None:
            host = str(parsed_address)
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    try:
        parsed_host = ip_address(host)
    except ValueError:
        normalized_host = normalize_hostname(host)
        if not HOSTNAME_PATTERN.fullmatch(normalized_host):
            raise ValueError("host must be an IPv4 address, IPv6 address, or fully qualified DNS name") from None
        return normalized_host, port, False
    return str(parsed_host), port, True


def normalize_ntp_source(value: str) -> str:
    """Normalize ntp source.

    Args:
        value: Candidate value consumed by normalize NTP source.


    Returns:
        The normalize ntp source result.
    """
    host, port, is_ip = parse_ntp_source(value)
    rendered_host = f"[{host}]" if is_ip and ip_address(host).version == 6 else host
    return f"{rendered_host}:{port}" if port is not None else rendered_host


def duplicate_ntp_upstream_source(sources: list[dict[str, object]]) -> str | None:
    """Return duplicate ntp upstream source.

    Args:
        sources: Sources consumed by duplicate NTP upstream source.
    """
    seen: set[str] = set()
    for item in sources:
        source = str(item.get("source") or "").strip()
        if not source:
            continue
        try:
            identity = normalize_ntp_source(source)
        except ValueError:
            identity = source.rstrip(".").lower()
        if identity in seen:
            return source
        seen.add(identity)
    return None


def ntp_upstream_sources(settings: NtpSettings) -> list[dict[str, object]]:
    """Return ntp upstream sources.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    raw_sources = (settings.upstream_sources_json or "").strip()
    sources: list[dict[str, object]] = []
    if raw_sources:
        try:
            parsed = json.loads(raw_sources)
        except json.JSONDecodeError:
            parsed = []
        if isinstance(parsed, list):
            for index, item in enumerate(parsed, start=1):
                if not isinstance(item, dict):
                    continue
                source = str(item.get("source") or "").strip()
                if source:
                    sources.append(
                        {
                            "id": str(item.get("id") or f"source-{index}"),
                            "source": source,
                            "enabled": bool(item.get("enabled", True)),
                            "use_nts": bool(item.get("use_nts", False)),
                            "description": str(item.get("description") or "").strip(),
                        }
                    )
    if sources:
        return sources
    servers = split_servers(settings.upstream_servers)
    if servers == split_servers(NTP_DEFAULT_UPSTREAM_SERVERS):
        return [dict(source) for source in NTP_DEFAULT_UPSTREAM_SOURCE_ROWS]
    return [
        {"id": f"source-{index}", "source": server, "enabled": True, "use_nts": False, "description": ""}
        for index, server in enumerate(servers, start=1)
    ]


def dump_ntp_upstream_sources(sources: list[dict[str, object]]) -> str:
    """Return dump ntp upstream sources.

    Args:
        sources: Sources consumed by dump NTP upstream sources.
    """
    normalized: list[dict[str, object]] = []
    for index, item in enumerate(sources, start=1):
        source = str(item.get("source") or "").strip()
        if source:
            normalized.append(
                {
                    "id": str(item.get("id") or f"source-{index}"),
                    "source": source,
                    "enabled": bool(item.get("enabled", True)),
                    "use_nts": bool(item.get("use_nts", False)),
                    "description": str(item.get("description") or "").strip(),
                }
            )
    return json.dumps(normalized, separators=(",", ":"), sort_keys=True)


NTP_DEFAULT_UPSTREAM_SOURCES_JSON = dump_ntp_upstream_sources(NTP_DEFAULT_UPSTREAM_SOURCE_ROWS)


def default_ntp_upstream_fields(raw_servers: str | None = None) -> dict[str, str]:
    """Return default ntp upstream fields.

    Args:
        raw_servers: Raw servers consumed by default NTP upstream fields.
    """
    servers = split_servers(raw_servers or "")
    if not servers:
        return {"upstream_servers": NTP_DEFAULT_UPSTREAM_SERVERS, "upstream_sources_json": NTP_DEFAULT_UPSTREAM_SOURCES_JSON}
    return {"upstream_servers": "\n".join(servers), "upstream_sources_json": ""}


def enabled_ntp_sources(settings: NtpSettings) -> list[dict[str, object]]:
    """Return enabled ntp sources.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    return [source for source in ntp_upstream_sources(settings) if bool(source.get("enabled", True))]


def split_allow_clients(value: str | None) -> list[str]:
    """Return split allow clients.

    Args:
        value: Candidate value consumed by split allow clients.
    """
    entries: list[str] = []
    for item in str(value or "").replace(",", "\n").splitlines():
        normalized = item.strip().lower()
        if normalized and normalized not in entries:
            entries.append(normalized)
    return entries


def join_allow_clients(values: list[str]) -> str:
    """Return join allow clients.

    Args:
        values: Candidate values consumed by join allow clients.
    """
    entries = split_allow_clients("\n".join(values))
    return "\n".join(entries) if entries else "any"


def normalize_hostname(value: str | None) -> str:
    """Normalize hostname.

    Args:
        value: Candidate value consumed by normalize hostname.


    Returns:
        The normalize hostname result.
    """
    return str(value or "").strip().strip(".").lower()


def ntp_settings_to_dict(settings: NtpSettings) -> dict:
    """Return ntp settings to dict.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    return {
        "id": settings.id,
        "enabled": settings.enabled,
        "hostname": settings.hostname,
        "listen_interface": settings.listen_interface,
        "listen_interfaces": split_interfaces(settings.listen_interface),
        "listen_address": settings.listen_address,
        "listen_addresses": split_addresses(settings.listen_address),
        "port": settings.port,
        "upstream_servers": [str(source["source"]) for source in enabled_ntp_sources(settings)],
        "upstream_sources": ntp_upstream_sources(settings),
        "allow_clients": settings.allow_clients,
        "allow_client_entries": split_allow_clients(settings.allow_clients),
        "nts_server_enabled": settings.nts_server_enabled,
        "nts_server_cert_path": settings.nts_server_cert_path,
        "nts_server_key_path": settings.nts_server_key_path,
        "nts_ke_port": settings.nts_ke_port,
        "minsources": settings.minsources,
        "config_path": settings.config_path,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else "",
    }


def validate_ntp_state(settings: NtpSettings, available_interfaces: set[str]) -> list[str]:
    """Validate ntp state.

    Args:
        settings: Current Atlaso settings used to configure the operation.
        available_interfaces: Candidate available interfaces to validate.


    Returns:
        The validate ntp state result.
    """
    errors: list[str] = []
    hostname = normalize_hostname(settings.hostname)
    if not hostname or not HOSTNAME_PATTERN.fullmatch(hostname):
        errors.append("NTP hostname must be a valid fully qualified DNS name.")
    duplicate_source = duplicate_ntp_upstream_source(ntp_upstream_sources(settings))
    if duplicate_source:
        errors.append(f"NTP upstream source {duplicate_source} is duplicated. Source names must be unique.")
    if settings.enabled:
        listen_interfaces = split_interfaces(settings.listen_interface)
        if not listen_interfaces:
            errors.append("NTP listen interface is required when the service is enabled.")
        for interface_name in listen_interfaces:
            if interface_name not in available_interfaces:
                errors.append(f"NTP listen interface {interface_name} is not an available access or VLAN interface.")
        listen_addresses = split_addresses(settings.listen_address)
        if not listen_addresses:
            errors.append("NTP listen address is required when the service is enabled.")
        for address in listen_addresses:
            try:
                ip_address(address)
            except ValueError:
                errors.append(f"NTP listen address {address} must be a valid IPv4 or IPv6 address.")
        sources = enabled_ntp_sources(settings)
        if not sources:
            errors.append("At least one NTP upstream server is required.")
        for source in sources:
            server = str(source.get("source") or "").strip()
            try:
                _host, _port, is_ip = parse_ntp_source(server)
            except ValueError:
                errors.append(f"NTP upstream server {server} must be an IPv4 address, IPv6 address, or fully qualified DNS name with an optional port.")
                continue
            if source.get("use_nts") and is_ip:
                errors.append(f"NTS upstream {server} must use a certificate-valid DNS hostname, not an IP address.")
    if settings.port != 123:
        errors.append("NTP port must be UDP 123.")
    if settings.nts_server_enabled:
        for label, raw_path in {"certificate": settings.nts_server_cert_path, "key": settings.nts_server_key_path}.items():
            path = raw_path.strip()
            if not path:
                errors.append(f"NTS server {label} path is required when NTS server mode is enabled.")
            elif not PurePosixPath(path).is_absolute():
                errors.append(f"NTS server {label} path must be absolute.")
    if settings.nts_ke_port != NTP_DEFAULT_NTS_KE_PORT:
        errors.append("NTS-KE port must be TCP 4460.")
    if settings.minsources is not None and settings.minsources < 1:
        errors.append("NTP minimum sources must be at least 1.")
    allow_entries = split_allow_clients(settings.allow_clients)
    if not allow_entries:
        errors.append("NTP client allow list must include 'any' or at least one IPv4/IPv6 CIDR.")
    elif "any" in allow_entries and len(allow_entries) > 1:
        errors.append("NTP client allow list can use 'any' only by itself.")
    else:
        for entry in allow_entries:
            if entry == "any":
                continue
            try:
                ip_network(entry, strict=False)
            except ValueError:
                errors.append(f"NTP client allow entry {entry} must be 'any' or a valid IPv4/IPv6 CIDR.")
    if not str(settings.config_path or "").startswith("/"):
        errors.append("NTP config path must be absolute.")
    return errors


def _restrict_line(entry: str) -> str:
    """Return restrict line.

    Args:
        entry: Entry consumed by restrict line.
    """
    network = ip_network(entry, strict=False)
    return f"restrict {network.network_address} mask {network.netmask} kod limited nomodify noquery"


def render_ntp_config(settings: NtpSettings) -> str:
    """Render ntp config.

    Args:
        settings: Current Atlaso settings used to configure the operation.


    Returns:
        The rendered ntp config.
    """
    sources = enabled_ntp_sources(settings)
    listen_addresses = split_addresses(settings.listen_address)
    allow_entries = split_allow_clients(settings.allow_clients) or ["any"]
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        f"# Atlaso NTP enabled: {str(bool(settings.enabled)).lower()}",
        f"# Atlaso NTP hostname: {normalize_hostname(settings.hostname)}",
        f"# Atlaso NTP listen interfaces: {', '.join(split_interfaces(settings.listen_interface)) or 'none'}",
        f"# Atlaso NTP listen addresses: {', '.join(listen_addresses) or 'none'}",
        f"# Atlaso NTP client allow list: {', '.join(allow_entries)}",
        f"driftfile {NTP_DRIFT_PATH}",
        "interface ignore wildcard",
    ]
    lines.extend(f"interface listen {address}" for address in listen_addresses)
    lines.extend(["restrict 127.0.0.1", "restrict ::1"])
    lines.append("restrict source kod limited nomodify noquery")
    if "any" in allow_entries:
        lines.append("restrict default kod limited nomodify noquery")
    else:
        lines.append("restrict default ignore")
        lines.extend(_restrict_line(entry) for entry in allow_entries)
    if settings.minsources is not None:
        lines.append(f"tos minsane {settings.minsources}")
    if settings.nts_server_enabled:
        lines.extend(
            [
                "nts enable",
                f"nts cert {settings.nts_server_cert_path.strip()}",
                f"nts key {settings.nts_server_key_path.strip()}",
                f"nts cookie {NTP_NTS_COOKIE_PATH}",
            ]
        )
    lines.append("")
    for source in sources:
        raw_source = str(source["source"]).strip()
        try:
            rendered_source = normalize_ntp_source(raw_source)
        except ValueError:
            rendered_source = raw_source
        parts = ["server", rendered_source, "iburst"]
        if source.get("use_nts"):
            parts.append("nts")
        lines.append(" ".join(parts))
    lines.append("")
    return "\n".join(lines)
