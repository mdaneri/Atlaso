import json
import re
import shlex
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address, ip_interface, ip_network
from pathlib import PurePosixPath

from atlaso.app.models import DhcpOption, DhcpReservation, DhcpScope, DhcpSettings, DnsRecord, DnsSettings, PhysicalInterface, VlanInterface

DNS_CONDITIONAL_FORWARDERS_SETTING_KEY = "dns.conditional_forwarders"
DNSMASQ_LEASE_FILE_PATH = "/var/lib/atlaso/dnsmasq/dhcp.leases"
DNSMASQ_DNSSEC_TRUST_ANCHORS_PATH = "/var/lib/atlaso/apply/dnsmasq/atlaso-trust-anchors.conf"
DHCP_DENY_RESERVATION_DESCRIPTION_PREFIX = "Deny DHCP for "
DNS_RECORD_TYPES = {"A", "AAAA", "CNAME", "TXT", "SRV", "MX", "CAA", "PTR"}
DNS_HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
DNS_AUTHORITATIVE_TTL_DEFAULT = 3600
DNS_AUTHORITATIVE_REFRESH_DEFAULT = 1200
DNS_AUTHORITATIVE_RETRY_DEFAULT = 180
DNS_AUTHORITATIVE_EXPIRE_DEFAULT = 1209600


def _dhcp_scope_network(scope: DhcpScope):
    try:
        return ip_network(f"{scope.site_address}/{scope.prefix_length}", strict=False)
    except ValueError:
        return None


def _parse_compact_ipv4_endpoint(value: str, start: IPv4Address) -> IPv4Address:
    parts = value.split(".")
    if not 1 <= len(parts) <= 4 or any(not part.isdigit() for part in parts):
        raise ValueError
    if len(parts) == 4:
        return IPv4Address(value)
    start_parts = str(start).split(".")
    merged = [*start_parts[: 4 - len(parts)], *parts]
    return IPv4Address(".".join(merged))


def parse_dhcp_range_expression(scope: DhcpScope) -> tuple[list[str], list[tuple[object, object]]]:
    errors: list[str] = []
    ranges: list[tuple[object, object]] = []
    label = f"DHCP IP zone {scope.name}"
    family = dhcp_scope_address_family(scope)
    required_version = 6 if family == "ipv6" else 4
    network = _dhcp_scope_network(scope)
    expression = (scope.range_expression or "").strip()
    if not expression:
        return [f"{label} range is required."], []
    for raw_part in expression.split(","):
        part = raw_part.strip()
        if not part:
            continue
        start_text, separator, end_text = part.partition("-")
        start_text = start_text.strip()
        end_text = end_text.strip() if separator else start_text
        try:
            start = ip_address(start_text)
        except ValueError:
            errors.append(f"{label} range {part} has an invalid start address.")
            continue
        try:
            if isinstance(start, IPv4Address):
                end = _parse_compact_ipv4_endpoint(end_text, start)
            else:
                end = ip_address(end_text)
        except ValueError:
            errors.append(f"{label} range {part} has an invalid end address.")
            continue
        if start.version != required_version or end.version != required_version:
            errors.append(f"{label} range {part} must use {'IPv6' if required_version == 6 else 'IPv4'} addresses.")
            continue
        if network and (start not in network or end not in network):
            errors.append(f"{label} range {part} must stay inside {network.with_prefixlen}.")
            continue
        if int(start) > int(end):
            errors.append(f"{label} range {part} start must be less than or equal to end.")
            continue
        ranges.append((start, end))
    if not ranges and not errors:
        errors.append(f"{label} range is required.")
    return errors, ranges


def compact_dhcp_range_expression(scope: DhcpScope) -> str:
    errors, ranges = parse_dhcp_range_expression(scope)
    if errors or not ranges:
        return (scope.range_expression or "").strip()
    return ", ".join(str(start) if start == end else f"{start}-{end}" for start, end in ranges)


def split_servers(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.replace(",", "\n").splitlines() if item.strip()]


def join_servers(servers: list[str]) -> str:
    return "\n".join(server.strip() for server in servers if server.strip())


def split_conditional_forwarders(raw: str | None) -> list[dict[str, str]]:
    if not raw:
        return []
    forwarders: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            domain, server_text = line.split("=", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            domain, server_text = parts
        normalized_domain = domain.strip().strip(".").lower()
        for server in server_text.split(","):
            normalized_server = server.strip()
            key = (normalized_domain, normalized_server)
            if normalized_domain and normalized_server and key not in seen:
                seen.add(key)
                forwarders.append({"domain": normalized_domain, "server": normalized_server})
    return forwarders


def join_conditional_forwarders(forwarders: list[dict[str, str]]) -> str:
    grouped: dict[str, list[str]] = {}
    for forwarder in forwarders:
        domain = str(forwarder.get("domain", "")).strip().strip(".").lower()
        server = str(forwarder.get("server", "")).strip()
        if domain and server:
            grouped.setdefault(domain, [])
            if server not in grouped[domain]:
                grouped[domain].append(server)
    return "\n".join(f"{domain}={','.join(servers)}" for domain, servers in grouped.items())


def split_interfaces(raw: str | None) -> list[str]:
    if not raw:
        return []
    return _ordered_unique([item.strip() for item in raw.replace(",", "\n").splitlines() if item.strip()])


def join_interfaces(interfaces: list[str]) -> str:
    return "\n".join(split_interfaces("\n".join(interfaces)))


def split_addresses(raw: str | None) -> list[str]:
    if not raw:
        return []
    return _ordered_unique([item.strip() for item in raw.replace(",", "\n").splitlines() if item.strip()])


def join_addresses(addresses: list[str]) -> str:
    return "\n".join(split_addresses("\n".join(addresses)))


def split_domains(raw: str | None) -> list[str]:
    if not raw:
        return []
    return _ordered_unique([item.strip().strip(".").lower() for item in raw.replace(",", "\n").splitlines() if item.strip()])


def join_domains(domains: list[str]) -> str:
    return "\n".join(split_domains("\n".join(domains)))


def authoritative_server_name(settings: DnsSettings) -> str:
    domains = split_domains(settings.domain) or ["atlaso.internal"]
    return (settings.authoritative_server or f"ns1.{domains[0]}").strip().strip(".").lower()


def authoritative_contact_name(settings: DnsSettings) -> str:
    domains = split_domains(settings.domain) or ["atlaso.internal"]
    return (settings.authoritative_contact or f"hostmaster.{domains[0]}").strip().strip(".").lower()


def ensure_dns_authoritative_defaults(settings: DnsSettings, *, now: datetime | None = None) -> bool:
    changed = False
    if not (settings.authoritative_server or "").strip():
        settings.authoritative_server = authoritative_server_name(settings)
        changed = True
    if not (settings.authoritative_contact or "").strip():
        settings.authoritative_contact = authoritative_contact_name(settings)
        changed = True
    if settings.authoritative_ttl is None:
        settings.authoritative_ttl = DNS_AUTHORITATIVE_TTL_DEFAULT
        changed = True
    if settings.authoritative_refresh is None:
        settings.authoritative_refresh = DNS_AUTHORITATIVE_REFRESH_DEFAULT
        changed = True
    if settings.authoritative_retry is None:
        settings.authoritative_retry = DNS_AUTHORITATIVE_RETRY_DEFAULT
        changed = True
    if settings.authoritative_expire is None:
        settings.authoritative_expire = DNS_AUTHORITATIVE_EXPIRE_DEFAULT
        changed = True
    if not settings.authoritative_serial or settings.authoritative_serial <= 0:
        settings.authoritative_serial = int((now or datetime.now(timezone.utc)).timestamp())
        changed = True
    return changed


def authoritative_zone_metadata(settings: DnsSettings, domain: str) -> dict[str, object]:
    server = authoritative_server_name(settings)
    zone = domain.strip().strip(".").lower()
    owner = f"{server}."
    if server == zone:
        owner = "@"
    elif server.endswith(f".{zone}"):
        owner = server[: -(len(zone) + 1)]
    return {
        "server": server,
        "contact": authoritative_contact_name(settings),
        "ttl": int(settings.authoritative_ttl or DNS_AUTHORITATIVE_TTL_DEFAULT),
        "serial": int(settings.authoritative_serial or 0),
        "refresh": int(settings.authoritative_refresh or DNS_AUTHORITATIVE_REFRESH_DEFAULT),
        "retry": int(settings.authoritative_retry or DNS_AUTHORITATIVE_RETRY_DEFAULT),
        "expire": int(settings.authoritative_expire or DNS_AUTHORITATIVE_EXPIRE_DEFAULT),
        "glue_owner": owner,
        "glue_addresses": split_addresses(settings.listen_address),
    }


def record_data(record: DnsRecord) -> dict[str, object]:
    raw_data = (record.record_data_json or "").strip()
    if raw_data:
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            return parsed
    return dns_record_data_from_value(record.record_type, record.address)


def dump_dns_record_data(record_type: str, address: str, data: dict[str, object] | None = None) -> str:
    payload = data if data is not None else dns_record_data_from_value(record_type, address)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True) if payload else ""


def dns_record_data_from_value(record_type: str, value: str) -> dict[str, object]:
    normalized_type = record_type.strip().upper()
    text = value.strip()
    if normalized_type == "SRV":
        parts = _split_record_value(text)
        if len(parts) >= 2:
            return {
                "target": parts[0],
                "port": parts[1],
                "priority": parts[2] if len(parts) > 2 else "0",
                "weight": parts[3] if len(parts) > 3 else "0",
            }
    if normalized_type == "MX":
        parts = _split_record_value(text)
        if len(parts) >= 1:
            return {
                "target": parts[0],
                "preference": parts[1] if len(parts) > 1 else "10",
            }
    if normalized_type == "CAA":
        parts = _split_record_value(text)
        if len(parts) >= 3:
            return {"flags": parts[0], "tag": parts[1], "value": " ".join(parts[2:])}
    return {}


def _split_record_value(value: str) -> list[str]:
    try:
        parts = shlex.split(value.replace(",", " "))
    except ValueError:
        parts = value.replace(",", " ").split()
    return [part.strip() for part in parts if part.strip()]


def _record_data_value(data: dict[str, object], key: str, fallback: str = "") -> str:
    return str(data.get(key) or fallback).strip()


def _quote_dnsmasq_text(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def dns_record_value_for_zone_file(record_type: str, value: str, data: dict[str, object] | None = None) -> str:
    normalized_type = record_type.strip().upper()
    payload = data or dns_record_data_from_value(normalized_type, value)
    if normalized_type == "MX":
        target = _record_data_value(payload, "target")
        preference = _record_data_value(payload, "preference", "10")
        return f"{preference} {target}".strip()
    if normalized_type == "SRV":
        priority = _record_data_value(payload, "priority", "0")
        weight = _record_data_value(payload, "weight", "0")
        port = _record_data_value(payload, "port")
        target = _record_data_value(payload, "target")
        return f"{priority} {weight} {port} {target}".strip()
    return value


def dns_record_value_from_zone_file(record_type: str, value: str) -> str:
    normalized_type = record_type.strip().upper()
    parts = _split_record_value(value)
    if normalized_type == "MX" and len(parts) >= 2:
        return f"{parts[1]} {parts[0]}"
    if normalized_type == "SRV" and len(parts) >= 4:
        return f"{parts[3]} {parts[2]} {parts[0]} {parts[1]}"
    return value


def parse_hosts_records(hosts_text: str) -> tuple[list[dict[str, str | bool | None]], list[str]]:
    records: list[dict[str, str | bool | None]] = []
    errors: list[str] = []
    seen: dict[tuple[str, str], str] = {}
    for line_number, raw_line in enumerate(hosts_text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            errors.append(f"Line {line_number}: expected an IP address followed by at least one hostname.")
            continue
        address = parts[0]
        parsed_address = _validate_ip(address, f"Line {line_number} address", errors)
        if not parsed_address:
            continue
        record_type = "AAAA" if parsed_address.version == 6 else "A"
        for hostname in parts[1:]:
            normalized = hostname.strip().lower()
            key = (normalized, record_type)
            existing_address = seen.get(key)
            if existing_address == address:
                continue
            if existing_address:
                errors.append(f"Line {line_number}: {normalized} already maps to {existing_address}.")
                continue
            seen[key] = address
            records.append(
                {
                    "hostname": normalized,
                    "record_type": record_type,
                    "address": address,
                    "description": "Imported from hosts editor",
                    "enabled": True,
                }
            )
    return records, errors


def render_hosts_records(records: list[DnsRecord]) -> str:
    lines = [
        "# Atlaso hosts editor",
        "# Format: <ip-address> <hostname> [alias ...]",
    ]
    for record in records:
        if record.enabled is not False and record.record_type.upper() in {"A", "AAAA"}:
            lines.append(f"{record.address} {record.hostname}")
    return "\n".join(lines) + "\n"


def render_zone_hosts_records(records: list[dict]) -> str:
    lines = [
        "# Atlaso hosts import",
        "# Format: <ip-address> <hostname> [alias ...]",
    ]
    for record in records:
        if record["enabled"] is not False and record["record_type"].upper() in {"A", "AAAA"}:
            lines.append(f"{record['address']} {record['host_label']}")
    return "\n".join(lines) + "\n"


def render_zone_file(domain: str, records: list[dict], dns_settings: DnsSettings | None = None) -> str:
    metadata = authoritative_zone_metadata(dns_settings, domain) if dns_settings and dns_settings.authoritative else None
    ttl = int(metadata["ttl"]) if metadata else DNS_AUTHORITATIVE_TTL_DEFAULT
    lines = [
        f"$ORIGIN {domain}.",
        f"$TTL {ttl}",
        "",
    ]
    if metadata:
        server = str(metadata["server"])
        contact = str(metadata["contact"])
        lines.extend(
            [
                f"@                        IN SOA   {server}. {contact}. {metadata['serial']} {metadata['refresh']} {metadata['retry']} {metadata['expire']} {metadata['ttl']}",
                f"@                        IN NS    {server}.",
            ]
        )
        for address in metadata["glue_addresses"]:
            record_type = "AAAA" if ":" in str(address) else "A"
            lines.append(f"{str(metadata['glue_owner']):<24} IN {record_type:<5} {address}")
        lines.append("")
    for record in records:
        if record["enabled"] is False:
            continue
        record_type = record["record_type"].upper()
        if record_type not in DNS_RECORD_TYPES:
            continue
        if metadata and record_type in {"A", "AAAA"} and record["hostname"].strip().strip(".").lower() == metadata["server"]:
            continue
        data = record.get("record_data")
        payload = data if isinstance(data, dict) else dns_record_data_from_value(record_type, str(record["address"]))
        value = dns_record_value_for_zone_file(record_type, str(record["address"]), payload)
        lines.append(f"{record['host_label']:<24} IN {record_type:<5} {value}")
    return "\n".join(lines) + "\n"


def _zone_logical_lines(zone_text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    depth = 0
    for line_number, raw_line in enumerate(zone_text.splitlines(), start=1):
        line = raw_line.split(";", 1)[0].strip()
        if not line:
            continue
        if not buffer:
            start_line = line_number
        buffer.append(line)
        depth += line.count("(") - line.count(")")
        if depth <= 0:
            logical = " ".join(buffer).replace("(", " ").replace(")", " ")
            lines.append((start_line, " ".join(logical.split())))
            buffer = []
            depth = 0
    if buffer:
        lines.append((start_line, " ".join(" ".join(buffer).replace("(", " ").replace(")", " ").split())))
    return lines


def _absolute_zone_name(value: str, origin: str) -> str:
    normalized = value.strip().lower()
    if normalized == "@":
        return origin
    if normalized.endswith("."):
        return normalized[:-1]
    return f"{normalized}.{origin}" if normalized != origin and not normalized.endswith(f".{origin}") else normalized


def parse_zone_records(
    zone_text: str,
    domain: str,
    dns_settings: DnsSettings | None = None,
) -> tuple[list[dict[str, str | bool | None]], list[str]]:
    records: list[dict[str, str | bool | None]] = []
    errors: list[str] = []
    origin = domain.strip().strip(".").lower()
    scoped_domain = origin
    metadata = authoritative_zone_metadata(dns_settings, scoped_domain) if dns_settings and dns_settings.authoritative else None
    for line_number, line in _zone_logical_lines(zone_text):
        if line.upper().startswith("$TTL"):
            parts = line.split()
            if metadata and len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) != metadata["ttl"]:
                errors.append(
                    f"Line {line_number}: zone TTL must match the Authoritative DNS setting ({metadata['ttl']})."
                )
            continue
        if line.upper().startswith("$ORIGIN"):
            parts = line.split()
            if len(parts) >= 2:
                origin = parts[1].strip().strip(".").lower()
                if origin != scoped_domain:
                    errors.append(f"Line {line_number}: zone origin must remain {scoped_domain}.")
            continue
        parts = line.split()
        if len(parts) < 3:
            errors.append(f"Line {line_number}: expected <host> [ttl] [IN] <type> <value>.")
            continue
        host = parts[0]
        tokens = parts[1:]
        if tokens and tokens[0].isdigit():
            tokens = tokens[1:]
        if tokens and tokens[0].upper() == "IN":
            tokens = tokens[1:]
        if len(tokens) < 2:
            errors.append(f"Line {line_number}: expected a record type and value.")
            continue
        record_type = tokens[0].upper()
        hostname = _zone_hostname(host, origin)
        if record_type in {"SOA", "NS"}:
            if not metadata:
                errors.append(
                    f"Line {line_number}: enable Authoritative DNS before importing {record_type} structural records."
                )
                continue
            if hostname != scoped_domain:
                errors.append(f"Line {line_number}: {record_type} must be owned by the zone apex (@).")
                continue
            if record_type == "NS":
                imported_server = _absolute_zone_name(tokens[1], origin)
                if imported_server != metadata["server"]:
                    errors.append(
                        f"Line {line_number}: primary NS must match the Authoritative DNS setting ({metadata['server']})."
                    )
                continue
            values = tokens[1:]
            if len(values) < 7:
                errors.append(
                    f"Line {line_number}: SOA requires primary server, administrator, serial, refresh, retry, expire, and minimum TTL."
                )
                continue
            imported = {
                "server": _absolute_zone_name(values[0], origin),
                "contact": _absolute_zone_name(values[1], origin),
                "serial": values[2],
                "refresh": values[3],
                "retry": values[4],
                "expire": values[5],
                "ttl": values[6],
            }
            expected = {key: str(metadata[key]) for key in imported}
            imported = {key: str(value) for key, value in imported.items()}
            if imported != expected:
                errors.append(
                    f"Line {line_number}: SOA metadata must match the shared Authoritative DNS settings."
                )
            continue
        if record_type in {"TXT", "SRV", "MX", "CAA"}:
            value = " ".join(tokens[1:]).strip()
        else:
            value = tokens[1].strip().strip(".").lower()
        value = dns_record_value_from_zone_file(record_type, value)
        if metadata and record_type in {"A", "AAAA"} and hostname == metadata["server"]:
            if value not in metadata["glue_addresses"]:
                errors.append(
                    f"Line {line_number}: nameserver glue must use a selected DNS listen address."
                )
            continue
        record_errors = validate_dns_record(hostname, record_type, value)
        if record_errors:
            errors.extend(f"Line {line_number}: {error}" for error in record_errors)
            continue
        records.append(
            {
                "hostname": hostname,
                "record_type": record_type,
                "address": value,
                "record_data_json": dump_dns_record_data(record_type, value),
                "description": "Imported from zone editor",
                "enabled": True,
            }
        )
    return records, errors


def dns_reverse_records(records: list[DnsRecord]) -> list[dict[str, str]]:
    reverse_records: list[dict[str, str]] = []
    for record in records:
        record_type = record.record_type.upper()
        if record.enabled is False or record_type not in {"A", "AAAA"}:
            continue
        try:
            parsed_address = ip_address(record.address)
        except ValueError:
            continue
        ptr_name = parsed_address.reverse_pointer
        zone = _reverse_zone_for_address(parsed_address)
        owner = ptr_name.removesuffix(f".{zone}") if ptr_name.endswith(f".{zone}") else ptr_name
        reverse_records.append(
            {
                "owner": owner,
                "zone": zone,
                "ptr_name": ptr_name,
                "target": record.hostname.strip().strip(".").lower(),
                "address": record.address,
                "record_type": record_type,
            }
        )
    return reverse_records


def dns_settings_to_dict(settings: DnsSettings, conditional_forwarders: str | None = None) -> dict:
    return {
        "id": settings.id,
        "enabled": settings.enabled,
        "listen_interface": settings.listen_interface,
        "listen_address": settings.listen_address,
        "domain": settings.domain,
        "upstream_servers": split_servers(settings.upstream_servers),
        "conditional_forwarders": split_conditional_forwarders(conditional_forwarders),
        "cache_size": settings.cache_size,
        "expand_hosts": settings.expand_hosts,
        "authoritative": settings.authoritative,
        "authoritative_server": authoritative_server_name(settings),
        "authoritative_contact": authoritative_contact_name(settings),
        "authoritative_ttl": settings.authoritative_ttl,
        "authoritative_serial": settings.authoritative_serial,
        "authoritative_refresh": settings.authoritative_refresh,
        "authoritative_retry": settings.authoritative_retry,
        "authoritative_expire": settings.authoritative_expire,
        "dnssec_enabled": settings.dnssec_enabled,
        "rebind_protection_enabled": settings.rebind_protection_enabled,
        "rebind_domain_exemptions": settings.rebind_domain_exemptions,
        "query_logging_mode": settings.query_logging_mode,
        "config_path": settings.config_path,
        "updated_at": settings.updated_at,
    }


def effective_dns_upstream_servers(settings: DnsSettings, fallback_servers: list[str] | None = None) -> list[str]:
    configured = _non_loopback_servers(split_servers(settings.upstream_servers))
    if configured:
        return configured
    return _non_loopback_servers([server.strip() for server in fallback_servers or [] if server.strip()])


def dhcp_settings_to_scope(settings: DhcpSettings) -> dict:
    return {
        "id": 0,
        "name": "SiteA",
        "address_family": "ipv4",
        "interface_name": settings.interface_name,
        "site_address": settings.site_address,
        "prefix_length": settings.prefix_length,
        "lease_time": settings.lease_time,
        "domain_name": settings.domain_name,
        "dns_server": settings.dns_server,
        "ntp_server": "",
        "enabled": settings.enabled,
        "description": "Compatibility scope from DHCP settings.",
    }


def dhcp_scope_to_dict(scope: DhcpScope) -> dict:
    return {
        "id": scope.id,
        "name": scope.name,
        "address_family": dhcp_scope_address_family(scope),
        "interface_name": scope.interface_name,
        "site_address": scope.site_address,
        "prefix_length": scope.prefix_length,
        "range_expression": compact_dhcp_range_expression(scope),
        "lease_time": scope.lease_time,
        "domain_name": scope.domain_name,
        "dns_server": scope.dns_server,
        "ntp_server": scope.ntp_server,
        "enabled": scope.enabled,
        "description": scope.description or "",
    }


def dhcp_option_to_dict(option: DhcpOption) -> dict:
    return {
        "id": option.id,
        "scope_id": option.scope_id if option.scope_id is not None else "__global__",
        "option_code": option.option_code,
        "value": option.value,
        "description": option.description or "",
        "enabled": option.enabled,
    }


def parse_dnsmasq_leases(raw_text: str, now: datetime | None = None) -> list[dict]:
    current_time = now or datetime.now(timezone.utc)
    leases: list[dict] = []
    for line in raw_text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        expires_raw, mac_address, ip, hostname = fields[:4]
        client_id = fields[4] if len(fields) > 4 else ""
        try:
            expires_epoch = int(expires_raw)
        except ValueError:
            continue
        expires_at = None if expires_epoch == 0 else datetime.fromtimestamp(expires_epoch, tz=timezone.utc)
        if expires_at is None:
            status = "reserved"
        elif expires_at > current_time:
            status = "active"
        else:
            status = "expired"
        leases.append(
            {
                "expires_at": expires_at,
                "mac_address": mac_address,
                "ip_address": ip,
                "hostname": hostname if hostname != "*" else "",
                "client_id": client_id if client_id != "*" else "",
                "status": status,
            }
        )
    return leases


def validate_dns_settings(settings: DnsSettings, records: list[DnsRecord], conditional_forwarders: str | None = None) -> list[str]:
    errors: list[str] = []
    if settings.enabled and not split_interfaces(settings.listen_interface):
        errors.append("DNS must listen on at least one interface.")
    if not split_domains(settings.domain):
        errors.append("DNS must manage at least one domain.")
    for domain in split_domains(settings.domain):
        if any(character.isspace() for character in domain):
            errors.append(f"DNS domain {domain} must not contain whitespace.")
        elif not _valid_dns_hostname(domain):
            errors.append(f"DNS domain {domain} must be a valid domain name.")
    if settings.authoritative:
        domains = split_domains(settings.domain)
        server = authoritative_server_name(settings)
        contact = authoritative_contact_name(settings)
        listen_addresses = split_addresses(settings.listen_address)
        if not _valid_dns_hostname(server):
            errors.append("Authoritative DNS primary nameserver must be a valid fully qualified DNS name.")
        elif not any(server == domain or server.endswith(f".{domain}") for domain in domains):
            errors.append("Authoritative DNS primary nameserver must belong to one of the managed domains.")
        if not _valid_dns_hostname(contact):
            errors.append("Authoritative DNS administrator must be a valid SOA DNS name.")
        if settings.enabled and not listen_addresses:
            errors.append("Authoritative DNS requires at least one selected listen address for nameserver glue.")
        timer_values = {
            "TTL": settings.authoritative_ttl,
            "refresh": settings.authoritative_refresh,
            "retry": settings.authoritative_retry,
            "expire": settings.authoritative_expire,
        }
        for label, value in timer_values.items():
            if not value or value <= 0 or value > 2147483647:
                errors.append(f"Authoritative DNS {label} must be between 1 and 2147483647 seconds.")
        if settings.authoritative_expire and settings.authoritative_expire <= max(
            settings.authoritative_refresh or 0,
            settings.authoritative_retry or 0,
        ):
            errors.append("Authoritative DNS expire must be greater than both refresh and retry.")
        if not settings.authoritative_serial or not 1 <= settings.authoritative_serial <= 4294967295:
            errors.append("Authoritative DNS serial must be between 1 and 4294967295.")
        for record in records:
            if record.enabled is False or record.hostname.strip().strip(".").lower() != server:
                continue
            record_type = record.record_type.strip().upper()
            if record_type == "CNAME":
                errors.append(f"Authoritative DNS primary nameserver {server} cannot also be a CNAME.")
            elif record_type in {"A", "AAAA"} and record.address not in listen_addresses:
                errors.append(
                    f"Authoritative DNS glue record {server} must use a selected DNS listen address; remove {record.address}."
                )
    for address in split_addresses(settings.listen_address):
        _validate_ip(address, f"DNS listen address {address}", errors)
    for server in split_servers(settings.upstream_servers):
        parsed = _validate_ip(server, f"upstream server {server}", errors)
        if parsed and parsed.is_loopback:
            errors.append(f"upstream server {server} must not be a loopback address.")
    for forwarder in split_conditional_forwarders(conditional_forwarders):
        domain = forwarder["domain"]
        server = forwarder["server"]
        if any(character.isspace() for character in domain):
            errors.append(f"conditional forwarder domain {domain} must not contain whitespace.")
        if not domain or "." not in domain:
            errors.append(f"conditional forwarder domain {domain or '(blank)'} must be a DNS domain.")
        _validate_forwarder_server(server, f"conditional forwarder {domain} server", errors)
    for record in records:
        if record.enabled is not False:
            errors.extend(validate_dns_record(record.hostname, record.record_type, record.address, record_data(record)))
    if settings.query_logging_mode not in {"off", "queries-extra"}:
        errors.append("DNS query logging mode must be off or queries-extra.")
    for raw_domain in (settings.rebind_domain_exemptions or "").replace(",", "\n").splitlines():
        domain = raw_domain.strip().strip(".").lower()
        if not domain:
            continue
        if any(character.isspace() for character in domain):
            errors.append(f"DNS rebind exemption {domain} must not contain whitespace.")
        elif not _valid_dns_hostname(domain):
            errors.append(f"DNS rebind exemption {domain} must be a valid domain name.")
    if (settings.cache_size or 0) < 0:
        errors.append("DNS cache size must be zero or greater.")
    return errors


def validate_authoritative_dns_record(
    settings: DnsSettings,
    hostname: str,
    record_type: str,
    address: str,
) -> list[str]:
    """Reject operator records that conflict with generated nameserver glue."""
    if not settings.authoritative:
        return []
    server = authoritative_server_name(settings)
    if hostname.strip().strip(".").lower() != server:
        return []
    normalized_type = record_type.strip().upper()
    if normalized_type == "CNAME":
        return [
            f"{server} is the generated authoritative nameserver and cannot also be a CNAME; "
            "change Primary nameserver in Authoritative DNS settings instead."
        ]
    if normalized_type in {"A", "AAAA"} and address not in split_addresses(settings.listen_address):
        return [
            f"{server} glue is generated from selected DNS listen addresses; "
            "change DNS listen interfaces or Primary nameserver instead of adding this record."
        ]
    return []


def validate_dns_listen_targets(settings: DnsSettings, available_interface_names: set[str]) -> list[str]:
    errors: list[str] = []
    if not settings.enabled:
        return errors
    if not available_interface_names:
        errors.append("DNS has no valid listen interfaces. Configure an access physical interface or enabled VLAN with an IP CIDR.")
        return errors
    for interface_name in split_interfaces(settings.listen_interface):
        if interface_name not in available_interface_names:
            errors.append(
                f"DNS listen interface {interface_name} is not a valid bind target. "
                "Use an access physical interface with an IP CIDR or an enabled VLAN interface with an IP CIDR."
            )
    return errors


def dhcp_bind_target_names(physical_interfaces: list[PhysicalInterface], vlan_interfaces: list[VlanInterface]) -> set[str]:
    return set(dhcp_bind_target_families(physical_interfaces, vlan_interfaces))


def dhcp_bind_target_families(physical_interfaces: list[PhysicalInterface], vlan_interfaces: list[VlanInterface]) -> dict[str, set[str]]:
    names: dict[str, set[str]] = {}
    def add(name: str, family: str) -> None:
        names.setdefault(name, set()).add(family)

    for interface in physical_interfaces:
        if interface.oper_state == "missing":
            continue
        mode = (interface.mode or "").strip().lower()
        if mode == "trunk":
            continue
        if _valid_cidr(interface.ip_cidr, version=4):
            add(interface.name, "ipv4")
        if _valid_cidr(interface.ipv6_cidr, version=6):
            add(interface.name, "ipv6")
    for vlan in vlan_interfaces:
        if vlan.enabled is False:
            continue
        if _valid_cidr(vlan.ip_cidr, version=4):
            add(vlan.name, "ipv4")
        if _valid_cidr(vlan.ipv6_cidr, version=6):
            add(vlan.name, "ipv6")
    return names


def validate_dhcp_bind_targets(settings: DhcpSettings, scopes: list[DhcpScope], available_interface_names: set[str] | dict[str, set[str]]) -> list[str]:
    errors: list[str] = []
    if not settings.enabled:
        return errors
    available_families = (
        {name: {"ipv4", "ipv6"} for name in available_interface_names}
        if isinstance(available_interface_names, set)
        else available_interface_names
    )
    scope_rows = scopes if scopes else [_legacy_scope(settings)]
    enabled_scopes = [scope for scope in scope_rows if scope.enabled is not False]
    if enabled_scopes and not available_families:
        return ["DHCP has no valid bind targets. Configure an access physical interface or enabled VLAN with an IP CIDR."]
    for scope in enabled_scopes:
        interface_name = scope.interface_name.strip()
        if interface_name not in available_families:
            errors.append(
                f"DHCP IP zone {scope.name} interface {interface_name or '<missing>'} is not a valid bind target. "
                "Use an access physical interface with an IP CIDR or an enabled VLAN interface with an IP CIDR."
            )
            continue
        family = dhcp_scope_address_family(scope)
        if family not in available_families.get(interface_name, set()):
            errors.append(
                f"DHCP IP zone {scope.name} is {family.upper()}, but interface {interface_name} does not have a matching "
                f"{'IPv4' if family == 'ipv4' else 'IPv6'} CIDR."
            )
    return errors


def dns_domain_warnings(domains: list[str]) -> list[str]:
    warnings: list[str] = []
    for domain in split_domains("\n".join(domains)):
        if domain.endswith(".local"):
            warnings.append(
                f"DNS domain {domain} uses .local. RFC 6762 defines .local for multicast DNS/link-local naming, "
                "and RFC 6761 lists it as a special-use domain. Use .internal for VCF labs; ICANN/IANA selected "
                ".internal for private-use internal networks, and VMware Cloud Foundation does not work reliably with .local domains."
            )
    return warnings


def validate_dns_record(hostname: str, record_type: str, address: str, data: dict[str, object] | None = None) -> list[str]:
    errors: list[str] = []
    normalized_type = record_type.strip().upper()
    if normalized_type not in DNS_RECORD_TYPES:
        errors.append(f"record {hostname} type must be one of {', '.join(sorted(DNS_RECORD_TYPES))}.")
        return errors
    if normalized_type == "CNAME":
        target = address.strip().strip(".").lower()
        if not target:
            errors.append(f"CNAME record {hostname} must point to a target hostname.")
            return errors
        if _is_ip_address(target):
            errors.append(f"CNAME record {hostname} must point to a hostname, not an IP address.")
        if any(character.isspace() for character in target):
            errors.append(f"CNAME record {hostname} target must not contain whitespace.")
        if target and not _valid_dns_hostname(target):
            errors.append(f"CNAME record {hostname} target must be a valid hostname.")
        return errors
    if normalized_type == "TXT":
        if not address.strip():
            errors.append(f"TXT record {hostname} must include text.")
        return errors
    if normalized_type == "PTR":
        target = address.strip().strip(".").lower()
        if not target or not _valid_dns_hostname(target):
            errors.append(f"PTR record {hostname} target must be a valid hostname.")
        return errors
    if normalized_type == "MX":
        payload = data or dns_record_data_from_value(normalized_type, address)
        target = _record_data_value(payload, "target").strip(".").lower()
        preference = _record_data_value(payload, "preference", "10")
        if not target or not _valid_dns_hostname(target):
            errors.append(f"MX record {hostname} target must be a valid hostname.")
        if not preference.isdigit() or not 0 <= int(preference) <= 65535:
            errors.append(f"MX record {hostname} preference must be 0-65535.")
        return errors
    if normalized_type == "SRV":
        payload = data or dns_record_data_from_value(normalized_type, address)
        target = _record_data_value(payload, "target").strip(".").lower()
        port = _record_data_value(payload, "port")
        priority = _record_data_value(payload, "priority", "0")
        weight = _record_data_value(payload, "weight", "0")
        if not hostname.startswith("_") or "._" not in hostname:
            errors.append(f"SRV record {hostname} owner should be _service._proto.name.")
        if not target or not _valid_dns_hostname(target):
            errors.append(f"SRV record {hostname} target must be a valid hostname.")
        for label, value in {"port": port, "priority": priority, "weight": weight}.items():
            if not value.isdigit() or not 0 <= int(value) <= 65535:
                errors.append(f"SRV record {hostname} {label} must be 0-65535.")
        return errors
    if normalized_type == "CAA":
        payload = data or dns_record_data_from_value(normalized_type, address)
        flags = _record_data_value(payload, "flags")
        tag = _record_data_value(payload, "tag")
        value = _record_data_value(payload, "value")
        if not flags.isdigit() or not 0 <= int(flags) <= 255:
            errors.append(f"CAA record {hostname} flags must be 0-255.")
        if tag not in {"issue", "issuewild", "iodef"}:
            errors.append(f"CAA record {hostname} tag must be issue, issuewild, or iodef.")
        if not value:
            errors.append(f"CAA record {hostname} value is required.")
        return errors
    parsed_address = _validate_ip(address, f"record {hostname}", errors)
    if not parsed_address:
        return errors
    if normalized_type == "A" and parsed_address.version != 4:
        errors.append(f"A record {hostname} must use an IPv4 address.")
    if normalized_type == "AAAA" and parsed_address.version != 6:
        errors.append(f"AAAA record {hostname} must use an IPv6 address.")
    return errors


def validate_dhcp_settings(
    settings: DhcpSettings,
    reservations: list[DhcpReservation],
    scopes: list[DhcpScope] | None = None,
    options: list[DhcpOption] | None = None,
) -> list[str]:
    errors: list[str] = []
    if not settings.enabled:
        return errors
    scope_rows = scopes if scopes else [_legacy_scope(settings)]
    enabled_scopes = [scope for scope in scope_rows if scope.enabled is not False]
    if settings.enabled and not enabled_scopes:
        errors.append("DHCP must have at least one enabled IP zone when the service is enabled.")
    networks = []
    for scope in scope_rows:
        scope_errors, network = validate_dhcp_scope(scope)
        errors.extend(scope_errors)
        if scope.enabled is not False and network:
            networks.append((scope.name, network))
    for reservation in reservations:
        if reservation.enabled is not False:
            reserved_ip = _validate_ip(reservation.ip_address, f"reservation {reservation.hostname}", errors)
            if networks and reserved_ip and not any(reserved_ip in network for _, network in networks):
                errors.append(f"reservation {reservation.hostname} must be inside an enabled DHCP IP zone.")
    scope_ids = {scope.id for scope in scope_rows if scope.id is not None}
    for option in options or []:
        if option.enabled is False:
            continue
        label = "global DHCP option" if option.scope_id is None else f"DHCP option for scope {option.scope_id}"
        if option.scope_id is not None and option.scope_id not in scope_ids:
            errors.append(f"{label} references a missing DHCP IP zone.")
        if not option.option_code.strip():
            errors.append(f"{label} code is required.")
        if not option.value.strip():
            errors.append(f"{label} value is required.")
    return errors


def validate_dhcp_scope(scope: DhcpScope) -> tuple[list[str], object | None]:
    errors: list[str] = []
    label = f"DHCP IP zone {scope.name}"
    family = dhcp_scope_address_family(scope)
    required_version = 6 if family == "ipv6" else 4
    if not scope.name.strip():
        errors.append("DHCP IP zone name is required.")
    site_address = _validate_ip(scope.site_address, f"{label} gateway", errors, version=required_version)
    range_errors, parsed_ranges = parse_dhcp_range_expression(scope)
    errors.extend(range_errors)
    dns_server = _validate_ip(scope.dns_server, f"{label} DNS server", errors, version=required_version)
    ntp_server = _validate_ip(scope.ntp_server, f"{label} NTP server", errors, version=required_version) if scope.ntp_server else None
    network = None
    if site_address:
        try:
            network = ip_network(f"{site_address}/{scope.prefix_length}", strict=False)
        except ValueError:
            errors.append(f"{label} prefix length is not valid.")
    if family == "ipv4" and not 1 <= int(scope.prefix_length or 0) <= 32:
        errors.append(f"{label} IPv4 prefix length must be between 1 and 32.")
    if family == "ipv6" and not 1 <= int(scope.prefix_length or 0) <= 128:
        errors.append(f"{label} IPv6 prefix length must be between 1 and 128.")
    if network and dns_server and dns_server not in network:
        errors.append(f"{label} DNS server {dns_server} is outside {network.with_prefixlen}. Bind DNS to {scope.interface_name} or leave the DNS server blank for this zone.")
    if network and ntp_server and ntp_server not in network:
        errors.append(f"{label} NTP server {ntp_server} is outside {network.with_prefixlen}. Bind NTPsec to {scope.interface_name} or leave the NTP server blank for this zone.")
    return errors, network


def render_dnsmasq_config(
    *,
    dns_settings: DnsSettings,
    dns_records: list[DnsRecord],
    dhcp_settings: DhcpSettings,
    dhcp_reservations: list[DhcpReservation],
    dhcp_scopes: list[DhcpScope] | None = None,
    dhcp_options: list[DhcpOption] | None = None,
    conditional_forwarders: str | None = None,
    fallback_upstream_servers: list[str] | None = None,
    esxi_pxe_boot: dict | None = None,
) -> str:
    ensure_dns_authoritative_defaults(dns_settings)
    domains = split_domains(dns_settings.domain) or ["atlaso.internal"]
    scopes = dhcp_scopes if dhcp_scopes else [_legacy_scope(dhcp_settings)]
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "domain-needed",
        "bogus-priv",
        "no-resolv",
        "bind-interfaces",
        f"dhcp-leasefile={DNSMASQ_LEASE_FILE_PATH}",
        f"cache-size={dns_settings.cache_size if dns_settings.cache_size is not None else 1000}",
    ]
    if dns_settings.query_logging_mode == "queries-extra":
        lines.append("log-queries=extra")
    if dns_settings.dnssec_enabled:
        lines.append("dnssec")
        lines.append(f"conf-file={DNSMASQ_DNSSEC_TRUST_ANCHORS_PATH}")
    if dns_settings.rebind_protection_enabled:
        lines.append("stop-dns-rebind")
        for domain in split_domains(dns_settings.rebind_domain_exemptions):
            lines.append(f"rebind-domain-ok=/{domain}/")
    for domain in domains:
        lines.append(f"domain={domain}")
        if dns_settings.authoritative:
            lines.append(f"auth-zone={domain}")
        else:
            lines.append(f"local=/{domain}/")
    if dns_settings.authoritative:
        server = authoritative_server_name(dns_settings)
        authoritative_interfaces = split_interfaces(dns_settings.listen_interface)
        auth_server = ",".join([server, *authoritative_interfaces])
        lines.append(f"auth-server={auth_server}")
        lines.append(
            "auth-soa="
            f"{dns_settings.authoritative_serial},{authoritative_contact_name(dns_settings)},"
            f"{dns_settings.authoritative_refresh},{dns_settings.authoritative_retry},{dns_settings.authoritative_expire}"
        )
        lines.append(f"auth-ttl={dns_settings.authoritative_ttl}")
        for listen_address in split_addresses(dns_settings.listen_address):
            lines.append(f"host-record={server},{listen_address}")
    if dns_settings.expand_hosts:
        lines.append("expand-hosts")
    if dhcp_settings.enabled and dhcp_settings.authoritative:
        lines.append("dhcp-authoritative")
    dhcp_interfaces = [scope.interface_name for scope in scopes if dhcp_settings.enabled and scope.enabled is not False]
    dns_interfaces = split_interfaces(dns_settings.listen_interface)
    if dns_settings.enabled:
        dns_interfaces.append("lo")
    for interface_name in _ordered_unique([*dns_interfaces, *dhcp_interfaces]):
        lines.append(f"interface={interface_name}")
    dns_listen_addresses = split_addresses(dns_settings.listen_address)
    if dns_settings.enabled:
        dns_listen_addresses.append("127.0.0.1")
    for listen_address in _ordered_unique(dns_listen_addresses):
        lines.append(f"listen-address={listen_address}")
    for server in effective_dns_upstream_servers(dns_settings, fallback_upstream_servers):
        lines.append(f"server={server}")
    for forwarder in split_conditional_forwarders(conditional_forwarders):
        lines.append(f"server=/{forwarder['domain']}/{forwarder['server']}")
    for record in dns_records:
        if record.enabled is False:
            continue
        record_type = record.record_type.upper()
        if dns_settings.authoritative and record_type in {"A", "AAAA"} and record.hostname.strip().strip(".").lower() == authoritative_server_name(dns_settings):
            continue
        if record_type in {"A", "AAAA"}:
            # dnsmasq host-record also creates the matching PTR record.
            lines.append(f"host-record={record.hostname},{record.address}")
        elif record_type == "CNAME":
            lines.append(f"cname={record.hostname},{record.address.strip().strip('.').lower()}")
        elif record_type == "TXT":
            lines.append(f"txt-record={record.hostname},{_quote_dnsmasq_text(record.address)}")
        elif record_type == "PTR":
            lines.append(f"ptr-record={record.hostname},{record.address.strip().strip('.').lower()}")
        elif record_type == "MX":
            data = record_data(record)
            lines.append(f"mx-host={record.hostname},{_record_data_value(data, 'target').strip().strip('.').lower()},{_record_data_value(data, 'preference', '10')}")
        elif record_type == "SRV":
            data = record_data(record)
            lines.append(
                "srv-host="
                f"{record.hostname},{_record_data_value(data, 'target').strip().strip('.').lower()},"
                f"{_record_data_value(data, 'port')},{_record_data_value(data, 'priority', '0')},{_record_data_value(data, 'weight', '0')}"
            )
        elif record_type == "CAA":
            data = record_data(record)
            lines.append(
                "caa-record="
                f"{record.hostname},{_record_data_value(data, 'flags')},{_record_data_value(data, 'tag')},"
                f"{_quote_dnsmasq_text(_record_data_value(data, 'value'))}"
            )
    scope_tags = {scope.id: dnsmasq_tag(scope.name) for scope in scopes}
    if dhcp_settings.enabled:
        if any(scope.enabled is not False and dhcp_scope_address_family(scope) == "ipv6" for scope in scopes):
            lines.append("enable-ra")
        if esxi_pxe_boot and esxi_pxe_boot.get("enabled"):
            tftp_hostname = str(esxi_pxe_boot.get("hostname") or "").strip()
            native_uefi_http_enabled = bool(esxi_pxe_boot.get("native_uefi_http_enabled"))
            manual_native_http_url = str(esxi_pxe_boot.get("native_uefi_http_url") or "").strip()
            http_port = esxi_pxe_boot.get("http_port") or 8080
            selected_scope_payloads = list(esxi_pxe_boot.get("dhcp_scopes") or [])
            pxe_scope_entries = []
            for scope_payload in selected_scope_payloads:
                if str(scope_payload.get("address_family") or "ipv4").lower() != "ipv4":
                    continue
                scope_id = scope_payload.get("id")
                scope_tag = scope_tags.get(scope_id) if isinstance(scope_id, int) else scope_tags.get(int(scope_id)) if str(scope_id or "").isdigit() else ""
                if not scope_tag:
                    scope_tag = dnsmasq_tag(str(scope_payload.get("name") or ""))
                pxe_scope_entries.append(
                    {
                        "prefix": f"tag:{scope_tag}," if scope_tag else "",
                        "address": str(scope_payload.get("site_address") or "").strip(),
                    }
                )
            if not pxe_scope_entries:
                pxe_scope_id = esxi_pxe_boot.get("dhcp_scope_id")
                pxe_scope_tag = ""
                if isinstance(pxe_scope_id, int):
                    pxe_scope_tag = scope_tags.get(pxe_scope_id, "")
                elif str(pxe_scope_id or "").isdigit():
                    pxe_scope_tag = scope_tags.get(int(pxe_scope_id), "")
                tftp_address = next(
                    (line.strip() for line in str(esxi_pxe_boot.get("listen_address") or "").replace(",", "\n").splitlines() if line.strip()),
                    "",
                )
                pxe_scope_entries.append({"prefix": f"tag:{pxe_scope_tag}," if pxe_scope_tag else "", "address": tftp_address})
            host_bootfiles = list(esxi_pxe_boot.get("host_bootfiles") or [])
            host_exclusion_tags = []
            for host_bootfile in host_bootfiles:
                host_tag = str(host_bootfile.get("tag") or "").strip()
                mac_address = str(host_bootfile.get("mac_address") or "").strip()
                if host_tag and mac_address:
                    lines.append(f"dhcp-mac=set:{host_tag},{mac_address}")
                    host_exclusion_tags.append(f"tag:!{host_tag}")
            if native_uefi_http_enabled:
                native_lines = []
                for scope_entry in pxe_scope_entries:
                    scope_address = scope_entry["address"]
                    base_url = f"http://{f'[{scope_address}]' if ':' in scope_address and not scope_address.startswith('[') else scope_address}:{http_port}/pxe/esxi" if scope_address else ""
                    native_http_url = manual_native_http_url or (f"{base_url}/{esxi_pxe_boot.get('native_uefi_bootfile') or 'mboot.efi'}" if base_url else "")
                    if not native_http_url:
                        continue
                    generic_native_uefi_http_tags = ",".join(["tag:uefi-http", "tag:uefi-http-x64", *host_exclusion_tags])
                    native_lines.append(f"dhcp-boot={scope_entry['prefix']}{generic_native_uefi_http_tags},{native_http_url}")
                    for host_bootfile in host_bootfiles:
                        host_tag = str(host_bootfile.get("tag") or "").strip()
                        mac_key = str(host_bootfile.get("mac_key") or "").strip()
                        if not mac_key:
                            uefi_second_stage = str(host_bootfile.get("uefi_second_stage_bootfile") or "")
                            mac_key = uefi_second_stage.split("/", 1)[0] if "/" in uefi_second_stage else ""
                        native_host_url = manual_native_http_url or (f"{base_url}/{mac_key}/{esxi_pxe_boot.get('native_uefi_bootfile') or 'mboot.efi'}" if base_url and mac_key else "")
                        if host_tag and native_host_url:
                            native_lines.append(f"dhcp-boot={scope_entry['prefix']}tag:{host_tag},tag:uefi-http,tag:uefi-http-x64,{native_host_url}")
                if native_lines:
                    lines.extend(["dhcp-vendorclass=set:uefi-http,HTTPClient", "dhcp-match=set:uefi-http-x64,option:client-arch,16", *native_lines])
        if esxi_pxe_boot and esxi_pxe_boot.get("enabled"):
            lines.extend(
                [
                    "enable-tftp",
                    f"tftp-root={esxi_pxe_boot.get('tftp_root')}",
                    "dhcp-userclass=set:ipxe,iPXE",
                    "dhcp-match=set:ipxe,175",
                    "dhcp-match=set:efi-x86_64,option:client-arch,7",
                    "dhcp-match=set:efi-x86_64,option:client-arch,9",
                ]
            )
            for scope_entry in pxe_scope_entries:
                boot_server = ""
                if tftp_hostname and scope_entry["address"]:
                    lines.append(f"dhcp-option={scope_entry['prefix']}66,{tftp_hostname}")
                    boot_server = f",{tftp_hostname},{scope_entry['address']}"
                generic_uefi_second_stage_tags = ",".join(["tag:ipxe", "tag:efi-x86_64", *host_exclusion_tags])
                generic_uefi_second_stage_boot = str(esxi_pxe_boot.get("uefi_second_stage_bootfile") or "")
                lines.extend(
                    [
                        f"dhcp-boot={scope_entry['prefix']}{generic_uefi_second_stage_tags},{generic_uefi_second_stage_boot}{boot_server}",
                        f"dhcp-boot={scope_entry['prefix']}tag:ipxe,tag:!efi-x86_64,{esxi_pxe_boot.get('bios_second_stage_bootfile')}{boot_server}",
                        f"dhcp-boot={scope_entry['prefix']}tag:!ipxe,tag:efi-x86_64,{esxi_pxe_boot.get('uefi_bootfile')}{boot_server}",
                        f"dhcp-boot={scope_entry['prefix']}tag:!ipxe,tag:!efi-x86_64,{esxi_pxe_boot.get('bios_bootfile')}{boot_server}",
                    ]
                )
                for host_bootfile in host_bootfiles:
                    host_tag = str(host_bootfile.get("tag") or "").strip()
                    uefi_second_stage = str(host_bootfile.get("uefi_second_stage_bootfile") or "").strip()
                    if host_tag and uefi_second_stage:
                        lines.append(f"dhcp-boot={scope_entry['prefix']}tag:{host_tag},tag:ipxe,tag:efi-x86_64,{uefi_second_stage}{boot_server}")
        for scope in scopes:
            if scope.enabled is False:
                continue
            tag = dnsmasq_tag(scope.name)
            range_errors, parsed_ranges = parse_dhcp_range_expression(scope)
            if range_errors:
                continue
            if dhcp_scope_address_family(scope) == "ipv6":
                for start_address, end_address in parsed_ranges:
                    lines.append(f"dhcp-range=set:{tag},{start_address},{end_address},{scope.prefix_length},{scope.lease_time or '12h'}")
                lines.extend(
                    [
                        f"dhcp-option=tag:{tag},option6:dns-server,{_dnsmasq_ipv6_option_address(scope.dns_server)}",
                        f"dhcp-option=tag:{tag},option6:domain-search,{scope.domain_name or domains[0]}",
                    ]
                )
                if scope.ntp_server:
                    lines.append(f"dhcp-option=tag:{tag},option6:ntp-server,{_dnsmasq_ipv6_option_address(scope.ntp_server)}")
            else:
                for start_address, end_address in parsed_ranges:
                    lines.append(f"dhcp-range=set:{tag},{start_address},{end_address},{scope.lease_time or '12h'}")
                lines.extend(
                    [
                        f"dhcp-option=tag:{tag},option:router,{scope.site_address}",
                        f"dhcp-option=tag:{tag},option:dns-server,{scope.dns_server}",
                        f"dhcp-option=tag:{tag},option:domain-name,{scope.domain_name or domains[0]}",
                    ]
                )
                if scope.ntp_server:
                    lines.append(f"dhcp-option=tag:{tag},option:ntp-server,{scope.ntp_server}")
        for option in dhcp_options or []:
            if option.enabled is False:
                continue
            option_code = option.option_code.strip()
            option_value = option.value.strip()
            if not option_code or not option_value:
                continue
            if option.scope_id is None:
                lines.append(f"dhcp-option=option:{option_code},{option_value}")
            elif option.scope_id in scope_tags:
                lines.append(f"dhcp-option=tag:{scope_tags[option.scope_id]},option:{option_code},{option_value}")
        for reservation in dhcp_reservations:
            if reservation.enabled is False and (reservation.description or "").startswith(DHCP_DENY_RESERVATION_DESCRIPTION_PREFIX):
                lines.append(f"dhcp-host={reservation.mac_address},ignore")
            elif reservation.enabled is not False:
                try:
                    reserved_ip = ip_address(reservation.ip_address)
                except ValueError:
                    reserved_ip = None
                reservation_ip = f"[{reservation.ip_address}]" if reserved_ip and reserved_ip.version == 6 else reservation.ip_address
                lines.append(f"dhcp-host={reservation.mac_address},{reservation.hostname},{reservation_ip}")
    return "\n".join(lines) + "\n"


def reservation_dns_record(reservation: DhcpReservation, scopes: list[DhcpScope]) -> tuple[str, str, str] | None:
    try:
        reserved_ip = ip_address(reservation.ip_address)
    except ValueError:
        return None
    matching_scope = _scope_for_ip(reserved_ip, scopes)
    if matching_scope is None:
        return None
    hostname = reservation.hostname.strip().strip(".").lower()
    domain = matching_scope.domain_name.strip().strip(".").lower()
    fqdn = hostname if "." in hostname else f"{hostname}.{domain}"
    record_type = "AAAA" if reserved_ip.version == 6 else "A"
    return fqdn, record_type, str(reserved_ip)


def dnsmasq_test_command(config_path: str) -> list[str]:
    normalized_path = str(PurePosixPath(config_path))
    return ["dnsmasq", "--test", f"--conf-file={normalized_path}"]


def _validate_ip(value: str, label: str, errors: list[str], *, version: int | None = None):
    try:
        parsed = ip_address(value)
    except ValueError:
        errors.append(f"{label} is not a valid IP address.")
        return None
    if version is not None and parsed.version != version:
        errors.append(f"{label} must be an IPv{version} address.")
        return None
    return parsed


def _non_loopback_servers(servers: list[str]) -> list[str]:
    filtered: list[str] = []
    seen: set[str] = set()
    for server in servers:
        try:
            parsed = ip_address(server)
        except ValueError:
            normalized = server.strip()
        else:
            if parsed.is_loopback:
                continue
            normalized = str(parsed)
        if normalized and normalized not in seen:
            seen.add(normalized)
            filtered.append(normalized)
    return filtered


def _valid_cidr(value: str | None, *, version: int | None = None) -> bool:
    if not value:
        return False
    try:
        parsed = ip_interface(value)
    except ValueError:
        return False
    if version is not None and parsed.version != version:
        return False
    return True


def dhcp_scope_address_family(scope: DhcpScope) -> str:
    family = str(getattr(scope, "address_family", "") or "").strip().lower()
    if family in {"ipv4", "ipv6"}:
        return family
    try:
        return "ipv6" if ip_address(scope.site_address).version == 6 else "ipv4"
    except ValueError:
        return "ipv4"


def _dnsmasq_ipv6_option_address(value: str) -> str:
    address = value.strip()
    if not address:
        return ""
    return address if address.startswith("[") and address.endswith("]") else f"[{address}]"


def _is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _valid_dns_hostname(value: str) -> bool:
    normalized = value.strip().strip(".").lower()
    return bool(normalized and DNS_HOSTNAME_PATTERN.fullmatch(normalized))


def _validate_forwarder_server(value: str, label: str, errors: list[str]) -> None:
    server = value.strip()
    if "#" in server:
        server, port = server.rsplit("#", 1)
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            errors.append(f"{label} port must be between 1 and 65535.")
    _validate_ip(server, label, errors)


def _zone_hostname(host: str, origin: str) -> str:
    raw = host.strip().lower()
    absolute = raw.endswith(".")
    normalized = raw.strip(".")
    if normalized == "@":
        return origin
    if normalized.endswith(f".{origin}"):
        return normalized
    if absolute:
        return normalized
    return f"{normalized}.{origin}"


def _reverse_zone_for_address(value) -> str:
    if value.version == 4:
        octets = str(value).split(".")
        return f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
    labels = value.reverse_pointer.split(".")
    return ".".join(labels[16:])


def _legacy_scope(settings: DhcpSettings) -> DhcpScope:
    return DhcpScope(
        id=0,
        name="SiteA",
        address_family="ipv4",
        interface_name=settings.interface_name,
        site_address=settings.site_address,
        prefix_length=settings.prefix_length,
        range_expression="",
        lease_time=settings.lease_time,
        domain_name=settings.domain_name,
        dns_server=settings.dns_server,
        ntp_server="",
        enabled=settings.enabled,
        description="Compatibility scope from DHCP settings.",
    )


def dnsmasq_tag(value: str) -> str:
    normalized = "".join(character.lower() if character.isalnum() else "-" for character in value.strip())
    return normalized.strip("-") or "scope"


def _scope_for_ip(value, scopes: list[DhcpScope]) -> DhcpScope | None:
    for scope in scopes:
        if scope.enabled is False:
            continue
        try:
            network = ip_network(f"{scope.site_address}/{scope.prefix_length}", strict=False)
        except ValueError:
            continue
        if value in network:
            return scope
    return None


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
