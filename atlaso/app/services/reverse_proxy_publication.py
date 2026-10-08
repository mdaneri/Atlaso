"""Project reverse-proxy intent into the existing Public Services owners."""

import json
import re
import sys
from ipaddress import ip_address, ip_interface
from typing import Any
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app import models
from atlaso.app.services.ca import (
    CA_SERVER_PROFILE_NAME,
    ManagedCertificateSpec,
    safe_certificate_name,
)
from atlaso.app.services.dnsmasq import split_domains
from atlaso.app.services.firewall import ATLASO_SERVICE_FIREWALL_RULE_MARKER
from atlaso.app.services.nginx import format_nginx_listen
from atlaso.app.services.reverse_proxy_transport import (
    SOCKET_ROOT,
    manifest_generation,
    validate_manifest,
)

RESERVED_PATTERN = r"^/(?:ui(?:/|$)|api(?:/|$)|openapi\.json(?:/|$)|identity(?:/|$)|ca(?:/|$)|pxe(?:/|$)|PROD(?:/|$)|depot(?:/|$)|registry(?:/|$)|v2(?:/|$)|static(?:/|$)|manifest\.webmanifest(?:/|$)|service-worker\.js(?:/|$)|terminal(?:/|$)|requests(?:/|$))"
STAGED_PATH = "/var/lib/atlaso/apply/public-services/atlaso-public-services.conf"
DNS_OWNER_PREFIX = "Atlaso-managed reverse proxy DNS: "
GENERATION_MARKER = "# Managed reverse-proxy generation: "
MANIFEST_MARKER = "# Reverse-proxy transport manifest: "
INTENT_MARKER = "# Reverse-proxy intent: "
METADATA_CHUNK_SIZE = 2048


def _metadata_lines(marker: str, value: Any) -> list[str]:
    """Keep ASCII metadata comments below nginx's configuration token buffer.

    Args:
        marker: Input used by  metadata lines.
        value: Candidate value to normalize or validate.
    """
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return [marker + encoded[offset:offset + METADATA_CHUNK_SIZE]
            for offset in range(0, len(encoded), METADATA_CHUNK_SIZE)]


def _read_metadata(lines: list[str], start: int, marker: str) -> tuple[Any, int]:
    """Read consecutive bounded fragments; canonical rendering verifies order.

    Args:
        lines: Input used by  read metadata.
        start: Input used by  read metadata.
        marker: Input used by  read metadata.
    """
    fragments = []
    while start < len(lines) and lines[start].startswith(marker):
        fragment = lines[start][len(marker):].rstrip("\n")
        if not 1 <= len(fragment) <= METADATA_CHUNK_SIZE:
            raise ValueError("Reverse-proxy metadata fragment exceeds its bound.")
        fragments.append(fragment)
        start += 1
    if not fragments:
        raise ValueError("Reverse-proxy generation metadata is incomplete.")
    return json.loads("".join(fragments)), start


def proxy_certificate_paths(proxy_id: int, hostname: str) -> tuple[str, str, str]:
    """Use the CA's bounded filename convention beneath one stable owner root.

    Args:
        proxy_id: Exact saved proxy identifier.
        hostname: Canonical hostname whose proxy reservation is checked.
    """
    base = f"/etc/atlaso/reverse-proxy-{proxy_id}/certs/{safe_certificate_name(hostname)}"
    return f"{base}.crt", f"{base}.key", f"{base}-chain.pem"


def validated_snapshot(text: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Reject modified directives independently of the desired-state producer.

    Args:
        text: Bounded staged or applied Public Services site text.

    The appended proxy block must exactly match strict, canonical metadata and
    its transport generation. Arbitrary nginx directives are never admitted.
    """
    from atlaso.app.reverse_proxy_schemas import ReverseProxyCreate
    from atlaso.app.services.reverse_proxies import validate_proxy

    if len(text.encode("utf-8")) > 2_000_000:
        raise ValueError("Public Services site exceeds its size bound.")
    lines = text.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.startswith(GENERATION_MARKER)]
    if not starts:
        if any(line.startswith((MANIFEST_MARKER, INTENT_MARKER)) for line in lines):
            raise ValueError("Reverse-proxy metadata has no generation owner.")
        return [], None
    if len(starts) != 1:
        raise ValueError("Reverse-proxy generation must occur exactly once.")
    start = starts[0]
    manifest, metadata_end = _read_metadata(lines, start + 1, MANIFEST_MARKER)
    proxies, _metadata_end = _read_metadata(lines, metadata_end, INTENT_MARKER)
    validate_manifest(manifest)
    if not isinstance(proxies, list) or not 1 <= len(proxies) <= 256:
        raise ValueError("Invalid reverse-proxy collection size.")
    rows = []
    for proxy in proxies:
        if not isinstance(proxy, dict) or type(proxy.get("id")) is not int or not 1 <= proxy["id"] <= 0xFFFFFF:
            raise ValueError("Invalid reverse-proxy identity.")
        routes = proxy.get("routes")
        if not isinstance(routes, list) or not 1 <= len(routes) <= 64:
            raise ValueError("Invalid reverse-proxy route count.")
        for index, route in enumerate(routes):
            if not isinstance(route, dict) or type(route.get("id")) is not int or not 1 <= route["id"] <= 9_999_999_999 or route.get("position") != index:
                raise ValueError("Invalid reverse-proxy route identity or order.")
        request = ReverseProxyCreate.model_validate({
            **{key: value for key, value in proxy.items() if key not in {"id", "routes"}},
            "routes": [{**{key: value for key, value in route.items() if key != "position"},
                        "insecure_acknowledged": route.get("trust_mode") == "insecure"} for route in routes],
        })
        values = request.model_dump(exclude={"routes"})
        candidate = models.ReverseProxy(id=proxy["id"], **values, routes=[
            models.ReverseProxyRoute(id=route.id, position=index,
                **route.model_dump(exclude={"id", "insecure_acknowledged"}))
            for index, route in enumerate(request.routes)])
        rows.append(candidate)
    if len({row.id for row in rows}) != len(rows) or sum(len(row.routes) for row in rows) > 256:
        raise ValueError("Duplicate proxy identities or excessive routes.")
    inventory = {"listeners": [listener for row in rows for listener in row.listeners],
                 "addresses": set(manifest["forbidden_addresses"]), "service_hostnames": set(),
                 "claims": [], "port_forwards": []}
    for row in rows:
        # Immutable nginx metadata has no database CA inventory; the helper separately
        # validates its owned certificate files. Desired-state callers retain the CA gate.
        errors = validate_proxy(row, inventory, rows, exclude_id=row.id, require_managed_ca=False)
        if errors:
            raise ValueError("Invalid reverse-proxy publication metadata.")
    if manifest != transport_manifest(proxies, manifest["forbidden_addresses"]) or "".join(lines[start:]) != render_proxy_servers(proxies, manifest):
        raise ValueError("Reverse-proxy directives do not match their canonical intent.")
    return proxies, manifest


def transport_manifest(proxies: list[dict[str, Any]], forbidden_addresses: list[str]) -> dict[str, Any]:
    """Capture complete immutable upstream transport state without secrets.

    Args:
        proxies: Complete bounded proxy desired-state collection.
        forbidden_addresses: Input used by transport manifest.
    """
    routes = []
    for proxy in proxies:
        if not proxy["enabled"]:
            continue
        for route in proxy["routes"]:
            routes.append({"socket_id": f"{proxy['id']}-{route['id']}",
                           "probe_host": proxy["hostname"],
                           "probe_path": quote(route["path_prefix"], safe="/-._~") if route["path_behavior"] == "preserve" else "/",
                           **{key: route[key] for key in ("upstream_scheme", "upstream_host", "upstream_port", "trust_mode", "fingerprint")},
                           **{key: proxy[key] for key in ("connect_timeout", "read_timeout", "send_timeout")}})
    manifest: dict[str, Any] = {"schema": 1, "routes": sorted(routes, key=lambda item: item["socket_id"]),
                                "forbidden_addresses": sorted(set(forbidden_addresses))}
    manifest["generation"] = manifest_generation(manifest)
    validate_manifest(manifest)
    return manifest


def appliance_addresses(db: Session) -> list[str]:
    """Include desired addresses from every role in the outbound exclusion set.

    Args:
        db: Caller-owned database session for proxy desired state.
    """
    result = set()
    for model in (models.PhysicalInterface, models.VlanInterface):
        for row in db.scalars(select(model)):
            for field in ("ip_cidr", "ipv6_cidr"):
                try:
                    result.add(str(ip_interface(getattr(row, field) or "").ip))
                except ValueError:
                    pass
    return sorted(result)


def certificate_specs(proxies: list[dict[str, Any]]) -> list[ManagedCertificateSpec]:
    """Reuse CA custody and deterministic service paths for HTTPS certificates.

    Args:
        proxies: Complete bounded proxy desired-state collection.
    """
    result = []
    for proxy in proxies:
        if not proxy["enabled"] or proxy["scheme"] != "https":
            continue
        cert, key, chain = proxy_certificate_paths(proxy['id'], proxy["hostname"])
        result.append(ManagedCertificateSpec(owner=f"reverse_proxy:{proxy['id']}:https", common_name=proxy["hostname"],
            dns_names=[proxy["hostname"]], ip_addresses=[item["address"] for item in proxy["listeners"]],
            profile_name=CA_SERVER_PROFILE_NAME, description=f"Managed reverse proxy {proxy['name']}.",
            cert_path=cert, key_path=key, chain_path=chain))
    return result


def retire_obsolete_proxy_certificates(db: Session, proxies: list[dict[str, Any]]) -> bool:
    """Disable orphaned proxy CA owners and discard their encrypted private keys.

    Args:
        db: Caller-owned database session for proxy desired state.
        proxies: Complete bounded proxy desired-state collection.
    """
    owners = {spec.owner for spec in certificate_specs(proxies)}
    changed = False
    certificates = db.scalars(select(models.CaCertificate).where(models.CaCertificate.managed_owner.like("reverse_proxy:%")))
    for certificate in certificates:
        if not re.fullmatch(r"reverse_proxy:[1-9][0-9]*:https", certificate.managed_owner or ""):
            continue
        if certificate.managed_owner not in owners and (certificate.enabled or certificate.private_key_encrypted):
            certificate.enabled = False
            certificate.private_key_encrypted = ""
            changed = True
    if changed:
        db.flush()
    return changed


def render_proxy_servers(proxies: list[dict[str, Any]], manifest: dict[str, Any]) -> str:
    """Render exact-host servers; rejected paths take precedence over proxy routes.

    Args:
        proxies: Complete bounded proxy desired-state collection.
        manifest: Input used by render proxy servers.
    """
    validate_manifest(manifest)
    if not proxies:
        return ""
    lines = [GENERATION_MARKER + manifest["generation"],
             *_metadata_lines(MANIFEST_MARKER, manifest),
             *_metadata_lines(INTENT_MARKER, proxies)]
    if manifest["routes"]:
        lines.append("map $http_upgrade $atlaso_reverse_proxy_connection { default upgrade; '' close; }")
    for proxy in proxies:
        if not proxy["enabled"]:
            continue
        hostname = proxy["hostname"]
        cert, key, _chain = proxy_certificate_paths(proxy['id'], hostname)
        for listener in proxy["listeners"]:
            address = listener["address"]
            lines.extend(["# Exact-host managed reverse proxy.", "server {",
                          f"  listen {format_nginx_listen(address, proxy['port'])}{' ssl' if proxy['scheme'] == 'https' else ''};",
                          f"  server_name {hostname};", "  if ($http_host = '') { return 404; }",
                          f"  if ($host != {hostname}) {{ return 404; }}",
                          f"  add_header X-Atlaso-Reverse-Proxy {proxy['id']}-{manifest['generation']} always;",
                          f"  client_max_body_size {proxy['body_limit']};"])
            if proxy["scheme"] == "https":
                lines.extend([f"  if ($ssl_server_name !~* ^{re.escape(hostname)}$) {{ return 421; }}",
                              f"  ssl_certificate {cert};", f"  ssl_certificate_key {key};",
                              "  ssl_protocols TLSv1.2 TLSv1.3;"])
            lines.append(f"  location ~* {RESERVED_PATTERN} {{ return 404; }}")
            for route in proxy["routes"]:
                path = (SOCKET_ROOT / manifest["generation"] / f"{proxy['id']}-{route['id']}.sock").as_posix()
                suffix = ":/" if route["path_behavior"] == "strip" else ""
                lines.extend([f"  # Upstream TLS policy: {route['trust_mode']}{' - WARNING: certificate verification is disabled' if route['trust_mode'] == 'insecure' else ''}",
                              f"  location {route['path_prefix']} {{", f"    proxy_pass http://unix:{path}{suffix};",
                              "    proxy_http_version 1.1;", "    proxy_buffering off;", "    proxy_request_buffering on;",
                              "    proxy_set_header Host $host;", "    proxy_set_header X-Forwarded-For $remote_addr;",
                              "    proxy_set_header Forwarded '';",
                              f"    proxy_set_header X-Forwarded-Proto {proxy['scheme']};",
                              f"    proxy_set_header X-Forwarded-Port {proxy['port']};",
                              "    proxy_set_header X-Forwarded-Host $host;", "    proxy_set_header X-Real-IP $remote_addr;",
                              "    proxy_set_header X-Atlaso-Listener-Address '';", "    proxy_set_header Upgrade $http_upgrade;",
                              "    proxy_set_header Connection $atlaso_reverse_proxy_connection;",
                              f"    proxy_connect_timeout {proxy['connect_timeout']}s;",
                              f"    proxy_read_timeout {proxy['read_timeout']}s;", f"    proxy_send_timeout {proxy['send_timeout']}s;", "  }"])
            if not any(route["path_prefix"] == "/" for route in proxy["routes"]):
                lines.append("  location / { return 404; }")
            lines.append("}")
            if proxy["redirect_http"]:
                port = "" if proxy["port"] == 443 else f":{proxy['port']}"
                lines.extend(["# Exact-host reverse-proxy redirect.", "server {",
                              f"  listen {format_nginx_listen(address, proxy['redirect_port'])};", f"  server_name {hostname};",
                              "  if ($http_host = '') { return 404; }",
                              f"  if ($host != {hostname}) {{ return 404; }}",
                              f"  add_header X-Atlaso-Reverse-Proxy {proxy['id']}-{manifest['generation']} always;",
                              f"  location ~* {RESERVED_PATTERN} {{ return 404; }}",
                              f"  location / {{ return 308 https://{hostname}{port}$request_uri; }}", "}"])
    return "\n".join(lines) + "\n"


def directory_entries(proxies: list[dict[str, Any]], address: str) -> list[dict[str, Any]]:
    """Publish opted-in resources only on the called listener address.

    Args:
        proxies: Complete bounded proxy desired-state collection.
        address: Input used by directory entries.
    """
    entries = []
    for proxy in proxies:
        if not proxy["enabled"] or not proxy["public_listing"] or address not in {item["address"] for item in proxy["listeners"]}:
            continue
        port = "" if proxy["port"] == (443 if proxy["scheme"] == "https" else 80) else f":{proxy['port']}"
        for route in proxy["routes"]:
            entries.append({"id": f"reverse_proxy:{proxy['id']}:{route['id']}", "name": proxy["name"],
                "summary": proxy["description"] or "Managed reverse proxy", "href": f"{proxy['scheme']}://{proxy['hostname']}{port}{route['path_prefix']}",
                "scheme": proxy["scheme"], "port": proxy["port"], "dns_names": [proxy["hostname"]],
                "status": "configured", "pill": "warn" if route["trust_mode"] == "insecure" else "muted"})
    return entries


def firewall_rules(proxies: list[dict[str, Any]]) -> list[models.FirewallRule]:
    """Generate exact-address TCP admissions in the existing managed collection.

    Args:
        proxies: Complete bounded proxy desired-state collection.
    """
    result = []
    for proxy in proxies:
        if not proxy["enabled"]:
            continue
        for index, listener in enumerate(proxy["listeners"]):
            address = ip_address(listener["address"])
            ports = [proxy["port"], *([proxy["redirect_port"]] if proxy["redirect_http"] else [])]
            for port in ports:
                result.append(models.FirewallRule(name=f"reverse_proxy:{proxy['id']}:{index}:{port}", direction="input", action="accept",
                    protocol="tcp", source="any", destination=f"{address}/{32 if address.version == 4 else 128}", destination_port=str(port),
                    interface_name=listener["interface"], priority=40, enabled=True,
                    description=f"{ATLASO_SERVICE_FIREWALL_RULE_MARKER} for reverse proxy {proxy['name']} exact listener."))
    return result


def dns_plan(proxies: list[dict[str, Any]], settings: models.DnsSettings | None) -> tuple[list[dict[str, Any]], list[str]]:
    """Describe exact records and truthfully report external-DNS prerequisites.

    Args:
        proxies: Complete bounded proxy desired-state collection.
        settings: Input used by dns plan.
    """
    records = []
    warnings = []
    zones = set(split_domains(settings.domain)) - set(split_domains(settings.disabled_domains)) if settings else set()
    for proxy in proxies:
        served = bool(settings and settings.enabled and settings.authoritative and any(
            proxy["hostname"] == zone or proxy["hostname"].endswith("." + zone) for zone in zones))
        managed = bool(proxy["enabled"] and proxy["managed_dns"] and served)
        if proxy["enabled"] and not managed:
            warnings.append(f"{proxy['name']}: configure the displayed exact A/AAAA records externally; managed authoritative DNS is off or unavailable.")
        for address in sorted({item["address"] for item in proxy["listeners"]}):
            records.append({"hostname": proxy["hostname"], "record_type": "AAAA" if ip_address(address).version == 6 else "A",
                            "address": address, "managed": managed, "description": DNS_OWNER_PREFIX + str(proxy["id"])})
    return records, warnings


def dns_hostname_key(value: str) -> str:
    """Identify DNS-equivalent spellings for publication ownership guards.

    Args:
        value: Validated DNS hostname whose case and final root dot are insignificant.
    """
    return value.strip().rstrip(".").casefold()


def validate_dns_ownership(plan: list[dict[str, Any]], records: list[models.DnsRecord]) -> None:
    """Reject DNS-equivalent operator names before managed publication changes.

    Args:
        plan: Proposed exact DNS publication records, including managed eligibility.
        records: Existing or archived records whose ownership must be preserved.
    """
    wanted_names = {dns_hostname_key(row["hostname"]) for row in plan if row["managed"]}
    for record in records:
        if dns_hostname_key(record.hostname) in wanted_names and not (record.description or "").startswith(DNS_OWNER_PREFIX):
            raise ValueError("Managed reverse-proxy DNS conflicts with an operator or another service record. Preserve that record and resolve the hostname first.")


def reconcile_proxy_dns(db: Session, proxies: list[dict[str, Any]]) -> None:
    """Reconcile desired records within the caller's locked atomic transaction.

    Args:
        db: Caller-owned database session for proxy desired state.
        proxies: Complete bounded proxy desired-state collection.
    """
    plan, _warnings = dns_plan(proxies, db.scalar(select(models.DnsSettings)))
    wanted = {(row["hostname"], row["record_type"], row["address"]): row for row in plan if row["managed"]}
    existing = list(db.scalars(select(models.DnsRecord)))
    validate_dns_ownership(plan, existing)
    retained = set()
    for record in existing:
        if not (record.description or "").startswith(DNS_OWNER_PREFIX):
            continue
        key = (record.hostname, record.record_type, record.address)
        if key not in wanted:
            db.delete(record)
        else:
            record.enabled = True
            record.description = wanted[key]["description"]
            retained.add(key)
    for key, row in wanted.items():
        if key not in retained:
            db.add(models.DnsRecord(hostname=row["hostname"], record_type=row["record_type"], address=row["address"],
                                   description=row["description"], enabled=True))
    db.flush()


def context(db: Session) -> dict[str, Any]:
    """Build read-only collection, validation and redacted publication previews.

    Args:
        db: Caller-owned database session for proxy desired state.
    """
    from atlaso.app.reverse_proxy_schemas import response_for_proxy
    from atlaso.app.services.reverse_proxies import (
        desired_rows,
        listener_options,
        runtime_snapshot,
        validate_proxy,
        validation_context,
    )

    rows = desired_rows(db)
    proxies = runtime_snapshot(db)
    inventory = validation_context(db)
    errors = [f"{proxy.name}: {error}" for proxy in rows if proxy.enabled
              for error in validate_proxy(proxy, inventory, rows, exclude_id=proxy.id)]
    records, warnings = dns_plan(proxies, db.scalar(select(models.DnsSettings)))
    warnings.extend(f"{proxy['name']}: insecure upstream certificate verification remains enabled for {route['path_prefix']}."
                    for proxy in proxies if proxy["enabled"] for route in proxy["routes"] if route["trust_mode"] == "insecure")
    preview = ""
    manifest = None
    if not errors:
        try:
            manifest = transport_manifest(proxies, appliance_addresses(db))
            preview = render_proxy_servers(proxies, manifest)
        except ValueError:
            errors.append("Reverse-proxy transport intent is invalid; review routes and limits before Apply.")
    return {"reverse_proxies": [response_for_proxy(row).model_dump(mode="json") for row in rows], "reverse_proxy_listener_options": listener_options(db),
            "reverse_proxy_validation_errors": errors, "reverse_proxy_validation_warnings": warnings,
            "reverse_proxy_config_preview": preview, "reverse_proxy_config_path": STAGED_PATH,
            "reverse_proxy_manifest": manifest, "reverse_proxy_dns_records": records}


def main() -> None:
    """Validate bounded site input for the fixed privileged helper subprocess."""
    if sys.argv[1:] != ["--validate"]:
        raise SystemExit("Only reverse-proxy publication validation is supported.")
    try:
        raw = sys.stdin.buffer.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Publication exceeds its size bound.")
        proxies, manifest = validated_snapshot(raw.decode("utf-8"))
        endpoints = [{"proxy_id": proxy["id"], "hostname": proxy["hostname"],
                      "interface": listener["interface"], "address": listener["address"],
                      "scheme": proxy["scheme"], "port": proxy["port"]}
                     for proxy in proxies if proxy["enabled"] for listener in proxy["listeners"]]
        print(json.dumps({"manifest": manifest, "endpoints": endpoints, "proxies": proxies}, sort_keys=True))
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise SystemExit("Reverse-proxy publication metadata or generated directives are invalid.") from None


if __name__ == "__main__":
    main()
