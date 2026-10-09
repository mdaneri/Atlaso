"""Validate and persist managed reverse-proxy desired state."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso.app import models
from atlaso.app.reverse_proxy_schemas import ReverseProxyCreate
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.port_forwarding import ListenerClaim, listener_claims
from atlaso.app.services.traffic_publishing import nat_targets
from atlaso.app.ui_routes import PROTOCOL_EXACT_PATHS, PROTOCOL_PATH_PREFIXES

MAX_REVERSE_PROXIES = 256
MAX_PROXY_ROUTES = 64
MAX_TOTAL_PROXY_ROUTES = 256
MAX_TOTAL_PROXY_PUBLICATION_ROUTES = 256
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_SERVICE_SETTING_MODELS = (
    models.NtpSettings,
    models.CaSettings,
    models.KmsSettings,
    models.LdapSettings,
    models.EsxStorageSettings,
    models.OidcProviderSettings,
    models.VcfBackupSettings,
    models.VcfPrivateRegistrySettings,
    models.VcfOfflineDepotSettings,
)


def _legacy_ipv4_literal(value: str) -> bool:
    """Detect noncanonical inet-style numeric addresses without resolving DNS.

    Args:
        value: Candidate hostname or address spelling.
    """
    candidate = value.strip().rstrip(".").lower()
    try:
        ipaddress.IPv4Address(candidate)
        return False
    except ValueError:
        pass
    labels = candidate.split(".")
    if not 1 <= len(labels) <= 4:
        return False
    numbers: list[int] = []
    for label in labels:
        if re.fullmatch(r"0x[0-9a-f]+", label):
            base = 16
        elif re.fullmatch(r"[0-9]+", label):
            base = 8 if len(label) > 1 and label.startswith("0") else 10
        else:
            return False
        try:
            numbers.append(int(label, base))
        except ValueError:
            return False
    return all(number <= 255 for number in numbers[:-1]) and numbers[-1] < 1 << (8 * (5 - len(numbers)))


def _canonical_dns_name(value: str, *, require_fqdn: bool) -> str:
    """Return a canonical DNS name or raise for ambiguous host syntax.

    Args:
        value: Candidate value to normalize or validate.
        require_fqdn: Whether the DNS name must contain multiple labels.
    """
    candidate = value.strip().rstrip(".").lower()
    if _legacy_ipv4_literal(candidate):
        raise ValueError("Use a DNS hostname or canonical IP literal, not a legacy numeric address spelling.")
    if not candidate or len(candidate) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in candidate.split(".")):
        raise ValueError("Enter a valid DNS hostname without a URL, port, or credentials.")
    if require_fqdn and "." not in candidate:
        raise ValueError("The served hostname must be a fully qualified DNS name.")
    if require_fqdn:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            raise ValueError("Use a DNS hostname for the virtual host, not an IP literal.")
    return candidate


def _host_literal(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a safe upstream IP literal, excluding special-purpose addresses.

    Args:
        value: Candidate value to normalize or validate.
    """
    if _legacy_ipv4_literal(value):
        raise ValueError("Use a canonical upstream IP literal, not a legacy numeric address spelling.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if (
        "%" in value
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
    ):
        raise ValueError("Use an ordinary unicast upstream address; special-purpose literals are not allowed.")
    return address


def _valid_listener_address(value: str) -> bool:
    """Return whether an assigned listener address is an ordinary unicast address.

    Args:
        value: Candidate value to normalize or validate.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        "%" in value
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
    )


def desired_rows(db: Session) -> list[models.ReverseProxy]:
    """Return reverse proxies with routes in their saved order.

    Args:
        db: Caller-owned database session for proxy desired state.
    """
    return list(
        db.scalars(
            select(models.ReverseProxy)
            .options(selectinload(models.ReverseProxy.routes))
            .order_by(models.ReverseProxy.name, models.ReverseProxy.id)
        )
    )


def listener_options(db: Session) -> list[dict[str, str]]:
    """Return exact configured addresses on available non-management targets.

    Args:
        db: Caller-owned database session for proxy desired state.
    """
    interfaces = list(db.scalars(select(models.PhysicalInterface)))
    vlans = list(db.scalars(select(models.VlanInterface)))
    targets = nat_targets(interfaces, vlans)
    options: list[dict[str, str]] = []
    for target in targets:
        name = str(target["name"])
        for field in ("ip_cidr", "ipv6_cidr"):
            try:
                address = str(ipaddress.ip_interface(str(target.get(field) or "")).ip)
            except ValueError:
                continue
            if not _valid_listener_address(address):
                continue
            options.append({"interface": name, "address": address})
    return sorted(options, key=lambda item: (item["interface"], item["address"]))


def validate_interface_proxy_bindings(
    db: Session, interface_names: set[str], *, removed_names: set[str] | None = None,
) -> None:
    """Reject interface edits that strand an enabled proxy's reviewed exact tuple.

    Args:
        db: Caller-owned candidate-state transaction holding the Network Objects lock.
        interface_names: Direct and dependent interface names affected by the edit.
        removed_names: Names being deleted or renamed before their database rows are removed.
    """
    available = {(item["interface"], item["address"]) for item in listener_options(db)}
    for proxy in desired_rows(db):
        if not proxy.enabled:
            continue
        for listener in proxy.listeners:
            name = str(listener.get("interface") or "")
            address = str(listener.get("address") or "")
            if name in interface_names and (name in (removed_names or set()) or (name, address) not in available):
                raise ValueError(
                    f"Enabled reverse proxy {proxy.name} still depends on {name} at {address}. "
                    "Disable or move the proxy binding before changing its interface or listen address."
                )


def _service_hostnames(db: Session) -> set[str]:
    """Collect Atlaso-owned service and appliance names reserved by existing services.

    Args:
        db: Caller-owned database session for proxy desired state.
    """
    names: set[str] = set()
    from atlaso.app.services.dnsmasq import authoritative_server_name

    dns_settings = db.scalar(select(models.DnsSettings))
    if dns_settings is not None and dns_settings.authoritative:
        try:
            names.add(_canonical_dns_name(authoritative_server_name(dns_settings), require_fqdn=False))
        except ValueError:
            pass
    for model in _SERVICE_SETTING_MODELS:
        row = db.scalar(select(model))
        if row is None:
            continue
        for field in ("hostname", "portal_hostname"):
            value = str(getattr(row, field, "") or "").strip()
            if not value:
                continue
            try:
                names.add(_canonical_dns_name(value, require_fqdn=False))
            except ValueError:
                continue
    appliance = db.scalar(select(models.ApplianceSettings))
    if appliance is not None and appliance.fqdn:
        try:
            names.add(_canonical_dns_name(appliance.fqdn, require_fqdn=False))
        except ValueError:
            pass
    # Use the canonical Network Boot settings reader so absent and blank
    # hostname rows reserve the same appliance-domain default as publication.
    from atlaso.app.services.esxi_pxe import esxi_pxe_boot_settings

    try:
        names.add(_canonical_dns_name(esxi_pxe_boot_settings(db)["hostname"], require_fqdn=False))
    except (KeyError, ValueError):
        pass
    return names


def validation_context(db: Session) -> dict[str, Any]:
    """Capture eligible listeners, appliance identities, socket claims and peer state.

    Args:
        db: Caller-owned database session for proxy desired state.
    """
    interfaces = list(db.scalars(select(models.PhysicalInterface)))
    vlans = list(db.scalars(select(models.VlanInterface)))
    addresses: set[str] = set()
    for interface in [*interfaces, *vlans]:
        for field in ("ip_cidr", "ipv6_cidr", "host_ip_cidr", "host_ipv6_cidr"):
            try:
                addresses.add(str(ipaddress.ip_interface(str(getattr(interface, field, "") or "")).ip))
            except ValueError:
                continue
    return {
        "targets": nat_targets(interfaces, vlans),
        "listeners": listener_options(db),
        "addresses": addresses,
        "service_hostnames": _service_hostnames(db),
        "ca_enabled": bool((ca := db.scalar(select(models.CaSettings))) is not None and ca.enabled),
        "claims": listener_claims(db, include_reverse_proxies=False),
        "port_forwards": list(db.scalars(select(models.PortForward))),
    }


def _listener_sockets(proxy: models.ReverseProxy) -> list[tuple[str, str, int, str]]:
    """Enumerate the TCP sockets and protocol occupied by a proxy candidate.

    Args:
        proxy: Desired-state proxy model or projection.
    """
    ports = [(int(proxy.port), proxy.scheme)]
    if proxy.redirect_http:
        ports.append((int(proxy.redirect_port), "http"))
    return [
        (str(listener.get("interface") or ""), str(listener.get("address") or ""), port, scheme)
        for listener in proxy.listeners
        for port, scheme in ports
    ]


def _claim_conflicts(
    claim: ListenerClaim,
    *,
    address: str,
    port: int,
) -> bool:
    """Check exact or wildcard socket overlap with an existing service claim.

    Args:
        claim: Input used by  claim conflicts.
        address: Input used by  claim conflicts.
        port: Input used by  claim conflicts.
    """
    return (
        claim.address in ("*", "0.0.0.0", "::", address)
        and claim.protocol == "tcp"
        and claim.start <= port <= claim.end
    )


def _nginx_http_front_door(claim: ListenerClaim) -> bool:
    """Recognize only inventory entries explicitly owned by the nginx front door.

    Args:
        claim: Input used by  nginx http front door.
    """
    return (
        claim.owner == "nginx"
        and claim.scheme in {"http", "https"}
        and claim.protocol == "tcp"
        and claim.start == claim.end
    )


def validate_service_proxy_dependencies(db: Session) -> None:
    """Preserve saved proxy hostname ownership and enabled HTTPS CA dependencies.

    Callers hold the Network Objects writer lock and roll back on rejection.

    Args:
        db: Caller-owned session containing candidate service desired state.

    Raises:
        ValueError: If candidate service state would invalidate a saved proxy.
    """
    proxies = desired_rows(db)
    if not proxies:
        return
    names = _service_hostnames(db)
    ca = db.scalar(select(models.CaSettings))
    for proxy in proxies:
        if proxy.hostname.strip().rstrip(".").casefold() in names:
            raise ValueError(f"Service hostname conflicts with saved reverse proxy {proxy.name}. Move or remove the proxy before saving this service hostname.")
        if any(route.upstream_host.strip().rstrip(".").casefold() in names for route in proxy.routes):
            raise ValueError(f"Service hostname conflicts with an upstream of saved reverse proxy {proxy.name}. Change that upstream before saving this service hostname.")
        if proxy.enabled and proxy.scheme == "https" and (ca is None or not ca.enabled):
            raise ValueError("Disable enabled HTTPS reverse proxies before disabling their Certificate Authority.")


def validate_service_listener_sockets(db: Session) -> None:
    """Reject service edits that take an enabled proxy's socket before commit.

    Callers hold the Network Objects writer lock before reading or changing
    desired state and roll back their transaction when validation fails.

    Args:
        db: Caller-owned session containing the complete candidate service state.

    Raises:
        ValueError: If service state conflicts with proxy names, CA or sockets.
    """
    validate_service_proxy_dependencies(db)
    claims = listener_claims(db, include_reverse_proxies=False)
    for proxy in desired_rows(db):
        if not proxy.enabled:
            continue
        for interface, address, port, scheme in _listener_sockets(proxy):
            for claim in claims:
                if _claim_conflicts(claim, address=address, port=port):
                    if _nginx_http_front_door(claim) and scheme == claim.scheme:
                        continue
                    raise ValueError(
                        f"Service listener conflicts with enabled reverse proxy {proxy.name} on {interface} {address}:{port}. "
                        "Disable or move the proxy before saving this service listener."
                    )


def _route_overlap(left: str, right: str) -> bool:
    """Return whether nginx's prefix matching makes two routes ambiguous.

    Args:
        left: Input used by  route overlap.
        right: Input used by  route overlap.
    """
    return left.startswith(right) or right.startswith(left)


RESERVED_ROUTE_ROOTS = frozenset({
    "ui", "api", "openapi.json", "identity", "ca", "pxe", "prod", "registry", "v2", "static",
    "manifest.webmanifest", "service-worker.js", "terminal", "requests", "depot",
    "certificate-authority",
}) | frozenset(path.lstrip("/").split("/", 1)[0].casefold()
              for path in (*PROTOCOL_EXACT_PATHS, *PROTOCOL_PATH_PREFIXES))


def _reserved_route_path(path: str) -> bool:
    """Return whether a path would shadow a stable Atlaso machine or browser route.

    Args:
        path: Input used by  reserved route path.
    """
    if path == "/":
        return False
    folded = path.casefold()
    return (folded.lstrip("/").split("/", 1)[0] in RESERVED_ROUTE_ROOTS
            or any(folded.startswith(prefix.casefold()) for prefix in PROTOCOL_PATH_PREFIXES))


def validate_proxy(
    candidate: models.ReverseProxy,
    context: dict[str, Any],
    existing: list[models.ReverseProxy],
    exclude_id: int | None = None,
    *,
    require_binding: bool = True,
    require_managed_ca: bool = True,
) -> list[str]:
    """Validate one complete proxy and nested route replacement before persistence.

    Args:
        candidate: Input used by validate proxy.
        context: Validated listener, address, service, and socket inventory.
        existing: Current proxy collection used for replacement and conflict checks.
        exclude_id: Existing proxy replaced by the candidate.
        require_binding: Whether exact eligible listener binding must be present.
        require_managed_ca: Whether desired-state CA availability must be checked.
    """
    errors: list[str] = []
    try:
        hostname = _canonical_dns_name(candidate.hostname, require_fqdn=True)
        if hostname != candidate.hostname:
            errors.append("Use the canonical lowercase hostname without a final dot.")
    except ValueError as exc:
        hostname = ""
        errors.append(str(exc))

    service_names = context.get("service_hostnames", set())
    proxy_names = {
        peer.hostname.strip().rstrip(".").casefold()
        for peer in existing
        if peer.id != exclude_id
    }
    proxy_names.add(hostname)
    if candidate.managed_dns and len(hostname) > 120:
        errors.append("Managed DNS requires a hostname of at most 120 characters.")
    if hostname and hostname in service_names:
        errors.append("This hostname is already owned by an Atlaso service.")
    for proxy in existing:
        if proxy.id == exclude_id:
            continue
        if proxy.name.strip().casefold() == candidate.name.strip().casefold():
            errors.append("A reverse proxy with that name already exists.")
        if proxy.hostname.strip().rstrip(".").casefold() == hostname:
            errors.append("A reverse proxy with that hostname already exists.")

    if candidate.scheme not in {"http", "https"}:
        errors.append("Choose HTTP or HTTPS for the client-facing protocol.")
    if require_managed_ca and candidate.enabled and candidate.scheme == "https" and not context.get("ca_enabled", False):
        errors.append("Enabled HTTPS reverse proxies require an enabled CA to issue their managed certificate.")
    if not 1 <= candidate.port <= 65535 or not 1 <= candidate.redirect_port <= 65535:
        errors.append("Client-facing listener ports must be between 1 and 65535.")
    if candidate.redirect_http and candidate.scheme != "https":
        errors.append("HTTP redirection is available only for an HTTPS virtual host.")
    if not 1 <= candidate.connect_timeout <= 30:
        errors.append("Upstream connect timeout must be between 1 and 30 seconds.")
    if not 1 <= candidate.read_timeout <= 300 or not 1 <= candidate.send_timeout <= 300:
        errors.append("Upstream read and send timeouts must be between 1 and 300 seconds.")
    if not 1 <= candidate.body_limit <= 1073741824:
        errors.append("Request body limit must be between 1 byte and 1 GiB.")

    options = {
        (item["interface"], item["address"])
        for item in context.get("listeners", [])
    }
    seen_listeners: set[tuple[str, str]] = set()
    for listener in candidate.listeners:
        key = (str(listener.get("interface") or ""), str(listener.get("address") or ""))
        try:
            canonical_address = str(ipaddress.ip_address(key[1]))
        except ValueError:
            canonical_address = ""
        if (
            not key[0]
            or canonical_address != key[1]
            or not _valid_listener_address(key[1])
            or require_binding and key not in options
        ):
            errors.append("Select an exact saved address on an available non-management interface or VLAN.")
        if key in seen_listeners:
            errors.append("Each interface and address listener may be selected only once.")
        seen_listeners.add(key)
    if not candidate.listeners:
        errors.append("Select at least one interface and address listener.")
    if not candidate.routes:
        errors.append("A reverse proxy must include at least one path route.")

    candidate_sockets = [(int(candidate.port), candidate.scheme)]
    if candidate.redirect_http:
        candidate_sockets.append((int(candidate.redirect_port), "http"))
    if len({port for port, _scheme in candidate_sockets}) != len(candidate_sockets):
        errors.append("The HTTPS and HTTP redirect listeners must use different TCP ports.")
    claims: list[ListenerClaim] = context.get("claims", [])
    for listener in candidate.listeners:
        interface = str(listener.get("interface") or "")
        address = str(listener.get("address") or "")
        for port, socket_scheme in candidate_sockets:
            for claim in claims:
                if _claim_conflicts(claim, address=address, port=port):
                    if _nginx_http_front_door(claim) and socket_scheme == claim.scheme:
                        continue
                    errors.append("The listener collides with an exclusive Atlaso service socket.")
                    break
            for forward in context.get("port_forwards", []):
                if (
                    forward.enabled
                    and forward.protocol == "tcp"
                    and forward.ingress_interface == interface
                    and forward.listener_address == address
                    and forward.external_port_start <= port <= forward.external_port_end
                ):
                    errors.append("The listener collides with an enabled exclusive port-forward socket.")
                    break
            for peer in existing:
                if peer.id == exclude_id:
                    continue
                if not peer.enabled:
                    continue
                for _peer_interface, peer_address, peer_port, peer_scheme in _listener_sockets(peer):
                    if peer_address == address and peer_port == port:
                        if peer_scheme != socket_scheme:
                            errors.append("HTTP and HTTPS virtual hosts cannot share the same listener socket.")
                        elif hostname and peer.hostname.strip().rstrip(".").casefold() == hostname:
                            errors.append("The same hostname cannot claim an nginx socket more than once.")
                        # Distinct hostnames intentionally share an nginx listener socket.

    upstream_addresses = context.get("addresses", set())
    route_ids: set[int] = set()
    paths: list[str] = []
    for route in candidate.routes:
        route_id = getattr(route, "id", None)
        if route_id is not None:
            if route_id in route_ids:
                errors.append("A saved route identity may appear only once in a proxy replacement.")
            route_ids.add(route_id)
        path = str(getattr(route, "path_prefix", ""))
        if (
            not path.startswith("/")
            or "\\" in path
            or "%" in path
            or "?" in path
            or "#" in path
            or any(character.isspace() for character in path)
            or any(character in path for character in ";{}$\"'")
            or "//" in path
            or any(segment in {".", ".."} for segment in path.split("/"))
        ):
            errors.append("Use an absolute path prefix without encoded, dot, backslash or ambiguous path segments.")
        if path.startswith("/") and _reserved_route_path(path):
            errors.append("Reverse-proxy routes cannot shadow reserved Atlaso browser or machine paths.")
        if any(_route_overlap(path, other) for other in paths):
            errors.append("Route path prefixes cannot overlap within one virtual host.")
        paths.append(path)

        upstream_host = str(getattr(route, "upstream_host", "")).strip()
        try:
            parsed_address = _host_literal(upstream_host)
        except ValueError as exc:
            errors.append(str(exc))
            parsed_address = None
        if parsed_address is not None:
            if str(parsed_address) != upstream_host:
                errors.append("Use the canonical upstream IP literal without brackets or a zone identifier.")
            elif str(parsed_address) in upstream_addresses:
                errors.append("An upstream cannot target an address assigned to this Atlaso appliance.")
        else:
            try:
                canonical_host = _canonical_dns_name(upstream_host, require_fqdn=False)
                if canonical_host != upstream_host:
                    errors.append("Use a canonical lowercase upstream hostname without a final dot.")
                if canonical_host in service_names:
                    errors.append("An upstream cannot target an Atlaso-owned service hostname.")
                if canonical_host in proxy_names:
                    errors.append("An upstream cannot target a managed reverse-proxy hostname.")
            except ValueError as exc:
                errors.append(f"Invalid upstream host: {exc}")

        if not 1 <= int(getattr(route, "upstream_port", 0)) <= 65535:
            errors.append("Upstream ports must be between 1 and 65535.")
        if getattr(route, "upstream_scheme", "") not in {"http", "https"}:
            errors.append("Choose HTTP or HTTPS for every upstream connection.")
        if getattr(route, "path_behavior", "") not in {"preserve", "strip"}:
            errors.append("Choose whether the upstream path preserves or strips its matched prefix.")
        trust_mode = getattr(route, "trust_mode", "")
        fingerprint = str(getattr(route, "fingerprint", "") or "")
        if trust_mode not in {"trusted_ca", "fingerprint", "insecure"}:
            errors.append("Choose a supported HTTPS certificate trust mode.")
        if getattr(route, "upstream_scheme", "") == "http" and trust_mode != "trusted_ca":
            errors.append("HTTP upstreams do not use HTTPS certificate trust settings.")
        if trust_mode == "fingerprint" and not _FINGERPRINT.fullmatch(fingerprint):
            errors.append("Fingerprint trust mode requires a canonical lowercase SHA-256 fingerprint.")
        if trust_mode != "fingerprint" and fingerprint:
            errors.append("A certificate fingerprint is allowed only with fingerprint trust mode.")

    if len(candidate.routes) > MAX_PROXY_ROUTES:
        errors.append("A reverse proxy may contain at most 64 routes.")
    publication_routes = sum(len(peer.listeners or []) * len(peer.routes) for peer in existing if peer.id != exclude_id)
    publication_routes += len(candidate.listeners or []) * len(candidate.routes)
    if publication_routes > MAX_TOTAL_PROXY_PUBLICATION_ROUTES:
        errors.append("At most 256 reverse-proxy listener/route combinations may be saved across the appliance.")
    return list(dict.fromkeys(errors))


def save_proxy(
    db: Session,
    payload: ReverseProxyCreate | dict[str, Any],
    *,
    actor: str,
    proxy_id: int | None = None,
) -> models.ReverseProxy:
    """Atomically replace proxy and nested routes, then audit desired-state save.

    Args:
        db: Caller-owned database session for proxy desired state.
        payload: Desired-state or cached-observation fixture payload.
        actor: Authenticated audit identity responsible for the mutation.
        proxy_id: Exact saved proxy identifier.
    """
    request = payload if isinstance(payload, ReverseProxyCreate) else ReverseProxyCreate.model_validate(payload)
    acquire_network_objects_write_lock(db)
    try:
        from atlaso.app.services.applied_service_dns import (
            remember_applied_service_dns_records,
        )

        remember_applied_service_dns_records(db)
        peers = desired_rows(db)
        current = db.get(models.ReverseProxy, proxy_id) if proxy_id is not None else None
        if proxy_id is not None and current is None:
            raise LookupError("Reverse proxy does not exist.")
        if current is None and len(peers) >= MAX_REVERSE_PROXIES:
            raise ValueError("At most 256 reverse proxies may be saved.")

        values = request.model_dump(exclude={"routes"})
        values["listeners"] = [listener.model_dump() for listener in request.listeners]
        values["hostname"] = _canonical_dns_name(request.hostname, require_fqdn=True)
        candidate_routes: list[models.ReverseProxyRoute] = []
        route_replacements: list[tuple[int | None, int, dict[str, Any]]] = []
        previous_routes = {route.id: route for route in current.routes} if current is not None else {}
        for position, route_input in enumerate(request.routes):
            route_values = route_input.model_dump(exclude={"id", "insecure_acknowledged"})
            route_values["upstream_host"] = _normalize_upstream_host(route_input.upstream_host)
            route_id = route_input.id
            if route_id is not None and route_id not in previous_routes:
                raise ValueError("A route identity must belong to the reverse proxy being replaced.")
            route_replacements.append((route_id, position, route_values))
            candidate_routes.append(models.ReverseProxyRoute(id=route_id, **route_values, position=position))
        candidate = models.ReverseProxy(id=proxy_id, **values, routes=candidate_routes)
        retained_routes = sum(len(peer.routes) for peer in peers if peer.id != proxy_id)
        if retained_routes + len(candidate_routes) > MAX_TOTAL_PROXY_ROUTES:
            raise ValueError("At most 256 reverse-proxy routes may be saved across the appliance.")
        errors = validate_proxy(candidate, validation_context(db), peers, exclude_id=proxy_id)
        if errors:
            raise ValueError(" ".join(errors))
        if current is None:
            current = candidate
            db.add(current)
        else:
            retained_route_ids = {route_id for route_id, _position, _values in route_replacements if route_id is not None}
            for route in previous_routes.values():
                if route.id not in retained_route_ids:
                    db.delete(route)
            db.flush()
            for index, route_id in enumerate(sorted(retained_route_ids), start=1):
                previous_routes[route_id].position = -index
            db.flush()
            for key, value in values.items():
                setattr(current, key, value)
            route_rows: list[models.ReverseProxyRoute] = []
            for route_id, position, route_values in route_replacements:
                replacement_route = previous_routes.get(route_id) if route_id is not None else None
                if replacement_route is None:
                    replacement_route = models.ReverseProxyRoute(**route_values, position=position)
                else:
                    for key, value in route_values.items():
                        setattr(replacement_route, key, value)
                    replacement_route.position = position
                route_rows.append(replacement_route)
            current.routes = route_rows
            current.updated_at = models.utcnow()
        db.flush()
        if not 1 <= current.id <= 0xFFFFFF:
            raise ValueError("Reverse-proxy identity capacity is exhausted; contact the appliance maintainer.")
        from atlaso.app.services.reverse_proxy_publication import (
            appliance_addresses,
            validate_publication_size,
        )

        snapshot = runtime_snapshot(db)
        validate_publication_size(snapshot, appliance_addresses(db))
        from atlaso.app.services.reverse_proxy_publication import reconcile_proxy_dns

        reconcile_proxy_dns(db, runtime_snapshot(db))
        insecure_count = sum(route.trust_mode == "insecure" for route in current.routes)
        db.add(
            models.AuditEvent(
                actor=actor,
                action="create_reverse_proxy" if proxy_id is None else "update_reverse_proxy",
                resource_type="reverse_proxy",
                resource_id=str(current.id),
                success=True,
                detail=(
                    f"Desired state only; global Appliance Apply required; "
                    f"insecure_upstream_acknowledgements={insecure_count}."
                ),
            )
        )
        db.commit()
        if insecure_count:
            logging.getLogger("atlaso.operational").warning(
                "Reverse proxy desired state saved with acknowledged insecure upstream verification: proxy_id=%s routes=%s",
                current.id, insecure_count,
            )
        return current
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("A reverse proxy with that name or hostname already exists.") from exc
    except Exception:
        db.rollback()
        raise


def _normalize_upstream_host(value: str) -> str:
    """Normalize a validated upstream IP literal or DNS hostname.

    Args:
        value: Candidate value to normalize or validate.
    """
    address = _host_literal(value)
    if address is not None:
        return str(address)
    return _canonical_dns_name(value, require_fqdn=False)


def delete_proxy(db: Session, proxy_id: int, *, actor: str) -> None:
    """Delete one proxy and its ordered routes as an audited transaction.

    Args:
        db: Caller-owned database session for proxy desired state.
        proxy_id: Exact saved proxy identifier.
        actor: Authenticated audit identity responsible for the mutation.
    """
    acquire_network_objects_write_lock(db)
    try:
        from atlaso.app.services.applied_service_dns import (
            remember_applied_service_dns_records,
        )

        remember_applied_service_dns_records(db)
        proxy = db.get(models.ReverseProxy, proxy_id)
        if proxy is None:
            raise LookupError("Reverse proxy does not exist.")
        db.delete(proxy)
        db.flush()
        from atlaso.app.services.reverse_proxy_publication import reconcile_proxy_dns

        reconcile_proxy_dns(db, runtime_snapshot(db))
        db.add(
            models.AuditEvent(
                actor=actor,
                action="delete_reverse_proxy",
                resource_type="reverse_proxy",
                resource_id=str(proxy.id),
                success=True,
                detail="Desired state only; global Appliance Apply required.",
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def set_enabled(db: Session, proxy_id: int, *, enabled: bool, actor: str) -> models.ReverseProxy:
    """Save a complete proxy replacement with only the enabled value changed.

    Args:
        db: Caller-owned database session for proxy desired state.
        proxy_id: Exact saved proxy identifier.
        enabled: Input used by set enabled.
        actor: Authenticated audit identity responsible for the mutation.
    """
    acquire_network_objects_write_lock(db)
    proxy = db.scalar(
        select(models.ReverseProxy)
        .options(selectinload(models.ReverseProxy.routes))
        .where(models.ReverseProxy.id == proxy_id)
    )
    if proxy is None:
        raise LookupError("Reverse proxy does not exist.")
    values = {
        field: getattr(proxy, field)
        for field in ReverseProxyCreate.model_fields
        if field not in {"routes", "apply_required"}
    }
    values["enabled"] = enabled
    values["routes"] = [
        {
            "id": route.id,
            "path_prefix": route.path_prefix,
            "upstream_scheme": route.upstream_scheme,
            "upstream_host": route.upstream_host,
            "upstream_port": route.upstream_port,
            "path_behavior": route.path_behavior,
            "trust_mode": route.trust_mode,
            "fingerprint": route.fingerprint,
            "insecure_acknowledged": route.trust_mode == "insecure",
        }
        for route in proxy.routes
    ]
    return save_proxy(db, ReverseProxyCreate.model_validate(values), actor=actor, proxy_id=proxy_id)


def runtime_snapshot(db: Session) -> list[dict[str, Any]]:
    """Return renderer-safe desired state without private key material.

    Args:
        db: Caller-owned database session for proxy desired state.
    """
    return publication_snapshot(desired_rows(db))


def publication_snapshot(proxies: list[models.ReverseProxy]) -> list[dict[str, Any]]:
    """Project live or reconstructed rows through the same publication contract.

    Args:
        proxies: Complete desired-state proxy collection with ordered routes.
    """
    return [
        {
            "id": proxy.id,
            "name": proxy.name,
            "description": proxy.description,
            "hostname": proxy.hostname,
            "scheme": proxy.scheme,
            "port": proxy.port,
            "redirect_http": proxy.redirect_http,
            "redirect_port": proxy.redirect_port,
            "enabled": proxy.enabled,
            "public_listing": proxy.public_listing,
            "managed_dns": proxy.managed_dns,
            "listeners": [dict(listener) for listener in proxy.listeners],
            "connect_timeout": proxy.connect_timeout,
            "read_timeout": proxy.read_timeout,
            "send_timeout": proxy.send_timeout,
            "body_limit": proxy.body_limit,
            "routes": [
                {
                    "id": route.id,
                    "position": route.position,
                    "path_prefix": route.path_prefix,
                    "upstream_scheme": route.upstream_scheme,
                    "upstream_host": route.upstream_host,
                    "upstream_port": route.upstream_port,
                    "path_behavior": route.path_behavior,
                    "trust_mode": route.trust_mode,
                    "fingerprint": route.fingerprint,
                }
                for route in proxy.routes
            ],
        }
        for proxy in proxies
    ]
