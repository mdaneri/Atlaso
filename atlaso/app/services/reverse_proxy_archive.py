"""Reconstruct name-bound proxy routes without portable runtime identities."""

from ipaddress import ip_interface
from typing import Any

from atlaso.app import models
from atlaso.app.reverse_proxy_schemas import ReverseProxyCreate, ReverseProxyRouteInput
from atlaso.app.services.esxi_pxe import ESXI_PXE_HOSTNAME_KEY, _normalize_hostname
from atlaso.app.services.port_forwarding import ListenerClaim
from atlaso.app.services.reverse_proxies import validate_proxy
from atlaso.app.services.service_dns_defaults import factory_service_hostname


def candidates(data: dict[str, Any]) -> list[models.ReverseProxy]:
    """Validate strict archive projections before any desired-state deletion.

    Args:
        data: Candidate archive sections; routes refer to their proxy by name.
    """
    rows = data.get("reverse_proxies", [])
    routes = data.get("reverse_proxy_routes", [])
    if len(rows) > 256 or len(routes) > 256:
        raise ValueError("Settings archives may retain at most 256 proxies and 256 total routes.")
    names = {row["name"] for row in rows}
    if any(row["proxy_name"] not in names for row in routes):
        raise ValueError("Settings archive reverse-proxy route refers to an absent proxy name.")
    result = []
    for index, row in enumerate(rows, start=1):
        selected = sorted([route for route in routes if route["proxy_name"] == row["name"]], key=lambda route: route["position"])
        if [route["position"] for route in selected] != list(range(len(selected))):
            raise ValueError("Settings archive reverse-proxy route positions must be contiguous and unique.")
        if any(set(route) - (set(ReverseProxyRouteInput.model_fields) - {"id", "insecure_acknowledged"}) - {"position", "proxy_name"} for route in selected):
            raise ValueError("Settings archive reverse-proxy routes contain unsupported fields.")
        request = ReverseProxyCreate.model_validate({**row, "routes": [
            {**{key: value for key, value in route.items() if key not in {"position", "proxy_name"}},
             "insecure_acknowledged": route.get("trust_mode") == "insecure"}
            for route in selected]})
        normalized = request.model_dump(exclude={"routes"})
        reconstructed = [models.ReverseProxyRoute(id=position + 1, position=position,
                          **route.model_dump(exclude={"id", "insecure_acknowledged"}))
                         for position, route in enumerate(request.routes)]
        result.append(models.ReverseProxy(id=index, routes=reconstructed, **normalized))
    return result


def listener_claims(proxies: list[models.ReverseProxy]) -> list[ListenerClaim]:
    """Reserve exact proxy sockets when validating archived port forwards.

    Args:
        proxies: Strictly reconstructed archive candidate collection.
    """
    return [ListenerClaim(listener["interface"], listener["address"], "tcp", port, port)
            for proxy in proxies if proxy.enabled for listener in proxy.listeners
            for port in [proxy.port, *([proxy.redirect_port] if proxy.redirect_http else [])]]


def validate_candidates(proxies: list[models.ReverseProxy], data: dict[str, Any],
                        targets: list[dict[str, Any]], claims: list[ListenerClaim],
                        forwards: list[models.PortForward]) -> None:
    """Validate restored relationships and preserve unavailable exact bindings disabled.

    Args:
        proxies: Reconstructed candidate proxies.
        data: Candidate archive sections, updated only for explicit suspension.
        targets: Eligible archived physical and VLAN targets.
        claims: Existing Atlaso service socket ownership claims.
        forwards: Reconstructed candidate destination translations.
    """
    options = []
    addresses = set()
    for row in [*data["physical_interfaces"], *data["vlan_interfaces"]]:
        for field in ("ip_cidr", "ipv6_cidr"):
            try:
                addresses.add(str(ip_interface(row.get(field) or "").ip))
            except ValueError:
                pass
    for target in targets:
        for field in ("ip_cidr", "ipv6_cidr"):
            try:
                options.append({"interface": target["name"], "address": str(ip_interface(target.get(field) or "").ip)})
            except ValueError:
                pass
    names = {str(row.get(field) or "").strip().lower().rstrip(".")
             for section in ("appliance_settings", "ca_settings", "kms_settings", "ldap_settings",
                             "esx_storage_settings", "oidc_provider_settings", "ntp_settings", "vcf_backup_settings",
                             "vcf_offline_depot_settings", "vcf_private_registry_settings")
             for row in data.get(section, []) for field in ("hostname", "portal_hostname", "fqdn")}
    archived_settings = {
        str(row.get("key") or ""): str(row.get("value") or "")
        for row in data.get("settings", [])
    }
    appliance_fqdn = str(
        (data.get("appliance_settings") or [{}])[0].get("fqdn") or "core.atlaso.internal"
    )
    default_pxe_hostname = factory_service_hostname("esxi-pxe", appliance_fqdn)
    configured_pxe_hostname = archived_settings.get(ESXI_PXE_HOSTNAME_KEY, "").strip()
    pxe_hostname = _normalize_hostname(configured_pxe_hostname or default_pxe_hostname)
    names.add(pxe_hostname)
    context = {"targets": targets, "listeners": options, "addresses": addresses,
               "service_hostnames": names - {""}, "claims": claims, "port_forwards": forwards}
    for proxy, row in zip(proxies, data["reverse_proxies"], strict=True):
        available = all(listener in options for listener in proxy.listeners)
        if not available:
            proxy.enabled = False
            row["enabled"] = False
        errors = validate_proxy(proxy, context, proxies, exclude_id=proxy.id, require_binding=available)
        if errors:
            raise ValueError(f"Settings archive reverse proxy {proxy.name} is invalid: {errors[0]}")
