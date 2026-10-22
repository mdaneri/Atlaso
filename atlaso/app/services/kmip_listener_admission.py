"""Admit KMIP IP endpoints from successful Apply and fresh native ownership."""

from __future__ import annotations

import json
from ipaddress import ip_address, ip_interface
from subprocess import TimeoutExpired
from time import monotonic

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.models import Setting
from atlaso.app.services.management_bindings import (
    APPLIANCE_APPLY_BASELINES_KEY,
    _network_rows,
)
from atlaso.app.services.networking import (
    discover_host_physical_interfaces,
    native_automatic_ipv6_cidrs,
    native_static_ip_cidr,
    verify_native_management_vlans,
)


def applied_kmip_listener_addresses(db: Session, *, port: int) -> frozenset[str]:
    """Return only applied KMIP addresses still observed on their pinned owner.

    Missing legacy source metadata or unavailable native observation admits no IP.
    No desired rows, cached host observations, DNS, or remote labels prove ownership.

    Args:
        db: Active session reading successful appliance-apply baselines.
        port: Configured KMIP port which must also match successful Apply.
    """
    setting = db.execute(select(Setting).where(
        Setting.key == APPLIANCE_APPLY_BASELINES_KEY,
    ).execution_options(populate_existing=True)).scalar_one_or_none()
    try:
        baselines = json.loads(setting.value) if setting and setting.value else {}
        if not isinstance(baselines, dict):
            return frozenset()
        kms, network = baselines.get("kms"), baselines.get("network")
        if not isinstance(kms, dict) or not isinstance(network, dict):
            return frozenset()
        config = json.loads(kms.get("config_preview", ""))
        if not isinstance(config, dict) or config.get("enabled") is not True:
            return frozenset()
        listener = config.get("listen")
        if not isinstance(listener, dict) or type(listener.get("port")) is not int or listener["port"] != port:
            return frozenset()
        result = SystemAdapter().kms_listener_status()
        if result.returncode != 0 or result.dry_run:
            return frozenset()
        runtime = json.loads(result.stdout)
        if not isinstance(runtime, dict) or runtime.get("enabled") is not True or runtime.get("listen") != listener:
            return frozenset()
        addresses, sources = listener.get("addresses"), kms.get("applied_listener_sources")
        preview = network.get("config_preview")
        if not isinstance(addresses, list) or not isinstance(sources, dict) or not isinstance(preview, str):
            return frozenset()
        aliases = network.get("physical_interface_aliases", {})
        if not isinstance(aliases, dict):
            return frozenset()
        rows = _network_rows(preview)
        deadline = monotonic() + 5.0
        native = discover_host_physical_interfaces(timeout=5.0, require_success=True)
        admitted: set[str] = set()
        for value in addresses:
            if not isinstance(value, str):
                continue
            address = ip_address(value)
            if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast:
                continue
            source = sources.get(str(address))
            if not isinstance(source, str) or not source:
                continue
            source = aliases.get(source, source)
            owners = [row for row in rows if aliases.get(row["name"], row["name"]) == source]
            if len(owners) != 1:
                continue
            owner = owners[0]
            if owner.get("role") not in {"access", "route"}:
                continue
            cidr = owner.get("ip_cidr" if address.version == 4 else "ipv6_cidr", "")
            if owner["kind"] == "vlan":
                # VLANs have static addressing; native verification pins tag,
                # parent MAC/index, both up links, and preferred address lifetime.
                if not cidr or ip_interface(cidr).ip != address:
                    continue
                path = dict(owner, name=source, parent=aliases.get(owner.get("parent", ""), owner.get("parent", "")))
                remaining = deadline - monotonic()
                if remaining > 0 and verify_native_management_vlans([path], timeout=remaining):
                    admitted.add(str(address))
                continue
            if owner.get("admin_state") != "up" or owner.get("mode") != "access" or not owner.get("mac"):
                continue
            matches = [host for host in native if host.name == source
                       and host.mac_address.lower() == owner["mac"].lower()
                       and host.host_admin_state == "up" and host.oper_state == "up"]
            if len(matches) != 1:
                continue
            host = matches[0]
            if address.version == 6 and owner.get("ipv6_enabled") != "true":
                continue
            candidates: tuple[str, ...]
            if address.version == 4 and owner.get("ipv4_method") == "dhcp":
                # Ignore legacy static CIDRs even if a DHCP baseline retained one.
                candidates = (host.host_dhcp_ip_cidr,) if host.host_dhcp_ip_cidr else ()
            elif cidr and (address.version == 6 or owner.get("ipv4_method") == "static"):
                observed = native_static_ip_cidr(host, cidr)
                candidates = (observed,) if observed else ()
            elif address.version == 6:
                candidates = native_automatic_ipv6_cidrs(host)
            else:
                candidates = ()
            if any(ip_interface(candidate).ip == address for candidate in candidates):
                admitted.add(str(address))
        return frozenset(admitted)
    except (OSError, ValueError, TypeError, RuntimeError, TimeoutExpired):
        # A platform without native observations is an honest unsupported IP
        # admission, not a reason to fall back to desired or cached addresses.
        return frozenset()
