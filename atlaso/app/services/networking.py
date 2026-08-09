"""Implement networking service behavior."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from ipaddress import ip_address, ip_interface
from pathlib import Path
import subprocess

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    AuditEvent,
    CaSettings,
    DhcpScope,
    DhcpSettings,
    DnsSettings,
    FirewallRule,
    KmsSettings,
    NatRule,
    PhysicalInterface,
    Route,
    RoutingRule,
    Setting,
    VcfBackupSettings,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
)
from atlaso.app.models import utcnow


LOGGER = logging.getLogger("atlaso.networking")
NETWORK_INVENTORY_CLEANUP_WARNING_KEY = "network.inventory_cleanup.warning"
INTERFACE_ROLES = ["management", "access", "route", "unused"]
INTERFACE_MODES = ["access", "trunk", "unused"]
IPV4_METHODS = ["static", "dhcp"]
VLAN_ROLES = ["access", "management", "services", "storage", "route"]


@dataclass(frozen=True)
class HostPhysicalInterface:
    """Represent host physical interface.

    Attributes:
        name: Operator-facing name of the resource.
        mac_address: Mac address maintained by this hostphysicalinterface.
        driver: Driver maintained by this hostphysicalinterface.
        speed: Speed maintained by this hostphysicalinterface.
        host_ip_cidr: Host ip cidr maintained by this hostphysicalinterface.
        host_mtu: Host mtu maintained by this hostphysicalinterface.
        host_admin_state: Host admin state maintained by this hostphysicalinterface.
        oper_state: Oper state maintained by this hostphysicalinterface.
        host_ipv6_cidr: Host ipv6 cidr maintained by this hostphysicalinterface.
    """
    name: str
    mac_address: str
    driver: str | None
    speed: str | None
    host_ip_cidr: str | None
    host_mtu: int | None
    host_admin_state: str
    oper_state: str
    host_ipv6_cidr: str | None = None


def normalize_interface_mode(mode: str | None) -> str:
    """Normalize interface mode.

    Returns:
        The normalize interface mode result.
    """
    value = (mode or "unused").strip().lower()
    if value == "routed":
        return "access"
    if value in INTERFACE_MODES:
        return value
    return "unused"


def normalize_interface_role(role: str | None) -> str:
    """Normalize interface role.

    Returns:
        The normalize interface role result.
    """
    value = (role or "unused").strip().lower()
    if value in {"management", "access", "route", "services", "storage", "unused"}:
        return value
    return "unused"


def normalize_ipv4_method(value: str | None) -> str:
    """Normalize ipv4 method.

    Returns:
        The normalize ipv4 method result.
    """
    method = (value or "static").strip().lower()
    return method if method in IPV4_METHODS else "static"


def physical_interface_to_dict(interface: PhysicalInterface, vlan_count: int = 0) -> dict:
    """Return physical interface to dict."""
    role = normalize_interface_role(interface.role)
    return {
        "id": interface.id,
        "name": interface.name,
        "mac_address": interface.mac_address,
        "driver": interface.driver or "",
        "speed": interface.speed or "",
        "host_ip_cidr": interface.host_ip_cidr or "",
        "host_ipv6_cidr": interface.host_ipv6_cidr or "",
        "host_mtu": interface.host_mtu,
        "host_admin_state": interface.host_admin_state or "",
        "ip_cidr": interface.ip_cidr or "",
        "gateway": interface.gateway or "",
        "ipv4_method": normalize_ipv4_method(interface.ipv4_method),
        "ipv6_enabled": bool(interface.ipv6_enabled),
        "ipv6_cidr": interface.ipv6_cidr or "",
        "ipv6_gateway": interface.ipv6_gateway or "",
        "mtu": interface.mtu,
        "admin_state": interface.admin_state,
        "admin_up": interface.admin_state == "up",
        "oper_state": interface.oper_state,
        "role": role,
        "mode": normalize_interface_mode(interface.mode),
        "inventory_source": interface.inventory_source,
        "desired_state_source": interface.desired_state_source,
        "last_seen_at": interface.last_seen_at.isoformat() if interface.last_seen_at else "",
        "missing_since": interface.missing_since.isoformat() if interface.missing_since else "",
        "vlan_count": vlan_count,
    }


def vlan_interface_to_dict(vlan: VlanInterface, parent_missing: bool = False) -> dict:
    """Return vlan interface to dict."""
    role = normalize_interface_role(vlan.role)
    return {
        "id": vlan.id,
        "name": vlan.name,
        "parent_interface": vlan.parent_interface,
        "vlan_id": vlan.vlan_id,
        "ip_cidr": vlan.ip_cidr or "",
        "ipv6_cidr": vlan.ipv6_cidr or "",
        "mtu": vlan.mtu,
        "role": role,
        "enabled": False if parent_missing else vlan.enabled,
        "parent_missing": parent_missing,
    }


def trunk_parent_option(interface: PhysicalInterface) -> dict[str, str | int]:
    """Return trunk parent option."""
    label_parts = [interface.name, "trunk"]
    if interface.inventory_source == "host":
        label_parts.append("host NIC")
    if interface.mac_address:
        label_parts.append(interface.mac_address)
    return {
        "name": interface.name,
        "label": " - ".join(label_parts),
        "mtu": interface.mtu,
    }


def _read_text(path: Path) -> str:
    """Return text.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _interface_driver(sysfs_interface: Path) -> str | None:
    """Return interface driver."""
    driver_path = sysfs_interface / "device" / "driver"
    try:
        return driver_path.resolve().name
    except OSError:
        return None


def _interface_speed(sysfs_interface: Path) -> str | None:
    """Return interface speed."""
    speed = _read_text(sysfs_interface / "speed")
    if not speed or speed.startswith("-"):
        return None
    return f"{speed} Mbps"


def _host_ip_cidr(row: dict, family: str) -> str | None:
    """Return host ip cidr."""
    candidates = row.get("addr_info") or []
    for address in candidates:
        if address.get("family") != family:
            continue
        if address.get("scope") in {"host", "link"}:
            continue
        local = address.get("local")
        prefixlen = address.get("prefixlen")
        if local and prefixlen is not None:
            return f"{local}/{prefixlen}"
    return None


def parse_linux_ip_interfaces(payload: str, *, sysfs_base: Path = Path("/sys/class/net")) -> list[HostPhysicalInterface]:
    """Parse linux ip interfaces.

    Returns:
        The parsed linux ip interfaces.
    """
    try:
        rows = json.loads(payload)
    except json.JSONDecodeError:
        return []
    interfaces: list[HostPhysicalInterface] = []
    for row in rows:
        name = str(row.get("ifname") or "").strip()
        if not name or name == "lo" or "." in name:
            continue
        if row.get("link_type") != "ether":
            continue
        linkinfo = row.get("linkinfo") or {}
        if linkinfo.get("info_kind") == "vlan":
            continue
        mac_address = str(row.get("address") or "").strip().lower()
        if not mac_address or mac_address == "00:00:00:00:00:00":
            continue
        sysfs_interface = sysfs_base / name
        flags = {str(flag).upper() for flag in row.get("flags") or []}
        interfaces.append(
            HostPhysicalInterface(
                name=name,
                mac_address=mac_address,
                driver=_interface_driver(sysfs_interface),
                speed=_interface_speed(sysfs_interface),
                host_ip_cidr=_host_ip_cidr(row, "inet"),
                host_ipv6_cidr=_host_ip_cidr(row, "inet6"),
                host_mtu=int(row["mtu"]) if row.get("mtu") is not None else None,
                host_admin_state="up" if "UP" in flags else "down",
                oper_state=str(row.get("operstate") or "unknown").lower(),
            )
        )
    return interfaces


def discover_host_physical_interfaces() -> list[HostPhysicalInterface]:
    """Return discover host physical interfaces."""
    try:
        completed = subprocess.run(
            ["ip", "-j", "address", "show"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return []
    if completed.returncode != 0:
        return []
    return parse_linux_ip_interfaces(completed.stdout)


def _mac_key(value: str | None) -> str:
    """Return mac key."""
    return (value or "").strip().lower()


def _missing_interface_name(interface: PhysicalInterface, used_names: set[str]) -> str:
    """Return missing interface name."""
    mac = "".join(character for character in _mac_key(interface.mac_address) if character.isalnum())
    suffix = mac[-10:] or str(interface.id or interface.name or "nic")
    base = f"missing_{suffix}"[:50]
    candidate = base
    counter = 2
    while candidate in used_names:
        marker = f"_{counter}"
        candidate = f"{base[: 50 - len(marker)]}{marker}"
        counter += 1
    return candidate


def _replace_interface_tokens(value: str | None, renames: dict[str, str]) -> str:
    """Return replace interface tokens."""
    if not value:
        return value or ""
    tokens = [token.strip() for token in value.replace(",", "\n").splitlines() if token.strip()]
    if not tokens:
        return ""
    return "\n".join(renames.get(token, token) for token in tokens)


def _address_from_cidr(value: str | None) -> str:
    """Return address from cidr."""
    if not value:
        return ""
    try:
        return str(ip_interface(value.strip()).ip)
    except ValueError:
        return ""


def _cidr_validation_error(label: str, value: str | None, version: int) -> str | None:
    """Return cidr validation error."""
    if not value:
        return None
    family = "IPv4" if version == 4 else "IPv6"
    try:
        parsed = ip_interface(value.strip())
    except ValueError:
        return f"{label} {family} CIDR {value} is invalid."
    if parsed.version != version:
        return f"{label} {family} CIDR {value} must be an {family} address and prefix."
    return None


def _set_setting_value(db: Session, key: str, value: str) -> Setting:
    """Update setting value.

    Args:
        db: Active database session.
        key: Stable setting, vault, or mapping key.
        value: Value to process.

    Returns:
        The set setting value result.
    """
    setting = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
    if setting is None:
        setting = Setting(key=key, value=value)
        db.add(setting)
    else:
        setting.value = value
        setting.updated_at = utcnow()
    return setting


def _remove_interface_tokens(value: str | None, targets: set[str]) -> tuple[str, list[str]]:
    """Remove interface tokens.

    Returns:
        The remove interface tokens result.
    """
    if not value:
        return "", []
    kept: list[str] = []
    removed: list[str] = []
    seen: set[str] = set()
    for token in [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]:
        if token in targets:
            removed.append(token)
            continue
        if token not in seen:
            kept.append(token)
            seen.add(token)
    return "\n".join(kept), removed


def _disable_service_without_bind(settings: object, label: str, details: list[str]) -> None:
    """Handle disable service without bind."""
    if not bool(getattr(settings, "enabled", False)):
        return
    if _remove_interface_tokens(getattr(settings, "listen_interface", ""), set())[0]:
        return
    if _remove_interface_tokens(getattr(settings, "listen_address", ""), set())[0]:
        return
    setattr(settings, "enabled", False)
    details.append(f"disabled {label}: removed NIC was the only listen target")


def _cleanup_missing_interface_references(db: Session, missing_renames: dict[str, str]) -> list[str]:
    """Remove missing interface references.

    Args:
        db: Active database session.
        missing_renames: Missing renames supplied by the caller.

    Returns:
        The cleanup missing interface references result.
    """
    if not missing_renames:
        return []
    details: list[str] = []
    unavailable_targets = set(missing_renames) | set(missing_renames.values())
    target_replacements = dict(missing_renames)
    unavailable_addresses: set[str] = set()

    for interface in db.execute(select(PhysicalInterface)).scalars().all():
        if interface.oper_state == "missing":
            unavailable_targets.add(interface.name)
            for address in (
                _address_from_cidr(interface.ip_cidr),
                _address_from_cidr(interface.ipv6_cidr),
                _address_from_cidr(interface.host_ip_cidr),
                _address_from_cidr(interface.host_ipv6_cidr),
            ):
                if address:
                    unavailable_addresses.add(address)
            interface.role = "unused"
            interface.mode = "unused"
            interface.ip_cidr = None
            interface.ipv6_cidr = None
            interface.ipv6_gateway = None
            interface.admin_state = "down"

    for vlan in db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all():
        if vlan.parent_interface not in unavailable_targets:
            continue
        old_name = vlan.name
        old_parent = vlan.parent_interface
        new_parent = missing_renames.get(vlan.parent_interface, vlan.parent_interface)
        for address in (_address_from_cidr(vlan.ip_cidr), _address_from_cidr(vlan.ipv6_cidr)):
            if address:
                unavailable_addresses.add(address)
        vlan.parent_interface = new_parent
        vlan.name = f"{new_parent}.{vlan.vlan_id}"
        changed = vlan.enabled or vlan.parent_interface != old_parent or vlan.name != old_name
        vlan.enabled = False
        target_replacements[old_name] = vlan.name
        unavailable_targets.update({old_name, vlan.name})
        if changed:
            details.append(f"disabled VLAN {old_name}: parent {old_parent} is missing")

    for route in db.execute(select(Route)).scalars().all():
        if route.interface_name in unavailable_targets:
            old_interface = route.interface_name
            route.interface_name = target_replacements.get(route.interface_name, "")
            if route.enabled:
                route.enabled = False
                details.append(f"disabled route {route.destination_cidr}: interface {old_interface} is missing")

    for rule in db.execute(select(NatRule)).scalars().all():
        if rule.outbound_interface in unavailable_targets:
            old_interface = rule.outbound_interface
            rule.outbound_interface = ""
            if rule.enabled:
                rule.enabled = False
                details.append(f"disabled NAT rule {rule.name}: outbound interface {old_interface} is missing")

    for rule in db.execute(select(RoutingRule)).scalars().all():
        removed_bindings = []
        if rule.source_interface in unavailable_targets:
            removed_bindings.append(f"source {rule.source_interface}")
            rule.source_interface = target_replacements.get(rule.source_interface, "")
        if rule.destination_interface in unavailable_targets:
            removed_bindings.append(f"destination {rule.destination_interface}")
            rule.destination_interface = target_replacements.get(rule.destination_interface, "")
        if removed_bindings and rule.enabled:
            rule.enabled = False
            details.append(f"disabled routing rule {rule.name}: {' and '.join(removed_bindings)} is missing")

    for rule in db.execute(select(FirewallRule)).scalars().all():
        if rule.interface_name in unavailable_targets:
            old_interface = rule.interface_name
            rule.interface_name = ""
            if rule.enabled:
                rule.enabled = False
                details.append(f"disabled firewall rule {rule.name}: interface {old_interface} is missing")

    for settings in db.execute(select(DhcpSettings)).scalars().all():
        if settings.interface_name in unavailable_targets:
            settings.interface_name = ""
            if settings.enabled:
                settings.enabled = False
                details.append("disabled DHCP: removed NIC was the legacy bind interface")

    dhcp_scopes = db.execute(select(DhcpScope)).scalars().all()
    for scope in dhcp_scopes:
        if scope.interface_name in unavailable_targets:
            old_interface = scope.interface_name
            scope.interface_name = ""
            if scope.enabled:
                scope.enabled = False
                details.append(f"disabled DHCP IP zone {scope.name}: interface {old_interface} is missing")

    for settings in db.execute(select(DhcpSettings)).scalars().all():
        if settings.enabled and not any(scope.enabled is not False for scope in dhcp_scopes):
            settings.enabled = False
            details.append("disabled DHCP: removed NIC left no enabled DHCP IP zones")

    service_targets = [
        (DnsSettings, "DNS"),
        (CaSettings, "Certificate Authority"),
        (KmsSettings, "KMS / KMIP"),
        (VcfBackupSettings, "VCF Backups"),
        (VcfPrivateRegistrySettings, "VCF Private Registry"),
        (VcfOfflineDepotSettings, "VCF Offline Depot"),
    ]
    for model, label in service_targets:
        for settings in db.execute(select(model)).scalars().all():
            updated_interfaces, removed_interfaces = _remove_interface_tokens(settings.listen_interface, unavailable_targets)
            updated_addresses, removed_addresses = _remove_interface_tokens(
                getattr(settings, "listen_address", ""),
                unavailable_addresses,
            )
            if not removed_interfaces and not removed_addresses:
                continue
            settings.listen_interface = updated_interfaces
            if hasattr(settings, "listen_address"):
                settings.listen_address = updated_addresses
            if removed_interfaces:
                details.append(f"removed {', '.join(removed_interfaces)} from {label} listen interfaces")
            if removed_addresses:
                details.append(f"removed {', '.join(removed_addresses)} from {label} listen addresses")
            _disable_service_without_bind(settings, label, details)

    esxi_listen_interface = db.execute(select(Setting).where(Setting.key == "esxi_pxe.boot.listen_interface")).scalar_one_or_none()
    if esxi_listen_interface is not None:
        updated, removed = _remove_interface_tokens(esxi_listen_interface.value, unavailable_targets)
        if removed:
            esxi_listen_interface.value = updated
            details.append(f"removed {', '.join(removed)} from ESXi PXE listen interfaces")
            if not updated:
                for key in ("esxi_pxe.boot.enabled", "esxi_pxe.boot.native_uefi_http_enabled"):
                    _set_setting_value(db, key, "false")
                details.append("disabled ESXi PXE boot services: removed NIC was the only listen interface")
    esxi_listen_address = db.execute(select(Setting).where(Setting.key == "esxi_pxe.boot.listen_address")).scalar_one_or_none()
    if esxi_listen_address is not None:
        updated, removed = _remove_interface_tokens(esxi_listen_address.value, unavailable_addresses)
        if removed:
            esxi_listen_address.value = updated
            details.append(f"removed {', '.join(removed)} from ESXi PXE listen addresses")
            if not updated:
                for key in ("esxi_pxe.boot.enabled", "esxi_pxe.boot.native_uefi_http_enabled"):
                    _set_setting_value(db, key, "false")
                details.append("disabled ESXi PXE boot services: removed NIC was the only listen address")

    if details:
        message = "Missing physical interface cleanup: " + "; ".join(details)
        LOGGER.warning(message)
        _set_setting_value(db, NETWORK_INVENTORY_CLEANUP_WARNING_KEY, message)
        db.add(
            AuditEvent(
                actor="system",
                action="cleanup_missing_physical_interface_bindings",
                resource_type="network",
                detail=message,
            )
        )
    return details


def _retarget_interface_references(db: Session, renames: dict[str, str]) -> None:
    """Handle retarget interface references.

    Args:
        db: Active database session.
        renames: Renames supplied by the caller.
    """
    if not renames:
        return
    expanded_renames = dict(renames)
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    for vlan in vlans:
        new_parent = renames.get(vlan.parent_interface)
        if not new_parent:
            continue
        old_name = vlan.name
        vlan.parent_interface = new_parent
        vlan.name = f"{new_parent}.{vlan.vlan_id}"
        expanded_renames[old_name] = vlan.name

    scalar_targets = [
        (Route, "interface_name"),
        (NatRule, "outbound_interface"),
        (RoutingRule, "source_interface"),
        (RoutingRule, "destination_interface"),
        (FirewallRule, "interface_name"),
        (DhcpSettings, "interface_name"),
        (DhcpScope, "interface_name"),
    ]
    for model, field_name in scalar_targets:
        for row in db.execute(select(model)).scalars().all():
            current = getattr(row, field_name)
            if current in expanded_renames:
                setattr(row, field_name, expanded_renames[current])

    list_targets = [
        (DnsSettings, "listen_interface"),
        (CaSettings, "listen_interface"),
        (KmsSettings, "listen_interface"),
        (VcfBackupSettings, "listen_interface"),
        (VcfPrivateRegistrySettings, "listen_interface"),
        (VcfOfflineDepotSettings, "listen_interface"),
    ]
    for model, field_name in list_targets:
        for row in db.execute(select(model)).scalars().all():
            updated = _replace_interface_tokens(getattr(row, field_name), expanded_renames)
            if updated != getattr(row, field_name):
                setattr(row, field_name, updated)

    esxi_listen_interface = db.execute(select(Setting).where(Setting.key == "esxi_pxe.boot.listen_interface")).scalar_one_or_none()
    if esxi_listen_interface is not None:
        esxi_listen_interface.value = _replace_interface_tokens(esxi_listen_interface.value, expanded_renames)


def _rename_interface(
    interface: PhysicalInterface,
    new_name: str,
    *,
    by_name: dict[str, PhysicalInterface],
    used_names: set[str],
    renames: dict[str, str],
) -> None:
    """Handle rename interface.

    Args:
        interface: Interface supplied by the caller.
        new_name: New name supplied by the caller.
        by_name: By name supplied by the caller.
        used_names: Used names supplied by the caller.
        renames: Renames supplied by the caller.
    """
    old_name = interface.name
    if old_name == new_name:
        return
    by_name.pop(old_name, None)
    used_names.discard(old_name)
    interface.name = new_name
    by_name[new_name] = interface
    used_names.add(new_name)
    renames[old_name] = new_name


def _physical_interface_name_changes(interfaces: list[PhysicalInterface]) -> list[tuple[PhysicalInterface, str, str]]:
    """Return physical interface name changes."""
    changes: list[tuple[PhysicalInterface, str, str]] = []
    for interface in interfaces:
        state = inspect(interface)
        if not state.persistent:
            continue
        history = state.attrs.name.history
        if not history.has_changes() or not history.deleted:
            continue
        old_name = str(history.deleted[0])
        new_name = str(interface.name)
        if old_name != new_name:
            changes.append((interface, old_name, new_name))
    return changes


def _flush_physical_interface_name_changes(db: Session, changes: list[tuple[PhysicalInterface, str, str]]) -> None:
    """Handle flush physical interface name changes.

    Args:
        db: Active database session.
        changes: Changes supplied by the caller.
    """
    if not changes:
        return
    used_names = {new_name for _interface, _old_name, new_name in changes}
    staged: list[tuple[PhysicalInterface, str]] = []
    for index, (interface, _old_name, final_name) in enumerate(changes, start=1):
        temp_name = f"__renaming_{interface.id}_{index}"
        while temp_name in used_names:
            temp_name = f"{temp_name}_"
        interface.name = temp_name
        used_names.add(temp_name)
        staged.append((interface, final_name))
    db.flush()
    for interface, final_name in staged:
        interface.name = final_name


def reconcile_host_physical_interfaces(
    interfaces: list[PhysicalInterface],
    discovered: list[HostPhysicalInterface],
    *,
    renames: dict[str, str] | None = None,
) -> list[PhysicalInterface]:
    """Return reconcile host physical interfaces."""
    now = utcnow()
    by_name = {interface.name: interface for interface in interfaces}
    mac_counts: dict[str, int] = {}
    for interface in interfaces:
        mac = _mac_key(interface.mac_address)
        if mac:
            mac_counts[mac] = mac_counts.get(mac, 0) + 1
    by_mac = {
        _mac_key(interface.mac_address): interface
        for interface in interfaces
        if _mac_key(interface.mac_address) and mac_counts.get(_mac_key(interface.mac_address)) == 1
    }
    used_names = set(by_name)
    name_changes: dict[str, str] = {}
    seen_interface_ids: set[int] = set()
    for host in discovered:
        host_mac = _mac_key(host.mac_address)
        interface = by_mac.get(host_mac)
        name_match = by_name.get(host.name)
        if interface is not None and name_match is not None and name_match is not interface:
            replacement_name = _missing_interface_name(name_match, used_names)
            _rename_interface(
                name_match,
                replacement_name,
                by_name=by_name,
                used_names=used_names,
                renames=name_changes,
            )
        if interface is not None and interface.name != host.name:
            _rename_interface(interface, host.name, by_name=by_name, used_names=used_names, renames=name_changes)
        if interface is None:
            interface = by_name.get(host.name)
            if interface is not None and interface.desired_state_source != "seed" and _mac_key(interface.mac_address) != host_mac:
                replacement_name = _missing_interface_name(interface, used_names)
                _rename_interface(
                    interface,
                    replacement_name,
                    by_name=by_name,
                    used_names=used_names,
                    renames=name_changes,
                )
                interface = None
        seed_desired = interface is None or interface.desired_state_source == "seed"
        if interface is None:
            interface = PhysicalInterface(
                name=host.name,
                mac_address=host_mac,
                role="unused",
                mode="access",
                desired_state_source="seed",
            )
            interfaces.append(interface)
            by_name[host.name] = interface
            used_names.add(host.name)
        interface.mac_address = host_mac
        by_mac[host_mac] = interface
        interface.driver = host.driver
        interface.speed = host.speed
        interface.host_ip_cidr = host.host_ip_cidr
        interface.host_ipv6_cidr = host.host_ipv6_cidr
        interface.host_mtu = host.host_mtu
        interface.host_admin_state = host.host_admin_state
        interface.oper_state = host.oper_state
        interface.inventory_source = "host"
        interface.last_seen_at = now
        interface.missing_since = None
        seen_interface_ids.add(id(interface))
        if seed_desired:
            interface.ip_cidr = (
                host.host_ip_cidr
                if (interface.name == "eth0" or interface.role == "management") and normalize_ipv4_method(interface.ipv4_method) != "dhcp"
                else None
            )
            if interface.name != "eth0" and interface.role != "management":
                interface.ipv6_enabled = False
                interface.ipv6_cidr = None
                interface.ipv6_gateway = None
            interface.mtu = host.host_mtu or interface.mtu
            interface.admin_state = host.host_admin_state if interface.name == "eth0" or interface.role == "management" else "down"
    for interface in interfaces:
        if interface.inventory_source == "host" and id(interface) not in seen_interface_ids:
            if interface.missing_since is None:
                interface.missing_since = now
            interface.oper_state = "missing"
            if not interface.name.startswith("missing_"):
                replacement_name = _missing_interface_name(interface, used_names)
                _rename_interface(
                    interface,
                    replacement_name,
                    by_name=by_name,
                    used_names=used_names,
                    renames=name_changes,
                )
    if renames is not None:
        renames.update(name_changes)
    return interfaces


def sync_host_physical_interfaces(db: Session) -> tuple[list[PhysicalInterface], int]:
    """Return sync host physical interfaces.

    Args:
        db: Active database session.
    """
    discovered = discover_host_physical_interfaces()
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    renames: dict[str, str] = {}
    reconciled = reconcile_host_physical_interfaces(interfaces, discovered, renames=renames)
    name_changes = _physical_interface_name_changes(reconciled)
    final_renames = {old: new for _interface, old, new in name_changes}
    missing_renames = {old: new for old, new in final_renames.items() if new.startswith("missing_")}
    for interface in reconciled:
        if interface.oper_state == "missing":
            missing_renames.setdefault(interface.name, interface.name)
    _cleanup_missing_interface_references(db, missing_renames)
    live_renames = {old: new for old, new in final_renames.items() if old not in missing_renames and new not in set(missing_renames.values())}
    _retarget_interface_references(db, live_renames)
    if discovered:
        discovered_names = {interface.name for interface in discovered}
        seed_only_missing = [
            interface
            for interface in reconciled
            if interface.name not in discovered_names
            and interface.inventory_source == "seed"
            and interface.desired_state_source == "seed"
        ]
        if seed_only_missing:
            removed_names = {interface.name for interface in seed_only_missing}
            dependent_vlans = db.execute(select(VlanInterface).where(VlanInterface.parent_interface.in_(removed_names))).scalars().all()
            removed_targets = removed_names | {vlan.name for vlan in dependent_vlans}
            dependent_routes = db.execute(select(Route).where(Route.interface_name.in_(removed_targets))).scalars().all()
            for route in dependent_routes:
                db.delete(route)
            for vlan in dependent_vlans:
                db.delete(vlan)
            for interface in seed_only_missing:
                db.delete(interface)
            reconciled = [interface for interface in reconciled if interface.name not in removed_names]
    for interface in reconciled:
        db.add(interface)
    _flush_physical_interface_name_changes(db, name_changes)
    db.commit()
    return db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all(), len(discovered)


def render_network_config(
    *,
    interfaces: list[PhysicalInterface],
    vlans: list[VlanInterface],
) -> str:
    """Render network config.

    Returns:
        The rendered network config.
    """
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "# Dry-run preview of desired Linux network state.",
        "# Static management gateways install in the main table and management policy table 100.",
        "",
        "[physical_interfaces]",
    ]
    for interface in interfaces:
        if interface.oper_state == "missing":
            continue
        mode = normalize_interface_mode(interface.mode)
        role = normalize_interface_role(interface.role)
        lines.extend(
            [
                f"interface={interface.name}",
                f"  role={role}",
                f"  mode={mode}",
                f"  ipv4_method={normalize_ipv4_method(interface.ipv4_method)}",
                f"  ip_cidr={interface.ip_cidr or ''}",
                f"  gateway={interface.gateway or ''}",
                f"  ipv6_enabled={'true' if interface.ipv6_enabled else 'false'}",
                f"  ipv6_cidr={interface.ipv6_cidr or ''}",
                f"  ipv6_gateway={interface.ipv6_gateway or ''}",
                f"  admin_state={interface.admin_state}",
                f"  mtu={interface.mtu}",
            ]
        )
    lines.extend(["", "[vlan_interfaces]"])
    for vlan in vlans:
        if not vlan.enabled:
            continue
        role = normalize_interface_role(vlan.role)
        lines.extend(
            [
                f"vlan={vlan.name}",
                f"  parent={vlan.parent_interface}",
                f"  vlan_id={vlan.vlan_id}",
                f"  ip_cidr={vlan.ip_cidr or ''}",
                f"  ipv6_cidr={vlan.ipv6_cidr or ''}",
                f"  mtu={vlan.mtu}",
                f"  role={role}",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def validate_network_state(
    *,
    interfaces: list[PhysicalInterface],
    vlans: list[VlanInterface],
) -> list[str]:
    """Validate network state.

    Returns:
        The validate network state result.
    """
    errors: list[str] = []
    interface_names = {interface.name for interface in interfaces}
    management_interfaces = [interface for interface in interfaces if interface.oper_state != "missing" and normalize_interface_role(interface.role) == "management"]
    if len(management_interfaces) != 1:
        errors.append("Network desired state must include exactly one management physical interface.")
    elif management_interfaces[0].name != "eth0":
        errors.append("Network desired state must keep eth0 as the management physical interface.")
    for interface in interfaces:
        if interface.oper_state == "missing":
            continue
        role = normalize_interface_role(interface.role)
        ipv4_method = normalize_ipv4_method(interface.ipv4_method)
        if role not in INTERFACE_ROLES:
            errors.append(f"Interface {interface.name} role {interface.role} is not supported.")
        if ipv4_method not in IPV4_METHODS:
            errors.append(f"Interface {interface.name} IPv4 method {interface.ipv4_method} is not supported.")
        if ipv4_method == "dhcp" and role != "management":
            errors.append(f"Interface {interface.name} can use DHCP only when its role is management.")
        if ipv4_method == "dhcp" and interface.ip_cidr:
            errors.append(f"Interface {interface.name} cannot set an IPv4 CIDR while IPv4 method is DHCP.")
        if interface.gateway:
            if role != "management":
                errors.append(f"Interface {interface.name} can set an IPv4 gateway only when its role is management.")
            elif ipv4_method != "static" or not interface.ip_cidr:
                errors.append(f"Interface {interface.name} can set an IPv4 gateway only with static management IPv4.")
            else:
                try:
                    gateway = ip_address(interface.gateway)
                    address = ip_interface(interface.ip_cidr)
                except ValueError:
                    errors.append(f"Interface {interface.name} IPv4 gateway {interface.gateway} is invalid.")
                else:
                    if gateway.version != 4:
                        errors.append(f"Interface {interface.name} IPv4 gateway {interface.gateway} uses the wrong IP family.")
                    elif gateway not in address.network:
                        errors.append(
                            f"Interface {interface.name} IPv4 gateway {interface.gateway} is not on-link for {interface.ip_cidr}."
                        )
                    elif gateway == address.ip:
                        errors.append(f"Interface {interface.name} IPv4 gateway cannot equal its interface address.")
        if not interface.ipv6_enabled and interface.ipv6_cidr:
            errors.append(f"Interface {interface.name} cannot set an IPv6 CIDR while IPv6 is disabled.")
        if not interface.ipv6_enabled and interface.ipv6_gateway:
            errors.append(f"Interface {interface.name} cannot set an IPv6 gateway while IPv6 is disabled.")
        if interface.ipv6_gateway:
            if role != "management":
                errors.append(f"Interface {interface.name} can set an IPv6 gateway only when its role is management.")
            elif not interface.ipv6_enabled or not interface.ipv6_cidr:
                errors.append(f"Interface {interface.name} can set an IPv6 gateway only with static management IPv6.")
            else:
                try:
                    gateway = ip_address(interface.ipv6_gateway)
                    address = ip_interface(interface.ipv6_cidr)
                except ValueError:
                    errors.append(f"Interface {interface.name} IPv6 gateway {interface.ipv6_gateway} is invalid.")
                else:
                    if gateway.version != 6:
                        errors.append(f"Interface {interface.name} IPv6 gateway {interface.ipv6_gateway} uses the wrong IP family.")
                    elif not gateway.is_link_local and gateway not in address.network:
                        errors.append(
                            f"Interface {interface.name} IPv6 gateway {interface.ipv6_gateway} is not link-local or on-link for {interface.ipv6_cidr}."
                        )
                    elif gateway == address.ip:
                        errors.append(f"Interface {interface.name} IPv6 gateway cannot equal its interface address.")
        if role == "management" and ipv4_method == "static" and not interface.ip_cidr:
            errors.append(f"Interface {interface.name} must set an IPv4 CIDR when IPv4 method is static.")
        mode = normalize_interface_mode(interface.mode)
        if mode not in INTERFACE_MODES:
            errors.append(f"Interface {interface.name} link type {interface.mode} is not supported.")
        if interface.mtu < 576 or interface.mtu > 9000:
            errors.append(f"Interface {interface.name} MTU must be between 576 and 9000.")
        if interface.admin_state not in {"up", "down"}:
            errors.append(f"Interface {interface.name} admin state must be up or down.")
        if error := _cidr_validation_error(f"Interface {interface.name}", interface.ip_cidr, 4):
            errors.append(error)
        if error := _cidr_validation_error(f"Interface {interface.name}", interface.ipv6_cidr, 6):
            errors.append(error)
    interface_modes = {interface.name: normalize_interface_mode(interface.mode) for interface in interfaces}
    for vlan in vlans:
        if vlan.enabled is False:
            continue
        if vlan.parent_interface not in interface_names:
            errors.append(f"VLAN {vlan.name} parent interface {vlan.parent_interface} does not exist.")
        else:
            parent = next(interface for interface in interfaces if interface.name == vlan.parent_interface)
            if parent.inventory_source == "host" and parent.oper_state == "missing":
                errors.append(f"VLAN {vlan.name} parent interface {vlan.parent_interface} is missing from host inventory.")
        if vlan.parent_interface in interface_names and interface_modes.get(vlan.parent_interface) != "trunk":
            errors.append(
                f"VLAN {vlan.name} parent {vlan.parent_interface} has {interface_modes.get(vlan.parent_interface)} link type. "
                "Tagged VLAN interfaces require a trunk parent; use physical interface CIDRs for access-mode networks."
            )
        if vlan.vlan_id < 1 or vlan.vlan_id > 4094:
            errors.append(f"VLAN {vlan.name} ID must be between 1 and 4094.")
        if vlan.mtu < 576 or vlan.mtu > 9000:
            errors.append(f"VLAN {vlan.name} MTU must be between 576 and 9000.")
        role = normalize_interface_role(vlan.role)
        if role not in VLAN_ROLES:
            errors.append(f"VLAN {vlan.name} role {vlan.role} is not supported.")
        if not vlan.ip_cidr and not vlan.ipv6_cidr:
            errors.append(f"VLAN {vlan.name} must include IPv4 CIDR, IPv6 CIDR, or both.")
        if error := _cidr_validation_error(f"VLAN {vlan.name}", vlan.ip_cidr, 4):
            errors.append(error)
        if error := _cidr_validation_error(f"VLAN {vlan.name}", vlan.ipv6_cidr, 6):
            errors.append(error)
    return errors
