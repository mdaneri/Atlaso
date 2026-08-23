"""Resolve applied and desired management browser bindings."""

from __future__ import annotations

import json
from ipaddress import ip_interface

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import PhysicalInterface, Setting, VlanInterface
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
)

APPLIANCE_APPLY_BASELINES_KEY = "appliance_apply.baselines.v1"
MANAGEMENT_LISTENER_REQUIRED_DETAIL = (
    "At least one complete management listener must remain. Keep a management-role interface, "
    "or configure an enabled access-role interface or VLAN with Management UI exposure and a "
    "usable address before removing the final listener."
)


def _address_from_cidr(value: str | None) -> str:
    """Return a normalized host address from an optional CIDR.

    Args:
        value: Optional interface address in CIDR notation.
    """
    if not value:
        return ""
    try:
        return str(ip_interface(value).ip).lower()
    except ValueError:
        return ""


def _network_rows(config_preview: str) -> list[dict[str, str]]:
    """Parse physical and VLAN rows from a rendered Network preview.

    Args:
        config_preview: Rendered Network configuration snapshot.
    """
    rows: list[dict[str, str]] = []
    section = ""
    current: dict[str, str] | None = None
    for raw_line in (config_preview or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]")
            current = None
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if section == "physical_interfaces" and key == "interface":
            current = {"kind": "physical", "name": value}
            rows.append(current)
        elif section == "vlan_interfaces" and key == "vlan":
            current = {"kind": "vlan", "name": value}
            rows.append(current)
        elif current is not None and section in {"physical_interfaces", "vlan_interfaces"}:
            current[key] = value
    return rows


def _network_baseline(db: Session) -> dict[str, object] | None:
    """Return the last-applied Network baseline, or ``None`` when none is usable.

    Args:
        db: Active database session used to load the baseline setting.
    """
    setting = db.execute(
        select(Setting).where(Setting.key == APPLIANCE_APPLY_BASELINES_KEY)
    ).scalar_one_or_none()
    if setting is None or not setting.value:
        return None
    try:
        payload = json.loads(setting.value)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    network = payload.get("network")
    if not isinstance(network, dict) or not isinstance(network.get("config_preview"), str):
        return None
    return network


def applied_management_bindings(db: Session) -> list[dict[str, str]] | None:
    """Return address-specific management bindings from the last-applied Network state.

    ``None`` means no usable baseline exists and lets development or upgrade compatibility callers
    retain the legacy desired-state fallback. An empty list is authoritative when an applied baseline
    exists but contains no management listener.

    Args:
        db: Active database session used to load applied and observed network state.
    """
    baseline = _network_baseline(db)
    if baseline is None:
        return None
    rows = _network_rows(str(baseline["config_preview"]))
    raw_aliases = baseline.get("physical_interface_aliases")
    aliases = (
        {str(old_name): str(new_name) for old_name, new_name in raw_aliases.items()}
        if isinstance(raw_aliases, dict)
        else {}
    )
    current_physical = {
        interface.name: interface
        for interface in db.execute(select(PhysicalInterface)).scalars().all()
    }
    bindings: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        dedicated = row.get("kind") == "physical" and row.get("role") == "management"
        flagged_physical = (
            row.get("kind") == "physical"
            and row.get("role") == "access"
            and row.get("mode") == "access"
            and row.get("admin_state") == "up"
            and row.get("access_management_ui_enabled", "false").lower() == "true"
        )
        flagged_vlan = (
            row.get("kind") == "vlan"
            and row.get("role") == "access"
            and row.get("access_management_ui_enabled", "false").lower() == "true"
        )
        if not (dedicated or flagged_physical or flagged_vlan):
            continue
        cidrs = [row.get("ip_cidr"), row.get("ipv6_cidr")]
        if row.get("kind") == "physical":
            applied_name = row.get("name", "")
            current_name = aliases.get(applied_name, applied_name)
            observed = current_physical.get(current_name)
            if observed is not None and observed.oper_state != "missing":
                cidrs.extend((observed.host_ip_cidr, observed.host_ipv6_cidr))
        for cidr in cidrs:
            address = _address_from_cidr(cidr)
            if not address or address in seen:
                continue
            seen.add(address)
            bindings.append(
                {
                    "interface": current_name if row.get("kind") == "physical" else row.get("name", ""),
                    "role": row.get("role", ""),
                    "address": address,
                    "management_ui": "true",
                }
            )
    return bindings


def _has_usable_address(*values: str | None) -> bool:
    """Return whether any CIDR contains a usable non-loopback, non-link-local address.

    Args:
        *values: Desired or observed address values in CIDR notation.
    """
    for value in values:
        if not value:
            continue
        try:
            address = ip_interface(value).ip
        except ValueError:
            continue
        if not (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            return True
    return False


def desired_management_candidate_exists(db: Session) -> bool:
    """Return whether desired state contains a complete management listener candidate.

    Args:
        db: Active transaction containing the proposed desired-state mutation.
    """
    physical_interfaces = db.execute(select(PhysicalInterface)).scalars().all()
    physical_by_name = {interface.name: interface for interface in physical_interfaces}
    for interface in physical_interfaces:
        if interface.oper_state == "missing" or interface.admin_state != "up":
            continue
        role = normalize_interface_role(interface.role)
        mode = normalize_interface_mode(interface.mode)
        if role == "management" and mode == "access":
            ipv4_candidate = interface.ipv4_method == "dhcp" or _has_usable_address(
                interface.ip_cidr
            )
            # Network validation requires every static management interface to configure IPv4;
            # IPv6 availability cannot substitute for that Apply prerequisite.
            if ipv4_candidate:
                return True
        if (
            role == "access"
            and mode == "access"
            and interface.access_management_ui_enabled
            and _has_usable_address(
                interface.ip_cidr,
                interface.ipv6_cidr,
            )
        ):
            return True
    for vlan in db.execute(select(VlanInterface).where(VlanInterface.enabled.is_(True))).scalars().all():
        parent = physical_by_name.get(vlan.parent_interface)
        if (
            normalize_interface_role(vlan.role) == "access"
            and vlan.access_management_ui_enabled
            and parent is not None
            and parent.oper_state != "missing"
            and parent.admin_state == "up"
            and normalize_interface_mode(parent.mode) == "trunk"
            and _has_usable_address(vlan.ip_cidr, vlan.ipv6_cidr)
        ):
            return True
    return False
