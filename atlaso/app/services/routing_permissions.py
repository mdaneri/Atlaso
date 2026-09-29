"""Canonical directed routing authorization and desired/applied projections."""

from __future__ import annotations

import hashlib
import json
import re
from ipaddress import ip_interface, ip_network
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import PhysicalInterface, RoutingRule, Setting, VlanInterface
from atlaso.app.services.firewall import (
    managed_routing_firewall_rules,
    routing_firewall_targets,
)
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
    normalize_ipv4_method,
)
from atlaso.app.services.routes_wan import (
    ensure_routes_wan_settings,
    generated_route_role_rules,
    nat_eligible_target_names,
)

ROUTING_POLICIES = {"automatic", "allow", "deny"}
_LINE_SEPARATORS = re.compile(r"[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]")


def routing_permission_name_conflicts(db: Session, name: str, *, exclude_rule_id: int | None = None) -> bool:
    """Match the case-insensitive name rule used when validating WAN state."""
    normalized_name = name.strip().lower()
    return any(
        rule.id != exclude_rule_id and rule.name.strip().lower() == normalized_name
        for rule in db.scalars(select(RoutingRule))
    )


def routing_policy(rule: RoutingRule) -> str:
    """Read legacy defaults without interpreting an invalid policy as an allow.

    Args:
        rule: Persisted or newly constructed permission.
    """
    return rule.policy if rule.policy is not None else "allow"


def routing_family(rule: RoutingRule) -> int:
    """Read the legacy dual-stack default.

    Args:
        rule: Persisted or newly constructed permission.
    """
    return rule.ip_family if rule.ip_family is not None else 0


def _configured_address(cidr: str | None) -> str:
    """Keep incomplete topology visible to validation without a projection crash.

    Args:
        cidr: Saved interface address and prefix.
    """
    try:
        return str(ip_interface(cidr).ip) if cidr else ""
    except ValueError:
        return ""


def target_networks(target: dict[str, Any], family: int = 0) -> list[str]:
    """Canonicalize configured prefixes for one traffic boundary.

    Args:
        target: Interface/VLAN topology row.
        family: Zero for both address families.
    """
    networks: list[str] = []
    for value in (target.get("ip_cidr"), target.get("ipv6_cidr")):
        if value:
            try:
                network = ip_network(value, strict=False)
            except ValueError:
                continue
            if not family or network.version == family:
                networks.append(str(network))
    return networks


def validate_routing_permission(rule: RoutingRule, targets: list[dict[str, Any]], *, db: Session | None = None) -> list[str]:
    """Reject malformed scope and management conflicts even while Routing is off.

    Args:
        rule: Complete proposed desired-state permission.
        targets: Current configured interface/VLAN topology.
        db: Optional persisted inventory protecting unavailable management targets during writes.
    """
    errors: list[str] = []
    policy = routing_policy(rule)
    family = routing_family(rule)
    if policy not in ROUTING_POLICIES:
        errors.append("Routing permission policy must be automatic, allow, or deny.")
    if isinstance(family, bool) or family not in {0, 4, 6}:
        errors.append("Routing permission IP family must be 0 (both), 4, or 6.")
    if not rule.name or not rule.name.strip() or len(rule.name) > 120:
        errors.append("Routing permission needs a name of at most 120 characters.")
    elif _LINE_SEPARATORS.search(rule.name):
        errors.append("Routing permission name must not contain line breaks.")
    if rule.priority is not None and rule.priority < 0:
        errors.append("Routing permission priority cannot be negative.")
    by_name = {target["name"]: target for target in targets}
    protected_names: set[str] = set()
    if db is not None:
        protected_names.update(db.scalars(select(PhysicalInterface.name).where(PhysicalInterface.role == "management")))
        protected_names.update(db.scalars(select(VlanInterface.name).where(VlanInterface.role == "management")))
    for label, name in (("source", rule.source_interface), ("destination", rule.destination_interface)):
        if not name or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", name):
            errors.append(f"Routing permission {label} must use a canonical interface name of at most 80 characters.")
        target = by_name.get(name)
        if name in protected_names or (target and (target.get("role") == "management" or target.get("routing_domain") == "management")):
            errors.append(f"Routing permission {label} must be a non-management Access or Route interface/VLAN; protected management rules cannot be overridden.")
        elif rule.enabled is not False and (target is None or target.get("role") not in {"route", "access"}):
            errors.append(f"Routing permission {label} must be a non-management Access or Route interface/VLAN.")
        elif rule.enabled is not False and family in {0, 4, 6} and target and not target_networks(target, family):
            errors.append(f"Routing permission {label} has no configured prefix for the selected IP family.")
    if rule.source_interface == rule.destination_interface:
        errors.append("Routing permission source and destination must be different.")
    source, destination = by_name.get(rule.source_interface), by_name.get(rule.destination_interface)
    if rule.enabled is not False and source and destination and family in {0, 4, 6}:
        common = {ip_network(n).version for n in target_networks(source, family)} & {ip_network(n).version for n in target_networks(destination, family)}
        if not common:
            errors.append("Routing permission targets need a common configured address family.")
    return errors


def routing_permission_rows(targets: list[dict[str, Any]], rules: list[RoutingRule], routing_enabled: bool = True) -> list[dict[str, Any]]:
    """Project explicit precedence for each directed pair and address family.

    Args:
        targets: Configured topology, including protected management targets.
        rules: Saved explicit operator permissions.
        routing_enabled: Global desired-state routing switch.
    """
    by_name = {target["name"]: target for target in targets}
    rows: list[dict[str, Any]] = []
    active_policies: dict[tuple[str, str, int], set[str]] = {}
    for rule in rules:
        if not rule.enabled or validate_routing_permission(rule, targets):
            continue
        for version in (4, 6) if routing_family(rule) == 0 else (routing_family(rule),):
            active_policies.setdefault((rule.source_interface, rule.destination_interface, version), set()).add(routing_policy(rule))
    candidates = [dict(row, policy="automatic", ip_family=0) for row in generated_route_role_rules(targets)]
    for rule in rules:
        candidates.append({"id": rule.id, "name": rule.name, "enabled": rule.enabled,
                           "source_interface": rule.source_interface, "destination_interface": rule.destination_interface,
                           "priority": rule.priority, "description": rule.description or "", "generated": False,
                           "policy": routing_policy(rule), "ip_family": routing_family(rule)})
    for row in candidates:
        source, destination = by_name.get(row["source_interface"], {}), by_name.get(row["destination_interface"], {})
        family = row["ip_family"]
        row["source_networks"] = target_networks(source, family)
        row["destination_networks"] = target_networks(destination, family)
        common = {ip_network(n).version for n in row["source_networks"]} & {ip_network(n).version for n in row["destination_networks"]}
        actions: dict[str, str] = {}
        for version in sorted(common):
            policies = active_policies.get((row["source_interface"], row["destination_interface"], version), set())
            action = "explicit deny" if "deny" in policies else "explicit allow" if "allow" in policies else "automatic allow" if source.get("role") == destination.get("role") == "route" else "automatic deny"
            actions[str(version)] = action
        valid_scope = source.get("role") in {"route", "access"} and destination.get("role") in {"route", "access"} and row["source_interface"] != row["destination_interface"] and family in {0, 4, 6} and row["policy"] in ROUTING_POLICIES
        row["effective_action"] = ("suspended" if not routing_enabled or not row["enabled"] else
                                   "conflict" if not common or not valid_scope else
                                   next(iter(actions.values())) if len(set(actions.values())) == 1 else
                                   "; ".join(f"IPv{version}: {action}" for version, action in actions.items()))
        row["family_effective_actions"] = actions
        row["address_family"] = " / ".join(f"IPv{version}" for version in sorted(common)) or "Unavailable"
        row["apply_state"] = "pending"
        rows.append(row)
    return rows


def routing_permission_fingerprint(db: Session) -> str:
    """Bind applied authorization to every generated forwarding boundary.

    Args:
        db: Desired-state database session.
    """
    rules = list(db.scalars(select(RoutingRule).order_by(RoutingRule.id)))
    interfaces = list(db.scalars(select(PhysicalInterface).order_by(PhysicalInterface.name)))
    vlans = list(db.scalars(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)))
    routing_enabled = ensure_routes_wan_settings(db).routing_enabled
    rows = routing_permission_rows(routing_permission_targets(db), rules, routing_enabled)
    generated = managed_routing_firewall_rules(interfaces, vlans, rules, routing_enabled=routing_enabled)
    policy = {
        "routing_enabled": routing_enabled,
        "rows": rows,
        # Include targets even when there is only one Access boundary and no
        # directed pair yet. A later Network Apply must not silently retain an
        # old Firewall baseline when that boundary gains a peer or a family.
        "targets": routing_firewall_targets(interfaces, vlans),
        "generated_firewall": [
            {
                "name": rule.name,
                "source_interface": rule.interface_name,
                "destination_interface": rule.routing_destination_interface,
                "phase": rule.routing_policy_phase,
                "action": rule.action,
                "source": rule.source,
                "destination": rule.destination,
                "priority": rule.priority,
            }
            for rule in generated
        ],
    }
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()


def routing_permission_apply_state(db: Session) -> str:
    """Require both executed WAN and Firewall baselines to prove application.

    Args:
        db: Session containing desired state and Apply baselines.
    """
    setting = db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1"))
    try:
        baselines = json.loads(setting.value if setting else "{}")
    except (TypeError, ValueError):
        return "pending"
    fingerprint = routing_permission_fingerprint(db)
    return "applied" if isinstance(baselines, dict) and all(isinstance(baselines.get(unit), dict) and baselines[unit].get("routing_permission_fingerprint") == fingerprint for unit in ("wan", "firewall")) else "pending"


def routing_permission_targets(db: Session) -> list[dict[str, Any]]:
    """Return wan routing targets.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    eligible_nat = nat_eligible_target_names(list(interfaces), list(vlans))
    interfaces_by_name = {interface.name: interface for interface in interfaces}
    targets: list[dict[str, Any]] = []
    for interface in interfaces:
        if interface.oper_state == "missing":
            continue
        mode = normalize_interface_mode(interface.mode)
        role = normalize_interface_role(interface.role)
        addresses = [address for cidr in (interface.ip_cidr, interface.ipv6_cidr) if (address := _configured_address(cidr))]
        if mode == "trunk" or not addresses:
            continue
        address_label = " / ".join(addresses)
        routing_domain = "management" if role == "management" else "lab"
        targets.append(
            {
                "name": interface.name,
                "nat_allowed": interface.name in eligible_nat,
                "nat_physical_interface": interface.name,
                "nat_physical_mac": interface.mac_address or "",
                "kind": "physical",
                "role": role,
                "ip_cidr": interface.ip_cidr or "",
                "gateway": interface.gateway or "",
                "ipv4_method": normalize_ipv4_method(interface.ipv4_method),
                "ipv6_cidr": interface.ipv6_cidr or "",
                "ipv6_gateway": interface.ipv6_gateway or "",
                "addresses": addresses,
                "routing_domain": routing_domain,
                "route_allowed": routing_domain == "lab",
                "management_ui": bool(
                    role == "access"
                    and mode == "access"
                    and str(interface.admin_state or "").lower() == "up"
                    and interface.access_management_ui_enabled
                ),
                "label": f"{interface.name} - physical / {role} / {address_label}",
            }
        )
    for vlan in vlans:
        parent = interfaces_by_name.get(vlan.parent_interface)
        role = normalize_interface_role(vlan.role)
        addresses = [address for cidr in (vlan.ip_cidr, vlan.ipv6_cidr) if (address := _configured_address(cidr))]
        if not vlan.enabled or not addresses:
            continue
        address_label = " / ".join(addresses)
        routing_domain = "management" if role == "management" else "lab"
        targets.append(
            {
                "name": vlan.name,
                "nat_allowed": vlan.name in eligible_nat,
                "nat_physical_interface": vlan.parent_interface,
                "nat_physical_mac": parent.mac_address if parent else "",
                "kind": "vlan",
                "role": role,
                "ip_cidr": vlan.ip_cidr or "",
                "ipv6_cidr": vlan.ipv6_cidr or "",
                "addresses": addresses,
                "routing_domain": routing_domain,
                "route_allowed": routing_domain == "lab",
                "management_ui": bool(
                    role == "access"
                    and vlan.access_management_ui_enabled
                    and parent is not None
                    and parent.oper_state != "missing"
                    and str(parent.admin_state or "").lower() == "up"
                    and normalize_interface_mode(parent.mode) == "trunk"
                ),
                "label": f"{vlan.name} - VLAN {vlan.vlan_id} on {vlan.parent_interface} / {role} / {address_label}",
            }
        )
    return targets
