"""Implement routes wan service behavior."""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import ip_address, ip_interface, ip_network

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    NatRule,
    PhysicalInterface,
    Route,
    RoutingRule,
    Setting,
    VlanInterface,
    WanPolicy,
)
from atlaso.app.services.firewall import (
    FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX,
    source_group_to_rule_source,
)
from atlaso.app.services.networking import normalize_interface_mode

WAN_CONFIG_PATH = "/var/lib/atlaso/apply/wan/atlaso-wan.conf"
WAN_MODES = ["interface"]
MANAGEMENT_ROUTE_TABLE_ID = 100
LAB_ROUTE_TABLE_ID = 200
MANAGEMENT_ROUTE_TABLE_NAME = "atlaso_mgmt"
LAB_ROUTE_TABLE_NAME = "atlaso_lab"
DEFAULT_ROUTE_DESTINATIONS = {4: "0.0.0.0/0", 6: "::/0"}
ROUTING_ENABLED_SETTING_KEY = "routes_wan.routing_enabled"
NAT_ENABLED_SETTING_KEY = "routes_wan.nat_enabled"
WAN_SIMULATION_ENABLED_SETTING_KEY = "routes_wan.wan_simulation_enabled"
ROUTES_WAN_SETTING_KEYS = frozenset(
    {
        ROUTING_ENABLED_SETTING_KEY,
        NAT_ENABLED_SETTING_KEY,
        WAN_SIMULATION_ENABLED_SETTING_KEY,
    }
)


@dataclass(frozen=True)
class RoutesWanSettings:
    """Saved global activation state for Routes and WAN features."""

    routing_enabled: bool = False
    nat_enabled: bool = False
    wan_simulation_enabled: bool = False

    @property
    def effective_nat_enabled(self) -> bool:
        """Return whether NAT can be active with the saved routing state."""
        return self.routing_enabled and self.nat_enabled

    def as_dict(self) -> dict[str, bool]:
        """Return the public representation of the saved feature settings."""
        return {
            "routing_enabled": self.routing_enabled,
            "nat_enabled": self.nat_enabled,
            "wan_simulation_enabled": self.wan_simulation_enabled,
            "effective_nat_enabled": self.effective_nat_enabled,
        }


def _setting_bool(value: str | None) -> bool:
    """Parse a persisted setting boolean using the repository's safe values.

    Args:
        value: Persisted setting value to interpret.
    """
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _has_routing_address(ipv4_cidr: str | None, ipv6_cidr: str | None) -> bool:
    """Return whether a target has at least one usable configured address.

    Args:
        ipv4_cidr: Optional configured IPv4 interface CIDR.
        ipv6_cidr: Optional configured IPv6 interface CIDR.
    """
    for cidr in (ipv4_cidr, ipv6_cidr):
        if not cidr:
            continue
        try:
            ip_interface(cidr)
        except ValueError:
            continue
        return True
    return False


def infer_routes_wan_settings(db: Session) -> RoutesWanSettings:
    """Infer legacy feature activation from previously effective desired rows.

    This is used only when one or more global settings are absent. Disabled or
    unused rows intentionally do not activate a feature.

    Args:
        db: Active database session containing legacy desired state.
    """
    enabled_routes = db.execute(select(Route).where(Route.enabled.is_(True))).scalars().all()
    enabled_routing_rule = db.execute(
        select(RoutingRule.id).where(RoutingRule.enabled.is_(True)).limit(1)
    ).first() is not None
    physical_route_targets = db.execute(
        select(PhysicalInterface).where(PhysicalInterface.role == "route")
    ).scalars().all()
    vlan_route_targets = db.execute(
        select(VlanInterface).where(
            VlanInterface.role == "route",
            VlanInterface.enabled.is_(True),
        )
    ).scalars().all()
    active_route_targets = {
        interface.name
        for interface in physical_route_targets
        if interface.oper_state != "missing"
        and normalize_interface_mode(interface.mode) != "trunk"
        and _has_routing_address(interface.ip_cidr, interface.ipv6_cidr)
    }
    active_route_targets.update(
        vlan.name
        for vlan in vlan_route_targets
        if _has_routing_address(vlan.ip_cidr, vlan.ipv6_cidr)
    )
    generated_routing_required = len(active_route_targets) >= 2
    enabled_nat_rule = db.execute(
        select(NatRule.id).where(NatRule.enabled.is_(True)).limit(1)
    ).first() is not None
    enabled_policy_ids = {
        policy_id
        for (policy_id,) in db.execute(
            select(WanPolicy.id).where(WanPolicy.enabled.is_(True))
        ).all()
    }
    wan_simulation_required = any(
        route.wan_policy_id in enabled_policy_ids for route in enabled_routes if route.wan_policy_id is not None
    )
    return RoutesWanSettings(
        routing_enabled=(
            bool(enabled_routes)
            or enabled_routing_rule
            or generated_routing_required
            or enabled_nat_rule
        ),
        nat_enabled=enabled_nat_rule,
        wan_simulation_enabled=wan_simulation_required,
    )


def ensure_routes_wan_settings(
    db: Session,
    *,
    force_disabled: bool = False,
) -> RoutesWanSettings:
    """Return saved settings, creating missing keys from legacy state once.

    Args:
        db: Active database session.
        force_disabled: Replace all three values with factory-safe defaults.
    """
    rows = {
        row.key: row
        for row in db.execute(select(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS))).scalars().all()
    }
    inferred = RoutesWanSettings() if force_disabled else infer_routes_wan_settings(db)
    inferred_values = {
        ROUTING_ENABLED_SETTING_KEY: inferred.routing_enabled,
        NAT_ENABLED_SETTING_KEY: inferred.nat_enabled,
        WAN_SIMULATION_ENABLED_SETTING_KEY: inferred.wan_simulation_enabled,
    }
    for key, inferred_value in inferred_values.items():
        row = rows.get(key)
        if row is None:
            row = Setting(key=key, value=_bool_value(inferred_value))
            db.add(row)
            rows[key] = row
        elif force_disabled:
            row.value = "false"
            db.add(row)
    db.flush()
    return RoutesWanSettings(
        routing_enabled=_setting_bool(rows[ROUTING_ENABLED_SETTING_KEY].value),
        nat_enabled=_setting_bool(rows[NAT_ENABLED_SETTING_KEY].value),
        wan_simulation_enabled=_setting_bool(rows[WAN_SIMULATION_ENABLED_SETTING_KEY].value),
    )


def save_routes_wan_settings(
    db: Session,
    *,
    routing_enabled: bool,
    nat_enabled: bool,
    wan_simulation_enabled: bool,
) -> RoutesWanSettings:
    """Persist global desired state without applying host networking changes.

    Args:
        db: Active database session.
        routing_enabled: Whether Atlaso lab routing is desired.
        nat_enabled: Whether Atlaso IPv4 masquerade is desired.
        wan_simulation_enabled: Whether Atlaso WAN impairment is desired.
    """
    ensure_routes_wan_settings(db)
    values = {
        ROUTING_ENABLED_SETTING_KEY: routing_enabled,
        NAT_ENABLED_SETTING_KEY: nat_enabled,
        WAN_SIMULATION_ENABLED_SETTING_KEY: wan_simulation_enabled,
    }
    rows = {
        row.key: row
        for row in db.execute(select(Setting).where(Setting.key.in_(ROUTES_WAN_SETTING_KEYS))).scalars().all()
    }
    for key, value in values.items():
        rows[key].value = _bool_value(value)
        db.add(rows[key])
    db.flush()
    return RoutesWanSettings(
        routing_enabled=routing_enabled,
        nat_enabled=nat_enabled,
        wan_simulation_enabled=wan_simulation_enabled,
    )


def save_routing_enabled_state(
    db: Session,
    *,
    enabled: bool,
) -> RoutesWanSettings:
    """Update only the global Routing desired-state switch.

    Args:
        db: Active database session.
        enabled: Whether Atlaso lab routing is desired.
    """
    current = ensure_routes_wan_settings(db)
    return save_routes_wan_settings(
        db,
        routing_enabled=enabled,
        nat_enabled=current.nat_enabled,
        wan_simulation_enabled=current.wan_simulation_enabled,
    )


def canonical_route_destination(value: str) -> str:
    """Return the canonical representation of a route destination CIDR.

    Args:
        value: Route destination CIDR to canonicalize.
    """
    return str(ip_network(value.strip(), strict=False))


def default_route_family(value: str) -> int | None:
    """Return the IP family when a destination represents a default route.

    Args:
        value: Route destination CIDR to inspect.
    """
    try:
        network = ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    return network.version if network.prefixlen == 0 else None


def route_gateway_target_error(gateway: str | None, target_cidrs: Iterable[str | None]) -> str | None:
    """Return why a route gateway cannot be reached through its selected target.

    Args:
        gateway: Validated route next-hop IP address, or no gateway for a direct route.
        target_cidrs: Configured IPv4 and IPv6 CIDRs on the selected route target.
    """
    if not gateway:
        return None
    try:
        gateway_address = ip_address(gateway)
    except ValueError:
        return f"Route gateway {gateway} is not a valid IP address."
    networks = []
    for raw_cidr in target_cidrs:
        if not raw_cidr:
            continue
        try:
            networks.append(ip_network(raw_cidr, strict=False))
        except ValueError:
            continue
    matching_networks = [network for network in networks if network.version == gateway_address.version]
    if not matching_networks:
        return f"Selected route target does not have a configured IPv{gateway_address.version} CIDR for gateway {gateway_address}."
    if gateway_address.version == 6 and gateway_address.is_link_local:
        return None
    if not any(gateway_address in network for network in matching_networks):
        return f"Route gateway {gateway_address} is not on-link for the selected target's configured IPv{gateway_address.version} CIDR."
    return None


def has_default_route_conflict(routes: list[Route], family: int, exclude_route_id: int | None = None) -> bool:
    """Return whether another saved route already defines the family default.

    Args:
        routes: Saved routes to inspect.
        family: IP family whose default must be unique.
        exclude_route_id: Existing route identifier to ignore during edits.
    """
    return any(
        route.id != exclude_route_id and default_route_family(route.destination_cidr) == family
        for route in routes
    )


def _bool_value(value: bool) -> str:
    """Return bool value.

    Args:
        value: Candidate value consumed by bool value.
    """
    return "true" if value else "false"


def wan_policy_to_dict(policy: WanPolicy) -> dict:
    """Return wan policy to dict.

    Args:
        policy: Policy consumed by WAN policy to dict.
    """
    return {
        "id": policy.id,
        "name": policy.name,
        "description": policy.description or "",
        "enabled": policy.enabled,
        "latency_ms": policy.latency_ms,
        "jitter_ms": policy.jitter_ms,
        "packet_loss_percent": policy.packet_loss_percent,
        "bandwidth_mbit": policy.bandwidth_mbit or "",
        "corrupt_percent": policy.corrupt_percent or 0.0,
        "duplicate_percent": policy.duplicate_percent or 0.0,
        "reorder_percent": policy.reorder_percent or 0.0,
    }


def route_to_dict(route: Route) -> dict:
    """Return route to dict.

    Args:
        route: Route consumed by route to dict.
    """
    destination = canonical_route_destination(route.destination_cidr)
    family = default_route_family(destination)
    return {
        "id": route.id,
        "destination_cidr": destination,
        "destination_label": f"Default route (IPv{family})" if family else destination,
        "default_route": family is not None,
        "default_route_family": family or "",
        "gateway": route.gateway or "",
        "interface_name": route.interface_name,
        "metric": route.metric,
        "enabled": route.enabled,
        "wan_policy_id": route.wan_policy_id or "",
        "wan_policy_name": route.wan_policy.name if route.wan_policy else "",
        "wan_mode": "interface",
    }


def nat_rule_to_dict(rule: NatRule) -> dict:
    """Return nat rule to dict.

    Args:
        rule: Rule consumed by nat rule to dict.
    """
    return {
        "id": rule.id,
        "name": rule.name,
        "enabled": rule.enabled,
        "source": rule.source,
        "outbound_interface": rule.outbound_interface,
        "masquerade": rule.masquerade,
        "priority": rule.priority,
        "description": rule.description or "",
    }


def routing_rule_to_dict(rule: RoutingRule) -> dict:
    """Return routing rule to dict.

    Args:
        rule: Rule consumed by routing rule to dict.
    """
    return {
        "id": rule.id,
        "name": rule.name,
        "enabled": rule.enabled,
        "source_interface": rule.source_interface,
        "destination_interface": rule.destination_interface,
        "priority": rule.priority,
        "description": rule.description or "",
        "generated": False,
    }


def generated_route_role_rules(targets: list[dict[str, str]]) -> list[dict]:
    """Return generated route role rules.

    Args:
        targets: Targets consumed by generated route role rules.
    """
    route_targets = [target for target in targets if target.get("role") == "route" and target.get("routing_domain") == "lab"]
    rows: list[dict] = []
    for source in route_targets:
        for destination in route_targets:
            if source["name"] == destination["name"]:
                continue
            rows.append(
                {
                    "id": f"generated:{source['name']}:{destination['name']}",
                    "name": f"{source['name']} to {destination['name']}",
                    "enabled": True,
                    "source_interface": source["name"],
                    "destination_interface": destination["name"],
                    "priority": 30,
                    "description": "Generated from route-role network intent.",
                    "generated": True,
                }
            )
    return rows


def wan_policy_summary(policy: WanPolicy | None) -> str:
    """Return wan policy summary.

    Args:
        policy: Policy consumed by WAN policy summary.
    """
    if policy is None:
        return "none"
    parts = [f"delay {policy.latency_ms}ms"]
    if policy.jitter_ms:
        parts.append(f"{policy.jitter_ms}ms jitter")
    if policy.packet_loss_percent:
        parts.append(f"loss {policy.packet_loss_percent}%")
    if policy.bandwidth_mbit:
        parts.append(f"rate {policy.bandwidth_mbit}mbit")
    if policy.corrupt_percent:
        parts.append(f"corrupt {policy.corrupt_percent}%")
    if policy.duplicate_percent:
        parts.append(f"duplicate {policy.duplicate_percent}%")
    if policy.reorder_percent:
        parts.append(f"reorder {policy.reorder_percent}%")
    return ", ".join(parts)


def netem_args(policy: WanPolicy) -> list[str]:
    """Return netem args.

    Args:
        policy: Policy consumed by netem args.
    """
    args = ["delay", f"{policy.latency_ms}ms"]
    if policy.jitter_ms:
        args.append(f"{policy.jitter_ms}ms")
    if policy.packet_loss_percent:
        args.extend(["loss", f"{policy.packet_loss_percent}%"])
    if policy.corrupt_percent:
        args.extend(["corrupt", f"{policy.corrupt_percent}%"])
    if policy.duplicate_percent:
        args.extend(["duplicate", f"{policy.duplicate_percent}%"])
    if policy.reorder_percent:
        args.extend(["reorder", f"{policy.reorder_percent}%"])
    if policy.bandwidth_mbit:
        args.extend(["rate", f"{policy.bandwidth_mbit}mbit"])
    return args


def validate_nat_source(value: str, source_group_ids: set[str] | None = None, source_groups: list[dict] | None = None) -> list[str]:
    """Validate nat source.

    Args:
        value: Candidate value consumed by validate nat source.
        source_group_ids: Stable identifiers of the associated source group resources.
        source_groups: Candidate source groups to validate.


    Returns:
        The validate nat source result.
    """
    source_group_ids = source_group_ids or set()
    raw_value = value.strip()
    if not raw_value:
        return ["NAT source is required."]
    if raw_value.lower() == "any":
        return []
    if raw_value.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
        group_id = raw_value[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX) :].strip()
        if group_id in source_group_ids:
            if source_groups is not None:
                groups_by_id = {str(group.get("id", "")): group for group in source_groups}
                resolved = source_group_to_rule_source(groups_by_id.get(group_id), groups_by_id)
                return validate_nat_source(resolved, source_group_ids, None)
            return []
        return [f"NAT source references a Source Group that does not exist: {raw_value}."]
    errors: list[str] = []
    for item in re.split(r"[\n,]+", raw_value):
        source = item.strip()
        if not source:
            continue
        try:
            network = ip_network(source, strict=False)
        except ValueError:
            errors.append("NAT source must be 'any', a Source Group reference, or valid IPv4 CIDRs.")
            break
        if network.version != 4:
            errors.append("NAT v1 supports IPv4 source CIDRs only.")
            break
    return errors


def validate_wan_state(
    routes: list[Route],
    policies: list[WanPolicy],
    target_names: set[str],
    nat_rules: list[NatRule] | None = None,
    wan_target_names: set[str] | None = None,
    source_groups: list[dict] | None = None,
    routing_rules: list[RoutingRule] | None = None,
    routing_target_names: set[str] | None = None,
    route_target_cidrs: dict[str, Iterable[str | None]] | None = None,
    management_target_names: set[str] | None = None,
    routing_enabled: bool = True,
    nat_enabled: bool = True,
    wan_simulation_enabled: bool = True,
) -> list[str]:
    """Validate wan state.

    Args:
        routes: Routes supplied by the caller.
        policies: Policies supplied by the caller.
        target_names: Target names supplied by the caller.
        nat_rules: Nat rules supplied by the caller.
        wan_target_names: Wan target names supplied by the caller.
        source_groups: Source Groups available to the rule.
        routing_rules: Routing rules supplied by the caller.
        routing_target_names: Routing target names supplied by the caller.
        route_target_cidrs: Configured target CIDRs used to validate route next hops.
        management_target_names: Targets whose enabled defaults remain active for management reachability.
        routing_enabled: Validate routing resources when globally active.
        nat_enabled: Validate NAT resources when effectively active.
        wan_simulation_enabled: Validate WAN policy resources when globally active.

    Returns:
        The validate wan state result.
    """
    errors: list[str] = []
    policy_ids = {policy.id for policy in policies}
    management_target_names = management_target_names or set()
    default_families: set[int] = set()
    for route in routes:
        if not route.destination_cidr:
            errors.append("Route destination CIDR is required.")
            continue
        try:
            destination_network = ip_network(route.destination_cidr, strict=False)
        except ValueError:
            errors.append(f"Route {route.destination_cidr} is not a valid destination CIDR.")
            continue
        management_default_active = bool(
            route.enabled
            and destination_network.prefixlen == 0
            and route.interface_name in management_target_names
        )
        if not routing_enabled and not management_default_active:
            continue
        if destination_network.prefixlen == 0:
            if destination_network.version in default_families:
                errors.append(f"Only one IPv{destination_network.version} default route can be configured.")
            default_families.add(destination_network.version)
            if not route.gateway:
                errors.append(f"Default IPv{destination_network.version} route {route.destination_cidr} requires a gateway.")
        if route.gateway:
            try:
                gateway_address = ip_address(route.gateway)
            except ValueError:
                errors.append(f"Gateway {route.gateway} for {route.destination_cidr} is not a valid IP address.")
                gateway_address = None
            if gateway_address and gateway_address.version != destination_network.version:
                errors.append(f"Gateway {route.gateway} for {route.destination_cidr} must use the same IP family as the destination.")
            elif gateway_address and route_target_cidrs and route.interface_name in route_target_cidrs:
                target_error = route_gateway_target_error(route.gateway, route_target_cidrs[route.interface_name])
                if target_error:
                    errors.append(f"Route {route.destination_cidr}: {target_error}")
        if route.enabled and route.interface_name not in target_names:
            errors.append(f"Route {route.destination_cidr} uses {route.interface_name}, which is not an access interface or VLAN target.")
        if route.metric < 0:
            errors.append(f"Route {route.destination_cidr} has a negative metric.")

    if wan_simulation_enabled:
        for route in routes:
            if route.enabled and route.wan_policy_id and route.interface_name not in target_names:
                errors.append(
                    f"Route {route.destination_cidr} uses {route.interface_name}, which is not an access interface or VLAN target."
                )
            if route.wan_policy_id and route.wan_policy_id not in policy_ids:
                errors.append(f"Route {route.destination_cidr} references a missing WAN policy.")

    if nat_enabled:
        seen_nat_names: set[str] = set()
        wan_target_names = wan_target_names or set()
        source_groups = source_groups or []
        source_group_ids = {str(group.get("id", "")) for group in source_groups}
        for rule in nat_rules or []:
            if not rule.name.strip():
                errors.append("NAT rule name is required.")
            normalized_name = rule.name.strip().lower()
            if normalized_name in seen_nat_names:
                errors.append(f"NAT rule {rule.name} is duplicated.")
            seen_nat_names.add(normalized_name)
            if rule.enabled:
                errors.extend(validate_nat_source(rule.source, source_group_ids, source_groups))
            if rule.enabled and rule.outbound_interface not in wan_target_names:
                errors.append(f"NAT rule {rule.name} must use an access physical interface or enabled VLAN with an IP CIDR.")
            if rule.priority < 0:
                errors.append(f"NAT rule {rule.name} has a negative priority.")
            if rule.enabled and not rule.masquerade:
                errors.append(f"NAT rule {rule.name} must use masquerade; destination NAT and port forwarding are not supported in v1.")

    if routing_enabled:
        routing_target_names = routing_target_names or target_names
        seen_routing_names: set[str] = set()
        for rule in routing_rules or []:
            if not rule.name.strip():
                errors.append("Routing rule name is required.")
            normalized_name = rule.name.strip().lower()
            if normalized_name in seen_routing_names:
                errors.append(f"Routing rule {rule.name} is duplicated.")
            seen_routing_names.add(normalized_name)
            if rule.enabled and rule.source_interface not in routing_target_names:
                errors.append(f"Routing rule {rule.name} source must be a non-management access or route interface.")
            if rule.enabled and rule.destination_interface not in routing_target_names:
                errors.append(f"Routing rule {rule.name} destination must be a non-management access or route interface.")
            if rule.enabled and rule.source_interface == rule.destination_interface:
                errors.append(f"Routing rule {rule.name} must use different source and destination interfaces.")
            if rule.priority < 0:
                errors.append(f"Routing rule {rule.name} has a negative priority.")

    if wan_simulation_enabled:
        for policy in policies:
            if not policy.name.strip():
                errors.append("WAN policy name is required.")
            if policy.latency_ms < 0 or policy.jitter_ms < 0:
                errors.append(f"WAN policy {policy.name} cannot have negative latency or jitter.")
            for field_name, value in [
                ("packet loss", policy.packet_loss_percent or 0.0),
                ("corruption", policy.corrupt_percent or 0.0),
                ("duplication", policy.duplicate_percent or 0.0),
                ("reordering", policy.reorder_percent or 0.0),
            ]:
                if value < 0 or value > 100:
                    errors.append(f"WAN policy {policy.name} has invalid {field_name} percentage.")
            if policy.bandwidth_mbit is not None and policy.bandwidth_mbit < 1:
                errors.append(f"WAN policy {policy.name} bandwidth must be at least 1 Mbps when set.")
    return errors


def _policy_by_id(policies: list[WanPolicy]) -> dict[int, WanPolicy]:
    """Return policy by id.

    Args:
        policies: Policies consumed by policy by identifier.
    """
    return {policy.id: policy for policy in policies}


def _target_networks(target: dict[str, str]) -> list:
    """Return target networks.

    Args:
        target: Target resource or location affected by the operation.
    """
    return [
        ip_network(target[cidr_key], strict=False)
        for cidr_key in ("ip_cidr", "ipv6_cidr")
        if target.get(cidr_key)
    ]


def _target_network_owners(targets: list[dict[str, str]]) -> dict[str, int]:
    """Return target network owners.

    Args:
        targets: Targets consumed by target network owners.
    """
    owners: dict[str, int] = {}
    for index, target in enumerate(targets):
        for network in _target_networks(target):
            key = str(network)
            owner_index = owners.get(key)
            if owner_index is None:
                owners[key] = index
                continue
            owner = targets[owner_index]
            if owner.get("routing_domain") != "management" and target.get("routing_domain") == "management":
                owners[key] = index
    return owners


def _nat_source_resolved(rule: NatRule, source_groups: list[dict] | None = None) -> str:
    """Return nat source resolved.

    Args:
        rule: Rule consumed by nat source resolved.
        source_groups: Source groups consumed by nat source resolved.
    """
    source = rule.source.strip()
    if source.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
        group_id = source[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX) :].strip()
        groups_by_id = {str(group.get("id", "")): group for group in source_groups or []}
        resolved = source_group_to_rule_source(groups_by_id.get(group_id), groups_by_id)
        return ", ".join(item.strip() for item in re.split(r"[\n,]+", resolved) if item.strip())
    return source or "any"


def _nft_source_expr(source: str) -> str:
    """Return nft source expr.

    Args:
        source: Source object or location from which data is obtained.
    """
    source_value = source.strip()
    if not source_value or source_value.lower() == "any":
        return ""
    values = [item.strip() for item in re.split(r"[\n,]+", source_value) if item.strip()]
    if len(values) == 1:
        return f"ip saddr {values[0]} "
    return f"ip saddr {{ {', '.join(values)} }} "


def mirrored_management_default_routes(
    config_preview: str,
) -> set[tuple[str, str, str, str]]:
    """Return enabled default-route state mirrored for management listeners.

    Args:
        config_preview: Previously rendered Routes & WAN configuration.
    """
    targets: dict[str, bool] = {}
    routes: list[dict[str, str]] = []
    current_section = ""
    current_route: dict[str, str] | None = None
    current_target = ""
    for raw_line in (config_preview or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")
            current_route = None
            current_target = ""
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if current_section == "targets" and key == "target":
            current_target = value
            targets[current_target] = False
        elif current_section == "targets" and current_target and key == "management_ui":
            targets[current_target] = value.lower() == "true"
        elif current_section == "routes" and key == "route":
            current_route = {"destination_cidr": value}
            routes.append(current_route)
        elif current_section == "routes" and current_route is not None:
            current_route[key] = value

    mirrored: set[tuple[str, str, str, str]] = set()
    for route in routes:
        interface_name = route.get("interface", "")
        if not interface_name or not targets.get(interface_name):
            continue
        if route.get("enabled", "true").lower() != "true":
            continue
        try:
            destination = canonical_route_destination(route.get("destination_cidr", ""))
        except ValueError:
            continue
        if ip_network(destination, strict=False).prefixlen == 0:
            mirrored.add(
                (
                    destination,
                    interface_name,
                    route.get("gateway", ""),
                    route.get("metric", "100"),
                )
            )
    return mirrored


def mirrored_management_default_keys(config_preview: str) -> set[tuple[str, str]]:
    """Return identities of enabled defaults mirrored for management listeners.

    Args:
        config_preview: Previously rendered Routes & WAN configuration.
    """
    return {
        (destination, interface_name)
        for destination, interface_name, _gateway, _metric in mirrored_management_default_routes(
            config_preview
        )
    }


def render_wan_config(
    routes: list[Route],
    policies: list[WanPolicy] | None = None,
    nat_rules: list[NatRule] | None = None,
    targets: list[dict[str, str]] | None = None,
    routing_rules: list[RoutingRule] | None = None,
    removed_routes: list[dict[str, str]] | None = None,
    source_groups: list[dict] | None = None,
    previous_config_preview: str = "",
    settings: RoutesWanSettings | None = None,
) -> str:
    """Render wan config.

    Args:
        routes: Routes supplied by the caller.
        policies: Policies supplied by the caller.
        nat_rules: Nat rules supplied by the caller.
        targets: Targets supplied by the caller.
        routing_rules: Routing rules supplied by the caller.
        removed_routes: Removed routes supplied by the caller.
        source_groups: Source Groups available to the rule.
        previous_config_preview: Last-applied configuration used to retire prior host defaults.
        settings: Saved global activation state. Omission preserves the legacy active behavior.

    Returns:
        The rendered wan config.
    """
    policies = policies or []
    nat_rules = nat_rules or []
    targets = targets or []
    routing_rules = routing_rules or []
    settings = settings or RoutesWanSettings(True, True, True)
    policy_lookup = _policy_by_id(policies)
    previously_mirrored_defaults = mirrored_management_default_keys(
        previous_config_preview
    )
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "# Desired route, NAT, and WAN simulation state for Photon appliances.",
        "",
        "[feature_settings]",
        f"routing_enabled={_bool_value(settings.routing_enabled)}",
        f"nat_enabled={_bool_value(settings.nat_enabled)}",
        f"wan_simulation_enabled={_bool_value(settings.wan_simulation_enabled)}",
        f"effective_nat_enabled={_bool_value(settings.effective_nat_enabled)}",
        "",
        "[targets]",
    ]
    for target in targets:
        lines.extend(
            [
                f"target={target['name']}",
                f"  kind={target.get('kind', '')}",
                f"  role={target.get('role', '')}",
                f"  ip_cidr={target.get('ip_cidr', '')}",
                f"  ipv6_cidr={target.get('ipv6_cidr', '')}",
                f"  gateway={target.get('gateway', '')}",
                f"  ipv6_gateway={target.get('ipv6_gateway', '')}",
                f"  ipv4_method={target.get('ipv4_method', 'static')}",
                f"  routing_domain={target.get('routing_domain', 'lab')}",
                f"  route_allowed={_bool_value(bool(target.get('route_allowed', True)))}",
                f"  management_ui={_bool_value(bool(target.get('management_ui', False)))}",
            ]
        )

    lines.extend(
        [
            "",
            "[routes]",
        ]
    )
    for route in routes:
        destination_cidr = canonical_route_destination(route.destination_cidr)
        policy = policy_lookup.get(route.wan_policy_id or 0) or route.wan_policy
        lines.extend(
            [
                f"route={destination_cidr}",
                f"  gateway={route.gateway or ''}",
                f"  interface={route.interface_name}",
                f"  metric={route.metric}",
                f"  enabled={_bool_value(route.enabled)}",
                f"  wan_policy={policy.name if policy else ''}",
                "  wan_mode=interface",
            ]
        )

    if removed_routes:
        lines.extend(["", "[removed_routes]"])
        for route in removed_routes:
            lines.extend(
                [
                    f"route={route.get('destination_cidr', '')}",
                    f"  gateway={route.get('gateway', '')}",
                    f"  interface={route.get('interface_name', '')}",
                    f"  metric={route.get('metric', '100')}",
                ]
            )

    lines.extend(["", "[routing_rules]"])
    for generated in generated_route_role_rules(targets):
        lines.extend(
            [
                f"routing={generated['name']}",
                "  enabled=true",
                f"  source_interface={generated['source_interface']}",
                f"  destination_interface={generated['destination_interface']}",
                f"  priority={generated['priority']}",
                "  generated=true",
                f"  description={generated['description']}",
            ]
        )
    for rule in sorted(routing_rules, key=lambda item: item.priority):
        lines.extend(
            [
                f"routing={rule.name}",
                f"  enabled={_bool_value(rule.enabled)}",
                f"  source_interface={rule.source_interface}",
                f"  destination_interface={rule.destination_interface}",
                f"  priority={rule.priority}",
                "  generated=false",
                f"  description={(rule.description or '').replace(chr(10), ' ')}",
            ]
        )

    lines.extend(["", "[nat_rules]"])
    for rule in sorted(nat_rules, key=lambda item: item.priority):
        lines.extend(
            [
                f"nat={rule.name}",
                f"  enabled={_bool_value(rule.enabled)}",
                f"  source={rule.source}",
                f"  source_resolved={_nat_source_resolved(rule, source_groups)}",
                f"  outbound_interface={rule.outbound_interface}",
                f"  masquerade={_bool_value(rule.masquerade)}",
                f"  priority={rule.priority}",
                f"  description={(rule.description or '').replace(chr(10), ' ')}",
            ]
        )

    lines.extend(["", "[wan_policies]"])
    for policy in policies:
        lines.extend(
            [
                f"policy={policy.name}",
                f"  enabled={_bool_value(policy.enabled)}",
                f"  latency_ms={policy.latency_ms}",
                f"  jitter_ms={policy.jitter_ms}",
                f"  packet_loss_percent={policy.packet_loss_percent}",
                f"  bandwidth_mbit={policy.bandwidth_mbit or ''}",
                f"  corrupt_percent={policy.corrupt_percent or 0.0}",
                f"  duplicate_percent={policy.duplicate_percent or 0.0}",
                f"  reorder_percent={policy.reorder_percent or 0.0}",
            ]
        )

    lines.extend(
        [
            "",
            "[route_tables]",
            f"management={MANAGEMENT_ROUTE_TABLE_ID} {MANAGEMENT_ROUTE_TABLE_NAME}",
            f"lab={LAB_ROUTE_TABLE_ID} {LAB_ROUTE_TABLE_NAME}",
            "",
            "[rendered_nftables_nat]",
            "table ip atlaso_nat {",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
        ]
    )
    for rule in sorted(
        [item for item in nat_rules if item.enabled and settings.effective_nat_enabled],
        key=lambda item: item.priority,
    ):
        source_expr = _nft_source_expr(_nat_source_resolved(rule, source_groups))
        comment = rule.name.replace('"', "'")
        lines.append(f'    {source_expr}oifname "{rule.outbound_interface}" masquerade comment "{comment}"')
    lines.extend(["  }", "}", "", "[commands]"])

    forwarding_value = 1 if settings.routing_enabled else 0
    lines.append(
        f"sysctl -w net.ipv4.ip_forward={forwarding_value}  # global Routing switch"
    )
    lines.append(
        f"sysctl -w net.ipv6.conf.all.forwarding={forwarding_value}  # global Routing switch"
    )
    target_network_owners = _target_network_owners(targets)
    for index, target in enumerate(targets):
        management = target.get("routing_domain") == "management"
        table = MANAGEMENT_ROUTE_TABLE_ID if management else LAB_ROUTE_TABLE_ID
        if not management and not settings.routing_enabled:
            for network in _target_networks(target):
                route_family = "-6 " if network.version == 6 else ""
                lines.append(
                    f"ip {route_family}route del {network} dev {target['name']} table {table}"
                )
            continue
        priority = (1000 if management else 2000) + index
        gateways = [
            str(target.get(key, "") or "").strip()
            for key in ("gateway", "ipv6_gateway")
            if str(target.get(key, "") or "").strip()
        ]
        gateway_by_version: dict[int, str] = {}
        for gateway in gateways:
            try:
                gateway_by_version[ip_address(gateway).version] = gateway
            except ValueError:
                continue
        for network in _target_networks(target):
            owner_index = target_network_owners[str(network)]
            if owner_index != index:
                owner_name = targets[owner_index]["name"]
                lines.append(f"# {network} on {target['name']} reuses the subnet owned by {owner_name}; no duplicate policy route generated")
                continue
            if management and network.version not in gateway_by_version:
                lines.append(f"# {network} on {target['name']} has no management default gateway; the main routing table remains authoritative")
                continue
            route_family = "-6 " if network.version == 6 else ""
            lines.append(f"ip {route_family}rule add from {network} table {table} priority {priority}")
            lines.append(f"ip {route_family}route replace {network} dev {target['name']} table {table}")
        if management and gateways:
            for version, gateway in sorted(gateway_by_version.items()):
                route_family = "-6 " if version == 6 else ""
                lines.append(f"ip {route_family}route replace default via {gateway} dev {target['name']}")
                lines.append(f"ip {route_family}route replace default via {gateway} dev {target['name']} table {MANAGEMENT_ROUTE_TABLE_ID}")
        if management and target.get("ipv4_method", "static") == "static" and not target.get("gateway"):
            lines.append(f"ip route del default dev {target['name']}  # no static management IPv4 gateway configured")
        if management and target.get("ipv6_cidr") and not target.get("ipv6_gateway"):
            lines.append(f"ip -6 route del default dev {target['name']}  # no static management IPv6 gateway configured")
    if settings.effective_nat_enabled and any(rule.enabled for rule in nat_rules):
        lines.append("nft -f /etc/atlaso/nftables.d/atlaso-nat.nft")

    for route in routes:
        destination_cidr = canonical_route_destination(route.destination_cidr)
        destination = ip_network(destination_cidr, strict=False)
        route_family = "-6 " if destination.version == 6 else ""
        route_target = next(
            (target for target in targets if target.get("name") == route.interface_name),
            {},
        )
        management_ui_default = bool(
            destination.prefixlen == 0 and route_target.get("management_ui")
        )
        previously_mirrored_default = (
            destination_cidr,
            route.interface_name,
        ) in previously_mirrored_defaults
        route_effective = route.enabled and settings.routing_enabled
        if not route_effective:
            lines.append(f"ip {route_family}route del {destination_cidr} dev {route.interface_name} table {LAB_ROUTE_TABLE_ID}  # disabled desired route")
            if route.enabled and management_ui_default:
                main_command = ["ip", "-6", "route", "replace", destination_cidr] if destination.version == 6 else ["ip", "route", "replace", destination_cidr]
                if route.gateway:
                    main_command.extend(["via", route.gateway])
                main_command.extend(["dev", route.interface_name, "metric", str(route.metric)])
                lines.append(" ".join(main_command) + "  # flagged-management host default")
            elif (not route.enabled) and (management_ui_default or previously_mirrored_default):
                lines.append(
                    f"ip {route_family}route del {destination_cidr} dev {route.interface_name}"
                    "  # disabled flagged-management default"
                )
        else:
            command = ["ip", "-6", "route", "replace", destination_cidr] if destination.version == 6 else ["ip", "route", "replace", destination_cidr]
            if route.gateway:
                command.extend(["via", route.gateway])
            command.extend(["dev", route.interface_name, "metric", str(route.metric), "table", str(LAB_ROUTE_TABLE_ID)])
            lines.append(" ".join(command))
            if management_ui_default:
                main_command = command[:-2]
                lines.append(" ".join(main_command) + "  # flagged-management host default")
            elif previously_mirrored_default:
                lines.append(
                    f"ip {route_family}route del {destination_cidr} dev {route.interface_name}"
                    "  # retired flagged-management host default"
                )
        policy = policy_lookup.get(route.wan_policy_id or 0) or route.wan_policy
        if settings.wan_simulation_enabled and route.enabled and policy and policy.enabled:
            lines.append(" ".join(["tc", "qdisc", "replace", "dev", route.interface_name, "root", "netem", *netem_args(policy)]))
        else:
            lines.append(" ".join(["tc", "qdisc", "del", "dev", route.interface_name, "root"]))
    for route in removed_routes or []:
        try:
            destination = ip_network(str(route.get("destination_cidr", "")), strict=False)
        except ValueError:
            destination = None
        route_family = "-6 " if destination and destination.version == 6 else ""
        lines.append(f"ip {route_family}route del {route.get('destination_cidr', '')} dev {route.get('interface_name', '')} table {LAB_ROUTE_TABLE_ID}  # removed managed route")
        route_target = next(
            (
                target
                for target in targets
                if target.get("name") == route.get("interface_name", "")
            ),
            {},
        )
        removed_key = (
            canonical_route_destination(str(route.get("destination_cidr", ""))),
            str(route.get("interface_name", "")),
        ) if destination else ("", "")
        if destination and destination.prefixlen == 0 and (
            route_target.get("management_ui")
            or removed_key in previously_mirrored_defaults
        ):
            lines.append(
                f"ip {route_family}route del {route.get('destination_cidr', '')} "
                f"dev {route.get('interface_name', '')}  # removed flagged-management default"
            )
    return "\n".join(lines).strip() + "\n"
