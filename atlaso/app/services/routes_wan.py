"""Implement routes wan service behavior."""

import re
from collections.abc import Iterable
from ipaddress import ip_address, ip_network

from atlaso.app.models import NatRule, Route, RoutingRule, WanPolicy
from atlaso.app.services.firewall import (
    FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX,
    source_group_to_rule_source,
)

WAN_CONFIG_PATH = "/var/lib/atlaso/apply/wan/atlaso-wan.conf"
WAN_MODES = ["interface"]
MANAGEMENT_ROUTE_TABLE_ID = 100
LAB_ROUTE_TABLE_ID = 200
MANAGEMENT_ROUTE_TABLE_NAME = "atlaso_mgmt"
LAB_ROUTE_TABLE_NAME = "atlaso_lab"
DEFAULT_ROUTE_DESTINATIONS = {4: "0.0.0.0/0", 6: "::/0"}


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

    Returns:
        The validate wan state result.
    """
    errors: list[str] = []
    policy_ids = {policy.id for policy in policies}
    default_families: set[int] = set()
    for route in routes:
        try:
            destination_network = ip_network(route.destination_cidr, strict=False)
        except ValueError:
            errors.append(f"Route {route.destination_cidr} is not a valid destination CIDR.")
            destination_network = None
        if destination_network and destination_network.prefixlen == 0:
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
            if destination_network and gateway_address and gateway_address.version != destination_network.version:
                errors.append(f"Gateway {route.gateway} for {route.destination_cidr} must use the same IP family as the destination.")
            elif gateway_address and route_target_cidrs and route.interface_name in route_target_cidrs:
                target_error = route_gateway_target_error(route.gateway, route_target_cidrs[route.interface_name])
                if target_error:
                    errors.append(f"Route {route.destination_cidr}: {target_error}")
        if route.enabled and route.interface_name not in target_names:
            errors.append(f"Route {route.destination_cidr} uses {route.interface_name}, which is not an access interface or VLAN target.")
        if route.metric < 0:
            errors.append(f"Route {route.destination_cidr} has a negative metric.")
        if route.wan_policy_id and route.wan_policy_id not in policy_ids:
            errors.append(f"Route {route.destination_cidr} references a missing WAN policy.")

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

    for policy in policies:
        if not policy.name.strip():
            errors.append("WAN policy name is required.")
        if policy.latency_ms < 0 or policy.jitter_ms < 0:
            errors.append(f"WAN policy {policy.name} cannot have negative latency or jitter.")
        for field_name, value in [
            ("packet loss", policy.packet_loss_percent),
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


def render_wan_config(
    routes: list[Route],
    policies: list[WanPolicy] | None = None,
    nat_rules: list[NatRule] | None = None,
    targets: list[dict[str, str]] | None = None,
    routing_rules: list[RoutingRule] | None = None,
    removed_routes: list[dict[str, str]] | None = None,
    source_groups: list[dict] | None = None,
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

    Returns:
        The rendered wan config.
    """
    policies = policies or []
    nat_rules = nat_rules or []
    targets = targets or []
    routing_rules = routing_rules or []
    policy_lookup = _policy_by_id(policies)
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "# Desired route, NAT, and WAN simulation state for Photon appliances.",
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
    for rule in sorted([item for item in nat_rules if item.enabled], key=lambda item: item.priority):
        source_expr = _nft_source_expr(_nat_source_resolved(rule, source_groups))
        comment = rule.name.replace('"', "'")
        lines.append(f'    {source_expr}oifname "{rule.outbound_interface}" masquerade comment "{comment}"')
    lines.extend(["  }", "}", "", "[commands]"])

    generated_lab_routing_enabled = any(row["generated"] and row["enabled"] for row in generated_route_role_rules(targets))
    if any(rule.enabled for rule in nat_rules):
        lines.append("sysctl -w net.ipv4.ip_forward=1  # required for NAT rules")
    if any(route.enabled for route in routes):
        lines.append("sysctl -w net.ipv4.ip_forward=1  # required for lab routes")
    if generated_lab_routing_enabled or any(rule.enabled for rule in routing_rules):
        lines.append("sysctl -w net.ipv4.ip_forward=1  # required for lab routing rules")
    if not any(rule.enabled for rule in nat_rules) and not any(route.enabled for route in routes) and not generated_lab_routing_enabled and not any(rule.enabled for rule in routing_rules):
        lines.append("sysctl -w net.ipv4.ip_forward=0  # no Atlaso lab routing or NAT requires forwarding")
    target_network_owners = _target_network_owners(targets)
    for index, target in enumerate(targets):
        management = target.get("routing_domain") == "management"
        table = MANAGEMENT_ROUTE_TABLE_ID if management else LAB_ROUTE_TABLE_ID
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
    if any(rule.enabled for rule in nat_rules):
        lines.append("nft -f /etc/atlaso/nftables.d/atlaso-nat.nft")

    for route in routes:
        destination_cidr = canonical_route_destination(route.destination_cidr)
        destination = ip_network(destination_cidr, strict=False)
        route_family = "-6 " if destination.version == 6 else ""
        if not route.enabled:
            lines.append(f"ip {route_family}route del {destination_cidr} dev {route.interface_name} table {LAB_ROUTE_TABLE_ID}  # disabled desired route")
            continue
        command = ["ip", "-6", "route", "replace", destination_cidr] if destination.version == 6 else ["ip", "route", "replace", destination_cidr]
        if route.gateway:
            command.extend(["via", route.gateway])
        command.extend(["dev", route.interface_name, "metric", str(route.metric), "table", str(LAB_ROUTE_TABLE_ID)])
        lines.append(" ".join(command))
        policy = policy_lookup.get(route.wan_policy_id or 0) or route.wan_policy
        if policy and policy.enabled:
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
    return "\n".join(lines).strip() + "\n"
