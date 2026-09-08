"""Own source translation desired state, validation and reviewed helper input."""

import re
from dataclasses import dataclass
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import NatRule, PhysicalInterface, Setting, VlanInterface
from atlaso.app.services.firewall import (
    FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX,
    source_group_to_rule_source,
)
from atlaso.app.services.networking import normalize_interface_mode

NAT_ENABLED_SETTING_KEY = "traffic_publishing.nat_enabled"
LEGACY_NAT_ENABLED_SETTING_KEY = "routes_wan.nat_enabled"
NAT_CONFIG_PATH = "/var/lib/atlaso/apply/nat/atlaso-nat.conf"
NAT_RUNTIME_PATH = "/etc/atlaso/traffic-publishing/atlaso-nat.conf"


@dataclass(frozen=True)
class TrafficPublishingSettings:
    """Canonical NAT intent paired with the independently owned Routing switch."""

    nat_enabled: bool = False
    routing_enabled: bool = False

    @property
    def effective_nat_enabled(self) -> bool:
        """Return whether forwarding translation is currently desired."""
        return self.nat_enabled and self.routing_enabled

    @property
    def suspended(self) -> bool:
        """Retain NAT intent while Routing prevents runtime translation."""
        return self.nat_enabled and not self.routing_enabled

    def as_dict(self) -> dict[str, bool]:
        """Expose canonical settings without claiming applied runtime state."""
        return {"nat_enabled": self.nat_enabled, "routing_enabled": self.routing_enabled,
                "effective_nat_enabled": self.effective_nat_enabled, "suspended": self.suspended}


def ensure_traffic_publishing_settings(db: Session, *, force_disabled: bool = False) -> TrafficPublishingSettings:
    """Migrate explicit or inferred legacy intent once; empty installations default off.

    Args:
        db: Transaction that owns the desired-state read or mutation.
        force_disabled: Restore the factory default without inferring rule intent.
    """
    keys = (NAT_ENABLED_SETTING_KEY, LEGACY_NAT_ENABLED_SETTING_KEY, "routes_wan.routing_enabled")
    rows = {row.key: row for row in db.scalars(select(Setting).where(Setting.key.in_(keys)))}
    row = rows.get(NAT_ENABLED_SETTING_KEY)
    if row is None:
        legacy = rows.get(LEGACY_NAT_ENABLED_SETTING_KEY)
        inferred = not force_disabled and db.scalar(
            select(NatRule.id).where(NatRule.enabled.is_(True)).limit(1)
        ) is not None
        row = Setting(key=NAT_ENABLED_SETTING_KEY, value=legacy.value if legacy else str(inferred).lower())
        db.add(row)
    if force_disabled:
        row.value = "false"
    # Keep one owner. Legacy transports project this row instead of saving a mirror.
    legacy = rows.get(LEGACY_NAT_ENABLED_SETTING_KEY)
    if legacy is not None:
        db.delete(legacy)
    db.flush()
    routing = rows.get("routes_wan.routing_enabled")
    return TrafficPublishingSettings(str(row.value).lower() in {"true", "1", "on", "yes"},
                                     routing is not None and str(routing.value).lower() in {"true", "1", "on", "yes"})


def save_traffic_publishing_settings(db: Session, *, nat_enabled: bool) -> TrafficPublishingSettings:
    """Save canonical intent within the caller's transaction; never touch the host.

    Args:
        db: Transaction shared with authorization, related settings and audit.
        nat_enabled: Reviewed source translation enablement.
    """
    ensure_traffic_publishing_settings(db)
    row = db.scalar(select(Setting).where(Setting.key == NAT_ENABLED_SETTING_KEY))
    assert row is not None
    row.value = "true" if nat_enabled else "false"
    db.flush()
    return ensure_traffic_publishing_settings(db)


def nat_targets(interfaces: list[PhysicalInterface], vlans: list[VlanInterface]) -> list[dict[str, Any]]:
    """Return addressed, available lab targets with physical identity for replay.

    Args:
        interfaces: Saved physical posture and observed identity.
        vlans: Saved VLANs, whose parent must remain an enabled trunk.
    """
    parents = {item.name: item for item in interfaces}
    result = []
    items: list[PhysicalInterface | VlanInterface] = [*interfaces, *vlans]
    for item in items:
        is_vlan = isinstance(item, VlanInterface)
        parent = parents.get(item.parent_interface) if isinstance(item, VlanInterface) else item
        if parent is None or parent.admin_state != "up" or parent.oper_state == "missing":
            continue
        if item.role not in {"access", "route"}:
            continue
        if normalize_interface_mode(parent.mode) != ("trunk" if is_vlan else "access"):
            continue
        if isinstance(item, VlanInterface) and not item.enabled:
            continue
        families = []
        for family, cidr in ((4, item.ip_cidr), (6, item.ipv6_cidr)):
            try:
                address = ip_interface(cidr or "")
            except ValueError:
                continue
            if address.version == family:
                families.append(family)
        if not families:
            continue
        result.append({"name": item.name, "kind": "vlan" if is_vlan else "physical",
                       "role": item.role, "routing_domain": "lab", "route_allowed": True,
                       "nat_allowed": True, "nat_physical_interface": parent.name,
                       "nat_physical_mac": parent.mac_address or "", "ip_cidr": item.ip_cidr or "",
                       "ipv6_cidr": item.ipv6_cidr or "", "ip_families": families,
                       "label": f"{item.name} / {item.role} / IPv" + ", IPv".join(map(str, families))})
    return sorted(result, key=lambda target: (target["name"], target["kind"]))


def resolved_nat_source(source: str, source_groups: list[dict[str, Any]]) -> str:
    """Resolve a stable Source Group reference inside its reviewed family boundary.

    Args:
        source: Any, CIDRs or a stable shared Source Group reference.
        source_groups: Current validated shared groups.
    """
    if source.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
        groups = {str(group.get("id", "")): group for group in source_groups}
        key = source[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):].strip()
        if key not in groups:
            raise ValueError("NAT source references a Source Group that does not exist.")
        return source_group_to_rule_source(groups[key], groups)
    return source.strip()


def validate_nat_rule(rule: NatRule, targets: list[dict[str, Any]], source_groups: list[dict[str, Any]], *, creating: bool = False, allow_legacy: bool = False) -> list[str]:
    """Validate a complete dual-stack rule before saving, restoring or applying.

    Args:
        rule: Complete candidate desired rule.
        targets: Eligible lab targets with configured same-family addresses.
        source_groups: Current shared Source Groups.
        creating: Require eligible targets even for a newly created disabled rule.
        allow_legacy: Preserve unscoped archive rows for explicit later review.
    """
    errors = []
    family = 4 if rule.ip_family is None else rule.ip_family
    mode = rule.translation_mode or "masquerade"
    if family not in {4, 6}:
        errors.append("NAT IP family must be IPv4 or IPv6.")
    if mode not in {"masquerade", "snat"}:
        errors.append("Choose interface-address masquerade or fixed SNAT.")
    if rule.enabled and mode == "masquerade" and rule.masquerade is False:
        errors.append("Legacy non-masquerade NAT requires explicit translation review.")
    inbound = rule.inbound_interfaces or []
    if not isinstance(inbound, list) or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", name) for name in inbound):
        return ["NAT inbound interfaces must be canonical interface/VLAN names."]
    if len(inbound) > 128 or len(set(inbound)) != len(inbound):
        errors.append("NAT inbound interfaces must be unique and contain at most 128 targets.")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", rule.outbound_interface or ""):
        errors.append("Select a canonical outbound interface name.")
    if rule.outbound_interface in inbound:
        errors.append("NAT inbound and outbound interfaces must be different.")
    active = creating or bool(rule.enabled)
    if active and not inbound and not allow_legacy:
        errors.append("Select at least one inbound interface or VLAN; legacy NAT rules require explicit review.")
    eligible = {target["name"]: target for target in targets if family in target["ip_families"]}
    if active:
        for name in [*inbound, rule.outbound_interface]:
            if name not in eligible:
                errors.append(f"NAT target {name} is unavailable; select an enabled non-management IPv{family} interface or VLAN.")
    try:
        source = resolved_nat_source(rule.source, source_groups)
        if not source:
            raise ValueError("NAT source is required.")
        if source.lower() != "any":
            values = [value.strip() for value in re.split(r"[\n,]+", source) if value.strip()]
            if not values or any(ip_network(value, strict=False).version != family for value in values):
                raise ValueError(f"NAT source must contain only IPv{family} addresses or CIDRs.")
    except ValueError:
        errors.append(f"NAT source is invalid; select a valid Source Group or IPv{family} addresses or CIDRs.")
    if mode == "snat":
        try:
            translated = ip_address(rule.translated_address or "")
            if translated.version != family:
                raise ValueError("Fixed SNAT address must use the rule's IP family.")
            target = eligible.get(rule.outbound_interface)
            if active and (target is None or translated != ip_interface(target["ip_cidr" if family == 4 else "ipv6_cidr"]).ip):
                raise ValueError("Fixed SNAT address must be assigned to the selected egress interface.")
        except ValueError:
            errors.append("Fixed SNAT requires a valid same-family address assigned to the selected egress interface.")
    elif rule.translated_address:
        errors.append("Interface-address masquerade cannot specify a fixed translated address.")
    if (rule.priority or 0) < 0:
        errors.append("NAT priority cannot be negative.")
    return errors


def render_nat_config(rules: list[NatRule], targets: list[dict[str, Any]], source_groups: list[dict[str, Any]], settings: TrafficPublishingSettings) -> str:
    """Render typed NAT intent; the helper independently rebuilds nftables input.

    Args:
        rules: Saved source translation rules in priority order.
        targets: Available lab targets and their replay identities.
        source_groups: Shared groups resolved at snapshot capture.
        settings: Exact saved activation snapshot.
    """
    lines = ["# Managed by Atlaso Traffic Publishing.", "[feature_settings]",
             f"routing_enabled={str(settings.routing_enabled).lower()}",
             f"nat_enabled={str(settings.nat_enabled).lower()}", "wan_simulation_enabled=false", "", "[targets]"]
    for target in targets:
        for key in ("name", "nat_physical_interface"):
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", target[key]):
                raise ValueError("NAT physical identity is invalid.")
        if target["nat_physical_mac"] and not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", target["nat_physical_mac"]):
            raise ValueError("NAT physical identity is invalid.")
        lines.append(f"target={target['name']}")
        for key in ("kind", "role", "routing_domain", "nat_allowed", "route_allowed", "nat_physical_interface", "nat_physical_mac", "ip_cidr", "ipv6_cidr"):
            lines.append(f"  {key}={str(target[key]).lower() if isinstance(target[key], bool) else target[key]}")
    lines.extend(["", "[nat_rules]"])
    for rule in sorted(rules, key=lambda item: (item.priority, item.name)):
        inbound = rule.inbound_interfaces or []
        if not isinstance(inbound, list) or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", name) for name in inbound):
            raise ValueError("NAT inbound interfaces must be canonical interface/VLAN names.")
        # Values are data, never nft expressions. The helper rejects malformed input independently.
        try:
            resolved = resolved_nat_source(rule.source, source_groups)
        except ValueError:
            resolved = "invalid"
        values = {"enabled": str(rule.enabled).lower(), "ip_family": rule.ip_family or 4,
                  "masquerade": str(rule.masquerade is not False).lower(),
                  "source": rule.source, "source_resolved": resolved,
                  "inbound_interfaces": ",".join(rule.inbound_interfaces or []),
                  "outbound_interface": rule.outbound_interface, "translation_mode": rule.translation_mode or "masquerade",
                  "translated_address": rule.translated_address or "", "priority": rule.priority}
        lines.append("nat=" + rule.name.replace("\n", " ").replace("\r", " "))
        for key, value in values.items():
            lines.append(f"  {key}={str(value).replace(chr(10), ',').replace(chr(13), '')}")
    return "\n".join([*lines, ""])
