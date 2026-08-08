from ipaddress import ip_network
import json
import re

from atlaso.app.config import get_settings
from atlaso.app.models import (
    DhcpScope,
    DhcpSettings,
    DnsSettings,
    CaSettings,
    FirewallRule,
    FirewallSettings,
    KmsSettings,
    LdapSettings,
    NtpSettings,
    OidcProviderSettings,
    PhysicalInterface,
    RoutingRule,
    VcfBackupSettings,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
)
from atlaso.app.services.dnsmasq import dhcp_scope_address_family, split_interfaces
from atlaso.app.services.networking import normalize_interface_mode, normalize_interface_role


FIREWALL_DIRECTIONS = ["input", "forward", "output"]
FIREWALL_ACTIONS = ["accept", "drop", "reject"]
FIREWALL_PROTOCOLS = ["any", "tcp", "udp", "icmp"]
FIREWALL_POLICIES = ["accept", "drop"]
FIREWALL_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/firewall/atlaso.nft"
FIREWALL_SOURCE_GROUPS_SETTING_KEY = "firewall.managed_source_groups"
FIREWALL_ANY_SOURCE_GROUP_ID = "any"
FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX = "group:"
ATLASO_DHCP_FIREWALL_RULE_MARKER = "Atlaso-managed DNS/DHCP access"
ATLASO_DNS_FIREWALL_RULE_MARKER = "Atlaso-managed DNS access"
ATLASO_SERVICE_FIREWALL_RULE_MARKER = "Atlaso-managed service access"
ATLASO_ROUTING_FIREWALL_RULE_MARKER = "Atlaso-managed lab routing"
ATLASO_MANAGEMENT_ISOLATION_RULE_MARKER = "Atlaso-managed management routing isolation"
ATLASO_LEGACY_DHCP_FIREWALL_RULE_NAMES = {"sitea-dns-dhcp"}
ATLASO_LEGACY_SERVICE_FIREWALL_RULE_NAMES = {"mgmt-console"}


def firewall_settings_to_dict(settings: FirewallSettings) -> dict:
    return {
        "id": settings.id,
        "enabled": settings.enabled,
        "default_input_policy": settings.default_input_policy,
        "default_forward_policy": settings.default_forward_policy,
        "default_output_policy": settings.default_output_policy,
        "allow_established": settings.allow_established,
        "allow_loopback": settings.allow_loopback,
        "allow_icmp": settings.allow_icmp,
        "log_dropped": settings.log_dropped,
        "config_path": settings.config_path,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else "",
    }


def firewall_rule_to_dict(rule: FirewallRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "direction": rule.direction,
        "action": rule.action,
        "protocol": rule.protocol,
        "source": rule.source,
        "destination": rule.destination,
        "destination_port": rule.destination_port,
        "interface_name": rule.interface_name,
        "priority": rule.priority,
        "enabled": rule.enabled,
        "description": rule.description or "",
        "created_at": rule.created_at.isoformat() if rule.created_at else "",
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else "",
        "is_new": False,
    }


def validate_firewall_settings(settings: FirewallSettings) -> list[str]:
    errors: list[str] = []
    for field_name, value in [
        ("Default input policy", settings.default_input_policy),
        ("Default forward policy", settings.default_forward_policy),
        ("Default output policy", settings.default_output_policy),
    ]:
        if value not in FIREWALL_POLICIES:
            errors.append(f"{field_name} must be accept or drop.")
    return errors


def validate_firewall_rule(rule: FirewallRule, source_groups: list[dict] | None = None, *, require_group_addresses: bool = False) -> list[str]:
    errors: list[str] = []
    if not rule.name.strip():
        errors.append("Rule name is required.")
    if rule.direction not in FIREWALL_DIRECTIONS:
        errors.append("Direction must be input, forward, or output.")
    if rule.action not in FIREWALL_ACTIONS:
        errors.append("Action must be accept, drop, or reject.")
    if rule.protocol not in FIREWALL_PROTOCOLS:
        errors.append("Protocol must be any, tcp, udp, or icmp.")
    if rule.protocol in {"any", "icmp"} and rule.destination_port.strip():
        errors.append("Destination port is only valid for TCP or UDP rules.")
    groups_by_id = {str(group.get("id", "")): group for group in source_groups or []}
    names = _source_group_name_index(groups_by_id)
    for label, value in [("Source", rule.source), ("Destination", rule.destination)]:
        if require_group_addresses:
            group_error = _validate_rule_group_reference(label, value, groups_by_id)
            if group_error:
                errors.append(group_error)
                continue
        errors.extend(_validate_rule_address_value(label, value, groups_by_id, names))
    if rule.destination_port.strip():
        errors.extend(_validate_ports(rule.destination_port))
    return errors


def dhcp_firewall_rules(
    dhcp_settings: DhcpSettings,
    scopes: list[DhcpScope],
) -> list[FirewallRule]:
    if not dhcp_settings.enabled:
        return []
    generated_rules: list[FirewallRule] = []
    for index, scope in enumerate([item for item in scopes if item.enabled], start=1):
        family = dhcp_scope_address_family(scope)
        port = "547" if family == "ipv6" else "67"
        rule_name = f"{_slug(scope.name)}-dns-dhcp{'v6' if family == 'ipv6' else ''}"
        generated_rules.append(
            FirewallRule(
                name=rule_name,
                direction="input",
                action="accept",
                protocol="udp",
                source="any",
                destination="any",
                destination_port=port,
                interface_name=scope.interface_name.strip(),
                priority=20 + index,
                enabled=True,
                description=f"{ATLASO_DHCP_FIREWALL_RULE_MARKER} for DHCP {'IPv6' if family == 'ipv6' else 'IPv4'} IP zone {scope.name}. DHCP bootstrap traffic is interface-bound and not group-restricted.",
            )
        )
    return generated_rules


def managed_service_firewall_rules(
    *,
    dns_settings: DnsSettings,
    dhcp_settings: DhcpSettings,
    dhcp_scopes: list[DhcpScope],
    ca_settings: CaSettings,
    ca_portal_interfaces: list[str] | None = None,
    kms_settings: KmsSettings,
    ntp_settings: NtpSettings,
    vcf_backup_settings: VcfBackupSettings,
    vcf_depot_settings: VcfOfflineDepotSettings,
    vcf_registry_settings: VcfPrivateRegistrySettings,
    esxi_pxe_boot: dict | None = None,
    interface_networks: dict[str, str],
    source_groups: list[dict] | None = None,
    source_group_assignments: dict[str, str] | None = None,
    web_terminal_interfaces: list[str] | None = None,
    ldap_settings: LdapSettings | None = None,
    oidc_settings: OidcProviderSettings | None = None,
    esx_storage_rules: list[dict[str, str]] | None = None,
) -> list[FirewallRule]:
    source_groups_by_id = {str(group.get("id", "")): group for group in source_groups or []}
    source_group_assignments = source_group_assignments or {}
    rules = [
        _service_firewall_rule(
            name="mgmt-console",
            service="Management console",
            interface_name="eth0",
            source=_managed_rule_source("mgmt-console", "eth0", interface_networks, source_groups_by_id, source_group_assignments),
            protocol="tcp",
            ports="22,80,443",
            priority=10,
        )
    ]
    for index, interface_name in enumerate(web_terminal_interfaces or [], start=1):
        if interface_name == "eth0":
            continue
        rule_name = f"web-terminal-{interface_name}"
        rules.append(
            _service_firewall_rule(
                name=rule_name,
                service="Web terminal",
                interface_name=interface_name,
                source=_managed_rule_source(rule_name, interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                protocol="tcp",
                ports="443",
                priority=15 + index,
            )
        )
    rules.extend(dns_firewall_rules(dns_settings, interface_networks, source_groups_by_id, source_group_assignments))
    rules.extend(dhcp_firewall_rules(dhcp_settings, dhcp_scopes))
    if ca_settings.enabled:
        ca_interfaces = ca_portal_interfaces if ca_portal_interfaces is not None else split_interfaces(ca_settings.listen_interface)
        for index, interface_name in enumerate(ca_interfaces, start=1):
            rules.append(
                _service_firewall_rule(
                    name=f"ca-portal-{interface_name}",
                    service="CA portal",
                    interface_name=interface_name,
                    source=_managed_rule_source("ca-portal", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="tcp",
                    ports="80,443",
                    priority=55 + index,
                )
            )
    if kms_settings.enabled:
        for index, interface_name in enumerate(split_interfaces(kms_settings.listen_interface), start=1):
            rules.append(
                _service_firewall_rule(
                    name=f"kms-kmip-{interface_name}",
                    service="KMS / KMIP",
                    interface_name=interface_name,
                    source=_managed_rule_source("kms-kmip", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="tcp",
                    ports=str(kms_settings.port),
                    priority=60 + index,
                )
            )
    if ldap_settings and ldap_settings.enabled:
        for index, interface_name in enumerate(split_interfaces(ldap_settings.listen_interface), start=1):
            if ldap_settings.ldaps_enabled:
                rule_name = f"ldap-ldaps-{interface_name}"
                rules.append(
                    _service_firewall_rule(
                        name=rule_name,
                        service="Managed LDAP / LDAPS",
                        interface_name=interface_name,
                        source=_managed_rule_source(rule_name, interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                        protocol="tcp",
                        ports=str(ldap_settings.port),
                        priority=63 + index,
                    )
                )
            if ldap_settings.ldap_enabled:
                rule_name = f"ldap-plaintext-{interface_name}"
                rules.append(
                    _service_firewall_rule(
                        name=rule_name,
                        service="Managed LDAP / plaintext LDAP",
                        interface_name=interface_name,
                        source=_managed_rule_source(rule_name, interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                        protocol="tcp",
                        ports=str(ldap_settings.ldap_port),
                        priority=64 + index,
                    )
                )
    if oidc_settings and oidc_settings.enabled:
        for index, interface_name in enumerate(
            split_interfaces(oidc_settings.listen_interface), start=1
        ):
            rule_name = f"oidc-{interface_name}"
            rules.append(
                _service_firewall_rule(
                    name=rule_name,
                    service="OpenID Connect",
                    interface_name=interface_name,
                    source=_managed_rule_source(
                        rule_name,
                        interface_name,
                        interface_networks,
                        source_groups_by_id,
                        source_group_assignments,
                    ),
                    protocol="tcp",
                    ports=str(oidc_settings.port),
                    priority=69 + index,
                )
            )
    if ntp_settings.enabled:
        for index, interface_name in enumerate(split_interfaces(ntp_settings.listen_interface), start=1):
            rule_name = f"ntpd-{interface_name}"
            rules.append(
                _service_firewall_rule(
                    name=rule_name,
                    service="NTPsec",
                    interface_name=interface_name,
                    source=_managed_rule_source(rule_name, interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="udp",
                    ports=str(ntp_settings.port),
                    priority=65 + index,
                )
            )
    if vcf_backup_settings.enabled:
        for index, interface_name in enumerate(split_interfaces(vcf_backup_settings.listen_interface), start=1):
            rules.append(
                _service_firewall_rule(
                    name=f"vcf-backups-sftp-{interface_name}",
                    service="VCF Backups SFTP",
                    interface_name=interface_name,
                    source=_managed_rule_source("vcf-backups-sftp", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="tcp",
                    ports=str(vcf_backup_settings.port),
                    priority=70 + index,
                )
            )
    public_service_interfaces: list[str] = []
    if ca_settings.enabled:
        public_service_interfaces.extend(ca_portal_interfaces if ca_portal_interfaces is not None else split_interfaces(ca_settings.listen_interface))
    if vcf_depot_settings.enabled:
        public_service_interfaces.extend(split_interfaces(vcf_depot_settings.listen_interface))
    if vcf_registry_settings.enabled:
        public_service_interfaces.extend(split_interfaces(vcf_registry_settings.listen_interface))
    if esxi_pxe_boot and esxi_pxe_boot.get("enabled"):
        public_service_interfaces.extend(split_interfaces(str(esxi_pxe_boot.get("listen_interface") or "")))
    for index, interface_name in enumerate(_ordered_unique(public_service_interfaces), start=1):
        if interface_name not in interface_networks:
            continue
        rules.append(
            _service_firewall_rule(
                name=f"public-services-{interface_name}",
                service="Public service directory",
                interface_name=interface_name,
                source=_managed_rule_source("public-services", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                protocol="tcp",
                ports="80",
                priority=75 + index,
            )
        )
    if vcf_depot_settings.enabled:
        for index, interface_name in enumerate(split_interfaces(vcf_depot_settings.listen_interface), start=1):
            rules.append(
                _service_firewall_rule(
                    name=f"vcf-offline-depot-{interface_name}",
                    service="VCF Offline Depot",
                    interface_name=interface_name,
                    source=_managed_rule_source("vcf-offline-depot", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="tcp",
                    ports=str(vcf_depot_settings.port),
                    priority=80 + index,
                )
            )
    if vcf_registry_settings.enabled:
        for index, interface_name in enumerate(split_interfaces(vcf_registry_settings.listen_interface), start=1):
            rules.append(
                _service_firewall_rule(
                    name=f"vcf-private-registry-{interface_name}",
                    service="VCF Private Registry",
                    interface_name=interface_name,
                    source=_managed_rule_source("vcf-private-registry", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="tcp",
                    ports=str(vcf_registry_settings.port),
                    priority=90 + index,
                )
            )
    if esxi_pxe_boot and esxi_pxe_boot.get("enabled"):
        http_port = str(esxi_pxe_boot.get("http_port") or 8080)
        for index, interface_name in enumerate(split_interfaces(str(esxi_pxe_boot.get("listen_interface") or "")), start=1):
            rules.append(
                _service_firewall_rule(
                    name=f"esxi-pxe-tftp-{interface_name}",
                    service="ESXi PXE TFTP",
                    interface_name=interface_name,
                    source=_managed_rule_source("esxi-pxe-tftp", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="udp",
                    ports="69",
                    priority=100 + index,
                )
            )
            rules.append(
                _service_firewall_rule(
                    name=f"esxi-pxe-http-{interface_name}",
                    service="ESXi PXE HTTP",
                    interface_name=interface_name,
                    source=_managed_rule_source("esxi-pxe-http", interface_name, interface_networks, source_groups_by_id, source_group_assignments),
                    protocol="tcp",
                    ports=http_port,
                    priority=110 + index,
                )
            )
    for spec in esx_storage_rules or []:
        rules.append(
            _service_firewall_rule(
                name=spec["name"],
                service=f"ESX NFS {spec['family'].upper()}",
                interface_name=spec["interface_name"],
                source=spec["source"],
                protocol="tcp",
                ports=spec["ports"],
                priority=125 + len(rules),
            )
        )
    return rules


def routing_firewall_targets(interfaces: list[PhysicalInterface], vlans: list[VlanInterface]) -> list[dict]:
    targets: list[dict] = []
    for interface in interfaces:
        if interface.oper_state == "missing" or normalize_interface_mode(interface.mode) == "trunk":
            continue
        networks = _networks_from_cidrs(interface.ip_cidr, interface.ipv6_cidr)
        if not networks:
            continue
        role = normalize_interface_role(interface.role)
        targets.append({"name": interface.name, "role": role, "networks": networks})
    for vlan in vlans:
        if not vlan.enabled:
            continue
        networks = _networks_from_cidrs(vlan.ip_cidr, vlan.ipv6_cidr)
        if not networks:
            continue
        role = normalize_interface_role(vlan.role)
        targets.append({"name": vlan.name, "role": role, "networks": networks})
    return targets


def managed_routing_firewall_rules(
    interfaces: list[PhysicalInterface],
    vlans: list[VlanInterface],
    routing_rules: list[RoutingRule] | None = None,
) -> list[FirewallRule]:
    targets = routing_firewall_targets(interfaces, vlans)
    targets_by_name = {target["name"]: target for target in targets}
    management_targets = [target for target in targets if target["role"] == "management"]
    lab_targets = [target for target in targets if target["role"] != "management"]
    rules: list[FirewallRule] = []

    for lab in lab_targets:
        for management in management_targets:
            rules.append(
                _routing_firewall_rule(
                    name=f"isolate-{_slug(lab['name'])}-to-{_slug(management['name'])}",
                    action="drop",
                    source_interface=lab["name"],
                    source_networks=lab["networks"],
                    destination_networks=management["networks"],
                    priority=-100,
                    description=ATLASO_MANAGEMENT_ISOLATION_RULE_MARKER,
                )
            )
            rules.append(
                _routing_firewall_rule(
                    name=f"isolate-{_slug(management['name'])}-to-{_slug(lab['name'])}",
                    action="drop",
                    source_interface=management["name"],
                    source_networks=management["networks"],
                    destination_networks=lab["networks"],
                    priority=-100,
                    description=ATLASO_MANAGEMENT_ISOLATION_RULE_MARKER,
                )
            )

    route_targets = [target for target in lab_targets if target["role"] == "route"]
    for source in route_targets:
        for destination in route_targets:
            if source["name"] == destination["name"]:
                continue
            rules.append(
                _routing_firewall_rule(
                    name=f"route-{_slug(source['name'])}-to-{_slug(destination['name'])}",
                    action="accept",
                    source_interface=source["name"],
                    source_networks=source["networks"],
                    destination_networks=destination["networks"],
                    priority=30,
                    description=f"{ATLASO_ROUTING_FIREWALL_RULE_MARKER} from route-role networks.",
                )
            )

    for rule in routing_rules or []:
        if not rule.enabled:
            continue
        source = targets_by_name.get(rule.source_interface)
        destination = targets_by_name.get(rule.destination_interface)
        if not source or not destination:
            continue
        if source["role"] == "management" or destination["role"] == "management":
            continue
        if source["name"] == destination["name"]:
            continue
        rules.append(
            _routing_firewall_rule(
                name=f"routing-{_slug(rule.name)}",
                action="accept",
                source_interface=source["name"],
                source_networks=source["networks"],
                destination_networks=destination["networks"],
                priority=rule.priority,
                description=f"{ATLASO_ROUTING_FIREWALL_RULE_MARKER} from explicit routing rule {rule.name}.",
            )
        )
    return rules


def firewall_source_group_state(raw_json: str, interface_networks: dict[str, str]) -> dict:
    saved: dict = {}
    if raw_json.strip():
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                saved = parsed
        except ValueError:
            saved = {}
    saved_groups = {str(group.get("id", "")): group for group in saved.get("groups", []) if isinstance(group, dict)}
    groups: list[dict] = [_source_group("any", "Any", ["any"], "Allow traffic from any source or destination address.", builtin=True)]
    for group_id, saved_group in saved_groups.items():
        if group_id == "any":
            continue
        default_entries = interface_networks[group_id.removeprefix("interface:")] if group_id.startswith("interface:") and group_id.removeprefix("interface:") in interface_networks else ["any"]
        groups.append(
            _source_group(
                group_id,
                str(saved_group.get("name") or group_id),
                _source_group_entries(saved_group, default_entries),
                str(saved_group.get("description") or "Custom firewall group."),
            )
        )
    assignments = saved.get("assignments", {})
    if not isinstance(assignments, dict):
        assignments = {}
    valid_group_ids = {group["id"] for group in groups}
    return {
        "groups": groups,
        "assignments": {str(rule_name): str(group_id) for rule_name, group_id in assignments.items() if str(group_id) in valid_group_ids},
    }


def validate_firewall_source_groups(groups: list[dict]) -> list[str]:
    errors: list[str] = []
    groups_by_id = {str(group.get("id", "")): group for group in groups}
    names: dict[str, str] = {}
    for group in groups:
        group_id = str(group.get("id", ""))
        label = str(group.get("name") or group_id or "Firewall group")
        normalized_name = label.strip().lower()
        if not label.strip():
            errors.append("Firewall group name is required.")
        elif normalized_name in names and names[normalized_name] != group_id:
            errors.append(f"Firewall group name '{label}' is already used.")
        names[normalized_name] = group_id
    for group in groups:
        group_id = str(group.get("id", ""))
        label = str(group.get("name") or group_id or "Firewall group")
        entries = _source_group_entries(group, ["any"])
        if group_id == FIREWALL_ANY_SOURCE_GROUP_ID and entries != ["any"]:
            errors.append("Any is built in and must contain only 'any'.")
            continue
        address_entries = [entry for entry in entries if not _source_group_reference_target(entry, groups_by_id, names)]
        for entry in entries:
            if entry.strip().lower() == "any":
                continue
            if _source_group_reference_target(entry, groups_by_id, names):
                continue
            if _looks_like_source_group_reference(entry):
                errors.append(f"{label} references a firewall group that does not exist: {entry}.")
        for error in _validate_address_value(label, "\n".join(address_entries)):
            errors.append(error)
        if "any" in [entry.strip().lower() for entry in entries] and len(entries) > 1:
            errors.append(f"{label} can use 'any' only by itself.")
    errors.extend(_validate_source_group_cycles(groups, groups_by_id, names))
    return errors


def source_group_to_rule_source(group: dict | None, source_groups_by_id: dict[str, dict] | None = None) -> str:
    sources = _expand_source_group_entries(group, source_groups_by_id or {})
    return "\n".join(sources or ["any"])


def firewall_interface_networks(interfaces: list[PhysicalInterface], vlans: list[VlanInterface]) -> dict[str, list[str]]:
    networks: dict[str, list[str]] = {}
    for interface in interfaces:
        if interface.oper_state == "missing":
            continue
        interface_networks = _networks_from_cidrs(interface.ip_cidr, interface.ipv6_cidr)
        if interface_networks:
            networks[interface.name] = interface_networks
    for vlan in vlans:
        if not vlan.enabled:
            continue
        vlan_networks = _networks_from_cidrs(vlan.ip_cidr, vlan.ipv6_cidr)
        if vlan_networks:
            networks[vlan.name] = vlan_networks
    return networks


def ca_portal_firewall_interfaces(
    interfaces: list[PhysicalInterface],
    vlans: list[VlanInterface],
    interface_networks: dict[str, list[str]],
) -> list[str]:
    targets: list[str] = []
    for interface in interfaces:
        if interface.oper_state == "missing" or interface.name not in interface_networks:
            continue
        if normalize_interface_mode(interface.mode) == "trunk" or (interface.role or "").strip().lower() == "management":
            continue
        targets.append(interface.name)
    for vlan in vlans:
        if not vlan.enabled or vlan.name not in interface_networks:
            continue
        if (vlan.role or "").strip().lower() == "management":
            continue
        targets.append(vlan.name)
    return targets


def effective_firewall_rules(
    rules: list[FirewallRule],
    generated_rules: list[FirewallRule] | None = None,
    replace_atlaso_dhcp_rules: bool = False,
    replace_atlaso_dns_rules: bool = False,
    replace_atlaso_service_rules: bool = False,
) -> list[FirewallRule]:
    generated_rules = generated_rules or []
    if not generated_rules and not replace_atlaso_dhcp_rules and not replace_atlaso_dns_rules and not replace_atlaso_service_rules:
        return rules
    return [
        rule
        for rule in rules
        if not (
            (replace_atlaso_dhcp_rules and is_atlaso_dhcp_firewall_rule(rule))
            or (replace_atlaso_dns_rules and is_atlaso_dns_firewall_rule(rule))
            or (replace_atlaso_service_rules and is_atlaso_managed_firewall_rule(rule))
        )
    ] + generated_rules


def is_atlaso_managed_firewall_rule(rule: FirewallRule) -> bool:
    normalized_name = rule.name.strip().lower()
    description = (rule.description or "").strip()
    return (
        normalized_name in ATLASO_LEGACY_SERVICE_FIREWALL_RULE_NAMES
        or ATLASO_SERVICE_FIREWALL_RULE_MARKER in description
        or ATLASO_ROUTING_FIREWALL_RULE_MARKER in description
        or ATLASO_MANAGEMENT_ISOLATION_RULE_MARKER in description
        or is_atlaso_dns_firewall_rule(rule)
        or is_atlaso_dhcp_firewall_rule(rule)
    )


def is_atlaso_dhcp_firewall_rule(rule: FirewallRule) -> bool:
    normalized_name = rule.name.strip().lower()
    description = (rule.description or "").strip()
    return normalized_name in ATLASO_LEGACY_DHCP_FIREWALL_RULE_NAMES or ATLASO_DHCP_FIREWALL_RULE_MARKER in description


def is_atlaso_dns_firewall_rule(rule: FirewallRule) -> bool:
    normalized_name = rule.name.strip().lower()
    description = (rule.description or "").strip()
    protocol = rule.protocol.strip().lower()
    return (
        ATLASO_DNS_FIREWALL_RULE_MARKER in description
        or (
            normalized_name.startswith("allow-")
            and "-dns-" in normalized_name
            and protocol in {"tcp", "udp"}
            and rule.destination_port.strip() == "53"
            and description.startswith("Allow DNS from ")
        )
    )


def validate_firewall_state(
    settings: FirewallSettings,
    rules: list[FirewallRule],
    generated_rules: list[FirewallRule] | None = None,
    source_groups: list[dict] | None = None,
    replace_atlaso_dhcp_rules: bool = False,
    replace_atlaso_dns_rules: bool = False,
    replace_atlaso_service_rules: bool = False,
) -> list[str]:
    errors = validate_firewall_settings(settings)
    seen_names: set[str] = set()
    for rule in effective_firewall_rules(
        rules,
        generated_rules,
        replace_atlaso_dhcp_rules,
        replace_atlaso_dns_rules,
        replace_atlaso_service_rules,
    ):
        normalized_name = rule.name.strip().lower()
        if normalized_name in seen_names:
            errors.append(f"Firewall rule {rule.name} is duplicated.")
        seen_names.add(normalized_name)
        errors.extend(validate_firewall_rule(rule, source_groups))
    return errors


def render_nftables_config(
    settings: FirewallSettings,
    rules: list[FirewallRule],
    generated_rules: list[FirewallRule] | None = None,
    source_groups: list[dict] | None = None,
    replace_atlaso_dhcp_rules: bool = False,
    replace_atlaso_dns_rules: bool = False,
    replace_atlaso_service_rules: bool = False,
    management_source_cidr: str | None = None,
) -> str:
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        "# nftables firewall state for Photon OS appliance images.",
        "flush ruleset",
    ]
    if not settings.enabled:
        lines.extend(
            [
                "# Atlaso firewall desired state is disabled.",
                "# Applying this state clears Atlaso-managed nftables rules.",
            ]
        )
        return "\n".join(lines) + "\n"
    effective_management_source_cidr = management_source_cidr or get_settings().management_source_cidr
    ip_network(effective_management_source_cidr, strict=False)
    source_groups_by_id = {str(group.get("id", "")): group for group in source_groups or []}
    lines.append("table inet atlaso {")
    for chain_name, policy in [
        ("input", settings.default_input_policy),
        ("forward", settings.default_forward_policy),
        ("output", settings.default_output_policy),
    ]:
        hook_priority = "filter"
        lines.append(f"  chain {chain_name} {{")
        lines.append(f"    type filter hook {chain_name} priority {hook_priority}; policy {policy};")
        if chain_name == "input" and settings.allow_loopback:
            lines.append('    iifname "lo" accept comment "Atlaso loopback"')
        if settings.allow_established:
            lines.append('    ct state established,related accept comment "Atlaso established traffic"')
        if chain_name == "input" and not replace_atlaso_service_rules:
            lines.append(f'    ip saddr {effective_management_source_cidr} tcp dport {{ 22, 80, 443 }} accept comment "Atlaso management access"')
        if settings.allow_icmp:
            lines.append('    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"')
            lines.append('    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"')
        for rule in sorted(
            [
                item
                for item in effective_firewall_rules(
                    rules,
                    generated_rules,
                    replace_atlaso_dhcp_rules,
                    replace_atlaso_dns_rules,
                    replace_atlaso_service_rules,
                )
                if item.enabled and item.direction == chain_name
            ],
            key=lambda item: item.priority,
        ):
            for rendered_rule in _rule_family_variants(rule, source_groups_by_id):
                lines.append(f"    {_render_rule(rendered_rule, source_groups_by_id)}")
        if settings.log_dropped and policy == "drop":
            lines.append(f'    log prefix "atlaso {chain_name} drop: " flags all counter')
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_rule(rule: FirewallRule, source_groups_by_id: dict[str, dict] | None = None) -> str:
    source_groups_by_id = source_groups_by_id or {}
    parts: list[str] = []
    if rule.interface_name.strip():
        interface_key = "oifname" if rule.direction == "output" else "iifname"
        parts.append(f'{interface_key} "{rule.interface_name.strip()}"')
    protocol = rule.protocol.strip().lower()
    if protocol == "icmp":
        parts.append("meta l4proto icmp")
    source = _rule_address_value(rule.source, source_groups_by_id)
    if source and source != "any":
        parts.append(_address_expr("saddr", source))
    destination = _rule_address_value(rule.destination, source_groups_by_id)
    if destination and destination != "any":
        parts.append(_address_expr("daddr", destination))
    if protocol in {"tcp", "udp"} and rule.destination_port.strip():
        ports = _render_ports(rule.destination_port)
        parts.append(f"{protocol} dport {ports}")
    elif protocol in {"tcp", "udp"}:
        parts.append(f"meta l4proto {protocol}")
    parts.append(rule.action)
    parts.append(f'comment "{_safe_comment(rule.name)}"')
    return " ".join(parts)


def _rule_family_variants(rule: FirewallRule, source_groups_by_id: dict[str, dict]) -> list[FirewallRule]:
    source = _rule_address_value(rule.source, source_groups_by_id)
    destination = _rule_address_value(rule.destination, source_groups_by_id)
    source_by_family = _address_values_by_family(source)
    destination_by_family = _address_values_by_family(destination)
    source_families = {family for family, values in source_by_family.items() if values}
    destination_families = {family for family, values in destination_by_family.items() if values}
    families = sorted(source_families | destination_families)
    if not families:
        return [rule]
    variants: list[FirewallRule] = []
    for family in families:
        if source_families and family not in source_families:
            continue
        if destination_families and family not in destination_families:
            continue
        variant = FirewallRule(
            name=rule.name,
            direction=rule.direction,
            action=rule.action,
            protocol=rule.protocol,
            source="\n".join(source_by_family.get(family) or ["any"]),
            destination="\n".join(destination_by_family.get(family) or ["any"]),
            destination_port=rule.destination_port,
            interface_name=rule.interface_name,
            priority=rule.priority,
            enabled=rule.enabled,
            description=rule.description,
        )
        variants.append(variant)
    return variants or [rule]


def _validate_ports(raw_ports: str) -> list[str]:
    errors: list[str] = []
    for item in raw_ports.replace(",", "\n").splitlines():
        value = item.strip()
        if not value:
            continue
        if "-" in value:
            start, end = value.split("-", 1)
            if not _valid_port(start) or not _valid_port(end) or int(start) > int(end):
                errors.append(f"Port range {value} is invalid.")
        elif not _valid_port(value):
            errors.append(f"Port {value} is invalid.")
    return errors


def _valid_port(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65535


def _address_expr(direction: str, value: str) -> str:
    values = _split_address_values(value)
    family = "ip6" if ip_network(values[0], strict=False).version == 6 else "ip"
    if len(values) == 1:
        return f"{family} {direction} {values[0]}"
    return f"{family} {direction} {{ {', '.join(values)} }}"


def _render_ports(raw_ports: str) -> str:
    ports = [item.strip().replace("-", "-") for item in raw_ports.replace(",", "\n").splitlines() if item.strip()]
    if not ports:
        return ""
    if len(ports) == 1:
        return ports[0].replace("-", "-")
    return "{ " + ", ".join(ports) + " }"


def _safe_comment(value: str) -> str:
    return value.replace('"', "'").strip()


def _service_firewall_rule(
    *,
    name: str,
    service: str,
    interface_name: str,
    source: str,
    protocol: str,
    ports: str,
    priority: int,
) -> FirewallRule:
    return FirewallRule(
        name=name,
        direction="input",
        action="accept",
        protocol=protocol,
        source=source,
        destination="any",
        destination_port=ports,
        interface_name=interface_name.strip(),
        priority=priority,
        enabled=True,
        description=f"{ATLASO_SERVICE_FIREWALL_RULE_MARKER} for {service}.",
    )


def _routing_firewall_rule(
    *,
    name: str,
    action: str,
    source_interface: str,
    source_networks: list[str],
    destination_networks: list[str],
    priority: int,
    description: str,
) -> FirewallRule:
    return FirewallRule(
        name=name,
        direction="forward",
        action=action,
        protocol="any",
        source="\n".join(source_networks or ["any"]),
        destination="\n".join(destination_networks or ["any"]),
        destination_port="",
        interface_name=source_interface,
        priority=priority,
        enabled=True,
        description=description,
    )


def _managed_rule_source(
    rule_name: str,
    interface_name: str,
    interface_networks: dict[str, str],
    source_groups_by_id: dict[str, dict],
    assignments: dict[str, str],
) -> str:
    group_id = assignments.get(rule_name, FIREWALL_ANY_SOURCE_GROUP_ID)
    group = source_groups_by_id.get(group_id) or source_groups_by_id.get(FIREWALL_ANY_SOURCE_GROUP_ID)
    if group:
        return source_group_to_rule_source(group, source_groups_by_id)
    return "any"


def dns_firewall_rules(
    dns_settings: DnsSettings,
    interface_networks: dict[str, str],
    source_groups_by_id: dict[str, dict] | None = None,
    assignments: dict[str, str] | None = None,
) -> list[FirewallRule]:
    if not dns_settings.enabled:
        return []
    source_groups_by_id = source_groups_by_id or {}
    assignments = assignments or {}
    generated_rules: list[FirewallRule] = []
    listen_interfaces = [item.strip() for item in dns_settings.listen_interface.replace(",", "\n").splitlines() if item.strip()]
    for index, interface_name in enumerate(listen_interfaces, start=1):
        for protocol_offset, protocol in enumerate(["tcp", "udp"]):
            rule_name = f"{_slug(interface_name)}-dns-{protocol}"
            generated_rules.append(
                FirewallRule(
                    name=rule_name,
                    direction="input",
                    action="accept",
                    protocol=protocol,
                    source=_managed_rule_source(rule_name, interface_name, interface_networks, source_groups_by_id, assignments),
                    destination="any",
                    destination_port="53",
                    interface_name=interface_name,
                    priority=40 + (index * 2) + protocol_offset,
                    enabled=True,
                    description=f"{ATLASO_DNS_FIREWALL_RULE_MARKER} for DNS listener {interface_name}.",
                )
            )
    return generated_rules


def _scope_network(scope: DhcpScope) -> str:
    try:
        return str(ip_network(f"{scope.site_address.strip()}/{scope.prefix_length}", strict=False))
    except ValueError:
        return scope.site_address.strip() or "any"


def _network_from_cidr(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(ip_network(value, strict=False))
    except ValueError:
        return ""


def _networks_from_cidrs(*values: str | None) -> list[str]:
    networks: list[str] = []
    for value in values:
        network = _network_from_cidr(value)
        if network and network not in networks:
            networks.append(network)
    return networks


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "dhcp-scope"


def _ordered_unique(values: list[str]) -> list[str]:
    ordered: list[str] = []
    for value in values:
        if value and value not in ordered:
            ordered.append(value)
    return ordered


def _source_group(group_id: str, name: str, entries: list[str], description: str, *, builtin: bool = False) -> dict:
    normalized_entries = _source_group_entries({"entries": entries}, ["any"])
    return {
        "id": group_id,
        "name": name,
        "entries": normalized_entries,
        "sources": normalized_entries,
        "description": description,
        "builtin": builtin,
    }


def _source_group_entries(group: dict | None, default_entries: list[str]) -> list[str]:
    group = group or {}
    raw_entries = group.get("entries")
    if raw_entries is None:
        raw_entries = group.get("sources")
    if isinstance(raw_entries, str):
        values = _split_source_group_entry_values(raw_entries)
    elif isinstance(raw_entries, list):
        values = [str(item).strip() for item in raw_entries if str(item).strip()]
    else:
        values = []
    normalized: list[str] = []
    for value in values or default_entries:
        item = str(value).strip()
        if item.lower() == "any":
            item = "any"
        elif item.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
            item = f"{FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX}{item[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):]}"
        normalized.append(item)
    return normalized


def _split_source_group_entry_values(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\n,]+", value) if item.strip()]


def _looks_like_source_group_reference(value: str) -> bool:
    return value.strip().startswith("@") or value.strip().lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX)


def _source_group_name_index(groups: dict[str, dict]) -> dict[str, str]:
    return {str(group.get("name", "")).strip().lower(): group_id for group_id, group in groups.items() if str(group.get("name", "")).strip()}


def _source_group_reference_target(value: str, groups_by_id: dict[str, dict], names: dict[str, str] | None = None) -> str:
    item = value.strip()
    if item.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
        group_id = item[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):]
        return group_id if group_id in groups_by_id else ""
    if item.startswith("@"):
        name_index = names or _source_group_name_index(groups_by_id)
        return name_index.get(item[1:].strip().lower(), "")
    return ""


def _expand_source_group_entries(group: dict | None, groups_by_id: dict[str, dict], stack: tuple[str, ...] = ()) -> list[str]:
    entries = _source_group_entries(group, ["any"])
    expanded: list[str] = []
    seen: set[str] = set()
    name_index = _source_group_name_index(groups_by_id)
    for entry in entries:
        normalized = entry.strip()
        if normalized.lower() == "any":
            return ["any"]
        target_id = _source_group_reference_target(normalized, groups_by_id, name_index)
        if target_id:
            if target_id in stack:
                continue
            nested_sources = _expand_source_group_entries(groups_by_id.get(target_id), groups_by_id, (*stack, target_id))
            if nested_sources == ["any"]:
                return ["any"]
            for source in nested_sources:
                if source not in seen:
                    seen.add(source)
                    expanded.append(source)
            continue
        if normalized not in seen:
            seen.add(normalized)
            expanded.append(normalized)
    return expanded or ["any"]


def _validate_source_group_cycles(groups: list[dict], groups_by_id: dict[str, dict], names: dict[str, str]) -> list[str]:
    errors: list[str] = []

    def visit(group_id: str, path: list[str]) -> None:
        if group_id in path:
            cycle_ids = [*path[path.index(group_id):], group_id]
            cycle_names = [str(groups_by_id[item].get("name") or item) for item in cycle_ids if item in groups_by_id]
            errors.append(f"Firewall groups cannot reference each other in a cycle: {' -> '.join(cycle_names)}.")
            return
        group = groups_by_id.get(group_id)
        if not group:
            return
        for entry in _source_group_entries(group, ["any"]):
            target_id = _source_group_reference_target(entry, groups_by_id, names)
            if target_id:
                visit(target_id, [*path, group_id])

    for group in groups:
        group_id = str(group.get("id", ""))
        if group_id:
            visit(group_id, [])
    return errors


def _rule_address_value(value: str, source_groups_by_id: dict[str, dict]) -> str:
    raw_value = value.strip()
    if not raw_value:
        return "any"
    target_id = _source_group_reference_target(raw_value, source_groups_by_id)
    if target_id:
        return "\n".join(_expand_source_group_entries(source_groups_by_id.get(target_id), source_groups_by_id))
    return raw_value.lower()


def _validate_rule_address_value(label: str, value: str, source_groups_by_id: dict[str, dict], names: dict[str, str]) -> list[str]:
    raw_value = value.strip()
    if not raw_value:
        return []
    target_id = _source_group_reference_target(raw_value, source_groups_by_id, names)
    if target_id:
        group = source_groups_by_id.get(target_id)
        return _validate_address_value(label, "\n".join(_expand_source_group_entries(group, source_groups_by_id)))
    if _looks_like_source_group_reference(raw_value):
        return [f"{label} references a firewall group that does not exist: {raw_value}."]
    return _validate_address_value(label, raw_value)


def _validate_rule_group_reference(label: str, value: str, source_groups_by_id: dict[str, dict]) -> str:
    raw_value = value.strip()
    if raw_value.lower() == "any":
        return ""
    if raw_value.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
        if _source_group_reference_target(raw_value, source_groups_by_id):
            return ""
        return f"{label} references a firewall group that does not exist: {raw_value}."
    return f"{label} must use Any or a firewall group."


def _split_address_values(value: str) -> list[str]:
    return [item.strip().lower() for item in re.split(r"[\n,]+", value) if item.strip()]


def _address_values_by_family(value: str) -> dict[int, list[str]]:
    family_values: dict[int, list[str]] = {4: [], 6: []}
    for item in _split_address_values(value):
        if item == "any":
            return family_values
        try:
            family = ip_network(item, strict=False).version
        except ValueError:
            continue
        if item not in family_values[family]:
            family_values[family].append(item)
    return family_values


def _validate_address_value(label: str, value: str) -> list[str]:
    normalized_values = _split_address_values(value)
    if not normalized_values:
        return []
    if "any" in normalized_values:
        return [] if normalized_values == ["any"] else [f"{label} can use 'any' only by itself."]
    families: set[int] = set()
    errors: list[str] = []
    for item in normalized_values:
        try:
            families.add(ip_network(item, strict=False).version)
        except ValueError:
            errors.append(f"{label} must be 'any' or valid IPv4/IPv6 addresses or CIDRs.")
    return errors
