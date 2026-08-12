"""Apply atomic desired-state updates for physical network interfaces."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    ApplianceSettings,
    CaSettings,
    DhcpReservation,
    DhcpScope,
    DhcpSettings,
    DnsRecord,
    DnsSettings,
    EsxNfsShare,
    EsxiPxeHost,
    KmsSettings,
    LdapSettings,
    NtpSettings,
    OidcProviderSettings,
    PhysicalInterface,
    Setting,
    VcfBackupSettings,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
    utcnow,
)
from atlaso.app.services.appliance_settings import (
    management_dhcp_dns_context,
    web_terminal_interface_options,
    web_terminal_interfaces_from_json,
    web_terminal_interfaces_to_json,
)
from atlaso.app.services.dnsmasq import (
    compact_dhcp_range_expression,
    join_addresses,
    join_interfaces,
    join_servers,
    parse_dhcp_range_expression,
    reservation_dns_record,
    split_addresses,
    split_interfaces,
    split_servers,
)
from atlaso.app.services.esxi_pxe import (
    ESXI_PXE_DEFAULT_HOSTNAME,
    ESXI_PXE_HOST_MANAGED_DESCRIPTION_PREFIX,
    ESXI_PXE_HTTP_PORT,
    ESXI_PXE_LISTEN_ADDRESS_KEY,
    ESXI_PXE_LISTEN_INTERFACE_KEY,
    esxi_pxe_boot_settings,
    save_esxi_pxe_boot_settings,
)
from atlaso.app.services.esx_storage import normalize_families as normalize_esx_storage_families
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
    normalize_ipv4_method,
)


DependentDnsRefresher = Callable[[Session, str | None], list[str]]


def _esxi_managed_host_id(description: str | None) -> int | None:
    """Return the ESXi PXE host identifier encoded in a managed-row marker.

    Args:
        description: Persisted DHCP-reservation ownership marker.
    """
    marker = str(description or "").strip()
    if not marker.startswith(ESXI_PXE_HOST_MANAGED_DESCRIPTION_PREFIX) or not marker.endswith("."):
        return None
    identifier = marker[len(ESXI_PXE_HOST_MANAGED_DESCRIPTION_PREFIX) : -1]
    if not identifier.isdecimal():
        return None
    return int(identifier)


def _replace_url_host(value: str, old_host: str, new_host: str) -> str:
    """Replace an exact URL host while preserving valid IP-literal syntax.

    Args:
        value: Absolute URL whose authority may use the old host.
        old_host: Exact current hostname or IP literal.
        new_host: Replacement hostname or IP literal.
    """
    try:
        parsed = urlsplit(value)
        if parsed.hostname != old_host:
            return value
        replacement = ip_address(new_host)
        rendered_host = f"[{replacement}]" if replacement.version == 6 else str(replacement)
        netloc = rendered_host
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except ValueError:
        return value


class PhysicalInterfaceUpdateError(ValueError):
    """Represent a rejected physical-interface desired-state update."""

    def __init__(self, detail: str, *, status_code: int = 422) -> None:
        """Initialize a domain validation error.

        Args:
            detail: Operator-facing reason the update was rejected.
            status_code: HTTP-compatible status used by transport adapters.
        """
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


@dataclass(frozen=True)
class PhysicalInterfaceUpdateResult:
    """Describe one committed physical-interface desired-state update."""

    interface: PhysicalInterface
    dependent_updates: tuple[str, ...]
    preserved_dhcp_dns: tuple[str, ...]


def _address_from_cidr(value: str | None) -> str:
    """Return the host address from a CIDR value.

    Args:
        value: Optional address and prefix to parse.
    """
    if not value:
        return ""
    try:
        return str(ip_interface(value).ip)
    except ValueError:
        return ""


def _prefix_from_cidr(value: str | None) -> int | None:
    """Return the prefix length from a CIDR value.

    Args:
        value: Optional address and prefix to parse.
    """
    if not value:
        return None
    try:
        return int(ip_interface(value).network.prefixlen)
    except ValueError:
        return None


def _interface_addresses_from_cidrs(ipv4_cidr: str | None, ipv6_cidr: str | None) -> list[str]:
    """Return unique host addresses from IPv4 and IPv6 CIDRs.

    Args:
        ipv4_cidr: Optional IPv4 address and prefix.
        ipv6_cidr: Optional IPv6 address and prefix.
    """
    addresses: list[str] = []
    for cidr in (ipv4_cidr, ipv6_cidr):
        address = _address_from_cidr(cidr)
        if address and address not in addresses:
            addresses.append(address)
    return addresses


def _service_bind_options(db: Session) -> list[dict[str, Any]]:
    """Return desired interfaces eligible for dependent service binding.

    Args:
        db: Active database session.
    """
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(
        select(VlanInterface)
        .where(VlanInterface.enabled.is_(True))
        .order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    interfaces_by_name = {interface.name: interface for interface in physical_interfaces}
    options: list[dict[str, Any]] = []
    for interface in physical_interfaces:
        role = normalize_interface_role(interface.role)
        mode = normalize_interface_mode(interface.mode)
        addresses = _interface_addresses_from_cidrs(interface.ip_cidr, interface.ipv6_cidr)
        if (
            interface.oper_state == "missing"
            or interface.admin_state != "up"
            or role in {"management", "unused"}
            or mode == "trunk"
            or not addresses
        ):
            continue
        options.append(
            {
                "name": interface.name,
                "addresses": addresses,
                "ipv4_address": _address_from_cidr(interface.ip_cidr),
                "ipv4_prefix": _prefix_from_cidr(interface.ip_cidr),
                "ipv6_address": _address_from_cidr(interface.ipv6_cidr),
                "ipv6_prefix": _prefix_from_cidr(interface.ipv6_cidr),
            }
        )
    for vlan in vlan_interfaces:
        parent = interfaces_by_name.get(vlan.parent_interface)
        role = normalize_interface_role(vlan.role)
        addresses = _interface_addresses_from_cidrs(vlan.ip_cidr, vlan.ipv6_cidr)
        if (
            parent is None
            or parent.oper_state == "missing"
            or parent.admin_state != "up"
            or normalize_interface_mode(parent.mode) != "trunk"
            or role in {"management", "unused"}
            or not addresses
        ):
            continue
        options.append(
            {
                "name": vlan.name,
                "addresses": addresses,
                "ipv4_address": _address_from_cidr(vlan.ip_cidr),
                "ipv4_prefix": _prefix_from_cidr(vlan.ip_cidr),
                "ipv6_address": _address_from_cidr(vlan.ipv6_cidr),
                "ipv6_prefix": _prefix_from_cidr(vlan.ipv6_cidr),
            }
        )
    return options


def _network_from_cidr(value: str | None):
    """Return a parsed network for a CIDR value when valid.

    Args:
        value: Optional address and prefix to parse.
    """
    if not value:
        return None
    try:
        return ip_network(value, strict=False)
    except ValueError:
        return None


def _address_family_from_scope(scope: DhcpScope) -> int:
    """Return the IP version represented by a DHCP scope.

    Args:
        scope: DHCP scope whose configured family is inspected.
    """
    return 6 if str(scope.address_family or "").strip().lower() == "ipv6" else 4


def _replace_interface_selection(raw_value: str | None, old_name: str, new_name: str) -> str:
    """Replace one interface token while preserving order and uniqueness.

    Args:
        raw_value: Persisted interface selection.
        old_name: Previous interface name to replace.
        new_name: Replacement interface name, or blank when removing it.
    """
    interfaces = split_interfaces(raw_value)
    if old_name != new_name:
        interfaces = [new_name if item == old_name else item for item in interfaces]
    return join_interfaces(interfaces)


def _derive_addresses_for_interfaces(
    selected_interfaces: list[str],
    options_by_name: dict[str, dict[str, Any]],
) -> str:
    """Derive listener addresses for the selected desired interfaces.

    Args:
        selected_interfaces: Ordered desired interface names.
        options_by_name: Eligible binding metadata keyed by interface name.
    """
    derived: list[str] = []
    for interface_name in selected_interfaces:
        option = options_by_name.get(interface_name)
        if not option:
            continue
        for address in option.get("addresses") or []:
            if address and address not in derived:
                derived.append(address)
    return join_addresses(derived)


def _rebase_address_in_network(value: str, old_network, new_network) -> str:
    """Preserve an address offset while moving it between equivalent networks.

    Args:
        value: Address whose host offset should be preserved.
        old_network: Source IP network.
        new_network: Destination IP network.
    """
    if not value or old_network is None or new_network is None or old_network.version != new_network.version:
        return value
    try:
        address = ip_address(value)
    except ValueError:
        return value
    if address not in old_network:
        return value
    offset = int(address) - int(old_network.network_address)
    if offset < 0 or offset >= new_network.num_addresses:
        return value
    return str(ip_address(int(new_network.network_address) + offset))


def _address_in_network(value: str | None, network) -> bool:
    """Return whether an address belongs to a parsed network.

    Args:
        value: Optional address to inspect.
        network: Parsed network that should contain the address.
    """
    if not value or network is None:
        return False
    try:
        return ip_address(value) in network
    except ValueError:
        return False


def _primary_listen_address(raw_address: str | None) -> str:
    """Return the first configured listener address.

    Args:
        raw_address: Persisted listener-address selection.
    """
    addresses = split_addresses(raw_address)
    return addresses[0] if addresses else ""


def refresh_interface_dependent_addresses(
    db: Session,
    *,
    old_name: str,
    new_name: str,
    old_ip_cidr: str | None,
    old_ipv6_cidr: str | None,
    actor: str | None = None,
    dns_refresher: DependentDnsRefresher | None = None,
) -> list[str]:
    """Refresh desired service, DHCP, PXE, and DNS state after an interface change.

    The caller owns the transaction. This function never commits, so every dependent row can be
    rolled back together with the interface row.

    Args:
        db: Active database session owned by the caller's transaction.
        old_name: Previous interface name.
        new_name: Current interface name, or blank when deleting the interface.
        old_ip_cidr: Previous IPv4 address and prefix.
        old_ipv6_cidr: Previous IPv6 address and prefix.
        actor: Optional audit actor passed to DNS reconciliation.
        dns_refresher: Optional callback for app-owned service aliases.
    """
    options_by_name = {str(option["name"]): option for option in _service_bind_options(db)}
    physical_parent = db.execute(
        select(PhysicalInterface).where(
            PhysicalInterface.name.in_([name for name in (old_name, new_name) if name])
        )
    ).scalars().first()
    affected_interface_names = [old_name]
    if physical_parent is not None:
        affected_interface_names.extend(
            vlan.name
            for vlan in db.execute(
                select(VlanInterface)
                .where(VlanInterface.parent_interface == physical_parent.name)
                .order_by(VlanInterface.vlan_id)
            ).scalars()
            if vlan.name not in affected_interface_names
        )

    def selection_replacements(eligible_names: set[str]) -> dict[str, str]:
        """Return replacements for every directly or transitively affected interface.

        Args:
            eligible_names: Interface names that remain valid for the dependent feature.
        """
        replacements: dict[str, str] = {}
        for affected_name in affected_interface_names:
            candidate = new_name if affected_name == old_name else affected_name
            replacements[affected_name] = candidate if candidate in eligible_names else ""
        return replacements

    def reconcile_selection(raw_value: str | None, replacements: Mapping[str, str]) -> str:
        """Apply ordered interface-token replacements to one persisted selection.

        Args:
            raw_value: Persisted newline- or comma-separated interface selection.
            replacements: Replacement interface name keyed by affected token.
        """
        updated = str(raw_value or "")
        for affected_name, replacement in replacements.items():
            updated = _replace_interface_selection(updated, affected_name, replacement)
        return updated

    service_replacements = selection_replacements(set(options_by_name))
    previous_esxi_boot = esxi_pxe_boot_settings(db)
    raw_esxi_listen_interface = db.execute(
        select(Setting).where(Setting.key == ESXI_PXE_LISTEN_INTERFACE_KEY)
    ).scalar_one_or_none()
    raw_esxi_listen_address = db.execute(
        select(Setting).where(Setting.key == ESXI_PXE_LISTEN_ADDRESS_KEY)
    ).scalar_one_or_none()
    old_addresses = {
        address
        for address in _interface_addresses_from_cidrs(old_ip_cidr, old_ipv6_cidr)
        if address
    }
    old_networks = {4: _network_from_cidr(old_ip_cidr), 6: _network_from_cidr(old_ipv6_cidr)}
    new_option = options_by_name.get(new_name, {})
    new_addresses = {
        4: str(new_option.get("ipv4_address") or ""),
        6: str(new_option.get("ipv6_address") or ""),
    }
    new_prefixes = {
        4: new_option.get("ipv4_prefix"),
        6: new_option.get("ipv6_prefix"),
    }
    new_networks = {
        4: _network_from_cidr(f"{new_addresses[4]}/{new_prefixes[4]}")
        if new_addresses[4] and new_prefixes[4] is not None
        else None,
        6: _network_from_cidr(f"{new_addresses[6]}/{new_prefixes[6]}")
        if new_addresses[6] and new_prefixes[6] is not None
        else None,
    }
    changed: list[str] = []

    def mark_changed(label: str) -> None:
        """Record one changed dependent unit.

        Args:
            label: Operator-facing dependent unit name.
        """
        if label not in changed:
            changed.append(label)

    def update_listener_rows(model, label: str) -> None:
        """Refresh listeners stored by one dependent settings model.

        Args:
            model: SQLAlchemy settings model to reconcile.
            label: Operator-facing dependent unit name.
        """
        for row in db.execute(select(model)).scalars().all():
            selected = split_interfaces(getattr(row, "listen_interface", ""))
            if not any(name in selected for name in affected_interface_names):
                continue
            updated_interfaces = reconcile_selection(
                getattr(row, "listen_interface", ""),
                service_replacements,
            )
            updated_addresses = _derive_addresses_for_interfaces(
                split_interfaces(updated_interfaces),
                options_by_name,
            )
            if model is CaSettings and not split_addresses(updated_addresses):
                updated_interfaces = ""
            if (
                bool(getattr(row, "enabled", False))
                and model is not CaSettings
                and not split_addresses(updated_addresses)
            ):
                raise PhysicalInterfaceUpdateError(
                    f"Enabled {label} still depends on {old_name}. "
                    "Disable or move the service binding before removing its listen address."
                )
            if (
                updated_interfaces != getattr(row, "listen_interface", "")
                or updated_addresses != (getattr(row, "listen_address", "") or "")
            ):
                row.listen_interface = updated_interfaces
                row.listen_address = updated_addresses
                if hasattr(row, "updated_at"):
                    row.updated_at = utcnow()
                db.add(row)
                mark_changed(label)

    for model, label in [
        (DnsSettings, "DNS"),
        (NtpSettings, "NTP / NTS"),
        (CaSettings, "Certificate Authority"),
        (KmsSettings, "KMS"),
        (LdapSettings, "LDAP"),
        (OidcProviderSettings, "OIDC"),
        (VcfBackupSettings, "VCF Backups"),
        (VcfOfflineDepotSettings, "VCF Offline Depot"),
        (VcfPrivateRegistrySettings, "VCF Private Registry"),
    ]:
        update_listener_rows(model, label)

    physical_interfaces = db.execute(
        select(PhysicalInterface).order_by(PhysicalInterface.name)
    ).scalars().all()
    vlan_interfaces = db.execute(
        select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    terminal_names = {
        str(option.get("name") or "")
        for option in web_terminal_interface_options(physical_interfaces, vlan_interfaces)
        if option.get("name")
    }
    terminal_replacements = selection_replacements(terminal_names)
    appliance_settings = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    if appliance_settings is not None:
        terminal_selection = web_terminal_interfaces_from_json(
            appliance_settings.web_terminal_interfaces_json
        )
        if any(name in terminal_selection for name in affected_interface_names):
            updated_terminal_selection = split_interfaces(
                reconcile_selection(
                    join_interfaces(terminal_selection),
                    terminal_replacements,
                )
            )
            updated_terminal_json = web_terminal_interfaces_to_json(
                updated_terminal_selection
            )
            if updated_terminal_json != appliance_settings.web_terminal_interfaces_json:
                appliance_settings.web_terminal_interfaces_json = updated_terminal_json
                appliance_settings.updated_at = utcnow()
                db.add(appliance_settings)
                mark_changed("Appliance Settings")

    for share in db.execute(select(EsxNfsShare)).scalars().all():
        if share.interface_name not in affected_interface_names:
            continue
        replacement_name = service_replacements.get(share.interface_name, "")
        replacement_option = options_by_name.get(replacement_name)
        if share.enabled:
            if not replacement_name or replacement_option is None:
                raise PhysicalInterfaceUpdateError(
                    f"Enabled ESX Storage datastore {share.datastore_name} still depends on "
                    f"{share.interface_name}. Disable or move the datastore binding before "
                    "making that interface unavailable."
                )
            try:
                families = normalize_esx_storage_families(share.address_families)
            except ValueError as exc:
                raise PhysicalInterfaceUpdateError(
                    f"Enabled ESX Storage datastore {share.datastore_name} has invalid address families."
                ) from exc
            missing_families = [
                family
                for family in families
                if not replacement_option.get(f"{family}_address")
            ]
            if missing_families:
                family_labels = ", ".join(family.upper() for family in missing_families)
                raise PhysicalInterfaceUpdateError(
                    f"Enabled ESX Storage datastore {share.datastore_name} requires "
                    f"{family_labels} on {share.interface_name}. Disable that address family "
                    "or move the datastore binding before removing its interface address."
                )
        if replacement_name != share.interface_name:
            share.interface_name = replacement_name
            share.updated_at = utcnow()
            db.add(share)
            mark_changed("ESX Storage")

    dns_settings = db.execute(select(DnsSettings)).scalar_one_or_none()
    ntp_settings = db.execute(select(NtpSettings)).scalar_one_or_none()
    dns_bound = bool(
        dns_settings
        and dns_settings.enabled
        and new_name in split_interfaces(dns_settings.listen_interface)
    )
    ntp_bound = bool(
        ntp_settings
        and ntp_settings.enabled
        and new_name in split_interfaces(ntp_settings.listen_interface)
    )
    dependent_address_replacements: dict[str, str] = {}

    def update_dhcp_scope(scope: DhcpScope | DhcpSettings, label: str) -> None:
        """Refresh one DHCP binding and its address-dependent values.

        Args:
            scope: DHCP scope or legacy settings row to reconcile.
            label: Operator-facing dependent unit name.
        """
        bound_name = getattr(scope, "interface_name", "")
        if bound_name not in affected_interface_names:
            return
        if bound_name != old_name:
            replacement_name = service_replacements.get(bound_name, "")
            if replacement_name != bound_name:
                scope.interface_name = replacement_name
                if hasattr(scope, "updated_at"):
                    scope.updated_at = utcnow()
                db.add(scope)
                mark_changed(label)
            return
        family = _address_family_from_scope(scope) if isinstance(scope, DhcpScope) else 4
        new_address = new_addresses[family]
        if not new_address:
            if old_networks[family] is not None and bool(getattr(scope, "enabled", False)):
                family_label = "IPv6" if family == 6 else "IPv4"
                dependency_label = (
                    f"DHCP scope {scope.name}"
                    if isinstance(scope, DhcpScope)
                    else "DHCP settings"
                )
                dependency_verb = "depends" if isinstance(scope, DhcpScope) else "depend"
                raise PhysicalInterfaceUpdateError(
                    f"Enabled {dependency_label} still {dependency_verb} on "
                    f"{old_name} {family_label}. "
                    "Disable or move the DHCP binding before removing that interface address."
                )
            if new_name != old_name:
                scope.interface_name = new_name
                if hasattr(scope, "updated_at"):
                    scope.updated_at = utcnow()
                db.add(scope)
                mark_changed(label)
            return
        scope_site_address = getattr(scope, "site_address", "")
        scope_prefix = getattr(scope, "prefix_length", None)
        scope_network = (
            _network_from_cidr(f"{scope_site_address}/{scope_prefix}")
            if scope_site_address and scope_prefix is not None
            else None
        )
        old_network = old_networks[family]
        if old_network is None or (
            scope_site_address and not _address_in_network(scope_site_address, old_network)
        ):
            old_network = scope_network
        new_network = new_networks[family]
        stale_addresses = set(old_addresses)
        before = (
            getattr(scope, "interface_name", ""),
            getattr(scope, "site_address", ""),
            getattr(scope, "prefix_length", None),
            getattr(scope, "range_expression", ""),
            getattr(scope, "dns_server", ""),
            getattr(scope, "ntp_server", ""),
        )
        parsed_range_errors, parsed_ranges = (
            parse_dhcp_range_expression(scope) if isinstance(scope, DhcpScope) else ([], [])
        )
        scope.interface_name = new_name
        site_address_is_stale = bool(
            scope_site_address
            and new_network
            and not _address_in_network(scope_site_address, new_network)
        )
        site_address_changed = bool(
            not getattr(scope, "site_address", "")
            or getattr(scope, "site_address", "") in old_addresses
            or site_address_is_stale
        )
        if site_address_changed:
            scope.site_address = new_address
            if scope_site_address:
                stale_addresses.add(scope_site_address)
                if new_address and scope_site_address != new_address:
                    dependent_address_replacements[scope_site_address] = new_address
        if new_prefixes[family] is not None and (
            not getattr(scope, "prefix_length", None)
            or getattr(scope, "prefix_length", None)
            == (old_network.prefixlen if old_network else None)
        ):
            scope.prefix_length = int(new_prefixes[family])
        if isinstance(scope, DhcpScope) and not parsed_range_errors and parsed_ranges:
            resulting_scope_network = _network_from_cidr(
                f"{scope.site_address}/{scope.prefix_length}"
            )
            range_source_network = scope_network or old_network
            range_target_network = resulting_scope_network or new_network
            rebased_ranges: list[str] = []
            for start_address, end_address in parsed_ranges:
                rebased_start = _rebase_address_in_network(
                    str(start_address), range_source_network, range_target_network
                )
                rebased_end = _rebase_address_in_network(
                    str(end_address), range_source_network, range_target_network
                )
                if not _address_in_network(
                    rebased_start, range_target_network
                ) or not _address_in_network(
                    rebased_end,
                    range_target_network,
                ):
                    raise PhysicalInterfaceUpdateError(
                        f"DHCP scope {scope.name} range cannot fit within the updated "
                        f"{range_target_network.with_prefixlen} scope network."
                    )
                rebased_ranges.append(
                    rebased_start
                    if rebased_start == rebased_end
                    else f"{rebased_start}-{rebased_end}"
                )
            scope.range_expression = ", ".join(rebased_ranges)
            scope.range_expression = compact_dhcp_range_expression(scope)
        if (
            not getattr(scope, "dns_server", "")
            or getattr(scope, "dns_server", "") in stale_addresses
        ):
            scope.dns_server = (
                new_address
                if dns_bound or getattr(scope, "dns_server", "") in stale_addresses
                else getattr(scope, "dns_server", "")
            )
        if isinstance(scope, DhcpScope) and (
            not scope.ntp_server or scope.ntp_server in stale_addresses
        ):
            scope.ntp_server = (
                new_address
                if ntp_bound or scope.ntp_server in stale_addresses
                else scope.ntp_server
            )
        after = (
            getattr(scope, "interface_name", ""),
            getattr(scope, "site_address", ""),
            getattr(scope, "prefix_length", None),
            getattr(scope, "range_expression", ""),
            getattr(scope, "dns_server", ""),
            getattr(scope, "ntp_server", ""),
        )
        if before != after:
            if hasattr(scope, "updated_at"):
                scope.updated_at = utcnow()
            db.add(scope)
            mark_changed(label)

    scope_rows = db.execute(select(DhcpScope).order_by(DhcpScope.id)).scalars().all()
    scope_networks_before = {
        scope.id: _network_from_cidr(f"{scope.site_address}/{scope.prefix_length}")
        for scope in scope_rows
        if scope.id is not None and scope.site_address and scope.prefix_length is not None
    }
    if not scope_rows:
        for settings in db.execute(select(DhcpSettings)).scalars().all():
            update_dhcp_scope(settings, "DHCP")
    for scope in scope_rows:
        if (
            scope.enabled
            and scope.interface_name in affected_interface_names
            and not service_replacements.get(scope.interface_name)
        ):
            raise PhysicalInterfaceUpdateError(
                f"Enabled DHCP scope {scope.name} still depends on {scope.interface_name}. "
                "Disable or move the DHCP binding before making that interface unavailable."
            )
        update_dhcp_scope(scope, "DHCP")

    enabled_scope_networks_after = [
        (scope.id, network)
        for scope in scope_rows
        if scope.enabled is not False
        and (
            network := _network_from_cidr(
                f"{scope.site_address}/{scope.prefix_length}"
            )
        )
        is not None
    ]
    changed_scope_networks = [
        (scope.id, old_network, new_network)
        for scope in scope_rows
        if scope.enabled is not False
        and (old_network := scope_networks_before.get(scope.id)) is not None
        and (
            new_network := _network_from_cidr(
                f"{scope.site_address}/{scope.prefix_length}"
            )
        )
        is not None
        and old_network != new_network
    ]
    reservations = (
        db.execute(
            select(DhcpReservation).where(DhcpReservation.enabled.is_(True))
        ).scalars().all()
        if changed_scope_networks
        else []
    )
    for reservation in reservations:
        try:
            reserved_address = ip_address(reservation.ip_address)
        except ValueError:
            continue
        if any(
            reserved_address in network
            for _scope_id, network in enabled_scope_networks_after
        ):
            continue
        applicable_scope_moves: list[tuple[int | None, str]] = []
        for scope_id, old_network, new_network in changed_scope_networks:
            if reserved_address.version != old_network.version or reserved_address not in old_network:
                continue
            candidate = _rebase_address_in_network(
                str(reserved_address),
                old_network,
                new_network,
            )
            if _address_in_network(candidate, new_network):
                applicable_scope_moves.append((scope_id, candidate))
        if len(applicable_scope_moves) != 1:
            raise PhysicalInterfaceUpdateError(
                f"Enabled DHCP reservation {reservation.hostname} cannot be mapped unambiguously "
                "into the updated DHCP IP zones. Move or disable the reservation before changing "
                "the interface network."
            )
        source_scope_id, candidate_address = applicable_scope_moves[0]
        destination_scope_ids = [
            scope_id
            for scope_id, network in enabled_scope_networks_after
            if _address_in_network(candidate_address, network)
        ]
        if destination_scope_ids != [source_scope_id]:
            raise PhysicalInterfaceUpdateError(
                f"Enabled DHCP reservation {reservation.hostname} cannot be mapped unambiguously "
                "into the updated DHCP IP zones. Move or disable the reservation before changing "
                "the interface network."
            )
        previous_address = reservation.ip_address
        reservation.ip_address = candidate_address
        db.add(reservation)
        mark_changed("DHCP")
        managed_host_id = _esxi_managed_host_id(reservation.description)
        if managed_host_id is not None:
            managed_host = db.get(EsxiPxeHost, managed_host_id)
            reservation_hostname = str(reservation.hostname or "").strip().strip(".").lower()
            managed_hostname = (
                str(managed_host.hostname or "").strip().strip(".").lower()
                if managed_host is not None
                else ""
            )
            hostname_matches = bool(
                managed_hostname
                and (
                    reservation_hostname == managed_hostname
                    or (
                        "." not in managed_hostname
                        and reservation_hostname.startswith(f"{managed_hostname}.")
                    )
                )
            )
            if (
                managed_host is None
                or managed_host.enabled is False
                or not hostname_matches
                or str(managed_host.mac_address or "").strip().lower()
                != str(reservation.mac_address or "").strip().lower()
                or str(managed_host.ip_address or "").strip() != previous_address
            ):
                raise PhysicalInterfaceUpdateError(
                    f"Enabled DHCP reservation {reservation.hostname} has an inconsistent "
                    "ESXi PXE ownership marker. Repair or disable the reservation before "
                    "changing the interface network."
                )
            managed_host.ip_address = reservation.ip_address
            managed_host.updated_at = utcnow()
            db.add(managed_host)
            mark_changed("ESXi PXE")
        generated_description = f"Created from DHCP reservation for {reservation.mac_address}."
        owned_description = (
            str(reservation.description or "").strip()
            if managed_host_id is not None
            else generated_description
        )
        record_values = reservation_dns_record(reservation, scope_rows)
        if record_values is None:
            continue
        expected_hostname, expected_type, _expected_address = record_values
        for record in db.execute(
            select(DnsRecord).where(
                DnsRecord.address == previous_address,
                DnsRecord.description == owned_description,
                DnsRecord.hostname == expected_hostname,
                DnsRecord.record_type == expected_type,
            )
        ).scalars().all():
            collision = db.execute(
                select(DnsRecord).where(
                    DnsRecord.id != record.id,
                    DnsRecord.hostname == expected_hostname,
                    DnsRecord.record_type == expected_type,
                    DnsRecord.address == reservation.ip_address,
                )
            ).scalar_one_or_none()
            if collision is not None:
                raise PhysicalInterfaceUpdateError(
                    f"DHCP reservation {reservation.hostname} cannot move its generated DNS "
                    "record because the destination address already exists. Resolve the DNS "
                    "conflict before changing the interface network."
                )
            record.address = reservation.ip_address
            db.add(record)
            mark_changed("DNS")

    esxi_boot = esxi_pxe_boot_settings(db)
    esxi_interfaces = split_interfaces(str(esxi_boot.get("listen_interface") or ""))
    if any(name in esxi_interfaces for name in affected_interface_names):
        updated_interfaces = reconcile_selection(
            str(esxi_boot.get("listen_interface") or ""),
            service_replacements,
        )
        updated_addresses = _derive_addresses_for_interfaces(
            split_interfaces(updated_interfaces),
            options_by_name,
        )
        if (
            bool(esxi_boot.get("enabled"))
            and not split_addresses(updated_addresses)
        ):
            raise PhysicalInterfaceUpdateError(
                f"Enabled ESXi PXE still depends on {old_name}. "
                "Disable or move the Network Boot/PXE binding before removing its listen address."
            )
        stale_boot_addresses = split_addresses(
            str(previous_esxi_boot.get("listen_address") or "")
        )
        native_uefi_http_url = str(esxi_boot.get("native_uefi_http_url") or "")
        replacement_address = _primary_listen_address(updated_addresses)
        direct_address_replacements = {
            stale_address: new_addresses[family] or replacement_address
            for family, stale_address in (
                (4, _address_from_cidr(old_ip_cidr)),
                (6, _address_from_cidr(old_ipv6_cidr)),
            )
            if stale_address
        }
        direct_address_replacements.update(dependent_address_replacements)
        for stale_address in stale_boot_addresses:
            mapped_address = direct_address_replacements.get(stale_address, "")
            if mapped_address and stale_address != mapped_address:
                native_uefi_http_url = _replace_url_host(
                    native_uefi_http_url,
                    stale_address,
                    mapped_address,
                )
        if (
            updated_interfaces != str(esxi_boot.get("listen_interface") or "")
            or updated_addresses != str(esxi_boot.get("listen_address") or "")
            or updated_interfaces
            != str(previous_esxi_boot.get("listen_interface") or "")
            or updated_addresses != str(previous_esxi_boot.get("listen_address") or "")
            or updated_interfaces
            != (raw_esxi_listen_interface.value if raw_esxi_listen_interface else "")
            or updated_addresses
            != (raw_esxi_listen_address.value if raw_esxi_listen_address else "")
            or native_uefi_http_url
            != str(esxi_boot.get("native_uefi_http_url") or "")
        ):
            save_esxi_pxe_boot_settings(
                db,
                enabled=bool(esxi_boot.get("enabled")),
                hostname=str(esxi_boot.get("hostname") or ESXI_PXE_DEFAULT_HOSTNAME),
                listen_interface=updated_interfaces,
                listen_address=updated_addresses,
                dhcp_scope_ids=list(esxi_boot.get("dhcp_scope_ids") or []),
                tftp_root=str(esxi_boot.get("tftp_root") or ""),
                http_port=int(esxi_boot.get("http_port") or ESXI_PXE_HTTP_PORT),
                bios_bootfile=str(esxi_boot.get("bios_bootfile") or ""),
                uefi_bootfile=str(esxi_boot.get("uefi_bootfile") or ""),
                native_uefi_http_enabled=bool(
                    esxi_boot.get("native_uefi_http_enabled")
                ),
                native_uefi_http_url=native_uefi_http_url,
            )
            mark_changed("ESXi PXE")

    if dns_refresher is not None:
        for label in dns_refresher(db, actor):
            mark_changed(label)
    return changed


def _preserve_management_dhcp_dns_on_static_conversion(
    db: Session,
    interface: PhysicalInterface,
    *,
    new_role: str,
    old_ipv4_method: str,
    new_ipv4_method: str,
) -> list[str]:
    """Preserve observed DHCP DNS when management moves to static IPv4.

    Args:
        db: Active database session.
        interface: Management interface being converted.
        new_role: Normalized desired interface role.
        old_ipv4_method: Previous normalized IPv4 method.
        new_ipv4_method: Desired normalized IPv4 method.
    """
    if (
        new_role != "management"
        or old_ipv4_method != "dhcp"
        or new_ipv4_method != "static"
    ):
        return []
    _management, observed_servers = management_dhcp_dns_context([interface])
    if not observed_servers:
        return []
    preserved: list[str] = []
    appliance_settings = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    dns_settings = db.execute(select(DnsSettings)).scalar_one_or_none()
    if (
        appliance_settings is not None
        and dns_settings is not None
        and not dns_settings.enabled
        and not split_servers(appliance_settings.external_dns_servers)
    ):
        appliance_settings.external_dns_servers = join_servers(observed_servers)
        appliance_settings.updated_at = utcnow()
        db.add(appliance_settings)
        preserved.append("appliance resolver DNS")
    if dns_settings is not None and not split_servers(dns_settings.upstream_servers):
        dns_settings.upstream_servers = join_servers(observed_servers)
        dns_settings.updated_at = utcnow()
        db.add(dns_settings)
        preserved.append("DNS service forwarders")
    return preserved


def _parse_cidr(value: Any, version: int, field_name: str) -> str | None:
    """Normalize and validate an optional interface CIDR.

    Args:
        value: Candidate CIDR value.
        version: Required IP version.
        field_name: Operator-facing field name used in validation errors.
    """
    candidate = str(value or "").strip()
    if not candidate:
        return None
    try:
        parsed = ip_interface(candidate)
    except ValueError as exc:
        raise PhysicalInterfaceUpdateError(
            f"{field_name} must be a valid address and prefix."
        ) from exc
    if parsed.version != version:
        family = "IPv4" if version == 4 else "IPv6"
        raise PhysicalInterfaceUpdateError(
            f"{field_name} must use an {family} address and prefix."
        )
    return candidate


def update_physical_interface_desired_state(
    db: Session,
    interface: PhysicalInterface,
    changes: Mapping[str, Any],
    *,
    dns_refresher: DependentDnsRefresher | None = None,
) -> PhysicalInterfaceUpdateResult:
    """Validate, reconcile, and atomically commit one physical-interface update.

    Args:
        db: Active database session.
        interface: Persisted physical interface to update.
        changes: Supplied desired-state fields and values.
        dns_refresher: Optional callback for app-owned service aliases.
    """
    supported_fields = {
        "role",
        "mode",
        "ipv4_method",
        "ip_cidr",
        "gateway",
        "ipv6_enabled",
        "ipv6_cidr",
        "ipv6_gateway",
        "mtu",
        "admin_state",
        "access_management_ui_enabled",
    }
    unknown_fields = sorted(set(changes) - supported_fields)
    if unknown_fields:
        raise PhysicalInterfaceUpdateError(
            f"Unsupported physical interface field{'s' if len(unknown_fields) != 1 else ''}: "
            f"{', '.join(unknown_fields)}."
        )

    try:
        new_mode = normalize_interface_mode(str(changes.get("mode", interface.mode) or ""))
        vlan_count = db.scalar(
            select(func.count())
            .select_from(VlanInterface)
            .where(VlanInterface.parent_interface == interface.name)
        ) or 0
        if new_mode != "trunk" and vlan_count:
            raise PhysicalInterfaceUpdateError(
                f"{interface.name} is the parent of {vlan_count} VLAN "
                f"interface{'s' if vlan_count != 1 else ''}. Move or delete those VLANs before "
                "changing the link type.",
                status_code=409,
            )

        old_role = normalize_interface_role(interface.role)
        role_value = (
            "unused"
            if new_mode == "trunk"
            else normalize_interface_role(str(changes.get("role", interface.role) or ""))
        )
        management_ui_value = changes.get(
            "access_management_ui_enabled",
            interface.access_management_ui_enabled,
        )
        if not isinstance(management_ui_value, bool):
            raise PhysicalInterfaceUpdateError(
                "access_management_ui_enabled must be a boolean."
            )
        if (
            old_role == "management"
            and role_value == "access"
            and "access_management_ui_enabled" not in changes
        ):
            management_ui_value = True
        if role_value == "management" or new_mode == "trunk":
            management_ui_value = False
        if management_ui_value and role_value != "access":
            raise PhysicalInterfaceUpdateError(
                "Management UI exposure is available only for an access-role interface."
            )

        ipv4_method_value = (
            "static"
            if new_mode == "trunk"
            else normalize_ipv4_method(
                str(changes.get("ipv4_method", interface.ipv4_method) or "")
            )
        )
        if ipv4_method_value == "dhcp" and role_value != "management":
            raise PhysicalInterfaceUpdateError(
                "IPv4 DHCP is available only for the management interface."
            )
        requested_ip = changes.get("ip_cidr", interface.ip_cidr)
        ip_value = None
        if new_mode != "trunk" and ipv4_method_value == "static":
            ip_value = _parse_cidr(requested_ip, 4, "ip_cidr")

        gateway_value = str(changes.get("gateway", interface.gateway) or "").strip()
        if role_value != "management" or ipv4_method_value != "static" or new_mode == "trunk":
            gateway_value = ""
        if gateway_value:
            if not ip_value:
                raise PhysicalInterfaceUpdateError(
                    "IPv4 gateway is available only for a management interface using static IPv4."
                )
            try:
                parsed_gateway = ip_address(gateway_value)
                parsed_interface = ip_interface(ip_value)
            except ValueError as exc:
                raise PhysicalInterfaceUpdateError(
                    "gateway must be a valid IPv4 address."
                ) from exc
            if parsed_gateway.version != 4:
                raise PhysicalInterfaceUpdateError("gateway must be an IPv4 address.")
            if parsed_gateway not in parsed_interface.network:
                raise PhysicalInterfaceUpdateError(
                    f"gateway must be on-link for {ip_value}."
                )
            if parsed_gateway == parsed_interface.ip:
                raise PhysicalInterfaceUpdateError(
                    "gateway cannot equal the management interface address."
                )

        ipv6_enabled_value = bool(
            changes.get("ipv6_enabled", interface.ipv6_enabled)
        ) and new_mode != "trunk"
        disabling_ipv6 = new_mode == "trunk" or (
            changes.get("ipv6_enabled") is False and "ipv6_enabled" in changes
        )
        requested_ipv6_cidr = changes.get(
            "ipv6_cidr",
            None if disabling_ipv6 else interface.ipv6_cidr,
        )
        requested_ipv6_gateway = changes.get(
            "ipv6_gateway",
            None if disabling_ipv6 else interface.ipv6_gateway,
        )
        if new_mode == "trunk":
            requested_ipv6_cidr = None
            requested_ipv6_gateway = None
        if not ipv6_enabled_value and (
            str(requested_ipv6_cidr or "").strip()
            or str(requested_ipv6_gateway or "").strip()
        ):
            raise PhysicalInterfaceUpdateError(
                "IPv6 CIDR and gateway must be blank while IPv6 is disabled."
            )
        ipv6_value = (
            _parse_cidr(requested_ipv6_cidr, 6, "ipv6_cidr")
            if ipv6_enabled_value
            else None
        )
        ipv6_gateway_value = str(requested_ipv6_gateway or "").strip()
        if role_value != "management" or not ipv6_enabled_value or not ipv6_value:
            ipv6_gateway_value = ""
        if ipv6_gateway_value:
            try:
                parsed_ipv6_gateway = ip_address(ipv6_gateway_value)
                parsed_ipv6_interface = ip_interface(ipv6_value)
            except ValueError as exc:
                raise PhysicalInterfaceUpdateError(
                    "ipv6_gateway must be a valid IPv6 address."
                ) from exc
            if parsed_ipv6_gateway.version != 6:
                raise PhysicalInterfaceUpdateError(
                    "ipv6_gateway must be an IPv6 address."
                )
            if (
                not parsed_ipv6_gateway.is_link_local
                and parsed_ipv6_gateway not in parsed_ipv6_interface.network
            ):
                raise PhysicalInterfaceUpdateError(
                    f"ipv6_gateway must be link-local or on-link for {ipv6_value}."
                )
            if parsed_ipv6_gateway == parsed_ipv6_interface.ip:
                raise PhysicalInterfaceUpdateError(
                    "ipv6_gateway cannot equal the management interface address."
                )

        mtu_value = changes.get("mtu", interface.mtu)
        if isinstance(mtu_value, bool) or not isinstance(mtu_value, int) or not 576 <= mtu_value <= 9000:
            raise PhysicalInterfaceUpdateError("mtu must be an integer from 576 through 9000.")
        admin_state_value = str(changes.get("admin_state", interface.admin_state) or "").strip().lower()
        if admin_state_value not in {"up", "down"}:
            raise PhysicalInterfaceUpdateError("Interface admin state must be up or down.")
        if role_value == "management" and admin_state_value != "up":
            raise PhysicalInterfaceUpdateError("The management interface must stay enabled.")

        old_ip_cidr = interface.ip_cidr
        old_ipv6_cidr = interface.ipv6_cidr
        old_ipv4_method = normalize_ipv4_method(interface.ipv4_method)
        preserved_dhcp_dns = _preserve_management_dhcp_dns_on_static_conversion(
            db,
            interface,
            new_role=role_value,
            old_ipv4_method=old_ipv4_method,
            new_ipv4_method=ipv4_method_value,
        )
        interface.role = role_value
        interface.mode = new_mode
        interface.ipv4_method = ipv4_method_value
        interface.ip_cidr = ip_value
        interface.gateway = gateway_value or None
        interface.ipv6_enabled = ipv6_enabled_value
        interface.ipv6_cidr = (
            ""
            if ipv6_enabled_value
            and "ipv6_cidr" in changes
            and not str(requested_ipv6_cidr or "").strip()
            else ipv6_value
        )
        interface.ipv6_gateway = ipv6_gateway_value or None
        interface.mtu = mtu_value
        interface.admin_state = admin_state_value
        interface.access_management_ui_enabled = management_ui_value
        interface.desired_state_source = "user"
        db.add(interface)
        db.flush()
        dependent_updates = refresh_interface_dependent_addresses(
            db,
            old_name=interface.name,
            new_name=interface.name,
            old_ip_cidr=old_ip_cidr,
            old_ipv6_cidr=old_ipv6_cidr,
            actor=None,
            dns_refresher=dns_refresher,
        )
        db.commit()
        db.refresh(interface)
        return PhysicalInterfaceUpdateResult(
            interface=interface,
            dependent_updates=tuple(dependent_updates),
            preserved_dhcp_dns=tuple(preserved_dhcp_dns),
        )
    except Exception:
        db.rollback()
        raise
