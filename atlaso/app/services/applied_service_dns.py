"""Preserve exact applied service DNS ownership inside caller-owned transactions."""

import json
from ipaddress import ip_address, ip_interface
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    CaSettings,
    DnsRecord,
    KmsSettings,
    LdapSettings,
    NtpSettings,
    OidcProviderSettings,
    PhysicalInterface,
    Setting,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
    utcnow,
)
from atlaso.app.services.appliance_settings import APPLIANCE_DNS_RECORD_DESCRIPTION
from atlaso.app.services.dnsmasq import split_interfaces
from atlaso.app.services.esx_storage import ESX_STORAGE_DNS_DESCRIPTION
from atlaso.app.services.esxi_pxe import (
    ESXI_PXE_DNS_RECORD_DESCRIPTION,
    esxi_pxe_boot_settings,
)
from atlaso.app.services.kms import KMS_DNS_RECORD_DESCRIPTION
from atlaso.app.services.ldap import LDAP_DNS_RECORD_DESCRIPTION
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
)
from atlaso.app.services.oidc import OIDC_DNS_RECORD_DESCRIPTION
from atlaso.app.services.service_dns_defaults import NTP_DNS_DESCRIPTION

APPLIANCE_APPLY_BASELINES_KEY = "appliance_apply.baselines.v1"
CA_PORTAL_DNS_DESCRIPTION = "Created from Certificate Authority portal endpoint."
VCF_DEPOT_DNS_DESCRIPTION = "Created from VCF Offline Depot endpoint."
VCF_REGISTRY_DNS_DESCRIPTION = "Created from VCF private registry endpoint."

def address_from_cidr(value: str | None) -> str:
    """Return address from cidr.

    Args:
        value: Candidate value consumed by address from CIDR.
    """
    if not value:
        return ""
    try:
        return str(ip_interface(value).ip)
    except ValueError:
        return ""


def prefix_from_cidr(value: str | None) -> int | None:
    """Return prefix from cidr.

    Args:
        value: Candidate value consumed by prefix from CIDR.
    """
    if not value:
        return None
    try:
        return int(ip_interface(value).network.prefixlen)
    except ValueError:
        return None


def interface_addresses_from_cidrs(ipv4_cidr: str | None, ipv6_cidr: str | None) -> list[str]:
    """Return interface addresses from cidrs.

    Args:
        ipv4_cidr: Ipv4 cidr consumed by interface addresses from cidrs.
        ipv6_cidr: Ipv6 cidr consumed by interface addresses from cidrs.
    """
    addresses: list[str] = []
    for cidr in (ipv4_cidr, ipv6_cidr):
        address = address_from_cidr(cidr)
        if address and address not in addresses:
            addresses.append(address)
    return addresses


def service_bind_options(db: Session) -> list[dict[str, Any]]:
    """Return service bind options.

    Args:
        db: Active database session.
    """
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(
        select(VlanInterface).where(VlanInterface.enabled.is_(True)).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    interfaces_by_name = {interface.name: interface for interface in physical_interfaces}
    options: list[dict[str, Any]] = []
    for interface in physical_interfaces:
        if interface.oper_state == "missing" or interface.admin_state != "up":
            continue
        mode = normalize_interface_mode(interface.mode)
        role = normalize_interface_role(interface.role)
        ipv4_cidr = interface.host_ip_cidr if interface.ipv4_method == "dhcp" else interface.ip_cidr
        ipv6_cidr = (interface.ipv6_cidr or interface.host_ipv6_cidr) if interface.ipv6_enabled else None
        addresses = interface_addresses_from_cidrs(
            ipv4_cidr, ipv6_cidr,
        )
        if role in {"management", "unused"} or mode == "trunk" or not addresses:
            continue
        address_label = " / ".join(addresses)
        options.append(
            {
                "name": interface.name,
                "label": f"{interface.name} - {role} / {mode} / {address_label}",
                "role": role,
                "address": addresses[0],
                "addresses": addresses,
                "ipv4_address": address_from_cidr(ipv4_cidr),
                "ipv4_prefix": prefix_from_cidr(ipv4_cidr),
                "ipv6_address": address_from_cidr(ipv6_cidr),
                "ipv6_prefix": prefix_from_cidr(ipv6_cidr),
            }
        )
    for vlan in vlan_interfaces:
        parent = interfaces_by_name.get(vlan.parent_interface)
        if parent and parent.oper_state == "missing":
            continue
        role = normalize_interface_role(vlan.role)
        addresses = interface_addresses_from_cidrs(vlan.ip_cidr, vlan.ipv6_cidr)
        if role in {"management", "unused"} or not addresses:
            continue
        address_label = " / ".join(addresses)
        options.append(
            {
                "name": vlan.name,
                "label": f"{vlan.name} - VLAN {vlan.vlan_id} on {vlan.parent_interface} / {role} / {address_label}",
                "role": role,
                "address": addresses[0],
                "addresses": addresses,
                "ipv4_address": address_from_cidr(vlan.ip_cidr),
                "ipv4_prefix": prefix_from_cidr(vlan.ip_cidr),
                "ipv6_address": address_from_cidr(vlan.ipv6_cidr),
                "ipv6_prefix": prefix_from_cidr(vlan.ipv6_cidr),
            }
        )
    return options


def primary_listen_interface(raw_interface: str | None) -> str:
    """Return primary listen interface.

    Args:
        raw_interface: Raw interface consumed by primary listen interface.
    """
    interfaces = split_interfaces(raw_interface)
    return interfaces[0] if interfaces else ""


def set_setting_value(db: Session, key: str, value: str) -> Setting:
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
    db.flush()
    return setting


def load_appliance_apply_baselines(db: Session, *, refresh: bool = False) -> dict[str, dict[str, Any]]:
    """Return appliance apply baselines.

    Args:
        db: Active database session.
        refresh: Reload the baseline row after writer admission.
    """
    row = db.scalar(select(Setting).where(Setting.key == APPLIANCE_APPLY_BASELINES_KEY)
                    .execution_options(populate_existing=refresh))
    raw_value = row.value if row is not None else ""
    if not raw_value:
        return {}
    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    baselines = {str(key): value for key, value in payload.items() if isinstance(value, dict)}
    return baselines


def save_appliance_apply_baselines(db: Session, baselines: dict[str, dict[str, Any]]) -> None:
    """Persist appliance apply baselines.

    Args:
        db: Active database session.
        baselines: Baselines supplied by the caller.
    """
    acquire_network_objects_write_lock(db)
    set_setting_value(db, APPLIANCE_APPLY_BASELINES_KEY, json.dumps(baselines, indent=2, sort_keys=True))


def owned_service_dns_records(db: Session, config: str) -> list[dict[str, str]]:
    """Capture exact owned records present in a rendered DNS snapshot.

    Args:
        db: Session used to prove record ownership.
        config: DNS configuration whose ownership is being recorded.
    """
    descriptions = {
        APPLIANCE_DNS_RECORD_DESCRIPTION, CA_PORTAL_DNS_DESCRIPTION,
        ESX_STORAGE_DNS_DESCRIPTION, ESXI_PXE_DNS_RECORD_DESCRIPTION,
        KMS_DNS_RECORD_DESCRIPTION, LDAP_DNS_RECORD_DESCRIPTION,
        NTP_DNS_DESCRIPTION, OIDC_DNS_RECORD_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION, VCF_REGISTRY_DNS_DESCRIPTION,
    }
    from atlaso.app.services.reverse_proxy_publication import DNS_OWNER_PREFIX

    descriptions.update(str(row.description) for row in db.scalars(select(DnsRecord))
                        if (row.description or "").startswith(DNS_OWNER_PREFIX))
    directives = {line.removeprefix("# atlaso-authoritative-config: ") for line in config.splitlines()}
    service_interfaces = {}
    for model, description in (
        (CaSettings, CA_PORTAL_DNS_DESCRIPTION), (KmsSettings, KMS_DNS_RECORD_DESCRIPTION),
        (LdapSettings, LDAP_DNS_RECORD_DESCRIPTION), (OidcProviderSettings, OIDC_DNS_RECORD_DESCRIPTION),
        (NtpSettings, NTP_DNS_DESCRIPTION), (VcfOfflineDepotSettings, VCF_DEPOT_DNS_DESCRIPTION),
        (VcfPrivateRegistrySettings, VCF_REGISTRY_DNS_DESCRIPTION),
    ):
        settings = db.scalars(select(model)).first()
        if settings is not None:
            selected = split_interfaces(getattr(settings, "listen_interface", None))
            if len(selected) == 1:
                service_interfaces[description] = selected[0]
    service_interfaces[ESXI_PXE_DNS_RECORD_DESCRIPTION] = primary_listen_interface(str(esxi_pxe_boot_settings(db).get("listen_interface") or ""))
    explicit_ptrs = {row.hostname for row in db.scalars(select(DnsRecord).where(DnsRecord.record_type == "PTR", DnsRecord.enabled.is_(True)))}
    address_sources = {address: option["name"] for option in service_bind_options(db) for address in option["addresses"]}
    # The management plane is deliberately excluded from service bind choices.
    # Its generated FQDN still needs provenance, including the assigned DHCP
    # address retained in observations while a static candidate is reviewed.
    for interface in db.scalars(select(PhysicalInterface)):
        for cidr in (interface.ip_cidr, interface.ipv6_cidr, interface.host_ip_cidr, interface.host_ipv6_cidr):
            address = address_from_cidr(cidr)
            if address:
                address_sources.setdefault(address, interface.name)
    result = []
    for row in db.scalars(select(DnsRecord).where(DnsRecord.description.in_(descriptions))):
        if not row.enabled or row.record_type not in {"A", "AAAA", "CNAME"}:
            continue
        directive = f"{'cname' if row.record_type == 'CNAME' else 'host-record'}={row.hostname},{row.address}"
        if directive not in directives:
            continue
        generated_ptr = row.record_type in {"A", "AAAA"} and ip_address(row.address).reverse_pointer not in explicit_ptrs
        result.append({
            "hostname": row.hostname, "record_type": row.record_type,
            "address": row.address, "description": row.description or "",
            "generated_ptr": "true" if generated_ptr else "false",
            "source_interface": service_interfaces.get(row.description or "", address_sources.get(row.address, "")),
        })
    captured = {(row["hostname"], row["record_type"], row["address"]) for row in result}
    # A partial DNS publication can retain applied owned rows whose desired
    # identity was edited separately. Preserve their applied provenance.
    for row in (load_appliance_apply_baselines(db).get("dnsmasq") or {}).get("service_dns_records", []):
        key = (row["hostname"], row["record_type"], row["address"])
        directive = f"{'cname' if row['record_type'] == 'CNAME' else 'host-record'}={row['hostname']},{row['address']}"
        if row.get("description") in descriptions and key not in captured and directive in directives:
            result.append(row)
    return result


def remember_applied_service_dns_records(db: Session) -> None:
    """Preserve legacy exact-marker ownership before desired aliases are replaced.

    Args:
        db: Caller-owned transaction; this function never commits.
    """
    acquire_network_objects_write_lock(db)
    db.flush()
    baselines = load_appliance_apply_baselines(db, refresh=True)
    baseline = baselines.get("dnsmasq")
    if not baseline or "service_dns_records" in baseline:
        return
    baseline["service_dns_records"] = owned_service_dns_records(db, str(baseline.get("config_preview") or ""))
    save_appliance_apply_baselines(db, baselines)
