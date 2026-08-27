"""Derive and reconcile factory-owned service DNS identities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    ApplianceSettings,
    CaSettings,
    DnsRecord,
    EsxStorageSettings,
    KmsSettings,
    LdapSettings,
    NtpSettings,
    OidcProviderSettings,
    Setting,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    utcnow,
)
from atlaso.app.services.appliance_settings import normalize_fqdn

FACTORY_APPLIANCE_FQDN = "core.atlaso.internal"
FACTORY_APPLIANCE_DOMAIN = "atlaso.internal"

CA_PORTAL_DNS_DESCRIPTION = "Created from Certificate Authority portal endpoint."
ESX_STORAGE_DNS_DESCRIPTION = "Created from ESX Storage endpoint."
ESXI_PXE_DNS_DESCRIPTION = "Created from ESXi PXE boot endpoint."
KMS_DNS_DESCRIPTION = "Atlaso app-owned KMS/KMIP endpoint record."
LDAP_DNS_DESCRIPTION = "Managed by Atlaso LDAP service"
OIDC_DNS_DESCRIPTION = "Created from OpenID Connect provider endpoint."
VCF_DEPOT_DNS_DESCRIPTION = "Created from VCF Offline Depot endpoint."
VCF_REGISTRY_DNS_DESCRIPTION = "Created from VCF private registry endpoint."

ESXI_PXE_HOSTNAME_KEY = "esxi_pxe.boot.hostname"


@dataclass(frozen=True)
class FactoryServiceIdentity:
    """Describe one factory-owned service hostname and its coupled state."""

    key: str
    model: type[Any]
    hostname_attribute: str
    label: str
    dns_description: str | None = None
    coupled_hostname_attributes: tuple[str, ...] = ()
    certificate_owner: str | None = None


FACTORY_SERVICE_IDENTITIES = (
    FactoryServiceIdentity(
        "ntp",
        NtpSettings,
        "hostname",
        "ntp",
        certificate_owner="ntp:nts",
    ),
    FactoryServiceIdentity(
        "ca_portal",
        CaSettings,
        "portal_hostname",
        "ca",
        dns_description=CA_PORTAL_DNS_DESCRIPTION,
        certificate_owner="ca_portal:https",
    ),
    FactoryServiceIdentity(
        "kms",
        KmsSettings,
        "hostname",
        "kms",
        dns_description=KMS_DNS_DESCRIPTION,
        coupled_hostname_attributes=("server_certificate",),
        certificate_owner="kms:server",
    ),
    FactoryServiceIdentity(
        "ldap",
        LdapSettings,
        "hostname",
        "ldap",
        dns_description=LDAP_DNS_DESCRIPTION,
        certificate_owner="ldap:ldaps",
    ),
    FactoryServiceIdentity(
        "oidc",
        OidcProviderSettings,
        "hostname",
        "oidc",
        dns_description=OIDC_DNS_DESCRIPTION,
        certificate_owner="oidc:https",
    ),
    FactoryServiceIdentity(
        "esx_storage",
        EsxStorageSettings,
        "hostname",
        "nfs",
        dns_description=ESX_STORAGE_DNS_DESCRIPTION,
    ),
    FactoryServiceIdentity(
        "vcf_private_registry",
        VcfPrivateRegistrySettings,
        "hostname",
        "registry",
        dns_description=VCF_REGISTRY_DNS_DESCRIPTION,
        coupled_hostname_attributes=("server_certificate",),
        certificate_owner="vcf_private_registry:https",
    ),
    FactoryServiceIdentity(
        "vcf_offline_depot",
        VcfOfflineDepotSettings,
        "hostname",
        "depot",
        dns_description=VCF_DEPOT_DNS_DESCRIPTION,
        coupled_hostname_attributes=("server_certificate",),
        certificate_owner="vcf_offline_depot:https",
    ),
)


def appliance_domain_from_fqdn(fqdn: str) -> str:
    """Return the validated domain portion of an appliance FQDN."""

    normalized = normalize_fqdn(fqdn)
    if not normalized or "." not in normalized:
        return ""
    return normalized.split(".", 1)[1]


def factory_service_hostname(label: str, appliance_fqdn: str) -> str:
    """Return a factory service hostname under the appliance domain."""

    domain = appliance_domain_from_fqdn(appliance_fqdn) or FACTORY_APPLIANCE_DOMAIN
    return f"{label}.{domain}"


def factory_oidc_issuer(hostname: str, port: int = 443) -> str:
    """Return the canonical factory OIDC issuer for a service hostname."""

    authority = hostname if int(port) == 443 else f"{hostname}:{int(port)}"
    return f"https://{authority}/identity"


def _eligible_factory_hostnames(
    label: str,
    *,
    previous_appliance_fqdn: str | None,
) -> set[str]:
    hostnames = {f"{label}.{FACTORY_APPLIANCE_DOMAIN}"}
    previous_domain = appliance_domain_from_fqdn(previous_appliance_fqdn or "")
    if previous_domain:
        hostnames.add(f"{label}.{previous_domain}")
    return hostnames


def _renamed_service_record_hostname(hostname: str, old_hostname: str, new_hostname: str) -> str | None:
    if hostname == old_hostname:
        return new_hostname
    old_label, old_domain = old_hostname.split(".", 1)
    new_label, new_domain = new_hostname.split(".", 1)
    prefix = f"{old_label}-"
    suffix = f".{old_domain}"
    if hostname.startswith(prefix) and hostname.endswith(suffix):
        token = hostname[len(old_label) : -len(suffix)]
        return f"{new_label}{token}.{new_domain}"
    return None


def _migrate_owned_dns_records(
    db: Session,
    *,
    description: str,
    old_hostname: str,
    new_hostname: str,
) -> tuple[int, int]:
    """Rename only exact app-owned records and preserve conflicting operator rows."""

    changed = 0
    conflicts = 0
    records = db.execute(
        select(DnsRecord).where(DnsRecord.description == description)
    ).scalars().all()
    for record in records:
        renamed_hostname = _renamed_service_record_hostname(
            record.hostname, old_hostname, new_hostname
        )
        if renamed_hostname is None:
            continue
        renamed_address = record.address
        if record.record_type == "CNAME":
            renamed_address = (
                _renamed_service_record_hostname(
                    record.address, old_hostname, new_hostname
                )
                or record.address
            )
        conflicting_record_types = (
            ["A", "AAAA", "CNAME"]
            if record.record_type == "CNAME"
            else [record.record_type, "CNAME"]
        )
        destination_records = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == renamed_hostname,
                DnsRecord.record_type.in_(conflicting_record_types),
                DnsRecord.id != record.id,
            )
        ).scalars().all()
        if any(candidate.description != description for candidate in destination_records):
            db.delete(record)
            changed += 1
            conflicts += 1
            continue
        duplicate = next(
            (
                candidate
                for candidate in destination_records
                if candidate.address == renamed_address
            ),
            None,
        )
        if duplicate is not None:
            duplicate.enabled = duplicate.enabled or record.enabled
            db.delete(record)
            changed += 1
            continue
        record.hostname = renamed_hostname
        record.address = renamed_address
        changed += 1
    return changed, conflicts


def _reconcile_managed_certificate(
    db: Session,
    *,
    owner: str,
    old_hostname: str,
    new_hostname: str,
) -> bool:
    """Mark an existing managed certificate stale for its new service identity."""

    from atlaso.app.models import CaCertificate

    certificate = db.execute(
        select(CaCertificate).where(CaCertificate.managed_owner == owner)
    ).scalar_one_or_none()
    if certificate is None:
        return False
    changed = False
    if normalize_fqdn(certificate.common_name) == old_hostname:
        certificate.common_name = new_hostname
        changed = True
    dns_names = [line.strip() for line in (certificate.subject_alt_names or "").splitlines()]
    replaced_dns_names = [new_hostname if normalize_fqdn(line) == old_hostname else line for line in dns_names]
    if replaced_dns_names != dns_names:
        certificate.subject_alt_names = "\n".join(replaced_dns_names)
        changed = True
    for attribute in ("cert_path", "key_path", "chain_path"):
        value = str(getattr(certificate, attribute) or "")
        if old_hostname in value:
            setattr(certificate, attribute, value.replace(old_hostname, new_hostname))
            changed = True
    if changed:
        certificate.status = "planned"
    return changed


def reconcile_factory_service_identities(
    db: Session,
    *,
    previous_appliance_fqdn: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Reconcile only provably factory-derived service identities.

    A legacy package default and the exact hostname under the immediately previous appliance
    domain are eligible. Any other hostname is treated as operator-owned and remains unchanged.
    """

    appliance = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    if appliance is None or not appliance_domain_from_fqdn(appliance.fqdn):
        return {}
    changes: dict[str, dict[str, Any]] = {}
    for identity in FACTORY_SERVICE_IDENTITIES:
        row = db.execute(select(identity.model)).scalars().first()
        if row is None:
            continue
        current_hostname = normalize_fqdn(
            str(getattr(row, identity.hostname_attribute) or "")
        )
        target_hostname = factory_service_hostname(identity.label, appliance.fqdn)
        if current_hostname == target_hostname:
            continue
        eligible = _eligible_factory_hostnames(
            identity.label,
            previous_appliance_fqdn=previous_appliance_fqdn,
        )
        if current_hostname not in eligible:
            continue
        setattr(row, identity.hostname_attribute, target_hostname)
        for attribute in identity.coupled_hostname_attributes:
            coupled = normalize_fqdn(str(getattr(row, attribute) or ""))
            if coupled in eligible or coupled == current_hostname:
                setattr(row, attribute, target_hostname)
        if isinstance(row, OidcProviderSettings):
            old_issuer = factory_oidc_issuer(current_hostname, row.port)
            if row.issuer_url == old_issuer:
                row.issuer_url = factory_oidc_issuer(target_hostname, row.port)
        if hasattr(row, "updated_at"):
            row.updated_at = utcnow()
        dns_changed = 0
        conflicts = 0
        if identity.dns_description:
            dns_changed, conflicts = _migrate_owned_dns_records(
                db,
                description=identity.dns_description,
                old_hostname=current_hostname,
                new_hostname=target_hostname,
            )
        certificate_changed = False
        if identity.certificate_owner:
            certificate_changed = _reconcile_managed_certificate(
                db,
                owner=identity.certificate_owner,
                old_hostname=current_hostname,
                new_hostname=target_hostname,
            )
        changes[identity.key] = {
            "old_hostname": current_hostname,
            "new_hostname": target_hostname,
            "dns_records_changed": dns_changed,
            "dns_conflicts": conflicts,
            "certificate_changed": certificate_changed,
        }

    pxe_row = db.execute(
        select(Setting).where(Setting.key == ESXI_PXE_HOSTNAME_KEY)
    ).scalar_one_or_none()
    if pxe_row is not None:
        current_hostname = normalize_fqdn(pxe_row.value)
        target_hostname = factory_service_hostname("esxi-pxe", appliance.fqdn)
        eligible = _eligible_factory_hostnames(
            "esxi-pxe", previous_appliance_fqdn=previous_appliance_fqdn
        )
        if current_hostname != target_hostname and current_hostname in eligible:
            pxe_row.value = target_hostname
            dns_changed, conflicts = _migrate_owned_dns_records(
                db,
                description=ESXI_PXE_DNS_DESCRIPTION,
                old_hostname=current_hostname,
                new_hostname=target_hostname,
            )
            changes["esxi_pxe"] = {
                "old_hostname": current_hostname,
                "new_hostname": target_hostname,
                "dns_records_changed": dns_changed,
                "dns_conflicts": conflicts,
                "certificate_changed": False,
            }
    if changes:
        db.flush()
    return changes
