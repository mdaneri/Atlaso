"""Implement settings archive service behavior."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from sqlalchemy import DateTime as SqlDateTime
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from atlaso import __version__
from atlaso.app.models import (
    ApplianceSettings,
    AutomationScript,
    AutomationScriptRevision,
    CaCertificate,
    CaProfile,
    CaSettings,
    DhcpOption,
    DhcpReservation,
    DhcpScope,
    DhcpSettings,
    DnsRecord,
    DnsSettings,
    EsxiKickstart,
    EsxiKickstartVaultBinding,
    EsxiPxeHost,
    EsxNfsShare,
    EsxStorageSettings,
    EsxStorageVolume,
    FirewallRule,
    FirewallSettings,
    KmsSettings,
    Job,
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapRecoveryArchive,
    LdapSettings,
    LdapUser,
    ManagedPackage,
    NatRule,
    NetworkBootEnvironment,
    NetworkBootMedia,
    NtpSettings,
    OidcClient,
    OidcClientRedirectUri,
    OidcAuthorizationCode,
    OidcAuthorizationTransaction,
    OidcGroupMapping,
    OidcProviderSettings,
    OidcSigningKey,
    OidcSubject,
    PhysicalInterface,
    Route,
    RoutingRule,
    ServiceState,
    Setting,
    Schedule,
    UpdateSource,
    User,
    VcfBackupSettings,
    VcfDepotDownloadProfile,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VcfRegistryBundle,
    Vault,
    VaultEntry,
    VlanInterface,
    WanPolicy,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
)
from atlaso.app.seed import NTP_NTS_RESTORATION_SETTING_KEY, SEED_EXAMPLES_SETTING_KEY, seed_initial_data, seed_update_sources
from atlaso.app.services.appliance_settings import (
    management_interface_context,
    normalize_fqdn,
    normalized_web_terminal_interfaces,
    validate_appliance_settings,
    web_terminal_interface_options,
)
from atlaso.app.services.ca import validate_ca_state
from atlaso.app.services.dnsmasq import (
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    split_addresses,
    split_interfaces,
    validate_dhcp_scope,
    validate_dhcp_settings,
    validate_dns_settings,
)
from atlaso.app.services.esxi_pxe import (
    ESXI_PXE_CUSTOM_VARIABLES_KEY,
    host_variables_json,
    normalize_host_mac,
    normalize_host_variables,
)
from atlaso.app.services.firewall import (
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    firewall_source_group_state,
    validate_firewall_rule,
    validate_firewall_state,
)
from atlaso.app.services.local_users import LOCAL_USERS_PASSWORD_POLICY_KEY
from atlaso.app.services.esx_storage import StorageInterface, validate_storage_state
from atlaso.app.services.kms import KMS_DEFAULT_CONFIG_PATH, KMS_DEFAULT_DATABASE_PATH
from atlaso.app.services.ldap import (
    clear_ldap_recovery_payload,
    ensure_organization_bind_secret,
    validate_ldap_state,
)
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
    normalize_ipv4_method,
    validate_network_state,
)
from atlaso.app.services.ntp import validate_ntp_state
from atlaso.app.services.oidc import (
    OIDC_TOKEN_LIFETIME_SECONDS,
    OidcConfigurationError,
    expected_issuer_url,
    normalize_issuer_url,
)
from atlaso.app.services.routes_wan import validate_nat_source, validate_wan_state
from atlaso.app.services.update_sources import UPDATE_SOURCE_KINDS
from atlaso.app.services.vcf_backups import VCF_BACKUP_DEFAULT_USERNAME, validate_vcf_backup_state
from atlaso.app.services.vcf_offline_depot import validate_vcf_depot_state
from atlaso.app.services.vcf_private_registry import validate_vcf_registry_state
from atlaso.app.services.vsphere_key_providers import normalize_service_hostname

ARCHIVE_SCHEMA_VERSION = 2
LEGACY_ARCHIVE_SCHEMA_VERSION = 1
ARCHIVE_KIND = "atlaso-settings-archive"
SAFE_SETTING_KEYS = {
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    ESXI_PXE_CUSTOM_VARIABLES_KEY,
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    LOCAL_USERS_PASSWORD_POLICY_KEY,
    NTP_NTS_RESTORATION_SETTING_KEY,
}

SCALAR_TABLES = {
    "physical_interfaces": PhysicalInterface,
    "vlan_interfaces": VlanInterface,
    "wan_policies": WanPolicy,
    "nat_rules": NatRule,
    "routing_rules": RoutingRule,
    "service_states": ServiceState,
    "appliance_settings": ApplianceSettings,
    "oidc_provider_settings": OidcProviderSettings,
    "ntp_settings": NtpSettings,
    "dns_settings": DnsSettings,
    "dns_records": DnsRecord,
    "dhcp_settings": DhcpSettings,
    "dhcp_scopes": DhcpScope,
    "dhcp_reservations": DhcpReservation,
    "firewall_settings": FirewallSettings,
    "firewall_rules": FirewallRule,
    "ca_settings": CaSettings,
    "ca_profiles": CaProfile,
    "kms_settings": KmsSettings,
    "ldap_settings": LdapSettings,
    "vcf_private_registry_settings": VcfPrivateRegistrySettings,
    "vcf_registry_bundles": VcfRegistryBundle,
    "vcf_offline_depot_settings": VcfOfflineDepotSettings,
    "vcf_depot_download_profiles": VcfDepotDownloadProfile,
    "esxi_kickstarts": EsxiKickstart,
    "esx_storage_settings": EsxStorageSettings,
}

ARCHIVE_SECTION_MODELS = {
    **SCALAR_TABLES,
    "routes": Route,
    "dhcp_options": DhcpOption,
    "ca_certificates": CaCertificate,
    "ldap_organizations": LdapOrganization,
    "ldap_users": LdapUser,
    "ldap_groups": LdapGroup,
    "oidc_clients": OidcClient,
    "oidc_client_redirect_uris": OidcClientRedirectUri,
    "oidc_signing_keys": OidcSigningKey,
    "vcf_backup_settings": VcfBackupSettings,
    "vcf_offline_depot_settings": VcfOfflineDepotSettings,
    "esxi_pxe_hosts": EsxiPxeHost,
    "network_boot_environments": NetworkBootEnvironment,
    "esx_storage_volumes": EsxStorageVolume,
    "esx_nfs_shares": EsxNfsShare,
    "update_sources": UpdateSource,
    "managed_packages": ManagedPackage,
    "automation_scripts": AutomationScript,
    "schedules": Schedule,
    "settings": Setting,
}
ARCHIVE_REQUIRED_FIELD_REPLACEMENTS = {
    "ldap_users": ({"organization_id"}, {"organization_slug"}),
    "ldap_groups": ({"organization_id"}, {"organization_slug"}),
    "oidc_client_redirect_uris": ({"oidc_client_id"}, {"client_id"}),
    "esx_nfs_shares": ({"volume_id"}, {"volume_name"}),
}
ARCHIVE_CUSTOM_REQUIRED_FIELDS = {
    "vsphere_key_providers": {"id", "name"},
    "vsphere_trusted_vcenters": {"id", "provider_id", "name"},
    "vsphere_trusted_vcenter_certificates": {
        "id",
        "trusted_vcenter_id",
        "fingerprint_sha256",
        "certificate_pem",
    },
    "ldap_group_memberships": {"organization_slug", "group_name", "member_type", "member_name"},
    "oidc_subjects": {"subject_uuid", "source", "username"},
    "oidc_group_mappings": {
        "source_type",
        "local_role",
        "ldap_group_name",
        "organization_slug",
        "client_id",
        "external_group_name",
    },
}
ARCHIVE_SECTION_NAMES = frozenset(ARCHIVE_SECTION_MODELS) | frozenset(ARCHIVE_CUSTOM_REQUIRED_FIELDS)
ARCHIVE_BLANK_REQUIRED_TEXT_FIELDS = {
    "dhcp_reservations": {"hostname"},
    "oidc_group_mappings": {
        "client_id",
        "external_group_name",
        "ldap_group_name",
        "local_role",
        "organization_slug",
    },
    "settings": {"value"},
}
ARCHIVE_SINGLETON_SECTIONS = frozenset(
    {
        "appliance_settings",
        "ca_settings",
        "dhcp_settings",
        "dns_settings",
        "firewall_settings",
        "kms_settings",
        "ldap_settings",
        "ntp_settings",
        "vcf_backup_settings",
        "vcf_offline_depot_settings",
        "vcf_private_registry_settings",
    }
)
ARCHIVE_OPTIONAL_SINGLETON_SECTIONS = frozenset(
    {
        "esx_storage_settings",
        "oidc_provider_settings",
    }
)

RESTORE_DELETE_MODELS = [
    OidcGroupMapping,
    EsxiKickstartVaultBinding,
    VaultEntry,
    Vault,
    Schedule,
    AutomationScriptRevision,
    AutomationScript,
    ManagedPackage,
    UpdateSource,
    LdapRecoveryArchive,
    EsxiPxeHost,
    EsxiKickstart,
    EsxNfsShare,
    EsxStorageVolume,
    EsxStorageSettings,
    VcfRegistryBundle,
    VcfDepotDownloadProfile,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VcfBackupSettings,
    VsphereTrustedVcenterCertificate,
    VsphereTrustedVcenter,
    VsphereKeyProvider,
    KmsSettings,
    OidcClientRedirectUri,
    OidcAuthorizationCode,
    OidcAuthorizationTransaction,
    OidcClient,
    OidcSubject,
    OidcSigningKey,
    OidcProviderSettings,
    LdapGroupMembership,
    LdapGroup,
    LdapUser,
    LdapOrganization,
    LdapSettings,
    CaCertificate,
    CaProfile,
    CaSettings,
    FirewallRule,
    FirewallSettings,
    DhcpOption,
    DhcpReservation,
    DhcpScope,
    DhcpSettings,
    DnsRecord,
    DnsSettings,
    Route,
    RoutingRule,
    NatRule,
    WanPolicy,
    VlanInterface,
    PhysicalInterface,
    ServiceState,
    NtpSettings,
    ApplianceSettings,
    Setting,
]


def _utc_iso() -> str:
    """Return utc iso."""
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: object, *, exclude: set[str] | None = None) -> dict[str, Any]:
    """Return row to dict.

    Args:
        row: Persistent database row affected by the operation.
        exclude: Exclude consumed by row to dict.
    """
    excluded = {"id", "created_at", "updated_at", *(exclude or set())}
    payload: dict[str, Any] = {}
    for column in row.__table__.columns:
        if column.name in excluded or isinstance(column.type, SqlDateTime):
            continue
        payload[column.name] = getattr(row, column.name)
    return payload


def _settings_rows(db: Session) -> list[dict[str, str]]:
    """Return settings rows.

    Args:
        db: Active database session.
    """
    rows = db.execute(select(Setting).where(Setting.key.in_(SAFE_SETTING_KEYS)).order_by(Setting.key)).scalars().all()
    return [_row_to_dict(row) for row in rows]


def export_settings_archive(db: Session, *, actor: str) -> dict[str, Any]:
    """Serialize settings archive.

    Args:
        db: Active database session.
        actor: Authenticated identity attributed to the audit record.

    Returns:
        The export settings archive result.
    """
    payload: dict[str, Any] = {
        "kind": ARCHIVE_KIND,
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "app_version": __version__,
        "exported_at": _utc_iso(),
        "exported_by": actor,
        "notes": [
            "Contains Atlaso desired-state configuration only.",
            "Audit events, jobs, API tokens, password hashes, and uploaded secret bodies are not included; encrypted CA private-key material is included for trust portability.",
            "Managed LDAP metadata is included, but LDAP password hashes and VCF bind secrets require the separate encrypted LDAP recovery archive or credential resets.",
            "OIDC client secret hashes, exact redirect configuration, external group mappings, and encrypted signing keys are included; plaintext client secrets are never included.",
            "Restoring usable CA and OIDC signing private-key material requires the same ATLASO_SECRETS_KEY.",
            "Restore updates the control-plane database; host services change only after global appliance apply.",
        ],
        "data": {},
    }
    data = payload["data"]
    for key, model in SCALAR_TABLES.items():
        rows = db.execute(select(model)).scalars().all()
        data[key] = [_row_to_dict(row) for row in rows]

    data["routes"] = _routes_to_archive(db)
    data["dhcp_options"] = _dhcp_options_to_archive(db)
    ntp_server_enabled = any(bool(row.get("nts_server_enabled")) for row in data["ntp_settings"])
    data["ca_certificates"] = [
        row
        for row in _ca_certificates_to_archive(db)
        if ntp_server_enabled or row.get("managed_owner") != "ntp:nts"
    ]
    data["vsphere_key_providers"] = _vsphere_key_providers_to_archive(db)
    data["vsphere_trusted_vcenters"] = _vsphere_trusted_vcenters_to_archive(db)
    data["vsphere_trusted_vcenter_certificates"] = _vsphere_certificates_to_archive(db)
    data["ldap_organizations"] = _ldap_organizations_to_archive(db)
    data["ldap_users"] = _ldap_users_to_archive(db)
    data["ldap_groups"] = _ldap_groups_to_archive(db)
    data["ldap_group_memberships"] = _ldap_group_memberships_to_archive(db)
    data["oidc_subjects"] = _oidc_subjects_to_archive(db)
    data["oidc_clients"] = _oidc_clients_to_archive(db)
    data["oidc_client_redirect_uris"] = _oidc_client_redirect_uris_to_archive(db)
    data["oidc_group_mappings"] = _oidc_group_mappings_to_archive(db)
    data["oidc_signing_keys"] = [
        _row_to_dict(row)
        for row in db.execute(select(OidcSigningKey).order_by(OidcSigningKey.created_at)).scalars().all()
    ]
    data["vcf_backup_settings"] = _vcf_backup_settings_to_archive(db)
    data["vcf_offline_depot_settings"] = _vcf_offline_depot_settings_to_archive(db)
    data["esxi_pxe_hosts"] = _esxi_pxe_hosts_to_archive(db)
    data["network_boot_environments"] = [
        _row_to_dict(row, exclude={"active_version"})
        for row in db.execute(
            select(NetworkBootEnvironment).order_by(NetworkBootEnvironment.key)
        ).scalars().all()
    ]
    data["esx_storage_volumes"] = [_row_to_dict(row) for row in db.execute(select(EsxStorageVolume).order_by(EsxStorageVolume.name)).scalars().all()]
    volume_names = {row.id: row.name for row in db.execute(select(EsxStorageVolume)).scalars().all()}
    data["esx_nfs_shares"] = [
        _row_to_dict(row, exclude={"volume_id"}) | {"volume_name": volume_names.get(row.volume_id, "")}
        for row in db.execute(select(EsxNfsShare).order_by(EsxNfsShare.datastore_name)).scalars().all()
    ]
    data["update_sources"] = _update_sources_to_archive(db)
    data["managed_packages"] = _managed_packages_to_archive(db)
    data["automation_scripts"] = _automation_scripts_to_archive(db)
    data["schedules"] = _schedules_to_archive(db)
    data["settings"] = _settings_rows(db)
    return payload


def _routes_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return routes to archive.

    Args:
        db: Active database session.
    """
    policies = {policy.id: policy.name for policy in db.execute(select(WanPolicy)).scalars().all()}
    rows = []
    for route in db.execute(select(Route)).scalars().all():
        payload = _row_to_dict(route, exclude={"wan_policy_id"})
        payload["wan_policy_name"] = policies.get(route.wan_policy_id) if route.wan_policy_id else ""
        rows.append(payload)
    return rows


def _dhcp_options_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return dhcp options to archive.

    Args:
        db: Active database session.
    """
    scopes = {scope.id: scope.name for scope in db.execute(select(DhcpScope)).scalars().all()}
    rows = []
    for option in db.execute(select(DhcpOption)).scalars().all():
        payload = _row_to_dict(option, exclude={"scope_id"})
        payload["scope_name"] = scopes.get(option.scope_id) if option.scope_id else ""
        rows.append(payload)
    return rows


def _ca_certificates_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return ca certificates to archive.

    Args:
        db: Active database session.
    """
    profiles = {profile.id: profile.name for profile in db.execute(select(CaProfile)).scalars().all()}
    rows = []
    for certificate in db.execute(select(CaCertificate)).scalars().all():
        payload = _row_to_dict(certificate, exclude={"profile_id", "issued_at", "expires_at"})
        payload["profile_name"] = profiles.get(certificate.profile_id) if certificate.profile_id else ""
        rows.append(payload)
    return rows


def _vsphere_key_providers_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return public provider desired state with immutable UUIDs.

    Args:
        db: Active database session.
    """
    return [
        {
            "id": row.id,
            "name": row.name,
            "description": row.description,
            "enabled": row.enabled,
        }
        for row in db.execute(select(VsphereKeyProvider).order_by(VsphereKeyProvider.name)).scalars().all()
    ]


def _vsphere_trusted_vcenters_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return provider-scoped trusted-vCenter desired state.

    Args:
        db: Active database session.
    """
    return [
        {
            "id": row.id,
            "provider_id": row.provider_id,
            "name": row.name,
            "hostname": row.hostname,
            "description": row.description,
            "enabled": row.enabled,
        }
        for row in db.execute(select(VsphereTrustedVcenter).order_by(VsphereTrustedVcenter.name)).scalars().all()
    ]


def _vsphere_certificates_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return public certificate trust without private or operational-key material.

    Args:
        db: Active database session.
    """
    return [
        {
            "id": row.id,
            "trusted_vcenter_id": row.trusted_vcenter_id,
            "fingerprint_sha256": row.fingerprint_sha256,
            "certificate_pem": row.certificate_pem,
            "subject": row.subject,
            "issuer": row.issuer,
            "serial_number": row.serial_number,
            "source": row.source,
        }
        for row in db.execute(
            select(VsphereTrustedVcenterCertificate).order_by(
                VsphereTrustedVcenterCertificate.fingerprint_sha256
            )
        ).scalars().all()
    ]


def _ldap_organizations_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return ldap organizations to archive.

    Args:
        db: Active database session.
    """
    return [
        _row_to_dict(row, exclude={"bind_password_encrypted"})
        for row in db.execute(select(LdapOrganization).order_by(LdapOrganization.name)).scalars().all()
    ]


def _ldap_users_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return ldap users to archive.

    Args:
        db: Active database session.
    """
    organizations = {row.id: row.slug for row in db.execute(select(LdapOrganization)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for user in db.execute(select(LdapUser).order_by(LdapUser.uid)).scalars().all():
        payload = _row_to_dict(user, exclude={"organization_id", "unlock_requested_at"})
        payload["organization_slug"] = organizations.get(user.organization_id, "")
        payload["password_status"] = "not_staged"
        rows.append(payload)
    return rows


def _ldap_groups_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return ldap groups to archive.

    Args:
        db: Active database session.
    """
    organizations = {row.id: row.slug for row in db.execute(select(LdapOrganization)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for group in db.execute(select(LdapGroup).order_by(LdapGroup.name)).scalars().all():
        payload = _row_to_dict(group, exclude={"organization_id"})
        payload["organization_slug"] = organizations.get(group.organization_id, "")
        rows.append(payload)
    return rows


def _ldap_group_memberships_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return ldap group memberships to archive.

    Args:
        db: Active database session.
    """
    users = {row.id: row.uid for row in db.execute(select(LdapUser)).scalars().all()}
    groups = {row.id: row for row in db.execute(select(LdapGroup)).scalars().all()}
    organizations = {row.id: row.slug for row in db.execute(select(LdapOrganization)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for membership in db.execute(select(LdapGroupMembership)).scalars().all():
        group = groups.get(membership.group_id)
        if group is None:
            continue
        rows.append(
            {
                "organization_slug": organizations.get(group.organization_id, ""),
                "group_name": group.name,
                "member_type": "user" if membership.member_user_id is not None else "group",
                "member_name": users.get(membership.member_user_id, "") if membership.member_user_id is not None else (groups.get(membership.member_group_id).name if groups.get(membership.member_group_id) else ""),
            }
        )
    return rows


def _oidc_clients_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return oidc clients to archive.

    Args:
        db: Active database session.
    """
    organizations = {row.id: row.slug for row in db.execute(select(LdapOrganization)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for client in db.execute(select(OidcClient).order_by(OidcClient.name)).scalars().all():
        payload = _row_to_dict(client, exclude={"organization_id"})
        payload["organization_slug"] = organizations.get(client.organization_id, "")
        rows.append(payload)
    return rows


def _oidc_subjects_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return oidc subjects to archive.

    Args:
        db: Active database session.
    """
    local_users = {row.id: row.username for row in db.execute(select(User)).scalars().all()}
    ldap_users = {
        row.id: (row.organization.slug, row.uid)
        for row in db.execute(select(LdapUser)).scalars().all()
    }
    rows: list[dict[str, Any]] = []
    for subject in db.execute(select(OidcSubject).order_by(OidcSubject.id)).scalars().all():
        payload = {"subject_uuid": subject.subject_uuid, "source": "", "username": "", "organization_slug": ""}
        if subject.local_user_id is not None:
            payload.update(source="local", username=local_users.get(subject.local_user_id, ""))
        elif subject.ldap_user_id is not None:
            organization_slug, uid = ldap_users.get(subject.ldap_user_id, ("", ""))
            payload.update(source="managed_ldap", username=uid, organization_slug=organization_slug)
        if payload["username"]:
            rows.append(payload)
    return rows


def _oidc_client_redirect_uris_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return oidc client redirect uris to archive.

    Args:
        db: Active database session.
    """
    clients = {row.id: row.client_id for row in db.execute(select(OidcClient)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for redirect in db.execute(
        select(OidcClientRedirectUri).order_by(
            OidcClientRedirectUri.oidc_client_id,
            OidcClientRedirectUri.kind,
            OidcClientRedirectUri.id,
        )
    ).scalars().all():
        payload = _row_to_dict(redirect, exclude={"oidc_client_id"})
        payload["client_id"] = clients.get(redirect.oidc_client_id, "")
        rows.append(payload)
    return rows


def _oidc_group_mappings_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return oidc group mappings to archive.

    Args:
        db: Active database session.
    """
    organizations = {
        row.id: row.slug
        for row in db.execute(select(LdapOrganization)).scalars().all()
    }
    clients = {
        row.id: row.client_id
        for row in db.execute(select(OidcClient)).scalars().all()
    }
    groups = {
        row.id: row.name
        for row in db.execute(select(LdapGroup)).scalars().all()
    }
    rows: list[dict[str, Any]] = []
    for mapping in db.execute(
        select(OidcGroupMapping).order_by(OidcGroupMapping.id)
    ).scalars().all():
        rows.append(
            {
                "source_type": mapping.source_type,
                "local_role": mapping.local_role,
                "ldap_group_name": groups.get(mapping.ldap_group_id, ""),
                "organization_slug": organizations.get(mapping.organization_id, ""),
                "client_id": clients.get(mapping.oidc_client_id, ""),
                "external_group_name": mapping.external_group_name,
            }
        )
    return rows


def _vcf_backup_settings_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return vcf backup settings to archive.

    Args:
        db: Active database session.
    """
    users = {user.id: user.username for user in db.execute(select(User)).scalars().all()}
    rows = []
    for settings in db.execute(select(VcfBackupSettings)).scalars().all():
        payload = _row_to_dict(settings, exclude={"sftp_user_id"})
        payload["sftp_username"] = users.get(settings.sftp_user_id) if settings.sftp_user_id else ""
        rows.append(payload)
    return rows


def _vcf_offline_depot_settings_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return vcf offline depot settings to archive.

    Args:
        db: Active database session.
    """
    users = {user.id: user.username for user in db.execute(select(User)).scalars().all()}
    rows = []
    for settings in db.execute(select(VcfOfflineDepotSettings)).scalars().all():
        payload = _row_to_dict(settings, exclude={"http_user_id"})
        payload["http_username"] = users.get(settings.http_user_id) if settings.http_user_id else ""
        rows.append(payload)
    return rows


def _esxi_pxe_hosts_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return esxi pxe hosts to archive.

    Args:
        db: Active database session.
    """
    kickstarts = {row.id: row.name for row in db.execute(select(EsxiKickstart)).scalars().all()}
    rows = []
    for host in db.execute(select(EsxiPxeHost)).scalars().all():
        payload = _row_to_dict(host, exclude={"kickstart_id", "variables_json"})
        payload["kickstart_name"] = kickstarts.get(host.kickstart_id) if host.kickstart_id else ""
        payload["variables"] = normalize_host_variables(host.variables_json or "{}")
        rows.append(payload)
    return rows


def _update_sources_to_archive(db: Session) -> list[dict[str, Any]]:
    """Update sources to archive.

    Args:
        db: Active database session.

    Returns:
        The update sources to archive result.
    """
    rows: list[dict[str, Any]] = []
    for source in db.execute(select(UpdateSource).order_by(UpdateSource.kind, UpdateSource.priority, UpdateSource.name)).scalars().all():
        payload = _row_to_dict(source, exclude={"credential_encrypted", "validation_status", "validation_message"})
        payload["credential_status"] = "not_exported"
        rows.append(payload)
    return rows


def _managed_packages_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return managed packages to archive.

    Args:
        db: Active database session.
    """
    sources = {source.id: source for source in db.execute(select(UpdateSource)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for package in db.execute(select(ManagedPackage).order_by(ManagedPackage.ecosystem, ManagedPackage.name)).scalars().all():
        payload = _row_to_dict(package, exclude={"source_id"})
        source = sources.get(package.source_id)
        payload["source_kind"] = source.kind if source else ""
        payload["source_name"] = source.name if source else ""
        rows.append(payload)
    return rows


def _automation_scripts_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return automation scripts to archive.

    Args:
        db: Active database session.
    """
    rows: list[dict[str, Any]] = []
    for script in db.execute(select(AutomationScript).order_by(AutomationScript.name)).scalars().all():
        payload = _row_to_dict(script)
        payload["revisions"] = [
            _row_to_dict(revision, exclude={"script_id", "enabled"}) | {"enabled": False}
            for revision in db.execute(
                select(AutomationScriptRevision)
                .where(AutomationScriptRevision.script_id == script.id)
                .order_by(AutomationScriptRevision.revision)
            ).scalars().all()
        ]
        rows.append(payload)
    return rows


def _schedules_to_archive(db: Session) -> list[dict[str, Any]]:
    """Return schedules to archive.

    Args:
        db: Active database session.
    """
    profiles = {profile.id: profile.name for profile in db.execute(select(VcfDepotDownloadProfile)).scalars().all()}
    revisions = {revision.id: revision for revision in db.execute(select(AutomationScriptRevision)).scalars().all()}
    scripts = {script.id: script.name for script in db.execute(select(AutomationScript)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for schedule in db.execute(select(Schedule).order_by(Schedule.name)).scalars().all():
        payload = _row_to_dict(schedule, exclude={"enabled", "next_run_at", "last_run_at", "last_job_id", "run_once_at"})
        payload["enabled"] = False
        payload["run_once_at"] = schedule.run_once_at.isoformat() if schedule.run_once_at else None
        try:
            config = json.loads(schedule.task_config_json or "{}")
        except json.JSONDecodeError:
            config = {}
        if schedule.task_type == "vcf_depot_download":
            payload["vcf_profile_name"] = profiles.get(config.get("profile_id"), "")
        elif schedule.task_type == "managed_script":
            revision = revisions.get(config.get("revision_id"))
            if revision is not None:
                payload["script_name"] = scripts.get(revision.script_id, "")
                payload["script_revision"] = revision.revision
        rows.append(payload)
    return rows


def restore_settings_archive(db: Session, archive: dict[str, Any]) -> dict[str, int]:
    """Return restore settings archive.

    Args:
        db: Active database session.
        archive: Archive payload or path to process.
    """
    prepared_archive = _prepare_archive_for_restore(db, archive)
    _validate_archive(prepared_archive)
    _validate_archive_database_relationships(db, prepared_archive["data"])
    recovery_archives = db.execute(select(LdapRecoveryArchive)).scalars().all()
    try:
        counts = _restore_settings_archive_data(db, prepared_archive["data"])
        db.commit()
    except ValueError:
        db.rollback()
        raise
    except (AttributeError, IntegrityError, KeyError, StatementError, TypeError) as exc:
        db.rollback()
        raise ValueError("The settings archive contains invalid desired-state values.") from exc
    except Exception:
        db.rollback()
        raise
    for recovery_archive in recovery_archives:
        clear_ldap_recovery_payload(recovery_archive)
    return counts


def _restore_settings_archive_data(db: Session, data: dict[str, Any]) -> dict[str, int]:
    """Restore preflighted archive data within the caller-owned transaction.

    Args:
        db: Active database session.
        data: Validated archive data collections.
    """
    from atlaso.app.services.network_boot import ensure_environment_rows

    _clear_desired_state(db)

    counts: dict[str, int] = {}
    for key in ["physical_interfaces", "vlan_interfaces", "wan_policies", "nat_rules", "routing_rules"]:
        counts[key] = _insert_rows(db, SCALAR_TABLES[key], data.get(key, []))
    db.flush()

    counts["routes"] = _restore_routes(db, data.get("routes", []))
    for key in [
        "service_states",
        "appliance_settings",
        "oidc_provider_settings",
        "ntp_settings",
        "dns_settings",
        "dns_records",
        "dhcp_settings",
        "dhcp_scopes",
    ]:
        counts[key] = _insert_rows(db, SCALAR_TABLES[key], data.get(key, []))
    db.flush()
    _force_services_stopped_unconfigured(db)

    counts["dhcp_options"] = _restore_dhcp_options(db, data.get("dhcp_options", []))
    for key in [
        "dhcp_reservations",
        "firewall_settings",
        "firewall_rules",
        "ca_settings",
        "ca_profiles",
    ]:
        counts[key] = _insert_rows(db, SCALAR_TABLES[key], data.get(key, []))
    db.flush()

    counts["ca_certificates"] = _restore_ca_certificates(db, data.get("ca_certificates", []))
    restored_ntp_settings = db.execute(select(NtpSettings)).scalar_one_or_none()
    if restored_ntp_settings is not None and not restored_ntp_settings.nts_server_enabled:
        stale_nts_certificates = db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner == "ntp:nts")
        ).scalars().all()
        for certificate in stale_nts_certificates:
            db.delete(certificate)
        counts["ca_certificates"] -= len(stale_nts_certificates)
    counts["kms_settings"] = _insert_rows(db, KmsSettings, data.get("kms_settings", []))
    counts["vsphere_key_providers"] = _restore_vsphere_key_providers(
        db,
        data.get("vsphere_key_providers", []),
    )
    counts["vsphere_trusted_vcenters"] = _restore_vsphere_trusted_vcenters(
        db,
        data.get("vsphere_trusted_vcenters", []),
    )
    counts["vsphere_trusted_vcenter_certificates"] = _restore_vsphere_certificates(
        db,
        data.get("vsphere_trusted_vcenter_certificates", []),
    )
    counts["ldap_settings"] = _insert_rows(db, LdapSettings, data.get("ldap_settings", []))
    counts["ldap_organizations"] = _restore_ldap_organizations(db, data.get("ldap_organizations", []))
    counts["ldap_users"] = _restore_ldap_users(db, data.get("ldap_users", []))
    counts["oidc_subjects"] = _restore_oidc_subjects(db, data.get("oidc_subjects", []))
    counts["ldap_groups"] = _restore_ldap_groups(db, data.get("ldap_groups", []))
    counts["ldap_group_memberships"] = _restore_ldap_group_memberships(db, data.get("ldap_group_memberships", []))
    counts["oidc_clients"] = _restore_oidc_clients(db, data.get("oidc_clients", []))
    counts["oidc_client_redirect_uris"] = _restore_oidc_client_redirect_uris(
        db,
        data.get("oidc_client_redirect_uris", []),
    )
    counts["oidc_group_mappings"] = _restore_oidc_group_mappings(
        db,
        data.get("oidc_group_mappings", []),
    )
    counts["oidc_signing_keys"] = _insert_rows(db, OidcSigningKey, data.get("oidc_signing_keys", []))
    counts["vcf_backup_settings"] = _restore_vcf_backup_settings(db, data.get("vcf_backup_settings", []))
    counts["vcf_offline_depot_settings"] = _restore_vcf_offline_depot_settings(db, data.get("vcf_offline_depot_settings", []))
    for key in [
        "vcf_private_registry_settings",
        "vcf_registry_bundles",
        "vcf_depot_download_profiles",
        "esxi_kickstarts",
    ]:
        counts[key] = _insert_rows(db, SCALAR_TABLES[key], data.get(key, []))
    db.flush()
    counts["esxi_pxe_hosts"] = _restore_esxi_pxe_hosts(db, data.get("esxi_pxe_hosts", []))
    for state in ensure_environment_rows(db):
        state.enabled = False
        state.desired_version = ""
        state.active_version = ""
        db.add(state)
    for row in data.get("network_boot_environments", []):
        payload = _model_kwargs(
            NetworkBootEnvironment,
            row,
            exclude={"active_version"},
        )
        payload["active_version"] = ""
        state = db.get(NetworkBootEnvironment, payload["key"])
        if state is None:
            state = NetworkBootEnvironment(**payload)
        else:
            for field, value in payload.items():
                setattr(state, field, value)
        db.add(state)
    db.flush()
    ensure_environment_rows(db)
    counts["network_boot_environments"] = len(
        db.execute(select(NetworkBootEnvironment)).scalars().all()
    )
    counts["esx_storage_settings"] = _insert_rows(db, EsxStorageSettings, data.get("esx_storage_settings", []))
    counts["esx_storage_volumes"] = _restore_esx_storage_volumes(db, data.get("esx_storage_volumes", []))
    counts["esx_nfs_shares"] = _restore_esx_nfs_shares(db, data.get("esx_nfs_shares", []))
    counts["update_sources"] = _restore_update_sources(db, data.get("update_sources", []))
    counts["managed_packages"] = _restore_managed_packages(db, data.get("managed_packages", []))
    counts["automation_scripts"] = _restore_automation_scripts(db, data.get("automation_scripts", []))
    counts["schedules"] = _restore_schedules(db, data.get("schedules", []))
    counts["settings"] = _insert_rows(db, Setting, [row for row in data.get("settings", []) if row.get("key") in SAFE_SETTING_KEYS])
    _disable_startup_example_seed(db)
    return counts


def factory_reset_desired_state(db: Session) -> dict[str, int]:
    """Return factory reset desired state.

    Args:
        db: Active database session.
    """
    from atlaso.app.services.network_boot import ensure_environment_rows

    recovery_archives = db.execute(select(LdapRecoveryArchive)).scalars().all()
    try:
        _clear_desired_state(db)
        seed_initial_data(db, include_examples=False, commit=False)
        for state in ensure_environment_rows(db):
            state.enabled = False
            state.desired_version = ""
            state.active_version = ""
            db.add(state)
        _disable_startup_example_seed(db)
        _force_services_stopped_unconfigured(db)
        db.commit()
    except Exception:
        db.rollback()
        raise
    for recovery_archive in recovery_archives:
        clear_ldap_recovery_payload(recovery_archive)
    return desired_state_counts(db)


def desired_state_counts(db: Session) -> dict[str, int]:
    """Return desired state counts.

    Args:
        db: Active database session.
    """
    counts = {key: len(db.execute(select(model)).scalars().all()) for key, model in SCALAR_TABLES.items()}
    counts["routes"] = len(db.execute(select(Route)).scalars().all())
    counts["routing_rules"] = len(db.execute(select(RoutingRule)).scalars().all())
    counts["dhcp_options"] = len(db.execute(select(DhcpOption)).scalars().all())
    counts["ca_certificates"] = len(db.execute(select(CaCertificate)).scalars().all())
    counts["vsphere_key_providers"] = len(db.execute(select(VsphereKeyProvider)).scalars().all())
    counts["vsphere_trusted_vcenters"] = len(db.execute(select(VsphereTrustedVcenter)).scalars().all())
    counts["vsphere_trusted_vcenter_certificates"] = len(
        db.execute(select(VsphereTrustedVcenterCertificate)).scalars().all()
    )
    counts["ldap_organizations"] = len(db.execute(select(LdapOrganization)).scalars().all())
    counts["ldap_users"] = len(db.execute(select(LdapUser)).scalars().all())
    counts["ldap_groups"] = len(db.execute(select(LdapGroup)).scalars().all())
    counts["ldap_group_memberships"] = len(db.execute(select(LdapGroupMembership)).scalars().all())
    counts["oidc_clients"] = len(db.execute(select(OidcClient)).scalars().all())
    counts["oidc_client_redirect_uris"] = len(db.execute(select(OidcClientRedirectUri)).scalars().all())
    counts["oidc_group_mappings"] = len(db.execute(select(OidcGroupMapping)).scalars().all())
    counts["oidc_signing_keys"] = len(db.execute(select(OidcSigningKey)).scalars().all())
    counts["oidc_subjects"] = len(db.execute(select(OidcSubject)).scalars().all())
    counts["vcf_backup_settings"] = len(db.execute(select(VcfBackupSettings)).scalars().all())
    counts["esxi_pxe_hosts"] = len(db.execute(select(EsxiPxeHost)).scalars().all())
    counts["network_boot_environments"] = len(
        db.execute(select(NetworkBootEnvironment)).scalars().all()
    )
    counts["esx_storage_volumes"] = len(db.execute(select(EsxStorageVolume)).scalars().all())
    counts["esx_nfs_shares"] = len(db.execute(select(EsxNfsShare)).scalars().all())
    counts["update_sources"] = len(db.execute(select(UpdateSource)).scalars().all())
    counts["managed_packages"] = len(db.execute(select(ManagedPackage)).scalars().all())
    counts["automation_scripts"] = len(db.execute(select(AutomationScript)).scalars().all())
    counts["schedules"] = len(db.execute(select(Schedule)).scalars().all())
    counts["settings"] = len(db.execute(select(Setting).where(Setting.key.in_(SAFE_SETTING_KEYS))).scalars().all())
    return counts


def archive_summary(archive: dict[str, Any]) -> dict[str, Any]:
    """Return archive summary.

    Args:
        archive: Archive consumed by archive summary.
    """
    _validate_archive(archive, allow_legacy_incomplete=True)
    data = archive["data"]
    table_counts = {key: len(value) for key, value in data.items() if isinstance(value, list)}
    return {
        "exported_at": archive.get("exported_at", ""),
        "exported_by": archive.get("exported_by", ""),
        "app_version": archive.get("app_version", ""),
        "table_counts": table_counts,
        "total_rows": sum(table_counts.values()),
    }


def _clear_desired_state(db: Session) -> None:
    """Remove desired state.

    Args:
        db: Active database session.
    """
    for job in db.execute(select(Job).where(Job.schedule_id.is_not(None))).scalars().all():
        job.schedule_id = None
        db.add(job)
    db.flush()
    for model in RESTORE_DELETE_MODELS:
        db.execute(delete(model))
    db.flush()


def _force_services_stopped_unconfigured(db: Session) -> None:
    """Handle force services stopped unconfigured.

    Args:
        db: Active database session.
    """
    service_rows = db.execute(select(ServiceState)).scalars().all()
    for service in service_rows:
        service.running = False
        service.enabled = False
        service.health = "unconfigured"
        service.detail = "Stopped after settings restore or factory reset."
        db.add(service)
    db.flush()


def _disable_startup_example_seed(db: Session) -> None:
    """Handle disable startup example seed.

    Args:
        db: Active database session.
    """
    existing = db.execute(select(Setting).where(Setting.key == SEED_EXAMPLES_SETTING_KEY)).scalar_one_or_none()
    if existing is None:
        db.add(Setting(key=SEED_EXAMPLES_SETTING_KEY, value="false"))
    else:
        existing.value = "false"
    db.flush()


def _prepare_archive_for_restore(db: Session, archive: dict[str, Any]) -> dict[str, Any]:
    """Upgrade a legacy settings archive without discarding newer target state.

    Args:
        db: Active database session used to export retained sections.
        archive: Candidate archive supplied by an operator.

    Returns:
        A schema-v2 archive ready for complete preflight validation.
    """
    if not isinstance(archive, dict) or archive.get("schema_version") != LEGACY_ARCHIVE_SCHEMA_VERSION:
        return archive
    if not isinstance(archive.get("data"), dict):
        return archive
    prepared = deepcopy(archive)
    retained = export_settings_archive(db, actor="legacy-settings-archive-migration")["data"]
    for section_name in ARCHIVE_SECTION_NAMES.difference(prepared["data"]):
        prepared["data"][section_name] = deepcopy(retained[section_name])
    prepared["schema_version"] = ARCHIVE_SCHEMA_VERSION
    return prepared


def _validate_archive(
    archive: dict[str, Any],
    *,
    allow_legacy_incomplete: bool = False,
) -> None:
    """Validate archive.

    Args:
        archive: Candidate archive to validate.
        allow_legacy_incomplete: Allow summary validation before database-backed migration.


    Raises:
        ValueError: If an input value is invalid.
    """
    if not isinstance(archive, dict) or archive.get("kind") != ARCHIVE_KIND:
        raise ValueError("Upload a Atlaso settings archive.")
    schema_version = archive.get("schema_version")
    if schema_version not in {LEGACY_ARCHIVE_SCHEMA_VERSION, ARCHIVE_SCHEMA_VERSION}:
        raise ValueError("This settings archive schema is not supported by this Atlaso build.")
    if not isinstance(archive.get("data"), dict):
        raise ValueError("The settings archive is missing its data section.")
    data = archive["data"]
    if any(section_name not in ARCHIVE_SECTION_NAMES for section_name in data):
        raise ValueError("The settings archive contains an unsupported data section.")
    missing_sections = ARCHIVE_SECTION_NAMES.difference(data)
    legacy_incomplete = bool(
        missing_sections
        and allow_legacy_incomplete
        and schema_version == LEGACY_ARCHIVE_SCHEMA_VERSION
    )
    if missing_sections and not legacy_incomplete:
        raise ValueError("The settings archive is missing a required data section.")
    for section_name, rows in data.items():
        if not isinstance(rows, list):
            raise ValueError(f"The settings archive data section '{section_name}' must be a list.")
        if section_name in ARCHIVE_SINGLETON_SECTIONS and len(rows) != 1:
            raise ValueError(
                f"The settings archive data section '{section_name}' must contain exactly one row."
            )
        if section_name in ARCHIVE_OPTIONAL_SINGLETON_SECTIONS and len(rows) > 1:
            raise ValueError(
                f"The settings archive data section '{section_name}' must contain at most one row."
            )
        required_fields = _archive_required_fields(section_name)
        for row_index, row in enumerate(rows, start=1):
            _validate_archive_row(section_name, row_index, row, required_fields)
    if not legacy_incomplete:
        _validate_archive_relationships(data)


def _validate_archive_relationships(data: dict[str, list[dict[str, Any]]]) -> None:
    """Validate archive relationships that restore resolves by public names.

    Args:
        data: Structurally validated archive data collections.

    Raises:
        ValueError: If a relationship target is empty or absent.
    """
    def require_reference(
        section_name: str,
        row_index: int,
        value: Any,
        known_values: set[Any],
        reference_name: str,
        *,
        optional: bool = False,
    ) -> None:
        """Require one archive relationship to resolve.

        Args:
            section_name: Archive data section being validated.
            row_index: One-based position used in bounded validation feedback.
            value: Relationship value supplied by the archive row.
            known_values: Valid relationship targets from the archive.
            reference_name: Bounded relationship name used in validation feedback.
            optional: Allow an empty relationship value when true.
        """
        if optional and not value:
            return
        if not value or value not in known_values:
            raise ValueError(
                f"The settings archive row {row_index} in '{section_name}' references an unknown {reference_name}."
            )

    def valid_ip_address(value: str) -> bool:
        """Return whether one archive listener token is a valid IP address.

        Args:
            value: Candidate listener address supplied by an archive row.
        """
        try:
            ip_address(value)
        except ValueError:
            return False
        return True

    wan_policy_names = {str(row["name"]) for row in data.get("wan_policies", [])}

    physical_interfaces = {
        str(row["name"]): row
        for row in data.get("physical_interfaces", [])
    }
    vlan_interfaces = {
        str(row["name"]): row
        for row in data.get("vlan_interfaces", [])
    }
    archived_interfaces = [
        PhysicalInterface(**_model_kwargs_with_scalar_defaults(PhysicalInterface, row))
        for row in data.get("physical_interfaces", [])
    ]
    archived_vlans = [
        VlanInterface(**_model_kwargs_with_scalar_defaults(VlanInterface, row))
        for row in data.get("vlan_interfaces", [])
    ]
    for row_index, row in enumerate(data.get("vlan_interfaces", []), start=1):
        enabled = row.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(
                f"The settings archive row {row_index} in 'vlan_interfaces' has an invalid enabled value."
            )
        if not enabled:
            continue
        parent = physical_interfaces.get(str(row["parent_interface"] or ""))
        parent_is_missing = (
            parent is None
            or (
                str(parent.get("inventory_source") or "") == "host"
                and str(parent.get("oper_state") or "") == "missing"
            )
        )
        if parent_is_missing or normalize_interface_mode(parent.get("mode")) != "trunk":
            raise ValueError(
                f"The settings archive row {row_index} in 'vlan_interfaces' has an ineligible parent interface."
            )
    network_errors = validate_network_state(
        interfaces=archived_interfaces,
        vlans=archived_vlans,
    )
    if network_errors:
        raise ValueError(
            f"The settings archive network state is invalid: {network_errors[0]}"
        )

    def address_families(row: dict[str, Any]) -> set[str]:
        """Return valid IP CIDR families supplied by one archived interface.

        Args:
            row: Structurally validated archived interface row.
        """
        families: set[str] = set()
        for field_name, family, version in (("ip_cidr", "ipv4", 4), ("ipv6_cidr", "ipv6", 6)):
            try:
                parsed = ip_interface(str(row.get(field_name) or ""))
            except ValueError:
                continue
            if parsed.version == version:
                families.add(family)
        return families

    dhcp_target_families = {
        name: address_families(row)
        for name, row in physical_interfaces.items()
        if str(row.get("oper_state") or "") != "missing"
        and normalize_interface_mode(row.get("mode")) != "trunk"
        and address_families(row)
    }
    dhcp_target_families.update(
        {
            str(row["name"]): address_families(row)
            for row in data.get("vlan_interfaces", [])
            if row.get("enabled", True) and address_families(row)
        }
    )
    route_target_families = {
        name: families
        for name, families in dhcp_target_families.items()
        if normalize_interface_role((physical_interfaces.get(name) or vlan_interfaces.get(name, {})).get("role"))
        != "management"
    }
    route_target_names = set(route_target_families)
    service_target_names = {
        name
        for name in dhcp_target_families
        if normalize_interface_role((physical_interfaces.get(name) or vlan_interfaces.get(name, {})).get("role"))
        not in {"management", "unused"}
        and (
            name in physical_interfaces
            or str(physical_interfaces.get(str(vlan_interfaces[name].get("parent_interface") or ""), {}).get("oper_state") or "")
            != "missing"
        )
    }
    ldap_target_names: set[str] = set()
    for name, row in physical_interfaces.items():
        effective_row = dict(row)
        if normalize_ipv4_method(row.get("ipv4_method")) == "dhcp":
            effective_row["ip_cidr"] = row.get("host_ip_cidr")
        effective_row["ipv6_cidr"] = row.get("ipv6_cidr") or row.get("host_ipv6_cidr")
        if (
            str(row.get("oper_state") or "") != "missing"
            and str(row.get("admin_state") or "up") == "up"
            and normalize_interface_mode(row.get("mode")) != "trunk"
            and normalize_interface_role(row.get("role")) not in {"management", "unused"}
            and address_families(effective_row)
        ):
            ldap_target_names.add(name)

    firewall_source_groups_json = next(
        (
            str(row.get("value") or "")
            for row in data.get("settings", [])
            if str(row.get("key") or "") == FIREWALL_SOURCE_GROUPS_SETTING_KEY
        ),
        "",
    )
    firewall_source_groups = firewall_source_group_state(firewall_source_groups_json, {})["groups"]
    firewall_source_group_ids = {str(group.get("id") or "") for group in firewall_source_groups}
    for name, row in vlan_interfaces.items():
        parent = physical_interfaces.get(str(row.get("parent_interface") or ""))
        if (
            row.get("enabled", True)
            and parent is not None
            and str(parent.get("oper_state") or "") != "missing"
            and str(parent.get("admin_state") or "up") == "up"
            and normalize_interface_role(row.get("role")) not in {"management", "unused"}
            and address_families(row)
        ):
            ldap_target_names.add(name)

    oidc_target_addresses: dict[str, list[str]] = {}
    for name in ldap_target_names:
        row = physical_interfaces.get(name) or vlan_interfaces.get(name, {})
        ipv4_cidr = row.get("ip_cidr")
        ipv6_cidr = row.get("ipv6_cidr")
        if name in physical_interfaces:
            if normalize_ipv4_method(row.get("ipv4_method")) == "dhcp":
                ipv4_cidr = row.get("host_ip_cidr")
            ipv6_cidr = row.get("ipv6_cidr") or row.get("host_ipv6_cidr")
        addresses: list[str] = []
        for cidr in (ipv4_cidr, ipv6_cidr):
            try:
                address = str(ip_interface(str(cidr or "")).ip)
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)
        oidc_target_addresses[name] = addresses

    appliance_row = data["appliance_settings"][0]
    appliance_settings = ApplianceSettings(
        **_model_kwargs_with_scalar_defaults(ApplianceSettings, appliance_row)
    )
    management_interface = management_interface_context(archived_interfaces)
    options = web_terminal_interface_options(archived_interfaces, archived_vlans)
    if appliance_row.get("web_terminal_enabled", False):
        if not appliance_row.get("management_https_enabled", False):
            raise ValueError(
                "The settings archive enables Web Terminal without Management UI HTTPS."
            )
        selected_interfaces = normalized_web_terminal_interfaces(
            appliance_settings,
            management_interface,
        )
        options_by_name = {str(option["name"]): option for option in options}
        if not management_interface.get("name") or any(
            name not in options_by_name
            or not bool(options_by_name[name].get("web_terminal_allowed", True))
            for name in selected_interfaces
        ):
            raise ValueError(
                "The settings archive appliance settings select an ineligible Web Terminal interface."
            )
    ca_row = data["ca_settings"][0]
    management_certificate_ready = any(
        str(row.get("managed_owner") or "") == "appliance:https"
        and str(row.get("status") or "") == "issued"
        and bool(str(row.get("certificate_pem") or ""))
        and bool(str(row.get("private_key_encrypted") or ""))
        for row in data.get("ca_certificates", [])
    )
    appliance_errors, _appliance_warnings = validate_appliance_settings(
        appliance_settings,
        local_dns_enabled=bool(data["dns_settings"][0].get("enabled", False)),
        management_interface=management_interface,
        ca_enabled=bool(ca_row.get("enabled", False)),
        management_https_cert_available=management_certificate_ready,
        web_terminal_options=options,
    )
    if appliance_errors:
        raise ValueError(
            f"The settings archive Appliance Settings are invalid: {appliance_errors[0]}"
        )

    for section_name, target_names, require_listener, address_requirement in (
        ("dns_settings", service_target_names, True, "authoritative"),
        ("ntp_settings", service_target_names, True, "enabled"),
        ("ca_settings", service_target_names, False, "never"),
        ("kms_settings", service_target_names, True, "enabled"),
        ("ldap_settings", ldap_target_names, True, "enabled"),
        ("oidc_provider_settings", ldap_target_names, True, "enabled"),
        ("vcf_backup_settings", service_target_names, True, "enabled"),
        ("vcf_private_registry_settings", service_target_names, True, "enabled"),
        ("vcf_offline_depot_settings", service_target_names, True, "enabled"),
    ):
        for row_index, row in enumerate(data.get(section_name, []), start=1):
            enabled = row.get("enabled", False)
            if not isinstance(enabled, bool):
                raise ValueError(
                    f"The settings archive row {row_index} in '{section_name}' has an invalid enabled value."
                )
            if not enabled:
                continue
            selected_interfaces = split_interfaces(str(row.get("listen_interface") or ""))
            if require_listener and not selected_interfaces:
                raise ValueError(
                    f"The settings archive row {row_index} in '{section_name}' has no listen interface."
                )
            if any(interface_name not in target_names for interface_name in selected_interfaces):
                raise ValueError(
                    f"The settings archive row {row_index} in '{section_name}' has an ineligible listen interface."
                )
            address_required = address_requirement == "enabled" or (
                address_requirement == "authoritative" and row.get("authoritative", False)
            )
            selected_addresses = split_addresses(str(row.get("listen_address") or ""))
            if address_required and not selected_addresses:
                raise ValueError(
                    f"The settings archive row {row_index} in '{section_name}' has no listen address."
                )
            if any(not valid_ip_address(address) for address in selected_addresses):
                raise ValueError(
                    f"The settings archive row {row_index} in '{section_name}' has an invalid listen address."
                )

    conditional_forwarders = next(
        (
            str(row.get("value") or "")
            for row in data.get("settings", [])
            if str(row.get("key") or "") == DNS_CONDITIONAL_FORWARDERS_SETTING_KEY
        ),
        "",
    )
    dns_errors = validate_dns_settings(
        DnsSettings(**_model_kwargs_with_scalar_defaults(DnsSettings, data["dns_settings"][0])),
        [
            DnsRecord(**_model_kwargs_with_scalar_defaults(DnsRecord, row))
            for row in data.get("dns_records", [])
        ],
        conditional_forwarders,
    )
    if dns_errors:
        raise ValueError(
            f"The settings archive DNS settings are invalid: {dns_errors[0]}"
        )

    for row in data.get("ntp_settings", []):
        ntp_errors = validate_ntp_state(
            NtpSettings(**_model_kwargs_with_scalar_defaults(NtpSettings, row)),
            service_target_names,
        )
        if ntp_errors:
            raise ValueError(
                f"The settings archive NTP settings are invalid: {ntp_errors[0]}"
            )
        if row.get("nts_server_enabled", False):
            nts_certificate_ready = any(
                str(certificate.get("managed_owner") or "") == "ntp:nts"
                and str(certificate.get("status") or "") == "issued"
                and bool(str(certificate.get("certificate_pem") or ""))
                and bool(str(certificate.get("private_key_encrypted") or ""))
                for certificate in data.get("ca_certificates", [])
            )
            if not data["ca_settings"][0].get("enabled", False) or not nts_certificate_ready:
                raise ValueError(
                    "The settings archive enables NTPsec NTS server mode without an enabled CA and issued NTS certificate."
                )

    for row_index, row in enumerate(data.get("firewall_rules", []), start=1):
        candidate = FirewallRule(
            name=str(row.get("name") or ""),
            direction=str(row.get("direction") or "input"),
            action=str(row.get("action") or "accept"),
            protocol=str(row.get("protocol") or "tcp"),
            source=str(row.get("source") or "any"),
            destination=str(row.get("destination") or "any"),
            destination_port=str(row.get("destination_port") or ""),
            interface_name=str(row.get("interface_name") or ""),
            priority=row.get("priority", 100),
            enabled=row.get("enabled", True),
            description=row.get("description"),
        )
        if validate_firewall_rule(candidate, firewall_source_groups):
            raise ValueError(
                f"The settings archive row {row_index} in 'firewall_rules' has an invalid source or destination."
            )
    firewall_errors = validate_firewall_state(
        FirewallSettings(
            **_model_kwargs_with_scalar_defaults(
                FirewallSettings,
                data["firewall_settings"][0],
            )
        ),
        [
            FirewallRule(**_model_kwargs_with_scalar_defaults(FirewallRule, row))
            for row in data.get("firewall_rules", [])
        ],
        source_groups=firewall_source_groups,
    )
    if firewall_errors:
        raise ValueError(
            f"The settings archive Firewall state is invalid: {firewall_errors[0]}"
        )

    for row_index, row in enumerate(data.get("routes", []), start=1):
        enabled = row.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(
                f"The settings archive row {row_index} in 'routes' has an invalid enabled value."
            )
        if enabled and str(row.get("interface_name") or "") not in route_target_names:
            raise ValueError(
                f"The settings archive row {row_index} in 'routes' has an ineligible target interface."
            )
        require_reference(
            "routes",
            row_index,
            str(row.get("wan_policy_name") or ""),
            wan_policy_names,
            "WAN policy",
            optional=True,
        )

    for row_index, row in enumerate(data.get("nat_rules", []), start=1):
        enabled = row.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(
                f"The settings archive row {row_index} in 'nat_rules' has an invalid enabled value."
            )
        if enabled and "ipv4" not in route_target_families.get(str(row.get("outbound_interface") or ""), set()):
            raise ValueError(
                f"The settings archive row {row_index} in 'nat_rules' has an ineligible outbound interface."
            )
        if enabled and validate_nat_source(
            str(row.get("source") or ""),
            firewall_source_group_ids,
            firewall_source_groups,
        ):
            raise ValueError(
                f"The settings archive row {row_index} in 'nat_rules' has an invalid source."
            )

    for row_index, row in enumerate(data.get("routing_rules", []), start=1):
        enabled = row.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(
                f"The settings archive row {row_index} in 'routing_rules' has an invalid enabled value."
            )
        source = str(row.get("source_interface") or "")
        destination = str(row.get("destination_interface") or "")
        if enabled and (source not in route_target_names or destination not in route_target_names):
            raise ValueError(
                f"The settings archive row {row_index} in 'routing_rules' has an ineligible interface."
            )
        if enabled and source == destination:
            raise ValueError(
                f"The settings archive row {row_index} in 'routing_rules' has identical source and destination interfaces."
            )

    policy_ids = {
        str(row["name"]): row_index
        for row_index, row in enumerate(data.get("wan_policies", []), start=1)
    }
    wan_errors = validate_wan_state(
        [
            Route(
                **_model_kwargs_with_scalar_defaults(Route, row, exclude={"wan_policy_id"}),
                wan_policy_id=policy_ids.get(str(row.get("wan_policy_name") or "")),
            )
            for row in data.get("routes", [])
        ],
        [
            WanPolicy(
                id=policy_ids[str(row["name"])],
                **_model_kwargs_with_scalar_defaults(WanPolicy, row),
            )
            for row in data.get("wan_policies", [])
        ],
        route_target_names,
        nat_rules=[
            NatRule(**_model_kwargs_with_scalar_defaults(NatRule, row))
            for row in data.get("nat_rules", [])
        ],
        wan_target_names={
            name for name, families in route_target_families.items() if "ipv4" in families
        },
        source_groups=firewall_source_groups,
        routing_rules=[
            RoutingRule(**_model_kwargs_with_scalar_defaults(RoutingRule, row))
            for row in data.get("routing_rules", [])
        ],
        routing_target_names=route_target_names,
    )
    if wan_errors:
        raise ValueError(
            f"The settings archive Routes and WAN state is invalid: {wan_errors[0]}"
        )

    dhcp_enabled = False
    for row_index, row in enumerate(data.get("dhcp_settings", []), start=1):
        enabled = row.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError(
                f"The settings archive row {row_index} in 'dhcp_settings' has an invalid enabled value."
            )
        dhcp_enabled = dhcp_enabled or enabled
    if dhcp_enabled:
        enabled_dhcp_networks = []
        scopes = data.get("dhcp_scopes", [])
        if scopes:
            enabled_scope_count = 0
            for row_index, row in enumerate(scopes, start=1):
                enabled = row.get("enabled", True)
                if not isinstance(enabled, bool):
                    raise ValueError(
                        f"The settings archive row {row_index} in 'dhcp_scopes' has an invalid enabled value."
                    )
                family = str(row.get("address_family") or "ipv4").strip().lower()
                interface_name = str(row.get("interface_name") or "")
                if enabled and family not in dhcp_target_families.get(interface_name, set()):
                    raise ValueError(
                        f"The settings archive row {row_index} in 'dhcp_scopes' has an ineligible bind interface."
                    )
                if enabled:
                    enabled_scope_count += 1
                    scope_errors, network = validate_dhcp_scope(
                        DhcpScope(**_model_kwargs(DhcpScope, row))
                    )
                    if scope_errors or network is None:
                        raise ValueError(
                            f"The settings archive row {row_index} in 'dhcp_scopes' is invalid."
                        )
                    enabled_dhcp_networks.append(network)
            if enabled_scope_count == 0:
                raise ValueError(
                    "The settings archive enables DHCP without an enabled DHCP scope."
                )
        else:
            for row_index, row in enumerate(data.get("dhcp_settings", []), start=1):
                if row.get("enabled", False) and "ipv4" not in dhcp_target_families.get(
                    str(row.get("interface_name") or ""), set()
                ):
                    raise ValueError(
                        f"The settings archive row {row_index} in 'dhcp_settings' has an ineligible bind interface."
                    )
                if row.get("enabled", False):
                    legacy_errors = validate_dhcp_settings(
                        DhcpSettings(
                            **_model_kwargs_with_scalar_defaults(DhcpSettings, row)
                        ),
                        [],
                        scopes=[],
                        options=[],
                    )
                    if legacy_errors:
                        raise ValueError(
                            f"The settings archive DHCP settings are invalid: {legacy_errors[0]}"
                        )
                    try:
                        enabled_dhcp_networks.append(
                            ip_network(
                                f"{ip_address(str(row.get('site_address') or ''))}/{int(row.get('prefix_length') or 0)}",
                                strict=False,
                            )
                        )
                    except (TypeError, ValueError) as exc:
                        raise ValueError(
                            f"The settings archive row {row_index} in 'dhcp_settings' is invalid."
                        ) from exc
        for row_index, row in enumerate(data.get("dhcp_reservations", []), start=1):
            if not row.get("enabled", True):
                continue
            try:
                reservation_address = ip_address(str(row.get("ip_address") or ""))
            except ValueError as exc:
                raise ValueError(
                    f"The settings archive row {row_index} in 'dhcp_reservations' has an invalid IP address."
                ) from exc
            if enabled_dhcp_networks and not any(
                reservation_address in network for network in enabled_dhcp_networks
            ):
                raise ValueError(
                    f"The settings archive row {row_index} in 'dhcp_reservations' is outside every enabled DHCP scope."
                )

    dhcp_scope_names = {str(row["name"]) for row in data.get("dhcp_scopes", [])}
    for row_index, row in enumerate(data.get("dhcp_options", []), start=1):
        require_reference(
            "dhcp_options",
            row_index,
            str(row.get("scope_name") or ""),
            dhcp_scope_names,
            "DHCP scope",
            optional=True,
        )

    ca_profiles = {
        str(row["name"]): bool(row.get("enabled", True))
        for row in data.get("ca_profiles", [])
    }
    ca_profile_names = set(ca_profiles)
    for row_index, row in enumerate(data.get("ca_certificates", []), start=1):
        profile_name = str(row.get("profile_name") or "")
        require_reference(
            "ca_certificates",
            row_index,
            profile_name,
            ca_profile_names,
            "CA profile",
            optional=True,
        )
        if row.get("enabled", True) and profile_name and not ca_profiles[profile_name]:
            raise ValueError(
                f"The settings archive row {row_index} in 'ca_certificates' references a disabled CA profile."
            )

    ca_profile_ids = {
        str(row["name"]): row_index
        for row_index, row in enumerate(data.get("ca_profiles", []), start=1)
    }
    ca_errors = validate_ca_state(
        settings=CaSettings(
            **_model_kwargs_with_scalar_defaults(CaSettings, ca_row)
        ),
        profiles=[
            CaProfile(
                id=ca_profile_ids[str(row["name"])],
                **_model_kwargs_with_scalar_defaults(CaProfile, row),
            )
            for row in data.get("ca_profiles", [])
        ],
        certificates=[
            CaCertificate(
                **_model_kwargs_with_scalar_defaults(
                    CaCertificate,
                    row,
                    exclude={"profile_id"},
                ),
                profile_id=ca_profile_ids.get(str(row.get("profile_name") or "")),
            )
            for row in data.get("ca_certificates", [])
        ],
    )
    if ca_errors:
        raise ValueError(
            f"The settings archive Certificate Authority state is invalid: {ca_errors[0]}"
        )

    kms_row = data["kms_settings"][0]
    kms_settings = KmsSettings(
        **_model_kwargs_with_scalar_defaults(KmsSettings, kms_row)
    )
    if kms_settings.backend != "atlaso-kmip":
        raise ValueError(
            "The settings archive KMS state is invalid: KMS backend must be atlaso-kmip."
        )
    if not 1 <= kms_settings.port <= 65535:
        raise ValueError(
            "The settings archive KMS state is invalid: KMS port must be between 1 and 65535."
        )
    try:
        normalized_kms_hostname = normalize_service_hostname(kms_settings.hostname)
    except ValueError as exc:
        raise ValueError(f"The settings archive KMS state is invalid: {exc}") from exc
    if normalized_kms_hostname != kms_settings.hostname:
        raise ValueError(
            "The settings archive KMS state is invalid: KMS hostname must be normalized."
        )
    if kms_settings.database_path != KMS_DEFAULT_DATABASE_PATH:
        raise ValueError(
            "The settings archive KMS state is invalid: KMS database path must use the fixed appliance path."
        )
    if kms_settings.config_path != KMS_DEFAULT_CONFIG_PATH:
        raise ValueError(
            "The settings archive KMS state is invalid: KMS config path must use the fixed appliance path."
        )
    if (
        not kms_settings.ca_certificate_path.startswith("/")
        or not kms_settings.require_client_cert
        or kms_settings.allow_register
        or kms_settings.allow_destroy
    ):
        raise ValueError(
            "The settings archive KMS state is invalid: KMS must retain bounded certificate and operation policy."
        )
    if kms_row.get("enabled", False):
        ca_row = data["ca_settings"][0]
        kms_certificate_ready = any(
            str(row.get("managed_owner") or "") == "kms:server"
            and str(row.get("status") or "") == "issued"
            and bool(str(row.get("certificate_pem") or ""))
            and bool(str(row.get("private_key_encrypted") or ""))
            for row in data.get("ca_certificates", [])
        )
        if not ca_row.get("enabled", False) or not kms_certificate_ready:
            raise ValueError(
                "The settings archive enables KMS without an enabled CA and issued KMS server certificate."
            )

    enabled_oidc_rows = [
        row for row in data.get("oidc_provider_settings", []) if row.get("enabled", False)
    ]
    if enabled_oidc_rows:
        active_signing_key_ready = any(
            str(row.get("status") or "") == "active"
            and row.get("active_slot") == 1
            and bool(str(row.get("private_key_encrypted") or ""))
            and bool(str(row.get("public_jwk_json") or ""))
            for row in data.get("oidc_signing_keys", [])
        )
        oidc_certificate_ready = any(
            str(row.get("managed_owner") or "") == "oidc:https"
            and str(row.get("status") or "") == "issued"
            and bool(str(row.get("certificate_pem") or ""))
            and bool(str(row.get("private_key_encrypted") or ""))
            for row in data.get("ca_certificates", [])
        )
        if not active_signing_key_ready or not oidc_certificate_ready:
            raise ValueError(
                "The settings archive enables OIDC without an active signing key and issued HTTPS certificate."
            )
        for row_index, row in enumerate(enabled_oidc_rows, start=1):
            provider = OidcProviderSettings(
                **_model_kwargs_with_scalar_defaults(OidcProviderSettings, row)
            )
            if not 1 <= int(provider.port or 0) <= 65535:
                raise ValueError(
                    f"The settings archive row {row_index} in 'oidc_provider_settings' has an invalid HTTPS port."
                )
            try:
                normalized_issuer = normalize_issuer_url(provider.issuer_url)
            except OidcConfigurationError as exc:
                raise ValueError(
                    f"The settings archive row {row_index} in 'oidc_provider_settings' is invalid: {exc}"
                ) from exc
            if normalized_issuer != expected_issuer_url(provider):
                raise ValueError(
                    f"The settings archive row {row_index} in 'oidc_provider_settings' has an issuer URL that does not match its hostname and port."
                )
            if not provider.hostname or "." not in normalize_fqdn(provider.hostname):
                raise ValueError(
                    f"The settings archive row {row_index} in 'oidc_provider_settings' has an invalid hostname."
                )
            if (
                provider.access_token_lifetime_seconds != OIDC_TOKEN_LIFETIME_SECONDS
                or provider.id_token_lifetime_seconds != OIDC_TOKEN_LIFETIME_SECONDS
            ):
                raise ValueError(
                    f"The settings archive row {row_index} in 'oidc_provider_settings' has an unsupported token lifetime."
                )
            derived_addresses: list[str] = []
            for interface_name in split_interfaces(str(row.get("listen_interface") or "")):
                for address in oidc_target_addresses.get(interface_name, []):
                    if address not in derived_addresses:
                        derived_addresses.append(address)
            if split_addresses(str(row.get("listen_address") or "")) != derived_addresses:
                raise ValueError(
                    f"The settings archive row {row_index} in 'oidc_provider_settings' has listener addresses not derived from its interfaces."
                )

    provider_ids = {str(row["id"]) for row in data.get("vsphere_key_providers", [])}
    for row_index, row in enumerate(data.get("vsphere_trusted_vcenters", []), start=1):
        require_reference(
            "vsphere_trusted_vcenters",
            row_index,
            str(row["provider_id"]),
            provider_ids,
            "vSphere Key Provider",
        )
    trusted_vcenter_ids = {str(row["id"]) for row in data.get("vsphere_trusted_vcenters", [])}
    for row_index, row in enumerate(data.get("vsphere_trusted_vcenter_certificates", []), start=1):
        require_reference(
            "vsphere_trusted_vcenter_certificates",
            row_index,
            str(row["trusted_vcenter_id"]),
            trusted_vcenter_ids,
            "trusted vCenter",
        )

    organization_slugs = {str(row["slug"]) for row in data.get("ldap_organizations", [])}
    ldap_row = data["ldap_settings"][0]
    if ldap_row.get("enabled", False) and not organization_slugs:
        raise ValueError(
            "The settings archive enables LDAP without an LDAP organization."
        )
    ca_row = data["ca_settings"][0]
    if (
        ldap_row.get("enabled", False)
        and ldap_row.get("ldaps_enabled", True)
        and (
            not ca_row.get("enabled", False)
            or not str(ca_row.get("root_certificate_pem") or "")
        )
    ):
        raise ValueError(
            "The settings archive enables LDAPS without a ready Certificate Authority."
        )
    ldap_users = {
        (str(row["organization_slug"]), str(row["uid"]))
        for row in data.get("ldap_users", [])
    }
    ldap_groups = {
        (str(row["organization_slug"]), str(row["name"]))
        for row in data.get("ldap_groups", [])
    }
    for section_name in ("ldap_users", "ldap_groups"):
        for row_index, row in enumerate(data.get(section_name, []), start=1):
            organization_slug = str(row["organization_slug"] or "")
            require_reference(
                section_name,
                row_index,
                organization_slug,
                organization_slugs,
                "LDAP organization",
            )
    for row_index, row in enumerate(data.get("ldap_group_memberships", []), start=1):
        organization_slug = str(row["organization_slug"] or "")
        group_name = str(row["group_name"] or "")
        member_type = str(row["member_type"] or "")
        member_name = str(row["member_name"] or "")
        member_exists = (
            (organization_slug, member_name) in ldap_users
            if member_type == "user"
            else (organization_slug, member_name) in ldap_groups
            if member_type == "group"
            else False
        )
        if (
            not organization_slug
            or (organization_slug, group_name) not in ldap_groups
            or not member_exists
        ):
            raise ValueError(
                "The settings archive row "
                f"{row_index} in 'ldap_group_memberships' references an unknown LDAP object."
            )

    ldap_group_edges = {group: set() for group in ldap_groups}
    for row in data.get("ldap_group_memberships", []):
        if str(row.get("member_type") or "") != "group":
            continue
        organization_slug = str(row.get("organization_slug") or "")
        ldap_group_edges[(organization_slug, str(row.get("group_name") or ""))].add(
            (organization_slug, str(row.get("member_name") or ""))
        )
    remaining_edges = dict(ldap_group_edges)
    while remaining_edges:
        remaining_groups = set(remaining_edges)
        terminal_groups = {
            group
            for group, members in remaining_edges.items()
            if not members.intersection(remaining_groups)
        }
        if not terminal_groups:
            raise ValueError("The settings archive contains cyclic LDAP group membership.")
        for group in terminal_groups:
            remaining_edges.pop(group)

    archived_organizations = {
        str(row["slug"]): LdapOrganization(
            id=row_index,
            **_model_kwargs_with_scalar_defaults(LdapOrganization, row),
        )
        for row_index, row in enumerate(data.get("ldap_organizations", []), start=1)
    }
    for row in data.get("ldap_users", []):
        organization = archived_organizations.get(str(row.get("organization_slug") or ""))
        if organization is not None:
            organization.users.append(
                LdapUser(
                    **_model_kwargs_with_scalar_defaults(
                        LdapUser,
                        row,
                        exclude={"organization_id"},
                    )
                )
            )
    ldap_errors, _ldap_warnings = validate_ldap_state(
        LdapSettings(
            **_model_kwargs_with_scalar_defaults(LdapSettings, ldap_row)
        ),
        list(archived_organizations.values()),
        available_interfaces=ldap_target_names,
        ca_ready=bool(ca_row.get("enabled", False) and str(ca_row.get("root_certificate_pem") or "")),
        recovery_staged=True,
    )
    if ldap_errors:
        raise ValueError(
            f"The settings archive LDAP state is invalid: {ldap_errors[0]}"
        )

    oidc_client_ids = {str(row["client_id"]) for row in data.get("oidc_clients", [])}
    for row_index, row in enumerate(data.get("oidc_clients", []), start=1):
        require_reference(
            "oidc_clients",
            row_index,
            str(row.get("organization_slug") or ""),
            organization_slugs,
            "LDAP organization",
            optional=True,
        )
    for row_index, row in enumerate(data.get("oidc_client_redirect_uris", []), start=1):
        require_reference(
            "oidc_client_redirect_uris",
            row_index,
            str(row["client_id"] or ""),
            oidc_client_ids,
            "OIDC client",
        )
    for row_index, row in enumerate(data.get("oidc_subjects", []), start=1):
        source = str(row["source"] or "")
        if source == "managed_ldap":
            require_reference(
                "oidc_subjects",
                row_index,
                (str(row.get("organization_slug") or ""), str(row["username"] or "")),
                ldap_users,
                "managed LDAP user",
            )
        elif source != "local":
            raise ValueError(
                f"The settings archive row {row_index} in 'oidc_subjects' has an unsupported identity source."
            )
    for row_index, row in enumerate(data.get("oidc_group_mappings", []), start=1):
        source_type = str(row["source_type"] or "")
        if source_type == "ldap_group":
            require_reference(
                "oidc_group_mappings",
                row_index,
                (str(row["organization_slug"] or ""), str(row["ldap_group_name"] or "")),
                ldap_groups,
                "managed LDAP group",
            )
        elif source_type != "local_role":
            raise ValueError(
                f"The settings archive row {row_index} in 'oidc_group_mappings' has an unsupported source type."
            )
        require_reference(
            "oidc_group_mappings",
            row_index,
            str(row["client_id"] or ""),
            oidc_client_ids,
            "OIDC client",
            optional=True,
        )

    kickstart_names = {str(row["name"]) for row in data.get("esxi_kickstarts", [])}
    for row_index, row in enumerate(data.get("esxi_pxe_hosts", []), start=1):
        mac_address = str(row.get("mac_address") or "")
        if mac_address and not normalize_host_mac(mac_address):
            raise ValueError(
                f"The settings archive row {row_index} in 'esxi_pxe_hosts' has an invalid MAC address."
            )
        require_reference(
            "esxi_pxe_hosts",
            row_index,
            str(row.get("kickstart_name") or ""),
            kickstart_names,
            "ESXi Kickstart",
            optional=True,
        )

    volume_names = {str(row["name"]) for row in data.get("esx_storage_volumes", [])}
    for row_index, row in enumerate(data.get("esx_nfs_shares", []), start=1):
        require_reference(
            "esx_nfs_shares",
            row_index,
            str(row["volume_name"] or ""),
            volume_names,
            "ESX storage volume",
        )
        if not row.get("enabled", True):
            continue
        interface_name = str(row.get("interface_name") or "")
        requested_families = {
            family.strip().lower()
            for family in str(row.get("address_families") or "").replace(",", "\n").splitlines()
            if family.strip()
        }
        available_families = (
            dhcp_target_families.get(interface_name, set())
            if interface_name in service_target_names
            else set()
        )
        if (
            not requested_families
            or not requested_families.issubset({"ipv4", "ipv6"})
            or not requested_families.issubset(available_families)
        ):
            raise ValueError(
                f"The settings archive row {row_index} in 'esx_nfs_shares' has an ineligible interface or address family."
            )

    volume_ids = {
        str(row["name"]): row_index
        for row_index, row in enumerate(data.get("esx_storage_volumes", []), start=1)
    }
    storage_interfaces: dict[str, StorageInterface] = {}
    for interface_name in service_target_names:
        row = physical_interfaces.get(interface_name) or vlan_interfaces.get(interface_name, {})
        addresses = {"ipv4": [], "ipv6": []}
        for field_name, family in (("ip_cidr", "ipv4"), ("ipv6_cidr", "ipv6")):
            try:
                addresses[family].append(str(ip_interface(str(row.get(field_name) or "")).ip))
            except ValueError:
                continue
        storage_interfaces[interface_name] = StorageInterface(
            interface_name,
            tuple(addresses["ipv4"]),
            tuple(addresses["ipv6"]),
        )
    if data.get("esx_storage_settings"):
        storage_errors, _storage_warnings = validate_storage_state(
            EsxStorageSettings(
                **_model_kwargs_with_scalar_defaults(
                    EsxStorageSettings,
                    data["esx_storage_settings"][0],
                )
            ),
            [
                EsxStorageVolume(
                    id=volume_ids[str(row["name"])],
                    **_model_kwargs_with_scalar_defaults(EsxStorageVolume, row),
                )
                for row in data.get("esx_storage_volumes", [])
            ],
            [
                EsxNfsShare(
                    **_model_kwargs_with_scalar_defaults(
                        EsxNfsShare,
                        row,
                        exclude={"volume_id"},
                    ),
                    volume_id=volume_ids.get(str(row.get("volume_name") or "")),
                )
                for row in data.get("esx_nfs_shares", [])
            ],
            storage_interfaces,
            dns_enabled=bool(data["dns_settings"][0].get("enabled", False)),
        )
        if storage_errors:
            raise ValueError(
                f"The settings archive ESX Storage state is invalid: {storage_errors[0]}"
            )

    update_sources = {
        (str(row["kind"]), str(row["name"]))
        for row in data.get("update_sources", [])
        if str(row["kind"]) in UPDATE_SOURCE_KINDS
    }
    for row_index, row in enumerate(data.get("update_sources", []), start=1):
        if str(row["kind"] or "") not in UPDATE_SOURCE_KINDS:
            raise ValueError(
                f"The settings archive row {row_index} in 'update_sources' has an unsupported source kind."
            )
    for row_index, row in enumerate(data.get("managed_packages", []), start=1):
        source = (str(row.get("source_kind") or ""), str(row.get("source_name") or ""))
        require_reference(
            "managed_packages",
            row_index,
            source if any(source) else None,
            update_sources,
            "update source",
            optional=True,
        )

    profile_names = {str(row["name"]) for row in data.get("vcf_depot_download_profiles", [])}
    script_revisions: set[tuple[str, int]] = set()
    for script_index, script in enumerate(data.get("automation_scripts", []), start=1):
        for revision in script["revisions"]:
            try:
                revision_number = int(revision["revision"])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "The settings archive row "
                    f"{script_index} in 'automation_scripts' has an invalid revision number."
                ) from exc
            script_revisions.add((str(script["name"]), revision_number))
    for row_index, row in enumerate(data.get("schedules", []), start=1):
        task_type = str(row["task_type"] or "")
        if task_type == "vcf_depot_download":
            require_reference(
                "schedules",
                row_index,
                str(row.get("vcf_profile_name") or ""),
                profile_names,
                "VCF depot download profile",
            )
        elif task_type == "managed_script":
            try:
                script_revision = int(row.get("script_revision") or 0)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"The settings archive row {row_index} in 'schedules' has an invalid script revision."
                ) from exc
            require_reference(
                "schedules",
                row_index,
                (str(row.get("script_name") or ""), script_revision),
                script_revisions,
                "automation script revision",
            )

    for row_index, row in enumerate(data.get("settings", []), start=1):
        if str(row["key"] or "") not in SAFE_SETTING_KEYS:
            raise ValueError(
                f"The settings archive row {row_index} in 'settings' has an unsupported setting key."
            )


def _validate_archive_database_relationships(db: Session, data: dict[str, list[dict[str, Any]]]) -> None:
    """Validate archive relationships to desired state retained during restore.

    Args:
        db: Active database session.
        data: Structurally validated archive data collections.

    Raises:
        ValueError: If a relationship target is absent from retained desired state.
    """
    users = {row.username: bool(row.enabled) for row in db.execute(select(User)).scalars().all()}
    usernames = set(users)
    for row_index, row in enumerate(data.get("oidc_subjects", []), start=1):
        if row["source"] == "local" and str(row["username"] or "") not in usernames:
            raise ValueError(
                f"The settings archive row {row_index} in 'oidc_subjects' references an unknown local user."
            )
    for section_name, username_field, creatable_username in (
        ("vcf_backup_settings", "sftp_username", VCF_BACKUP_DEFAULT_USERNAME),
        ("vcf_offline_depot_settings", "http_username", ""),
    ):
        for row_index, row in enumerate(data.get(section_name, []), start=1):
            username = str(row.get(username_field) or "")
            if username and username != creatable_username and username not in usernames:
                raise ValueError(
                    f"The settings archive row {row_index} in '{section_name}' references an unknown local user."
                )

    for row_index, row in enumerate(data.get("vcf_backup_settings", []), start=1):
        username = str(row.get("sftp_username") or "")
        creates_default_user = username == VCF_BACKUP_DEFAULT_USERNAME and username not in users
        if row.get("enabled", False) and not creates_default_user and not users.get(username, False):
            raise ValueError(
                f"The settings archive row {row_index} in 'vcf_backup_settings' requires an enabled local user."
            )
    for row_index, row in enumerate(data.get("vcf_offline_depot_settings", []), start=1):
        username = str(row.get("http_username") or "")
        requires_user = row.get("enabled", False) and not row.get("allow_unauthenticated_access", False)
        if requires_user and not users.get(username, False):
            raise ValueError(
                f"The settings archive row {row_index} in 'vcf_offline_depot_settings' requires an enabled local user."
            )

    archived_users = list(db.execute(select(User)).scalars().all())
    users_by_name = {user.username: user for user in archived_users}
    backup_row = data["vcf_backup_settings"][0]
    backup_username = str(backup_row.get("sftp_username") or "")
    backup_settings = VcfBackupSettings(
        **_model_kwargs_with_scalar_defaults(
            VcfBackupSettings,
            backup_row,
            exclude={"sftp_user_id"},
        ),
        sftp_user_id=(users_by_name.get(backup_username).id if backup_username in users_by_name else None),
    )
    backup_errors = validate_vcf_backup_state(
        backup_settings,
        archived_users,
        interface_names={
            str(row.get("name") or "")
            for row in data.get("physical_interfaces", []) + data.get("vlan_interfaces", [])
        },
    )
    if backup_errors:
        raise ValueError(
            f"The settings archive VCF Backup state is invalid: {backup_errors[0]}"
        )

    registry_errors, _registry_warnings = validate_vcf_registry_state(
        VcfPrivateRegistrySettings(
            **_model_kwargs_with_scalar_defaults(
                VcfPrivateRegistrySettings,
                data["vcf_private_registry_settings"][0],
            )
        ),
        [
            VcfRegistryBundle(
                **_model_kwargs_with_scalar_defaults(VcfRegistryBundle, row)
            )
            for row in data.get("vcf_registry_bundles", [])
        ],
        managed_dns_names={
            normalize_fqdn(str(row.get("hostname") or ""))
            for row in data.get("dns_records", [])
            if row.get("enabled", True)
        },
        interface_names={
            str(row.get("name") or "")
            for row in data.get("physical_interfaces", []) + data.get("vlan_interfaces", [])
        },
        ca_bundle_source=(
            "local-ca" if data["ca_settings"][0].get("enabled", False) else "uploaded"
        ),
        ca_bundle_available=bool(data["ca_settings"][0].get("enabled", False)),
    )
    if registry_errors:
        raise ValueError(
            f"The settings archive VCF Private Registry state is invalid: {registry_errors[0]}"
        )

    depot_row = data["vcf_offline_depot_settings"][0]
    depot_username = str(depot_row.get("http_username") or "")
    depot_errors, _depot_warnings = validate_vcf_depot_state(
        VcfOfflineDepotSettings(
            **_model_kwargs_with_scalar_defaults(
                VcfOfflineDepotSettings,
                depot_row,
                exclude={"http_user_id"},
            ),
            http_user_id=(users_by_name.get(depot_username).id if depot_username in users_by_name else None),
        ),
        [
            VcfDepotDownloadProfile(
                **_model_kwargs_with_scalar_defaults(VcfDepotDownloadProfile, row)
            )
            for row in data.get("vcf_depot_download_profiles", [])
        ],
        download_token_present=True,
        activation_code_present=True,
        interface_names={
            str(row.get("name") or "")
            for row in data.get("physical_interfaces", []) + data.get("vlan_interfaces", [])
        },
        management_interface_names={
            str(row.get("name") or "")
            for row in data.get("physical_interfaces", [])
            if normalize_interface_role(row.get("role")) == "management"
        },
        users=archived_users,
    )
    if depot_errors:
        raise ValueError(
            f"The settings archive VCF Offline Depot state is invalid: {depot_errors[0]}"
        )

    from atlaso.app.services.network_boot import CATALOG_BY_KEY

    installed_media = {
        (row.environment_key, row.version)
        for row in db.execute(select(NetworkBootMedia)).scalars().all()
    }
    for row_index, row in enumerate(data.get("network_boot_environments", []), start=1):
        key = str(row.get("key") or "")
        version = str(row.get("desired_version") or "")
        if key not in CATALOG_BY_KEY:
            raise ValueError(
                f"The settings archive row {row_index} in 'network_boot_environments' has an unsupported environment key."
            )
        if row.get("enabled", False) and not version:
            raise ValueError(
                f"The settings archive row {row_index} in 'network_boot_environments' has no desired version."
            )
        if version and (key, version) not in installed_media:
            raise ValueError(
                f"The settings archive row {row_index} in 'network_boot_environments' references unavailable verified media."
            )


def _archive_required_fields(section_name: str) -> set[str]:
    """Return fields that every row in an archive section must provide.

    Args:
        section_name: Archive data section being validated.
    """
    required_fields = set(ARCHIVE_CUSTOM_REQUIRED_FIELDS.get(section_name, set()))
    model = ARCHIVE_SECTION_MODELS.get(section_name)
    if model is not None:
        required_fields.update(_required_model_fields(model))
    removed_fields, added_fields = ARCHIVE_REQUIRED_FIELD_REPLACEMENTS.get(section_name, (set(), set()))
    required_fields.difference_update(removed_fields)
    required_fields.update(added_fields)
    if section_name == "network_boot_environments":
        required_fields.add("key")
    if section_name == "automation_scripts":
        required_fields.add("revisions")
    return required_fields


def _validate_archive_row(
    section_name: str,
    row_index: int,
    row: Any,
    required_fields: set[str],
) -> None:
    """Validate one archive row without changing database or process state.

    Args:
        section_name: Archive data section being validated.
        row_index: One-based position used in bounded validation feedback.
        row: Candidate archive row.
        required_fields: Fields required by the section contract.
    """
    if not isinstance(row, dict):
        raise ValueError(f"The settings archive row {row_index} in '{section_name}' must be an object.")
    model = ARCHIVE_SECTION_MODELS.get(section_name)
    if model is not None:
        for column in model.__table__.columns:
            value = row.get(column.name)
            if value is None or isinstance(column.type, SqlDateTime):
                continue
            try:
                expected_type = column.type.python_type
            except NotImplementedError:
                continue
            valid_type = (
                type(value) is expected_type
                if expected_type in {bool, int, str}
                else isinstance(value, expected_type)
            )
            if not valid_type:
                type_label = {
                    bool: "a boolean",
                    int: "an integer",
                    str: "a string",
                }.get(expected_type, f"a {expected_type.__name__}")
                raise ValueError(
                    f"The settings archive row {row_index} in '{section_name}' field '{column.name}' must be {type_label}."
                )
    missing_fields = sorted(field for field in required_fields if field not in row or row[field] is None)
    if missing_fields:
        raise ValueError(
            f"The settings archive row {row_index} in '{section_name}' is missing required field '{missing_fields[0]}'."
        )
    blank_allowed = ARCHIVE_BLANK_REQUIRED_TEXT_FIELDS.get(section_name, set())
    blank_fields = sorted(
        field
        for field in required_fields
        if field not in blank_allowed and isinstance(row[field], str) and not row[field].strip()
    )
    if blank_fields:
        raise ValueError(
            f"The settings archive row {row_index} in '{section_name}' has empty required field '{blank_fields[0]}'."
        )
    if section_name == "automation_scripts":
        revisions = row["revisions"]
        if not isinstance(revisions, list):
            raise ValueError(
                f"The settings archive row {row_index} in 'automation_scripts' has a revisions value that must be a list."
            )
        revision_required_fields = _required_model_fields(
            AutomationScriptRevision,
            exclude={"script_id", "enabled"},
        )
        for revision_index, revision in enumerate(revisions, start=1):
            _validate_archive_row(
                f"automation_scripts[{row_index}].revisions",
                revision_index,
                revision,
                revision_required_fields,
            )
    if section_name == "esxi_pxe_hosts" and "variables" in row and not isinstance(row["variables"], dict):
        raise ValueError(
            f"The settings archive row {row_index} in 'esxi_pxe_hosts' has a variables value that must be an object."
        )


def _required_model_fields(model: type, *, exclude: set[str] | None = None) -> set[str]:
    """Return required non-generated fields for a persisted model.

    Args:
        model: SQLAlchemy model whose archive inputs are validated.
        exclude: Fields supplied by the restore relationship or normalization logic.
    """
    excluded = {"id", "created_at", "updated_at", *(exclude or set())}
    return {
        column.name
        for column in model.__table__.columns
        if column.name not in excluded
        and not column.primary_key
        and not column.nullable
        and column.default is None
        and column.server_default is None
        and not isinstance(column.type, SqlDateTime)
    }


def _insert_rows(db: Session, model: type, rows: list[dict[str, Any]]) -> int:
    """Create rows.

    Args:
        db: Active database session.
        model: Model supplied by the caller.
        rows: Database or collection rows to process.

    Returns:
        The insert rows result.
    """
    for row in rows:
        db.add(model(**_model_kwargs(model, row)))
    db.flush()
    return len(rows)


def _restore_update_sources(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore update sources.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    rows = [row for row in rows if str(row.get("kind") or "") in UPDATE_SOURCE_KINDS]
    if not rows:
        seed_update_sources(db)
        db.flush()
        return len(db.execute(select(UpdateSource)).scalars().all())
    for row in rows:
        payload = _model_kwargs(
            UpdateSource,
            row,
            exclude={"credential_encrypted", "validation_status", "validation_message"},
        )
        payload.update(
            {
                "credential_encrypted": "",
                "validation_status": "not_checked",
                "validation_message": "Credentials are not included in settings archives; synchronize this source after restore.",
            }
        )
        db.add(UpdateSource(**payload))
    db.flush()
    return len(rows)


def _restore_managed_packages(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore managed packages.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    if not rows:
        return len(db.execute(select(ManagedPackage)).scalars().all())
    sources = {
        (source.kind, source.name): source.id
        for source in db.execute(select(UpdateSource)).scalars().all()
    }
    for row in rows:
        payload = _model_kwargs(ManagedPackage, row, exclude={"source_id"})
        payload["source_id"] = sources.get((str(row.get("source_kind") or ""), str(row.get("source_name") or "")))
        db.add(ManagedPackage(**payload))
    db.flush()
    return len(rows)


def _restore_automation_scripts(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore automation scripts.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    for row in rows:
        script = AutomationScript(**_model_kwargs(AutomationScript, row))
        db.add(script)
        db.flush()
        for revision_row in row.get("revisions", []):
            if not isinstance(revision_row, dict):
                continue
            payload = _model_kwargs(AutomationScriptRevision, revision_row, exclude={"script_id", "enabled"})
            payload.update({"script_id": script.id, "enabled": False})
            db.add(AutomationScriptRevision(**payload))
    db.flush()
    return len(rows)


def _restore_schedules(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore schedules.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    profiles = {profile.name: profile.id for profile in db.execute(select(VcfDepotDownloadProfile)).scalars().all()}
    scripts = {script.name: script.id for script in db.execute(select(AutomationScript)).scalars().all()}
    revisions = {
        (revision.script_id, revision.revision): revision.id
        for revision in db.execute(select(AutomationScriptRevision)).scalars().all()
    }
    for row in rows:
        payload = _model_kwargs(
            Schedule,
            row,
            exclude={"enabled", "next_run_at", "last_run_at", "last_job_id", "run_once_at"},
        )
        raw_once = row.get("run_once_at")
        payload.update(
            {
                "enabled": False,
                "next_run_at": None,
                "last_run_at": None,
                "last_job_id": "",
                "run_once_at": datetime.fromisoformat(raw_once) if isinstance(raw_once, str) and raw_once else None,
            }
        )
        try:
            config = json.loads(str(payload.get("task_config_json") or "{}"))
        except json.JSONDecodeError:
            config = {}
        task_type = str(payload.get("task_type") or "")
        if task_type in {"appliance_update_check", "appliance_update_install"}:
            streams = config.get("selected_streams")
            normalized: list[str] = []
            for value in streams if isinstance(streams, list) else []:
                stream = str(value)
                if stream in {"photon_os", "powershell_modules", "atlaso_release"} and stream not in normalized:
                    normalized.append(stream)
            config["selected_streams"] = normalized
        if task_type == "vcf_depot_download":
            config["profile_id"] = profiles.get(str(row.get("vcf_profile_name") or ""), 0)
        elif task_type == "managed_script":
            script_id = scripts.get(str(row.get("script_name") or ""), 0)
            config["revision_id"] = revisions.get((script_id, int(row.get("script_revision") or 0)), 0)
        payload["task_config_json"] = json.dumps(config, sort_keys=True)
        db.add(Schedule(**payload))
    db.flush()
    return len(rows)


def _model_kwargs(model: type, row: dict[str, Any], *, exclude: set[str] | None = None) -> dict[str, Any]:
    """Return model kwargs.

    Args:
        model: Model consumed by model kwargs.
        row: Persistent database row affected by the operation.
        exclude: Exclude consumed by model kwargs.
    """
    excluded = {"id", "created_at", "updated_at", *(exclude or set())}
    column_names = {column.name for column in model.__table__.columns if not isinstance(column.type, SqlDateTime)}
    return {key: value for key, value in row.items() if key in column_names and key not in excluded}


def _model_kwargs_with_scalar_defaults(
    model: type,
    row: dict[str, Any],
    *,
    exclude: set[str] | None = None,
) -> dict[str, Any]:
    """Return model kwargs with database scalar defaults applied for validation.

    Args:
        model: Model consumed by model kwargs.
        row: Persistent database row affected by the operation.
        exclude: Exclude consumed by model kwargs.
    """
    payload = _model_kwargs(model, row, exclude=exclude)
    for column in model.__table__.columns:
        if column.name not in payload and column.default is not None and column.default.is_scalar:
            payload[column.name] = column.default.arg
    return payload


def _restore_routes(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore routes.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    policies = {policy.name: policy.id for policy in db.execute(select(WanPolicy)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(Route, row, exclude={"wan_policy_id"})
        policy_name = str(row.get("wan_policy_name") or "")
        payload["wan_policy_id"] = policies.get(policy_name) if policy_name else None
        db.add(Route(**payload))
    db.flush()
    return len(rows)


def _restore_dhcp_options(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore dhcp options.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    scopes = {scope.name: scope.id for scope in db.execute(select(DhcpScope)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(DhcpOption, row, exclude={"scope_id"})
        scope_name = str(row.get("scope_name") or "")
        payload["scope_id"] = scopes.get(scope_name) if scope_name else None
        db.add(DhcpOption(**payload))
    db.flush()
    return len(rows)


def _restore_ca_certificates(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore ca certificates.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    profiles = {profile.name: profile.id for profile in db.execute(select(CaProfile)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(CaCertificate, row, exclude={"profile_id", "issued_at", "expires_at"})
        profile_name = str(row.get("profile_name") or "")
        payload["profile_id"] = profiles.get(profile_name) if profile_name else None
        db.add(CaCertificate(**payload))
    db.flush()
    return len(rows)


def _restore_vsphere_key_providers(db: Session, rows: list[dict[str, Any]]) -> int:
    """Restore provider UUIDs and public desired-state metadata.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    for row in rows:
        db.add(
            VsphereKeyProvider(
                id=str(row["id"]),
                name=str(row["name"]),
                description=str(row.get("description") or ""),
                enabled=bool(row.get("enabled", False)),
            )
        )
    db.flush()
    return len(rows)


def _restore_vsphere_trusted_vcenters(db: Session, rows: list[dict[str, Any]]) -> int:
    """Restore trusted-vCenter rows without changing provider UUIDs.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    provider_ids = set(db.execute(select(VsphereKeyProvider.id)).scalars().all())
    for row in rows:
        provider_id = str(row["provider_id"])
        if provider_id not in provider_ids:
            raise ValueError("Archived trusted vCenter references an unknown provider UUID.")
        db.add(
            VsphereTrustedVcenter(
                id=str(row["id"]),
                provider_id=provider_id,
                name=str(row["name"]),
                hostname=str(row.get("hostname") or ""),
                description=str(row.get("description") or ""),
                enabled=bool(row.get("enabled", False)),
            )
        )
    db.flush()
    return len(rows)


def _restore_vsphere_certificates(db: Session, rows: list[dict[str, Any]]) -> int:
    """Restore and revalidate public certificate trust records.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    from atlaso.app.services.vsphere_key_providers import parse_public_certificate

    vcenter_ids = set(db.execute(select(VsphereTrustedVcenter.id)).scalars().all())
    fingerprints: set[str] = set()
    for row in rows:
        vcenter_id = str(row["trusted_vcenter_id"])
        if vcenter_id not in vcenter_ids:
            raise ValueError("Archived public certificate references an unknown trusted vCenter UUID.")
        fingerprint = str(row["fingerprint_sha256"]).replace(":", "").casefold()
        if fingerprint in fingerprints:
            raise ValueError("Archived public certificate fingerprint is duplicated.")
        certificate_pem = str(row.get("certificate_pem") or "")
        parsed = parse_public_certificate(certificate_pem, require_current=False)
        if parsed["fingerprint_sha256"] != fingerprint:
            raise ValueError("Archived public certificate fingerprint does not match its PEM body.")
        db.add(
            VsphereTrustedVcenterCertificate(
                id=str(row["id"]),
                trusted_vcenter_id=vcenter_id,
                fingerprint_sha256=fingerprint,
                certificate_pem=str(parsed["certificate_pem"]),
                subject=str(parsed["subject"]),
                issuer=str(parsed["issuer"]),
                serial_number=str(parsed["serial_number"]),
                not_valid_before=parsed["not_valid_before"],
                not_valid_after=parsed["not_valid_after"],
                source="uploaded_public",
            )
        )
        fingerprints.add(fingerprint)
    db.flush()
    return len(rows)


def _restore_ldap_organizations(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore ldap organizations.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    for row in rows:
        payload = _model_kwargs(LdapOrganization, row, exclude={"bind_password_encrypted"})
        organization = LdapOrganization(**payload)
        ensure_organization_bind_secret(organization)
        db.add(organization)
    db.flush()
    return len(rows)


def _restore_ldap_users(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore ldap users.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    organizations = {row.slug: row.id for row in db.execute(select(LdapOrganization)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(LdapUser, row, exclude={"organization_id", "unlock_requested_at"})
        payload["organization_id"] = organizations.get(str(row.get("organization_slug") or ""))
        payload["password_status"] = "not_staged"
        if payload["organization_id"] is not None:
            db.add(LdapUser(**payload))
    db.flush()
    return len(rows)


def _restore_oidc_subjects(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore oidc subjects.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    local_users = {row.username: row.id for row in db.execute(select(User)).scalars().all()}
    organizations = {row.slug: row.id for row in db.execute(select(LdapOrganization)).scalars().all()}
    ldap_users = {
        (row.organization_id, row.uid): row.id
        for row in db.execute(select(LdapUser)).scalars().all()
    }
    restored = 0
    for row in rows:
        source = str(row.get("source") or "")
        username = str(row.get("username") or "")
        subject_uuid = str(row.get("subject_uuid") or "")
        if source == "local":
            source_id = local_users.get(username)
            if source_id is not None and subject_uuid:
                db.add(OidcSubject(subject_uuid=subject_uuid, local_user_id=source_id))
                restored += 1
        elif source == "managed_ldap":
            organization_id = organizations.get(str(row.get("organization_slug") or ""))
            source_id = ldap_users.get((organization_id, username))
            if source_id is not None and subject_uuid:
                db.add(OidcSubject(subject_uuid=subject_uuid, ldap_user_id=source_id))
                restored += 1
    db.flush()
    return restored


def _restore_oidc_clients(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore oidc clients.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    organizations = {row.slug: row.id for row in db.execute(select(LdapOrganization)).scalars().all()}
    restored = 0
    for row in rows:
        payload = _model_kwargs(OidcClient, row, exclude={"organization_id"})
        organization_slug = str(row.get("organization_slug") or "")
        payload["organization_id"] = organizations.get(organization_slug) if organization_slug else None
        if organization_slug and payload["organization_id"] is None:
            continue
        db.add(OidcClient(**payload))
        restored += 1
    db.flush()
    return restored


def _restore_oidc_client_redirect_uris(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore oidc client redirect uris.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    clients = {row.client_id: row.id for row in db.execute(select(OidcClient)).scalars().all()}
    restored = 0
    for row in rows:
        payload = _model_kwargs(OidcClientRedirectUri, row, exclude={"oidc_client_id"})
        client_record_id = clients.get(str(row.get("client_id") or ""))
        if client_record_id is None:
            continue
        payload["oidc_client_id"] = client_record_id
        db.add(OidcClientRedirectUri(**payload))
        restored += 1
    db.flush()
    return restored


def _restore_oidc_group_mappings(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore oidc group mappings.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    from atlaso.app.services.oidc import (
        create_group_mapping,
        validate_all_mapping_contexts,
    )

    organizations = {
        row.slug: row.id
        for row in db.execute(select(LdapOrganization)).scalars().all()
    }
    groups = {
        (row.organization_id, row.name): row.id
        for row in db.execute(select(LdapGroup)).scalars().all()
    }
    clients = {
        row.client_id: row.id
        for row in db.execute(select(OidcClient)).scalars().all()
    }
    restored = 0
    for row in rows:
        source_type = str(row.get("source_type") or "")
        organization_slug = str(row.get("organization_slug") or "")
        organization_id = organizations.get(organization_slug)
        group_id = (
            groups.get(
                (
                    organization_id,
                    str(row.get("ldap_group_name") or ""),
                )
            )
            if source_type == "ldap_group"
            else None
        )
        client_public_id = str(row.get("client_id") or "")
        client_record_id = clients.get(client_public_id) if client_public_id else None
        if (
            (source_type == "ldap_group" and group_id is None)
            or (client_public_id and client_record_id is None)
        ):
            continue
        create_group_mapping(
            db,
            source_type=source_type,
            local_role=str(row.get("local_role") or ""),
            ldap_group_id=group_id,
            oidc_client_id=client_record_id,
            external_group_name=str(row.get("external_group_name") or ""),
            validate_effective_contexts=False,
        )
        restored += 1
    db.flush()
    validate_all_mapping_contexts(db)
    return restored


def _restore_ldap_groups(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore ldap groups.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    organizations = {row.slug: row.id for row in db.execute(select(LdapOrganization)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(LdapGroup, row, exclude={"organization_id"})
        payload["organization_id"] = organizations.get(str(row.get("organization_slug") or ""))
        if payload["organization_id"] is not None:
            db.add(LdapGroup(**payload))
    db.flush()
    return len(rows)


def _restore_ldap_group_memberships(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore ldap group memberships.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    organizations = {row.slug: row.id for row in db.execute(select(LdapOrganization)).scalars().all()}
    users = {(row.organization_id, row.uid): row.id for row in db.execute(select(LdapUser)).scalars().all()}
    groups = {(row.organization_id, row.name): row.id for row in db.execute(select(LdapGroup)).scalars().all()}
    restored = 0
    for row in rows:
        organization_id = organizations.get(str(row.get("organization_slug") or ""))
        group_id = groups.get((organization_id, str(row.get("group_name") or "")))
        if organization_id is None or group_id is None:
            continue
        member_name = str(row.get("member_name") or "")
        if row.get("member_type") == "user":
            member_user_id = users.get((organization_id, member_name))
            if member_user_id is None:
                continue
            db.add(LdapGroupMembership(group_id=group_id, member_user_id=member_user_id))
        else:
            member_group_id = groups.get((organization_id, member_name))
            if member_group_id is None:
                continue
            db.add(LdapGroupMembership(group_id=group_id, member_group_id=member_group_id))
        restored += 1
    db.flush()
    return restored


def _restore_vcf_backup_settings(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore vcf backup settings.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    users = {user.username: user.id for user in db.execute(select(User)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(VcfBackupSettings, row, exclude={"sftp_user_id"})
        username = str(row.get("sftp_username") or "")
        if username == VCF_BACKUP_DEFAULT_USERNAME and username not in users:
            user = User(username=username, role="viewer", roles_json='["viewer"]', shell="/sbin/nologin", enabled=False, os_sync_status="password_not_staged")
            db.add(user)
            db.flush()
            users[username] = user.id
        payload["sftp_user_id"] = users.get(username) if username else None
        db.add(VcfBackupSettings(**payload))
    db.flush()
    return len(rows)


def _restore_vcf_offline_depot_settings(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore vcf offline depot settings.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    users = {user.username: user.id for user in db.execute(select(User)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(VcfOfflineDepotSettings, row, exclude={"http_user_id"})
        username = str(row.get("http_username") or "")
        payload["http_user_id"] = users.get(username) if username else None
        db.add(VcfOfflineDepotSettings(**payload))
    db.flush()
    return len(rows)


def _restore_esxi_pxe_hosts(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore esxi pxe hosts.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    kickstarts = {row.name: row.id for row in db.execute(select(EsxiKickstart)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(EsxiPxeHost, row, exclude={"kickstart_id"})
        kickstart_name = str(row.get("kickstart_name") or "")
        payload["kickstart_id"] = kickstarts.get(kickstart_name) if kickstart_name else None
        payload["mac_address"] = normalize_host_mac(str(row.get("mac_address") or ""))
        payload["variables_json"] = host_variables_json(row.get("variables", row.get("variables_json", {})))
        db.add(EsxiPxeHost(**payload))
    db.flush()
    return len(rows)


def _restore_esx_storage_volumes(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore esx storage volumes.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    for row in rows:
        payload = _model_kwargs(EsxStorageVolume, row, exclude={"applied", "state"})
        payload["applied"] = False
        payload["state"] = "mounted" if payload.get("source_type") == "mounted_ext4" else "pending_verification"
        db.add(EsxStorageVolume(**payload))
    db.flush()
    return len(rows)


def _restore_esx_nfs_shares(db: Session, rows: list[dict[str, Any]]) -> int:
    """Return restore esx nfs shares.

    Args:
        db: Active database session.
        rows: Database or collection rows to process.
    """
    volumes = {row.name: row.id for row in db.execute(select(EsxStorageVolume)).scalars().all()}
    restored = 0
    for row in rows:
        volume_id = volumes.get(str(row.get("volume_name") or ""))
        if volume_id is None:
            continue
        payload = _model_kwargs(EsxNfsShare, row, exclude={"volume_id"})
        payload["volume_id"] = volume_id
        db.add(EsxNfsShare(**payload))
        restored += 1
    db.flush()
    return restored
