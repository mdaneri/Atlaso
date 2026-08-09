from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime as SqlDateTime
from sqlalchemy import delete, select
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
    KmsClient,
    KmsKey,
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
)
from atlaso.app.seed import SEED_EXAMPLES_SETTING_KEY, seed_initial_data, seed_update_sources
from atlaso.app.services.dnsmasq import DNS_CONDITIONAL_FORWARDERS_SETTING_KEY
from atlaso.app.services.esxi_pxe import (
    ESXI_PXE_CUSTOM_VARIABLES_KEY,
    host_variables_json,
    normalize_host_mac,
    normalize_host_variables,
)
from atlaso.app.services.firewall import FIREWALL_SOURCE_GROUPS_SETTING_KEY
from atlaso.app.services.local_users import LOCAL_USERS_PASSWORD_POLICY_KEY
from atlaso.app.services.ldap import clear_ldap_recovery_payload, ensure_organization_bind_secret
from atlaso.app.services.update_sources import UPDATE_SOURCE_KINDS
from atlaso.app.services.vcf_backups import VCF_BACKUP_DEFAULT_USERNAME

ARCHIVE_SCHEMA_VERSION = 1
ARCHIVE_KIND = "atlaso-settings-archive"
SAFE_SETTING_KEYS = {
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    ESXI_PXE_CUSTOM_VARIABLES_KEY,
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    LOCAL_USERS_PASSWORD_POLICY_KEY,
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
    "kms_clients": KmsClient,
    "ldap_settings": LdapSettings,
    "vcf_private_registry_settings": VcfPrivateRegistrySettings,
    "vcf_registry_bundles": VcfRegistryBundle,
    "vcf_offline_depot_settings": VcfOfflineDepotSettings,
    "vcf_depot_download_profiles": VcfDepotDownloadProfile,
    "esxi_kickstarts": EsxiKickstart,
    "esx_storage_settings": EsxStorageSettings,
}

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
    KmsKey,
    KmsClient,
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
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: object, *, exclude: set[str] | None = None) -> dict[str, Any]:
    excluded = {"id", "created_at", "updated_at", *(exclude or set())}
    payload: dict[str, Any] = {}
    for column in row.__table__.columns:
        if column.name in excluded or isinstance(column.type, SqlDateTime):
            continue
        payload[column.name] = getattr(row, column.name)
    return payload


def _settings_rows(db: Session) -> list[dict[str, str]]:
    rows = db.execute(select(Setting).where(Setting.key.in_(SAFE_SETTING_KEYS)).order_by(Setting.key)).scalars().all()
    return [_row_to_dict(row) for row in rows]


def export_settings_archive(db: Session, *, actor: str) -> dict[str, Any]:
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
    data["kms_keys"] = _kms_keys_to_archive(db)
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
    policies = {policy.id: policy.name for policy in db.execute(select(WanPolicy)).scalars().all()}
    rows = []
    for route in db.execute(select(Route)).scalars().all():
        payload = _row_to_dict(route, exclude={"wan_policy_id"})
        payload["wan_policy_name"] = policies.get(route.wan_policy_id) if route.wan_policy_id else ""
        rows.append(payload)
    return rows


def _dhcp_options_to_archive(db: Session) -> list[dict[str, Any]]:
    scopes = {scope.id: scope.name for scope in db.execute(select(DhcpScope)).scalars().all()}
    rows = []
    for option in db.execute(select(DhcpOption)).scalars().all():
        payload = _row_to_dict(option, exclude={"scope_id"})
        payload["scope_name"] = scopes.get(option.scope_id) if option.scope_id else ""
        rows.append(payload)
    return rows


def _ca_certificates_to_archive(db: Session) -> list[dict[str, Any]]:
    profiles = {profile.id: profile.name for profile in db.execute(select(CaProfile)).scalars().all()}
    rows = []
    for certificate in db.execute(select(CaCertificate)).scalars().all():
        payload = _row_to_dict(certificate, exclude={"profile_id", "issued_at", "expires_at"})
        payload["profile_name"] = profiles.get(certificate.profile_id) if certificate.profile_id else ""
        rows.append(payload)
    return rows


def _kms_keys_to_archive(db: Session) -> list[dict[str, Any]]:
    clients = {client.id: client.name for client in db.execute(select(KmsClient)).scalars().all()}
    rows = []
    for key in db.execute(select(KmsKey)).scalars().all():
        payload = _row_to_dict(key, exclude={"owner_client_id"})
        payload["owner_client_name"] = clients.get(key.owner_client_id) if key.owner_client_id else ""
        rows.append(payload)
    return rows


def _ldap_organizations_to_archive(db: Session) -> list[dict[str, Any]]:
    return [
        _row_to_dict(row, exclude={"bind_password_encrypted"})
        for row in db.execute(select(LdapOrganization).order_by(LdapOrganization.name)).scalars().all()
    ]


def _ldap_users_to_archive(db: Session) -> list[dict[str, Any]]:
    organizations = {row.id: row.slug for row in db.execute(select(LdapOrganization)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for user in db.execute(select(LdapUser).order_by(LdapUser.uid)).scalars().all():
        payload = _row_to_dict(user, exclude={"organization_id", "unlock_requested_at"})
        payload["organization_slug"] = organizations.get(user.organization_id, "")
        payload["password_status"] = "not_staged"
        rows.append(payload)
    return rows


def _ldap_groups_to_archive(db: Session) -> list[dict[str, Any]]:
    organizations = {row.id: row.slug for row in db.execute(select(LdapOrganization)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for group in db.execute(select(LdapGroup).order_by(LdapGroup.name)).scalars().all():
        payload = _row_to_dict(group, exclude={"organization_id"})
        payload["organization_slug"] = organizations.get(group.organization_id, "")
        rows.append(payload)
    return rows


def _ldap_group_memberships_to_archive(db: Session) -> list[dict[str, Any]]:
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
    organizations = {row.id: row.slug for row in db.execute(select(LdapOrganization)).scalars().all()}
    rows: list[dict[str, Any]] = []
    for client in db.execute(select(OidcClient).order_by(OidcClient.name)).scalars().all():
        payload = _row_to_dict(client, exclude={"organization_id"})
        payload["organization_slug"] = organizations.get(client.organization_id, "")
        rows.append(payload)
    return rows


def _oidc_subjects_to_archive(db: Session) -> list[dict[str, Any]]:
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
    users = {user.id: user.username for user in db.execute(select(User)).scalars().all()}
    rows = []
    for settings in db.execute(select(VcfBackupSettings)).scalars().all():
        payload = _row_to_dict(settings, exclude={"sftp_user_id"})
        payload["sftp_username"] = users.get(settings.sftp_user_id) if settings.sftp_user_id else ""
        rows.append(payload)
    return rows


def _vcf_offline_depot_settings_to_archive(db: Session) -> list[dict[str, Any]]:
    users = {user.id: user.username for user in db.execute(select(User)).scalars().all()}
    rows = []
    for settings in db.execute(select(VcfOfflineDepotSettings)).scalars().all():
        payload = _row_to_dict(settings, exclude={"http_user_id"})
        payload["http_username"] = users.get(settings.http_user_id) if settings.http_user_id else ""
        rows.append(payload)
    return rows


def _esxi_pxe_hosts_to_archive(db: Session) -> list[dict[str, Any]]:
    kickstarts = {row.id: row.name for row in db.execute(select(EsxiKickstart)).scalars().all()}
    rows = []
    for host in db.execute(select(EsxiPxeHost)).scalars().all():
        payload = _row_to_dict(host, exclude={"kickstart_id", "variables_json"})
        payload["kickstart_name"] = kickstarts.get(host.kickstart_id) if host.kickstart_id else ""
        payload["variables"] = normalize_host_variables(host.variables_json or "{}")
        rows.append(payload)
    return rows


def _update_sources_to_archive(db: Session) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in db.execute(select(UpdateSource).order_by(UpdateSource.kind, UpdateSource.priority, UpdateSource.name)).scalars().all():
        payload = _row_to_dict(source, exclude={"credential_encrypted", "validation_status", "validation_message"})
        payload["credential_status"] = "not_exported"
        rows.append(payload)
    return rows


def _managed_packages_to_archive(db: Session) -> list[dict[str, Any]]:
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
    from atlaso.app.services.network_boot import ensure_environment_rows

    _validate_archive(archive)
    data = archive["data"]
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
    counts["kms_clients"] = _insert_rows(db, KmsClient, data.get("kms_clients", []))
    db.flush()
    counts["kms_keys"] = _restore_kms_keys(db, data.get("kms_keys", []))
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
    db.commit()
    return counts


def factory_reset_desired_state(db: Session) -> dict[str, int]:
    from atlaso.app.services.network_boot import ensure_environment_rows

    _clear_desired_state(db)
    seed_initial_data(db, include_examples=False)
    for state in ensure_environment_rows(db):
        state.enabled = False
        state.desired_version = ""
        state.active_version = ""
        db.add(state)
    _disable_startup_example_seed(db)
    _force_services_stopped_unconfigured(db)
    db.commit()
    return desired_state_counts(db)


def desired_state_counts(db: Session) -> dict[str, int]:
    counts = {key: len(db.execute(select(model)).scalars().all()) for key, model in SCALAR_TABLES.items()}
    counts["routes"] = len(db.execute(select(Route)).scalars().all())
    counts["routing_rules"] = len(db.execute(select(RoutingRule)).scalars().all())
    counts["dhcp_options"] = len(db.execute(select(DhcpOption)).scalars().all())
    counts["ca_certificates"] = len(db.execute(select(CaCertificate)).scalars().all())
    counts["kms_keys"] = len(db.execute(select(KmsKey)).scalars().all())
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
    _validate_archive(archive)
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
    recovery_archives = db.execute(select(LdapRecoveryArchive)).scalars().all()
    for recovery_archive in recovery_archives:
        clear_ldap_recovery_payload(recovery_archive)
    for job in db.execute(select(Job).where(Job.schedule_id.is_not(None))).scalars().all():
        job.schedule_id = None
        db.add(job)
    db.flush()
    for model in RESTORE_DELETE_MODELS:
        db.execute(delete(model))
    db.flush()


def _force_services_stopped_unconfigured(db: Session) -> None:
    service_rows = db.execute(select(ServiceState)).scalars().all()
    for service in service_rows:
        service.running = False
        service.enabled = False
        service.health = "unconfigured"
        service.detail = "Stopped after settings restore or factory reset."
        db.add(service)
    db.flush()


def _disable_startup_example_seed(db: Session) -> None:
    existing = db.execute(select(Setting).where(Setting.key == SEED_EXAMPLES_SETTING_KEY)).scalar_one_or_none()
    if existing is None:
        db.add(Setting(key=SEED_EXAMPLES_SETTING_KEY, value="false"))
    else:
        existing.value = "false"
    db.flush()


def _validate_archive(archive: dict[str, Any]) -> None:
    if archive.get("kind") != ARCHIVE_KIND:
        raise ValueError("Upload a Atlaso settings archive.")
    if archive.get("schema_version") != ARCHIVE_SCHEMA_VERSION:
        raise ValueError("This settings archive schema is not supported by this Atlaso build.")
    if not isinstance(archive.get("data"), dict):
        raise ValueError("The settings archive is missing its data section.")


def _insert_rows(db: Session, model: type, rows: list[dict[str, Any]]) -> int:
    for row in rows:
        db.add(model(**_model_kwargs(model, row)))
    db.flush()
    return len(rows)


def _restore_update_sources(db: Session, rows: list[dict[str, Any]]) -> int:
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
    excluded = {"id", "created_at", "updated_at", *(exclude or set())}
    column_names = {column.name for column in model.__table__.columns if not isinstance(column.type, SqlDateTime)}
    return {key: value for key, value in row.items() if key in column_names and key not in excluded}


def _restore_routes(db: Session, rows: list[dict[str, Any]]) -> int:
    policies = {policy.name: policy.id for policy in db.execute(select(WanPolicy)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(Route, row, exclude={"wan_policy_id"})
        policy_name = str(row.get("wan_policy_name") or "")
        payload["wan_policy_id"] = policies.get(policy_name) if policy_name else None
        db.add(Route(**payload))
    db.flush()
    return len(rows)


def _restore_dhcp_options(db: Session, rows: list[dict[str, Any]]) -> int:
    scopes = {scope.name: scope.id for scope in db.execute(select(DhcpScope)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(DhcpOption, row, exclude={"scope_id"})
        scope_name = str(row.get("scope_name") or "")
        payload["scope_id"] = scopes.get(scope_name) if scope_name else None
        db.add(DhcpOption(**payload))
    db.flush()
    return len(rows)


def _restore_ca_certificates(db: Session, rows: list[dict[str, Any]]) -> int:
    profiles = {profile.name: profile.id for profile in db.execute(select(CaProfile)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(CaCertificate, row, exclude={"profile_id", "issued_at", "expires_at"})
        profile_name = str(row.get("profile_name") or "")
        payload["profile_id"] = profiles.get(profile_name) if profile_name else None
        db.add(CaCertificate(**payload))
    db.flush()
    return len(rows)


def _restore_kms_keys(db: Session, rows: list[dict[str, Any]]) -> int:
    clients = {client.name: client.id for client in db.execute(select(KmsClient)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(KmsKey, row, exclude={"owner_client_id"})
        client_name = str(row.get("owner_client_name") or "")
        payload["owner_client_id"] = clients.get(client_name) if client_name else None
        db.add(KmsKey(**payload))
    db.flush()
    return len(rows)


def _restore_ldap_organizations(db: Session, rows: list[dict[str, Any]]) -> int:
    for row in rows:
        payload = _model_kwargs(LdapOrganization, row, exclude={"bind_password_encrypted"})
        organization = LdapOrganization(**payload)
        ensure_organization_bind_secret(organization)
        db.add(organization)
    db.flush()
    return len(rows)


def _restore_ldap_users(db: Session, rows: list[dict[str, Any]]) -> int:
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
    organizations = {row.slug: row.id for row in db.execute(select(LdapOrganization)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(LdapGroup, row, exclude={"organization_id"})
        payload["organization_id"] = organizations.get(str(row.get("organization_slug") or ""))
        if payload["organization_id"] is not None:
            db.add(LdapGroup(**payload))
    db.flush()
    return len(rows)


def _restore_ldap_group_memberships(db: Session, rows: list[dict[str, Any]]) -> int:
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
    users = {user.username: user.id for user in db.execute(select(User)).scalars().all()}
    for row in rows:
        payload = _model_kwargs(VcfOfflineDepotSettings, row, exclude={"http_user_id"})
        username = str(row.get("http_username") or "")
        payload["http_user_id"] = users.get(username) if username else None
        db.add(VcfOfflineDepotSettings(**payload))
    db.flush()
    return len(rows)


def _restore_esxi_pxe_hosts(db: Session, rows: list[dict[str, Any]]) -> int:
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
    for row in rows:
        payload = _model_kwargs(EsxStorageVolume, row, exclude={"applied", "state"})
        payload["applied"] = False
        payload["state"] = "mounted" if payload.get("source_type") == "mounted_ext4" else "pending_verification"
        db.add(EsxStorageVolume(**payload))
    db.flush()
    return len(rows)


def _restore_esx_nfs_shares(db: Session, rows: list[dict[str, Any]]) -> int:
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
