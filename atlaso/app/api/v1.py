"""Expose the versioned REST API for Atlaso resources and workflows."""

import json
import re
import socket
from datetime import datetime
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi import Path as ApiPath
from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso import __build_git_commit__, __build_time_utc__, __version__
from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    ApiToken,
    ApplianceSettings,
    AuditEvent,
    CaCertificate,
    CaSettings,
    DhcpOption,
    DhcpReservation,
    DhcpScope,
    DhcpSettings,
    DnsRecord,
    DnsSettings,
    EsxiKickstart,
    EsxiPxeHost,
    EsxNfsShare,
    EsxStorageSettings,
    EsxStorageVolume,
    FirewallRule,
    FirewallSettings,
    Job,
    JobStatus,
    KmsSettings,
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapRecoveryArchive,
    LdapSettings,
    LdapUser,
    NatRule,
    NtpSettings,
    PhysicalInterface,
    Route,
    RoutingRule,
    ServiceState,
    Setting,
    User,
    VcfBackupSettings,
    VcfDepotDownloadProfile,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VcfRegistryBundle,
    VlanInterface,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
    WanPolicy,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenResponse,
    ApplianceVersionResponse,
    AuditEventResponse,
    ConfigApplyResponse,
    ConfigValidationResponse,
    DashboardResponse,
    DhcpLeaseResponse,
    DhcpOptionCreate,
    DhcpOptionResponse,
    DhcpReservationCreate,
    DhcpReservationResponse,
    DhcpScopeCreate,
    DhcpScopeResponse,
    DhcpSettingsResponse,
    DhcpSettingsUpdate,
    DhcpStatusResponse,
    DnsHostsImportRequest,
    DnsHostsImportResponse,
    DnsRecordCreate,
    DnsRecordResponse,
    DnsSettingsResponse,
    DnsSettingsUpdate,
    DnsStatusResponse,
    EsxiCustomVariableCreate,
    EsxiCustomVariableResponse,
    EsxiCustomVariableUpdate,
    EsxiInstallerIsoResponse,
    EsxiKickstartCreate,
    EsxiKickstartDuplicateRequest,
    EsxiKickstartPreviewResponse,
    EsxiKickstartResponse,
    EsxiKickstartUpdate,
    EsxiKickstartValidationResponse,
    EsxiPxeHostCreate,
    EsxiPxeHostResponse,
    EsxNfsShareCreate,
    EsxNfsShareResponse,
    EsxNfsShareUpdate,
    EsxStorageDiskResponse,
    EsxStorageSettingsUpdate,
    EsxStorageStatusResponse,
    EsxStorageVolumeCreate,
    EsxStorageVolumeResponse,
    EsxStorageVolumeUpdate,
    FirewallRuleCreate,
    FirewallRuleResponse,
    FirewallSettingsResponse,
    FirewallSettingsUpdate,
    FirewallStatusResponse,
    IdentityResponse,
    JobResponse,
    LdapBindCredentialResponse,
    LdapGroupCreate,
    LdapGroupResponse,
    LdapHealthResponse,
    LdapOrganizationCreate,
    LdapOrganizationResponse,
    LdapPasswordResetRequest,
    LdapRecoveryExportRequest,
    LdapRecoveryImportResponse,
    LdapSettingsResponse,
    LdapSettingsUpdate,
    LdapUserCreate,
    LdapUserResponse,
    LdapVcfConfigureRequest,
    LdapVcfInspectionResponse,
    LdapVcfInspectRequest,
    MonitorResponse,
    NatRuleCreate,
    NatRuleResponse,
    PhysicalInterfaceResponse,
    PhysicalInterfaceUpdate,
    RouteCreate,
    RouteResponse,
    ServiceActionResponse,
    ServiceStateResponse,
    SettingsResponse,
    SettingsUpdate,
    VcfBackupStatusResponse,
    VcfOfflineDepotStatusResponse,
    VcfPrivateRegistryStatusResponse,
    VlanCreate,
    VlanResponse,
    VsphereKeyProviderCreate,
    VsphereKeyProviderResponse,
    VsphereKeyProviderSettingsResponse,
    VsphereKeyProviderSettingsUpdate,
    VsphereKeyProviderUpdate,
    VsphereProviderHealthResponse,
    VsphereProviderLifecycleCountsResponse,
    VsphereProviderReadinessResponse,
    VsphereServerCertificateResponse,
    VsphereTrustedCertificateCreate,
    VsphereTrustedCertificateResponse,
    VsphereTrustedVcenterCreate,
    VsphereTrustedVcenterResponse,
    VsphereTrustedVcenterUpdate,
    WanPolicyCreate,
    WanPolicyResponse,
    WanStatusResponse,
)
from atlaso.app.security import (
    Identity,
    authenticate_user,
    require_scope,
)
from atlaso.app.services.appliance_settings import (
    APPLIANCE_SETTINGS_STAGED_CONFIG_PATH,
    appliance_settings_to_dict,
    management_dhcp_dns_context,
    management_interface_context,
    management_ui_context,
    normalize_fqdn,
    normalize_multiline_values,
    normalized_web_terminal_interfaces,
    render_appliance_settings_config,
    validate_appliance_settings,
    web_terminal_interface_options,
    web_terminal_interfaces_to_json,
)
from atlaso.app.services.ca import ca_service_state, managed_certificate_for_owner
from atlaso.app.services.dnsmasq import (
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    dhcp_bind_target_families,
    dhcp_bind_target_names,
    dhcp_dns_upstream_required,
    dns_domain_warnings,
    dns_settings_to_dict,
    dnsmasq_test_command,
    dump_dns_record_data,
    effective_dns_upstream_servers,
    ensure_dns_authoritative_defaults,
    join_conditional_forwarders,
    join_domains,
    join_servers,
    parse_dnsmasq_leases,
    parse_hosts_records,
    render_dnsmasq_config,
    reservation_dns_record,
    split_addresses,
    split_domains,
    split_interfaces,
    validate_authoritative_dns_record,
    validate_dhcp_bind_targets,
    validate_dhcp_settings,
    validate_dns_listen_targets,
    validate_dns_record,
    validate_dns_settings,
)
from atlaso.app.services.esx_storage import (
    ESX_STORAGE_MOUNT_ROOT,
    StorageInterface,
    normalize_families,
    normalize_relative_path,
    parse_disk_inventory_output,
    select_inventory_candidate,
    storage_slug,
    validate_mounted_volume_path,
)
from atlaso.app.services.esx_storage import (
    firewall_rule_specs as esx_storage_firewall_rule_specs,
)
from atlaso.app.services.esx_storage import (
    render_manifest as render_esx_storage_manifest,
)
from atlaso.app.services.esx_storage import (
    rpcbind_required as esx_storage_rpcbind_required,
)
from atlaso.app.services.esx_storage import (
    split_lines as split_esx_storage_lines,
)
from atlaso.app.services.esxi_pxe import (
    assign_kickstart_content,
    canonical_http_path,
    content_hash,
    custom_variable_definitions,
    decode_kickstart_upload,
    delete_custom_variable_definition,
    esxi_pxe_boot_settings,
    esxi_pxe_service_state_from_boot,
    host_to_dict,
    host_variables_json,
    installer_iso_inventory,
    kickstart_to_dict,
    kickstart_validation,
    normalize_host_mac,
    normalize_installer_iso_path,
    normalize_kickstart_name,
    redacted_kickstart_preview,
    save_custom_variable_definition,
    store_installer_iso_upload,
    strict_validation_enabled,
    sync_esxi_pxe_host_network_records,
    validate_kickstart_custom_references,
    validate_kickstart_vault_references,
)
from atlaso.app.services.firewall import (
    FIREWALL_POLICIES,
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    FIREWALL_STAGED_CONFIG_PATH,
    ca_portal_firewall_interfaces,
    firewall_interface_networks,
    firewall_source_group_state,
    managed_routing_firewall_rules,
    managed_service_firewall_rules,
    render_nftables_config,
    validate_firewall_rule,
    validate_firewall_source_groups,
    validate_firewall_state,
)
from atlaso.app.services.interface_updates import (
    PhysicalInterfaceUpdateError,
    update_physical_interface_desired_state,
)
from atlaso.app.services.kms import KMS_DEFAULT_CONFIG_PATH, join_csv
from atlaso.app.services.ldap import (
    LDAP_GROUP_PATTERN,
    LDAP_RECOVERY_DIR,
    LDAP_STAGED_CONFIG_PATH,
    LDAP_UID_PATTERN,
    VcfAutomationLdapClient,
    VcfLdapError,
    clear_ldap_recovery_payload,
    clear_pending_ldap_password,
    decrypt_recovery_payload,
    default_organization_suffix,
    encrypt_recovery_payload,
    ensure_organization_bind_secret,
    invalidate_ldap_user_password_for_uid_change,
    ldap_group_to_dict,
    ldap_organization_to_dict,
    ldap_settings_to_dict,
    ldap_user_to_dict,
    manual_vcf_bundle,
    normalize_dn,
    normalize_ldap_slug,
    normalize_vcf_target_url,
    recovery_sha256,
    rotate_organization_bind_secret,
    stage_ldap_recovery_payload,
    stage_ldap_user_password,
    tls_sha256_fingerprint,
    validate_group_cycles,
    validate_ldap_state,
    vcf_ldap_settings,
)
from atlaso.app.services.monitoring import monitor_payload
from atlaso.app.services.network_boot import cleanup_network_boot_upload
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
    sync_host_physical_interfaces,
)
from atlaso.app.services.ntp import default_ntp_upstream_fields
from atlaso.app.services.routes_wan import validate_nat_source
from atlaso.app.services.service_registry import (
    SERVICE_STATE_IDS,
    SERVICE_SYSTEMD_UNITS,
)
from atlaso.app.services.vcf_backups import (
    vcf_backup_service_state,
    vcf_backup_settings_to_dict,
)
from atlaso.app.services.vcf_offline_depot import (
    VCF_DEPOT_ACTIVATION_VALUE_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
    VCF_DEPOT_DEFAULT_STORE_PATH,
    VCF_DEPOT_LEGACY_STORE_PATH,
    VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
    VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
    VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
    VCF_DEPOT_TOKEN_VALUE_KEY,
    VCF_DEPOT_TOOL_VERSION_SOURCE_COMMAND,
    VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
    find_local_vcf_download_tool_archive,
    validate_vcf_depot_state,
    vcf_depot_service_state,
    vcf_depot_settings_to_dict,
)
from atlaso.app.services.vcf_private_registry import (
    VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY,
    validate_vcf_registry_state,
    vcf_registry_settings_to_dict,
)
from atlaso.app.services.vsphere_key_providers import (
    authenticated_provider_counts,
    certificate_to_dict,
    mark_provider_desired_changed,
    normalize_service_hostname,
    normalize_vcenter_hostname,
    parse_public_certificate,
    provider_requires_appliance_apply,
    provider_rows,
    provider_to_dict,
    runtime_status_snapshot,
    trusted_vcenter_to_dict,
    usable_certificates,
    validate_provider_state,
)
from atlaso.app.token_service import create_token_for_user, token_to_response
from atlaso.app.ui import refresh_interface_service_dns_aliases

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
DNSMASQ_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/dnsmasq/atlaso.conf"

APPROVED_SERVICES = set(SERVICE_STATE_IDS) | {"vcf-offline-depot"}


def backing_systemd_unit_active(unit: str) -> bool | None:
    """Return backing systemd unit active.

    Args:
        unit: Unit consumed by backing systemd unit active.
    """
    if get_settings().dry_run_system_adapters:
        return None
    result = SystemAdapter().service_status(unit)
    if not result.stdout:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    active_state = str(payload.get("active") or "").strip()
    if not active_state or active_state == "unknown":
        return None
    return active_state == "active"


def service_state_response(row: ServiceState, db: Session | None = None) -> ServiceStateResponse:
    """Return service state response.

    Args:
        row: Database or collection row to process.
        db: Active database session.
    """
    data = {
        "id": row.id,
        "service": row.service,
        "display_name": row.display_name,
        "running": row.running,
        "enabled": row.enabled,
        "health": row.health,
        "detail": row.detail,
    }
    if row.service in {"dns", "dhcp"} and db is not None:
        if row.service == "dns":
            data["enabled"] = get_dns_settings_row(db).enabled
        else:
            data["enabled"] = get_dhcp_settings_row(db).enabled
        active = backing_systemd_unit_active("dnsmasq.service")
        if active is not None:
            data["running"] = active
        if data["running"] and data["enabled"]:
            data["health"] = "healthy"
        elif data["running"] or data["enabled"]:
            data["health"] = "degraded"
        else:
            data["health"] = "disabled"
        return ServiceStateResponse(**data)
    if row.service == "esxi-pxe" and db is not None:
        data.update(esxi_pxe_service_state_from_boot(esxi_pxe_boot_settings(db)))
        data["detail"] = "dnsmasq TFTP/DHCP boot options and PXE HTTP files"
        data.pop("label", None)
        data.pop("pill", None)
        return ServiceStateResponse(**data)
    if row.service == "ca" and db is not None:
        settings = db.execute(select(CaSettings)).scalar_one_or_none() or CaSettings()
        data.update(ca_service_state(settings))
        data["detail"] = row.detail or "Atlaso CA material and issued certificates"
        data.pop("label", None)
        data.pop("pill", None)
        return ServiceStateResponse(**data)
    if row.service == "ldap" and db is not None:
        settings = db.execute(select(LdapSettings)).scalar_one_or_none() or LdapSettings()
        data["enabled"] = settings.enabled
        active = backing_systemd_unit_active("slapd.service")
        if active is not None:
            data["running"] = active
        data["health"] = "healthy" if data["enabled"] and data["running"] else "degraded" if data["enabled"] else "disabled"
        protocols = []
        if settings.ldaps_enabled:
            protocols.append(f"LDAPS TCP {settings.port}")
        if settings.ldap_enabled:
            protocols.append(f"LDAP TCP {settings.ldap_port}")
        data["detail"] = "OpenLDAP / " + (", ".join(protocols) if protocols else "no external listener")
        return ServiceStateResponse(**data)
    if row.service == "vcf-backups" and db is not None:
        data.update(vcf_backup_service_state(get_vcf_backup_settings(db), sshd_active=backing_systemd_unit_active("sshd.service")))
        data.pop("label", None)
        data.pop("pill", None)
        return ServiceStateResponse(**data)
    if row.service == "repository" and db is not None:
        data.update(vcf_depot_service_state(get_vcf_offline_depot_settings(db), nginx_active=backing_systemd_unit_active("nginx.service")))
        data.pop("label", None)
        data.pop("pill", None)
        return ServiceStateResponse(**data)
    if row.service == "esx-storage" and db is not None:
        settings = db.execute(select(EsxStorageSettings)).scalar_one_or_none() or EsxStorageSettings()
        shares = db.execute(select(EsxNfsShare).where(EsxNfsShare.enabled.is_(True))).scalars().all()
        nfs_active = backing_systemd_unit_active("nfs-server.service")
        requires_rpcbind = esx_storage_rpcbind_required(shares)
        rpcbind_active = backing_systemd_unit_active("rpcbind.service") if requires_rpcbind else True
        data["enabled"] = settings.enabled
        if nfs_active is not None:
            data["running"] = nfs_active
        if requires_rpcbind and not get_settings().dry_run_system_adapters and rpcbind_active is not True:
            data["running"] = False
            data["detail"] = "NFS 3 / 4.1 over equivalent IPv4 and IPv6 listeners; rpcbind.service is required by an enabled NFS 3 share but is not active"
        else:
            data["detail"] = "NFS 3 / 4.1 over equivalent IPv4 and IPv6 listeners"
        data["health"] = "healthy" if data["enabled"] and data["running"] else "degraded" if data["enabled"] else "disabled"
        return ServiceStateResponse(**data)
    unit = SERVICE_SYSTEMD_UNITS.get(row.service)
    if unit and not get_settings().dry_run_system_adapters:
        result = SystemAdapter().service_status(unit)
        if result.stdout:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                payload = {}
            active_state = str(payload.get("active") or "").strip()
            enabled_state = str(payload.get("enabled") or "").strip()
            if active_state:
                data["running"] = active_state == "active"
            if enabled_state:
                data["enabled"] = enabled_state in {"enabled", "enabled-runtime"}
            if data["running"] and data["enabled"]:
                data["health"] = "healthy"
            elif data["running"] or data["enabled"]:
                data["health"] = "degraded"
            else:
                data["health"] = "disabled"
    return ServiceStateResponse(**data)


def validate_vlan_api_payload(payload: VlanCreate, db: Session) -> dict:
    """Validate vlan api payload.

    Args:
        payload: Validated request or operation payload.
        db: Active database session.

    Returns:
        The validate vlan api payload result.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    values = payload.model_dump()
    values["parent_interface"] = values["parent_interface"].strip()
    values["ip_cidr"] = values["ip_cidr"].strip()
    values["ipv6_cidr"] = values["ipv6_cidr"].strip()
    values["role"] = normalize_interface_role(values["role"])
    if values["access_management_ui_enabled"] and values["role"] != "access":
        raise HTTPException(
            status_code=422,
            detail="access_management_ui_enabled is available only for an access-role VLAN.",
        )
    if not values["ip_cidr"] and not values["ipv6_cidr"]:
        raise HTTPException(status_code=422, detail="VLAN IPv4 CIDR, IPv6 CIDR, or both are required.")
    if values["ip_cidr"]:
        try:
            parsed_ipv4 = ip_interface(values["ip_cidr"])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="VLAN IPv4 CIDR must be a valid address and prefix, for example 192.168.50.1/24.") from exc
        if parsed_ipv4.version != 4:
            raise HTTPException(status_code=422, detail="VLAN IPv4 CIDR must use an IPv4 address and prefix.")
    if values["ipv6_cidr"]:
        try:
            parsed_ipv6 = ip_interface(values["ipv6_cidr"])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="VLAN IPv6 CIDR must be a valid address and prefix, for example fd00:50::1/64.") from exc
        if parsed_ipv6.version != 6:
            raise HTTPException(status_code=422, detail="VLAN IPv6 CIDR must use an IPv6 address and prefix.")
    parent = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == values["parent_interface"])).scalar_one_or_none()
    if parent and parent.oper_state == "missing":
        if values.get("enabled", True):
            raise HTTPException(
                status_code=409,
                detail=f"{values['parent_interface']} is missing from host inventory. Move the VLAN to an available trunk parent before enabling it.",
            )
        return values
    if not parent or normalize_interface_mode(parent.mode) != "trunk":
        raise HTTPException(
            status_code=409,
            detail=f"{values['parent_interface'] or 'Selected parent'} is not a trunk interface. Mark the physical NIC as trunk before creating VLANs on it.",
        )
    return values


def get_firewall_settings(db: Session) -> FirewallSettings:
    """Return firewall settings.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(FirewallSettings)).scalar_one_or_none()
    if settings is None:
        settings = FirewallSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_dhcp_settings_row(db: Session) -> DhcpSettings:
    """Return dhcp settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(DhcpSettings)).scalar_one_or_none()
    if settings is None:
        settings = DhcpSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_kms_settings_row(db: Session) -> KmsSettings:
    """Return kms settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(KmsSettings)).scalar_one_or_none()
    if settings is None:
        settings = KmsSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_ntp_settings(db: Session) -> NtpSettings:
    """Return ntp settings.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(NtpSettings)).scalar_one_or_none()
    if settings is None:
        ntp_upstreams = default_ntp_upstream_fields()
        settings = NtpSettings(
            upstream_servers=ntp_upstreams["upstream_servers"],
            upstream_sources_json=ntp_upstreams["upstream_sources_json"],
        )
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_appliance_settings(db: Session) -> ApplianceSettings:
    """Return appliance settings.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    if settings is None:
        settings = ApplianceSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def ca_managed_certificate_available(db: Session, owner: str) -> tuple[bool, str, str]:
    """Return ca managed certificate available.

    Args:
        db: Active database session.
        owner: Owner supplied by the caller.
    """
    certificate = managed_certificate_for_owner(db, owner)
    if certificate is None or certificate.status != "issued":
        return False, "", ""
    available = bool(certificate.certificate_pem and certificate.private_key_encrypted and certificate.cert_path and certificate.key_path)
    return available, certificate.cert_path or "", certificate.key_path or ""


def appliance_settings_response(db: Session, app_settings: Settings) -> SettingsResponse:
    """Return appliance settings response.

    Args:
        db: Active database session.
        app_settings: App settings supplied by the caller.
    """
    desired = get_appliance_settings(db)
    dns_settings = db.execute(select(DnsSettings)).scalar_one_or_none()
    ca_settings = db.execute(select(CaSettings)).scalar_one_or_none()
    management_https_cert_available, management_https_cert_path, management_https_key_path = ca_managed_certificate_available(db, "appliance:https")
    local_dns_enabled = bool(dns_settings and dns_settings.enabled)
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    management = management_ui_context(interfaces, vlans)
    terminal_options = web_terminal_interface_options(interfaces, vlans)
    validation_errors, validation_warnings = validate_appliance_settings(
        desired,
        local_dns_enabled=local_dns_enabled,
        management_interface=management,
        ca_enabled=bool(ca_settings and ca_settings.enabled),
        management_https_cert_available=management_https_cert_available,
        web_terminal_options=terminal_options,
    )
    return SettingsResponse(
        app_name=app_settings.app_name,
        appliance_hostname=socket.gethostname(),
        dry_run_system_adapters=app_settings.dry_run_system_adapters,
        repository_path=str(app_settings.repository_path),
        vcf_backup_path=str(app_settings.vcf_backup_path),
        appliance_fqdn=desired.fqdn,
        management_https_enabled=desired.management_https_enabled,
        management_https_cert_available=management_https_cert_available,
        web_terminal_enabled=desired.web_terminal_enabled,
        web_terminal_interfaces=normalized_web_terminal_interfaces(desired, management),
        root_ssh_enabled=desired.root_ssh_enabled,
        external_dns_servers=appliance_settings_to_dict(desired)["external_dns_servers"],
        appliance_settings_config_path=desired.config_path,
        local_dns_enabled=local_dns_enabled,
        management_interface=management["name"],
        management_ip=management["ip"],
        valid=not validation_errors,
        validation_errors=validation_errors,
        validation_warnings=validation_warnings,
        config_preview=render_appliance_settings_config(
            desired,
            local_dns_enabled=local_dns_enabled,
            management_interface=management,
            management_https_cert_path=management_https_cert_path,
            management_https_key_path=management_https_key_path,
            web_terminal_options=terminal_options,
        ),
    )


def assign_firewall_rule_values(rule: FirewallRule, values: dict) -> FirewallRule:
    """Return assign firewall rule values.

    Args:
        rule: Rule consumed by assign firewall rule values.
        values: Candidate values consumed by assign firewall rule values.
    """
    rule.name = values["name"].strip()
    rule.direction = values.get("direction", "input")
    rule.action = values.get("action", "accept")
    rule.protocol = values.get("protocol", "tcp")
    rule.source = values.get("source", "any").strip() or "any"
    rule.destination = values.get("destination", "any").strip() or "any"
    rule.destination_port = values.get("destination_port", "").strip()
    rule.interface_name = values.get("interface_name", "").strip()
    rule.priority = values.get("priority", 100)
    rule.enabled = values.get("enabled", True)
    rule.description = values.get("description") or None
    rule.updated_at = utcnow()
    return rule


def get_vcf_backup_settings(db: Session) -> VcfBackupSettings:
    """Return vcf backup settings.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(VcfBackupSettings).options(selectinload(VcfBackupSettings.sftp_user))).scalar_one_or_none()
    if settings is None:
        user = db.execute(select(User).where(User.enabled.is_(True)).order_by(User.username)).scalar_one_or_none()
        settings = VcfBackupSettings(sftp_user_id=user.id if user else None)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_vcf_private_registry_settings(db: Session) -> VcfPrivateRegistrySettings:
    """Return vcf private registry settings.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(VcfPrivateRegistrySettings)).scalar_one_or_none()
    if settings is None:
        settings = VcfPrivateRegistrySettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_vcf_offline_depot_settings(db: Session) -> VcfOfflineDepotSettings:
    """Return vcf offline depot settings.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one_or_none()
    if settings is None:
        settings = VcfOfflineDepotSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    if settings.depot_store_path == VCF_DEPOT_LEGACY_STORE_PATH:
        settings.depot_store_path = VCF_DEPOT_DEFAULT_STORE_PATH
        settings.updated_at = utcnow()
        db.commit()
        db.refresh(settings)
    if settings.tool_archive_path and settings.tool_version:
        version_source = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOOL_VERSION_SOURCE_KEY)).scalar_one_or_none()
        if not version_source or version_source.value != VCF_DEPOT_TOOL_VERSION_SOURCE_COMMAND:
            settings.tool_version = ""
            settings.updated_at = utcnow()
            db.commit()
            db.refresh(settings)
    if not settings.tool_archive_path:
        archive = find_local_vcf_download_tool_archive()
        if archive is not None:
            settings.tool_archive_path = str(archive)
            settings.tool_version = ""
            settings.updated_at = utcnow()
            db.commit()
            db.refresh(settings)
    return settings


def vcf_registry_ca_bundle_status(db: Session) -> tuple[str, bool]:
    """Return vcf registry ca bundle status.

    Args:
        db: Active database session.
    """
    ca_settings = db.execute(select(CaSettings)).scalar_one_or_none()
    if ca_settings is not None and ca_settings.enabled:
        return "local-ca", True
    uploaded = db.execute(select(Setting).where(Setting.key == VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY)).scalar_one_or_none()
    return "uploaded", bool(uploaded and uploaded.value.strip())


def vcf_depot_secret_status(db: Session) -> tuple[bool, bool]:
    """Return vcf depot secret status.

    Args:
        db: Active database session.
    """
    token = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one_or_none()
    activation_code = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)).scalar_one_or_none()
    return bool(token and token.value.strip()), bool(activation_code and activation_code.value.strip())


def firewall_validation_payload(db: Session) -> tuple[FirewallSettings, list[FirewallRule], str, list[str]]:
    """Return firewall validation payload.

    Args:
        db: Active database session.
    """
    settings = get_firewall_settings(db)
    rules = db.execute(select(FirewallRule).order_by(FirewallRule.priority, FirewallRule.name)).scalars().all()
    dns_settings = get_dns_settings_row(db)
    dhcp_settings = get_dhcp_settings_row(db)
    dhcp_scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    interface_networks = firewall_interface_networks(physical_interfaces, vlan_interfaces)
    source_group_state = firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), interface_networks)
    generated_rules = managed_service_firewall_rules(
        dns_settings=dns_settings,
        dhcp_settings=dhcp_settings,
        dhcp_scopes=dhcp_scopes,
        ca_settings=db.execute(select(CaSettings)).scalar_one_or_none() or CaSettings(),
        ca_portal_interfaces=ca_portal_firewall_interfaces(physical_interfaces, vlan_interfaces, interface_networks),
        kms_settings=get_kms_settings_row(db),
        ntp_settings=get_ntp_settings(db),
        vcf_backup_settings=get_vcf_backup_settings(db),
        vcf_depot_settings=get_vcf_offline_depot_settings(db),
        vcf_registry_settings=get_vcf_private_registry_settings(db),
        esxi_pxe_boot=esxi_pxe_boot_settings(db),
        interface_networks=interface_networks,
        source_groups=source_group_state["groups"],
        source_group_assignments=source_group_state["assignments"],
        ldap_settings=db.execute(select(LdapSettings)).scalar_one_or_none() or LdapSettings(),
        esx_storage_rules=esx_storage_firewall_rule_specs(esx_storage_state(db)[4]),
        management_interface=management_interface_context(physical_interfaces).get("name", ""),
        access_management_ui_interfaces=[
            interface.name
            for interface in physical_interfaces
            if normalize_interface_role(interface.role) == "access"
            and normalize_interface_mode(interface.mode) == "access"
            and interface.admin_state == "up"
            and interface.access_management_ui_enabled
        ] + [
            vlan.name
            for vlan in vlan_interfaces
            if vlan.enabled
            and normalize_interface_role(vlan.role) == "access"
            and vlan.access_management_ui_enabled
        ],
    )
    generated_rules.extend(
        managed_routing_firewall_rules(
            physical_interfaces,
            vlan_interfaces,
            db.execute(select(RoutingRule).order_by(RoutingRule.priority, RoutingRule.name)).scalars().all(),
        )
    )
    return (
        settings,
        rules,
        render_nftables_config(
            settings,
            rules,
            generated_rules,
            source_groups=source_group_state["groups"],
            replace_atlaso_service_rules=True,
        ),
        [
            *validate_firewall_source_groups(source_group_state["groups"]),
            *validate_firewall_state(
                settings,
                rules,
                generated_rules,
                source_groups=source_group_state["groups"],
                replace_atlaso_service_rules=True,
            ),
        ],
    )


def stage_api_firewall_config(config_preview: str) -> str:
    """Return stage api firewall config.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    from atlaso.app.ui import stage_appliance_apply_config

    return stage_appliance_apply_config(FIREWALL_STAGED_CONFIG_PATH, config_preview)


def stage_api_dnsmasq_config(config_preview: str) -> str:
    """Return stage api dnsmasq config.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    from atlaso.app.ui import stage_appliance_apply_config

    return stage_appliance_apply_config(DNSMASQ_STAGED_CONFIG_PATH, config_preview)


@router.get(
    "/version",
    response_model=ApplianceVersionResponse,
    tags=["Appliance"],
    operation_id="getApplianceVersion",
)
def get_appliance_version() -> ApplianceVersionResponse:
    """Get the installed Atlaso version and build provenance.

    This unauthenticated, read-only compatibility endpoint exposes only public release metadata and never changes saved
    desired state or appliance runtime state. A successful response identifies the installed package, base semantic
    version, source commit, and UTC build time for client compatibility and support correlation.
    """
    return ApplianceVersionResponse(
        version=__version__,
        base_version=__version__.split("+", 1)[0],
        git_commit=__build_git_commit__,
        built_at=__build_time_utc__,
    )


@router.post(
    "/auth/login",
    response_model=ApiTokenCreated,
    tags=["Auth"],
    operation_id="loginForApi",
    responses={401: {"description": "Invalid credentials"}},
)
def login_for_api(
    payload: ApiTokenCreate,
    request: Request,
    username: str = Query(..., description='Atlaso account name used only for this authentication exchange.'),
    password: str = Query(..., description='Sensitive Atlaso account password used only for this authentication exchange; never place a real value in documentation or shared URLs.'),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ApiTokenCreated:
    """Login For Api.

    Authenticates a local Atlaso account and returns a one-time API bearer token. No bearer token is
    required for this exchange; treat the username, password, and returned token as sensitive and
    never place real values in shared URLs, logs, examples, or screenshots.

    Args:
        payload: Validated request or task payload consumed by the operation.
        request: Incoming HTTP request carrying the operation context.
        username: Atlaso account name associated with the operation.
        password: Password consumed by login for API.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    user = authenticate_user(db, username, password)
    if not user:
        record_audit(
            db,
            actor=username,
            action="api_login_failed",
            resource_type="auth",
            success=False,
            request_id=getattr(request.state, "request_id", None),
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return create_token_for_user(db, user=user, create=payload, settings=settings, actor=user.username)


@router.get("/auth/me", response_model=IdentityResponse, tags=["Auth"], operation_id="getCurrentIdentity")
def get_me(identity: Annotated[Identity, Depends(require_scope("read:dashboard"))]) -> IdentityResponse:
    """Get Current Identity.

    Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
    """
    return IdentityResponse(
        username=identity.username,
        role=identity.role,
        roles=identity.roles,
        scopes=sorted(identity.scopes),
        auth_type=identity.auth_type,
    )


@router.get("/api-tokens", response_model=list[ApiTokenResponse], tags=["API Tokens"], operation_id="listApiTokens")
def list_api_tokens(
    identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    db: Session = Depends(get_db),
) -> list[ApiTokenResponse]:
    """List Api Tokens.

    Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    query = select(ApiToken).order_by(desc(ApiToken.created_at))
    if not identity.has_role("admin"):
        query = query.where(ApiToken.owner_user_id == identity.user_id)
    return [token_to_response(token) for token in db.execute(query).scalars().all()]


@router.post(
    "/api-tokens",
    response_model=ApiTokenCreated,
    status_code=201,
    tags=["API Tokens"],
    operation_id="createApiToken",
)
def create_api_token(
    payload: ApiTokenCreate,
    identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ApiTokenCreated:
    """Create Api Token.

    Requires the `read:dashboard` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    user = db.get(User, identity.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Current user not found")
    return create_token_for_user(db, user=user, create=payload, settings=settings, actor=identity.username)


@router.get("/api-tokens/{token_id}", response_model=ApiTokenResponse, tags=["API Tokens"], operation_id="getApiToken")
def get_api_token(
    token_id: Annotated[int, ApiPath(description='Unique identifier of the token record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    db: Session = Depends(get_db),
) -> ApiTokenResponse:
    """Get Api Token.

    Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        token_id: Stable identifier of the associated token resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    token = db.get(ApiToken, token_id)
    if not token or (not identity.has_role("admin") and token.owner_user_id != identity.user_id):
        raise HTTPException(status_code=404, detail="API token not found")
    return token_to_response(token)


def revoke_token(db: Session, token: ApiToken, identity: Identity) -> ApiTokenResponse:
    """Return revoke token.

    Args:
        db: Active database session.
        token: Token supplied by the caller.
        identity: Authenticated identity authorizing the request.
    """
    token.enabled = False
    token.revoked_at = utcnow()
    token.revoked_by = identity.username
    db.add(token)
    db.commit()
    db.refresh(token)
    record_audit(
        db,
        actor=identity.username,
        action="revoke_api_token",
        resource_type="api_token",
        resource_id=str(token.id),
        detail=f"Revoked API token {token.name}",
    )
    return token_to_response(token)


@router.delete("/api-tokens/{token_id}", status_code=204, tags=["API Tokens"], operation_id="deleteApiToken")
def delete_api_token(
    token_id: Annotated[int, ApiPath(description='Unique identifier of the token record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Api Token.

    Requires the `read:dashboard` API scope. Removal or revocation takes effect in Atlaso
    application state; appliance host changes remain subject to the documented apply boundary for
    the resource.

    Args:
        token_id: Stable identifier of the associated token resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    token = db.get(ApiToken, token_id)
    if not token or (not identity.has_role("admin") and token.owner_user_id != identity.user_id):
        raise HTTPException(status_code=404, detail="API token not found")
    revoke_token(db, token, identity)
    return Response(status_code=204)


@router.post("/api-tokens/{token_id}/revoke", response_model=ApiTokenResponse, tags=["API Tokens"], operation_id="revokeApiToken")
def revoke_api_token(
    token_id: Annotated[int, ApiPath(description='Unique identifier of the token record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    db: Session = Depends(get_db),
) -> ApiTokenResponse:
    """Revoke Api Token.

    Requires the `read:dashboard` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        token_id: Stable identifier of the associated token resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    token = db.get(ApiToken, token_id)
    if not token or (not identity.has_role("admin") and token.owner_user_id != identity.user_id):
        raise HTTPException(status_code=404, detail="API token not found")
    return revoke_token(db, token, identity)


@router.get("/dashboard", response_model=DashboardResponse, tags=["Dashboard"], operation_id="getDashboard")
def get_dashboard(
    identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DashboardResponse:
    """Get Dashboard.

    Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    services = db.execute(select(ServiceState).order_by(ServiceState.display_name)).scalars().all()
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    policies = db.execute(select(WanPolicy).where(WanPolicy.enabled.is_(True)).order_by(WanPolicy.name)).scalars().all()
    audit_events = db.execute(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(5)).scalars().all()
    return DashboardResponse(
        appliance={
            "hostname": socket.gethostname(),
            "management_ip": "127.0.0.1",
            "uptime": "development session",
            "cpu_usage_percent": 12,
            "memory_usage_percent": 38,
        },
        service_health=[ServiceStateResponse.model_validate(service) for service in services],
        interfaces=[PhysicalInterfaceResponse.model_validate(interface) for interface in interfaces],
        active_wan_policies=[WanPolicyResponse.model_validate(policy) for policy in policies],
        disk_usage={"root_percent": 41, "repository_percent": 3, "vcf_backup_percent": 1},
        recent_audit_events=[
            {
                "created_at": event.created_at.isoformat(),
                "actor": event.actor,
                "action": event.action,
                "resource_type": event.resource_type,
                "success": event.success,
            }
            for event in audit_events
        ],
    )


@router.get("/monitor", response_model=MonitorResponse, tags=["Monitor"], operation_id="getMonitor")
def get_monitor(
    identity: Annotated[Identity, Depends(require_scope("read:monitoring"))],
    db: Session = Depends(get_db),
    hours: int = Query(default=6, ge=1, le=24, description='Monitoring history window, in hours, from 1 through 24.'),
) -> MonitorResponse:
    """Get Monitor.

    Requires the `read:monitoring` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        hours: Hours consumed by get monitor.
    """
    return MonitorResponse(**monitor_payload(db, hours=hours))


@router.get(
    "/interfaces/physical",
    response_model=list[PhysicalInterfaceResponse],
    tags=["Interfaces"],
    operation_id="listPhysicalInterfaces",
)
def list_physical_interfaces(
    identity: Annotated[Identity, Depends(require_scope("read:interfaces"))],
    db: Session = Depends(get_db),
) -> list[PhysicalInterfaceResponse]:
    """List Physical Interfaces.

    Requires the `read:interfaces` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [PhysicalInterfaceResponse.model_validate(row) for row in db.execute(select(PhysicalInterface)).scalars().all()]


@router.get(
    "/interfaces/physical/{name}",
    response_model=PhysicalInterfaceResponse,
    tags=["Interfaces"],
    operation_id="getPhysicalInterface",
)
def get_physical_interface(
    name: Annotated[str, ApiPath(description='Stable name identifying the resource addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:interfaces"))],
    db: Session = Depends(get_db),
) -> PhysicalInterfaceResponse:
    """Get Physical Interface.

    Requires the `read:interfaces` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        name: Stable name identifying the resource or operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == name)).scalar_one_or_none()
    if not interface:
        raise HTTPException(status_code=404, detail="Interface not found")
    return PhysicalInterfaceResponse.model_validate(interface)


@router.patch(
    "/interfaces/physical/{name}",
    response_model=PhysicalInterfaceResponse,
    tags=["Interfaces"],
    operation_id="updatePhysicalInterface",
)
def update_physical_interface(
    name: Annotated[str, ApiPath(description='Stable name identifying the resource addressed by this operation.')],
    payload: PhysicalInterfaceUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
    db: Session = Depends(get_db),
) -> PhysicalInterfaceResponse:
    """Update Physical Interface Desired State.

    Requires the `write:interfaces` API scope. This operation validates and saves the supplied
    physical-interface fields, then atomically reconciles dependent DNS, NTP/NTS, Certificate
    Authority, KMS, LDAP, VCF service, ESX Storage, Web Terminal, DHCP, and Network Boot bindings.
    If any dependent update fails, Atlaso rolls back the interface and every dependent row. The
    call changes desired state only; the global Appliance Apply workflow remains the
    host-enforcement boundary.

    Args:
        name: Stable name identifying the resource or operation.
        payload: Typed partial physical-interface desired-state update.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    interface = db.execute(
        select(PhysicalInterface).where(PhysicalInterface.name == name)
    ).scalar_one_or_none()
    if not interface:
        raise HTTPException(status_code=404, detail="Interface not found")
    try:
        result = update_physical_interface_desired_state(
            db,
            interface,
            payload.model_dump(exclude_unset=True),
            dns_refresher=refresh_interface_service_dns_aliases,
        )
    except PhysicalInterfaceUpdateError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    detail_parts: list[str] = []
    if result.dependent_updates:
        detail_parts.append(
            "Refreshed dependent desired-state addresses: "
            f"{', '.join(result.dependent_updates)}."
        )
    if result.preserved_dhcp_dns:
        detail_parts.append(
            "Preserved DHCP-provided DNS in desired state: "
            f"{', '.join(result.preserved_dhcp_dns)}."
        )
    record_audit(
        db,
        actor=identity.username,
        action="update_interface",
        resource_type="interface",
        resource_id=name,
        detail=" ".join(detail_parts),
    )
    return PhysicalInterfaceResponse.model_validate(result.interface)


@router.post("/interfaces/physical/{name}/enable", response_model=PhysicalInterfaceResponse, tags=["Interfaces"], operation_id="enablePhysicalInterface")
def enable_physical_interface(
    name: Annotated[str, ApiPath(description='Stable name identifying the resource addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
    db: Session = Depends(get_db),
) -> PhysicalInterfaceResponse:
    """Enable Physical Interface.

    Requires the `write:interfaces` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        name: Stable name identifying the resource or operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return update_physical_interface(name, PhysicalInterfaceUpdate(admin_state="up"), identity, db)


@router.post("/interfaces/physical/{name}/disable", response_model=PhysicalInterfaceResponse, tags=["Interfaces"], operation_id="disablePhysicalInterface")
def disable_physical_interface(
    name: Annotated[str, ApiPath(description='Stable name identifying the resource addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
    db: Session = Depends(get_db),
) -> PhysicalInterfaceResponse:
    """Disable Physical Interface.

    Requires the `write:interfaces` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        name: Stable name identifying the resource or operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return update_physical_interface(name, PhysicalInterfaceUpdate(admin_state="down"), identity, db)


@router.post("/interfaces/refresh", response_model=list[PhysicalInterfaceResponse], tags=["Interfaces"], operation_id="refreshPhysicalInterfaces")
def refresh_physical_interfaces(
    identity: Annotated[Identity, Depends(require_scope("write:interfaces"))],
    db: Session = Depends(get_db),
) -> list[PhysicalInterfaceResponse]:
    """Refresh Physical Interfaces.

    Requires the `write:interfaces` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    interfaces, discovered_count = sync_host_physical_interfaces(db)
    record_audit(
        db,
        actor=identity.username,
        action="refresh_physical_interface_inventory",
        resource_type="interface",
        detail=f"{discovered_count} host interface{'s' if discovered_count != 1 else ''} discovered",
    )
    return [PhysicalInterfaceResponse.model_validate(row) for row in interfaces]


@router.get("/vlans", response_model=list[VlanResponse], tags=["VLANs"], operation_id="listVlans")
def list_vlans(
    identity: Annotated[Identity, Depends(require_scope("read:vlans"))],
    db: Session = Depends(get_db),
) -> list[VlanResponse]:
    """List Vlans.

    Requires the `read:vlans` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [VlanResponse.model_validate(row) for row in db.execute(select(VlanInterface)).scalars().all()]


@router.post("/vlans", response_model=VlanResponse, status_code=201, tags=["VLANs"], operation_id="createVlan")
def create_vlan(
    payload: VlanCreate,
    identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
    db: Session = Depends(get_db),
) -> VlanResponse:
    """Create Vlan.

    Requires the `write:vlans` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    values = validate_vlan_api_payload(payload, db)
    vlan = VlanInterface(name=f"{values['parent_interface']}.{values['vlan_id']}", **values)
    db.add(vlan)
    db.commit()
    db.refresh(vlan)
    record_audit(db, actor=identity.username, action="create_vlan", resource_type="vlan", resource_id=str(vlan.id))
    return VlanResponse.model_validate(vlan)


@router.get("/vlans/{vlan_id}", response_model=VlanResponse, tags=["VLANs"], operation_id="getVlan")
def get_vlan(
    vlan_id: Annotated[int, ApiPath(description='Unique identifier of the vlan record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:vlans"))],
    db: Session = Depends(get_db),
) -> VlanResponse:
    """Get Vlan.

    Requires the `read:vlans` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        vlan_id: Stable identifier of the associated VLAN resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    vlan = db.get(VlanInterface, vlan_id)
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")
    return VlanResponse.model_validate(vlan)


@router.patch("/vlans/{vlan_id}", response_model=VlanResponse, tags=["VLANs"], operation_id="updateVlan")
def update_vlan(
    vlan_id: Annotated[int, ApiPath(description='Unique identifier of the vlan record addressed by this operation.')],
    payload: VlanCreate,
    identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
    db: Session = Depends(get_db),
) -> VlanResponse:
    """Update Vlan.

    Requires the `write:vlans` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        vlan_id: Stable identifier of the associated VLAN resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    vlan = db.get(VlanInterface, vlan_id)
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")
    values = validate_vlan_api_payload(payload, db)
    for key, value in values.items():
        setattr(vlan, key, value)
    vlan.name = f"{vlan.parent_interface}.{vlan.vlan_id}"
    db.commit()
    db.refresh(vlan)
    record_audit(db, actor=identity.username, action="update_vlan", resource_type="vlan", resource_id=str(vlan.id))
    return VlanResponse.model_validate(vlan)


@router.delete("/vlans/{vlan_id}", status_code=204, tags=["VLANs"], operation_id="deleteVlan")
def delete_vlan(
    vlan_id: Annotated[int, ApiPath(description='Unique identifier of the vlan record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:vlans"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Vlan.

    Requires the `write:vlans` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        vlan_id: Stable identifier of the associated VLAN resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    vlan = db.get(VlanInterface, vlan_id)
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")
    db.delete(vlan)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_vlan", resource_type="vlan", resource_id=str(vlan_id))
    return Response(status_code=204)


@router.post("/vlans/{vlan_id}/enable", response_model=VlanResponse, tags=["VLANs"], operation_id="enableVlan")
def enable_vlan(vlan_id: Annotated[int, ApiPath(description='Unique identifier of the vlan record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:vlans"))], db: Session = Depends(get_db)) -> VlanResponse:
    """Enable Vlan.

    Requires the `write:vlans` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        vlan_id: Stable identifier of the associated VLAN resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    vlan = db.get(VlanInterface, vlan_id)
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")
    parent = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == vlan.parent_interface)).scalar_one_or_none()
    if parent and parent.oper_state == "missing":
        raise HTTPException(
            status_code=409,
            detail=f"{vlan.parent_interface} is missing from host inventory. Move the VLAN to an available trunk parent before enabling it.",
        )
    vlan.enabled = True
    db.commit()
    db.refresh(vlan)
    record_audit(db, actor=identity.username, action="enable_vlan", resource_type="vlan", resource_id=str(vlan.id))
    return VlanResponse.model_validate(vlan)


@router.post("/vlans/{vlan_id}/disable", response_model=VlanResponse, tags=["VLANs"], operation_id="disableVlan")
def disable_vlan(vlan_id: Annotated[int, ApiPath(description='Unique identifier of the vlan record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:vlans"))], db: Session = Depends(get_db)) -> VlanResponse:
    """Disable Vlan.

    Requires the `write:vlans` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        vlan_id: Stable identifier of the associated VLAN resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    vlan = db.get(VlanInterface, vlan_id)
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")
    vlan.enabled = False
    db.commit()
    db.refresh(vlan)
    record_audit(db, actor=identity.username, action="disable_vlan", resource_type="vlan", resource_id=str(vlan.id))
    return VlanResponse.model_validate(vlan)


@router.post("/vlans/{vlan_id}/apply", response_model=VlanResponse, tags=["VLANs"], operation_id="applyVlan")
def apply_vlan(vlan_id: Annotated[int, ApiPath(description='Unique identifier of the vlan record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:vlans"))], db: Session = Depends(get_db)) -> VlanResponse:
    """Apply Vlan.

    Requires the `write:vlans` API scope. The action runs through the endpoint's existing audited
    adapter or task boundary; inspect the returned state before treating the operation as complete.

    Args:
        vlan_id: Stable identifier of the associated VLAN resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    vlan = get_vlan(vlan_id, identity, db)
    record_audit(db, actor=identity.username, action="apply_vlan_dry_run", resource_type="vlan", resource_id=str(vlan_id))
    return vlan


@router.get("/routes", response_model=list[RouteResponse], tags=["Routes"], operation_id="listRoutes")
def list_routes(identity: Annotated[Identity, Depends(require_scope("read:routes"))], db: Session = Depends(get_db)) -> list[RouteResponse]:
    """List Routes.

    Requires the `read:routes` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = db.execute(select(Route).options(selectinload(Route.wan_policy)).order_by(Route.destination_cidr)).scalars().all()
    return [route_response(row) for row in rows]


def route_response(route: Route) -> RouteResponse:
    """Return route response.

    Args:
        route: Route consumed by route response.
    """
    return RouteResponse(
        id=route.id,
        destination_cidr=route.destination_cidr,
        gateway=route.gateway,
        interface_name=route.interface_name,
        metric=route.metric,
        enabled=route.enabled,
        wan_policy_id=route.wan_policy_id,
        wan_mode="interface",
        wan_policy=WanPolicyResponse.model_validate(route.wan_policy) if route.wan_policy else None,
    )


def route_target_names(db: Session) -> set[str]:
    """Return route target names.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
    names = {
        interface.name
        for interface in interfaces
        if interface.oper_state != "missing"
        and normalize_interface_mode(interface.mode) != "trunk"
        and (interface.role or "").strip().lower() != "management"
        and (interface.ip_cidr or interface.ipv6_cidr)
    }
    names.update({vlan.name for vlan in vlans if vlan.enabled and (vlan.role or "").strip().lower() != "management" and (vlan.ip_cidr or vlan.ipv6_cidr)})
    return names


def validate_route_payload(payload: RouteCreate, db: Session) -> None:
    """Validate route payload.

    Args:
        payload: Validated request or operation payload.
        db: Active database session.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    try:
        destination = ip_network(payload.destination_cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{payload.destination_cidr} is not a valid destination CIDR.") from exc
    if payload.gateway:
        try:
            gateway = ip_address(payload.gateway)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"{payload.gateway} is not a valid gateway IP address.") from exc
        if gateway.version != destination.version:
            raise HTTPException(status_code=422, detail="Route gateway family must match the destination CIDR family.")
    if payload.interface_name not in route_target_names(db):
        raise HTTPException(status_code=422, detail="Choose an access physical interface or enabled VLAN interface with an IP CIDR.")
    if payload.metric < 0:
        raise HTTPException(status_code=422, detail="Route metric cannot be negative.")


@router.post("/routes", response_model=RouteResponse, status_code=201, tags=["Routes"], operation_id="createRoute")
def create_route(payload: RouteCreate, identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
    """Create Route.

    Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    validate_route_payload(payload, db)
    route = Route(**payload.model_dump())
    db.add(route)
    db.commit()
    db.refresh(route)
    record_audit(db, actor=identity.username, action="create_route", resource_type="route", resource_id=str(route.id))
    return route_response(db.get(Route, route.id))


@router.get("/routes/{route_id}", response_model=RouteResponse, tags=["Routes"], operation_id="getRoute")
def get_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("read:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
    """Get Route.

    Requires the `read:routes` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        route_id: Stable identifier of the associated route resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    route = db.execute(select(Route).options(selectinload(Route.wan_policy)).where(Route.id == route_id)).scalar_one_or_none()
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
    return route_response(route)


@router.patch("/routes/{route_id}", response_model=RouteResponse, tags=["Routes"], operation_id="updateRoute")
def update_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], payload: RouteCreate, identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
    """Update Route.

    Requires the `write:routes` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        route_id: Stable identifier of the associated route resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    route = db.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
    validate_route_payload(payload, db)
    for key, value in payload.model_dump().items():
        setattr(route, key, value)
    db.commit()
    record_audit(db, actor=identity.username, action="update_route", resource_type="route", resource_id=str(route_id))
    return get_route(route_id, identity, db)


@router.delete("/routes/{route_id}", status_code=204, tags=["Routes"], operation_id="deleteRoute")
def delete_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> Response:
    """Delete Route.

    Requires the `write:routes` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        route_id: Stable identifier of the associated route resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    route = db.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
    db.delete(route)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_route", resource_type="route", resource_id=str(route_id))
    return Response(status_code=204)


@router.post("/routes/{route_id}/enable", response_model=RouteResponse, tags=["Routes"], operation_id="enableRoute")
def enable_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
    """Enable Route.

    Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        route_id: Stable identifier of the associated route resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    route = db.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
    route.enabled = True
    db.commit()
    record_audit(db, actor=identity.username, action="enable_route", resource_type="route", resource_id=str(route_id))
    return get_route(route_id, identity, db)


@router.post("/routes/{route_id}/disable", response_model=RouteResponse, tags=["Routes"], operation_id="disableRoute")
def disable_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
    """Disable Route.

    Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        route_id: Stable identifier of the associated route resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    route = db.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
    route.enabled = False
    db.commit()
    record_audit(db, actor=identity.username, action="disable_route", resource_type="route", resource_id=str(route_id))
    return get_route(route_id, identity, db)


@router.post("/routes/{route_id}/wan-policy", response_model=RouteResponse, tags=["Routes"], operation_id="assignRouteWanPolicy")
def assign_route_wan_policy(
    route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')],
    wan_policy_id: Annotated[int, Query(description='Unique identifier of the wan policy record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:routes"))],
    db: Session = Depends(get_db),
) -> RouteResponse:
    """Assign Route Wan Policy.

    Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        route_id: Stable identifier of the associated route resource.
        wan_policy_id: Stable identifier of the associated WAN policy resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    route = db.get(Route, route_id)
    policy = db.get(WanPolicy, wan_policy_id)
    if not route or not policy:
        raise HTTPException(status_code=404, detail="Route or WAN policy not found")
    route.wan_policy_id = policy.id
    db.commit()
    record_audit(db, actor=identity.username, action="assign_wan_policy", resource_type="route", resource_id=str(route_id))
    return get_route(route_id, identity, db)


@router.delete("/routes/{route_id}/wan-policy", response_model=RouteResponse, tags=["Routes"], operation_id="clearRouteWanPolicy")
def clear_route_wan_policy(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
    """Clear Route Wan Policy.

    Requires the `write:routes` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        route_id: Stable identifier of the associated route resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    route = db.get(Route, route_id)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
    route.wan_policy_id = None
    db.commit()
    record_audit(db, actor=identity.username, action="clear_route_wan_policy", resource_type="route", resource_id=str(route_id))
    return get_route(route_id, identity, db)


@router.get("/wan/policies", response_model=list[WanPolicyResponse], tags=["WAN"], operation_id="listWanPolicies")
def list_wan_policies(identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> list[WanPolicyResponse]:
    """List Wan Policies.

    Requires the `read:wan` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [WanPolicyResponse.model_validate(row) for row in db.execute(select(WanPolicy).order_by(WanPolicy.name)).scalars().all()]


@router.post("/wan/policies", response_model=WanPolicyResponse, status_code=201, tags=["WAN"], operation_id="createWanPolicy")
def create_wan_policy(payload: WanPolicyCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> WanPolicyResponse:
    """Create Wan Policy.

    Requires the `write:wan` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    policy = WanPolicy(**payload.model_dump())
    db.add(policy)
    db.commit()
    db.refresh(policy)
    record_audit(db, actor=identity.username, action="create_wan_policy", resource_type="wan_policy", resource_id=str(policy.id))
    return WanPolicyResponse.model_validate(policy)


@router.get("/wan/policies/{policy_id}", response_model=WanPolicyResponse, tags=["WAN"], operation_id="getWanPolicy")
def get_wan_policy(policy_id: Annotated[int, ApiPath(description='Unique identifier of the policy record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> WanPolicyResponse:
    """Get Wan Policy.

    Requires the `read:wan` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        policy_id: Stable identifier of the associated policy resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    policy = db.get(WanPolicy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="WAN policy not found")
    return WanPolicyResponse.model_validate(policy)


@router.patch("/wan/policies/{policy_id}", response_model=WanPolicyResponse, tags=["WAN"], operation_id="updateWanPolicy")
def update_wan_policy(policy_id: Annotated[int, ApiPath(description='Unique identifier of the policy record addressed by this operation.')], payload: WanPolicyCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> WanPolicyResponse:
    """Update Wan Policy.

    Requires the `write:wan` API scope. The operation updates saved Atlaso state and does not bypass
    the documented global Appliance Apply or service lifecycle boundary.

    Args:
        policy_id: Stable identifier of the associated policy resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    policy = db.get(WanPolicy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="WAN policy not found")
    for key, value in payload.model_dump().items():
        setattr(policy, key, value)
    db.commit()
    db.refresh(policy)
    record_audit(db, actor=identity.username, action="update_wan_policy", resource_type="wan_policy", resource_id=str(policy.id))
    return WanPolicyResponse.model_validate(policy)


@router.delete("/wan/policies/{policy_id}", status_code=204, tags=["WAN"], operation_id="deleteWanPolicy")
def delete_wan_policy(policy_id: Annotated[int, ApiPath(description='Unique identifier of the policy record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> Response:
    """Delete Wan Policy.

    Requires the `write:wan` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        policy_id: Stable identifier of the associated policy resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    policy = db.get(WanPolicy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="WAN policy not found")
    db.delete(policy)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_wan_policy", resource_type="wan_policy", resource_id=str(policy_id))
    return Response(status_code=204)


def nat_outbound_target_names(db: Session) -> set[str]:
    """Return nat outbound target names.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
    names = {
        interface.name
        for interface in interfaces
        if interface.ip_cidr and interface.oper_state != "missing" and normalize_interface_mode(interface.mode) != "trunk"
    }
    names.update({vlan.name for vlan in vlans if vlan.enabled and vlan.ip_cidr})
    return names


def nat_source_group_ids(db: Session) -> set[str]:
    """Return nat source group ids.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
    networks = firewall_interface_networks(interfaces, vlans)
    state = firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), networks)
    return {str(group.get("id", "")) for group in state["groups"]}


def validate_nat_rule_payload(payload: NatRuleCreate, db: Session) -> None:
    """Validate nat rule payload.

    Args:
        payload: Validated request or operation payload.
        db: Active database session.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    source_groups = firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), firewall_interface_networks(db.execute(select(PhysicalInterface)).scalars().all(), db.execute(select(VlanInterface)).scalars().all()))["groups"]
    source_errors = validate_nat_source(payload.source, nat_source_group_ids(db), source_groups)
    if source_errors:
        raise HTTPException(status_code=422, detail=source_errors[0])
    if payload.outbound_interface not in nat_outbound_target_names(db):
        raise HTTPException(status_code=422, detail="Choose an access physical interface or enabled VLAN interface with an IP CIDR.")
    if not payload.masquerade:
        raise HTTPException(status_code=422, detail="NAT v1 supports masquerade only.")


@router.get("/nat/rules", response_model=list[NatRuleResponse], tags=["NAT"], operation_id="listNatRules")
def list_nat_rules(identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> list[NatRuleResponse]:
    """List Nat Rules.

    Requires the `read:wan` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = db.execute(select(NatRule).order_by(NatRule.priority, NatRule.name)).scalars().all()
    return [NatRuleResponse.model_validate(row) for row in rows]


@router.post("/nat/rules", response_model=NatRuleResponse, status_code=201, tags=["NAT"], operation_id="createNatRule")
def create_nat_rule(payload: NatRuleCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> NatRuleResponse:
    """Create Nat Rule.

    Requires the `write:wan` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    validate_nat_rule_payload(payload, db)
    rule = NatRule(**payload.model_dump())
    db.add(rule)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"NAT rule {rule.name} already exists") from None
    db.refresh(rule)
    record_audit(db, actor=identity.username, action="create_nat_rule", resource_type="nat_rule", resource_id=str(rule.id))
    return NatRuleResponse.model_validate(rule)


@router.get("/nat/rules/{rule_id}", response_model=NatRuleResponse, tags=["NAT"], operation_id="getNatRule")
def get_nat_rule(rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> NatRuleResponse:
    """Get Nat Rule.

    Requires the `read:wan` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        rule_id: Stable identifier of the associated rule resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rule = db.get(NatRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="NAT rule not found")
    return NatRuleResponse.model_validate(rule)


@router.patch("/nat/rules/{rule_id}", response_model=NatRuleResponse, tags=["NAT"], operation_id="updateNatRule")
def update_nat_rule(rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')], payload: NatRuleCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> NatRuleResponse:
    """Update Nat Rule.

    Requires the `write:wan` API scope. The operation updates saved Atlaso state and does not bypass
    the documented global Appliance Apply or service lifecycle boundary.

    Args:
        rule_id: Stable identifier of the associated rule resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rule = db.get(NatRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="NAT rule not found")
    validate_nat_rule_payload(payload, db)
    for key, value in payload.model_dump().items():
        setattr(rule, key, value)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"NAT rule {rule.name} already exists") from None
    db.refresh(rule)
    record_audit(db, actor=identity.username, action="update_nat_rule", resource_type="nat_rule", resource_id=str(rule.id))
    return NatRuleResponse.model_validate(rule)


@router.delete("/nat/rules/{rule_id}", status_code=204, tags=["NAT"], operation_id="deleteNatRule")
def delete_nat_rule(rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> Response:
    """Delete Nat Rule.

    Requires the `write:wan` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        rule_id: Stable identifier of the associated rule resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rule = db.get(NatRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="NAT rule not found")
    db.delete(rule)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_nat_rule", resource_type="nat_rule", resource_id=str(rule_id))
    return Response(status_code=204)


@router.get("/wan/status", response_model=WanStatusResponse, tags=["WAN"], operation_id="getWanStatus")
def get_wan_status(identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> WanStatusResponse:
    """Get Wan Status.

    Requires the `read:wan` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    routes = db.execute(select(Route).where(Route.wan_policy_id.is_not(None))).scalars().all()
    nat_rules = db.execute(select(NatRule).where(NatRule.enabled.is_(True))).scalars().all()
    return WanStatusResponse(
        active_policy_count=len(routes),
        managed_interfaces=sorted({route.interface_name for route in routes} | {rule.outbound_interface for rule in nat_rules}),
        dry_run=SystemAdapter().dry_run,
    )


def get_dns_settings_row(db: Session) -> DnsSettings:
    """Return dns settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(DnsSettings)).scalar_one_or_none()
    if settings is None:
        settings = DnsSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    if ensure_dns_authoritative_defaults(settings):
        db.commit()
        db.refresh(settings)
    return settings


def setting_value(db: Session, key: str) -> str:
    """Return setting value.

    Args:
        db: Active database session.
        key: Stable setting, vault, or mapping key.
    """
    setting = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
    return setting.value if setting else ""


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


def get_dnsmasq_state(
    db: Session,
) -> tuple[
    DnsSettings,
    list[DnsRecord],
    DhcpSettings,
    list[DhcpScope],
    list[DhcpOption],
    list[DhcpReservation],
    list[str],
    bool,
    str,
]:
    """Return dnsmasq state.

    Args:
        db: Active database session.
    """
    dns_settings = get_dns_settings_row(db)
    conditional_forwarders = setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY)
    dns_records = db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()
    dhcp_settings = get_dhcp_settings_row(db)
    dhcp_scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    dhcp_options = db.execute(select(DhcpOption).order_by(DhcpOption.scope_id, DhcpOption.option_code)).scalars().all()
    dhcp_reservations = db.execute(select(DhcpReservation).order_by(DhcpReservation.hostname)).scalars().all()
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    management_interface, observed_dhcp_upstream_servers = management_dhcp_dns_context(physical_interfaces)
    fallback_upstream_servers = observed_dhcp_upstream_servers if not effective_dns_upstream_servers(dns_settings) else []
    require_dhcp_upstream = dhcp_dns_upstream_required(dns_settings, management_interface)
    config_preview = render_dnsmasq_config(
        dns_settings=dns_settings,
        dns_records=dns_records,
        dhcp_settings=dhcp_settings,
        dhcp_reservations=dhcp_reservations,
        dhcp_scopes=dhcp_scopes,
        dhcp_options=dhcp_options,
        conditional_forwarders=conditional_forwarders,
        fallback_upstream_servers=fallback_upstream_servers,
        require_dhcp_upstream=require_dhcp_upstream,
        esxi_pxe_boot=esxi_pxe_boot_settings(db),
    )
    return (
        dns_settings,
        dns_records,
        dhcp_settings,
        dhcp_scopes,
        dhcp_options,
        dhcp_reservations,
        fallback_upstream_servers,
        require_dhcp_upstream,
        config_preview,
    )


def ensure_dns_for_dhcp_reservation(db: Session, reservation: DhcpReservation, actor: str) -> None:
    """Ensure dns for dhcp reservation.

    Args:
        db: Active database session.
        reservation: Reservation supplied by the caller.
        actor: Authenticated identity attributed to the audit record.
    """
    scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    record_values = reservation_dns_record(reservation, scopes)
    if record_values is None:
        return
    hostname, record_type, address = record_values
    reservation.hostname = hostname
    existing = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == hostname,
            DnsRecord.record_type == record_type,
        )
    ).scalar_one_or_none()
    if existing:
        return
    record = DnsRecord(
        hostname=hostname,
        record_type=record_type,
        address=address,
        description=f"Created from DHCP reservation for {reservation.mac_address}.",
        enabled=True,
    )
    db.add(record)
    db.flush()
    record_audit(db, actor=actor, action="create_dns_record_from_dhcp_reservation", resource_type="dns_record", resource_id=str(record.id))


@router.get("/dns/status", response_model=DnsStatusResponse, tags=["DNS"], operation_id="getDnsStatus")
def get_dns_status(identity: Annotated[Identity, Depends(require_scope("read:dns"))], db: Session = Depends(get_db)) -> DnsStatusResponse:
    """Get Dns Status.

    Requires the `read:dns` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_dns_settings_row(db)
    service = db.execute(select(ServiceState).where(ServiceState.service == "dns")).scalar_one_or_none()
    record_count = db.scalar(select(func.count()).select_from(DnsRecord).where(DnsRecord.enabled.is_(True)))
    return DnsStatusResponse(
        enabled=settings.enabled,
        service=ServiceStateResponse.model_validate(service) if service else None,
        listen_interface=settings.listen_interface,
        listen_address=settings.listen_address,
        domain=settings.domain,
        record_count=record_count or 0,
        config_path=settings.config_path,
        dry_run=SystemAdapter().dry_run,
    )


@router.get("/dns/settings", response_model=DnsSettingsResponse, tags=["DNS"], operation_id="getDnsSettings")
def get_dns_settings(identity: Annotated[Identity, Depends(require_scope("read:dns"))], db: Session = Depends(get_db)) -> DnsSettingsResponse:
    """Get Dns Settings.

    Requires the `read:dns` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return DnsSettingsResponse(
        **dns_settings_to_dict(
            get_dns_settings_row(db),
            setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY),
        )
    )


@router.patch("/dns/settings", response_model=DnsSettingsResponse, tags=["DNS"], operation_id="updateDnsSettings")
def update_dns_settings(
    payload: DnsSettingsUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:dns"))],
    db: Session = Depends(get_db),
) -> DnsSettingsResponse:
    """Update Dns Settings.

    Requires the `write:dns` API scope. The operation updates saved Atlaso state and does not bypass
    the documented global Appliance Apply or service lifecycle boundary.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_dns_settings_row(db)
    for key, value in payload.model_dump().items():
        if key == "upstream_servers":
            value = join_servers(value)
        elif key == "conditional_forwarders":
            set_setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY, join_conditional_forwarders(value))
            continue
        elif key == "domain":
            value = join_domains(split_domains(value))
        setattr(settings, key, value)
    settings.updated_at = utcnow()
    db.commit()
    db.refresh(settings)
    record_audit(
        db,
        actor=identity.username,
        action="update_dns_settings",
        resource_type="dns",
        resource_id=str(settings.id),
        detail=(
            f"authoritative={settings.authoritative}; primary={settings.authoritative_server}; "
            f"contact={settings.authoritative_contact}; ttl={settings.authoritative_ttl}; "
            f"serial={settings.authoritative_serial}; refresh={settings.authoritative_refresh}; "
            f"retry={settings.authoritative_retry}; expire={settings.authoritative_expire}"
        ),
    )
    return DnsSettingsResponse(
        **dns_settings_to_dict(
            settings,
            setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY),
        )
    )


@router.get("/dns/records", response_model=list[DnsRecordResponse], tags=["DNS"], operation_id="listDnsRecords")
def list_dns_records(identity: Annotated[Identity, Depends(require_scope("read:dns"))], db: Session = Depends(get_db)) -> list[DnsRecordResponse]:
    """List Dns Records.

    Requires the `read:dns` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [DnsRecordResponse.model_validate(row) for row in db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()]


@router.post("/dns/records", response_model=DnsRecordResponse, status_code=201, tags=["DNS"], operation_id="createDnsRecord")
def create_dns_record(
    payload: DnsRecordCreate,
    identity: Annotated[Identity, Depends(require_scope("write:dns"))],
    db: Session = Depends(get_db),
) -> DnsRecordResponse:
    """Create Dns Record.

    Requires the `write:dns` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    hostname = payload.hostname.strip().lower()
    record_type = payload.record_type.strip().upper()
    address = payload.address.strip()
    record_data_json = dump_dns_record_data(record_type, address)
    validation_errors = validate_dns_record(hostname, record_type, address)
    validation_errors.extend(validate_authoritative_dns_record(get_dns_settings_row(db), hostname, record_type, address))
    if validation_errors:
        raise HTTPException(status_code=422, detail=" ".join(validation_errors))
    existing = db.execute(
        select(DnsRecord).where(
            func.lower(DnsRecord.hostname) == hostname,
            func.lower(DnsRecord.record_type) == record_type.lower(),
            DnsRecord.address == address,
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"DNS {record_type} record already exists for {hostname}")
    record = DnsRecord(
        hostname=hostname,
        record_type=record_type,
        address=address,
        record_data_json=record_data_json,
        description=payload.description,
        enabled=payload.enabled,
    )
    db.add(record)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"DNS {record_type} record already exists for {hostname}") from exc
    db.refresh(record)
    record_audit(db, actor=identity.username, action="create_dns_record", resource_type="dns_record", resource_id=str(record.id))
    return DnsRecordResponse.model_validate(record)


@router.patch("/dns/records/{record_id}", response_model=DnsRecordResponse, tags=["DNS"], operation_id="updateDnsRecord")
def update_dns_record(
    record_id: Annotated[int, ApiPath(description='Unique identifier of the record record addressed by this operation.')],
    payload: DnsRecordCreate,
    identity: Annotated[Identity, Depends(require_scope("write:dns"))],
    db: Session = Depends(get_db),
) -> DnsRecordResponse:
    """Update Dns Record.

    Requires the `write:dns` API scope. The operation updates saved Atlaso state and does not bypass
    the documented global Appliance Apply or service lifecycle boundary.

    Args:
        record_id: Stable identifier of the associated record resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    record = db.get(DnsRecord, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="DNS record not found")
    hostname = payload.hostname.strip().lower()
    record_type = payload.record_type.strip().upper()
    address = payload.address.strip()
    record_data_json = dump_dns_record_data(record_type, address)
    validation_errors = validate_dns_record(hostname, record_type, address)
    validation_errors.extend(validate_authoritative_dns_record(get_dns_settings_row(db), hostname, record_type, address))
    if validation_errors:
        raise HTTPException(status_code=422, detail=" ".join(validation_errors))
    existing = db.execute(
        select(DnsRecord).where(
            DnsRecord.id != record_id,
            func.lower(DnsRecord.hostname) == hostname,
            func.lower(DnsRecord.record_type) == record_type.lower(),
            DnsRecord.address == address,
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"DNS {record_type} record already exists for {hostname}")
    record.hostname = hostname
    record.record_type = record_type
    record.address = address
    record.record_data_json = record_data_json
    record.description = payload.description
    record.enabled = payload.enabled
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"DNS {record_type} record already exists for {hostname}") from exc
    db.refresh(record)
    record_audit(db, actor=identity.username, action="update_dns_record", resource_type="dns_record", resource_id=str(record.id))
    return DnsRecordResponse.model_validate(record)


@router.post("/dns/records/import", response_model=DnsHostsImportResponse, tags=["DNS"], operation_id="importDnsHostsFile")
def import_dns_hosts_file(
    payload: DnsHostsImportRequest,
    identity: Annotated[Identity, Depends(require_scope("write:dns"))],
    db: Session = Depends(get_db),
) -> DnsHostsImportResponse:
    """Import Dns Hosts File.

    Requires the `write:dns` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    parsed_records, errors = parse_hosts_records(payload.hosts_text)
    dns_settings = get_dns_settings_row(db)
    for item in parsed_records:
        errors.extend(
            validate_authoritative_dns_record(
                dns_settings,
                str(item["hostname"]),
                str(item["record_type"]),
                str(item["address"]),
            )
        )
    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors))
    if payload.replace_existing:
        for record in db.execute(select(DnsRecord)).scalars().all():
            db.delete(record)
        db.flush()
    for item in parsed_records:
        existing = None
        if not payload.replace_existing:
            existing = db.execute(
                select(DnsRecord).where(
                    DnsRecord.hostname == item["hostname"],
                    DnsRecord.record_type == item["record_type"],
                    DnsRecord.address == item["address"],
                )
            ).scalar_one_or_none()
        if existing:
            existing.address = str(item["address"])
            existing.record_data_json = dump_dns_record_data(str(item["record_type"]), str(item["address"]))
            existing.description = str(item["description"] or "")
            existing.enabled = bool(item["enabled"])
        else:
            item["record_data_json"] = dump_dns_record_data(str(item["record_type"]), str(item["address"]))
            db.add(DnsRecord(**item))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Imported hosts contain duplicate DNS records") from exc
    rows = db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()
    record_audit(
        db,
        actor=identity.username,
        action="import_dns_hosts_file",
        resource_type="dns_record",
        detail=f"Imported {len(parsed_records)} records; replace_existing={payload.replace_existing}",
    )
    return DnsHostsImportResponse(
        imported_count=len(parsed_records),
        replaced_existing=payload.replace_existing,
        records=[DnsRecordResponse.model_validate(row) for row in rows],
    )


@router.delete("/dns/records/{record_id}", status_code=204, tags=["DNS"], operation_id="deleteDnsRecord")
def delete_dns_record(
    record_id: Annotated[int, ApiPath(description='Unique identifier of the record record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:dns"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Dns Record.

    Requires the `write:dns` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        record_id: Stable identifier of the associated record resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    record = db.get(DnsRecord, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="DNS record not found")
    db.delete(record)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_dns_record", resource_type="dns_record", resource_id=str(record_id))
    return Response(status_code=204)


def dnsmasq_validation_response(db: Session) -> ConfigValidationResponse:
    """Return dnsmasq validation response.

    Args:
        db: Active database session.
    """
    (
        dns_settings,
        dns_records,
        dhcp_settings,
        dhcp_scopes,
        dhcp_options,
        dhcp_reservations,
        fallback_upstream_servers,
        require_dhcp_upstream,
        config_preview,
    ) = get_dnsmasq_state(db)
    conditional_forwarders = setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY)
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
    bind_targets = dhcp_bind_target_names(physical_interfaces, vlan_interfaces)
    bind_target_families = dhcp_bind_target_families(physical_interfaces, vlan_interfaces)
    errors = (
        validate_dns_settings(
            dns_settings,
            dns_records,
            conditional_forwarders,
            fallback_upstream_servers=fallback_upstream_servers,
            require_dhcp_upstream=require_dhcp_upstream,
        )
        + validate_dns_listen_targets(dns_settings, bind_targets)
        + validate_dhcp_bind_targets(dhcp_settings, dhcp_scopes, bind_target_families)
        + validate_dhcp_settings(
            dhcp_settings,
            dhcp_reservations,
            dhcp_scopes,
            dhcp_options,
        )
    )
    warnings = dns_domain_warnings(split_domains(dns_settings.domain))
    adapter = SystemAdapter()
    config_path = dns_settings.config_path
    if not adapter.dry_run:
        config_path = stage_api_dnsmasq_config(config_preview)
    result = adapter.validate_dnsmasq_config(config_path)
    return ConfigValidationResponse(
        valid=not errors,
        dry_run=result.dry_run,
        command=result.command if result.command else dnsmasq_test_command(config_path),
        config_path=config_path,
        config_preview=config_preview,
        errors=errors,
        warnings=warnings,
    )


@router.post("/dns/validate", response_model=ConfigValidationResponse, tags=["DNS"], operation_id="validateDnsConfig")
def validate_dns_config(identity: Annotated[Identity, Depends(require_scope("read:dns"))], db: Session = Depends(get_db)) -> ConfigValidationResponse:
    """Validate Dns Config.

    Requires the `read:dns` API scope. The request is evaluated without persisting desired state or
    mutating appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return dnsmasq_validation_response(db)


@router.post(
    "/dns/apply",
    response_model=ConfigApplyResponse,
    tags=["DNS"],
    operation_id="applyDnsConfig",
    include_in_schema=False,
)
def apply_dns_config(identity: Annotated[Identity, Depends(require_scope("write:dns"))], db: Session = Depends(get_db)) -> ConfigApplyResponse:
    """Apply Dns Config.

    Requires the `write:dns` API scope. The action runs through the endpoint's existing audited
    adapter or task boundary; inspect the returned state before treating the operation as complete.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    validation = dnsmasq_validation_response(db)
    if not validation.valid:
        return ConfigApplyResponse(**validation.model_dump(), reloaded=False)
    apply_result = SystemAdapter().apply_dnsmasq_config(validation.config_path)
    reload_result = SystemAdapter().reload_dnsmasq()
    record_audit(
        db,
        actor=identity.username,
        action="apply_dns_config_dry_run",
        resource_type="dns",
        detail=" ".join(apply_result.command + [";"] + reload_result.command),
    )
    payload = validation.model_dump()
    payload["command"] = apply_result.command
    return ConfigApplyResponse(**payload, reloaded=not apply_result.dry_run)


@router.get("/dns/logs", response_model=list[str], tags=["DNS"], operation_id="getDnsLogs")
def get_dns_logs(identity: Annotated[Identity, Depends(require_scope("read:dns"))]) -> list[str]:
    """Get Dns Logs.

    Requires the `read:dns` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
    """
    return ["dry-run log source for dnsmasq", "Host journal reading is reserved for the provisioned appliance."]


@router.get("/dhcp/status", response_model=DhcpStatusResponse, tags=["DHCP"], operation_id="getDhcpStatus")
def get_dhcp_status(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))], db: Session = Depends(get_db)) -> DhcpStatusResponse:
    """Get Dhcp Status.

    Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_dhcp_settings_row(db)
    first_scope = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().first()
    service = db.execute(select(ServiceState).where(ServiceState.service == "dhcp")).scalar_one_or_none()
    reservations = db.execute(select(DhcpReservation).where(DhcpReservation.enabled.is_(True))).scalars().all()
    return DhcpStatusResponse(
        enabled=settings.enabled,
        service=ServiceStateResponse.model_validate(service) if service else None,
        interface_name=first_scope.interface_name if first_scope else settings.interface_name,
        range_expression=first_scope.range_expression if first_scope else "",
        reservation_count=len(reservations),
        config_path=settings.config_path,
        dry_run=SystemAdapter().dry_run,
    )


@router.get("/dhcp/settings", response_model=DhcpSettingsResponse, tags=["DHCP"], operation_id="getDhcpSettings")
def get_dhcp_settings(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))], db: Session = Depends(get_db)) -> DhcpSettingsResponse:
    """Get Dhcp Settings.

    Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return DhcpSettingsResponse.model_validate(get_dhcp_settings_row(db))


@router.patch("/dhcp/settings", response_model=DhcpSettingsResponse, tags=["DHCP"], operation_id="updateDhcpSettings")
def update_dhcp_settings(
    payload: DhcpSettingsUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> DhcpSettingsResponse:
    """Update Dhcp Settings.

    Requires the `write:dhcp` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_dhcp_settings_row(db)
    for key, value in payload.model_dump().items():
        setattr(settings, key, value)
    settings.updated_at = utcnow()
    db.commit()
    db.refresh(settings)
    record_audit(db, actor=identity.username, action="update_dhcp_settings", resource_type="dhcp", resource_id=str(settings.id))
    return DhcpSettingsResponse.model_validate(settings)


@router.get("/dhcp/scopes", response_model=list[DhcpScopeResponse], tags=["DHCP"], operation_id="listDhcpScopes")
def list_dhcp_scopes(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))], db: Session = Depends(get_db)) -> list[DhcpScopeResponse]:
    """List Dhcp Scopes.

    Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [DhcpScopeResponse.model_validate(row) for row in db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()]


@router.post("/dhcp/scopes", response_model=DhcpScopeResponse, status_code=201, tags=["DHCP"], operation_id="createDhcpScope")
def create_dhcp_scope(
    payload: DhcpScopeCreate,
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> DhcpScopeResponse:
    """Create Dhcp Scope.

    Requires the `write:dhcp` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    scope = DhcpScope(**payload.model_dump())
    db.add(scope)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="DHCP IP zone already exists") from exc
    db.refresh(scope)
    record_audit(db, actor=identity.username, action="create_dhcp_scope", resource_type="dhcp_scope", resource_id=str(scope.id))
    return DhcpScopeResponse.model_validate(scope)


@router.patch("/dhcp/scopes/{scope_id}", response_model=DhcpScopeResponse, tags=["DHCP"], operation_id="updateDhcpScope")
def update_dhcp_scope(
    scope_id: Annotated[int, ApiPath(description='Unique identifier of the scope record addressed by this operation.')],
    payload: DhcpScopeCreate,
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> DhcpScopeResponse:
    """Update Dhcp Scope.

    Requires the `write:dhcp` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        scope_id: Stable identifier of the associated scope resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    scope = db.get(DhcpScope, scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="DHCP IP zone not found")
    if payload.address_family != scope.address_family:
        raise HTTPException(status_code=409, detail="DHCP IP zone family cannot be changed after it is created")
    for key, value in payload.model_dump().items():
        setattr(scope, key, value)
    scope.updated_at = utcnow()
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="DHCP IP zone already exists") from exc
    db.refresh(scope)
    record_audit(db, actor=identity.username, action="update_dhcp_scope", resource_type="dhcp_scope", resource_id=str(scope.id))
    return DhcpScopeResponse.model_validate(scope)


@router.delete("/dhcp/scopes/{scope_id}", status_code=204, tags=["DHCP"], operation_id="deleteDhcpScope")
def delete_dhcp_scope(
    scope_id: Annotated[int, ApiPath(description='Unique identifier of the scope record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Dhcp Scope.

    Requires the `write:dhcp` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        scope_id: Stable identifier of the associated scope resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    scope = db.get(DhcpScope, scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="DHCP IP zone not found")
    for option in db.execute(select(DhcpOption).where(DhcpOption.scope_id == scope_id)).scalars().all():
        db.delete(option)
    db.delete(scope)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_dhcp_scope", resource_type="dhcp_scope", resource_id=str(scope_id))
    return Response(status_code=204)


@router.get("/dhcp/options", response_model=list[DhcpOptionResponse], tags=["DHCP"], operation_id="listDhcpOptions")
def list_dhcp_options(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))], db: Session = Depends(get_db)) -> list[DhcpOptionResponse]:
    """List Dhcp Options.

    Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [DhcpOptionResponse.model_validate(row) for row in db.execute(select(DhcpOption).order_by(DhcpOption.scope_id, DhcpOption.option_code)).scalars().all()]


@router.post("/dhcp/options", response_model=DhcpOptionResponse, status_code=201, tags=["DHCP"], operation_id="createDhcpOption")
def create_dhcp_option(
    payload: DhcpOptionCreate,
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> DhcpOptionResponse:
    """Create Dhcp Option.

    Requires the `write:dhcp` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if payload.scope_id is not None and not db.get(DhcpScope, payload.scope_id):
        raise HTTPException(status_code=404, detail="DHCP IP zone not found")
    option = DhcpOption(**payload.model_dump())
    db.add(option)
    db.commit()
    db.refresh(option)
    record_audit(db, actor=identity.username, action="create_dhcp_option", resource_type="dhcp_option", resource_id=str(option.id))
    return DhcpOptionResponse.model_validate(option)


@router.patch("/dhcp/options/{option_id}", response_model=DhcpOptionResponse, tags=["DHCP"], operation_id="updateDhcpOption")
def update_dhcp_option(
    option_id: Annotated[int, ApiPath(description='Unique identifier of the option record addressed by this operation.')],
    payload: DhcpOptionCreate,
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> DhcpOptionResponse:
    """Update Dhcp Option.

    Requires the `write:dhcp` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        option_id: Stable identifier of the associated option resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    option = db.get(DhcpOption, option_id)
    if not option:
        raise HTTPException(status_code=404, detail="DHCP option not found")
    if payload.scope_id is not None and not db.get(DhcpScope, payload.scope_id):
        raise HTTPException(status_code=404, detail="DHCP IP zone not found")
    for key, value in payload.model_dump().items():
        setattr(option, key, value)
    option.updated_at = utcnow()
    db.commit()
    db.refresh(option)
    record_audit(db, actor=identity.username, action="update_dhcp_option", resource_type="dhcp_option", resource_id=str(option.id))
    return DhcpOptionResponse.model_validate(option)


@router.delete("/dhcp/options/{option_id}", status_code=204, tags=["DHCP"], operation_id="deleteDhcpOption")
def delete_dhcp_option(
    option_id: Annotated[int, ApiPath(description='Unique identifier of the option record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Dhcp Option.

    Requires the `write:dhcp` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        option_id: Stable identifier of the associated option resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    option = db.get(DhcpOption, option_id)
    if not option:
        raise HTTPException(status_code=404, detail="DHCP option not found")
    db.delete(option)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_dhcp_option", resource_type="dhcp_option", resource_id=str(option_id))
    return Response(status_code=204)


@router.get("/dhcp/reservations", response_model=list[DhcpReservationResponse], tags=["DHCP"], operation_id="listDhcpReservations")
def list_dhcp_reservations(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))], db: Session = Depends(get_db)) -> list[DhcpReservationResponse]:
    """List Dhcp Reservations.

    Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [DhcpReservationResponse.model_validate(row) for row in db.execute(select(DhcpReservation).order_by(DhcpReservation.hostname)).scalars().all()]


@router.get("/dhcp/leases", response_model=list[DhcpLeaseResponse], tags=["DHCP"], operation_id="listDhcpLeases")
def list_dhcp_leases(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))]) -> list[DhcpLeaseResponse]:
    """List Dhcp Leases.

    Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
    """
    result = SystemAdapter().read_dhcp_leases()
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=result.stderr.strip() or "Unable to read dnsmasq DHCP leases.")
    return [DhcpLeaseResponse(**lease) for lease in parse_dnsmasq_leases(result.stdout)]


@router.post("/dhcp/reservations", response_model=DhcpReservationResponse, status_code=201, tags=["DHCP"], operation_id="createDhcpReservation")
def create_dhcp_reservation(
    payload: DhcpReservationCreate,
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> DhcpReservationResponse:
    """Create Dhcp Reservation.

    Requires the `write:dhcp` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    reservation = DhcpReservation(**payload.model_dump())
    db.add(reservation)
    db.flush()
    ensure_dns_for_dhcp_reservation(db, reservation, identity.username)
    db.commit()
    db.refresh(reservation)
    record_audit(db, actor=identity.username, action="create_dhcp_reservation", resource_type="dhcp_reservation", resource_id=str(reservation.id))
    return DhcpReservationResponse.model_validate(reservation)


@router.delete("/dhcp/reservations/{reservation_id}", status_code=204, tags=["DHCP"], operation_id="deleteDhcpReservation")
def delete_dhcp_reservation(
    reservation_id: Annotated[int, ApiPath(description='Unique identifier of the reservation record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Dhcp Reservation.

    Requires the `write:dhcp` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        reservation_id: Stable identifier of the associated reservation resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    reservation = db.get(DhcpReservation, reservation_id)
    if not reservation:
        raise HTTPException(status_code=404, detail="DHCP reservation not found")
    db.delete(reservation)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_dhcp_reservation", resource_type="dhcp_reservation", resource_id=str(reservation_id))
    return Response(status_code=204)


@router.post("/dhcp/validate", response_model=ConfigValidationResponse, tags=["DHCP"], operation_id="validateDhcpConfig")
def validate_dhcp_config(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))], db: Session = Depends(get_db)) -> ConfigValidationResponse:
    """Validate Dhcp Config.

    Requires the `read:dhcp` API scope. The request is evaluated without persisting desired state or
    mutating appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return dnsmasq_validation_response(db)


@router.post(
    "/dhcp/apply",
    response_model=ConfigApplyResponse,
    tags=["DHCP"],
    operation_id="applyDhcpConfig",
    include_in_schema=False,
)
def apply_dhcp_config(identity: Annotated[Identity, Depends(require_scope("write:dhcp"))], db: Session = Depends(get_db)) -> ConfigApplyResponse:
    """Apply Dhcp Config.

    Requires the `write:dhcp` API scope. The action runs through the endpoint's existing audited
    adapter or task boundary; inspect the returned state before treating the operation as complete.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    validation = dnsmasq_validation_response(db)
    if not validation.valid:
        return ConfigApplyResponse(**validation.model_dump(), reloaded=False)
    apply_result = SystemAdapter().apply_dnsmasq_config(validation.config_path)
    reload_result = SystemAdapter().reload_dnsmasq()
    record_audit(
        db,
        actor=identity.username,
        action="apply_dhcp_config_dry_run",
        resource_type="dhcp",
        detail=" ".join(apply_result.command + [";"] + reload_result.command),
    )
    payload = validation.model_dump()
    payload["command"] = apply_result.command
    return ConfigApplyResponse(**payload, reloaded=not apply_result.dry_run)


@router.get("/dhcp/logs", response_model=list[str], tags=["DHCP"], operation_id="getDhcpLogs")
def get_dhcp_logs(identity: Annotated[Identity, Depends(require_scope("read:dhcp"))]) -> list[str]:
    """Get Dhcp Logs.

    Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
    """
    return ["dry-run log source for dnsmasq DHCP leases", "Host lease files are read only on provisioned appliances."]


@router.get("/firewall/status", response_model=FirewallStatusResponse, tags=["Firewall"], operation_id="getFirewallStatus")
def get_firewall_status(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> FirewallStatusResponse:
    """Get Firewall Status.

    Requires the `read:firewall` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_firewall_settings(db)
    service = db.execute(select(ServiceState).where(ServiceState.service == "firewall")).scalar_one_or_none()
    rule_count = db.scalar(select(func.count()).select_from(FirewallRule)) or 0
    return FirewallStatusResponse(
        enabled=settings.enabled,
        service=ServiceStateResponse.model_validate(service) if service else None,
        rule_count=rule_count,
        config_path=settings.config_path,
        dry_run=get_settings().dry_run_system_adapters,
    )


@router.get("/firewall/settings", response_model=FirewallSettingsResponse, tags=["Firewall"], operation_id="getFirewallSettings")
def get_firewall_settings_api(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> FirewallSettingsResponse:
    """Get Firewall Settings.

    Requires the `read:firewall` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return FirewallSettingsResponse.model_validate(get_firewall_settings(db))


@router.patch("/firewall/settings", response_model=FirewallSettingsResponse, tags=["Firewall"], operation_id="updateFirewallSettings")
def update_firewall_settings_api(
    payload: FirewallSettingsUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
    db: Session = Depends(get_db),
) -> FirewallSettingsResponse:
    """Update Firewall Settings.

    Requires the `write:firewall` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_firewall_settings(db)
    values = payload.model_dump()
    if values["default_input_policy"] not in FIREWALL_POLICIES or values["default_forward_policy"] not in FIREWALL_POLICIES or values["default_output_policy"] not in FIREWALL_POLICIES:
        raise HTTPException(status_code=422, detail="Firewall default policies must be accept or drop.")
    for key, value in values.items():
        setattr(settings, key, value)
    settings.updated_at = utcnow()
    db.add(settings)
    db.commit()
    record_audit(db, actor=identity.username, action="update_firewall_settings", resource_type="firewall", resource_id=str(settings.id))
    db.refresh(settings)
    return FirewallSettingsResponse.model_validate(settings)


@router.get("/firewall/rules", response_model=list[FirewallRuleResponse], tags=["Firewall"], operation_id="listFirewallRules")
def list_firewall_rules(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> list[FirewallRuleResponse]:
    """List Firewall Rules.

    Requires the `read:firewall` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [FirewallRuleResponse.model_validate(row) for row in db.execute(select(FirewallRule).order_by(FirewallRule.priority, FirewallRule.name)).scalars().all()]


def firewall_groups_for_api_validation(db: Session) -> list[dict]:
    """Return firewall groups for api validation.

    Args:
        db: Active database session.
    """
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    interface_networks = firewall_interface_networks(physical_interfaces, vlan_interfaces)
    return firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), interface_networks)["groups"]


@router.post("/firewall/rules", response_model=FirewallRuleResponse, tags=["Firewall"], operation_id="createFirewallRule")
def create_firewall_rule_api(
    payload: FirewallRuleCreate,
    identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
    db: Session = Depends(get_db),
) -> FirewallRuleResponse:
    """Create Firewall Rule.

    Requires the `write:firewall` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rule = assign_firewall_rule_values(FirewallRule(), payload.model_dump())
    errors = validate_firewall_rule(rule, firewall_groups_for_api_validation(db), require_group_addresses=True)
    if errors:
        raise HTTPException(status_code=422, detail=" ".join(errors))
    db.add(rule)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Firewall rule {rule.name} already exists.") from exc
    record_audit(db, actor=identity.username, action="create_firewall_rule", resource_type="firewall_rule", resource_id=str(rule.id))
    db.refresh(rule)
    return FirewallRuleResponse.model_validate(rule)


@router.patch("/firewall/rules/{rule_id}", response_model=FirewallRuleResponse, tags=["Firewall"], operation_id="updateFirewallRule")
def update_firewall_rule_api(
    rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')],
    payload: FirewallRuleCreate,
    identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
    db: Session = Depends(get_db),
) -> FirewallRuleResponse:
    """Update Firewall Rule.

    Requires the `write:firewall` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        rule_id: Stable identifier of the associated rule resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rule = db.get(FirewallRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    assign_firewall_rule_values(rule, payload.model_dump())
    errors = validate_firewall_rule(rule, firewall_groups_for_api_validation(db), require_group_addresses=True)
    if errors:
        raise HTTPException(status_code=422, detail=" ".join(errors))
    db.add(rule)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Firewall rule {rule.name} already exists.") from exc
    record_audit(db, actor=identity.username, action="update_firewall_rule", resource_type="firewall_rule", resource_id=str(rule.id))
    db.refresh(rule)
    return FirewallRuleResponse.model_validate(rule)


@router.delete("/firewall/rules/{rule_id}", response_model=dict, tags=["Firewall"], operation_id="deleteFirewallRule")
def delete_firewall_rule_api(
    rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
    db: Session = Depends(get_db),
) -> dict:
    """Delete Firewall Rule.

    Requires the `write:firewall` API scope. Removal or revocation takes effect in Atlaso
    application state; appliance host changes remain subject to the documented apply boundary for
    the resource.

    Args:
        rule_id: Stable identifier of the associated rule resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rule = db.get(FirewallRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    db.delete(rule)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_firewall_rule", resource_type="firewall_rule", resource_id=str(rule_id))
    return {"deleted": True}


@router.get("/firewall/validate", response_model=ConfigValidationResponse, tags=["Firewall"], operation_id="validateFirewall")
def validate_firewall(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> ConfigValidationResponse:
    """Validate Firewall.

    Requires the `read:firewall` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings, _rules, config_preview, errors = firewall_validation_payload(db)
    adapter = SystemAdapter()
    config_path = settings.config_path
    if not adapter.dry_run:
        config_path = stage_api_firewall_config(config_preview)
    result = adapter.validate_firewall_config(config_path)
    return ConfigValidationResponse(
        valid=not errors,
        dry_run=result.dry_run,
        command=result.command,
        config_path=config_path,
        config_preview=config_preview,
        errors=errors,
    )


@router.post(
    "/firewall/apply",
    response_model=ConfigApplyResponse,
    tags=["Firewall"],
    operation_id="applyFirewall",
    include_in_schema=False,
)
def apply_firewall(identity: Annotated[Identity, Depends(require_scope("write:firewall"))], db: Session = Depends(get_db)) -> ConfigApplyResponse:
    """Apply Firewall.

    Requires the `write:firewall` API scope. The action runs through the endpoint's existing audited
    adapter or task boundary; inspect the returned state before treating the operation as complete.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    validation = validate_firewall(identity, db)
    apply_result = SystemAdapter().apply_firewall_config(validation.config_path)
    record_audit(db, actor=identity.username, action="apply_firewall_dry_run", resource_type="firewall", detail=" ".join(apply_result.command))
    payload = validation.model_dump()
    payload["command"] = apply_result.command
    return ConfigApplyResponse(**payload, reloaded=not apply_result.dry_run)


@router.get("/firewall/logs", response_model=list[str], tags=["Firewall"], operation_id="getFirewallLogs")
def get_firewall_logs(identity: Annotated[Identity, Depends(require_scope("read:firewall"))]) -> list[str]:
    """Get Firewall Logs.

    Requires the `read:firewall` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
    """
    return ["dry-run log source for nftables", "Host nftables logs are not read in development mode."]


@router.get("/services", response_model=list[ServiceStateResponse], tags=["Services"], operation_id="listServices")
def list_services(identity: Annotated[Identity, Depends(require_scope("read:services"))], db: Session = Depends(get_db)) -> list[ServiceStateResponse]:
    """List Services.

    Requires the `read:services` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = db.execute(select(ServiceState).where(ServiceState.service.in_(SERVICE_STATE_IDS)).order_by(ServiceState.display_name)).scalars().all()
    return [service_state_response(row, db) for row in rows]


@router.get("/services/{service}", response_model=ServiceStateResponse, tags=["Services"], operation_id="getService")
def get_service(service: Annotated[str, ApiPath(description='Path value for service, identifying the resource addressed by `/api/v1/services/{service}`.')], identity: Annotated[Identity, Depends(require_scope("read:services"))], db: Session = Depends(get_db)) -> ServiceStateResponse:
    """Get Service.

    Requires the `read:services` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        service: Atlaso or host service affected by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if service not in SERVICE_STATE_IDS:
        raise HTTPException(status_code=404, detail="Service not found")
    row = db.execute(select(ServiceState).where(ServiceState.service == service)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Service not found")
    return service_state_response(row, db)


def service_action(service: str, action: str, identity: Identity, db: Session) -> ServiceActionResponse:
    """Return service action.

    Args:
        service: Atlaso service affected by the operation.
        action: Operation to perform on the target resource.
        identity: Authenticated identity authorizing the request.
        db: Active database session.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if service not in APPROVED_SERVICES:
        raise HTTPException(status_code=404, detail="Service is not approved for control")
    if action not in {"start", "stop", "restart", "enable", "disable"}:
        raise HTTPException(status_code=422, detail="Unsupported service action")
    row = db.execute(select(ServiceState).where(ServiceState.service == service)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Service not found")
    if action == "enable":
        row.enabled = True
        if service == "dns":
            get_dns_settings_row(db).enabled = True
        elif service == "dhcp":
            get_dhcp_settings_row(db).enabled = True
    elif action == "disable":
        row.enabled = False
        if service == "dns":
            get_dns_settings_row(db).enabled = False
        elif service == "dhcp":
            get_dhcp_settings_row(db).enabled = False
    elif action in {"start", "restart"}:
        row.running = True
    elif action == "stop":
        row.running = False
    db.add(row)
    result = SystemAdapter().service_action(service, action)
    record_audit(db, actor=identity.username, action=f"{action}_service_dry_run", resource_type="service", resource_id=service, detail=" ".join(result.command))
    return ServiceActionResponse(service=service, action=action, dry_run=result.dry_run, command=result.command)


@router.post("/services/{service}/start", response_model=ServiceActionResponse, tags=["Services"], operation_id="startService")
def start_service(service: Annotated[str, ApiPath(description='Path value for service, identifying the resource addressed by `/api/v1/services/{service}/start`.')], identity: Annotated[Identity, Depends(require_scope("write:services"))], db: Session = Depends(get_db)) -> ServiceActionResponse:
    """Start Service.

    Requires the `write:services` API scope. The action runs through the endpoint's existing audited
    adapter or task boundary; inspect the returned state before treating the operation as complete.

    Args:
        service: Atlaso or host service affected by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return service_action(service, "start", identity, db)


@router.post("/services/{service}/stop", response_model=ServiceActionResponse, tags=["Services"], operation_id="stopService")
def stop_service(service: Annotated[str, ApiPath(description='Path value for service, identifying the resource addressed by `/api/v1/services/{service}/stop`.')], identity: Annotated[Identity, Depends(require_scope("write:services"))], db: Session = Depends(get_db)) -> ServiceActionResponse:
    """Stop Service.

    Requires the `write:services` API scope. The action runs through the endpoint's existing audited
    adapter or task boundary; inspect the returned state before treating the operation as complete.

    Args:
        service: Atlaso or host service affected by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return service_action(service, "stop", identity, db)


@router.post("/services/{service}/restart", response_model=ServiceActionResponse, tags=["Services"], operation_id="restartService")
def restart_service(service: Annotated[str, ApiPath(description='Path value for service, identifying the resource addressed by `/api/v1/services/{service}/restart`.')], identity: Annotated[Identity, Depends(require_scope("write:services"))], db: Session = Depends(get_db)) -> ServiceActionResponse:
    """Restart Service.

    Requires the `write:services` API scope. The action runs through the endpoint's existing audited
    adapter or task boundary; inspect the returned state before treating the operation as complete.

    Args:
        service: Atlaso or host service affected by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return service_action(service, "restart", identity, db)


@router.post("/services/{service}/enable", response_model=ServiceActionResponse, tags=["Services"], operation_id="enableService")
def enable_service(service: Annotated[str, ApiPath(description='Path value for service, identifying the resource addressed by `/api/v1/services/{service}/enable`.')], identity: Annotated[Identity, Depends(require_scope("write:services"))], db: Session = Depends(get_db)) -> ServiceActionResponse:
    """Enable Service.

    Requires the `write:services` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        service: Atlaso or host service affected by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return service_action(service, "enable", identity, db)


@router.post("/services/{service}/disable", response_model=ServiceActionResponse, tags=["Services"], operation_id="disableService")
def disable_service(service: Annotated[str, ApiPath(description='Path value for service, identifying the resource addressed by `/api/v1/services/{service}/disable`.')], identity: Annotated[Identity, Depends(require_scope("write:services"))], db: Session = Depends(get_db)) -> ServiceActionResponse:
    """Disable Service.

    Requires the `write:services` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        service: Atlaso or host service affected by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return service_action(service, "disable", identity, db)


@router.get("/services/{service}/logs", response_model=list[str], tags=["Services"], operation_id="getServiceLogs")
def get_service_logs(service: Annotated[str, ApiPath(description='Path value for service, identifying the resource addressed by `/api/v1/services/{service}/logs`.')], identity: Annotated[Identity, Depends(require_scope("read:logs"))]) -> list[str]:
    """Get Service Logs.

    Requires the `read:logs` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        service: Atlaso or host service affected by the operation.
        identity: Authenticated identity authorizing the operation.
    """
    if service not in APPROVED_SERVICES:
        raise HTTPException(status_code=404, detail="Log source is not approved")
    return [f"dry-run log source for {service}", "No host journal is read in development mode."]


@router.get("/logs", response_model=list[str], tags=["Logs"], operation_id="listLogs")
def list_logs(identity: Annotated[Identity, Depends(require_scope("read:logs"))]) -> list[str]:
    """List Logs.

    Requires the `read:logs` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
    """
    return ["system", "atlaso", "dnsmasq", "ldap", "ntp", "nginx", "openssh", "nftables"]


@router.get("/logs/{source}", response_model=list[str], tags=["Logs"], operation_id="getLogSource")
def get_log_source(source: Annotated[str, ApiPath(description='Path value for source, identifying the resource addressed by `/api/v1/logs/{source}`.')], identity: Annotated[Identity, Depends(require_scope("read:logs"))]) -> list[str]:
    """Get Log Source.

    Requires the `read:logs` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        source: Source object or location from which data is obtained.
        identity: Authenticated identity authorizing the operation.
    """
    if source not in {"system", "atlaso", "dnsmasq", "ldap", "ntp", "nginx", "openssh", "nftables"}:
        raise HTTPException(status_code=404, detail="Log source is not approved")
    return [f"dry-run log source for {source}", "Host log streaming is not enabled in the MVP scaffold."]


@router.get("/audit", response_model=list[AuditEventResponse], tags=["Audit"], operation_id="listAuditEvents")
def list_audit_events(
    identity: Annotated[Identity, Depends(require_scope("read:audit"))],
    db: Session = Depends(get_db),
    user: Annotated[str | None, Query(description='Optional query value controlling user for this response.')] = None,
    action: Annotated[str | None, Query(description='Optional query value controlling action for this response.')] = None,
    resource_type: Annotated[str | None, Query(description='Optional query value controlling resource type for this response.')] = None,
    success: Annotated[bool | None, Query(description='Optional query value controlling success for this response.')] = None,
    start_time: Annotated[datetime | None, Query(description='Optional query value controlling start time for this response.')] = None,
    end_time: Annotated[datetime | None, Query(description='Optional query value controlling end time for this response.')] = None,
) -> list[AuditEventResponse]:
    """List Audit Events.

    Requires the `read:audit` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        user: User record or identity affected by the operation.
        action: Action consumed by list audit events.
        resource_type: Resource type consumed by list audit events.
        success: Success consumed by list audit events.
        start_time: Start time consumed by list audit events.
        end_time: End time consumed by list audit events.
    """
    query = select(AuditEvent)
    if user:
        query = query.where(AuditEvent.actor == user)
    if action:
        query = query.where(AuditEvent.action == action)
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
    if success is not None:
        query = query.where(AuditEvent.success.is_(success))
    if start_time:
        query = query.where(AuditEvent.created_at >= start_time)
    if end_time:
        query = query.where(AuditEvent.created_at <= end_time)
    return [AuditEventResponse.model_validate(row) for row in db.execute(query.order_by(desc(AuditEvent.created_at)).limit(200)).scalars().all()]


@router.get("/jobs", response_model=list[JobResponse], tags=["Jobs"], operation_id="listJobs")
def list_jobs(identity: Annotated[Identity, Depends(require_scope("read:dashboard"))], db: Session = Depends(get_db)) -> list[JobResponse]:
    """List Jobs.

    Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [JobResponse.model_validate(row) for row in db.execute(select(Job).order_by(desc(Job.created_at))).scalars().all()]


@router.post("/jobs", response_model=JobResponse, status_code=202, tags=["Jobs"], operation_id="createJob")
def create_job(identity: Annotated[Identity, Depends(require_scope("admin:all"))], db: Session = Depends(get_db)) -> JobResponse:
    """Create Job.

    Requires the `admin:all` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    job = Job(id=f"job_{uuid4().hex[:12]}", type="manual-placeholder", created_by=identity.username)
    db.add(job)
    db.commit()
    db.refresh(job)
    record_audit(db, actor=identity.username, action="create_job", resource_type="job", resource_id=job.id)
    return JobResponse.model_validate(job)


@router.get("/jobs/{job_id}", response_model=JobResponse, tags=["Jobs"], operation_id="getJob")
def get_job(job_id: Annotated[str, ApiPath(description='Unique identifier of the job record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("read:dashboard"))], db: Session = Depends(get_db)) -> JobResponse:
    """Get Job.

    Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        job_id: Stable identifier of the associated job resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobResponse.model_validate(job)


@router.post("/jobs/{job_id}/cancel", response_model=JobResponse, tags=["Jobs"], operation_id="cancelJob")
def cancel_job(job_id: Annotated[str, ApiPath(description='Unique identifier of the job record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("admin:all"))], db: Session = Depends(get_db)) -> JobResponse:
    """Cancel Job.

    Requires the `admin:all` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        job_id: Stable identifier of the associated job resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.type == "pxe-media-sync" and job.status == JobStatus.RUNNING.value:
        try:
            config = json.loads(job.task_config_json or "{}")
        except json.JSONDecodeError:
            config = {}
        if config.get("source") == "delete":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A running Network Boot media deletion cannot be cancelled.",
            )
    if job.type == "pxe-media-sync" and job.status == "pending":
        try:
            config = json.loads(job.task_config_json or "{}")
        except json.JSONDecodeError:
            config = {}
        if config.get("source") == "upload":
            cleanup_network_boot_upload(job.id)
    job.status = "cancelled"
    job.finished_at = utcnow()
    db.commit()
    db.refresh(job)
    record_audit(db, actor=identity.username, action="cancel_job", resource_type="job", resource_id=job.id)
    return JobResponse.model_validate(job)


@router.get("/settings", response_model=SettingsResponse, tags=["Settings"], operation_id="getSettings")
def get_app_settings(
    identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SettingsResponse:
    """Get Settings.

    Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    return appliance_settings_response(db, settings)


@router.patch("/settings", response_model=SettingsResponse, tags=["Settings"], operation_id="updateSettings")
def update_app_settings(
    payload: SettingsUpdate,
    identity: Annotated[Identity, Depends(require_scope("admin:all"))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SettingsResponse:
    """Update Settings.

    Requires the `admin:all` API scope. The operation updates saved Atlaso state and does not bypass
    the documented global Appliance Apply or service lifecycle boundary.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    desired = get_appliance_settings(db)
    desired.fqdn = normalize_fqdn(payload.appliance_fqdn)
    desired.management_https_enabled = payload.management_https_enabled
    desired.web_terminal_enabled = payload.web_terminal_enabled
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    management = management_ui_context(interfaces, vlans)
    requested_terminal_interfaces = list(payload.web_terminal_interfaces)
    if desired.web_terminal_enabled and management.get("name"):
        requested_terminal_interfaces = [
            management["name"],
            *[name for name in requested_terminal_interfaces if name != management["name"]],
        ]
    desired.web_terminal_interfaces_json = web_terminal_interfaces_to_json(requested_terminal_interfaces)
    desired.root_ssh_enabled = payload.root_ssh_enabled
    desired.external_dns_servers = normalize_multiline_values("\n".join(payload.external_dns_servers))
    desired.config_path = APPLIANCE_SETTINGS_STAGED_CONFIG_PATH
    desired.updated_at = utcnow()
    db.add(desired)
    db.commit()
    db.refresh(desired)
    ca_settings = db.execute(select(CaSettings)).scalar_one_or_none()
    if desired.management_https_enabled and ca_settings and ca_settings.enabled:
        from atlaso.app import ui as ui_module

        ui_module.ensure_ca_state(db)
        db.refresh(desired)
    record_audit(db, actor=identity.username, action="update_appliance_settings", resource_type="settings", resource_id=str(desired.id))
    return appliance_settings_response(db, settings)


@router.get("/vcf-backups/status", response_model=VcfBackupStatusResponse, tags=["VCF Backups"], operation_id="getVcfBackupsStatus")
def get_vcf_backups_status(
    identity: Annotated[Identity, Depends(require_scope("read:vcf-backups"))],
    db: Session = Depends(get_db),
) -> VcfBackupStatusResponse:
    """Get Vcf Backups Status.

    Requires the `read:vcf-backups` API scope. This read-only operation does not change saved
    desired state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_vcf_backup_settings(db)
    row = db.execute(select(ServiceState).where(ServiceState.service == "vcf-backups")).scalar_one_or_none()
    payload = vcf_backup_settings_to_dict(settings)
    return VcfBackupStatusResponse(
        enabled=settings.enabled,
        service=ServiceStateResponse.model_validate(row) if row else None,
        listen_interface=payload["listen_interface"],
        listen_address=payload["listen_address"],
        port=payload["port"],
        sftp_username=payload["sftp_username"] or None,
        storage_path=payload["storage_path"],
        remote_directory=payload["remote_directory"],
        config_path=payload["config_path"],
        dry_run=get_settings().dry_run_system_adapters,
    )


def get_esx_storage_settings(db: Session) -> EsxStorageSettings:
    """Return esx storage settings.

    Args:
        db: Active database session.
    """
    row = db.execute(select(EsxStorageSettings).order_by(EsxStorageSettings.id)).scalars().first()
    if row is None:
        dns = db.execute(select(DnsSettings).order_by(DnsSettings.id)).scalars().first()
        domain = (dns.domain if dns else "atlaso.internal").splitlines()[0].strip().strip(".")
        row = EsxStorageSettings(enabled=False, hostname=f"nfs.{domain}")
        db.add(row)
        db.flush()
    return row


def esx_storage_interfaces(db: Session) -> dict[str, StorageInterface]:
    """Return esx storage interfaces.

    Args:
        db: Active database session.
    """
    interfaces: dict[str, StorageInterface] = {}
    for row in db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all():
        if row.oper_state == "missing" or row.mode == "trunk" or row.role not in {"access", "services", "storage", "route"}:
            continue
        interfaces[row.name] = StorageInterface(
            row.name,
            tuple(value for value in [row.ip_cidr] if value),
            tuple(value for value in [row.ipv6_cidr] if value and row.ipv6_enabled),
        )
    for row in db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all():
        if not row.enabled or row.role not in {"access", "services", "storage", "route"}:
            continue
        interfaces[row.name] = StorageInterface(
            row.name,
            tuple(value for value in [row.ip_cidr] if value),
            tuple(value for value in [row.ipv6_cidr] if value),
        )
    return interfaces


def esx_storage_state(db: Session) -> tuple[EsxStorageSettings, list[EsxStorageVolume], list[EsxNfsShare], dict[str, StorageInterface], dict[str, Any]]:
    """Return esx storage state.

    Args:
        db: Active database session.
    """
    settings = get_esx_storage_settings(db)
    volumes = db.execute(select(EsxStorageVolume).order_by(EsxStorageVolume.name)).scalars().all()
    shares = db.execute(select(EsxNfsShare).order_by(EsxNfsShare.datastore_name)).scalars().all()
    interfaces = esx_storage_interfaces(db)
    dns = db.execute(select(DnsSettings).order_by(DnsSettings.id)).scalars().first()
    appliance = get_appliance_settings(db)
    manifest = render_esx_storage_manifest(
        settings,
        volumes,
        shares,
        interfaces,
        dns_enabled=bool(dns and dns.enabled),
        dns_naming_mode=appliance.service_dns_target_naming or "ip",
    )
    return settings, volumes, shares, interfaces, manifest


def esx_share_response(share: EsxNfsShare, manifest: dict[str, Any]) -> EsxNfsShareResponse:
    """Return esx share response.

    Args:
        share: Share consumed by ESX share response.
        manifest: Manifest consumed by ESX share response.
    """
    rendered = next(item for item in manifest["shares"] if item["id"] == share.id)
    return EsxNfsShareResponse(
        id=share.id,
        datastore_name=share.datastore_name,
        volume_id=share.volume_id,
        volume_name=rendered["volume_name"],
        relative_path=share.relative_path,
        preferred_nfs_version=share.preferred_nfs_version,
        interface_name=share.interface_name,
        address_families=rendered["address_families"],
        ipv4_clients=rendered["clients"]["ipv4"],
        ipv6_clients=rendered["clients"]["ipv6"],
        listeners=rendered["listeners"],
        target_hostnames=rendered["target_hostnames"],
        local_path=rendered["source_path"],
        remote_path=rendered["remote_path"],
        connection_commands=rendered["connection_commands"],
        powercli_commands=rendered["powercli_commands"],
        enabled=share.enabled,
    )


def reconcile_esx_storage_dns(db: Session, actor: str, *, previous_hostname: str | None = None) -> None:
    """Handle reconcile esx storage dns.

    Args:
        db: Active database session.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.
    """
    from atlaso.app import ui as ui_module

    ui_module.ensure_dns_for_esx_storage(db, actor, previous_hostname=previous_hostname)


@router.get("/esx-storage/status", response_model=EsxStorageStatusResponse, tags=["ESX Storage"], operation_id="getEsxStorageStatus")
def get_esx_storage_status(
    identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
    db: Session = Depends(get_db),
) -> EsxStorageStatusResponse:
    """Get Esx Storage Status.

    Requires the `read:esx-storage` API scope. This read-only operation does not change saved
    desired state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings, volumes, shares, _interfaces, manifest = esx_storage_state(db)
    return EsxStorageStatusResponse(
        enabled=settings.enabled,
        hostname=settings.hostname,
        valid=not manifest["validation"]["errors"],
        validation_errors=manifest["validation"]["errors"],
        validation_warnings=manifest["validation"]["warnings"],
        volume_count=len(volumes),
        share_count=len(shares),
        active_share_count=len([row for row in shares if row.enabled]),
        dry_run=get_settings().dry_run_system_adapters,
    )


@router.patch("/esx-storage/status", response_model=EsxStorageStatusResponse, tags=["ESX Storage"], operation_id="updateEsxStorageSettings")
def update_esx_storage_settings(
    payload: EsxStorageSettingsUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
    db: Session = Depends(get_db),
) -> EsxStorageStatusResponse:
    """Update Esx Storage Settings.

    Requires the `write:esx-storage` API scope. The request is evaluated without persisting desired
    state or mutating appliance runtime state.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    row = get_esx_storage_settings(db)
    previous_hostname = row.hostname
    hostname = payload.hostname.strip().lower().rstrip(".")
    if "." not in hostname:
        raise HTTPException(status_code=422, detail="ESX Storage hostname must be a fully qualified DNS name.")
    row.enabled = payload.enabled
    row.hostname = hostname
    row.updated_at = utcnow()
    reconcile_esx_storage_dns(db, identity.username, previous_hostname=previous_hostname)
    db.commit()
    record_audit(db, actor=identity.username, action="update_esx_storage_settings", resource_type="esx_storage", resource_id=str(row.id))
    return get_esx_storage_status(identity, db)


@router.get("/esx-storage/disks", response_model=list[EsxStorageDiskResponse], tags=["ESX Storage"], operation_id="getEsxStorageDisks")
def get_esx_storage_disks(
    identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
    db: Session = Depends(get_db),
) -> list[EsxStorageDiskResponse]:
    """Get Esx Storage Disks.

    Requires the `read:esx-storage` API scope. This read-only operation does not change saved
    desired state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    result = SystemAdapter().esx_storage_inventory()
    if result.returncode:
        raise HTTPException(status_code=503, detail=result.stderr or "ESX Storage disk inventory failed.")
    claimed = set(db.execute(select(EsxStorageVolume.stable_device_id)).scalars().all())
    try:
        entries = parse_disk_inventory_output(result.stdout, claimed_ids=claimed)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="ESX Storage disk inventory returned invalid JSON.") from exc
    return [EsxStorageDiskResponse(**item) for item in entries]


@router.get("/esx-storage/volumes", response_model=list[EsxStorageVolumeResponse], tags=["ESX Storage"], operation_id="getEsxStorageVolumes")
def get_esx_storage_volumes(
    identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
    db: Session = Depends(get_db),
) -> list[EsxStorageVolumeResponse]:
    """Get Esx Storage Volumes.

    Requires the `read:esx-storage` API scope. This read-only operation does not change saved
    desired state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [EsxStorageVolumeResponse.model_validate(row) for row in db.execute(select(EsxStorageVolume).order_by(EsxStorageVolume.name)).scalars().all()]


@router.post("/esx-storage/volumes", response_model=EsxStorageVolumeResponse, status_code=201, tags=["ESX Storage"], operation_id="createEsxStorageVolume")
def create_esx_storage_volume(
    payload: EsxStorageVolumeCreate,
    identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
    db: Session = Depends(get_db),
) -> EsxStorageVolumeResponse:
    """Create Esx Storage Volume.

    Requires the `write:esx-storage` API scope. The operation changes saved Atlaso application
    state; any appliance host enforcement remains subject to the documented apply or task boundary
    for the resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    name = payload.name.strip()
    if payload.source_type == "blank_disk" and not payload.stable_device_id.startswith("/dev/disk/by-id/"):
        raise HTTPException(status_code=422, detail="Blank disks require a stable /dev/disk/by-id identity.")
    if payload.source_type == "mounted_ext4":
        try:
            validate_mounted_volume_path(payload.mount_path)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    candidate: dict[str, Any] = {}
    if not get_settings().dry_run_system_adapters:
        result = SystemAdapter(dry_run=False).esx_storage_inventory()
        if result.returncode:
            raise HTTPException(status_code=503, detail=result.stderr or "ESX Storage disk inventory failed.")
        try:
            inventory = parse_disk_inventory_output(
                result.stdout,
                claimed_ids=set(db.execute(select(EsxStorageVolume.stable_device_id)).scalars().all()),
            )
            candidate = select_inventory_candidate(
                inventory,
                source_type=payload.source_type,
                stable_device_id=payload.stable_device_id,
                mount_path=payload.mount_path,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    row = EsxStorageVolume(
        name=name,
        source_type=payload.source_type,
        stable_device_id=str(candidate.get("stable_device_id") or payload.stable_device_id).strip(),
        device_path=str(candidate.get("device_path") or ""),
        device_model=str(candidate.get("model") or ""),
        device_serial=str(candidate.get("serial") or ""),
        device_wwn=str(candidate.get("wwn") or ""),
        capacity_bytes=int(candidate.get("size_bytes") or 0),
        filesystem_uuid=str(candidate.get("filesystem_uuid") or ""),
        filesystem_label=str(candidate.get("filesystem_label") or ""),
        mount_path=str(candidate.get("mount_path") or payload.mount_path).strip() or f"{ESX_STORAGE_MOUNT_ROOT}/{storage_slug(name)}",
        state="pending_format" if payload.source_type == "blank_disk" else "mounted",
        applied=False,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="The volume name or stable disk identity is already claimed.") from exc
    db.refresh(row)
    reconcile_esx_storage_dns(db, identity.username)
    db.commit()
    record_audit(db, actor=identity.username, action="create_esx_storage_volume", resource_type="esx_storage_volume", resource_id=str(row.id), detail=f"name={row.name} source_type={row.source_type}")
    return EsxStorageVolumeResponse.model_validate(row)


@router.patch("/esx-storage/volumes/{volume_id}", response_model=EsxStorageVolumeResponse, tags=["ESX Storage"], operation_id="updateEsxStorageVolume")
def update_esx_storage_volume(
    volume_id: Annotated[int, ApiPath(description='Unique identifier of the volume record addressed by this operation.')],
    payload: EsxStorageVolumeUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
    db: Session = Depends(get_db),
) -> EsxStorageVolumeResponse:
    """Update Esx Storage Volume.

    Requires the `write:esx-storage` API scope. The operation updates saved Atlaso state and does
    not bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        volume_id: Stable identifier of the associated volume resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    row = db.get(EsxStorageVolume, volume_id)
    if row is None:
        raise HTTPException(status_code=404, detail="ESX Storage volume not found.")
    if any(value is not None for value in [payload.stable_device_id, payload.mount_path]):
        raise HTTPException(status_code=409, detail="Volume identity and mount path are immutable after the inventory-backed claim is created.")
    if payload.name is not None:
        row.name = payload.name.strip()
    if payload.stable_device_id is not None:
        if row.source_type == "blank_disk" and not payload.stable_device_id.startswith("/dev/disk/by-id/"):
            raise HTTPException(status_code=422, detail="Blank disks require a stable /dev/disk/by-id identity.")
        row.stable_device_id = payload.stable_device_id.strip()
    if payload.mount_path is not None:
        row.mount_path = payload.mount_path.strip()
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    reconcile_esx_storage_dns(db, identity.username)
    db.commit()
    record_audit(db, actor=identity.username, action="update_esx_storage_volume", resource_type="esx_storage_volume", resource_id=str(row.id))
    return EsxStorageVolumeResponse.model_validate(row)


@router.get("/esx-storage/shares", response_model=list[EsxNfsShareResponse], tags=["ESX Storage"], operation_id="getEsxNfsShares")
def get_esx_nfs_shares(
    identity: Annotated[Identity, Depends(require_scope("read:esx-storage"))],
    db: Session = Depends(get_db),
) -> list[EsxNfsShareResponse]:
    """Get Esx Nfs Shares.

    Requires the `read:esx-storage` API scope. This read-only operation does not change saved
    desired state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    _settings, _volumes, shares, _interfaces, manifest = esx_storage_state(db)
    return [esx_share_response(row, manifest) for row in shares]


def apply_esx_share_payload(row: EsxNfsShare, payload: EsxNfsShareCreate | EsxNfsShareUpdate) -> None:
    """Update esx share payload.

    Args:
        row: Persistent database row affected by the operation.
        payload: Validated request or task payload consumed by the operation.


    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    values = payload.model_dump(exclude_unset=True)
    if "relative_path" in values:
        values["relative_path"] = normalize_relative_path(values["relative_path"])
    if "address_families" in values:
        families = normalize_families(values["address_families"])
        if not families:
            raise HTTPException(status_code=422, detail="Enable IPv4, IPv6, or both.")
        values["address_families"] = "\n".join(families)
    if "ipv4_clients" in values:
        values["ipv4_clients"] = "\n".join(split_esx_storage_lines(values["ipv4_clients"]))
    if "ipv6_clients" in values:
        values["ipv6_clients"] = "\n".join(split_esx_storage_lines(values["ipv6_clients"]))
    for key, value in values.items():
        setattr(row, key, value)
    row.updated_at = utcnow()


@router.post("/esx-storage/shares", response_model=EsxNfsShareResponse, status_code=201, tags=["ESX Storage"], operation_id="createEsxNfsShare")
def create_esx_nfs_share(
    payload: EsxNfsShareCreate,
    identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
    db: Session = Depends(get_db),
) -> EsxNfsShareResponse:
    """Create Esx Nfs Share.

    Requires the `write:esx-storage` API scope. The operation changes saved Atlaso application
    state; any appliance host enforcement remains subject to the documented apply or task boundary
    for the resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if db.get(EsxStorageVolume, payload.volume_id) is None:
        raise HTTPException(status_code=422, detail="Selected ESX Storage volume does not exist.")
    row = EsxNfsShare(datastore_name=payload.datastore_name, volume_id=payload.volume_id)
    apply_esx_share_payload(row, payload)
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Datastore name already exists.") from exc
    db.refresh(row)
    reconcile_esx_storage_dns(db, identity.username)
    db.commit()
    record_audit(db, actor=identity.username, action="create_esx_nfs_share", resource_type="esx_nfs_share", resource_id=str(row.id), detail=f"datastore={row.datastore_name}")
    return esx_share_response(row, esx_storage_state(db)[4])


@router.patch("/esx-storage/shares/{share_id}", response_model=EsxNfsShareResponse, tags=["ESX Storage"], operation_id="updateEsxNfsShare")
def update_esx_nfs_share(
    share_id: Annotated[int, ApiPath(description='Unique identifier of the share record addressed by this operation.')],
    payload: EsxNfsShareUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
    db: Session = Depends(get_db),
) -> EsxNfsShareResponse:
    """Update Esx Nfs Share.

    Requires the `write:esx-storage` API scope. The operation updates saved Atlaso state and does
    not bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        share_id: Stable identifier of the associated share resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    row = db.get(EsxNfsShare, share_id)
    if row is None:
        raise HTTPException(status_code=404, detail="NFS datastore share not found.")
    if payload.volume_id is not None and db.get(EsxStorageVolume, payload.volume_id) is None:
        raise HTTPException(status_code=422, detail="Selected ESX Storage volume does not exist.")
    apply_esx_share_payload(row, payload)
    reconcile_esx_storage_dns(db, identity.username)
    db.commit()
    db.refresh(row)
    record_audit(db, actor=identity.username, action="update_esx_nfs_share", resource_type="esx_nfs_share", resource_id=str(row.id), detail=f"datastore={row.datastore_name}")
    return esx_share_response(row, esx_storage_state(db)[4])


@router.delete("/esx-storage/shares/{share_id}", status_code=204, tags=["ESX Storage"], operation_id="deleteEsxNfsShare")
def delete_esx_nfs_share(
    share_id: Annotated[int, ApiPath(description='Unique identifier of the share record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:esx-storage"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Esx Nfs Share.

    Requires the `write:esx-storage` API scope. Removal or revocation takes effect in Atlaso
    application state; appliance host changes remain subject to the documented apply boundary for
    the resource.

    Args:
        share_id: Stable identifier of the associated share resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    row = db.get(EsxNfsShare, share_id)
    if row is None:
        raise HTTPException(status_code=404, detail="NFS datastore share not found.")
    name = row.datastore_name
    db.delete(row)
    db.flush()
    reconcile_esx_storage_dns(db, identity.username)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_esx_nfs_share", resource_type="esx_nfs_share", resource_id=str(share_id), detail=f"datastore={name}; data preserved")
    return Response(status_code=204)


def build_vcf_offline_depot_status(db: Session) -> VcfOfflineDepotStatusResponse:
    """Build vcf offline depot status.

    Args:
        db: Active database session.

    Returns:
        The built vcf offline depot status.
    """
    settings = get_vcf_offline_depot_settings(db)
    profiles = db.execute(select(VcfDepotDownloadProfile).order_by(VcfDepotDownloadProfile.name)).scalars().all()
    row = db.execute(select(ServiceState).where(ServiceState.service == "repository")).scalar_one_or_none()
    download_token_present, activation_code_present = vcf_depot_secret_status(db)
    application_properties = setting_value(db, VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY)
    management_interface_names = {
        interface.name
        for interface in db.execute(select(PhysicalInterface).where(PhysicalInterface.role == "management")).scalars().all()
    }
    management_interface_names.update(
        vlan.name for vlan in db.execute(select(VlanInterface).where(VlanInterface.role == "management")).scalars().all()
    )
    validation_errors, _warnings = validate_vcf_depot_state(
        settings,
        profiles,
        download_token_present=download_token_present,
        activation_code_present=activation_code_present,
        management_interface_names=management_interface_names,
        users=db.execute(select(User).order_by(User.username)).scalars().all(),
    )
    payload = vcf_depot_settings_to_dict(settings)
    return VcfOfflineDepotStatusResponse(
        enabled=settings.enabled,
        service=ServiceStateResponse.model_validate(row) if row else None,
        hostname=str(payload["hostname"]),
        endpoint=str(payload["endpoint"]),
        listen_interface=str(payload["listen_interface"]),
        listen_address=str(payload["listen_address"]),
        port=int(payload["port"]),
        http_username=str(payload["http_username"]),
        allow_unauthenticated_access=bool(payload["allow_unauthenticated_access"]),
        depot_store_path=str(payload["depot_store_path"]),
        tool_archive_name=str(payload["tool_archive_name"]),
        tool_version=str(payload["tool_version"]),
        software_depot_id=setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY),
        software_depot_id_generated_at=setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY),
        software_depot_id_error=setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY),
        download_token_present=download_token_present,
        activation_code_present=activation_code_present,
        application_properties_present=bool(application_properties.strip()),
        application_properties_source=setting_value(db, VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY),
        application_properties_updated_at=setting_value(db, VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY),
        profile_count=len([profile for profile in profiles if profile.enabled]),
        config_path=str(payload["config_path"]),
        valid=not validation_errors,
        dry_run=get_settings().dry_run_system_adapters,
    )


@router.get(
    "/vcf-offline-depot/status",
    response_model=VcfOfflineDepotStatusResponse,
    tags=["VCF Offline Depot"],
    operation_id="getVcfOfflineDepotStatus",
)
def get_vcf_offline_depot_status(
    identity: Annotated[Identity, Depends(require_scope("read:repository"))],
    db: Session = Depends(get_db),
) -> VcfOfflineDepotStatusResponse:
    """Get Vcf Offline Depot Status.

    Requires the `read:repository` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return build_vcf_offline_depot_status(db)


@router.get(
    "/repository/status",
    response_model=VcfOfflineDepotStatusResponse,
    tags=["VCF Offline Depot"],
    operation_id="getRepositoryStatus",
)
def get_repository_status_alias(
    identity: Annotated[Identity, Depends(require_scope("read:repository"))],
    db: Session = Depends(get_db),
) -> VcfOfflineDepotStatusResponse:
    """Get Repository Status.

    Requires the `read:repository` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return build_vcf_offline_depot_status(db)


@router.get(
    "/vcf-private-registry/status",
    response_model=VcfPrivateRegistryStatusResponse,
    tags=["VCF Private Registry"],
    operation_id="getVcfPrivateRegistryStatus",
)
def get_vcf_private_registry_status(
    identity: Annotated[Identity, Depends(require_scope("read:vcf-registry"))],
    db: Session = Depends(get_db),
) -> VcfPrivateRegistryStatusResponse:
    """Get Vcf Private Registry Status.

    Requires the `read:vcf-registry` API scope. This read-only operation does not change saved
    desired state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_vcf_private_registry_settings(db)
    bundles = db.execute(select(VcfRegistryBundle).order_by(VcfRegistryBundle.name)).scalars().all()
    row = db.execute(select(ServiceState).where(ServiceState.service == "vcf-private-registry")).scalar_one_or_none()
    ca_bundle_source, ca_bundle_available = vcf_registry_ca_bundle_status(db)
    validation_errors, _warnings = validate_vcf_registry_state(
        settings,
        bundles,
        ca_bundle_source=ca_bundle_source,
        ca_bundle_available=ca_bundle_available,
    )
    payload = vcf_registry_settings_to_dict(settings)
    return VcfPrivateRegistryStatusResponse(
        enabled=settings.enabled,
        service=ServiceStateResponse.model_validate(row) if row else None,
        hostname=str(payload["hostname"]),
        endpoint=str(payload["endpoint"]),
        listen_interface=str(payload["listen_interface"]),
        listen_address=str(payload["listen_address"]),
        port=int(payload["port"]),
        harbor_project=str(payload["harbor_project"]),
        storage_path=str(payload["storage_path"]),
        config_path=str(payload["config_path"]),
        bundle_count=len([bundle for bundle in bundles if bundle.enabled]),
        valid=not validation_errors,
        dry_run=get_settings().dry_run_system_adapters,
    )


def _kickstart_response(kickstart: EsxiKickstart, identity: Identity) -> EsxiKickstartResponse:
    """Return kickstart response.

    Args:
        kickstart: Kickstart supplied by the caller.
        identity: Authenticated identity authorizing the request.
    """
    include_content = identity.can("write:esxi-pxe")
    return EsxiKickstartResponse(**kickstart_to_dict(kickstart, include_content=include_content))


def _assign_kickstart_payload(kickstart: EsxiKickstart, payload: EsxiKickstartCreate | EsxiKickstartUpdate, max_bytes: int) -> None:
    """Handle assign kickstart payload.

    Args:
        kickstart: Kickstart supplied by the caller.
        payload: Validated request or operation payload.
        max_bytes: Maximum accepted payload size in bytes.
    """
    kickstart.name = normalize_kickstart_name(payload.name)
    kickstart.description = payload.description or None
    kickstart.enabled = payload.enabled
    assign_kickstart_content(kickstart, payload.content, max_bytes=max_bytes)


@router.get(
    "/esxi-pxe/custom-variables",
    response_model=list[EsxiCustomVariableResponse],
    tags=["ESXi PXE"],
    operation_id="listEsxiCustomVariables",
)
def list_esxi_custom_variables(
    identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> list[EsxiCustomVariableResponse]:
    """List Esxi Custom Variables.

    Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [EsxiCustomVariableResponse(**row) for row in custom_variable_definitions(db)]


@router.post(
    "/esxi-pxe/custom-variables",
    response_model=EsxiCustomVariableResponse,
    status_code=201,
    tags=["ESXi PXE"],
    operation_id="createEsxiCustomVariable",
)
def create_esxi_custom_variable(
    payload: EsxiCustomVariableCreate,
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> EsxiCustomVariableResponse:
    """Create Esxi Custom Variable.

    Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    try:
        variable = save_custom_variable_definition(
            db,
            name=payload.name,
            description=payload.description,
            default_value=payload.default_value,
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        status_code = 409 if "already exists" in str(exc).lower() else 422
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="create_esxi_custom_variable",
        resource_type="esxi_custom_variable",
        resource_id=variable["name"],
        detail=f"name={variable['name']}",
    )
    return EsxiCustomVariableResponse(**variable)


@router.put(
    "/esxi-pxe/custom-variables/{variable_name}",
    response_model=EsxiCustomVariableResponse,
    tags=["ESXi PXE"],
    operation_id="updateEsxiCustomVariable",
)
def update_esxi_custom_variable(
    variable_name: Annotated[str, ApiPath(description='Stable variable name identifying the resource addressed by this operation.')],
    payload: EsxiCustomVariableUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> EsxiCustomVariableResponse:
    """Update Esxi Custom Variable.

    Requires the `write:esxi-pxe` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        variable_name: Filesystem path associated with variable name.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if variable_name not in {row["name"] for row in custom_variable_definitions(db)}:
        raise HTTPException(status_code=404, detail="Custom variable not found")
    try:
        variable = save_custom_variable_definition(
            db,
            name=payload.name,
            description=payload.description,
            default_value=payload.default_value,
            original_name=variable_name,
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        status_code = 409 if "already exists" in str(exc).lower() else 422
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="update_esxi_custom_variable",
        resource_type="esxi_custom_variable",
        resource_id=variable["name"],
        detail=f"previous_name={variable_name} name={variable['name']}",
    )
    return EsxiCustomVariableResponse(**variable)


@router.delete(
    "/esxi-pxe/custom-variables/{variable_name}",
    response_model=dict,
    tags=["ESXi PXE"],
    operation_id="deleteEsxiCustomVariable",
)
def delete_esxi_custom_variable(
    variable_name: Annotated[str, ApiPath(description='Stable variable name identifying the resource addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> dict:
    """Delete Esxi Custom Variable.

    Requires the `write:esxi-pxe` API scope. Removal or revocation takes effect in Atlaso
    application state; appliance host changes remain subject to the documented apply boundary for
    the resource.

    Args:
        variable_name: Filesystem path associated with variable name.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if not delete_custom_variable_definition(db, variable_name):
        raise HTTPException(status_code=404, detail="Custom variable not found")
    db.commit()
    record_audit(
        db,
        actor=identity.username,
        action="delete_esxi_custom_variable",
        resource_type="esxi_custom_variable",
        resource_id=variable_name,
    )
    return {"deleted": True}


@router.get(
    "/esxi-pxe/kickstarts",
    response_model=list[EsxiKickstartResponse],
    tags=["ESXi PXE"],
    operation_id="listEsxiKickstarts",
)
def list_esxi_kickstarts(
    identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> list[EsxiKickstartResponse]:
    """List Esxi Kickstarts.

    Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = db.execute(select(EsxiKickstart).order_by(EsxiKickstart.name)).scalars().all()
    return [_kickstart_response(row, identity) for row in rows]


@router.post(
    "/esxi-pxe/kickstarts",
    response_model=EsxiKickstartResponse,
    status_code=201,
    tags=["ESXi PXE"],
    operation_id="createEsxiKickstart",
)
def create_esxi_kickstart(
    payload: EsxiKickstartCreate,
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EsxiKickstartResponse:
    """Create Esxi Kickstart.

    Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    kickstart = EsxiKickstart(name=normalize_kickstart_name(payload.name), content="", content_hash="", enabled=payload.enabled)
    db.add(kickstart)
    db.flush()
    _assign_kickstart_payload(kickstart, payload, settings.esxi_kickstart_max_bytes)
    try:
        validate_kickstart_custom_references(db, kickstart.content)
        validate_kickstart_vault_references(db, kickstart.content)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Kickstart {payload.name} already exists.") from exc
    db.refresh(kickstart)
    record_audit(db, actor=identity.username, action="create_esxi_kickstart", resource_type="esxi_kickstart", resource_id=str(kickstart.id), detail=f"name={kickstart.name} hash={kickstart.content_hash}")
    return _kickstart_response(kickstart, identity)


@router.get(
    "/esxi-pxe/kickstarts/{kickstart_id}",
    response_model=EsxiKickstartResponse,
    tags=["ESXi PXE"],
    operation_id="getEsxiKickstart",
)
def get_esxi_kickstart(
    kickstart_id: Annotated[int, ApiPath(description='Unique identifier of the kickstart record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> EsxiKickstartResponse:
    """Get Esxi Kickstart.

    Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        kickstart_id: Stable identifier of the associated kickstart resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    kickstart = db.get(EsxiKickstart, kickstart_id)
    if not kickstart:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    return _kickstart_response(kickstart, identity)


@router.put(
    "/esxi-pxe/kickstarts/{kickstart_id}",
    response_model=EsxiKickstartResponse,
    tags=["ESXi PXE"],
    operation_id="updateEsxiKickstart",
)
def update_esxi_kickstart(
    kickstart_id: Annotated[int, ApiPath(description='Unique identifier of the kickstart record addressed by this operation.')],
    payload: EsxiKickstartUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EsxiKickstartResponse:
    """Update Esxi Kickstart.

    Requires the `write:esxi-pxe` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        kickstart_id: Stable identifier of the associated kickstart resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    kickstart = db.get(EsxiKickstart, kickstart_id)
    if not kickstart:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    _assign_kickstart_payload(kickstart, payload, settings.esxi_kickstart_max_bytes)
    db.add(kickstart)
    try:
        validate_kickstart_custom_references(db, kickstart.content)
        validate_kickstart_vault_references(db, kickstart.content)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Kickstart {payload.name} already exists.") from exc
    db.refresh(kickstart)
    record_audit(db, actor=identity.username, action="update_esxi_kickstart", resource_type="esxi_kickstart", resource_id=str(kickstart.id), detail=f"name={kickstart.name} hash={kickstart.content_hash}")
    return _kickstart_response(kickstart, identity)


@router.delete(
    "/esxi-pxe/kickstarts/{kickstart_id}",
    response_model=dict,
    tags=["ESXi PXE"],
    operation_id="deleteEsxiKickstart",
)
def delete_esxi_kickstart(
    kickstart_id: Annotated[int, ApiPath(description='Unique identifier of the kickstart record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> dict:
    """Delete Esxi Kickstart.

    Requires the `write:esxi-pxe` API scope. Removal or revocation takes effect in Atlaso
    application state; appliance host changes remain subject to the documented apply boundary for
    the resource.

    Args:
        kickstart_id: Stable identifier of the associated kickstart resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    kickstart = db.get(EsxiKickstart, kickstart_id)
    if not kickstart:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    for host in db.execute(select(EsxiPxeHost).where(EsxiPxeHost.kickstart_id == kickstart.id)).scalars().all():
        host.kickstart_id = None
        host.updated_at = utcnow()
        db.add(host)
    db.delete(kickstart)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_esxi_kickstart", resource_type="esxi_kickstart", resource_id=str(kickstart_id))
    return {"deleted": True}


@router.post(
    "/esxi-pxe/kickstarts/{kickstart_id}/duplicate",
    response_model=EsxiKickstartResponse,
    status_code=201,
    tags=["ESXi PXE"],
    operation_id="duplicateEsxiKickstart",
)
def duplicate_esxi_kickstart(
    kickstart_id: Annotated[int, ApiPath(description='Unique identifier of the kickstart record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    payload: EsxiKickstartDuplicateRequest | None = None,
    db: Session = Depends(get_db),
) -> EsxiKickstartResponse:
    """Duplicate Esxi Kickstart.

    Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        kickstart_id: Stable identifier of the associated kickstart resource.
        identity: Authenticated identity authorizing the operation.
        payload: Validated request or task payload consumed by the operation.
        db: Active database session used by the operation.
    """
    source = db.get(EsxiKickstart, kickstart_id)
    if not source:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    name = normalize_kickstart_name(payload.name if payload and payload.name else f"{source.name} Copy")
    duplicate = EsxiKickstart(
        name=name,
        description=source.description,
        content=source.content,
        content_hash=source.content_hash,
        rendered_content=source.rendered_content,
        enabled=source.enabled,
    )
    db.add(duplicate)
    db.flush()
    duplicate.http_path = canonical_http_path(duplicate.id, duplicate.content_hash)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Kickstart {name} already exists.") from exc
    db.refresh(duplicate)
    record_audit(db, actor=identity.username, action="duplicate_esxi_kickstart", resource_type="esxi_kickstart", resource_id=str(duplicate.id), detail=f"source_id={source.id} name={duplicate.name}")
    return _kickstart_response(duplicate, identity)


@router.post(
    "/esxi-pxe/kickstarts/{kickstart_id}/validate",
    response_model=EsxiKickstartValidationResponse,
    tags=["ESXi PXE"],
    operation_id="validateEsxiKickstart",
)
def validate_esxi_kickstart(
    kickstart_id: Annotated[int, ApiPath(description='Unique identifier of the kickstart record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EsxiKickstartValidationResponse:
    """Validate Esxi Kickstart.

    Requires the `read:esxi-pxe` API scope. The request is evaluated without persisting desired
    state or mutating appliance runtime state.

    Args:
        kickstart_id: Stable identifier of the associated kickstart resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    kickstart = db.get(EsxiKickstart, kickstart_id)
    if not kickstart:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    errors, warnings = kickstart_validation(
        kickstart.content,
        strict=strict_validation_enabled(db),
        max_bytes=settings.esxi_kickstart_max_bytes,
    )
    try:
        validate_kickstart_custom_references(db, kickstart.content)
        validate_kickstart_vault_references(db, kickstart.content)
    except ValueError as exc:
        errors.append(str(exc))
    record_audit(db, actor=identity.username, action="validate_esxi_kickstart", resource_type="esxi_kickstart", resource_id=str(kickstart.id), detail=f"errors={len(errors)} warnings={len(warnings)}")
    return EsxiKickstartValidationResponse(valid=not errors, errors=errors, warnings=warnings, redacted_preview=redacted_kickstart_preview(kickstart.content))


@router.get(
    "/esxi-pxe/kickstarts/{kickstart_id}/preview",
    response_model=EsxiKickstartPreviewResponse,
    tags=["ESXi PXE"],
    operation_id="previewEsxiKickstart",
)
def preview_esxi_kickstart(
    kickstart_id: Annotated[int, ApiPath(description='Unique identifier of the kickstart record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> EsxiKickstartPreviewResponse:
    """Preview Esxi Kickstart.

    Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        kickstart_id: Stable identifier of the associated kickstart resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    kickstart = db.get(EsxiKickstart, kickstart_id)
    if not kickstart:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    payload = kickstart_to_dict(kickstart)
    return EsxiKickstartPreviewResponse(id=kickstart.id, redacted_preview=payload["redacted_preview"], content_hash=kickstart.content_hash, drift_state=payload["drift_state"])


@router.get(
    "/esxi-pxe/kickstarts/{kickstart_id}/download",
    response_model=None,
    tags=["ESXi PXE"],
    operation_id="downloadEsxiKickstart",
)
def download_esxi_kickstart(
    kickstart_id: Annotated[int, ApiPath(description='Unique identifier of the kickstart record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> Response:
    """Download Esxi Kickstart.

    Requires the `write:esxi-pxe` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        kickstart_id: Stable identifier of the associated kickstart resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    kickstart = db.get(EsxiKickstart, kickstart_id)
    if not kickstart:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    filename = re.sub(r"[^A-Za-z0-9_.-]+", "-", kickstart.name).strip("-") or f"kickstart-{kickstart.id}"
    return Response(
        kickstart.content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}.cfg"'},
    )


@router.post(
    "/esxi-pxe/kickstarts/upload",
    response_model=EsxiKickstartResponse,
    status_code=201,
    tags=["ESXi PXE"],
    operation_id="uploadEsxiKickstart",
)
async def upload_esxi_kickstart(
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    upload_file: UploadFile = File(..., description='Request value supplying upload file for this operation.'),
    name: str = Form("", description='Stable name identifying the resource addressed by this operation.'),
    description: str = Form("", description='Request value supplying description for this operation.'),
    enabled: bool = Form(True, description='Request value supplying enabled for this operation.'),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EsxiKickstartResponse:
    """Upload Esxi Kickstart.

    Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        identity: Authenticated identity authorizing the operation.
        upload_file: Upload file consumed by upload ESXi kickstart.
        name: Stable name identifying the resource or operation.
        description: Operator-facing purpose or context for the resource.
        enabled: Whether the associated resource or behavior is enabled.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    raw = await upload_file.read()
    content = decode_kickstart_upload(raw, max_bytes=settings.esxi_kickstart_max_bytes)
    candidate_name = name or Path(upload_file.filename or "uploaded-kickstart").stem
    kickstart = EsxiKickstart(name=normalize_kickstart_name(candidate_name), description=description or None, content=content, content_hash=content_hash(content), rendered_content=content, enabled=enabled)
    db.add(kickstart)
    db.flush()
    kickstart.http_path = canonical_http_path(kickstart.id, kickstart.content_hash)
    try:
        validate_kickstart_custom_references(db, kickstart.content)
        validate_kickstart_vault_references(db, kickstart.content)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Kickstart {candidate_name} already exists.") from exc
    db.refresh(kickstart)
    record_audit(db, actor=identity.username, action="upload_esxi_kickstart", resource_type="esxi_kickstart", resource_id=str(kickstart.id), detail=f"name={kickstart.name} hash={kickstart.content_hash}")
    return _kickstart_response(kickstart, identity)


@router.get(
    "/esxi-pxe/isos",
    response_model=list[EsxiInstallerIsoResponse],
    tags=["ESXi PXE"],
    operation_id="listEsxiInstallerIsos",
)
def list_esxi_installer_isos(
    identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
) -> list[EsxiInstallerIsoResponse]:
    """List Esxi Installer Isos.

    Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
    """
    return [EsxiInstallerIsoResponse(**row) for row in installer_iso_inventory()]


@router.post(
    "/esxi-pxe/isos/upload",
    response_model=EsxiInstallerIsoResponse,
    status_code=201,
    tags=["ESXi PXE"],
    operation_id="uploadEsxiInstallerIso",
)
async def upload_esxi_installer_iso(
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    upload_file: UploadFile = File(..., description='Request value supplying upload file for this operation.'),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EsxiInstallerIsoResponse:
    """Upload Esxi Installer Iso.

    Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        identity: Authenticated identity authorizing the operation.
        upload_file: Upload file consumed by upload ESXi installer ISO.
        db: Active database session used by the operation.
        settings: Current Atlaso settings used to configure the operation.
    """
    try:
        iso = await store_installer_iso_upload(upload_file, max_bytes=settings.esxi_installer_iso_max_bytes)
    except ValueError as exc:
        status_code = 413 if "too large" in str(exc).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    record_audit(db, actor=identity.username, action="upload_esxi_installer_iso", resource_type="esxi_installer_iso", resource_id=iso["relative_path"], detail=f"path={iso['path']} size={iso['size_bytes']}")
    return EsxiInstallerIsoResponse(**iso)


@router.get(
    "/esxi-pxe/hosts",
    response_model=list[EsxiPxeHostResponse],
    tags=["ESXi PXE"],
    operation_id="listEsxiPxeHosts",
)
def list_esxi_pxe_hosts(
    identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> list[EsxiPxeHostResponse]:
    """List Esxi Pxe Hosts.

    Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
    state or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = db.execute(select(EsxiPxeHost).options(selectinload(EsxiPxeHost.kickstart)).order_by(EsxiPxeHost.hostname)).scalars().all()
    return [EsxiPxeHostResponse(**host_to_dict(row)) for row in rows]


@router.post(
    "/esxi-pxe/hosts",
    response_model=EsxiPxeHostResponse,
    status_code=201,
    tags=["ESXi PXE"],
    operation_id="createEsxiPxeHost",
)
def create_esxi_pxe_host(
    payload: EsxiPxeHostCreate,
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> EsxiPxeHostResponse:
    """Create Esxi Pxe Host.

    Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
    any appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    if payload.kickstart_id and not db.get(EsxiKickstart, payload.kickstart_id):
        raise HTTPException(status_code=404, detail="Kickstart not found")
    try:
        normalized_mac = normalize_host_mac(payload.mac_address)
        if not normalized_mac:
            raise ValueError("ESXi PXE host MAC address is invalid.")
        installer_iso_path = normalize_installer_iso_path(payload.installer_iso_path)
        variables_json = host_variables_json(payload.variables)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    host = EsxiPxeHost(
        hostname=payload.hostname.strip(),
        mac_address=normalized_mac,
        ip_address=payload.ip_address.strip(),
        kickstart_id=payload.kickstart_id,
        installer_iso_path=installer_iso_path,
        variables_json=variables_json,
        enabled=payload.enabled,
    )
    db.add(host)
    try:
        db.flush()
        sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409 if "already exists" in str(exc) else 400, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"ESXi PXE host for {payload.mac_address} already exists.") from exc
    db.refresh(host)
    record_audit(db, actor=identity.username, action="update_esxi_pxe_host", resource_type="esxi_pxe_host", resource_id=str(host.id), detail=f"kickstart_id={host.kickstart_id} installer_iso={host.installer_iso_path}")
    return EsxiPxeHostResponse(**host_to_dict(host))


@router.put(
    "/esxi-pxe/hosts/{host_id}",
    response_model=EsxiPxeHostResponse,
    tags=["ESXi PXE"],
    operation_id="updateEsxiPxeHost",
)
def update_esxi_pxe_host(
    host_id: Annotated[int, ApiPath(description='Unique identifier of the host record addressed by this operation.')],
    payload: EsxiPxeHostCreate,
    identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
    db: Session = Depends(get_db),
) -> EsxiPxeHostResponse:
    """Update Esxi Pxe Host.

    Requires the `write:esxi-pxe` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        host_id: Stable identifier of the associated host resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    host = db.get(EsxiPxeHost, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="ESXi PXE host not found")
    if payload.kickstart_id and not db.get(EsxiKickstart, payload.kickstart_id):
        raise HTTPException(status_code=404, detail="Kickstart not found")
    try:
        normalized_mac = normalize_host_mac(payload.mac_address)
        if not normalized_mac:
            raise ValueError("ESXi PXE host MAC address is invalid.")
        installer_iso_path = normalize_installer_iso_path(payload.installer_iso_path)
        variables_json = host_variables_json(payload.variables)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    host.hostname = payload.hostname.strip()
    host.mac_address = normalized_mac
    host.ip_address = payload.ip_address.strip()
    host.kickstart_id = payload.kickstart_id
    host.installer_iso_path = installer_iso_path
    host.variables_json = variables_json
    host.enabled = payload.enabled
    host.updated_at = utcnow()
    db.add(host)
    try:
        db.flush()
        sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409 if "already exists" in str(exc) else 400, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"ESXi PXE host for {payload.mac_address} already exists.") from exc
    db.refresh(host)
    record_audit(db, actor=identity.username, action="update_esxi_pxe_host", resource_type="esxi_pxe_host", resource_id=str(host.id), detail=f"kickstart_id={host.kickstart_id} installer_iso={host.installer_iso_path}")
    return EsxiPxeHostResponse(**host_to_dict(host))


def _ldap_settings_row(db: Session) -> LdapSettings:
    """Return ldap settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(LdapSettings)).scalar_one_or_none()
    if settings is None:
        settings = LdapSettings(config_path=LDAP_STAGED_CONFIG_PATH)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def _ldap_organizations(db: Session) -> list[LdapOrganization]:
    """Return ldap organizations.

    Args:
        db: Active database session.
    """
    return (
        db.execute(
            select(LdapOrganization)
            .options(
                selectinload(LdapOrganization.users),
                selectinload(LdapOrganization.groups).selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_user),
                selectinload(LdapOrganization.groups).selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_group),
            )
            .order_by(LdapOrganization.name)
        )
        .scalars()
        .all()
    )


def _ldap_api_interface_addresses(db: Session) -> dict[str, list[str]]:
    """Return ldap api interface addresses.

    Args:
        db: Active database session.
    """
    result: dict[str, list[str]] = {}
    physical_rows = db.execute(select(PhysicalInterface)).scalars().all()
    physical_by_name = {row.name: row for row in physical_rows}
    for row in physical_rows:
        if (
            row.oper_state == "missing"
            or row.admin_state == "down"
            or normalize_interface_role(row.role) in {"management", "unused"}
            or normalize_interface_mode(row.mode) == "trunk"
        ):
            continue
        addresses: list[str] = []
        ipv4_cidr = row.host_ip_cidr if row.ipv4_method == "dhcp" else row.ip_cidr
        ipv6_cidr = row.ipv6_cidr or row.host_ipv6_cidr
        for cidr in (ipv4_cidr, ipv6_cidr):
            if not cidr:
                continue
            try:
                addresses.append(str(ip_interface(cidr).ip))
            except ValueError:
                continue
        if addresses:
            result[row.name] = addresses
    for row in db.execute(select(VlanInterface)).scalars().all():
        parent = physical_by_name.get(row.parent_interface)
        if (
            not row.enabled
            or normalize_interface_role(row.role) in {"management", "unused"}
            or (parent and (parent.oper_state == "missing" or parent.admin_state == "down"))
        ):
            continue
        addresses = []
        for cidr in (row.ip_cidr, row.ipv6_cidr):
            if not cidr:
                continue
            try:
                addresses.append(str(ip_interface(cidr).ip))
            except ValueError:
                continue
        if addresses:
            result[row.name] = addresses
    return result


def _ldap_settings_response(db: Session) -> LdapSettingsResponse:
    """Return ldap settings response.

    Args:
        db: Active database session.
    """
    settings = _ldap_settings_row(db)
    organizations = _ldap_organizations(db)
    ca = db.execute(select(CaSettings)).scalar_one_or_none()
    available_interfaces = set(_ldap_api_interface_addresses(db))
    errors, warnings = validate_ldap_state(
        settings,
        organizations,
        available_interfaces=available_interfaces,
        ca_ready=bool(ca and ca.enabled and ca.root_certificate_pem),
    )
    data = ldap_settings_to_dict(settings)
    policy = data["password_policy"]
    return LdapSettingsResponse(
        id=settings.id,
        enabled=settings.enabled,
        hostname=settings.hostname,
        listen_interfaces=split_interfaces(settings.listen_interface),
        listen_addresses=split_addresses(settings.listen_address),
        ldaps_enabled=settings.ldaps_enabled,
        port=settings.port,
        ldap_enabled=settings.ldap_enabled,
        ldap_port=settings.ldap_port,
        password_policy=policy,
        config_path=settings.config_path,
        certificate_path=data["certificate_path"],
        key_path=data["key_path"],
        chain_path=data["chain_path"],
        root_ca_path=data["root_ca_path"],
        valid=not errors,
        validation_errors=errors,
        validation_warnings=warnings,
        updated_at=settings.updated_at,
    )


@router.get("/ldap/settings", response_model=LdapSettingsResponse, tags=["LDAP"], operation_id="getLdapSettings")
def get_ldap_settings(
    identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
    db: Session = Depends(get_db),
) -> LdapSettingsResponse:
    """Get Ldap Settings.

    Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return _ldap_settings_response(db)


@router.get("/ldap/health", response_model=LdapHealthResponse, tags=["LDAP"], operation_id="getLdapHealth")
def get_ldap_health(
    identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
    db: Session = Depends(get_db),
) -> LdapHealthResponse:
    """Get Ldap Health.

    Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    response = _ldap_settings_response(db)
    organizations = _ldap_organizations(db)
    service = db.execute(select(ServiceState).where(ServiceState.service == "ldap")).scalar_one_or_none()
    running = bool(service and service.running)
    if not get_settings().dry_run_system_adapters:
        running = backing_systemd_unit_active("slapd.service") is True
    health = "healthy" if response.enabled and running and response.valid else "degraded" if response.enabled else "disabled"
    return LdapHealthResponse(
        enabled=response.enabled,
        running=running,
        health=health,
        ldaps_only=bool(response.ldaps_enabled and not response.ldap_enabled),
        ldaps_enabled=response.ldaps_enabled,
        ldaps_port=response.port,
        ldap_enabled=response.ldap_enabled,
        ldap_port=response.ldap_port,
        hostname=response.hostname,
        port=response.port,
        organization_count=len(organizations),
        user_count=sum(len(row.users) for row in organizations),
        group_count=sum(len(row.groups) for row in organizations),
        validation_errors=response.validation_errors,
        validation_warnings=response.validation_warnings,
    )


@router.patch("/ldap/settings", response_model=LdapSettingsResponse, tags=["LDAP"], operation_id="updateLdapSettings")
def update_ldap_settings(
    payload: LdapSettingsUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapSettingsResponse:
    """Update Ldap Settings.

    Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = _ldap_settings_row(db)
    settings.enabled = payload.enabled
    settings.hostname = payload.hostname.strip().lower()
    available = _ldap_api_interface_addresses(db)
    selected_interfaces = [item.strip() for item in payload.listen_interfaces if item.strip() in available]
    settings.listen_interface = ",".join(dict.fromkeys(selected_interfaces))
    settings.listen_address = ",".join(
        dict.fromkeys(
            address
            for interface_name in selected_interfaces
            for address in available[interface_name]
        )
    )
    settings.ldaps_enabled = payload.ldaps_enabled
    settings.port = payload.port
    settings.ldap_enabled = payload.ldap_enabled
    settings.ldap_port = payload.ldap_port
    settings.min_password_length = payload.password_policy.min_length
    settings.require_uppercase = payload.password_policy.require_uppercase
    settings.require_lowercase = payload.password_policy.require_lowercase
    settings.require_number = payload.password_policy.require_number
    settings.require_special = payload.password_policy.require_special
    settings.disallow_username = payload.password_policy.disallow_username
    settings.max_failures = payload.password_policy.max_failures
    settings.lockout_minutes = payload.password_policy.lockout_minutes
    settings.failure_window_minutes = payload.password_policy.failure_window_minutes
    settings.password_history = payload.password_policy.history
    settings.password_max_age_days = payload.password_policy.max_age_days
    settings.config_path = LDAP_STAGED_CONFIG_PATH
    settings.updated_at = utcnow()
    db.commit()
    record_audit(db, actor=identity.username, action="update_ldap_settings", resource_type="ldap", resource_id=str(settings.id))
    return _ldap_settings_response(db)


@router.get("/ldap/organizations", response_model=list[LdapOrganizationResponse], tags=["LDAP"], operation_id="listLdapOrganizations")
def list_ldap_organizations(
    identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
    db: Session = Depends(get_db),
) -> list[LdapOrganizationResponse]:
    """List Ldap Organizations.

    Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [LdapOrganizationResponse(**ldap_organization_to_dict(row)) for row in _ldap_organizations(db)]


@router.post(
    "/ldap/organizations",
    response_model=LdapOrganizationResponse,
    status_code=201,
    tags=["LDAP"],
    operation_id="createLdapOrganization",
)
def create_ldap_organization(
    payload: LdapOrganizationCreate,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapOrganizationResponse:
    """Create Ldap Organization.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    try:
        slug = normalize_ldap_slug(payload.slug or payload.name)
        suffix = normalize_dn(payload.suffix_dn or default_organization_suffix(slug))
        if not suffix.lower().startswith("dc="):
            raise ValueError("LDAP organization suffix must start with a dc component.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    organization = LdapOrganization(
        name=payload.name.strip(),
        slug=slug,
        suffix_dn=suffix,
        enabled=payload.enabled,
    )
    raw_secret = ensure_organization_bind_secret(organization)
    db.add(organization)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="LDAP organization slug or suffix already exists.") from exc
    db.refresh(organization)
    record_audit(db, actor=identity.username, action="create_ldap_organization", resource_type="ldap_organization", resource_id=str(organization.id))
    return LdapOrganizationResponse(**ldap_organization_to_dict(organization, reveal_bind_secret=raw_secret))


@router.put("/ldap/organizations/{organization_id}", response_model=LdapOrganizationResponse, tags=["LDAP"], operation_id="updateLdapOrganization")
def update_ldap_organization(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    payload: LdapOrganizationCreate,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapOrganizationResponse:
    """Update Ldap Organization.

    Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    try:
        organization.name = payload.name.strip()
        new_slug = normalize_ldap_slug(payload.slug or payload.name)
        new_suffix = normalize_dn(payload.suffix_dn or default_organization_suffix(new_slug))
        if not new_suffix.lower().startswith("dc="):
            raise ValueError("LDAP organization suffix must start with a dc component.")
        if (new_slug != organization.slug or new_suffix != organization.suffix_dn) and (organization.users or organization.groups):
            raise ValueError("LDAP organization slug and suffix cannot change after directory entries exist.")
        organization.slug = new_slug
        organization.suffix_dn = new_suffix
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    organization.bind_dn = f"uid=vcf-bind,ou=service-accounts,{organization.suffix_dn}"
    organization.enabled = payload.enabled
    organization.updated_at = utcnow()
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="LDAP organization slug or suffix already exists.") from exc
    record_audit(db, actor=identity.username, action="update_ldap_organization", resource_type="ldap_organization", resource_id=str(organization.id))
    return LdapOrganizationResponse(**ldap_organization_to_dict(organization))


@router.delete("/ldap/organizations/{organization_id}", status_code=204, tags=["LDAP"], operation_id="deleteLdapOrganization")
def delete_ldap_organization(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Ldap Organization.

    Requires the `write:ldap` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    db.delete(organization)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_ldap_organization", resource_type="ldap_organization", resource_id=str(organization_id))
    return Response(status_code=204)


@router.post(
    "/ldap/organizations/{organization_id}/bind-credential/rotate",
    response_model=LdapBindCredentialResponse,
    tags=["LDAP"],
    operation_id="rotateLdapBindCredential",
)
def rotate_ldap_bind_credential(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapBindCredentialResponse:
    """Rotate Ldap Bind Credential.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    raw_secret = rotate_organization_bind_secret(organization)
    db.commit()
    record_audit(db, actor=identity.username, action="rotate_ldap_bind_credential", resource_type="ldap_organization", resource_id=str(organization.id))
    response = LdapOrganizationResponse(**ldap_organization_to_dict(organization))
    return LdapBindCredentialResponse(organization=response, raw_bind_password=raw_secret)


@router.get("/ldap/organizations/{organization_id}/users", response_model=list[LdapUserResponse], tags=["LDAP"], operation_id="listLdapUsers")
def list_ldap_users(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
    db: Session = Depends(get_db),
) -> list[LdapUserResponse]:
    """List Ldap Users.

    Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = db.execute(select(LdapUser).where(LdapUser.organization_id == organization_id).order_by(LdapUser.uid)).scalars().all()
    return [LdapUserResponse(**ldap_user_to_dict(row)) for row in rows]


def _apply_ldap_user_payload(user: LdapUser, payload: LdapUserCreate) -> None:
    """Update ldap user payload.

    Args:
        user: User record or identity affected by the operation.
        payload: Validated request or task payload consumed by the operation.


    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    uid = payload.uid.strip().lower()
    if not LDAP_UID_PATTERN.fullmatch(uid):
        raise HTTPException(status_code=400, detail="LDAP uid must start with a letter and use only lowercase letters, numbers, dot, underscore, or hyphen.")
    user.uid = uid
    user.given_name = payload.given_name.strip()
    user.surname = payload.surname.strip() or payload.display_name.strip() or uid
    user.display_name = payload.display_name.strip() or " ".join(part for part in [user.given_name, user.surname] if part).strip() or uid
    user.email = payload.email.strip().lower()
    user.telephone = payload.telephone.strip()
    user.enabled = payload.enabled
    user.updated_at = utcnow()


@router.post(
    "/ldap/organizations/{organization_id}/users",
    response_model=LdapUserResponse,
    status_code=201,
    tags=["LDAP"],
    operation_id="createLdapUser",
)
def create_ldap_user(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    payload: LdapUserCreate,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapUserResponse:
    """Create Ldap User.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    user = LdapUser(organization_id=organization_id)
    _apply_ldap_user_payload(user, payload)
    db.add(user)
    try:
        db.flush()
        if payload.password:
            stage_ldap_user_password(user, payload.password, _ldap_settings_row(db))
        db.commit()
    except (IntegrityError, ValueError) as exc:
        db.rollback()
        status_code = 409 if isinstance(exc, IntegrityError) else 400
        raise HTTPException(status_code=status_code, detail="LDAP uid already exists in this organization." if status_code == 409 else str(exc)) from exc
    db.refresh(user)
    record_audit(db, actor=identity.username, action="create_ldap_user", resource_type="ldap_user", resource_id=str(user.id), detail=f"organization_id={organization_id}")
    return LdapUserResponse(**ldap_user_to_dict(user))


@router.put("/ldap/users/{user_id}", response_model=LdapUserResponse, tags=["LDAP"], operation_id="updateLdapUser")
def update_ldap_user(
    user_id: Annotated[int, ApiPath(description='Unique identifier of the user record addressed by this operation.')],
    payload: LdapUserCreate,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapUserResponse:
    """Update Ldap User.

    Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        user_id: Stable identifier of the associated user resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    user = db.get(LdapUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    invalidate_ldap_user_password_for_uid_change(user, payload.uid.strip().lower())
    _apply_ldap_user_payload(user, payload)
    try:
        if payload.password:
            stage_ldap_user_password(user, payload.password, _ldap_settings_row(db))
        db.commit()
    except (IntegrityError, ValueError) as exc:
        db.rollback()
        status_code = 409 if isinstance(exc, IntegrityError) else 400
        raise HTTPException(status_code=status_code, detail="LDAP uid already exists in this organization." if status_code == 409 else str(exc)) from exc
    record_audit(db, actor=identity.username, action="update_ldap_user", resource_type="ldap_user", resource_id=str(user.id))
    return LdapUserResponse(**ldap_user_to_dict(user))


@router.post("/ldap/users/{user_id}/password", response_model=LdapUserResponse, tags=["LDAP"], operation_id="resetLdapUserPassword")
def reset_ldap_user_password(
    user_id: Annotated[int, ApiPath(description='Unique identifier of the user record addressed by this operation.')],
    payload: LdapPasswordResetRequest,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapUserResponse:
    """Reset Ldap User Password.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        user_id: Stable identifier of the associated user resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    user = db.get(LdapUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    try:
        stage_ldap_user_password(user, payload.password, _ldap_settings_row(db))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    record_audit(db, actor=identity.username, action="reset_ldap_user_password", resource_type="ldap_user", resource_id=str(user.id))
    return LdapUserResponse(**ldap_user_to_dict(user))


@router.post("/ldap/users/{user_id}/unlock", response_model=LdapUserResponse, tags=["LDAP"], operation_id="unlockLdapUser")
def unlock_ldap_user(
    user_id: Annotated[int, ApiPath(description='Unique identifier of the user record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapUserResponse:
    """Unlock Ldap User.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        user_id: Stable identifier of the associated user resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    user = db.get(LdapUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    user.unlock_requested_at = utcnow()
    db.commit()
    record_audit(db, actor=identity.username, action="unlock_ldap_user", resource_type="ldap_user", resource_id=str(user.id))
    return LdapUserResponse(**ldap_user_to_dict(user))


@router.delete("/ldap/users/{user_id}", status_code=204, tags=["LDAP"], operation_id="deleteLdapUser")
def delete_ldap_user(
    user_id: Annotated[int, ApiPath(description='Unique identifier of the user record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Ldap User.

    Requires the `write:ldap` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        user_id: Stable identifier of the associated user resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    user = db.get(LdapUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    clear_pending_ldap_password(user)
    db.delete(user)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_ldap_user", resource_type="ldap_user", resource_id=str(user_id))
    return Response(status_code=204)


def _set_ldap_group_members(db: Session, group: LdapGroup, payload: LdapGroupCreate) -> None:
    """Update ldap group members.

    Args:
        db: Active database session.
        group: Role, firewall, or directory group to process.
        payload: Validated request or operation payload.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    group.members.clear()
    db.flush()
    for member in payload.members:
        if member.type == "user":
            user = db.get(LdapUser, member.id)
            if user is None or user.organization_id != group.organization_id:
                raise HTTPException(status_code=400, detail="LDAP group member user must belong to the same organization.")
            group.members.append(LdapGroupMembership(member_user=user))
        else:
            member_group = db.get(LdapGroup, member.id)
            if member_group is None or member_group.organization_id != group.organization_id:
                raise HTTPException(status_code=400, detail="Nested LDAP group must belong to the same organization.")
            if member_group.id == group.id:
                raise HTTPException(status_code=400, detail="LDAP group cannot contain itself.")
            group.members.append(LdapGroupMembership(member_group=member_group))
    db.flush()
    organization_groups = db.execute(select(LdapGroup).where(LdapGroup.organization_id == group.organization_id)).scalars().all()
    cycle_errors = validate_group_cycles(organization_groups)
    if cycle_errors:
        raise HTTPException(status_code=400, detail=cycle_errors[0])


@router.get("/ldap/organizations/{organization_id}/groups", response_model=list[LdapGroupResponse], tags=["LDAP"], operation_id="listLdapGroups")
def list_ldap_groups(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
    db: Session = Depends(get_db),
) -> list[LdapGroupResponse]:
    """List Ldap Groups.

    Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    rows = (
        db.execute(
            select(LdapGroup)
            .where(LdapGroup.organization_id == organization_id)
            .options(
                selectinload(LdapGroup.organization),
                selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_user).selectinload(LdapUser.organization),
                selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_group).selectinload(LdapGroup.organization),
            )
            .order_by(LdapGroup.name)
        )
        .scalars()
        .all()
    )
    return [LdapGroupResponse(**ldap_group_to_dict(row)) for row in rows]


def _ldap_group_response(db: Session, group_id: int) -> LdapGroupResponse:
    """Return ldap group response.

    Args:
        db: Active database session.
        group_id: Identifier of the group.
    """
    group = (
        db.execute(
            select(LdapGroup)
            .where(LdapGroup.id == group_id)
            .options(
                selectinload(LdapGroup.organization),
                selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_user).selectinload(LdapUser.organization),
                selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_group).selectinload(LdapGroup.organization),
            )
        )
        .scalars()
        .one()
    )
    return LdapGroupResponse(**ldap_group_to_dict(group))


@router.post(
    "/ldap/organizations/{organization_id}/groups",
    response_model=LdapGroupResponse,
    status_code=201,
    tags=["LDAP"],
    operation_id="createLdapGroup",
)
def create_ldap_group(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    payload: LdapGroupCreate,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapGroupResponse:
    """Create Ldap Group.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    if not LDAP_GROUP_PATTERN.fullmatch(payload.name.strip()):
        raise HTTPException(status_code=400, detail="LDAP group name contains unsupported characters.")
    group = LdapGroup(
        organization=organization,
        name=payload.name.strip(),
        description=payload.description.strip(),
        enabled=payload.enabled,
    )
    db.add(group)
    try:
        db.flush()
        _set_ldap_group_members(db, group, payload)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="LDAP group name already exists in this organization.") from exc
    db.refresh(group)
    record_audit(db, actor=identity.username, action="create_ldap_group", resource_type="ldap_group", resource_id=str(group.id))
    return _ldap_group_response(db, group.id)


@router.put("/ldap/groups/{group_id}", response_model=LdapGroupResponse, tags=["LDAP"], operation_id="updateLdapGroup")
def update_ldap_group(
    group_id: Annotated[int, ApiPath(description='Unique identifier of the group record addressed by this operation.')],
    payload: LdapGroupCreate,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapGroupResponse:
    """Update Ldap Group.

    Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
    bypass the documented global Appliance Apply or service lifecycle boundary.

    Args:
        group_id: Stable identifier of the associated group resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    group = db.get(LdapGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="LDAP group not found")
    if not LDAP_GROUP_PATTERN.fullmatch(payload.name.strip()):
        raise HTTPException(status_code=400, detail="LDAP group name contains unsupported characters.")
    group.name = payload.name.strip()
    group.description = payload.description.strip()
    group.enabled = payload.enabled
    group.updated_at = utcnow()
    try:
        _set_ldap_group_members(db, group, payload)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="LDAP group name already exists in this organization.") from exc
    record_audit(db, actor=identity.username, action="update_ldap_group", resource_type="ldap_group", resource_id=str(group.id))
    return _ldap_group_response(db, group.id)


@router.delete("/ldap/groups/{group_id}", status_code=204, tags=["LDAP"], operation_id="deleteLdapGroup")
def delete_ldap_group(
    group_id: Annotated[int, ApiPath(description='Unique identifier of the group record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete Ldap Group.

    Requires the `write:ldap` API scope. Removal or revocation takes effect in Atlaso application
    state; appliance host changes remain subject to the documented apply boundary for the resource.

    Args:
        group_id: Stable identifier of the associated group resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    group = db.get(LdapGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="LDAP group not found")
    db.delete(group)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_ldap_group", resource_type="ldap_group", resource_id=str(group_id))
    return Response(status_code=204)


@router.get("/ldap/organizations/{organization_id}/vcf-bundle", response_model=dict[str, Any], tags=["LDAP"], operation_id="getLdapVcfBundle")
def get_ldap_vcf_bundle(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get Ldap Vcf Bundle.

    Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
    or appliance runtime state.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    ca = db.execute(select(CaSettings)).scalar_one_or_none()
    bundle = manual_vcf_bundle(_ldap_settings_row(db), organization, root_ca_pem=ca.root_certificate_pem if ca else "")
    record_audit(db, actor=identity.username, action="generate_ldap_vcf_bundle", resource_type="ldap_organization", resource_id=str(organization.id))
    return bundle


def _sanitize_vcf_ldap_settings(payload: dict[str, Any]) -> dict[str, Any]:
    """Return sanitize vcf ldap settings.

    Args:
        payload: Validated request or task payload consumed by the operation.
    """
    sanitized = json.loads(json.dumps(payload))
    defined = sanitized.get("definedSettings")
    if isinstance(defined, dict) and "password" in defined:
        defined["password"] = "[redacted]"
    return sanitized


@router.post(
    "/ldap/organizations/{organization_id}/vcf/inspect",
    response_model=LdapVcfInspectionResponse,
    tags=["LDAP"],
    operation_id="inspectLdapVcfConnection",
)
def inspect_ldap_vcf_connection(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    payload: LdapVcfInspectRequest,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapVcfInspectionResponse:
    """Inspect Ldap Vcf Connection.

    Requires the `write:ldap` API scope. The request is evaluated without persisting desired state
    or mutating appliance runtime state.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    target_url = normalize_vcf_target_url(payload.target_url)
    try:
        fingerprint = tls_sha256_fingerprint(target_url)
    except (ValueError, VcfLdapError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    proposed = vcf_ldap_settings(_ldap_settings_row(db), organization, include_password=False)
    if not payload.confirmed_tls_fingerprint:
        record_audit(db, actor=identity.username, action="inspect_vcf_organization_tls", resource_type="ldap_organization", resource_id=str(organization.id), detail=f"target={target_url}; org_id={payload.organization_id}")
        return LdapVcfInspectionResponse(
            target_url=target_url,
            organization_id=payload.organization_id,
            organization_name=payload.organization_name,
            tls_fingerprint=fingerprint,
            current_settings={},
            proposed_settings=proposed,
            changed=True,
        )
    try:
        client = VcfAutomationLdapClient(
            target_url,
            username=payload.username,
            password=payload.password,
            organization_id=payload.organization_id,
            confirmed_tls_fingerprint=payload.confirmed_tls_fingerprint,
        )
        current = client.get_settings()
    except (ValueError, VcfLdapError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(db, actor=identity.username, action="inspect_vcf_organization_ldap", resource_type="ldap_organization", resource_id=str(organization.id), detail=f"target={target_url}; org_id={payload.organization_id}")
    return LdapVcfInspectionResponse(
        target_url=target_url,
        organization_id=payload.organization_id,
        organization_name=payload.organization_name,
        tls_fingerprint=fingerprint,
        current_settings=_sanitize_vcf_ldap_settings(current),
        proposed_settings=proposed,
        changed=_sanitize_vcf_ldap_settings(current) != _sanitize_vcf_ldap_settings(proposed),
    )


@router.post(
    "/ldap/organizations/{organization_id}/vcf/configure",
    response_model=LdapVcfInspectionResponse,
    tags=["LDAP"],
    operation_id="configureLdapVcfConnection",
)
def configure_ldap_vcf_connection(
    organization_id: Annotated[int, ApiPath(description='Unique identifier of the organization record addressed by this operation.')],
    payload: LdapVcfConfigureRequest,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> LdapVcfInspectionResponse:
    """Configure Ldap Vcf Connection.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    organization = db.get(LdapOrganization, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="LDAP organization not found")
    settings = _ldap_settings_row(db)
    proposed = vcf_ldap_settings(settings, organization, include_password=True)
    try:
        client = VcfAutomationLdapClient(
            payload.target_url,
            username=payload.username,
            password=payload.password,
            organization_id=payload.organization_id,
            confirmed_tls_fingerprint=payload.confirmed_tls_fingerprint,
        )
        current = client.get_settings()
        current_enabled = bool(current.get("enabled"))
        if current_enabled and not payload.replace_existing:
            raise VcfLdapError("VCF organization already has LDAP enabled; confirm replacement before configuring it.")
        client.configure(proposed)
        test_result = client.test(proposed)
        users = client.search_users()
        groups = client.search_groups()
        if not users or not groups:
            raise VcfLdapError("VCF LDAP verification must find at least one user and one group.")
        verified = client.get_settings()
    except (ValueError, VcfLdapError) as exc:
        organization.vcf_last_status = "failed"
        organization.vcf_last_message = str(exc)
        organization.updated_at = utcnow()
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    organization.vcf_target_url = normalize_vcf_target_url(payload.target_url)
    organization.vcf_org_id = payload.organization_id
    organization.vcf_org_name = payload.organization_name
    organization.vcf_tls_fingerprint = payload.confirmed_tls_fingerprint.upper()
    organization.vcf_last_status = "verified"
    organization.vcf_last_message = f"LDAP configured; VCF found {len(users)} users and {len(groups)} groups."
    organization.vcf_last_verified_at = utcnow()
    organization.updated_at = utcnow()
    db.commit()
    record_audit(
        db,
        actor=identity.username,
        action="configure_vcf_organization_ldap",
        resource_type="ldap_organization",
        resource_id=str(organization.id),
        detail=f"target={organization.vcf_target_url}; org_id={organization.vcf_org_id}; users={len(users)}; groups={len(groups)}",
    )
    return LdapVcfInspectionResponse(
        target_url=organization.vcf_target_url,
        organization_id=organization.vcf_org_id,
        organization_name=organization.vcf_org_name,
        tls_fingerprint=organization.vcf_tls_fingerprint,
        current_settings=_sanitize_vcf_ldap_settings(verified),
        proposed_settings=_sanitize_vcf_ldap_settings(proposed),
        changed=False,
        test_result=test_result,
        user_count=len(users),
        group_count=len(groups),
    )


@router.post("/ldap/recovery/export", response_model=None, tags=["LDAP"], operation_id="exportLdapRecovery")
def export_ldap_recovery(
    payload: LdapRecoveryExportRequest,
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    db: Session = Depends(get_db),
) -> Response:
    """Export Ldap Recovery.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        payload: Validated request or task payload consumed by the operation.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    timestamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    plain_path = Path(LDAP_RECOVERY_DIR) / f"ldap-recovery-{timestamp}.tar.gz"
    result = SystemAdapter().export_ldap_recovery(str(plain_path))
    if result.dry_run:
        raise HTTPException(status_code=409, detail="LDAP recovery export requires a live appliance with OpenLDAP applied.")
    if result.returncode != 0 or not plain_path.is_file():
        raise HTTPException(status_code=500, detail=(result.stderr or "LDAP recovery export failed.").strip())
    try:
        encrypted = encrypt_recovery_payload(plain_path.read_bytes(), payload.passphrase)
    finally:
        plain_path.unlink(missing_ok=True)
    record_audit(db, actor=identity.username, action="export_ldap_recovery", resource_type="ldap_recovery", detail=f"created_at={timestamp}")
    return Response(
        encrypted,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="atlaso-ldap-recovery-{timestamp}.lfldap"'},
    )


@router.post(
    "/ldap/recovery/import",
    response_model=LdapRecoveryImportResponse,
    status_code=201,
    tags=["LDAP"],
    operation_id="stageLdapRecoveryImport",
)
async def stage_ldap_recovery_import(
    identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
    archive: UploadFile = File(..., description='Request value supplying archive for this operation.'),
    passphrase: str = Form(..., description='Request value supplying passphrase for this operation.'),
    db: Session = Depends(get_db),
) -> LdapRecoveryImportResponse:
    """Stage Ldap Recovery Import.

    Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
    appliance host enforcement remains subject to the documented apply or task boundary for the
    resource.

    Args:
        identity: Authenticated identity authorizing the operation.
        archive: Archive consumed by stage LDAP recovery import.
        passphrase: Passphrase consumed by stage LDAP recovery import.
        db: Active database session used by the operation.
    """
    encrypted = await archive.read()
    try:
        decrypted = decrypt_recovery_payload(encrypted, passphrase)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    for stale in db.execute(select(LdapRecoveryArchive).where(LdapRecoveryArchive.state == "staged")).scalars().all():
        clear_ldap_recovery_payload(stale)
        stale.state = "replaced"
    row = LdapRecoveryArchive(
        filename=archive.filename or "ldap-recovery.lfldap",
        path="memory://pending-ldap-recovery",
        sha256=recovery_sha256(decrypted),
        state="staged",
        organization_count=0,
        created_by=identity.username,
    )
    db.add(row)
    db.flush()
    try:
        manifest = stage_ldap_recovery_payload(row, decrypted)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    row.organization_count = len(manifest.get("databases") or [])
    db.commit()
    db.refresh(row)
    record_audit(db, actor=identity.username, action="stage_ldap_recovery_import", resource_type="ldap_recovery", resource_id=str(row.id), detail=f"sha256={row.sha256}; databases={row.organization_count}")
    return LdapRecoveryImportResponse(
        id=row.id,
        filename=row.filename,
        sha256=row.sha256,
        state=row.state,
        organization_count=row.organization_count,
        created_at=row.created_at,
    )


def _normalize_vsphere_service_hostname(value: str) -> str:
    """Return a canonical fully qualified DNS name for the shared listener.

    Args:
        value: Candidate public listener hostname.

    Returns:
        Canonical lowercase fully qualified DNS name.
    """
    try:
        return normalize_service_hostname(value)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="vSphere Key Provider hostname must be a valid fully qualified DNS name.",
        ) from None


def _normalize_vsphere_vcenter_hostname(value: str) -> str:
    """Return a canonical optional vCenter IP address or fully qualified DNS name.

    Args:
        value: Candidate trusted-vCenter network identifier.

    Returns:
        Canonical IP address or lowercase fully qualified DNS name, or an empty string.
    """
    try:
        return normalize_vcenter_hostname(value)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Trusted vCenter hostname must be an IP address or valid fully qualified DNS name.",
        ) from None


def _normalize_vsphere_listener_values(
    payload: VsphereKeyProviderSettingsUpdate,
    db: Session,
) -> tuple[list[str], list[str], str]:
    """Validate and normalize public listener settings before saving desired state.

    Args:
        payload: Submitted appliance-wide listener desired state.
        db: Active database session used to resolve current service bind targets.

    Returns:
        Deduplicated interface names, canonical IP addresses, and canonical hostname.
    """
    from atlaso.app.ui import service_bind_options

    available = {
        str(option["name"]): [str(address) for address in option.get("addresses", [])]
        for option in service_bind_options(db)
    }
    interfaces: list[str] = []
    for raw_interface in payload.listen_interfaces:
        interface = raw_interface.strip()
        if interface not in available:
            raise HTTPException(
                status_code=422,
                detail="Listener interfaces must be available addressed access or VLAN interfaces.",
            )
        if interface not in interfaces:
            interfaces.append(interface)

    addresses = list(
        dict.fromkeys(
            address
            for interface in interfaces
            for address in available[interface]
        )
    )

    if payload.enabled and not interfaces:
        raise HTTPException(status_code=422, detail="At least one listener interface is required while the service is enabled.")
    if payload.enabled and not addresses:
        raise HTTPException(status_code=422, detail="At least one listener address is required while the service is enabled.")
    return interfaces, addresses, _normalize_vsphere_service_hostname(payload.hostname)


def _vsphere_provider(db: Session, provider_id: str) -> VsphereKeyProvider:
    """Return one provider graph or raise a public not-found error.

    Args:
        db: Active database session.
        provider_id: Immutable provider UUID.
    """
    try:
        canonical_id = str(UUID(provider_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="vSphere Key Provider not found.") from exc
    provider = next((item for item in provider_rows(db) if item.id == canonical_id), None)
    if provider is None:
        raise HTTPException(status_code=404, detail="vSphere Key Provider not found.")
    return provider


def _vsphere_vcenter(
    db: Session,
    provider_id: str,
    vcenter_id: str,
) -> VsphereTrustedVcenter:
    """Return one provider-scoped vCenter or raise a public not-found error.

    Args:
        db: Active database session.
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
    """
    provider = _vsphere_provider(db, provider_id)
    try:
        canonical_id = str(UUID(vcenter_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Trusted vCenter not found.") from exc
    vcenter = next((item for item in provider.trusted_vcenters if item.id == canonical_id), None)
    if vcenter is None:
        raise HTTPException(status_code=404, detail="Trusted vCenter not found.")
    return vcenter


def _vsphere_settings_response(db: Session) -> VsphereKeyProviderSettingsResponse:
    """Return the appliance-wide listener settings and secret-free validation.

    Args:
        db: Active database session.
    """
    settings = get_kms_settings_row(db)
    providers = provider_rows(db)
    errors = validate_provider_state(providers) if settings.enabled else []
    if settings.enabled and not split_interfaces(settings.listen_interface):
        errors.append("At least one listener interface is required while the service is enabled.")
    if settings.enabled and not split_addresses(settings.listen_address):
        errors.append("At least one listener address is required while the service is enabled.")
    return VsphereKeyProviderSettingsResponse(
        enabled=settings.enabled,
        listen_interfaces=split_interfaces(settings.listen_interface),
        listen_addresses=split_addresses(settings.listen_address),
        port=settings.port,
        hostname=settings.hostname,
        updated_at=settings.updated_at,
        valid=not errors,
        validation_errors=errors,
        config_path=KMS_DEFAULT_CONFIG_PATH,
    )


@router.get(
    "/vsphere-key-providers/settings",
    response_model=VsphereKeyProviderSettingsResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereKeyProviderSettings",
)
def get_vsphere_key_provider_settings(
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereKeyProviderSettingsResponse:
    """Get appliance-wide vSphere Key Provider listener settings.

    Requires the `read:kms` API scope. The response describes saved desired state and never returns
    runtime credentials, client private keys, or operational key identifiers.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return _vsphere_settings_response(db)


@router.patch(
    "/vsphere-key-providers/settings",
    response_model=VsphereKeyProviderSettingsResponse,
    tags=["vSphere Key Providers"],
    operation_id="updateVsphereKeyProviderSettings",
)
def update_vsphere_key_provider_settings(
    payload: VsphereKeyProviderSettingsUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> VsphereKeyProviderSettingsResponse:
    """Update saved listener desired state without mutating the appliance host.

    Requires the `write:kms` API scope. Enforcement remains exclusively in global Appliance Apply.

    Args:
        payload: Validated listener desired state.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    interfaces, addresses, hostname = _normalize_vsphere_listener_values(payload, db)
    settings = get_kms_settings_row(db)
    settings.enabled = payload.enabled
    settings.listen_interface = join_csv(interfaces)
    settings.listen_address = join_csv(addresses)
    settings.port = payload.port
    settings.hostname = hostname
    settings.server_certificate = settings.hostname
    settings.backend = "atlaso-kmip"
    settings.require_client_cert = True
    settings.allow_register = False
    settings.allow_destroy = False
    settings.updated_at = utcnow()
    db.commit()
    record_audit(
        db,
        actor=identity.username,
        action="update_vsphere_key_provider_settings",
        resource_type="vsphere_key_provider_settings",
        resource_id=str(settings.id),
        detail=f"enabled={settings.enabled}; port={settings.port}; hostname={settings.hostname}",
    )
    return _vsphere_settings_response(db)


@router.get(
    "/vsphere-key-providers/server-certificate",
    response_model=VsphereServerCertificateResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereKeyProviderServerCertificate",
)
def get_vsphere_key_provider_server_certificate(
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereServerCertificateResponse:
    """Download the public appliance-wide KMIP server certificate chain.

    Requires the `read:kms` API scope. Only public X.509 material and metadata are returned.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    settings = get_kms_settings_row(db)
    certificate = db.execute(
        select(CaCertificate)
        .where(CaCertificate.managed_owner == "kms:server")
        .order_by(CaCertificate.id.desc())
    ).scalars().first()
    return VsphereServerCertificateResponse(
        available=bool(certificate and certificate.certificate_pem),
        hostname=settings.hostname,
        fingerprint_sha256=certificate.fingerprint if certificate else "",
        certificate_pem=certificate.certificate_pem if certificate else "",
        chain_pem=certificate.chain_pem if certificate else "",
        expires_at=certificate.expires_at if certificate else None,
    )


@router.get(
    "/vsphere-key-providers",
    response_model=list[VsphereKeyProviderResponse],
    tags=["vSphere Key Providers"],
    operation_id="listVsphereKeyProviders",
)
def list_vsphere_key_providers(
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> list[VsphereKeyProviderResponse]:
    """List logical provider namespaces and redacted trust counts.

    Requires the `read:kms` API scope. Operational key identifiers and wrapped-key metadata are not
    part of this management API.

    Args:
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return [VsphereKeyProviderResponse(**provider_to_dict(item)) for item in provider_rows(db)]


@router.post(
    "/vsphere-key-providers",
    response_model=VsphereKeyProviderResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["vSphere Key Providers"],
    operation_id="createVsphereKeyProvider",
)
def create_vsphere_key_provider(
    payload: VsphereKeyProviderCreate,
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> VsphereKeyProviderResponse:
    """Create an isolated provider namespace with an immutable UUID.

    Requires the `write:kms` API scope. The saved namespace is enforced only by global Appliance Apply.

    Args:
        payload: Validated provider fields.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = VsphereKeyProvider(
        id=str(uuid4()),
        name=payload.name.strip(),
        description=payload.description.strip(),
        enabled=payload.enabled,
    )
    db.add(provider)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Provider name already exists.") from exc
    record_audit(db, actor=identity.username, action="create_vsphere_key_provider", resource_type="vsphere_key_provider", resource_id=provider.id, detail=f"name={provider.name}; enabled={provider.enabled}")
    return VsphereKeyProviderResponse(**provider_to_dict(_vsphere_provider(db, provider.id)))


@router.get(
    "/vsphere-key-providers/{provider_id}",
    response_model=VsphereKeyProviderResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereKeyProvider",
)
def get_vsphere_key_provider(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereKeyProviderResponse:
    """Get one logical provider namespace.

    Requires the `read:kms` API scope. The response contains redacted trust counts only.

    Args:
        provider_id: Immutable provider UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return VsphereKeyProviderResponse(**provider_to_dict(_vsphere_provider(db, provider_id)))


@router.patch(
    "/vsphere-key-providers/{provider_id}",
    response_model=VsphereKeyProviderResponse,
    tags=["vSphere Key Providers"],
    operation_id="updateVsphereKeyProvider",
)
def update_vsphere_key_provider(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    payload: VsphereKeyProviderUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> VsphereKeyProviderResponse:
    """Update a provider name, description, or saved enabled state.

    Requires the `write:kms` API scope. The immutable provider UUID is never replaced.

    Args:
        provider_id: Immutable provider UUID.
        payload: Validated mutable provider fields.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = _vsphere_provider(db, provider_id)
    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(provider, key, value.strip() if isinstance(value, str) else value)
    provider.updated_at = utcnow()
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Provider name already exists.") from exc
    record_audit(db, actor=identity.username, action="update_vsphere_key_provider", resource_type="vsphere_key_provider", resource_id=provider.id, detail=f"name={provider.name}; enabled={provider.enabled}")
    return VsphereKeyProviderResponse(**provider_to_dict(_vsphere_provider(db, provider.id)))


@router.delete(
    "/vsphere-key-providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["vSphere Key Providers"],
    operation_id="deleteVsphereKeyProvider",
)
def delete_vsphere_key_provider(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete a disabled, detached, verified-empty provider namespace.

    Requires the `write:kms` API scope. The disabled and detached state must complete global
    Appliance Apply before authenticated runtime evidence of zero operational keys can authorize
    deletion; unavailable evidence fails closed.

    Args:
        provider_id: Immutable provider UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = _vsphere_provider(db, provider_id)
    if provider.enabled or provider.trusted_vcenters:
        raise HTTPException(status_code=409, detail="Disable the provider and detach every trusted vCenter before deletion.")
    if provider_requires_appliance_apply(provider):
        raise HTTPException(
            status_code=409,
            detail="Apply the disabled and detached provider state before deletion.",
        )
    snapshot = runtime_status_snapshot()
    counts = authenticated_provider_counts(snapshot, provider.id)
    if counts is None or counts.get("total") != 0:
        raise HTTPException(status_code=409, detail="Authenticated zero-key runtime evidence is required before deletion.")
    name = provider.name
    db.delete(provider)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_vsphere_key_provider", resource_type="vsphere_key_provider", resource_id=provider.id, detail=f"name={name}; verified_empty=true")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters",
    response_model=list[VsphereTrustedVcenterResponse],
    tags=["vSphere Key Providers"],
    operation_id="listVsphereTrustedVcenters",
)
def list_vsphere_trusted_vcenters(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> list[VsphereTrustedVcenterResponse]:
    """List trusted vCenters scoped to one provider.

    Requires the `read:kms` API scope. The response contains no credentials or private key material.

    Args:
        provider_id: Immutable provider UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = _vsphere_provider(db, provider_id)
    return [VsphereTrustedVcenterResponse(**trusted_vcenter_to_dict(item)) for item in provider.trusted_vcenters]


@router.post(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters",
    response_model=VsphereTrustedVcenterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["vSphere Key Providers"],
    operation_id="createVsphereTrustedVcenter",
)
def create_vsphere_trusted_vcenter(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    payload: VsphereTrustedVcenterCreate,
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> VsphereTrustedVcenterResponse:
    """Create a provider-scoped trusted-vCenter record.

    Requires the `write:kms` API scope. Public certificates are assigned through the certificate subresource.

    Args:
        provider_id: Immutable provider UUID.
        payload: Validated trusted-vCenter fields.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = _vsphere_provider(db, provider_id)
    item = VsphereTrustedVcenter(id=str(uuid4()), provider_id=provider.id, name=payload.name.strip(), hostname=_normalize_vsphere_vcenter_hostname(payload.hostname), description=payload.description.strip(), enabled=payload.enabled)
    db.add(item)
    mark_provider_desired_changed(provider)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Trusted vCenter name already exists for this provider.") from exc
    record_audit(db, actor=identity.username, action="create_vsphere_trusted_vcenter", resource_type="vsphere_trusted_vcenter", resource_id=item.id, detail=f"provider_id={provider.id}; name={item.name}; enabled={item.enabled}")
    return VsphereTrustedVcenterResponse(**trusted_vcenter_to_dict(_vsphere_vcenter(db, provider.id, item.id)))


@router.get(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
    response_model=VsphereTrustedVcenterResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereTrustedVcenter",
)
def get_vsphere_trusted_vcenter(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    vcenter_id: Annotated[str, ApiPath(description="Immutable trusted-vCenter UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereTrustedVcenterResponse:
    """Get one provider-scoped trusted vCenter.

    Requires the `read:kms` API scope. The response exposes public X.509 material only.

    Args:
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    return VsphereTrustedVcenterResponse(**trusted_vcenter_to_dict(_vsphere_vcenter(db, provider_id, vcenter_id)))


@router.patch(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
    response_model=VsphereTrustedVcenterResponse,
    tags=["vSphere Key Providers"],
    operation_id="updateVsphereTrustedVcenter",
)
def update_vsphere_trusted_vcenter(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    vcenter_id: Annotated[str, ApiPath(description="Immutable trusted-vCenter UUID.")],
    payload: VsphereTrustedVcenterUpdate,
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> VsphereTrustedVcenterResponse:
    """Update provider-scoped trusted-vCenter metadata and enabled state.

    Requires the `write:kms` API scope.

    Args:
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
        payload: Validated mutable trusted-vCenter fields.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    item = _vsphere_vcenter(db, provider_id, vcenter_id)
    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(item, key, value.strip() if isinstance(value, str) else value)
    item.hostname = _normalize_vsphere_vcenter_hostname(item.hostname)
    item.updated_at = utcnow()
    mark_provider_desired_changed(item.provider)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Trusted vCenter name already exists for this provider.") from exc
    record_audit(db, actor=identity.username, action="update_vsphere_trusted_vcenter", resource_type="vsphere_trusted_vcenter", resource_id=item.id, detail=f"provider_id={provider_id}; name={item.name}; enabled={item.enabled}")
    return VsphereTrustedVcenterResponse(**trusted_vcenter_to_dict(_vsphere_vcenter(db, provider_id, item.id)))


@router.delete(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["vSphere Key Providers"],
    operation_id="deleteVsphereTrustedVcenter",
)
def delete_vsphere_trusted_vcenter(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    vcenter_id: Annotated[str, ApiPath(description="Immutable trusted-vCenter UUID.")],
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> Response:
    """Delete a disabled trusted vCenter after every certificate is retired.

    Requires the `write:kms` API scope.

    Args:
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    item = _vsphere_vcenter(db, provider_id, vcenter_id)
    if item.enabled or item.certificates:
        raise HTTPException(status_code=409, detail="Disable the trusted vCenter and retire every certificate before deletion.")
    name = item.name
    mark_provider_desired_changed(item.provider)
    db.delete(item)
    db.commit()
    record_audit(db, actor=identity.username, action="delete_vsphere_trusted_vcenter", resource_type="vsphere_trusted_vcenter", resource_id=vcenter_id, detail=f"provider_id={provider_id}; name={name}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates",
    response_model=list[VsphereTrustedCertificateResponse],
    tags=["vSphere Key Providers"],
    operation_id="listVsphereTrustedVcenterCertificates",
)
def list_vsphere_trusted_vcenter_certificates(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    vcenter_id: Annotated[str, ApiPath(description="Immutable trusted-vCenter UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> list[VsphereTrustedCertificateResponse]:
    """List exact public certificates assigned to a trusted vCenter.

    Requires the `read:kms` API scope. Only public certificate material and parsed metadata are returned.

    Args:
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    item = _vsphere_vcenter(db, provider_id, vcenter_id)
    return [VsphereTrustedCertificateResponse(**certificate_to_dict(cert)) for cert in item.certificates]


@router.post(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates",
    response_model=VsphereTrustedCertificateResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["vSphere Key Providers"],
    operation_id="createVsphereTrustedVcenterCertificate",
)
def create_vsphere_trusted_vcenter_certificate(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    vcenter_id: Annotated[str, ApiPath(description="Immutable trusted-vCenter UUID.")],
    payload: VsphereTrustedCertificateCreate,
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> VsphereTrustedCertificateResponse:
    """Assign one current public X.509 client certificate to a trusted vCenter.

    Requires the `write:kms` API scope. Private-key blocks, expired certificates, malformed input,
    and fingerprints already assigned anywhere in the appliance are rejected.

    Args:
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
        payload: One public PEM certificate.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    item = _vsphere_vcenter(db, provider_id, vcenter_id)
    try:
        parsed = parse_public_certificate(payload.certificate_pem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    certificate = VsphereTrustedVcenterCertificate(id=str(uuid4()), trusted_vcenter_id=item.id, source="uploaded_public", **parsed)
    db.add(certificate)
    mark_provider_desired_changed(item.provider)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Certificate fingerprint is already assigned.") from exc
    record_audit(db, actor=identity.username, action="add_vsphere_trusted_certificate", resource_type="vsphere_trusted_certificate", resource_id=certificate.id, detail=f"provider_id={provider_id}; trusted_vcenter_id={vcenter_id}; public_certificate=true")
    refreshed = _vsphere_vcenter(db, provider_id, vcenter_id)
    stored = next(cert for cert in refreshed.certificates if cert.id == certificate.id)
    return VsphereTrustedCertificateResponse(**certificate_to_dict(stored))


@router.get(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates/{certificate_id}",
    response_model=VsphereTrustedCertificateResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereTrustedVcenterCertificate",
)
def get_vsphere_trusted_vcenter_certificate(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    vcenter_id: Annotated[str, ApiPath(description="Immutable trusted-vCenter UUID.")],
    certificate_id: Annotated[str, ApiPath(description="Immutable public certificate UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereTrustedCertificateResponse:
    """Get one exact public certificate record.

    Requires the `read:kms` API scope. The response exposes public X.509 material only.

    Args:
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
        certificate_id: Immutable public certificate UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    item = _vsphere_vcenter(db, provider_id, vcenter_id)
    certificate = next((cert for cert in item.certificates if cert.id == certificate_id), None)
    if certificate is None:
        raise HTTPException(status_code=404, detail="Certificate not found.")
    return VsphereTrustedCertificateResponse(**certificate_to_dict(certificate))


@router.delete(
    "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates/{certificate_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["vSphere Key Providers"],
    operation_id="deleteVsphereTrustedVcenterCertificate",
)
def delete_vsphere_trusted_vcenter_certificate(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    vcenter_id: Annotated[str, ApiPath(description="Immutable trusted-vCenter UUID.")],
    certificate_id: Annotated[str, ApiPath(description="Immutable public certificate UUID.")],
    identity: Annotated[Identity, Depends(require_scope("write:kms"))],
    db: Session = Depends(get_db),
) -> Response:
    """Retire one public certificate trust assignment.

    Requires the `write:kms` API scope. The last usable certificate of an enabled trusted vCenter
    cannot be retired until that record is disabled.

    Args:
        provider_id: Immutable provider UUID.
        vcenter_id: Immutable trusted-vCenter UUID.
        certificate_id: Immutable public certificate UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    item = _vsphere_vcenter(db, provider_id, vcenter_id)
    certificate = next((cert for cert in item.certificates if cert.id == certificate_id), None)
    if certificate is None:
        raise HTTPException(status_code=404, detail="Certificate not found.")
    usable = usable_certificates(item)
    if item.enabled and certificate in usable and len(usable) <= 1:
        raise HTTPException(status_code=409, detail="Disable the trusted vCenter before retiring its last usable public certificate.")
    mark_provider_desired_changed(item.provider)
    db.delete(certificate)
    db.commit()
    record_audit(db, actor=identity.username, action="retire_vsphere_trusted_certificate", resource_type="vsphere_trusted_certificate", resource_id=certificate_id, detail=f"provider_id={provider_id}; trusted_vcenter_id={vcenter_id}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/vsphere-key-providers/{provider_id}/readiness",
    response_model=VsphereProviderReadinessResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereKeyProviderReadiness",
)
def get_vsphere_key_provider_readiness(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereProviderReadinessResponse:
    """Evaluate one provider's saved desired-state readiness.

    Requires the `read:kms` API scope. This operation performs no host mutation.

    Args:
        provider_id: Immutable provider UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = _vsphere_provider(db, provider_id)
    reasons = validate_provider_state([provider]) if provider.enabled else []
    return VsphereProviderReadinessResponse(provider_id=provider.id, ready=not reasons, reasons=reasons, requires_appliance_apply=provider_requires_appliance_apply(provider))


@router.get(
    "/vsphere-key-providers/{provider_id}/health",
    response_model=VsphereProviderHealthResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereKeyProviderHealth",
)
def get_vsphere_key_provider_health(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereProviderHealthResponse:
    """Return redacted shared-daemon and authenticated store health.

    Requires the `read:kms` API scope. Raw helper errors and operational key identifiers are never returned.

    Args:
        provider_id: Immutable provider UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = _vsphere_provider(db, provider_id)
    snapshot = runtime_status_snapshot()
    return VsphereProviderHealthResponse(provider_id=provider.id, desired_state="enabled" if provider.enabled else "disabled", runtime_state=str(snapshot.get("runtime_state", "not-reported")), store_status=str(snapshot.get("store_status", "not-reported")), observed_at=utcnow())


@router.get(
    "/vsphere-key-providers/{provider_id}/lifecycle-counts",
    response_model=VsphereProviderLifecycleCountsResponse,
    tags=["vSphere Key Providers"],
    operation_id="getVsphereKeyProviderLifecycleCounts",
)
def get_vsphere_key_provider_lifecycle_counts(
    provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
    identity: Annotated[Identity, Depends(require_scope("read:kms"))],
    db: Session = Depends(get_db),
) -> VsphereProviderLifecycleCountsResponse:
    """Return authenticated redacted lifecycle counts for one provider namespace.

    Requires the `read:kms` API scope. Unavailable runtime evidence is represented by null counts,
    never fabricated zeroes.

    Args:
        provider_id: Immutable provider UUID.
        identity: Authenticated identity authorizing the operation.
        db: Active database session used by the operation.
    """
    provider = _vsphere_provider(db, provider_id)
    snapshot = runtime_status_snapshot()
    counts = authenticated_provider_counts(snapshot, provider.id)
    available = isinstance(counts, dict) and all(isinstance(counts.get(key), int) for key in ("pre_active", "active", "total"))
    return VsphereProviderLifecycleCountsResponse(provider_id=provider.id, status="available" if available else "not-reported", pre_active=counts.get("pre_active") if available else None, active=counts.get("active") if available else None, total=counts.get("total") if available else None, observed_at=utcnow())


def add_placeholder_resource_routes() -> None:
    """Create placeholder resource routes."""
    placeholder_specs = [
        ("ca", "CA", "read:ca"),
        ("backup", "Backup Restore", "write:backup"),
    ]

    for prefix, tag, scope in placeholder_specs:
        async def placeholder(
            identity: Annotated[Identity, Depends(require_scope(scope))],
            resource: Annotated[
                str,
                Query(description="Stable scaffolded resource name returned by this compatibility endpoint."),
            ] = prefix,
        ) -> dict[str, str]:
            """Return the scaffolded compatibility resource status.

            Args:
                identity: Authenticated identity authorizing the operation.
                resource: Resource consumed by placeholder.
            """
            return {"resource": resource, "status": "scaffolded", "mode": "dry-run"}

        operation_name = f"get{tag.replace(' ', '').replace('/', '')}Status"
        operation_description = (
            f"Return the scaffolded {tag} API status.\n\n"
            f"Requires the `{scope}` API scope. This read-only compatibility endpoint reports dry-run "
            "scaffold state and does not change saved desired state or appliance runtime state."
        )
        router.add_api_route(
            f"/{prefix}/status" if prefix not in {"backup"} else f"/{prefix}",
            placeholder,
            methods=["GET"],
            response_model=dict[str, str],
            summary=f"Get {tag} status",
            description=operation_description,
            response_description=f"Current scaffolded {tag} status and dry-run mode.",
            tags=[tag],
            operation_id=operation_name,
        )


add_placeholder_resource_routes()
