"""Expose the versioned REST API for Atlaso resources and workflows."""

import json
import socket
from datetime import datetime
from ipaddress import ip_interface
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi import Path as ApiPath
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso import __build_git_commit__, __build_time_utc__, __version__
from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
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
    EsxNfsShare,
    EsxStorageSettings,
    EsxStorageVolume,
    FirewallRule,
    FirewallSettings,
    Job,
    JobStatus,
    KmsSettings,
    LdapSettings,
    NtpSettings,
    PhysicalInterface,
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
from atlaso.app.routers.api_v1 import API_V1_ROUTER_REGISTRY
from atlaso.app.routers.api_v1.dns_dhcp import DnsDhcpApiDependencies
from atlaso.app.routers.api_v1.dns_dhcp import (
    build_router as build_dns_dhcp_api_router,
)
from atlaso.app.routers.api_v1.firewall import FirewallApiDependencies
from atlaso.app.routers.api_v1.firewall import build_router as build_firewall_api_router
from atlaso.app.routers.api_v1.identity import build_router as build_identity_api_router
from atlaso.app.routers.api_v1.managed_ldap import ManagedLdapApiDependencies
from atlaso.app.routers.api_v1.managed_ldap import (
    build_router as build_managed_ldap_api_router,
)
from atlaso.app.routers.api_v1.network_boot import (
    build_router as build_network_boot_api_router,
)
from atlaso.app.routers.api_v1.physical_vlans import PhysicalVlanApiDependencies
from atlaso.app.routers.api_v1.physical_vlans import (
    build_router as build_physical_vlan_api_router,
)
from atlaso.app.routers.api_v1.routes_wan import RoutesWanApiDependencies
from atlaso.app.routers.api_v1.routes_wan import (
    build_router as build_routes_wan_api_router,
)
from atlaso.app.routers.registry import RouterContribution
from atlaso.app.schemas import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApplianceVersionResponse,
    AuditEventResponse,
    DashboardResponse,
    EsxNfsShareCreate,
    EsxNfsShareResponse,
    EsxNfsShareUpdate,
    EsxStorageDiskResponse,
    EsxStorageSettingsUpdate,
    EsxStorageStatusResponse,
    EsxStorageVolumeCreate,
    EsxStorageVolumeResponse,
    EsxStorageVolumeUpdate,
    JobResponse,
    MonitorResponse,
    PhysicalInterfaceResponse,
    ServiceActionResponse,
    ServiceStateResponse,
    SettingsResponse,
    SettingsUpdate,
    VcfBackupStatusResponse,
    VcfOfflineDepotStatusResponse,
    VcfPrivateRegistryStatusResponse,
    VlanCreate,
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
    WanPolicyResponse,
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
    dhcp_dns_upstream_required,
    effective_dns_upstream_servers,
    ensure_dns_authoritative_defaults,
    render_dnsmasq_config,
    reservation_dns_record,
    split_addresses,
    split_interfaces,
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
    esxi_pxe_boot_settings,
    esxi_pxe_service_state_from_boot,
)
from atlaso.app.services.firewall import (
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    FIREWALL_STAGED_CONFIG_PATH,
    ca_portal_firewall_interfaces,
    firewall_interface_networks,
    firewall_source_group_state,
    managed_routing_firewall_rules,
    managed_service_firewall_rules,
    render_nftables_config,
    validate_firewall_source_groups,
    validate_firewall_state,
)
from atlaso.app.services.kms import KMS_DEFAULT_CONFIG_PATH, join_csv
from atlaso.app.services.monitoring import monitor_payload
from atlaso.app.services.network_boot import cleanup_network_boot_upload
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
)
from atlaso.app.services.ntp import default_ntp_upstream_fields
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
from atlaso.app.token_service import create_token_for_user
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


_api_before_identity_router = router
_identity_api = build_identity_api_router()
identity_router = _identity_api.router
get_me = _identity_api.endpoints["get_me"]
list_api_tokens = _identity_api.endpoints["list_api_tokens"]
create_api_token = _identity_api.endpoints["create_api_token"]
get_api_token = _identity_api.endpoints["get_api_token"]
revoke_token = _identity_api.endpoints["revoke_token"]
delete_api_token = _identity_api.endpoints["delete_api_token"]
revoke_api_token = _identity_api.endpoints["revoke_api_token"]

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
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


_api_between_identity_physical_vlans_router = router
_physical_vlans_api = build_physical_vlan_api_router(
    PhysicalVlanApiDependencies(
        refresh_interface_service_dns_aliases=refresh_interface_service_dns_aliases,
        validate_vlan_api_payload=validate_vlan_api_payload,
    )
)
physical_vlans_router = _physical_vlans_api.router
list_physical_interfaces = _physical_vlans_api.endpoints["list_physical_interfaces"]
get_physical_interface = _physical_vlans_api.endpoints["get_physical_interface"]
update_physical_interface = _physical_vlans_api.endpoints["update_physical_interface"]
enable_physical_interface = _physical_vlans_api.endpoints["enable_physical_interface"]
disable_physical_interface = _physical_vlans_api.endpoints["disable_physical_interface"]
refresh_physical_interfaces = _physical_vlans_api.endpoints["refresh_physical_interfaces"]
list_vlans = _physical_vlans_api.endpoints["list_vlans"]
create_vlan = _physical_vlans_api.endpoints["create_vlan"]
get_vlan = _physical_vlans_api.endpoints["get_vlan"]
update_vlan = _physical_vlans_api.endpoints["update_vlan"]
delete_vlan = _physical_vlans_api.endpoints["delete_vlan"]
enable_vlan = _physical_vlans_api.endpoints["enable_vlan"]
disable_vlan = _physical_vlans_api.endpoints["disable_vlan"]
apply_vlan = _physical_vlans_api.endpoints["apply_vlan"]

_routes_wan_api = build_routes_wan_api_router(
    RoutesWanApiDependencies(setting_value=lambda db, key: setting_value(db, key))
)
routes_wan_router = _routes_wan_api.router
list_routes = _routes_wan_api.endpoints["list_routes"]
route_response = _routes_wan_api.endpoints["route_response"]
route_target_names = _routes_wan_api.endpoints["route_target_names"]
validate_route_payload = _routes_wan_api.endpoints["validate_route_payload"]
create_route = _routes_wan_api.endpoints["create_route"]
get_route = _routes_wan_api.endpoints["get_route"]
update_route = _routes_wan_api.endpoints["update_route"]
delete_route = _routes_wan_api.endpoints["delete_route"]
enable_route = _routes_wan_api.endpoints["enable_route"]
disable_route = _routes_wan_api.endpoints["disable_route"]
assign_route_wan_policy = _routes_wan_api.endpoints["assign_route_wan_policy"]
clear_route_wan_policy = _routes_wan_api.endpoints["clear_route_wan_policy"]
list_wan_policies = _routes_wan_api.endpoints["list_wan_policies"]
create_wan_policy = _routes_wan_api.endpoints["create_wan_policy"]
get_wan_policy = _routes_wan_api.endpoints["get_wan_policy"]
update_wan_policy = _routes_wan_api.endpoints["update_wan_policy"]
delete_wan_policy = _routes_wan_api.endpoints["delete_wan_policy"]
nat_outbound_target_names = _routes_wan_api.endpoints["nat_outbound_target_names"]
nat_source_group_ids = _routes_wan_api.endpoints["nat_source_group_ids"]
validate_nat_rule_payload = _routes_wan_api.endpoints["validate_nat_rule_payload"]
list_nat_rules = _routes_wan_api.endpoints["list_nat_rules"]
create_nat_rule = _routes_wan_api.endpoints["create_nat_rule"]
get_nat_rule = _routes_wan_api.endpoints["get_nat_rule"]
update_nat_rule = _routes_wan_api.endpoints["update_nat_rule"]
delete_nat_rule = _routes_wan_api.endpoints["delete_nat_rule"]
get_wan_status = _routes_wan_api.endpoints["get_wan_status"]

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
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


_dns_dhcp_api = build_dns_dhcp_api_router(
    DnsDhcpApiDependencies(
        ensure_dns_for_dhcp_reservation=ensure_dns_for_dhcp_reservation,
        get_dhcp_settings_row=get_dhcp_settings_row,
        get_dns_settings_row=get_dns_settings_row,
        get_dnsmasq_state=get_dnsmasq_state,
        set_setting_value=set_setting_value,
        setting_value=setting_value,
        stage_api_dnsmasq_config=stage_api_dnsmasq_config,
    )
)
dns_dhcp_router = _dns_dhcp_api.router
get_dns_status = _dns_dhcp_api.endpoints["get_dns_status"]
get_dns_settings = _dns_dhcp_api.endpoints["get_dns_settings"]
update_dns_settings = _dns_dhcp_api.endpoints["update_dns_settings"]
list_dns_records = _dns_dhcp_api.endpoints["list_dns_records"]
create_dns_record = _dns_dhcp_api.endpoints["create_dns_record"]
update_dns_record = _dns_dhcp_api.endpoints["update_dns_record"]
import_dns_hosts_file = _dns_dhcp_api.endpoints["import_dns_hosts_file"]
delete_dns_record = _dns_dhcp_api.endpoints["delete_dns_record"]
validate_dns_config = _dns_dhcp_api.endpoints["validate_dns_config"]
apply_dns_config = _dns_dhcp_api.endpoints["apply_dns_config"]
get_dns_logs = _dns_dhcp_api.endpoints["get_dns_logs"]
get_dhcp_status = _dns_dhcp_api.endpoints["get_dhcp_status"]
get_dhcp_settings = _dns_dhcp_api.endpoints["get_dhcp_settings"]
update_dhcp_settings = _dns_dhcp_api.endpoints["update_dhcp_settings"]
list_dhcp_scopes = _dns_dhcp_api.endpoints["list_dhcp_scopes"]
create_dhcp_scope = _dns_dhcp_api.endpoints["create_dhcp_scope"]
update_dhcp_scope = _dns_dhcp_api.endpoints["update_dhcp_scope"]
delete_dhcp_scope = _dns_dhcp_api.endpoints["delete_dhcp_scope"]
list_dhcp_options = _dns_dhcp_api.endpoints["list_dhcp_options"]
create_dhcp_option = _dns_dhcp_api.endpoints["create_dhcp_option"]
update_dhcp_option = _dns_dhcp_api.endpoints["update_dhcp_option"]
delete_dhcp_option = _dns_dhcp_api.endpoints["delete_dhcp_option"]
list_dhcp_reservations = _dns_dhcp_api.endpoints["list_dhcp_reservations"]
list_dhcp_leases = _dns_dhcp_api.endpoints["list_dhcp_leases"]
create_dhcp_reservation = _dns_dhcp_api.endpoints["create_dhcp_reservation"]
delete_dhcp_reservation = _dns_dhcp_api.endpoints["delete_dhcp_reservation"]
validate_dhcp_config = _dns_dhcp_api.endpoints["validate_dhcp_config"]
apply_dhcp_config = _dns_dhcp_api.endpoints["apply_dhcp_config"]
get_dhcp_logs = _dns_dhcp_api.endpoints["get_dhcp_logs"]
dnsmasq_validation_response = _dns_dhcp_api.endpoints["dnsmasq_validation_response"]

_api_between_routes_wan_dns_dhcp_router = router
_firewall_api = build_firewall_api_router(
    FirewallApiDependencies(
        assign_firewall_rule_values=assign_firewall_rule_values,
        firewall_validation_payload=firewall_validation_payload,
        get_firewall_settings=get_firewall_settings,
        setting_value=setting_value,
        stage_api_firewall_config=stage_api_firewall_config,
    )
)
firewall_router = _firewall_api.router
get_firewall_status = _firewall_api.endpoints["get_firewall_status"]
get_firewall_settings_api = _firewall_api.endpoints["get_firewall_settings_api"]
update_firewall_settings_api = _firewall_api.endpoints[
    "update_firewall_settings_api"
]
list_firewall_rules = _firewall_api.endpoints["list_firewall_rules"]
firewall_groups_for_api_validation = _firewall_api.endpoints[
    "firewall_groups_for_api_validation"
]
create_firewall_rule_api = _firewall_api.endpoints["create_firewall_rule_api"]
update_firewall_rule_api = _firewall_api.endpoints["update_firewall_rule_api"]
delete_firewall_rule_api = _firewall_api.endpoints["delete_firewall_rule_api"]
validate_firewall = _firewall_api.endpoints["validate_firewall"]
apply_firewall = _firewall_api.endpoints["apply_firewall"]
get_firewall_logs = _firewall_api.endpoints["get_firewall_logs"]

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
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
        if row.oper_state == "missing" or row.mode == "trunk" or normalize_interface_role(row.role) not in {"access", "route"}:
            continue
        interfaces[row.name] = StorageInterface(
            row.name,
            tuple(value for value in [row.ip_cidr] if value),
            tuple(value for value in [row.ipv6_cidr] if value and row.ipv6_enabled),
        )
    for row in db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all():
        if not row.enabled or normalize_interface_role(row.role) not in {"access", "route"}:
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


_api_between_firewall_network_boot_router = router
_network_boot_api = build_network_boot_api_router()
network_boot_router = _network_boot_api.router
_kickstart_response = _network_boot_api.endpoints["_kickstart_response"]
_assign_kickstart_payload = _network_boot_api.endpoints["_assign_kickstart_payload"]
list_esxi_custom_variables = _network_boot_api.endpoints["list_esxi_custom_variables"]
create_esxi_custom_variable = _network_boot_api.endpoints["create_esxi_custom_variable"]
update_esxi_custom_variable = _network_boot_api.endpoints["update_esxi_custom_variable"]
delete_esxi_custom_variable = _network_boot_api.endpoints["delete_esxi_custom_variable"]
list_esxi_kickstarts = _network_boot_api.endpoints["list_esxi_kickstarts"]
create_esxi_kickstart = _network_boot_api.endpoints["create_esxi_kickstart"]
get_esxi_kickstart = _network_boot_api.endpoints["get_esxi_kickstart"]
update_esxi_kickstart = _network_boot_api.endpoints["update_esxi_kickstart"]
delete_esxi_kickstart = _network_boot_api.endpoints["delete_esxi_kickstart"]
duplicate_esxi_kickstart = _network_boot_api.endpoints["duplicate_esxi_kickstart"]
validate_esxi_kickstart = _network_boot_api.endpoints["validate_esxi_kickstart"]
preview_esxi_kickstart = _network_boot_api.endpoints["preview_esxi_kickstart"]
download_esxi_kickstart = _network_boot_api.endpoints["download_esxi_kickstart"]
upload_esxi_kickstart = _network_boot_api.endpoints["upload_esxi_kickstart"]
list_esxi_installer_isos = _network_boot_api.endpoints["list_esxi_installer_isos"]
upload_esxi_installer_iso = _network_boot_api.endpoints["upload_esxi_installer_iso"]
list_esxi_pxe_hosts = _network_boot_api.endpoints["list_esxi_pxe_hosts"]
create_esxi_pxe_host = _network_boot_api.endpoints["create_esxi_pxe_host"]
update_esxi_pxe_host = _network_boot_api.endpoints["update_esxi_pxe_host"]


_managed_ldap_api = build_managed_ldap_api_router(
    ManagedLdapApiDependencies(
        backing_systemd_unit_active=backing_systemd_unit_active,
    )
)
managed_ldap_router = _managed_ldap_api.router
_ldap_settings_row = _managed_ldap_api.endpoints["_ldap_settings_row"]
_ldap_organizations = _managed_ldap_api.endpoints["_ldap_organizations"]
_ldap_api_interface_addresses = _managed_ldap_api.endpoints["_ldap_api_interface_addresses"]
_ldap_settings_response = _managed_ldap_api.endpoints["_ldap_settings_response"]
get_ldap_settings = _managed_ldap_api.endpoints["get_ldap_settings"]
get_ldap_health = _managed_ldap_api.endpoints["get_ldap_health"]
update_ldap_settings = _managed_ldap_api.endpoints["update_ldap_settings"]
list_ldap_organizations = _managed_ldap_api.endpoints["list_ldap_organizations"]
create_ldap_organization = _managed_ldap_api.endpoints["create_ldap_organization"]
update_ldap_organization = _managed_ldap_api.endpoints["update_ldap_organization"]
delete_ldap_organization = _managed_ldap_api.endpoints["delete_ldap_organization"]
rotate_ldap_bind_credential = _managed_ldap_api.endpoints["rotate_ldap_bind_credential"]
list_ldap_users = _managed_ldap_api.endpoints["list_ldap_users"]
_apply_ldap_user_payload = _managed_ldap_api.endpoints["_apply_ldap_user_payload"]
create_ldap_user = _managed_ldap_api.endpoints["create_ldap_user"]
update_ldap_user = _managed_ldap_api.endpoints["update_ldap_user"]
reset_ldap_user_password = _managed_ldap_api.endpoints["reset_ldap_user_password"]
unlock_ldap_user = _managed_ldap_api.endpoints["unlock_ldap_user"]
delete_ldap_user = _managed_ldap_api.endpoints["delete_ldap_user"]
_set_ldap_group_members = _managed_ldap_api.endpoints["_set_ldap_group_members"]
list_ldap_groups = _managed_ldap_api.endpoints["list_ldap_groups"]
_ldap_group_response = _managed_ldap_api.endpoints["_ldap_group_response"]
create_ldap_group = _managed_ldap_api.endpoints["create_ldap_group"]
update_ldap_group = _managed_ldap_api.endpoints["update_ldap_group"]
delete_ldap_group = _managed_ldap_api.endpoints["delete_ldap_group"]
get_ldap_vcf_bundle = _managed_ldap_api.endpoints["get_ldap_vcf_bundle"]
_sanitize_vcf_ldap_settings = _managed_ldap_api.endpoints["_sanitize_vcf_ldap_settings"]
inspect_ldap_vcf_connection = _managed_ldap_api.endpoints["inspect_ldap_vcf_connection"]
configure_ldap_vcf_connection = _managed_ldap_api.endpoints["configure_ldap_vcf_connection"]
export_ldap_recovery = _managed_ldap_api.endpoints["export_ldap_recovery"]
stage_ldap_recovery_import = _managed_ldap_api.endpoints["stage_ldap_recovery_import"]

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)

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

_api_after_managed_ldap_router = router
API_V1_ROUTER_REGISTRY.register(
    "facade_before_identity",
    (RouterContribution(plane="api_v1", router=_api_before_identity_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "identity",
    (RouterContribution(plane="api_v1", router=identity_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_between_identity_physical_vlans",
    (RouterContribution(plane="api_v1", router=_api_between_identity_physical_vlans_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "physical_vlans",
    (RouterContribution(plane="api_v1", router=physical_vlans_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "routes_wan",
    (RouterContribution(plane="api_v1", router=routes_wan_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_between_routes_wan_dns_dhcp",
    (
        RouterContribution(
            plane="api_v1",
            router=_api_between_routes_wan_dns_dhcp_router,
        ),
    ),
)
API_V1_ROUTER_REGISTRY.register(
    "dns_dhcp",
    (RouterContribution(plane="api_v1", router=dns_dhcp_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "firewall",
    (RouterContribution(plane="api_v1", router=firewall_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_between_firewall_network_boot",
    (RouterContribution(plane="api_v1", router=_api_between_firewall_network_boot_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "network_boot",
    (RouterContribution(plane="api_v1", router=network_boot_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "managed_ldap",
    (RouterContribution(plane="api_v1", router=managed_ldap_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_after_managed_ldap",
    (RouterContribution(plane="api_v1", router=_api_after_managed_ldap_router),),
)
API_V1_ROUTER_REGISTRY.validate_domains(
    (
        "facade_before_identity",
        "identity",
        "facade_between_identity_physical_vlans",
        "physical_vlans",
        "routes_wan",
        "facade_between_routes_wan_dns_dhcp",
        "dns_dhcp",
        "firewall",
        "facade_between_firewall_network_boot",
        "network_boot",
        "managed_ldap",
        "facade_after_managed_ldap",
    )
)

router = APIRouter()
for registered_router in API_V1_ROUTER_REGISTRY.routers_for_plane("api_v1"):
    router.routes.extend(registered_router.routes)
