"""Expose the versioned REST API for Atlaso resources and workflows."""

import json
import socket
from ipaddress import ip_interface
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
)
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from atlaso import __build_git_commit__, __build_time_utc__, __version__
from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    ApplianceSettings,
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
    VlanInterface,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.routers.api_v1 import API_V1_ROUTER_REGISTRY
from atlaso.app.routers.api_v1.certificate_trust import (
    CertificateTrustApiDependencies,
)
from atlaso.app.routers.api_v1.certificate_trust import (
    build_router as build_certificate_trust_api_router,
)
from atlaso.app.routers.api_v1.dashboard_monitor import (
    DashboardMonitorApiDependencies,
)
from atlaso.app.routers.api_v1.dashboard_monitor import (
    build_router as build_dashboard_monitor_api_router,
)
from atlaso.app.routers.api_v1.dns_dhcp import DnsDhcpApiDependencies
from atlaso.app.routers.api_v1.dns_dhcp import (
    build_router as build_dns_dhcp_api_router,
)
from atlaso.app.routers.api_v1.esx_storage import EsxStorageApiDependencies
from atlaso.app.routers.api_v1.esx_storage import (
    build_router as build_esx_storage_api_router,
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
from atlaso.app.routers.api_v1.operations import OperationsApiDependencies
from atlaso.app.routers.api_v1.operations import (
    build_router as build_operations_api_router,
)
from atlaso.app.routers.api_v1.physical_vlans import PhysicalVlanApiDependencies
from atlaso.app.routers.api_v1.physical_vlans import (
    build_router as build_physical_vlan_api_router,
)
from atlaso.app.routers.api_v1.routes_wan import RoutesWanApiDependencies
from atlaso.app.routers.api_v1.routes_wan import (
    build_router as build_routes_wan_api_router,
)
from atlaso.app.routers.api_v1.settings import SettingsApiDependencies
from atlaso.app.routers.api_v1.settings import build_router as build_settings_api_router
from atlaso.app.routers.api_v1.vcf_workflows import VcfWorkflowsApiDependencies
from atlaso.app.routers.api_v1.vcf_workflows import (
    build_routers as build_vcf_workflows_api_routers,
)
from atlaso.app.routers.registry import RouterContribution
from atlaso.app.schemas import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApplianceVersionResponse,
    EsxNfsShareResponse,
    ServiceStateResponse,
    SettingsResponse,
    VcfOfflineDepotStatusResponse,
    VlanCreate,
)
from atlaso.app.schemas import SettingsUpdate as SettingsUpdate
from atlaso.app.security import (
    Identity,
    authenticate_user,
    require_scope,
)
from atlaso.app.services.appliance_settings import (
    APPLIANCE_SETTINGS_STAGED_CONFIG_PATH as APPLIANCE_SETTINGS_STAGED_CONFIG_PATH,
)
from atlaso.app.services.appliance_settings import (
    appliance_settings_to_dict,
    management_dhcp_dns_context,
    management_interface_context,
    management_ui_context,
    normalized_web_terminal_interfaces,
    render_appliance_settings_config,
    validate_appliance_settings,
    web_terminal_interface_options,
)
from atlaso.app.services.appliance_settings import normalize_fqdn as normalize_fqdn
from atlaso.app.services.appliance_settings import (
    normalize_multiline_values as normalize_multiline_values,
)
from atlaso.app.services.appliance_settings import (
    web_terminal_interfaces_to_json as web_terminal_interfaces_to_json,
)
from atlaso.app.services.ca import ca_service_state, managed_certificate_for_owner
from atlaso.app.services.dnsmasq import (
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    dhcp_dns_upstream_required,
    effective_dns_upstream_servers,
    ensure_dns_authoritative_defaults,
    render_dnsmasq_config,
    reservation_dns_record,
)
from atlaso.app.services.esx_storage import (
    StorageInterface,
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
from atlaso.app.services.monitoring import monitor_payload
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
)
from atlaso.app.services.ntp import default_ntp_upstream_fields
from atlaso.app.services.service_dns_defaults import (
    factory_service_hostname,
    reconcile_factory_service_identities,
)
from atlaso.app.services.service_registry import (
    SERVICE_SYSTEMD_UNITS,
)
from atlaso.app.services.vcf_backups import (
    vcf_backup_service_state,
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
)
from atlaso.app.token_service import create_token_for_user
from atlaso.app.ui import refresh_interface_service_dns_aliases

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
DNSMASQ_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/dnsmasq/atlaso.conf"

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
        hostname = factory_service_hostname(
            "kms", get_appliance_settings(db).fqdn
        )
        settings = KmsSettings(hostname=hostname, server_certificate=hostname)
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
            hostname=factory_service_hostname(
                "ntp", get_appliance_settings(db).fqdn
            ),
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
        hostname = factory_service_hostname(
            "registry", get_appliance_settings(db).fqdn
        )
        settings = VcfPrivateRegistrySettings(
            hostname=hostname,
            server_certificate=hostname,
        )
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
        hostname = factory_service_hostname(
            "depot", get_appliance_settings(db).fqdn
        )
        settings = VcfOfflineDepotSettings(
            hostname=hostname,
            server_certificate=hostname,
        )
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

_dashboard_monitor_api = build_dashboard_monitor_api_router(
    DashboardMonitorApiDependencies(monitor_payload=monitor_payload)
)
dashboard_monitor_router = _dashboard_monitor_api.router
get_dashboard = _dashboard_monitor_api.endpoints["get_dashboard"]
get_monitor = _dashboard_monitor_api.endpoints["get_monitor"]

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
_api_between_firewall_operations_router = router
_operations_api = build_operations_api_router(
    OperationsApiDependencies(
        get_dhcp_settings_row=get_dhcp_settings_row,
        get_dns_settings_row=get_dns_settings_row,
        service_state_response=service_state_response,
    )
)
operations_router = _operations_api.router
list_services = _operations_api.endpoints["list_services"]
get_service = _operations_api.endpoints["get_service"]
service_action = _operations_api.endpoints["service_action"]
start_service = _operations_api.endpoints["start_service"]
stop_service = _operations_api.endpoints["stop_service"]
restart_service = _operations_api.endpoints["restart_service"]
enable_service = _operations_api.endpoints["enable_service"]
disable_service = _operations_api.endpoints["disable_service"]
get_service_logs = _operations_api.endpoints["get_service_logs"]
list_logs = _operations_api.endpoints["list_logs"]
get_log_source = _operations_api.endpoints["get_log_source"]
list_audit_events = _operations_api.endpoints["list_audit_events"]
list_jobs = _operations_api.endpoints["list_jobs"]
create_job = _operations_api.endpoints["create_job"]
get_job = _operations_api.endpoints["get_job"]
cancel_job = _operations_api.endpoints["cancel_job"]

def _ensure_settings_ca_state(
    db: Session, *, commit: bool = True
) -> list[str]:
    """Use the stable UI facade's CA compatibility helper.

    Args:
        db: Active database session.
        commit: Whether CA reconciliation may commit before returning.

    Returns:
        Public-safe CA validation errors.
    """
    from atlaso.app import ui as ui_module

    return ui_module.ensure_ca_state(db, commit=commit)


_settings_api = build_settings_api_router(
    SettingsApiDependencies(
        appliance_settings_response=lambda *args, **kwargs: appliance_settings_response(
            *args, **kwargs
        ),
        get_appliance_settings=lambda *args, **kwargs: get_appliance_settings(
            *args, **kwargs
        ),
        ensure_ca_state=_ensure_settings_ca_state,
        reconcile_factory_service_identities=reconcile_factory_service_identities,
        reconcile_service_dns_aliases=lambda *args, **kwargs: refresh_interface_service_dns_aliases(
            *args, **kwargs
        ),
    )
)
settings_router = _settings_api.router
get_app_settings = _settings_api.endpoints["get_app_settings"]
update_app_settings = _settings_api.endpoints["update_app_settings"]

_vcf_workflows_api = build_vcf_workflows_api_routers(
    VcfWorkflowsApiDependencies(
        build_vcf_offline_depot_status=lambda *args, **kwargs: build_vcf_offline_depot_status(*args, **kwargs),
        get_vcf_backup_settings=get_vcf_backup_settings,
        get_vcf_private_registry_settings=get_vcf_private_registry_settings,
        vcf_registry_ca_bundle_status=vcf_registry_ca_bundle_status,
    )
)
vcf_workflows_backups_router = _vcf_workflows_api.backups_router
vcf_workflows_offline_depot_router = _vcf_workflows_api.offline_depot_router
vcf_workflows_private_registry_router = _vcf_workflows_api.private_registry_router
get_vcf_backups_status = _vcf_workflows_api.endpoints["get_vcf_backups_status"]
get_vcf_offline_depot_status = _vcf_workflows_api.endpoints["get_vcf_offline_depot_status"]
get_vcf_private_registry_status = _vcf_workflows_api.endpoints["get_vcf_private_registry_status"]

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)


def get_esx_storage_settings(db: Session) -> EsxStorageSettings:
    """Return esx storage settings.

    Args:
        db: Active database session.
    """
    row = db.execute(select(EsxStorageSettings).order_by(EsxStorageSettings.id)).scalars().first()
    if row is None:
        row = EsxStorageSettings(
            enabled=False,
            hostname=factory_service_hostname(
                "nfs", get_appliance_settings(db).fqdn
            ),
        )
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


_esx_storage_api = build_esx_storage_api_router(
    EsxStorageApiDependencies(
        esx_share_response=lambda *args, **kwargs: esx_share_response(*args, **kwargs),
        esx_storage_state=lambda *args, **kwargs: esx_storage_state(*args, **kwargs),
        get_esx_storage_settings=lambda *args, **kwargs: get_esx_storage_settings(*args, **kwargs),
        reconcile_esx_storage_dns=lambda *args, **kwargs: reconcile_esx_storage_dns(*args, **kwargs),
        system_adapter_factory=lambda *args, **kwargs: SystemAdapter(*args, **kwargs),
    )
)
esx_storage_router = _esx_storage_api.router
get_esx_storage_status = _esx_storage_api.endpoints["get_esx_storage_status"]
update_esx_storage_settings = _esx_storage_api.endpoints["update_esx_storage_settings"]
get_esx_storage_disks = _esx_storage_api.endpoints["get_esx_storage_disks"]
get_esx_storage_volumes = _esx_storage_api.endpoints["get_esx_storage_volumes"]
create_esx_storage_volume = _esx_storage_api.endpoints["create_esx_storage_volume"]
update_esx_storage_volume = _esx_storage_api.endpoints["update_esx_storage_volume"]
get_esx_nfs_shares = _esx_storage_api.endpoints["get_esx_nfs_shares"]
apply_esx_share_payload = _esx_storage_api.endpoints["apply_esx_share_payload"]
create_esx_nfs_share = _esx_storage_api.endpoints["create_esx_nfs_share"]
update_esx_nfs_share = _esx_storage_api.endpoints["update_esx_nfs_share"]
delete_esx_nfs_share = _esx_storage_api.endpoints["delete_esx_nfs_share"]

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
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


_api_between_vcf_backups_offline_depot_router = router
router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)


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


_api_between_offline_depot_private_registry_router = router
router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
_api_between_vcf_private_registry_network_boot_router = router
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
delete_esxi_pxe_host = _network_boot_api.endpoints["delete_esxi_pxe_host"]


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

def _certificate_trust_service_bind_options(db: Session) -> list[dict[str, object]]:
    """Resolve current service bind options through the stable UI facade seam.

    Args:
        db: Active database session.
    """
    from atlaso.app import ui as ui_module

    return ui_module.service_bind_options(db)

_certificate_trust_api = build_certificate_trust_api_router(
    CertificateTrustApiDependencies(
        get_kms_settings_row=get_kms_settings_row,
        service_bind_options=_certificate_trust_service_bind_options,
    )
)
certificate_trust_router = _certificate_trust_api.router
_normalize_vsphere_service_hostname = _certificate_trust_api.endpoints["_normalize_vsphere_service_hostname"]
_normalize_vsphere_vcenter_hostname = _certificate_trust_api.endpoints["_normalize_vsphere_vcenter_hostname"]
_normalize_vsphere_listener_values = _certificate_trust_api.endpoints["_normalize_vsphere_listener_values"]
_vsphere_provider = _certificate_trust_api.endpoints["_vsphere_provider"]
_vsphere_vcenter = _certificate_trust_api.endpoints["_vsphere_vcenter"]
_vsphere_settings_response = _certificate_trust_api.endpoints["_vsphere_settings_response"]
get_vsphere_key_provider_settings = _certificate_trust_api.endpoints["get_vsphere_key_provider_settings"]
update_vsphere_key_provider_settings = _certificate_trust_api.endpoints["update_vsphere_key_provider_settings"]
get_vsphere_key_provider_server_certificate = _certificate_trust_api.endpoints["get_vsphere_key_provider_server_certificate"]
list_vsphere_key_providers = _certificate_trust_api.endpoints["list_vsphere_key_providers"]
create_vsphere_key_provider = _certificate_trust_api.endpoints["create_vsphere_key_provider"]
get_vsphere_key_provider = _certificate_trust_api.endpoints["get_vsphere_key_provider"]
update_vsphere_key_provider = _certificate_trust_api.endpoints["update_vsphere_key_provider"]
delete_vsphere_key_provider = _certificate_trust_api.endpoints["delete_vsphere_key_provider"]
list_vsphere_trusted_vcenters = _certificate_trust_api.endpoints["list_vsphere_trusted_vcenters"]
create_vsphere_trusted_vcenter = _certificate_trust_api.endpoints["create_vsphere_trusted_vcenter"]
get_vsphere_trusted_vcenter = _certificate_trust_api.endpoints["get_vsphere_trusted_vcenter"]
update_vsphere_trusted_vcenter = _certificate_trust_api.endpoints["update_vsphere_trusted_vcenter"]
delete_vsphere_trusted_vcenter = _certificate_trust_api.endpoints["delete_vsphere_trusted_vcenter"]
list_vsphere_trusted_vcenter_certificates = _certificate_trust_api.endpoints["list_vsphere_trusted_vcenter_certificates"]
create_vsphere_trusted_vcenter_certificate = _certificate_trust_api.endpoints["create_vsphere_trusted_vcenter_certificate"]
get_vsphere_trusted_vcenter_certificate = _certificate_trust_api.endpoints["get_vsphere_trusted_vcenter_certificate"]
delete_vsphere_trusted_vcenter_certificate = _certificate_trust_api.endpoints["delete_vsphere_trusted_vcenter_certificate"]
get_vsphere_key_provider_readiness = _certificate_trust_api.endpoints["get_vsphere_key_provider_readiness"]
get_vsphere_key_provider_health = _certificate_trust_api.endpoints["get_vsphere_key_provider_health"]
get_vsphere_key_provider_lifecycle_counts = _certificate_trust_api.endpoints["get_vsphere_key_provider_lifecycle_counts"]
placeholder = _certificate_trust_api.endpoints["placeholder"]

router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
def add_placeholder_resource_routes() -> None:
    """Create placeholder resource routes."""
    placeholder_specs = [
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

_api_after_certificate_trust_router = router
API_V1_ROUTER_REGISTRY.register(
    "facade_before_identity",
    (RouterContribution(plane="api_v1", router=_api_before_identity_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "identity",
    (RouterContribution(plane="api_v1", router=identity_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "dashboard_monitor",
    (RouterContribution(plane="api_v1", router=dashboard_monitor_router),),
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
    "facade_between_firewall_operations",
    (
        RouterContribution(
            plane="api_v1", router=_api_between_firewall_operations_router
        ),
    ),
)
API_V1_ROUTER_REGISTRY.register(
    "operations",
    (RouterContribution(plane="api_v1", router=operations_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "settings",
    (RouterContribution(plane="api_v1", router=settings_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "vcf_workflows_backups",
    (RouterContribution(plane="api_v1", router=vcf_workflows_backups_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "esx_storage",
    (RouterContribution(plane="api_v1", router=esx_storage_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_between_vcf_backups_offline_depot",
    (
        RouterContribution(
            plane="api_v1", router=_api_between_vcf_backups_offline_depot_router
        ),
    ),
)
API_V1_ROUTER_REGISTRY.register(
    "vcf_workflows_offline_depot",
    (RouterContribution(plane="api_v1", router=vcf_workflows_offline_depot_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_between_offline_depot_private_registry",
    (
        RouterContribution(
            plane="api_v1", router=_api_between_offline_depot_private_registry_router
        ),
    ),
)
API_V1_ROUTER_REGISTRY.register(
    "vcf_workflows_private_registry",
    (RouterContribution(plane="api_v1", router=vcf_workflows_private_registry_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_between_vcf_private_registry_network_boot",
    (
        RouterContribution(
            plane="api_v1", router=_api_between_vcf_private_registry_network_boot_router
        ),
    ),
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
    "certificate_trust",
    (RouterContribution(plane="api_v1", router=certificate_trust_router),),
)
API_V1_ROUTER_REGISTRY.register(
    "facade_after_certificate_trust",
    (RouterContribution(plane="api_v1", router=_api_after_certificate_trust_router),),
)
API_V1_ROUTER_REGISTRY.validate_domains(
    (
        "facade_before_identity",
        "identity",
        "dashboard_monitor",
        "physical_vlans",
        "routes_wan",
        "facade_between_routes_wan_dns_dhcp",
        "dns_dhcp",
        "firewall",
        "facade_between_firewall_operations",
        "operations",
        "settings",
        "vcf_workflows_backups",
        "esx_storage",
        "facade_between_vcf_backups_offline_depot",
        "vcf_workflows_offline_depot",
        "facade_between_offline_depot_private_registry",
        "vcf_workflows_private_registry",
        "facade_between_vcf_private_registry_network_boot",
        "network_boot",
        "managed_ldap",
        "certificate_trust",
        "facade_after_certificate_trust",
    )
)



router = APIRouter()
for registered_router in API_V1_ROUTER_REGISTRY.routers_for_plane("api_v1"):
    router.routes.extend(registered_router.routes)
