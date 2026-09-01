"""Serve the admin portal and orchestrate its desired-state workflows."""

import difflib
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
from pathlib import Path, PurePosixPath
from secrets import token_urlsafe
from typing import Any, Callable
from urllib.parse import quote, unquote, urlsplit
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates
from sqlalchemy import String, and_, cast, delete, desc, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal, get_db
from atlaso.app.factory_reset import (
    FACTORY_RESET_STAGED_CREDENTIALS_PATH,
    read_factory_reset_state,
    replace_database_with_factory_candidate,
)
from atlaso.app.models import (
    ApiToken,
    ApplianceSettings,
    AuditEvent,
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
    EsxiPxeHost,
    EsxNfsShare,
    EsxStorageSettings,
    EsxStorageVolume,
    FirewallRule,
    FirewallSettings,
    Job,
    JobStatus,
    JobStep,
    KmsSettings,
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapRecoveryArchive,
    LdapSettings,
    LdapUser,
    ManagedPackage,
    NatRule,
    NetworkBootEsxiBootCapability,
    NtpSettings,
    OidcProviderSettings,
    PhysicalInterface,
    Role,
    Route,
    RoutingRule,
    Schedule,
    ServiceState,
    Setting,
    UpdateSource,
    User,
    Vault,
    VcfBackupSettings,
    VcfDepotDownloadProfile,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VcfRegistryBundle,
    VcfTrustTarget,
    VlanInterface,
    WanPolicy,
    utcnow,
)
from atlaso.app.operational_logging import (
    configure_operational_logging,
    logging_preferences_from_db,
    logging_preferences_to_dict,
    save_logging_preferences,
)
from atlaso.app.routers.registry import (
    RouterContribution,
    allow_compatible_route_shadow,
)
from atlaso.app.routers.ui import UI_ROUTER_REGISTRY
from atlaso.app.routers.ui.appliance_apply import ApplianceApplyUiDependencies
from atlaso.app.routers.ui.appliance_apply import (
    build_router as build_appliance_apply_ui_router,
)
from atlaso.app.routers.ui.appliance_maintenance import (
    ApplianceMaintenanceUiDependencies,
)
from atlaso.app.routers.ui.appliance_maintenance import (
    build_routers as build_appliance_maintenance_ui_routers,
)
from atlaso.app.routers.ui.automation import AutomationUiDependencies
from atlaso.app.routers.ui.automation import build_router as build_automation_ui_router
from atlaso.app.routers.ui.certificate_trust import CertificateTrustUiDependencies
from atlaso.app.routers.ui.certificate_trust import (
    build_routers as build_certificate_trust_ui_routers,
)
from atlaso.app.routers.ui.dashboard_monitor import DashboardMonitorUiDependencies
from atlaso.app.routers.ui.dashboard_monitor import (
    build_router as build_dashboard_monitor_ui_router,
)
from atlaso.app.routers.ui.dns_dhcp import DnsDhcpUiDependencies
from atlaso.app.routers.ui.dns_dhcp import build_router as build_dns_dhcp_ui_router
from atlaso.app.routers.ui.esx_storage import EsxStorageUiDependencies
from atlaso.app.routers.ui.esx_storage import (
    build_router as build_esx_storage_ui_router,
)
from atlaso.app.routers.ui.firewall import FirewallUiDependencies
from atlaso.app.routers.ui.firewall import build_router as build_firewall_ui_router
from atlaso.app.routers.ui.identity import IdentityUiDependencies
from atlaso.app.routers.ui.identity import build_router as build_identity_ui_router
from atlaso.app.routers.ui.managed_ldap import ManagedLdapUiDependencies
from atlaso.app.routers.ui.managed_ldap import (
    build_router as build_managed_ldap_ui_router,
)
from atlaso.app.routers.ui.network_boot import NetworkBootUiDependencies
from atlaso.app.routers.ui.network_boot import (
    build_router as build_network_boot_ui_router,
)
from atlaso.app.routers.ui.network_objects import NetworkObjectsUiDependencies
from atlaso.app.routers.ui.network_objects import (
    build_router as build_network_objects_ui_router,
)
from atlaso.app.routers.ui.ntp import NtpUiDependencies
from atlaso.app.routers.ui.ntp import build_router as build_ntp_ui_router
from atlaso.app.routers.ui.operations import OperationsUiDependencies
from atlaso.app.routers.ui.operations import build_router as build_operations_ui_router
from atlaso.app.routers.ui.physical_vlans import (
    PhysicalVlanUiDependencies,
)
from atlaso.app.routers.ui.physical_vlans import (
    build_router as build_physical_vlan_ui_router,
)
from atlaso.app.routers.ui.routes_wan import RoutesWanUiDependencies
from atlaso.app.routers.ui.routes_wan import build_router as build_routes_wan_ui_router
from atlaso.app.routers.ui.settings_backup import SettingsBackupUiDependencies
from atlaso.app.routers.ui.settings_backup import (
    build_router as build_settings_backup_ui_router,
)
from atlaso.app.routers.ui.vaults import VaultsUiDependencies
from atlaso.app.routers.ui.vaults import build_router as build_vaults_ui_router
from atlaso.app.routers.ui.vcf_workflows import VcfWorkflowsUiDependencies
from atlaso.app.routers.ui.vcf_workflows import (
    build_router as build_vcf_workflows_ui_router,
)
from atlaso.app.secrets import decrypt_secret, encrypt_secret, secret_key_status
from atlaso.app.security import (
    Identity,
    authenticate_user,
    consume_browser_session_expired_notice,
    end_browser_session,
    get_session_identity,
    normalize_roles,
    primary_role,
    require_session_identity,
    role_label,
    start_browser_session,
    user_roles,
)
from atlaso.app.services.appliance_settings import (
    APPLIANCE_DNS_RECORD_DESCRIPTION,
    APPLIANCE_SETTINGS_STAGED_CONFIG_PATH,
    SERVICE_DNS_TARGET_NAMING_CHOICES,
    appliance_settings_preview_payload,
    appliance_settings_to_dict,
    invalidate_observed_management_dhcp_dns,
    is_app_owned_appliance_dns_record,
    management_dhcp_dns_context,
    management_interface_context,
    management_ui_context,
    normalize_fqdn,
    normalize_multiline_values,
    normalize_service_dns_target_naming,
    normalized_web_terminal_interfaces,
    validate_appliance_settings,
    web_terminal_addresses,
    web_terminal_interface_options,
    web_terminal_interfaces_to_json,
    web_terminal_listener_interfaces,
)
from atlaso.app.services.appliance_update import (
    APPLIANCE_UPDATE_AVAILABILITY_KEY,
    APPLIANCE_UPDATE_EXECUTION_ORDER,
    APPLIANCE_UPDATE_FINALIZER_PATH,
    APPLIANCE_UPDATE_INFO_PATH,
    APPLIANCE_UPDATE_SETTINGS_KEY,
    APPLIANCE_UPDATE_STAGED_CONFIG_PATH,
    APPLIANCE_UPDATE_STAGED_CREDENTIALS_PATH,
    DEFAULT_ATLASO_MANIFEST_URL,
    UPDATE_STREAM_LABELS,
    UPDATE_STREAMS,
    appliance_update_evidence_state,
    clear_installed_update_availability,
    current_version_info,
    ensure_appliance_update_job_steps,
    manual_install_gate,
    normalized_availability_result,
    photon_repository_details,
    photon_repository_summary,
    read_appliance_file,
    record_update_availability_attempt,
    render_update_manifest,
    selected_update_streams,
    update_availability_from_json,
    update_availability_summary,
    update_availability_to_json,
    update_settings_from_json,
    update_settings_to_json,
    update_stream_configuration_fingerprint,
    update_stream_configuration_fingerprints,
    validate_update_settings,
)
from atlaso.app.services.automation import (
    SCHEDULE_TASK_TYPES,
    SCRIPT_INTERPRETERS,
    create_script_revision,
    normalize_script_content,
)
from atlaso.app.services.ca import (
    CA_DEFAULT_PORTAL_HOSTNAME,
    CA_SERVER_PROFILE_NAME,
    CA_STAGED_CONFIG_PATH,
    ManagedCertificateSpec,
    ca_certificate_to_dict,
    ca_profile_to_dict,
    ca_service_state,
    ensure_aware,
    ensure_ca_issued_state,
    ensure_default_ca_profiles,
    ensure_managed_certificate_rows,
    ensure_root_ca_material,
    managed_certificate_for_owner,
    render_ca_apply_payload,
    render_ca_config,
    safe_certificate_name,
    validate_ca_state,
)
from atlaso.app.services.dnsmasq import (
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    DNS_HOSTNAME_PATTERN,
    authoritative_zone_metadata,
    compact_dhcp_range_expression,
    dhcp_bind_target_families,
    dhcp_dns_upstream_required,
    dhcp_option_to_dict,
    dhcp_scope_to_dict,
    dns_domain_warnings,
    dns_reverse_records,
    dnsmasq_tag,
    dump_dns_record_data,
    effective_dns_upstream_servers,
    ensure_dns_authoritative_defaults,
    join_addresses,
    join_conditional_forwarders,
    join_domains,
    join_interfaces,
    join_servers,
    parse_dhcp_range_expression,
    parse_dnsmasq_leases,
    record_data,
    render_dnsmasq_config,
    render_hosts_records,
    render_zone_file,
    render_zone_hosts_records,
    reservation_dns_record,
    split_addresses,
    split_conditional_forwarders,
    split_domains,
    split_interfaces,
    split_servers,
    validate_dhcp_bind_targets,
    validate_dhcp_settings,
    validate_dns_listen_targets,
    validate_dns_record,
    validate_dns_settings,
)
from atlaso.app.services.esx_storage import (
    ESX_STORAGE_DNS_DESCRIPTION,
    ESX_STORAGE_STAGED_CONFIG_PATH,
    StorageInterface,
)
from atlaso.app.services.esx_storage import (
    desired_dns_records as desired_esx_storage_dns_records,
)
from atlaso.app.services.esx_storage import (
    firewall_rule_specs as esx_storage_firewall_rule_specs,
)
from atlaso.app.services.esx_storage import (
    format_authorization as esx_storage_format_authorization,
)
from atlaso.app.services.esx_storage import (
    manifest_json as esx_storage_manifest_json,
)
from atlaso.app.services.esx_storage import (
    normalize_families as normalize_esx_storage_families,
)
from atlaso.app.services.esx_storage import (
    parse_disk_inventory_output as parse_esx_storage_disk_inventory_output,
)
from atlaso.app.services.esx_storage import (
    render_manifest as render_esx_storage_manifest,
)
from atlaso.app.services.esx_storage import (
    split_lines as split_esx_storage_lines,
)
from atlaso.app.services.esxi_pxe import (
    DEFAULT_ESXI_KICKSTART_CONTENT,
    DEFAULT_ESXI_KICKSTART_NAME,
    ESXI_IPXE_HTTP_SCRIPT_PATH,
    ESXI_PXE_DEFAULT_HOSTNAME,
    ESXI_PXE_DNS_RECORD_DESCRIPTION,
    ESXI_PXE_STAGED_CONFIG_PATH,
    custom_variable_definitions,
    default_host_to_dict,
    esxi_pxe_boot_settings,
    esxi_pxe_default_host_settings,
    esxi_pxe_host_artifacts,
    esxi_pxe_service_state_from_boot,
    generated_kickstart_path,
    host_to_dict,
    installer_iso_inventory,
    installer_iso_root_path,
    kickstart_drift_state,
    kickstart_template_validation_errors,
    kickstart_template_variables,
    kickstart_to_dict,
    kickstart_validation,
    mark_kickstarts_applied,
    native_uefi_http_url_is_absolute,
    render_esxi_pxe_manifest,
    render_esxi_pxe_preview,
    strict_validation_enabled,
    validate_kickstart_custom_references,
    validate_kickstart_vault_references,
)
from atlaso.app.services.firewall import (
    ATLASO_DHCP_FIREWALL_RULE_MARKER,
    FIREWALL_ACTIONS,
    FIREWALL_DIRECTIONS,
    FIREWALL_POLICIES,
    FIREWALL_PROTOCOLS,
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    FIREWALL_STAGED_CONFIG_PATH,
    ca_portal_firewall_interfaces,
    firewall_interface_networks,
    firewall_rule_to_dict,
    firewall_source_group_state,
    is_atlaso_managed_firewall_rule,
    managed_routing_firewall_rules,
    managed_service_firewall_rules,
    render_nftables_config,
    validate_firewall_source_groups,
    validate_firewall_state,
)
from atlaso.app.services.kms import (
    KMS_DNS_RECORD_DESCRIPTION,
    KMS_STAGED_CLIENT_TRUST_PATH,
    KMS_STAGED_CONFIG_PATH,
)
from atlaso.app.services.ldap import (
    LDAP_CERT_PATH,
    LDAP_CHAIN_PATH,
    LDAP_DEFAULT_HOSTNAME,
    LDAP_DEFAULT_PORT,
    LDAP_DNS_RECORD_DESCRIPTION,
    LDAP_KEY_PATH,
    LDAP_PENDING_RECOVERY_PAYLOADS,
    LDAP_STAGED_CONFIG_PATH,
    clear_ldap_recovery_payload,
    has_pending_ldap_password,
    ldap_group_to_dict,
    ldap_organization_to_dict,
    ldap_settings_to_dict,
    ldap_user_to_dict,
    mark_ldap_apply_complete,
    render_ldap_apply_config,
    render_ldap_preview,
    validate_ldap_state,
    vcf_ldap_settings,
)
from atlaso.app.services.local_users import (
    DEFAULT_LOCAL_USER_SHELL,
    DEFAULT_PASSWORD_POLICY,
    LOCAL_USER_SHELLS,
    LOCAL_USERS_PASSWORD_POLICY_KEY,
    LOCAL_USERS_STAGED_CONFIG_PATH,
    clear_pending_os_password,
    has_pending_os_password,
    local_user_sync_rows,
    mark_local_users_applied,
    mark_local_users_failed,
    normalize_user_shell,
    password_policy_from_json,
    password_policy_summary,
    pending_os_password_count,
    render_local_users_apply_config,
    render_local_users_preview,
    validate_local_usernames,
    validate_password,
)
from atlaso.app.services.management_bindings import applied_management_bindings
from atlaso.app.services.monitoring import monitor_payload
from atlaso.app.services.networking import (
    INTERFACE_MODES,
    IPV4_METHODS,
    NETWORK_INVENTORY_CLEANUP_WARNING_KEY,
    NETWORK_ROLES,
    discover_host_ipv4_default_gateways,
    discover_host_physical_interfaces,
    is_canonical_network_role,
    normalize_interface_mode,
    normalize_interface_role,
    normalize_ipv4_method,
    physical_interface_to_dict,
    render_network_config,
    trunk_parent_option,
    validate_network_state,
    vlan_interface_to_dict,
)
from atlaso.app.services.ntp import (
    NTP_DEFAULT_HOSTNAME,
    NTP_STAGED_CONFIG_PATH,
    default_ntp_upstream_fields,
    dump_ntp_upstream_sources,
    ntp_settings_to_dict,
    ntp_upstream_sources,
    render_ntp_config,
    validate_ntp_state,
)
from atlaso.app.services.oidc import (
    OIDC_DEFAULT_HOSTNAME,
    OIDC_DNS_RECORD_DESCRIPTION,
)
from atlaso.app.services.oidc import (
    ensure_provider_settings as ensure_oidc_provider_settings,
)
from atlaso.app.services.public_services import (
    PUBLIC_SERVICES_STAGED_CONFIG_PATH,
    public_service_entries,
    public_service_interface_entries,
    public_services_for_address,
    render_public_services_nginx_config,
)
from atlaso.app.services.routes_wan import (
    WAN_CONFIG_PATH,
    WAN_MODES,
    canonical_route_destination,
    default_route_family,
    ensure_routes_wan_settings,
    generated_route_role_rules,
    mirrored_management_default_routes,
    nat_rule_to_dict,
    render_wan_config,
    route_to_dict,
    routing_rule_to_dict,
    validate_wan_state,
    wan_policy_to_dict,
)
from atlaso.app.services.service_dns_defaults import (
    appliance_domain_from_fqdn as canonical_appliance_domain_from_fqdn,
)
from atlaso.app.services.service_dns_defaults import (
    factory_service_hostname,
    reconcile_factory_service_identities,
)
from atlaso.app.services.service_registry import (
    SERVICE_STATE_IDS,
)
from atlaso.app.services.settings_archive import (
    archive_summary,
    desired_state_counts,
    export_settings_archive,
    restore_settings_archive,
)
from atlaso.app.services.update_sources import (
    ATLASO_CHANNELS,
    UPDATE_SOURCE_KINDS,
    default_source_settings,
    effective_update_settings,
    managed_package_rows,
    source_rows,
    unsynchronized_photon_repositories,
    unsynchronized_powershell_repositories,
    update_source_payload,
    update_source_settings,
    validate_managed_package,
    validate_update_source,
)
from atlaso.app.services.vaults import (
    VaultEntryInput,
    create_vault,
    kickstart_vault_marker_catalog,
    list_vaults,
    parse_vault_uris_json,
    update_vault_entry,
    upsert_vault_entry,
    vault_entry_metadata,
    vault_marker_name,
)
from atlaso.app.services.vcf_backups import (
    VCF_BACKUP_DEFAULT_USERNAME,
    VCF_BACKUP_STAGED_CONFIG_PATH,
    render_vcf_backup_config,
    validate_vcf_backup_state,
    vcf_backup_remote_directory,
    vcf_backup_service_state,
    vcf_backup_settings_to_dict,
)
from atlaso.app.services.vcf_depot_downloads import (
    acquire_vcf_depot_admission_gate,
    active_vcf_depot_download_job,
    active_vcf_depot_download_jobs,
    active_vcf_depot_exclusive_job,
    active_vcf_depot_operation_job,
    disable_vcf_depot_profile_schedules,
    vcf_depot_job_profile_id,
    vcf_depot_task_log_reference,
)
from atlaso.app.services.vcf_depot_target import (
    LocalDepotEndpoint,
    VcfDepotTargetError,
    VcfDepotTargetPartialError,
    configure_target_depot,
)
from atlaso.app.services.vcf_offline_depot import (
    VCF_DEPOT_ACTIVATION_NAME_KEY,
    VCF_DEPOT_ACTIVATION_VALUE_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
    VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
    VCF_DEPOT_ARCHIVE_PATTERN,
    VCF_DEPOT_BINARY_TYPES,
    VCF_DEPOT_COMPONENTS,
    VCF_DEPOT_DEFAULT_HOSTNAME,
    VCF_DEPOT_DEFAULT_STORE_PATH,
    VCF_DEPOT_DEFAULT_USERNAME,
    VCF_DEPOT_ESX_DISABLED_PLATFORMS,
    VCF_DEPOT_EXTRACT_DIR,
    VCF_DEPOT_LEGACY_STORE_PATH,
    VCF_DEPOT_PROFILE_TYPES,
    VCF_DEPOT_RUNTIME_RESET_PENDING_KEY,
    VCF_DEPOT_RUNTIME_TOOL_DIR,
    VCF_DEPOT_SKUS,
    VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
    VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
    VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
    VCF_DEPOT_STAGED_ACTIVATION_FILE,
    VCF_DEPOT_STAGED_APPLICATION_PROPERTIES_PATH,
    VCF_DEPOT_STAGED_CONFIG_PATH,
    VCF_DEPOT_STAGED_TOKEN_FILE,
    VCF_DEPOT_STAGED_TOOL_DIR,
    VCF_DEPOT_TOKEN_NAME_KEY,
    VCF_DEPOT_TOKEN_VALUE_KEY,
    VCF_DEPOT_TOOL_VERSION_SOURCE_COMMAND,
    VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
    VCF_DEPOT_UPLOAD_DIR,
    _find_vcf_download_tool_binary,
    _safe_extract_tar_gz,
    find_local_vcf_download_tool_archive,
    generate_vcf_software_depot_id,
    render_nginx_depot_config,
    render_vcfdt_command_preview,
    safe_archive_upload_name,
    setting_secret_state,
    staged_vcf_download_tool_version,
    validate_vcf_depot_state,
    validate_vcf_download_tool_upload_envelope,
    vcf_depot_application_properties_from_tool,
    vcf_depot_endpoint,
    vcf_depot_profile_start_blocker,
    vcf_depot_profile_to_dict,
    vcf_depot_service_state,
    vcf_depot_settings_to_dict,
    vcfdt_commands_for_profile,
)
from atlaso.app.services.vcf_private_registry import (
    VCF_REGISTRY_DEFAULT_HOSTNAME,
    VCF_REGISTRY_UPLOADED_CA_BUNDLE_NAME_KEY,
    VCF_REGISTRY_UPLOADED_CA_BUNDLE_PATH,
    VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY,
    render_harbor_config,
    render_imgpkg_relocation_preview,
    validate_vcf_registry_state,
    vcf_registry_bundle_to_dict,
    vcf_registry_endpoint,
    vcf_registry_settings_to_dict,
)
from atlaso.app.services.vcf_sddc_deployment import (
    SDDC_MANAGER_OVA_ROOT,
    VcfSddcDeploymentCancelled,
    VcfSddcDeploymentError,
    VcfSddcPostImportError,
    deploy_ova,
    inspect_ova,
    ova_inventory,
    tls_sha256_fingerprint,
)
from atlaso.app.services.vcf_trust import (
    RootCaInfo,
    VcfApiClient,
    VcfTrustCredentials,
    VcfTrustError,
    execute_vcf_trust,
    root_ca_info,
    sanitized_result,
)
from atlaso.app.services.vcf_vault_import import discover_vcf_passwords
from atlaso.app.services.vsphere_key_providers import (
    certificate_to_dict,
    provider_rows,
    provider_to_dict,
    render_client_trust_bundle,
    render_provider_config,
    runtime_status_snapshot,
    trusted_vcenter_to_dict,
    validate_provider_state,
)
from atlaso.app.ui_routes import (
    MANAGEMENT_UI_ROOT,
    PUBLIC_UI_ROOT,
    management_ui_path,
    public_ui_path,
    safe_management_return_path,
    safe_public_return_path,
)

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"
VCF_DEPOT_VDT_LOG_PATH = PurePosixPath("/var/lib/atlaso/vcfDownloadTool/active-tool/log/vdt.log")
ATLASO_APP_LOG_PATH = get_settings().app_log_path
KMS_SERVER_LOG_PATH = Path("/var/log/atlaso/kmip/server.log")
APPLY_LOGGER = logging.getLogger("atlaso.appliance_apply")
APPLIANCE_UPDATE_LOGGER = logging.getLogger("atlaso.appliance_update")
KICKSTART_REFERENCE_VALIDATION_ERROR = "Kickstart source is invalid. Review its variable and vault markers."
KICKSTART_UPLOAD_ERROR = "Kickstart upload is invalid. Review the file, name, and reference markers."
NETWORK_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/network/atlaso-network.conf"
MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH = "/var/lib/atlaso/apply/management-handoff/atlaso-management-handoff.json"
MANAGEMENT_HANDOFF_UNIT_IDS = ("ca", "network", "firewall", "appliance_settings", "public_services")
MANAGEMENT_HANDOFF_WAN_ROLLBACK_PATH = "/var/lib/atlaso/apply/wan/atlaso-wan-rollback.conf"
MANAGEMENT_HANDOFF_APPLIANCE_SETTINGS_KEYS = {
    "resolver_mode",
    "resolver_servers",
    "local_dns_enabled",
    "management_interface",
    "management_ip",
    "management_ip_cidr",
    "management_http_port",
    "management_public_http_port",
    "management_public_https_port",
    "management_upstream_host",
    "management_upstream_port",
    "management_https_enabled",
    "management_https_cert_path",
    "management_https_key_path",
    "web_terminal_interfaces",
    "web_terminal_addresses",
}
DNSMASQ_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/dnsmasq/atlaso.conf"
PUBLIC_DOCUMENTATION_URL = "https://mdaneri.github.io/Atlaso/docs/"

templates = Jinja2Templates(directory=TEMPLATES_DIR)


def management_ui_request_allowed(request: Request, db: Session) -> bool:
    """Return whether the called host may expose the management browser plane.

    Args:
        request: Incoming HTTP request.
        db: Active database session.
    """
    request_host = request_host_name(request)
    try:
        if ip_address(request_host.strip("[]")).is_loopback:
            return True
    except ValueError:
        pass
    binding = request_host_interface_binding(request_host, db)
    if binding is not None:
        return bool(binding.get("management_ui"))
    return getattr(get_settings(), "environment", "development") != "appliance"


def require_management_ui_request(request: Request, db: Session = Depends(get_db)) -> None:
    """Hide the management namespace from non-management listeners.

    Args:
        request: Incoming HTTP request.
        db: Active database session.
    """
    binding = request_host_interface_binding(request_host_name(request), db)
    request.state.management_interface_binding = binding
    if not management_ui_request_allowed(request, db):
        raise HTTPException(status_code=404, detail="Not found")


def public_ui_request_allowed(request: Request, db: Session, path: str = "") -> bool:
    """Return whether the called host may expose a requested public UI path.

    Args:
        request: Incoming HTTP request.
        db: Active database session.
        path: Public-plane path being evaluated.
    """
    binding = request_host_interface_binding(request_host_name(request), db)
    if not binding or binding.get("role") == "management":
        return False
    normalized = path or request.url.path.removeprefix(PUBLIC_UI_ROOT)
    if normalized.startswith("/ca"):
        return request_allows_public_service(db, request, "ca")
    if normalized.startswith("/terminal"):
        return request_allows_public_service(db, request, "web_terminal")
    return True


router = APIRouter(prefix=MANAGEMENT_UI_ROOT, dependencies=[Depends(require_management_ui_request)])
public_router = APIRouter(prefix=PUBLIC_UI_ROOT)
front_door_router = APIRouter()
protocol_router = APIRouter()

templates.env.globals.update(
    management_ui_path=management_ui_path,
    public_ui_path=public_ui_path,
    management_ui_root=MANAGEMENT_UI_ROOT,
    public_ui_root=PUBLIC_UI_ROOT,
)


def csrf_token(request: Request) -> str:
    """Return csrf token.

    Args:
        request: Incoming HTTP request.
    """
    token = request.session.get("csrf_token")
    if not token:
        token = token_urlsafe(24)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, token: str) -> None:
    """Validate csrf.

    Args:
        request: Incoming HTTP request.
        token: Token supplied by the caller.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not token or token != request.session.get("csrf_token"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


def render(request: Request, template: str, context: dict, status_code: int = 200) -> HTMLResponse:
    """Render operation.

    Args:
        request: Incoming HTTP request.
        template: Template supplied by the caller.
        context: Runtime or protocol context for the operation.
        status_code: HTTP status code for the response.

    Returns:
        The render result.
    """
    context = dict(context)
    identity = context.pop("identity", None)
    if identity and "sidebar_pending_apply_count" not in context:
        if "changed_apply_unit_count" in context:
            context["sidebar_pending_apply_count"] = context["changed_apply_unit_count"]
        elif isinstance(context.get("appliance_apply_status"), dict):
            context["sidebar_pending_apply_count"] = context["appliance_apply_status"].get("sidebar_pending_apply_count", 0)
        else:
            context["sidebar_pending_apply_count"] = 0
    if identity and "global_update_availability" not in context:
        try:
            with SessionLocal() as db:
                context["global_update_availability"] = appliance_update_availability_summary(db)
        except Exception:  # noqa: BLE001 - page rendering must survive unavailable optional indicator state.
            context["global_update_availability"] = {
                "available": False,
                "affected_stream_count": 0,
                "streams": [],
                "url": f"{MANAGEMENT_UI_ROOT}/appliance-update#appliance-update-streams",
            }
    return templates.TemplateResponse(
        request,
        template,
        {
            "app_name": "Atlaso",
            "identity": identity,
            "csrf_token": csrf_token(request),
            "server_time": utcnow(),
            "public_github_url": "https://github.com/mdaneri/Atlaso",
            "public_documentation_url": PUBLIC_DOCUMENTATION_URL,
            "current_version_info": current_version_info(),
            "management_ui_root": MANAGEMENT_UI_ROOT,
            "public_ui_root": PUBLIC_UI_ROOT,
            "cohosted_public_ui": bool(
                (binding := getattr(request.state, "management_interface_binding", None))
                and binding.get("role") == "access"
                and binding.get("management_ui")
            ),
            **context,
        },
        status_code=status_code,
    )


def grid_request(request: Request) -> bool:
    """Return grid request.

    Args:
        request: Incoming HTTP request.
    """
    return request.headers.get("X-Atlaso-Grid") == "1"


def grid_saved_response(
    request: Request,
    *,
    redirect_url: str,
    resource_name: str,
    resource: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> RedirectResponse | JSONResponse:
    """Return grid saved response.

    Args:
        request: Incoming HTTP request.
        redirect_url: URL for the redirect.
        resource_name: Resource name supplied by the caller.
        resource: Resource supplied by the caller.
        extra: Extra supplied by the caller.
    """
    if grid_request(request):
        return JSONResponse(
            jsonable_encoder(
                {
                    resource_name: resource,
                    **(extra or {}),
                }
            )
        )
    return RedirectResponse(redirect_url, status_code=303)


def grid_error_response(
    request: Request,
    *,
    detail: str,
    status_code: int,
    template_name: str,
    context: dict[str, Any],
) -> HTMLResponse | JSONResponse:
    """Return grid error response.

    Args:
        request: Incoming HTTP request.
        detail: Detail supplied by the caller.
        status_code: HTTP status code for the response.
        template_name: Template name supplied by the caller.
        context: Runtime or protocol context for the operation.
    """
    if grid_request(request):
        return JSONResponse({"detail": detail}, status_code=status_code)
    return render(request, template_name, context, status_code=status_code)


def require_admin_identity(identity: Identity) -> None:
    """Handle require admin identity.

    Args:
        identity: Authenticated identity authorizing the request.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not identity.has_role("admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required")


def require_certificate_workflow_identity(identity: Identity) -> None:
    """Handle require certificate workflow identity.

    Args:
        identity: Authenticated identity authorizing the request.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not (identity.has_role(Role.ADMIN.value) or identity.has_role(Role.CERTIFICATE_OPERATOR.value)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Certificate operator role required")


def require_vcf_helper_write(identity: Identity) -> None:
    """Handle require vcf helper write.

    Args:
        identity: Authenticated identity authorizing the request.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not (identity.has_role(Role.ADMIN.value) or identity.has_role(Role.SERVICE_ADMIN.value)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Service administrator role required")


def roles_from_form(primary_role_value: str = "", roles: list[str] | None = None, roles_text: str = "") -> list[str]:
    """Return roles from form.

    Args:
        primary_role_value: Primary role value consumed by roles from form.
        roles: Normalized Atlaso roles granted or required by the operation.
        roles_text: Roles text consumed by roles from form.
    """
    values: list[str] = []
    if roles_text.strip():
        values.extend(roles_text.replace(",", "\n").splitlines())
    else:
        for value in roles or []:
            values.extend(str(value).replace(",", "\n").splitlines())
    if not values and primary_role_value:
        values.append(primary_role_value)
    return normalize_roles(values)


def require_monitoring_read(identity: Identity) -> None:
    """Handle require monitoring read.

    Args:
        identity: Authenticated identity authorizing the request.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not identity.can("read:monitoring"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Monitoring read permission required")


def local_user_os_statuses(users: list[User], policy: dict[str, bool | int]) -> dict[str, dict[str, Any]]:
    """Return local user os statuses.

    Args:
        users: Users consumed by local user operating-system statuses.
        policy: Policy consumed by local user operating-system statuses.
    """
    statuses: dict[str, dict[str, Any]] = {}
    adapter = SystemAdapter()
    if adapter.dry_run or not hasattr(adapter, "local_users_status"):
        return statuses
    apply_path = Path(LOCAL_USERS_STAGED_CONFIG_PATH)
    status_path = apply_path.with_name(f".{apply_path.stem}.status-{uuid4().hex}{apply_path.suffix}")
    try:
        config_path = stage_appliance_apply_config(str(status_path), render_local_users_preview(users, password_policy=policy))
        result = adapter.local_users_status(config_path)
    except OSError:
        result = None
    finally:
        status_path.unlink(missing_ok=True)
    if result is None or result.returncode != 0:
        return statuses
    payload: dict[str, Any] | None = None
    for raw_line in reversed((result.stdout or "").splitlines()):
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("users"), list):
            payload = parsed
            break
    if payload is None:
        return statuses
    for row in payload.get("users", []):
        if not isinstance(row, dict):
            continue
        username = str(row.get("username") or "").strip().lower()
        if username:
            statuses[username] = row
    return statuses


def user_to_dict(user: User, current_user_id: int | None = None, os_status: dict[str, Any] | None = None) -> dict:
    """Return user to dict.

    Args:
        user: User record or identity affected by the operation.
        current_user_id: Current user identifier inspected by the operation.
        os_status: Operating-system status consumed by user to dict.
    """
    os_state = str((os_status or {}).get("state") or "status unavailable")
    os_detail = str((os_status or {}).get("detail") or "")
    return {
        "id": user.id,
        "username": user.username,
        "description": user.description or "",
        "role": primary_role(user_roles(user)),
        "roles": user_roles(user),
        "roles_label": role_label(user_roles(user)),
        "roles_text": ", ".join(user_roles(user)),
        "auth_provider": user.auth_provider or "local",
        "shell": normalize_user_shell(user.shell),
        "web_terminal_access": bool(user.web_terminal_access),
        "enabled": user.enabled,
        "created_at": user.created_at.strftime("%Y-%m-%d"),
        "os_sync_status": local_user_sync_rows([user])[0]["sync_status"],
        "os_password_pending": has_pending_os_password(user),
        "os_password_available": bool(has_pending_os_password(user) or user.os_password_applied_at),
        "os_account_state": os_state,
        "os_account_detail": os_detail,
        "os_unlock_available": os_state in {"locked", "faillock blocked"},
        "unlock_requested": bool(user.os_unlock_requested_at),
        "is_current": user.id == current_user_id,
        "is_new": False,
    }


def local_users_password_policy(db: Session) -> dict[str, bool | int]:
    """Return local users password policy.

    Args:
        db: Active database session.
    """
    return password_policy_from_json(setting_value(db, LOCAL_USERS_PASSWORD_POLICY_KEY))


def users_context(db: Session, identity: Identity) -> dict:
    """Return users context.

    Args:
        db: Active database session.
        identity: Authenticated identity authorizing the request.
    """
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    policy = local_users_password_policy(db)
    os_statuses = local_user_os_statuses(users, policy)
    return {
        "users": users,
        "users_json": [user_to_dict(user, identity.user_id, os_statuses.get(user.username.strip().lower())) for user in users],
        "roles": [role.value for role in Role],
        "shells": LOCAL_USER_SHELLS,
        "password_policy": policy,
        "password_policy_summary": password_policy_summary(policy),
        "local_user_sync_rows": local_user_sync_rows(users),
        "local_user_os_statuses": os_statuses,
    }


def enabled_admin_count(db: Session) -> int:
    """Return enabled admin count.

    Args:
        db: Active database session.
    """
    users = db.execute(select(User).where(User.enabled.is_(True))).scalars().all()
    return len([user for user in users if Role.ADMIN.value in user_roles(user)])


def protect_last_admin(db: Session, user: User, *, next_roles: list[str] | None = None, next_enabled: bool | None = None) -> None:
    """Handle protect last admin.

    Args:
        db: Active database session.
        user: Local or directory user affected by the operation.
        next_roles: Next roles supplied by the caller.
        next_enabled: Next enabled supplied by the caller.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    roles = normalize_roles(next_roles) if next_roles is not None else user_roles(user)
    enabled = next_enabled if next_enabled is not None else user.enabled
    if Role.ADMIN.value in user_roles(user) and user.enabled and (Role.ADMIN.value not in roles or not enabled) and enabled_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="At least one enabled local administrator must remain.")


def revoke_user_tokens(db: Session, user: User, actor: str) -> None:
    """Handle revoke user tokens.

    Args:
        db: Active database session.
        user: Local or directory user affected by the operation.
        actor: Authenticated identity attributed to the audit record.
    """
    tokens = db.execute(
        select(ApiToken).where(ApiToken.owner_user_id == user.id, ApiToken.revoked_at.is_(None), ApiToken.enabled.is_(True))
    ).scalars().all()
    for token in tokens:
        token.enabled = False
        token.revoked_at = utcnow()
        token.revoked_by = actor
        db.add(token)


def disable_default_vcf_backup_user_when_service_off(db: Session, settings: VcfBackupSettings, *, actor: str | None = None) -> bool:
    """Return disable default vcf backup user when service off.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
    """
    if settings.enabled or not settings.sftp_user_id:
        return False
    user = db.get(User, settings.sftp_user_id)
    if user is None or user.username != VCF_BACKUP_DEFAULT_USERNAME or not user.enabled:
        return False
    user.enabled = False
    user.os_sync_status = "pending"
    user.os_unlock_requested_at = None
    if actor:
        revoke_user_tokens(db, user, actor)
    db.add(user)
    return True


def disable_default_vcf_depot_user_when_service_off(db: Session, settings: VcfOfflineDepotSettings, *, actor: str | None = None) -> bool:
    """Return disable default vcf depot user when service off.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
    """
    if settings.enabled or not settings.http_user_id:
        return False
    user = db.get(User, settings.http_user_id)
    if user is None or user.username != VCF_DEPOT_DEFAULT_USERNAME or not user.enabled:
        return False
    user.enabled = False
    user.os_sync_status = "pending"
    user.os_unlock_requested_at = None
    if actor:
        revoke_user_tokens(db, user, actor)
    db.add(user)
    return True


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


def get_appliance_settings_row(db: Session) -> ApplianceSettings:
    """Return appliance settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    if settings is None:
        settings = ApplianceSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    normalized_naming = normalize_service_dns_target_naming(settings.service_dns_target_naming)
    if settings.service_dns_target_naming != normalized_naming:
        settings.service_dns_target_naming = normalized_naming
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


def get_ca_settings_row(db: Session) -> CaSettings:
    """Return ca settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(CaSettings)).scalar_one_or_none()
    if settings is None:
        settings = CaSettings(
            portal_hostname=factory_service_hostname(
                "ca", get_appliance_settings_row(db).fqdn
            )
        )
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def ca_service_cert_paths(service_dir: str, certificate_name: str) -> tuple[str, str, str]:
    """Return ca service cert paths.

    Args:
        service_dir: Service dir consumed by CA service cert paths.
        certificate_name: Certificate name consumed by CA service cert paths.
    """
    safe_name = safe_certificate_name(certificate_name)
    base = f"/etc/atlaso/{service_dir}/certs/{safe_name}"
    return f"{base}.crt", f"{base}.key", f"{base}-chain.pem"


def ntp_nts_certificate_paths(settings: NtpSettings) -> tuple[str, str, str]:
    """Return ntp nts certificate paths.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    hostname = normalize_dns_hostname(settings.hostname or NTP_DEFAULT_HOSTNAME)
    return ca_service_cert_paths("ntp", hostname)


def remove_ntp_nts_certificate_rows(db: Session) -> int:
    """Remove ntp nts certificate rows.

    Args:
        db: Active database session.

    Returns:
        The remove ntp nts certificate rows result.
    """
    certificates = db.execute(
        select(CaCertificate).where(CaCertificate.managed_owner == "ntp:nts")
    ).scalars().all()
    for certificate in certificates:
        db.delete(certificate)
    return len(certificates)


def managed_ca_certificate_specs(db: Session) -> list[ManagedCertificateSpec]:
    """Return managed ca certificate specs.

    Args:
        db: Active database session.
    """
    specs: list[ManagedCertificateSpec] = []
    appliance = get_appliance_settings_row(db)
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    management, observed_dhcp_dns_servers = management_dhcp_dns_context(interfaces)
    terminal_options = web_terminal_interface_options(interfaces, vlans)
    terminal_ips = web_terminal_addresses(normalized_web_terminal_interfaces(appliance, management), terminal_options) if appliance.web_terminal_enabled else []
    appliance_ips = management_ui_addresses(db)
    appliance_ips.extend(address for address in terminal_ips if address not in appliance_ips)
    appliance_cert, appliance_key, appliance_chain = ca_service_cert_paths("https", appliance.fqdn)
    specs.append(
        ManagedCertificateSpec(
            owner="appliance:https",
            common_name=appliance.fqdn,
            dns_names=[appliance.fqdn],
            ip_addresses=appliance_ips,
            profile_name=CA_SERVER_PROFILE_NAME,
            description="Managed Atlaso appliance HTTPS certificate.",
            cert_path=appliance_cert,
            key_path=appliance_key,
            chain_path=appliance_chain,
        )
    )

    oidc_settings = ensure_oidc_provider_settings(db)
    if oidc_settings.enabled:
        oidc_hostname = normalize_dns_hostname(
            oidc_settings.hostname or OIDC_DEFAULT_HOSTNAME
        )
        cert_path, key_path, chain_path = ca_service_cert_paths(
            "oidc", oidc_hostname
        )
        specs.append(
            ManagedCertificateSpec(
                owner="oidc:https",
                common_name=oidc_hostname,
                dns_names=[oidc_hostname],
                ip_addresses=split_addresses(oidc_settings.listen_address),
                profile_name=CA_SERVER_PROFILE_NAME,
                description="Managed OpenID Connect provider HTTPS certificate.",
                cert_path=cert_path,
                key_path=key_path,
                chain_path=chain_path,
            )
        )

    ca_settings = get_ca_settings_row(db)
    if ca_settings.enabled:
        ca_portal_hostname = normalize_dns_hostname(ca_settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME)
        cert_path, key_path, chain_path = ca_service_cert_paths("ca-portal", ca_portal_hostname)
        specs.append(
            ManagedCertificateSpec(
                owner="ca_portal:https",
                common_name=ca_portal_hostname,
                dns_names=[ca_portal_hostname],
                ip_addresses=split_addresses(ca_settings.listen_address),
                profile_name=CA_SERVER_PROFILE_NAME,
                description="Managed CA portal HTTPS certificate.",
                cert_path=cert_path,
                key_path=key_path,
                chain_path=chain_path,
            )
        )

    kms_settings = get_kms_settings_row(db)
    if kms_settings.enabled:
        cert_path, key_path, chain_path = ca_service_cert_paths("kmip", kms_settings.server_certificate or kms_settings.hostname)
        specs.append(
            ManagedCertificateSpec(
                owner="kms:server",
                common_name=kms_settings.hostname,
                dns_names=[kms_settings.hostname],
                ip_addresses=split_addresses(kms_settings.listen_address),
                profile_name=CA_SERVER_PROFILE_NAME,
                description="Managed KMS/KMIP server TLS certificate.",
                cert_path=cert_path,
                key_path=key_path,
                chain_path=chain_path,
            )
        )
    ldap_settings = get_ldap_settings_row(db)
    if ldap_settings.enabled and ldap_settings.ldaps_enabled:
        _ldap_interfaces, ldap_certificate_addresses = resolve_ldap_bind_targets(
            db,
            split_interfaces(ldap_settings.listen_interface),
            current_interface=ldap_settings.listen_interface,
            listen_interfaces_present="1",
        )
        specs.append(
            ManagedCertificateSpec(
                owner="ldap:ldaps",
                common_name=ldap_settings.hostname,
                dns_names=[ldap_settings.hostname],
                ip_addresses=split_addresses(ldap_certificate_addresses),
                profile_name=CA_SERVER_PROFILE_NAME,
                description="Managed OpenLDAP LDAPS server certificate.",
                cert_path=LDAP_CERT_PATH,
                key_path=LDAP_KEY_PATH,
                chain_path=LDAP_CHAIN_PATH,
            )
        )

    ntp_settings = get_ntp_settings_row(db)
    if ntp_settings.nts_server_enabled:
        cert_path, key_path, chain_path = ntp_nts_certificate_paths(ntp_settings)
        specs.append(
            ManagedCertificateSpec(
                owner="ntp:nts",
                common_name=normalize_dns_hostname(ntp_settings.hostname or NTP_DEFAULT_HOSTNAME),
                dns_names=[normalize_dns_hostname(ntp_settings.hostname or NTP_DEFAULT_HOSTNAME)],
                ip_addresses=split_addresses(ntp_settings.listen_address),
                profile_name=CA_SERVER_PROFILE_NAME,
                description="Managed NTPsec NTS server certificate.",
                cert_path=cert_path,
                key_path=key_path,
                chain_path=chain_path,
            )
        )

    depot_settings = get_vcf_offline_depot_settings_row(db)
    if depot_settings.enabled:
        cert_path, key_path, chain_path = ca_service_cert_paths("vcf-offline-depot", depot_settings.server_certificate or depot_settings.hostname)
        specs.append(
            ManagedCertificateSpec(
                owner="vcf_offline_depot:https",
                common_name=depot_settings.hostname,
                dns_names=[depot_settings.hostname],
                ip_addresses=[depot_settings.listen_address] if depot_settings.listen_address else [],
                profile_name=CA_SERVER_PROFILE_NAME,
                description="Managed VCF Offline Depot HTTPS certificate.",
                cert_path=cert_path,
                key_path=key_path,
                chain_path=chain_path,
            )
        )

    registry_settings = get_vcf_private_registry_settings_row(db)
    if registry_settings.enabled:
        cert_path, key_path, chain_path = ca_service_cert_paths("harbor", registry_settings.server_certificate or registry_settings.hostname)
        specs.append(
            ManagedCertificateSpec(
                owner="vcf_private_registry:https",
                common_name=registry_settings.hostname,
                dns_names=[registry_settings.hostname],
                ip_addresses=[registry_settings.listen_address] if registry_settings.listen_address else [],
                profile_name=CA_SERVER_PROFILE_NAME,
                description="Managed VCF Private Registry HTTPS certificate.",
                cert_path=cert_path,
                key_path=key_path,
                chain_path=chain_path,
            )
        )
    return specs


def ca_certificate_available(db: Session, owner: str) -> bool:
    """Return ca certificate available.

    Args:
        db: Active database session.
        owner: Owner supplied by the caller.
    """
    certificate = managed_certificate_for_owner(db, owner)
    return bool(certificate and certificate.status == "issued" and certificate.certificate_pem and certificate.private_key_encrypted)


def ca_managed_certificate_paths(db: Session, owner: str) -> tuple[str, str, str]:
    """Return ca managed certificate paths.

    Args:
        db: Active database session.
        owner: Owner supplied by the caller.
    """
    certificate = managed_certificate_for_owner(db, owner)
    if certificate is None or certificate.status != "issued":
        return "", "", ""
    return certificate.cert_path or "", certificate.key_path or "", certificate.chain_path or ""


def ensure_ca_state(db: Session, *, commit: bool = True) -> list[str]:
    """Ensure ca state.

    Args:
        db: Active database session.
        commit: Whether to commit reconciled CA state before returning.

    Returns:
        The ensure ca state result.
    """
    settings = get_ca_settings_row(db)
    errors: list[str] = []
    try:
        changed = ensure_default_ca_profiles(db)
        profiles = db.execute(select(CaProfile).order_by(CaProfile.name)).scalars().all()
        normalized_portal_hostname = normalize_dns_hostname(settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME)
        if normalized_portal_hostname != settings.portal_hostname:
            settings.portal_hostname = normalized_portal_hostname
            changed = True
        changed = ensure_root_ca_material(settings) or changed
        changed = ensure_managed_certificate_rows(db, settings=settings, profiles=profiles, specs=managed_ca_certificate_specs(db)) or changed
        certificates = (
            db.execute(select(CaCertificate).options(selectinload(CaCertificate.profile)).order_by(CaCertificate.common_name))
            .scalars()
            .all()
        )
        changed = ensure_ca_issued_state(db, settings=settings, profiles=profiles, certificates=certificates) or changed
        if changed:
            if commit:
                db.commit()
            else:
                db.flush()
    except IntegrityError as exc:
        db.rollback()
        if "ca_certificates.managed_owner" not in str(exc):
            raise
    except ValueError as exc:
        db.rollback()
        errors.append(str(exc))
    return errors


def get_kms_settings_row(db: Session) -> KmsSettings:
    """Return kms settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(KmsSettings)).scalar_one_or_none()
    if settings is None:
        hostname = factory_service_hostname(
            "kms", get_appliance_settings_row(db).fqdn
        )
        settings = KmsSettings(hostname=hostname, server_certificate=hostname)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_ldap_settings_row(db: Session) -> LdapSettings:
    """Return ldap settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(LdapSettings)).scalar_one_or_none()
    if settings is None:
        settings = LdapSettings(
            hostname=factory_service_hostname(
                "ldap", get_appliance_settings_row(db).fqdn
            ),
            port=LDAP_DEFAULT_PORT,
            config_path=LDAP_STAGED_CONFIG_PATH,
        )
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_ntp_settings_row(db: Session) -> NtpSettings:
    """Return ntp settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(NtpSettings)).scalar_one_or_none()
    if settings is None:
        ntp_upstreams = default_ntp_upstream_fields()
        settings = NtpSettings(
            hostname=factory_service_hostname(
                "ntp", get_appliance_settings_row(db).fqdn
            ),
            upstream_servers=ntp_upstreams["upstream_servers"],
            upstream_sources_json=ntp_upstreams["upstream_sources_json"],
            config_path=NTP_STAGED_CONFIG_PATH,
        )
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_firewall_settings_row(db: Session) -> FirewallSettings:
    """Return firewall settings row.

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


def get_vcf_backup_settings_row(db: Session, *, reconcile_default_user: bool = True) -> VcfBackupSettings:
    """Return vcf backup settings row.

    Args:
        db: Active database session.
        reconcile_default_user: Reconcile default user supplied by the caller.
    """
    settings = db.execute(select(VcfBackupSettings).options(selectinload(VcfBackupSettings.sftp_user))).scalar_one_or_none()
    if settings is None:
        first_admin = db.execute(select(User).where(User.role == Role.ADMIN.value, User.enabled.is_(True)).order_by(User.username)).scalar_one_or_none()
        settings = VcfBackupSettings(sftp_user_id=first_admin.id if first_admin else None)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_vcf_private_registry_settings_row(db: Session, *, reconcile: bool = True) -> VcfPrivateRegistrySettings:
    """Return vcf private registry settings row.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = db.execute(select(VcfPrivateRegistrySettings)).scalar_one_or_none()
    if settings is None:
        hostname = factory_service_hostname(
            "registry", get_appliance_settings_row(db).fqdn
        )
        settings = VcfPrivateRegistrySettings(
            hostname=hostname,
            server_certificate=hostname,
        )
        if reconcile:
            db.add(settings)
            db.commit()
            db.refresh(settings)
    return settings


def get_vcf_offline_depot_settings_row(
    db: Session,
    *,
    reconcile_default_user: bool = True,
    reconcile: bool = True,
) -> VcfOfflineDepotSettings:
    """Return vcf offline depot settings row.

    Args:
        db: Active database session.
        reconcile_default_user: Reconcile default user supplied by the caller.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = db.execute(select(VcfOfflineDepotSettings).options(selectinload(VcfOfflineDepotSettings.http_user))).scalar_one_or_none()
    default_user = db.execute(select(User).where(User.username == VCF_DEPOT_DEFAULT_USERNAME).order_by(User.username)).scalar_one_or_none()
    if settings is None:
        hostname = factory_service_hostname(
            "depot", get_appliance_settings_row(db).fqdn
        )
        settings = VcfOfflineDepotSettings(
            hostname=hostname,
            server_certificate=hostname,
            http_user_id=default_user.id if default_user else None,
        )
        if reconcile:
            db.add(settings)
            db.commit()
            db.refresh(settings)
    elif reconcile and not settings.http_user_id and default_user is not None:
        settings.http_user_id = default_user.id
        settings.updated_at = utcnow()
        db.commit()
        db.refresh(settings)
    if reconcile and settings.depot_store_path == VCF_DEPOT_LEGACY_STORE_PATH:
        settings.depot_store_path = VCF_DEPOT_DEFAULT_STORE_PATH
        settings.updated_at = utcnow()
        db.commit()
        db.refresh(settings)
    if reconcile and settings.tool_archive_path and settings.tool_version:
        version_source = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOOL_VERSION_SOURCE_KEY)).scalar_one_or_none()
        if not version_source or version_source.value != VCF_DEPOT_TOOL_VERSION_SOURCE_COMMAND:
            settings.tool_version = ""
            settings.updated_at = utcnow()
            db.commit()
            db.refresh(settings)
    if reconcile and not settings.tool_archive_path:
        archive = find_local_vcf_download_tool_archive()
        if archive is not None:
            settings.tool_archive_path = str(archive)
            settings.tool_version = ""
            settings.updated_at = utcnow()
            db.commit()
            db.refresh(settings)
    if reconcile and not settings.tool_archive_path:
        stale_credentials = db.execute(
            select(Setting).where(
                Setting.key.in_(
                    [
                        VCF_DEPOT_TOKEN_NAME_KEY,
                        VCF_DEPOT_TOKEN_VALUE_KEY,
                        VCF_DEPOT_ACTIVATION_NAME_KEY,
                        VCF_DEPOT_ACTIVATION_VALUE_KEY,
                    ]
                )
            )
        ).scalars().all()
        if stale_credentials:
            for credential in stale_credentials:
                db.delete(credential)
            set_setting_value(db, VCF_DEPOT_RUNTIME_RESET_PENDING_KEY, "1")
            db.commit()
        runtime_tool_path = Path(VCF_DEPOT_RUNTIME_TOOL_DIR) / "vcf-download-tool"
        if runtime_tool_path.exists() and not setting_value(db, VCF_DEPOT_RUNTIME_RESET_PENDING_KEY):
            set_setting_value(db, VCF_DEPOT_RUNTIME_RESET_PENDING_KEY, "1")
            db.commit()
    return settings


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


def cidr_for_family(value: str, version: int, label: str) -> Response | str:
    """Return cidr for family.

    Args:
        value: Candidate value consumed by CIDR for family.
        version: Atlaso or artifact version being validated or produced.
        label: Human-readable label used to identify the result.
    """
    candidate = value.strip()
    if not candidate:
        return ""
    try:
        parsed = ip_interface(candidate)
    except ValueError:
        return Response(f"{label} must be a valid address and prefix.", status_code=409, media_type="text/plain")
    if parsed.version != version:
        family = "IPv4" if version == 4 else "IPv6"
        return Response(f"{label} must use an {family} address and prefix.", status_code=409, media_type="text/plain")
    return candidate


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


def service_bind_options(db: Session) -> list[dict]:
    """Return service bind options.

    Args:
        db: Active database session.
    """
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(
        select(VlanInterface).where(VlanInterface.enabled.is_(True)).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    interfaces_by_name = {interface.name: interface for interface in physical_interfaces}
    options: list[dict[str, str]] = []
    for interface in physical_interfaces:
        if interface.oper_state == "missing":
            continue
        mode = normalize_interface_mode(interface.mode)
        role = normalize_interface_role(interface.role)
        addresses = interface_addresses_from_cidrs(interface.ip_cidr, interface.ipv6_cidr)
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
                "ipv4_address": address_from_cidr(interface.ip_cidr),
                "ipv4_prefix": prefix_from_cidr(interface.ip_cidr),
                "ipv6_address": address_from_cidr(interface.ipv6_cidr),
                "ipv6_prefix": prefix_from_cidr(interface.ipv6_cidr),
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


def ldap_service_bind_options(db: Session) -> list[dict[str, Any]]:
    """Return ldap service bind options.

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
        mode = normalize_interface_mode(interface.mode)
        role = normalize_interface_role(interface.role)
        ipv4_cidr = interface.host_ip_cidr if interface.ipv4_method == "dhcp" else interface.ip_cidr
        ipv6_cidr = interface.ipv6_cidr or interface.host_ipv6_cidr
        addresses = interface_addresses_from_cidrs(ipv4_cidr, ipv6_cidr)
        if interface.oper_state == "missing" or interface.admin_state == "down" or role in {"management", "unused"} or mode == "trunk" or not addresses:
            continue
        options.append(
            {
                "name": interface.name,
                "label": f"{interface.name} - {role} / {mode} / {' / '.join(addresses)}",
                "role": role,
                "address": addresses[0],
                "addresses": addresses,
            }
        )
    for vlan in vlan_interfaces:
        parent = interfaces_by_name.get(vlan.parent_interface)
        role = normalize_interface_role(vlan.role)
        addresses = interface_addresses_from_cidrs(vlan.ip_cidr, vlan.ipv6_cidr)
        if (parent and (parent.oper_state == "missing" or parent.admin_state == "down")) or role in {"management", "unused"} or not addresses:
            continue
        options.append(
            {
                "name": vlan.name,
                "label": f"{vlan.name} - VLAN {vlan.vlan_id} on {vlan.parent_interface} / {role} / {' / '.join(addresses)}",
                "role": role,
                "address": addresses[0],
                "addresses": addresses,
            }
        )
    return options


def resolve_ldap_bind_targets(
    db: Session,
    listen_interfaces: list[str],
    *,
    current_interface: str = "",
    listen_interfaces_present: str | None = None,
) -> tuple[str, str]:
    """Return ldap bind targets.

    Args:
        db: Active database session.
        listen_interfaces: Interfaces on which the service should listen.
        current_interface: Current interface supplied by the caller.
        listen_interfaces_present: Whether the caller supplied listen interfaces.
    """
    options = ldap_service_bind_options(db)
    options_by_name = {option["name"]: option for option in options}
    selected = split_interfaces(join_interfaces(listen_interfaces))
    if listen_interfaces_present is None and not selected:
        selected = split_interfaces(current_interface)
    selected = [interface for interface in selected if interface in options_by_name]
    addresses: list[str] = []
    for interface in selected:
        for address in options_by_name[interface]["addresses"]:
            if address not in addresses:
                addresses.append(address)
    return join_interfaces(selected), join_addresses(addresses)


def vcf_depot_service_bind_options(db: Session) -> list[dict[str, Any]]:
    """Return vcf depot service bind options.

    Args:
        db: Active database session.
    """
    return service_bind_options(db)


def _network_from_cidr(value: str | None):
    """Return network from cidr.

    Args:
        value: Candidate value consumed by network from CIDR.
    """
    if not value:
        return None
    try:
        return ip_network(value, strict=False)
    except ValueError:
        return None


def resolve_single_service_bind(db: Session, listen_interface: str, listen_address: str) -> tuple[str, str]:
    """Return single service bind.

    Args:
        db: Active database session.
        listen_interface: Interface on which the service should listen.
        listen_address: Address on which the service should listen.
    """
    options = service_bind_options(db)
    options_by_name = {option["name"]: option for option in options}
    selected_interface = listen_interface.strip()
    selected_address = listen_address.strip()
    if selected_address:
        address_match = next((option for option in options if option["address"] == selected_address), None)
        if address_match and (not selected_interface or selected_interface not in options_by_name or options_by_name[selected_interface]["address"] != selected_address):
            selected_interface = address_match["name"]
    if selected_interface in options_by_name:
        return selected_interface, join_addresses(options_by_name[selected_interface].get("addresses", []))
    return selected_interface, ""


def normalize_service_bind_settings(db: Session, settings: Any) -> bool:
    """Normalize service bind settings.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.

    Returns:
        The normalize service bind settings result.
    """
    selected_interfaces, selected_addresses = resolve_service_bind_targets(
        db,
        [],
        [],
        current_interface=str(getattr(settings, "listen_interface", "") or ""),
        current_address=str(getattr(settings, "listen_address", "") or ""),
        listen_addresses_present="1",
    )
    changed = False
    if selected_interfaces != (getattr(settings, "listen_interface", "") or ""):
        settings.listen_interface = selected_interfaces
        changed = True
    if selected_addresses != (getattr(settings, "listen_address", "") or ""):
        settings.listen_address = selected_addresses
        changed = True
    if changed and hasattr(settings, "updated_at"):
        settings.updated_at = utcnow()
    return changed


def resolve_service_bind_targets(
    db: Session,
    listen_interfaces: list[str],
    listen_addresses: list[str],
    *,
    current_interface: str = "",
    current_address: str = "",
    listen_interfaces_present: str | None = None,
    listen_addresses_present: str | None = None,
) -> tuple[str, str]:
    """Return service bind targets.

    Args:
        db: Active database session.
        listen_interfaces: Interfaces on which the service should listen.
        listen_addresses: Addresses on which the service should listen.
        current_interface: Current interface supplied by the caller.
        current_address: Current address supplied by the caller.
        listen_interfaces_present: Whether the caller supplied listen interfaces.
        listen_addresses_present: Whether the caller supplied listen addresses.
    """
    options = service_bind_options(db)
    options_by_name = {option["name"]: option for option in options}

    selected_interfaces = split_interfaces(join_interfaces(listen_interfaces))
    if listen_interfaces_present is None and not selected_interfaces:
        selected_interfaces = split_interfaces(current_interface)
    selected_interfaces = [interface for interface in selected_interfaces if interface in options_by_name]

    derived_addresses: list[str] = []
    for interface in selected_interfaces:
        for address in options_by_name[interface].get("addresses", []):
            if address and address not in derived_addresses:
                derived_addresses.append(address)
    if not selected_interfaces and listen_addresses_present is None:
        for address in split_addresses(current_address):
            if address and address not in derived_addresses:
                derived_addresses.append(address)

    return join_interfaces(selected_interfaces), join_addresses(derived_addresses)


def primary_listen_address(raw_address: str | None) -> str:
    """Return primary listen address.

    Args:
        raw_address: Raw address consumed by primary listen address.
    """
    addresses = split_addresses(raw_address)
    return addresses[0] if addresses else ""


def primary_listen_interface(raw_interface: str | None) -> str:
    """Return primary listen interface.

    Args:
        raw_interface: Raw interface consumed by primary listen interface.
    """
    interfaces = split_interfaces(raw_interface)
    return interfaces[0] if interfaces else ""


def service_bind_label(raw_interface: str | None, raw_address: str | None) -> str:
    """Return service bind label.

    Args:
        raw_interface: Raw interface consumed by service bind label.
        raw_address: Raw address consumed by service bind label.
    """
    interfaces = split_interfaces(raw_interface)
    addresses = split_addresses(raw_address)
    if not interfaces and not addresses:
        return "not selected"
    interface_label = ", ".join(interfaces) if interfaces else "no interface"
    address_label = ", ".join(addresses) if addresses else "no interface IP"
    return f"{interface_label} / {address_label}"


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


def vcf_backup_context(db: Session, *, reconcile: bool = True) -> dict:
    """Return vcf backup context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = get_vcf_backup_settings_row(db, reconcile_default_user=reconcile)
    if reconcile and normalize_service_bind_settings(db, settings):
        db.commit()
        db.refresh(settings)
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    available_interfaces = service_bind_options(db)
    config_preview = render_vcf_backup_config(settings)
    validation_errors = validate_vcf_backup_state(settings, users, {interface["name"] for interface in available_interfaces})
    return {
        "vcf_backup_settings": settings,
        "vcf_backup_settings_json": vcf_backup_settings_to_dict(settings),
        "vcf_backup_users": users,
        "available_interfaces": available_interfaces,
        "selected_vcf_backup_interfaces": split_interfaces(settings.listen_interface),
        "selected_vcf_backup_addresses": split_addresses(settings.listen_address),
        "available_vcf_backup_addresses": available_service_listen_addresses(settings.listen_address, available_interfaces),
        "vcf_backup_primary_listen_address": primary_listen_address(settings.listen_address),
        "vcf_backup_bind_label": service_bind_label(settings.listen_interface, settings.listen_address),
        "vcf_backup_remote_directory": vcf_backup_remote_directory(settings),
        "vcf_backup_config_preview": config_preview,
        "vcf_backup_validation_errors": validation_errors,
        "vcf_backup_service_status": vcf_backup_service_state(settings, sshd_active=backing_systemd_unit_active("sshd.service")),
    }


def ntpd_capabilities_payload(result: AdapterResult) -> dict[str, Any]:
    """Return ntpd capabilities payload.

    Args:
        result: Operation result being inspected or returned.
    """
    if result.returncode != 0:
        return {}
    text = result.stdout or ""
    decoder = json.JSONDecoder()
    index = 0
    capabilities: dict[str, Any] = {}
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            payload, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            return {}
        if isinstance(payload, dict) and "nts" in payload:
            capabilities = payload
    return capabilities


def ntp_context(db: Session, *, include_runtime_health: bool = False, reconcile: bool = True) -> dict:
    """Return ntp context.

    Args:
        db: Active database session.
        include_runtime_health: Include runtime health supplied by the caller.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = get_ntp_settings_row(db)
    if reconcile and normalize_service_bind_settings(db, settings):
        db.commit()
        db.refresh(settings)
    capability_result = SystemAdapter().read_ntpd_capabilities()
    ntp_capabilities = ntpd_capabilities_payload(capability_result)
    ntp_nts_capability_known = "nts" in ntp_capabilities
    ntp_nts_supported = ntp_capabilities.get("nts") is True
    if ntp_nts_capability_known and not ntp_nts_supported:
        upstream_sources = ntp_upstream_sources(settings)
        nts_state_changed = settings.nts_server_enabled or any(bool(source.get("use_nts")) for source in upstream_sources)
        if reconcile and nts_state_changed:
            for source in upstream_sources:
                source["use_nts"] = False
            settings.nts_server_enabled = False
            settings.nts_server_cert_path = ""
            settings.nts_server_key_path = ""
            settings.upstream_sources_json = dump_ntp_upstream_sources(upstream_sources)
            settings.upstream_servers = join_servers([str(source["source"]) for source in upstream_sources if source.get("enabled")])
            settings.updated_at = utcnow()
            db.add(settings)
            remove_ntp_nts_certificate_rows(db)
            db.commit()
            db.refresh(settings)
            record_audit(
                db,
                actor="system",
                action="disable_unsupported_ntp_nts",
                resource_type="ntpd",
                resource_id=str(settings.id),
                detail="Installed ntpd does not include NTS support; NTS server and upstream flags were disabled.",
            )
    available_interfaces = service_bind_options(db)
    ntp_nts_cert_path, ntp_nts_key_path, ntp_nts_chain_path = ntp_nts_certificate_paths(settings)
    if reconcile and settings.nts_server_enabled:
        settings.nts_server_cert_path = ntp_nts_chain_path
        settings.nts_server_key_path = ntp_nts_key_path
        settings.nts_ke_port = 4460
    elif reconcile:
        removed_certificates = remove_ntp_nts_certificate_rows(db)
        certificate_state_changed = bool(
            settings.nts_server_cert_path or settings.nts_server_key_path or removed_certificates
        )
        settings.nts_server_cert_path = ""
        settings.nts_server_key_path = ""
        if certificate_state_changed:
            settings.updated_at = utcnow()
            db.add(settings)
            db.commit()
            db.refresh(settings)
    config_preview = render_ntp_config(settings)
    ca_state_errors = ensure_ca_state(db) if reconcile and settings.nts_server_enabled else []
    validation_errors = [*ca_state_errors, *validate_ntp_state(settings, {interface["name"] for interface in available_interfaces})]
    if settings.nts_server_enabled:
        ca_settings = get_ca_settings_row(db)
        if not ca_settings.enabled:
            validation_errors.append("NTPsec NTS server mode requires Certificate Authority to be enabled.")
        elif ca_state_errors:
            validation_errors.append("NTPsec NTS server mode requires healthy Certificate Authority state.")
        elif not ca_certificate_available(db, "ntp:nts"):
            validation_errors.append("NTPsec NTS server mode requires an issued CA-managed server certificate before apply.")
    nts_requested = settings.nts_server_enabled or any(
        bool(source.get("enabled", True)) and bool(source.get("use_nts"))
        for source in ntp_upstream_sources(settings)
    )
    if not ntp_nts_capability_known and nts_requested:
        validation_errors.append(
            "NTPsec NTS capability detection is temporarily unavailable; existing NTS desired state was preserved, "
            "but appliance apply is blocked until detection succeeds."
        )
    status_result = SystemAdapter().read_ntpd_status() if include_runtime_health else None
    return {
        "ntp_settings": settings,
        "ntp_settings_json": ntp_settings_to_dict(settings),
        "available_interfaces": available_interfaces,
        "selected_ntp_interfaces": split_interfaces(settings.listen_interface),
        "selected_ntp_addresses": split_addresses(settings.listen_address),
        "available_ntp_addresses": available_service_listen_addresses(settings.listen_address, available_interfaces),
        "ntp_primary_listen_address": primary_listen_address(settings.listen_address),
        "ntp_bind_label": service_bind_label(settings.listen_interface, settings.listen_address),
        "ntp_config_preview": config_preview,
        "ntp_validation_errors": validation_errors,
        "ntp_service_status": service_runtime_status(db, "ntpd"),
        "ntp_ntpq_status": status_result.stdout if status_result else "NTPsec source health is not loaded during page render.",
        "ntp_ntpq_status_error": status_result.stderr if status_result and status_result.returncode != 0 else "",
        "ntp_ntpq_status_dry_run": status_result.dry_run if status_result else False,
        "ntp_nts_cert_path": ntp_nts_chain_path,
        "ntp_nts_key_path": ntp_nts_key_path,
        "ntp_nts_chain_path": ntp_nts_chain_path,
        "ntp_nts_capability_known": ntp_nts_capability_known,
        "ntp_nts_supported": ntp_nts_supported,
        "ntp_nts_capabilities": ntp_capabilities,
    }


def managed_dns_fqdns(db: Session) -> set[str]:
    """Return managed dns fqdns.

    Args:
        db: Active database session.
    """
    records = db.execute(select(DnsRecord)).scalars().all()
    names: set[str] = set()
    for record in records:
        hostname = record.hostname.strip().strip(".").lower()
        if hostname:
            names.add(hostname)
    return names


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


def appliance_settings_management_context(db: Session) -> dict[str, Any]:
    """Return appliance settings management context.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(
        select(VlanInterface)
        .where(VlanInterface.enabled.is_(True))
        .order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    return management_ui_context(interfaces, vlans)


def management_ui_addresses(db: Session) -> list[str]:
    """Return all desired addresses that expose the management browser plane.

    Args:
        db: Active database session used to load desired interface state.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(
        select(VlanInterface)
        .where(VlanInterface.enabled.is_(True))
        .order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    addresses: list[str] = []
    for interface in interfaces:
        role = normalize_interface_role(interface.role)
        enabled = role == "management" or (
            role == "access"
            and normalize_interface_mode(interface.mode) == "access"
            and interface.admin_state == "up"
            and interface.access_management_ui_enabled
        )
        if interface.oper_state == "missing" or not enabled:
            continue
        for cidr in (interface.ip_cidr or interface.host_ip_cidr, interface.ipv6_cidr or interface.host_ipv6_cidr):
            address = interface_address(cidr)
            if address and address not in addresses:
                addresses.append(address)
    for vlan in vlans:
        if normalize_interface_role(vlan.role) != "access" or not vlan.access_management_ui_enabled:
            continue
        for cidr in (vlan.ip_cidr, vlan.ipv6_cidr):
            address = interface_address(cidr)
            if address and address not in addresses:
                addresses.append(address)
    return addresses


def appliance_dns_record_conflict(db: Session, fqdn: str) -> bool:
    """Return appliance dns record conflict.

    Args:
        db: Active database session.
        fqdn: Fully qualified domain name to validate or use.
    """
    normalized = normalize_fqdn(fqdn)
    if not normalized:
        return False
    records = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == normalized,
            DnsRecord.record_type.in_(["A", "AAAA"]),
        )
    ).scalars().all()
    return any(not is_app_owned_appliance_dns_record(record.description) for record in records)


def appliance_domain_from_fqdn(fqdn: str) -> str:
    """Return appliance domain from fqdn.

    Args:
        fqdn: Fqdn consumed by appliance domain from FQDN.
    """
    return canonical_appliance_domain_from_fqdn(fqdn)


def ensure_dns_domain_for_appliance_settings(dns_settings: DnsSettings, fqdn: str) -> bool:
    """Ensure dns domain for appliance settings.

    Args:
        dns_settings: Dns settings consumed by ensure DNS domain for appliance settings.
        fqdn: Fqdn consumed by ensure DNS domain for appliance settings.


    Returns:
        The ensure dns domain for appliance settings result.
    """
    domain = appliance_domain_from_fqdn(fqdn)
    if not domain:
        return False
    domains = split_domains(dns_settings.domain)
    if domain in domains:
        return False
    dns_settings.domain = join_domains([domain, *domains])
    dns_settings.updated_at = utcnow()
    return True


def ensure_dns_for_appliance_settings(
    db: Session,
    settings: ApplianceSettings,
    *,
    previous_fqdn: str,
    actor: str | None,
) -> str | None:
    """Ensure dns for appliance settings.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        previous_fqdn: Previous fqdn supplied by the caller.
        actor: Authenticated identity attributed to the audit record.

    Returns:
        The ensure dns for appliance settings result.
    """
    dns_settings = get_dns_settings_row(db)
    ensure_dns_domain_for_appliance_settings(dns_settings, settings.fqdn)
    fqdn = normalize_fqdn(settings.fqdn)
    desired_addresses = management_ui_addresses(db)
    if not fqdn or not desired_addresses:
        return None
    actions: list[str] = []
    existing_records = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == fqdn,
            DnsRecord.record_type.in_(["A", "AAAA"]),
        )
    ).scalars().all()
    existing_by_key = {(record.record_type, record.address): record for record in existing_records}
    desired_keys: set[tuple[str, str]] = set()
    for candidate in desired_addresses:
        try:
            parsed_address = ip_address(candidate)
        except ValueError:
            continue
        record_type = "AAAA" if parsed_address.version == 6 else "A"
        address = str(parsed_address)
        if validate_dns_record(fqdn, record_type, address):
            continue
        key = (record_type, address)
        desired_keys.add(key)
        existing = existing_by_key.get(key)
        if existing and not is_app_owned_appliance_dns_record(existing.description):
            actions.append("conflict")
            continue
        if existing:
            if not existing.enabled:
                existing.enabled = True
                actions.append("updated")
            else:
                actions.append("unchanged")
            continue
        record = DnsRecord(
            hostname=fqdn,
            record_type=record_type,
            address=address,
            description=APPLIANCE_DNS_RECORD_DESCRIPTION,
            enabled=True,
        )
        db.add(record)
        db.flush()
        if actor:
            record_audit(
                db,
                actor=actor,
                action="create_dns_record_from_appliance_settings",
                resource_type="dns_record",
                resource_id=str(record.id),
                detail=f"{fqdn} {record_type} -> {address}",
            )
        actions.append("created")
    for record in existing_records:
        if is_app_owned_appliance_dns_record(record.description) and (record.record_type, record.address) not in desired_keys:
            db.delete(record)
            actions.append("removed-stale")
    db.flush()

    previous = normalize_fqdn(previous_fqdn)
    if previous and previous != fqdn:
        removed = 0
        records = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == previous,
                DnsRecord.record_type.in_(["A", "AAAA"]),
            )
        ).scalars().all()
        for record in records:
            if not is_app_owned_appliance_dns_record(record.description):
                continue
            db.delete(record)
            removed += 1
            if actor:
                record_audit(
                    db,
                    actor=actor,
                    action="delete_dns_record_from_appliance_settings_rename",
                    resource_type="dns_record",
                    resource_id=str(record.id),
                    detail=f"{record.hostname} {record.record_type}",
                )
        if removed:
            db.flush()
            actions.append("removed-old")
    return "+".join(actions) if actions else None


def appliance_settings_context(db: Session, *, reconcile_dns: bool = True) -> dict[str, Any]:
    """Return appliance settings context.

    Args:
        db: Active database session.
        reconcile_dns: Reconcile dns supplied by the caller.
    """
    settings = get_appliance_settings_row(db)
    dns_settings = get_dns_settings_row(db)
    if reconcile_dns and ensure_dns_for_appliance_settings(db, settings, previous_fqdn=settings.fqdn, actor=None):
        db.commit()
        db.refresh(settings)
        db.refresh(dns_settings)
    local_dns_enabled = bool(
        dns_settings.enabled
        and applied_local_dns_enabled(load_appliance_apply_baselines(db).get("dnsmasq"))
    )
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    management, observed_dhcp_dns_servers = management_dhcp_dns_context(interfaces, vlans)
    terminal_options = web_terminal_interface_options(interfaces, vlans)
    ca_settings = get_ca_settings_row(db)
    management_https_cert_path, management_https_key_path, _management_https_chain_path = ca_managed_certificate_paths(db, "appliance:https")
    management_https_cert_available = bool(management_https_cert_path and management_https_key_path and ca_certificate_available(db, "appliance:https"))
    validation_errors, validation_warnings = validate_appliance_settings(
        settings,
        local_dns_enabled=local_dns_enabled,
        management_interface=management,
        dns_record_conflict=local_dns_enabled and appliance_dns_record_conflict(db, settings.fqdn),
        ca_enabled=bool(ca_settings.enabled),
        management_https_cert_available=management_https_cert_available,
        web_terminal_options=terminal_options,
    )
    if settings.root_ssh_enabled and get_settings().dry_run_system_adapters:
        validation_warnings.append("Root SSH is enabled as desired state, but dry-run system adapters are active. Global appliance apply will record intent without changing sshd.")
    appliance_settings_preview = appliance_settings_preview_payload(
        settings,
        local_dns_enabled=local_dns_enabled,
        management_interface=management,
        management_https_cert_path=management_https_cert_path,
        management_https_key_path=management_https_key_path,
        web_terminal_options=terminal_options,
    )
    if appliance_settings_preview["resolver_mode"] != "dhcp":
        observed_dhcp_dns_servers = []
    return {
        "app_settings": get_settings(),
        "runtime_hostname": socket.gethostname(),
        "appliance_settings": settings,
        "appliance_settings_json": appliance_settings_to_dict(settings),
        "service_dns_target_naming_choices": SERVICE_DNS_TARGET_NAMING_CHOICES,
        "local_dns_enabled": local_dns_enabled,
        "ca_enabled": bool(ca_settings.enabled),
        "management_https_cert_available": management_https_cert_available,
        "management_https_cert_path": management_https_cert_path,
        "management_https_key_path": management_https_key_path,
        "management_interface": management,
        "web_terminal_interface_options": terminal_options,
        "selected_web_terminal_interfaces": normalized_web_terminal_interfaces(settings, management),
        "web_terminal_addresses": web_terminal_addresses(normalized_web_terminal_interfaces(settings, management), terminal_options),
        "logging_preferences": logging_preferences_to_dict(logging_preferences_from_db(db)),
        "appliance_settings_validation_errors": validation_errors,
        "appliance_settings_validation_warnings": validation_warnings,
        "appliance_settings_resolver_mode": appliance_settings_preview["resolver_mode"],
        "appliance_settings_observed_dhcp_dns_servers": observed_dhcp_dns_servers,
        "appliance_settings_config_preview": json.dumps(appliance_settings_preview, indent=2, sort_keys=True) + "\n",
    }


def uploaded_vcf_registry_ca_bundle(db: Session) -> dict[str, object]:
    """Return uploaded vcf registry ca bundle.

    Args:
        db: Active database session.
    """
    name = setting_value(db, VCF_REGISTRY_UPLOADED_CA_BUNDLE_NAME_KEY)
    pem = setting_value(db, VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY)
    return {"name": name, "present": bool(pem.strip())}


def store_uploaded_vcf_registry_ca_bundle(db: Session, ca_bundle_file: UploadFile | None, actor: str) -> str | None:
    """Persist uploaded vcf registry ca bundle.

    Args:
        db: Active database session.
        ca_bundle_file: Ca bundle file supplied by the caller.
        actor: Authenticated identity attributed to the audit record.

    Returns:
        The store uploaded vcf registry ca bundle result.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if ca_bundle_file is None or not ca_bundle_file.filename:
        return None
    content = ca_bundle_file.file.read()
    if not content:
        return None
    if len(content) > 1024 * 1024:
        raise HTTPException(status_code=400, detail="CA bundle upload must be 1 MB or smaller.")
    try:
        pem_text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CA bundle upload must be a PEM text file.") from exc
    if "-----BEGIN CERTIFICATE-----" not in pem_text or "-----END CERTIFICATE-----" not in pem_text:
        raise HTTPException(status_code=400, detail="CA bundle upload must contain at least one PEM certificate.")
    name_setting = set_setting_value(db, VCF_REGISTRY_UPLOADED_CA_BUNDLE_NAME_KEY, ca_bundle_file.filename)
    set_setting_value(db, VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY, pem_text)
    record_audit(
        db,
        actor=actor,
        action="upload_vcf_registry_ca_bundle",
        resource_type="setting",
        resource_id=str(name_setting.id),
        detail=ca_bundle_file.filename,
    )
    return ca_bundle_file.filename


def store_uploaded_vcf_depot_secret(
    db: Session,
    upload: UploadFile | None,
    *,
    name_key: str,
    value_key: str,
    actor: str,
    action: str,
    pending_audits: list[AuditEvent] | None = None,
) -> str | None:
    """Persist uploaded vcf depot secret.

    Args:
        db: Active database session.
        upload: Upload supplied by the caller.
        name_key: Name key supplied by the caller.
        value_key: Value key supplied by the caller.
        actor: Authenticated identity attributed to the audit record.
        action: Operation to perform on the target resource.
        pending_audits: Pending audits supplied by the caller.

    Returns:
        The store uploaded vcf depot secret result.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if upload is None or not upload.filename:
        return None
    content = upload.file.read()
    if not content:
        raise HTTPException(status_code=400, detail="VCFDT credential uploads cannot be empty.")
    if len(content) > 128 * 1024:
        raise HTTPException(status_code=400, detail="VCFDT credential uploads must be 128 KB or smaller.")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="VCFDT credential uploads must be text files.") from exc
    if not text.strip():
        raise HTTPException(status_code=400, detail="VCFDT credential uploads cannot be empty.")
    name_setting = set_setting_value(db, name_key, Path(upload.filename).name)
    set_setting_value(db, value_key, text)
    if pending_audits is None:
        record_audit(
            db,
            actor=actor,
            action=action,
            resource_type="setting",
            resource_id=str(name_setting.id),
            detail=Path(upload.filename).name,
        )
    else:
        audit = AuditEvent(
            actor=actor,
            action=action,
            resource_type="setting",
            resource_id=str(name_setting.id),
            detail=Path(upload.filename).name,
        )
        db.add(audit)
        pending_audits.append(audit)
    return Path(upload.filename).name


def store_pasted_vcf_depot_secret(
    db: Session,
    value: str,
    *,
    name_key: str,
    value_key: str,
    display_name: str,
    actor: str,
    action: str,
    pending_audits: list[AuditEvent] | None = None,
) -> str:
    """Persist pasted vcf depot secret.

    Args:
        db: Active database session.
        value: Value to process.
        name_key: Name key supplied by the caller.
        value_key: Value key supplied by the caller.
        display_name: Display name supplied by the caller.
        actor: Authenticated identity attributed to the audit record.
        action: Operation to perform on the target resource.
        pending_audits: Pending audits supplied by the caller.

    Returns:
        The store pasted vcf depot secret result.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if len(value.encode("utf-8")) > 128 * 1024:
        raise HTTPException(status_code=400, detail="VCFDT credential text must be 128 KB or smaller.")
    if not value.strip():
        raise HTTPException(status_code=400, detail="VCFDT credential text cannot be empty.")
    name_setting = set_setting_value(db, name_key, display_name)
    set_setting_value(db, value_key, value)
    if pending_audits is None:
        record_audit(
            db,
            actor=actor,
            action=action,
            resource_type="setting",
            resource_id=str(name_setting.id),
            detail=display_name,
        )
    else:
        audit = AuditEvent(
            actor=actor,
            action=action,
            resource_type="setting",
            resource_id=str(name_setting.id),
            detail=display_name,
        )
        db.add(audit)
        pending_audits.append(audit)
    return display_name


def store_uploaded_vcf_depot_archive(settings: VcfOfflineDepotSettings, archive_file: UploadFile | None) -> str | None:
    """Persist uploaded vcf depot archive.

    Args:
        settings: Current Atlaso settings used to configure the operation.
        archive_file: Archive file consumed by store uploaded VCF depot archive.


    Returns:
        The store uploaded vcf depot archive result.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if archive_file is None or not archive_file.filename:
        return None
    try:
        archive_name = safe_archive_upload_name(archive_file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    VCF_DEPOT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = VCF_DEPOT_UPLOAD_DIR / archive_name
    temp_path = VCF_DEPOT_UPLOAD_DIR / f".{archive_name}.{uuid4().hex}.upload"
    try:
        with temp_path.open("wb") as destination:
            shutil.copyfileobj(archive_file.file, destination)
        validate_vcf_download_tool_upload_envelope(temp_path)
        temp_path.replace(archive_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Unable to store the VCF Download Tool archive.") from exc
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
    settings.tool_archive_path = str(archive_path)
    settings.tool_version = ""
    return archive_name


def reset_vcf_depot_tool_staging(db: Session, settings: VcfOfflineDepotSettings) -> None:
    """Remove vcf depot tool staging.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
    """
    archive_path = Path(settings.tool_archive_path) if settings.tool_archive_path else None
    if archive_path is not None:
        try:
            upload_root = VCF_DEPOT_UPLOAD_DIR.resolve()
            resolved_archive = archive_path.resolve()
            if resolved_archive.is_relative_to(upload_root) and resolved_archive.is_file():
                resolved_archive.unlink(missing_ok=True)
        except OSError:
            pass
    settings.tool_archive_path = ""
    settings.tool_version = ""
    settings.updated_at = utcnow()
    for profile in db.execute(select(VcfDepotDownloadProfile)).scalars().all():
        profile.enabled = False
        profile.status = "planned"
        profile.updated_at = utcnow()
        disable_vcf_depot_profile_schedules(db, profile.id)
    keys = [
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
        VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
    ]
    for setting in db.execute(select(Setting).where(Setting.key.in_(keys))).scalars().all():
        db.delete(setting)
    set_setting_value(db, VCF_DEPOT_RUNTIME_RESET_PENDING_KEY, "1")


def clear_vcf_depot_credentials(db: Session) -> None:
    """Remove vcf depot credentials.

    Args:
        db: Active database session.
    """
    credential_keys = [
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
    ]
    for setting in db.execute(select(Setting).where(Setting.key.in_(credential_keys))).scalars().all():
        db.delete(setting)


def invalidate_vcf_depot_software_depot_identity(db: Session, error: str) -> None:
    """Handle invalidate vcf depot software depot identity.

    Args:
        db: Active database session.
        error: Public-safe error detail to record or return.
    """
    for key in [VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY]:
        setting = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
        if setting is not None:
            db.delete(setting)
    clear_vcf_depot_credentials(db)
    set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY, error)


def vcf_depot_software_depot_id_context(db: Session) -> dict[str, str]:
    """Return vcf depot software depot id context.

    Args:
        db: Active database session.
    """
    software_id = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)).scalar_one_or_none()
    generated_at = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY)).scalar_one_or_none()
    error = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY)).scalar_one_or_none()
    return {
        "id": software_id.value if software_id else "",
        "generated_at": generated_at.value if generated_at else "",
        "error": error.value if error else "",
    }


def generate_and_store_vcf_software_depot_id(db: Session, settings: VcfOfflineDepotSettings) -> dict[str, str]:
    """Build and store vcf software depot id.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.

    Returns:
        The generate and store vcf software depot id result.
    """
    result = generate_vcf_software_depot_id(settings.tool_archive_path)
    if result.success:
        generated_at = utcnow().isoformat()
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, result.software_depot_id)
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY, generated_at)
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY, "")
        return {"id": result.software_depot_id, "generated_at": generated_at, "error": ""}
    error = result.error or "VCFDT software depot ID generation failed."
    set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY, error)
    return {**vcf_depot_software_depot_id_context(db), "error": error}


def helper_json_payloads(output: str) -> list[dict[str, Any]]:
    """Return helper json payloads.

    Args:
        output: Output consumed by helper JSON payloads.
    """
    payloads: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    text = output or ""
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            payload, end_index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            next_line = text.find("\n", index)
            if next_line == -1:
                break
            index = next_line + 1
            continue
        if isinstance(payload, dict):
            payloads.append(payload)
        index = end_index
    return payloads


def helper_json_payload_with_key(output: str, key: str) -> dict[str, Any]:
    """Return helper json payload with key.

    Args:
        output: Output consumed by helper JSON payload with key.
        key: Stable key identifying the setting, secret, or mapping entry.
    """
    for payload in reversed(helper_json_payloads(output)):
        if key in payload:
            return payload
    return {}


def persist_vcf_depot_metadata_from_apply(db: Session, unit_results: list[dict[str, Any]]) -> None:
    """Persist vcf depot metadata from apply.

    Args:
        db: Active database session.
        unit_results: Unit results supplied by the caller.
    """
    for result in unit_results:
        if result.get("unit_id") != "vcf_offline_depot":
            continue
        settings = get_vcf_offline_depot_settings_row(db, reconcile_default_user=False)
        for command in result.get("commands", []):
            command_parts = [str(part) for part in command.get("command") or []]
            if command.get("dry_run"):
                continue
            stdout = str(command.get("stdout") or "")
            stderr = str(command.get("stderr") or "")
            returncode = int(command.get("returncode") or 0)
            if returncode == 0 and ("reset-tool" in command_parts or "stage-tool" in command_parts):
                pending_reset = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_RUNTIME_RESET_PENDING_KEY)).scalar_one_or_none()
                if pending_reset is not None:
                    db.delete(pending_reset)
            if "stage-tool" in command_parts and returncode == 0:
                payload = helper_json_payload_with_key(stdout, "tool_version")
                tool_version = str(payload.get("tool_version") or "").strip()
                if tool_version and settings.tool_version != tool_version:
                    settings.tool_version = tool_version
                    settings.updated_at = utcnow()
                    set_setting_value(db, VCF_DEPOT_TOOL_VERSION_SOURCE_KEY, VCF_DEPOT_TOOL_VERSION_SOURCE_COMMAND)
            if "generate-software-depot-id" not in command_parts:
                continue
            generated_at = utcnow().isoformat()
            software_depot_id = ""
            if returncode == 0:
                payload = helper_json_payload_with_key(stdout, "software_depot_id")
                software_depot_id = str(payload.get("software_depot_id") or "").strip()
            if software_depot_id:
                set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, software_depot_id)
                set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY, generated_at)
                set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY, "")
                clear_vcf_depot_credentials(db)
            else:
                invalidated = helper_json_payload_with_key(stdout, "software_depot_id_invalidated")
                if invalidated.get("software_depot_id_invalidated") is True:
                    for key in [VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY]:
                        stale_setting = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
                        if stale_setting is not None:
                            db.delete(stale_setting)
                    clear_vcf_depot_credentials(db)
                error = (
                    _strip_task_action_metadata(stderr)
                    or _strip_task_action_metadata(stdout)
                    or "VCFDT software depot ID generation failed."
                )
                set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY, error)
        return


def vcf_depot_secret_context(db: Session) -> dict[str, object]:
    """Return vcf depot secret context.

    Args:
        db: Active database session.
    """
    token_name = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_NAME_KEY)).scalar_one_or_none()
    token_value = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one_or_none()
    activation_name = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_NAME_KEY)).scalar_one_or_none()
    activation_value = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)).scalar_one_or_none()
    token_state = setting_secret_state(token_name, token_value)
    activation_state = setting_secret_state(activation_name, activation_value)
    download_credential_type = "download_token"
    if activation_state.present and (
        not token_state.present or activation_state.updated_at > token_state.updated_at
    ):
        download_credential_type = "activation_code"
    return {
        "download_token": token_state,
        "activation_code": activation_state,
        "download_token_present": token_state.present,
        "activation_code_present": activation_state.present,
        "download_credential_type": download_credential_type,
    }


def vcf_depot_profile_start_states(db: Session) -> list[dict[str, object]]:
    """Return current non-secret profile prerequisites for task refresh.

    Args:
        db: Active database session.
    """
    secrets = vcf_depot_secret_context(db)
    profiles = db.execute(
        select(VcfDepotDownloadProfile).order_by(VcfDepotDownloadProfile.id)
    ).scalars().all()
    states: list[dict[str, object]] = []
    for profile in profiles:
        row = vcf_depot_profile_to_dict(
            profile,
            download_token_present=bool(secrets["download_token_present"]),
            activation_code_present=bool(secrets["activation_code_present"]),
        )
        states.append(
            {
                "profile_id": profile.id,
                "status": profile.status,
                "can_start": bool(row["prerequisite_can_start"]),
                "start_blocker": str(row["prerequisite_start_blocker"]),
            }
        )
    return states


def vcf_depot_application_properties_context(db: Session, settings: VcfOfflineDepotSettings) -> dict[str, str | bool]:
    """Return vcf depot application properties context.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
    """
    content_setting = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY)).scalar_one_or_none()
    if content_setting and content_setting.value.strip():
        source = setting_value(db, VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY) or "operator saved"
        updated_at = setting_value(db, VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY)
        return {
            "present": True,
            "saved": True,
            "filename": VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
            "content": content_setting.value,
            "source": source,
            "updated_at": updated_at or (content_setting.updated_at.isoformat() if content_setting.updated_at else ""),
            "staged_path": VCF_DEPOT_STAGED_APPLICATION_PROPERTIES_PATH,
        }
    content, source = vcf_depot_application_properties_from_tool(settings)
    return {
        "present": bool(content.strip()),
        "saved": False,
        "filename": VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
        "content": content,
        "source": source,
        "updated_at": "",
        "staged_path": VCF_DEPOT_STAGED_APPLICATION_PROPERTIES_PATH,
    }


def vcf_depot_download_job_rows(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 10,
) -> tuple[list[dict[str, str]], int]:
    """Return vcf depot download job rows.

    Args:
        db: Active database session.
        page: Page supplied by the caller.
        page_size: Page size supplied by the caller.
    """
    total = int(
        db.scalar(select(func.count()).select_from(Job).where(Job.type == "vcf-depot-download")) or 0
    )
    jobs = (
        db.execute(
            select(Job)
            .where(Job.type == "vcf-depot-download")
            .order_by(desc(Job.created_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    rows: list[dict[str, str]] = []
    for job in jobs:
        profile_name = ""
        dry_run = False
        try:
            result = json.loads(job.result or "{}")
            profile_name = str(result.get("profile_name") or "")
            dry_run = bool(result.get("dry_run"))
        except json.JSONDecodeError:
            pass
        rows.append(
            {
                "id": job.id,
                "status": job.status,
                "profile_name": profile_name,
                "created_at": job.created_at.isoformat() if job.created_at else "",
                "started_at": job.started_at.isoformat() if job.started_at else "",
                "finished_at": job.finished_at.isoformat() if job.finished_at else "",
                "progress_percent": str(job.progress_percent),
                "dry_run": "yes" if dry_run else "no",
                "log_url": f"/vcf-offline-depot/tasks/{job.id}/log",
            }
        )
    return rows, total


def vcf_depot_active_download_job(db: Session) -> Job | None:
    """Return vcf depot active download job.

    Args:
        db: Active database session.
    """
    return active_vcf_depot_download_job(db)


def recover_interrupted_vcf_depot_download_jobs(db: Session) -> int:
    """Return recover interrupted vcf depot download jobs.

    Args:
        db: Active database session.
    """
    jobs = db.scalars(
        select(Job).where(
            Job.type == "vcf-depot-download",
            Job.status == JobStatus.RUNNING.value,
        )
    ).all()
    if not jobs:
        return 0
    finished = utcnow()
    for job in jobs:
        job.status = JobStatus.FAILED.value
        job.finished_at = finished
        job.progress_percent = 100
        job.error = "Interrupted by a Atlaso restart before completion. Start the download again."
        try:
            profile_id = int(json.loads(job.result or "{}").get("profile_id"))
        except (json.JSONDecodeError, TypeError, ValueError):
            profile_id = 0
        profile = db.get(VcfDepotDownloadProfile, profile_id) if profile_id else None
        if profile is not None:
            profile.status = "blocked"
            profile.updated_at = finished
    db.commit()
    return len(jobs)


def recover_interrupted_vcf_depot_software_id_jobs(db: Session) -> int:
    """Return recover interrupted vcf depot software id jobs.

    Args:
        db: Active database session.
    """
    jobs = db.scalars(
        select(Job).options(selectinload(Job.steps)).where(
            Job.type == "vcf-depot-software-id",
            Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
        )
    ).all()
    if not jobs:
        return 0
    finished = utcnow()
    running_jobs = [job for job in jobs if job.status == JobStatus.RUNNING.value]
    reconciliation_message = ""
    if running_jobs:
        previous_id = str(vcf_depot_software_depot_id_context(db).get("id") or "").strip()
        readback = SystemAdapter(dry_run=False).read_vcf_offline_depot_software_depot_id()
        readback_payload = helper_json_payload_with_key(readback.stdout, "software_depot_id")
        runtime_id = str(readback_payload.get("software_depot_id") or "").strip()
        if readback.returncode == 0 and runtime_id:
            if runtime_id != previous_id:
                set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, runtime_id)
                set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY, finished.isoformat())
                clear_vcf_depot_credentials(db)
                reconciliation_message = " The runtime Software Depot ID was reconciled and obsolete credentials were removed."
            else:
                reconciliation_message = " The existing Software Depot ID was confirmed by canonical VCFDT readback."
            set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY, "")
        else:
            reconciliation_error = (
                "Atlaso restarted while VCFDT identity replacement was running and the runtime Software Depot ID "
                "could not be verified. The stored identity and credentials were invalidated."
            )
            invalidate_vcf_depot_software_depot_identity(db, reconciliation_error)
            reconciliation_message = f" {reconciliation_error}"
    for job in jobs:
        job.status = JobStatus.FAILED.value
        job.finished_at = finished
        job.progress_percent = 100
        job.error = "Interrupted by an Atlaso restart before VCFDT Software Depot ID generation completed."
        if job in running_jobs:
            job.error += reconciliation_message
        payload = _job_payload(job)
        payload["state"] = JobStatus.FAILED.value
        payload["interrupted"] = True
        payload["interrupted_at"] = finished.isoformat()
        job.result = json.dumps(payload, indent=2, sort_keys=True)
        for step in job.steps:
            if step.status == JobStatus.RUNNING.value:
                step.status = JobStatus.FAILED.value
                step.error = job.error
            elif step.status == JobStatus.PENDING.value:
                step.status = "skipped"
                step.error = "Skipped because Atlaso restarted before this operation began."
            step.finished_at = finished
            step.progress_percent = 100
    db.commit()
    return len(jobs)


def recover_interrupted_appliance_apply_jobs(db: Session) -> int:
    """Return recover interrupted appliance apply jobs.

    Args:
        db: Active database session.
    """
    candidate_jobs = db.scalars(
        select(Job)
        .options(selectinload(Job.steps))
        .where(Job.type == "appliance-apply")
    ).all()
    jobs = [
        job
        for job in candidate_jobs
        if job.status in {JobStatus.PENDING.value, JobStatus.RUNNING.value}
        or _job_payload(job).get("management_handoff_runtime_commit_pending")
    ]
    if not jobs:
        return 0
    finished = utcnow()
    handoff_jobs = [
        job
        for job in jobs
        if _job_payload(job).get("management_handoff")
        or _job_payload(job).get("management_handoff_runtime_commit_pending")
    ]
    handoff_recoveries: dict[str, tuple[AdapterResult, dict[str, Any]]] = {}
    if handoff_jobs:
        adapter = SystemAdapter(dry_run=False)
        for handoff_job in handoff_jobs:
            handoff_payload = _job_payload(handoff_job)
            if (
                handoff_payload.get("management_handoff_runtime_commit_pending")
                and handoff_payload.get("management_handoff_application_committed") is True
            ):
                recovery = adapter.acknowledge_management_handoff(handoff_job.id)
            else:
                recovery = adapter.recover_management_handoff()
            handoff_recoveries[handoff_job.id] = (
                recovery,
                management_handoff_result_evidence(recovery),
            )
    for job in jobs:
        job_was_pending = job.status == JobStatus.PENDING.value
        for step in job.steps:
            if step.status == JobStatus.RUNNING.value:
                step.status = JobStatus.FAILED.value
                step.error = "Interrupted by a Atlaso restart while this component was running."
                step.finished_at = finished
                step.progress_percent = 100
            elif step.status == JobStatus.PENDING.value:
                step.status = "skipped"
                step.error = "Skipped because the appliance apply task was interrupted."
                step.finished_at = finished
                step.progress_percent = 100
        job.status = JobStatus.FAILED.value
        job.finished_at = finished
        job.progress_percent = 100
        handoff_recovery = handoff_recoveries.get(job.id)
        if handoff_recovery is not None:
            recovery_result, recovery_evidence = handoff_recovery
            recovery_state = str(recovery_evidence.get("management_handoff") or "")
            if recovery_result.returncode == 0 and recovery_state in {"committed", "already committed"}:
                job.error = (
                    "Interrupted after the management handoff baselines were committed. The candidate management "
                    "path remains active; review the task evidence before applying any remaining components."
                )
            elif recovery_result.returncode == 0 and recovery_evidence.get("rolled_back") is True:
                job.error = (
                    "Interrupted during the management handoff. Atlaso rolled back to the previous management path; "
                    "review the task evidence and submit the desired change again."
                )
            elif (
                job_was_pending
                and recovery_result.returncode == 0
                and recovery_state == "no interrupted transaction"
            ):
                job.error = (
                    "Interrupted before the privileged management handoff transaction began. No runtime rollback was "
                    "necessary; review the task evidence and submit the desired change again."
                )
            else:
                job.error = (
                    "Interrupted during the management handoff, and automatic recovery could not prove either a "
                    "committed candidate path or a ready previous path. Use the local appliance console and inspect "
                    "the recovery task evidence."
                )
        else:
            job.error = (
                "Interrupted by a Atlaso restart before completion. "
                "Review current appliance state and submit the selected changes again."
            )
        payload = _job_payload(job)
        payload["state"] = "failed"
        payload["interrupted"] = True
        payload["interrupted_at"] = finished.isoformat()
        if handoff_recovery is not None:
            recovery_result, recovery_evidence = handoff_recovery
            payload["management_handoff_recovery"] = adapter_result_to_payload(
                recovery_result
            )
            payload["management_handoff_recovery"]["evidence"] = recovery_evidence
            if recovery_evidence.get("management_handoff") in {"committed", "already committed"}:
                payload["management_handoff_runtime_commit_pending"] = False
                payload.pop("management_handoff_application_committed", None)
                payload["management_handoff_runtime_committed"] = True
            elif recovery_result.returncode == 0 and recovery_evidence.get("rolled_back") is True:
                payload.pop("management_handoff_runtime_commit_pending", None)
                payload.pop("management_handoff_application_committed", None)
            elif (
                job_was_pending
                and recovery_result.returncode == 0
                and recovery_state == "no interrupted transaction"
            ):
                payload.pop("management_handoff_runtime_commit_pending", None)
                payload.pop("management_handoff_application_committed", None)
            else:
                payload["management_handoff_runtime_commit_pending"] = True
                if payload.get("management_handoff_application_committed") is not True:
                    payload.pop("management_handoff_application_committed", None)
        job.result = json.dumps(payload, indent=2, sort_keys=True)
    db.commit()
    return len(jobs)


def recover_interrupted_vcf_helper_jobs(db: Session) -> int:
    """Return recover interrupted vcf helper jobs.

    Args:
        db: Active database session.
    """
    jobs = db.scalars(
        select(Job).where(
            Job.type.in_(["vcf-sddc-manager-deploy", "vcf-offline-depot-target-config"]),
            Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
        )
    ).all()
    if not jobs:
        return 0
    finished = utcnow()
    for job in jobs:
        job.status = JobStatus.FAILED.value
        job.finished_at = finished
        job.progress_percent = 100
        job.error = "Interrupted by a Atlaso restart. Transient credentials were discarded; submit the helper task again."
        payload = _job_payload(job)
        payload["state"] = "failed"
        payload["interrupted"] = True
        job.result = json.dumps(payload, sort_keys=True)
    db.commit()
    return len(jobs)


def vcf_registry_ca_bundle_context(db: Session) -> dict[str, object]:
    """Return vcf registry ca bundle context.

    Args:
        db: Active database session.
    """
    ca_settings = get_ca_settings_row(db)
    uploaded_bundle = uploaded_vcf_registry_ca_bundle(db)
    if ca_settings.enabled:
        ensure_ca_state(db)
        path = f"{ca_settings.storage_path.rstrip('/')}/ca-bundle.pem"
        return {
            "source": "local-ca",
            "source_label": "Local CA",
            "path": path,
            "available": True,
            "uploaded_name": uploaded_bundle["name"],
        }
    return {
        "source": "uploaded",
        "source_label": "Uploaded bundle",
        "path": VCF_REGISTRY_UPLOADED_CA_BUNDLE_PATH,
        "available": uploaded_bundle["present"],
        "uploaded_name": uploaded_bundle["name"],
    }


def vcf_private_registry_context(db: Session, *, reconcile: bool = True) -> dict:
    """Return vcf private registry context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = get_vcf_private_registry_settings_row(db, reconcile=reconcile)
    if reconcile and normalize_service_bind_settings(db, settings):
        db.commit()
        db.refresh(settings)
    bundles = db.execute(select(VcfRegistryBundle).order_by(VcfRegistryBundle.name)).scalars().all()
    available_interfaces = service_bind_options(db)
    ca_bundle_context = vcf_registry_ca_bundle_context(db)
    if reconcile:
        settings.ca_bundle_path = str(ca_bundle_context["path"])
    validation_errors, validation_warnings = validate_vcf_registry_state(
        settings,
        bundles,
        {interface["name"] for interface in available_interfaces},
        managed_dns_fqdns(db),
        str(ca_bundle_context["source"]),
        bool(ca_bundle_context["available"]),
    )
    if settings.enabled and get_ca_settings_row(db).enabled and not ca_certificate_available(db, "vcf_private_registry:https"):
        validation_errors.append("VCF Private Registry requires an issued CA-managed HTTPS certificate before apply.")
    harbor_config_preview = render_harbor_config(settings)
    relocation_preview = render_imgpkg_relocation_preview(settings, bundles)
    return {
        "vcf_registry_settings": settings,
        "vcf_registry_settings_json": vcf_registry_settings_to_dict(settings),
        "vcf_registry_service_status": service_runtime_status(db, "vcf-private-registry"),
        "vcf_registry_bundles": bundles,
        "vcf_registry_bundle_rows": [vcf_registry_bundle_to_dict(bundle) for bundle in bundles],
        "vcf_registry_available_interfaces": available_interfaces,
        "selected_vcf_registry_interfaces": split_interfaces(settings.listen_interface),
        "selected_vcf_registry_addresses": split_addresses(settings.listen_address),
        "available_vcf_registry_addresses": available_service_listen_addresses(settings.listen_address, available_interfaces),
        "vcf_registry_primary_listen_address": primary_listen_address(settings.listen_address),
        "vcf_registry_bind_label": service_bind_label(settings.listen_interface, settings.listen_address),
        "vcf_registry_endpoint": vcf_registry_endpoint(settings),
        "vcf_registry_harbor_config_preview": harbor_config_preview,
        "vcf_registry_relocation_preview": relocation_preview,
        "vcf_registry_validation_errors": validation_errors,
        "vcf_registry_validation_warnings": validation_warnings,
        "vcf_registry_ca_bundle_source": ca_bundle_context["source"],
        "vcf_registry_ca_bundle_source_label": ca_bundle_context["source_label"],
        "vcf_registry_ca_bundle_available": ca_bundle_context["available"],
        "vcf_registry_uploaded_ca_bundle_name": ca_bundle_context["uploaded_name"],
    }


def vcf_depot_tool_installed(settings: VcfOfflineDepotSettings) -> bool:
    """Return vcf depot tool installed.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    if get_settings().environment == "appliance":
        runtime_home = filesystem_path(VCF_DEPOT_RUNTIME_TOOL_DIR)
        return bool(settings.tool_archive_path) and any(
            candidate.is_file()
            for candidate in (runtime_home / "bin" / "vcf-download-tool", runtime_home / "vcf-download-tool")
        )
    return bool(settings.tool_archive_path and Path(settings.tool_archive_path).is_file())


def vcf_offline_depot_context(db: Session, *, reconcile: bool = True) -> dict:
    """Return vcf offline depot context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = get_vcf_offline_depot_settings_row(db, reconcile_default_user=reconcile, reconcile=reconcile)
    appliance_settings = get_appliance_settings_row(db)
    if reconcile and normalize_service_bind_settings(db, settings):
        db.commit()
        db.refresh(settings)
    profile_type_order = {"metadata": 0, "binaries": 1, "esx": 2}
    profiles = sorted(
        db.execute(select(VcfDepotDownloadProfile)).scalars().all(),
        key=lambda profile: (
            profile_type_order.get(str(profile.profile_type or "").strip().lower(), 99),
            str(profile.name or "").casefold(),
            int(profile.id or 0),
        ),
    )
    if reconcile and not vcf_depot_tool_installed(settings):
        changed_profiles = [profile for profile in profiles if profile.enabled]
        changed_schedule_count = 0
        for profile in profiles:
            if profile.enabled:
                profile.enabled = False
                profile.updated_at = utcnow()
            disabled_schedules = disable_vcf_depot_profile_schedules(db, profile.id)
            if disabled_schedules:
                changed_schedule_count += len(disabled_schedules)
                db.add(
                    AuditEvent(
                        actor="system:vcf-offline-depot",
                        action="disable_vcf_depot_profile_schedules",
                        resource_type="vcf_depot_profile",
                        resource_id=str(profile.id),
                        detail="tool unavailable; schedules=" + ",".join(schedule.name for schedule in disabled_schedules),
                    )
                )
        if changed_profiles or changed_schedule_count:
            db.commit()
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    all_service_interfaces = service_bind_options(db)
    available_interfaces = vcf_depot_service_bind_options(db)
    management_interface_names = {
        str(interface["name"])
        for interface in all_service_interfaces
        if str(interface.get("role") or "").strip().lower() == "management"
    }
    secrets = vcf_depot_secret_context(db)
    software_depot_id = vcf_depot_software_depot_id_context(db)
    tool_display_version = settings.tool_version or staged_vcf_download_tool_version(settings.tool_archive_path)
    application_properties = vcf_depot_application_properties_context(db, settings)
    validation_errors, validation_warnings = validate_vcf_depot_state(
        settings,
        profiles,
        {interface["name"] for interface in available_interfaces},
        bool(secrets["download_token_present"]),
        bool(secrets["activation_code_present"]),
        management_interface_names,
        users=users,
    )
    depot_cert_path, depot_key_path, _depot_chain_path = ca_managed_certificate_paths(db, "vcf_offline_depot:https")
    if settings.enabled and get_ca_settings_row(db).enabled and not ca_certificate_available(db, "vcf_offline_depot:https"):
        validation_errors.append("VCF Offline Depot requires an issued CA-managed HTTPS certificate before apply.")
    https_config_preview = render_nginx_depot_config(settings, certificate_path=depot_cert_path, key_path=depot_key_path)
    command_preview = render_vcfdt_command_preview(
        settings,
        profiles,
        vmware_ceip_enabled=bool(appliance_settings.vmware_ceip_enabled),
        download_token_present=bool(secrets["download_token_present"]),
        activation_code_present=bool(secrets["activation_code_present"]),
        preferred_credential_type=str(secrets["download_credential_type"]),
    )
    profile_rows = [
        vcf_depot_profile_to_dict(
            profile,
            download_token_present=bool(secrets["download_token_present"]),
            activation_code_present=bool(secrets["activation_code_present"]),
        )
        for profile in profiles
    ]
    active_downloads = {
        vcf_depot_job_profile_id(job): job
        for job in active_vcf_depot_download_jobs(db)
        if vcf_depot_job_profile_id(job)
    }
    exclusive_job = active_vcf_depot_exclusive_job(db)
    for row in profile_rows:
        row.update(
            {
                "download_active": False,
                "active_job_id": "",
                "active_task_status": "",
                "active_task_blocker": "",
            }
        )
        profile_id = int(row.get("id") or 0)
        active_download = active_downloads.get(profile_id)
        if active_download is not None:
            state = "queued" if active_download.status == JobStatus.PENDING.value else "running"
            row["download_active"] = True
            row["active_job_id"] = active_download.id
            row["active_task_status"] = active_download.status
            row["active_task_blocker"] = (
                f"VCFDT task {active_download.id} is {state} for this profile. "
                "Wait for it to finish before starting the same profile again."
            )
        elif exclusive_job is not None:
            row["download_active"] = True
            row["active_task_blocker"] = vcf_depot_execution_conflict_detail(exclusive_job)
        if row["download_active"]:
            row["can_start"] = False
            row["start_blocker"] = row["active_task_blocker"]
    return {
        "vcf_depot_settings": settings,
        "vcf_depot_settings_json": {
            **vcf_depot_settings_to_dict(settings),
            "tool_display_version": tool_display_version,
            "vmware_ceip_enabled": bool(appliance_settings.vmware_ceip_enabled),
        },
        "vcf_depot_tool_display_version": tool_display_version,
        "vmware_ceip_enabled": bool(appliance_settings.vmware_ceip_enabled),
        "vcf_depot_users": users,
        "vcf_depot_profiles": profiles,
        "vcf_depot_profile_rows": profile_rows,
        "vcf_depot_profile_start_state": {int(row["id"]): row for row in profile_rows if row.get("id") is not None},
        "vcf_depot_available_interfaces": available_interfaces,
        "selected_vcf_depot_interfaces": split_interfaces(settings.listen_interface),
        "selected_vcf_depot_addresses": split_addresses(settings.listen_address),
        "available_vcf_depot_addresses": available_service_listen_addresses(settings.listen_address, available_interfaces),
        "vcf_depot_primary_listen_address": primary_listen_address(settings.listen_address),
        "vcf_depot_bind_label": service_bind_label(settings.listen_interface, settings.listen_address),
        "vcf_depot_endpoint": vcf_depot_endpoint(settings),
        "vcf_depot_service_status": vcf_depot_service_state(settings, nginx_active=backing_systemd_unit_active("nginx.service")),
        "vcf_depot_https_config_preview": https_config_preview,
        "vcf_depot_https_cert_path": depot_cert_path,
        "vcf_depot_https_key_path": depot_key_path,
        "vcf_depot_command_preview": command_preview,
        "vcf_depot_application_properties": application_properties,
        "vcf_depot_download_jobs": vcf_depot_download_job_rows(db)[0],
        "vcf_depot_validation_errors": validation_errors,
        "vcf_depot_validation_warnings": validation_warnings,
        "vcf_depot_download_token": secrets["download_token"],
        "vcf_depot_activation_code": secrets["activation_code"],
        "vcf_depot_software_depot_id": software_depot_id,
        "vcf_depot_runtime_reset_pending": bool(setting_value(db, VCF_DEPOT_RUNTIME_RESET_PENDING_KEY)),
        "vcf_depot_download_token_present": secrets["download_token_present"],
        "vcf_depot_activation_code_present": secrets["activation_code_present"],
        "vcf_depot_profile_types": sorted(VCF_DEPOT_PROFILE_TYPES),
        "vcf_depot_skus": sorted(VCF_DEPOT_SKUS),
        "vcf_depot_binary_types": sorted(VCF_DEPOT_BINARY_TYPES),
        "vcf_depot_components": [
            {"value": value, "label": f"{value} - {label}"}
            for value, label in sorted(VCF_DEPOT_COMPONENTS.items())
        ],
        "vcf_depot_esx_disabled_platforms": [
            {"value": platform, "label": platform}
            for platform in VCF_DEPOT_ESX_DISABLED_PLATFORMS
        ],
        "vcf_depot_archive_pattern": VCF_DEPOT_ARCHIVE_PATTERN,
    }


def vcf_depot_secret_snapshot(context: dict[str, Any]) -> str:
    """Return vcf depot secret snapshot.

    Args:
        context: Operation context providing related state and metadata.
    """
    token_state = context["vcf_depot_download_token"]
    activation_state = context["vcf_depot_activation_code"]
    return "\n".join(
        [
            "# VCFDT input file status",
            "# Contents are not rendered here.",
            f"# Download token input file: {'staged' if token_state.present else 'not staged'}",
            f"# Download token input updated: {token_state.updated_at or 'never'}",
            f"# Activation-code input file: {'staged' if activation_state.present else 'not staged'}",
            f"# Activation-code input updated: {activation_state.updated_at or 'never'}",
        ]
    )


def vcf_depot_tool_snapshot(context: dict[str, Any]) -> str:
    """Return vcf depot tool snapshot.

    Args:
        context: Operation context providing related state and metadata.
    """
    settings = context["vcf_depot_settings"]
    archive_path = Path(settings.tool_archive_path) if settings.tool_archive_path else None
    archive_name = archive_path.name if archive_path else "not staged"
    archive_size = "missing"
    archive_mtime = "missing"
    if archive_path:
        try:
            archive_stat = archive_path.stat()
            archive_size = str(archive_stat.st_size)
            archive_mtime = str(archive_stat.st_mtime_ns)
        except OSError:
            pass
    software_depot_id = context["vcf_depot_software_depot_id"]
    return "\n".join(
        [
            "# VCFDT tool package status",
            f"# Archive: {archive_name}",
            f"# Archive size bytes: {archive_size if archive_path else 'not staged'}",
            f"# Archive modified ns: {archive_mtime if archive_path else 'not staged'}",
            f"# Tool version: {settings.tool_version or 'not detected'}",
            f"# Software depot ID: {'generated' if software_depot_id.get('id') else 'not generated'}",
            f"# Runtime reset pending: {'yes' if context.get('vcf_depot_runtime_reset_pending') else 'no'}",
        ]
    )


def vcf_depot_application_properties_snapshot(context: dict[str, Any]) -> str:
    """Return vcf depot application properties snapshot.

    Args:
        context: Operation context providing related state and metadata.
    """
    properties = context["vcf_depot_application_properties"]
    content = str(properties.get("content") or "").strip()
    if not content:
        content = "# No application-prodv2.properties desired state is available."
    return "\n".join(
        [
            f"# VCFDT {VCF_DEPOT_APPLICATION_PROPERTIES_NAME}",
            f"# Source: {properties.get('source') or 'unknown'}",
            f"# Updated: {properties.get('updated_at') or 'not saved'}",
            f"# Staged path: {VCF_DEPOT_STAGED_APPLICATION_PROPERTIES_PATH}",
            content,
        ]
    )


def vcf_depot_command_entry(command: list[str], *, dry_run: bool) -> dict[str, Any]:
    """Return vcf depot command entry.

    Args:
        command: Command and arguments to execute.
        dry_run: Whether to report planned actions without mutating host state.
    """
    resolved = [
        f"{VCF_DEPOT_RUNTIME_TOOL_DIR}/bin/vcf-download-tool" if value == "vcf-download-tool" else value
        for value in command
    ]
    return {
        "command": resolved,
        "command_line": " ".join(shlex.quote(value) for value in resolved),
        "dry_run": dry_run,
        "stdout": "dry-run: VCFDT download command recorded" if dry_run else "",
        "stderr": "",
        "returncode": 0,
    }


def vcf_depot_runtime_secret_path(staged_path: str) -> Path:
    """Return vcf depot runtime secret path.

    Args:
        staged_path: Filesystem path used for staged.
    """
    name = Path(staged_path).name
    return filesystem_path(VCF_DEPOT_VDT_LOG_PATH.parent.parent / "secrets" / name)


def vcf_depot_runtime_command(command: list[str], tool_path: Path) -> list[str]:
    """Return vcf depot runtime command.

    Args:
        command: Command and arguments to execute.
        tool_path: Filesystem path used for tool.
    """
    runtime_command: list[str] = []
    for arg in command:
        if arg == "vcf-download-tool":
            runtime_command.append(str(tool_path))
        elif arg == f"--depot-download-token-file={VCF_DEPOT_STAGED_TOKEN_FILE}":
            runtime_command.append(f"--depot-download-token-file={vcf_depot_runtime_secret_path(VCF_DEPOT_STAGED_TOKEN_FILE)}")
        elif arg == f"--depot-download-activation-code-file={VCF_DEPOT_STAGED_ACTIVATION_FILE}":
            runtime_command.append(f"--depot-download-activation-code-file={vcf_depot_runtime_secret_path(VCF_DEPOT_STAGED_ACTIVATION_FILE)}")
        else:
            runtime_command.append(arg)
    return runtime_command


def resolve_vcf_download_tool(settings: VcfOfflineDepotSettings) -> Path:
    """Return vcf download tool.

    Args:
        settings: Current Atlaso settings used to configure the operation.


    Raises:
        FileNotFoundError: If a required file does not exist.
    """
    archive = Path(settings.tool_archive_path)
    if VCF_DEPOT_EXTRACT_DIR.exists():
        try:
            return _find_vcf_download_tool_binary(VCF_DEPOT_EXTRACT_DIR)
        except FileNotFoundError:
            pass
    if archive.is_file():
        _safe_extract_tar_gz(archive, VCF_DEPOT_EXTRACT_DIR)
        return _find_vcf_download_tool_binary(VCF_DEPOT_EXTRACT_DIR)
    staged = Path(VCF_DEPOT_STAGED_TOOL_DIR) / "vcf-download-tool"
    if staged.is_file():
        return staged
    raise FileNotFoundError(f"VCF Download Tool archive does not exist: {archive}")


def vcf_download_tool_home(tool_path: Path) -> Path:
    """Return vcf download tool home.

    Args:
        tool_path: Filesystem path used for tool.
    """
    return tool_path.parent.parent if tool_path.parent.name == "bin" else tool_path.parent


def write_vcf_depot_runtime_file(path: Path, value: str) -> None:
    """Persist vcf depot runtime file.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        value: Value to process.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def stage_vcf_depot_runtime_application_properties(db: Session, settings: VcfOfflineDepotSettings, tool_home: Path) -> None:
    """Handle stage vcf depot runtime application properties.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        tool_home: Tool home supplied by the caller.
    """
    properties = vcf_depot_application_properties_context(db, settings)
    content = str(properties.get("content") or "")
    if content.strip():
        write_vcf_depot_runtime_file(tool_home / "conf" / VCF_DEPOT_APPLICATION_PROPERTIES_NAME, content)


def stage_vcf_depot_runtime_secrets(db: Session) -> None:
    """Handle stage vcf depot runtime secrets.

    Args:
        db: Active database session.
    """
    token = setting_value(db, VCF_DEPOT_TOKEN_VALUE_KEY)
    if token.strip():
        write_vcf_depot_runtime_file(vcf_depot_runtime_secret_path(VCF_DEPOT_STAGED_TOKEN_FILE), token)
    activation_code = setting_value(db, VCF_DEPOT_ACTIVATION_VALUE_KEY)
    if activation_code.strip():
        write_vcf_depot_runtime_file(vcf_depot_runtime_secret_path(VCF_DEPOT_STAGED_ACTIVATION_FILE), activation_code)


def stage_vcf_depot_runtime_secrets_after_upload(db: Session) -> None:
    """Handle stage vcf depot runtime secrets after upload.

    Args:
        db: Active database session.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    try:
        stage_vcf_depot_runtime_secrets(db)
    except OSError as exc:
        if get_settings().environment == "appliance":
            raise HTTPException(
                status_code=500,
                detail="Unable to stage VCFDT runtime credential files under /var/lib/atlaso/vcfDownloadTool/active-tool/secrets.",
            ) from exc


def prepare_vcf_depot_runtime(settings: VcfOfflineDepotSettings, db: Session) -> Path:
    """Return prepare vcf depot runtime.

    Args:
        settings: Desired or runtime settings consumed by the operation.
        db: Active database session.
    """
    tool_path = resolve_vcf_download_tool(settings)
    tool_home = vcf_download_tool_home(tool_path)
    vdt_log_path = filesystem_path(VCF_DEPOT_VDT_LOG_PATH)
    vdt_log_path.parent.mkdir(parents=True, exist_ok=True)
    vdt_log_path.touch(exist_ok=True)
    stage_vcf_depot_runtime_secrets(db)
    stage_vcf_depot_runtime_application_properties(db, settings, tool_home)
    appliance_settings = get_appliance_settings_row(db)
    telemetry_choice = "ENABLE" if appliance_settings.vmware_ceip_enabled else "DISABLE"
    telemetry_file = tool_home / "conf" / "telemetry" / "telemetry.flag"
    write_vcf_depot_runtime_file(telemetry_file, f"obtu.telemetry.config={telemetry_choice}\n")
    Path(settings.depot_store_path).mkdir(parents=True, exist_ok=True)
    return tool_path


def append_vcf_depot_log(text: str) -> None:
    """Handle append vcf depot log.

    Args:
        text: Text content consumed by the operation.
    """
    vdt_log_path = filesystem_path(VCF_DEPOT_VDT_LOG_PATH)
    vdt_log_path.parent.mkdir(parents=True, exist_ok=True)
    with vdt_log_path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def vcf_depot_task_log_path(job_id: str, profile_name: str = "") -> Path:
    """Return vcf depot task log path.

    Args:
        job_id: Stable identifier of the associated job resource.
        profile_name: Profile name consumed by VCF depot task log path.
    """
    return filesystem_path(vcf_depot_task_log_reference(job_id, profile_name))


def append_vcf_depot_task_log(job_id: str, profile_name: str, text: str) -> None:
    """Handle append vcf depot task log.

    Args:
        job_id: Stable identifier of the associated job resource.
        profile_name: Profile name consumed by append VCF depot task log.
        text: Text content consumed by the operation.
    """
    append_vcf_depot_log(text)


def resolve_vcf_depot_download_mode_flags(*flags: str | None) -> tuple[bool, bool, bool]:
    """Return vcf depot download mode flags.

    Args:
        *flags: Additional positional arguments accepted by the callable.


    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    selected = tuple(flag == "on" for flag in flags)
    if sum(selected) > 1:
        raise HTTPException(
            status_code=400,
            detail="Choose only one VCFDT download mode: automated install, upgrades only, or patches only.",
        )
    return selected if any(selected) else (True, False, False)


def vcf_depot_download_preflight(
    db: Session,
    profile: VcfDepotDownloadProfile,
) -> tuple[VcfOfflineDepotSettings, list[list[str]], list[str]]:
    """Return vcf depot download preflight.

    Args:
        db: Active database session.
        profile: Profile supplied by the caller.

    Raises:
        ValueError: If an input value is invalid.
    """
    settings = get_vcf_offline_depot_settings_row(db)
    secrets = vcf_depot_secret_context(db)
    start_blocker = vcf_depot_profile_start_blocker(
        profile,
        download_token_present=bool(secrets["download_token_present"]),
        activation_code_present=bool(secrets["activation_code_present"]),
    )
    if start_blocker:
        raise ValueError(start_blocker)
    if not vcf_depot_tool_installed(settings):
        raise ValueError("Apply the staged VCF Download Tool before starting this profile.")
    all_service_interfaces = service_bind_options(db)
    management_interface_names = {
        str(interface["name"])
        for interface in all_service_interfaces
        if str(interface.get("role") or "").strip().lower() == "management"
    }
    validation_errors, validation_warnings = validate_vcf_depot_state(
        settings,
        [profile],
        {interface["name"] for interface in vcf_depot_service_bind_options(db)},
        bool(secrets["download_token_present"]),
        bool(secrets["activation_code_present"]),
        management_interface_names,
        users=db.execute(select(User).order_by(User.username)).scalars().all(),
    )
    if validation_errors:
        raise ValueError(" ".join(validation_errors))
    commands = vcfdt_commands_for_profile(
        settings,
        profile,
        download_token_present=bool(secrets["download_token_present"]),
        activation_code_present=bool(secrets["activation_code_present"]),
        preferred_credential_type=str(secrets["download_credential_type"]),
    )
    if not commands:
        raise ValueError("The VCFDT download profile did not produce any commands.")
    return settings, commands, validation_warnings


def archive_vcf_depot_task_log(job_id: str, profile_name: str) -> Path:
    """Return archive vcf depot task log.

    Args:
        job_id: Stable identifier of the associated job resource.
        profile_name: Profile name consumed by archive VCF depot task log.
    """
    active_log_path = filesystem_path(VCF_DEPOT_VDT_LOG_PATH)
    task_log_path = vcf_depot_task_log_path(job_id, profile_name)
    task_log_path.parent.mkdir(parents=True, exist_ok=True)
    if active_log_path.exists():
        active_log_path.replace(task_log_path)
    return task_log_path


def run_vcf_depot_download_job(job_id: str, profile_id: int) -> None:
    """Run vcf depot download job.

    Args:
        job_id: Stable identifier of the associated job resource.
        profile_id: Stable identifier of the associated profile resource.


    Raises:
        RuntimeError: If the operation cannot be completed safely.
        ValueError: If an input value is invalid.
    """
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        profile = db.get(VcfDepotDownloadProfile, profile_id)
        started = utcnow()
        if job:
            job.status = JobStatus.RUNNING.value
            job.started_at = started
            job.progress_percent = 5
            db.commit()
        if not job:
            return
        try:
            if profile is None:
                raise ValueError("The VCF Offline Depot profile no longer exists.")
            settings, commands, validation_warnings = vcf_depot_download_preflight(db, profile)
            active_log_path = filesystem_path(VCF_DEPOT_VDT_LOG_PATH)
            active_log_path.parent.mkdir(parents=True, exist_ok=True)
            active_log_path.write_text("", encoding="utf-8")
            appliance_settings = get_appliance_settings_row(db)
            secrets = vcf_depot_secret_context(db)
            generated_script = render_vcfdt_command_preview(
                settings,
                [profile],
                vmware_ceip_enabled=bool(appliance_settings.vmware_ceip_enabled),
                download_token_present=bool(secrets["download_token_present"]),
                activation_code_present=bool(secrets["activation_code_present"]),
                preferred_credential_type=str(secrets["download_credential_type"]),
                include_disabled_profiles=True,
            )
            tool_path = prepare_vcf_depot_runtime(settings, db)
            command_results: list[dict[str, Any]] = []
            append_vcf_depot_task_log(
                job_id,
                profile.name,
                "\n".join(
                    [
                        "===== Generated VCFDT script =====",
                        generated_script.rstrip(),
                        "===== Task output =====",
                        f"===== Atlaso VCFDT job {job_id} started {started.isoformat()} =====",
                        f"profile={profile.name}",
                        f"tool={tool_path}",
                        f"depot_store={settings.depot_store_path}",
                        "",
                    ]
                )
            )
            for index, command in enumerate(commands, start=1):
                runtime_command = vcf_depot_runtime_command(command, tool_path)
                command_line = " ".join(shlex.quote(value) for value in runtime_command)
                append_vcf_depot_task_log(job_id, profile.name, f"$ {command_line}\n")
                completed = subprocess.run(
                    runtime_command,
                    cwd=str(vcf_download_tool_home(tool_path)),
                    capture_output=True,
                    check=False,
                    text=True,
                )
                if completed.stdout:
                    append_vcf_depot_task_log(job_id, profile.name, completed.stdout)
                if completed.stderr:
                    append_vcf_depot_task_log(job_id, profile.name, completed.stderr)
                command_results.append(
                    {
                        "command": runtime_command,
                        "command_line": command_line,
                        "returncode": completed.returncode,
                        "stdout": apply_output_excerpt(completed.stdout),
                        "stderr": apply_output_excerpt(completed.stderr),
                    }
                )
                job.progress_percent = int(index / max(len(commands), 1) * 95)
                job.result = json.dumps(
                    {
                        **json.loads(job.result or "{}"),
                        "commands": command_results,
                        "validation_warnings": validation_warnings,
                    },
                    indent=2,
                    sort_keys=True,
                )
                db.commit()
                if completed.returncode != 0:
                    raise RuntimeError(f"VCFDT command exited with code {completed.returncode}.")
            finished = utcnow()
            profile.status = "synced"
            profile.updated_at = finished
            job.status = JobStatus.SUCCEEDED.value
            job.finished_at = finished
            job.progress_percent = 100
            job.error = None
            job.result = json.dumps(
                {
                    **json.loads(job.result or "{}"),
                    "status": JobStatus.SUCCEEDED.value,
                    "success": True,
                },
                indent=2,
                sort_keys=True,
            )
            append_vcf_depot_task_log(job_id, profile.name, f"===== Atlaso VCFDT job {job_id} succeeded {finished.isoformat()} =====\n")
            archive_vcf_depot_task_log(job_id, profile.name)
            db.add(
                AuditEvent(
                    actor=job.created_by,
                    action="complete_vcf_depot_download",
                    resource_type="job",
                    resource_id=job.id,
                    detail=f"profile_id={profile.id}; trigger={job.trigger}",
                )
            )
            db.commit()
        except Exception as exc:  # noqa: BLE001 - background worker must persist failures instead of crashing silently.
            finished = utcnow()
            profile_name = profile.name if profile is not None else "deleted-profile"
            if profile is not None:
                profile.status = "blocked"
                profile.updated_at = finished
            job.status = JobStatus.FAILED.value
            job.finished_at = finished
            job.progress_percent = 100
            job.error = str(exc)
            job.result = json.dumps(
                {
                    **json.loads(job.result or "{}"),
                    "status": JobStatus.FAILED.value,
                    "success": False,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
            try:
                append_vcf_depot_task_log(job_id, profile_name, f"ERROR: {exc}\n")
                append_vcf_depot_task_log(
                    job_id,
                    profile_name,
                    f"===== Atlaso VCFDT job {job_id} failed {finished.isoformat()} =====\n",
                )
                archive_vcf_depot_task_log(job_id, profile_name)
            except OSError:
                # Preserve the actionable execution failure even when a development
                # or recovery environment cannot write the appliance log directory.
                pass
            db.add(
                AuditEvent(
                    actor=job.created_by,
                    action="fail_vcf_depot_download",
                    resource_type="job",
                    resource_id=job.id,
                    success=False,
                    detail=f"profile_id={profile_id}; trigger={job.trigger}; error={exc}",
                )
            )
            db.commit()


def firewall_context(db: Session, *, reconcile: bool = True) -> dict:
    """Return firewall context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = get_firewall_settings_row(db)
    rules = db.execute(select(FirewallRule).order_by(FirewallRule.priority, FirewallRule.name)).scalars().all()
    dns_settings = get_dns_settings_row(db)
    dhcp_settings = get_dhcp_settings_row(db)
    dhcp_scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    interface_networks = firewall_interface_networks(physical_interfaces, vlan_interfaces)
    source_group_state = firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), interface_networks)
    appliance_settings = get_appliance_settings_row(db)
    management = management_interface_context(physical_interfaces)
    terminal_options = web_terminal_interface_options(physical_interfaces, vlan_interfaces)
    terminal_interfaces = (
        web_terminal_listener_interfaces(
            normalized_web_terminal_interfaces(appliance_settings, management),
            terminal_options,
        )
        if appliance_settings.web_terminal_enabled
        else []
    )
    generated_rules = managed_service_firewall_rules(
        dns_settings=dns_settings,
        dhcp_settings=dhcp_settings,
        dhcp_scopes=dhcp_scopes,
        ca_settings=get_ca_settings_row(db),
        ca_portal_interfaces=ca_portal_firewall_interfaces(physical_interfaces, vlan_interfaces, interface_networks),
        kms_settings=get_kms_settings_row(db),
        ntp_settings=get_ntp_settings_row(db),
        vcf_backup_settings=get_vcf_backup_settings_row(db, reconcile_default_user=reconcile),
        vcf_depot_settings=get_vcf_offline_depot_settings_row(
            db,
            reconcile_default_user=reconcile,
            reconcile=reconcile,
        ),
        vcf_registry_settings=get_vcf_private_registry_settings_row(db, reconcile=reconcile),
        esxi_pxe_boot=esxi_pxe_boot_settings(db),
        interface_networks=interface_networks,
        source_groups=source_group_state["groups"],
        source_group_assignments=source_group_state["assignments"],
        web_terminal_interfaces=terminal_interfaces,
        ldap_settings=get_ldap_settings_row(db),
        oidc_settings=ensure_oidc_provider_settings(db),
        esx_storage_rules=esx_storage_firewall_rule_specs(esx_storage_context(db, reconcile=False)["esx_storage_manifest"]),
        management_interface=management.get("name", ""),
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
    config_preview = render_nftables_config(
        settings,
        rules,
        generated_rules,
        source_groups=source_group_state["groups"],
        replace_atlaso_service_rules=True,
    )
    validation_errors = [
        *validate_firewall_source_groups(source_group_state["groups"]),
        *validate_firewall_state(
            settings,
            rules,
            generated_rules,
            source_groups=source_group_state["groups"],
            replace_atlaso_service_rules=True,
        ),
    ]
    editable_rules = [rule for rule in rules if not is_atlaso_managed_firewall_rule(rule)]
    replaced_rules = [rule for rule in rules if is_atlaso_managed_firewall_rule(rule)]
    available_interfaces = service_bind_options(db)
    return {
        "firewall_settings": settings,
        "firewall_rules": editable_rules,
        "firewall_rules_json": [firewall_rule_to_dict(rule) for rule in editable_rules],
        "firewall_generated_rules": generated_rules,
        "firewall_generated_rules_json": [firewall_rule_to_dict(rule) for rule in generated_rules],
        "firewall_managed_rule_rows": managed_firewall_rule_rows(generated_rules, replaced_rules, source_group_state["groups"], source_group_state["assignments"]),
        "firewall_source_groups": source_group_state["groups"],
        "firewall_source_group_assignments": source_group_state["assignments"],
        "firewall_config_preview": config_preview,
        "firewall_validation_errors": validation_errors,
        "firewall_service_status": service_runtime_status(db, "firewall"),
        "firewall_directions": FIREWALL_DIRECTIONS,
        "firewall_actions": FIREWALL_ACTIONS,
        "firewall_protocols": FIREWALL_PROTOCOLS,
        "firewall_policies": FIREWALL_POLICIES,
        "firewall_interface_options": available_interfaces,
    }


def managed_firewall_rule_rows(
    generated_rules: list[FirewallRule],
    replaced_rules: list[FirewallRule],
    source_groups: list[dict] | None = None,
    assignments: dict[str, str] | None = None,
) -> list[dict]:
    """Return managed firewall rule rows.

    Args:
        generated_rules: Generated rules consumed by managed firewall rule rows.
        replaced_rules: Replaced rules consumed by managed firewall rule rows.
        source_groups: Source groups consumed by managed firewall rule rows.
        assignments: Assignments consumed by managed firewall rule rows.
    """
    rows: list[dict] = []
    replaced_by_name: dict[str, list[FirewallRule]] = {}
    source_groups_by_id = {str(group["id"]): group for group in source_groups or []}
    assignments = assignments or {}
    for rule in replaced_rules:
        replaced_by_name.setdefault(rule.name.strip().lower(), []).append(rule)
    for rule in generated_rules:
        if ATLASO_DHCP_FIREWALL_RULE_MARKER in (rule.description or ""):
            source_group_id = ""
            source_group = {"name": "DHCP bootstrap", "entries": ["interface-bound"]}
        else:
            source_group_id = assignments.get(rule.name, "any")
            if source_group_id not in source_groups_by_id:
                source_group_id = "any"
            source_group = source_groups_by_id.get(source_group_id, {})
        rows.append(
            {
                **firewall_rule_to_dict(rule),
                "id": f"generated:{rule.name}",
                "managed_state": "generated",
                "managed_status": "generated",
                "source_group_id": source_group_id,
                "source_group_name": source_group.get("name", source_group_id),
                "source_group_sources": ", ".join(source_group.get("entries") or source_group.get("sources") or []),
            }
        )
        for replaced_rule in replaced_by_name.pop(rule.name.strip().lower(), []):
            rows.append(managed_replaced_firewall_rule_row(replaced_rule))
    for matching_replaced_rules in replaced_by_name.values():
        for rule in matching_replaced_rules:
            rows.append(managed_replaced_firewall_rule_row(rule))
    return rows


def managed_replaced_firewall_rule_row(rule: FirewallRule) -> dict:
    """Return managed replaced firewall rule row.

    Args:
        rule: Rule consumed by managed replaced firewall rule row.
    """
    return {
        **firewall_rule_to_dict(rule),
        "id": f"replaced:{rule.id or rule.name}",
        "managed_state": "replaced",
        "managed_status": "replaced",
        "source_group_id": "",
        "source_group_name": "",
        "source_group_sources": "",
        "enabled": False,
    }


def ca_context(db: Session, *, reconcile: bool = True) -> dict:
    """Return ca context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    state_errors = ensure_ca_state(db) if reconcile else []
    settings = get_ca_settings_row(db)
    if reconcile and normalize_service_bind_settings(db, settings):
        db.commit()
        db.refresh(settings)
    available_interfaces = service_bind_options(db)
    available_names = {option["name"] for option in available_interfaces}
    profiles = db.execute(select(CaProfile).order_by(CaProfile.name)).scalars().all()
    certificates = (
        db.execute(select(CaCertificate).options(selectinload(CaCertificate.profile)).order_by(CaCertificate.common_name))
        .scalars()
        .all()
    )
    config_preview = render_ca_config(settings=settings, profiles=profiles, certificates=certificates)
    apply_payload = render_ca_apply_payload(settings, certificates, include_private_keys=False)
    validation_errors = [*state_errors, *validate_ca_state(settings=settings, profiles=profiles, certificates=certificates)]
    selected_interfaces = split_interfaces(settings.listen_interface)
    invalid_interfaces = [interface for interface in selected_interfaces if interface not in available_names]
    if settings.enabled and invalid_interfaces:
        validation_errors.append("CA listen interfaces must be access physical interfaces or enabled VLANs with IP addresses.")
    issued_count = len([certificate for certificate in certificates if certificate.status == "issued"])
    expiring_count = len(
        [
            certificate
            for certificate in certificates
            if certificate.status == "issued" and certificate.expires_at and ensure_aware(certificate.expires_at) <= utcnow() + timedelta(days=30)
        ]
    )
    managed_count = len([certificate for certificate in certificates if certificate.managed_owner])
    key_status = secret_key_status()
    ca_status = ca_service_state(settings)
    if settings.enabled and validation_errors:
        ca_status = {**ca_status, "health": "degraded", "label": "needs attention", "pill": "warn"}
    return {
        "ca_settings": settings,
        "ca_public_portal_url": _absolute_public_url(
            "https",
            settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME,
            public_ui_path("/ca/requests"),
            port=443,
        ),
        "ca_profiles": profiles,
        "ca_profile_rows": [ca_profile_to_dict(profile) for profile in profiles],
        "ca_certificate_rows": [ca_certificate_to_dict(certificate) for certificate in certificates],
        "ca_profile_choices": [
            {
                "id": profile.id,
                "label": profile.name,
                "certificate_type": profile.certificate_type,
                "san_required": profile.san_required,
            }
            for profile in profiles
            if profile.enabled
        ],
        "available_interfaces": available_interfaces,
        "available_ca_addresses": available_service_listen_addresses(settings.listen_address, available_interfaces),
        "selected_ca_interfaces": selected_interfaces,
        "selected_ca_addresses": split_addresses(settings.listen_address),
        "ca_certificates": certificates,
        "ca_config_preview": config_preview,
        "ca_apply_payload": apply_payload,
        "ca_apply_config_path": CA_STAGED_CONFIG_PATH,
        "ca_validation_errors": validation_errors,
        "ca_service_status": ca_status,
        "ca_status_summary": {
            "root_present": bool(settings.root_certificate_pem),
            "bundle_present": bool(settings.root_certificate_pem),
            "issued_count": issued_count,
            "expiring_count": expiring_count,
            "managed_count": managed_count,
            "secrets_key_source": key_status.source,
            "secrets_key_dedicated": key_status.dedicated,
        },
    }


def public_services_context(db: Session, *, reconcile: bool = True) -> dict[str, Any]:
    """Return public services context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).where(VlanInterface.enabled.is_(True)).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    ca_settings = get_ca_settings_row(db)
    depot_settings = get_vcf_offline_depot_settings_row(
        db,
        reconcile_default_user=reconcile,
        reconcile=reconcile,
    )
    registry_settings = get_vcf_private_registry_settings_row(db, reconcile=reconcile)
    oidc_settings = ensure_oidc_provider_settings(db)
    esxi_boot = esxi_pxe_boot_settings(db)
    entries = public_service_entries(
        interfaces=interfaces,
        vlans=vlans,
        ca_settings=ca_settings,
        esxi_pxe_boot=esxi_boot,
        vcf_depot_settings=depot_settings,
        vcf_registry_settings=registry_settings,
        oidc_settings=oidc_settings,
    )
    management_interfaces = {
        interface.name
        for interface in interfaces
        if normalize_interface_role(interface.role) == "access"
        and normalize_interface_mode(interface.mode) == "access"
        and interface.admin_state == "up"
        and interface.access_management_ui_enabled
    }
    management_interfaces.update(
        vlan.name
        for vlan in vlans
        if normalize_interface_role(vlan.role) == "access"
        and vlan.access_management_ui_enabled
    )
    for entry in entries:
        entry["management_ui"] = entry.get("interface") in management_interfaces
    appliance_settings = get_appliance_settings_row(db)
    management = appliance_settings_management_context(db)
    terminal_options = web_terminal_interface_options(interfaces, vlans)
    terminal_interfaces = web_terminal_listener_interfaces(
        normalized_web_terminal_interfaces(appliance_settings, management),
        terminal_options,
    )
    terminal_cert_path, terminal_key_path, _terminal_chain_path = ca_managed_certificate_paths(db, "appliance:https")
    terminal_https_ready = bool(
        appliance_settings.management_https_enabled
        and terminal_cert_path
        and terminal_key_path
        and ca_certificate_available(db, "appliance:https")
    )
    terminal_addresses = set(
        web_terminal_addresses(terminal_interfaces, terminal_options)
        if appliance_settings.web_terminal_enabled and terminal_https_ready
        else []
    )
    management_address = management.get("ip", "")
    for entry in entries:
        entry["web_terminal"] = bool(entry.get("address") in terminal_addresses and entry.get("address") != management_address)
    terminal_extra_requested = bool(
        appliance_settings.web_terminal_enabled
        and any(
            address != management_address
            for address in web_terminal_addresses(terminal_interfaces, terminal_options)
        )
    )
    validation_errors = []
    if depot_settings.enabled and not depot_settings.allow_unauthenticated_access:
        depot_user = db.get(User, depot_settings.http_user_id) if depot_settings.http_user_id else None
        if depot_user is None:
            validation_errors.append(
                "Public Services cannot publish VCF Offline Depot until an HTTP user is selected."
            )
        elif not depot_user.enabled:
            validation_errors.append(
                f"Public Services cannot publish VCF Offline Depot while HTTP user {depot_user.username} is disabled. "
                "Enable the user and apply Local Users first."
            )
    if terminal_extra_requested and not terminal_https_ready:
        validation_errors.append(
            "Web terminal public listeners require valid Management HTTPS and an issued appliance HTTPS certificate. Apply Certificate Authority and Appliance Settings first."
        )
    ca_portal_hostname = normalize_dns_hostname(ca_settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME)
    ca_portal_cert_path, ca_portal_key_path, _ca_portal_chain_path = ca_service_cert_paths("ca-portal", ca_portal_hostname)
    oidc_cert_path, oidc_key_path, _oidc_chain_path = ca_managed_certificate_paths(
        db, "oidc:https"
    )
    if oidc_settings.enabled and (not oidc_cert_path or not oidc_key_path):
        validation_errors.append(
            "OIDC public listeners require an issued managed OIDC service certificate. Apply Certificate Authority first."
        )
    config_preview = render_public_services_nginx_config(
        entries,
        depot_store_path=depot_settings.depot_store_path,
        http_port=int(esxi_boot.get("http_port") or 8080),
        ca_certificate_path=ca_portal_cert_path,
        ca_key_path=ca_portal_key_path,
        terminal_certificate_path=terminal_cert_path,
        terminal_key_path=terminal_key_path,
        oidc_certificate_path=oidc_cert_path,
        oidc_key_path=oidc_key_path,
        management_certificate_path=terminal_cert_path,
        management_key_path=terminal_key_path,
    )
    return {
        "public_service_entries": entries,
        "public_service_config_preview": config_preview,
        "public_service_config_path": PUBLIC_SERVICES_STAGED_CONFIG_PATH,
        "public_service_validation_errors": validation_errors,
        "public_service_validation_warnings": [],
    }


def public_ca_context(db: Session) -> dict:
    """Return public ca context.

    Args:
        db: Active database session.
    """
    settings = get_ca_settings_row(db)
    return {
        "ca_settings": settings,
        "portal_hostname": settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME,
        "root_available": bool(settings.root_certificate_pem),
        "root_fingerprint": settings.root_fingerprint,
        "root_issued_at": settings.root_issued_at,
        "root_expires_at": settings.root_expires_at,
        **public_portal_links_context(db),
    }


def public_portal_links_context(db: Session) -> dict[str, str]:
    """Return public portal links context.

    Args:
        db: Active database session.
    """
    management = appliance_settings_management_context(db)
    settings = get_appliance_settings_row(db)
    host = _url_host(management.get("ip") or settings.fqdn)
    scheme = "https" if settings.management_https_enabled else "http"
    base_url = f"{scheme}://{host}" if host else ""
    return {
        "public_management_base_url": base_url,
        "public_management_url": f"{base_url}{MANAGEMENT_UI_ROOT}" if base_url else "",
        "public_swagger_url": f"{base_url}/api/docs" if base_url else "/api/docs",
        "public_openapi_url": f"{base_url}/api/docs" if base_url else "/api/docs",
    }


def _url_host(value: str) -> str:
    """Return url host.

    Args:
        value: Candidate value consumed by URL host.
    """
    host = (value or "").strip().strip(".")
    if not host:
        return ""
    try:
        parsed = ip_address(host.strip("[]"))
    except ValueError:
        return host
    return f"[{parsed}]" if parsed.version == 6 else str(parsed)


def _absolute_public_url(scheme: str, host: str, path: str, *, port: int | None = None) -> str:
    """Return absolute public url.

    Args:
        scheme: Scheme supplied by the caller.
        host: Host targeted by the operation.
        path: Filesystem or URL path to read, validate, or update.
        port: TCP or UDP port of the target service.
    """
    normalized_host = _url_host(host)
    if not normalized_host:
        return path
    normalized_path = path if path.startswith("/") else f"/{path}"
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    port_part = "" if not port or default_port else f":{port}"
    return f"{scheme}://{normalized_host}{port_part}{normalized_path}"


def _public_service_hostname(service: dict[str, Any]) -> str:
    """Return public service hostname.

    Args:
        service: Atlaso or host service affected by the operation.
    """
    for value in service.get("dns_names") or []:
        candidate = str(value or "").strip().strip(".")
        if candidate:
            return candidate
    return ""


def public_service_link_variants(service: dict[str, Any], binding: dict[str, str], *, esxi_pxe_boot: dict[str, Any]) -> dict[str, str]:
    """Return public service link variants.

    Args:
        service: Atlaso or host service affected by the operation.
        binding: Binding consumed by public service link variants.
        esxi_pxe_boot: Esxi pxe boot consumed by public service link variants.
    """
    service_id = str(service.get("id") or "")
    address = str(binding.get("address") or "")
    hostname = _public_service_hostname(service) or address
    try:
        service_port = int(service.get("port") or 0)
    except (TypeError, ValueError):
        service_port = 0
    if service_id == "ca":
        name_href = _absolute_public_url("https", hostname, public_ui_path("/ca"), port=service_port or 443)
        ip_href = _absolute_public_url("https", address, public_ui_path("/ca"), port=service_port or 443)
    elif service_id == "vcf_offline_depot":
        name_href = _absolute_public_url("https", hostname, "/PROD/", port=service_port or 443)
        ip_href = _absolute_public_url("https", address, "/PROD/", port=service_port or 443)
    elif service_id == "esxi_pxe":
        try:
            http_port = int(service_port or esxi_pxe_boot.get("http_port") or 8080)
        except (TypeError, ValueError):
            http_port = 8080
        name_href = _absolute_public_url("http", hostname, "/pxe/esxi/", port=http_port)
        ip_href = _absolute_public_url("http", address, "/pxe/esxi/", port=http_port)
    elif service_id == "web_terminal":
        name_href = _absolute_public_url("https", address, public_ui_path("/terminal"), port=service_port or 443)
        ip_href = name_href
    else:
        name_href = str(service.get("href") or "")
        ip_href = name_href
    return {"href": name_href, "name_href": name_href, "ip_href": ip_href}


def safe_login_next(value: str | None) -> str:
    """Return a fail-closed management-plane login target.

    Args:
        value: Candidate value consumed by safe login next.
    """
    return safe_management_return_path(value)


def request_host_name(request: Request) -> str:
    """Return the trusted listener address or direct request host name.

    Args:
        request: Incoming HTTP request.
    """
    listener_address = (request.headers.get("x-atlaso-listener-address") or "").strip().strip("[]")
    server_host = str((request.scope.get("server") or ("", 0))[0]).strip().strip("[]")
    try:
        trusted_proxy = ip_address(server_host).is_loopback
    except ValueError:
        trusted_proxy = False
    if trusted_proxy and listener_address:
        try:
            return str(ip_address(listener_address)).lower()
        except ValueError:
            pass
    raw_host = (request.headers.get("host") or "").strip().lower()
    if raw_host.startswith("["):
        closing_bracket = raw_host.find("]")
        if closing_bracket != -1:
            return raw_host[1:closing_bracket].strip().strip(".")
    return raw_host.split(":", 1)[0].strip().strip(".")


def interface_address(raw_cidr: str | None) -> str:
    """Return interface address.

    Args:
        raw_cidr: Raw cidr consumed by interface address.
    """
    if not raw_cidr:
        return ""
    try:
        return str(ip_interface(raw_cidr.strip()).ip).lower()
    except ValueError:
        return ""


def request_host_interface_role(request_host: str, db: Session) -> str:
    """Return request host interface role.

    Args:
        request_host: Request host supplied by the caller.
        db: Active database session.
    """
    binding = request_host_interface_binding(request_host, db)
    return str((binding or {}).get("role") or "")


def request_host_interface_binding(request_host: str, db: Session) -> dict[str, Any] | None:
    """Return request host interface binding.

    Args:
        request_host: Request host supplied by the caller.
        db: Active database session.
    """
    if not request_host:
        return None
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    enabled_vlans = db.execute(
        select(VlanInterface)
        .where(VlanInterface.enabled.is_(True))
        .order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    entries = public_service_interface_entries(
        physical_interfaces,
        enabled_vlans,
    )
    applied_bindings = applied_management_bindings(db)
    use_desired_fallback = applied_bindings is None
    physical_management = {
        interface.name: use_desired_fallback
        and (
            normalize_interface_role(interface.role) == "management"
            or (
                normalize_interface_role(interface.role) == "access"
                and normalize_interface_mode(interface.mode) == "access"
                and interface.admin_state == "up"
                and interface.access_management_ui_enabled
            )
        )
        for interface in physical_interfaces
    }
    vlan_management = {
        vlan.name: use_desired_fallback
        and normalize_interface_role(vlan.role) == "access"
        and vlan.access_management_ui_enabled
        for vlan in enabled_vlans
    }
    for entry in entries:
        entry["management_ui"] = bool(
            physical_management.get(entry["interface"], False)
            or vlan_management.get(entry["interface"], False)
        )
    for interface in physical_interfaces:
        if interface.oper_state == "missing":
            continue
        for cidr in (interface.host_ip_cidr, interface.host_ipv6_cidr):
            address = interface_address(cidr)
            if address:
                entries.append(
                    {
                        "interface": interface.name,
                        "role": normalize_interface_role(interface.role),
                        "address": address,
                        "management_ui": physical_management.get(interface.name, False),
                    }
                )
    if applied_bindings is not None:
        entries.extend(
            {
                **binding,
                "management_ui": True,
            }
            for binding in applied_bindings
        )
    by_address = {entry["address"].lower(): entry for entry in entries}
    try:
        parsed_host = str(ip_address(request_host.strip("[]"))).lower()
    except ValueError:
        parsed_host = ""
    if parsed_host and parsed_host in by_address:
        return by_address[parsed_host]

    hostname = normalize_dns_hostname(request_host)
    candidate_addresses: list[str] = []
    if hostname:
        records = db.execute(
            select(DnsRecord).where(
                DnsRecord.enabled.is_(True),
                DnsRecord.hostname == hostname,
                DnsRecord.record_type.in_(["A", "AAAA"]),
            )
        ).scalars()
        candidate_addresses.extend(record.address for record in records)

        appliance_settings = db.execute(select(ApplianceSettings).order_by(ApplianceSettings.id)).scalars().first()
        if appliance_settings is not None and hostname == normalize_dns_hostname(appliance_settings.fqdn):
            candidate_addresses.extend(
                entry["address"] for entry in entries if entry.get("management_ui")
            )

        ca_settings = db.execute(select(CaSettings).order_by(CaSettings.id)).scalars().first()
        if ca_settings is not None and hostname == normalize_dns_hostname(ca_settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME):
            candidate_addresses.extend(split_addresses(ca_settings.listen_address))

        depot_settings = db.execute(select(VcfOfflineDepotSettings).order_by(VcfOfflineDepotSettings.id)).scalars().first()
        if depot_settings is not None and hostname == normalize_dns_hostname(depot_settings.hostname or VCF_DEPOT_DEFAULT_HOSTNAME):
            candidate_addresses.extend(split_addresses(depot_settings.listen_address))

        registry_settings = db.execute(select(VcfPrivateRegistrySettings).order_by(VcfPrivateRegistrySettings.id)).scalars().first()
        if registry_settings is not None and hostname == normalize_dns_hostname(registry_settings.hostname or VCF_REGISTRY_DEFAULT_HOSTNAME):
            candidate_addresses.extend(split_addresses(registry_settings.listen_address))

        esxi_boot = esxi_pxe_boot_settings(db)
        if hostname == normalize_dns_hostname(str(esxi_boot.get("hostname") or "")):
            candidate_addresses.extend(split_addresses(str(esxi_boot.get("listen_address") or "")))

    for candidate in candidate_addresses:
        try:
            normalized = str(ip_address(candidate)).lower()
        except ValueError:
            continue
        if normalized in by_address:
            return by_address[normalized]
    return None


def public_service_directory_context(db: Session, binding: dict[str, str]) -> dict[str, Any]:
    """Return public service directory context.

    Args:
        db: Active database session.
        binding: Binding supplied by the caller.
    """
    ca_settings = get_ca_settings_row(db)
    depot_settings = get_vcf_offline_depot_settings_row(db)
    registry_settings = get_vcf_private_registry_settings_row(db)
    esxi_boot = esxi_pxe_boot_settings(db)
    services = public_services_for_address(
        binding["address"],
        ca_settings=ca_settings,
        esxi_pxe_boot=esxi_boot,
        vcf_depot_settings=depot_settings,
        vcf_registry_settings=registry_settings,
        oidc_settings=ensure_oidc_provider_settings(db),
    )
    appliance_settings = get_appliance_settings_row(db)
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlan_interfaces = db.execute(select(VlanInterface).where(VlanInterface.enabled.is_(True)).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    management = appliance_settings_management_context(db)
    terminal_options = web_terminal_interface_options(physical_interfaces, vlan_interfaces)
    terminal_interfaces = web_terminal_listener_interfaces(
        normalized_web_terminal_interfaces(appliance_settings, management),
        terminal_options,
    )
    if appliance_settings.web_terminal_enabled and binding.get("interface") in terminal_interfaces:
        services.append(
            {
                "id": "web_terminal",
                "name": "Web Terminal",
                "summary": "Administrative appliance shell",
                "dns_names": [],
                "scheme": "https",
                "port": 443,
                "status": "enabled",
                "pill": "good",
            }
        )
    services = [
        {
            **service,
            **public_service_link_variants(service, binding, esxi_pxe_boot=esxi_boot),
        }
        for service in services
    ]
    return {
        "public_interface": binding,
        "public_services": services,
        "public_service_count": len(services),
        "public_ca_service_available": any(service.get("id") == "ca" for service in services),
        "public_address_mode_switch": bool(services),
        "public_github_url": "https://github.com/mdaneri/Atlaso",
        "current_version_info": current_version_info(),
        **public_portal_links_context(db),
    }


def request_allows_public_service(db: Session, request: Request, service_id: str) -> bool:
    """Return request allows public service.

    Args:
        db: Active database session.
        request: Incoming HTTP request.
        service_id: Identifier of the service.
    """
    binding = request_host_interface_binding(request_host_name(request), db)
    if not binding or binding.get("role") == "management":
        return False
    services = public_service_directory_context(db, binding)["public_services"]
    return any(service.get("id") == service_id for service in services)


def request_public_service_route_allowed(db: Session, request: Request, service_id: str) -> bool:
    """Return request public service route allowed.

    Args:
        db: Active database session.
        request: Incoming HTTP request.
        service_id: Identifier of the service.
    """
    binding = request_host_interface_binding(request_host_name(request), db)
    if not binding or binding.get("role") == "management":
        return True
    services = public_service_directory_context(db, binding)["public_services"]
    return any(service.get("id") == service_id for service in services)


def is_ca_portal_host(request: Request, db: Session) -> bool:
    """Return whether ca portal host.

    Args:
        request: Incoming HTTP request.
        db: Active database session.
    """
    settings = get_ca_settings_row(db)
    request_host = request_host_name(request)
    portal_hostname = normalize_dns_hostname(settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME)
    if portal_hostname and request_host == portal_hostname:
        return True
    interface_role = request_host_interface_role(request_host, db)
    if interface_role == "management":
        return False
    if interface_role:
        return True
    listen_addresses = {address.lower() for address in split_addresses(settings.listen_address)}
    return bool(request_host and request_host in listen_addresses)


def ca_request_to_dict(certificate: CaCertificate) -> dict[str, Any]:
    """Return ca request to dict.

    Args:
        certificate: Certificate record or parsed certificate being processed.
    """
    return {
        "id": certificate.id,
        "common_name": certificate.common_name,
        "profile_name": certificate.profile.name if certificate.profile else "Unassigned",
        "status": certificate.status,
        "serial_number": certificate.serial_number or "",
        "revoked_at": certificate.revoked_at.isoformat() if certificate.revoked_at else "",
        "can_revoke": certificate.status == "issued" and bool(certificate.serial_number),
    }


def ca_request_context(db: Session) -> dict:
    """Return ca request context.

    Args:
        db: Active database session.
    """
    if ensure_default_ca_profiles(db):
        db.commit()
    profiles = db.execute(select(CaProfile).order_by(CaProfile.name)).scalars().all()
    certificates = (
        db.execute(select(CaCertificate).options(selectinload(CaCertificate.profile)).order_by(CaCertificate.common_name))
        .scalars()
        .all()
    )
    return {
        "ca_profiles": profiles,
        "ca_profile_choices": [{"id": profile.id, "label": profile.name} for profile in profiles if profile.enabled],
        "ca_certificates": certificates,
        "ca_request_rows": [ca_request_to_dict(certificate) for certificate in certificates],
    }


def kms_context(db: Session, *, reconcile: bool = True) -> dict:
    """Return kms context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = get_kms_settings_row(db)
    available_interfaces = service_bind_options(db)
    changed = False
    changed = reconcile and normalize_service_bind_settings(db, settings) or changed
    normalized_hostname = normalize_dns_hostname(settings.hostname)
    if reconcile and normalized_hostname and settings.hostname != normalized_hostname:
        settings.hostname = normalized_hostname
        changed = True
    if reconcile and settings.enabled:
        dns_action = ensure_dns_for_kms(db, settings, actor=None, previous_hostname=settings.hostname)
        changed = bool(dns_action) or changed
    if changed:
        settings.updated_at = utcnow()
        db.commit()
        db.refresh(settings)
    ca_state_errors = ensure_ca_state(db) if reconcile else []
    providers = provider_rows(db)
    trusted_vcenters = [
        trusted
        for provider in providers
        for trusted in provider.trusted_vcenters
    ]
    certificates = [
        certificate
        for trusted in trusted_vcenters
        for certificate in trusted.certificates
    ]
    config_preview = render_provider_config(settings, providers)
    trust_bundle = render_client_trust_bundle(db, providers)
    validation_errors = [
        *ca_state_errors,
        *(validate_provider_state(providers) if settings.enabled else []),
    ]
    ca_settings = get_ca_settings_row(db)
    if settings.enabled:
        invalid_interfaces = [
            interface
            for interface in split_interfaces(settings.listen_interface)
            if interface not in {option["name"] for option in available_interfaces}
        ]
        if invalid_interfaces:
            validation_errors.append("KMS listen interface must be an access physical interface or enabled VLAN with an IP address.")
        if kms_dns_record_conflict(db, settings.hostname):
            validation_errors.append("KMS hostname conflicts with an existing non-KMS DNS record.")
        if not ca_settings.enabled:
            validation_errors.append("KMS requires Certificate Authority to be enabled before activation.")
        elif ca_state_errors:
            validation_errors.append("KMS cannot be activated until Certificate Authority state is healthy.")
        elif not ca_certificate_available(db, "kms:server"):
            validation_errors.append("KMS requires an issued CA-managed server certificate before apply.")
    server_certificate = db.execute(
        select(CaCertificate)
        .where(CaCertificate.managed_owner == "kms:server")
        .order_by(CaCertificate.id.desc())
    ).scalars().first()
    runtime = service_runtime_status(db, "kms")
    status_snapshot = runtime_status_snapshot()
    runtime_counts = status_snapshot.get("providers")
    runtime_counts = runtime_counts if isinstance(runtime_counts, dict) else {}
    status_rows = [
        {
            "provider_id": provider.id,
            "provider_name": provider.name,
            "desired_state": "enabled" if provider.enabled else "disabled",
            "readiness": "ready" if provider.enabled and not validate_provider_state([provider]) else "needs attention",
            "runtime_state": str(status_snapshot.get("runtime_state") or runtime["label"]),
            "pre_active_count": runtime_counts.get(provider.id, {}).get("pre_active"),
            "active_count": runtime_counts.get(provider.id, {}).get("active"),
            "total_count": runtime_counts.get(provider.id, {}).get("total"),
            "count_status": "available" if provider.id in runtime_counts else "not reported",
        }
        for provider in providers
    ]
    return {
        "kms_settings": settings,
        "kms_clients": [],
        "kms_keys": [],
        "vsphere_key_providers": providers,
        "vsphere_key_provider_rows": [provider_to_dict(provider) for provider in providers],
        "vsphere_trusted_vcenters": trusted_vcenters,
        "vsphere_trusted_vcenter_rows": [trusted_vcenter_to_dict(trusted) for trusted in trusted_vcenters],
        "vsphere_certificates": certificates,
        "vsphere_certificate_rows": [certificate_to_dict(certificate) for certificate in certificates],
        "vsphere_status_rows": status_rows,
        "vsphere_provider_choices": [{"id": provider.id, "label": provider.name} for provider in providers],
        "kms_client_trust_bundle": trust_bundle,
        "kms_server_certificate": server_certificate,
        "available_interfaces": available_interfaces,
        "selected_kms_interfaces": split_interfaces(settings.listen_interface),
        "selected_kms_addresses": split_addresses(settings.listen_address),
        "available_kms_addresses": available_service_listen_addresses(settings.listen_address, available_interfaces),
        "kms_config_preview": config_preview,
        "kms_validation_errors": validation_errors,
        "kms_service_status": runtime,
        "kms_lab_notice": (
            "The appliance-native atlaso-kmip service implements the bounded candidate VCF 9.1 profile. "
            "Treat it as experimental until the observed interoperability and recovery gate in issue #172 passes; "
            "it is not a production HSM or hardened enterprise key manager."
        ),
    }


def ldap_organizations_query(db: Session) -> list[LdapOrganization]:
    """Return ldap organizations query.

    Args:
        db: Active database session.
    """
    return (
        db.execute(
            select(LdapOrganization)
            .options(
                selectinload(LdapOrganization.users).selectinload(LdapUser.organization),
                selectinload(LdapOrganization.groups).selectinload(LdapGroup.organization),
                selectinload(LdapOrganization.groups).selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_user).selectinload(LdapUser.organization),
                selectinload(LdapOrganization.groups).selectinload(LdapGroup.members).selectinload(LdapGroupMembership.member_group).selectinload(LdapGroup.organization),
            )
            .order_by(LdapOrganization.name)
        )
        .scalars()
        .all()
    )


def ldap_context(db: Session, *, reconcile: bool = True, selected_organization_id: int | None = None) -> dict[str, Any]:
    """Return ldap context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
        selected_organization_id: Identifier of the selected organization.
    """
    settings = get_ldap_settings_row(db)
    available_interfaces = ldap_service_bind_options(db)
    available_by_name = {option["name"]: option for option in available_interfaces}
    changed = False
    selected_interfaces = [name for name in split_interfaces(settings.listen_interface) if name in available_by_name]
    selected_addresses = [
        address
        for name in selected_interfaces
        for address in available_by_name[name]["addresses"]
        if address
    ]
    normalized_interfaces = join_interfaces(selected_interfaces)
    normalized_addresses = join_addresses(list(dict.fromkeys(selected_addresses)))
    if reconcile and settings.listen_interface != normalized_interfaces:
        settings.listen_interface = normalized_interfaces
        changed = True
    if reconcile and settings.listen_address != normalized_addresses:
        settings.listen_address = normalized_addresses
        changed = True
    normalized_hostname = normalize_dns_hostname(settings.hostname or LDAP_DEFAULT_HOSTNAME)
    if reconcile and normalized_hostname and normalized_hostname != settings.hostname:
        settings.hostname = normalized_hostname
        changed = True
    if reconcile:
        ensure_dns_for_ldap(db, settings, actor=None, previous_hostname=settings.hostname)
    if changed:
        settings.updated_at = utcnow()
        db.commit()
        db.refresh(settings)

    ca_errors = ensure_ca_state(db) if reconcile else []
    organizations = ldap_organizations_query(db)
    selected_organization = next((row for row in organizations if row.id == selected_organization_id), None)
    if selected_organization is None and organizations:
        selected_organization = organizations[0]
    recovery_archive = (
        db.execute(
            select(LdapRecoveryArchive)
            .where(LdapRecoveryArchive.state == "staged")
            .order_by(LdapRecoveryArchive.created_at.desc())
        )
        .scalars()
        .first()
    )
    recovery_ready = recovery_archive is not None and recovery_archive.id in LDAP_PENDING_RECOVERY_PAYLOADS
    ca_settings = get_ca_settings_row(db)
    validation_errors, validation_warnings = validate_ldap_state(
        settings,
        organizations,
        available_interfaces=set(available_by_name),
        ca_ready=bool(ca_settings.enabled and ca_settings.root_certificate_pem),
        recovery_staged=recovery_ready,
    )
    validation_errors = [*ca_errors, *validation_errors]
    if settings.enabled:
        if ldap_dns_record_conflict(db, settings.hostname):
            validation_errors.append("LDAP hostname conflicts with an existing non-LDAP DNS record.")
        if settings.ldaps_enabled and not ca_certificate_available(db, "ldap:ldaps"):
            validation_errors.append("LDAP requires an issued CA-managed LDAPS certificate before apply.")

    if recovery_archive is not None and not recovery_ready:
        validation_errors.append("The staged LDAP recovery import was lost after restart; upload it and enter its passphrase again.")
    apply_config = render_ldap_apply_config(settings, organizations, recovery_archive=recovery_archive)
    runtime_status = service_runtime_status(db, "ldap")
    runtime_status["enabled"] = settings.enabled
    if not settings.enabled:
        runtime_status.update({"label": "disabled", "pill": "muted", "health": "disabled"})
    elif runtime_status.get("running"):
        runtime_status.update({"label": "live", "pill": "good", "health": "healthy"})
    else:
        runtime_status.update({"label": "pending", "pill": "warn", "health": "degraded"})
    return {
        "ldap_settings": settings,
        "ldap_settings_json": ldap_settings_to_dict(settings),
        "ldap_organizations": organizations,
        "ldap_organization_rows": [ldap_organization_to_dict(row) for row in organizations],
        "ldap_selected_organization": selected_organization,
        "ldap_users": list(selected_organization.users) if selected_organization else [],
        "ldap_user_rows": [ldap_user_to_dict(row) for row in selected_organization.users] if selected_organization else [],
        "ldap_groups": list(selected_organization.groups) if selected_organization else [],
        "ldap_group_rows": [ldap_group_to_dict(row) for row in selected_organization.groups] if selected_organization else [],
        "ldap_available_interfaces": available_interfaces,
        "ldap_selected_interfaces": split_interfaces(settings.listen_interface),
        "ldap_selected_addresses": split_addresses(settings.listen_address),
        "ldap_validation_errors": list(dict.fromkeys(validation_errors)),
        "ldap_validation_warnings": list(dict.fromkeys(validation_warnings)),
        "ldap_config_preview": render_ldap_preview(settings, organizations, recovery_archive=recovery_archive),
        "ldap_apply_config": apply_config,
        "ldap_service_status": runtime_status,
        "ldap_recovery_archive": recovery_archive,
        "ldap_vcf_mapping": (
            vcf_ldap_settings(settings, selected_organization, include_password=False)
            if selected_organization
            else {}
        ),
    }


def network_context(db: Session) -> dict:
    """Return network context.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    interfaces_by_name = {interface.name: interface for interface in interfaces}
    vlan_counts: dict[str, int] = {}
    for vlan in vlans:
        vlan_counts[vlan.parent_interface] = vlan_counts.get(vlan.parent_interface, 0) + 1
    observed_ipv4_gateways = discover_host_ipv4_default_gateways()
    config_preview = render_network_config(interfaces=interfaces, vlans=vlans)
    validation_errors = validate_network_state(interfaces=interfaces, vlans=vlans)
    trunk_interfaces = [
        interface
        for interface in interfaces
        if normalize_interface_mode(interface.mode) == "trunk" and interface.oper_state != "missing"
    ]
    return {
        "physical_interfaces": interfaces,
        "physical_interface_rows": [
            physical_interface_to_dict(
                interface,
                vlan_counts.get(interface.name, 0),
                observed_ipv4_gateway=observed_ipv4_gateways.get(interface.name, ""),
            )
            for interface in interfaces
        ],
        "vlan_interfaces": vlans,
        "vlan_interface_rows": [
            vlan_interface_to_dict(
                vlan,
                parent_missing=bool((parent := interfaces_by_name.get(vlan.parent_interface)) and parent.oper_state == "missing"),
            )
            for vlan in vlans
        ],
        "interface_names": [interface.name for interface in interfaces],
        "trunk_interface_names": [interface.name for interface in trunk_interfaces],
        "trunk_parent_options": [trunk_parent_option(interface) for interface in trunk_interfaces],
        "network_roles": NETWORK_ROLES,
        "interface_modes": INTERFACE_MODES,
        "ipv4_methods": IPV4_METHODS,
        "network_config_preview": config_preview,
        "network_validation_errors": validation_errors,
        "network_inventory_cleanup_warning": setting_value(db, NETWORK_INVENTORY_CLEANUP_WARNING_KEY),
        "network_config_path": NETWORK_STAGED_CONFIG_PATH,
    }


def wan_route_targets(db: Session) -> list[dict[str, str]]:
    """Return wan route targets.

    Args:
        db: Active database session.
    """
    return [target for target in wan_routing_targets(db) if target["routing_domain"] == "lab"]


def wan_routing_targets(db: Session) -> list[dict[str, str]]:
    """Return wan routing targets.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
    interfaces_by_name = {interface.name: interface for interface in interfaces}
    targets: list[dict[str, str]] = []
    for interface in interfaces:
        if interface.oper_state == "missing":
            continue
        mode = normalize_interface_mode(interface.mode)
        role = normalize_interface_role(interface.role)
        addresses = interface_addresses_from_cidrs(interface.ip_cidr, interface.ipv6_cidr)
        if mode == "trunk" or not addresses:
            continue
        address_label = " / ".join(addresses)
        routing_domain = "management" if role == "management" else "lab"
        targets.append(
            {
                "name": interface.name,
                "kind": "physical",
                "role": role,
                "ip_cidr": interface.ip_cidr or "",
                "gateway": interface.gateway or "",
                "ipv4_method": normalize_ipv4_method(interface.ipv4_method),
                "ipv6_cidr": interface.ipv6_cidr or "",
                "ipv6_gateway": interface.ipv6_gateway or "",
                "addresses": addresses,
                "routing_domain": routing_domain,
                "route_allowed": routing_domain == "lab",
                "management_ui": bool(
                    role == "access"
                    and mode == "access"
                    and str(interface.admin_state or "").lower() == "up"
                    and interface.access_management_ui_enabled
                ),
                "label": f"{interface.name} - physical / {role} / {address_label}",
            }
        )
    for vlan in vlans:
        parent = interfaces_by_name.get(vlan.parent_interface)
        role = normalize_interface_role(vlan.role)
        addresses = interface_addresses_from_cidrs(vlan.ip_cidr, vlan.ipv6_cidr)
        if not vlan.enabled or not addresses:
            continue
        address_label = " / ".join(addresses)
        routing_domain = "management" if role == "management" else "lab"
        targets.append(
            {
                "name": vlan.name,
                "kind": "vlan",
                "role": role,
                "ip_cidr": vlan.ip_cidr or "",
                "ipv6_cidr": vlan.ipv6_cidr or "",
                "addresses": addresses,
                "routing_domain": routing_domain,
                "route_allowed": routing_domain == "lab",
                "management_ui": bool(
                    role == "access"
                    and vlan.access_management_ui_enabled
                    and parent is not None
                    and parent.oper_state != "missing"
                    and str(parent.admin_state or "").lower() == "up"
                    and normalize_interface_mode(parent.mode) == "trunk"
                ),
                "label": f"{vlan.name} - VLAN {vlan.vlan_id} on {vlan.parent_interface} / {role} / {address_label}",
            }
        )
    return targets


def wan_nat_targets_from_route_targets(targets: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return wan nat targets from route targets.

    Args:
        targets: Targets consumed by WAN nat targets from route targets.
    """
    return [target for target in targets if target.get("ip_cidr")]


def routes_wan_context(db: Session) -> dict:
    """Return routes wan context.

    Args:
        db: Active database session.
    """
    routes = db.execute(select(Route).options(selectinload(Route.wan_policy)).order_by(Route.destination_cidr)).scalars().all()
    policies = db.execute(select(WanPolicy).order_by(WanPolicy.name)).scalars().all()
    nat_rules = db.execute(select(NatRule).order_by(NatRule.priority, NatRule.name)).scalars().all()
    routing_rules = db.execute(select(RoutingRule).order_by(RoutingRule.priority, RoutingRule.name)).scalars().all()
    all_targets = wan_routing_targets(db)
    targets = wan_route_targets(db)
    generated_routing_rows = generated_route_role_rules(targets)
    routing_summary = {
        "generated_count": len(generated_routing_rows),
        "explicit_count": len(routing_rules),
        "route_target_count": len([target for target in targets if target.get("role") == "route"]),
        "access_target_count": len([target for target in targets if target.get("role") != "route"]),
        "management_target_count": len([target for target in all_targets if target.get("routing_domain") == "management"]),
    }
    nat_targets = wan_nat_targets_from_route_targets(targets)
    source_groups = firewall_source_group_state_for_db(db)["groups"]
    feature_settings = ensure_routes_wan_settings(db)
    validation_args = (
        routes,
        policies,
        {target["name"] for target in targets},
        nat_rules,
        {target["name"] for target in nat_targets},
        source_groups,
        routing_rules,
        {target["name"] for target in targets},
        {
            target["name"]: (target.get("ip_cidr"), target.get("ipv6_cidr"))
            for target in targets
        },
    )
    routing_validation_errors = validate_wan_state(
        *validation_args,
        routing_enabled=True,
        nat_enabled=False,
        wan_simulation_enabled=False,
    )
    nat_validation_errors = validate_wan_state(
        *validation_args,
        routing_enabled=False,
        nat_enabled=True,
        wan_simulation_enabled=False,
    )
    wan_simulation_validation_errors = validate_wan_state(
        *validation_args,
        routing_enabled=False,
        nat_enabled=False,
        wan_simulation_enabled=True,
    )
    management_validation_errors = validate_wan_state(
        *validation_args,
        management_target_names={
            target["name"] for target in targets if target.get("management_ui")
        },
        routing_enabled=False,
        nat_enabled=False,
        wan_simulation_enabled=False,
    )
    validation_errors = [
        *management_validation_errors,
        *(
            routing_validation_errors
            if feature_settings.routing_enabled
            else []
        ),
        *(
            nat_validation_errors
            if feature_settings.effective_nat_enabled
            else []
        ),
        *(
            wan_simulation_validation_errors
            if feature_settings.wan_simulation_enabled
            else []
        ),
    ]
    feature_status = {
        "routing": (
            "needs attention"
            if feature_settings.routing_enabled and routing_validation_errors
            else "valid"
            if feature_settings.routing_enabled
            else "disabled"
        ),
        "nat": (
            "suspended"
            if feature_settings.nat_enabled and not feature_settings.routing_enabled
            else "needs attention"
            if feature_settings.effective_nat_enabled and nat_validation_errors
            else "valid"
            if feature_settings.effective_nat_enabled
            else "disabled"
        ),
        "wan_simulation": (
            "needs attention"
            if feature_settings.wan_simulation_enabled and wan_simulation_validation_errors
            else "valid"
            if feature_settings.wan_simulation_enabled
            else "disabled"
        ),
    }
    config_preview = render_wan_config(
        routes,
        policies,
        nat_rules,
        all_targets,
        routing_rules,
        source_groups=source_groups,
        settings=feature_settings,
    )
    return {
        "routes": routes,
        "policies": policies,
        "nat_rules": nat_rules,
        "routing_rules": routing_rules,
        "route_rows": [route_to_dict(route) for route in routes],
        "nat_rule_rows": [nat_rule_to_dict(rule) for rule in nat_rules],
        "routing_rule_rows": [routing_rule_to_dict(rule) for rule in routing_rules],
        "generated_routing_rule_rows": generated_routing_rows,
        "routing_summary": routing_summary,
        "policy_rows": [wan_policy_to_dict(policy) for policy in policies],
        "wan_all_targets": all_targets,
        "wan_route_targets": targets,
        "wan_route_target_names": [target["name"] for target in targets],
        "wan_nat_targets": nat_targets,
        "wan_nat_target_names": [target["name"] for target in nat_targets],
        "wan_source_groups": source_groups,
        "wan_policy_options": [{"id": policy.id, "label": policy.name} for policy in policies],
        "wan_modes": WAN_MODES,
        "wan_config_path": WAN_CONFIG_PATH,
        "wan_config_preview": config_preview,
        "wan_validation_errors": validation_errors,
        "routes_wan_settings": feature_settings,
        "routes_wan_feature_status": feature_status,
        "routing_validation_errors": routing_validation_errors,
        "nat_validation_errors": nat_validation_errors,
        "wan_simulation_validation_errors": wan_simulation_validation_errors,
    }


def dnsmasq_context(db: Session, *, reconcile: bool = True) -> dict:
    """Return dnsmasq context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    dns_settings = get_dns_settings_row(db)
    if reconcile and normalize_service_bind_settings(db, dns_settings):
        db.commit()
        db.refresh(dns_settings)
    appliance_settings = get_appliance_settings_row(db)
    if reconcile and ensure_dns_for_appliance_settings(db, appliance_settings, previous_fqdn=appliance_settings.fqdn, actor=None):
        db.commit()
        db.refresh(dns_settings)
    conditional_forwarders = setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY)
    dns_records = db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()
    dhcp_settings = get_dhcp_settings_row(db)
    dhcp_scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    dhcp_options = db.execute(select(DhcpOption).order_by(DhcpOption.scope_id, DhcpOption.option_code)).scalars().all()
    dhcp_reservations = db.execute(select(DhcpReservation).order_by(DhcpReservation.hostname)).scalars().all()
    esxi_boot = esxi_pxe_boot_settings(db)
    available_interfaces = service_bind_options(db)
    physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    management_interface, observed_dhcp_upstream_servers = management_dhcp_dns_context(physical_interfaces)
    fallback_upstream_servers = observed_dhcp_upstream_servers if not split_servers(dns_settings.upstream_servers) else []
    require_dhcp_upstream = dhcp_dns_upstream_required(dns_settings, management_interface)
    effective_upstream_servers = effective_dns_upstream_servers(dns_settings, fallback_upstream_servers)
    vlan_interfaces = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
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
        esxi_pxe_boot=esxi_boot,
    )
    validation_errors = (
        validate_dns_settings(
            dns_settings,
            dns_records,
            conditional_forwarders,
            fallback_upstream_servers=fallback_upstream_servers,
            require_dhcp_upstream=require_dhcp_upstream,
        )
        + validate_dns_listen_targets(dns_settings, {interface["name"] for interface in available_interfaces})
        + validate_dhcp_bind_targets(
            dhcp_settings,
            dhcp_scopes,
            dhcp_bind_target_families(
                physical_interfaces,
                vlan_interfaces,
            ),
        )
        + validate_dhcp_settings(
            dhcp_settings,
            dhcp_reservations,
            dhcp_scopes,
            dhcp_options,
        )
    )
    if esxi_boot.get("enabled") and not dhcp_settings.enabled:
        validation_errors.append("ESXi PXE boot services require DHCP to be enabled so clients receive boot files.")
    active_dns_domains = split_domains(dns_settings.domain) or ["atlaso.internal"]
    dns_domains = dns_domains_for_settings(dns_settings)
    dns_warnings = dns_domain_warnings(dns_domains)
    dns_record_groups = dns_records_by_domain(dns_records, dns_domains, dns_settings)
    domain_descriptions = dns_domain_descriptions(dns_settings)
    for group in dns_record_groups:
        group["enabled"] = group["domain"] in active_dns_domains
        group["description"] = domain_descriptions.get(group["domain"], "")
        if not group["enabled"]:
            group["authority"] = None
        group["suggested_ipv4"] = dns_record_suggested_ipv4(dns_records, group["domain"], dhcp_scopes, dhcp_reservations)
    reverse_zone_groups = reverse_records_by_zone(dns_reverse_records(dns_records))
    lease_result = SystemAdapter().read_dhcp_leases()
    dhcp_lease_error = lease_result.stderr.strip() if lease_result.returncode != 0 else ""
    dhcp_leases = [] if dhcp_lease_error else filter_current_dhcp_leases(parse_dnsmasq_leases(lease_result.stdout), dhcp_scopes)
    return {
        "dns_settings": dns_settings,
        "dns_records": dns_records,
        "dns_record_groups": dns_record_groups,
        "reverse_zone_groups": reverse_zone_groups,
        "dhcp_settings": dhcp_settings,
        "dhcp_scopes": dhcp_scopes,
        "dhcp_scope_rows": [dhcp_scope_to_dict(scope) for scope in dhcp_scopes],
        "dhcp_scope_grid_defaults": dhcp_scope_grid_defaults(
            available_interfaces=available_interfaces,
            dns_settings=dns_settings,
            ntp_settings=get_ntp_settings_row(db),
            dhcp_scopes=dhcp_scopes,
            dns_domains=dns_domains,
        ),
        "dhcp_options": dhcp_options,
        "dhcp_option_rows": [dhcp_option_to_dict(option) for option in dhcp_options],
        "dhcp_option_scope_choices": dhcp_option_scope_choices(dhcp_scopes),
        "dhcp_generated_pxe_options": generated_esxi_pxe_dhcp_options(esxi_boot, dhcp_scopes),
        "dhcp_reservations": dhcp_reservations,
        "dhcp_reservation_rows": [dhcp_reservation_payload(item, dhcp_scopes) for item in dhcp_reservations],
        "dhcp_leases": dhcp_leases,
        "dhcp_lease_rows": [dhcp_lease_payload(lease, dhcp_scopes) for lease in dhcp_leases],
        "dhcp_lease_dry_run": lease_result.dry_run,
        "dhcp_lease_command": " ".join(lease_result.command),
        "dhcp_lease_error": dhcp_lease_error,
        "available_interfaces": available_interfaces,
        "available_dns_addresses": available_dns_listen_addresses(dns_settings, dhcp_settings, available_interfaces, vlan_interfaces),
        "selected_dns_interfaces": split_interfaces(dns_settings.listen_interface),
        "selected_dns_addresses": split_addresses(dns_settings.listen_address),
        "management_interface": management_interface,
        "observed_dhcp_upstream_servers": fallback_upstream_servers,
        "effective_upstream_servers": effective_upstream_servers,
        "config_preview": config_preview,
        "dns_domains": "\n".join(dns_domains),
        "hosts_editor_text": render_hosts_records(dns_records),
        "validation_errors": validation_errors,
        "dns_warnings": dns_warnings,
        "upstream_servers": "\n".join(split_servers(dns_settings.upstream_servers)),
        "conditional_forwarders": join_conditional_forwarders(split_conditional_forwarders(conditional_forwarders)),
        "dns_domain_options": dns_domains,
        "dns_service_status": service_runtime_status(db, "dns"),
        "dhcp_service_status": service_runtime_status(db, "dhcp"),
    }


def dhcp_scope_grid_defaults(
    *,
    available_interfaces: list[dict[str, Any]],
    dns_settings: DnsSettings,
    ntp_settings: NtpSettings,
    dhcp_scopes: list[DhcpScope],
    dns_domains: list[str],
) -> dict[str, Any]:
    """Return dhcp scope grid defaults.

    Args:
        available_interfaces: Available interfaces supplied by the caller.
        dns_settings: DNS service settings that constrain the operation.
        ntp_settings: Ntp settings supplied by the caller.
        dhcp_scopes: Dhcp scopes supplied by the caller.
        dns_domains: Dns domains supplied by the caller.
    """
    dns_interfaces = set(split_interfaces(dns_settings.listen_interface)) if dns_settings.enabled else set()
    ntp_interfaces = set(split_interfaces(ntp_settings.listen_interface)) if ntp_settings.enabled else set()
    dns_addresses = set(split_addresses(dns_settings.listen_address)) if dns_settings.enabled else set()
    ntp_addresses = set(split_addresses(ntp_settings.listen_address)) if ntp_settings.enabled else set()
    defaults: list[dict[str, Any]] = []
    for interface in available_interfaces:
        ipv4_address = str(interface.get("ipv4_address") or "")
        ipv6_address = str(interface.get("ipv6_address") or "")
        primary_address = ipv4_address or ipv6_address or str(interface.get("address") or "")
        interface_name = str(interface.get("name") or "")
        dns_enabled = interface_name in dns_interfaces
        ntp_enabled = interface_name in ntp_interfaces
        ipv4_dns_default = ipv4_address if dns_enabled and ipv4_address and (not dns_addresses or ipv4_address in dns_addresses) else ""
        ipv6_dns_default = ipv6_address if dns_enabled and ipv6_address and (not dns_addresses or ipv6_address in dns_addresses) else ""
        ipv4_ntp_default = ipv4_address if ntp_enabled and ipv4_address and (not ntp_addresses or ipv4_address in ntp_addresses) else ""
        ipv6_ntp_default = ipv6_address if ntp_enabled and ipv6_address and (not ntp_addresses or ipv6_address in ntp_addresses) else ""
        defaults.append(
            {
                "name": interface_name,
                "address": primary_address,
                "ipv4_address": ipv4_address,
                "ipv4_prefix": interface.get("ipv4_prefix"),
                "ipv6_address": ipv6_address,
                "ipv6_prefix": interface.get("ipv6_prefix"),
                "dns_default": ipv4_dns_default or ipv6_dns_default,
                "ntp_default": ipv4_ntp_default or ipv6_ntp_default,
                "ipv4_dns_default": ipv4_dns_default,
                "ipv6_dns_default": ipv6_dns_default,
                "ipv4_ntp_default": ipv4_ntp_default,
                "ipv6_ntp_default": ipv6_ntp_default,
            }
        )
    return {
        "interfaces": defaults,
        "existing_names": [scope.name.strip().lower() for scope in dhcp_scopes if scope.name.strip()],
        "default_domain": dns_domains[0] if dns_domains else "atlaso.internal",
    }


def lease_matches_current_dhcp_scope(lease: dict[str, Any], scopes: list[DhcpScope]) -> bool:
    """Return lease matches current dhcp scope.

    Args:
        lease: Lease consumed by lease matches current dhcp scope.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    try:
        lease_address = ip_address(str(lease.get("ip_address") or ""))
    except ValueError:
        return False
    for scope in scopes:
        if scope.enabled is False:
            continue
        network = _network_from_cidr(f"{scope.site_address}/{scope.prefix_length}") if scope.site_address and scope.prefix_length else None
        if network is not None and lease_address.version == network.version and lease_address in network:
            return True
    return False


def filter_current_dhcp_leases(leases: list[dict[str, Any]], scopes: list[DhcpScope]) -> list[dict[str, Any]]:
    """Return filter current dhcp leases.

    Args:
        leases: Leases consumed by filter current dhcp leases.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    return [lease for lease in leases if lease_matches_current_dhcp_scope(lease, scopes)]


def generated_esxi_pxe_dhcp_options(esxi_boot: dict[str, Any], scopes: list[DhcpScope]) -> list[dict[str, str]]:
    """Return generated esxi pxe dhcp options.

    Args:
        esxi_boot: Esxi boot consumed by generated ESXi PXE dhcp options.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    if not esxi_boot or not esxi_boot.get("enabled"):
        return []
    rows: list[dict[str, str]] = []
    tftp_hostname = str(esxi_boot.get("hostname") or "").strip()
    native_uefi_http_enabled = bool(esxi_boot.get("native_uefi_http_enabled"))
    http_port = esxi_boot.get("http_port") or 8080
    scope_ids = {int(scope_id) for scope_id in (esxi_boot.get("dhcp_scope_ids") or []) if str(scope_id).isdigit()}
    selected_scopes = [scope for scope in scopes if scope.id in scope_ids]
    if not selected_scopes and esxi_boot.get("dhcp_scope_id"):
        selected_scopes = [scope for scope in scopes if scope.id == esxi_boot.get("dhcp_scope_id")]
    fallback_addresses = [
        line.strip()
        for line in str(esxi_boot.get("listen_address") or "").replace(",", "\n").splitlines()
        if line.strip()
    ]
    scope_entries: list[dict[str, str]] = []
    for scope in selected_scopes:
        scope_entries.append(
            {
                "applies_to": scope.name,
                "prefix": f"tag:{dnsmasq_tag(scope.name)},",
                "address": scope.site_address.strip(),
            }
        )
    if not scope_entries:
        scope_entries.append(
            {
                "applies_to": "All DHCP zones",
                "prefix": "",
                "address": fallback_addresses[0] if fallback_addresses else "",
            }
        )

    host_bootfiles = list(esxi_boot.get("host_bootfiles") or [])
    def add(applies_to: str, flow: str, line: str, note: str) -> None:
        """Create operation.

        Args:
            applies_to: Applies to consumed by add.
            flow: Flow consumed by add.
            line: Source or output line being parsed.
            note: Note consumed by add.
        """
        rows.append({"applies_to": applies_to, "flow": flow, "line": line, "note": note})

    def scope_http_base(address: str) -> str:
        """Return scope http base.

        Args:
            address: Network address contacted or validated by the operation.
        """
        if not address:
            return ""
        host = f"[{address}]" if ":" in address and not address.startswith("[") else address
        return f"http://{host}:{http_port}/pxe/esxi"

    if native_uefi_http_enabled:
        add("All selected zones", "Native UEFI HTTP", "dhcp-vendorclass=set:uefi-http,HTTPClient", "Detect HTTPClient firmware")
        add("All selected zones", "Native UEFI HTTP", "dhcp-match=set:uefi-http-x64,option:client-arch,16", "Match x64 HTTP boot")
        for scope_entry in scope_entries:
            base_url = scope_http_base(scope_entry["address"])
            native_http_url = f"{base_url}/{esxi_boot.get('uefi_bootfile') or 'snponly.efi'}" if base_url else ""
            if not native_http_url:
                continue
            add(scope_entry["applies_to"], "Native UEFI HTTP", f"dhcp-boot={scope_entry['prefix']}tag:uefi-http,tag:uefi-http-x64,{native_http_url}", "Load iPXE before resolving the safe per-host boot menu")

    if esxi_boot.get("enabled"):
        add("All selected zones", "PXE TFTP", "enable-tftp", "Enable dnsmasq TFTP")
        add("All selected zones", "PXE TFTP", f"tftp-root={esxi_boot.get('tftp_root')}", "Serve generated boot files")
        add("All selected zones", "iPXE detection", "dhcp-userclass=set:ipxe,iPXE", "Detect iPXE second request")
        add("All selected zones", "iPXE detection", "dhcp-match=set:ipxe,175", "Compatibility iPXE marker")
        add("All selected zones", "UEFI PXE detection", "dhcp-match=set:efi-x86_64,option:client-arch,7", "Match x64 UEFI PXE")
        add("All selected zones", "UEFI PXE detection", "dhcp-match=set:efi-x86_64,option:client-arch,9", "Match x64 UEFI PXE")
        for host_bootfile in host_bootfiles:
            host_tag = str(host_bootfile.get("tag") or "").strip()
            mac_address = str(host_bootfile.get("mac_address") or "").strip()
            if host_tag and mac_address:
                add("All selected zones", "Host-specific PXE", f"dhcp-mac=set:{host_tag},{mac_address}", "Tag known ESXi host MAC")
        for scope_entry in scope_entries:
            boot_server = f",{tftp_hostname},{scope_entry['address']}" if tftp_hostname and scope_entry["address"] else ""
            if tftp_hostname:
                add(scope_entry["applies_to"], "PXE TFTP", f"dhcp-option={scope_entry['prefix']}66,{tftp_hostname}", "Advertise TFTP server name")
            address = scope_entry["address"]
            rendered_address = f"[{address}]" if ":" in address and not address.startswith("[") else address
            menu_url = f"http://{rendered_address}:{http_port}/pxe/boot.ipxe" if address else "/pxe/boot.ipxe"
            add(scope_entry["applies_to"], "iPXE second stage", f"dhcp-boot={scope_entry['prefix']}tag:ipxe,{menu_url}", "Resolve the inventory-first Network Boot menu and exact host assignment")
            add(scope_entry["applies_to"], "UEFI first stage", f"dhcp-boot={scope_entry['prefix']}tag:!ipxe,tag:efi-x86_64,{esxi_boot.get('uefi_bootfile')}{boot_server}", "UEFI PXE clients load iPXE by TFTP before ESXi mboot")
            add(scope_entry["applies_to"], "PXE first stage", f"dhcp-boot={scope_entry['prefix']}tag:!ipxe,tag:!efi-x86_64,{esxi_boot.get('bios_bootfile')}{boot_server}", "BIOS PXE first-stage iPXE")
    return rows


def dhcp_scope_network_any(scope: DhcpScope):
    """Return dhcp scope network any.

    Args:
        scope: Scope consumed by dhcp scope network any.
    """
    try:
        return ip_network(f"{scope.site_address}/{scope.prefix_length}", strict=False)
    except ValueError:
        return None


def dhcp_scope_name_for_ip(value: str | None, scopes: list[DhcpScope]) -> str:
    """Return dhcp scope name for ip.

    Args:
        value: Candidate value consumed by dhcp scope name for IP.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    try:
        address = ip_address(str(value or "").strip())
    except ValueError:
        return ""
    for scope in scopes:
        network = dhcp_scope_network_any(scope)
        if network is not None and address.version == network.version and address in network:
            return scope.name
    return ""


def dhcp_reservation_payload(reservation: DhcpReservation, scopes: list[DhcpScope] | None = None) -> dict:
    """Return dhcp reservation payload.

    Args:
        reservation: Reservation consumed by dhcp reservation payload.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    return {
        "id": reservation.id,
        "hostname": reservation.hostname,
        "mac_address": reservation.mac_address,
        "ip_address": reservation.ip_address,
        "zone_name": dhcp_scope_name_for_ip(reservation.ip_address, scopes or []),
        "description": reservation.description or "",
        "enabled": reservation.enabled,
    }


def dhcp_lease_payload(lease: dict[str, Any], scopes: list[DhcpScope] | None = None) -> dict[str, str]:
    """Return dhcp lease payload.

    Args:
        lease: Lease consumed by dhcp lease payload.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    expires_at = lease.get("expires_at")
    ip_address_value = str(lease.get("ip_address") or "")
    return {
        "status": str(lease.get("status") or ""),
        "hostname": str(lease.get("hostname") or ""),
        "ip_address": ip_address_value,
        "zone_name": dhcp_scope_name_for_ip(ip_address_value, scopes or []),
        "mac_address": str(lease.get("mac_address") or ""),
        "expires_at": expires_at.isoformat() if hasattr(expires_at, "isoformat") else str(expires_at or "never"),
        "client_id": str(lease.get("client_id") or ""),
    }


def dhcp_option_scope_choices(scopes: list[DhcpScope]) -> list[dict]:
    """Return dhcp option scope choices.

    Args:
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    return [{"id": "__global__", "label": "Global defaults"}, *[{"id": scope.id, "label": scope.name} for scope in scopes]]


def parse_dhcp_option_scope_id(raw_value: str) -> int | None:
    """Parse dhcp option scope id.

    Args:
        raw_value: Candidate raw value to parse.


    Returns:
        The parsed dhcp option scope id.
    """
    if raw_value in {"", "__global__", "global", "None"}:
        return None
    return int(raw_value)


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


def desired_dns_records_for_listen_addresses(raw_addresses: str | None) -> dict[str, str]:
    """Return desired dns records for listen addresses.

    Args:
        raw_addresses: Raw addresses consumed by desired DNS records for listen addresses.
    """
    desired: dict[str, str] = {}
    for selected_address in split_addresses(raw_addresses):
        try:
            parsed_address = ip_address(selected_address)
        except ValueError:
            continue
        record_type = "AAAA" if parsed_address.version == 6 else "A"
        desired.setdefault(record_type, str(parsed_address))
    return desired


VCF_DEPOT_DNS_DESCRIPTION = "Created from VCF Offline Depot endpoint."
VCF_REGISTRY_DNS_DESCRIPTION = "Created from VCF private registry endpoint."
CA_PORTAL_DNS_DESCRIPTION = "Created from Certificate Authority portal endpoint."


def service_dns_target_token(strategy: str, interface_name: str, address: str) -> str:
    """Return service dns target token.

    Args:
        strategy: Strategy consumed by service DNS target token.
        interface_name: Host network-interface name affected by the operation.
        address: Network address contacted or validated by the operation.
    """
    if strategy == "ip":
        try:
            parsed = ip_address(address)
        except ValueError:
            return re.sub(r"[^a-z0-9]+", "-", address.strip().lower()).strip("-") or "address"
        if parsed.version == 4:
            return str(parsed).replace(".", "-")
        return "-".join(format(int(group, 16), "x") for group in parsed.exploded.split(":"))
    safe_interface = re.sub(r"[^a-z0-9]+", "-", interface_name.strip().lower()).strip("-")
    return safe_interface or "interface"


def service_target_hostname(hostname: str, target_token: str) -> str:
    """Return service target hostname.

    Args:
        hostname: DNS hostname contacted, validated, or configured by the operation.
        target_token: Target token consumed by service target hostname.
    """
    normalized = normalize_dns_hostname(hostname)
    if "." not in normalized:
        return normalized
    label, domain = normalized.split(".", 1)
    safe_token = re.sub(r"[^a-z0-9]+", "-", target_token.strip().lower()).strip("-") or "target"
    suffix = f"-{safe_token}"
    if len(label) + len(suffix) <= 63:
        target_label = f"{label}{suffix}"
    else:
        digest = hashlib.sha1(f"{label}{suffix}".encode("utf-8")).hexdigest()[:8]
        hash_suffix = f"-{digest}"
        max_label_len = 63 - len(suffix) - len(hash_suffix)
        if max_label_len >= 1:
            target_label = f"{label[:max_label_len].rstrip('-')}{suffix}{hash_suffix}"
        else:
            target_label = f"{safe_token[: max(1, 63 - len(hash_suffix))].rstrip('-')}{hash_suffix}"
    return f"{target_label}.{domain}"


def service_interface_dns_targets(
    db: Session,
    *,
    hostname: str,
    listen_interface: str,
    listen_address: str | None,
    bind_options: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Return service interface dns targets.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
        listen_interface: Interface on which the service should listen.
        listen_address: Address on which the service should listen.
        bind_options: Bind options supplied by the caller.
    """
    selected_addresses = split_addresses(listen_address)
    if not selected_addresses:
        return []
    naming_strategy = normalize_service_dns_target_naming(get_appliance_settings_row(db).service_dns_target_naming)
    selected_address_set = set(selected_addresses)
    options_by_name = {option["name"]: option for option in (bind_options if bind_options is not None else service_bind_options(db))}
    targets: list[dict[str, str]] = []
    for interface_name in split_interfaces(listen_interface):
        option = options_by_name.get(interface_name)
        if not option:
            continue
        interface_addresses = [address for address in (option or {}).get("addresses", []) if address in selected_address_set]
        for address in interface_addresses:
            try:
                parsed_address = ip_address(address)
            except ValueError:
                continue
            target_token = service_dns_target_token(naming_strategy, interface_name, str(parsed_address))
            target_hostname = service_target_hostname(hostname, target_token)
            targets.append(
                {
                    "hostname": target_hostname,
                    "interface": interface_name,
                    "record_type": "AAAA" if parsed_address.version == 6 else "A",
                    "address": str(parsed_address),
                }
            )
    return targets


def summarize_dns_actions(actions: list[str]) -> str | None:
    """Return summarize dns actions.

    Args:
        actions: Actions consumed by summarize DNS actions.
    """
    if not actions:
        return None
    if "conflict" in actions:
        changed = any(action in {"created", "updated", "removed-old", "removed-stale"} for action in actions)
        return "conflict+changed" if changed else "conflict"
    primary = "unchanged"
    for candidate in ["created", "updated"]:
        if candidate in actions:
            primary = candidate
            break
    if any(action in {"removed-old", "removed-stale"} for action in actions):
        return f"{primary}+removed-old" if primary != "unchanged" else "removed-old"
    return primary


def ensure_interface_dns_alias(
    db: Session,
    *,
    hostname: str,
    listen_interface: str,
    listen_address: str | None,
    description: str,
    actor: str | None,
    audit_prefix: str,
    previous_hostname: str | None = None,
    enabled: bool = True,
    bind_options: list[dict[str, Any]] | None = None,
) -> str | None:
    """Ensure interface dns alias.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
        listen_interface: Interface on which the service should listen.
        listen_address: Address on which the service should listen.
        description: Human-readable description of the resource.
        actor: Authenticated identity attributed to the audit record.
        audit_prefix: Audit prefix supplied by the caller.
        previous_hostname: Hostname previously owned by the resource.
        enabled: Whether the requested behavior is enabled.
        bind_options: Bind options supplied by the caller.

    Returns:
        The ensure interface dns alias result.
    """
    normalized_hostname = normalize_dns_hostname(hostname)
    if not enabled:
        return remove_interface_dns_alias(db, hostname=previous_hostname or normalized_hostname, description=description, actor=actor, audit_prefix=audit_prefix)
    targets = service_interface_dns_targets(db, hostname=normalized_hostname, listen_interface=listen_interface, listen_address=listen_address, bind_options=bind_options)
    if not normalized_hostname:
        return None
    if not targets:
        return remove_interface_dns_alias(db, hostname=previous_hostname or normalized_hostname, description=description, actor=actor, audit_prefix=audit_prefix)
    actions: list[str] = []
    target_hostnames = {target["hostname"] for target in targets}
    desired_keys = {(target["hostname"], target["record_type"], target["address"]) for target in targets}
    canonical_target = targets[0]["hostname"]
    label_prefix = f"{normalized_hostname.split('.', 1)[0]}-"

    canonical_records = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == normalized_hostname,
            DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
        )
    ).scalars().all()
    canonical_record_conflict = any(
        record.description != description for record in canonical_records
    )
    generated_target_conflict = False
    for target in targets:
        target_records = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == target["hostname"],
                DnsRecord.record_type.in_([target["record_type"], "CNAME"]),
            )
        ).scalars().all()
        if any(record.description != description for record in target_records):
            generated_target_conflict = True
            break
    canonical_conflict = canonical_record_conflict or generated_target_conflict
    if canonical_conflict:
        actions.append("conflict")

    owned_records = db.execute(
        select(DnsRecord).where(
            DnsRecord.description == description,
            DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
        )
    ).scalars().all()
    for record in owned_records:
        if record.hostname == normalized_hostname and record.record_type in {"A", "AAAA"}:
            db.delete(record)
            actions.append("removed-old")
            if actor:
                record_audit(db, actor=actor, action=f"delete_dns_record_from_{audit_prefix}_cname", resource_type="dns_record", resource_id=str(record.id), detail=f"{record.hostname} {record.record_type}")
            continue
        if record.hostname in target_hostnames and record.record_type == "CNAME":
            db.delete(record)
            actions.append("removed-stale")
            if actor:
                record_audit(db, actor=actor, action=f"delete_dns_record_from_{audit_prefix}_stale_target_alias", resource_type="dns_record", resource_id=str(record.id), detail=f"{record.hostname} CNAME -> {record.address}")
            continue
        if record.hostname.startswith(label_prefix) and record.hostname not in target_hostnames:
            db.delete(record)
            actions.append("removed-old")
            if actor:
                record_audit(db, actor=actor, action=f"delete_dns_record_from_{audit_prefix}_stale_interface", resource_type="dns_record", resource_id=str(record.id), detail=f"{record.hostname} {record.record_type}")
            continue
        if record.hostname in target_hostnames and record.record_type in {"A", "AAAA"} and (record.hostname, record.record_type, record.address) not in desired_keys:
            db.delete(record)
            actions.append("removed-stale")
            if actor:
                record_audit(db, actor=actor, action=f"delete_dns_record_from_{audit_prefix}_stale_address", resource_type="dns_record", resource_id=str(record.id), detail=f"{record.hostname} {record.record_type} -> {record.address}")

    if not canonical_conflict and not validate_dns_record(normalized_hostname, "CNAME", canonical_target):
        existing_cname = next((record for record in canonical_records if record.record_type == "CNAME"), None)
        if existing_cname:
            if existing_cname.address == canonical_target and existing_cname.enabled:
                actions.append("unchanged")
            else:
                existing_cname.address = canonical_target
                existing_cname.enabled = True
                existing_cname.description = description
                db.flush()
                actions.append("updated")
                if actor:
                    record_audit(db, actor=actor, action=f"update_dns_record_from_{audit_prefix}_cname", resource_type="dns_record", resource_id=str(existing_cname.id), detail=f"{normalized_hostname} CNAME -> {canonical_target}")
        else:
            record = DnsRecord(hostname=normalized_hostname, record_type="CNAME", address=canonical_target, description=description, enabled=True)
            db.add(record)
            db.flush()
            actions.append("created")
            if actor:
                record_audit(db, actor=actor, action=f"create_dns_record_from_{audit_prefix}_cname", resource_type="dns_record", resource_id=str(record.id), detail=f"{normalized_hostname} CNAME -> {canonical_target}")

    for target in targets:
        record_type = target["record_type"]
        address = target["address"]
        target_hostname = target["hostname"]
        if validate_dns_record(target_hostname, record_type, address):
            continue
        matching_records = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == target_hostname,
                DnsRecord.record_type.in_([record_type, "CNAME"]),
            )
        ).scalars().all()
        matching_records = [
            record for record in matching_records if record not in db.deleted
        ]
        if any(record.description != description for record in matching_records):
            actions.append("conflict")
            continue
        existing = next(
            (
                record
                for record in matching_records
                if record.record_type == record_type
            ),
            None,
        )
        if existing:
            if existing.address == address and existing.enabled:
                actions.append("unchanged")
                continue
            existing.address = address
            existing.enabled = True
            existing.description = description
            db.flush()
            actions.append("updated")
            if actor:
                record_audit(db, actor=actor, action=f"update_dns_record_from_{audit_prefix}", resource_type="dns_record", resource_id=str(existing.id), detail=f"{target_hostname} {record_type} -> {address}")
            continue
        record = DnsRecord(hostname=target_hostname, record_type=record_type, address=address, description=description, enabled=True)
        db.add(record)
        db.flush()
        actions.append("created")
        if actor:
            record_audit(db, actor=actor, action=f"create_dns_record_from_{audit_prefix}", resource_type="dns_record", resource_id=str(record.id), detail=f"{target_hostname} {record_type} -> {address}")

    previous = normalize_dns_hostname(previous_hostname or "")
    if previous and previous != normalized_hostname:
        removed = remove_interface_dns_alias(db, hostname=previous, description=description, actor=actor, audit_prefix=audit_prefix)
        if removed:
            actions.append("removed-old")
    if actions:
        db.flush()
    return summarize_dns_actions(actions)


def remove_interface_dns_alias(
    db: Session,
    *,
    hostname: str,
    description: str,
    actor: str | None,
    audit_prefix: str,
) -> str | None:
    """Remove interface dns alias.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
        description: Human-readable description of the resource.
        actor: Authenticated identity attributed to the audit record.
        audit_prefix: Audit prefix supplied by the caller.

    Returns:
        The remove interface dns alias result.
    """
    normalized_hostname = normalize_dns_hostname(hostname)
    if not normalized_hostname:
        return None
    label_prefix = f"{normalized_hostname.split('.', 1)[0]}-"
    records = db.execute(select(DnsRecord).where(DnsRecord.description == description, DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]))).scalars().all()
    removed = 0
    for record in records:
        if record.hostname != normalized_hostname and not record.hostname.startswith(label_prefix):
            continue
        db.delete(record)
        removed += 1
        if actor:
            record_audit(db, actor=actor, action=f"delete_dns_record_from_{audit_prefix}", resource_type="dns_record", resource_id=str(record.id), detail=f"{record.hostname} {record.record_type}")
    if removed:
        db.flush()
        return "removed-old"
    return None


def ensure_dns_for_vcf_registry(db: Session, settings: VcfPrivateRegistrySettings, actor: str, *, previous_hostname: str | None = None) -> str | None:
    """Ensure dns for vcf registry.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for vcf registry result.
    """
    hostname = normalize_dns_hostname(settings.hostname)
    if not hostname:
        return None
    settings.hostname = hostname
    return ensure_interface_dns_alias(
        db,
        hostname=hostname,
        listen_interface=settings.listen_interface,
        listen_address=settings.listen_address,
        description=VCF_REGISTRY_DNS_DESCRIPTION,
        actor=actor,
        audit_prefix="vcf_registry",
        previous_hostname=previous_hostname,
        enabled=settings.enabled,
    )


def ensure_dns_for_vcf_offline_depot(db: Session, settings: VcfOfflineDepotSettings, actor: str, *, previous_hostname: str | None = None) -> str | None:
    """Ensure dns for vcf offline depot.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for vcf offline depot result.
    """
    hostname = normalize_dns_hostname(settings.hostname)
    if not hostname:
        return None
    settings.hostname = hostname
    return ensure_interface_dns_alias(
        db,
        hostname=hostname,
        listen_interface=settings.listen_interface,
        listen_address=settings.listen_address,
        description=VCF_DEPOT_DNS_DESCRIPTION,
        actor=actor,
        audit_prefix="vcf_offline_depot",
        previous_hostname=previous_hostname,
        enabled=settings.enabled,
        bind_options=vcf_depot_service_bind_options(db),
    )


def ensure_dns_for_ca_portal(db: Session, settings: CaSettings, actor: str | None, *, previous_hostname: str | None = None) -> str | None:
    """Ensure dns for ca portal.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for ca portal result.
    """
    hostname = normalize_dns_hostname(settings.portal_hostname or CA_DEFAULT_PORTAL_HOSTNAME)
    if not hostname:
        return None
    settings.portal_hostname = hostname
    return ensure_interface_dns_alias(
        db,
        hostname=hostname,
        listen_interface=settings.listen_interface,
        listen_address=settings.listen_address,
        description=CA_PORTAL_DNS_DESCRIPTION,
        actor=actor,
        audit_prefix="ca_portal",
        previous_hostname=previous_hostname,
        enabled=settings.enabled,
    )


def kms_dns_record_conflict(db: Session, hostname: str) -> bool:
    """Return kms dns record conflict.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
    """
    normalized = normalize_dns_hostname(hostname)
    if not normalized:
        return False
    records = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == normalized,
            DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
        )
    ).scalars().all()
    return any(record.description != KMS_DNS_RECORD_DESCRIPTION for record in records)


def ensure_dns_for_kms(db: Session, settings: KmsSettings, actor: str | None, *, previous_hostname: str | None = None) -> str | None:
    """Ensure dns for kms.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for kms result.
    """
    hostname = normalize_dns_hostname(settings.hostname)
    if not hostname:
        return None
    settings.hostname = hostname
    return ensure_interface_dns_alias(
        db,
        hostname=hostname,
        listen_interface=settings.listen_interface,
        listen_address=settings.listen_address,
        description=KMS_DNS_RECORD_DESCRIPTION,
        actor=actor,
        audit_prefix="kms",
        previous_hostname=previous_hostname,
        enabled=settings.enabled,
    )


def ldap_dns_record_conflict(db: Session, hostname: str) -> bool:
    """Return ldap dns record conflict.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
    """
    normalized = normalize_dns_hostname(hostname)
    if not normalized:
        return False
    records = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == normalized,
            DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
        )
    ).scalars().all()
    return any(record.description != LDAP_DNS_RECORD_DESCRIPTION for record in records)


def ensure_dns_for_ldap(db: Session, settings: LdapSettings, actor: str | None, *, previous_hostname: str | None = None) -> str | None:
    """Ensure dns for ldap.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for ldap result.
    """
    hostname = normalize_dns_hostname(settings.hostname)
    if not hostname:
        return None
    settings.hostname = hostname
    return ensure_interface_dns_alias(
        db,
        hostname=hostname,
        listen_interface=settings.listen_interface,
        listen_address=settings.listen_address,
        description=LDAP_DNS_RECORD_DESCRIPTION,
        actor=actor,
        audit_prefix="ldap",
        previous_hostname=previous_hostname,
        enabled=settings.enabled,
        bind_options=ldap_service_bind_options(db),
    )


def ensure_dns_for_oidc(
    db: Session,
    settings: OidcProviderSettings,
    actor: str | None,
    *,
    previous_hostname: str | None = None,
) -> str | None:
    """Ensure dns for oidc.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for oidc result.
    """
    hostname = normalize_dns_hostname(settings.hostname or OIDC_DEFAULT_HOSTNAME)
    settings.hostname = hostname
    return ensure_interface_dns_alias(
        db,
        hostname=hostname,
        listen_interface=settings.listen_interface,
        listen_address=settings.listen_address,
        description=OIDC_DNS_RECORD_DESCRIPTION,
        actor=actor,
        audit_prefix="oidc",
        previous_hostname=previous_hostname,
        enabled=settings.enabled,
        bind_options=ldap_service_bind_options(db),
    )


def remove_dns_for_vcf_offline_depot_hostname(db: Session, hostname: str, actor: str) -> str | None:
    """Remove dns for vcf offline depot hostname.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
        actor: Authenticated identity attributed to the audit record.

    Returns:
        The remove dns for vcf offline depot hostname result.
    """
    return remove_interface_dns_alias(
        db,
        hostname=hostname,
        description=VCF_DEPOT_DNS_DESCRIPTION,
        actor=actor,
        audit_prefix="vcf_offline_depot",
    )


def esxi_pxe_dns_record_conflict(db: Session, hostname: str) -> bool:
    """Return esxi pxe dns record conflict.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
    """
    normalized = normalize_dns_hostname(hostname)
    if not normalized:
        return False
    records = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == normalized,
            DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
        )
    ).scalars().all()
    return any(record.description != ESXI_PXE_DNS_RECORD_DESCRIPTION for record in records)


def remove_dns_for_esxi_pxe_hostname(db: Session, hostname: str, actor: str | None) -> str | None:
    """Remove dns for esxi pxe hostname.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
        actor: Authenticated identity attributed to the audit record.

    Returns:
        The remove dns for esxi pxe hostname result.
    """
    return remove_interface_dns_alias(
        db,
        hostname=hostname,
        description=ESXI_PXE_DNS_RECORD_DESCRIPTION,
        actor=actor,
        audit_prefix="esxi_pxe",
    )


def ensure_dns_for_esxi_pxe(db: Session, boot: dict[str, Any], actor: str | None, *, previous_hostname: str | None = None) -> str | None:
    """Ensure dns for esxi pxe.

    Args:
        db: Active database session.
        boot: Boot supplied by the caller.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for esxi pxe result.
    """
    hostname = normalize_dns_hostname(str(boot.get("hostname") or ESXI_PXE_DEFAULT_HOSTNAME))
    if not bool(boot.get("enabled")):
        return remove_dns_for_esxi_pxe_hostname(db, previous_hostname or hostname, actor)
    if not hostname:
        return None
    return ensure_interface_dns_alias(
        db,
        hostname=hostname,
        listen_interface=str(boot.get("listen_interface") or ""),
        listen_address=str(boot.get("listen_address") or ""),
        description=ESXI_PXE_DNS_RECORD_DESCRIPTION,
        actor=actor,
        audit_prefix="esxi_pxe",
        previous_hostname=previous_hostname,
        enabled=bool(boot.get("enabled")),
    )


def refresh_interface_service_dns_aliases(db: Session, actor: str | None = None) -> list[str]:
    """Refresh app-owned service DNS aliases after interface listener changes.

    Args:
        db: Active database session owned by the interface mutation transaction.
        actor: Optional audit actor. Atomic interface mutations pass ``None`` so nested audit commits
            cannot split the transaction.
    """
    changed: list[str] = []

    def mark(label: str, action: str | None) -> None:
        """Record an alias unit only when its reconciler changed state.

        Args:
            label: Operator-facing dependent unit name.
            action: Alias reconciliation result.
        """
        if action not in {None, "unchanged", "conflict"} and label not in changed:
            changed.append(label)

    kms_settings = db.execute(select(KmsSettings)).scalar_one_or_none()
    if kms_settings:
        mark(
            "KMS",
            ensure_dns_for_kms(
                db,
                kms_settings,
                actor=actor,
                previous_hostname=kms_settings.hostname,
            ),
        )
    ldap_settings = db.execute(select(LdapSettings)).scalar_one_or_none()
    if ldap_settings:
        mark(
            "LDAP",
            ensure_dns_for_ldap(
                db,
                ldap_settings,
                actor=actor,
                previous_hostname=ldap_settings.hostname,
            ),
        )
    oidc_settings = db.execute(select(OidcProviderSettings)).scalar_one_or_none()
    if oidc_settings:
        mark(
            "OIDC",
            ensure_dns_for_oidc(
                db,
                oidc_settings,
                actor=actor,
                previous_hostname=oidc_settings.hostname,
            ),
        )
    depot_settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one_or_none()
    if depot_settings:
        mark(
            "VCF Offline Depot",
            ensure_dns_for_vcf_offline_depot(
                db,
                depot_settings,
                actor=actor,
                previous_hostname=depot_settings.hostname,
            ),
        )
    registry_settings = db.execute(select(VcfPrivateRegistrySettings)).scalar_one_or_none()
    if registry_settings:
        mark(
            "VCF Private Registry",
            ensure_dns_for_vcf_registry(
                db,
                registry_settings,
                actor=actor,
                previous_hostname=registry_settings.hostname,
            ),
        )
    ca_settings = db.execute(select(CaSettings)).scalar_one_or_none()
    if ca_settings:
        mark(
            "Certificate Authority",
            ensure_dns_for_ca_portal(
                db,
                ca_settings,
                actor=actor,
                previous_hostname=ca_settings.portal_hostname,
            ),
        )
    esxi_boot = esxi_pxe_boot_settings(db)
    mark(
        "ESXi PXE",
        ensure_dns_for_esxi_pxe(
            db,
            esxi_boot,
            actor,
            previous_hostname=str(esxi_boot.get("hostname") or ""),
        ),
    )
    esx_settings = get_esx_storage_settings_row(db)
    mark(
        "ESX Storage",
        ensure_dns_for_esx_storage(
            db,
            actor,
            previous_hostname=esx_settings.hostname,
        ),
    )
    return changed


def get_esx_storage_settings_row(db: Session) -> EsxStorageSettings:
    """Return esx storage settings row.

    Args:
        db: Active database session.
    """
    settings = db.execute(select(EsxStorageSettings).order_by(EsxStorageSettings.id)).scalars().first()
    if settings is None:
        settings = EsxStorageSettings(
            enabled=False,
            hostname=factory_service_hostname(
                "nfs", get_appliance_settings_row(db).fqdn
            ),
        )
        db.add(settings)
        db.flush()
    return settings


def esx_storage_bind_state(db: Session, shares: list[EsxNfsShare] | None = None) -> tuple[str, str, dict[str, StorageInterface]]:
    """Return esx storage bind state.

    Args:
        db: Active database session.
        shares: Shares supplied by the caller.
    """
    options = service_bind_options(db)
    by_name = {str(option["name"]): option for option in options}
    interfaces = {
        name: StorageInterface(
            name,
            tuple(address for address in option.get("addresses", []) if ":" not in address),
            tuple(address for address in option.get("addresses", []) if ":" in address),
        )
        for name, option in by_name.items()
    }
    active = shares if shares is not None else db.execute(select(EsxNfsShare).where(EsxNfsShare.enabled.is_(True))).scalars().all()
    names: list[str] = []
    addresses: list[str] = []
    for share in active:
        if not share.enabled or share.interface_name not in interfaces:
            continue
        if share.interface_name not in names:
            names.append(share.interface_name)
        try:
            families = normalize_esx_storage_families(share.address_families)
        except ValueError:
            families = []
        option = by_name[share.interface_name]
        for address in option.get("addresses", []):
            family = "ipv6" if ":" in address else "ipv4"
            if family in families and address not in addresses:
                addresses.append(address)
    return join_interfaces(names), join_addresses(addresses), interfaces


def ensure_dns_for_esx_storage(db: Session, actor: str | None, *, previous_hostname: str | None = None) -> str | None:
    """Ensure dns for esx storage.

    Args:
        db: Active database session.
        actor: Authenticated identity attributed to the audit record.
        previous_hostname: Hostname previously owned by the resource.

    Returns:
        The ensure dns for esx storage result.
    """
    settings = get_esx_storage_settings_row(db)
    settings.hostname = normalize_dns_hostname(settings.hostname)
    volumes = db.execute(select(EsxStorageVolume).order_by(EsxStorageVolume.name)).scalars().all()
    shares = db.execute(select(EsxNfsShare).order_by(EsxNfsShare.datastore_name)).scalars().all()
    _listen_interface, _listen_address, interfaces = esx_storage_bind_state(db, shares)
    dns = db.execute(select(DnsSettings).order_by(DnsSettings.id)).scalars().first()
    manifest = render_esx_storage_manifest(
        settings,
        volumes,
        shares,
        interfaces,
        dns_enabled=bool(dns and dns.enabled),
        dns_naming_mode=get_appliance_settings_row(db).service_dns_target_naming or "ip",
    )
    desired = desired_esx_storage_dns_records(manifest) if settings.enabled and any(share.enabled for share in shares) else []
    desired_keys = {(row["hostname"], row["record_type"], row["address"]) for row in desired}
    owned = db.execute(select(DnsRecord).where(DnsRecord.description == ESX_STORAGE_DNS_DESCRIPTION)).scalars().all()
    actions: list[str] = []
    for record in owned:
        if (record.hostname, record.record_type, record.address) in desired_keys:
            continue
        db.delete(record)
        actions.append("removed-stale")
        if actor:
            record_audit(
                db,
                actor=actor,
                action="delete_dns_record_from_esx_storage_stale_endpoint",
                resource_type="dns_record",
                resource_id=str(record.id),
                detail=f"{record.hostname} {record.record_type} -> {record.address}",
            )
    for desired_record in desired:
        matching = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == desired_record["hostname"],
                DnsRecord.record_type == desired_record["record_type"],
            )
        ).scalars().all()
        if any(record.description != ESX_STORAGE_DNS_DESCRIPTION for record in matching):
            actions.append("conflict")
            continue
        existing = next((record for record in matching if record.address == desired_record["address"]), None)
        if existing:
            if not existing.enabled:
                existing.enabled = True
                actions.append("updated")
            else:
                actions.append("unchanged")
            continue
        record = DnsRecord(
            hostname=desired_record["hostname"],
            record_type=desired_record["record_type"],
            address=desired_record["address"],
            description=ESX_STORAGE_DNS_DESCRIPTION,
            enabled=True,
        )
        db.add(record)
        db.flush()
        actions.append("created")
        if actor:
            record_audit(
                db,
                actor=actor,
                action="create_dns_record_from_esx_storage",
                resource_type="dns_record",
                resource_id=str(record.id),
                detail=f"{record.hostname} {record.record_type} -> {record.address}",
            )
    if previous_hostname and normalize_dns_hostname(previous_hostname) != settings.hostname:
        actions.append("removed-old")
    if actions:
        db.flush()
    return summarize_dns_actions(actions)


def reconcile_service_dns_aliases(db: Session, actor: str | None = None) -> list[str]:
    """Return reconcile service dns aliases.

    Args:
        db: Active database session.
        actor: Authenticated identity attributed to the audit record.
    """
    return refresh_interface_service_dns_aliases(db, actor=actor)


def available_dns_listen_addresses(
    dns_settings: DnsSettings,
    dhcp_settings: DhcpSettings,
    listen_options: list[dict[str, str]],
    vlan_interfaces: list[VlanInterface],
) -> list[dict[str, str]]:
    """Return available dns listen addresses.

    Args:
        dns_settings: Dns settings consumed by available DNS listen addresses.
        dhcp_settings: Dhcp settings consumed by available DNS listen addresses.
        listen_options: Listen options consumed by available DNS listen addresses.
        vlan_interfaces: Vlan interfaces consumed by available DNS listen addresses.
    """
    choices: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(address: str | None, source: str) -> None:
        """Create operation.

        Args:
            address: Network address contacted or validated by the operation.
            source: Source object or location from which data is obtained.
        """
        for item in split_addresses(address):
            if item not in seen:
                seen.add(item)
                choices.append({"address": item, "source": source})

    add(dns_settings.listen_address, "current DNS")
    for option in listen_options:
        for address in option.get("addresses") or [option.get("address")]:
            add(address, option["name"])
    add(dhcp_settings.site_address, "SiteA gateway")
    for vlan in vlan_interfaces:
        for cidr in (vlan.ip_cidr, vlan.ipv6_cidr):
            if cidr:
                try:
                    add(str(ip_interface(cidr).ip), vlan.name)
                except ValueError:
                    add(cidr, vlan.name)
    return choices


def available_service_listen_addresses(current_addresses: str | None, listen_options: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return available service listen addresses.

    Args:
        current_addresses: Current addresses inspected by the operation.
        listen_options: Listen options consumed by available service listen addresses.
    """
    choices: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(address: str | None, source: str) -> None:
        """Create operation.

        Args:
            address: Network address contacted or validated by the operation.
            source: Source object or location from which data is obtained.
        """
        for item in split_addresses(address):
            if item not in seen:
                seen.add(item)
                choices.append({"address": item, "source": source})

    add(current_addresses, "current")
    for option in listen_options:
        for address in option.get("addresses") or [option.get("address")]:
            add(address, option["name"])
    return choices


def dns_records_by_domain(records: list[DnsRecord], domains: list[str], dns_settings: DnsSettings | None = None) -> list[dict]:
    """Return dns records by domain.

    Args:
        records: Persistent or reported records processed by the operation.
        domains: Domains consumed by DNS records by domain.
        dns_settings: Dns settings consumed by DNS records by domain.
    """
    groups = [{"domain": domain, "records": []} for domain in domains]
    group_map = {group["domain"]: group for group in groups}
    for record in records:
        domain = matching_domain(record.hostname, domains) or domains[0]
        group_map.setdefault(domain, {"domain": domain, "records": []})
        group_map[domain]["records"].append(dns_record_payload(record, domain))
    for group in groups:
        group["hosts_editor_text"] = render_zone_hosts_records(group["records"])
        group["authority"] = authoritative_zone_metadata(dns_settings, group["domain"]) if dns_settings and dns_settings.authoritative else None
        group["zone_file_text"] = render_zone_file(group["domain"], group["records"], dns_settings)
    return groups


def ipv4_address_or_none(value: str | None) -> IPv4Address | None:
    """Return ipv4 address or none.

    Args:
        value: Candidate value consumed by IPv4 address or none.
    """
    try:
        address = ip_address((value or "").strip())
    except ValueError:
        return None
    return address if isinstance(address, IPv4Address) else None


def ip_address_or_none(value: str | None) -> IPv4Address | IPv6Address | None:
    """Return ip address or none.

    Args:
        value: Candidate value consumed by IP address or none.
    """
    try:
        return ip_address((value or "").strip())
    except ValueError:
        return None


def ipv4_range(start: str | None, end: str | None) -> set[IPv4Address]:
    """Return ipv4 range.

    Args:
        start: Start consumed by IPv4 range.
        end: End consumed by IPv4 range.
    """
    start_address = ipv4_address_or_none(start)
    end_address = ipv4_address_or_none(end)
    if not start_address or not end_address:
        return set()
    start_int = int(start_address)
    end_int = int(end_address)
    if end_int < start_int or end_int - start_int > 8192:
        return set()
    return {IPv4Address(value) for value in range(start_int, end_int + 1)}


def dhcp_scope_network(scope: DhcpScope) -> IPv4Network | None:
    """Return dhcp scope network.

    Args:
        scope: Scope consumed by dhcp scope network.
    """
    site_address = ipv4_address_or_none(scope.site_address)
    if not site_address:
        return None
    try:
        return ip_network(f"{site_address}/{scope.prefix_length}", strict=False)
    except ValueError:
        return None


def dns_record_suggested_ipv4(records: list[DnsRecord], domain: str, dhcp_scopes: list[DhcpScope], dhcp_reservations: list[DhcpReservation]) -> str:
    """Return dns record suggested ipv4.

    Args:
        records: Persistent or reported records processed by the operation.
        domain: Domain consumed by DNS record suggested IPv4.
        dhcp_scopes: Dhcp scopes consumed by DNS record suggested IPv4.
        dhcp_reservations: Dhcp reservations consumed by DNS record suggested IPv4.
    """
    domain_records = [record for record in records if matching_domain(record.hostname, [domain]) == domain]
    used_addresses = {
        address
        for address in [ipv4_address_or_none(record.address) for record in records if record.record_type.strip().upper() == "A"]
        if address is not None
    }
    used_addresses.update(
        address
        for address in [ipv4_address_or_none(reservation.ip_address) for reservation in dhcp_reservations]
        if address is not None
    )

    excluded_addresses = set(used_addresses)
    candidate_networks: list[tuple[IPv4Network, set[IPv4Address]]] = []
    for scope in dhcp_scopes:
        if not scope.enabled:
            continue
        if scope.domain_name.strip().strip(".").lower() != domain:
            continue
        network = dhcp_scope_network(scope)
        if network is None:
            continue
        scope_excluded = set(excluded_addresses)
        site_address = ipv4_address_or_none(scope.site_address)
        if site_address:
            scope_excluded.add(site_address)
        range_errors, parsed_ranges = parse_dhcp_range_expression(scope)
        if not range_errors:
            for start_address, end_address in parsed_ranges:
                scope_excluded.update(ipv4_range(str(start_address), str(end_address)))
        candidate_networks.append((network, scope_excluded))

    inferred_networks: dict[IPv4Network, int] = {}
    for record in domain_records:
        if record.record_type.strip().upper() != "A":
            continue
        address = ipv4_address_or_none(record.address)
        if not address:
            continue
        network = ip_network(f"{address}/24", strict=False)
        inferred_networks[network] = inferred_networks.get(network, 0) + 1
    for network, _count in sorted(inferred_networks.items(), key=lambda item: (-item[1], int(item[0].network_address))):
        candidate_networks.append((network, set(excluded_addresses)))

    for network, excluded in candidate_networks:
        for candidate in network.hosts():
            if candidate not in excluded:
                return str(candidate)
    return ""


def vcf_sddc_dhcp_assignment_scope(scope: DhcpScope, records: list[DnsRecord], reservations: list[DhcpReservation]) -> dict[str, Any] | None:
    """Return vcf sddc dhcp assignment scope.

    Args:
        scope: Scope consumed by VCF SDDC dhcp assignment scope.
        records: Persistent or reported records processed by the operation.
        reservations: Reservations consumed by VCF SDDC dhcp assignment scope.
    """
    if not scope.enabled or scope.address_family.strip().lower() != "ipv4":
        return None
    network = dhcp_scope_network(scope)
    gateway = ipv4_address_or_none(scope.site_address)
    if network is None or gateway is None:
        return None
    range_errors, parsed_ranges = parse_dhcp_range_expression(scope)
    ranges = parsed_ranges if not range_errors else []
    occupied = {
        address
        for address in [ipv4_address_or_none(record.address) for record in records if record.record_type.strip().upper() == "A"]
        if address is not None
    }
    occupied.update(
        address
        for address in [ipv4_address_or_none(reservation.ip_address) for reservation in reservations if reservation.enabled is not False]
        if address is not None
    )
    occupied.add(gateway)
    suggested = ""
    for candidate in network.hosts():
        if candidate in occupied:
            continue
        if any(start <= candidate <= end for start, end in ranges):
            continue
        suggested = str(candidate)
        break
    return {
        "id": scope.id,
        "name": scope.name,
        "domain_name": scope.domain_name.strip().strip(".").lower(),
        "gateway": str(gateway),
        "prefix_length": int(scope.prefix_length or 24),
        "netmask": str(network.netmask),
        "dns_server": scope.dns_server.strip(),
        "ntp_server": scope.ntp_server.strip(),
        "suggested_ipv4": suggested,
        "network": network.with_prefixlen,
        "range_expression": compact_dhcp_range_expression(scope),
    }


def vcf_sddc_dhcp_assignment_context(db: Session) -> dict[str, Any]:
    """Return vcf sddc dhcp assignment context.

    Args:
        db: Active database session.
    """
    settings = get_dhcp_settings_row(db)
    if not settings.enabled:
        return {"available": False, "reasons": ["Enable DHCP desired state."], "scopes": []}
    records = db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()
    reservations = db.execute(select(DhcpReservation).order_by(DhcpReservation.hostname)).scalars().all()
    scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    scope_rows = [row for scope in scopes if (row := vcf_sddc_dhcp_assignment_scope(scope, records, reservations))]
    if not scope_rows:
        return {"available": False, "reasons": ["Create at least one enabled IPv4 DHCP IP zone."], "scopes": []}
    return {"available": True, "reasons": [], "scopes": scope_rows}


def validate_vlan_form_values(
    parent_interface: str,
    vlan_id: str,
    ip_cidr: str,
    ipv6_cidr: str,
    mtu: int,
    role: str,
    enabled: bool,
    db: Session,
) -> tuple[str, int, str, str, int, str, bool] | Response:
    """Validate vlan form values.

    Args:
        parent_interface: Parent interface supplied by the caller.
        vlan_id: Identifier of the vlan.
        ip_cidr: Ip cidr supplied by the caller.
        ipv6_cidr: IPv6 network or address in CIDR notation.
        mtu: Requested interface maximum transmission unit.
        role: Requested VLAN role.
        enabled: Whether the requested behavior is enabled.
        db: Active database session.

    Returns:
        The validate vlan form values result.
    """
    parent_name = parent_interface.strip()
    if not parent_name:
        return Response("VLAN parent interface is required.", status_code=409, media_type="text/plain")
    raw_vlan_id = str(vlan_id).strip()
    if not raw_vlan_id:
        return Response("VLAN ID is required.", status_code=409, media_type="text/plain")
    try:
        parsed_vlan_id = int(raw_vlan_id)
    except ValueError:
        return Response("VLAN ID must be a number between 1 and 4094.", status_code=409, media_type="text/plain")
    if parsed_vlan_id < 1 or parsed_vlan_id > 4094:
        return Response("VLAN ID must be between 1 and 4094.", status_code=409, media_type="text/plain")
    if ip_cidr.strip() and "/" not in ip_cidr:
        return Response("VLAN IPv4 CIDR must include an address and prefix.", status_code=409, media_type="text/plain")
    if ipv6_cidr.strip() and "/" not in ipv6_cidr:
        return Response("VLAN IPv6 CIDR must include an address and prefix.", status_code=409, media_type="text/plain")
    ip_value = cidr_for_family(ip_cidr, 4, "VLAN IPv4 CIDR")
    if isinstance(ip_value, Response):
        return ip_value
    ipv6_value = cidr_for_family(ipv6_cidr, 6, "VLAN IPv6 CIDR")
    if isinstance(ipv6_value, Response):
        return ipv6_value
    if not ip_value and not ipv6_value:
        return Response("VLAN IPv4 CIDR, IPv6 CIDR, or both are required.", status_code=409, media_type="text/plain")
    if mtu < 576 or mtu > 9000:
        return Response("VLAN MTU must be between 576 and 9000.", status_code=409, media_type="text/plain")
    if not is_canonical_network_role(role):
        return Response(
            f"VLAN role must be one of: {', '.join(NETWORK_ROLES)}.",
            status_code=409,
            media_type="text/plain",
        )
    role_value = normalize_interface_role(role)
    parent = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == parent_name)).scalar_one_or_none()
    parent_missing = bool(parent and parent.oper_state == "missing")
    if parent_missing:
        if enabled:
            return Response(
                f"{parent_name} is missing from host inventory. Move the VLAN to an available trunk parent before enabling it.",
                status_code=409,
                media_type="text/plain",
            )
        return parent_name, parsed_vlan_id, ip_value, ipv6_value, mtu, role_value, True
    if not parent or normalize_interface_mode(parent.mode) != "trunk":
        return Response(
            f"{parent_name or 'Selected parent'} is not a trunk interface. Mark the physical NIC as trunk before creating VLANs on it.",
            status_code=409,
            media_type="text/plain",
        )
    return parent_name, parsed_vlan_id, ip_value, ipv6_value, mtu, role_value, False


def vlan_form_validation_response(request: Request, response: Response) -> Response | JSONResponse:
    """Return a recoverable wizard error without changing ordinary form behavior.

    Args:
        request: Incoming HTTP request.
        response: Plain-text VLAN validation response.

    Returns:
        JSON for shared grid wizard requests, otherwise the original response.
    """
    if not grid_request(request):
        return response
    detail = response.body.decode(response.charset or "utf-8", errors="replace")
    return JSONResponse({"detail": detail}, status_code=response.status_code)


def reverse_records_by_zone(records: list[dict[str, str]]) -> list[dict]:
    """Return reverse records by zone.

    Args:
        records: Persistent or reported records processed by the operation.
    """
    groups: dict[str, dict] = {}
    for record in records:
        group = groups.setdefault(record["zone"], {"zone": record["zone"], "records": []})
        group["records"].append(record)
    return sorted(groups.values(), key=lambda item: item["zone"])


def matching_domain(hostname: str, domains: list[str]) -> str | None:
    """Return matching domain.

    Args:
        hostname: DNS hostname contacted, validated, or configured by the operation.
        domains: Domains consumed by matching domain.
    """
    normalized = hostname.strip().strip(".").lower()
    for domain in sorted(domains, key=len, reverse=True):
        if normalized == domain or normalized.endswith(f".{domain}"):
            return domain
    return None


def dns_record_payload(record: DnsRecord, domain: str) -> dict:
    """Return dns record payload.

    Args:
        record: Persistent or reported record affected by the operation.
        domain: Domain consumed by DNS record payload.
    """
    hostname = record.hostname.strip().strip(".").lower()
    suffix = f".{domain}"
    if hostname == domain:
        host_label = "@"
    elif hostname.endswith(suffix):
        host_label = hostname[: -len(suffix)]
    else:
        host_label = hostname
    return {
        "id": record.id,
        "hostname": record.hostname,
        "host_label": host_label,
        "domain": domain,
        "record_type": record.record_type,
        "address": record.address,
        "record_data_json": record.record_data_json or "",
        "description": record.description or "",
        "enabled": record.enabled,
        **dns_record_reverse_status(record),
    }


def dns_record_reverse_status(record: DnsRecord) -> dict[str, str]:
    """Return dns record reverse status.

    Args:
        record: Persistent or reported record affected by the operation.
    """
    record_type = record.record_type.strip().upper()
    if record_type not in {"A", "AAAA"}:
        return {
            "reverse_status": "not-applicable",
            "reverse_label": "not applicable",
            "reverse_ptr": "",
            "reverse_zone": "",
        }
    if record.enabled is False:
        return {
            "reverse_status": "disabled",
            "reverse_label": "disabled",
            "reverse_ptr": "",
            "reverse_zone": "",
        }
    reverse_records = dns_reverse_records([record])
    if not reverse_records:
        return {
            "reverse_status": "invalid",
            "reverse_label": "invalid address",
            "reverse_ptr": "",
            "reverse_zone": "",
        }
    reverse_record = reverse_records[0]
    return {
        "reverse_status": "generated",
        "reverse_label": reverse_record["ptr_name"],
        "reverse_ptr": reverse_record["ptr_name"],
        "reverse_zone": reverse_record["zone"],
    }


def normalize_dns_hostname(hostname: str, domain: str | None = None) -> str:
    """Normalize dns hostname.

    Args:
        hostname: DNS hostname contacted, validated, or configured by the operation.
        domain: Candidate domain to normalize.


    Returns:
        The normalize dns hostname result.
    """
    normalized = hostname.strip().strip(".").lower()
    zone = (domain or "").strip().strip(".").lower()
    if zone and normalized == "@":
        return zone
    if zone and normalized and normalized != zone and not normalized.endswith(f".{zone}"):
        return f"{normalized}.{zone}"
    return normalized


def dns_domains_for_settings(settings: DnsSettings) -> list[str]:
    """Return dns domains for settings.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    active = split_domains(settings.domain) or ["atlaso.internal"]
    return split_domains("\n".join([*active, *split_domains(settings.disabled_domains)]))


def dns_domain_descriptions(settings: DnsSettings) -> dict[str, str]:
    """Return dns domain descriptions.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    try:
        payload = json.loads(settings.domain_descriptions_json or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(domain).strip().strip(".").lower(): str(description).strip()
        for domain, description in payload.items()
        if str(domain).strip() and str(description).strip()
    }


def save_dns_domain_description(settings: DnsSettings, domain: str, description: str) -> None:
    """Persist dns domain description.

    Args:
        settings: Current Atlaso settings used to configure the operation.
        domain: Domain consumed by save DNS domain description.
        description: Operator-facing purpose or context for the resource.
    """
    descriptions = dns_domain_descriptions(settings)
    normalized_domain = domain.strip().strip(".").lower()
    normalized_description = description.strip()
    if normalized_description:
        descriptions[normalized_domain] = normalized_description
    else:
        descriptions.pop(normalized_domain, None)
    settings.domain_descriptions_json = json.dumps(
        descriptions,
        sort_keys=True,
        separators=(",", ":"),
    )


def save_dns_domains(settings: DnsSettings, domains: list[str]) -> None:
    """Persist dns domains.

    Args:
        settings: Current Atlaso settings used to configure the operation.
        domains: Domains consumed by save DNS domains.
    """
    settings.domain = join_domains(domains) or "atlaso.internal"


def save_disabled_dns_domains(settings: DnsSettings, domains: list[str]) -> None:
    """Persist disabled dns domains.

    Args:
        settings: Current Atlaso settings used to configure the operation.
        domains: Domains consumed by save disabled DNS domains.
    """
    settings.disabled_domains = join_domains(domains)


def records_for_domain(db: Session, domain: str) -> list[DnsRecord]:
    """Return records for domain.

    Args:
        db: Active database session.
        domain: Managed DNS domain affected by the operation.
    """
    records = db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()
    return [record for record in records if matching_domain(record.hostname, [domain]) == domain]


VCF_GENERATED_FQDN_COMPONENTS = [
    {"host": "vc01", "description": "vCenter"},
    {"host": "nsx01", "description": "NSX Manager cluster"},
    {"host": "nsx02", "description": "NSX Manager appliance 1"},
    {"host": "nsx03", "description": "NSX Manager appliance 2"},
    {"host": "nsx04", "description": "NSX Manager appliance 3"},
    {"host": "ops01", "description": "VCF Operations primary node"},
    {"host": "ops02", "description": "VCF Operations replica node"},
    {"host": "ops03", "description": "VCF Operations data node"},
    {"host": "collector", "description": "Cloud Proxy"},
    {"host": "auto-vip", "description": "VCF Automation"},
    {"host": "auto-platform", "description": "VCF Automation Runtime"},
    {"host": "sddcm", "description": "SDDC Manager"},
    {"host": "vsp01", "description": "VCF services runtime"},
    {"host": "fleetlcm", "description": "Fleet components"},
    {"host": "shared01", "description": "Instance components"},
    {"host": "vidb", "description": "Identity Broker"},
    {"host": "license", "description": "License Server"},
]

VCF_HELPER_TARGET_OPTIONS = [
    {"value": "vcf-9.1", "label": "VCF 9.1", "hosts": [component["host"] for component in VCF_GENERATED_FQDN_COMPONENTS]},
    {"value": "vvf-9.1", "label": "VVF 9.1", "hosts": ["vc01", "ops01", "vsp01", "fleetlcm", "shared01", "license"]},
]
VCF_HELPER_TARGET_LABELS = {target["value"]: target["label"] for target in VCF_HELPER_TARGET_OPTIONS}
VCF_HELPER_TARGET_HOSTS = {target["value"]: set(target["hosts"]) for target in VCF_HELPER_TARGET_OPTIONS}
VCF_HELPER_DEFAULT_TARGET = "vcf-9.1"
VCF_HELPER_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_vcf_helper_target(target: str) -> str:
    """Normalize vcf helper target.

    Args:
        target: Target resource or location affected by the operation.


    Returns:
        The normalize vcf helper target result.
    """
    return target.strip().lower() or VCF_HELPER_DEFAULT_TARGET


def vcf_helper_target_components(target: str) -> list[dict[str, str]]:
    """Return vcf helper target components.

    Args:
        target: Target resource or location affected by the operation.
    """
    normalized_target = normalize_vcf_helper_target(target)
    hosts = VCF_HELPER_TARGET_HOSTS.get(normalized_target)
    if hosts is None:
        return []
    return [component for component in VCF_GENERATED_FQDN_COMPONENTS if component["host"] in hosts]


def vcf_helper_target_component_map() -> dict[str, list[dict[str, str]]]:
    """Return vcf helper target component map."""
    return {target["value"]: vcf_helper_target_components(target["value"]) for target in VCF_HELPER_TARGET_OPTIONS}


def vcf_generated_host_label(base_host: str, prefix: str, suffix: str) -> str:
    """Return vcf generated host label.

    Args:
        base_host: Base host consumed by VCF generated host label.
        prefix: Prefix consumed by VCF generated host label.
        suffix: Suffix consumed by VCF generated host label.
    """
    return f"{prefix.strip().lower()}{base_host}{suffix.strip().lower()}"


def validate_vcf_helper_hostname_entries(
    target: str,
    component_keys: list[str],
    hostnames: list[str],
) -> tuple[dict[str, str], list[str]]:
    """Normalize and validate an exact component-keyed hostname mapping.

    Args:
        target: Resource targeted by the operation.
        component_keys: Catalog component keys submitted by the caller.
        hostnames: Reviewed hostname labels paired with the submitted component keys.

    Returns:
        The normalized mapping and any validation errors.
    """
    normalized_target = normalize_vcf_helper_target(target)
    components = vcf_helper_target_components(normalized_target)
    if not components:
        return {}, [f"VCF Helper target {target or '(blank)'} is not supported."]
    expected_keys = [component["host"] for component in components]
    expected_set = set(expected_keys)
    all_component_keys = {component["host"] for component in VCF_GENERATED_FQDN_COMPONENTS}
    errors: list[str] = []
    if len(component_keys) != len(hostnames):
        errors.append("Every submitted VCF component must have exactly one hostname.")

    normalized_mapping: dict[str, str] = {}
    for raw_key, raw_hostname in zip(component_keys, hostnames, strict=False):
        component_key = raw_key.strip().lower()
        if component_key != raw_key:
            errors.append(f"VCF component key {raw_key or '(blank)'} is malformed.")
            continue
        if component_key in normalized_mapping:
            errors.append(f"VCF component key {component_key or '(blank)'} was submitted more than once.")
            continue
        if component_key not in all_component_keys:
            errors.append(f"VCF component key {component_key or '(blank)'} is unknown.")
            continue
        if component_key not in expected_set:
            errors.append(f"VCF component key {component_key} is not part of {VCF_HELPER_TARGET_LABELS[normalized_target]}.")
            continue
        hostname = raw_hostname.strip().lower()
        if not hostname:
            errors.append(f"{component_key} hostname cannot be empty.")
        elif not VCF_HELPER_HOST_LABEL_PATTERN.fullmatch(hostname):
            errors.append(
                f"{component_key} hostname {hostname} must be one DNS label of 1 to 63 letters, numbers, or hyphens and cannot start or end with a hyphen."
            )
        normalized_mapping[component_key] = hostname

    missing_keys = [key for key in expected_keys if key not in normalized_mapping]
    if missing_keys:
        errors.append(f"VCF hostname mapping is missing components: {', '.join(missing_keys)}.")
    duplicate_hostnames = sorted(
        hostname
        for hostname in set(normalized_mapping.values())
        if list(normalized_mapping.values()).count(hostname) > 1
    )
    if duplicate_hostnames:
        errors.append(f"VCF hostname mapping contains duplicate hostnames: {', '.join(duplicate_hostnames)}.")
    if set(normalized_mapping) != expected_set:
        return {}, errors
    return normalized_mapping, errors


def vcf_generated_fqdn_preview(
    domain: str,
    prefix: str = "",
    suffix: str = "",
    target: str = VCF_HELPER_DEFAULT_TARGET,
    hostnames: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Return vcf generated fqdn preview.

    Args:
        domain: Domain consumed by VCF generated FQDN preview.
        prefix: Prefix consumed by VCF generated FQDN preview.
        suffix: Suffix consumed by VCF generated FQDN preview.
        target: Target resource or location affected by the operation.
        hostnames: Optional reviewed hostname labels keyed by immutable catalog component.
    """
    return [
        {
            "host": component["host"],
            "host_label": (hostnames or {}).get(
                component["host"],
                vcf_generated_host_label(component["host"], prefix, suffix),
            ),
            "fqdn": normalize_dns_hostname(
                (hostnames or {}).get(
                    component["host"],
                    vcf_generated_host_label(component["host"], prefix, suffix),
                ),
                domain,
            ),
            "description": component["description"],
        }
        for component in vcf_helper_target_components(target)
    ]


def occupied_vcf_helper_addresses(record_type: str, db: Session) -> set[IPv4Address | IPv6Address]:
    """Return occupied vcf helper addresses.

    Args:
        record_type: Record type supplied by the caller.
        db: Active database session.
    """
    normalized_type = record_type.strip().upper()
    occupied: set[IPv4Address | IPv6Address] = set()
    for record in db.execute(select(DnsRecord).where(func.upper(DnsRecord.record_type) == normalized_type)).scalars().all():
        address = ip_address_or_none(record.address)
        if normalized_type == "A" and isinstance(address, IPv4Address):
            occupied.add(address)
        if normalized_type == "AAAA" and isinstance(address, IPv6Address):
            occupied.add(address)
    if normalized_type == "A":
        occupied.update(
            address
            for address in [
                ipv4_address_or_none(reservation.ip_address)
                for reservation in db.execute(select(DhcpReservation)).scalars().all()
            ]
            if address is not None
        )
    return occupied


def vcf_helper_existing_address_records(records: list[DnsRecord]) -> dict[str, list[str]]:
    """Return vcf helper existing address records.

    Args:
        records: Persistent or reported records processed by the operation.
    """
    addresses: dict[str, list[str]] = {}
    for record in records:
        if record.record_type.strip().upper() not in {"A", "AAAA"}:
            continue
        if ip_address_or_none(record.address) is None:
            continue
        fqdn = record.hostname.strip().strip(".").lower()
        if record.address not in addresses.setdefault(fqdn, []):
            addresses[fqdn].append(record.address)
    return addresses


def vcf_helper_start_network(
    start_ipv4: str,
    network_prefix: str = "",
) -> tuple[IPv4Address | IPv6Address | None, IPv4Network | IPv6Network | None, str | None]:
    """Return vcf helper start network.

    Args:
        start_ipv4: Start ipv4 consumed by VCF helper start network.
        network_prefix: Network prefix consumed by VCF helper start network.
    """
    candidate = start_ipv4.strip()
    if "/" not in candidate and network_prefix.strip():
        candidate = f"{candidate}/{network_prefix.strip().removeprefix('/')}"
    try:
        interface = ip_interface(candidate)
    except ValueError:
        return None, None, "Starting IP / prefix must be a valid IPv4 or IPv6 CIDR, such as 192.168.50.100/24 or 2001:db8::100/64."
    network = interface.network
    start_address = interface.ip
    if isinstance(start_address, IPv4Address):
        if network.prefixlen > 30:
            return None, None, "IPv4 network prefix must be a CIDR prefix from /0 through /30."
        if start_address == network.network_address or start_address == network.broadcast_address:
            return None, None, f"Starting IPv4 address must be a usable host address in {network}."
    elif isinstance(start_address, IPv6Address):
        if network.prefixlen > 127:
            return None, None, "IPv6 network prefix must be a CIDR prefix from /0 through /127."
        if start_address == network.network_address:
            return None, None, f"Starting IPv6 address must not be the subnet-router anycast address in {network}."
    else:
        return None, None, "Starting IP / prefix must be a valid IPv4 or IPv6 CIDR."
    return start_address, network, None


def next_available_vcf_address(
    candidate: IPv4Address | IPv6Address,
    occupied: set[IPv4Address | IPv6Address],
    network: IPv4Network | IPv6Network,
) -> IPv4Address | IPv6Address | None:
    """Return next available vcf address.

    Args:
        candidate: Candidate consumed by next available VCF address.
        occupied: Occupied consumed by next available VCF address.
        network: Network consumed by next available VCF address.
    """
    current = int(candidate)
    last_host = int(network.broadcast_address) - 1 if isinstance(candidate, IPv4Address) else int(network.broadcast_address)
    while current <= last_host:
        address = IPv4Address(current) if isinstance(candidate, IPv4Address) else IPv6Address(current)
        if address not in occupied:
            return address
        current += 1
    return None


def allocate_vcf_generated_records(
    db: Session,
    *,
    target: str,
    domain: str,
    prefix: str,
    suffix: str,
    start_ipv4: str,
    network_prefix: str,
    component_keys: list[str],
    hostnames: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    """Return allocate vcf generated records.

    Args:
        db: Active database session.
        target: Resource targeted by the operation.
        domain: Managed DNS domain affected by the operation.
        prefix: Prefix supplied by the caller.
        suffix: Suffix supplied by the caller.
        start_ipv4: Start ipv4 supplied by the caller.
        network_prefix: Network prefix supplied by the caller.
        component_keys: Catalog component keys submitted by the caller.
        hostnames: Reviewed hostname labels paired with the submitted component keys.
    """
    domains = dns_domains_for_settings(get_dns_settings_row(db))
    normalized_domain = domain.strip().strip(".").lower()
    if normalized_domain not in domains:
        return [], [], [f"DNS domain {normalized_domain or '(blank)'} is not managed by Atlaso."]
    normalized_target = normalize_vcf_helper_target(target)
    if normalized_target not in VCF_HELPER_TARGET_LABELS:
        return [], [], [f"VCF Helper target {target or '(blank)'} is not supported."]
    hostname_mapping, hostname_errors = validate_vcf_helper_hostname_entries(
        normalized_target,
        component_keys,
        hostnames,
    )
    if hostname_errors:
        return [], [], hostname_errors
    start_address, network, network_error = vcf_helper_start_network(start_ipv4, network_prefix)
    if network_error or start_address is None or network is None:
        return [], [], [network_error or "Starting IP / prefix is invalid."]
    record_type = "AAAA" if isinstance(start_address, IPv6Address) else "A"

    preview_rows = vcf_generated_fqdn_preview(
        normalized_domain,
        prefix,
        suffix,
        normalized_target,
        hostname_mapping,
    )
    errors: list[str] = []
    for row in preview_rows:
        if not row["host_label"]:
            errors.append(f"{row['description']} generated hostname cannot be empty.")
            continue
        if not DNS_HOSTNAME_PATTERN.match(row["fqdn"]):
            errors.append(f"{row['description']} generated FQDN {row['fqdn']} is not a valid DNS hostname.")
            continue
        errors.extend(validate_dns_record(row["fqdn"], record_type, str(start_address)))
    if errors:
        return [], [], errors

    existing_records = db.execute(select(DnsRecord)).scalars().all()
    existing_fqdns = {record.hostname.strip().strip(".").lower() for record in existing_records}
    existing_address_records = vcf_helper_existing_address_records(existing_records)
    skipped = [
        {**row, **({"address": ", ".join(existing_address_records[row["fqdn"]])} if row["fqdn"] in existing_address_records else {})}
        for row in preview_rows
        if row["fqdn"] in existing_fqdns
    ]
    rows_to_create = [row for row in preview_rows if row["fqdn"] not in existing_fqdns]
    occupied = occupied_vcf_helper_addresses(record_type, db)
    created: list[dict[str, str]] = []
    next_candidate = start_address
    for row in rows_to_create:
        assigned = next_available_vcf_address(next_candidate, occupied, network)
        if assigned is None:
            address_family = "IPv6" if record_type == "AAAA" else "IPv4"
            return [], skipped, [f"Not enough available {address_family} addresses remain in {network} after the starting address."]
        row_with_address = {**row, "address": str(assigned), "record_type": record_type}
        validation_errors = validate_dns_record(row_with_address["fqdn"], record_type, row_with_address["address"])
        if validation_errors:
            return [], skipped, validation_errors
        created.append(row_with_address)
        occupied.add(assigned)
        if isinstance(assigned, IPv6Address):
            next_candidate = IPv6Address(int(assigned) + 1) if int(assigned) < int(network.broadcast_address) else assigned
        else:
            next_candidate = IPv4Address(int(assigned) + 1)
    return created, skipped, []


def create_vcf_generated_dns_records(
    db: Session,
    *,
    target: str,
    domain: str,
    prefix: str,
    suffix: str,
    start_ipv4: str,
    network_prefix: str,
    component_keys: list[str],
    hostnames: list[str],
    actor: str,
    expected_created: list[dict[str, str]] | None = None,
    expected_skipped: list[dict[str, str]] | None = None,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    """Create vcf generated dns records.

    Args:
        db: Active database session.
        target: Resource targeted by the operation.
        domain: Managed DNS domain affected by the operation.
        prefix: Prefix supplied by the caller.
        suffix: Suffix supplied by the caller.
        start_ipv4: Start ipv4 supplied by the caller.
        network_prefix: Network prefix supplied by the caller.
        component_keys: Catalog component keys submitted by the caller.
        hostnames: Reviewed hostname labels paired with the submitted component keys.
        actor: Authenticated identity attributed to the audit record.
        expected_created: Exact reviewed allocation required before mutation.
        expected_skipped: Exact reviewed existing-record set required before mutation.

    Returns:
        The created vcf generated dns records.
    """
    created, skipped, errors = allocate_vcf_generated_records(
        db,
        target=target,
        domain=domain,
        prefix=prefix,
        suffix=suffix,
        start_ipv4=start_ipv4,
        network_prefix=network_prefix,
        component_keys=component_keys,
        hostnames=hostnames,
    )
    if errors:
        return [], skipped, errors
    if (
        expected_created is not None
        and expected_skipped is not None
        and (created != expected_created or skipped != expected_skipped)
    ):
        return [], skipped, [
            "Generated FQDN allocation changed since Populate. Select Populate and review the current plan again."
        ]
    for row in created:
        record_type = row["record_type"]
        db.add(
            DnsRecord(
                hostname=row["fqdn"],
                record_type=record_type,
                address=row["address"],
                record_data_json=dump_dns_record_data(
                    record_type,
                    row["address"],
                    {
                        "source": "vcf_helper",
                        "component": row["host"],
                        "host_label": row["host_label"],
                    },
                ),
                description=row["description"],
                enabled=True,
            )
        )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return [], skipped, ["Generated VCF FQDNs conflict with existing DNS records."]
    record_audit(
        db,
        actor=actor,
        action="generate_vcf_fqdns",
        resource_type="dns_record",
        detail=f"Created {len(created)} {VCF_HELPER_TARGET_LABELS[normalize_vcf_helper_target(target)]} DNS records; skipped {len(skipped)} existing records in {domain.strip().strip('.').lower()}.",
    )
    return created, skipped, []


def delete_vcf_generated_dns_records(
    db: Session,
    *,
    target: str,
    domain: str,
    prefix: str,
    suffix: str,
    component_keys: list[str],
    hostnames: list[str],
    actor: str,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    """Remove vcf generated dns records.

    Args:
        db: Active database session.
        target: Resource targeted by the operation.
        domain: Managed DNS domain affected by the operation.
        prefix: Prefix supplied by the caller.
        suffix: Suffix supplied by the caller.
        component_keys: Catalog component keys submitted by the caller.
        hostnames: Reviewed hostname labels paired with the submitted component keys.
        actor: Authenticated identity attributed to the audit record.

    Returns:
        The delete vcf generated dns records result.
    """
    domains = dns_domains_for_settings(get_dns_settings_row(db))
    normalized_domain = domain.strip().strip(".").lower()
    if normalized_domain not in domains:
        return [], [], [f"DNS domain {normalized_domain or '(blank)'} is not managed by Atlaso."]
    normalized_target = normalize_vcf_helper_target(target)
    if normalized_target not in VCF_HELPER_TARGET_LABELS:
        return [], [], [f"VCF Helper target {target or '(blank)'} is not supported."]

    hostname_mapping, hostname_errors = validate_vcf_helper_hostname_entries(
        normalized_target,
        component_keys,
        hostnames,
    )
    if hostname_errors:
        return [], [], hostname_errors
    preview_rows = vcf_generated_fqdn_preview(
        normalized_domain,
        prefix,
        suffix,
        normalized_target,
        hostname_mapping,
    )
    rows_by_fqdn = {row["fqdn"]: row for row in preview_rows}
    matching_records = db.execute(
        select(DnsRecord).where(
            func.lower(DnsRecord.hostname).in_(list(rows_by_fqdn)),
            func.upper(DnsRecord.record_type).in_(["A", "AAAA"]),
        )
    ).scalars().all()
    deleted: list[dict[str, str]] = []
    preserved: list[dict[str, str]] = []
    for record in matching_records:
        row = rows_by_fqdn.get(record.hostname.strip().strip(".").lower())
        if row is None:
            continue
        metadata = record_data(record)
        helper_owned = (
            metadata.get("source") == "vcf_helper"
            and metadata.get("component") == row["host"]
            and metadata.get("host_label", row["host_label"]) == row["host_label"]
        )
        result_row = {**row, "address": record.address, "record_type": record.record_type.strip().upper()}
        if helper_owned:
            db.delete(record)
            deleted.append(result_row)
        else:
            preserved.append(result_row)
    db.commit()
    record_audit(
        db,
        actor=actor,
        action="delete_vcf_fqdns",
        resource_type="dns_record",
        detail=f"Deleted {len(deleted)} {VCF_HELPER_TARGET_LABELS[normalized_target]} DNS records; preserved {len(preserved)} unrelated records in {normalized_domain}.",
    )
    return deleted, preserved, []


def vcf_helper_context(db: Session) -> dict[str, Any]:
    """Return vcf helper context.

    Args:
        db: Active database session.
    """
    domains = dns_domains_for_settings(get_dns_settings_row(db))
    default_domain = domains[0] if domains else "atlaso.internal"
    records = db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()
    reservations = db.execute(select(DhcpReservation).order_by(DhcpReservation.hostname)).scalars().all()
    scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    suggested_start_ipv4 = dns_record_suggested_ipv4(records, default_domain, scopes, reservations)
    return {
        "dns_domain_options": domains,
        "vcf_helper_target_options": VCF_HELPER_TARGET_OPTIONS,
        "vcf_helper_default_target": VCF_HELPER_DEFAULT_TARGET,
        "vcf_helper_target_components": vcf_helper_target_component_map(),
        "vcf_helper_default_domain": default_domain,
        "vcf_helper_default_prefix": "",
        "vcf_helper_default_suffix": "",
        "vcf_helper_rows": vcf_generated_fqdn_preview(default_domain, target=VCF_HELPER_DEFAULT_TARGET),
        "vcf_helper_existing_fqdns": sorted(record.hostname.strip().strip(".").lower() for record in records),
        "vcf_helper_existing_address_records": vcf_helper_existing_address_records(records),
        "vcf_helper_default_start_ipv4": f"{suggested_start_ipv4}/24" if suggested_start_ipv4 else "",
        **vcf_sddc_helper_context(db),
    }


def vcf_ldap_helper_context(db: Session, *, selected_organization_id: int | None = None) -> dict[str, Any]:
    """Return vcf ldap helper context.

    Args:
        db: Active database session.
        selected_organization_id: Identifier of the selected organization.
    """
    organizations = ldap_organizations_query(db)
    selected_organization = next((row for row in organizations if row.id == selected_organization_id), None)
    if selected_organization is None and organizations:
        selected_organization = organizations[0]
    settings = get_ldap_settings_row(db)
    missing_password_count = sum(
        1
        for user in (selected_organization.users if selected_organization else [])
        if user.enabled and not user.password_applied_at and not has_pending_ldap_password(user)
    )
    return {
        "vcf_ldap_organizations": organizations,
        "vcf_ldap_selected_organization": selected_organization,
        "vcf_ldap_available": settings.enabled and any(organization.enabled for organization in organizations),
        "vcf_ldap_missing_password_count": missing_password_count,
        "vcf_ldap_mapping": (
            vcf_ldap_settings(settings, selected_organization, include_password=False)
            if selected_organization
            else {}
        ),
    }


def local_vcf_depot_target_context(db: Session) -> dict[str, Any]:
    """Return local vcf depot target context.

    Args:
        db: Active database session.
    """
    settings = get_vcf_offline_depot_settings_row(db)
    software_depot = vcf_depot_software_depot_id_context(db)
    apply_state = appliance_apply_status(db, "vcf_offline_depot")
    username = settings.http_user.username if settings.http_user else ""
    endpoint = vcf_depot_endpoint(settings)
    url = f"https://{endpoint}"
    reasons: list[str] = []
    if not settings.enabled:
        reasons.append("Enable VCF Offline Depot.")
    if apply_state.get("changed"):
        reasons.append("Apply the current VCF Offline Depot desired state.")
    if not software_depot.get("id"):
        reasons.append("Generate the software depot ID through Appliance Apply.")
    if not username:
        reasons.append("Select a VCF Offline Depot HTTP user.")
    if not ca_certificate_available(db, "vcf_offline_depot:https"):
        reasons.append("Issue the CA-managed VCF Offline Depot HTTPS certificate.")
    nginx_active = backing_systemd_unit_active("nginx.service")
    if get_settings().environment == "appliance" and nginx_active is not True:
        reasons.append("The appliance nginx service is not active.")
    return {
        "available": not reasons,
        "reasons": reasons,
        "hostname": settings.hostname.strip(),
        "port": int(settings.port or 443),
        "url": url,
        "username": username,
        "software_depot_id": software_depot.get("id", ""),
    }


def vcf_sddc_helper_context(db: Session) -> dict[str, Any]:
    """Return vcf sddc helper context.

    Args:
        db: Active database session.
    """
    try:
        inventory = ova_inventory()
        inventory_error = ""
    except OSError as exc:
        inventory = []
        inventory_error = str(exc)
    latest_deploy = db.execute(
        select(Job).where(Job.type == "vcf-sddc-manager-deploy").order_by(desc(Job.created_at))
    ).scalars().first()
    latest_depot = db.execute(
        select(Job).where(Job.type == "vcf-offline-depot-target-config").order_by(desc(Job.created_at))
    ).scalars().first()
    return {
        "vcf_sddc_ovas": inventory,
        "vcf_sddc_ova_root": str(SDDC_MANAGER_OVA_ROOT),
        "vcf_sddc_inventory_error": inventory_error,
        "vcf_sddc_dhcp_assignment": vcf_sddc_dhcp_assignment_context(db),
        "vcf_sddc_latest_job": latest_deploy,
        "vcf_sddc_latest_result": json.loads(latest_deploy.result or "{}") if latest_deploy else {},
        "vcf_target_depot": local_vcf_depot_target_context(db),
        "vcf_target_depot_latest_job": latest_depot,
        "vcf_target_depot_latest_result": json.loads(latest_depot.result or "{}") if latest_depot else {},
    }


def _job_payload(job: Job) -> dict[str, Any]:
    """Return job payload.

    Args:
        job: Background job record affected by the operation.
    """
    try:
        return dict(json.loads(job.result or "{}"))
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


class JobCancelled(RuntimeError):
    """Represent job cancelled."""
    pass


ACTIVE_JOB_STATUSES = {JobStatus.PENDING.value, JobStatus.RUNNING.value}
FAILED_JOB_STATUSES = {JobStatus.FAILED.value, "partial-failure"}
SERVICE_ADMIN_CANCELLABLE_JOB_TYPES = {
    "vcf-sddc-manager-deploy",
    "vcf-offline-depot-target-config",
    "vcf-ca-trust",
    "pxe-media-sync",
}
TASK_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|credential|authorization|activation|private[_-]?key|api[_-]?key|payload[_-]?b64)", re.IGNORECASE)
TASK_SECRET_VALUE_RE = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[A-Za-z0-9_-]{16,}|Bearer\s+[A-Za-z0-9._-]{12,})", re.IGNORECASE)
TASK_INLINE_SECRET_RE = re.compile(
    r"(?P<label>\b[a-z0-9_-]*(?:password|passwd|secret|token|credential|authorization|activation|private[_-]?key|api[_-]?key|payload[_-]?b64)\b)"
    r"(?P<separator>\s*(?:=|:)\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)",
    re.IGNORECASE,
)


def _raise_if_job_cancelled(job: Job, db: Session) -> None:
    """Handle raise if job cancelled.

    Args:
        job: Job being processed.
        db: Active database session.

    Raises:
        JobCancelled: If the operation encounters an invalid state.
    """
    db.refresh(job)
    if job.status == JobStatus.CANCELLED.value:
        raise JobCancelled("Task was cancelled by an operator.")


def _update_job(job: Job, db: Session, percent: int, state: str, **values: Any) -> None:
    """Update job.

    Args:
        job: Job being processed.
        db: Active database session.
        percent: Completion percentage to record for the job.
        state: Lifecycle or job state to persist.
        **values: Values to normalize, validate, or persist.
    """
    payload = _job_payload(job)
    payload.update(values)
    payload["state"] = state
    job.progress_percent = max(0, min(100, percent))
    job.result = json.dumps(payload, sort_keys=True)
    db.commit()


def _update_cancelable_job(job: Job, db: Session, percent: int, state: str, **values: Any) -> None:
    """Update cancelable job.

    Args:
        job: Job being processed.
        db: Active database session.
        percent: Completion percentage to record for the job.
        state: Lifecycle or job state to persist.
        **values: Values to normalize, validate, or persist.
    """
    _raise_if_job_cancelled(job, db)
    _update_job(job, db, percent, state, **values)


def _redact_task_value(value: Any, *, key: str = "") -> Any:
    """Return redact task value.

    Args:
        value: Candidate value consumed by redact task value.
        key: Stable key identifying the setting, secret, or mapping entry.
    """
    if key and TASK_SECRET_KEY_RE.search(key):
        return "[redacted]"
    if isinstance(value, dict):
        return {str(item_key): _redact_task_value(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact_task_value(item) for item in value]
    if isinstance(value, str):
        if TASK_SECRET_VALUE_RE.search(value):
            return "[redacted]"
        return TASK_INLINE_SECRET_RE.sub(lambda match: f"{match.group('label')}{match.group('separator')}[redacted]", value)
    return value


def _task_failure_messages(value: Any) -> list[str]:
    """Return task failure messages.

    Args:
        value: Candidate value consumed by task failure messages.
    """
    messages: list[str] = []
    message_keys = {"error", "errors", "detail", "message", "reason", "stderr"}

    def add_message(candidate: Any) -> None:
        """Create message.

        Args:
            candidate: Candidate consumed by add message.
        """
        if isinstance(candidate, str):
            message = candidate.strip()
            if message and message not in messages:
                messages.append(message[:4000])
        elif isinstance(candidate, list):
            for item in candidate:
                add_message(item)

    def collect(candidate: Any) -> None:
        """Handle collect.

        Args:
            candidate: Candidate consumed by collect.
        """
        if isinstance(candidate, dict):
            successful_command = candidate.get("returncode") == 0 or candidate.get("success") is True
            for item_key, item_value in candidate.items():
                normalized_key = str(item_key).lower()
                if normalized_key in message_keys and not (normalized_key == "stderr" and successful_command):
                    add_message(item_value)
                if isinstance(item_value, (dict, list)):
                    collect(item_value)
        elif isinstance(candidate, list):
            for item in candidate:
                collect(item)

    collect(value)
    return messages[:8]


def _task_status_pill(status_value: str) -> str:
    """Return task status pill.

    Args:
        status_value: Status value consumed by task status pill.
    """
    if status_value in {JobStatus.SUCCEEDED.value, "no-op"}:
        return "good"
    if status_value in FAILED_JOB_STATUSES:
        return "error"
    if status_value == JobStatus.CANCELLED.value:
        return "muted"
    if status_value in ACTIVE_JOB_STATUSES:
        return "warn"
    return "muted"


def _task_console_output(result: dict[str, Any]) -> str:
    """Return task console output.

    Args:
        result: Operation result being inspected or returned.
    """
    stdout, stderr = _task_console_streams(result)
    sections: list[str] = []
    if stdout:
        sections.append(stdout)
    if stderr:
        sections.append(f"stderr:\n{stderr}")
    return "\n\n".join(sections)


def _task_console_streams(result: dict[str, Any]) -> tuple[str, str]:
    """Return task console streams.

    Args:
        result: Operation result being inspected or returned.
    """
    return (
        _strip_task_action_metadata(result.get("stdout")),
        _strip_task_action_metadata(result.get("stderr")),
    )


def _strip_task_action_metadata(value: Any) -> str:
    """Remove helper execution envelopes while preserving script output.

    Args:
        value: Candidate value consumed by strip task action metadata.
    """
    text = str(value or "").strip()
    decoder = json.JSONDecoder()
    while text.startswith("{"):
        try:
            payload, end = decoder.raw_decode(text)
        except json.JSONDecodeError:
            break
        if not isinstance(payload, dict) or not {"helper", "group", "action"}.issubset(payload):
            break
        text = text[end:].lstrip()
    return text


def _task_type_label(job_type: str) -> str:
    """Return task type label.

    Args:
        job_type: Job type consumed by task type label.
    """
    labels = {
        "appliance-apply": "Appliance Apply",
        "appliance-reboot": "Appliance Reboot",
        "appliance-shutdown": "Appliance Shutdown",
        "appliance-update": "Appliance Update",
        "vcf-sddc-manager-deploy": "Deploy SDDC Manager",
        "vcf-offline-depot-target-config": "Configure VCF Offline Depot",
        "vcf-ca-trust": "VCF Certificate Trust",
        "vcf-depot-download": "VCF Depot Download",
        "vcf-depot-software-id": "VCFDT Software Depot ID",
        "pxe-media-sync": "Network Boot Media Sync",
    }
    return labels.get(job_type, job_type.replace("-", " ").title())


def _appliance_update_task_label(mode: str) -> str:
    """Return appliance update task label.

    Args:
        mode: Mode consumed by appliance update task label.
    """
    return {
        "check": "Appliance Update check",
        "run": "Appliance Update install",
        "source_sync": "Appliance Update repository sync",
    }.get(mode, "Appliance Update")


APPLIANCE_UPDATE_TASK_MODES_BY_LABEL = {
    _appliance_update_task_label(mode).lower(): mode for mode in ("check", "run", "source_sync")
}


def _appliance_update_mode_filter_clause(mode: str) -> Any:
    """Return appliance update mode filter clause.

    Args:
        mode: Mode consumed by appliance update mode filter clause.
    """
    mode_patterns = (f'"mode":"{mode}"', f'"mode": "{mode}"')
    return and_(
        Job.type == "appliance-update",
        or_(
            *(func.lower(Job.task_config_json).contains(pattern) for pattern in mode_patterns),
            *(func.lower(Job.result).contains(pattern) for pattern in mode_patterns),
        ),
    )


def _task_row_type_label(job: Job, result: dict[str, Any]) -> str:
    """Return task row type label.

    Args:
        job: Background job record affected by the operation.
        result: Operation result being inspected or returned.
    """
    if job.type != "appliance-update":
        return _task_type_label(job.type)
    mode = str(result.get("mode") or "")
    if not mode:
        try:
            task_config = json.loads(job.task_config_json or "{}")
        except (json.JSONDecodeError, TypeError):
            task_config = {}
        if isinstance(task_config, dict):
            mode = str(task_config.get("mode") or "")
    return _appliance_update_task_label(mode)


def _task_time_label(value: datetime | None) -> str:
    """Return task time label.

    Args:
        value: Candidate value consumed by task time label.
    """
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _can_cancel_task(job: Job, identity: Identity | None = None) -> bool:
    """Return whether cancel task.

    Args:
        job: Job being processed.
        identity: Authenticated identity authorizing the request.
    """
    if job.status not in ACTIVE_JOB_STATUSES:
        return False
    if job.type == "pxe-media-sync" and job.status == JobStatus.RUNNING.value:
        try:
            config = json.loads(job.task_config_json or "{}")
        except json.JSONDecodeError:
            config = {}
        if config.get("source") == "delete":
            return False
    if job.type == "appliance-apply" and _job_payload(job).get("cancel_requested"):
        return False
    if job.type == "appliance-update" and job.status == JobStatus.RUNNING.value:
        return False
    if job.type == "vcf-depot-software-id":
        return False
    if job.type == "vcf-depot-download" and job.status == JobStatus.RUNNING.value:
        return False
    if identity is None:
        return True
    if identity.has_role(Role.ADMIN.value):
        return True
    return identity.has_role(Role.SERVICE_ADMIN.value) and job.type in SERVICE_ADMIN_CANCELLABLE_JOB_TYPES


def _job_step_payload(step: JobStep) -> dict[str, Any]:
    """Return job step payload.

    Args:
        step: Step consumed by job step payload.
    """
    if not step.result:
        return {}
    try:
        value = json.loads(step.result)
    except (json.JSONDecodeError, TypeError):
        return {"raw": str(step.result)}
    return value if isinstance(value, dict) else {"value": value}


def _task_row(job: Job, identity: Identity | None = None) -> dict[str, Any]:
    """Return task row.

    Args:
        job: Job being processed.
        identity: Authenticated identity authorizing the request.
    """
    raw_result = _job_payload(job)
    result = _redact_task_value(raw_result)
    status_value = str(job.status or "")
    state = str(result.get("state") or status_value)
    summary = str(result.get("target") or result.get("fqdn") or result.get("vm_name") or result.get("profile_name") or "")
    if not summary and isinstance(result.get("vm"), dict):
        summary = str(result["vm"].get("vm_name") or result["vm"].get("guest_ip") or "")
    error = _redact_task_value(job.error or "")
    error_messages = _task_failure_messages(result)
    if error and error not in error_messages:
        error_messages.append(str(error))
    steps = sorted(job.steps, key=lambda step: (step.position, step.id))
    if not summary and steps:
        summary = f"{len(steps)} component{'s' if len(steps) != 1 else ''}"
    console_stdout, console_stderr = _task_console_streams(result)
    row = {
        "id": job.id,
        "type": job.type,
        "type_label": _task_row_type_label(job, raw_result),
        "status": status_value,
        "status_pill": _task_status_pill(status_value),
        "state": state,
        "summary": summary,
        "created_by": job.created_by,
        "created_at": _task_time_label(job.created_at),
        "started_at": _task_time_label(job.started_at),
        "finished_at": _task_time_label(job.finished_at),
        "progress_percent": max(0, min(100, int(job.progress_percent or 0))),
        "result": result,
        "result_json": json.dumps(result, indent=2, sort_keys=True),
        "console_output": _task_console_output(result),
        "console_stdout": console_stdout,
        "console_stderr": console_stderr,
        "error": error,
        "error_messages": error_messages,
        "can_cancel": _can_cancel_task(job, identity),
        "can_start": False,
    }
    if job.type == "vcf-depot-download":
        row["log_url"] = f"/vcf-offline-depot/tasks/{job.id}/log"
    if job.type == "appliance-apply":
        management_restart_window = appliance_apply_management_restart_window(job)
        if management_restart_window is not None:
            row["management_restart_window"] = management_restart_window
    if steps:
        row["_children"] = [_job_step_row(step) for step in steps]
    return row


def _job_step_row(step: JobStep) -> dict[str, Any]:
    """Return job step row.

    Args:
        step: Step consumed by job step row.
    """
    result = _redact_task_value(_job_step_payload(step))
    error = _redact_task_value(step.error or "")
    error_messages = _task_failure_messages(result)
    if error and error not in error_messages:
        error_messages.append(str(error))
    status_value = str(step.status or JobStatus.PENDING.value)
    console_stdout, console_stderr = _task_console_streams(result)
    is_appliance_update = step.job is not None and step.job.type == "appliance-update"
    return {
        "id": step.id,
        "job_id": step.job_id,
        "component_key": step.component_key,
        "label": step.label,
        "type": "appliance-update-step" if is_appliance_update else "appliance-apply-step",
        "type_label": "Update stream" if is_appliance_update else "Apply component",
        "status": status_value,
        "status_pill": _task_status_pill(status_value),
        "state": status_value,
        "summary": " · ".join(str(item) for item in result.get("summary", []) if item),
        "created_by": step.job.created_by if step.job is not None else "",
        "created_at": _task_time_label(step.created_at),
        "started_at": _task_time_label(step.started_at),
        "finished_at": _task_time_label(step.finished_at),
        "progress_percent": max(0, min(100, int(step.progress_percent or 0))),
        "result": result,
        "result_json": json.dumps(result, indent=2, sort_keys=True),
        "console_output": _task_console_output(result),
        "console_stdout": console_stdout,
        "console_stderr": console_stderr,
        "error": error,
        "error_messages": error_messages,
        "can_cancel": False,
        "is_step": True,
        "position": step.position,
    }


def _task_filter_clauses(raw_filters: str) -> list[Any]:
    """Return task filter clauses.

    Args:
        raw_filters: Raw filters consumed by task filter clauses.


    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    try:
        filters = json.loads(raw_filters or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Task filters must be valid JSON.") from exc
    if not isinstance(filters, list) or len(filters) > 10:
        raise HTTPException(status_code=400, detail="Task filters must be a list of at most 10 filters.")
    clauses: list[Any] = []
    allowed_fields = {"status", "id", "state", "created_at"}
    for item in filters:
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail="Each task filter must be an object.")
        field = str(item.get("field") or "")
        filter_type = str(item.get("type") or "")
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        if field not in allowed_fields or filter_type not in {"=", "like"} or len(value) > 100:
            raise HTTPException(status_code=400, detail="Unsupported task filter.")
        normalized = value.lower()
        if field == "status":
            clauses.append(func.lower(Job.status) == normalized)
        elif field == "id":
            type_value = normalized.replace(" ", "-")
            appliance_update_mode = APPLIANCE_UPDATE_TASK_MODES_BY_LABEL.get(normalized)
            clauses.append(
                or_(
                    func.lower(Job.id).contains(normalized),
                    func.lower(Job.type).contains(normalized),
                    func.lower(Job.type).contains(type_value),
                    *(
                        [_appliance_update_mode_filter_clause(appliance_update_mode)]
                        if appliance_update_mode
                        else []
                    ),
                    Job.steps.any(
                        or_(
                            func.lower(JobStep.label).contains(normalized),
                            func.lower(JobStep.component_key).contains(normalized),
                        )
                    ),
                )
            )
        elif field == "state":
            clauses.append(or_(func.lower(Job.status).contains(normalized), func.lower(Job.result).contains(normalized)))
        elif field == "created_at":
            clauses.append(func.lower(cast(Job.created_at, String)).contains(normalized))
    return clauses


def _task_component_filter_options(db: Session) -> list[str]:
    """Return task component filter options.

    Args:
        db: Active database session.
    """
    task_types = db.execute(select(Job.type).where(Job.type.is_not(None)).distinct().order_by(Job.type)).scalars().all()
    component_labels = db.execute(
        select(JobStep.label).where(JobStep.label.is_not(None), JobStep.label != "").distinct().order_by(JobStep.label)
    ).scalars().all()
    options = {_task_type_label(task_type) for task_type in task_types if task_type}
    if "appliance-update" in task_types:
        options.update(_appliance_update_task_label(mode) for mode in ("check", "run", "source_sync"))
    options.update(label for label in component_labels if label)
    return sorted(options, key=str.lower)


def _task_log_lines(job: Job, db: Session) -> list[str]:
    """Return task log lines.

    Args:
        job: Job being processed.
        db: Active database session.
    """
    row = _task_row(job)
    lines = [
        f"Job: {row['id']}",
        f"Type: {row['type_label']} ({row['type']})",
        f"Status: {row['status']}",
        f"State: {row['state']}",
        f"Progress: {row['progress_percent']}%",
        f"Created: {row['created_at'] or 'not recorded'} by {row['created_by']}",
        f"Started: {row['started_at'] or 'not started'}",
        f"Finished: {row['finished_at'] or 'not finished'}",
    ]
    if row["summary"]:
        lines.append(f"Summary: {row['summary']}")
    if row["error"]:
        lines.append(f"Error: {row['error']}")
    result = row["result"]
    if isinstance(result, dict):
        for key, value in result.items():
            if key == "log_lines" and isinstance(value, list):
                lines.append("")
                lines.append("Job log lines:")
                lines.extend(str(item) for item in value)
                continue
            if key in {"state"}:
                continue
            lines.append(f"{key}: {json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value}")
    audit_events = db.execute(
        select(AuditEvent).where(AuditEvent.resource_type == "job", AuditEvent.resource_id == job.id).order_by(AuditEvent.created_at)
    ).scalars().all()
    if audit_events:
        lines.append("")
        lines.append("Audit events:")
        for event in audit_events:
            detail = _redact_task_value(event.detail or "")
            outcome = "success" if event.success else "failed"
            lines.append(f"{event.created_at.isoformat()} {event.action} {outcome} {detail}".rstrip())
    return [str(_redact_task_value(line)) for line in lines]


def _local_depot_endpoint(db: Session) -> LocalDepotEndpoint:
    """Return local depot endpoint.

    Args:
        db: Active database session.

    Raises:
        VcfDepotTargetError: If the operation encounters an invalid state.
    """
    context = local_vcf_depot_target_context(db)
    if not context["available"]:
        raise VcfDepotTargetError(" ".join(context["reasons"]))
    return LocalDepotEndpoint(
        hostname=str(context["hostname"]),
        port=int(context["port"]),
        url=str(context["url"]),
        username=str(context["username"]),
    )


def run_vcf_target_depot_job(
    job_id: str,
    *,
    address: str,
    port: int,
    api_username: str,
    api_password: str,
    depot_password: str,
    replace_existing: bool,
    expected_fingerprint: str,
) -> None:
    """Run vcf target depot job.

    Args:
        job_id: Identifier of the job.
        address: Network address of the target service or interface.
        port: TCP or UDP port of the target service.
        api_username: Api username supplied by the caller.
        api_password: Api password supplied by the caller.
        depot_password: Depot password supplied by the caller.
        replace_existing: Replace existing supplied by the caller.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.
    """
    with SessionLocal() as db:
        configure_operational_logging(db)
        job = db.get(Job, job_id)
        if not job:
            return
        job.status = JobStatus.RUNNING.value
        job.started_at = utcnow()
        db.commit()
        try:
            local = _local_depot_endpoint(db)

            def update(percent: int, state: str) -> None:
                """Update operation.

                Args:
                    percent: Percent consumed by update.
                    state: Current lifecycle state consumed by the operation.
                """
                _update_cancelable_job(job, db, percent, state)

            outcome = configure_target_depot(
                address,
                api_username,
                api_password,
                local,
                depot_password,
                replace_existing=replace_existing,
                progress=update,
                port=port,
                expected_fingerprint=expected_fingerprint,
            )
            _raise_if_job_cancelled(job, db)
            job.status = JobStatus.SUCCEEDED.value if outcome["configuration"] == "updated" else "no-op"
            job.finished_at = utcnow()
            job.error = None
            _update_job(job, db, 100, job.status, target=address, port=port, **outcome)
            success = True
        except JobCancelled:
            job.status = JobStatus.CANCELLED.value
            job.finished_at = utcnow()
            job.error = "Task cancelled by operator."
            _update_job(job, db, 100, "cancelled", target=address, port=port)
            success = False
        except VcfDepotTargetPartialError as exc:
            job.status = "partial-failure"
            job.finished_at = utcnow()
            job.error = str(exc)
            _update_job(job, db, 100, "partial-failure", target=address, port=port, manual_recovery_required=True)
            success = False
        except Exception as exc:  # noqa: BLE001 - persist a sanitized terminal task state.
            job.status = JobStatus.FAILED.value
            job.finished_at = utcnow()
            job.error = str(exc) if isinstance(exc, VcfDepotTargetError) else "VCF Offline Depot target configuration failed unexpectedly."
            _update_job(job, db, 100, "failed", target=address, port=port)
            success = False
        record_audit(
            db,
            actor=job.created_by,
            action="configure_vcf_offline_depot_target",
            resource_type="job",
            resource_id=job.id,
            success=success,
            detail=f"target={address}:{port}; result={job.status}",
        )


def queue_vcf_target_depot_job(job_id: str, **kwargs: Any) -> None:
    """Handle queue vcf target depot job.

    Args:
        job_id: Stable identifier of the associated job resource.
        **kwargs: Additional keyword arguments accepted by the callable.
    """
    threading.Thread(
        target=run_vcf_target_depot_job,
        kwargs={"job_id": job_id, **kwargs},
        name=f"vcf-target-depot-{job_id}",
        daemon=True,
    ).start()


def _add_deployed_vcf_dns(db: Session, fqdn: str, addresses: list[str], *, job_id: str) -> dict[str, Any]:
    """Create deployed vcf dns.

    Args:
        db: Active database session.
        fqdn: Fully qualified domain name to validate or use.
        addresses: Addresses supplied by the caller.
        job_id: Identifier of the job.

    Returns:
        The add deployed vcf dns result.
    """
    settings = get_dns_settings_row(db)
    normalized = fqdn.strip().strip(".").lower()
    domains = [item.lower() for item in dns_domains_for_settings(settings)]
    managed = next((domain for domain in domains if normalized == domain or normalized.endswith(f".{domain}")), "")
    if not settings.enabled or not managed:
        return {"status": "skipped", "reason": "DNS is disabled or the FQDN is outside managed domains."}
    created: list[str] = []
    conflicts: list[str] = []
    for raw_address in addresses:
        try:
            parsed = ip_address(raw_address)
        except ValueError:
            continue
        record_type = "AAAA" if isinstance(parsed, IPv6Address) else "A"
        address = str(parsed)
        exact = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == normalized, DnsRecord.record_type == record_type, DnsRecord.address == address)
        ).scalar_one_or_none()
        if exact:
            continue
        other = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == normalized, DnsRecord.record_type == record_type)
        ).scalars().first()
        if other:
            conflicts.append(f"{record_type} {other.address}")
            continue
        db.add(
            DnsRecord(
                hostname=normalized,
                record_type=record_type,
                address=address,
                record_data_json=dump_dns_record_data(record_type, address),
                description=f"Created by VCF Helper SDDC Manager deployment {job_id}.",
                enabled=True,
            )
        )
        created.append(f"{record_type} {address}")
    db.commit()
    return {"status": "warning" if conflicts else "saved", "created": created, "conflicts": conflicts}


def _wait_for_vcf_api(address: str, username: str, password: str, *, timeout: float = 5400.0, cancelled: Callable[[], bool] | None = None) -> dict[str, str]:
    """Return wait for vcf api.

    Args:
        address: Network address of the target service or interface.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        timeout: Maximum time to wait for completion.
        cancelled: Callback that reports whether cancellation was requested.

    Raises:
        JobCancelled: If the operation encounters an invalid state.
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    started = time.monotonic()
    last_error: Exception | None = None
    while time.monotonic() - started < timeout:
        if cancelled and cancelled():
            raise JobCancelled("Task was cancelled by an operator.")
        try:
            with VcfApiClient(address, username, password, timeout=30.0) as api:
                return api.appliance_info()
        except Exception as exc:  # noqa: BLE001 - startup can surface transport, auth, or SDK readiness failures.
            last_error = exc
            for _ in range(15):
                if cancelled and cancelled():
                    raise JobCancelled("Task was cancelled by an operator.") from exc
                time.sleep(1)
    raise VcfSddcDeploymentError("VCF API did not become ready before the 90-minute timeout.") from last_error


def _configure_deployed_target_depot(
    db: Session,
    job: Job,
    *,
    address: str,
    local_password: str,
    depot_password: str,
) -> dict[str, Any]:
    """Update deployed target depot.

    Args:
        db: Active database session.
        job: Job being processed.
        address: Network address of the target service or interface.
        local_password: Local password supplied by the caller.
        depot_password: Depot password supplied by the caller.

    Returns:
        The configure deployed target depot result.
    """
    local = _local_depot_endpoint(db)

    def update(percent: int, state: str) -> None:
        """Update operation.

        Args:
            percent: Percent consumed by update.
            state: Current lifecycle state consumed by the operation.
        """
        _update_cancelable_job(job, db, min(99, 90 + int(percent / 10)), f"depot-{state}")

    return configure_target_depot(
        address,
        "admin@local",
        local_password,
        local,
        depot_password,
        replace_existing=True,
        progress=update,
    )


def _execute_deployed_target_trust(
    address: str,
    *,
    local_password: str,
    expected_tls_fingerprint: str,
    ca: RootCaInfo,
    progress: Callable[[int, str], None] | None = None,
) -> dict[str, Any]:
    """Run deployed target trust.

    Args:
        address: Network address of the target service or interface.
        local_password: Local password supplied by the caller.
        expected_tls_fingerprint: Expected tls fingerprint supplied by the caller.
        ca: Ca supplied by the caller.
        progress: Progress supplied by the caller.

    Returns:
        The execute deployed target trust result.
    """
    return execute_vcf_trust(
        address=address,
        port=443,
        expected_tls_fingerprint=expected_tls_fingerprint,
        credentials=VcfTrustCredentials(
            api_username="admin@local",
            api_password=local_password,
        ),
        ca=ca,
        progress=progress,
    )


def run_vcf_sddc_deployment_job(
    job_id: str,
    *,
    ova_path: str,
    endpoint: str,
    endpoint_username: str,
    endpoint_password: str,
    endpoint_fingerprint: str,
    destination: dict[str, Any],
    vm_name: str,
    disk_provisioning: str,
    deployment_option: str = "",
    power_on: bool,
    property_values: dict[str, str],
    add_dns: bool,
    apply_trust: bool,
    configure_offline_depot: bool,
    depot_password: str,
) -> None:
    """Run vcf sddc deployment job.

    Args:
        job_id: Identifier of the job.
        ova_path: Filesystem path for the ova.
        endpoint: Endpoint supplied by the caller.
        endpoint_username: Endpoint username supplied by the caller.
        endpoint_password: Endpoint password supplied by the caller.
        endpoint_fingerprint: Endpoint fingerprint supplied by the caller.
        destination: Destination path, address, or resource.
        vm_name: Vm name supplied by the caller.
        disk_provisioning: Disk provisioning supplied by the caller.
        deployment_option: Target-supported OVF deployment option key.
        power_on: Power on supplied by the caller.
        property_values: Property values supplied by the caller.
        add_dns: Add dns supplied by the caller.
        apply_trust: Apply trust supplied by the caller.
        configure_offline_depot: Configure offline depot supplied by the caller.
        depot_password: Depot password supplied by the caller.

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    with SessionLocal() as db:
        configure_operational_logging(db)
        job = db.get(Job, job_id)
        if not job:
            return
        job.status = JobStatus.RUNNING.value
        job.started_at = utcnow()
        db.commit()

        def update(percent: int, state: str) -> None:
            """Update operation.

            Args:
                percent: Percent consumed by update.
                state: Current lifecycle state consumed by the operation.
            """
            _update_cancelable_job(job, db, percent, state)

        def cancelled() -> bool:
            """Return cancelled."""
            db.refresh(job)
            return job.status == JobStatus.CANCELLED.value

        vm_created = False
        target_address = ""
        try:
            descriptor = inspect_ova(ova_path)
            result = deploy_ova(
                descriptor,
                endpoint=endpoint,
                username=endpoint_username,
                password=endpoint_password,
                resource_pool_id=str(destination.get("resource_pool_id") or ""),
                datastore_id=str(destination.get("datastore_id") or ""),
                network_ids={str(key): str(value) for key, value in dict(destination.get("network_ids") or {}).items()},
                vm_name=vm_name,
                property_values=property_values,
                folder_id=str(destination.get("folder_id") or ""),
                host_id=str(destination.get("host_id") or ""),
                port=int(destination.get("port") or 443),
                progress=update,
                expected_fingerprint=endpoint_fingerprint,
                disk_provisioning=disk_provisioning,
                deployment_option=deployment_option,
                power_on=power_on,
                cancelled=cancelled,
            )
            vm_created = True
            fqdn = str(property_values.get("vami.hostname") or "").strip().strip(".")
            if not power_on:
                dns_result = None
                if add_dns:
                    addresses = [property_values.get("ip0", ""), property_values.get("ipv6", "")]
                    dns_result = _add_deployed_vcf_dns(db, fqdn, [item for item in addresses if item], job_id=job.id) if fqdn else {"status": "skipped", "reason": "No FQDN was supplied."}
                job.status = JobStatus.SUCCEEDED.value
                job.finished_at = utcnow()
                job.error = None
                _update_job(job, db, 100, "deployed-powered-off", vm=result, vm_preserved=True, fqdn=fqdn, dns=dns_result)
                success = True
                record_audit(
                    db,
                    actor=job.created_by,
                    action="deploy_vcf_sddc_manager",
                    resource_type="job",
                    resource_id=job.id,
                    success=success,
                    detail=f"vm_name={vm_name}; target=powered-off; snapshot_skipped=true; result={job.status}",
                )
                return
            target_address = str(result.get("guest_ip") or property_values.get("ip0") or property_values.get("ipv6") or fqdn or "")
            if not target_address:
                raise VcfSddcDeploymentError("The VM powered on, but no VCF API address was available.")
            _update_job(job, db, 82, "waiting-for-vcf-api", vm=result, target=target_address, fqdn=fqdn)
            appliance = _wait_for_vcf_api(target_address, "admin@local", property_values.get("LOCAL_USER_PASSWORD", ""), cancelled=cancelled)
            _update_job(job, db, 88, "vcf-api-ready", appliance=appliance)
            if add_dns:
                addresses = [str(result.get("guest_ip") or ""), property_values.get("ip0", ""), property_values.get("ipv6", "")]
                dns_result = _add_deployed_vcf_dns(db, fqdn, [item for item in addresses if item], job_id=job.id) if fqdn else {"status": "skipped", "reason": "No FQDN was supplied."}
                _update_job(job, db, 89, "dns-saved", dns=dns_result)
            if apply_trust:
                ca = root_ca_info(get_ca_settings_row(db))
                tls_fingerprint = tls_sha256_fingerprint(target_address, 443)

                def trust_update(percent: int, state: str) -> None:
                    """Handle trust update.

                    Args:
                        percent: Percent consumed by trust update.
                        state: Current lifecycle state consumed by the operation.
                    """
                    _update_cancelable_job(job, db, 90 + int(percent / 12), f"trust-{state}")

                trust_result = _execute_deployed_target_trust(
                    target_address,
                    local_password=property_values.get("LOCAL_USER_PASSWORD", ""),
                    expected_tls_fingerprint=tls_fingerprint,
                    ca=ca,
                    progress=trust_update,
                )
                _update_job(job, db, 98 if not configure_offline_depot else 94, "trust-succeeded", trust=trust_result, snapshot_skipped="new-deployment")
            if configure_offline_depot:
                depot_result = _configure_deployed_target_depot(
                    db,
                    job,
                    address=target_address,
                    local_password=property_values.get("LOCAL_USER_PASSWORD", ""),
                    depot_password=depot_password,
                )
                _update_job(job, db, 99, "depot-succeeded", target_depot=depot_result)
            job.status = JobStatus.SUCCEEDED.value
            job.finished_at = utcnow()
            job.error = None
            _update_job(job, db, 100, "succeeded")
            success = True
        except VcfDepotTargetPartialError as exc:
            job.status = "partial-failure"
            job.finished_at = utcnow()
            job.error = str(exc)
            _update_job(job, db, 100, "partial-failure", target=target_address, vm_preserved=vm_created, manual_recovery_required=True)
            success = False
        except VcfSddcPostImportError as exc:
            vm_created = True
            imported = dict(exc.vm_result)
            target_address = str(imported.get("guest_ip") or property_values.get("ip0") or property_values.get("ipv6") or property_values.get("vami.hostname") or target_address or "")
            job.status = "partial-failure"
            job.finished_at = utcnow()
            job.error = str(exc)
            _update_job(job, db, 100, "partial-failure", target=target_address, vm=imported, vm_preserved=True, manual_recovery_required=True)
            success = False
        except (JobCancelled, VcfSddcDeploymentCancelled):
            job.status = JobStatus.CANCELLED.value
            job.finished_at = utcnow()
            job.error = "Task cancelled by operator."
            _update_job(job, db, 100, "cancelled", target=target_address, vm_preserved=vm_created)
            success = False
        except Exception as exc:  # noqa: BLE001 - background worker persists a safe terminal state.
            job.status = "partial-failure" if vm_created else JobStatus.FAILED.value
            job.finished_at = utcnow()
            safe_types = (VcfSddcDeploymentError, VcfTrustError, VcfDepotTargetError)
            job.error = str(exc) if isinstance(exc, safe_types) else "SDDC Manager deployment failed unexpectedly."
            _update_job(job, db, 100, job.status, target=target_address, vm_preserved=vm_created)
            success = False
        record_audit(
            db,
            actor=job.created_by,
            action="deploy_vcf_sddc_manager",
            resource_type="job",
            resource_id=job.id,
            success=success,
            detail=f"vm_name={vm_name}; target={target_address or 'not-created'}; snapshot_skipped=true; result={job.status}",
        )


def queue_vcf_sddc_deployment_job(job_id: str, **kwargs: Any) -> None:
    """Handle queue vcf sddc deployment job.

    Args:
        job_id: Stable identifier of the associated job resource.
        **kwargs: Additional keyword arguments accepted by the callable.
    """
    threading.Thread(
        target=run_vcf_sddc_deployment_job,
        kwargs={"job_id": job_id, **kwargs},
        name=f"vcf-sddc-deploy-{job_id}",
        daemon=True,
    ).start()


def vcf_trust_context(db: Session) -> dict[str, Any]:
    """Return vcf trust context.

    Args:
        db: Active database session.
    """
    try:
        trust_ca = root_ca_info(get_ca_settings_row(db))
        trust_ca_error = ""
    except VcfTrustError as exc:
        trust_ca = None
        trust_ca_error = str(exc)
    trust_targets = db.execute(select(VcfTrustTarget).order_by(desc(VcfTrustTarget.updated_at))).scalars().all()
    latest_trust_job = db.execute(
        select(Job)
        .where(Job.type == "vcf-ca-trust")
        .order_by(desc(Job.created_at))
    ).scalars().first()
    return {
        "vcf_trust_ca": trust_ca,
        "vcf_trust_ca_error": trust_ca_error,
        "vcf_trust_targets": trust_targets,
        "vcf_trusted_target_count": sum(target.last_result in {"succeeded", "no-op"} for target in trust_targets),
        "latest_vcf_trust_job": latest_trust_job,
        "latest_vcf_trust_result": json.loads(latest_trust_job.result or "{}") if latest_trust_job else {},
    }


def _vcf_trust_target(db: Session, address: str, port: int) -> VcfTrustTarget:
    """Return vcf trust target.

    Args:
        db: Active database session.
        address: Network address of the target service or interface.
        port: TCP or UDP port of the target service.
    """
    target = db.execute(
        select(VcfTrustTarget).where(VcfTrustTarget.address == address, VcfTrustTarget.api_port == port)
    ).scalar_one_or_none()
    if target is None:
        target = VcfTrustTarget(address=address, api_port=port)
        db.add(target)
        db.flush()
    return target


def run_vcf_trust_job(job_id: str, target_id: int, credentials: VcfTrustCredentials, ca: RootCaInfo) -> None:
    """Run vcf trust job.

    Args:
        job_id: Identifier of the job.
        target_id: Identifier of the target.
        credentials: Credential bundle used for the immediate external request.
        ca: Ca supplied by the caller.
    """
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        target = db.get(VcfTrustTarget, target_id)
        if not job or not target:
            return
        if job.status == JobStatus.CANCELLED.value:
            return
        job.status = JobStatus.RUNNING.value
        job.started_at = utcnow()
        target.last_attempted_at = job.started_at
        target.last_job_id = job.id
        db.commit()

        def update(percent: int, state: str) -> None:
            """Update operation.

            Args:
                percent: Percent consumed by update.
                state: Current lifecycle state consumed by the operation.
            """
            _raise_if_job_cancelled(job, db)
            job.progress_percent = percent
            job.result = sanitized_result(
                address=target.address,
                port=target.api_port,
                ca=ca,
                state=state,
                tls_fingerprint=target.tls_fingerprint,
            )
            db.commit()

        success = False
        try:
            outcome = execute_vcf_trust(
                address=target.address,
                port=target.api_port,
                expected_tls_fingerprint=target.tls_fingerprint,
                credentials=credentials,
                ca=ca,
                progress=update,
            )
            finished = utcnow()
            job.status = "no-op" if outcome["outcome"] == "no-op" else JobStatus.SUCCEEDED.value
            job.progress_percent = 100
            job.finished_at = finished
            job.error = None
            job.result = sanitized_result(
                address=target.address,
                port=target.api_port,
                ca=ca,
                state=job.status,
                tls_fingerprint=target.tls_fingerprint,
                **outcome,
            )
            target.appliance_role = str(outcome.get("role") or "")
            target.appliance_version = str(outcome.get("version") or "")
            target.last_ca_fingerprint = ca.fingerprint
            target.last_result = job.status
            target.last_succeeded_at = finished
            target.updated_at = finished
            success = True
            db.commit()
        except JobCancelled as exc:
            finished = utcnow()
            job.status = JobStatus.CANCELLED.value
            job.progress_percent = 100
            job.finished_at = finished
            job.error = str(exc)
            job.result = sanitized_result(
                address=target.address,
                port=target.api_port,
                ca=ca,
                state="cancelled",
                tls_fingerprint=target.tls_fingerprint,
            )
            target.last_result = "cancelled"
            target.updated_at = finished
            db.commit()
        except Exception as exc:  # noqa: BLE001 - background task must persist a sanitized terminal state.
            finished = utcnow()
            safe_error = str(exc) if isinstance(exc, VcfTrustError) else "VCF trust task failed unexpectedly."
            job.status = JobStatus.FAILED.value
            job.progress_percent = 100
            job.finished_at = finished
            job.error = safe_error
            job.result = sanitized_result(
                address=target.address,
                port=target.api_port,
                ca=ca,
                state="failed",
                tls_fingerprint=target.tls_fingerprint,
            )
            target.last_result = "failed"
            target.updated_at = finished
            db.commit()
        record_audit(
            db,
            actor=job.created_by,
            action="import_vcf_root_ca",
            resource_type="job",
            resource_id=job.id,
            success=success,
            detail=(
                f"target={target.address}:{target.api_port}; role={target.appliance_role or 'unknown'}; "
                f"version={target.appliance_version or 'unknown'}; ca_fingerprint={ca.fingerprint}; "
                f"result={target.last_result}"
            ),
        )


def queue_vcf_trust_job(job_id: str, target_id: int, credentials: VcfTrustCredentials, ca: RootCaInfo) -> None:
    """Handle queue vcf trust job.

    Args:
        job_id: Identifier of the job.
        target_id: Identifier of the target.
        credentials: Credential bundle used for the immediate external request.
        ca: Ca supplied by the caller.
    """
    threading.Thread(
        target=run_vcf_trust_job,
        args=(job_id, target_id, credentials, ca),
        name=f"vcf-ca-trust-{job_id}",
        daemon=True,
    ).start()


def _normalize_vcf_trust_address(address: str) -> tuple[str, list[str]]:
    """Normalize vcf trust address.

    Args:
        address: Network address contacted or validated by the operation.


    Returns:
        The normalize vcf trust address result.
    """
    normalized_address = address.strip()
    errors: list[str] = []
    if not normalized_address or any(character.isspace() for character in normalized_address):
        errors.append("Enter one VCF appliance IP address or hostname.")
    return normalized_address, errors


APPLIANCE_APPLY_BASELINES_KEY = "appliance_apply.baselines.v1"
APPLIANCE_APPLY_MANAGEMENT_RESTART_DELAY_SECONDS = 3
APPLIANCE_APPLY_MANAGEMENT_RECONNECT_GRACE_SECONDS = 15
MANAGEMENT_CERTIFICATE_CONNECTION_WARNING = (
    "Applying the selected management HTTPS change will replace or rebind the management certificate. "
    "This browser connection will be interrupted; reconnect and verify or trust the certificate presented by the appliance."
)
APPLIANCE_APPLY_UNIT_IDS = {
    "local_users",
    "appliance_settings",
    "network",
    "wan",
    "firewall",
    "dnsmasq",
    "esxi_pxe",
    "esx_storage",
    "ca",
    "kms",
    "ldap",
    "ntpd",
    "vcf_backups",
    "vcf_offline_depot",
    "vcf_private_registry",
    "public_services",
}


def appliance_settings_management_status_transition(results: list[Any]) -> dict[str, Any] | None:
    """Return the bounded status transition confirmed by the Appliance Settings helper.

    Args:
        results: Adapter results returned by Appliance Settings validation and apply.

    Returns:
        Durable reconnect metadata only when the real helper scheduled the restart.
    """
    for result in reversed(results):
        if result.dry_run or result.returncode != 0:
            continue
        for line in reversed(str(result.stdout or "").splitlines()):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            transition = payload.get("management_status_transition") if isinstance(payload, dict) else None
            if not isinstance(transition, dict) or transition.get("kind") != "planned_service_restart":
                continue
            restart_delay_seconds = transition.get("restart_delay_seconds")
            if (
                not isinstance(restart_delay_seconds, int)
                or isinstance(restart_delay_seconds, bool)
                or restart_delay_seconds != APPLIANCE_APPLY_MANAGEMENT_RESTART_DELAY_SECONDS
            ):
                continue
            return {
                "kind": "planned_service_restart",
                "restart_delay_seconds": restart_delay_seconds,
                "grace_seconds": APPLIANCE_APPLY_MANAGEMENT_RECONNECT_GRACE_SECONDS,
            }
    return None


SECRET_LINE_PATTERN = re.compile(
    r"(rootpw|password|passwd|token|secret|credential|private[_.-]?key|robot[_.-]?account|ca[_.-]?bundle[_.-]?pem|activation[_.-]?code|license|ipxe[_.-]?script|payload[_.-]?b64)",
    re.IGNORECASE,
)
PRIVATE_KEY_BEGIN_PATTERN = re.compile(r"-----BEGIN .*PRIVATE KEY-----")
PRIVATE_KEY_END_PATTERN = re.compile(r"-----END .*PRIVATE KEY-----")
JWT_PATH_SEGMENT_PATTERN = re.compile(r"(?<=/)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?=/|$)")
JSON_SECRET_FIELD_PATTERN = re.compile(r'^(\s*"[^"]+"\s*:\s*)(.*?)(,?)\s*$')


def redact_config_preview(config_preview: str) -> str:
    """Return redact config preview.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    lines: list[str] = []
    in_private_key = False
    for line in (config_preview or "").splitlines():
        if PRIVATE_KEY_BEGIN_PATTERN.search(line):
            lines.append("[redacted private key]")
            in_private_key = True
            continue
        if in_private_key:
            if PRIVATE_KEY_END_PATTERN.search(line):
                in_private_key = False
            continue
        if SECRET_LINE_PATTERN.search(line):
            json_match = JSON_SECRET_FIELD_PATTERN.match(line)
            if json_match:
                lines.append(f'{json_match.group(1)}"[redacted]"{json_match.group(3)}')
                continue
            separator = "=" if "=" in line else ":" if ":" in line else None
            if separator:
                prefix = line.split(separator, 1)[0].rstrip()
                lines.append(f"{prefix}{separator} [redacted]")
            else:
                lines.append("[redacted sensitive line]")
            continue
        lines.append(JWT_PATH_SEGMENT_PATTERN.sub("[redacted-token]", line))
    return "\n".join(lines)


def load_appliance_apply_baselines(db: Session) -> dict[str, dict[str, Any]]:
    """Return appliance apply baselines.

    Args:
        db: Active database session.
    """
    raw_value = setting_value(db, APPLIANCE_APPLY_BASELINES_KEY)
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


def applied_local_dns_enabled(baseline: dict[str, Any] | None) -> bool:
    """Return whether the last-applied DNS unit enabled local DNS.

    Args:
        baseline: Last-applied DNS/DHCP unit baseline.

    Returns:
        Whether local DNS is proven active by the baseline.
    """
    if not baseline:
        return False
    enabled = baseline.get("dns_enabled")
    if isinstance(enabled, bool):
        return enabled
    summary = baseline.get("summary")
    return bool(isinstance(summary, list) and summary and summary[0] == "DNS enabled")


def save_appliance_apply_baselines(db: Session, baselines: dict[str, dict[str, Any]]) -> None:
    """Persist appliance apply baselines.

    Args:
        db: Active database session.
        baselines: Baselines supplied by the caller.
    """
    set_setting_value(db, APPLIANCE_APPLY_BASELINES_KEY, json.dumps(baselines, indent=2, sort_keys=True))


def appliance_snapshot_hash(payload: dict[str, Any]) -> str:
    """Return appliance snapshot hash.

    Args:
        payload: Validated request or task payload consumed by the operation.
    """
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def config_diff_for_unit(unit_id: str, current_preview: str, baseline: dict[str, Any] | None) -> str:
    """Return config diff for unit.

    Args:
        unit_id: Stable identifier of the associated unit resource.
        current_preview: Current preview inspected by the operation.
        baseline: Baseline consumed by config diff for unit.
    """
    if not baseline or not baseline.get("config_preview"):
        return ""
    previous_preview = str(baseline.get("config_preview") or "")
    if previous_preview == current_preview:
        return ""
    return "\n".join(
        difflib.unified_diff(
            previous_preview.splitlines(),
            current_preview.splitlines(),
            fromfile=f"last-applied/{unit_id}",
            tofile=f"current/{unit_id}",
            lineterm="",
        )
    )


def network_management_signature(config_preview: str) -> dict[str, str]:
    """Return network management signature.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    interfaces: list[dict[str, str]] = []
    current_section = ""
    current: dict[str, str] | None = None
    for raw_line in (config_preview or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")
            current = None
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if current_section == "physical_interfaces" and key == "interface":
            current = {"name": value}
            interfaces.append(current)
            continue
        if current_section == "physical_interfaces" and current is not None:
            current[key] = value
    management = next((interface for interface in interfaces if interface.get("role") == "management"), None)
    if management is None:
        return {}
    return {
        "name": management.get("name", ""),
        "ipv4_method": management.get("ipv4_method", ""),
        "ip_cidr": management.get("ip_cidr", ""),
        "gateway": management.get("gateway", ""),
        "ipv6_enabled": management.get("ipv6_enabled", ""),
        "ipv6_cidr": management.get("ipv6_cidr", ""),
        "ipv6_gateway": management.get("ipv6_gateway", ""),
    }


def network_interface_entries(config_preview: str) -> list[dict[str, str]]:
    """Return normalized physical and VLAN rows from a network preview.

    Args:
        config_preview: Rendered network configuration approved for staging.

    Returns:
        Parsed physical and VLAN interface rows.
    """
    rows: list[dict[str, str]] = []
    section = ""
    current: dict[str, str] | None = None
    for raw_line in (config_preview or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]")
            current = None
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if section == "physical_interfaces" and key == "interface":
            current = {"kind": "physical", "name": value}
            rows.append(current)
        elif section == "vlan_interfaces" and key == "vlan":
            current = {"kind": "vlan", "name": value}
            rows.append(current)
        elif current is not None and section in {"physical_interfaces", "vlan_interfaces"}:
            current[key] = value
    return rows


def network_management_paths(config_preview: str) -> list[dict[str, str]]:
    """Return every effective management browser path in a network preview.

    Args:
        config_preview: Rendered network configuration approved for staging.

    Returns:
        Normalized dedicated and flagged-access management paths.
    """
    rows = network_interface_entries(config_preview)
    paths: list[dict[str, str]] = []
    physical_admin_states = {
        row.get("name", ""): row.get("admin_state", "")
        for row in rows
        if row.get("kind") == "physical"
    }
    for row in rows:
        dedicated = row.get("kind") == "physical" and row.get("role") == "management"
        flagged_physical = (
            row.get("kind") == "physical"
            and row.get("role") == "access"
            and row.get("mode") == "access"
            and row.get("admin_state") == "up"
            and row.get("access_management_ui_enabled", "false").lower() == "true"
        )
        flagged_vlan = (
            row.get("kind") == "vlan"
            and row.get("role") == "access"
            and row.get("enabled", "true").lower() == "true"
            and row.get("access_management_ui_enabled", "false").lower() == "true"
        )
        if not (dedicated or flagged_physical or flagged_vlan):
            continue
        paths.append(
            {
                "kind": row.get("kind", ""),
                "name": row.get("name", ""),
                "parent": row.get("parent", ""),
                "parent_admin_state": physical_admin_states.get(row.get("parent", ""), ""),
                "role": row.get("role", ""),
                "mtu": row.get("mtu", ""),
                "ipv4_method": row.get("ipv4_method", ""),
                "ip_cidr": row.get("ip_cidr", ""),
                "gateway": row.get("gateway", ""),
                "ipv6_enabled": row.get("ipv6_enabled", ""),
                "ipv6_cidr": row.get("ipv6_cidr", ""),
                "ipv6_gateway": row.get("ipv6_gateway", ""),
            }
        )
    return sorted(
        paths,
        key=lambda item: (
            item["name"],
            item["kind"],
            item["parent"],
            item["parent_admin_state"],
            item["mtu"],
            item["ip_cidr"],
            item["gateway"],
            item["ipv6_enabled"],
            item["ipv6_cidr"],
            item["ipv6_gateway"],
        ),
    )


def refresh_management_handoff_dynamic_observations(
    db: Session,
    config_preview: str,
    handoff_evidence: dict[str, Any],
) -> None:
    """Persist helper-confirmed dynamic addresses before publishing the Network baseline.

    Args:
        db: Active Appliance Apply transaction.
        config_preview: Exact Network configuration staged for the successful handoff.
        handoff_evidence: Bounded helper result containing every probed candidate address.
    """
    dynamic_paths = [
        path
        for path in network_management_paths(config_preview)
        if path.get("kind") == "physical"
        and (
            path.get("ipv4_method") == "dhcp"
            or (
                path.get("ipv6_enabled", "").lower() == "true"
                and not path.get("ipv6_cidr")
            )
        )
    ]
    if not dynamic_paths:
        return
    try:
        confirmed_addresses = {
            str(ip_address(str(value)))
            for value in handoff_evidence.get("candidate_addresses", [])
        }
    except ValueError as exc:
        raise RuntimeError("Management handoff returned an invalid candidate address.") from exc
    discovered = {row.name: row for row in discover_host_physical_interfaces()}
    for path in dynamic_paths:
        name = str(path.get("name") or "")
        observed = discovered.get(name)
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == name))
        if observed is None or interface is None:
            raise RuntimeError(
                f"Management handoff could not refresh observed addresses for {name}."
            )
        required = []
        if path.get("ipv4_method") == "dhcp":
            required.append(("IPv4", observed.host_ip_cidr, "host_ip_cidr"))
        if path.get("ipv6_enabled", "").lower() == "true" and not path.get("ipv6_cidr"):
            required.append(("IPv6", observed.host_ipv6_cidr, "host_ipv6_cidr"))
        for family, cidr, attribute in required:
            address = address_from_cidr(cidr)
            if not address or address not in confirmed_addresses:
                raise RuntimeError(
                    f"Management handoff could not confirm the observed dynamic {family} address for {name}."
                )
            setattr(interface, attribute, cidr)
    db.flush()


def management_handoff_required(network_unit: dict[str, Any], baseline: dict[str, Any] | None) -> bool:
    """Return whether Network changes require a two-phase handoff.

    Args:
        network_unit: Current Network apply unit.
        baseline: Last successful Network baseline.

    Returns:
        Whether a previous known-good management path changes.
    """
    previous_preview = str((baseline or {}).get("config_preview") or "")
    current_paths = network_management_paths(
        str(network_unit.get("raw_config_preview") or network_unit.get("config_preview") or "")
    )
    if not previous_preview:
        return bool(current_paths)
    return network_management_paths(previous_preview) != current_paths


def management_handoff_completes_appliance_settings(
    current_preview: str,
    baseline: dict[str, Any] | None,
) -> bool:
    """Return whether the handoff covers every Appliance Settings difference.

    Args:
        current_preview: Current redacted Appliance Settings preview.
        baseline: Last successful Appliance Settings baseline.

    Returns:
        Whether non-handoff settings already match the applied baseline.
    """
    previous = json_config_object(str((baseline or {}).get("config_preview") or ""))
    current = json_config_object(current_preview)
    if not previous or not current:
        return False
    for key in MANAGEMENT_HANDOFF_APPLIANCE_SETTINGS_KEYS:
        if key in previous or key in current:
            previous[key] = current.get(key)
    return previous == current


def management_address_label(signature: dict[str, str]) -> str:
    """Return management address label.

    Args:
        signature: Signature consumed by management address label.
    """
    if signature.get("ip_cidr"):
        return signature["ip_cidr"]
    if signature.get("ipv4_method") == "dhcp":
        return "a DHCP-assigned address"
    if signature.get("ipv6_cidr"):
        return signature["ipv6_cidr"]
    return "no configured management address"


def json_config_object(config_preview: str) -> dict[str, Any]:
    """Return json config object.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    try:
        payload = json.loads(config_preview or "")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def management_tls_binding_signature(config_preview: str) -> dict[str, Any]:
    """Return management tls binding signature.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    payload = json_config_object(config_preview)
    if not payload:
        return {}
    return {
        "management_https_enabled": bool(payload.get("management_https_enabled")),
        "management_https_cert_path": str(payload.get("management_https_cert_path") or ""),
        "management_https_key_path": str(payload.get("management_https_key_path") or ""),
    }


def management_certificate_signature(config_preview: str) -> dict[str, str]:
    """Return management certificate signature.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    payload = json_config_object(config_preview)
    for certificate in payload.get("certificates", []):
        if not isinstance(certificate, dict) or certificate.get("managed_owner") != "appliance:https":
            continue
        return {
            "common_name": str(certificate.get("common_name") or ""),
            "fingerprint": str(certificate.get("fingerprint") or ""),
            "certificate_pem": str(certificate.get("certificate_pem") or ""),
            "cert_path": str(certificate.get("cert_path") or ""),
            "key_path": str(certificate.get("key_path") or ""),
            "chain_path": str(certificate.get("chain_path") or ""),
        }
    return {}


def appliance_apply_connection_warnings(
    unit_id: str,
    current_preview: str,
    baseline: dict[str, Any] | None,
) -> list[str]:
    """Return appliance apply connection warnings.

    Args:
        unit_id: Stable identifier of the associated unit resource.
        current_preview: Current preview inspected by the operation.
        baseline: Baseline consumed by appliance apply connection warnings.
    """
    previous_preview = str((baseline or {}).get("config_preview") or "")
    if not previous_preview:
        return []
    if unit_id == "network":
        previous = network_management_signature(previous_preview)
        current = network_management_signature(current_preview)
        if previous and current:
            warnings: list[str] = []
            address_keys = ("name", "ipv4_method", "ip_cidr", "ipv6_cidr")
            if any(previous.get(key) != current.get(key) for key in address_keys):
                warnings.append(
                    "Applying Network will change the management address "
                    f"from {management_address_label(previous)} to {management_address_label(current)}. "
                    "This browser connection will be lost; reconnect to the new management address after the task completes."
                )
            if previous.get("gateway", "") != current.get("gateway", ""):
                warnings.append(
                    "Applying Network will change the management IPv4 gateway "
                    f"from {previous.get('gateway') or 'none'} to {current.get('gateway') or 'none'}. "
                    "Existing management connections may be interrupted while policy routing is updated."
                )
            return warnings
    if unit_id == "appliance_settings":
        previous = management_tls_binding_signature(previous_preview)
        current = management_tls_binding_signature(current_preview)
        if previous and current and previous != current:
            return [MANAGEMENT_CERTIFICATE_CONNECTION_WARNING]
    if unit_id == "ca":
        previous = management_certificate_signature(previous_preview)
        current = management_certificate_signature(current_preview)
        if previous != current and (previous or current):
            return [MANAGEMENT_CERTIFICATE_CONNECTION_WARNING]
    return []


def network_vlan_entries_from_config(config_preview: str) -> list[dict[str, str]]:
    """Return network vlan entries from config.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    vlan_entries: list[dict[str, str]] = []
    current_section = ""
    current: dict[str, str] | None = None
    for raw_line in (config_preview or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")
            current = None
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if current_section == "vlan_interfaces" and key == "vlan":
            current = {"name": value}
            vlan_entries.append(current)
            continue
        if current_section == "vlan_interfaces" and current is not None:
            current[key] = value
    return vlan_entries


def successful_network_apply_vlan_entries(db: Session, baseline: dict[str, Any] | None) -> list[dict[str, str]]:
    """Return successful network apply vlan entries.

    Args:
        db: Active database session.
        baseline: Baseline supplied by the caller.
    """
    applied_by_name: dict[str, dict[str, str]] = {}
    baseline_preview = str((baseline or {}).get("config_preview") or "")
    for entry in network_vlan_entries_from_config(baseline_preview):
        if entry.get("name"):
            applied_by_name[entry["name"]] = entry

    jobs = (
        db.execute(
            select(Job)
            .where(Job.type == "appliance-apply", Job.status == JobStatus.SUCCEEDED.value)
            .order_by(Job.created_at)
        )
        .scalars()
        .all()
    )
    for job in jobs:
        try:
            result = json.loads(job.result or "")
        except json.JSONDecodeError:
            continue
        for unit in result.get("units", []):
            if unit.get("unit_id") != "network" or not unit.get("success") or unit.get("dry_run"):
                continue
            for entry in network_vlan_entries_from_config(str(unit.get("config_preview") or "")):
                if entry.get("name"):
                    applied_by_name[entry["name"]] = entry
            for entry in unit.get("removed_vlan_interfaces", []):
                name = entry.get("name") if isinstance(entry, dict) else ""
                if name:
                    applied_by_name.pop(str(name), None)
    return list(applied_by_name.values())


def removed_network_vlan_entries(current_preview: str, applied_entries: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return removed network vlan entries.

    Args:
        current_preview: Current preview inspected by the operation.
        applied_entries: Applied entries consumed by removed network VLAN entries.
    """
    current_names = {entry.get("name", "") for entry in network_vlan_entries_from_config(current_preview)}
    removed: list[dict[str, str]] = []
    for entry in applied_entries:
        name = entry.get("name", "")
        if name and name not in current_names:
            removed.append(
                {
                    "name": name,
                    "parent": entry.get("parent", ""),
                    "vlan_id": entry.get("vlan_id", ""),
                }
            )
    return removed


def local_usernames_from_config(config_preview: str) -> list[str]:
    """Return local usernames from config.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    try:
        payload = json.loads(config_preview or "")
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    usernames: list[str] = []
    for row in payload.get("users", []):
        if not isinstance(row, dict):
            continue
        username = str(row.get("username") or "").strip().lower()
        if username and username not in usernames:
            usernames.append(username)
    return usernames


def removed_local_usernames(users: list[User], baseline: dict[str, Any] | None) -> list[str]:
    """Return removed local usernames.

    Args:
        users: Users consumed by removed local usernames.
        baseline: Baseline consumed by removed local usernames.
    """
    current = {user.username.strip().lower() for user in users}
    previous = local_usernames_from_config(str((baseline or {}).get("config_preview") or ""))
    return [username for username in previous if username not in current]


def network_config_with_removed_vlans(config_preview: str, removed_vlans: list[dict[str, str]]) -> str:
    """Return network config with removed vlans.

    Args:
        config_preview: Rendered configuration text approved for staging.
        removed_vlans: Removed vlans supplied by the caller.
    """
    if not removed_vlans:
        return config_preview
    lines = [config_preview.rstrip(), "", "[removed_vlan_interfaces]"]
    for vlan in removed_vlans:
        lines.extend(
            [
                f"vlan={vlan['name']}",
                f"  parent={vlan.get('parent', '')}",
                f"  vlan_id={vlan.get('vlan_id', '')}",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def wan_route_entries_from_config(config_preview: str) -> list[dict[str, str]]:
    """Return wan route entries from config.

    Args:
        config_preview: Rendered configuration text approved for staging.
    """
    entries: list[dict[str, str]] = []
    current_section = ""
    current: dict[str, str] | None = None
    for raw_line in (config_preview or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")
            current = None
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if current_section == "routes" and key == "route":
            current = {"destination_cidr": value}
            entries.append(current)
            continue
        if current_section == "routes" and current is not None:
            current[key] = value
    return entries


def removed_wan_route_entries(current_preview: str, baseline: dict[str, Any] | None) -> list[dict[str, str]]:
    """Return removed wan route entries.

    Args:
        current_preview: Current preview inspected by the operation.
        baseline: Baseline consumed by removed WAN route entries.
    """
    baseline_preview = str((baseline or {}).get("config_preview") or "")

    def route_key(entry: dict[str, str]) -> tuple[str, str]:
        """Return a canonical destination and interface identity for a route entry.

        Args:
            entry: Parsed route entry whose identity is required.
        """
        destination = entry.get("destination_cidr", "")
        if destination:
            try:
                destination = canonical_route_destination(destination)
            except ValueError:
                pass
        return destination, entry.get("interface", "")

    current_keys = {
        route_key(entry)
        for entry in wan_route_entries_from_config(current_preview)
    }
    removed: list[dict[str, str]] = []
    for entry in wan_route_entries_from_config(baseline_preview):
        key = route_key(entry)
        if key[0] and key[1] and key not in current_keys:
            removed.append(
                {
                    "destination_cidr": key[0],
                    "gateway": entry.get("gateway", ""),
                    "interface_name": key[1],
                    "metric": entry.get("metric", "100"),
                }
            )
    return removed


def management_gateway_route_migrations(
    network_unit: dict[str, Any],
    network_baseline: dict[str, Any] | None,
    wan_unit: dict[str, Any],
    wan_baseline: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Return default routes coupled to a management-to-access handoff.

    Args:
        network_unit: Current Network apply unit.
        network_baseline: Last successfully applied Network unit.
        wan_unit: Current Routes & WAN Simulation apply unit.
        wan_baseline: Last successfully applied Routes & WAN Simulation unit.

    Returns:
        Current enabled default routes that preserve gateways removed from management-only fields.
    """
    previous_paths = network_management_paths(
        str((network_baseline or {}).get("config_preview") or "")
    )
    current_paths = {
        path.get("name", ""): path
        for path in network_interface_entries(
            str(
                network_unit.get("raw_config_preview")
                or network_unit.get("config_preview")
                or ""
            )
        )
        if path.get("kind") == "physical"
    }
    current_routes = wan_route_entries_from_config(
        str(wan_unit.get("raw_config_preview") or wan_unit.get("config_preview") or "")
    )
    applied_routes = wan_route_entries_from_config(
        str((wan_baseline or {}).get("config_preview") or "")
    )
    migrations: list[dict[str, str]] = []
    for previous in previous_paths:
        current = current_paths.get(str(previous.get("name") or ""))
        if (
            previous.get("role") != "management"
            or not current
            or current.get("role") != "access"
        ):
            continue
        for family, destination, gateway_field in (
            (4, "0.0.0.0/0", "gateway"),
            (6, "::/0", "ipv6_gateway"),
        ):
            gateway = str(previous.get(gateway_field) or "")
            if not gateway:
                continue
            expected = next(
                (
                    route
                    for route in current_routes
                    if default_route_family(route.get("destination_cidr", "")) == family
                    and route.get("interface", "") == current.get("name", "")
                    and route.get("gateway", "") == gateway
                    and route.get("enabled", "true").lower() == "true"
                ),
                None,
            )
            if expected is None:
                continue
            already_applied = any(
                default_route_family(route.get("destination_cidr", "")) == family
                and route.get("interface", "") == current.get("name", "")
                and route.get("gateway", "") == gateway
                and route.get("enabled", "true").lower() == "true"
                for route in applied_routes
            )
            if not already_applied:
                migrations.append(
                    {
                        "family": str(family),
                        "destination_cidr": destination,
                        "gateway": gateway,
                        "interface": str(current.get("name") or ""),
                    }
                )
    return migrations


def wan_rollback_config_preview(
    candidate_preview: str, baseline: dict[str, Any] | None
) -> str:
    """Return the last-applied WAN config plus removals for candidate-only routes.

    Args:
        candidate_preview: Exact candidate WAN configuration.
        baseline: Last successfully applied WAN unit.

    Returns:
        A helper-valid WAN configuration that restores the prior runtime intent.
    """
    baseline_preview = str((baseline or {}).get("config_preview") or "").rstrip()
    removed = removed_wan_route_entries(
        baseline_preview,
        {"config_preview": candidate_preview},
    )
    candidate_mirrors = mirrored_management_default_routes(candidate_preview)
    baseline_mirrors = mirrored_management_default_routes(baseline_preview)
    removed_main_defaults = sorted(candidate_mirrors - baseline_mirrors)
    if not removed and not removed_main_defaults:
        return baseline_preview + "\n"
    lines = [baseline_preview]
    if removed:
        lines.extend(["", "[removed_routes]"])
        for route in removed:
            lines.extend(
                [
                    f"route={route['destination_cidr']}",
                    f"gateway={route.get('gateway', '')}",
                    f"interface={route['interface_name']}",
                    f"metric={route.get('metric', '100')}",
                ]
            )
    if removed_main_defaults:
        lines.extend(["", "[removed_main_defaults]"])
        for destination, interface_name, gateway, metric in removed_main_defaults:
            lines.extend(
                [
                    f"route={destination}",
                    f"gateway={gateway}",
                    f"interface={interface_name}",
                    f"metric={metric}",
                ]
            )
    return "\n".join(lines).lstrip("\n") + "\n"


def make_appliance_apply_unit(
    *,
    unit_id: str,
    label: str,
    page_url: str,
    context: dict[str, Any],
    summary: list[str],
    validation_errors: list[str],
    validation_warnings: list[str] | None = None,
    config_path: str,
    config_preview: str,
    baseline: dict[str, Any] | None,
    raw_config_preview: str | None = None,
    snapshot_marker: Any = None,
) -> dict[str, Any]:
    """Build appliance apply unit.

    Args:
        unit_id: Identifier of the unit.
        label: Human-readable label used in validation output.
        page_url: URL for the page.
        context: Runtime or protocol context for the operation.
        summary: Summary supplied by the caller.
        validation_errors: Validation errors supplied by the caller.
        validation_warnings: Validation warnings supplied by the caller.
        config_path: Filesystem path for the config.
        config_preview: Rendered configuration text approved for staging.
        baseline: Baseline supplied by the caller.
        raw_config_preview: Raw config preview supplied by the caller.
        snapshot_marker: Snapshot marker supplied by the caller.

    Returns:
        The make appliance apply unit result.
    """
    redacted_preview = redact_config_preview(config_preview)
    snapshot_payload = {
        "unit_id": unit_id,
        "summary": summary,
        "config_path": config_path,
        "config_preview": redacted_preview,
        "snapshot_marker": snapshot_marker,
    }
    current_hash = appliance_snapshot_hash(snapshot_payload)
    baseline_hash = str((baseline or {}).get("snapshot_hash") or "")
    return {
        "id": unit_id,
        "label": label,
        "page_url": page_url,
        "context": context,
        "summary": summary,
        "validation_errors": validation_errors,
        "validation_warnings": validation_warnings or [],
        "valid": not validation_errors,
        "config_path": config_path,
        "raw_config_preview": raw_config_preview if raw_config_preview is not None else config_preview,
        "config_preview": redacted_preview,
        "snapshot_hash": current_hash,
        "changed": current_hash != baseline_hash,
        "has_baseline": bool(baseline_hash),
        "last_applied_at": (baseline or {}).get("applied_at"),
        "config_diff": config_diff_for_unit(unit_id, redacted_preview, baseline),
    }


def local_users_apply_context(db: Session, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return local users apply context.

    Args:
        db: Active database session.
        baseline: Baseline supplied by the caller.
    """
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    validation_errors = validate_local_usernames(users)
    policy = local_users_password_policy(db)
    removed_users = removed_local_usernames(users, baseline)
    config_preview = render_local_users_preview(users, password_policy=policy, removed_users=removed_users)
    try:
        config_preview = render_local_users_apply_config(users, password_policy=policy, removed_users=removed_users)
    except ValueError as exc:
        validation_errors.append(str(exc))
    return {
        "local_users": users,
        "local_user_sync_rows": local_user_sync_rows(users),
        "local_user_validation_errors": validation_errors,
        "local_user_config_preview": config_preview,
        "local_user_display_preview": render_local_users_preview(users, password_policy=policy, removed_users=removed_users),
        "local_user_pending_password_count": pending_os_password_count(users),
        "local_user_unlock_request_count": sum(1 for user in users if user.os_unlock_requested_at),
        "local_user_removed_users": removed_users,
    }


def esxi_pxe_context(db: Session) -> dict[str, Any]:
    """Return esxi pxe context.

    Args:
        db: Active database session.
    """
    from atlaso.app.services.network_boot import desired_environment_manifest_rows

    kickstarts = db.execute(select(EsxiKickstart).order_by(EsxiKickstart.name)).scalars().all()
    hosts = db.execute(select(EsxiPxeHost).options(selectinload(EsxiPxeHost.kickstart)).order_by(EsxiPxeHost.hostname)).scalars().all()
    dhcp_scopes = db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().all()
    default_host = esxi_pxe_default_host_settings(db)
    available_interfaces = service_bind_options(db)
    iso_error = ""
    try:
        installer_isos = installer_iso_inventory()
    except OSError as exc:
        installer_isos = []
        iso_error = f"Installer ISO folder could not be prepared: {exc}"
    installer_isos = annotate_esxi_installer_iso_sources(db, installer_isos)
    strict = strict_validation_enabled(db)
    max_bytes = get_settings().esxi_kickstart_max_bytes
    validation_errors: list[str] = []
    validation_warnings: list[str] = []
    validation_by_id: dict[int, dict[str, list[str] | bool]] = {}
    for row in kickstarts:
        errors, warnings = kickstart_validation(row.content, strict=strict, max_bytes=max_bytes)
        validation_by_id[row.id] = {"valid": not errors, "errors": errors, "warnings": warnings}
        validation_errors.extend(f"{row.name}: {error}" for error in errors)
        validation_warnings.extend(f"{row.name}: {warning}" for warning in warnings)
        if kickstart_drift_state(row) == "filesystem_modified":
            validation_warnings.append(
                f"{row.name}: Filesystem copy differs from database source. The next ESXi PXE apply will overwrite the filesystem copy from the database."
            )
    known_iso_paths = {row["path"] for row in installer_isos}
    if default_host.get("enabled") and not (default_host.get("installer_iso_path") or "").strip():
        validation_warnings.append("Default / undefined MACs: no installer ISO selected.")
    if default_host.get("installer_iso_path") and default_host.get("installer_iso_path") not in known_iso_paths:
        validation_warnings.append("Default / undefined MACs: selected installer ISO is missing from the ESX_HOST depot folder.")
    for host in hosts:
        if host.enabled and not (host.installer_iso_path or "").strip():
            validation_warnings.append(f"{host.hostname}: no installer ISO selected.")
        if host.installer_iso_path and host.installer_iso_path not in known_iso_paths:
            validation_warnings.append(f"{host.hostname}: selected installer ISO is missing from the ESX_HOST depot folder.")
    if iso_error:
        validation_warnings.append(iso_error)
    boot_settings = esxi_pxe_boot_settings(db)
    selected_boot_interfaces = split_interfaces(boot_settings.get("listen_interface"))
    selected_boot_addresses = split_addresses(boot_settings.get("listen_address"))
    available_boot_addresses = available_service_listen_addresses(boot_settings.get("listen_address"), available_interfaces)
    if boot_settings["enabled"]:
        if not boot_settings["hostname"]:
            validation_errors.append("ESXi PXE hostname is required when PXE/TFTP bootstrap is enabled.")
        if not boot_settings.get("dhcp_scope_ids"):
            validation_errors.append("ESXi PXE boot service requires at least one DHCP IP zone.")
        if not selected_boot_addresses:
            validation_errors.append("ESXi PXE boot service requires at least one listen address.")
        if esxi_pxe_dns_record_conflict(db, boot_settings["hostname"]):
            validation_errors.append("ESXi PXE hostname conflicts with an existing non-ESXi PXE DNS record.")
        elif boot_settings["hostname"].lower() not in managed_dns_fqdns(db):
            validation_warnings.append(f"ESXi PXE hostname {boot_settings['hostname']} is not present in managed DNS records.")
        if not esxi_pxe_host_artifacts(hosts, boot_settings, default_host):
            validation_warnings.append("ESXi PXE bootstrap is enabled, but no enabled host reference or default profile has an installer ISO selected.")
        if boot_settings["native_uefi_http_enabled"]:
            native_http_url = str(
                boot_settings["native_uefi_http_url"]
                or boot_settings.get("effective_native_uefi_http_url")
                or ""
            ).strip()
            if not native_uefi_http_url_is_absolute(native_http_url):
                validation_errors.append(
                    "Native UEFI HTTP requires an absolute HTTP or HTTPS URL. "
                    "Select an IPv4 DHCP zone with a listen address or turn off Native UEFI HTTP."
                )
            elif not boot_settings["native_uefi_http_url"]:
                validation_warnings.append(
                    "Native UEFI HTTP boot URL will be generated from the ESXi PXE HTTP endpoint."
                )
            elif len(boot_settings.get("dhcp_scope_ids") or []) > 1:
                validation_warnings.append(
                    "Native UEFI HTTP boot uses the manual URL for every selected DHCP zone."
                )
    custom_variables = custom_variable_definitions(db)
    custom_defaults = {item["name"]: item["default_value"] for item in custom_variables}
    validation_errors.extend(kickstart_template_validation_errors(kickstarts, hosts, boot_settings, default_host, custom_defaults))
    for kickstart in kickstarts:
        try:
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
        except ValueError:
            validation_errors.append(f"{kickstart.name}: {KICKSTART_REFERENCE_VALIDATION_ERROR}")
    esxi_service_state = esxi_pxe_service_state_from_boot(boot_settings)
    network_boot_environments = desired_environment_manifest_rows(db)
    return {
        "esxi_kickstarts": kickstarts,
        "esxi_kickstart_completions": [
            *[
                [f"custom.{item['name']}", item["description"] or "Custom ESXi Kickstart variable"]
                for item in custom_variables
            ],
            *kickstart_vault_marker_catalog(db),
        ],
        "esxi_custom_variables": custom_variables,
        "esxi_kickstart_rows": [kickstart_to_dict(row) for row in kickstarts],
        "esxi_pxe_hosts": hosts,
        "esxi_pxe_host_rows": [default_host_to_dict(default_host), *[host_to_dict(row) for row in hosts]],
        "esxi_pxe_host_kickstart_options": [{"id": "", "label": "No Kickstart"}, *[{"id": row.id, "label": row.name} for row in kickstarts]],
        "esxi_pxe_host_iso_options": [{"id": "", "label": "No ISO selected"}, *[{"id": row["path"], "label": f"{row['relative_path']} ({row['source_label']})"} for row in installer_isos]],
        "esxi_installer_iso_root": installer_iso_root_path(),
        "esxi_installer_isos": installer_isos,
        "esxi_installer_iso_error": iso_error,
        "esxi_pxe_boot": boot_settings,
        "esxi_pxe_default_host": default_host,
        "esxi_pxe_default_host_row": default_host_to_dict(default_host),
        "esxi_pxe_dhcp_scope_options": [
            {
                "id": scope.id,
                "name": scope.name,
                "interface_name": scope.interface_name,
                "site_address": scope.site_address,
                "label": f"{scope.name} - {scope.interface_name} / {scope.site_address}/{scope.prefix_length}",
            }
            for scope in dhcp_scopes
            if scope.enabled is not False
        ],
        "esxi_pxe_available_interfaces": available_interfaces,
        "esxi_pxe_selected_interfaces": selected_boot_interfaces,
        "esxi_pxe_selected_addresses": selected_boot_addresses,
        "esxi_pxe_available_addresses": available_boot_addresses,
        "esxi_pxe_bind_label": service_bind_label(boot_settings.get("listen_interface"), boot_settings.get("listen_address")),
        "esxi_pxe_primary_listen_address": primary_listen_address(boot_settings.get("listen_address")),
        "esxi_pxe_service_status": {
            **esxi_service_state,
            "detail": "dnsmasq TFTP/DHCP boot options and PXE HTTP files",
        },
        "esxi_pxe_artifacts": esxi_pxe_host_artifacts(hosts, boot_settings, default_host),
        "esxi_pxe_validation_errors": validation_errors,
        "esxi_pxe_validation_warnings": list(dict.fromkeys(validation_warnings)),
        "esxi_pxe_validation_by_id": validation_by_id,
        "esxi_pxe_manifest": render_esxi_pxe_manifest(
            kickstarts,
            hosts,
            boot_settings,
            default_host,
            custom_variables,
            network_boot_environments,
        ),
        "esxi_pxe_preview": render_esxi_pxe_preview(
            kickstarts,
            hosts,
            boot_settings,
            default_host,
            custom_variables,
            network_boot_environments,
        ),
        "esxi_pxe_config_path": ESXI_PXE_STAGED_CONFIG_PATH,
        "esxi_pxe_strict_validation": strict,
        "esxi_default_kickstart_name": DEFAULT_ESXI_KICKSTART_NAME,
        "esxi_default_kickstart_content": DEFAULT_ESXI_KICKSTART_CONTENT,
    }


def annotate_esxi_installer_iso_sources(db: Session, installer_isos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return annotate esxi installer iso sources.

    Args:
        db: Active database session.
        installer_isos: Installer isos supplied by the caller.
    """
    upload_events = {
        row.resource_id: row
        for row in db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "upload_esxi_installer_iso", AuditEvent.resource_type == "esxi_installer_iso")
            .order_by(AuditEvent.created_at.desc())
        )
        .scalars()
        .all()
        if row.resource_id
    }
    annotated: list[dict[str, Any]] = []
    for iso in installer_isos:
        row = dict(iso)
        upload_event = upload_events.get(str(row.get("relative_path") or ""))
        if upload_event is not None:
            row["source"] = "uploaded"
            row["source_label"] = "Uploaded by user"
            row["source_at"] = upload_event.created_at.isoformat()
        else:
            row["source"] = "vcfdt"
            row["source_label"] = "Downloaded by VCFDT"
            row["source_at"] = row.get("updated_at") or ""
        annotated.append(row)
    return annotated


def parse_optional_esxi_kickstart_id(db: Session, kickstart_id: str, *, label: str = "Kickstart") -> int | None:
    """Parse optional esxi kickstart id.

    Args:
        db: Active database session.
        kickstart_id: Identifier of the kickstart.
        label: Human-readable label used in validation output.

    Returns:
        The parsed optional esxi kickstart id.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    value = str(kickstart_id or "").strip()
    if not value:
        return None
    if not value.isdigit():
        raise HTTPException(status_code=400, detail=f"{label} is invalid.")
    normalized_id = int(value)
    if db.get(EsxiKickstart, normalized_id) is None:
        raise HTTPException(status_code=404, detail=f"{label} not found")
    return normalized_id


def esx_storage_context(db: Session, *, reconcile: bool = True) -> dict[str, Any]:
    """Return esx storage context.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    settings = get_esx_storage_settings_row(db)
    volumes = db.execute(select(EsxStorageVolume).order_by(EsxStorageVolume.name)).scalars().all()
    shares = db.execute(select(EsxNfsShare).order_by(EsxNfsShare.datastore_name)).scalars().all()
    listen_interface, listen_address, interfaces = esx_storage_bind_state(db, shares)
    if reconcile:
        ensure_dns_for_esx_storage(db, None, previous_hostname=settings.hostname)
    dns = db.execute(select(DnsSettings).order_by(DnsSettings.id)).scalars().first()
    naming_mode = get_appliance_settings_row(db).service_dns_target_naming or "ip"
    manifest = render_esx_storage_manifest(
        settings,
        volumes,
        shares,
        interfaces,
        dns_enabled=bool(dns and dns.enabled),
        dns_naming_mode=naming_mode,
    )
    desired_records = desired_esx_storage_dns_records(manifest)
    owned_records = db.execute(select(DnsRecord).where(DnsRecord.description == ESX_STORAGE_DNS_DESCRIPTION)).scalars().all()
    desired_keys = {(row["hostname"], row["record_type"], row["address"]) for row in desired_records}
    record_conflicts: list[str] = []
    for record in desired_records:
        existing = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == record["hostname"], DnsRecord.record_type == record["record_type"])
        ).scalars().all()
        if any(row.description != ESX_STORAGE_DNS_DESCRIPTION for row in existing):
            record_conflicts.append(f"DNS record {record['hostname']} {record['record_type']} is operator-owned and blocks ESX Storage.")
    validation_errors = [*manifest["validation"]["errors"], *record_conflicts]
    disk_inventory: list[dict[str, Any]] = []
    inventory_error = ""
    inventory_result = SystemAdapter().esx_storage_inventory()
    if inventory_result.returncode:
        inventory_error = inventory_result.stderr.strip() or "ESX Storage disk inventory is unavailable."
    else:
        try:
            disk_inventory = parse_esx_storage_disk_inventory_output(
                inventory_result.stdout,
                claimed_ids={row.stable_device_id for row in volumes if row.stable_device_id},
            )
        except (json.JSONDecodeError, ValueError) as exc:
            inventory_error = str(exc)
    volume_rows = [
        {
            "id": row.id,
            "name": row.name,
            "source_type": row.source_type,
            "stable_device_id": row.stable_device_id,
            "device_model": row.device_model,
            "device_serial": row.device_serial,
            "device_wwn": row.device_wwn,
            "capacity_bytes": row.capacity_bytes,
            "filesystem_uuid": row.filesystem_uuid,
            "filesystem_label": row.filesystem_label,
            "mount_path": row.mount_path,
            "state": row.state,
            "applied": row.applied,
        }
        for row in volumes
    ]
    share_rows: list[dict[str, Any]] = []
    rendered_by_id = {item["id"]: item for item in manifest["shares"]}
    for row in shares:
        rendered = rendered_by_id[row.id]
        share_rows.append(
            {
                "id": row.id,
                "datastore_name": row.datastore_name,
                "volume_id": row.volume_id,
                "volume_name": rendered["volume_name"],
                "relative_path": row.relative_path,
                "preferred_nfs_version": row.preferred_nfs_version,
                "interface_name": row.interface_name,
                "address_families": rendered["address_families"],
                "ipv4_clients": split_esx_storage_lines(row.ipv4_clients),
                "ipv6_clients": split_esx_storage_lines(row.ipv6_clients),
                "listeners": rendered["listeners"],
                "target_hostnames": rendered["target_hostnames"],
                "remote_path": rendered["remote_path"],
                "connection_commands": rendered["connection_commands"],
                "powercli_commands": rendered["powercli_commands"],
                "enabled": row.enabled,
            }
        )
    return {
        "esx_storage_settings": settings,
        "esx_storage_volumes": volumes,
        "esx_storage_volume_rows": volume_rows,
        "esx_storage_disk_inventory": disk_inventory,
        "esx_storage_inventory_error": inventory_error,
        "esx_storage_shares": shares,
        "esx_storage_share_rows": share_rows,
        "esx_storage_interfaces": [
            {
                "name": interface.name,
                "ipv4": list(interface.ipv4),
                "ipv6": list(interface.ipv6),
                "default_families": [family for family in ("ipv4", "ipv6") if (interface.ipv4 if family == "ipv4" else interface.ipv6)],
            }
            for interface in interfaces.values()
        ],
        "esx_storage_listen_interface": listen_interface,
        "esx_storage_listen_address": listen_address,
        "esx_storage_manifest": manifest,
        "esx_storage_manifest_preview": esx_storage_manifest_json(manifest),
        "esx_storage_validation_errors": list(dict.fromkeys(validation_errors)),
        "esx_storage_validation_warnings": manifest["validation"]["warnings"],
        "esx_storage_dns_records": desired_records,
        "esx_storage_owned_dns_record_count": len(owned_records),
        "esx_storage_stale_dns_record_count": len(
            [record for record in owned_records if (record.hostname, record.record_type, record.address) not in desired_keys]
        ),
        "esx_storage_firewall_rules": esx_storage_firewall_rule_specs(manifest),
        "esx_storage_config_path": ESX_STORAGE_STAGED_CONFIG_PATH,
    }


def appliance_apply_units(db: Session, *, reconcile: bool = True) -> list[dict[str, Any]]:
    """Return appliance apply units.

    Args:
        db: Active database session.
        reconcile: Whether dependent desired state should be reconciled.
    """
    baselines = load_appliance_apply_baselines(db)
    local_users = local_users_apply_context(db, baselines.get("local_users"))
    appliance_settings = appliance_settings_context(db, reconcile_dns=reconcile)
    network = network_context(db)
    wan = routes_wan_context(db)
    firewall = firewall_context(db, reconcile=reconcile)
    dnsmasq = dnsmasq_context(db, reconcile=reconcile)
    esxi_pxe = esxi_pxe_context(db)
    esx_storage = esx_storage_context(db, reconcile=reconcile)
    ca = ca_context(db, reconcile=reconcile)
    kms = kms_context(db, reconcile=reconcile)
    ldap = ldap_context(db, reconcile=reconcile)
    ntp = ntp_context(db, reconcile=reconcile)
    vcf_backup = vcf_backup_context(db, reconcile=reconcile)
    vcf_depot = vcf_offline_depot_context(db, reconcile=reconcile)
    vcf_registry = vcf_private_registry_context(db, reconcile=reconcile)
    public_services = public_services_context(db, reconcile=reconcile)

    network_baseline = baselines.get("network")
    network_removed_vlans = removed_network_vlan_entries(
        network["network_config_preview"],
        successful_network_apply_vlan_entries(db, network_baseline),
    )
    network_summary = [f"{len(network['physical_interfaces'])} physical interfaces", f"{len(network['vlan_interfaces'])} VLAN interfaces"]
    management_interface = next(
        (interface for interface in network["physical_interfaces"] if normalize_interface_role(interface.role) == "management"),
        None,
    )
    if management_interface is not None:
        network_summary.append(f"management IPv4 gateway {management_interface.gateway or 'none'}")
        network_summary.append(f"management IPv6 gateway {management_interface.ipv6_gateway or 'none'}")
    if network_removed_vlans:
        network_summary.append(f"{len(network_removed_vlans)} VLAN removals")
    network_validation_errors = list(network["network_validation_errors"])
    network_baseline_preview = str((network_baseline or {}).get("config_preview") or "")
    if (
        get_settings().environment == "appliance"
        and not network_baseline_preview
        and _has_operator_appliance_activity(db)
    ):
        network_validation_errors.append(
            "Network apply is blocked because the last-applied Network baseline is unavailable. Restore a known-good "
            "settings archive containing apply baselines or use the local console for maintainer-guided recovery."
        )
    network_unit = make_appliance_apply_unit(
        unit_id="network",
        label="Network",
        page_url="/physical-interfaces",
        context=network,
        summary=network_summary,
        validation_errors=network_validation_errors,
        config_path=network["network_config_path"],
        config_preview=network["network_config_preview"],
        baseline=network_baseline,
    )
    network_unit["removed_vlan_interfaces"] = network_removed_vlans
    network_unit["management_handoff_required"] = management_handoff_required(
        network_unit,
        network_baseline,
    )
    network_unit["previous_management_paths"] = network_management_paths(
        network_baseline_preview
    )

    wan_baseline = baselines.get("wan")
    wan_removed_routes = removed_wan_route_entries(wan["wan_config_preview"], wan_baseline)
    wan["wan_config_preview"] = render_wan_config(
        wan["routes"],
        wan["policies"],
        wan["nat_rules"],
        wan["wan_all_targets"],
        wan["routing_rules"],
        removed_routes=wan_removed_routes,
        source_groups=wan["wan_source_groups"],
        previous_config_preview=str((wan_baseline or {}).get("config_preview") or ""),
        settings=wan["routes_wan_settings"],
    )
    wan_summary = [
        f"{len(wan['routes'])} routes",
        f"{len(wan['routing_rules'])} explicit routing rules",
        f"{len(wan['nat_rules'])} NAT rules",
        f"{len(wan['policies'])} WAN policies",
    ]
    if wan_removed_routes:
        wan_summary.append(f"{len(wan_removed_routes)} route removals")
    wan_unit = make_appliance_apply_unit(
        unit_id="wan",
        label="Routes & WAN Simulation",
        page_url="/routes-wan",
        context=wan,
        summary=wan_summary,
        validation_errors=wan["wan_validation_errors"],
        config_path=wan["wan_config_path"],
        config_preview=wan["wan_config_preview"],
        baseline=wan_baseline,
    )
    gateway_route_migrations = management_gateway_route_migrations(
        network_unit,
        network_baseline,
        wan_unit,
        wan_baseline,
    )
    network_unit["management_gateway_route_migrations"] = gateway_route_migrations
    network_unit["management_default_mirror_change"] = bool(
        mirrored_management_default_routes(wan["wan_config_preview"])
        != mirrored_management_default_routes(
            str((wan_baseline or {}).get("config_preview") or "")
        )
    )

    units = [
        make_appliance_apply_unit(
            unit_id="local_users",
            label="Local Users",
            page_url="/users",
            context=local_users,
            summary=[
                f"{len(local_users['local_users'])} local users",
                f"{local_users['local_user_pending_password_count']} pending OS passwords",
                f"{local_users['local_user_unlock_request_count']} unlock requests",
                f"{len(local_users['local_user_removed_users'])} removed OS accounts",
            ],
            validation_errors=local_users["local_user_validation_errors"],
            config_path=LOCAL_USERS_STAGED_CONFIG_PATH,
            config_preview=local_users["local_user_config_preview"],
            baseline=baselines.get("local_users"),
        ),
        make_appliance_apply_unit(
            unit_id="appliance_settings",
            label="Appliance Settings",
            page_url="/settings",
            context=appliance_settings,
            summary=[
                f"FQDN {appliance_settings['appliance_settings'].fqdn}",
                f"resolver {'local DNS' if appliance_settings['local_dns_enabled'] else 'external DNS'}",
                f"root SSH {'enabled' if appliance_settings['appliance_settings'].root_ssh_enabled else 'disabled'}",
                f"VMware CEIP {'enabled' if appliance_settings['appliance_settings'].vmware_ceip_enabled else 'disabled'}",
            ],
            validation_errors=appliance_settings["appliance_settings_validation_errors"],
            validation_warnings=appliance_settings["appliance_settings_validation_warnings"],
            config_path=appliance_settings["appliance_settings"].config_path,
            config_preview=appliance_settings["appliance_settings_config_preview"],
            baseline=baselines.get("appliance_settings"),
        ),
        network_unit,
        make_appliance_apply_unit(
            unit_id="firewall",
            label="Firewall",
            page_url="/firewall",
            context=firewall,
            summary=[
                "service enabled" if firewall["firewall_settings"].enabled else "service disabled",
                f"{len(firewall['firewall_rules'])} editable rules",
                f"{len(firewall['firewall_generated_rules'])} managed service rules",
            ],
            validation_errors=firewall["firewall_validation_errors"],
            config_path=firewall["firewall_settings"].config_path,
            config_preview=firewall["firewall_config_preview"],
            baseline=baselines.get("firewall"),
        ),
        wan_unit,
        make_appliance_apply_unit(
            unit_id="dnsmasq",
            label="DNS/DHCP (dnsmasq)",
            page_url="/dns",
            context=dnsmasq,
            summary=[
                "DNS enabled" if dnsmasq["dns_settings"].enabled else "DNS disabled",
                (
                    f"{len(split_domains(dnsmasq['dns_settings'].domain))} authoritative zones via "
                    f"{dnsmasq['dns_settings'].authoritative_server} (serial {dnsmasq['dns_settings'].authoritative_serial})"
                    if dnsmasq["dns_settings"].authoritative
                    else f"{len(split_domains(dnsmasq['dns_settings'].domain))} local zones"
                ),
                "DHCP enabled" if dnsmasq["dhcp_settings"].enabled else "DHCP disabled",
                f"{len(dnsmasq['dns_records'])} DNS records",
                f"{len(dnsmasq['dhcp_scopes'])} DHCP scopes",
                f"{len(dnsmasq['dhcp_reservations'])} reservations",
            ],
            validation_errors=dnsmasq["validation_errors"],
            validation_warnings=dnsmasq["dns_warnings"],
            config_path=dnsmasq["dns_settings"].config_path,
            config_preview=dnsmasq["config_preview"],
            baseline=baselines.get("dnsmasq"),
        ),
        make_appliance_apply_unit(
            unit_id="esxi_pxe",
            label="ESXi PXE",
            page_url="/esxi-pxe",
            context=esxi_pxe,
            summary=[
                f"{len(esxi_pxe['esxi_kickstarts'])} Kickstarts",
                f"{len([row for row in esxi_pxe['esxi_kickstarts'] if row.enabled])} enabled",
                f"{len(esxi_pxe['esxi_pxe_hosts'])} host definitions",
                "boot services enabled" if esxi_pxe["esxi_pxe_boot"]["enabled"] else "boot services disabled",
            ],
            validation_errors=esxi_pxe["esxi_pxe_validation_errors"],
            validation_warnings=esxi_pxe["esxi_pxe_validation_warnings"],
            config_path=esxi_pxe["esxi_pxe_config_path"],
            config_preview=esxi_pxe["esxi_pxe_manifest"],
            baseline=baselines.get("esxi_pxe"),
        ),
        make_appliance_apply_unit(
            unit_id="esx_storage",
            label="ESX Storage",
            page_url="/esx-storage",
            context=esx_storage,
            summary=[
                "service enabled" if esx_storage["esx_storage_settings"].enabled else "service disabled",
                f"{len(esx_storage['esx_storage_volumes'])} storage volumes",
                f"{len([row for row in esx_storage['esx_storage_shares'] if row.enabled])} enabled NFS datastores",
                "IPv4 and IPv6 are equivalent listener families",
            ],
            validation_errors=esx_storage["esx_storage_validation_errors"],
            validation_warnings=esx_storage["esx_storage_validation_warnings"],
            config_path=ESX_STORAGE_STAGED_CONFIG_PATH,
            config_preview=esx_storage["esx_storage_manifest_preview"],
            baseline=baselines.get("esx_storage"),
        ),
        make_appliance_apply_unit(
            unit_id="ca",
            label="Certificate Authority",
            page_url="/certificate-authority",
            context=ca,
            summary=[
                "service enabled" if ca["ca_settings"].enabled else "service disabled",
                f"{len(ca['ca_profiles'])} profiles",
                f"{len(ca['ca_certificates'])} certificate requests",
            ],
            validation_errors=ca["ca_validation_errors"],
            config_path=CA_STAGED_CONFIG_PATH,
            config_preview=ca["ca_apply_payload"],
            baseline=baselines.get("ca"),
        ),
        make_appliance_apply_unit(
            unit_id="kms",
            label="vSphere Key Providers",
            page_url="/vsphere-key-providers",
            context=kms,
            summary=[
                "service enabled" if kms["kms_settings"].enabled else "service disabled",
                f"{len(kms['vsphere_key_providers'])} providers",
                f"{len(kms['vsphere_trusted_vcenters'])} trusted vCenters",
            ],
            validation_errors=kms["kms_validation_errors"],
            config_path=KMS_STAGED_CONFIG_PATH,
            config_preview=kms["kms_config_preview"],
            baseline=baselines.get("kms"),
        ),
        make_appliance_apply_unit(
            unit_id="ldap",
            label="Managed LDAP",
            page_url="/ldap",
            context=ldap,
            summary=[
                "service enabled" if ldap["ldap_settings"].enabled else "service disabled",
                f"{len(ldap['ldap_organizations'])} organizations",
                f"{sum(len(row.users) for row in ldap['ldap_organizations'])} users",
                f"{sum(len(row.groups) for row in ldap['ldap_organizations'])} groups",
            ],
            validation_errors=ldap["ldap_validation_errors"],
            validation_warnings=ldap["ldap_validation_warnings"],
            config_path=LDAP_STAGED_CONFIG_PATH,
            config_preview=ldap["ldap_config_preview"],
            raw_config_preview=ldap["ldap_apply_config"],
            snapshot_marker={
                "bind_secret_fingerprints": [
                    hashlib.sha256(row.bind_password_encrypted.encode("utf-8")).hexdigest()
                    for row in ldap["ldap_organizations"]
                ],
                "pending_password_user_ids": sorted(
                    user.id
                    for row in ldap["ldap_organizations"]
                    for user in row.users
                    if user.id is not None and has_pending_ldap_password(user)
                ),
                "recovery_sha256": (
                    ldap["ldap_recovery_archive"].sha256
                    if ldap.get("ldap_recovery_archive") is not None
                    else ""
                ),
            },
            baseline=baselines.get("ldap"),
        ),
        make_appliance_apply_unit(
            unit_id="ntpd",
            label="NTP / NTS",
            page_url="/ntp",
            context=ntp,
            summary=[
                "service enabled" if ntp["ntp_settings"].enabled else "service disabled",
                f"{len(ntp['ntp_settings_json']['upstream_servers'])} upstream servers",
                f"{len(ntp['selected_ntp_interfaces'])} listen interfaces",
            ],
            validation_errors=ntp["ntp_validation_errors"],
            config_path=NTP_STAGED_CONFIG_PATH,
            config_preview=ntp["ntp_config_preview"],
            baseline=baselines.get("ntpd"),
        ),
        make_appliance_apply_unit(
            unit_id="vcf_backups",
            label="VCF Backups",
            page_url="/vcf-backups",
            context=vcf_backup,
            summary=["service enabled" if vcf_backup["vcf_backup_settings"].enabled else "service disabled", f"remote {vcf_backup['vcf_backup_remote_directory']}"],
            validation_errors=vcf_backup["vcf_backup_validation_errors"],
            config_path=vcf_backup["vcf_backup_settings"].config_path,
            config_preview=vcf_backup["vcf_backup_config_preview"],
            baseline=baselines.get("vcf_backups"),
        ),
        make_appliance_apply_unit(
            unit_id="vcf_offline_depot",
            label="VCF Offline Depot",
            page_url="/vcf-offline-depot",
            context=vcf_depot,
            summary=[
                "service enabled" if vcf_depot["vcf_depot_settings"].enabled else "service disabled",
                f"{len([profile for profile in vcf_depot['vcf_depot_profiles'] if profile.enabled])} enabled profiles",
            ],
            validation_errors=vcf_depot["vcf_depot_validation_errors"],
            validation_warnings=vcf_depot["vcf_depot_validation_warnings"],
            config_path=vcf_depot["vcf_depot_settings"].config_path,
            config_preview=f"{vcf_depot['vcf_depot_https_config_preview']}\n\n{vcf_depot_tool_snapshot(vcf_depot)}\n\n{vcf_depot_secret_snapshot(vcf_depot)}\n\n{vcf_depot_application_properties_snapshot(vcf_depot)}\n\n# VCFDT command preview\n{vcf_depot['vcf_depot_command_preview']}",
            baseline=baselines.get("vcf_offline_depot"),
        ),
        make_appliance_apply_unit(
            unit_id="vcf_private_registry",
            label="VCF Private Registry",
            page_url="/vcf-private-registry",
            context=vcf_registry,
            summary=[
                "service enabled" if vcf_registry["vcf_registry_settings"].enabled else "service disabled",
                f"{len([bundle for bundle in vcf_registry['vcf_registry_bundles'] if bundle.enabled])} enabled bundles",
            ],
            validation_errors=vcf_registry["vcf_registry_validation_errors"],
            validation_warnings=vcf_registry["vcf_registry_validation_warnings"],
            config_path=vcf_registry["vcf_registry_settings"].config_path,
            config_preview=f"{vcf_registry['vcf_registry_harbor_config_preview']}\n\n# Bundle relocation preview\n{vcf_registry['vcf_registry_relocation_preview']}",
            baseline=baselines.get("vcf_private_registry"),
        ),
        make_appliance_apply_unit(
            unit_id="public_services",
            label="Public Services",
            page_url="/appliance-apply",
            context=public_services,
            summary=[
                f"{len(public_services['public_service_entries'])} non-management addresses",
                f"{sum(len(entry['services']) for entry in public_services['public_service_entries'])} public service bindings",
            ],
            validation_errors=public_services["public_service_validation_errors"],
            validation_warnings=public_services["public_service_validation_warnings"],
            config_path=public_services["public_service_config_path"],
            config_preview=public_services["public_service_config_preview"],
            baseline=baselines.get("public_services"),
        ),
    ]
    for unit in units:
        unit["connection_warnings"] = appliance_apply_connection_warnings(
            unit["id"],
            unit["config_preview"],
            baselines.get(unit["id"]),
        )
    return units


def appliance_apply_status(db: Session, unit_id: str, *, refresh: bool = False) -> dict[str, Any]:
    """Return appliance apply status.

    Args:
        db: Active database session.
        unit_id: Identifier of the unit.
        refresh: Whether to replace the cached projection immediately.
    """
    projection = appliance_apply_status_projection(db, refresh=refresh)
    for unit in projection["units"]:
        if unit["id"] == unit_id:
            return unit
    sidebar_count = projection["pending_count"]
    return {"state": "unknown", "pill": "muted", "changed": False, "validation_errors": [], "sidebar_pending_apply_count": sidebar_count}


_APPLIANCE_APPLY_STATUS_CACHE_TTL_SECONDS = 60.0
_appliance_apply_status_cache: tuple[float, dict[str, Any]] | None = None
_appliance_apply_status_cache_lock = threading.Lock()


def invalidate_appliance_apply_status_projection() -> None:
    """Invalidate the cached sidebar projection after desired-state mutation."""
    global _appliance_apply_status_cache

    with _appliance_apply_status_cache_lock:
        _appliance_apply_status_cache = None


def appliance_apply_status_projection(db: Session, *, refresh: bool = False) -> dict[str, Any]:
    """Return the bounded, non-reconciling sidebar status projection.

    Args:
        db: Active database session.
        refresh: Whether to replace the cached projection immediately.
    """
    global _appliance_apply_status_cache

    now = time.monotonic()
    with _appliance_apply_status_cache_lock:
        if not refresh and _appliance_apply_status_cache is not None:
            cached_at, cached_projection = _appliance_apply_status_cache
            if now - cached_at < _APPLIANCE_APPLY_STATUS_CACHE_TTL_SECONDS:
                return cached_projection
        units = appliance_apply_units(db, reconcile=False)
        submitted_ids = active_appliance_apply_submitted_unit_ids(db)
        pending_count = sum(unit["changed"] and unit["id"] not in submitted_ids for unit in units)
        projection = {
            "units": [appliance_apply_status_from_unit(unit, sidebar_pending_apply_count=pending_count) for unit in units],
            "pending_count": pending_count,
        }
        _appliance_apply_status_cache = (now, projection)
        return projection


def appliance_apply_status_from_unit(unit: dict[str, Any], *, sidebar_pending_apply_count: int | None = None) -> dict[str, Any]:
    """Return appliance apply status from unit.

    Args:
        unit: Unit consumed by appliance apply status from unit.
        sidebar_pending_apply_count: Number of sidebar pending apply entries.
    """
    if unit["validation_errors"]:
        state = "needs attention"
        pill = "warn"
    elif unit["changed"]:
        state = "pending"
        pill = "warn"
    else:
        state = "current"
        pill = "good"
    sidebar_count = sidebar_pending_apply_count if sidebar_pending_apply_count is not None else int(bool(unit["changed"]))
    return {"state": state, "pill": pill, "sidebar_pending_apply_count": sidebar_count, **unit}


def appliance_apply_client_status(status: dict[str, Any]) -> dict[str, Any]:
    """Return only the JSON-safe apply metadata needed by autosave clients.

    Args:
        status: Lifecycle or operation status to record or evaluate.
    """
    return {
        "id": status.get("id", ""),
        "label": status.get("label", "Appliance component"),
        "state": status.get("state", "unknown"),
        "pill": status.get("pill", "muted"),
        "changed": bool(status.get("changed")),
        "validation_errors": list(status.get("validation_errors") or []),
        "sidebar_pending_apply_count": int(status.get("sidebar_pending_apply_count") or 0),
    }


def dnsmasq_apply_status(db: Session, dnsmasq: dict[str, Any]) -> dict[str, Any]:
    """Return dnsmasq apply status.

    Args:
        db: Active database session.
        dnsmasq: Dnsmasq supplied by the caller.
    """
    baselines = load_appliance_apply_baselines(db)
    unit = make_appliance_apply_unit(
        unit_id="dnsmasq",
        label="DNS/DHCP (dnsmasq)",
        page_url="/dns",
        context=dnsmasq,
        summary=[
            "DNS enabled" if dnsmasq["dns_settings"].enabled else "DNS disabled",
            (
                f"{len(split_domains(dnsmasq['dns_settings'].domain))} authoritative zones via "
                f"{dnsmasq['dns_settings'].authoritative_server} (serial {dnsmasq['dns_settings'].authoritative_serial})"
                if dnsmasq["dns_settings"].authoritative
                else f"{len(split_domains(dnsmasq['dns_settings'].domain))} local zones"
            ),
            "DHCP enabled" if dnsmasq["dhcp_settings"].enabled else "DHCP disabled",
            f"{len(dnsmasq['dns_records'])} DNS records",
            f"{len(dnsmasq['dhcp_scopes'])} DHCP scopes",
            f"{len(dnsmasq['dhcp_reservations'])} reservations",
        ],
        validation_errors=dnsmasq["validation_errors"],
        validation_warnings=dnsmasq["dns_warnings"],
        config_path=dnsmasq["dns_settings"].config_path,
        config_preview=dnsmasq["config_preview"],
        baseline=baselines.get("dnsmasq"),
    )
    return appliance_apply_status_from_unit(unit)


def ntpd_apply_status(db: Session, ntp: dict[str, Any]) -> dict[str, Any]:
    """Return ntpd apply status.

    Args:
        db: Active database session.
        ntp: Ntp supplied by the caller.
    """
    baselines = load_appliance_apply_baselines(db)
    unit = make_appliance_apply_unit(
        unit_id="ntpd",
        label="NTP / NTS",
        page_url="/ntp",
        context=ntp,
        summary=[
            "service enabled" if ntp["ntp_settings"].enabled else "service disabled",
            f"{len(ntp['ntp_settings_json']['upstream_servers'])} upstream servers",
            f"{len(ntp['selected_ntp_interfaces'])} listen interfaces",
        ],
        validation_errors=ntp["ntp_validation_errors"],
        config_path=NTP_STAGED_CONFIG_PATH,
        config_preview=ntp["ntp_config_preview"],
        baseline=baselines.get("ntpd"),
    )
    return appliance_apply_status_from_unit(unit)


def service_runtime_status(db: Session, service_id: str) -> dict[str, Any]:
    """Return service runtime status.

    Args:
        db: Active database session.
        service_id: Identifier of the service.
    """
    row = db.execute(select(ServiceState).where(ServiceState.service == service_id)).scalar_one_or_none()
    if row is None:
        return {"label": "unknown", "pill": "muted", "running": False, "enabled": False, "health": "unknown", "detail": ""}
    service_row = service_state_status_row(row)
    running = bool(service_row["running"])
    enabled = bool(service_row["enabled"])
    if running and enabled:
        label = "live"
        pill = "good"
    elif running:
        label = "running"
        pill = "warn"
    elif enabled:
        label = "stopped"
        pill = "warn"
    else:
        label = "disabled"
        pill = "muted"
    return {
        "label": label,
        "pill": pill,
        "running": running,
        "enabled": enabled,
        "health": service_row["health"],
        "detail": str(service_row["detail"]),
    }


def appliance_apply_context(db: Session) -> dict[str, Any]:
    """Return appliance apply context.

    Args:
        db: Active database session.
    """
    units = appliance_apply_units(db)
    submitted_ids = active_appliance_apply_submitted_unit_ids(db)
    changed_units = [unit for unit in units if unit["changed"] and unit["id"] not in submitted_ids]
    initial_apply_required = (
        db.execute(
            select(Job.id)
            .where(Job.type == "appliance-apply", Job.status == JobStatus.SUCCEEDED.value)
            .limit(1)
        ).first()
        is None
    )
    review_units = (
        [unit for unit in units if unit["id"] not in submitted_ids]
        if initial_apply_required
        else changed_units
    )
    return {
        "apply_units": units,
        "changed_apply_units": changed_units,
        "review_apply_units": review_units,
        "unchanged_apply_units": [unit for unit in units if not unit["changed"]],
        "changed_apply_unit_count": len(changed_units),
        "submitted_apply_unit_ids": submitted_ids,
        "initial_apply_required": initial_apply_required,
    }


def dashboard_appliance_apply_units(db: Session) -> list[dict[str, Any]]:
    """Project desired-state status without running apply-time reconciliation.

    Args:
        db: Active database session used by the operation.
    """
    return appliance_apply_units(db, reconcile=False)


def _dashboard_iso(value: datetime | None) -> str:
    """Return dashboard iso.

    Args:
        value: Candidate value consumed by dashboard ISO.
    """
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _dashboard_activity_outcome(status_value: str) -> tuple[str, str]:
    """Return dashboard activity outcome.

    Args:
        status_value: Status value consumed by dashboard activity outcome.
    """
    normalized = str(status_value or "").strip().lower()
    if normalized in {JobStatus.SUCCEEDED.value, "success"}:
        return "Succeeded", "good"
    if normalized in FAILED_JOB_STATUSES:
        return "Failed", "error"
    if normalized == JobStatus.CANCELLED.value:
        return "Cancelled", "muted"
    if normalized in ACTIVE_JOB_STATUSES:
        return normalized.title(), "warn"
    return normalized.title() or "Recorded", "muted"


def _appliance_apply_selected_unit_ids(job: Job) -> set[str]:
    """Return appliance apply selected unit ids.

    Args:
        job: Background job record affected by the operation.
    """
    payload = _job_payload(job)
    selected = {str(unit_id) for unit_id in payload.get("selected_units", []) if str(unit_id)}
    if selected:
        return selected
    return {
        str(unit.get("unit_id"))
        for unit in payload.get("units", [])
        if isinstance(unit, dict) and unit.get("unit_id")
    }


def _appliance_apply_unresolved_unit_ids(job: Job) -> set[str]:
    """Return appliance apply unresolved unit ids.

    Args:
        job: Background job record affected by the operation.
    """
    payload = _job_payload(job)
    selected = _appliance_apply_selected_unit_ids(job)
    succeeded = {
        str(unit.get("unit_id"))
        for unit in payload.get("units", [])
        if isinstance(unit, dict) and unit.get("unit_id") and unit.get("success") is True
    }
    return selected - succeeded


def _appliance_apply_failure_is_resolved(job: Job, successful_applies: list[Job]) -> bool:
    """Return appliance apply failure is resolved.

    Args:
        job: Background job record affected by the operation.
        successful_applies: Successful applies consumed by appliance apply failure is resolved.
    """
    unresolved_units = _appliance_apply_unresolved_unit_ids(job)
    if not unresolved_units:
        return False
    retried_units: set[str] = set()
    for successful_job in successful_applies:
        if successful_job.created_at > job.created_at:
            retried_units.update(_appliance_apply_selected_unit_ids(successful_job))
    return unresolved_units <= retried_units


def dashboard_snapshot(db: Session) -> dict[str, Any]:
    """Build the private operator dashboard without exposing task or audit details.

    Args:
        db: Active database session used by the operation.
    """
    generated_at = utcnow()
    units = dashboard_appliance_apply_units(db)
    changed_units = [unit for unit in units if unit["changed"]]
    invalid_changed_units = [unit for unit in changed_units if not unit["valid"]]
    valid_changed_units = [unit for unit in changed_units if unit["valid"]]

    jobs = db.execute(select(Job).order_by(desc(Job.created_at)).limit(50)).scalars().all()
    successful_apply = db.execute(
        select(Job)
        .where(Job.type == "appliance-apply", Job.status == JobStatus.SUCCEEDED.value)
        .order_by(desc(Job.created_at))
        .limit(1)
    ).scalar_one_or_none()
    recent_failure_cutoff = generated_at - timedelta(hours=24)
    recent_successful_applies = (
        db.execute(
            select(Job)
            .where(
                Job.type == "appliance-apply",
                Job.status == JobStatus.SUCCEEDED.value,
                Job.created_at >= recent_failure_cutoff,
            )
            .order_by(desc(Job.created_at))
        )
        .scalars()
        .all()
    )
    failed_jobs = (
        db.execute(
            select(Job)
            .where(Job.status.in_(FAILED_JOB_STATUSES), Job.created_at >= recent_failure_cutoff)
            .order_by(desc(Job.created_at))
        )
        .scalars()
        .all()
    )
    failed_jobs = [
        job
        for job in failed_jobs
        if job.type != "appliance-apply" or not _appliance_apply_failure_is_resolved(job, recent_successful_applies)
    ]
    active_jobs = (
        db.execute(select(Job).where(Job.status.in_(ACTIVE_JOB_STATUSES)).order_by(desc(Job.created_at)))
        .scalars()
        .all()
    )

    services = (
        db.execute(select(ServiceState).where(ServiceState.service.in_(SERVICE_STATE_IDS)).order_by(ServiceState.display_name))
        .scalars()
        .all()
    )
    enabled_services = [service for service in services if service.enabled]
    unhealthy_services = [
        service
        for service in enabled_services
        if not service.running or str(service.health or "").lower() not in {"healthy", "running", "good"}
    ]

    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    vlans = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
    configured_interfaces = [
        interface
        for interface in interfaces
        if str(interface.role or "unused").lower() != "unused" or str(interface.mode or "unused").lower() != "unused"
    ]
    interface_exceptions = [
        interface
        for interface in configured_interfaces
        if str(interface.oper_state or "").lower() == "missing"
        or (str(interface.admin_state or "").lower() == "up" and str(interface.oper_state or "").lower() not in {"up", "unknown"})
    ]
    management = next((interface for interface in configured_interfaces if str(interface.role or "").lower() == "management"), None)
    management_discovered = bool(management and str(management.oper_state or "").lower() != "missing")
    management_address = ""
    if management is not None:
        management_address = str(management.host_ip_cidr if management.ipv4_method == "dhcp" else management.ip_cidr or "")
        management_address = management_address or str(management.ipv6_cidr or "")
    management_healthy = bool(
        management_discovered
        and management_address
        and str(management.admin_state or "").lower() == "up"
        and str(management.oper_state or "").lower() == "up"
    )

    settings_unit = next((unit for unit in units if unit["id"] == "appliance_settings"), None)
    all_desired_state_valid = all(unit["valid"] for unit in units)
    readiness_items = [
        {
            "id": "management-discovery",
            "label": "Management interface discovered",
            "complete": management_discovered,
            "summary": management.name if management_discovered and management else "Discover a management interface from the appliance host.",
            "url": "/physical-interfaces",
        },
        {
            "id": "management-network",
            "label": "Management addressing and link healthy",
            "complete": management_healthy,
            "summary": management_address if management_healthy else "Management needs an address, admin-up desired state, and an active link.",
            "url": "/physical-interfaces",
        },
        {
            "id": "appliance-settings",
            "label": "Appliance Settings valid",
            "complete": bool(settings_unit and settings_unit["valid"]),
            "summary": "Ready" if settings_unit and settings_unit["valid"] else "Resolve Appliance Settings validation before the first apply.",
            "url": "/settings",
        },
        {
            "id": "desired-state",
            "label": "Desired state valid",
            "complete": all_desired_state_valid,
            "summary": "All apply units validate" if all_desired_state_valid else f"{sum(1 for unit in units if not unit['valid'])} apply units need attention.",
            "url": "/appliance-apply",
        },
        {
            "id": "first-apply",
            "label": "First appliance apply succeeded",
            "complete": successful_apply is not None,
            "summary": "Initial desired state applied" if successful_apply else "Submit the reviewed desired state through Appliance Apply.",
            "url": "/appliance-apply",
        },
    ]
    readiness_mode = not (management_healthy and successful_apply is not None)

    attention_items: list[dict[str, Any]] = []
    for unit in invalid_changed_units:
        attention_items.append(
            {
                "kind": "invalid-change",
                "severity": "error",
                "title": f"{unit['label']} changes are invalid",
                "summary": str(unit["validation_errors"][0]) if unit["validation_errors"] else "Resolve validation before appliance apply.",
                "timestamp": generated_at.isoformat(),
                "url": str(unit["page_url"]),
            }
        )
    for job in failed_jobs:
        attention_items.append(
            {
                "kind": "failed-task",
                "severity": "error",
                "title": f"{_task_type_label(job.type)} task failed",
                "summary": "A task failed within the last 24 hours. Open Tasks for the redacted operator detail.",
                "timestamp": _dashboard_iso(job.finished_at or job.created_at),
                "url": f"/tasks?job_id={quote(job.id)}",
            }
        )
    for service in unhealthy_services:
        state = "stopped" if not service.running else str(service.health or "unhealthy").replace("_", " ")
        attention_items.append(
            {
                "kind": "service",
                "severity": "warn",
                "title": f"{service.display_name} is {state}",
                "summary": "This enabled service is not reporting a healthy running state.",
                "timestamp": generated_at.isoformat(),
                "url": "/services",
            }
        )
    for interface in interface_exceptions:
        state = "missing" if str(interface.oper_state or "").lower() == "missing" else "down"
        attention_items.append(
            {
                "kind": "interface",
                "severity": "warn",
                "title": f"{interface.name} is {state}",
                "summary": f"Configured {interface.role} interface is not available in its expected state.",
                "timestamp": _dashboard_iso(interface.missing_since) or generated_at.isoformat(),
                "url": "/physical-interfaces",
            }
        )

    if readiness_mode:
        overall_state = "setup-incomplete"
        overall_label = "Setup incomplete"
        primary_item = next((item for item in readiness_items if not item["complete"]), readiness_items[-1])
        primary_action = {"label": "Continue setup", "url": primary_item["url"]}
    elif attention_items:
        overall_state = "needs-attention"
        overall_label = "Needs attention"
        primary_action = {"label": "Review next issue", "url": attention_items[0]["url"]}
    elif valid_changed_units:
        overall_state = "healthy"
        overall_label = "Healthy"
        primary_action = {"label": "Review appliance changes", "url": "/appliance-apply"}
    elif active_jobs:
        overall_state = "healthy"
        overall_label = "Healthy"
        primary_action = {"label": "View running tasks", "url": "/tasks"}
    else:
        overall_state = "healthy"
        overall_label = "Healthy"
        primary_action = {"label": "Open monitor", "url": "/monitor"}

    audit_events = db.execute(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(20)).scalars().all()
    activity: list[dict[str, Any]] = []
    for job in jobs:
        outcome, pill = _dashboard_activity_outcome(job.status)
        activity.append(
            {
                "source": "Task",
                "title": _task_type_label(job.type),
                "outcome": outcome,
                "outcome_pill": pill,
                "actor": job.created_by,
                "timestamp": _dashboard_iso(job.created_at),
                "url": f"/tasks?job_id={quote(job.id)}",
            }
        )
    for event in audit_events:
        activity.append(
            {
                "source": "Audit",
                "title": str(event.action or "Activity").replace("_", " ").title(),
                "outcome": "Succeeded" if event.success else "Failed",
                "outcome_pill": "good" if event.success else "error",
                "actor": event.actor,
                "timestamp": _dashboard_iso(event.created_at),
                "url": "/audit-log",
            }
        )
    activity.sort(key=lambda row: row["timestamp"], reverse=True)

    appliance_settings = db.execute(select(ApplianceSettings).limit(1)).scalar_one_or_none()
    fqdn = str(appliance_settings.fqdn if appliance_settings else "").strip()
    hostname = fqdn.split(".", 1)[0] if fqdn else "Unknown appliance"
    return {
        "generated_at": generated_at.isoformat(),
        "overall": {
            "state": overall_state,
            "label": overall_label,
            "hostname": hostname,
            "fqdn": fqdn,
            "dry_run": bool(get_settings().dry_run_system_adapters),
            "primary_action": primary_action,
        },
        "readiness": {"active": readiness_mode, "items": readiness_items},
        "attention_items": attention_items,
        "pending_changes": {
            "count": len(valid_changed_units),
            "invalid_count": len(invalid_changed_units),
            "units": [{"id": unit["id"], "label": unit["label"], "url": unit["page_url"]} for unit in valid_changed_units],
            "url": "/appliance-apply",
        },
        "tasks": {
            "pending": sum(1 for job in active_jobs if job.status == JobStatus.PENDING.value),
            "running": sum(1 for job in active_jobs if job.status == JobStatus.RUNNING.value),
            "failed_24h": len(failed_jobs),
            "url": "/tasks",
        },
        "services": {
            "enabled": len(enabled_services),
            "running": sum(1 for service in enabled_services if service.running),
            "unhealthy": len(unhealthy_services),
            "exceptions": [
                {"name": service.display_name, "state": "stopped" if not service.running else str(service.health or "unhealthy"), "url": "/services"}
                for service in unhealthy_services
            ],
            "url": "/services",
        },
        "network": {
            "management": {
                "name": management.name if management else "Not discovered",
                "address": management_address,
                "link": str(management.oper_state if management else "missing"),
                "healthy": management_healthy,
            },
            "configured": len(configured_interfaces),
            "physical": len(interfaces),
            "vlans": len([vlan for vlan in vlans if vlan.enabled]),
            "missing_or_down": len(interface_exceptions),
            "exceptions": [{"name": interface.name, "state": str(interface.oper_state or "unknown"), "url": "/physical-interfaces"} for interface in interface_exceptions],
            "url": "/physical-interfaces",
        },
        "recent_activity": activity[:6],
    }


def appliance_update_settings(db: Session) -> dict[str, Any]:
    """Return appliance update settings.

    Args:
        db: Active database session.
    """
    stored = update_settings_from_json(setting_value(db, APPLIANCE_UPDATE_SETTINGS_KEY))
    settings = effective_update_settings(db, stored=stored)
    settings["vmware_ceip_enabled"] = bool(get_appliance_settings_row(db).vmware_ceip_enabled)
    return settings


def appliance_update_availability_state(db: Session) -> dict[str, Any]:
    """Return the durable operational availability state.

    Args:
        db: Active database session.
    """
    return update_availability_from_json(
        setting_value(db, APPLIANCE_UPDATE_AVAILABILITY_KEY)
    )


APPLIANCE_UPDATE_SOURCE_READINESS_REPOSITORY_LIMIT = 6


def appliance_update_source_readiness(
    db: Session, settings: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Return current repository synchronization readiness by update stream.

    Args:
        db: Active database session.
        settings: Effective Appliance Update settings.
    """
    recent_jobs = db.execute(
        select(Job)
        .where(Job.type == "appliance-update")
        .order_by(desc(Job.created_at))
        .limit(24)
    ).scalars().all()
    source_sync_active = False
    for job in recent_jobs:
        try:
            task_config = json.loads(job.task_config_json or "{}")
        except json.JSONDecodeError:
            task_config = {}
        if not isinstance(task_config, dict) or task_config.get("mode") != "source_sync":
            continue
        source_sync_active = job.status in {
            JobStatus.PENDING.value,
            JobStatus.RUNNING.value,
        }
        break

    definitions = settings.get("source_definitions")
    definitions = definitions if isinstance(definitions, list) else []
    rows: dict[str, dict[str, Any]] = {}
    for stream, kind, repositories in (
        (
            "photon_os",
            "photon",
            unsynchronized_photon_repositories(settings),
        ),
        (
            "powershell_modules",
            "powershell",
            unsynchronized_powershell_repositories(settings),
        ),
    ):
        names = list(
            dict.fromkeys(
                str(name).strip() for name in repositories if str(name).strip()
            )
        )
        displayed_names = names[:APPLIANCE_UPDATE_SOURCE_READINESS_REPOSITORY_LIMIT]
        repositories_omitted = len(names) - len(displayed_names)
        invalid_names = {
            str(source.get("name") or "").strip()
            for source in definitions
            if isinstance(source, dict)
            and source.get("kind") == kind
            and source.get("validation_status") == "invalid"
        }
        ready = not names
        state = (
            "ready"
            if ready
            else "synchronizing"
            if source_sync_active
            else "failed"
            if invalid_names.intersection(names)
            else "required"
        )
        repository_label = ", ".join(displayed_names) or (
            "configured Photon repositories"
            if kind == "photon"
            else "configured PowerShell repositories"
        )
        if repositories_omitted:
            repository_label += f", and {repositories_omitted} more repositories"
        reason = ""
        if state == "synchronizing":
            reason = (
                f"Repository synchronization is in progress for {repository_label}. "
                f"{UPDATE_STREAM_LABELS[stream]} becomes available after it succeeds."
            )
        elif state == "failed":
            reason = (
                f"Repository synchronization failed for {repository_label}. Review the recent task, "
                "correct the reported repository problem, and retry Synchronize repositories."
            )
        elif state == "required":
            reason = (
                f"Synchronize repositories for {repository_label} before checking or installing "
                f"{UPDATE_STREAM_LABELS[stream]}."
            )
        rows[stream] = {
            "required": True,
            "ready": ready,
            "state": state,
            "source_kind": kind,
            "repositories": displayed_names,
            "repository_count": len(names),
            "repositories_omitted": repositories_omitted,
            "reason": reason,
        }
    rows["atlaso_release"] = {
        "required": False,
        "ready": True,
        "state": "ready",
        "source_kind": "atlaso",
        "repositories": [],
        "repository_count": 0,
        "repositories_omitted": 0,
        "reason": "",
    }
    return rows


def appliance_update_availability_summary(
    db: Session,
    *,
    result_streams: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Return the sanitized availability projection for the current configuration.

    Args:
        db: Active database session.
        result_streams: Optional stream subset for the composite result summary.
    """
    settings = appliance_update_settings(db)
    source_readiness = appliance_update_source_readiness(db, settings)
    availability_state = appliance_update_availability_state(db)
    sanitized_state = update_availability_from_json(
        update_availability_to_json(availability_state)
    )
    prerequisite_attempts_cleared: set[str] = set()
    for stream, readiness in source_readiness.items():
        stream_state = sanitized_state["streams"].get(stream)
        if not readiness["required"] or not isinstance(stream_state, dict):
            continue
        attempt = stream_state.get("last_attempt")
        remediation = (
            str(attempt.get("remediation") or "")
            if isinstance(attempt, dict)
            else ""
        )
        if "Synchronize repositories" in remediation:
            stream_state.pop("last_attempt", None)
            prerequisite_attempts_cleared.add(stream)
    summary = update_availability_summary(
        sanitized_state,
        settings,
        result_streams=result_streams,
    )
    for row in summary["streams"]:
        row["source_sync"] = source_readiness[str(row["id"])]
        row["check_required"] = str(row["id"]) in prerequisite_attempts_cleared
    available = [
        row
        for row in summary["streams"]
        if row["source_sync"]["ready"]
        and row["confirmed"]
        and row["confirmed"]["update_available"]
    ]
    summary["available"] = bool(available)
    summary["affected_stream_count"] = len(available)
    return summary


def appliance_update_context(
    db: Session,
    *,
    selected_stream_ids: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Return appliance update context.

    Args:
        db: Active database session.
        selected_stream_ids: Optional submitted stream selection to preserve.
    """
    settings = appliance_update_settings(db)
    recent_jobs = db.execute(
        select(Job)
        .options(selectinload(Job.steps))
        .where(Job.type == "appliance-update")
        .order_by(desc(Job.created_at))
        .limit(8)
    ).scalars().all()
    apply_started_patterns = ('"apply_started":true', '"apply_started": true')
    legacy_apply_patterns = (
        '"command_line":"/opt/atlaso/bin/atlaso-helper appliance-update apply --real ',
        '"command_line": "/opt/atlaso/bin/atlaso-helper appliance-update apply --real ',
        '"command_line":"sudo -n /opt/atlaso/bin/atlaso-helper appliance-update apply --real ',
        '"command_line": "sudo -n /opt/atlaso/bin/atlaso-helper appliance-update apply --real ',
    )
    qualifying_step = db.execute(
        select(
            Job.id.label("job_id"),
            JobStep.component_key.label("stream"),
            JobStep.started_at.label("step_started_at"),
            Job.started_at.label("job_started_at"),
            Job.created_at.label("job_created_at"),
        )
        .join(Job, Job.id == JobStep.job_id)
        .where(
            Job.type == "appliance-update",
            Job.status.in_([JobStatus.SUCCEEDED.value, JobStatus.FAILED.value]),
            _appliance_update_mode_filter_clause("run"),
            or_(
                *(
                    func.lower(JobStep.result).contains(pattern)
                    for pattern in (*apply_started_patterns, *legacy_apply_patterns)
                )
            ),
        )
        .order_by(
            desc(func.coalesce(JobStep.started_at, Job.started_at, Job.created_at)),
            desc(JobStep.id),
        )
        .limit(1)
    ).first()
    qualifying_stepless_job = db.execute(
        select(Job.id, Job.started_at, Job.created_at).where(
            Job.type == "appliance-update",
            Job.status.in_([JobStatus.SUCCEEDED.value, JobStatus.FAILED.value]),
            _appliance_update_mode_filter_clause("run"),
            ~Job.steps.any(),
            or_(
                *(
                    func.lower(Job.result).contains(pattern)
                    for pattern in (*apply_started_patterns, *legacy_apply_patterns)
                )
            ),
        )
        .order_by(desc(func.coalesce(Job.started_at, Job.created_at)), desc(Job.id))
        .limit(1)
    ).first()
    qualifying_candidates: list[dict[str, Any]] = []
    if qualifying_step is not None:
        qualifying_candidates.append(
            {
                "job_id": str(qualifying_step.job_id),
                "stream": str(qualifying_step.stream),
                "started_at": (
                    qualifying_step.step_started_at
                    or qualifying_step.job_started_at
                    or qualifying_step.job_created_at
                ),
            }
        )
    if qualifying_stepless_job is not None:
        qualifying_candidates.append(
            {
                "job_id": str(qualifying_stepless_job.id),
                "stream": "",
                "started_at": (
                    qualifying_stepless_job.started_at or qualifying_stepless_job.created_at
                ),
            }
        )
    qualifying_install = max(
        qualifying_candidates,
        key=lambda candidate: (
            candidate["started_at"],
            candidate["job_id"],
            candidate["stream"],
        ),
        default=None,
    )
    sources = source_rows(db)
    packages = managed_package_rows(db)
    source_payloads = [update_source_payload(source) for source in sources]
    powershell_sources = [source for source in sources if source.kind == "powershell"]
    powershell_packages = [
        {
            "id": package.id,
            "name": package.name,
            "source_id": package.source_id,
            "source_name": package.source.name if package.source is not None else "Unavailable repository",
            "policy": package.policy,
            "target_version": package.target_version,
            "enabled": package.enabled,
        }
        for package in packages
        if package.ecosystem == "powershell"
    ]
    readiness = appliance_update_source_readiness(db, settings)
    selected = [
        stream
        for stream in selected_update_streams(
            selected_stream_ids if selected_stream_ids is not None else UPDATE_STREAMS
        )
        if readiness[stream]["ready"]
    ]
    manifest_preview = render_update_manifest(selected_streams=selected, settings=settings, actor="preview")
    photon_repositories = photon_repository_details()
    availability = appliance_update_availability_summary(
        db, result_streams=selected_stream_ids
    )
    availability_by_stream = {
        str(row.get("id")): row
        for row in availability["streams"]
        if isinstance(row, dict)
    }
    active_update_task = db.execute(
        select(Job).where(
            Job.type == "appliance-update",
            Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
        )
    ).scalars().first()
    _install_allowed, install_reason = manual_install_gate(availability, selected)
    submitted = selected_update_streams(selected_stream_ids or [])
    blocked_submitted = [
        stream for stream in submitted if not readiness[stream]["ready"]
    ]
    if not selected and blocked_submitted:
        blocked_labels = " and ".join(
            UPDATE_STREAM_LABELS[stream] for stream in blocked_submitted
        )
        install_reason = (
            "Select a ready update stream. Repository setup is required for "
            f"{blocked_labels}."
        )
    if active_update_task is not None:
        install_reason = "Wait for the active Appliance Update task to finish."
    return {
        "update_settings": settings,
        "update_sources": source_payloads,
        "update_source_groups": [
            {"kind": kind, "sources": [source for source in source_payloads if source["kind"] == kind]}
            for kind in sorted(UPDATE_SOURCE_KINDS)
        ],
        "update_source_kinds": sorted(UPDATE_SOURCE_KINDS),
        "managed_packages": packages,
        "powershell_sources": powershell_sources,
        "powershell_packages": powershell_packages,
        "photon_repository_details": photon_repositories,
        "photon_repository_summary": photon_repository_summary(),
        "photon_repository_rows": min(max(len(photon_repositories), 2), 8),
        "atlaso_channels": sorted(ATLASO_CHANNELS),
        "update_streams": [
            {
                "id": stream,
                "label": UPDATE_STREAM_LABELS[stream],
                "source_sync_required": readiness[stream]["required"],
                "source_sync_ready": readiness[stream]["ready"],
                "source_sync_state": readiness[stream]["state"],
                "source_sync_reason": readiness[stream]["reason"],
                "source_kind": readiness[stream]["source_kind"],
                "source_repositories": readiness[stream]["repositories"],
                "availability": availability_by_stream.get(stream),
            }
            for stream in UPDATE_STREAMS
        ],
        "appliance_update_availability": availability,
        "appliance_update_active": active_update_task is not None,
        "selected_update_stream_ids": selected,
        "appliance_update_check_allowed": bool(selected)
        and active_update_task is None,
        "appliance_update_install_reason": install_reason,
        "default_atlaso_manifest_url": DEFAULT_ATLASO_MANIFEST_URL,
        "current_version_info": current_version_info(),
        "appliance_update_manifest_preview": manifest_preview,
        "appliance_update_staged_config_path": APPLIANCE_UPDATE_STAGED_CONFIG_PATH,
        "recent_update_tasks": [_task_row(job) for job in recent_jobs],
        "task_component_filter_options": _task_component_filter_options(db),
        "appliance_update_info_path": APPLIANCE_UPDATE_INFO_PATH,
        "update_info_file": appliance_update_evidence_state(
            qualifying_install_job_id=(
                str(qualifying_install["job_id"]) if qualifying_install is not None else ""
            ),
            qualifying_install_stream=(
                str(qualifying_install["stream"]) if qualifying_install is not None else ""
            ),
            qualifying_install_started_at=(
                qualifying_install["started_at"] if qualifying_install is not None else None
            ),
        ),
        "update_settings_errors": validate_update_settings(settings),
        "system_adapter_dry_run": get_settings().dry_run_system_adapters,
    }


def vaults_context(db: Session) -> dict[str, Any]:
    """Return vaults context.

    Args:
        db: Active database session.
    """
    return {
        "vaults": [
            {
                "id": vault.id,
                "name": vault.name,
                "description": vault.description,
                "entry_rows": [vault_entry_metadata(entry) for entry in vault.entries],
            }
            for vault in list_vaults(db)
        ]
    }


def _vaults_render_error(
    request: Request,
    identity: Identity,
    db: Session,
    message: str,
    *,
    status_code: int = 422,
) -> HTMLResponse:
    """Return vaults render error.

    Args:
        request: Incoming HTTP request.
        identity: Authenticated identity authorizing the request.
        db: Active database session.
        message: Public-safe status or error message.
        status_code: HTTP status code for the response.
    """
    return render(
        request,
        "vaults.html",
        {"identity": identity, **vaults_context(db), "vault_error": message},
        status_code=status_code,
    )


_management_before_vaults_router = router
_vaults_ui = build_vaults_ui_router(
    VaultsUiDependencies(
        require_management_ui_request=require_management_ui_request,
        require_admin_identity=lambda *args, **kwargs: require_admin_identity(
            *args, **kwargs
        ),
        render=lambda *args, **kwargs: render(*args, **kwargs),
        verify_csrf=lambda *args, **kwargs: verify_csrf(*args, **kwargs),
        vaults_context=lambda *args, **kwargs: vaults_context(*args, **kwargs),
        vaults_render_error=lambda *args, **kwargs: _vaults_render_error(
            *args, **kwargs
        ),
        create_vault=lambda *args, **kwargs: create_vault(*args, **kwargs),
        decrypt_secret=lambda *args, **kwargs: decrypt_secret(*args, **kwargs),
        kickstart_template_variables=lambda *args, **kwargs: kickstart_template_variables(
            *args, **kwargs
        ),
        parse_vault_uris_json=lambda *args, **kwargs: parse_vault_uris_json(
            *args, **kwargs
        ),
        record_audit=lambda *args, **kwargs: record_audit(*args, **kwargs),
        update_vault_entry=lambda *args, **kwargs: update_vault_entry(
            *args, **kwargs
        ),
        upsert_vault_entry=lambda *args, **kwargs: upsert_vault_entry(
            *args, **kwargs
        ),
        vault_entry_input=lambda *args, **kwargs: VaultEntryInput(*args, **kwargs),
        vault_marker_name=lambda *args, **kwargs: vault_marker_name(*args, **kwargs),
    )
)
vaults_router = _vaults_ui.router
vaults_page = _vaults_ui.endpoints["vaults_page"]
create_vault_from_ui = _vaults_ui.endpoints["create_vault_from_ui"]
create_vault_entry_from_ui = _vaults_ui.endpoints["create_vault_entry_from_ui"]
edit_vault_entry_from_ui = _vaults_ui.endpoints["edit_vault_entry_from_ui"]
reveal_vault_entry_from_ui = _vaults_ui.endpoints["reveal_vault_entry_from_ui"]
delete_vault_entry_from_ui = _vaults_ui.endpoints["delete_vault_entry_from_ui"]
delete_vault_from_ui = _vaults_ui.endpoints["delete_vault_from_ui"]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)


def automation_context(db: Session) -> dict[str, Any]:
    """Return automation context.

    Args:
        db: Active database session.
    """
    schedules = db.execute(select(Schedule).order_by(Schedule.name)).scalars().all()
    scripts = db.execute(
        select(AutomationScript).options(selectinload(AutomationScript.revisions)).order_by(AutomationScript.name)
    ).scalars().all()
    schedule_rows: list[dict[str, Any]] = []
    schedule_names = {schedule.id: schedule.name for schedule in schedules}
    for schedule in schedules:
        try:
            task_config = json.loads(schedule.task_config_json or "{}")
        except json.JSONDecodeError:
            task_config = {}
        latest_job = db.execute(select(Job).where(Job.schedule_id == schedule.id).order_by(desc(Job.created_at))).scalars().first()
        local_once = ""
        if schedule.run_once_at:
            try:
                run_once_at = schedule.run_once_at
                if run_once_at.tzinfo is None:
                    run_once_at = run_once_at.replace(tzinfo=timezone.utc)
                local_once = run_once_at.astimezone(ZoneInfo(schedule.timezone_name)).strftime("%Y-%m-%dT%H:%M")
            except ZoneInfoNotFoundError:
                local_once = run_once_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M")
        schedule_rows.append(
            {
                "id": schedule.id,
                "name": schedule.name,
                "task_type": schedule.task_type,
                "schedule": schedule.run_once_at.isoformat() if schedule.schedule_kind == "once" and schedule.run_once_at else schedule.cron_expression,
                "timezone": schedule.timezone_name,
                "enabled": schedule.enabled,
                "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else "",
                "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else "",
                "last_job_id": schedule.last_job_id,
                "last_job_status": latest_job.status if latest_job else "never",
                "task_config": task_config if isinstance(task_config, dict) else {},
                "schedule_kind": schedule.schedule_kind,
                "cron_expression": schedule.cron_expression,
                "run_once_local": local_once,
            }
        )
    execution_jobs = db.execute(
        select(Job)
        .where(Job.trigger.in_(["scheduled", "manual_schedule"]))
        .order_by(desc(Job.created_at))
        .limit(500)
    ).scalars().all()
    execution_rows: list[dict[str, Any]] = []
    for job in execution_jobs:
        result = _job_payload(job)
        try:
            task_config = json.loads(job.task_config_json or "{}")
        except json.JSONDecodeError:
            task_config = {}
        if not isinstance(task_config, dict):
            task_config = {}
        stored_schedule_id = result.get("schedule_id") or task_config.get("_schedule_id")
        schedule_id = job.schedule_id if job.schedule_id is not None else stored_schedule_id
        schedule_name = str(result.get("schedule_name") or task_config.get("_schedule_name") or schedule_names.get(schedule_id) or f"Deleted schedule #{schedule_id or 'unknown'}")
        execution_rows.append(
            {
                "id": job.id,
                "schedule_id": schedule_id,
                "schedule_name": schedule_name,
                "task_type": job.type,
                "task_label": _task_type_label(job.type),
                "trigger": job.trigger,
                "trigger_label": "Run now" if job.trigger == "manual_schedule" else "Scheduled",
                "status": str(job.status or ""),
                "status_pill": _task_status_pill(str(job.status or "")),
                "planned_for": _task_time_label(job.planned_for),
                "created_at": _task_time_label(job.created_at),
                "started_at": _task_time_label(job.started_at),
                "finished_at": _task_time_label(job.finished_at),
                "task_url": f"/tasks?job_id={quote(job.id)}",
            }
        )
    scheduled_revision_ids = {
        row["task_config"].get("revision_id")
        for row in schedule_rows
        if row["task_type"] == "managed_script"
    }
    revision_schedule_counts: dict[int, int] = {}
    enabled_revision_schedule_counts: dict[int, int] = {}
    for row in schedule_rows:
        if row["task_type"] != "managed_script":
            continue
        revision_id = row["task_config"].get("revision_id")
        if isinstance(revision_id, int):
            revision_schedule_counts[revision_id] = revision_schedule_counts.get(revision_id, 0) + 1
            if row["enabled"]:
                enabled_revision_schedule_counts[revision_id] = enabled_revision_schedule_counts.get(revision_id, 0) + 1
    script_rows: list[dict[str, Any]] = []
    revisions: list[AutomationScriptRevision] = []
    for script in scripts:
        revisions.extend(script.revisions)
        latest = script.revisions[-1] if script.revisions else None
        script_rows.append(
            {
                "id": script.id,
                "name": script.name,
                "description": script.description,
                "latest_revision": latest.revision if latest else 0,
                "latest_revision_id": latest.id if latest else None,
                "interpreter": latest.interpreter if latest else "",
                "timeout_seconds": latest.timeout_seconds if latest else 3600,
                "source_content": latest.content if latest else "",
                "revisions": [
                    {
                        "id": revision.id,
                        "revision": revision.revision,
                        "interpreter": revision.interpreter,
                        "timeout_seconds": revision.timeout_seconds,
                        "enabled": revision.enabled,
                        "content": revision.content,
                        "created_by": revision.created_by,
                        "created_at": revision.created_at.isoformat(),
                    }
                    for revision in script.revisions
                ],
                "latest_enabled": latest.enabled if latest else False,
                "enabled_revisions": sum(1 for revision in script.revisions if revision.enabled),
                "updated_at": script.updated_at.isoformat(),
                "schedule_count": sum(1 for revision in script.revisions if revision.id in scheduled_revision_ids),
            }
        )
    profiles = db.execute(select(VcfDepotDownloadProfile).order_by(VcfDepotDownloadProfile.name)).scalars().all()
    return {
        "automation_schedule_rows": schedule_rows,
        "automation_execution_rows": execution_rows,
        "automation_script_rows": script_rows,
        "automation_scripts": scripts,
        "automation_revisions": sorted(revisions, key=lambda revision: (revision.script_id, revision.revision), reverse=True),
        "automation_revision_schedule_counts": revision_schedule_counts,
        "automation_enabled_revision_schedule_counts": enabled_revision_schedule_counts,
        "automation_task_types": sorted(SCHEDULE_TASK_TYPES),
        "automation_interpreters": sorted(SCRIPT_INTERPRETERS),
        "automation_vcf_profiles": profiles,
        "automation_vcf_enabled_profile_count": sum(1 for profile in profiles if profile.enabled),
        "automation_vaults": db.execute(select(Vault).order_by(Vault.name)).scalars().all(),
        "automation_update_streams": [{"id": stream, "label": UPDATE_STREAM_LABELS[stream]} for stream in UPDATE_STREAMS],
        "system_adapter_dry_run": get_settings().dry_run_system_adapters,
    }


def _last_helper_json(value: str) -> dict[str, Any]:
    """Return the last complete JSON object embedded in helper stdout.

    Args:
        value: Helper standard output to scan.
    """
    decoder = json.JSONDecoder()
    last: dict[str, Any] = {}
    for index, character in enumerate(value or ""):
        if character != "{":
            continue
        try:
            payload, end = decoder.raw_decode(value[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and not value[index + end :].strip():
            last = payload
    return last


def execute_appliance_update_job(
    *,
    selected_stream_ids: list[str],
    settings: dict[str, str],
    actor: str,
    mode: str,
    job_id: str = "",
    credentials: dict[str, dict[str, str]] | None = None,
    before_apply: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Run appliance update job.

    Args:
        selected_stream_ids: Selected stream ids supplied by the caller.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        mode: Operating mode selected for the workflow.
        job_id: Identifier of the job.
        credentials: Credential bundle used for the immediate external request.
        before_apply: Durable phase-transition callback run before a real apply.

    Returns:
        The execute appliance update job result.
    """
    adapter = SystemAdapter()
    manifest_preview = render_update_manifest(
        selected_streams=selected_stream_ids,
        settings=settings,
        actor=actor,
        job_id=job_id,
    )
    config_path = APPLIANCE_UPDATE_STAGED_CONFIG_PATH
    credentials_path = ""
    if not adapter.dry_run:
        config_path = stage_appliance_apply_config(APPLIANCE_UPDATE_STAGED_CONFIG_PATH, manifest_preview)
        if credentials:
            credentials_path = stage_appliance_apply_config(
                APPLIANCE_UPDATE_STAGED_CREDENTIALS_PATH,
                json.dumps({"sources": credentials}, sort_keys=True),
            )

    try:
        if mode == "source_sync":
            results = [
                adapter.sync_appliance_update_sources(config_path, credentials_path)
                if credentials_path
                else adapter.sync_appliance_update_sources(config_path)
            ]
        else:
            results = [
                adapter.check_appliance_update_config(config_path, credentials_path)
                if credentials_path
                else adapter.check_appliance_update_config(config_path)
            ]
            if mode == "run" and results[-1].returncode == 0:
                if not adapter.dry_run and before_apply is not None:
                    before_apply()
                results.append(
                    adapter.apply_appliance_update_config(config_path, credentials_path)
                    if credentials_path
                    else adapter.apply_appliance_update_config(config_path)
                )
    finally:
        if credentials_path:
            Path(credentials_path).unlink(missing_ok=True)

    succeeded = all(result.returncode == 0 for result in results)
    helper_payloads = [
        payload
        for result in results
        if (payload := _last_helper_json(result.stdout))
    ]
    source_results: list[dict[str, Any]] = []
    if mode == "source_sync":
        for result in results:
            if result.dry_run:
                continue
            helper_payload = _last_helper_json(result.stdout)
            if isinstance(helper_payload.get("source_results"), list):
                source_results.extend(
                    source_result
                    for source_result in helper_payload["source_results"]
                    if isinstance(source_result, dict)
                )
    finalizer = read_appliance_file(APPLIANCE_UPDATE_FINALIZER_PATH)
    release_transaction: dict[str, Any] = {}
    if finalizer.get("available"):
        try:
            parsed_finalizer = json.loads(str(finalizer.get("content") or "{}"))
        except json.JSONDecodeError:
            parsed_finalizer = {}
        if isinstance(parsed_finalizer, dict) and (not job_id or parsed_finalizer.get("job_id") == job_id):
            release_transaction = parsed_finalizer
    unit_id = selected_stream_ids[0] if len(selected_stream_ids) == 1 else "appliance_update"
    label = UPDATE_STREAM_LABELS[unit_id] if unit_id in UPDATE_STREAM_LABELS else "Appliance Update"
    availability: dict[str, Any] = {}
    if unit_id in UPDATE_STREAM_LABELS and mode in {"check", "run"}:
        check_payload = helper_payloads[0] if helper_payloads else {}
        checks = check_payload.get("checks") if isinstance(check_payload.get("checks"), dict) else {}
        availability = normalized_availability_result(checks.get(unit_id))
        if not helper_payloads and any(result.dry_run for result in results):
            availability = normalized_availability_result(
                {
                    "state": "up_to_date",
                    "current": "Dry-run check",
                    "target": "No host query executed",
                    "summary": "Dry-run recorded command intent without changing or querying the appliance.",
                }
            )
        elif not helper_payloads and not succeeded:
            availability = normalized_availability_result(
                {
                    "state": "failed",
                    "remediation": "Review the failed check task, correct the reported prerequisite, and check again.",
                }
            )
        if mode == "check":
            unsynchronized = (
                unsynchronized_photon_repositories(settings)
                if unit_id == "photon_os"
                else unsynchronized_powershell_repositories(settings)
                if unit_id == "powershell_modules"
                else []
            )
            if unsynchronized:
                availability = normalized_availability_result(
                    {
                        "state": "failed",
                        "remediation": (
                            f"Synchronize repositories for {', '.join(unsynchronized)} "
                            f"and check {label} again."
                        ),
                    }
                )
                succeeded = False
    return {
        "unit_id": unit_id,
        "label": label,
        "mode": mode,
        "selected_streams": selected_stream_ids,
        "selected_labels": [UPDATE_STREAM_LABELS[stream] for stream in selected_stream_ids],
        "status": JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value,
        "success": succeeded,
        "dry_run": any(result.dry_run for result in results),
        "apply_started": mode == "run" and len(results) > 1 and not results[1].dry_run,
        "restart_after_commit": mode == "run"
        and succeeded
        and bool({"atlaso_release", "photon_os"} & set(selected_stream_ids)),
        "commands": [adapter_result_to_payload(result) for result in results],
        "config_path": config_path,
        "config_preview": manifest_preview,
        "release_transaction": release_transaction,
        "source_results": source_results,
        "availability": availability,
    }


def aggregate_appliance_update_results(
    *,
    selected_stream_ids: list[str],
    settings: dict[str, str],
    actor: str,
    mode: str,
    stream_results: list[dict[str, Any]],
    job_id: str = "",
    execution_order: list[str] | None = None,
) -> dict[str, Any]:
    """Return aggregate appliance update results.

    Args:
        selected_stream_ids: Selected stream ids supplied by the caller.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        mode: Operating mode selected for the workflow.
        stream_results: Stream results supplied by the caller.
        job_id: Identifier of the job.
        execution_order: Stored stream order used for execution and reporting.
    """
    selected = selected_update_streams(selected_stream_ids)
    results_by_stream = {
        str(result.get("unit_id") or ""): result
        for result in stream_results
        if str(result.get("unit_id") or "") in UPDATE_STREAM_LABELS
    }
    stored_order = [str(stream) for stream in execution_order or []]
    if len(stored_order) != len(selected) or set(stored_order) != set(selected):
        stored_order = []
        for result in stream_results:
            stream = str(result.get("unit_id") or "")
            if stream in selected and stream not in stored_order:
                stored_order.append(stream)
    ordered_results = [
        results_by_stream[stream]
        for stream in stored_order
        if stream in results_by_stream
    ]
    succeeded = len(ordered_results) == len(selected) and all(
        bool(result.get("success")) and result.get("status") == JobStatus.SUCCEEDED.value
        for result in ordered_results
    )
    release_transaction = next(
        (
            result.get("release_transaction")
            for result in ordered_results
            if isinstance(result.get("release_transaction"), dict) and result.get("release_transaction")
        ),
        {},
    )
    release_worker_restarted = bool(
        isinstance(release_transaction.get("worker_restart"), dict)
        and release_transaction["worker_restart"].get("success") is True
    )
    release_no_change = release_transaction.get("no_change") is True
    photon_succeeded = bool(
        isinstance(results_by_stream.get("photon_os"), dict)
        and results_by_stream["photon_os"].get("success") is True
        and results_by_stream["photon_os"].get("status") == JobStatus.SUCCEEDED.value
    )
    photon_apply_started = bool(
        isinstance(results_by_stream.get("photon_os"), dict)
        and results_by_stream["photon_os"].get("apply_started") is True
    )
    photon_changed = photon_succeeded or photon_apply_started
    release_restart_covers_photon = bool(
        release_worker_restarted
        and "photon_os" in stored_order
        and "atlaso_release" in stored_order
        and stored_order.index("atlaso_release") > stored_order.index("photon_os")
    )
    return {
        "unit_id": "appliance_update",
        "label": _appliance_update_task_label(mode),
        "mode": mode,
        "selected_streams": selected,
        "selected_labels": [UPDATE_STREAM_LABELS[stream] for stream in selected],
        "status": JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value,
        "success": succeeded,
        "dry_run": any(bool(result.get("dry_run")) for result in ordered_results),
        "apply_started": any(bool(result.get("apply_started")) for result in ordered_results),
        "restart_after_commit": mode == "run"
        and (
            (photon_changed and not release_restart_covers_photon)
            or (
                not release_worker_restarted
                and succeeded
                and "atlaso_release" in selected
                and not release_no_change
            )
        ),
        "release_worker_restarted": release_worker_restarted,
        "release_no_change": release_no_change,
        "commands": [
            command
            for result in ordered_results
            for command in result.get("commands", [])
            if isinstance(command, dict)
        ],
        "config_path": APPLIANCE_UPDATE_STAGED_CONFIG_PATH,
        "config_preview": render_update_manifest(
            selected_streams=selected,
            settings=settings,
            actor=actor,
            job_id=job_id,
        ),
        "release_transaction": release_transaction,
        "stream_results": {stream: results_by_stream[stream] for stream in results_by_stream},
        "configuration_fingerprints": update_stream_configuration_fingerprints(settings),
    }


def complete_appliance_update_task(db: Session, *, job: Job, update_result: dict[str, Any]) -> Job:
    """Return complete appliance update task.

    Args:
        db: Active database session.
        job: Job being processed.
        update_result: Update result supplied by the caller.
    """
    now = utcnow()
    try:
        task_config = json.loads(job.task_config_json or "{}")
    except json.JSONDecodeError:
        task_config = {}
    task_settings = task_config.get("settings") if isinstance(task_config, dict) else {}
    task_settings = task_settings if isinstance(task_settings, dict) else {}
    availability_state = appliance_update_availability_state(db)
    stream_results = update_result.get("stream_results")
    stream_results = stream_results if isinstance(stream_results, dict) else {}
    result_fingerprints = update_result.get("configuration_fingerprints")
    result_fingerprints = result_fingerprints if isinstance(result_fingerprints, dict) else {}
    if update_result.get("mode") == "check":
        for stream in selected_update_streams(update_result.get("selected_streams") or []):
            stream_result = stream_results.get(stream)
            if not isinstance(stream_result, dict):
                stream_result = update_result if update_result.get("unit_id") == stream else {}
            availability = stream_result.get("availability")
            if not isinstance(availability, dict):
                availability = {
                    "state": "failed",
                    "remediation": "Review the failed check task, correct the reported prerequisite, and check again.",
                }
            availability_state = record_update_availability_attempt(
                availability_state,
                stream=stream,
                job_id=job.id,
                checked_at=now,
                fingerprint=str(result_fingerprints.get(stream) or "")
                or update_stream_configuration_fingerprint(stream, task_settings),
                result=availability,
            )
        set_setting_value(
            db,
            APPLIANCE_UPDATE_AVAILABILITY_KEY,
            update_availability_to_json(availability_state),
        )
    elif update_result.get("mode") == "run":
        successful_streams = [
            stream
            for stream in selected_update_streams(update_result.get("selected_streams") or [])
            if isinstance(stream_results.get(stream), dict)
            and stream_results[stream].get("success") is True
            and not bool(stream_results[stream].get("dry_run"))
        ]
        if successful_streams:
            availability_state = clear_installed_update_availability(
                availability_state, successful_streams=successful_streams
            )
            set_setting_value(
                db,
                APPLIANCE_UPDATE_AVAILABILITY_KEY,
                update_availability_to_json(availability_state),
            )
    if update_result.get("mode") == "source_sync":
        reported_results = {
            str(result.get("id")): result
            for result in update_result.get("source_results", [])
            if isinstance(result, dict) and result.get("id") is not None
        }
        for source in db.execute(
            select(UpdateSource).where(
                UpdateSource.enabled.is_(True),
                UpdateSource.kind.in_(["photon", "powershell"]),
            )
        ).scalars().all():
            reported = reported_results.get(str(source.id))
            source_succeeded = bool(reported.get("success")) if reported is not None else bool(update_result["success"])
            source.validation_status = "valid" if source_succeeded else "invalid"
            source.validation_message = (
                "Source definition validated in dry-run; host package clients were not changed."
                if source_succeeded and update_result.get("dry_run")
                else "Repository synchronized with its appliance package client."
                if source_succeeded
                else "Source synchronization failed. Review the task output."
            )
            source.validated_at = now
            db.add(source)
    job.status = update_result["status"]
    job.started_at = job.started_at or now
    job.finished_at = now
    job.progress_percent = 100
    job.result = json.dumps(update_result, indent=2)
    job.error = None if update_result["success"] else appliance_update_failure_message(update_result)
    db.add(job)
    db.commit()
    should_log_final_result = not update_result.get("restart_after_commit")
    if should_log_final_result:
        if not update_result["success"]:
            log_appliance_update_failures(job.id, update_result)
        log_appliance_update_submission(job.id, update_result)
        should_log_final_result = False
    detail = " ; ".join(" ".join(command["command"]) for command in update_result["commands"])
    record_audit(
        db,
        actor=job.created_by,
        action=f"{update_result['mode']}_appliance_update",
        resource_type="job",
        resource_id=job.id,
        detail=detail,
        success=update_result["success"],
    )
    if update_result.get("restart_after_commit"):
        update_result["restart_dispatch_started_at"] = datetime.now(timezone.utc).isoformat()
        update_result["restart_scheduled"] = False
        job.result = json.dumps(update_result, indent=2)
        db.add(job)
        db.commit()
        restart_result = SystemAdapter().restart_appliance_after_update(str(update_result["config_path"]))
        update_result["commands"].append(adapter_result_to_payload(restart_result))
        update_result["restart_scheduled"] = restart_result.returncode == 0
        if restart_result.returncode != 0:
            # A synchronous helper failure proves that no delayed restart was
            # scheduled. Do not make recovery wait for an active-helper window.
            update_result.pop("restart_dispatch_started_at", None)
        update_result["success"] = bool(update_result["success"]) and restart_result.returncode == 0
        update_result["status"] = JobStatus.SUCCEEDED.value if update_result["success"] else JobStatus.FAILED.value
        job.status = update_result["status"]
        job.result = json.dumps(update_result, indent=2)
        job.error = None if update_result["success"] else "Atlaso service restart scheduling failed."
        db.add(job)
        db.commit()
        should_log_final_result = True
        record_audit(
            db,
            actor=job.created_by,
            action="schedule_appliance_update_restart",
            resource_type="job",
            resource_id=job.id,
            detail=" ".join(restart_result.command),
            success=restart_result.returncode == 0,
        )
    if should_log_final_result:
        if not update_result["success"]:
            log_appliance_update_failures(job.id, update_result)
        log_appliance_update_submission(job.id, update_result)
    return job


def appliance_update_failure_message(update_result: dict[str, Any]) -> str:
    """Handle appliance update failure message.

    Args:
        update_result: Update result consumed by appliance update failure message.
    """
    explicit = str(update_result.get("error") or "").strip()
    if explicit:
        return apply_output_excerpt(explicit, limit=2000)
    for command in update_result.get("commands", []):
        if not isinstance(command, dict) or int(command.get("returncode") or 0) == 0:
            continue
        detail = str(command.get("stderr") or "").strip()
        if detail:
            return apply_output_excerpt(detail, limit=2000)
    return "One or more appliance update steps reported a failure."


def appliance_update_exception_result(
    *,
    selected_stream_ids: list[str],
    settings: dict[str, str],
    actor: str,
    mode: str,
    exc: Exception,
) -> dict[str, Any]:
    """Return appliance update exception result.

    Args:
        selected_stream_ids: Selected stream ids supplied by the caller.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        mode: Operating mode selected for the workflow.
        exc: Exception that caused the operation to fail.
    """
    manifest_preview = render_update_manifest(selected_streams=selected_stream_ids, settings=settings, actor=actor)
    unit_id = selected_stream_ids[0] if len(selected_stream_ids) == 1 else "appliance_update"
    label = UPDATE_STREAM_LABELS[unit_id] if unit_id in UPDATE_STREAM_LABELS else "Appliance Update"
    command = ["stage-appliance-update", APPLIANCE_UPDATE_STAGED_CONFIG_PATH]
    return {
        "unit_id": unit_id,
        "label": label,
        "mode": mode,
        "selected_streams": selected_stream_ids,
        "selected_labels": [UPDATE_STREAM_LABELS[stream] for stream in selected_stream_ids],
        "status": JobStatus.FAILED.value,
        "success": False,
        "dry_run": get_settings().dry_run_system_adapters,
        "restart_after_commit": False,
        "commands": [
            {
                "command": command,
                "command_line": " ".join(command),
                "dry_run": get_settings().dry_run_system_adapters,
                "stdout": "",
                "stderr": str(exc),
                "returncode": 1,
            }
        ],
        "config_path": APPLIANCE_UPDATE_STAGED_CONFIG_PATH,
        "config_preview": manifest_preview,
        "error": str(exc),
    }


def adapter_result_to_payload(result: Any) -> dict[str, Any]:
    """Return adapter result to payload.

    Args:
        result: Operation result being inspected or returned.
    """
    return {
        "command": result.command,
        "command_line": " ".join(result.command),
        "dry_run": result.dry_run,
        "stdout": apply_output_excerpt(result.stdout),
        "stderr": apply_output_excerpt(result.stderr),
        "returncode": result.returncode,
    }


def management_handoff_result_evidence(result: Any) -> dict[str, Any]:
    """Return the last bounded management-handoff object from helper output.

    Args:
        result: Management handoff adapter result.

    Returns:
        Parsed non-secret helper evidence, or an empty object.
    """
    for stream in (result.stdout, result.stderr):
        for line in reversed((stream or "").splitlines()):
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict) and "management_handoff" in candidate:
                return candidate
    return {}


def apply_output_excerpt(value: str, *, limit: int = 2400) -> str:
    """Update output excerpt.

    Args:
        value: Candidate value consumed by apply output excerpt.
        limit: Limit consumed by apply output excerpt.


    Returns:
        The apply output excerpt result.
    """
    redacted = redact_config_preview(value or "").strip()
    if len(redacted) <= limit:
        return redacted
    return f"{redacted[:limit].rstrip()}\n... output truncated ..."


def log_appliance_update_failures(job_id: str, update_result: dict[str, Any]) -> None:
    """Handle log appliance update failures.

    Args:
        job_id: Stable identifier of the associated job resource.
        update_result: Update result consumed by log appliance update failures.
    """
    for command in update_result.get("commands", []):
        if int(command.get("returncode") or 0) == 0:
            continue
        APPLIANCE_UPDATE_LOGGER.error(
            "Appliance update task %s failed mode=%s streams=%s command=%s returncode=%s stderr=%s stdout=%s",
            job_id,
            update_result.get("mode") or "",
            ",".join(str(stream) for stream in update_result.get("selected_streams", [])),
            apply_output_excerpt(str(command.get("command_line") or " ".join(command.get("command") or [])), limit=800),
            command.get("returncode"),
            apply_output_excerpt(str(command.get("stderr") or "")),
            apply_output_excerpt(str(command.get("stdout") or "")),
        )


def log_appliance_update_submission(job_id: str, update_result: dict[str, Any]) -> None:
    """Handle log appliance update submission.

    Args:
        job_id: Stable identifier of the associated job resource.
        update_result: Update result consumed by log appliance update submission.
    """
    APPLIANCE_UPDATE_LOGGER.info(
        "Appliance update task %s completed status=%s mode=%s streams=%s dry_run=%s config_path=%s",
        job_id,
        update_result.get("status") or "",
        update_result.get("mode") or "",
        ",".join(str(stream) for stream in update_result.get("selected_streams", [])),
        bool(update_result.get("dry_run")),
        update_result.get("config_path") or "",
    )
    for command in update_result.get("commands", []):
        APPLIANCE_UPDATE_LOGGER.info(
            "Appliance update task %s command=%s returncode=%s dry_run=%s",
            job_id,
            apply_output_excerpt(str(command.get("command_line") or " ".join(command.get("command") or [])), limit=800),
            command.get("returncode"),
            bool(command.get("dry_run")),
        )


def filesystem_path(path: Path | PurePosixPath) -> Path:
    """Return filesystem path.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    return path if isinstance(path, Path) else Path(path)


LOG_LINE_OPTIONS = {100, 200, 500}


def normalized_log_line_count(value: int) -> int:
    """Return normalized log line count.

    Args:
        value: Candidate value consumed by normalized log line count.
    """
    return value if value in LOG_LINE_OPTIONS else 100


def tail_fixed_log_file(path: Path | PurePosixPath, *, max_bytes: int = 256 * 1024, max_lines: int = 100) -> dict[str, Any]:
    """Return tail fixed log file.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        max_bytes: Maximum accepted payload size in bytes.
        max_lines: Max lines supplied by the caller.
    """
    read_path = filesystem_path(path)
    try:
        if not read_path.exists():
            return {"path": str(path), "available": False, "lines": [], "size_bytes": 0, "updated_at": "", "error": ""}
        size = read_path.stat().st_size
        with read_path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
            raw = handle.read(max_bytes)
    except OSError as exc:
        return {"path": str(path), "available": False, "lines": [], "size_bytes": 0, "updated_at": "", "error": str(exc)}
    text = raw.decode("utf-8", errors="replace")
    all_lines = redact_config_preview(text).splitlines()
    lines = all_lines[-max_lines:]
    updated_at = utcnow()
    try:
        updated_at = datetime.fromtimestamp(read_path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        pass
    return {
        "path": str(path),
        "available": True,
        "lines": lines,
        "size_bytes": size,
        "updated_at": updated_at.isoformat(),
        "truncated": size > max_bytes or len(all_lines) > max_lines,
    }


def journal_log_source(
    source_id: str,
    label: str,
    unit: str,
    result: AdapterResult,
    *,
    max_lines: int,
    line_filter: Callable[[str], bool] | None = None,
    path_label: str | None = None,
) -> dict[str, Any]:
    """Return journal log source.

    Args:
        source_id: Identifier of the source.
        label: Human-readable label used in validation output.
        unit: Appliance Apply unit being processed.
        result: Operation result to summarize, validate, or persist.
        max_lines: Max lines supplied by the caller.
        line_filter: Line filter supplied by the caller.
        path_label: Path label supplied by the caller.
    """
    available = result.returncode == 0 and not result.dry_run
    text = redact_config_preview(result.stdout or "") if available else ""
    all_lines = text.splitlines()
    if line_filter is not None:
        all_lines = [line for line in all_lines if line_filter(line)]
    return {
        "id": source_id,
        "label": label,
        "path": path_label or f"systemd journal: {unit}",
        "available": available,
        "lines": all_lines[-max_lines:],
        "size_bytes": len(text.encode("utf-8")),
        "updated_at": "",
        "truncated": len(all_lines) > max_lines,
        "error": "" if available else redact_config_preview(result.stderr or result.stdout or ""),
    }


def dnsmasq_log_category(line: str) -> str:
    """Return dnsmasq log category.

    Args:
        line: Source or output line being parsed.
    """
    if re.search(r"\bdnsmasq-dhcp(?:\[\d+\])?:", line):
        return "dhcp"
    if re.search(r"\bdnsmasq-tftp(?:\[\d+\])?:", line):
        return "tftp"
    return "dns"


def log_sources_context(*, max_lines: int = 100) -> list[dict[str, Any]]:
    """Return log sources context.

    Args:
        max_lines: Max lines consumed by log sources context.
    """
    line_count = normalized_log_line_count(max_lines)
    adapter = SystemAdapter()
    dnsmasq_logs = adapter.read_dnsmasq_logs()
    return [
        {
            "id": "app",
            "label": "Atlaso App",
            **tail_fixed_log_file(ATLASO_APP_LOG_PATH, max_lines=line_count),
        },
        journal_log_source(
            "dnsmasq-dns",
            "DNS",
            "dnsmasq.service",
            dnsmasq_logs,
            max_lines=line_count,
            line_filter=lambda line: dnsmasq_log_category(line) == "dns",
            path_label="dnsmasq.service journal: DNS and service messages",
        ),
        journal_log_source(
            "dnsmasq-dhcp",
            "DHCP",
            "dnsmasq.service",
            dnsmasq_logs,
            max_lines=line_count,
            line_filter=lambda line: dnsmasq_log_category(line) == "dhcp",
            path_label="dnsmasq.service journal: DHCP messages",
        ),
        journal_log_source(
            "dnsmasq-tftp",
            "TFTP",
            "dnsmasq.service",
            dnsmasq_logs,
            max_lines=line_count,
            line_filter=lambda line: dnsmasq_log_category(line) == "tftp",
            path_label="dnsmasq.service journal: TFTP messages",
        ),
        journal_log_source(
            "ldap",
            "LDAP / LDAPS",
            "slapd.service",
            adapter.read_ldap_logs(),
            max_lines=line_count,
            path_label="slapd.service journal: LDAP and LDAPS directory events",
        ),
        journal_log_source("ntp", "NTP / NTS", "ntpd.service", adapter.read_ntpd_logs(), max_lines=line_count),
        journal_log_source("esx-storage", "ESX Storage NFS", "nfs-server.service", adapter.esx_storage_logs(), max_lines=line_count),
        journal_log_source("nginx", "Nginx", "nginx.service", adapter.read_nginx_logs(), max_lines=line_count),
        journal_log_source(
            "nginx-access",
            "HTTP Access",
            "nginx.service",
            adapter.read_nginx_access_logs(),
            max_lines=line_count,
            path_label="/var/log/nginx/access.log · management and service HTTP requests",
        ),
        journal_log_source(
            "nginx-error",
            "HTTP Errors",
            "nginx.service",
            adapter.read_nginx_error_logs(),
            max_lines=line_count,
            path_label="/var/log/nginx/error.log · management and service HTTP errors",
        ),
        {
            "id": "kms",
            "label": "KMS",
            **tail_fixed_log_file(KMS_SERVER_LOG_PATH, max_lines=line_count),
        },
    ]


def logs_context(db: Session, *, max_lines: int = 100) -> dict[str, Any]:
    """Return logs context.

    Args:
        db: Active database session.
        max_lines: Max lines supplied by the caller.
    """
    line_count = normalized_log_line_count(max_lines)
    return {
        "log_sources": log_sources_context(max_lines=line_count),
        "log_line_count": line_count,
    }


def audit_event_rows_context(db: Session, *, limit: int = 500) -> list[dict[str, Any]]:
    """Return audit event rows context.

    Args:
        db: Active database session.
        limit: Limit supplied by the caller.
    """
    events = db.execute(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(limit)).scalars().all()
    return [
        {
            "id": event.id,
            "created_at": event.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "actor": event.actor,
            "action": event.action,
            "resource": f"{event.resource_type}:{event.resource_id}" if event.resource_id else event.resource_type,
            "success": event.success,
            "detail": event.detail or "",
        }
        for event in events
    ]


def appliance_apply_failure_summaries(unit_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return appliance apply failure summaries.

    Args:
        unit_results: Unit results consumed by appliance apply failure summaries.
    """
    summaries: list[dict[str, Any]] = []
    for unit in unit_results:
        failed_commands = []
        for command in unit.get("commands", []):
            if int(command.get("returncode") or 0) == 0:
                continue
            failed_commands.append(
                {
                    "command_line": apply_output_excerpt(str(command.get("command_line") or ""), limit=800),
                    "returncode": command.get("returncode"),
                    "stdout": apply_output_excerpt(str(command.get("stdout") or "")),
                    "stderr": apply_output_excerpt(str(command.get("stderr") or "")),
                }
            )
        if failed_commands:
            summaries.append(
                {
                    "unit_id": unit.get("unit_id"),
                    "label": unit.get("label") or unit.get("unit_id"),
                    "commands": failed_commands,
                }
            )
    return summaries


def log_appliance_apply_failures(job_id: str, unit_results: list[dict[str, Any]]) -> None:
    """Handle log appliance apply failures.

    Args:
        job_id: Stable identifier of the associated job resource.
        unit_results: Unit results consumed by log appliance apply failures.
    """
    if appliance_apply_failure_summaries(unit_results):
        APPLY_LOGGER.error(
            "Appliance apply task %s failed; helper and desired-state details omitted from operational logs.",
            job_id,
        )


def log_appliance_apply_submission(
    job_id: str,
    *,
    selected_units: list[str],
    skipped_changed_units: list[dict[str, Any]],
    unit_results: list[dict[str, Any]],
    succeeded: bool,
) -> None:
    """Handle log appliance apply submission.

    Args:
        job_id: Identifier of the job.
        selected_units: Selected units supplied by the caller.
        skipped_changed_units: Skipped changed units supplied by the caller.
        unit_results: Unit results supplied by the caller.
        succeeded: Succeeded supplied by the caller.
    """
    if succeeded:
        APPLY_LOGGER.info(
            "Appliance apply task %s succeeded; desired-state and helper details omitted from operational logs.",
            job_id,
        )
    else:
        APPLY_LOGGER.info(
            "Appliance apply task %s failed; desired-state and helper details omitted from operational logs.",
            job_id,
        )


def _write_staged_config_file(path: Path, config_preview: str) -> None:
    """Persist staged config file.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        config_preview: Rendered configuration text approved for staging.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    file_descriptor = -1
    try:
        file_descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            file_descriptor = -1
            # The constrained helper requires transient file input; mode and terminal cleanup are enforced below.
            # codeql[py/clear-text-storage-sensitive-data]
            handle.write(config_preview)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.chmod(0o600)
        temp_path.replace(path)
        path.chmod(0o600)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if temp_path.exists():
            temp_path.unlink()


def stage_appliance_apply_config(config_path: str, config_preview: str) -> str:
    """Return stage appliance apply config.

    Args:
        config_path: Filesystem path for the config.
        config_preview: Rendered configuration text approved for staging.

    Raises:
        PermissionError: If the operation lacks the required permission.
    """
    path = Path(config_path)
    try:
        _write_staged_config_file(path, config_preview)
    except PermissionError as exc:
        repair = SystemAdapter().prepare_apply_staging_path(str(path))
        if repair.returncode != 0:
            detail = (repair.stderr or repair.stdout or "apply staging ownership repair failed").strip()
            raise PermissionError(f"Unable to prepare apply staging path {path}: {detail}") from exc
        _write_staged_config_file(path, config_preview)
    return str(path)


def cleanup_transient_secret_staging_files() -> None:
    """Remove transient secret staging files.

    Raises:
        PermissionError: If the operation lacks the required permission.
    """
    adapter = SystemAdapter()
    for path_value in (
        LOCAL_USERS_STAGED_CONFIG_PATH,
        CA_STAGED_CONFIG_PATH,
        LDAP_STAGED_CONFIG_PATH,
        FACTORY_RESET_STAGED_CREDENTIALS_PATH,
    ):
        staged_path = Path(path_value)
        if not adapter.dry_run:
            repair = adapter.prepare_apply_staging_path(str(staged_path))
            if repair.returncode != 0:
                detail = (repair.stderr or repair.stdout or "apply staging ownership repair failed").strip()
                raise PermissionError(f"Unable to prepare transient staging cleanup for {staged_path}: {detail}")
        staged_path.unlink(missing_ok=True)
        for temp_path in staged_path.parent.glob(f".{staged_path.name}.*.tmp"):
            temp_path.unlink(missing_ok=True)
    factory_reset_template = Path(FACTORY_RESET_STAGED_CREDENTIALS_PATH)
    request_name_pattern = re.compile(
        rf"^{re.escape(factory_reset_template.stem)}-[0-9a-f]{{32}}{re.escape(factory_reset_template.suffix)}$"
    )
    request_temp_name_pattern = re.compile(
        rf"^\.{re.escape(factory_reset_template.stem)}-[0-9a-f]{{32}}"
        rf"{re.escape(factory_reset_template.suffix)}\.[0-9a-f]{{32}}\.tmp$"
    )
    for request_path in factory_reset_template.parent.glob(
        f"{factory_reset_template.stem}-*{factory_reset_template.suffix}"
    ):
        if request_name_pattern.fullmatch(request_path.name):
            request_path.unlink(missing_ok=True)
    for request_temp_path in factory_reset_template.parent.glob(
        f".{factory_reset_template.stem}-*{factory_reset_template.suffix}.*.tmp"
    ):
        if request_temp_name_pattern.fullmatch(request_temp_path.name):
            request_temp_path.unlink(missing_ok=True)
    local_users_path = Path(LOCAL_USERS_STAGED_CONFIG_PATH)
    for status_path in local_users_path.parent.glob(
        f".{local_users_path.stem}.status-*{local_users_path.suffix}"
    ):
        status_path.unlink(missing_ok=True)
    for status_temp_path in local_users_path.parent.glob(
        f"..{local_users_path.stem}.status-*{local_users_path.suffix}.*.tmp"
    ):
        status_temp_path.unlink(missing_ok=True)


def synchronize_routing_service_runtime(
    db: Session,
    *,
    routing_enabled: bool,
) -> None:
    """Publish the successfully applied Routing runtime state."""
    routing_service = db.execute(
        select(ServiceState).where(ServiceState.service == "routing")
    ).scalar_one_or_none()
    if routing_service is None:
        return
    routing_service.enabled = routing_enabled
    routing_service.running = routing_enabled
    routing_service.health = "healthy" if routing_enabled else "disabled"
    db.add(routing_service)


def execute_appliance_apply_unit(
    unit: dict[str, Any],
    *,
    adapter: SystemAdapter | None = None,
    db: Session | None = None,
) -> dict[str, Any]:
    """Run appliance apply unit.

    Args:
        unit: Unit consumed by execute appliance apply unit.
        adapter: Adapter consumed by execute appliance apply unit.
        db: Active database session for successful apply bookkeeping.


    Returns:
        The execute appliance apply unit result.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    context = unit["context"]
    adapter = adapter or SystemAdapter()
    unit_id = unit["id"]

    def run_adapter_steps(steps: list[Any]) -> list[Any]:
        """Run adapter steps.

        Args:
            steps: Steps consumed by run adapter steps.


        Returns:
            The run adapter steps result.
        """
        results = []
        for step in steps:
            result = step()
            results.append(result)
            if result.returncode != 0:
                break
        return results

    def run_secret_config_steps(
        staged_path: str,
        config_preview: str,
        steps_for_path: Any,
    ) -> list[Any]:
        """Run secret config steps.

        Args:
            staged_path: Filesystem path for the staged.
            config_preview: Rendered configuration text approved for staging.
            steps_for_path: Filesystem path for the steps for.

        Returns:
            The run secret config steps result.
        """
        if adapter.dry_run:
            return run_adapter_steps(steps_for_path(staged_path))
        try:
            config_path = stage_appliance_apply_config(staged_path, config_preview)
            return run_adapter_steps(steps_for_path(config_path))
        finally:
            Path(staged_path).unlink(missing_ok=True)

    if unit_id == "local_users":
        results = run_secret_config_steps(
            LOCAL_USERS_STAGED_CONFIG_PATH,
            unit["raw_config_preview"],
            lambda config_path: [
                lambda: adapter.validate_local_users_config(config_path),
                lambda: adapter.apply_local_users_config(config_path),
            ],
        )
    elif unit_id == "appliance_settings":
        settings = context["appliance_settings"]
        config_path = settings.config_path
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(APPLIANCE_SETTINGS_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_appliance_settings_config(config_path),
                lambda: adapter.apply_appliance_settings_config(config_path),
            ]
        )
    elif unit_id == "network":
        config_path = context["network_config_path"]
        if not adapter.dry_run:
            config_preview = network_config_with_removed_vlans(unit["raw_config_preview"], unit.get("removed_vlan_interfaces", []))
            config_path = stage_appliance_apply_config(NETWORK_STAGED_CONFIG_PATH, config_preview)
        results = run_adapter_steps(
            [
                lambda: adapter.validate_network_config(config_path),
                lambda: adapter.apply_network_config(config_path),
            ]
        )
    elif unit_id == "wan":
        config_path = context["wan_config_path"]
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(WAN_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_wan_config(config_path),
                lambda: adapter.apply_wan_config(config_path),
            ]
        )
    elif unit_id == "firewall":
        settings = context["firewall_settings"]
        config_path = settings.config_path
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(FIREWALL_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_firewall_config(config_path),
                lambda: adapter.apply_firewall_config(config_path),
            ]
        )
    elif unit_id == "dnsmasq":
        config_path = context["dns_settings"].config_path
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(DNSMASQ_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_dnsmasq_config(config_path),
                lambda: adapter.apply_dnsmasq_config(config_path),
                adapter.reload_dnsmasq,
            ]
        )
    elif unit_id == "esxi_pxe":
        config_path = context["esxi_pxe_config_path"]
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(ESXI_PXE_STAGED_CONFIG_PATH, context["esxi_pxe_manifest"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_esxi_pxe_config(config_path),
                lambda: adapter.apply_esxi_pxe_config(config_path),
            ]
        )
    elif unit_id == "esx_storage":
        config_path = ESX_STORAGE_STAGED_CONFIG_PATH
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(ESX_STORAGE_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_esx_storage_config(config_path),
                lambda: adapter.apply_esx_storage_config(config_path),
            ]
        )
    elif unit_id == "ca":
        results = run_secret_config_steps(
            CA_STAGED_CONFIG_PATH,
            render_ca_apply_payload(context["ca_settings"], context["ca_certificates"], include_private_keys=True),
            lambda config_path: [
                lambda: adapter.validate_ca_config(config_path),
                lambda: adapter.apply_ca_config(config_path),
            ],
        )
    elif unit_id == "kms":
        config_path = KMS_STAGED_CONFIG_PATH
        if not adapter.dry_run:
            stage_appliance_apply_config(
                KMS_STAGED_CLIENT_TRUST_PATH,
                context["kms_client_trust_bundle"],
            )
            config_path = stage_appliance_apply_config(KMS_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_kms_config(config_path),
                lambda: adapter.apply_kms_config(config_path),
            ]
        )
    elif unit_id == "ldap":
        results = run_secret_config_steps(
            LDAP_STAGED_CONFIG_PATH,
            unit["raw_config_preview"],
            lambda config_path: [
                lambda: adapter.validate_ldap_config(config_path),
                lambda: adapter.apply_ldap_config(config_path),
            ],
        )
    elif unit_id == "ntpd":
        config_path = NTP_STAGED_CONFIG_PATH
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(NTP_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_ntpd_config(config_path),
                lambda: adapter.apply_ntpd_config(config_path),
            ]
        )
    elif unit_id == "vcf_backups":
        settings = context["vcf_backup_settings"]
        config_path = settings.config_path
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(VCF_BACKUP_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_vcf_backup_config(config_path),
                lambda: adapter.apply_vcf_backup_config(config_path),
            ]
        )
    elif unit_id == "vcf_offline_depot":
        settings = context["vcf_depot_settings"]
        software_depot_id = str(context["vcf_depot_software_depot_id"].get("id") or "").strip()
        refresh_software_depot_id = bool(unit.get("refresh_vcf_depot_software_depot_id"))
        software_depot_id_only = bool(unit.get("vcf_depot_id_only"))
        config_path = settings.config_path
        properties_path = VCF_DEPOT_STAGED_APPLICATION_PROPERTIES_PATH
        if not adapter.dry_run:
            if not software_depot_id_only:
                config_path = stage_appliance_apply_config(VCF_DEPOT_STAGED_CONFIG_PATH, context["vcf_depot_https_config_preview"])
            properties_path = stage_appliance_apply_config(
                VCF_DEPOT_STAGED_APPLICATION_PROPERTIES_PATH,
                str(context["vcf_depot_application_properties"].get("content") or ""),
            )
        if software_depot_id_only:
            steps = [
                lambda: adapter.stage_vcf_offline_depot_tool(settings.tool_archive_path),
                lambda: adapter.apply_vcf_offline_depot_application_properties(properties_path),
                lambda: adapter.apply_vcf_offline_depot_ceip(bool(context["vmware_ceip_enabled"])),
                lambda: adapter.generate_vcf_offline_depot_software_depot_id(),
            ]
        else:
            steps = [lambda: adapter.validate_vcf_offline_depot_config(config_path)]
        if not software_depot_id_only and settings.tool_archive_path:
            steps.extend(
                [
                    lambda: adapter.stage_vcf_offline_depot_tool(settings.tool_archive_path),
                    lambda: adapter.apply_vcf_offline_depot_application_properties(properties_path),
                    lambda: adapter.apply_vcf_offline_depot_ceip(bool(context["vmware_ceip_enabled"])),
                ]
            )
            if not software_depot_id or refresh_software_depot_id:
                steps.append(lambda: adapter.generate_vcf_offline_depot_software_depot_id())
        elif not software_depot_id_only and not settings.tool_archive_path:
            steps.append(lambda: adapter.reset_vcf_offline_depot_tool())
        if not software_depot_id_only:
            steps.extend(
                [
                    lambda: adapter.sync_vcf_offline_depot(config_path),
                    lambda: adapter.apply_vcf_offline_depot_https_config(config_path),
                ]
            )
        results = run_adapter_steps(steps)
    elif unit_id == "vcf_private_registry":
        settings = context["vcf_registry_settings"]
        results = run_adapter_steps(
            [
                lambda: adapter.validate_vcf_private_registry_config(settings.config_path),
                lambda: adapter.apply_vcf_private_registry_config(settings.config_path),
                lambda: adapter.relocate_vcf_private_registry_bundles(settings.config_path),
            ]
        )
    elif unit_id == "public_services":
        config_path = context["public_service_config_path"]
        if not adapter.dry_run:
            config_path = stage_appliance_apply_config(PUBLIC_SERVICES_STAGED_CONFIG_PATH, unit["raw_config_preview"])
        results = run_adapter_steps(
            [
                lambda: adapter.validate_public_services_config(config_path),
                lambda: adapter.apply_public_services_config(config_path),
            ]
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown apply unit {unit_id}.")

    succeeded = all(result.returncode == 0 for result in results)
    if unit_id == "local_users" and not any(result.dry_run for result in results):
        users = list(context["local_users"])
        if succeeded:
            mark_local_users_applied(users)
        else:
            error = "\n".join(result.stderr for result in results if result.stderr).strip() or "Local user OS sync failed."
            mark_local_users_failed(users, error)
    if unit_id == "esxi_pxe" and succeeded and not any(result.dry_run for result in results):
        if db is None:
            raise RuntimeError("A database session is required to finalize an ESXi PXE apply.")
        db.execute(delete(NetworkBootEsxiBootCapability))
        mark_kickstarts_applied(list(context["esxi_kickstarts"]))
    if unit_id == "kms" and succeeded and not any(result.dry_run for result in results):
        applied_at = utcnow()
        for provider in context["vsphere_key_providers"]:
            provider.applied_at = applied_at
    if unit_id == "wan" and succeeded and not any(result.dry_run for result in results):
        if db is None:
            raise RuntimeError("A database session is required to finalize a Routes and WAN apply.")
        synchronize_routing_service_runtime(
            db,
            routing_enabled=context["routes_wan_settings"].routing_enabled,
        )
    if (
        unit_id == "ldap"
        and context["ldap_settings"].enabled
        and succeeded
        and not any(result.dry_run for result in results)
    ):
        mark_ldap_apply_complete(
            [user for organization in context["ldap_organizations"] for user in organization.users]
        )
        recovery_archive = context.get("ldap_recovery_archive")
        if recovery_archive is not None:
            recovery_archive.state = "applied"
            recovery_archive.applied_at = utcnow()
            clear_ldap_recovery_payload(recovery_archive)
    unit_result = {
        "unit_id": unit_id,
        "label": unit["label"],
        "status": JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value,
        "success": succeeded,
        "dry_run": any(result.dry_run for result in results),
        "commands": [adapter_result_to_payload(result) for result in results],
        "summary": unit["summary"],
        "validation_errors": unit["validation_errors"],
        "validation_warnings": unit["validation_warnings"],
        "removed_vlan_interfaces": unit.get("removed_vlan_interfaces", []),
        "generated_files": [str(generated_kickstart_path(row.id, row.content_hash)) for row in context.get("esxi_kickstarts", []) if row.enabled],
        "config_path": unit["config_path"],
        "config_preview": unit["config_preview"],
        "config_diff": unit["config_diff"],
    }
    if unit_id == "appliance_settings":
        management_status_transition = appliance_settings_management_status_transition(results)
        if management_status_transition is not None:
            unit_result["management_status_transition"] = management_status_transition
    return unit_result


def execute_management_handoff(
    units_by_id: dict[str, dict[str, Any]],
    *,
    job_id: str,
    adapter: SystemAdapter | None = None,
    db: Session,
    include_wan: bool | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute management-affecting apply units as one recoverable transaction.

    Args:
        units_by_id: Current apply units keyed by stable identifier.
        job_id: Appliance Apply task identifier.
        adapter: System adapter used for helper execution.
        db: Active database session.
        include_wan: Whether the captured WAN unit participates in the transaction.

    Returns:
        The group result and one truthful result per bundled apply unit.
    """
    adapter = adapter or SystemAdapter()
    network = units_by_id["network"]
    settings = units_by_id["appliance_settings"]
    firewall = units_by_id["firewall"]
    public_services = units_by_id["public_services"]
    ca = units_by_id["ca"]
    wan_required = (
        bool(include_wan)
        if include_wan is not None
        else bool(
            network.get("management_gateway_route_migrations")
            or network.get("management_default_mirror_change")
        )
    )
    wan = units_by_id["wan"] if wan_required else None
    handoff_unit_ids = (
        *MANAGEMENT_HANDOFF_UNIT_IDS,
        *(("wan",) if wan_required else ()),
    )
    baselines = load_appliance_apply_baselines(db)
    previous_paths = list(network.get("previous_management_paths") or [])
    previous_addresses: list[str] = []
    previous_interfaces: list[str] = []
    previous_parent_interfaces: list[str] = []
    for path in previous_paths:
        parent = str(path.get("parent") or "")
        if parent and parent not in previous_parent_interfaces:
            previous_parent_interfaces.append(parent)
        name = str(path.get("name") or "")
        if name and name not in previous_interfaces:
            previous_interfaces.append(name)
        for field in ("ip_cidr", "ipv6_cidr"):
            value = str(path.get(field) or "")
            if value:
                previous_addresses.append(str(ip_interface(value).ip))
    previous_settings = json_config_object(
        str((baselines.get("appliance_settings") or {}).get("config_preview") or "")
    )
    manifest_path = MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH
    ca_path = CA_STAGED_CONFIG_PATH
    if not adapter.dry_run:
        network_preview = network_config_with_removed_vlans(
            network["raw_config_preview"],
            network.get("removed_vlan_interfaces", []),
        )
        network_path = stage_appliance_apply_config(NETWORK_STAGED_CONFIG_PATH, network_preview)
        firewall_path = stage_appliance_apply_config(
            FIREWALL_STAGED_CONFIG_PATH,
            firewall["raw_config_preview"],
        )
        settings_path = stage_appliance_apply_config(
            APPLIANCE_SETTINGS_STAGED_CONFIG_PATH,
            settings["raw_config_preview"],
        )
        public_path = stage_appliance_apply_config(
            PUBLIC_SERVICES_STAGED_CONFIG_PATH,
            public_services["raw_config_preview"],
        )
        wan_path = ""
        wan_rollback_path = ""
        if wan is not None:
            wan_path = stage_appliance_apply_config(
                str(wan["config_path"]),
                str(wan["raw_config_preview"]),
            )
            wan_rollback_path = stage_appliance_apply_config(
                MANAGEMENT_HANDOFF_WAN_ROLLBACK_PATH,
                wan_rollback_config_preview(
                    str(wan["raw_config_preview"]),
                    baselines.get("wan"),
                ),
            )
        manifest_staged = False
        try:
            ca_context_value = ca["context"]
            ca_path = stage_appliance_apply_config(
                CA_STAGED_CONFIG_PATH,
                render_ca_apply_payload(
                    ca_context_value["ca_settings"],
                    ca_context_value["ca_certificates"],
                    include_private_keys=True,
                ),
            )
            manifest = {
                "schema_version": 1,
                "job_id": job_id,
                "network_config_path": network_path,
                "firewall_config_path": firewall_path,
                "appliance_settings_config_path": settings_path,
                "public_services_config_path": public_path,
                "ca_config_path": ca_path,
                "wan_config_path": wan_path,
                "wan_rollback_config_path": wan_rollback_path,
                "previous_management_interfaces": previous_interfaces,
                "previous_management_parent_interfaces": previous_parent_interfaces,
                "previous_management_addresses": list(dict.fromkeys(previous_addresses)),
                "previous_management_paths": [
                    {
                        "name": str(path.get("name") or ""),
                        "ipv4_method": str(path.get("ipv4_method") or ""),
                        "ipv6_enabled": str(path.get("ipv6_enabled") or ""),
                        "ipv6_cidr": str(path.get("ipv6_cidr") or ""),
                    }
                    for path in previous_paths
                ],
                "previous_https_enabled": bool(
                    previous_settings.get("management_https_enabled", True)
                ),
                "previous_management_public_port": int(
                    previous_settings.get(
                        "management_public_https_port"
                        if previous_settings.get("management_https_enabled", True)
                        else "management_public_http_port",
                        443 if previous_settings.get("management_https_enabled", True) else 80,
                    )
                ),
            }
            manifest_path = stage_appliance_apply_config(
                MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH,
                json.dumps(manifest, indent=2, sort_keys=True),
            )
            manifest_staged = True
        finally:
            if not manifest_staged:
                Path(ca_path).unlink(missing_ok=True)
    results: list[AdapterResult] = []
    recovery_result: AdapterResult | None = None
    try:
        results = [adapter.validate_management_handoff(manifest_path)]
        if results[0].returncode == 0:
            results.append(adapter.apply_management_handoff(manifest_path))
            if not adapter.dry_run and results[-1].returncode != 0:
                recovery_result = adapter.recover_management_handoff()
    finally:
        if not adapter.dry_run:
            Path(ca_path).unlink(missing_ok=True)
    succeeded = bool(results) and all(result.returncode == 0 for result in results)
    apply_result = results[1] if len(results) > 1 else None
    evidence = next(
        (
            parsed
            for result in reversed(results)
            if (parsed := management_handoff_result_evidence(result))
        ),
        {},
    )
    recovery_evidence = (
        management_handoff_result_evidence(recovery_result)
        if recovery_result is not None
        else {}
    )
    if apply_result is not None and apply_result.returncode == 124 and not evidence.get("failing_layer"):
        evidence = {
            **evidence,
            "failing_layer": "handoff helper wait",
            "error": "Management handoff helper wait timed out; immediate recovery was attempted.",
        }
    apply_rolled_back = bool(evidence.get("rolled_back")) or evidence.get("management_handoff") == "rolled back"
    if recovery_evidence:
        evidence = {**evidence, "recovery": recovery_evidence}
        if recovery_result is not None and recovery_result.returncode == 0 and recovery_evidence.get("rolled_back") is True:
            evidence = {
                **evidence,
                "management_handoff": "rolled back",
                "rolled_back": True,
            }
    recovery_rolled_back = bool(
        recovery_result is not None
        and recovery_result.returncode == 0
        and recovery_evidence.get("rolled_back") is True
    )
    rolled_back = apply_rolled_back or recovery_rolled_back
    recovery_state = str(recovery_evidence.get("management_handoff") or "")
    rollback_proven = (
        apply_result is None
        or apply_rolled_back
        or recovery_rolled_back
        or bool(
            recovery_result is not None
            and recovery_result.returncode == 0
            and recovery_state == "no interrupted transaction"
        )
    )
    if not succeeded and apply_result is not None and not rollback_proven:
        evidence = {
            **evidence,
            "failing_layer": str(evidence.get("failing_layer") or "interruption recovery"),
            "error": str(
                evidence.get("error")
                or "Management handoff failed and immediate recovery could not be proven."
            ),
        }
    if wan is not None and succeeded and not any(result.dry_run for result in results):
        synchronize_routing_service_runtime(
            db,
            routing_enabled=wan["context"]["routes_wan_settings"].routing_enabled,
        )
    group_result = {
        "success": succeeded,
        "dry_run": any(result.dry_run for result in results),
        "commands": [
            adapter_result_to_payload(result)
            for result in [*results, *([recovery_result] if recovery_result is not None else [])]
        ],
        "management_handoff": evidence or {
            "management_handoff": "committed" if succeeded else "failed before bounded helper evidence"
        },
        "rollback_proven": rollback_proven,
    }
    failure_layer = str(group_result["management_handoff"].get("failing_layer") or "")
    failure_error = str(group_result["management_handoff"].get("error") or "")
    unit_results = []
    for unit_id in handoff_unit_ids:
        unit = units_by_id[unit_id]
        unit_results.append(
            {
                "unit_id": unit_id,
                "label": unit["label"],
                "status": JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value,
                "success": succeeded,
                "dry_run": group_result["dry_run"],
                "commands": group_result["commands"] if unit_id == "network" else [],
                "management_handoff": group_result["management_handoff"],
                "failing_layer": failure_layer,
                "rolled_back": rolled_back,
                "rollback_proven": rollback_proven,
                "error": failure_error if not succeeded else "",
                "summary": unit["summary"],
                "validation_errors": unit["validation_errors"],
                "validation_warnings": unit["validation_warnings"],
                "config_path": unit["config_path"],
                "config_preview": unit["config_preview"],
                "config_diff": unit["config_diff"],
            }
        )
    return group_result, unit_results


def update_appliance_apply_baselines(db: Session, units: list[dict[str, Any]], selected_ids: set[str]) -> None:
    """Update appliance apply baselines.

    Args:
        db: Active database session.
        units: Units supplied by the caller.
        selected_ids: Selected ids supplied by the caller.
    """
    baselines = load_appliance_apply_baselines(db)
    applied_at = utcnow().isoformat()
    for unit in units:
        if unit["id"] not in selected_ids:
            continue
        baseline = {
            "snapshot_hash": unit["snapshot_hash"],
            "config_path": unit["config_path"],
            "config_preview": unit["config_preview"],
            "summary": unit["summary"],
            "applied_at": applied_at,
        }
        runtime_config_preview = unit.get("runtime_config_preview")
        if isinstance(runtime_config_preview, str):
            baseline["runtime_config_preview"] = runtime_config_preview
        if unit["id"] == "dnsmasq":
            baseline["dns_enabled"] = bool(unit["context"]["dns_settings"].enabled)
        baselines[unit["id"]] = baseline
    save_appliance_apply_baselines(db, baselines)


def _has_operator_appliance_activity(db: Session) -> bool:
    """Return whether operator appliance activity.

    Args:
        db: Active database session.
    """
    if db.execute(select(Job.id).where(Job.type == "appliance-apply").limit(1)).first() is not None:
        return True
    return db.execute(select(AuditEvent.id).where(AuditEvent.resource_type != "auth").limit(1)).first() is not None


def _mark_provisioned_bootstrap_admin_applied(db: Session) -> None:
    """Handle mark provisioned bootstrap admin applied.

    Args:
        db: Active database session.
    """
    settings = get_settings()
    bootstrap_user = db.execute(select(User).where(User.username == settings.bootstrap_admin_username)).scalar_one_or_none()
    if bootstrap_user is None or not bootstrap_user.enabled:
        return
    timestamp = utcnow()
    clear_pending_os_password(bootstrap_user)
    bootstrap_user.os_password_applied_at = bootstrap_user.os_password_applied_at or timestamp
    bootstrap_user.os_sync_applied_at = bootstrap_user.os_sync_applied_at or timestamp
    bootstrap_user.os_sync_status = "applied"
    bootstrap_user.os_sync_error = None
    bootstrap_user.os_unlock_requested_at = None
    db.add(bootstrap_user)


def initialize_factory_appliance_apply_baseline(db: Session) -> bool:
    """Return initialize factory appliance apply baseline.

    Args:
        db: Active database session.
    """
    settings = get_settings()
    if settings.environment != "appliance":
        return False
    if setting_value(db, APPLIANCE_APPLY_BASELINES_KEY):
        return False
    if _has_operator_appliance_activity(db):
        return False

    _mark_provisioned_bootstrap_admin_applied(db)
    units = appliance_apply_units(db)
    update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
    db.commit()
    record_audit(
        db,
        actor="system",
        action="initialize_factory_appliance_apply_baseline",
        resource_type="appliance_apply",
        detail=f"{len(units)} factory desired-state units baselined without host mutation",
    )
    return True


@front_door_router.get("/favicon.ico", response_model=None)
def favicon() -> FileResponse:
    """Handle the favicon endpoint.

    Returns:
        The endpoint response.
    """
    return FileResponse(STATIC_DIR / "brand" / "favicon.ico", media_type="image/x-icon")


@front_door_router.get("/manifest.webmanifest", response_model=None)
def webmanifest() -> FileResponse:
    """Handle the webmanifest endpoint.

    Returns:
        The endpoint response.
    """
    return FileResponse(
        STATIC_DIR / "manifest.webmanifest",
        media_type="application/manifest+json",
        headers={"Cache-Control": "no-cache"},
    )


@front_door_router.get("/service-worker.js", response_model=None)
def service_worker() -> FileResponse:
    """Handle the service worker endpoint.

    Returns:
        The endpoint response.
    """
    return FileResponse(
        STATIC_DIR / "service-worker.js",
        media_type="application/javascript",
        headers={
            "Cache-Control": "no-cache",
            "Service-Worker-Allowed": f"{MANAGEMENT_UI_ROOT}/",
        },
    )


@front_door_router.get("/", response_class=HTMLResponse, response_model=None)
def root(
    request: Request,
    identity: Identity | None = Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse | JSONResponse:
    """Handle the root endpoint.

    Args:
        request: Incoming HTTP request.
        identity: Authenticated identity authorizing the request.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    binding = request_host_interface_binding(request_host_name(request), db)
    if management_ui_request_allowed(request, db):
        return RedirectResponse(MANAGEMENT_UI_ROOT, status_code=303)
    if binding and binding.get("role") != "management":
        return RedirectResponse(PUBLIC_UI_ROOT, status_code=303)
    raise HTTPException(status_code=404, detail="Not found")


@router.get("", response_class=HTMLResponse, response_model=None)
def management_home(identity: Identity | None = Depends(get_session_identity)) -> RedirectResponse:
    """Dispatch the canonical management UI root to sign-in or Dashboard.

    Args:
        identity: Optional authenticated session identity.
    """
    if not identity:
        return RedirectResponse(management_ui_path("/login"), status_code=303)
    return RedirectResponse(management_ui_path("/dashboard"), status_code=303)


@public_router.get("", response_class=HTMLResponse, response_model=None)
def public_home(
    request: Request,
    identity: Identity | None = Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Render the canonical interface-scoped Public Services directory.

    Args:
        request: Incoming HTTP request.
        identity: Optional authenticated session identity.
        db: Active database session.
    """
    binding = request_host_interface_binding(request_host_name(request), db)
    if not binding or binding.get("role") == "management":
        raise HTTPException(status_code=404, detail="Not found")
    return render(request, "public_service_home.html", {"identity": identity, **public_service_directory_context(db, binding)})


@router.post("/session/activity", response_model=None)
@public_router.post("/session/activity", response_model=None)
def browser_session_activity(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Refresh server-owned browser activity after a bounded deliberate user event.

    Args:
        request: Incoming HTTP request.
        db: Active database session used to validate and refresh the session.
    """
    verify_csrf(request, request.headers.get("X-CSRF-Token", ""))
    if get_session_identity(request, db) is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return Response(status_code=204)


def _format_file_size(size: int) -> str:
    """Render file size.

    Args:
        size: Size consumed by format file size.


    Returns:
        The format file size result.
    """
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _format_byte_rate(value: float | int | None) -> str:
    """Render byte rate.

    Args:
        value: Candidate value consumed by format byte rate.


    Returns:
        The format byte rate result.
    """
    if value is None:
        return "--"
    return f"{_format_file_size(max(0, int(value)))}/s"


def _depot_browser_context(db: Session, depot_path: str = "") -> dict[str, Any]:
    """Return depot browser context.

    Args:
        db: Active database session.
        depot_path: Filesystem path for the depot.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    settings = get_vcf_offline_depot_settings_row(db)
    root = (Path(settings.depot_store_path) / "PROD").resolve(strict=False)
    relative_parts = [part for part in PurePosixPath(depot_path or "").parts if part not in {"", "."}]
    if any(part == ".." for part in relative_parts):
        raise HTTPException(status_code=404, detail="Depot path not found")
    current = root.joinpath(*relative_parts).resolve(strict=False)
    try:
        current.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Depot path not found") from exc
    if not current.exists() or not current.is_dir():
        raise HTTPException(status_code=404, detail="Depot path not found")

    entries: list[dict[str, str]] = []
    for child in sorted(current.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
        child_relative = child.relative_to(root).as_posix()
        is_dir = child.is_dir()
        href = "/PROD/" + quote(child_relative, safe="/")
        if is_dir:
            href += "/"
        stat = child.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        entries.append(
            {
                "name": child.name + ("/" if is_dir else ""),
                "href": href,
                "kind": "Directory" if is_dir else "File",
                "is_directory": is_dir,
                "pill": "muted" if is_dir else "good",
                "size": "-" if is_dir else _format_file_size(stat.st_size),
                "modified": modified.strftime("%Y-%m-%d %H:%M UTC"),
            }
        )

    relative_path = PurePosixPath(*relative_parts).as_posix() if relative_parts else ""
    parent_href = ""
    if relative_parts:
        parent_path = PurePosixPath(*relative_parts[:-1]).as_posix() if len(relative_parts) > 1 else ""
        parent_href = "/PROD/" + (quote(parent_path, safe="/") + "/" if parent_path else "")
    return {
        "depot_path": "/PROD/" + (relative_path + "/" if relative_path else ""),
        "depot_entries": entries,
        "depot_parent_href": parent_href,
        "depot_allow_unauthenticated_access": settings.allow_unauthenticated_access,
        **public_portal_links_context(db),
    }


@protocol_router.get("/PROD", response_model=None)
def public_depot_redirect() -> RedirectResponse:
    """Handle the public depot redirect endpoint.

    Returns:
        The endpoint response.
    """
    return RedirectResponse("/PROD/", status_code=301)


def safe_depot_login_next(value: str | None) -> str:
    """Return safe depot login next.

    Args:
        value: Candidate value consumed by safe depot login next.
    """
    fallback = "/PROD/"
    target = (value or "").strip()
    if not target or "\\" in target or any(ord(character) < 0x20 or ord(character) == 0x7F for character in target):
        return fallback
    try:
        parsed = urlsplit(target)
    except ValueError:
        return fallback
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return fallback

    decoded_path = parsed.path
    for _ in range(4):
        next_decoded_path = unquote(decoded_path)
        if next_decoded_path == decoded_path:
            break
        decoded_path = next_decoded_path
    else:
        return fallback
    if (
        "\\" in decoded_path
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded_path)
        or "//" in decoded_path
        or any(segment in {".", ".."} for segment in decoded_path.split("/"))
    ):
        return fallback

    if parsed.path == "/PROD":
        return "/PROD" + ("?" + parsed.query if parsed.query else "")
    if not parsed.path.startswith("/PROD/") or not decoded_path.startswith("/PROD/"):
        return fallback
    depot_suffix = parsed.path.removeprefix("/PROD/")
    return "/PROD/" + depot_suffix + ("?" + parsed.query if parsed.query else "")


def depot_login_response(request: Request, *, return_to: str = "/PROD/", error: str | None = None, status_code: int = 200, db: Session | None = None) -> HTMLResponse:
    """Return depot login response.

    Args:
        request: Incoming HTTP request.
        return_to: Return to supplied by the caller.
        error: Public-safe error detail to record or return.
        status_code: HTTP status code for the response.
        db: Active database session.
    """
    return render(
        request,
        "ca_request_login.html",
        {
            "error": error,
            "return_to": safe_depot_login_next(return_to),
            "login_action": "/PROD/login",
            "portal_title": "VCF Offline Depot",
            "portal_subtitle": "Public depot browser",
            "back_href": "/",
            "back_label": "Cancel",
            **(public_portal_links_context(db) if db else {}),
        },
        status_code=status_code,
    )


@protocol_router.get("/PROD/login", response_class=HTMLResponse, response_model=None)
def depot_login_page(
    request: Request,
    next: str = Query("/PROD/"),
    identity: Identity | None = Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    """Handle the depot login page endpoint.

    Args:
        request: Incoming HTTP request.
        next: Relative destination requested after authentication.
        identity: Authenticated identity authorizing the request.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not request_allows_public_service(db, request, "vcf_offline_depot"):
        raise HTTPException(status_code=404, detail="VCF Offline Depot is not available on this interface")
    return_to = safe_depot_login_next(next)
    if identity:
        return RedirectResponse(return_to, status_code=303)
    return depot_login_response(
        request,
        error=consume_browser_session_expired_notice(request),
        return_to=return_to,
        db=db,
    )


@protocol_router.post("/PROD/login", response_model=None)
def depot_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
    next: str = Form("/PROD/"),
    db: Session = Depends(get_db),
) -> RedirectResponse | HTMLResponse:
    """Handle the depot login endpoint.

    Args:
        request: Incoming HTTP request.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        csrf: Validated CSRF token authorizing the request.
        next: Relative destination requested after authentication.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not request_allows_public_service(db, request, "vcf_offline_depot"):
        raise HTTPException(status_code=404, detail="VCF Offline Depot is not available on this interface")
    return_to = safe_depot_login_next(next)
    verify_csrf(request, csrf)
    user = authenticate_user(db, username, password)
    if user is None:
        settings = get_vcf_offline_depot_settings_row(db)
        selected_user = settings.http_user
        if selected_user and selected_user.enabled and username == selected_user.username:
            authentication = SystemAdapter().authenticate_local_user(username, password)
            if authentication.returncode == 0 and not authentication.dry_run:
                user = selected_user
    if user is None:
        record_audit(db, actor=username, action="vcf_depot_login_failed", resource_type="auth", success=False)
        return depot_login_response(request, return_to=return_to, error="Invalid username or password", status_code=401, db=db)
    start_browser_session(request, db, user)
    record_audit(db, actor=user.username, action="vcf_depot_login", resource_type="auth")
    return RedirectResponse(return_to, status_code=303)


@protocol_router.post("/PROD/logout", response_model=None)
def depot_logout(request: Request, csrf: str = Form(...), next: str = Form("/"), db: Session = Depends(get_db)) -> RedirectResponse:
    """Handle the depot logout endpoint.

    Args:
        request: Incoming HTTP request.
        csrf: Validated CSRF token authorizing the request.
        next: Relative destination requested after authentication.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    verify_csrf(request, csrf)
    end_browser_session(request, db)
    return RedirectResponse(next if next in {"/", "/PROD/"} else "/", status_code=303)


@protocol_router.get("/PROD/auth-check", response_model=None)
def depot_auth_check(
    request: Request,
    identity: Identity | None = Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> Response:
    """Handle the depot auth check endpoint.

    Args:
        request: Incoming HTTP request.
        identity: Authenticated identity authorizing the request.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    if not request_allows_public_service(db, request, "vcf_offline_depot"):
        return Response(status_code=401)
    settings = get_vcf_offline_depot_settings_row(db)
    if identity or settings.allow_unauthenticated_access:
        return Response(status_code=204)
    return Response(status_code=401)


@protocol_router.get("/PROD/auth-failure", response_model=None)
@protocol_router.head("/PROD/auth-failure", response_model=None)
def depot_auth_failure(request: Request, db: Session = Depends(get_db)) -> Response:
    """Handle the depot auth failure endpoint.

    Args:
        request: Incoming HTTP request.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    if not request_allows_public_service(db, request, "vcf_offline_depot"):
        return Response(status_code=401)
    if "text/html" in request.headers.get("accept", "").lower():
        return_to = safe_depot_login_next(request.headers.get("X-Original-URI"))
        return RedirectResponse(f"/PROD/login?next={quote(return_to, safe='/')}", status_code=303)
    return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="VCF Offline Depot"'})


@protocol_router.get("/PROD/", response_class=HTMLResponse, response_model=None)
@protocol_router.head("/PROD/", response_class=HTMLResponse, response_model=None)
@protocol_router.get("/PROD/{depot_path:path}", response_class=HTMLResponse, response_model=None)
@protocol_router.head("/PROD/{depot_path:path}", response_class=HTMLResponse, response_model=None)
def public_depot_browser(
    request: Request,
    depot_path: str = "",
    identity: Identity | None = Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    """Handle the public depot browser endpoint.

    Args:
        request: Incoming HTTP request.
        depot_path: Filesystem path for the depot.
        identity: Authenticated identity authorizing the request.
        db: Active database session.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not request_allows_public_service(db, request, "vcf_offline_depot"):
        raise HTTPException(status_code=404, detail="Depot path not found")
    if depot_path and not depot_path.endswith("/"):
        raise HTTPException(status_code=404, detail="Depot path not found")
    settings = get_vcf_offline_depot_settings_row(db)
    basic_username = request.headers.get("X-Atlaso-Depot-Basic-User", "").strip()
    basic_authenticated = bool(
        basic_username
        and settings.http_user
        and settings.http_user.enabled
        and basic_username == settings.http_user.username
    )
    if identity is None and not settings.allow_unauthenticated_access and not basic_authenticated:
        next_path = "/PROD/" + depot_path if depot_path else "/PROD/"
        return RedirectResponse(f"/PROD/login?next={quote(next_path, safe='/')}", status_code=303)
    return render(request, "depot_browser.html", {"identity": identity, **_depot_browser_context(db, depot_path.rstrip("/"))})


def public_terminal_login_response(
    request: Request,
    *,
    error: str | None = None,
    status_code: int = 200,
    db: Session,
) -> HTMLResponse:
    """Return public terminal login response.

    Args:
        request: Incoming HTTP request.
        error: Public-safe error detail to record or return.
        status_code: HTTP status code for the response.
        db: Active database session.
    """
    return render(
        request,
        "ca_request_login.html",
        {
            "error": error,
            "return_to": public_ui_path("/terminal"),
            "login_action": public_ui_path("/login"),
            "portal_title": "Atlaso Web Terminal",
            "login_heading": "Sign in to Web Terminal",
            "login_copy": "Use a Atlaso local user with Web SSH access enabled.",
            "back_href": PUBLIC_UI_ROOT,
            "back_label": "Back to Public Services",
            **public_portal_links_context(db),
        },
        status_code=status_code,
    )


def local_user_has_web_terminal_access(user: User | None) -> bool:
    """Return local user has web terminal access.

    Args:
        user: User record or identity affected by the operation.
    """
    return bool(
        user
        and user.enabled
        and user.web_terminal_access
        and (user.auth_provider or "local") == "local"
        and normalize_user_shell(user.shell) != DEFAULT_LOCAL_USER_SHELL
    )


@router.get("/login", response_class=HTMLResponse, response_model=None)
def login_page(
    request: Request,
    next: str = Query(""),
    factory_reset: str = Query(""),
    identity: Identity | None = Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    """Handle the login page endpoint.

    Args:
        request: Incoming HTTP request.
        next: Relative destination requested after authentication.
        factory_reset: Factory-reset handoff state requested by the reset workflow.
        identity: Authenticated identity authorizing the request.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    return_to = safe_login_next(next)
    if identity:
        return RedirectResponse(return_to, status_code=303)
    reset_notice = None
    if factory_reset:
        reset_state = read_factory_reset_state()
        authenticated_completion = (
            factory_reset == "complete"
            and request.session.pop("factory_reset_completed", False) is True
        )
        if reset_state["state"] == "succeeded" or authenticated_completion:
            reset_notice = (
                "Factory reset completed. Sign in with the bootstrap administrator password "
                "selected for this reset. Earlier sessions, tokens, and removed account "
                "credentials are invalid."
            )
        elif reset_state["state"] == "failed":
            reset_notice = (
                reset_state["message"] or "Factory reset requires console recovery."
            )
        else:
            reset_notice = (
                "Factory reset is in progress. This page may be temporarily unavailable while "
                "the management plane restarts."
            )
    return render(
        request,
        "login.html",
        {"error": consume_browser_session_expired_notice(request), "return_to": return_to, "factory_reset_notice": reset_notice},
    )


@router.post("/login", response_model=None)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse | HTMLResponse | JSONResponse | Response:
    """Handle the login endpoint.

    Args:
        request: Incoming HTTP request.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        next: Relative destination requested after authentication.
        csrf: Validated CSRF token authorizing the request.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    verify_csrf(request, csrf)
    return_to = safe_login_next(next)
    user = authenticate_user(db, username, password)
    if not user:
        record_audit(db, actor=username, action="ui_login_failed", resource_type="auth", success=False)
        return render(request, "login.html", {"error": "Invalid username or password", "return_to": return_to})
    start_browser_session(request, db, user)
    record_audit(db, actor=user.username, action="ui_login", resource_type="auth")
    return RedirectResponse(return_to, status_code=303)


@router.post("/logout", response_model=None)
def logout(request: Request, csrf: str = Form(...), next: str = Form(""), db: Session = Depends(get_db)) -> RedirectResponse:
    """Handle the logout endpoint.

    Args:
        request: Incoming HTTP request.
        csrf: Validated CSRF token authorizing the request.
        next: Relative destination requested after authentication.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    verify_csrf(request, csrf)
    end_browser_session(request, db)
    return RedirectResponse(management_ui_path("/login"), status_code=303)


@public_router.get("/login", response_class=HTMLResponse, response_model=None)
def public_login_page(
    request: Request,
    next: str = Query(""),
    identity: Identity | None = Depends(get_session_identity),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    """Render the public-plane Web Terminal sign-in page.

    Args:
        request: Incoming HTTP request.
        next: Requested same-plane return path.
        identity: Optional authenticated session identity.
        db: Active database session.
    """
    if not public_ui_request_allowed(request, db, "/terminal"):
        raise HTTPException(status_code=404, detail="Not found")
    return_to = safe_public_return_path(next, default="/terminal")
    if identity:
        return RedirectResponse(return_to, status_code=303)
    return public_terminal_login_response(
        request,
        error=consume_browser_session_expired_notice(request),
        db=db,
    )


@public_router.post("/login", response_model=None)
def public_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse | HTMLResponse:
    """Authenticate an eligible local user for the public Web Terminal.

    Args:
        request: Incoming HTTP request.
        username: Local account name supplied for authentication.
        password: Password supplied for the immediate authentication attempt.
        next: Requested same-plane return path.
        csrf: Validated CSRF token authorizing the request.
        db: Active database session.
    """
    if not public_ui_request_allowed(request, db, "/terminal"):
        raise HTTPException(status_code=404, detail="Not found")
    verify_csrf(request, csrf)
    return_to = safe_public_return_path(next, default="/terminal")
    user = authenticate_user(db, username, password)
    if user is None:
        local_user = db.execute(select(User).where(User.username == username.strip().lower())).scalar_one_or_none()
        if local_user_has_web_terminal_access(local_user):
            authentication = SystemAdapter().authenticate_local_user(local_user.username, password)
            if authentication.returncode == 0 and not authentication.dry_run:
                user = local_user
    if not user:
        record_audit(db, actor=username, action="public_ui_login_failed", resource_type="auth", success=False)
        return public_terminal_login_response(request, error="Invalid username or password", status_code=401, db=db)
    start_browser_session(request, db, user)
    record_audit(db, actor=user.username, action="public_ui_login", resource_type="auth")
    return RedirectResponse(return_to, status_code=303)


@public_router.post("/logout", response_model=None)
def public_logout(request: Request, csrf: str = Form(...), next: str = Form(""), db: Session = Depends(get_db)) -> RedirectResponse:
    """End a public-plane session without crossing into management.

    Args:
        request: Incoming HTTP request.
        csrf: Validated CSRF token authorizing the request.
        next: Requested same-plane return path.
        db: Active database session.
    """
    verify_csrf(request, csrf)
    end_browser_session(request, db)
    return RedirectResponse(safe_public_return_path(next, default="/terminal"), status_code=303)


_management_between_vaults_appliance_maintenance_router = router
_appliance_maintenance_ui = build_appliance_maintenance_ui_routers(
    ApplianceMaintenanceUiDependencies(
        require_management_ui_request=require_management_ui_request,
        require_admin_identity=lambda *args, **kwargs: require_admin_identity(
            *args, **kwargs
        ),
        verify_csrf=lambda *args, **kwargs: verify_csrf(*args, **kwargs),
        render=lambda *args, **kwargs: render(*args, **kwargs),
        appliance_update_context=lambda *args, **kwargs: appliance_update_context(
            *args, **kwargs
        ),
        appliance_update_availability_summary=lambda *args, **kwargs: appliance_update_availability_summary(
            *args, **kwargs
        ),
        appliance_update_settings=lambda *args, **kwargs: appliance_update_settings(
            *args, **kwargs
        ),
        adapter_result_to_payload=lambda *args, **kwargs: adapter_result_to_payload(
            *args, **kwargs
        ),
        default_source_settings=lambda *args, **kwargs: default_source_settings(
            *args, **kwargs
        ),
        encrypt_secret=lambda *args, **kwargs: encrypt_secret(*args, **kwargs),
        get_settings=lambda *args, **kwargs: get_settings(*args, **kwargs),
        managed_package_from_form=lambda *args, **kwargs: _managed_package_from_form(
            *args, **kwargs
        ),
        record_audit=lambda *args, **kwargs: record_audit(*args, **kwargs),
        render_update_manifest=lambda *args, **kwargs: render_update_manifest(
            *args, **kwargs
        ),
        set_setting_value=lambda *args, **kwargs: set_setting_value(
            *args, **kwargs
        ),
        source_rows=lambda *args, **kwargs: source_rows(*args, **kwargs),
        submit_appliance_update=lambda *args, **kwargs: submit_appliance_update(
            *args, **kwargs
        ),
        system_adapter=lambda: SystemAdapter(),
        update_settings_to_json=lambda *args, **kwargs: update_settings_to_json(
            *args, **kwargs
        ),
        update_source_payload=lambda *args, **kwargs: update_source_payload(
            *args, **kwargs
        ),
        update_source_settings=lambda *args, **kwargs: update_source_settings(
            *args, **kwargs
        ),
        utcnow=lambda *args, **kwargs: utcnow(*args, **kwargs),
        validate_update_settings=lambda *args, **kwargs: validate_update_settings(
            *args, **kwargs
        ),
        validate_update_source=lambda *args, **kwargs: validate_update_source(
            *args, **kwargs
        ),
    )
)
appliance_maintenance_power_router = _appliance_maintenance_ui.power_router
appliance_maintenance_update_router = _appliance_maintenance_ui.update_router
appliance_power_action = _appliance_maintenance_ui.endpoints[
    "appliance_power_action"
]
appliance_update_page = _appliance_maintenance_ui.endpoints[
    "appliance_update_page"
]
appliance_update_availability = _appliance_maintenance_ui.endpoints[
    "appliance_update_availability"
]
update_appliance_update_settings = _appliance_maintenance_ui.endpoints[
    "update_appliance_update_settings"
]
update_appliance_update_source = _appliance_maintenance_ui.endpoints[
    "update_appliance_update_source"
]
create_appliance_update_source = _appliance_maintenance_ui.endpoints[
    "create_appliance_update_source"
]
delete_appliance_update_source = _appliance_maintenance_ui.endpoints[
    "delete_appliance_update_source"
]
create_managed_update_package = _appliance_maintenance_ui.endpoints[
    "create_managed_update_package"
]
update_managed_update_package = _appliance_maintenance_ui.endpoints[
    "update_managed_update_package"
]
delete_managed_update_package = _appliance_maintenance_ui.endpoints[
    "delete_managed_update_package"
]
sync_appliance_update_sources = _appliance_maintenance_ui.endpoints[
    "sync_appliance_update_sources"
]
check_appliance_update = _appliance_maintenance_ui.endpoints[
    "check_appliance_update"
]
run_appliance_update = _appliance_maintenance_ui.endpoints[
    "run_appliance_update"
]

_dashboard_monitor_ui = build_dashboard_monitor_ui_router(
    DashboardMonitorUiDependencies(
        require_management_ui_request=require_management_ui_request,
        render=render,
        dashboard_snapshot=dashboard_snapshot,
        require_monitoring_read=require_monitoring_read,
        monitor_payload=monitor_payload,
        format_byte_rate=_format_byte_rate,
        utcnow=utcnow,
    )
)
dashboard_monitor_router = _dashboard_monitor_ui.router
dashboard = _dashboard_monitor_ui.endpoints["dashboard"]
dashboard_data = _dashboard_monitor_ui.endpoints["dashboard_data"]
monitor_page = _dashboard_monitor_ui.endpoints["monitor_page"]
monitor_data = _dashboard_monitor_ui.endpoints["monitor_data"]
server_time = _dashboard_monitor_ui.endpoints["server_time"]


def _managed_package_from_form(
    package: ManagedPackage,
    *,
    name: str,
    source_id: int,
    policy: str,
    target_version: str,
    enabled: bool,
    db: Session,
) -> list[str]:
    """Return managed package from form.

    Args:
        package: Package supplied by the caller.
        name: Name of the target object.
        source_id: Identifier of the source.
        policy: Policy values to validate or enforce.
        target_version: Target version supplied by the caller.
        enabled: Whether the requested behavior is enabled.
        db: Active database session.
    """
    package.ecosystem = "powershell"
    package.name = name.strip()
    package.source_id = source_id
    package.source = db.get(UpdateSource, source_id)
    package.policy = policy.strip().lower()
    package.target_version = target_version.strip() if package.policy == "pinned" else ""
    package.enabled = enabled
    package.updated_at = utcnow()
    return validate_managed_package(package)


def submit_appliance_update(
    *,
    request: Request,
    selected_streams: list[str],
    csrf: str,
    identity: Identity,
    db: Session,
    mode: str,
) -> HTMLResponse | JSONResponse:
    """Return submit appliance update.

    Args:
        request: Incoming HTTP request.
        selected_streams: Update streams selected for the job.
        csrf: Validated CSRF token authorizing the request.
        identity: Authenticated identity authorizing the request.
        db: Active database session.
        mode: Operating mode selected for the workflow.
    """
    verify_csrf(request, csrf)
    require_admin_identity(identity)
    wants_json = "application/json" in request.headers.get("accept", "")
    selected = selected_update_streams(selected_streams)
    settings = appliance_update_settings(db)
    errors = validate_update_settings(settings)
    if not selected:
        errors.append("Select at least one update stream.")
    if "atlaso_release" in selected and not str(settings.get("atlaso_manifest_url") or "").strip():
        errors.append("Configure a signed Atlaso release repository before selecting Atlaso Release.")
    if mode == "run" and "powershell_modules" in selected and not str(settings.get("powershell_repository_url") or "").strip():
        errors.append("Configure an enabled PowerShell repository before selecting PowerShell Modules.")
    if "powershell_modules" in selected:
        for repository in unsynchronized_powershell_repositories(settings):
            errors.append(
                f"Synchronize PowerShell repository {repository} before checking or installing its managed modules."
            )
    if "photon_os" in selected:
        for repository in unsynchronized_photon_repositories(settings):
            errors.append(
                f"Synchronize Photon repository {repository} before checking or installing Photon OS updates."
            )
    if mode == "run" and selected:
        install_allowed, install_reason = manual_install_gate(
            appliance_update_availability_summary(db), selected
        )
        if not install_allowed and install_reason:
            errors.append(install_reason)
    if errors:
        if wants_json:
            return JSONResponse({"status": "error", "errors": errors, "detail": " ".join(errors)}, status_code=422)
        return render(
            request,
            "appliance_update.html",
            {
                "identity": identity,
                **appliance_update_context(db, selected_stream_ids=selected),
                "selected_update_stream_ids": selected,
                "update_error": " ".join(errors),
            },
            status_code=422,
        )
    active = db.execute(
        select(Job).where(
            Job.type == "appliance-update",
            Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
        )
    ).scalars().first()
    if active is not None:
        detail = f"Appliance update task {active.id} is already pending or running."
        if wants_json:
            return JSONResponse({"status": "active", "job_id": active.id, "detail": detail}, status_code=409)
        return render(
            request,
            "appliance_update.html",
            {
                "identity": identity,
                **appliance_update_context(db, selected_stream_ids=selected),
                "selected_update_stream_ids": selected,
                "update_error": detail,
            },
            status_code=409,
        )
    task_config = {
        "schema_version": 2,
        "selected_streams": selected,
        "execution_order": [
            stream for stream in APPLIANCE_UPDATE_EXECUTION_ORDER if stream in selected
        ],
        "status_transaction_id": uuid4().hex,
        "settings": settings,
        "mode": mode,
    }
    update_result = {
        "unit_id": "appliance_update",
        "label": _appliance_update_task_label(mode),
        "mode": mode,
        "selected_streams": selected,
        "selected_labels": [UPDATE_STREAM_LABELS[stream] for stream in selected],
        "status": JobStatus.PENDING.value,
        "success": False,
        "dry_run": get_settings().dry_run_system_adapters,
        "apply_started": False,
        "commands": [],
    }
    job = Job(
        id=f"job_{uuid4().hex[:12]}",
        type="appliance-update",
        status=JobStatus.PENDING.value,
        created_by=identity.username,
        progress_percent=0,
        trigger="manual",
        task_config_json=json.dumps(task_config, sort_keys=True),
        result=json.dumps(update_result, indent=2),
    )
    db.add(job)
    db.flush()
    ensure_appliance_update_job_steps(db, job=job, selected_streams=selected)
    db.commit()
    record_audit(
        db,
        actor=identity.username,
        action=f"queue_{mode}_appliance_update",
        resource_type="job",
        resource_id=job.id,
        detail=f"streams={','.join(selected)}",
    )
    if wants_json:
        return JSONResponse(
            {
                "status": JobStatus.PENDING.value,
                "job_id": job.id,
                "mode": mode,
                "selected_streams": selected,
            },
            status_code=202,
        )
    return render(
        request,
        "appliance_update.html",
        {
            "identity": identity,
            **appliance_update_context(db, selected_stream_ids=selected),
            "selected_update_stream_ids": selected,
            "appliance_update_task": job,
            "appliance_update_task_result": update_result,
            "appliance_update_failures": appliance_apply_failure_summaries([update_result]),
        },
    )


_automation_ui = build_automation_ui_router(
    AutomationUiDependencies(
        require_management_ui_request=require_management_ui_request,
        automation_context=automation_context,
        render=render,
        require_admin_identity=require_admin_identity,
        verify_csrf=verify_csrf,
        vcf_depot_download_preflight=vcf_depot_download_preflight,
        vcf_offline_depot_page=lambda *args, **kwargs: vcf_offline_depot_page(
            *args, **kwargs
        ),
        create_script_revision=lambda *args, **kwargs: create_script_revision(
            *args, **kwargs
        ),
        normalize_script_content=lambda *args, **kwargs: normalize_script_content(
            *args, **kwargs
        ),
    )
)
automation_router = _automation_ui.router
automation_page = _automation_ui.endpoints["automation_page"]
_automation_render_error = _automation_ui.endpoints["_automation_render_error"]
_automation_script_validation_message = _automation_ui.endpoints[
    "_automation_script_validation_message"
]
_automation_task_config = _automation_ui.endpoints["_automation_task_config"]
AutomationScheduleInputError = _automation_ui.endpoints["AutomationScheduleInputError"]
create_automation_schedule_record = _automation_ui.endpoints[
    "create_automation_schedule_record"
]
create_automation_schedule = _automation_ui.endpoints["create_automation_schedule"]
create_contextual_vcf_depot_schedule = _automation_ui.endpoints[
    "create_contextual_vcf_depot_schedule"
]
edit_automation_schedule = _automation_ui.endpoints["edit_automation_schedule"]
run_automation_schedule_now = _automation_ui.endpoints["run_automation_schedule_now"]
toggle_automation_schedule = _automation_ui.endpoints["toggle_automation_schedule"]
delete_automation_schedule = _automation_ui.endpoints["delete_automation_schedule"]
create_automation_script_from_ui = _automation_ui.endpoints[
    "create_automation_script_from_ui"
]
create_automation_script_revision_from_ui = _automation_ui.endpoints[
    "create_automation_script_revision_from_ui"
]
edit_automation_script_from_ui = _automation_ui.endpoints[
    "edit_automation_script_from_ui"
]
delete_automation_script_from_ui = _automation_ui.endpoints[
    "delete_automation_script_from_ui"
]
toggle_automation_script_revision = _automation_ui.endpoints[
    "toggle_automation_script_revision"
]
run_automation_script_revision = _automation_ui.endpoints[
    "run_automation_script_revision"
]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)




class ApplianceApplyJobError(RuntimeError):
    """An operator-safe failure raised before appliance apply execution begins."""


APPLIANCE_APPLY_SUBMIT_LOCK = threading.Lock()
VCF_DEPOT_SUBMIT_LOCK = threading.Lock()


def appliance_apply_management_restart_window(
    job: Job,
    *,
    now: datetime | None = None,
) -> dict[str, int] | None:
    """Return server-owned remaining time for a confirmed management restart.

    Args:
        job: Appliance Apply job carrying helper-confirmed transition metadata.
        now: Optional current UTC instant used by deterministic callers and tests.
    """
    transition = _job_payload(job).get("management_status_transition")
    if not isinstance(transition, dict) or transition.get("kind") != "planned_service_restart":
        return None
    restart_delay_seconds = transition.get("restart_delay_seconds")
    grace_seconds = transition.get("grace_seconds")
    if (
        not isinstance(restart_delay_seconds, int)
        or isinstance(restart_delay_seconds, bool)
        or restart_delay_seconds != APPLIANCE_APPLY_MANAGEMENT_RESTART_DELAY_SECONDS
    ):
        return None
    if (
        not isinstance(grace_seconds, int)
        or isinstance(grace_seconds, bool)
        or grace_seconds != APPLIANCE_APPLY_MANAGEMENT_RECONNECT_GRACE_SECONDS
    ):
        return None
    settings_step = next(
        (
            step
            for step in job.steps
            if step.component_key == "appliance_settings"
            and step.status == JobStatus.SUCCEEDED.value
            and step.finished_at is not None
        ),
        None,
    )
    if settings_step is None:
        return None
    observed_at = ensure_aware(now or utcnow())
    step_finished_at = ensure_aware(settings_step.finished_at)
    restart_at = step_finished_at + timedelta(seconds=restart_delay_seconds)
    deadline = restart_at + timedelta(seconds=grace_seconds)
    return {
        "restart_delay_remaining_ms": int(max(0.0, (restart_at - observed_at).total_seconds()) * 1000),
        "remaining_ms": int(max(0.0, (deadline - observed_at).total_seconds()) * 1000),
    }


def active_appliance_apply_job(db: Session) -> Job | None:
    """Return the Appliance Apply job that currently holds the mutation lock.

    Args:
        db: Active database session.
    """
    active = db.scalars(
        select(Job)
        .options(selectinload(Job.steps))
        .where(
            Job.type == "appliance-apply",
            or_(
                Job.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value]),
                Job.result.like('%"management_handoff_runtime_commit_pending": true%'),
            ),
        )
        .order_by(Job.created_at)
        .limit(1)
    ).first()
    if active is not None:
        return active

    now = utcnow()
    maximum_window = timedelta(
        seconds=(
            APPLIANCE_APPLY_MANAGEMENT_RESTART_DELAY_SECONDS
            + APPLIANCE_APPLY_MANAGEMENT_RECONNECT_GRACE_SECONDS
        )
    )
    recent = db.scalars(
        select(Job)
        .options(selectinload(Job.steps))
        .where(
            Job.type == "appliance-apply",
            Job.status.in_(
                [
                    JobStatus.SUCCEEDED.value,
                    JobStatus.FAILED.value,
                    JobStatus.CANCELLED.value,
                ]
            ),
            Job.finished_at.is_not(None),
            Job.finished_at >= now - maximum_window,
        )
        .order_by(desc(Job.finished_at))
    ).all()
    for job in recent:
        restart_window = appliance_apply_management_restart_window(job, now=now)
        if restart_window is not None and restart_window["remaining_ms"] > 0:
            return job
    return None


def active_appliance_apply_submitted_unit_ids(db: Session) -> set[str]:
    """Return active appliance apply submitted unit ids.

    Args:
        db: Active database session.
    """
    job = active_appliance_apply_job(db)
    if job is None:
        return set()
    if job.steps:
        return {step.component_key for step in job.steps}
    return {str(unit_id) for unit_id in _job_payload(job).get("selected_units", [])}


def active_vcf_depot_execution_job(db: Session) -> Job | None:
    """Return active vcf depot execution job.

    Args:
        db: Active database session.
    """
    return active_vcf_depot_operation_job(db)


def vcf_depot_execution_conflict_detail(job: Job) -> str:
    """Return vcf depot execution conflict detail.

    Args:
        job: Background job record affected by the operation.
    """
    if job.type == "vcf-depot-download":
        return (
            f"VCF Depot Download task {job.id} is {job.status}. "
            "Wait for the queued profile downloads to finish before starting an exclusive Software Depot ID or "
            "VCF Offline Depot Appliance Apply operation."
        )
    return (
        f"{_task_type_label(job.type)} task {job.id} is already {job.status}. "
        "Wait for it to finish before starting another VCFDT operation."
    )


def reconcile_management_handoff_exception(
    adapter: SystemAdapter,
    job_id: str,
    *,
    application_committed: bool,
) -> tuple[AdapterResult, dict[str, Any]]:
    """Reconcile retained helper state before an exception becomes terminal.

    Args:
        adapter: System adapter that owns the helper transaction.
        job_id: Appliance Apply task identifier.
        application_committed: Whether baselines and pending acknowledgement are durable.

    Returns:
        Adapter result and parsed bounded evidence.
    """
    result = (
        adapter.acknowledge_management_handoff(job_id)
        if application_committed
        else adapter.recover_management_handoff()
    )
    return result, management_handoff_result_evidence(result)


def run_appliance_apply_job(job_id: str, *, force_real: bool = False) -> None:
    """Run appliance apply job.

    Args:
        job_id: Stable identifier of the associated job resource.
        force_real: Whether force real applies to the operation.


    Raises:
        ApplianceApplyJobError: If the operation encounters an invalid state.
        ValueError: If an input value is invalid.
    """
    with SessionLocal() as db:
        job = db.scalar(select(Job).options(selectinload(Job.steps)).where(Job.id == job_id))
        if job is None or job.status != JobStatus.PENDING.value:
            return
        if force_real and job.created_by != "console:root":
            raise ValueError("Forced-real appliance apply is restricted to local console tasks.")
        job.status = JobStatus.RUNNING.value
        job.started_at = utcnow()
        job.progress_percent = 1
        db.commit()

        unit_results: list[dict[str, Any]] = []
        handoff_recovery_adapter: SystemAdapter | None = None
        handoff_runtime_pending = False
        handoff_application_committed = False
        try:
            job_result = json.loads(job.result or "{}")
            selected_order = [str(unit_id) for unit_id in job_result.get("selected_units", [])]
            captured_by_id = {
                str(unit.get("unit_id")): unit
                for unit in job_result.get("captured_units", [])
                if isinstance(unit, dict) and unit.get("unit_id")
            }
            invalidate_observed_management_dhcp_dns()
            invalidate_appliance_apply_status_projection()
            current_units = appliance_apply_units(db)
            current_by_id = {unit["id"]: unit for unit in current_units}
            missing_ids = [unit_id for unit_id in selected_order if unit_id not in current_by_id]
            if missing_ids:
                raise ApplianceApplyJobError(f"Selected appliance apply units are unavailable: {', '.join(missing_ids)}.")
            selected_units = [current_by_id[unit_id] for unit_id in selected_order]
            invalid_units = [unit["label"] for unit in selected_units if unit["validation_errors"]]
            if invalid_units:
                raise ApplianceApplyJobError(f"Desired state became invalid before execution: {', '.join(invalid_units)}.")
            changed_after_submit = [
                unit["label"]
                for unit in selected_units
                if str(captured_by_id.get(unit["id"], {}).get("snapshot_hash") or "") != str(unit["snapshot_hash"])
            ]
            if changed_after_submit:
                raise ApplianceApplyJobError(
                    f"Desired state changed after task submission: {', '.join(changed_after_submit)}. Submit the appliance changes again."
                )

            steps_by_key = {step.component_key: step for step in job.steps}
            total_steps = max(len(selected_units), 1)
            failed = False
            cancelled = False
            handoff_completed = False
            handoff_unit_ids = set(
                job_result.get("management_handoff_units", [])
                if job_result.get("management_handoff")
                else []
            )
            for index, unit in enumerate(selected_units, start=1):
                db.refresh(job)
                current_payload = _job_payload(job)
                if current_payload.get("cancel_requested"):
                    cancelled = True
                    for remaining_unit in selected_units[index - 1 :]:
                        remaining = steps_by_key.get(remaining_unit["id"])
                        if remaining is None or remaining.status != JobStatus.PENDING.value:
                            continue
                        remaining.status = "skipped"
                        remaining.progress_percent = 100
                        remaining.finished_at = utcnow()
                        remaining.error = "Skipped after the master task cancellation request."
                        remaining.result = json.dumps({"summary": remaining_unit["summary"], "reason": "cancelled"}, indent=2)
                    db.commit()
                    break

                if unit["id"] in handoff_unit_ids:
                    if handoff_completed:
                        continue
                    bundled_units = [
                        current_by_id[unit_id]
                        for unit_id in (*MANAGEMENT_HANDOFF_UNIT_IDS, "wan")
                        if unit_id in handoff_unit_ids
                    ]
                    if not set(MANAGEMENT_HANDOFF_UNIT_IDS).issubset(
                        {item["id"] for item in bundled_units}
                    ):
                        raise ApplianceApplyJobError(
                            "Management handoff is missing a required Network, Firewall, Certificate Authority, "
                            "Appliance Settings, or Public Services component."
                        )
                    started = utcnow()
                    for bundled in bundled_units:
                        bundled_step = steps_by_key.get(bundled["id"])
                        if bundled_step is None:
                            raise ApplianceApplyJobError(
                                f"Component task record is missing for {bundled['label']}."
                            )
                        bundled_step.status = JobStatus.RUNNING.value
                        bundled_step.started_at = started
                        bundled_step.progress_percent = 5
                    job.progress_percent = min(95, int(((index - 1) / total_steps) * 100))
                    db.commit()
                    handoff_adapter = SystemAdapter(dry_run=False) if force_real else SystemAdapter()
                    if not handoff_adapter.dry_run:
                        handoff_recovery_adapter = handoff_adapter
                        handoff_runtime_pending = True
                    group_result, bundled_results = execute_management_handoff(
                        current_by_id,
                        job_id=job.id,
                        adapter=handoff_adapter,
                        db=db,
                        include_wan="wan" in handoff_unit_ids,
                    )
                    if not group_result.get("success") and group_result.get("rollback_proven"):
                        handoff_runtime_pending = False
                    bundled_results = [_redact_task_value(result) for result in bundled_results]
                    unit_results.extend(bundled_results)
                    finished = utcnow()
                    handoff_succeeded = all(result["success"] for result in bundled_results)
                    for result in bundled_results:
                        bundled_step = steps_by_key[result["unit_id"]]
                        bundled_step.result = json.dumps(result, indent=2, sort_keys=True)
                        bundled_step.status = (
                            JobStatus.SUCCEEDED.value if result["success"] else JobStatus.FAILED.value
                        )
                        bundled_step.finished_at = finished
                        bundled_step.progress_percent = 100
                        messages = _task_failure_messages(result)
                        bundled_step.error = None if result["success"] else (
                            messages[0]
                            if messages
                            else "Management handoff failed and the previous path was rolled back."
                        )
                    current_payload = _job_payload(job)
                    next_payload = {**current_payload, "units": unit_results}
                    if handoff_runtime_pending:
                        next_payload["management_handoff_runtime_commit_pending"] = True
                    else:
                        next_payload.pop("management_handoff_runtime_commit_pending", None)
                    job.result = json.dumps(next_payload, indent=2)
                    if handoff_succeeded:
                        # These units were hash-checked against the submitted
                        # snapshots immediately before execution and are the
                        # exact configuration staged for the helper. Desired
                        # state may change in another session while the bounded
                        # readiness probes run; never promote that newer,
                        # unexecuted state into the applied baselines.
                        if not group_result.get("dry_run"):
                            refresh_management_handoff_dynamic_observations(
                                db,
                                str(current_by_id["network"].get("config_preview") or ""),
                                group_result["management_handoff"],
                            )
                        applied = [
                            current_by_id[unit_id]
                            for unit_id in (*MANAGEMENT_HANDOFF_UNIT_IDS, "wan")
                            if unit_id in handoff_unit_ids
                        ]
                        applied_ids = set(handoff_unit_ids)
                        baselines = load_appliance_apply_baselines(db)
                        settings_unit = next(
                            (candidate for candidate in applied if candidate["id"] == "appliance_settings"),
                            None,
                        )
                        settings_complete = bool(
                            settings_unit is not None
                            and management_handoff_completes_appliance_settings(
                                str(settings_unit.get("config_preview") or ""),
                                baselines.get("appliance_settings"),
                            )
                        )
                        if not settings_complete:
                            applied_ids.discard("appliance_settings")
                        settings_result = next(
                            (result for result in unit_results if result["unit_id"] == "appliance_settings"),
                            None,
                        )
                        if settings_result is not None:
                            settings_result["baseline_updated"] = settings_complete
                            if not settings_complete:
                                settings_result["remaining_pending_reason"] = (
                                    "Non-management Appliance Settings changes remain pending."
                                )
                            settings_step = steps_by_key.get("appliance_settings")
                            if settings_step is not None:
                                settings_step.result = json.dumps(settings_result, indent=2, sort_keys=True)
                        update_appliance_apply_baselines(
                            db,
                            applied,
                            applied_ids,
                        )
                        pending_payload = _job_payload(job)
                        job.result = json.dumps(
                            {
                                **pending_payload,
                                "units": unit_results,
                                "management_handoff_runtime_commit_pending": True,
                                "management_handoff_application_committed": True,
                            },
                            indent=2,
                        )
                        # This commit is the application-side transaction boundary:
                        # startup recovery rolls back before it and idempotently
                        # acknowledges the candidate after it.
                        db.commit()
                        handoff_application_committed = True
                        acknowledgement = handoff_adapter.acknowledge_management_handoff(job.id)
                        acknowledgement_evidence = management_handoff_result_evidence(acknowledgement)
                        group_result["commands"].append(adapter_result_to_payload(acknowledgement))
                        if acknowledgement.returncode != 0:
                            failed = True
                            acknowledgement_error = str(
                                acknowledgement_evidence.get("error")
                                or "management handoff commit acknowledgement failed"
                            )
                            job.error = (
                                "The candidate management path and baselines were committed, but the durable helper "
                                "acknowledgement was not proven. Startup recovery will retry the acknowledgement; "
                                "inspect the bounded component evidence."
                            )
                            for result in bundled_results:
                                result["success"] = False
                                result["status"] = JobStatus.FAILED.value
                                result["failing_layer"] = "application commit acknowledgement"
                                result["error"] = acknowledgement_error
                                result["management_handoff"] = acknowledgement_evidence
                                bundled_step = steps_by_key[result["unit_id"]]
                                bundled_step.status = JobStatus.FAILED.value
                                bundled_step.error = acknowledgement_error
                                bundled_step.result = json.dumps(result, indent=2, sort_keys=True)
                            for remaining_unit in selected_units[index:]:
                                if remaining_unit["id"] in handoff_unit_ids:
                                    continue
                                remaining = steps_by_key.get(remaining_unit["id"])
                                if remaining is None or remaining.status != JobStatus.PENDING.value:
                                    continue
                                remaining.status = "skipped"
                                remaining.progress_percent = 100
                                remaining.finished_at = utcnow()
                                remaining.error = "Skipped because management handoff acknowledgement was not proven."
                                remaining.result = json.dumps(
                                    {
                                        "summary": remaining_unit["summary"],
                                        "reason": "management_handoff_acknowledgement_failed",
                                    },
                                    indent=2,
                                )
                        else:
                            handoff_runtime_pending = False
                            committed_evidence = {
                                **group_result.get("management_handoff", {}),
                                "management_handoff": "committed",
                                "acknowledgement": acknowledgement_evidence,
                            }
                            group_result["management_handoff"] = committed_evidence
                            group_result["success"] = True
                            for result in bundled_results:
                                result["management_handoff"] = committed_evidence
                                bundled_step = steps_by_key[result["unit_id"]]
                                bundled_step.result = json.dumps(result, indent=2, sort_keys=True)
                            committed_payload = _job_payload(job)
                            committed_payload.pop("management_handoff_runtime_commit_pending", None)
                            committed_payload.pop("management_handoff_application_committed", None)
                            job.result = json.dumps(
                                {
                                    **committed_payload,
                                    "units": unit_results,
                                    "management_handoff_runtime_committed": True,
                                },
                                indent=2,
                            )
                    else:
                        failed = True
                        handoff_evidence = group_result.get("management_handoff", {})
                        failing_layer = str(handoff_evidence.get("failing_layer") or "unknown layer")
                        rollback_state = str(handoff_evidence.get("management_handoff") or "failed")
                        job.error = (
                            f"Management handoff failed at {failing_layer}; transaction state: {rollback_state}. "
                            "The component task result contains the bounded non-secret diagnostic."
                        )
                        for remaining_unit in selected_units[index:]:
                            if remaining_unit["id"] in handoff_unit_ids:
                                continue
                            remaining = steps_by_key.get(remaining_unit["id"])
                            if remaining is None or remaining.status != JobStatus.PENDING.value:
                                continue
                            remaining.status = "skipped"
                            remaining.progress_percent = 100
                            remaining.finished_at = finished
                            remaining.error = "Skipped because the management handoff failed and rolled back."
                            remaining.result = json.dumps(
                                {
                                    "summary": remaining_unit["summary"],
                                    "reason": "management_handoff_failed",
                                },
                                indent=2,
                            )
                    handoff_completed = True
                    db.commit()
                    if failed:
                        break
                    continue

                step = steps_by_key.get(unit["id"])
                if step is None:
                    raise ApplianceApplyJobError(f"Component task record is missing for {unit['label']}.")
                step.status = JobStatus.RUNNING.value
                step.started_at = utcnow()
                step.progress_percent = 5
                job.progress_percent = min(95, int(((index - 1) / total_steps) * 100))
                db.commit()

                execution_unit = unit
                if unit["id"] == "esx_storage":
                    manifest = json.loads(unit["raw_config_preview"])
                    manifest["format_authorizations"] = list(job_result.get("format_authorizations") or [])
                    execution_unit = {**unit, "raw_config_preview": esx_storage_manifest_json(manifest)}
                elif unit["id"] == "vcf_offline_depot":
                    execution_unit = {
                        **unit,
                        "refresh_vcf_depot_software_depot_id": bool(
                            job_result.get("refresh_vcf_depot_software_depot_id")
                        ),
                    }
                result = execute_appliance_apply_unit(
                    execution_unit,
                    adapter=SystemAdapter(dry_run=False) if force_real else None,
                    db=db,
                )
                persist_vcf_depot_metadata_from_apply(db, [result])
                result = _redact_task_value(result)
                db.refresh(job)
                current_payload = _job_payload(job)
                management_status_transition = result.get("management_status_transition")
                if unit["id"] == "appliance_settings" and isinstance(management_status_transition, dict):
                    current_payload["management_status_transition"] = management_status_transition
                unit_results.append(result)
                step.result = json.dumps(result, indent=2, sort_keys=True)
                step.status = JobStatus.SUCCEEDED.value if result["success"] else JobStatus.FAILED.value
                step.finished_at = utcnow()
                step.progress_percent = 100
                failure_messages = _task_failure_messages(result)
                step.error = None if result["success"] else (
                    failure_messages[0] if failure_messages else "The component reported an apply failure."
                )
                job.progress_percent = min(99, int((index / total_steps) * 100))
                job.result = json.dumps({**current_payload, "units": unit_results}, indent=2)
                if unit["id"] == "appliance_settings" and isinstance(management_status_transition, dict):
                    # The helper's three-second restart timer is already running. Make the
                    # confirmed transition and completed step durable before reconciliation.
                    db.commit()
                prune_network_boot_media = False
                if result["success"]:
                    if unit["id"] == "esxi_pxe" and not result.get("dry_run"):
                        from atlaso.app.services.network_boot import (
                            mark_network_boot_environments_applied,
                            prune_superseded_shredos_media,
                        )

                        mark_network_boot_environments_applied(db)
                        prune_network_boot_media = True
                    if unit["id"] == "esx_storage" and not result.get("dry_run"):
                        inventory_result = SystemAdapter(dry_run=False).esx_storage_inventory()
                        if inventory_result.returncode == 0:
                            try:
                                inventory_rows = json.loads(inventory_result.stdout.splitlines()[-1])
                            except (IndexError, json.JSONDecodeError):
                                inventory_rows = []
                            inventory_by_id = {str(item.get("stable_device_id") or ""): item for item in inventory_rows}
                            for volume in db.execute(select(EsxStorageVolume)).scalars().all():
                                inventory = inventory_by_id.get(volume.stable_device_id)
                                if volume.source_type == "mounted_ext4" or inventory:
                                    volume.applied = True
                                    volume.state = "mounted"
                                if inventory:
                                    volume.filesystem_uuid = str(inventory.get("filesystem_uuid") or volume.filesystem_uuid)
                                    volume.filesystem_label = str(inventory.get("filesystem_label") or volume.filesystem_label)
                                    volume.device_path = str(inventory.get("device_path") or volume.device_path)
                                    volume.updated_at = utcnow()
                    db.flush()
                    db.expire_all()
                    refreshed_units = appliance_apply_units(db, reconcile=False)
                    applied_unit = next((candidate for candidate in refreshed_units if candidate["id"] == unit["id"]), unit)
                    if unit["id"] == "esxi_pxe":
                        if result.get("dry_run"):
                            previous_baseline = load_appliance_apply_baselines(db).get(
                                "esxi_pxe",
                                {},
                            )
                            if not isinstance(previous_baseline, dict):
                                previous_baseline = {}
                            runtime_config_preview = str(
                                previous_baseline.get(
                                    "runtime_config_preview",
                                    previous_baseline.get("config_preview", ""),
                                )
                            )
                        else:
                            runtime_config_preview = str(
                                applied_unit["config_preview"]
                            )
                        applied_unit = {
                            **applied_unit,
                            "runtime_config_preview": runtime_config_preview,
                        }
                    update_appliance_apply_baselines(db, [applied_unit], {unit["id"]})
                else:
                    failed = True
                    for remaining_unit in selected_units[index:]:
                        remaining = steps_by_key.get(remaining_unit["id"])
                        if remaining is None or remaining.status != JobStatus.PENDING.value:
                            continue
                        remaining.status = "skipped"
                        remaining.progress_percent = 100
                        remaining.finished_at = utcnow()
                        remaining.error = f"Skipped because {unit['label']} failed."
                        remaining.result = json.dumps({"summary": remaining_unit["summary"], "reason": "previous_component_failed"}, indent=2)
                if current_payload.get("cancel_requested") and not failed:
                    cancelled = True
                    for remaining_unit in selected_units[index:]:
                        remaining = steps_by_key.get(remaining_unit["id"])
                        if remaining is None or remaining.status != JobStatus.PENDING.value:
                            continue
                        remaining.status = "skipped"
                        remaining.progress_percent = 100
                        remaining.finished_at = utcnow()
                        remaining.error = "Skipped after the master task cancellation request."
                        remaining.result = json.dumps({"summary": remaining_unit["summary"], "reason": "cancelled"}, indent=2)
                db.commit()
                if prune_network_boot_media:
                    removed_media = prune_superseded_shredos_media(db)
                    if removed_media:
                        APPLY_LOGGER.info(
                            "Removed %s superseded ShredOS media snapshot(s) after Network Boot apply.",
                            removed_media,
                        )
                if failed or cancelled:
                    break

            if failed:
                log_appliance_apply_failures(job_id, unit_results)
            succeeded = not failed and not cancelled and all(result["success"] for result in unit_results) and len(unit_results) == len(selected_units)
            log_appliance_apply_submission(
                job_id,
                selected_units=selected_order,
                skipped_changed_units=job_result.get("skipped_changed_units", []),
                unit_results=unit_results,
                succeeded=succeeded,
            )
            db.refresh(job)
            final_payload = _job_payload(job)
            job_result = {
                **final_payload,
                "units": unit_results,
                "dry_run": any(result["dry_run"] for result in unit_results),
            }
            if cancelled:
                job.status = JobStatus.CANCELLED.value
                job_result["state"] = JobStatus.CANCELLED.value
                job.error = "Appliance apply cancelled after the running component completed."
            elif succeeded:
                job.status = JobStatus.SUCCEEDED.value
                job_result["state"] = JobStatus.SUCCEEDED.value
                job.error = None
            else:
                job.status = JobStatus.FAILED.value
                job_result["state"] = JobStatus.FAILED.value
                job.error = job.error or "One or more appliance apply components reported a failure."
            job.finished_at = utcnow()
            job.progress_percent = 100
            job.result = json.dumps(job_result, indent=2)
            db.commit()
            record_audit(
                db,
                actor=job.created_by,
                action="complete_appliance_apply_task",
                resource_type="job",
                resource_id=job.id,
                detail=f"selected_units={','.join(selected_order)}; result={job.status}",
                success=succeeded,
            )
        except Exception as exc:  # noqa: BLE001 - background task must persist a safe terminal state.
            APPLY_LOGGER.exception("Appliance apply task %s failed before completion", job_id)
            db.rollback()
            exception_recovery: tuple[AdapterResult, dict[str, Any]] | None = None
            if handoff_runtime_pending and handoff_recovery_adapter is not None:
                exception_recovery = reconcile_management_handoff_exception(
                    handoff_recovery_adapter,
                    job_id,
                    application_committed=handoff_application_committed,
                )
            job = db.get(Job, job_id)
            if job is None:
                return
            safe_error = str(exc) if isinstance(exc, ApplianceApplyJobError) else "Appliance apply task failed unexpectedly."
            recovery_evidence: dict[str, Any] = {}
            if exception_recovery is not None:
                recovery_result, recovery_evidence = exception_recovery
                recovery_state = str(recovery_evidence.get("management_handoff") or "")
                if recovery_result.returncode == 0 and recovery_evidence.get("rolled_back") is True:
                    safe_error = (
                        "Appliance Apply failed after candidate activation; the previous management path was rolled "
                        "back before the task became terminal."
                    )
                elif recovery_result.returncode == 0 and recovery_state in {"committed", "already committed"}:
                    safe_error = (
                        "Appliance Apply failed after the management baselines committed; the candidate management "
                        "path remains active and its helper acknowledgement is complete."
                    )
                elif recovery_result.returncode == 0 and recovery_state == "no interrupted transaction":
                    safe_error = (
                        "Appliance Apply failed before the privileged management handoff transaction began; "
                        "no runtime rollback was necessary."
                    )
                else:
                    safe_error = (
                        "Appliance Apply failed after candidate activation, and immediate management recovery could "
                        "not be proven. The global apply lock remains held for recovery."
                    )
            finished = utcnow()
            for step in job.steps:
                if step.status == JobStatus.RUNNING.value:
                    step.status = JobStatus.FAILED.value
                    step.error = safe_error
                    step.finished_at = finished
                    step.progress_percent = 100
                elif step.status == JobStatus.PENDING.value:
                    step.status = "skipped"
                    step.error = "Skipped because the master task failed before this component started."
                    step.finished_at = finished
                    step.progress_percent = 100
            job_result = json.loads(job.result or "{}")
            if exception_recovery is not None:
                recovery_result, recovery_evidence = exception_recovery
                job_result["management_handoff_exception_recovery"] = {
                    **adapter_result_to_payload(recovery_result),
                    "evidence": recovery_evidence,
                }
                recovery_state = str(recovery_evidence.get("management_handoff") or "")
                if recovery_result.returncode == 0 and recovery_evidence.get("rolled_back") is True:
                    job_result.pop("management_handoff_runtime_commit_pending", None)
                    job_result.pop("management_handoff_application_committed", None)
                elif recovery_result.returncode == 0 and recovery_state in {"committed", "already committed"}:
                    job_result.pop("management_handoff_runtime_commit_pending", None)
                    job_result.pop("management_handoff_application_committed", None)
                    job_result["management_handoff_runtime_committed"] = True
                elif recovery_result.returncode == 0 and recovery_state == "no interrupted transaction":
                    job_result.pop("management_handoff_runtime_commit_pending", None)
                    job_result.pop("management_handoff_application_committed", None)
                else:
                    job_result["management_handoff_runtime_commit_pending"] = True
                    if handoff_application_committed:
                        job_result["management_handoff_application_committed"] = True
                    else:
                        job_result.pop("management_handoff_application_committed", None)
            job.status = JobStatus.FAILED.value
            job.finished_at = finished
            job.progress_percent = 100
            job.result = json.dumps({**job_result, "units": unit_results}, indent=2)
            job.error = safe_error
            db.commit()
            record_audit(
                db,
                actor=job.created_by,
                action="complete_appliance_apply_task",
                resource_type="job",
                resource_id=job.id,
                detail=f"result={job.status}",
                success=False,
            )
        finally:
            invalidate_appliance_apply_status_projection()


VCF_DEPOT_SOFTWARE_ID_TASK_STEPS = (
    ("stage-tool", "Stage VCF Download Tool"),
    ("apply-properties", "Apply application properties"),
    ("apply-ceip", "Apply VMware CEIP preference"),
    ("generate-software-depot-id", "Generate and read back Software Depot ID"),
)


def ensure_vcf_depot_software_id_task_steps(db: Session, job: Job) -> list[JobStep]:
    """Ensure vcf depot software id task steps.

    Args:
        db: Active database session.
        job: Job being processed.

    Returns:
        The ensure vcf depot software id task steps result.
    """
    existing = {step.component_key: step for step in job.steps}
    for position, (component_key, label) in enumerate(VCF_DEPOT_SOFTWARE_ID_TASK_STEPS, start=1):
        if component_key in existing:
            continue
        step = JobStep(
            id=f"{job.id}:{component_key}",
            job=job,
            component_key=component_key,
            label=label,
            position=position,
            status=JobStatus.PENDING.value,
            progress_percent=0,
            result=json.dumps({"summary": [f"{label} queued."]}, indent=2),
        )
        db.add(step)
        existing[component_key] = step
    db.flush()
    return [existing[component_key] for component_key, _label in VCF_DEPOT_SOFTWARE_ID_TASK_STEPS]


def run_vcf_depot_software_id_job(job_id: str) -> None:
    """Run vcf depot software id job.

    Args:
        job_id: Stable identifier of the associated job resource.
    """
    with SessionLocal() as db:
        job = db.scalar(select(Job).options(selectinload(Job.steps)).where(Job.id == job_id))
        if job is None or job.type != "vcf-depot-software-id" or job.status != JobStatus.PENDING.value:
            return
        task_steps = ensure_vcf_depot_software_id_task_steps(db, job)
        payload = _job_payload(job)
        previous_id = str(vcf_depot_software_depot_id_context(db).get("id") or "").strip()
        job.status = JobStatus.RUNNING.value
        job.started_at = utcnow()
        job.progress_percent = 1
        payload["state"] = JobStatus.RUNNING.value
        job.result = json.dumps(payload, indent=2)
        task_steps[0].status = JobStatus.RUNNING.value
        task_steps[0].started_at = job.started_at
        db.commit()
        try:
            unit = appliance_apply_status(db, "vcf_offline_depot")
            execution_unit = {
                **unit,
                "refresh_vcf_depot_software_depot_id": True,
                "vcf_depot_id_only": True,
            }
            raw_result = execute_appliance_apply_unit(execution_unit, db=db)
            persist_vcf_depot_metadata_from_apply(db, [raw_result])
            software_depot_id = str(vcf_depot_software_depot_id_context(db).get("id") or "").strip()
            id_readback_valid = bool(software_depot_id) and (not previous_id or software_depot_id != previous_id)
            succeeded = bool(raw_result.get("success")) and id_readback_valid
            command_results = list(raw_result.get("commands") or [])
            finished = utcnow()
            log_lines: list[str] = []
            success_messages = {
                "stage-tool": "VCF Download Tool package staged.",
                "apply-properties": "application-prodv2.properties applied.",
                "apply-ceip": "VMware CEIP preference applied.",
                "generate-software-depot-id": (
                    f"Software Depot ID generated and read back: {software_depot_id}"
                    if id_readback_valid
                    else "VCFDT returned without a new persisted Software Depot ID."
                ),
            }
            for index, step in enumerate(task_steps):
                command_result = command_results[index] if index < len(command_results) else None
                step.started_at = step.started_at or job.started_at
                step.finished_at = finished
                step.progress_percent = 100
                if command_result is None:
                    step.status = "skipped"
                    message = f"{step.label} skipped because an earlier VCFDT operation failed."
                    step.error = message
                else:
                    command_returncode = int(command_result.get("returncode") or 0)
                    command_succeeded = command_returncode == 0
                    if step.component_key == "generate-software-depot-id":
                        command_succeeded = command_succeeded and id_readback_valid
                    step.status = JobStatus.SUCCEEDED.value if command_succeeded else JobStatus.FAILED.value
                    if command_succeeded:
                        message = success_messages[step.component_key]
                    elif step.component_key == "generate-software-depot-id" and command_returncode == 0:
                        message = success_messages[step.component_key]
                    else:
                        failure_detail = apply_output_excerpt(
                            _strip_task_action_metadata(command_result.get("stderr") or command_result.get("stdout")),
                            limit=800,
                        )
                        message = f"{step.label} failed{f': {failure_detail}' if failure_detail else '.'}"
                    step.error = None if command_succeeded else message
                step.result = json.dumps({"summary": [message], "stdout": message}, indent=2)
                log_lines.append(f"{step.label}: {message}")
            safe_result = {
                "unit_id": "vcf_offline_depot",
                "label": "VCFDT Software Depot ID",
                "success": succeeded,
                "status": JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value,
                "summary": [
                    "Software Depot ID generated and saved."
                    if succeeded
                    else "Software Depot ID generation failed."
                ],
                "errors": [] if succeeded else ["VCFDT Software Depot ID generation failed. Review the Atlaso operational log."],
            }
            job.status = JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value
            job.finished_at = finished
            job.progress_percent = 100
            job.error = None if succeeded else "VCFDT Software Depot ID generation failed."
            job.result = json.dumps(
                {
                    **payload,
                    "state": job.status,
                    "software_depot_id": software_depot_id if succeeded else "",
                    "log_lines": log_lines,
                    "units": [safe_result],
                },
                indent=2,
            )
            db.commit()
            record_audit(
                db,
                actor=job.created_by,
                action="complete_vcf_depot_software_id_task",
                resource_type="job",
                resource_id=job.id,
                detail=f"result={job.status}",
                success=succeeded,
            )
        except Exception:  # noqa: BLE001 - persist an operator-safe terminal task state.
            APPLY_LOGGER.exception("VCFDT Software Depot ID task %s failed", job_id)
            db.rollback()
            job = db.get(Job, job_id)
            if job is None:
                return
            payload = _job_payload(job)
            job.status = JobStatus.FAILED.value
            job.finished_at = utcnow()
            job.progress_percent = 100
            job.error = "VCFDT Software Depot ID task failed unexpectedly."
            job.result = json.dumps({**payload, "state": JobStatus.FAILED.value}, indent=2)
            finished = job.finished_at
            for step in job.steps:
                if step.status == JobStatus.RUNNING.value:
                    step.status = JobStatus.FAILED.value
                    step.error = "VCFDT Software Depot ID task failed unexpectedly."
                elif step.status == JobStatus.PENDING.value:
                    step.status = "skipped"
                    step.error = "Skipped because an earlier VCFDT operation failed."
                step.finished_at = finished
                step.progress_percent = 100
            db.commit()
            record_audit(
                db,
                actor=job.created_by,
                action="complete_vcf_depot_software_id_task",
                resource_type="job",
                resource_id=job.id,
                detail="result=failed",
                success=False,
            )


def _submit_appliance_apply(
    request: Request,
    background_tasks: BackgroundTasks,
    selected_units: list[str] = Form(default=[]),
    format_confirmations: list[str] = Form(default=[]),
    refresh_vcf_depot_software_depot_id: bool = Form(False),
    csrf: str = Form(...),
    identity: Identity = Depends(require_session_identity),
    db: Session = Depends(get_db),
) -> Response:
    """Handle the submit appliance apply endpoint.

    Args:
        request: Incoming HTTP request.
        background_tasks: Background tasks supplied by the caller.
        selected_units: Selected units supplied by the caller.
        format_confirmations: Format confirmations supplied by the caller.
        refresh_vcf_depot_software_depot_id: Identifier of the refresh vcf depot software depot.
        csrf: Validated CSRF token authorizing the request.
        identity: Authenticated identity authorizing the request.
        db: Active database session.

    Returns:
        The endpoint response.
    """
    verify_csrf(request, csrf)
    wants_json = "application/json" in request.headers.get("accept", "")
    invalidate_observed_management_dhcp_dns()
    units = appliance_apply_units(db)
    unit_map = {unit["id"]: unit for unit in units}
    selected_ids = {unit_id for unit_id in selected_units if unit_id in APPLIANCE_APPLY_UNIT_IDS}
    refresh_vcf_depot_software_depot_id = bool(
        refresh_vcf_depot_software_depot_id and "vcf_offline_depot" in selected_ids
    )
    ntp_settings_for_apply = unit_map.get("ntpd", {}).get("context", {}).get("ntp_settings")
    ca_required_for_nts = bool(
        "ntpd" in selected_ids
        and getattr(ntp_settings_for_apply, "nts_server_enabled", False)
        and "ca" in unit_map
    )
    if ca_required_for_nts:
        selected_ids.add("ca")
    dns_settings_for_apply = unit_map.get("dnsmasq", {}).get("context", {}).get("dns_settings")
    local_dns_disable_requires_resolver = bool(
        "dnsmasq" in selected_ids
        and not getattr(dns_settings_for_apply, "enabled", False)
        and applied_local_dns_enabled(load_appliance_apply_baselines(db).get("dnsmasq"))
    )
    if local_dns_disable_requires_resolver and "appliance_settings" in unit_map:
        selected_ids.add("appliance_settings")
    ldap_related_units = {"ca", "dnsmasq", "firewall", "ldap"}
    ldap_context_for_apply = unit_map.get("ldap", {}).get("context", {})
    ldap_dependency_active = bool(
        getattr(ldap_context_for_apply.get("ldap_settings"), "enabled", False)
        or ldap_context_for_apply.get("ldap_organizations")
        or ldap_context_for_apply.get("ldap_recovery_archive")
    )
    if ldap_dependency_active and selected_ids & ldap_related_units and any(unit_map[unit_id]["changed"] for unit_id in ldap_related_units if unit_id in unit_map):
        selected_ids.update(
            unit_id
            for unit_id in ldap_related_units
            if unit_id in unit_map and unit_map[unit_id]["changed"]
        )
    depot_context_for_apply = unit_map.get("vcf_offline_depot", {}).get("context", {})
    depot_settings_for_apply = depot_context_for_apply.get("vcf_depot_settings")
    depot_publishing_units = {"vcf_offline_depot", "public_services"}
    depot_http_user_id = getattr(depot_settings_for_apply, "http_user_id", None)
    local_users_for_apply = unit_map.get("local_users", {}).get("context", {}).get("local_users", [])
    depot_http_user_for_apply = next(
        (user for user in local_users_for_apply if user.id == depot_http_user_id),
        None,
    )
    depot_http_user_has_pending_state = bool(
        depot_http_user_for_apply
        and (
            depot_http_user_for_apply.os_sync_status != "applied"
            or depot_http_user_for_apply.os_unlock_requested_at
            or has_pending_os_password(depot_http_user_for_apply)
        )
    )
    local_users_required_for_authenticated_depot = bool(
        selected_ids & depot_publishing_units
        and getattr(depot_settings_for_apply, "enabled", False)
        and not getattr(depot_settings_for_apply, "allow_unauthenticated_access", False)
        and depot_http_user_has_pending_state
    )
    if (
        local_users_required_for_authenticated_depot
        and "local_users" in unit_map
        and unit_map["local_users"]["changed"]
    ):
        selected_ids.add("local_users")
    management_handoff = bool(
        (
            selected_ids.intersection(MANAGEMENT_HANDOFF_UNIT_IDS)
            and unit_map.get("network", {}).get("management_handoff_required")
        )
        or (
            "wan" in selected_ids
            and unit_map.get("network", {}).get("management_default_mirror_change")
        )
    )
    if management_handoff:
        selected_ids.update(
            unit_id for unit_id in MANAGEMENT_HANDOFF_UNIT_IDS if unit_id in unit_map
        )
        if (
            (
                unit_map.get("network", {}).get("management_gateway_route_migrations")
                or unit_map.get("network", {}).get("management_default_mirror_change")
            )
            and "wan" in unit_map
        ):
            selected_ids.add("wan")
    if not selected_ids:
        detail = "Select at least one appliance change to submit."
        return JSONResponse({"detail": detail}, status_code=422) if wants_json else Response(detail, status_code=422, media_type="text/plain")
    invalid_units = [unit for unit in units if unit["id"] in selected_ids and unit["validation_errors"]]
    if invalid_units:
        detail = "Resolve validation errors before submitting appliance changes."
        return JSONResponse({"detail": detail}, status_code=422) if wants_json else Response(detail, status_code=422, media_type="text/plain")

    selected_ordered_units = [unit for unit in units if unit["id"] in selected_ids]
    skipped_changed_units = [
        {"unit_id": unit["id"], "label": unit["label"], "summary": unit["summary"]}
        for unit in units
        if unit["changed"] and unit["id"] not in selected_ids
    ]
    parsed_format_confirmations: dict[int, str] = {}
    for raw_confirmation in format_confirmations:
        try:
            item = json.loads(raw_confirmation)
            parsed_format_confirmations[int(item["volume_id"])] = str(item["confirmation"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            detail = "A disk format confirmation was malformed. Reopen appliance review and try again."
            return JSONResponse({"detail": detail}, status_code=422) if wants_json else Response(detail, status_code=422, media_type="text/plain")

    required_format_volumes = []
    if "esx_storage" in selected_ids:
        required_format_volumes = [
            volume
            for volume in unit_map["esx_storage"]["context"]["esx_storage_manifest"]["volumes"]
            if volume.get("requires_format")
        ]
    for volume in required_format_volumes:
        expected = f"FORMAT {volume['name']}"
        if parsed_format_confirmations.get(int(volume["id"])) != expected:
            detail = f"Formatting {volume['name']} requires the exact confirmation {expected!r}."
            return JSONResponse({"detail": detail}, status_code=422) if wants_json else Response(detail, status_code=422, media_type="text/plain")

    job_result = {
        "selected_units": [unit["id"] for unit in selected_ordered_units],
        "skipped_changed_units": skipped_changed_units,
        "captured_units": [
            {
                "unit_id": unit["id"],
                "label": unit["label"],
                "snapshot_hash": unit["snapshot_hash"],
                "summary": unit["summary"],
                "validation_errors": unit["validation_errors"],
                "validation_warnings": unit["validation_warnings"],
                "config_path": unit["config_path"],
                "config_preview": unit["config_preview"],
                "config_diff": unit["config_diff"],
            }
            for unit in selected_ordered_units
        ],
        "units": [],
        "dry_run": bool(get_settings().dry_run_system_adapters),
        "format_authorizations": [],
        "refresh_vcf_depot_software_depot_id": refresh_vcf_depot_software_depot_id,
        "management_handoff": management_handoff,
        "management_handoff_units": [
            unit_id
            for unit_id in (*MANAGEMENT_HANDOFF_UNIT_IDS, "wan")
            if management_handoff and unit_id in selected_ids
        ],
    }
    vcf_depot_submit_guard = VCF_DEPOT_SUBMIT_LOCK if "vcf_offline_depot" in selected_ids else nullcontext()
    with vcf_depot_submit_guard, APPLIANCE_APPLY_SUBMIT_LOCK:
        db.expire_all()
        if "vcf_offline_depot" in selected_ids:
            acquire_vcf_depot_admission_gate(db)
        active_job = active_appliance_apply_job(db)
        if active_job is not None:
            detail = (
                f"Appliance apply task {active_job.id} is already {active_job.status}. "
                "Wait for it to finish before submitting another appliance apply task."
            )
            return JSONResponse({"detail": detail}, status_code=409) if wants_json else Response(detail, status_code=409, media_type="text/plain")
        if "vcf_offline_depot" in selected_ids:
            conflicting_job = active_vcf_depot_execution_job(db)
            if conflicting_job is not None:
                detail = vcf_depot_execution_conflict_detail(conflicting_job)
                return JSONResponse({"detail": detail}, status_code=409) if wants_json else Response(detail, status_code=409, media_type="text/plain")

        job_id = f"job_{uuid4().hex[:12]}"
        if required_format_volumes:
            manifest = unit_map["esx_storage"]["context"]["esx_storage_manifest"]
            job_result["format_authorizations"] = [
                esx_storage_format_authorization(
                    job_id=job_id,
                    manifest=manifest,
                    volume=volume,
                    confirmation=parsed_format_confirmations[int(volume["id"])],
                )
                for volume in required_format_volumes
            ]
        job = Job(
            id=job_id,
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            vcf_depot_operation="vcf_offline_depot" in selected_ids,
            created_by=identity.username,
            progress_percent=0,
            result=json.dumps(job_result, indent=2),
            error=None,
        )
        db.add(job)
        for position, unit in enumerate(selected_ordered_units, start=1):
            captured = next(item for item in job_result["captured_units"] if item["unit_id"] == unit["id"])
            db.add(
                JobStep(
                    id=f"{job_id}:{unit['id']}",
                    job=job,
                    component_key=unit["id"],
                    label=unit["label"],
                    position=position,
                    status=JobStatus.PENDING.value,
                    progress_percent=0,
                    result=json.dumps(captured, indent=2, sort_keys=True),
                    error=None,
                )
            )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            if "vcf_offline_depot" not in selected_ids:
                raise
            conflicting_job = active_vcf_depot_execution_job(db)
            detail = (
                vcf_depot_execution_conflict_detail(conflicting_job)
                if conflicting_job is not None
                else "Another VCFDT operation became active. Wait for it to finish and try again."
            )
            return JSONResponse({"detail": detail}, status_code=409) if wants_json else Response(detail, status_code=409, media_type="text/plain")
        record_audit(
            db,
            actor=identity.username,
            action="create_appliance_apply_task",
            resource_type="job",
            resource_id=job.id,
            detail=f"selected_units={','.join(job_result['selected_units'])}",
        )
    background_tasks.add_task(run_appliance_apply_job, job.id)
    if wants_json:
        db.refresh(job)
        return JSONResponse(
            {
                "status": "pending",
                "job_id": job.id,
                "task": _task_row(job, identity),
                "status_url": f"/tasks/{job.id}/status",
            },
            status_code=202,
        )
    return RedirectResponse(f"/tasks?job_id={quote(job.id)}", status_code=303)


_management_before_routes_wan_router = router
_appliance_apply_ui = build_appliance_apply_ui_router(
    ApplianceApplyUiDependencies(
        require_management_ui_request=require_management_ui_request,
        require_session_identity=require_session_identity,
        invalidate_observed_management_dhcp_dns=invalidate_observed_management_dhcp_dns,
        appliance_apply_context=appliance_apply_context,
        appliance_apply_status_projection=appliance_apply_status_projection,
        appliance_apply_client_status=appliance_apply_client_status,
        active_appliance_apply_job=active_appliance_apply_job,
        submit_appliance_apply=_submit_appliance_apply,
        task_row=_task_row,
    )
)
appliance_apply_router = _appliance_apply_ui.router
appliance_apply_page = _appliance_apply_ui.endpoints["appliance_apply_page"]
appliance_apply_review = _appliance_apply_ui.endpoints["appliance_apply_review"]
appliance_apply_status_api = _appliance_apply_ui.endpoints[
    "appliance_apply_status_api"
]
submit_appliance_apply = _appliance_apply_ui.endpoints["submit_appliance_apply"]

_network_objects_ui = build_network_objects_ui_router(
    NetworkObjectsUiDependencies(
        require_management_ui_request=require_management_ui_request,
        render=render,
        verify_csrf=verify_csrf,
        setting_value=setting_value,
        set_setting_value=set_setting_value,
        grid_request=grid_request,
        firewall_context=firewall_context,
    )
)
network_objects_router = _network_objects_ui.router
network_objects = _network_objects_ui.endpoints["network_objects"]
network_objects_context = _network_objects_ui.endpoints["network_objects_context"]
firewall_source_group_state_for_db = _network_objects_ui.endpoints[
    "source_group_state_for_db"
]
persist_firewall_source_group_state = _network_objects_ui.endpoints[
    "persist_source_group_state"
]
legacy_firewall_source_groups_page = _network_objects_ui.endpoints[
    "legacy_source_groups_page"
]
update_firewall_source_groups = _network_objects_ui.endpoints[
    "update_source_groups"
]
update_firewall_source_groups_legacy = _network_objects_ui.endpoints[
    "update_source_groups_legacy"
]

_firewall_ui = build_firewall_ui_router(
    FirewallUiDependencies(
        require_management_ui_request=require_management_ui_request,
        render=render,
        firewall_context=firewall_context,
        appliance_apply_status=lambda *args, **kwargs: appliance_apply_status(*args, **kwargs),
        verify_csrf=verify_csrf,
        get_firewall_settings_row=get_firewall_settings_row,
        source_group_state_for_db=firewall_source_group_state_for_db,
        persist_source_group_state=persist_firewall_source_group_state,
        grid_request=grid_request,
        grid_saved_response=grid_saved_response,
    )
)
firewall_router = _firewall_ui.router
firewall = _firewall_ui.endpoints["firewall"]
update_firewall_settings = _firewall_ui.endpoints["update_firewall_settings"]
update_managed_firewall_rule_source_group = _firewall_ui.endpoints[
    "update_managed_firewall_rule_source_group"
]
_assign_firewall_rule = _firewall_ui.endpoints["_assign_firewall_rule"]
create_firewall_rule = _firewall_ui.endpoints["create_firewall_rule"]
update_firewall_rule = _firewall_ui.endpoints["update_firewall_rule"]
delete_firewall_rule = _firewall_ui.endpoints["delete_firewall_rule"]

_routes_wan_ui = build_routes_wan_ui_router(
    RoutesWanUiDependencies(
        require_management_ui_request=require_management_ui_request,
        render=render,
        appliance_apply_status=appliance_apply_status,
        routes_wan_context=routes_wan_context,
        verify_csrf=verify_csrf,
        wan_route_targets=wan_route_targets,
        wan_nat_targets_from_route_targets=wan_nat_targets_from_route_targets,
        firewall_source_group_state_for_db=firewall_source_group_state_for_db,
    )
)
routes_wan_router = _routes_wan_ui.router
routes_wan = _routes_wan_ui.endpoints["routes_wan"]
parse_int_form_value = _routes_wan_ui.endpoints["parse_int_form_value"]
parse_optional_int_form_value = _routes_wan_ui.endpoints[
    "parse_optional_int_form_value"
]
parse_float_form_value = _routes_wan_ui.endpoints["parse_float_form_value"]
validate_route_form_values = _routes_wan_ui.endpoints["validate_route_form_values"]
validate_wan_policy_form_values = _routes_wan_ui.endpoints[
    "validate_wan_policy_form_values"
]
validate_nat_rule_form_values = _routes_wan_ui.endpoints[
    "validate_nat_rule_form_values"
]
validate_routing_rule_form_values = _routes_wan_ui.endpoints[
    "validate_routing_rule_form_values"
]
create_route_from_ui = _routes_wan_ui.endpoints["create_route_from_ui"]
edit_route_from_ui = _routes_wan_ui.endpoints["edit_route_from_ui"]
delete_route_from_ui = _routes_wan_ui.endpoints["delete_route_from_ui"]
create_routing_rule_from_ui = _routes_wan_ui.endpoints[
    "create_routing_rule_from_ui"
]
edit_routing_rule_from_ui = _routes_wan_ui.endpoints[
    "edit_routing_rule_from_ui"
]
delete_routing_rule_from_ui = _routes_wan_ui.endpoints[
    "delete_routing_rule_from_ui"
]
create_nat_rule_from_ui = _routes_wan_ui.endpoints["create_nat_rule_from_ui"]
edit_nat_rule_from_ui = _routes_wan_ui.endpoints["edit_nat_rule_from_ui"]
delete_nat_rule_from_ui = _routes_wan_ui.endpoints["delete_nat_rule_from_ui"]
create_policy_from_ui = _routes_wan_ui.endpoints["create_policy_from_ui"]
edit_policy_from_ui = _routes_wan_ui.endpoints["edit_policy_from_ui"]
delete_policy_from_ui = _routes_wan_ui.endpoints["delete_policy_from_ui"]

_physical_vlans_ui = build_physical_vlan_ui_router(
    PhysicalVlanUiDependencies(
        require_management_ui_request=require_management_ui_request,
        render=render,
        verify_csrf=verify_csrf,
        grid_saved_response=grid_saved_response,
        grid_error_response=grid_error_response,
        network_context=network_context,
        refresh_interface_service_dns_aliases=refresh_interface_service_dns_aliases,
        validate_vlan_form_values=validate_vlan_form_values,
        vlan_form_validation_response=vlan_form_validation_response,
        appliance_apply_status=appliance_apply_status,
        vlan_interface_to_dict=vlan_interface_to_dict,
    )
)
physical_vlans_router = _physical_vlans_ui.router
physical_interfaces_page = _physical_vlans_ui.endpoints["physical_interfaces_page"]
refresh_physical_interfaces_from_ui = _physical_vlans_ui.endpoints[
    "refresh_physical_interfaces_from_ui"
]
edit_physical_interface_from_ui = _physical_vlans_ui.endpoints[
    "edit_physical_interface_from_ui"
]
forget_missing_physical_interface_from_ui = _physical_vlans_ui.endpoints[
    "forget_missing_physical_interface_from_ui"
]
vlan_interfaces_page = _physical_vlans_ui.endpoints["vlan_interfaces_page"]
create_vlan_interface_from_ui = _physical_vlans_ui.endpoints[
    "create_vlan_interface_from_ui"
]
edit_vlan_interface_from_ui = _physical_vlans_ui.endpoints[
    "edit_vlan_interface_from_ui"
]
delete_vlan_interface_from_ui = _physical_vlans_ui.endpoints[
    "delete_vlan_interface_from_ui"
]

_dns_dhcp_ui = build_dns_dhcp_ui_router(
    DnsDhcpUiDependencies(
        require_management_ui_request=require_management_ui_request,
        dns_domains_for_settings=dns_domains_for_settings,
        dnsmasq_apply_status=dnsmasq_apply_status,
        dnsmasq_context=dnsmasq_context,
        ensure_dns_for_dhcp_reservation=ensure_dns_for_dhcp_reservation,
        get_dhcp_settings_row=get_dhcp_settings_row,
        get_dns_settings_row=get_dns_settings_row,
        grid_error_response=grid_error_response,
        grid_request=grid_request,
        grid_saved_response=grid_saved_response,
        normalize_dns_hostname=normalize_dns_hostname,
        parse_dhcp_option_scope_id=parse_dhcp_option_scope_id,
        parse_optional_esxi_kickstart_id=parse_optional_esxi_kickstart_id,
        records_for_domain=records_for_domain,
        render=render,
        resolve_service_bind_targets=resolve_service_bind_targets,
        save_disabled_dns_domains=save_disabled_dns_domains,
        save_dns_domain_description=save_dns_domain_description,
        save_dns_domains=save_dns_domains,
        service_bind_options=service_bind_options,
        set_setting_value=set_setting_value,
        verify_csrf=verify_csrf,
        require_esxi_pxe_write=lambda identity: require_esxi_pxe_write(identity),
    )
)
dns_dhcp_router = _dns_dhcp_ui.router
dns_page = _dns_dhcp_ui.endpoints["dns_page"]
update_dns_from_ui = _dns_dhcp_ui.endpoints["update_dns_from_ui"]
create_dns_zone_from_ui = _dns_dhcp_ui.endpoints["create_dns_zone_from_ui"]
set_dns_zone_enabled_from_ui = _dns_dhcp_ui.endpoints["set_dns_zone_enabled_from_ui"]
delete_dns_zone_from_ui = _dns_dhcp_ui.endpoints["delete_dns_zone_from_ui"]
create_dns_record_from_ui = _dns_dhcp_ui.endpoints["create_dns_record_from_ui"]
delete_dns_record_from_ui = _dns_dhcp_ui.endpoints["delete_dns_record_from_ui"]
edit_dns_record_from_ui = _dns_dhcp_ui.endpoints["edit_dns_record_from_ui"]
import_dns_hosts_from_ui = _dns_dhcp_ui.endpoints["import_dns_hosts_from_ui"]
import_dns_zone_from_ui = _dns_dhcp_ui.endpoints["import_dns_zone_from_ui"]
dhcp_page = _dns_dhcp_ui.endpoints["dhcp_page"]
update_dhcp_from_ui = _dns_dhcp_ui.endpoints["update_dhcp_from_ui"]
create_dhcp_scope_from_ui = _dns_dhcp_ui.endpoints["create_dhcp_scope_from_ui"]
edit_dhcp_scope_from_ui = _dns_dhcp_ui.endpoints["edit_dhcp_scope_from_ui"]
delete_dhcp_scope_from_ui = _dns_dhcp_ui.endpoints["delete_dhcp_scope_from_ui"]
create_dhcp_option_from_ui = _dns_dhcp_ui.endpoints["create_dhcp_option_from_ui"]
edit_dhcp_option_from_ui = _dns_dhcp_ui.endpoints["edit_dhcp_option_from_ui"]
delete_dhcp_option_from_ui = _dns_dhcp_ui.endpoints["delete_dhcp_option_from_ui"]
create_dhcp_reservation_from_ui = _dns_dhcp_ui.endpoints["create_dhcp_reservation_from_ui"]
create_esxi_pxe_host_from_dhcp_lease = _dns_dhcp_ui.endpoints["create_esxi_pxe_host_from_dhcp_lease"]
deny_dhcp_lease_mac_from_ui = _dns_dhcp_ui.endpoints["deny_dhcp_lease_mac_from_ui"]
edit_dhcp_reservation_from_ui = _dns_dhcp_ui.endpoints["edit_dhcp_reservation_from_ui"]
delete_dhcp_reservation_from_ui = _dns_dhcp_ui.endpoints["delete_dhcp_reservation_from_ui"]
_lease_hostname_or_default = _dns_dhcp_ui.endpoints["_lease_hostname_or_default"]

_identity_ui = build_identity_ui_router(
    IdentityUiDependencies(
        require_management_ui_request=require_management_ui_request,
        appliance_apply_status=appliance_apply_status,
        ensure_ca_state=ensure_ca_state,
        ensure_dns_for_oidc=ensure_dns_for_oidc,
        get_dns_settings_row=get_dns_settings_row,
        grid_request=grid_request,
        grid_saved_response=grid_saved_response,
        ldap_service_bind_options=ldap_service_bind_options,
        local_users_password_policy=local_users_password_policy,
        normalize_dns_hostname=normalize_dns_hostname,
        protect_last_admin=protect_last_admin,
        public_services_context=public_services_context,
        render=render,
        require_admin_identity=require_admin_identity,
        resolve_ldap_bind_targets=resolve_ldap_bind_targets,
        revoke_user_tokens=revoke_user_tokens,
        roles_from_form=roles_from_form,
        set_setting_value=set_setting_value,
        user_to_dict=user_to_dict,
        users_context=users_context,
        verify_csrf=verify_csrf,
    )
)
identity_router = _identity_ui.router
authentication = _identity_ui.endpoints["authentication"]
openid_connect = _identity_ui.endpoints["openid_connect"]
api_token_grid_row = _identity_ui.endpoints["api_token_grid_row"]
authentication_context = _identity_ui.endpoints["authentication_context"]
update_oidc_provider_from_ui = _identity_ui.endpoints["update_oidc_provider_from_ui"]
create_oidc_client_from_ui = _identity_ui.endpoints["create_oidc_client_from_ui"]
update_oidc_client_from_ui = _identity_ui.endpoints["update_oidc_client_from_ui"]
export_oidc_client_integration_from_ui = _identity_ui.endpoints["export_oidc_client_integration_from_ui"]
create_oidc_group_mapping_from_ui = _identity_ui.endpoints["create_oidc_group_mapping_from_ui"]
update_oidc_group_mapping_from_ui = _identity_ui.endpoints["update_oidc_group_mapping_from_ui"]
delete_oidc_group_mapping_from_ui = _identity_ui.endpoints["delete_oidc_group_mapping_from_ui"]
rotate_oidc_client_secret_from_ui = _identity_ui.endpoints["rotate_oidc_client_secret_from_ui"]
delete_oidc_client_from_ui = _identity_ui.endpoints["delete_oidc_client_from_ui"]
create_oidc_signing_key_from_ui = _identity_ui.endpoints["create_oidc_signing_key_from_ui"]
delete_retired_oidc_signing_key_from_ui = _identity_ui.endpoints["delete_retired_oidc_signing_key_from_ui"]
create_token_from_ui = _identity_ui.endpoints["create_token_from_ui"]
revoke_token_from_ui = _identity_ui.endpoints["revoke_token_from_ui"]
users_page = _identity_ui.endpoints["users_page"]
users_status = _identity_ui.endpoints["users_status"]
update_users_password_policy = _identity_ui.endpoints["update_users_password_policy"]
create_user_from_ui = _identity_ui.endpoints["create_user_from_ui"]
update_user_from_ui = _identity_ui.endpoints["update_user_from_ui"]
disable_user_from_ui = _identity_ui.endpoints["disable_user_from_ui"]
request_user_os_unlock_from_ui = _identity_ui.endpoints["request_user_os_unlock_from_ui"]
delete_user_from_ui = _identity_ui.endpoints["delete_user_from_ui"]
reset_user_password_from_ui = _identity_ui.endpoints["reset_user_password_from_ui"]
legacy_ldap_users_redirect = _identity_ui.endpoints["legacy_ldap_users_redirect"]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)
_certificate_trust_ui = build_certificate_trust_ui_routers(
    CertificateTrustUiDependencies(
        public_router=public_router,
        protocol_router=protocol_router,
        appliance_apply_status=appliance_apply_status,
        ca_context=ca_context,
        ca_request_context=ca_request_context,
        ensure_ca_state=ensure_ca_state,
        ensure_dns_for_ca_portal=ensure_dns_for_ca_portal,
        ensure_dns_for_kms=ensure_dns_for_kms,
        get_ca_settings_row=get_ca_settings_row,
        get_kms_settings_row=get_kms_settings_row,
        grid_error_response=grid_error_response,
        grid_request=grid_request,
        grid_saved_response=grid_saved_response,
        kms_context=kms_context,
        normalize_dns_hostname=normalize_dns_hostname,
        primary_listen_address=primary_listen_address,
        primary_listen_interface=primary_listen_interface,
        public_ca_context=public_ca_context,
        public_portal_links_context=public_portal_links_context,
        public_ui_request_allowed=public_ui_request_allowed,
        render=render,
        request_public_service_route_allowed=request_public_service_route_allowed,
        require_certificate_workflow_identity=require_certificate_workflow_identity,
        require_management_ui_request=require_management_ui_request,
        resolve_service_bind_targets=resolve_service_bind_targets,
        verify_csrf=verify_csrf,
    )
)
certificate_trust_ca_router = _certificate_trust_ui.ca_router
certificate_trust_kms_router = _certificate_trust_ui.kms_router
certificate_authority_page = _certificate_trust_ui.endpoints["certificate_authority_page"]
public_ca_page = _certificate_trust_ui.endpoints["public_ca_page"]
ca_public_login_response = _certificate_trust_ui.endpoints["ca_public_login_response"]
authenticate_ca_portal_session = _certificate_trust_ui.endpoints["authenticate_ca_portal_session"]
ca_public_login_page = _certificate_trust_ui.endpoints["ca_public_login_page"]
ca_public_login = _certificate_trust_ui.endpoints["ca_public_login"]
public_root_ca_response = _certificate_trust_ui.endpoints["public_root_ca_response"]
download_public_root_ca = _certificate_trust_ui.endpoints["download_public_root_ca"]
download_public_ca_bundle = _certificate_trust_ui.endpoints["download_public_ca_bundle"]
ca_requests_page = _certificate_trust_ui.endpoints["ca_requests_page"]
ca_request_portal_login_response = _certificate_trust_ui.endpoints["ca_request_portal_login_response"]
ca_portal_requests_page = _certificate_trust_ui.endpoints["ca_portal_requests_page"]
ca_request_portal_login = _certificate_trust_ui.endpoints["ca_request_portal_login"]
ca_request_portal_logout = _certificate_trust_ui.endpoints["ca_request_portal_logout"]
_stage_ca_certificate_request = _certificate_trust_ui.endpoints["_stage_ca_certificate_request"]
_revoke_ca_certificate = _certificate_trust_ui.endpoints["_revoke_ca_certificate"]
submit_ca_request_from_portal = _certificate_trust_ui.endpoints["submit_ca_request_from_portal"]
submit_ca_request_from_portal_alias = _certificate_trust_ui.endpoints["submit_ca_request_from_portal_alias"]
revoke_ca_certificate_from_portal = _certificate_trust_ui.endpoints["revoke_ca_certificate_from_portal"]
revoke_ca_certificate_from_portal_alias = _certificate_trust_ui.endpoints["revoke_ca_certificate_from_portal_alias"]
download_root_ca = _certificate_trust_ui.endpoints["download_root_ca"]
download_ca_bundle = _certificate_trust_ui.endpoints["download_ca_bundle"]
get_exportable_ca_certificate = _certificate_trust_ui.endpoints["get_exportable_ca_certificate"]
download_ca_certificate = _certificate_trust_ui.endpoints["download_ca_certificate"]
download_ca_certificate_chain = _certificate_trust_ui.endpoints["download_ca_certificate_chain"]
download_ca_certificate_private_key = _certificate_trust_ui.endpoints["download_ca_certificate_private_key"]
update_ca_settings_from_ui = _certificate_trust_ui.endpoints["update_ca_settings_from_ui"]
parse_ca_profile_id = _certificate_trust_ui.endpoints["parse_ca_profile_id"]
create_ca_profile_from_ui = _certificate_trust_ui.endpoints["create_ca_profile_from_ui"]
edit_ca_profile_from_ui = _certificate_trust_ui.endpoints["edit_ca_profile_from_ui"]
delete_ca_profile_from_ui = _certificate_trust_ui.endpoints["delete_ca_profile_from_ui"]
create_ca_certificate_from_ui = _certificate_trust_ui.endpoints["create_ca_certificate_from_ui"]
edit_ca_certificate_from_ui = _certificate_trust_ui.endpoints["edit_ca_certificate_from_ui"]
delete_ca_certificate_from_ui = _certificate_trust_ui.endpoints["delete_ca_certificate_from_ui"]
_management_between_dns_dhcp_managed_ldap_router = router
_managed_ldap_ui = build_managed_ldap_ui_router(
    ManagedLdapUiDependencies(
        require_management_ui_request=require_management_ui_request,
        render=render,
        verify_csrf=verify_csrf,
        appliance_apply_status=appliance_apply_status,
        appliance_apply_client_status=appliance_apply_client_status,
        get_ldap_settings_row=get_ldap_settings_row,
        resolve_ldap_bind_targets=resolve_ldap_bind_targets,
        ensure_dns_for_ldap=ensure_dns_for_ldap,
        ldap_context=ldap_context,
        require_admin_identity=require_admin_identity,
        resolve_vcf_helper_credentials=lambda *args, **kwargs: _resolve_vcf_helper_credentials(*args, **kwargs),
        vcf_helper_page_context=lambda *args, **kwargs: vcf_helper_page_context(*args, **kwargs),
        get_ca_settings_row=get_ca_settings_row,
        normalize_dns_hostname=normalize_dns_hostname,
    )
)
managed_ldap_router = _managed_ldap_ui.router
ldap_page = _managed_ldap_ui.endpoints["ldap_page"]
update_ldap_settings_from_ui = _managed_ldap_ui.endpoints["update_ldap_settings_from_ui"]
create_ldap_organization_from_ui = _managed_ldap_ui.endpoints["create_ldap_organization_from_ui"]
delete_ldap_organization_from_ui = _managed_ldap_ui.endpoints["delete_ldap_organization_from_ui"]
rotate_ldap_bind_credential_from_ui = _managed_ldap_ui.endpoints["rotate_ldap_bind_credential_from_ui"]
_unique_ldap_synthetic_name = _managed_ldap_ui.endpoints["_unique_ldap_synthetic_name"]
_synthetic_ldap_password = _managed_ldap_ui.endpoints["_synthetic_ldap_password"]
_ldap_credentials_csv = _managed_ldap_ui.endpoints["_ldap_credentials_csv"]
generate_ldap_directory_from_ui = _managed_ldap_ui.endpoints["generate_ldap_directory_from_ui"]
create_ldap_user_from_ui = _managed_ldap_ui.endpoints["create_ldap_user_from_ui"]
edit_ldap_user_from_ui = _managed_ldap_ui.endpoints["edit_ldap_user_from_ui"]
reset_ldap_user_password_from_ui = _managed_ldap_ui.endpoints["reset_ldap_user_password_from_ui"]
unlock_ldap_user_from_ui = _managed_ldap_ui.endpoints["unlock_ldap_user_from_ui"]
set_ldap_user_enabled_from_ui = _managed_ldap_ui.endpoints["set_ldap_user_enabled_from_ui"]
delete_ldap_user_from_ui = _managed_ldap_ui.endpoints["delete_ldap_user_from_ui"]
ldap_group_members_from_form = _managed_ldap_ui.endpoints["ldap_group_members_from_form"]
create_ldap_group_from_ui = _managed_ldap_ui.endpoints["create_ldap_group_from_ui"]
edit_ldap_group_from_ui = _managed_ldap_ui.endpoints["edit_ldap_group_from_ui"]
update_ldap_group_members_from_ui = _managed_ldap_ui.endpoints["update_ldap_group_members_from_ui"]
delete_ldap_group_from_ui = _managed_ldap_ui.endpoints["delete_ldap_group_from_ui"]
set_ldap_group_enabled_from_ui = _managed_ldap_ui.endpoints["set_ldap_group_enabled_from_ui"]
download_ldap_vcf_bundle = _managed_ldap_ui.endpoints["download_ldap_vcf_bundle"]
inspect_ldap_vcf_from_ui = _managed_ldap_ui.endpoints["inspect_ldap_vcf_from_ui"]
configure_ldap_vcf_from_ui = _managed_ldap_ui.endpoints["configure_ldap_vcf_from_ui"]
export_ldap_recovery_from_ui = _managed_ldap_ui.endpoints["export_ldap_recovery_from_ui"]
import_ldap_recovery_from_ui = _managed_ldap_ui.endpoints["import_ldap_recovery_from_ui"]

kms_page = _certificate_trust_ui.endpoints["kms_page"]
download_vsphere_key_provider_server_chain = _certificate_trust_ui.endpoints["download_vsphere_key_provider_server_chain"]
update_kms_settings_from_ui = _certificate_trust_ui.endpoints["update_kms_settings_from_ui"]
_vsphere_grid_error = _certificate_trust_ui.endpoints["_vsphere_grid_error"]
create_vsphere_provider_from_ui = _certificate_trust_ui.endpoints["create_vsphere_provider_from_ui"]
edit_vsphere_provider_from_ui = _certificate_trust_ui.endpoints["edit_vsphere_provider_from_ui"]
delete_vsphere_provider_from_ui = _certificate_trust_ui.endpoints["delete_vsphere_provider_from_ui"]
_vsphere_vcenter_row = _certificate_trust_ui.endpoints["_vsphere_vcenter_row"]
_attach_vsphere_public_certificate = _certificate_trust_ui.endpoints["_attach_vsphere_public_certificate"]
create_vsphere_vcenter_from_ui = _certificate_trust_ui.endpoints["create_vsphere_vcenter_from_ui"]
edit_vsphere_vcenter_from_ui = _certificate_trust_ui.endpoints["edit_vsphere_vcenter_from_ui"]
delete_vsphere_vcenter_from_ui = _certificate_trust_ui.endpoints["delete_vsphere_vcenter_from_ui"]
add_vsphere_certificate_from_ui = _certificate_trust_ui.endpoints["add_vsphere_certificate_from_ui"]
retire_vsphere_certificate_from_ui = _certificate_trust_ui.endpoints["retire_vsphere_certificate_from_ui"]

_ntp_ui = build_ntp_ui_router(
    NtpUiDependencies(
        ensure_ca_state=lambda *args, **kwargs: ensure_ca_state(*args, **kwargs),
        get_ntp_settings_row=lambda *args, **kwargs: get_ntp_settings_row(*args, **kwargs),
        normalize_dns_hostname=lambda *args, **kwargs: normalize_dns_hostname(*args, **kwargs),
        ntp_context=lambda *args, **kwargs: ntp_context(*args, **kwargs),
        ntp_nts_certificate_paths=lambda *args, **kwargs: ntp_nts_certificate_paths(*args, **kwargs),
        ntpd_apply_status=lambda *args, **kwargs: ntpd_apply_status(*args, **kwargs),
        ntpd_capabilities_payload=lambda *args, **kwargs: ntpd_capabilities_payload(*args, **kwargs),
        primary_listen_address=lambda *args, **kwargs: primary_listen_address(*args, **kwargs),
        primary_listen_interface=lambda *args, **kwargs: primary_listen_interface(*args, **kwargs),
        remove_ntp_nts_certificate_rows=lambda *args, **kwargs: remove_ntp_nts_certificate_rows(*args, **kwargs),
        render=lambda *args, **kwargs: render(*args, **kwargs),
        require_management_ui_request=require_management_ui_request,
        resolve_service_bind_targets=lambda *args, **kwargs: resolve_service_bind_targets(*args, **kwargs),
        system_adapter_factory=lambda: SystemAdapter(),
        verify_csrf=lambda *args, **kwargs: verify_csrf(*args, **kwargs),
    )
)
ntp_router = _ntp_ui.router
ntp_page = _ntp_ui.endpoints["ntp_page"]
ntp_source_health = _ntp_ui.endpoints["ntp_source_health"]
update_ntp_settings_from_ui = _ntp_ui.endpoints["update_ntp_settings_from_ui"]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)

_management_between_ntp_vcf_workflows_router = router
_vcf_workflows_ui = build_vcf_workflows_ui_router(
    VcfWorkflowsUiDependencies(
        require_management_ui_request=require_management_ui_request,
        vcf_depot_submit_lock=VCF_DEPOT_SUBMIT_LOCK,
        vcf_depot_vdt_log_path=VCF_DEPOT_VDT_LOG_PATH,
        vcf_helper_default_target=VCF_HELPER_DEFAULT_TARGET,
        vcf_generated_fqdn_preview=vcf_generated_fqdn_preview,
        job_payload=_job_payload,
        normalize_vcf_trust_address=_normalize_vcf_trust_address,
        task_row=_task_row,
        vcf_trust_target=_vcf_trust_target,
        active_vcf_depot_execution_job=active_vcf_depot_execution_job,
        appliance_apply_client_status=appliance_apply_client_status,
        appliance_apply_status=appliance_apply_status,
        confirmed_tls_fingerprint=lambda *args, **kwargs: _confirmed_tls_fingerprint(*args, **kwargs),
        allocate_vcf_generated_records=allocate_vcf_generated_records,
        create_vcf_generated_dns_records=create_vcf_generated_dns_records,
        delete_vcf_generated_dns_records=delete_vcf_generated_dns_records,
        disable_default_vcf_backup_user_when_service_off=disable_default_vcf_backup_user_when_service_off,
        disable_default_vcf_depot_user_when_service_off=disable_default_vcf_depot_user_when_service_off,
        dnsmasq_apply_status=dnsmasq_apply_status,
        dnsmasq_context=dnsmasq_context,
        discover_vcf_passwords=lambda *args, **kwargs: discover_vcf_passwords(*args, **kwargs),
        ensure_dns_for_vcf_offline_depot=ensure_dns_for_vcf_offline_depot,
        ensure_dns_for_vcf_registry=ensure_dns_for_vcf_registry,
        ensure_vcf_depot_software_id_task_steps=ensure_vcf_depot_software_id_task_steps,
        get_appliance_settings_row=get_appliance_settings_row,
        get_ca_settings_row=get_ca_settings_row,
        get_vcf_backup_settings_row=get_vcf_backup_settings_row,
        get_vcf_offline_depot_settings_row=get_vcf_offline_depot_settings_row,
        get_vcf_private_registry_settings_row=get_vcf_private_registry_settings_row,
        grid_request=grid_request,
        grid_saved_response=grid_saved_response,
        local_vcf_depot_target_context=lambda *args, **kwargs: local_vcf_depot_target_context(*args, **kwargs),
        primary_listen_address=primary_listen_address,
        primary_listen_interface=primary_listen_interface,
        queue_vcf_sddc_deployment_job=lambda *args, **kwargs: queue_vcf_sddc_deployment_job(*args, **kwargs),
        queue_vcf_target_depot_job=queue_vcf_target_depot_job,
        queue_vcf_trust_job=lambda *args, **kwargs: queue_vcf_trust_job(*args, **kwargs),
        render=render,
        require_admin_identity=require_admin_identity,
        require_vcf_helper_write=require_vcf_helper_write,
        reset_vcf_depot_tool_staging=reset_vcf_depot_tool_staging,
        resolve_vcf_helper_credentials=lambda *args, **kwargs: _resolve_vcf_helper_credentials(*args, **kwargs),
        resolve_service_bind_targets=resolve_service_bind_targets,
        resolve_vcf_depot_download_mode_flags=resolve_vcf_depot_download_mode_flags,
        run_vcf_depot_software_id_job=lambda *args, **kwargs: run_vcf_depot_software_id_job(*args, **kwargs),
        set_setting_value=set_setting_value,
        stage_vcf_depot_runtime_secrets_after_upload=stage_vcf_depot_runtime_secrets_after_upload,
        store_pasted_vcf_depot_secret=store_pasted_vcf_depot_secret,
        store_uploaded_vcf_depot_archive=store_uploaded_vcf_depot_archive,
        store_uploaded_vcf_depot_secret=store_uploaded_vcf_depot_secret,
        store_uploaded_vcf_registry_ca_bundle=store_uploaded_vcf_registry_ca_bundle,
        tail_fixed_log_file=tail_fixed_log_file,
        vcf_backup_context=vcf_backup_context,
        vcf_depot_command_entry=vcf_depot_command_entry,
        vcf_depot_download_job_rows=vcf_depot_download_job_rows,
        vcf_depot_download_preflight=vcf_depot_download_preflight,
        vcf_depot_execution_conflict_detail=vcf_depot_execution_conflict_detail,
        vcf_depot_profile_start_states=vcf_depot_profile_start_states,
        vcf_depot_secret_context=vcf_depot_secret_context,
        vcf_depot_software_depot_id_context=vcf_depot_software_depot_id_context,
        vcf_depot_task_log_path=vcf_depot_task_log_path,
        vcf_depot_tool_installed=vcf_depot_tool_installed,
        vcf_helper_context=vcf_helper_context,
        vcf_ldap_helper_context=vcf_ldap_helper_context,
        vcf_offline_depot_context=vcf_offline_depot_context,
        vcf_private_registry_context=vcf_private_registry_context,
        vcf_registry_ca_bundle_context=vcf_registry_ca_bundle_context,
        vcf_trust_context=vcf_trust_context,
        verify_csrf=verify_csrf,
    )
)
vcf_workflows_router = _vcf_workflows_ui.router
legacy_https_repository_redirect = _vcf_workflows_ui.endpoints["legacy_https_repository_redirect"]
vcf_helper_page = _vcf_workflows_ui.endpoints["vcf_helper_page"]
vcf_helper_page_context = _vcf_workflows_ui.endpoints["vcf_helper_page_context"]
_vcf_helper_json = _vcf_workflows_ui.endpoints["_vcf_helper_json"]
_confirmed_tls_fingerprint = _vcf_workflows_ui.endpoints["_confirmed_tls_fingerprint"]
_split_vcf_endpoint_address_port = _vcf_workflows_ui.endpoints["_split_vcf_endpoint_address_port"]
_resolve_vcf_helper_credentials = _vcf_workflows_ui.endpoints["_resolve_vcf_helper_credentials"]
inspect_vcf_vault_import = _vcf_workflows_ui.endpoints["inspect_vcf_vault_import"]
import_vcf_passwords_to_vault = _vcf_workflows_ui.endpoints["import_vcf_passwords_to_vault"]
_validate_vcf_sddc_property_values = _vcf_workflows_ui.endpoints["_validate_vcf_sddc_property_values"]
vcf_sddc_manager_inventory = _vcf_workflows_ui.endpoints["vcf_sddc_manager_inventory"]
deploy_vcf_sddc_manager_from_ui = _vcf_workflows_ui.endpoints["deploy_vcf_sddc_manager_from_ui"]
vcf_sddc_manager_task_status = _vcf_workflows_ui.endpoints["vcf_sddc_manager_task_status"]
inspect_vcf_offline_depot_target_from_ui = _vcf_workflows_ui.endpoints["inspect_vcf_offline_depot_target_from_ui"]
configure_vcf_offline_depot_target_from_ui = _vcf_workflows_ui.endpoints["configure_vcf_offline_depot_target_from_ui"]
vcf_offline_depot_target_task_status = _vcf_workflows_ui.endpoints["vcf_offline_depot_target_task_status"]
vcf_trust_page = _vcf_workflows_ui.endpoints["vcf_trust_page"]
inspect_vcf_trust_target_from_ui = _vcf_workflows_ui.endpoints["inspect_vcf_trust_target_from_ui"]
trust_vcf_root_ca_from_ui = _vcf_workflows_ui.endpoints["trust_vcf_root_ca_from_ui"]
populate_vcf_fqdns_from_ui = _vcf_workflows_ui.endpoints["populate_vcf_fqdns_from_ui"]
generate_vcf_fqdns_from_ui = _vcf_workflows_ui.endpoints["generate_vcf_fqdns_from_ui"]
delete_vcf_fqdns_from_ui = _vcf_workflows_ui.endpoints["delete_vcf_fqdns_from_ui"]
vcf_offline_depot_page = _vcf_workflows_ui.endpoints["vcf_offline_depot_page"]
vcf_offline_depot_task_log_page = _vcf_workflows_ui.endpoints["vcf_offline_depot_task_log_page"]
vcf_offline_depot_task_status = _vcf_workflows_ui.endpoints["vcf_offline_depot_task_status"]
update_vcf_offline_depot_settings_from_ui = _vcf_workflows_ui.endpoints["update_vcf_offline_depot_settings_from_ui"]
upload_vcf_depot_tool_package_from_ui = _vcf_workflows_ui.endpoints["upload_vcf_depot_tool_package_from_ui"]
reset_vcf_depot_tool_from_ui = _vcf_workflows_ui.endpoints["reset_vcf_depot_tool_from_ui"]
_store_vcf_depot_credential_from_ui = _vcf_workflows_ui.endpoints["_store_vcf_depot_credential_from_ui"]
_save_vcf_depot_application_properties = _vcf_workflows_ui.endpoints["_save_vcf_depot_application_properties"]
_vcf_depot_tool_configuration_response = _vcf_workflows_ui.endpoints["_vcf_depot_tool_configuration_response"]
paste_vcf_depot_credential_from_ui = _vcf_workflows_ui.endpoints["paste_vcf_depot_credential_from_ui"]
paste_vcf_depot_download_token_from_ui = _vcf_workflows_ui.endpoints["paste_vcf_depot_download_token_from_ui"]
paste_vcf_depot_activation_code_from_ui = _vcf_workflows_ui.endpoints["paste_vcf_depot_activation_code_from_ui"]
save_vcf_depot_tool_configuration_from_ui = _vcf_workflows_ui.endpoints["save_vcf_depot_tool_configuration_from_ui"]
save_vcf_depot_application_properties_from_ui = _vcf_workflows_ui.endpoints["save_vcf_depot_application_properties_from_ui"]
generate_vcf_depot_software_depot_id_from_ui = _vcf_workflows_ui.endpoints["generate_vcf_depot_software_depot_id_from_ui"]
preview_vcf_depot_profile_from_ui = _vcf_workflows_ui.endpoints["preview_vcf_depot_profile_from_ui"]
create_vcf_depot_profile_from_ui = _vcf_workflows_ui.endpoints["create_vcf_depot_profile_from_ui"]
edit_vcf_depot_profile_from_ui = _vcf_workflows_ui.endpoints["edit_vcf_depot_profile_from_ui"]
start_vcf_depot_profile_download_from_ui = _vcf_workflows_ui.endpoints["start_vcf_depot_profile_download_from_ui"]
delete_vcf_depot_profile_from_ui = _vcf_workflows_ui.endpoints["delete_vcf_depot_profile_from_ui"]
vcf_private_registry_page = _vcf_workflows_ui.endpoints["vcf_private_registry_page"]
update_vcf_private_registry_settings_from_ui = _vcf_workflows_ui.endpoints["update_vcf_private_registry_settings_from_ui"]
create_vcf_registry_bundle_from_ui = _vcf_workflows_ui.endpoints["create_vcf_registry_bundle_from_ui"]
edit_vcf_registry_bundle_from_ui = _vcf_workflows_ui.endpoints["edit_vcf_registry_bundle_from_ui"]
delete_vcf_registry_bundle_from_ui = _vcf_workflows_ui.endpoints["delete_vcf_registry_bundle_from_ui"]
vcf_backups_page = _vcf_workflows_ui.endpoints["vcf_backups_page"]
update_vcf_backup_settings_from_ui = _vcf_workflows_ui.endpoints["update_vcf_backup_settings_from_ui"]

_esx_storage_ui = build_esx_storage_ui_router(
    EsxStorageUiDependencies(
        appliance_apply_client_status=lambda *args, **kwargs: appliance_apply_client_status(*args, **kwargs),
        appliance_apply_status=lambda *args, **kwargs: appliance_apply_status(*args, **kwargs),
        ensure_dns_for_esx_storage=lambda *args, **kwargs: ensure_dns_for_esx_storage(*args, **kwargs),
        esx_storage_context=lambda *args, **kwargs: esx_storage_context(*args, **kwargs),
        get_esx_storage_settings_row=lambda *args, **kwargs: get_esx_storage_settings_row(*args, **kwargs),
        normalize_dns_hostname=lambda *args, **kwargs: normalize_dns_hostname(*args, **kwargs),
        render=lambda *args, **kwargs: render(*args, **kwargs),
        require_management_ui_request=require_management_ui_request,
        system_adapter_factory=lambda *args, **kwargs: SystemAdapter(*args, **kwargs),
        verify_csrf=lambda *args, **kwargs: verify_csrf(*args, **kwargs),
    )
)
esx_storage_router = _esx_storage_ui.router
require_esx_storage_write = _esx_storage_ui.endpoints["require_esx_storage_write"]
esx_storage_page = _esx_storage_ui.endpoints["esx_storage_page"]
update_esx_storage_settings_from_ui = _esx_storage_ui.endpoints["update_esx_storage_settings_from_ui"]
create_esx_storage_volume_from_ui = _esx_storage_ui.endpoints["create_esx_storage_volume_from_ui"]
create_esx_nfs_share_from_ui = _esx_storage_ui.endpoints["create_esx_nfs_share_from_ui"]
update_esx_nfs_share_from_ui = _esx_storage_ui.endpoints["update_esx_nfs_share_from_ui"]
delete_esx_nfs_share_from_ui = _esx_storage_ui.endpoints["delete_esx_nfs_share_from_ui"]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)
_management_between_vcf_workflows_identity_router = router
router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)



def backup_restore_context(db: Session, result: dict[str, Any] | None = None, error: str | None = None) -> dict[str, Any]:
    """Return backup restore context.

    Args:
        db: Active database session.
        result: Operation result to summarize, validate, or persist.
        error: Public-safe error detail to record or return.
    """
    counts = desired_state_counts(db)
    ldap_recovery_archive = db.execute(
        select(LdapRecoveryArchive)
        .where(LdapRecoveryArchive.state == "staged")
        .order_by(LdapRecoveryArchive.created_at.desc())
    ).scalars().first()
    return {
        "settings_backup_counts": counts,
        "settings_backup_total_rows": sum(counts.values()),
        "backup_restore_result": result,
        "backup_restore_error": error,
        "factory_reset_password_policy_summary": password_policy_summary(
            DEFAULT_PASSWORD_POLICY
        ),
        "ldap_recovery_archive": ldap_recovery_archive,
        "ldap_recovery_ready": bool(
            ldap_recovery_archive is not None and ldap_recovery_archive.id in LDAP_PENDING_RECOVERY_PAYLOADS
        ),
    }


def require_esxi_pxe_write(identity: Identity) -> None:
    """Handle require esxi pxe write.

    Args:
        identity: Authenticated identity authorizing the request.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not identity.can("write:esxi-pxe"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ESXi PXE write permission required")


def next_kickstart_copy_name(db: Session, base_name: str) -> str:
    """Return next kickstart copy name.

    Args:
        db: Active database session.
        base_name: Base name supplied by the caller.
    """
    names = {row.name.lower() for row in db.execute(select(EsxiKickstart)).scalars().all()}
    candidate = f"{base_name} Copy"
    if candidate.lower() not in names:
        return candidate
    index = 2
    while True:
        candidate = f"{base_name} Copy {index}"
        if candidate.lower() not in names:
            return candidate
        index += 1


def esxi_pxe_page_context(
    db: Session,
    identity: Identity,
    *,
    selected_id: int | None = None,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Return esxi pxe page context.

    Args:
        db: Active database session.
        identity: Authenticated identity authorizing the request.
        selected_id: Identifier of the selected.
        result: Operation result to summarize, validate, or persist.
        error: Public-safe error detail to record or return.
    """
    from atlaso.app.models import NetworkBootDiscoveredHost
    from atlaso.app.services.network_boot import (
        catalog_rows,
        esxi_host_assignments_by_mac,
    )
    from atlaso.app.services.network_boot import (
        host_to_dict as inventory_host_to_dict,
    )

    context = esxi_pxe_context(db)
    kickstarts = context["esxi_kickstarts"]
    selected = next((row for row in kickstarts if row.id == selected_id), None) or (kickstarts[0] if kickstarts else None)
    selected_validation = {"valid": True, "errors": [], "warnings": []}
    if selected is not None:
        selected_validation = context["esxi_pxe_validation_by_id"].get(selected.id, selected_validation)
    grid_rows = [
        esxi_kickstart_grid_payload(row, include_content=identity.can("write:esxi-pxe"))
        for row in kickstarts
    ]
    discovered_hosts = db.execute(
        select(NetworkBootDiscoveredHost).order_by(
            NetworkBootDiscoveredHost.last_seen_at.desc(),
            NetworkBootDiscoveredHost.id,
        )
    ).scalars().all()
    inventory_assignments_by_mac = esxi_host_assignments_by_mac(db)
    discovered_host_rows = [
        inventory_host_to_dict(db, row, assignments_by_mac=inventory_assignments_by_mac)
        for row in discovered_hosts
    ]
    discovered_host_ids_by_esxi_host_id: dict[int, list[int]] = {}
    for discovered_host_row in discovered_host_rows:
        for assignment in discovered_host_row["esxi_assignments"]:
            discovered_host_ids_by_esxi_host_id.setdefault(assignment["id"], []).append(
                discovered_host_row["id"]
            )
    context["esxi_pxe_host_rows"] = [
        {
            **row,
            "discovered_host_ids": discovered_host_ids_by_esxi_host_id.get(row.get("id"), []),
        }
        for row in context["esxi_pxe_host_rows"]
    ]
    context["esxi_pxe_discovered_host_ids_by_host_id"] = discovered_host_ids_by_esxi_host_id
    media_jobs = db.execute(
        select(Job)
        .options(selectinload(Job.steps))
        .where(Job.type == "pxe-media-sync")
        .order_by(desc(Job.created_at))
        .limit(8)
    ).scalars().all()
    return {
        **context,
        "esxi_selected_kickstart": selected,
        "esxi_selected_kickstart_json": kickstart_to_dict(selected, include_content=identity.can("write:esxi-pxe")) if selected else None,
        "esxi_selected_validation": selected_validation,
        "esxi_can_write": identity.can("write:esxi-pxe"),
        "network_boot_can_write": identity.can("write:pxe"),
        "network_boot_environments": catalog_rows(db),
        "network_boot_discovered_hosts": discovered_host_rows,
        "network_boot_media_tasks": [_task_row(job, identity) for job in media_jobs],
        "task_component_filter_options": _task_component_filter_options(db),
        "esxi_kickstart_grid_rows": grid_rows,
        "esxi_pxe_result": result,
        "esxi_pxe_error": error,
    }


def esxi_kickstart_grid_payload(kickstart: EsxiKickstart, *, include_content: bool) -> dict[str, Any]:
    """Return esxi kickstart grid payload.

    Args:
        kickstart: Kickstart consumed by ESXi kickstart grid payload.
        include_content: Whether include content applies to the operation.
    """
    payload = kickstart_to_dict(kickstart, include_content=include_content)
    for field in ("created_at", "updated_at", "last_rendered_at", "last_applied_at"):
        value = payload[field]
        payload[field] = value.isoformat() if value else ""
    return payload


_management_between_identity_operations_router = router
_operations_ui = build_operations_ui_router(
    OperationsUiDependencies(
        require_management_ui_request=require_management_ui_request,
        active_job_statuses=ACTIVE_JOB_STATUSES,
        service_admin_cancellable_job_types=SERVICE_ADMIN_CANCELLABLE_JOB_TYPES,
        job_payload=_job_payload,
        redact_task_value=_redact_task_value,
        task_component_filter_options=_task_component_filter_options,
        task_filter_clauses=_task_filter_clauses,
        task_log_lines=_task_log_lines,
        task_row=_task_row,
        audit_event_rows_context=audit_event_rows_context,
        backing_systemd_unit_active=backing_systemd_unit_active,
        get_ca_settings_row=get_ca_settings_row,
        get_dhcp_settings_row=get_dhcp_settings_row,
        get_dns_settings_row=get_dns_settings_row,
        get_esx_storage_settings_row=get_esx_storage_settings_row,
        get_vcf_backup_settings_row=get_vcf_backup_settings_row,
        get_vcf_offline_depot_settings_row=get_vcf_offline_depot_settings_row,
        log_sources_context=lambda *args, **kwargs: log_sources_context(
            *args, **kwargs
        ),
        logs_context=lambda *args, **kwargs: logs_context(*args, **kwargs),
        normalized_log_line_count=lambda *args, **kwargs: normalized_log_line_count(
            *args, **kwargs
        ),
        render=render,
        vcf_depot_execution_conflict_detail=vcf_depot_execution_conflict_detail,
        vcf_depot_profile_start_states=vcf_depot_profile_start_states,
        verify_csrf=verify_csrf,
    )
)
operations_router = _operations_ui.router
service_state_status_row = _operations_ui.endpoints["service_state_status_row"]
service_state_to_grid_row = _operations_ui.endpoints["service_state_to_grid_row"]
dnsmasq_backed_service_grid_row = _operations_ui.endpoints[
    "dnsmasq_backed_service_grid_row"
]
esxi_pxe_service_grid_row = _operations_ui.endpoints["esxi_pxe_service_grid_row"]
ca_service_grid_row = _operations_ui.endpoints["ca_service_grid_row"]
vcf_backup_service_grid_row = _operations_ui.endpoints["vcf_backup_service_grid_row"]
vcf_depot_service_grid_row = _operations_ui.endpoints["vcf_depot_service_grid_row"]
esx_storage_service_grid_row = _operations_ui.endpoints["esx_storage_service_grid_row"]
service_grid_row = _operations_ui.endpoints["service_grid_row"]
services_template_context = _operations_ui.endpoints["services_template_context"]
service_action_from_ui = _operations_ui.endpoints["service_action_from_ui"]
service_logs_from_ui = _operations_ui.endpoints["service_logs_from_ui"]
services = _operations_ui.endpoints["services"]
logs_page = _operations_ui.endpoints["logs_page"]
logs_data = _operations_ui.endpoints["logs_data"]
tasks_page = _operations_ui.endpoints["tasks_page"]
tasks_status = _operations_ui.endpoints["tasks_status"]
task_status = _operations_ui.endpoints["task_status"]
task_log = _operations_ui.endpoints["task_log"]
cancel_task_from_ui = _operations_ui.endpoints["cancel_task_from_ui"]
audit_log = _operations_ui.endpoints["audit_log"]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)




@protocol_router.get(
    "/pxe/esxi/ks/{mac_key}/{kickstart_revision}/{capability_file}",
    response_model=None,
)
def serve_esxi_kickstart_file(
    mac_key: str,
    kickstart_revision: str,
    capability_file: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Consume one exact boot capability and return its applied Kickstart.

    Args:
        mac_key: PXE-formatted MAC address bound to the capability.
        kickstart_revision: Exact applied Kickstart content revision.
        capability_file: Bearer capability filename supplied by the boot artifact.
        request: Incoming PXE HTTP request used to bind the listener origin.
        db: Database session used to consume the capability.
    """
    from atlaso.app.services.network_boot import consume_esxi_boot_capability

    if not capability_file.endswith(".cfg"):
        raise HTTPException(status_code=404, detail="Kickstart not found")
    token = capability_file.removesuffix(".cfg")
    request_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
    try:
        rendered = consume_esxi_boot_capability(
            db,
            mac_key=mac_key.lower(),
            kickstart_revision=kickstart_revision.lower(),
            token=token,
            request_origin=request_origin,
        )
    except (OSError, TypeError, ValueError):
        db.rollback()
        rendered = None
    if rendered is None:
        raise HTTPException(status_code=404, detail="Kickstart not found")
    return Response(
        rendered,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
    )


@protocol_router.get("/pxe/esxi/boot.ipxe", response_model=None)
def serve_esxi_http_ipxe_script() -> FileResponse:
    """Handle the serve esxi http ipxe script endpoint.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    if not ESXI_IPXE_HTTP_SCRIPT_PATH.is_file():
        raise HTTPException(status_code=404, detail="ESXi iPXE boot script is not enabled")
    return FileResponse(ESXI_IPXE_HTTP_SCRIPT_PATH, media_type="text/plain; charset=utf-8")


_management_between_identity_network_boot_router = router
_network_boot_ui = build_network_boot_ui_router(
    NetworkBootUiDependencies(
        require_management_ui_request=require_management_ui_request,
        appliance_apply_status=appliance_apply_status,
        ensure_dns_for_esxi_pxe=ensure_dns_for_esxi_pxe,
        esxi_kickstart_grid_payload=esxi_kickstart_grid_payload,
        esxi_pxe_context=esxi_pxe_context,
        esxi_pxe_page_context=esxi_pxe_page_context,
        grid_saved_response=grid_saved_response,
        next_kickstart_copy_name=next_kickstart_copy_name,
        parse_optional_esxi_kickstart_id=parse_optional_esxi_kickstart_id,
        render=render,
        require_esxi_pxe_write=require_esxi_pxe_write,
        resolve_service_bind_targets=resolve_service_bind_targets,
        verify_csrf=verify_csrf,
        kickstart_reference_validation_error=KICKSTART_REFERENCE_VALIDATION_ERROR,
        kickstart_upload_error=KICKSTART_UPLOAD_ERROR,
    )
)
network_boot_router = _network_boot_ui.router
esxi_pxe_page = _network_boot_ui.endpoints["esxi_pxe_page"]
network_boot_page = _network_boot_ui.endpoints["network_boot_page"]
update_esxi_pxe_boot_settings_from_ui = _network_boot_ui.endpoints["update_esxi_pxe_boot_settings_from_ui"]
create_esxi_kickstart_from_ui = _network_boot_ui.endpoints["create_esxi_kickstart_from_ui"]
upload_esxi_kickstart_from_ui = _network_boot_ui.endpoints["upload_esxi_kickstart_from_ui"]
update_esxi_kickstart_from_ui = _network_boot_ui.endpoints["update_esxi_kickstart_from_ui"]
duplicate_esxi_kickstart_from_ui = _network_boot_ui.endpoints["duplicate_esxi_kickstart_from_ui"]
delete_esxi_kickstart_from_ui = _network_boot_ui.endpoints["delete_esxi_kickstart_from_ui"]
validate_esxi_kickstart_from_ui = _network_boot_ui.endpoints["validate_esxi_kickstart_from_ui"]
download_esxi_kickstart_from_ui = _network_boot_ui.endpoints["download_esxi_kickstart_from_ui"]
create_esxi_custom_variable_from_ui = _network_boot_ui.endpoints["create_esxi_custom_variable_from_ui"]
update_esxi_custom_variable_from_ui = _network_boot_ui.endpoints["update_esxi_custom_variable_from_ui"]
delete_esxi_custom_variable_from_ui = _network_boot_ui.endpoints["delete_esxi_custom_variable_from_ui"]
upload_esxi_installer_iso_from_ui = _network_boot_ui.endpoints["upload_esxi_installer_iso_from_ui"]
delete_esxi_installer_iso_from_ui = _network_boot_ui.endpoints["delete_esxi_installer_iso_from_ui"]
import_esxi_kickstart_filesystem_copy = _network_boot_ui.endpoints["import_esxi_kickstart_filesystem_copy"]
create_esxi_pxe_host_from_ui = _network_boot_ui.endpoints["create_esxi_pxe_host_from_ui"]
update_esxi_pxe_host_from_ui = _network_boot_ui.endpoints["update_esxi_pxe_host_from_ui"]
update_esxi_pxe_default_host_from_ui = _network_boot_ui.endpoints["update_esxi_pxe_default_host_from_ui"]
delete_esxi_pxe_host_from_ui = _network_boot_ui.endpoints["delete_esxi_pxe_host_from_ui"]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)


_settings_backup_ui = build_settings_backup_ui_router(
    SettingsBackupUiDependencies(
        require_management_ui_request=require_management_ui_request,
        require_admin_identity=lambda *args, **kwargs: require_admin_identity(
            *args, **kwargs
        ),
        render=lambda *args, **kwargs: render(*args, **kwargs),
        verify_csrf=lambda *args, **kwargs: verify_csrf(*args, **kwargs),
        backup_restore_context=lambda *args, **kwargs: backup_restore_context(
            *args, **kwargs
        ),
        export_settings_archive=lambda *args, **kwargs: export_settings_archive(
            *args, **kwargs
        ),
        archive_summary=lambda *args, **kwargs: archive_summary(*args, **kwargs),
        restore_settings_archive=lambda *args, **kwargs: restore_settings_archive(
            *args, **kwargs
        ),
        get_runtime_settings=lambda: get_settings(),
        factory_password_policy=DEFAULT_PASSWORD_POLICY,
        validate_password=lambda *args, **kwargs: validate_password(*args, **kwargs),
        stage_appliance_apply_config=lambda *args, **kwargs: stage_appliance_apply_config(
            *args, **kwargs
        ),
        system_adapter_factory=lambda *args, **kwargs: SystemAdapter(*args, **kwargs),
        replace_database_with_factory_candidate=lambda *args, **kwargs: replace_database_with_factory_candidate(
            *args, **kwargs
        ),
        invalidate_appliance_apply_status_projection=lambda: invalidate_appliance_apply_status_projection(),
        management_ui_path=lambda *args, **kwargs: management_ui_path(
            *args, **kwargs
        ),
        factory_reset_staged_credentials_path=FACTORY_RESET_STAGED_CREDENTIALS_PATH,
        appliance_settings_context=lambda *args, **kwargs: appliance_settings_context(
            *args, **kwargs
        ),
        appliance_apply_status=lambda *args, **kwargs: appliance_apply_status(
            *args, **kwargs
        ),
        get_appliance_settings_row=lambda *args, **kwargs: get_appliance_settings_row(
            *args, **kwargs
        ),
        get_dns_settings_row=lambda *args, **kwargs: get_dns_settings_row(
            *args, **kwargs
        ),
        appliance_settings_management_context=lambda *args, **kwargs: appliance_settings_management_context(
            *args, **kwargs
        ),
        web_terminal_interface_options=lambda *args, **kwargs: web_terminal_interface_options(
            *args, **kwargs
        ),
        normalized_web_terminal_interfaces=lambda *args, **kwargs: normalized_web_terminal_interfaces(
            *args, **kwargs
        ),
        web_terminal_interfaces_to_json=lambda *args, **kwargs: web_terminal_interfaces_to_json(
            *args, **kwargs
        ),
        get_ca_settings_row=lambda *args, **kwargs: get_ca_settings_row(
            *args, **kwargs
        ),
        normalize_fqdn=lambda *args, **kwargs: normalize_fqdn(*args, **kwargs),
        normalize_service_dns_target_naming=lambda *args, **kwargs: normalize_service_dns_target_naming(
            *args, **kwargs
        ),
        normalize_multiline_values=lambda *args, **kwargs: normalize_multiline_values(
            *args, **kwargs
        ),
        validate_appliance_settings=lambda *args, **kwargs: validate_appliance_settings(
            *args, **kwargs
        ),
        appliance_dns_record_conflict=lambda *args, **kwargs: appliance_dns_record_conflict(
            *args, **kwargs
        ),
        ensure_ca_state=lambda *args, **kwargs: ensure_ca_state(*args, **kwargs),
        ca_managed_certificate_paths=lambda *args, **kwargs: ca_managed_certificate_paths(
            *args, **kwargs
        ),
        ca_certificate_available=lambda *args, **kwargs: ca_certificate_available(
            *args, **kwargs
        ),
        ensure_dns_for_appliance_settings=lambda *args, **kwargs: ensure_dns_for_appliance_settings(
            *args, **kwargs
        ),
        reconcile_factory_service_identities=lambda *args, **kwargs: reconcile_factory_service_identities(
            *args, **kwargs
        ),
        reconcile_service_dns_aliases=lambda *args, **kwargs: reconcile_service_dns_aliases(
            *args, **kwargs
        ),
        save_logging_preferences=lambda *args, **kwargs: save_logging_preferences(
            *args, **kwargs
        ),
        configure_operational_logging=lambda *args, **kwargs: configure_operational_logging(
            *args, **kwargs
        ),
        logging_preferences_to_dict=lambda *args, **kwargs: logging_preferences_to_dict(
            *args, **kwargs
        ),
        appliance_settings_staged_config_path=APPLIANCE_SETTINGS_STAGED_CONFIG_PATH,
    )
)
settings_backup_router = _settings_backup_ui.router
backup_restore_page = _settings_backup_ui.endpoints["backup_restore_page"]
export_backup_restore_archive = _settings_backup_ui.endpoints[
    "export_backup_restore_archive"
]
restore_backup_restore_archive = _settings_backup_ui.endpoints[
    "restore_backup_restore_archive"
]
factory_reset_backup_restore = _settings_backup_ui.endpoints[
    "factory_reset_backup_restore"
]
settings_page = _settings_backup_ui.endpoints["settings_page"]
update_settings_from_ui = _settings_backup_ui.endpoints["update_settings_from_ui"]
update_authentication_lifetimes_from_ui = _settings_backup_ui.endpoints[
    "update_authentication_lifetimes_from_ui"
]
update_vmware_ceip_from_ui = _settings_backup_ui.endpoints[
    "update_vmware_ceip_from_ui"
]
update_logging_settings_from_ui = _settings_backup_ui.endpoints[
    "update_logging_settings_from_ui"
]

router = APIRouter(
    prefix=MANAGEMENT_UI_ROOT,
    dependencies=[Depends(require_management_ui_request)],
)

@router.get("/{page}", response_class=HTMLResponse, response_model=None)
def placeholder_page(page: str, request: Request, identity: Identity = Depends(require_session_identity)) -> HTMLResponse:
    """Handle the placeholder page endpoint.

    Args:
        page: Page supplied by the caller.
        request: Incoming HTTP request.
        identity: Authenticated identity authorizing the request.

    Returns:
        The endpoint response.

    Raises:
        HTTPException: If the request cannot be fulfilled.
    """
    known = {
        "physical-interfaces": "Physical Interfaces",
        "vlan-interfaces": "VLAN Interfaces",
        "certificate-authority": "Certificate Authority",
        "vcf-offline-depot": "VCF Offline Depot",
        "vcf-backups": "VCF Backups",
        "logs": "Logs",
    }
    if page not in known:
        raise HTTPException(status_code=404, detail="Page not found")
    return render(request, "placeholder.html", {"identity": identity, "title": known[page]})


allow_compatible_route_shadow(
    protocol_router,
    earlier_path="/PROD/{depot_path:path}",
    later_path="/PROD/",
    methods=("GET", "HEAD"),
)
_management_after_settings_backup_router = router
UI_ROUTER_REGISTRY.register(
    "facade_before_vaults",
    (
        RouterContribution(plane="front_door", router=front_door_router),
        RouterContribution(plane="protocol", router=protocol_router),
        RouterContribution(plane="public", router=public_router),
        RouterContribution(
            plane="management",
            router=_management_before_vaults_router,
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "vaults",
    (RouterContribution(plane="management", router=vaults_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_between_vaults_appliance_maintenance",
    (
        RouterContribution(
            plane="management",
            router=_management_between_vaults_appliance_maintenance_router,
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "appliance_maintenance_power",
    (
        RouterContribution(
            plane="management", router=appliance_maintenance_power_router
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "dashboard_monitor",
    (RouterContribution(plane="management", router=dashboard_monitor_router),),
)
UI_ROUTER_REGISTRY.register(
    "appliance_maintenance_update",
    (
        RouterContribution(
            plane="management", router=appliance_maintenance_update_router
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "automation",
    (RouterContribution(plane="management", router=automation_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_between_automation_routes_wan",
    (
        RouterContribution(
            plane="management", router=_management_before_routes_wan_router
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "appliance_apply",
    (RouterContribution(plane="management", router=appliance_apply_router),),
)
UI_ROUTER_REGISTRY.register(
    "network_objects",
    (RouterContribution(plane="management", router=network_objects_router),),
)
UI_ROUTER_REGISTRY.register(
    "routes_wan",
    (RouterContribution(plane="management", router=routes_wan_router),),
)
UI_ROUTER_REGISTRY.register(
    "firewall",
    (RouterContribution(plane="management", router=firewall_router),),
)
UI_ROUTER_REGISTRY.register(
    "physical_vlans",
    (RouterContribution(plane="management", router=physical_vlans_router),),
)
UI_ROUTER_REGISTRY.register(
    "dns_dhcp",
    (RouterContribution(plane="management", router=dns_dhcp_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_between_dns_dhcp_certificate_trust",
    (
        RouterContribution(
            plane="management", router=_management_between_dns_dhcp_managed_ldap_router
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "certificate_trust_ca",
    (RouterContribution(plane="management", router=certificate_trust_ca_router),),
)
UI_ROUTER_REGISTRY.register(
    "managed_ldap",
    (RouterContribution(plane="management", router=managed_ldap_router),),
)
UI_ROUTER_REGISTRY.register(
    "certificate_trust_kms",
    (RouterContribution(plane="management", router=certificate_trust_kms_router),),
)
UI_ROUTER_REGISTRY.register(
    "ntp",
    (RouterContribution(plane="management", router=ntp_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_between_ntp_vcf_workflows",
    (
        RouterContribution(
            plane="management", router=_management_between_ntp_vcf_workflows_router
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "vcf_workflows",
    (RouterContribution(plane="management", router=vcf_workflows_router),),
)
UI_ROUTER_REGISTRY.register(
    "esx_storage",
    (RouterContribution(plane="management", router=esx_storage_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_between_vcf_workflows_identity",
    (
        RouterContribution(
            plane="management", router=_management_between_vcf_workflows_identity_router
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "identity",
    (RouterContribution(plane="management", router=identity_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_between_identity_operations",
    (
        RouterContribution(
            plane="management", router=_management_between_identity_operations_router
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "operations",
    (RouterContribution(plane="management", router=operations_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_between_identity_network_boot",
    (
        RouterContribution(
            plane="management",
            router=_management_between_identity_network_boot_router,
        ),
    ),
)
UI_ROUTER_REGISTRY.register(
    "network_boot",
    (RouterContribution(plane="management", router=network_boot_router),),
)
UI_ROUTER_REGISTRY.register(
    "settings_backup",
    (RouterContribution(plane="management", router=settings_backup_router),),
)
UI_ROUTER_REGISTRY.register(
    "facade_after_settings_backup",
    (
        RouterContribution(
            plane="management", router=_management_after_settings_backup_router
        ),
    ),
)
UI_ROUTER_REGISTRY.validate_domains(
    (
        "facade_before_vaults",
        "vaults",
        "facade_between_vaults_appliance_maintenance",
        "appliance_maintenance_power",
        "dashboard_monitor",
        "appliance_maintenance_update",
        "automation",
        "facade_between_automation_routes_wan",
        "appliance_apply",
        "network_objects",
        "routes_wan",
        "firewall",
        "physical_vlans",
        "dns_dhcp",
        "facade_between_dns_dhcp_certificate_trust",
        "certificate_trust_ca",
        "managed_ldap",
        "certificate_trust_kms",
        "ntp",
        "facade_between_ntp_vcf_workflows",
        "vcf_workflows",
        "esx_storage",
        "facade_between_vcf_workflows_identity",
        "identity",
        "facade_between_identity_operations",
        "operations",
        "facade_between_identity_network_boot",
        "network_boot",
        "settings_backup",
        "facade_after_settings_backup",
    )
)



router = APIRouter()
for registered_router in UI_ROUTER_REGISTRY.routers_for_plane("management"):
    router.routes.extend(registered_router.routes)
