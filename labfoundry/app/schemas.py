from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ProblemDetails(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    instance: str
    error_code: str
    request_id: str


class IdentityResponse(BaseModel):
    username: str
    role: str
    roles: list[str] = Field(default_factory=list)
    scopes: list[str]
    auth_type: str


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    expires_at: datetime | None = None
    scopes: list[str] = Field(default_factory=lambda: ["read:dashboard"])


class ApiTokenResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    jti: str
    name: str
    description: str | None
    owner_user_id: int
    owner_username: str
    token_type: str
    role: str
    roles: list[str] = Field(default_factory=list)
    scopes: list[str]
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None
    enabled: bool
    signing_key_id: str | None


class ApiTokenCreated(BaseModel):
    token: ApiTokenResponse
    raw_token: str


class ServiceStateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    service: str
    display_name: str
    running: bool
    enabled: bool
    health: str
    detail: str | None


class FirewallSettingsUpdate(BaseModel):
    enabled: bool = False
    default_input_policy: str = "drop"
    default_forward_policy: str = "drop"
    default_output_policy: str = "accept"
    allow_established: bool = True
    allow_loopback: bool = True
    allow_icmp: bool = True
    log_dropped: bool = False


class FirewallSettingsResponse(FirewallSettingsUpdate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    config_path: str
    updated_at: datetime


class FirewallRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    direction: str = "input"
    action: str = "accept"
    protocol: str = "tcp"
    source: str = "any"
    destination: str = "any"
    destination_port: str = ""
    interface_name: str = ""
    priority: int = 100
    enabled: bool = True
    description: str | None = None


class FirewallRuleResponse(FirewallRuleCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class FirewallStatusResponse(BaseModel):
    enabled: bool
    service: ServiceStateResponse | None
    rule_count: int
    config_path: str
    dry_run: bool


class VcfBackupStatusResponse(BaseModel):
    enabled: bool
    service: ServiceStateResponse | None
    listen_interface: str
    listen_address: str
    port: int
    sftp_username: str | None
    storage_path: str
    remote_directory: str
    config_path: str
    dry_run: bool


class EsxStorageSettingsUpdate(BaseModel):
    enabled: bool = False
    hostname: str = Field(default="nfs.labfoundry.internal", min_length=1, max_length=253)


class EsxStorageVolumeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    source_type: Literal["blank_disk", "mounted_ext4"] = "blank_disk"
    stable_device_id: str = Field(default="", max_length=500)
    mount_path: str = Field(default="", max_length=500)


class EsxStorageVolumeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    stable_device_id: str | None = Field(default=None, max_length=500)
    mount_path: str | None = Field(default=None, max_length=500)


class EsxStorageVolumeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source_type: str
    stable_device_id: str
    device_path: str
    device_model: str
    device_serial: str
    device_wwn: str
    capacity_bytes: int
    filesystem_uuid: str
    filesystem_label: str
    mount_path: str
    state: str
    applied: bool
    created_at: datetime
    updated_at: datetime


class EsxNfsShareCreate(BaseModel):
    datastore_name: str = Field(min_length=1, max_length=120)
    volume_id: int
    relative_path: str = Field(min_length=1, max_length=500)
    preferred_nfs_version: Literal["3", "4.1"] = "4.1"
    interface_name: str = Field(min_length=1, max_length=80)
    address_families: list[Literal["ipv4", "ipv6"]] = Field(default_factory=lambda: ["ipv4", "ipv6"])
    ipv4_clients: list[str] = Field(default_factory=list)
    ipv6_clients: list[str] = Field(default_factory=list)
    enabled: bool = True


class EsxNfsShareUpdate(BaseModel):
    datastore_name: str | None = Field(default=None, min_length=1, max_length=120)
    volume_id: int | None = None
    relative_path: str | None = Field(default=None, min_length=1, max_length=500)
    preferred_nfs_version: Literal["3", "4.1"] | None = None
    interface_name: str | None = Field(default=None, min_length=1, max_length=80)
    address_families: list[Literal["ipv4", "ipv6"]] | None = None
    ipv4_clients: list[str] | None = None
    ipv6_clients: list[str] | None = None
    enabled: bool | None = None


class EsxNfsShareResponse(BaseModel):
    id: int
    datastore_name: str
    volume_id: int
    volume_name: str
    relative_path: str
    preferred_nfs_version: str
    interface_name: str
    address_families: list[str]
    ipv4_clients: list[str]
    ipv6_clients: list[str]
    listeners: dict[str, list[str]]
    target_hostnames: dict[str, list[str]]
    local_path: str
    remote_path: str
    connection_commands: dict[str, list[str]]
    powercli_commands: dict[str, list[str]]
    enabled: bool


class EsxStorageStatusResponse(BaseModel):
    enabled: bool
    hostname: str
    valid: bool
    validation_errors: list[str]
    validation_warnings: list[str]
    volume_count: int
    share_count: int
    active_share_count: int
    dry_run: bool


class EsxStorageDiskResponse(BaseModel):
    candidate_type: Literal["blank_disk", "mounted_ext4", ""] = ""
    stable_device_id: str
    device_path: str
    model: str = ""
    serial: str = ""
    wwn: str = ""
    size_bytes: int = 0
    filesystem_type: str = ""
    filesystem_uuid: str = ""
    filesystem_label: str = ""
    mount_path: str = ""
    eligible: bool
    eligibility_reason: str = ""


class VcfPrivateRegistryStatusResponse(BaseModel):
    enabled: bool
    service: ServiceStateResponse | None
    hostname: str
    endpoint: str
    listen_interface: str
    listen_address: str
    port: int
    harbor_project: str
    storage_path: str
    config_path: str
    bundle_count: int
    valid: bool
    dry_run: bool


class VcfOfflineDepotStatusResponse(BaseModel):
    enabled: bool
    service: ServiceStateResponse | None
    hostname: str
    endpoint: str
    listen_interface: str
    listen_address: str
    port: int
    http_username: str
    allow_unauthenticated_access: bool
    depot_store_path: str
    tool_archive_name: str
    tool_version: str
    software_depot_id: str
    software_depot_id_generated_at: str
    software_depot_id_error: str
    download_token_present: bool
    activation_code_present: bool
    application_properties_present: bool
    application_properties_source: str
    application_properties_updated_at: str
    profile_count: int
    config_path: str
    valid: bool
    dry_run: bool


class LdapPasswordPolicy(BaseModel):
    min_length: int = Field(default=14, ge=8, le=128)
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_number: bool = True
    require_special: bool = True
    disallow_username: bool = True
    max_failures: int = Field(default=5, ge=1, le=100)
    lockout_minutes: int = Field(default=15, ge=1, le=1440)
    failure_window_minutes: int = Field(default=15, ge=1, le=1440)
    history: int = Field(default=5, ge=0, le=24)
    max_age_days: int = Field(default=0, ge=0, le=3650)


class LdapSettingsUpdate(BaseModel):
    enabled: bool = False
    hostname: str = Field(default="ldap.labfoundry.internal", min_length=1, max_length=180)
    listen_interfaces: list[str] = Field(default_factory=list)
    listen_addresses: list[str] = Field(default_factory=list)
    ldaps_enabled: bool = True
    port: int = Field(default=636, ge=1, le=65535)
    ldap_enabled: bool = False
    ldap_port: int = Field(default=389, ge=1, le=65535)
    password_policy: LdapPasswordPolicy = Field(default_factory=LdapPasswordPolicy)


class LdapSettingsResponse(LdapSettingsUpdate):
    id: int
    config_path: str
    certificate_path: str
    key_path: str
    chain_path: str
    root_ca_path: str
    valid: bool
    validation_errors: list[str] = Field(default_factory=list)
    validation_warnings: list[str] = Field(default_factory=list)
    updated_at: datetime


class LdapOrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    slug: str = Field(default="", max_length=80)
    suffix_dn: str = Field(default="", max_length=500)
    enabled: bool = True


class LdapOrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    suffix_dn: str
    users_base_dn: str
    groups_base_dn: str
    service_accounts_base_dn: str
    bind_dn: str
    bind_secret_present: bool
    enabled: bool
    user_count: int
    group_count: int
    vcf_target_url: str
    vcf_org_id: str
    vcf_org_name: str
    vcf_tls_fingerprint: str
    vcf_last_status: str
    vcf_last_message: str
    vcf_last_verified_at: str
    created_at: str
    updated_at: str
    raw_bind_password: str | None = None


class LdapUserCreate(BaseModel):
    uid: str = Field(min_length=1, max_length=100)
    given_name: str = Field(default="", max_length=120)
    surname: str = Field(default="", max_length=120)
    display_name: str = Field(default="", max_length=180)
    email: str = Field(default="", max_length=240)
    telephone: str = Field(default="", max_length=80)
    enabled: bool = True
    password: str = Field(default="", max_length=512)


class LdapUserResponse(BaseModel):
    id: int
    organization_id: int
    uid: str
    dn: str
    given_name: str
    surname: str
    display_name: str
    email: str
    telephone: str
    enabled: bool
    password_status: str
    password_applied_at: str
    unlock_requested: bool
    created_at: str
    updated_at: str


class LdapPasswordResetRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class LdapGroupMember(BaseModel):
    type: Literal["user", "group"]
    id: int


class LdapGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    enabled: bool = True
    members: list[LdapGroupMember] = Field(default_factory=list)


class LdapGroupResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    dn: str
    description: str
    enabled: bool
    members: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


class LdapBindCredentialResponse(BaseModel):
    organization: LdapOrganizationResponse
    raw_bind_password: str


class LdapVcfInspectRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=500)
    organization_id: str = Field(min_length=1, max_length=240)
    organization_name: str = Field(default="", max_length=128)
    username: str = Field(min_length=1, max_length=240)
    password: str = Field(min_length=1, max_length=512)
    confirmed_tls_fingerprint: str = Field(default="", max_length=160)


class LdapVcfConfigureRequest(LdapVcfInspectRequest):
    replace_existing: bool = False


class LdapVcfInspectionResponse(BaseModel):
    target_url: str
    organization_id: str
    organization_name: str
    tls_fingerprint: str
    current_settings: dict[str, Any]
    proposed_settings: dict[str, Any]
    changed: bool
    test_result: dict[str, Any] | None = None
    user_count: int | None = None
    group_count: int | None = None


class LdapHealthResponse(BaseModel):
    enabled: bool
    running: bool
    health: str
    ldaps_only: bool
    ldaps_enabled: bool
    ldaps_port: int
    ldap_enabled: bool
    ldap_port: int
    hostname: str
    port: int
    organization_count: int
    user_count: int
    group_count: int
    validation_errors: list[str] = Field(default_factory=list)
    validation_warnings: list[str] = Field(default_factory=list)


class LdapRecoveryExportRequest(BaseModel):
    passphrase: str = Field(min_length=12, max_length=512)


class LdapRecoveryImportResponse(BaseModel):
    id: int
    filename: str
    sha256: str
    state: str
    organization_count: int
    created_at: datetime


class EsxiKickstartCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    content: str = Field(min_length=1)
    enabled: bool = True


class EsxiKickstartUpdate(EsxiKickstartCreate):
    pass


class EsxiKickstartResponse(BaseModel):
    id: int
    name: str
    description: str
    content_hash: str
    rendered_hash: str
    http_path: str
    enabled: bool
    created_at: datetime
    updated_at: datetime
    last_rendered_at: datetime | None
    last_applied_at: datetime | None
    redacted_preview: str
    drift_state: str
    content: str | None = None


class EsxiKickstartValidationResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    redacted_preview: str


class EsxiKickstartPreviewResponse(BaseModel):
    id: int
    redacted_preview: str
    content_hash: str
    drift_state: str


class EsxiKickstartDuplicateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=120)


class EsxiPxeHostCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=120)
    mac_address: str = Field(min_length=1, max_length=32)
    ip_address: str = Field(default="", max_length=64)
    kickstart_id: int | None = None
    installer_iso_path: str = ""
    variables: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True


class EsxiPxeHostResponse(EsxiPxeHostCreate):
    id: int
    kickstart_name: str = ""
    installer_iso_name: str = ""
    created_at: datetime
    updated_at: datetime


class EsxiInstallerIsoResponse(BaseModel):
    name: str
    path: str
    relative_path: str
    size_bytes: int
    updated_at: str


class PhysicalInterfaceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    mac_address: str
    driver: str | None
    speed: str | None
    host_ip_cidr: str | None
    host_ipv6_cidr: str | None
    host_mtu: int | None
    host_admin_state: str | None
    ip_cidr: str | None
    gateway: str | None
    ipv4_method: str = "static"
    ipv6_enabled: bool = False
    ipv6_cidr: str | None
    ipv6_gateway: str | None
    mtu: int
    admin_state: str
    oper_state: str
    role: str
    mode: str
    inventory_source: str
    desired_state_source: str
    last_seen_at: datetime | None
    missing_since: datetime | None


class VlanCreate(BaseModel):
    parent_interface: str
    vlan_id: int = Field(ge=1, le=4094)
    ip_cidr: str = ""
    ipv6_cidr: str = ""
    mtu: int = Field(default=1500, ge=576, le=9000)
    role: str = "access"
    enabled: bool = True


class VlanResponse(VlanCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class WanPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    enabled: bool = True
    latency_ms: int = Field(default=0, ge=0)
    jitter_ms: int = Field(default=0, ge=0)
    packet_loss_percent: float = Field(default=0.0, ge=0, le=100)
    bandwidth_mbit: int | None = Field(default=None, ge=1)
    corrupt_percent: float | None = Field(default=0.0, ge=0, le=100)
    duplicate_percent: float | None = Field(default=0.0, ge=0, le=100)
    reorder_percent: float | None = Field(default=0.0, ge=0, le=100)


class WanPolicyResponse(WanPolicyCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int


class RouteCreate(BaseModel):
    destination_cidr: str
    gateway: str | None = None
    interface_name: str
    metric: int = Field(default=100, ge=0)
    enabled: bool = True
    wan_policy_id: int | None = None
    wan_mode: Literal["interface"] = "interface"


class RouteResponse(RouteCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    wan_policy: WanPolicyResponse | None = None


class NatRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    source: str = Field(default="any", min_length=1, max_length=240)
    outbound_interface: str = Field(min_length=1, max_length=80)
    masquerade: bool = True
    priority: int = Field(default=100, ge=0)
    description: str | None = None


class NatRuleResponse(NatRuleCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int


class WanStatusResponse(BaseModel):
    active_policy_count: int
    managed_interfaces: list[str]
    dry_run: bool


class DnsConditionalForwarder(BaseModel):
    domain: str = Field(min_length=1, max_length=120)
    server: str = Field(min_length=1, max_length=120)


class DnsSettingsUpdate(BaseModel):
    enabled: bool = False
    listen_interface: str = Field(default="eth2", min_length=1, max_length=80)
    listen_address: str | None = Field(default=None, max_length=240)
    domain: str = Field(default="labfoundry.internal", min_length=1, max_length=500)
    upstream_servers: list[str] = Field(default_factory=lambda: ["1.1.1.1", "9.9.9.9"])
    conditional_forwarders: list[DnsConditionalForwarder] = Field(default_factory=list)
    cache_size: int = Field(default=1000, ge=0, le=100000)
    expand_hosts: bool = True
    authoritative: bool = True
    authoritative_server: str = Field(default="ns1.labfoundry.internal", min_length=1, max_length=253)
    authoritative_contact: str = Field(default="hostmaster.labfoundry.internal", min_length=1, max_length=253)
    authoritative_ttl: int = Field(default=3600, ge=1, le=2147483647)
    authoritative_refresh: int = Field(default=1200, ge=1, le=2147483647)
    authoritative_retry: int = Field(default=180, ge=1, le=2147483647)
    authoritative_expire: int = Field(default=1209600, ge=1, le=2147483647)
    dnssec_enabled: bool = False
    rebind_protection_enabled: bool = False
    rebind_domain_exemptions: str = ""
    query_logging_mode: str = "off"


class DnsSettingsResponse(DnsSettingsUpdate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    authoritative_serial: int
    config_path: str
    updated_at: datetime


class DnsRecordCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=120)
    record_type: str = Field(default="A", min_length=1, max_length=20)
    address: str = Field(min_length=1, max_length=120)
    description: str | None = None
    enabled: bool = True


class DnsRecordResponse(DnsRecordCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    record_data_json: str = ""
    created_at: datetime


class DnsHostsImportRequest(BaseModel):
    hosts_text: str = Field(min_length=1)
    replace_existing: bool = True


class DnsHostsImportResponse(BaseModel):
    imported_count: int
    replaced_existing: bool
    errors: list[str] = Field(default_factory=list)
    records: list[DnsRecordResponse]


class DhcpSettingsUpdate(BaseModel):
    enabled: bool = False
    interface_name: str = Field(default="eth2", min_length=1, max_length=80)
    site_address: str = Field(default="192.168.50.1", min_length=1, max_length=64)
    prefix_length: int = Field(default=24, ge=1, le=32)
    lease_time: str = Field(default="12h", min_length=1, max_length=40)
    domain_name: str = Field(default="labfoundry.internal", min_length=1, max_length=120)
    dns_server: str = Field(default="192.168.50.1", min_length=1, max_length=64)
    authoritative: bool = True


class DhcpSettingsResponse(DhcpSettingsUpdate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    config_path: str
    updated_at: datetime


class DhcpScopeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    address_family: str = Field(default="ipv4", pattern="^(ipv4|ipv6)$")
    interface_name: str
    site_address: str
    prefix_length: int = Field(ge=1, le=128)
    range_expression: str
    lease_time: str
    domain_name: str
    dns_server: str
    ntp_server: str = ""
    enabled: bool
    description: str | None = None


class DhcpScopeResponse(DhcpScopeCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class DhcpOptionCreate(BaseModel):
    scope_id: int | None = None
    option_code: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=240)
    description: str | None = None
    enabled: bool = True


class DhcpOptionResponse(DhcpOptionCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class DhcpReservationCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=120)
    mac_address: str = Field(min_length=1, max_length=32)
    ip_address: str = Field(min_length=1, max_length=64)
    description: str | None = None
    enabled: bool = True


class DhcpReservationResponse(DhcpReservationCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


class DhcpLeaseResponse(BaseModel):
    expires_at: datetime | None
    mac_address: str
    ip_address: str
    hostname: str
    client_id: str
    status: str


class ConfigValidationResponse(BaseModel):
    valid: bool
    dry_run: bool
    command: list[str]
    config_path: str
    config_preview: str
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ConfigApplyResponse(ConfigValidationResponse):
    reloaded: bool = False


class DnsStatusResponse(BaseModel):
    enabled: bool
    service: ServiceStateResponse | None
    listen_interface: str
    listen_address: str | None
    domain: str
    record_count: int
    config_path: str
    dry_run: bool


class DhcpStatusResponse(BaseModel):
    enabled: bool
    service: ServiceStateResponse | None
    interface_name: str
    range_expression: str
    reservation_count: int
    config_path: str
    dry_run: bool


class DashboardResponse(BaseModel):
    appliance: dict[str, Any]
    service_health: list[ServiceStateResponse]
    interfaces: list[PhysicalInterfaceResponse]
    active_wan_policies: list[WanPolicyResponse]
    disk_usage: dict[str, Any]
    recent_audit_events: list[dict[str, Any]]


class MonitorResponse(BaseModel):
    enabled: bool = True
    window_hours: int
    sample_interval_seconds: int
    generated_at: str
    last_sample_at: str | None
    sample_count: int
    summary: dict[str, Any]
    virtualization: dict[str, Any]
    cpu: list[dict[str, Any]]
    cpu_cores: list[dict[str, Any]]
    memory: list[dict[str, Any]]
    network_totals: list[dict[str, Any]]
    networks: list[dict[str, Any]]
    disk_io: list[dict[str, Any]]
    disk_devices: list[dict[str, Any]]
    disks: list[dict[str, Any]]


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    success: bool
    detail: str | None
    request_id: str | None


class JobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    type: str
    status: str
    created_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    progress_percent: int
    result: str | None
    error: str | None


class ServiceActionResponse(BaseModel):
    service: str
    action: str
    dry_run: bool
    command: list[str]


class SettingsResponse(BaseModel):
    app_name: str
    appliance_hostname: str
    dry_run_system_adapters: bool
    repository_path: str
    vcf_backup_path: str
    appliance_fqdn: str
    management_https_enabled: bool = False
    management_https_cert_available: bool = False
    web_terminal_enabled: bool = False
    web_terminal_interfaces: list[str] = Field(default_factory=list)
    root_ssh_enabled: bool = False
    external_dns_servers: list[str]
    appliance_settings_config_path: str
    local_dns_enabled: bool
    management_interface: str
    management_ip: str
    valid: bool
    validation_errors: list[str] = Field(default_factory=list)
    validation_warnings: list[str] = Field(default_factory=list)
    config_preview: str


class SettingsUpdate(BaseModel):
    appliance_fqdn: str = Field(default="labfoundry.labfoundry.internal", min_length=1, max_length=180)
    management_https_enabled: bool = False
    web_terminal_enabled: bool = False
    web_terminal_interfaces: list[str] = Field(default_factory=list)
    root_ssh_enabled: bool = False
    external_dns_servers: list[str] = Field(default_factory=lambda: ["1.1.1.1", "9.9.9.9"])


class OidcProviderSettingsUpdate(BaseModel):
    enabled: bool = False
    issuer_url: str = Field(min_length=1, max_length=500)
    access_token_lifetime_seconds: int = Field(default=300, ge=60, le=3600)
    id_token_lifetime_seconds: int = Field(default=300, ge=60, le=3600)
    authorization_code_lifetime_seconds: int = Field(default=60, ge=30, le=300)
    clock_skew_seconds: int = Field(default=120, ge=0, le=300)
    signing_key_overlap_seconds: int = Field(default=3600, ge=300, le=604800)


class OidcProviderSettingsResponse(OidcProviderSettingsUpdate):
    authorization_flow_available: bool
    valid: bool
    validation_errors: list[str] = Field(default_factory=list)
    discovery_url: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    end_session_endpoint: str


class OidcClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    organization_id: int | None = None
    redirect_uris: list[str] = Field(min_length=1)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(
        default_factory=lambda: ["openid", "profile", "email", "groups"]
    )
    allow_loopback_redirects: bool = False
    access_token_lifetime_seconds: int = Field(default=300, ge=60, le=3600)
    id_token_lifetime_seconds: int = Field(default=300, ge=60, le=3600)
    authorization_code_lifetime_seconds: int = Field(default=60, ge=30, le=300)
    enabled: bool = True


class OidcClientResponse(BaseModel):
    id: int
    name: str
    client_id: str
    organization_id: int | None
    organization_slug: str | None
    redirect_uris: list[str]
    post_logout_redirect_uris: list[str]
    allowed_scopes: list[str]
    token_endpoint_auth_method: str
    access_token_lifetime_seconds: int
    id_token_lifetime_seconds: int
    authorization_code_lifetime_seconds: int
    allow_loopback_redirects: bool
    enabled: bool
    created_at: datetime
    updated_at: datetime


class OidcClientCreated(BaseModel):
    client: OidcClientResponse
    client_secret: str


class OidcClientSecretRotated(BaseModel):
    client_id: str
    client_secret: str


class OidcClientEnabledUpdate(BaseModel):
    enabled: bool


class OidcSigningKeyResponse(BaseModel):
    id: int
    kid: str
    algorithm: str
    status: str
    key_type: str | None
    created_at: datetime
    activated_at: datetime
    retired_at: datetime | None
    publish_until: datetime | None


class OidcSubjectResponse(BaseModel):
    subject: str
    source: str
    username: str
    organization_id: int | None
    organization_name: str
    created_at: datetime
