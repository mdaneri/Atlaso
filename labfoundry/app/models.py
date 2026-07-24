from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from labfoundry.app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(StrEnum):
    ADMIN = "admin"
    NETWORK_ADMIN = "network-admin"
    SERVICE_ADMIN = "service-admin"
    CERTIFICATE_OPERATOR = "certificate-operator"
    VIEWER = "viewer"


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(50), default=Role.ADMIN.value)
    roles_json: Mapped[str] = mapped_column(Text, default="")
    auth_provider: Mapped[str] = mapped_column(String(40), default="local")
    external_subject: Mapped[str] = mapped_column(String(240), default="")
    external_display_name: Mapped[str] = mapped_column(String(180), default="")
    external_email: Mapped[str] = mapped_column(String(240), default="")
    role_override_json: Mapped[str] = mapped_column(Text, default="")
    shell: Mapped[str] = mapped_column(String(80), default="/sbin/nologin")
    web_terminal_access: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    os_password_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    os_sync_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    os_sync_status: Mapped[str] = mapped_column(String(80), default="password_not_staged")
    os_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_unlock_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tokens: Mapped[list["ApiToken"]] = relationship(back_populates="owner")


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    owner_username: Mapped[str] = mapped_column(String(100))
    token_type: Mapped[str] = mapped_column(String(20), default="bearer")
    role: Mapped[str] = mapped_column(String(50))
    scopes: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signing_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    owner: Mapped[User] = relationship(back_populates="tokens")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(120), index=True)
    resource_type: Mapped[str] = mapped_column(String(80), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class PhysicalInterface(Base):
    __tablename__ = "physical_interfaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    mac_address: Mapped[str] = mapped_column(String(32))
    driver: Mapped[str | None] = mapped_column(String(80), nullable=True)
    speed: Mapped[str | None] = mapped_column(String(50), nullable=True)
    host_ip_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_ipv6_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_mtu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    host_admin_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    ip_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ipv4_method: Mapped[str] = mapped_column(String(20), default="static")
    ipv6_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    ipv6_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ipv6_gateway: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mtu: Mapped[int] = mapped_column(Integer, default=1500)
    admin_state: Mapped[str] = mapped_column(String(20), default="up")
    oper_state: Mapped[str] = mapped_column(String(20), default="up")
    role: Mapped[str] = mapped_column(String(40), default="unused")
    mode: Mapped[str] = mapped_column(String(40), default="unused")
    inventory_source: Mapped[str] = mapped_column(String(40), default="seed")
    desired_state_source: Mapped[str] = mapped_column(String(40), default="seed")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    missing_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VlanInterface(Base):
    __tablename__ = "vlan_interfaces"
    __table_args__ = (UniqueConstraint("parent_interface", "vlan_id", name="uq_vlan_parent_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    parent_interface: Mapped[str] = mapped_column(String(50), index=True)
    vlan_id: Mapped[int] = mapped_column(Integer)
    ip_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ipv6_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mtu: Mapped[int] = mapped_column(Integer, default=1500)
    role: Mapped[str] = mapped_column(String(40), default="access")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class WanPolicy(Base):
    __tablename__ = "wan_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    jitter_ms: Mapped[int] = mapped_column(Integer, default=0)
    packet_loss_percent: Mapped[float] = mapped_column(default=0.0)
    bandwidth_mbit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    corrupt_percent: Mapped[float | None] = mapped_column(default=0.0, nullable=True)
    duplicate_percent: Mapped[float | None] = mapped_column(default=0.0, nullable=True)
    reorder_percent: Mapped[float | None] = mapped_column(default=0.0, nullable=True)

    routes: Mapped[list["Route"]] = relationship(back_populates="wan_policy")


class Route(Base):
    __tablename__ = "routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    destination_cidr: Mapped[str] = mapped_column(String(64), index=True)
    gateway: Mapped[str | None] = mapped_column(String(64), nullable=True)
    interface_name: Mapped[str] = mapped_column(String(80), index=True)
    metric: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    wan_policy_id: Mapped[int | None] = mapped_column(ForeignKey("wan_policies.id"), nullable=True)
    wan_mode: Mapped[str] = mapped_column(String(40), default="interface")

    wan_policy: Mapped[WanPolicy | None] = relationship(back_populates="routes")


class RoutingRule(Base):
    __tablename__ = "routing_rules"
    __table_args__ = (UniqueConstraint("name", name="uq_routing_rule_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source_interface: Mapped[str] = mapped_column(String(80), index=True)
    destination_interface: Mapped[str] = mapped_column(String(80), index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NatRule(Base):
    __tablename__ = "nat_rules"
    __table_args__ = (UniqueConstraint("name", name="uq_nat_rule_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(240), default="any")
    outbound_interface: Mapped[str] = mapped_column(String(80), index=True)
    masquerade: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceState(Base):
    __tablename__ = "service_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    running: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    health: Mapped[str] = mapped_column(String(40), default="unknown")
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class MonitorSample(Base):
    __tablename__ = "monitor_samples"
    __table_args__ = (Index("ix_monitor_samples_sampled_at_id", "sampled_at", "id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sampled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_count: Mapped[int] = mapped_column(Integer, default=0)
    cpu_total_jiffies: Mapped[int] = mapped_column(Integer, default=0)
    cpu_idle_jiffies: Mapped[int] = mapped_column(Integer, default=0)
    load1: Mapped[float | None] = mapped_column(Float, nullable=True)
    load5: Mapped[float | None] = mapped_column(Float, nullable=True)
    load15: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    memory_available_bytes: Mapped[int] = mapped_column(Integer, default=0)
    memory_used_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    swap_total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    swap_used_bytes: Mapped[int] = mapped_column(Integer, default=0)

    cpu_samples: Mapped[list["MonitorCpuSample"]] = relationship(back_populates="sample", cascade="all, delete-orphan")
    network_samples: Mapped[list["MonitorNetworkSample"]] = relationship(back_populates="sample", cascade="all, delete-orphan")
    disk_samples: Mapped[list["MonitorDiskSample"]] = relationship(back_populates="sample", cascade="all, delete-orphan")


class MonitorCpuSample(Base):
    __tablename__ = "monitor_cpu_samples"
    __table_args__ = (Index("ix_monitor_cpu_sample_cpu", "sample_id", "cpu_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("monitor_samples.id"), index=True)
    cpu_name: Mapped[str] = mapped_column(String(40), index=True)
    percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_jiffies: Mapped[int] = mapped_column(Integer, default=0)
    idle_jiffies: Mapped[int] = mapped_column(Integer, default=0)

    sample: Mapped[MonitorSample] = relationship(back_populates="cpu_samples")


class MonitorNetworkSample(Base):
    __tablename__ = "monitor_network_samples"
    __table_args__ = (Index("ix_monitor_network_sample_interface", "sample_id", "interface_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("monitor_samples.id"), index=True)
    interface_name: Mapped[str] = mapped_column(String(80), index=True)
    rx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    tx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    rx_bytes_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    tx_bytes_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    rx_packets: Mapped[int] = mapped_column(Integer, default=0)
    tx_packets: Mapped[int] = mapped_column(Integer, default=0)
    rx_errors: Mapped[int] = mapped_column(Integer, default=0)
    tx_errors: Mapped[int] = mapped_column(Integer, default=0)
    rx_dropped: Mapped[int] = mapped_column(Integer, default=0)
    tx_dropped: Mapped[int] = mapped_column(Integer, default=0)
    oper_state: Mapped[str] = mapped_column(String(40), default="unknown")

    sample: Mapped[MonitorSample] = relationship(back_populates="network_samples")


class MonitorDiskSample(Base):
    __tablename__ = "monitor_disk_samples"
    __table_args__ = (Index("ix_monitor_disk_sample_mount", "sample_id", "mount_point"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("monitor_samples.id"), index=True)
    mount_point: Mapped[str] = mapped_column(String(240), index=True)
    device: Mapped[str] = mapped_column(String(160), default="")
    filesystem: Mapped[str] = mapped_column(String(60), default="")
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    used_bytes: Mapped[int] = mapped_column(Integer, default=0)
    free_bytes: Mapped[int] = mapped_column(Integer, default=0)
    used_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    read_bytes: Mapped[int] = mapped_column(Integer, default=0)
    write_bytes: Mapped[int] = mapped_column(Integer, default=0)
    read_bytes_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    write_bytes_per_sec: Mapped[float | None] = mapped_column(Float, nullable=True)

    sample: Mapped[MonitorSample] = relationship(back_populates="disk_samples")


class ApplianceSettings(Base):
    __tablename__ = "appliance_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fqdn: Mapped[str] = mapped_column(String(180), default="labfoundry.labfoundry.internal")
    management_https_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    web_terminal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    web_terminal_interfaces_json: Mapped[str] = mapped_column(Text, default="[]")
    root_ssh_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    vmware_ceip_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    service_dns_target_naming: Mapped[str] = mapped_column(String(20), default="ip")
    external_dns_servers: Mapped[str] = mapped_column(Text, default="1.1.1.1\n9.9.9.9")
    config_path: Mapped[str] = mapped_column(String(240), default="/var/lib/labfoundry/apply/appliance-settings/labfoundry-settings.json")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NtpSettings(Base):
    __tablename__ = "ntp_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="ntp.labfoundry.internal")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=123)
    upstream_servers: Mapped[str] = mapped_column(Text, default="time.cloudflare.com\nnts.netnod.se")
    upstream_sources_json: Mapped[str] = mapped_column(
        Text,
        default='[{"description":"Cloudflare public NTS","enabled":true,"id":"cloudflare-nts","source":"time.cloudflare.com","use_nts":true},{"description":"Netnod public NTS","enabled":true,"id":"netnod-nts","source":"nts.netnod.se","use_nts":true}]',
    )
    allow_clients: Mapped[str] = mapped_column(Text, default="any")
    nts_server_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    nts_server_cert_path: Mapped[str] = mapped_column(String(300), default="")
    nts_server_key_path: Mapped[str] = mapped_column(String(300), default="")
    nts_ke_port: Mapped[int] = mapped_column(Integer, default=4460)
    minsources: Mapped[int | None] = mapped_column(Integer, nullable=True)
    config_path: Mapped[str] = mapped_column(String(240), default="/var/lib/labfoundry/apply/ntpd/labfoundry-ntp.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FirewallSettings(Base):
    __tablename__ = "firewall_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    default_input_policy: Mapped[str] = mapped_column(String(20), default="drop")
    default_forward_policy: Mapped[str] = mapped_column(String(20), default="drop")
    default_output_policy: Mapped[str] = mapped_column(String(20), default="accept")
    allow_established: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_loopback: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_icmp: Mapped[bool] = mapped_column(Boolean, default=True)
    log_dropped: Mapped[bool] = mapped_column(Boolean, default=False)
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/nftables.d/labfoundry.nft")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    __table_args__ = (UniqueConstraint("name", name="uq_firewall_rule_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    direction: Mapped[str] = mapped_column(String(20), default="input")
    action: Mapped[str] = mapped_column(String(20), default="accept")
    protocol: Mapped[str] = mapped_column(String(20), default="tcp")
    source: Mapped[str] = mapped_column(String(120), default="any")
    destination: Mapped[str] = mapped_column(String(120), default="any")
    destination_port: Mapped[str] = mapped_column(String(120), default="")
    interface_name: Mapped[str] = mapped_column(String(80), default="")
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DnsSettings(Base):
    __tablename__ = "dns_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    listen_interface: Mapped[str] = mapped_column(String(80), default="")
    listen_address: Mapped[str | None] = mapped_column(String(240), nullable=True)
    domain: Mapped[str] = mapped_column(String(500), default="labfoundry.internal")
    upstream_servers: Mapped[str] = mapped_column(Text, default="1.1.1.1\n9.9.9.9")
    cache_size: Mapped[int] = mapped_column(Integer, default=1000)
    expand_hosts: Mapped[bool] = mapped_column(Boolean, default=True)
    authoritative: Mapped[bool] = mapped_column(Boolean, default=True)
    authoritative_server: Mapped[str] = mapped_column(String(253), default="")
    authoritative_contact: Mapped[str] = mapped_column(String(253), default="")
    authoritative_ttl: Mapped[int] = mapped_column(Integer, default=3600)
    authoritative_serial: Mapped[int] = mapped_column(Integer, default=0)
    authoritative_refresh: Mapped[int] = mapped_column(Integer, default=1200)
    authoritative_retry: Mapped[int] = mapped_column(Integer, default=180)
    authoritative_expire: Mapped[int] = mapped_column(Integer, default=1209600)
    dnssec_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    rebind_protection_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    rebind_domain_exemptions: Mapped[str] = mapped_column(Text, default="")
    query_logging_mode: Mapped[str] = mapped_column(String(20), default="off")
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/dnsmasq.d/labfoundry.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DnsRecord(Base):
    __tablename__ = "dns_records"
    __table_args__ = (UniqueConstraint("hostname", "record_type", "address", name="uq_dns_record_hostname_type_address"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(120), index=True)
    record_type: Mapped[str] = mapped_column(String(20), default="A")
    address: Mapped[str] = mapped_column(String(120))
    record_data_json: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DhcpSettings(Base):
    __tablename__ = "dhcp_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interface_name: Mapped[str] = mapped_column(String(80), default="")
    site_address: Mapped[str] = mapped_column(String(64), default="")
    prefix_length: Mapped[int] = mapped_column(Integer, default=24)
    lease_time: Mapped[str] = mapped_column(String(40), default="12h")
    domain_name: Mapped[str] = mapped_column(String(120), default="labfoundry.internal")
    dns_server: Mapped[str] = mapped_column(String(64), default="")
    authoritative: Mapped[bool] = mapped_column(Boolean, default=True)
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/dnsmasq.d/labfoundry.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DhcpScope(Base):
    __tablename__ = "dhcp_scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    address_family: Mapped[str] = mapped_column(String(10), default="ipv4")
    interface_name: Mapped[str] = mapped_column(String(80), default="eth2")
    site_address: Mapped[str] = mapped_column(String(64), default="192.168.50.1")
    prefix_length: Mapped[int] = mapped_column(Integer, default=24)
    range_expression: Mapped[str] = mapped_column(String(500), default="192.168.50.100-192.168.50.200")
    lease_time: Mapped[str] = mapped_column(String(40), default="12h")
    domain_name: Mapped[str] = mapped_column(String(120), default="labfoundry.internal")
    dns_server: Mapped[str] = mapped_column(String(64), default="192.168.50.1")
    ntp_server: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DhcpOption(Base):
    __tablename__ = "dhcp_options"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[int | None] = mapped_column(ForeignKey("dhcp_scopes.id"), nullable=True, index=True)
    option_code: Mapped[str] = mapped_column(String(80))
    value: Mapped[str] = mapped_column(String(240))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DhcpReservation(Base):
    __tablename__ = "dhcp_reservations"
    __table_args__ = (UniqueConstraint("mac_address", name="uq_dhcp_reservation_mac"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(120))
    mac_address: Mapped[str] = mapped_column(String(32), index=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CaSettings(Base):
    __tablename__ = "ca_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_hostname: Mapped[str] = mapped_column(String(180), default="ca.labfoundry.internal")
    root_common_name: Mapped[str] = mapped_column(String(180), default="LabFoundry Internal Root CA")
    organization: Mapped[str] = mapped_column(String(180), default="LabFoundry")
    organizational_unit: Mapped[str] = mapped_column(String(180), default="Lab Infrastructure")
    country: Mapped[str] = mapped_column(String(2), default="US")
    state: Mapped[str] = mapped_column(String(120), default="")
    locality: Mapped[str] = mapped_column(String(120), default="")
    listen_interface: Mapped[str] = mapped_column(String(80), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    key_algorithm: Mapped[str] = mapped_column(String(20), default="RSA")
    key_size: Mapped[int] = mapped_column(Integer, default=4096)
    digest_algorithm: Mapped[str] = mapped_column(String(40), default="sha256")
    root_valid_days: Mapped[int] = mapped_column(Integer, default=3650)
    intermediate_valid_days: Mapped[int] = mapped_column(Integer, default=1825)
    publish_crl: Mapped[bool] = mapped_column(Boolean, default=True)
    ocsp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    storage_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/ca")
    root_certificate_pem: Mapped[str] = mapped_column(Text, default="")
    root_private_key_encrypted: Mapped[str] = mapped_column(Text, default="")
    root_serial_number: Mapped[str] = mapped_column(String(120), default="")
    root_fingerprint: Mapped[str] = mapped_column(String(128), default="")
    root_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    root_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CaProfile(Base):
    __tablename__ = "ca_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    certificate_type: Mapped[str] = mapped_column(String(40), default="server")
    validity_days: Mapped[int] = mapped_column(Integer, default=825)
    key_algorithm: Mapped[str] = mapped_column(String(20), default="RSA")
    key_size: Mapped[int] = mapped_column(Integer, default=2048)
    key_usage: Mapped[str] = mapped_column(String(240), default="digitalSignature,keyEncipherment")
    extended_key_usage: Mapped[str] = mapped_column(String(240), default="serverAuth")
    san_required: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    certificates: Mapped[list["CaCertificate"]] = relationship(back_populates="profile")


class CaCertificate(Base):
    __tablename__ = "ca_certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    common_name: Mapped[str] = mapped_column(String(180), index=True)
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("ca_profiles.id"), nullable=True, index=True)
    subject_alt_names: Mapped[str] = mapped_column(Text, default="")
    ip_addresses: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(40), default="planned")
    serial_number: Mapped[str | None] = mapped_column(String(80), nullable=True)
    certificate_pem: Mapped[str] = mapped_column(Text, default="")
    private_key_encrypted: Mapped[str] = mapped_column(Text, default="")
    chain_pem: Mapped[str] = mapped_column(Text, default="")
    issuer_common_name: Mapped[str] = mapped_column(String(180), default="")
    fingerprint: Mapped[str] = mapped_column(String(128), default="")
    managed_owner: Mapped[str] = mapped_column(String(120), default="")
    cert_path: Mapped[str] = mapped_column(String(300), default="")
    key_path: Mapped[str] = mapped_column(String(300), default="")
    chain_path: Mapped[str] = mapped_column(String(300), default="")
    csr_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    revocation_reason: Mapped[str] = mapped_column(String(120), default="")

    profile: Mapped[CaProfile | None] = relationship(back_populates="certificates")


class KmsSettings(Base):
    __tablename__ = "kms_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    backend: Mapped[str] = mapped_column(String(40), default="pykmip")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=5696)
    hostname: Mapped[str] = mapped_column(String(180), default="kms.labfoundry.internal")
    server_certificate: Mapped[str] = mapped_column(String(180), default="kms.labfoundry.internal")
    ca_certificate_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/ca/root.crt")
    database_path: Mapped[str] = mapped_column(String(240), default="/var/lib/labfoundry/kms/pykmip.db")
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/kms/pykmip.conf")
    require_client_cert: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_register: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_destroy: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KmsClient(Base):
    __tablename__ = "kms_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    certificate_subject: Mapped[str] = mapped_column(String(240))
    role: Mapped[str] = mapped_column(String(40), default="service")
    allowed_operations: Mapped[str] = mapped_column(Text, default="locate,get,register,create")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    keys: Mapped[list["KmsKey"]] = relationship(back_populates="owner_client")


class KmsKey(Base):
    __tablename__ = "kms_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    algorithm: Mapped[str] = mapped_column(String(40), default="AES")
    length: Mapped[int] = mapped_column(Integer, default=256)
    usage: Mapped[str] = mapped_column(String(240), default="encrypt,decrypt")
    state: Mapped[str] = mapped_column(String(40), default="active")
    owner_client_id: Mapped[int | None] = mapped_column(ForeignKey("kms_clients.id"), nullable=True, index=True)
    exportable: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner_client: Mapped[KmsClient | None] = relationship(back_populates="keys")


class LdapSettings(Base):
    __tablename__ = "ldap_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="ldap.labfoundry.internal")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    ldaps_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    port: Mapped[int] = mapped_column(Integer, default=636)
    ldap_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    ldap_port: Mapped[int] = mapped_column(Integer, default=389)
    min_password_length: Mapped[int] = mapped_column(Integer, default=14)
    require_uppercase: Mapped[bool] = mapped_column(Boolean, default=True)
    require_lowercase: Mapped[bool] = mapped_column(Boolean, default=True)
    require_number: Mapped[bool] = mapped_column(Boolean, default=True)
    require_special: Mapped[bool] = mapped_column(Boolean, default=True)
    disallow_username: Mapped[bool] = mapped_column(Boolean, default=True)
    max_failures: Mapped[int] = mapped_column(Integer, default=5)
    lockout_minutes: Mapped[int] = mapped_column(Integer, default=15)
    failure_window_minutes: Mapped[int] = mapped_column(Integer, default=15)
    password_history: Mapped[int] = mapped_column(Integer, default=5)
    password_max_age_days: Mapped[int] = mapped_column(Integer, default=0)
    config_path: Mapped[str] = mapped_column(
        String(240),
        default="/var/lib/labfoundry/apply/ldap/labfoundry-ldap.json",
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LdapOrganization(Base):
    __tablename__ = "ldap_organizations"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_ldap_organization_slug"),
        UniqueConstraint("suffix_dn", name="uq_ldap_organization_suffix"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    slug: Mapped[str] = mapped_column(String(80), index=True)
    suffix_dn: Mapped[str] = mapped_column(String(500), index=True)
    bind_dn: Mapped[str] = mapped_column(String(500), default="")
    bind_password_encrypted: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    vcf_target_url: Mapped[str] = mapped_column(String(500), default="")
    vcf_org_id: Mapped[str] = mapped_column(String(240), default="")
    vcf_org_name: Mapped[str] = mapped_column(String(128), default="")
    vcf_tls_fingerprint: Mapped[str] = mapped_column(String(160), default="")
    vcf_last_status: Mapped[str] = mapped_column(String(80), default="")
    vcf_last_message: Mapped[str] = mapped_column(Text, default="")
    vcf_last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    users: Mapped[list["LdapUser"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        order_by="LdapUser.uid",
    )
    groups: Mapped[list["LdapGroup"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        order_by="LdapGroup.name",
    )


class LdapUser(Base):
    __tablename__ = "ldap_users"
    __table_args__ = (UniqueConstraint("organization_id", "uid", name="uq_ldap_user_org_uid"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("ldap_organizations.id"), index=True)
    uid: Mapped[str] = mapped_column(String(100), index=True)
    given_name: Mapped[str] = mapped_column(String(120), default="")
    surname: Mapped[str] = mapped_column(String(120), default="")
    display_name: Mapped[str] = mapped_column(String(180), default="")
    email: Mapped[str] = mapped_column(String(240), default="")
    telephone: Mapped[str] = mapped_column(String(80), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    password_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_status: Mapped[str] = mapped_column(String(40), default="not_staged")
    unlock_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped[LdapOrganization] = relationship(back_populates="users")
    memberships: Mapped[list["LdapGroupMembership"]] = relationship(
        back_populates="member_user",
        cascade="all, delete-orphan",
        foreign_keys="LdapGroupMembership.member_user_id",
    )


class LdapGroup(Base):
    __tablename__ = "ldap_groups"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_ldap_group_org_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("ldap_organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped[LdapOrganization] = relationship(back_populates="groups")
    members: Mapped[list["LdapGroupMembership"]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan",
        foreign_keys="LdapGroupMembership.group_id",
    )
    parent_memberships: Mapped[list["LdapGroupMembership"]] = relationship(
        back_populates="member_group",
        cascade="all, delete-orphan",
        foreign_keys="LdapGroupMembership.member_group_id",
    )


class LdapGroupMembership(Base):
    __tablename__ = "ldap_group_memberships"
    __table_args__ = (
        UniqueConstraint("group_id", "member_user_id", name="uq_ldap_group_member_user"),
        UniqueConstraint("group_id", "member_group_id", name="uq_ldap_group_member_group"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("ldap_groups.id"), index=True)
    member_user_id: Mapped[int | None] = mapped_column(ForeignKey("ldap_users.id"), nullable=True, index=True)
    member_group_id: Mapped[int | None] = mapped_column(ForeignKey("ldap_groups.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    group: Mapped[LdapGroup] = relationship(
        back_populates="members",
        foreign_keys=[group_id],
    )
    member_user: Mapped[LdapUser | None] = relationship(
        back_populates="memberships",
        foreign_keys=[member_user_id],
    )
    member_group: Mapped[LdapGroup | None] = relationship(
        back_populates="parent_memberships",
        foreign_keys=[member_group_id],
    )


class OidcProviderSettings(Base):
    __tablename__ = "oidc_provider_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    issuer_url: Mapped[str] = mapped_column(String(500), default="")
    access_token_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=300)
    id_token_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=300)
    authorization_code_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=60)
    clock_skew_seconds: Mapped[int] = mapped_column(Integer, default=120)
    signing_key_overlap_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OidcClient(Base):
    __tablename__ = "oidc_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    client_id: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    client_secret_hash: Mapped[str] = mapped_column(Text)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ldap_organizations.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    allowed_scopes: Mapped[str] = mapped_column(Text, default="openid profile email groups")
    token_endpoint_auth_method: Mapped[str] = mapped_column(String(80), default="client_secret_basic")
    access_token_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=300)
    id_token_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=300)
    authorization_code_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=60)
    allow_loopback_redirects: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped[LdapOrganization | None] = relationship()
    redirect_uris: Mapped[list["OidcClientRedirectUri"]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
        order_by="OidcClientRedirectUri.id",
    )


class OidcClientRedirectUri(Base):
    __tablename__ = "oidc_client_redirect_uris"
    __table_args__ = (
        UniqueConstraint("oidc_client_id", "kind", "uri", name="uq_oidc_client_redirect_uri"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    oidc_client_id: Mapped[int] = mapped_column(ForeignKey("oidc_clients.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    uri: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[OidcClient] = relationship(back_populates="redirect_uris")


class OidcSubject(Base):
    __tablename__ = "oidc_subjects"
    __table_args__ = (
        CheckConstraint(
            "(local_user_id IS NOT NULL AND ldap_user_id IS NULL) OR "
            "(local_user_id IS NULL AND ldap_user_id IS NOT NULL)",
            name="ck_oidc_subject_exactly_one_source",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    local_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=True,
        index=True,
    )
    ldap_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ldap_users.id", ondelete="CASCADE"),
        unique=True,
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OidcSigningKey(Base):
    __tablename__ = "oidc_signing_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kid: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    algorithm: Mapped[str] = mapped_column(String(20), default="RS256")
    private_key_encrypted: Mapped[str] = mapped_column(Text)
    public_jwk_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    active_slot: Mapped[int | None] = mapped_column(Integer, unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    publish_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LdapRecoveryArchive(Base):
    __tablename__ = "ldap_recovery_archives"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(240))
    path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(40), default="staged")
    organization_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VcfBackupSettings(Base):
    __tablename__ = "vcf_backup_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=22)
    sftp_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    storage_path: Mapped[str] = mapped_column(String(240), default="/mnt/labfoundry-vcf-backups")
    chroot_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_password_auth: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_public_key_auth: Mapped[bool] = mapped_column(Boolean, default=True)
    max_sessions: Mapped[int] = mapped_column(Integer, default=4)
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/ssh/labfoundry-vcf-backups-sshd.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sftp_user: Mapped[User | None] = relationship()


class EsxStorageSettings(Base):
    __tablename__ = "esx_storage_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(253), default="nfs.labfoundry.internal")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EsxStorageVolume(Base):
    __tablename__ = "esx_storage_volumes"
    __table_args__ = (
        UniqueConstraint("name", name="uq_esx_storage_volume_name"),
        UniqueConstraint("stable_device_id", name="uq_esx_storage_volume_device"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    source_type: Mapped[str] = mapped_column(String(20), default="blank_disk")
    stable_device_id: Mapped[str] = mapped_column(String(500), default="")
    device_path: Mapped[str] = mapped_column(String(500), default="")
    device_model: Mapped[str] = mapped_column(String(240), default="")
    device_serial: Mapped[str] = mapped_column(String(240), default="")
    device_wwn: Mapped[str] = mapped_column(String(240), default="")
    capacity_bytes: Mapped[int] = mapped_column(Integer, default=0)
    filesystem_uuid: Mapped[str] = mapped_column(String(120), default="")
    filesystem_label: Mapped[str] = mapped_column(String(120), default="")
    mount_path: Mapped[str] = mapped_column(String(500), default="")
    state: Mapped[str] = mapped_column(String(40), default="pending_format")
    applied: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    shares: Mapped[list["EsxNfsShare"]] = relationship(back_populates="volume")


class EsxNfsShare(Base):
    __tablename__ = "esx_nfs_shares"
    __table_args__ = (UniqueConstraint("datastore_name", name="uq_esx_nfs_share_datastore_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    datastore_name: Mapped[str] = mapped_column(String(120), index=True)
    volume_id: Mapped[int] = mapped_column(ForeignKey("esx_storage_volumes.id"), index=True)
    relative_path: Mapped[str] = mapped_column(String(500), default="")
    preferred_nfs_version: Mapped[str] = mapped_column(String(10), default="4.1")
    interface_name: Mapped[str] = mapped_column(String(80), default="")
    address_families: Mapped[str] = mapped_column(String(40), default="ipv4\nipv6")
    ipv4_clients: Mapped[str] = mapped_column(Text, default="")
    ipv6_clients: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    volume: Mapped[EsxStorageVolume] = relationship(back_populates="shares")


class VcfTrustTarget(Base):
    __tablename__ = "vcf_trust_targets"
    __table_args__ = (UniqueConstraint("address", "api_port", name="uq_vcf_trust_target_address_api_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(240), index=True)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    api_port: Mapped[int] = mapped_column(Integer, default=443)
    appliance_role: Mapped[str] = mapped_column(String(40), default="")
    appliance_version: Mapped[str] = mapped_column(String(80), default="")
    ssh_host_key_fingerprint: Mapped[str] = mapped_column(String(160), default="")
    tls_fingerprint: Mapped[str] = mapped_column(String(160), default="")
    last_ca_fingerprint: Mapped[str] = mapped_column(String(128), default="")
    last_result: Mapped[str] = mapped_column(String(80), default="")
    last_job_id: Mapped[str] = mapped_column(String(40), default="")
    last_attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_succeeded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VcfPrivateRegistrySettings(Base):
    __tablename__ = "vcf_private_registry_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="registry.labfoundry.internal")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    harbor_project: Mapped[str] = mapped_column(String(120), default="vcf-supervisor-services")
    storage_path: Mapped[str] = mapped_column(String(240), default="/mnt/labfoundry-vcf-registry")
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/harbor/harbor.yml")
    ca_bundle_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/ca/ca-bundle.pem")
    server_certificate: Mapped[str] = mapped_column(String(180), default="registry.labfoundry.internal")
    robot_account: Mapped[str] = mapped_column(String(120), default="robot$vcf-supervisor-services")
    relocation_dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VcfOfflineDepotSettings(Base):
    __tablename__ = "vcf_offline_depot_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="depot.labfoundry.internal")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    http_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    allow_unauthenticated_access: Mapped[bool] = mapped_column(Boolean, default=False)
    server_certificate: Mapped[str] = mapped_column(String(180), default="depot.labfoundry.internal")
    depot_store_path: Mapped[str] = mapped_column(String(240), default="/mnt/labfoundry-vcf-offline-depot")
    tool_archive_path: Mapped[str] = mapped_column(String(500), default="")
    tool_version: Mapped[str] = mapped_column(String(80), default="")
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    http_user: Mapped[User | None] = relationship()


class VcfDepotDownloadProfile(Base):
    __tablename__ = "vcf_depot_download_profiles"
    __table_args__ = (UniqueConstraint("name", name="uq_vcf_depot_download_profile_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    profile_type: Mapped[str] = mapped_column(String(40), default="binaries")
    sku: Mapped[str] = mapped_column(String(20), default="VCF")
    vcf_version: Mapped[str] = mapped_column(String(40), default="9.1.0")
    binary_type: Mapped[str] = mapped_column(String(20), default="INSTALL")
    automated_install: Mapped[bool] = mapped_column(Boolean, default=True)
    upgrades_only: Mapped[bool] = mapped_column(Boolean, default=False)
    patches_only: Mapped[bool] = mapped_column(Boolean, default=False)
    component: Mapped[str] = mapped_column(String(80), default="")
    component_version: Mapped[str] = mapped_column(String(80), default="")
    disabled_platforms: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(40), default="planned")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UpdateSource(Base):
    __tablename__ = "update_sources"
    __table_args__ = (UniqueConstraint("kind", "name", name="uq_update_source_kind_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    url: Mapped[str] = mapped_column(String(1000), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    settings_json: Mapped[str] = mapped_column(Text, default="{}")
    credential_encrypted: Mapped[str] = mapped_column(Text, default="")
    validation_status: Mapped[str] = mapped_column(String(40), default="not_checked")
    validation_message: Mapped[str] = mapped_column(Text, default="")
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedPackage(Base):
    __tablename__ = "managed_packages"
    __table_args__ = (UniqueConstraint("ecosystem", "name", name="uq_managed_package_ecosystem_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(160), index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("update_sources.id"), nullable=True, index=True)
    policy: Mapped[str] = mapped_column(String(40), default="pinned")
    target_version: Mapped[str] = mapped_column(String(120), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    source: Mapped[UpdateSource | None] = relationship()


class AutomationScript(Base):
    __tablename__ = "automation_scripts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    revisions: Mapped[list["AutomationScriptRevision"]] = relationship(
        back_populates="script",
        cascade="all, delete-orphan",
        order_by="AutomationScriptRevision.revision",
    )


class AutomationScriptRevision(Base):
    __tablename__ = "automation_script_revisions"
    __table_args__ = (UniqueConstraint("script_id", "revision", name="uq_automation_script_revision"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    script_id: Mapped[int] = mapped_column(ForeignKey("automation_scripts.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    interpreter: Mapped[str] = mapped_column(String(20), default="powershell")
    content: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    script: Mapped[AutomationScript] = relationship(back_populates="revisions")


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    task_type: Mapped[str] = mapped_column(String(80), index=True)
    task_config_json: Mapped[str] = mapped_column(Text, default="{}")
    schedule_kind: Mapped[str] = mapped_column(String(20), default="cron")
    cron_expression: Mapped[str] = mapped_column(String(120), default="")
    run_once_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timezone_name: Mapped[str] = mapped_column(String(80), default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_job_id: Mapped[str] = mapped_column(String(40), default="")
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VcfRegistryBundle(Base):
    __tablename__ = "vcf_registry_bundles"
    __table_args__ = (UniqueConstraint("name", name="uq_vcf_registry_bundle_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    source_reference: Mapped[str] = mapped_column(String(500), default="")
    target_reference: Mapped[str] = mapped_column(String(500), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(40), default="planned")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EsxiKickstart(Base):
    __tablename__ = "esxi_kickstarts"
    __table_args__ = (UniqueConstraint("name", name="uq_esxi_kickstart_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    rendered_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    rendered_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    http_path: Mapped[str] = mapped_column(String(240), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_rendered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EsxiPxeHost(Base):
    __tablename__ = "esxi_pxe_hosts"
    __table_args__ = (UniqueConstraint("mac_address", name="uq_esxi_pxe_host_mac"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(120), index=True)
    mac_address: Mapped[str] = mapped_column(String(32), index=True)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    kickstart_id: Mapped[int | None] = mapped_column(ForeignKey("esxi_kickstarts.id"), nullable=True, index=True)
    installer_iso_path: Mapped[str] = mapped_column(String(500), default="")
    variables_json: Mapped[str] = mapped_column(Text, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    kickstart: Mapped[EsxiKickstart | None] = relationship()


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(40), default=JobStatus.PENDING.value)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("schedules.id"), nullable=True, index=True)
    trigger: Mapped[str] = mapped_column(String(20), default="manual")
    planned_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    task_config_json: Mapped[str] = mapped_column(Text, default="{}")

    steps: Mapped[list["JobStep"]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="JobStep.position",
    )


class JobStep(Base):
    __tablename__ = "job_steps"
    __table_args__ = (UniqueConstraint("job_id", "component_key", name="uq_job_step_component"),)

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), index=True)
    component_key: Mapped[str] = mapped_column(String(80))
    label: Mapped[str] = mapped_column(String(160))
    position: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(40), default=JobStatus.PENDING.value)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    job: Mapped[Job] = relationship(back_populates="steps")


class Setting(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
