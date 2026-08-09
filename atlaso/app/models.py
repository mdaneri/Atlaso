"""Define Atlaso's persistent SQLAlchemy domain models."""

from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from atlaso.app.database import Base


def utcnow() -> datetime:
    """Return the current timezone-aware UTC time."""
    return datetime.now(timezone.utc)


def _job_vcf_depot_operation_default(context) -> bool:
    """Return job vcf depot operation default."""
    return str(context.get_current_parameters().get("type") or "") in {
        "vcf-depot-download",
        "vcf-depot-software-id",
    }


class Role(StrEnum):
    """Represent role.

    Attributes:
        ADMIN: Symbolic value representing 'admin'.
        NETWORK_ADMIN: Symbolic value representing 'network-admin'.
        SERVICE_ADMIN: Symbolic value representing 'service-admin'.
        CERTIFICATE_OPERATOR: Symbolic value representing 'certificate-operator'.
        VIEWER: Symbolic value representing 'viewer'.
    """
    ADMIN = "admin"
    NETWORK_ADMIN = "network-admin"
    SERVICE_ADMIN = "service-admin"
    CERTIFICATE_OPERATOR = "certificate-operator"
    VIEWER = "viewer"


class JobStatus(StrEnum):
    """Represent job status.

    Attributes:
        PENDING: Symbolic value representing 'pending'.
        RUNNING: Symbolic value representing 'running'.
        SUCCEEDED: Symbolic value representing 'succeeded'.
        FAILED: Symbolic value representing 'failed'.
        SKIPPED: Symbolic value representing 'skipped'.
        CANCELLED: Symbolic value representing 'cancelled'.
    """
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class User(Base):
    """Represent user.

    Attributes:
        id: Unique database identifier for the resource.
        username: Persisted username for the user resource.
        description: Operator-facing purpose or context for the resource.
        role: Persisted role for the user resource.
        roles_json: Serialized JSON representation of roles.
        auth_provider: Persisted auth provider for the user resource.
        external_subject: Persisted external subject for the user resource.
        external_display_name: Persisted external display name for the user resource.
        external_email: Persisted external email for the user resource.
        role_override_json: Serialized JSON representation of role override.
        shell: Persisted shell for the user resource.
        web_terminal_access: Persisted web terminal access for the user resource.
        enabled: Whether the resource is enabled.
        os_password_applied_at: UTC timestamp associated with os password applied.
        os_sync_applied_at: UTC timestamp associated with os sync applied.
        os_sync_status: Persisted os sync status for the user resource.
        os_sync_error: Persisted os sync error for the user resource.
        os_unlock_requested_at: UTC timestamp associated with os unlock requested.
        created_at: UTC timestamp when the resource was created.
        tokens: Persisted tokens for the user resource.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
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
    """Represent api token.

    Attributes:
        id: Unique database identifier for the resource.
        jti: Persisted jti for the apitoken resource.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        owner_user_id: Identifier of the associated owner user.
        owner_username: Persisted owner username for the apitoken resource.
        token_type: Persisted token type for the apitoken resource.
        role: Persisted role for the apitoken resource.
        scopes: Persisted scopes for the apitoken resource.
        created_at: UTC timestamp when the resource was created.
        expires_at: UTC timestamp after which the resource is no longer valid.
        last_used_at: UTC timestamp associated with last used.
        revoked_at: UTC timestamp associated with revoked.
        revoked_by: Persisted revoked by for the apitoken resource.
        enabled: Whether the resource is enabled.
        token_hash: Persisted token hash for the apitoken resource.
        signing_key_id: Identifier of the associated signing key.
        owner: Persisted owner for the apitoken resource.
    """
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
    """Represent audit event.

    Attributes:
        id: Unique database identifier for the resource.
        created_at: UTC timestamp when the resource was created.
        actor: Persisted actor for the auditevent resource.
        action: Persisted action for the auditevent resource.
        resource_type: Persisted resource type for the auditevent resource.
        resource_id: Identifier of the associated resource.
        success: Persisted success for the auditevent resource.
        detail: Persisted detail for the auditevent resource.
        request_id: Identifier of the associated request.
    """
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
    """Represent physical interface.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        mac_address: Persisted mac address for the physicalinterface resource.
        driver: Persisted driver for the physicalinterface resource.
        speed: Persisted speed for the physicalinterface resource.
        host_ip_cidr: Persisted host ip cidr for the physicalinterface resource.
        host_ipv6_cidr: Persisted host ipv6 cidr for the physicalinterface resource.
        host_mtu: Persisted host mtu for the physicalinterface resource.
        host_admin_state: Persisted host admin state for the physicalinterface resource.
        ip_cidr: Persisted ip cidr for the physicalinterface resource.
        gateway: Persisted gateway for the physicalinterface resource.
        ipv4_method: Persisted ipv4 method for the physicalinterface resource.
        ipv6_enabled: Whether ipv6 is enabled.
        ipv6_cidr: Persisted ipv6 cidr for the physicalinterface resource.
        ipv6_gateway: Persisted ipv6 gateway for the physicalinterface resource.
        mtu: Persisted mtu for the physicalinterface resource.
        admin_state: Persisted admin state for the physicalinterface resource.
        oper_state: Persisted oper state for the physicalinterface resource.
        role: Persisted role for the physicalinterface resource.
        mode: Persisted mode for the physicalinterface resource.
        inventory_source: Persisted inventory source for the physicalinterface resource.
        desired_state_source: Persisted desired state source for the physicalinterface resource.
        last_seen_at: UTC timestamp associated with last seen.
        missing_since: Persisted missing since for the physicalinterface resource.
    """
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
    """Represent vlan interface.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        parent_interface: Persisted parent interface for the vlaninterface resource.
        vlan_id: Identifier of the associated vlan.
        ip_cidr: Persisted ip cidr for the vlaninterface resource.
        ipv6_cidr: Persisted ipv6 cidr for the vlaninterface resource.
        mtu: Persisted mtu for the vlaninterface resource.
        role: Persisted role for the vlaninterface resource.
        enabled: Whether the resource is enabled.
    """
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
    """Represent wan policy.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        enabled: Whether the resource is enabled.
        latency_ms: Persisted latency ms for the wanpolicy resource.
        jitter_ms: Persisted jitter ms for the wanpolicy resource.
        packet_loss_percent: Packet loss expressed as a percentage.
        bandwidth_mbit: Persisted bandwidth mbit for the wanpolicy resource.
        corrupt_percent: Corrupt expressed as a percentage.
        duplicate_percent: Duplicate expressed as a percentage.
        reorder_percent: Reorder expressed as a percentage.
        routes: Persisted routes for the wanpolicy resource.
    """
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
    """Represent route.

    Attributes:
        id: Unique database identifier for the resource.
        destination_cidr: Persisted destination cidr for the route resource.
        gateway: Persisted gateway for the route resource.
        interface_name: Persisted interface name for the route resource.
        metric: Persisted metric for the route resource.
        enabled: Whether the resource is enabled.
        wan_policy_id: Identifier of the associated wan policy.
        wan_mode: Persisted wan mode for the route resource.
        wan_policy: Persisted wan policy for the route resource.
    """
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
    """Represent routing rule.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        enabled: Whether the resource is enabled.
        source_interface: Persisted source interface for the routingrule resource.
        destination_interface: Persisted destination interface for the routingrule resource.
        priority: Persisted priority for the routingrule resource.
        description: Operator-facing purpose or context for the resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent nat rule.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        enabled: Whether the resource is enabled.
        source: Persisted source for the natrule resource.
        outbound_interface: Persisted outbound interface for the natrule resource.
        masquerade: Persisted masquerade for the natrule resource.
        priority: Persisted priority for the natrule resource.
        description: Operator-facing purpose or context for the resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent service state.

    Attributes:
        id: Unique database identifier for the resource.
        service: Persisted service for the servicestate resource.
        display_name: Persisted display name for the servicestate resource.
        running: Persisted running for the servicestate resource.
        enabled: Whether the resource is enabled.
        health: Persisted health for the servicestate resource.
        detail: Persisted detail for the servicestate resource.
    """
    __tablename__ = "service_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    running: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    health: Mapped[str] = mapped_column(String(40), default="unknown")
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class MonitorSample(Base):
    """Represent monitor sample.

    Attributes:
        id: Unique database identifier for the resource.
        sampled_at: UTC timestamp associated with sampled.
        cpu_percent: Cpu expressed as a percentage.
        cpu_count: Number of cpu items.
        cpu_total_jiffies: Persisted cpu total jiffies for the monitorsample resource.
        cpu_idle_jiffies: Persisted cpu idle jiffies for the monitorsample resource.
        load1: Persisted load1 for the monitorsample resource.
        load5: Persisted load5 for the monitorsample resource.
        load15: Persisted load15 for the monitorsample resource.
        memory_total_bytes: Memory total size in bytes.
        memory_available_bytes: Memory available size in bytes.
        memory_used_percent: Memory used expressed as a percentage.
        swap_total_bytes: Swap total size in bytes.
        swap_used_bytes: Swap used size in bytes.
        cpu_samples: Persisted cpu samples for the monitorsample resource.
        network_samples: Persisted network samples for the monitorsample resource.
        disk_samples: Persisted disk samples for the monitorsample resource.
    """
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
    """Represent monitor cpu sample.

    Attributes:
        id: Unique database identifier for the resource.
        sample_id: Identifier of the associated sample.
        cpu_name: Persisted cpu name for the monitorcpusample resource.
        percent: Persisted percent for the monitorcpusample resource.
        total_jiffies: Persisted total jiffies for the monitorcpusample resource.
        idle_jiffies: Persisted idle jiffies for the monitorcpusample resource.
        sample: Persisted sample for the monitorcpusample resource.
    """
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
    """Represent monitor network sample.

    Attributes:
        id: Unique database identifier for the resource.
        sample_id: Identifier of the associated sample.
        interface_name: Persisted interface name for the monitornetworksample resource.
        rx_bytes: Rx size in bytes.
        tx_bytes: Tx size in bytes.
        rx_bytes_per_sec: Persisted rx bytes per sec for the monitornetworksample resource.
        tx_bytes_per_sec: Persisted tx bytes per sec for the monitornetworksample resource.
        rx_packets: Persisted rx packets for the monitornetworksample resource.
        tx_packets: Persisted tx packets for the monitornetworksample resource.
        rx_errors: Persisted rx errors for the monitornetworksample resource.
        tx_errors: Persisted tx errors for the monitornetworksample resource.
        rx_dropped: Persisted rx dropped for the monitornetworksample resource.
        tx_dropped: Persisted tx dropped for the monitornetworksample resource.
        oper_state: Persisted oper state for the monitornetworksample resource.
        sample: Persisted sample for the monitornetworksample resource.
    """
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
    """Represent monitor disk sample.

    Attributes:
        id: Unique database identifier for the resource.
        sample_id: Identifier of the associated sample.
        mount_point: Persisted mount point for the monitordisksample resource.
        device: Persisted device for the monitordisksample resource.
        filesystem: Persisted filesystem for the monitordisksample resource.
        total_bytes: Total size in bytes.
        used_bytes: Used size in bytes.
        free_bytes: Free size in bytes.
        used_percent: Used expressed as a percentage.
        read_bytes: Read size in bytes.
        write_bytes: Write size in bytes.
        read_bytes_per_sec: Persisted read bytes per sec for the monitordisksample resource.
        write_bytes_per_sec: Persisted write bytes per sec for the monitordisksample resource.
        sample: Persisted sample for the monitordisksample resource.
    """
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
    """Represent appliance settings.

    Attributes:
        id: Unique database identifier for the resource.
        fqdn: Persisted fqdn for the appliancesettings resource.
        management_https_enabled: Whether management https is enabled.
        web_terminal_enabled: Whether web terminal is enabled.
        web_terminal_interfaces_json: Serialized JSON representation of web terminal interfaces.
        root_ssh_enabled: Whether root ssh is enabled.
        vmware_ceip_enabled: Whether vmware ceip is enabled.
        service_dns_target_naming: Persisted service dns target naming for the appliancesettings
            resource.
        external_dns_servers: Persisted external dns servers for the appliancesettings resource.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "appliance_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fqdn: Mapped[str] = mapped_column(String(180), default="core.atlaso.internal")
    management_https_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    web_terminal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    web_terminal_interfaces_json: Mapped[str] = mapped_column(Text, default="[]")
    root_ssh_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    vmware_ceip_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    service_dns_target_naming: Mapped[str] = mapped_column(String(20), default="ip")
    external_dns_servers: Mapped[str] = mapped_column(Text, default="1.1.1.1\n9.9.9.9")
    config_path: Mapped[str] = mapped_column(String(240), default="/var/lib/atlaso/apply/appliance-settings/atlaso-settings.json")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NtpSettings(Base):
    """Represent ntp settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        hostname: Persisted hostname for the ntpsettings resource.
        listen_interface: Persisted listen interface for the ntpsettings resource.
        listen_address: Persisted listen address for the ntpsettings resource.
        port: Persisted port for the ntpsettings resource.
        upstream_servers: Persisted upstream servers for the ntpsettings resource.
        upstream_sources_json: Serialized JSON representation of upstream sources.
        allow_clients: Whether clients is permitted.
        nts_server_enabled: Whether nts server is enabled.
        nts_server_cert_path: Filesystem path used for nts server cert.
        nts_server_key_path: Filesystem path used for nts server key.
        nts_ke_port: Network port used for nts ke.
        minsources: Persisted minsources for the ntpsettings resource.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "ntp_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="ntp.atlaso.internal")
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
    config_path: Mapped[str] = mapped_column(String(240), default="/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FirewallSettings(Base):
    """Represent firewall settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        default_input_policy: Persisted default input policy for the firewallsettings resource.
        default_forward_policy: Persisted default forward policy for the firewallsettings resource.
        default_output_policy: Persisted default output policy for the firewallsettings resource.
        allow_established: Whether established is permitted.
        allow_loopback: Whether loopback is permitted.
        allow_icmp: Whether icmp is permitted.
        log_dropped: Persisted log dropped for the firewallsettings resource.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/nftables.d/atlaso.nft")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FirewallRule(Base):
    """Represent firewall rule.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        direction: Persisted direction for the firewallrule resource.
        action: Persisted action for the firewallrule resource.
        protocol: Persisted protocol for the firewallrule resource.
        source: Persisted source for the firewallrule resource.
        destination: Persisted destination for the firewallrule resource.
        destination_port: Network port used for destination.
        interface_name: Persisted interface name for the firewallrule resource.
        priority: Persisted priority for the firewallrule resource.
        enabled: Whether the resource is enabled.
        description: Operator-facing purpose or context for the resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent dns settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        listen_interface: Persisted listen interface for the dnssettings resource.
        listen_address: Persisted listen address for the dnssettings resource.
        domain: Persisted domain for the dnssettings resource.
        disabled_domains: Persisted disabled domains for the dnssettings resource.
        domain_descriptions_json: Serialized JSON representation of domain descriptions.
        upstream_servers: Persisted upstream servers for the dnssettings resource.
        cache_size: Persisted cache size for the dnssettings resource.
        expand_hosts: Persisted expand hosts for the dnssettings resource.
        authoritative: Persisted authoritative for the dnssettings resource.
        authoritative_server: Persisted authoritative server for the dnssettings resource.
        authoritative_contact: Persisted authoritative contact for the dnssettings resource.
        authoritative_ttl: Persisted authoritative ttl for the dnssettings resource.
        authoritative_serial: Persisted authoritative serial for the dnssettings resource.
        authoritative_refresh: Persisted authoritative refresh for the dnssettings resource.
        authoritative_retry: Persisted authoritative retry for the dnssettings resource.
        authoritative_expire: Persisted authoritative expire for the dnssettings resource.
        dnssec_enabled: Whether dnssec is enabled.
        rebind_protection_enabled: Whether rebind protection is enabled.
        rebind_domain_exemptions: Persisted rebind domain exemptions for the dnssettings resource.
        query_logging_mode: Persisted query logging mode for the dnssettings resource.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "dns_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    listen_interface: Mapped[str] = mapped_column(String(80), default="")
    listen_address: Mapped[str | None] = mapped_column(String(240), nullable=True)
    domain: Mapped[str] = mapped_column(String(500), default="atlaso.internal")
    disabled_domains: Mapped[str] = mapped_column(String(500), default="")
    domain_descriptions_json: Mapped[str] = mapped_column(Text, default="{}")
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
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/dnsmasq.d/atlaso.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DnsRecord(Base):
    """Represent dns record.

    Attributes:
        id: Unique database identifier for the resource.
        hostname: Persisted hostname for the dnsrecord resource.
        record_type: Persisted record type for the dnsrecord resource.
        address: Persisted address for the dnsrecord resource.
        record_data_json: Serialized JSON representation of record data.
        description: Operator-facing purpose or context for the resource.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
    """
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
    """Represent dhcp settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        interface_name: Persisted interface name for the dhcpsettings resource.
        site_address: Persisted site address for the dhcpsettings resource.
        prefix_length: Persisted prefix length for the dhcpsettings resource.
        lease_time: Persisted lease time for the dhcpsettings resource.
        domain_name: Persisted domain name for the dhcpsettings resource.
        dns_server: Persisted dns server for the dhcpsettings resource.
        authoritative: Persisted authoritative for the dhcpsettings resource.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "dhcp_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interface_name: Mapped[str] = mapped_column(String(80), default="")
    site_address: Mapped[str] = mapped_column(String(64), default="")
    prefix_length: Mapped[int] = mapped_column(Integer, default=24)
    lease_time: Mapped[str] = mapped_column(String(40), default="12h")
    domain_name: Mapped[str] = mapped_column(String(120), default="atlaso.internal")
    dns_server: Mapped[str] = mapped_column(String(64), default="")
    authoritative: Mapped[bool] = mapped_column(Boolean, default=True)
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/dnsmasq.d/atlaso.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DhcpScope(Base):
    """Represent dhcp scope.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        address_family: Persisted address family for the dhcpscope resource.
        interface_name: Persisted interface name for the dhcpscope resource.
        site_address: Persisted site address for the dhcpscope resource.
        prefix_length: Persisted prefix length for the dhcpscope resource.
        range_expression: Persisted range expression for the dhcpscope resource.
        lease_time: Persisted lease time for the dhcpscope resource.
        domain_name: Persisted domain name for the dhcpscope resource.
        dns_server: Persisted dns server for the dhcpscope resource.
        ntp_server: Persisted ntp server for the dhcpscope resource.
        enabled: Whether the resource is enabled.
        description: Operator-facing purpose or context for the resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "dhcp_scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    address_family: Mapped[str] = mapped_column(String(10), default="ipv4")
    interface_name: Mapped[str] = mapped_column(String(80), default="eth2")
    site_address: Mapped[str] = mapped_column(String(64), default="192.168.50.1")
    prefix_length: Mapped[int] = mapped_column(Integer, default=24)
    range_expression: Mapped[str] = mapped_column(String(500), default="192.168.50.100-192.168.50.200")
    lease_time: Mapped[str] = mapped_column(String(40), default="12h")
    domain_name: Mapped[str] = mapped_column(String(120), default="atlaso.internal")
    dns_server: Mapped[str] = mapped_column(String(64), default="192.168.50.1")
    ntp_server: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DhcpOption(Base):
    """Represent dhcp option.

    Attributes:
        id: Unique database identifier for the resource.
        scope_id: Identifier of the associated scope.
        option_code: Persisted option code for the dhcpoption resource.
        value: Persisted value for the dhcpoption resource.
        description: Operator-facing purpose or context for the resource.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent dhcp reservation.

    Attributes:
        id: Unique database identifier for the resource.
        hostname: Persisted hostname for the dhcpreservation resource.
        mac_address: Persisted mac address for the dhcpreservation resource.
        ip_address: Persisted ip address for the dhcpreservation resource.
        description: Operator-facing purpose or context for the resource.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
    """
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
    """Represent ca settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        portal_hostname: Persisted portal hostname for the casettings resource.
        root_common_name: Persisted root common name for the casettings resource.
        organization: Persisted organization for the casettings resource.
        organizational_unit: Persisted organizational unit for the casettings resource.
        country: Persisted country for the casettings resource.
        state: Current lifecycle state.
        locality: Persisted locality for the casettings resource.
        listen_interface: Persisted listen interface for the casettings resource.
        listen_address: Persisted listen address for the casettings resource.
        key_algorithm: Persisted key algorithm for the casettings resource.
        key_size: Persisted key size for the casettings resource.
        digest_algorithm: Persisted digest algorithm for the casettings resource.
        root_valid_days: Root valid duration in days.
        intermediate_valid_days: Intermediate valid duration in days.
        publish_crl: Persisted publish crl for the casettings resource.
        ocsp_enabled: Whether ocsp is enabled.
        storage_path: Filesystem path used for storage.
        root_certificate_pem: Persisted root certificate pem for the casettings resource.
        root_private_key_encrypted: Persisted root private key encrypted for the casettings
            resource.
        root_serial_number: Persisted root serial number for the casettings resource.
        root_fingerprint: Persisted root fingerprint for the casettings resource.
        root_issued_at: UTC timestamp associated with root issued.
        root_expires_at: UTC timestamp associated with root expires.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "ca_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_hostname: Mapped[str] = mapped_column(String(180), default="ca.atlaso.internal")
    root_common_name: Mapped[str] = mapped_column(String(180), default="Atlaso Internal Root CA")
    organization: Mapped[str] = mapped_column(String(180), default="Atlaso")
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
    storage_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/ca")
    root_certificate_pem: Mapped[str] = mapped_column(Text, default="")
    root_private_key_encrypted: Mapped[str] = mapped_column(Text, default="")
    root_serial_number: Mapped[str] = mapped_column(String(120), default="")
    root_fingerprint: Mapped[str] = mapped_column(String(128), default="")
    root_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    root_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CaProfile(Base):
    """Represent ca profile.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        certificate_type: Persisted certificate type for the caprofile resource.
        validity_days: Validity duration in days.
        key_algorithm: Persisted key algorithm for the caprofile resource.
        key_size: Persisted key size for the caprofile resource.
        key_usage: Persisted key usage for the caprofile resource.
        extended_key_usage: Persisted extended key usage for the caprofile resource.
        san_required: Persisted san required for the caprofile resource.
        enabled: Whether the resource is enabled.
        description: Operator-facing purpose or context for the resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        certificates: Persisted certificates for the caprofile resource.
    """
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
    """Represent ca certificate.

    Attributes:
        id: Unique database identifier for the resource.
        common_name: Persisted common name for the cacertificate resource.
        profile_id: Identifier of the associated profile.
        subject_alt_names: Persisted subject alt names for the cacertificate resource.
        ip_addresses: Persisted ip addresses for the cacertificate resource.
        status: Current lifecycle or operation status.
        serial_number: Persisted serial number for the cacertificate resource.
        certificate_pem: Persisted certificate pem for the cacertificate resource.
        private_key_encrypted: Persisted private key encrypted for the cacertificate resource.
        chain_pem: Persisted chain pem for the cacertificate resource.
        issuer_common_name: Persisted issuer common name for the cacertificate resource.
        fingerprint: Persisted fingerprint for the cacertificate resource.
        managed_owner: Persisted managed owner for the cacertificate resource.
        cert_path: Filesystem path used for cert.
        key_path: Filesystem path used for key.
        chain_path: Filesystem path used for chain.
        csr_text: Persisted csr text for the cacertificate resource.
        description: Operator-facing purpose or context for the resource.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        issued_at: UTC timestamp associated with issued.
        expires_at: UTC timestamp after which the resource is no longer valid.
        revoked_at: UTC timestamp associated with revoked.
        revoked_by: Persisted revoked by for the cacertificate resource.
        revocation_reason: Persisted revocation reason for the cacertificate resource.
        profile: Persisted profile for the cacertificate resource.
    """
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
    """Represent kms settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        backend: Persisted backend for the kmssettings resource.
        provider_id: Identifier of the associated provider.
        listen_interface: Persisted listen interface for the kmssettings resource.
        listen_address: Persisted listen address for the kmssettings resource.
        port: Persisted port for the kmssettings resource.
        hostname: Persisted hostname for the kmssettings resource.
        server_certificate: Persisted server certificate for the kmssettings resource.
        ca_certificate_path: Filesystem path used for ca certificate.
        database_path: Filesystem path used for database.
        config_path: Filesystem path used for config.
        require_client_cert: Persisted require client cert for the kmssettings resource.
        allow_register: Whether register is permitted.
        allow_destroy: Whether destroy is permitted.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "kms_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    backend: Mapped[str] = mapped_column(String(40), default="atlaso-kmip")
    provider_id: Mapped[str] = mapped_column(String(36), default=lambda: str(uuid4()), unique=True)
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=5696)
    hostname: Mapped[str] = mapped_column(String(180), default="kms.atlaso.internal")
    server_certificate: Mapped[str] = mapped_column(String(180), default="kms.atlaso.internal")
    ca_certificate_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/ca/root.crt")
    database_path: Mapped[str] = mapped_column(String(240), default="/var/lib/atlaso/kmip/store.db")
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/kmip/server.json")
    require_client_cert: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_register: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_destroy: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KmsClient(Base):
    """Represent kms client.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        certificate_subject: Persisted certificate subject for the kmsclient resource.
        certificate_fingerprint: Persisted certificate fingerprint for the kmsclient resource.
        role: Persisted role for the kmsclient resource.
        allowed_operations: Persisted allowed operations for the kmsclient resource.
        enabled: Whether the resource is enabled.
        description: Operator-facing purpose or context for the resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        keys: Persisted keys for the kmsclient resource.
    """
    __tablename__ = "kms_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    certificate_subject: Mapped[str] = mapped_column(String(240))
    certificate_fingerprint: Mapped[str] = mapped_column(Text, default="")
    role: Mapped[str] = mapped_column(String(40), default="service")
    allowed_operations: Mapped[str] = mapped_column(
        Text,
        default="locate,get,create,activate,get-attributes,get-attribute-list,query,discover-versions",
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    keys: Mapped[list["KmsKey"]] = relationship(back_populates="owner_client")


class KmsKey(Base):
    """Represent kms key.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        algorithm: Persisted algorithm for the kmskey resource.
        length: Persisted length for the kmskey resource.
        usage: Persisted usage for the kmskey resource.
        state: Current lifecycle state.
        owner_client_id: Identifier of the associated owner client.
        exportable: Persisted exportable for the kmskey resource.
        enabled: Whether the resource is enabled.
        description: Operator-facing purpose or context for the resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        owner_client: Persisted owner client for the kmskey resource.
    """
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
    """Represent ldap settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        hostname: Persisted hostname for the ldapsettings resource.
        listen_interface: Persisted listen interface for the ldapsettings resource.
        listen_address: Persisted listen address for the ldapsettings resource.
        ldaps_enabled: Whether ldaps is enabled.
        port: Persisted port for the ldapsettings resource.
        ldap_enabled: Whether ldap is enabled.
        ldap_port: Network port used for ldap.
        min_password_length: Minimum required password length.
        require_uppercase: Persisted require uppercase for the ldapsettings resource.
        require_lowercase: Persisted require lowercase for the ldapsettings resource.
        require_number: Persisted require number for the ldapsettings resource.
        require_special: Persisted require special for the ldapsettings resource.
        disallow_username: Persisted disallow username for the ldapsettings resource.
        max_failures: Maximum accepted failures.
        lockout_minutes: Lockout duration in minutes.
        failure_window_minutes: Failure window duration in minutes.
        password_history: Persisted password history for the ldapsettings resource.
        password_max_age_days: Password max age duration in days.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "ldap_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="ldap.atlaso.internal")
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
        default="/var/lib/atlaso/apply/ldap/atlaso-ldap.json",
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LdapOrganization(Base):
    """Represent ldap organization.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        slug: Persisted slug for the ldaporganization resource.
        suffix_dn: Persisted suffix dn for the ldaporganization resource.
        bind_dn: Persisted bind dn for the ldaporganization resource.
        bind_password_encrypted: Persisted bind password encrypted for the ldaporganization
            resource.
        enabled: Whether the resource is enabled.
        vcf_target_url: URL used for vcf target.
        vcf_org_id: Identifier of the associated vcf org.
        vcf_org_name: Persisted vcf org name for the ldaporganization resource.
        vcf_tls_fingerprint: Persisted vcf tls fingerprint for the ldaporganization resource.
        vcf_last_status: Persisted vcf last status for the ldaporganization resource.
        vcf_last_message: Persisted vcf last message for the ldaporganization resource.
        vcf_last_verified_at: UTC timestamp associated with vcf last verified.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        users: Persisted users for the ldaporganization resource.
        groups: Persisted groups for the ldaporganization resource.
    """
    __tablename__ = "ldap_organizations"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_ldap_organization_slug"),
        UniqueConstraint("suffix_dn", name="uq_ldap_organization_suffix"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
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
    """Represent ldap user.

    Attributes:
        id: Unique database identifier for the resource.
        organization_id: Identifier of the associated organization.
        uid: Persisted uid for the ldapuser resource.
        given_name: Persisted given name for the ldapuser resource.
        surname: Persisted surname for the ldapuser resource.
        display_name: Persisted display name for the ldapuser resource.
        email: Persisted email for the ldapuser resource.
        telephone: Persisted telephone for the ldapuser resource.
        enabled: Whether the resource is enabled.
        password_applied_at: UTC timestamp associated with password applied.
        password_status: Persisted password status for the ldapuser resource.
        unlock_requested_at: UTC timestamp associated with unlock requested.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        organization: Persisted organization for the ldapuser resource.
        memberships: Persisted memberships for the ldapuser resource.
    """
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
    """Represent ldap group.

    Attributes:
        id: Unique database identifier for the resource.
        organization_id: Identifier of the associated organization.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        organization: Persisted organization for the ldapgroup resource.
        members: Persisted members for the ldapgroup resource.
        parent_memberships: Persisted parent memberships for the ldapgroup resource.
    """
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
    """Represent ldap group membership.

    Attributes:
        id: Unique database identifier for the resource.
        group_id: Identifier of the associated group.
        member_user_id: Identifier of the associated member user.
        member_group_id: Identifier of the associated member group.
        created_at: UTC timestamp when the resource was created.
        group: Persisted group for the ldapgroupmembership resource.
        member_user: Persisted member user for the ldapgroupmembership resource.
        member_group: Persisted member group for the ldapgroupmembership resource.
    """
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
    """Represent oidc provider settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        hostname: Persisted hostname for the oidcprovidersettings resource.
        listen_interface: Persisted listen interface for the oidcprovidersettings resource.
        listen_address: Persisted listen address for the oidcprovidersettings resource.
        port: Persisted port for the oidcprovidersettings resource.
        issuer_url: URL used for issuer.
        access_token_lifetime_seconds: Access token lifetime duration in seconds.
        id_token_lifetime_seconds: Id token lifetime duration in seconds.
        authorization_code_lifetime_seconds: Authorization code lifetime duration in seconds.
        clock_skew_seconds: Clock skew duration in seconds.
        signing_key_overlap_seconds: Signing key overlap duration in seconds.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "oidc_provider_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="oidc.atlaso.internal")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    issuer_url: Mapped[str] = mapped_column(String(500), default="https://oidc.atlaso.internal/identity")
    access_token_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=300)
    id_token_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=300)
    authorization_code_lifetime_seconds: Mapped[int] = mapped_column(Integer, default=60)
    clock_skew_seconds: Mapped[int] = mapped_column(Integer, default=120)
    signing_key_overlap_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OidcClient(Base):
    """Represent oidc client.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        client_id: Identifier of the associated client.
        client_secret_hash: Persisted client secret hash for the oidcclient resource.
        organization_id: Identifier of the associated organization.
        allowed_scopes: Persisted allowed scopes for the oidcclient resource.
        token_endpoint_auth_method: Persisted token endpoint auth method for the oidcclient
            resource.
        access_token_lifetime_seconds: Access token lifetime duration in seconds.
        id_token_lifetime_seconds: Id token lifetime duration in seconds.
        authorization_code_lifetime_seconds: Authorization code lifetime duration in seconds.
        allow_loopback_redirects: Whether loopback redirects is permitted.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        organization: Persisted organization for the oidcclient resource.
        redirect_uris: Persisted redirect uris for the oidcclient resource.
    """
    __tablename__ = "oidc_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
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
    """Represent oidc client redirect uri.

    Attributes:
        id: Unique database identifier for the resource.
        oidc_client_id: Identifier of the associated oidc client.
        kind: Persisted kind for the oidcclientredirecturi resource.
        uri: Persisted uri for the oidcclientredirecturi resource.
        created_at: UTC timestamp when the resource was created.
        client: Persisted client for the oidcclientredirecturi resource.
    """
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


class OidcGroupMapping(Base):
    """Represent oidc group mapping.

    Attributes:
        id: Unique database identifier for the resource.
        mapping_key: Persisted mapping key for the oidcgroupmapping resource.
        source_type: Persisted source type for the oidcgroupmapping resource.
        local_role: Persisted local role for the oidcgroupmapping resource.
        ldap_group_id: Identifier of the associated ldap group.
        organization_id: Identifier of the associated organization.
        oidc_client_id: Identifier of the associated oidc client.
        external_group_name: Persisted external group name for the oidcgroupmapping resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        ldap_group: Persisted ldap group for the oidcgroupmapping resource.
        organization: Persisted organization for the oidcgroupmapping resource.
        client: Persisted client for the oidcgroupmapping resource.
    """
    __tablename__ = "oidc_group_mappings"
    __table_args__ = (
        CheckConstraint(
            "(source_type = 'local_role' AND local_role <> '' "
            "AND ldap_group_id IS NULL AND organization_id IS NULL) OR "
            "(source_type = 'ldap_group' AND local_role = '' "
            "AND ldap_group_id IS NOT NULL AND organization_id IS NOT NULL)",
            name="ck_oidc_group_mapping_source",
        ),
        UniqueConstraint("mapping_key", name="uq_oidc_group_mapping_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mapping_key: Mapped[str] = mapped_column(String(240), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    local_role: Mapped[str] = mapped_column(String(50), default="")
    ldap_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("ldap_groups.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ldap_organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    oidc_client_id: Mapped[int | None] = mapped_column(
        ForeignKey("oidc_clients.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    external_group_name: Mapped[str] = mapped_column(String(160))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    ldap_group: Mapped[LdapGroup | None] = relationship()
    organization: Mapped[LdapOrganization | None] = relationship()
    client: Mapped[OidcClient | None] = relationship()


class OidcSubject(Base):
    """Represent oidc subject.

    Attributes:
        id: Unique database identifier for the resource.
        subject_uuid: Persisted subject uuid for the oidcsubject resource.
        local_user_id: Identifier of the associated local user.
        ldap_user_id: Identifier of the associated ldap user.
        created_at: UTC timestamp when the resource was created.
    """
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
    """Represent oidc signing key.

    Attributes:
        id: Unique database identifier for the resource.
        kid: Persisted kid for the oidcsigningkey resource.
        algorithm: Persisted algorithm for the oidcsigningkey resource.
        private_key_encrypted: Persisted private key encrypted for the oidcsigningkey resource.
        public_jwk_json: Serialized JSON representation of public jwk.
        status: Current lifecycle or operation status.
        active_slot: Persisted active slot for the oidcsigningkey resource.
        created_at: UTC timestamp when the resource was created.
        activated_at: UTC timestamp associated with activated.
        retired_at: UTC timestamp associated with retired.
        publish_until: Persisted publish until for the oidcsigningkey resource.
    """
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


class OidcAuthorizationTransaction(Base):
    """A short-lived, server-side binding for one browser authorization request.

    Attributes:
        id: Unique database identifier for the resource.
        transaction_id: Identifier of the associated transaction.
        oidc_client_id: Identifier of the associated oidc client.
        subject_id: Identifier of the associated subject.
        organization_id: Identifier of the associated organization.
        source: Persisted source for the oidcauthorizationtransaction resource.
        redirect_uri: URI used for redirect.
        scopes: Persisted scopes for the oidcauthorizationtransaction resource.
        state: Current lifecycle state.
        nonce: Persisted nonce for the oidcauthorizationtransaction resource.
        code_challenge: Persisted code challenge for the oidcauthorizationtransaction resource.
        browser_session_id: Identifier of the associated browser session.
        auth_time: Persisted auth time for the oidcauthorizationtransaction resource.
        prompt: Persisted prompt for the oidcauthorizationtransaction resource.
        max_age: Maximum accepted age.
        login_hint: Persisted login hint for the oidcauthorizationtransaction resource.
        expires_at: UTC timestamp after which the resource is no longer valid.
        created_at: UTC timestamp when the resource was created.
    """

    __tablename__ = "oidc_authorization_transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    transaction_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    oidc_client_id: Mapped[int] = mapped_column(ForeignKey("oidc_clients.id", ondelete="CASCADE"), index=True)
    subject_id: Mapped[int | None] = mapped_column(
        ForeignKey("oidc_subjects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ldap_organizations.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    source: Mapped[str] = mapped_column(String(32), default="")
    redirect_uri: Mapped[str] = mapped_column(Text)
    scopes: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(Text)
    code_challenge: Mapped[str] = mapped_column(String(160))
    browser_session_id: Mapped[str] = mapped_column(String(128), index=True)
    auth_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    prompt: Mapped[str] = mapped_column(String(16), default="login")
    max_age: Mapped[int | None] = mapped_column(Integer, nullable=True)
    login_hint: Mapped[str] = mapped_column(String(240), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OidcAuthorizationCode(Base):
    """A one-use code.  Only its SHA-256 digest is persisted.

    Attributes:
        id: Unique database identifier for the resource.
        code_hash: Persisted code hash for the oidcauthorizationcode resource.
        oidc_client_id: Identifier of the associated oidc client.
        subject_id: Identifier of the associated subject.
        organization_id: Identifier of the associated organization.
        redirect_uri: URI used for redirect.
        scopes: Persisted scopes for the oidcauthorizationcode resource.
        state: Current lifecycle state.
        nonce: Persisted nonce for the oidcauthorizationcode resource.
        code_challenge: Persisted code challenge for the oidcauthorizationcode resource.
        browser_session_id: Identifier of the associated browser session.
        source: Persisted source for the oidcauthorizationcode resource.
        auth_time: Persisted auth time for the oidcauthorizationcode resource.
        expires_at: UTC timestamp after which the resource is no longer valid.
        redeemed_at: UTC timestamp associated with redeemed.
        created_at: UTC timestamp when the resource was created.
    """

    __tablename__ = "oidc_authorization_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    oidc_client_id: Mapped[int] = mapped_column(ForeignKey("oidc_clients.id", ondelete="CASCADE"), index=True)
    subject_id: Mapped[int] = mapped_column(ForeignKey("oidc_subjects.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("ldap_organizations.id", ondelete="RESTRICT"), nullable=True)
    redirect_uri: Mapped[str] = mapped_column(Text)
    scopes: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(Text)
    code_challenge: Mapped[str] = mapped_column(String(160))
    browser_session_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32))
    auth_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LdapRecoveryArchive(Base):
    """Represent ldap recovery archive.

    Attributes:
        id: Unique database identifier for the resource.
        filename: Persisted filename for the ldaprecoveryarchive resource.
        path: Persisted path for the ldaprecoveryarchive resource.
        sha256: Persisted sha256 for the ldaprecoveryarchive resource.
        state: Current lifecycle state.
        organization_count: Number of organization items.
        created_by: Persisted created by for the ldaprecoveryarchive resource.
        created_at: UTC timestamp when the resource was created.
        applied_at: UTC timestamp associated with applied.
    """
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
    """Represent vcf backup settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        listen_interface: Persisted listen interface for the vcfbackupsettings resource.
        listen_address: Persisted listen address for the vcfbackupsettings resource.
        port: Persisted port for the vcfbackupsettings resource.
        sftp_user_id: Identifier of the associated sftp user.
        storage_path: Filesystem path used for storage.
        chroot_enabled: Whether chroot is enabled.
        allow_password_auth: Whether password auth is permitted.
        allow_public_key_auth: Whether public key auth is permitted.
        max_sessions: Maximum accepted sessions.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
        sftp_user: Persisted sftp user for the vcfbackupsettings resource.
    """
    __tablename__ = "vcf_backup_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=22)
    sftp_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    storage_path: Mapped[str] = mapped_column(String(240), default="/mnt/atlaso-vcf-backups")
    chroot_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_password_auth: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_public_key_auth: Mapped[bool] = mapped_column(Boolean, default=True)
    max_sessions: Mapped[int] = mapped_column(Integer, default=4)
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/ssh/atlaso-vcf-backups-sshd.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sftp_user: Mapped[User | None] = relationship()


class EsxStorageSettings(Base):
    """Represent esx storage settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        hostname: Persisted hostname for the esxstoragesettings resource.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "esx_storage_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(253), default="nfs.atlaso.internal")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EsxStorageVolume(Base):
    """Represent esx storage volume.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        source_type: Persisted source type for the esxstoragevolume resource.
        stable_device_id: Identifier of the associated stable device.
        device_path: Filesystem path used for device.
        device_model: Persisted device model for the esxstoragevolume resource.
        device_serial: Persisted device serial for the esxstoragevolume resource.
        device_wwn: Persisted device wwn for the esxstoragevolume resource.
        capacity_bytes: Capacity size in bytes.
        filesystem_uuid: Persisted filesystem uuid for the esxstoragevolume resource.
        filesystem_label: Persisted filesystem label for the esxstoragevolume resource.
        mount_path: Filesystem path used for mount.
        state: Current lifecycle state.
        applied: Persisted applied for the esxstoragevolume resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        shares: Persisted shares for the esxstoragevolume resource.
    """
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
    """Represent esx nfs share.

    Attributes:
        id: Unique database identifier for the resource.
        datastore_name: Persisted datastore name for the esxnfsshare resource.
        volume_id: Identifier of the associated volume.
        relative_path: Filesystem path used for relative.
        preferred_nfs_version: Persisted preferred nfs version for the esxnfsshare resource.
        interface_name: Persisted interface name for the esxnfsshare resource.
        address_families: Persisted address families for the esxnfsshare resource.
        ipv4_clients: Persisted ipv4 clients for the esxnfsshare resource.
        ipv6_clients: Persisted ipv6 clients for the esxnfsshare resource.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        volume: Persisted volume for the esxnfsshare resource.
    """
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
    """Represent vcf trust target.

    Attributes:
        id: Unique database identifier for the resource.
        address: Persisted address for the vcftrusttarget resource.
        ssh_port: Network port used for ssh.
        api_port: Network port used for api.
        appliance_role: Persisted appliance role for the vcftrusttarget resource.
        appliance_version: Persisted appliance version for the vcftrusttarget resource.
        ssh_host_key_fingerprint: Persisted ssh host key fingerprint for the vcftrusttarget
            resource.
        tls_fingerprint: Persisted tls fingerprint for the vcftrusttarget resource.
        last_ca_fingerprint: Persisted last ca fingerprint for the vcftrusttarget resource.
        last_result: Persisted last result for the vcftrusttarget resource.
        last_job_id: Identifier of the associated last job.
        last_attempted_at: UTC timestamp associated with last attempted.
        last_succeeded_at: UTC timestamp associated with last succeeded.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent vcf private registry settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        hostname: Persisted hostname for the vcfprivateregistrysettings resource.
        listen_interface: Persisted listen interface for the vcfprivateregistrysettings resource.
        listen_address: Persisted listen address for the vcfprivateregistrysettings resource.
        port: Persisted port for the vcfprivateregistrysettings resource.
        harbor_project: Persisted harbor project for the vcfprivateregistrysettings resource.
        storage_path: Filesystem path used for storage.
        config_path: Filesystem path used for config.
        ca_bundle_path: Filesystem path used for ca bundle.
        server_certificate: Persisted server certificate for the vcfprivateregistrysettings
            resource.
        robot_account: Persisted robot account for the vcfprivateregistrysettings resource.
        relocation_dry_run: Persisted relocation dry run for the vcfprivateregistrysettings
            resource.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "vcf_private_registry_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="registry.atlaso.internal")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    harbor_project: Mapped[str] = mapped_column(String(120), default="vcf-supervisor-services")
    storage_path: Mapped[str] = mapped_column(String(240), default="/mnt/atlaso-vcf-registry")
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/harbor/harbor.yml")
    ca_bundle_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/ca/ca-bundle.pem")
    server_certificate: Mapped[str] = mapped_column(String(180), default="registry.atlaso.internal")
    robot_account: Mapped[str] = mapped_column(String(120), default="robot$vcf-supervisor-services")
    relocation_dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VcfOfflineDepotSettings(Base):
    """Represent vcf offline depot settings.

    Attributes:
        id: Unique database identifier for the resource.
        enabled: Whether the resource is enabled.
        hostname: Persisted hostname for the vcfofflinedepotsettings resource.
        listen_interface: Persisted listen interface for the vcfofflinedepotsettings resource.
        listen_address: Persisted listen address for the vcfofflinedepotsettings resource.
        port: Persisted port for the vcfofflinedepotsettings resource.
        http_user_id: Identifier of the associated http user.
        allow_unauthenticated_access: Whether unauthenticated access is permitted.
        server_certificate: Persisted server certificate for the vcfofflinedepotsettings resource.
        depot_store_path: Filesystem path used for depot store.
        tool_archive_path: Filesystem path used for tool archive.
        tool_version: Persisted tool version for the vcfofflinedepotsettings resource.
        config_path: Filesystem path used for config.
        updated_at: UTC timestamp when the resource was last updated.
        http_user: Persisted http user for the vcfofflinedepotsettings resource.
    """
    __tablename__ = "vcf_offline_depot_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname: Mapped[str] = mapped_column(String(180), default="depot.atlaso.internal")
    listen_interface: Mapped[str] = mapped_column(String(240), default="")
    listen_address: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    http_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    allow_unauthenticated_access: Mapped[bool] = mapped_column(Boolean, default=False)
    server_certificate: Mapped[str] = mapped_column(String(180), default="depot.atlaso.internal")
    depot_store_path: Mapped[str] = mapped_column(String(240), default="/mnt/atlaso-vcf-offline-depot")
    tool_archive_path: Mapped[str] = mapped_column(String(500), default="")
    tool_version: Mapped[str] = mapped_column(String(80), default="")
    config_path: Mapped[str] = mapped_column(String(240), default="/etc/atlaso/nginx/sites.d/vcf-offline-depot.conf")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    http_user: Mapped[User | None] = relationship()


class VcfDepotDownloadProfile(Base):
    """Represent vcf depot download profile.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        profile_type: Persisted profile type for the vcfdepotdownloadprofile resource.
        sku: Persisted sku for the vcfdepotdownloadprofile resource.
        vcf_version: Persisted vcf version for the vcfdepotdownloadprofile resource.
        binary_type: Persisted binary type for the vcfdepotdownloadprofile resource.
        automated_install: Persisted automated install for the vcfdepotdownloadprofile resource.
        upgrades_only: Persisted upgrades only for the vcfdepotdownloadprofile resource.
        patches_only: Persisted patches only for the vcfdepotdownloadprofile resource.
        component: Persisted component for the vcfdepotdownloadprofile resource.
        component_version: Persisted component version for the vcfdepotdownloadprofile resource.
        disabled_platforms: Persisted disabled platforms for the vcfdepotdownloadprofile resource.
        enabled: Whether the resource is enabled.
        status: Current lifecycle or operation status.
        notes: Persisted notes for the vcfdepotdownloadprofile resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent update source.

    Attributes:
        id: Unique database identifier for the resource.
        kind: Persisted kind for the updatesource resource.
        name: Operator-facing name of the resource.
        url: Persisted url for the updatesource resource.
        enabled: Whether the resource is enabled.
        priority: Persisted priority for the updatesource resource.
        settings_json: Serialized JSON representation of settings.
        credential_encrypted: Persisted credential encrypted for the updatesource resource.
        validation_status: Persisted validation status for the updatesource resource.
        validation_message: Persisted validation message for the updatesource resource.
        validated_at: UTC timestamp associated with validated.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent managed package.

    Attributes:
        id: Unique database identifier for the resource.
        ecosystem: Persisted ecosystem for the managedpackage resource.
        name: Operator-facing name of the resource.
        source_id: Identifier of the associated source.
        policy: Persisted policy for the managedpackage resource.
        target_version: Persisted target version for the managedpackage resource.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        source: Persisted source for the managedpackage resource.
    """
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
    """Represent automation script.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        created_by: Persisted created by for the automationscript resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        revisions: Persisted revisions for the automationscript resource.
    """
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
    """Represent automation script revision.

    Attributes:
        id: Unique database identifier for the resource.
        script_id: Identifier of the associated script.
        revision: Persisted revision for the automationscriptrevision resource.
        interpreter: Persisted interpreter for the automationscriptrevision resource.
        content: Persisted content for the automationscriptrevision resource.
        content_sha256: Persisted content sha256 for the automationscriptrevision resource.
        enabled: Whether the resource is enabled.
        timeout_seconds: Timeout duration in seconds.
        created_by: Persisted created by for the automationscriptrevision resource.
        created_at: UTC timestamp when the resource was created.
        script: Persisted script for the automationscriptrevision resource.
    """
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
    """Represent schedule.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        task_type: Persisted task type for the schedule resource.
        task_config_json: Serialized JSON representation of task config.
        schedule_kind: Persisted schedule kind for the schedule resource.
        cron_expression: Persisted cron expression for the schedule resource.
        run_once_at: UTC timestamp associated with run once.
        timezone_name: Persisted timezone name for the schedule resource.
        enabled: Whether the resource is enabled.
        next_run_at: UTC timestamp associated with next run.
        last_run_at: UTC timestamp associated with last run.
        last_job_id: Identifier of the associated last job.
        created_by: Persisted created by for the schedule resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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
    """Represent vcf registry bundle.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        source_reference: Persisted source reference for the vcfregistrybundle resource.
        target_reference: Persisted target reference for the vcfregistrybundle resource.
        enabled: Whether the resource is enabled.
        status: Current lifecycle or operation status.
        notes: Persisted notes for the vcfregistrybundle resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
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


class Vault(Base):
    """Represent vault.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        created_by: Persisted created by for the vault resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        entries: Persisted entries for the vault resource.
    """
    __tablename__ = "vaults"
    __table_args__ = (UniqueConstraint("name", name="uq_vault_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    entries: Mapped[list["VaultEntry"]] = relationship(
        back_populates="vault",
        cascade="all, delete-orphan",
        order_by="VaultEntry.key",
    )


class VaultEntry(Base):
    """Represent vault entry.

    Attributes:
        id: Unique database identifier for the resource.
        vault_id: Identifier of the associated vault.
        key: Persisted key for the vaultentry resource.
        description: Operator-facing purpose or context for the resource.
        secret_type: Persisted secret type for the vaultentry resource.
        username: Persisted username for the vaultentry resource.
        resource_name: Persisted resource name for the vaultentry resource.
        source_type: Persisted source type for the vaultentry resource.
        source_endpoint: Persisted source endpoint for the vaultentry resource.
        uris_json: Serialized JSON representation of uris.
        encrypted_value: Persisted encrypted value for the vaultentry resource.
        created_by: Persisted created by for the vaultentry resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        imported_at: UTC timestamp associated with imported.
        vault: Persisted vault for the vaultentry resource.
    """
    __tablename__ = "vault_entries"
    __table_args__ = (
        UniqueConstraint("vault_id", "key", name="uq_vault_entry_vault_key"),
        CheckConstraint(
            "secret_type IN ('vcf_password', 'esx_password')",
            name="ck_vault_entry_secret_type",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vault_id: Mapped[int] = mapped_column(ForeignKey("vaults.id"), index=True)
    key: Mapped[str] = mapped_column(String(180), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    secret_type: Mapped[str] = mapped_column(String(40))
    username: Mapped[str] = mapped_column(String(180), default="")
    resource_name: Mapped[str] = mapped_column(String(240), default="")
    source_type: Mapped[str] = mapped_column(String(40), default="manual")
    source_endpoint: Mapped[str] = mapped_column(String(500), default="")
    uris_json: Mapped[str] = mapped_column(Text, default="[]")
    encrypted_value: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    vault: Mapped[Vault] = relationship(back_populates="entries")


class EsxiKickstart(Base):
    """Represent esxi kickstart.

    Attributes:
        id: Unique database identifier for the resource.
        name: Operator-facing name of the resource.
        description: Operator-facing purpose or context for the resource.
        content: Persisted content for the esxikickstart resource.
        content_hash: Persisted content hash for the esxikickstart resource.
        rendered_content: Persisted rendered content for the esxikickstart resource.
        rendered_hash: Persisted rendered hash for the esxikickstart resource.
        http_path: Filesystem path used for http.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        last_rendered_at: UTC timestamp associated with last rendered.
        last_applied_at: UTC timestamp associated with last applied.
    """
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


class EsxiKickstartVaultBinding(Base):
    """Represent esxi kickstart vault binding.

    Attributes:
        kickstart_id: Identifier of the associated kickstart.
        vault_id: Identifier of the associated vault.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "esxi_kickstart_vault_bindings"

    kickstart_id: Mapped[int] = mapped_column(
        ForeignKey("esxi_kickstarts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    vault_id: Mapped[int] = mapped_column(ForeignKey("vaults.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EsxiPxeHost(Base):
    """Represent esxi pxe host.

    Attributes:
        id: Unique database identifier for the resource.
        hostname: Persisted hostname for the esxipxehost resource.
        mac_address: Persisted mac address for the esxipxehost resource.
        ip_address: Persisted ip address for the esxipxehost resource.
        kickstart_id: Identifier of the associated kickstart.
        installer_iso_path: Filesystem path used for installer iso.
        variables_json: Serialized JSON representation of variables.
        enabled: Whether the resource is enabled.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        kickstart: Persisted kickstart for the esxipxehost resource.
    """
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


class NetworkBootEnvironment(Base):
    """Represent network boot environment.

    Attributes:
        key: Persisted key for the networkbootenvironment resource.
        enabled: Whether the resource is enabled.
        desired_version: Persisted desired version for the networkbootenvironment resource.
        active_version: Persisted active version for the networkbootenvironment resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "network_boot_environments"

    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    desired_version: Mapped[str] = mapped_column(String(120), default="")
    active_version: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NetworkBootMedia(Base):
    """Represent network boot media.

    Attributes:
        id: Unique database identifier for the resource.
        environment_key: Persisted environment key for the networkbootmedia resource.
        version: Persisted version for the networkbootmedia resource.
        source_url: URL used for source.
        license_name: Persisted license name for the networkbootmedia resource.
        artifact_sha256: Persisted artifact sha256 for the networkbootmedia resource.
        verification_method: Persisted verification method for the networkbootmedia resource.
        installed_path: Filesystem path used for installed.
        manifest_json: Serialized JSON representation of manifest.
        verified_at: UTC timestamp associated with verified.
        installed_at: UTC timestamp associated with installed.
    """
    __tablename__ = "network_boot_media"
    __table_args__ = (
        UniqueConstraint("environment_key", "version", name="uq_network_boot_media_environment_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    environment_key: Mapped[str] = mapped_column(
        ForeignKey("network_boot_environments.key", ondelete="CASCADE"),
        index=True,
    )
    version: Mapped[str] = mapped_column(String(120))
    source_url: Mapped[str] = mapped_column(String(1000))
    license_name: Mapped[str] = mapped_column(String(160), default="")
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    verification_method: Mapped[str] = mapped_column(String(240))
    installed_path: Mapped[str] = mapped_column(String(1000))
    manifest_json: Mapped[str] = mapped_column(Text, default="{}")
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NetworkBootDiscoveredHost(Base):
    """Represent network boot discovered host.

    Attributes:
        id: Unique database identifier for the resource.
        identity_key: Persisted identity key for the networkbootdiscoveredhost resource.
        dmi_uuid: Persisted dmi uuid for the networkbootdiscoveredhost resource.
        boot_mac: Persisted boot mac for the networkbootdiscoveredhost resource.
        macs_json: Serialized JSON representation of macs.
        manufacturer: Persisted manufacturer for the networkbootdiscoveredhost resource.
        product_name: Persisted product name for the networkbootdiscoveredhost resource.
        serial_number: Persisted serial number for the networkbootdiscoveredhost resource.
        cpu_model: Persisted cpu model for the networkbootdiscoveredhost resource.
        total_memory_bytes: Total memory size in bytes.
        disk_count: Number of disk items.
        interface_count: Number of interface items.
        collision: Persisted collision for the networkbootdiscoveredhost resource.
        first_seen_at: UTC timestamp associated with first seen.
        last_seen_at: UTC timestamp associated with last seen.
        latest_report_id: Identifier of the associated latest report.
        reports: Persisted reports for the networkbootdiscoveredhost resource.
    """
    __tablename__ = "network_boot_discovered_hosts"
    __table_args__ = (
        UniqueConstraint("identity_key", name="uq_network_boot_discovered_host_identity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_key: Mapped[str] = mapped_column(String(160), index=True)
    dmi_uuid: Mapped[str] = mapped_column(String(40), default="", index=True)
    boot_mac: Mapped[str] = mapped_column(String(32), default="", index=True)
    macs_json: Mapped[str] = mapped_column(Text, default="[]")
    manufacturer: Mapped[str] = mapped_column(String(240), default="")
    product_name: Mapped[str] = mapped_column(String(240), default="")
    serial_number: Mapped[str] = mapped_column(String(240), default="")
    cpu_model: Mapped[str] = mapped_column(String(500), default="")
    total_memory_bytes: Mapped[int] = mapped_column(Integer, default=0)
    disk_count: Mapped[int] = mapped_column(Integer, default=0)
    interface_count: Mapped[int] = mapped_column(Integer, default=0)
    collision: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    latest_report_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    reports: Mapped[list["NetworkBootInventoryReport"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
        foreign_keys="NetworkBootInventoryReport.host_id",
        order_by="NetworkBootInventoryReport.received_at.desc()",
    )


class NetworkBootInventoryReport(Base):
    """Represent network boot inventory report.

    Attributes:
        id: Unique database identifier for the resource.
        host_id: Identifier of the associated host.
        session_id: Identifier of the associated session.
        schema_version: Persisted schema version for the networkbootinventoryreport resource.
        payload_json: Serialized JSON representation of payload.
        received_at: UTC timestamp associated with received.
        host: Persisted host for the networkbootinventoryreport resource.
    """
    __tablename__ = "network_boot_inventory_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("network_boot_discovered_hosts.id", ondelete="CASCADE"),
        index=True,
    )
    session_id: Mapped[str] = mapped_column(String(40), index=True)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    payload_json: Mapped[str] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    host: Mapped[NetworkBootDiscoveredHost] = relationship(
        back_populates="reports",
        foreign_keys=[host_id],
    )


class NetworkBootInventorySession(Base):
    """Represent network boot inventory session.

    Attributes:
        id: Unique database identifier for the resource.
        token_hash: Persisted token hash for the networkbootinventorysession resource.
        bound_identity_key: Persisted bound identity key for the networkbootinventorysession
            resource.
        host_id: Identifier of the associated host.
        report_submitted_at: UTC timestamp associated with report submitted.
        heartbeat_at: UTC timestamp associated with heartbeat.
        created_at: UTC timestamp when the resource was created.
        expires_at: UTC timestamp after which the resource is no longer valid.
        revoked_at: UTC timestamp associated with revoked.
    """
    __tablename__ = "network_boot_inventory_sessions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    bound_identity_key: Mapped[str] = mapped_column(String(160), default="", index=True)
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_boot_discovered_hosts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    report_submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NetworkBootInventoryCommand(Base):
    """Represent network boot inventory command.

    Attributes:
        id: Unique database identifier for the resource.
        session_id: Identifier of the associated session.
        host_id: Identifier of the associated host.
        action: Persisted action for the networkbootinventorycommand resource.
        status: Current lifecycle or operation status.
        requested_by: Persisted requested by for the networkbootinventorycommand resource.
        created_at: UTC timestamp when the resource was created.
        delivered_at: UTC timestamp associated with delivered.
        acknowledged_at: UTC timestamp associated with acknowledged.
        expires_at: UTC timestamp after which the resource is no longer valid.
    """
    __tablename__ = "network_boot_inventory_commands"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("network_boot_inventory_sessions.id", ondelete="CASCADE"),
        index=True,
    )
    host_id: Mapped[int] = mapped_column(
        ForeignKey("network_boot_discovered_hosts.id", ondelete="CASCADE"),
        index=True,
    )
    action: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(40), default="queued")
    requested_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NetworkBootHostBootOverride(Base):
    """Represent network boot host boot override.

    Attributes:
        host_id: Identifier of the associated host.
        mac_address: Persisted mac address for the networkboothostbootoverride resource.
        environment_key: Persisted environment key for the networkboothostbootoverride resource.
        requested_by: Persisted requested by for the networkboothostbootoverride resource.
        requested_at: UTC timestamp associated with requested.
        expires_at: UTC timestamp after which the resource is no longer valid.
        claimed_at: UTC timestamp associated with claimed.
    """
    __tablename__ = "network_boot_host_boot_overrides"

    host_id: Mapped[int] = mapped_column(
        ForeignKey("esxi_pxe_hosts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    mac_address: Mapped[str] = mapped_column(String(32), index=True)
    environment_key: Mapped[str] = mapped_column(
        ForeignKey("network_boot_environments.key", ondelete="CASCADE"),
        default="inventory",
    )
    requested_by: Mapped[str] = mapped_column(String(100))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Job(Base):
    """Represent job.

    Attributes:
        id: Unique database identifier for the resource.
        type: Persisted type for the job resource.
        status: Current lifecycle or operation status.
        created_by: Persisted created by for the job resource.
        created_at: UTC timestamp when the resource was created.
        started_at: UTC timestamp associated with started.
        finished_at: UTC timestamp associated with finished.
        progress_percent: Progress expressed as a percentage.
        result: Persisted result for the job resource.
        error: Failure detail recorded for the latest unsuccessful operation.
        schedule_id: Identifier of the associated schedule.
        trigger: Persisted trigger for the job resource.
        planned_for: Persisted planned for for the job resource.
        task_config_json: Serialized JSON representation of task config.
        network_boot_environment_key: Persisted network boot environment key for the job resource.
        network_boot_source: Persisted network boot source for the job resource.
        vcf_depot_operation: Persisted vcf depot operation for the job resource.
        steps: Persisted steps for the job resource.
    """
    __tablename__ = "jobs"
    __table_args__ = (
        Index(
            "uq_jobs_active_network_boot_download",
            "network_boot_environment_key",
            unique=True,
            sqlite_where=text(
                "type = 'pxe-media-sync' "
                "AND network_boot_source = 'download' "
                "AND status IN ('pending', 'running')"
            ),
            postgresql_where=text(
                "type = 'pxe-media-sync' "
                "AND network_boot_source = 'download' "
                "AND status IN ('pending', 'running')"
            ),
        ),
    )

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
    network_boot_environment_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    network_boot_source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    vcf_depot_operation: Mapped[bool] = mapped_column(
        Boolean,
        default=_job_vcf_depot_operation_default,
    )

    steps: Mapped[list["JobStep"]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="JobStep.position",
    )


class JobStep(Base):
    """Represent job step.

    Attributes:
        id: Unique database identifier for the resource.
        job_id: Identifier of the associated job.
        component_key: Persisted component key for the jobstep resource.
        label: Persisted label for the jobstep resource.
        position: Persisted position for the jobstep resource.
        status: Current lifecycle or operation status.
        progress_percent: Progress expressed as a percentage.
        created_at: UTC timestamp when the resource was created.
        started_at: UTC timestamp associated with started.
        finished_at: UTC timestamp associated with finished.
        result: Persisted result for the jobstep resource.
        error: Failure detail recorded for the latest unsuccessful operation.
        job: Persisted job for the jobstep resource.
    """
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
    """Represent setting.

    Attributes:
        id: Unique database identifier for the resource.
        key: Persisted key for the setting resource.
        value: Persisted value for the setting resource.
        updated_at: UTC timestamp when the resource was last updated.
    """
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
