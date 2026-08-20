"""Implement seed behavior."""

from ipaddress import ip_interface

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.models import (
    ApplianceSettings,
    CaCertificate,
    CaProfile,
    CaSettings,
    DhcpReservation,
    DhcpScope,
    DhcpSettings,
    DnsRecord,
    DnsSettings,
    FirewallRule,
    FirewallSettings,
    KmsSettings,
    LdapSettings,
    ManagedPackage,
    NatRule,
    NtpSettings,
    PhysicalInterface,
    Route,
    ServiceState,
    Setting,
    UpdateSource,
    User,
    VcfBackupSettings,
    VcfDepotDownloadProfile,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
    WanPolicy,
)
from atlaso.app.security import ensure_appliance_instance_id
from atlaso.app.services.appliance_settings import (
    APPLIANCE_DNS_RECORD_DESCRIPTION,
    normalize_fqdn,
)
from atlaso.app.services.dnsmasq import (
    ensure_dns_authoritative_defaults,
    join_domains,
    split_domains,
    validate_dns_record,
)
from atlaso.app.services.esxi_pxe import ESXI_PXE_NATIVE_UEFI_HTTP_ENABLED_KEY
from atlaso.app.services.ldap import LDAP_DEFAULT_HOSTNAME, LDAP_STAGED_CONFIG_PATH
from atlaso.app.services.local_users import (
    DEFAULT_LOCAL_USER_SHELL,
    POWERSHELL_LOCAL_USER_SHELL,
    stage_user_os_password,
)
from atlaso.app.services.networking import (
    LEGACY_NETWORK_ROLE_REPLACEMENTS,
    normalize_interface_mode,
    normalize_interface_role,
    normalize_ipv4_method,
)
from atlaso.app.services.ntp import (
    NTP_DEFAULT_HOSTNAME,
    NTP_STAGED_CONFIG_PATH,
    default_ntp_upstream_fields,
    dump_ntp_upstream_sources,
    ntp_upstream_sources,
)
from atlaso.app.services.service_registry import (
    RETIRED_SERVICE_IDS,
    SERVICE_STATE_DEFAULTS,
)
from atlaso.app.services.vcf_backups import VCF_BACKUP_DEFAULT_USERNAME
from atlaso.app.services.vcf_offline_depot import VCF_DEPOT_DEFAULT_USERNAME

VCF_BACKUP_USERNAME = VCF_BACKUP_DEFAULT_USERNAME
VCF_DEPOT_USERNAME = VCF_DEPOT_DEFAULT_USERNAME
SEED_EXAMPLES_SETTING_KEY = "seed.include_examples"
NTP_NTS_RESTORATION_SETTING_KEY = "ntp.nts_restoration_v1"
NETWORK_ROLE_RECONCILIATION_SETTING_KEY = "network.roles_canonical_v1"
NTP_NTS_CANONICAL_DEFAULTS = {
    "time.cloudflare.com": {
        "ids": {"cloudflare-ntp", "cloudflare-nts"},
        "id": "cloudflare-nts",
        "enabled": True,
        "description": "Cloudflare public NTS",
    },
    "nts.netnod.se": {
        "ids": {"netnod-ntp", "netnod-nts"},
        "id": "netnod-nts",
        "enabled": True,
        "description": "Netnod public NTS",
    },
    "ptbtime1.ptb.de": {
        "ids": {"ptb-germany-ntp", "ptb-germany-nts"},
        "id": "ptb-germany-nts",
        "description": "PTB Germany public NTS",
    },
}


def restore_canonical_nts_defaults_once(db: Session, settings: NtpSettings) -> bool:
    """Return restore canonical nts defaults once.

    Args:
        db: Active database session.
        settings: Desired or runtime settings consumed by the operation.
    """
    marker = db.execute(
        select(Setting).where(Setting.key == NTP_NTS_RESTORATION_SETTING_KEY)
    ).scalar_one_or_none()
    if marker is not None:
        return False

    sources = ntp_upstream_sources(settings)
    changed = False
    for source in sources:
        source_name = str(source.get("source") or "").strip().rstrip(".").lower()
        source_id = str(source.get("id") or "")
        canonical = NTP_NTS_CANONICAL_DEFAULTS.get(source_name)
        if canonical is None or source_id not in canonical["ids"]:
            continue
        canonical_enabled = canonical.get("enabled")
        changed = changed or any(
            [
                source_id != canonical["id"],
                canonical_enabled is not None and bool(source.get("enabled")) != canonical_enabled,
                not bool(source.get("use_nts")),
                str(source.get("description") or "") != canonical["description"],
            ]
        )
        source["id"] = canonical["id"]
        if canonical_enabled is not None:
            source["enabled"] = canonical_enabled
        source["use_nts"] = True
        source["description"] = canonical["description"]

    if changed:
        settings.upstream_sources_json = dump_ntp_upstream_sources(sources)
        settings.upstream_servers = "\n".join(
            str(source["source"]) for source in sources if source.get("enabled")
        )
        db.add(settings)
    db.add(Setting(key=NTP_NTS_RESTORATION_SETTING_KEY, value="complete"))
    db.flush()
    return changed


def reconcile_legacy_network_roles_once(db: Session) -> dict[str, int]:
    """Replace retired network roles without changing any other interface state.

    Args:
        db: Active database session.
    """
    marker = db.execute(
        select(Setting).where(Setting.key == NETWORK_ROLE_RECONCILIATION_SETTING_KEY)
    ).scalar_one_or_none()
    if marker is not None:
        return {"physical_interfaces": 0, "vlan_interfaces": 0}

    counts = {"physical_interfaces": 0, "vlan_interfaces": 0}
    for key, model in (
        ("physical_interfaces", PhysicalInterface),
        ("vlan_interfaces", VlanInterface),
    ):
        for interface in db.execute(select(model)).scalars().all():
            raw_role = str(interface.role or "").strip().lower()
            replacement = LEGACY_NETWORK_ROLE_REPLACEMENTS.get(raw_role)
            if replacement is None:
                continue
            interface.role = replacement
            db.add(interface)
            counts[key] += 1

    db.add(Setting(key=NETWORK_ROLE_RECONCILIATION_SETTING_KEY, value="complete"))
    db.flush()
    return counts


def seed_initial_data(
    db: Session,
    *,
    include_examples: bool = True,
    appliance_mode: bool = False,
    commit: bool = True,
) -> None:
    """Handle seed initial data.

    Args:
        db: Active database session.
        include_examples: Include examples supplied by the caller.
        appliance_mode: Appliance mode supplied by the caller.
        commit: Commit seeded rows and emit post-commit restoration audit when true.
    """
    ntp_defaults_restored = False
    ensure_appliance_instance_id(db)
    reconciled_network_roles = reconcile_legacy_network_roles_once(db)
    if include_examples:
        seed_examples_setting = db.execute(select(Setting).where(Setting.key == SEED_EXAMPLES_SETTING_KEY)).scalar_one_or_none()
        if seed_examples_setting is not None and seed_examples_setting.value.strip().lower() in {"0", "false", "no"}:
            include_examples = False
    settings = get_settings()
    native_uefi_http_setting = db.execute(
        select(Setting).where(
            Setting.key == ESXI_PXE_NATIVE_UEFI_HTTP_ENABLED_KEY
        )
    ).scalar_one_or_none()
    if native_uefi_http_setting is None:
        db.add(
            Setting(
                key=ESXI_PXE_NATIVE_UEFI_HTTP_ENABLED_KEY,
                value="false",
            )
        )
    if db.bind is not None and db.bind.dialect.name == "sqlite":
        columns = {row[1] for row in db.execute(text("PRAGMA table_info(users)")).all()}
        if {"pending_os_password_encrypted", "os_password_pending_at"}.issubset(columns):
            db.execute(
                text(
                    "UPDATE users SET pending_os_password_encrypted = NULL, os_password_pending_at = NULL "
                    "WHERE pending_os_password_encrypted IS NOT NULL"
                )
            )
    bootstrap_user = db.execute(select(User).where(User.username == settings.bootstrap_admin_username)).scalar_one_or_none()
    if db.execute(select(User)).first() is None:
        bootstrap_user = User(
            username=settings.bootstrap_admin_username,
            role="admin",
            shell=POWERSHELL_LOCAL_USER_SHELL if settings.environment == "appliance" else DEFAULT_LOCAL_USER_SHELL,
            web_terminal_access=True,
        )
        stage_user_os_password(bootstrap_user, settings.bootstrap_admin_password)
        db.add(bootstrap_user)
        db.flush()
    vcf_backup_user = db.execute(select(User).where(User.username == VCF_BACKUP_USERNAME)).scalar_one_or_none()
    if vcf_backup_user is None:
        vcf_backup_user = User(
            username=VCF_BACKUP_USERNAME,
            role="viewer",
            enabled=False,
        )
        db.add(vcf_backup_user)
        db.flush()
    vcf_depot_user = db.execute(select(User).where(User.username == VCF_DEPOT_USERNAME)).scalar_one_or_none()
    if vcf_depot_user is None:
        vcf_depot_user = User(
            username=VCF_DEPOT_USERNAME,
            role="viewer",
            enabled=False,
        )
        db.add(vcf_depot_user)
        db.flush()

    management_cidr = settings.appliance_management_cidr or "192.168.49.1/24"
    management_uses_dhcp = management_cidr.strip().lower() == "dhcp"
    if db.execute(select(PhysicalInterface)).first() is None:
        physical_interfaces = [
            PhysicalInterface(
                name="eth0",
                mac_address="02:15:5d:00:10:01",
                driver="hv_netvsc",
                speed="10 Gbps",
                host_ip_cidr=None if management_uses_dhcp else management_cidr,
                host_mtu=1500,
                host_admin_state="up",
                ip_cidr=None if management_uses_dhcp else management_cidr,
                gateway=None if management_uses_dhcp else settings.appliance_management_gateway or None,
                ipv4_method="dhcp" if management_uses_dhcp else "static",
                ipv6_enabled=settings.appliance_management_ipv6_enabled,
                ipv6_cidr=settings.appliance_management_ipv6_cidr or None,
                ipv6_gateway=settings.appliance_management_ipv6_gateway or None,
                mtu=1500,
                role="management",
                mode="access",
                inventory_source="seed",
                desired_state_source="seed",
            )
        ]
        if include_examples:
            physical_interfaces.extend(
                [
                    PhysicalInterface(
                        name="eth1",
                        mac_address="02:15:5d:00:10:02",
                        driver="hv_netvsc",
                        speed="10 Gbps",
                        host_mtu=1500,
                        host_admin_state="up",
                        mtu=1500,
                        admin_state="up",
                        role="access",
                        mode="trunk",
                        inventory_source="seed",
                        desired_state_source="seed",
                    ),
                    PhysicalInterface(
                        name="eth2",
                        mac_address="02:15:5d:00:10:03",
                        driver="hv_netvsc",
                        speed="10 Gbps",
                        host_ip_cidr="192.168.50.1/24",
                        host_mtu=1500,
                        host_admin_state="up",
                        ip_cidr="192.168.50.1/24",
                        mtu=1500,
                        admin_state="up",
                        role="access",
                        mode="access",
                        inventory_source="seed",
                        desired_state_source="seed",
                    ),
                ]
            )
        db.add_all(physical_interfaces)
        db.flush()

    eth1_parent = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth1")).scalar_one_or_none()
    seed_sample_vlan = include_examples and eth1_parent is not None and normalize_interface_mode(eth1_parent.mode) == "trunk"
    if seed_sample_vlan and db.execute(select(VlanInterface).where(VlanInterface.name == "eth1.20")).scalar_one_or_none() is None:
        db.add(
            VlanInterface(
                name="eth1.20",
                parent_interface="eth1",
                vlan_id=20,
                ip_cidr="192.168.20.1/24",
                mtu=1500,
                role="route",
                enabled=True,
            )
        )
        db.flush()

    if include_examples and db.execute(select(WanPolicy)).first() is None:
        policy = WanPolicy(
            name="Europe WAN",
            description="Training-lab WAN profile for transatlantic latency.",
            latency_ms=150,
            jitter_ms=20,
            packet_loss_percent=0.5,
            bandwidth_mbit=100,
            corrupt_percent=0.01,
            duplicate_percent=0.0,
            reorder_percent=0.0,
        )
        db.add(policy)
        db.flush()
        if seed_sample_vlan and db.execute(select(VlanInterface).where(VlanInterface.name == "eth1.20")).scalar_one_or_none() is not None:
            db.add(
                Route(
                    destination_cidr="192.168.20.0/24",
                    gateway=None,
                    interface_name="eth1.20",
                    metric=100,
                    wan_policy_id=policy.id,
                )
            )

    if include_examples and seed_sample_vlan and db.execute(select(NatRule)).first() is None:
        db.add(
            NatRule(
                name="SiteA outbound WAN",
                source="192.168.50.0/24",
                outbound_interface="eth1.20",
                masquerade=True,
                priority=100,
                description="Demo outbound masquerade from SiteA through the sample WAN VLAN.",
                enabled=True,
            )
        )

    for retired_service in db.execute(select(ServiceState).where(ServiceState.service.in_(RETIRED_SERVICE_IDS))).scalars().all():
        db.delete(retired_service)
    vcf_backup_settings = db.execute(select(VcfBackupSettings)).scalar_one_or_none()
    vcf_backup_desired_enabled = bool(vcf_backup_settings and vcf_backup_settings.enabled)
    for service_state in SERVICE_STATE_DEFAULTS:
        existing_service = db.execute(select(ServiceState).where(ServiceState.service == service_state["service"])).scalar_one_or_none()
        if existing_service is None:
            db.add(ServiceState(**service_state))
        elif service_state["service"] in {"ntpd", "repository", "vcf-backups"}:
            existing_service.display_name = service_state["display_name"]
            existing_service.detail = service_state["detail"]
            if existing_service.health == "unconfigured":
                continue
            if existing_service.health == "healthy":
                existing_service.health = service_state["health"]
            if service_state["service"] == "repository":
                existing_service.enabled = service_state["enabled"]
                existing_service.running = service_state["running"]
            if service_state["service"] == "vcf-backups" and not vcf_backup_desired_enabled:
                existing_service.enabled = service_state["enabled"]
                existing_service.running = service_state["running"]
                existing_service.health = service_state["health"]

    appliance_settings = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    if appliance_settings is None:
        appliance_settings = ApplianceSettings(
            fqdn=normalize_fqdn(settings.appliance_fqdn) or "core.atlaso.internal",
            management_https_enabled=appliance_mode,
            root_ssh_enabled=settings.appliance_root_ssh_enabled,
            external_dns_servers=_settings_lines(settings.appliance_external_dns_servers),
        )
        db.add(appliance_settings)
        db.flush()

    ntp_settings = db.execute(select(NtpSettings)).scalar_one_or_none()
    if ntp_settings is None:
        ntp_upstreams = default_ntp_upstream_fields()
        ntp_settings = NtpSettings(
            hostname=NTP_DEFAULT_HOSTNAME,
            upstream_servers=ntp_upstreams["upstream_servers"],
            upstream_sources_json=ntp_upstreams["upstream_sources_json"],
            config_path=NTP_STAGED_CONFIG_PATH,
        )
        db.add(ntp_settings)
        db.flush()
        if db.execute(
            select(Setting).where(Setting.key == NTP_NTS_RESTORATION_SETTING_KEY)
        ).scalar_one_or_none() is None:
            db.add(Setting(key=NTP_NTS_RESTORATION_SETTING_KEY, value="complete"))
    else:
        ntp_defaults_restored = restore_canonical_nts_defaults_once(db, ntp_settings)

    if db.execute(select(LdapSettings)).scalar_one_or_none() is None:
        db.add(
            LdapSettings(
                enabled=False,
                hostname=LDAP_DEFAULT_HOSTNAME,
                config_path=LDAP_STAGED_CONFIG_PATH,
            )
        )

    appliance_dns_domain = _domain_from_fqdn(appliance_settings.fqdn) or "atlaso.internal"
    dns_settings = db.execute(select(DnsSettings)).scalar_one_or_none()
    if dns_settings is None:
        dns_settings = DnsSettings(
            enabled=False,
            listen_interface="eth2" if include_examples else "",
            listen_address="192.168.50.1" if include_examples else "",
            domain=appliance_dns_domain,
            upstream_servers=_settings_lines(settings.appliance_external_dns_servers),
        )
        db.add(dns_settings)
    else:
        domains = split_domains(dns_settings.domain)
        if appliance_dns_domain not in domains:
            dns_settings.domain = join_domains([appliance_dns_domain, *domains])
            db.add(dns_settings)
    ensure_dns_authoritative_defaults(dns_settings)

    _ensure_appliance_dns_record(db, appliance_settings)

    if db.execute(select(DhcpSettings)).first() is None:
        db.add(
            DhcpSettings(
                enabled=False,
                interface_name="eth2" if include_examples else "",
                site_address="192.168.50.1" if include_examples else "",
                prefix_length=24,
                lease_time="12h",
                domain_name="atlaso.internal",
                dns_server="192.168.50.1" if include_examples else "",
            )
        )

    if include_examples and db.execute(select(DhcpScope)).first() is None:
        db.add(
            DhcpScope(
                name="SiteA",
                interface_name="eth2",
                site_address="192.168.50.1",
                prefix_length=24,
                range_expression="192.168.50.100-192.168.50.200",
                lease_time="12h",
                domain_name="atlaso.internal",
                dns_server="192.168.50.1",
                ntp_server="192.168.50.1",
                enabled=True,
                description="Default SiteA DHCP IP zone.",
            )
        )

    if include_examples and db.execute(select(DhcpReservation)).first() is None:
        db.add(
            DhcpReservation(
                hostname="test-client",
                mac_address="02:15:5d:00:20:10",
                ip_address="192.168.50.120",
                description="Sample SiteA reservation for smoke tests.",
                enabled=False,
            )
        )

    if db.execute(select(FirewallSettings)).first() is None:
        db.add(FirewallSettings(enabled=True, default_input_policy="drop", default_forward_policy="drop", default_output_policy="accept"))

    if include_examples and db.execute(select(FirewallRule)).first() is None:
        db.add_all(
            [
                FirewallRule(
                    name="mgmt-console",
                    direction="input",
                    action="accept",
                    protocol="tcp",
                    source="192.168.49.0/24",
                    destination="any",
                    destination_port="22,80,443",
                    interface_name="eth0",
                    priority=10,
                    description="Allow management access to SSH, HTTP, and HTTPS.",
                ),
                FirewallRule(
                    name="sitea-dns-dhcp",
                    direction="input",
                    action="accept",
                    protocol="udp",
                    source="192.168.50.0/24",
                    destination="any",
                    destination_port="53,67",
                    interface_name="eth2",
                    priority=20,
                    description="Allow SiteA clients to reach Atlaso DNS and DHCP.",
                ),
            ]
        )

    if db.execute(select(CaSettings)).first() is None:
        db.add(
            CaSettings(
                enabled=appliance_mode,
                portal_hostname="ca.atlaso.internal",
                root_common_name="Atlaso Internal Root CA",
                organization="Atlaso",
                organizational_unit="Lab Infrastructure",
                country="US",
                storage_path="/etc/atlaso/ca",
            )
        )

    if include_examples and db.execute(select(CaProfile)).first() is None:
        server_profile = CaProfile(
            name="VCF service TLS",
            certificate_type="server",
            validity_days=825,
            key_algorithm="RSA",
            key_size=2048,
            key_usage="digitalSignature,keyEncipherment",
            extended_key_usage="serverAuth",
            san_required=True,
            description="Default profile for VCF lab services and appliance endpoints.",
        )
        db.add(server_profile)
        db.flush()
        db.add(
            CaProfile(
                name="VCF KMIP client",
                certificate_type="client",
                validity_days=825,
                key_algorithm="RSA",
                key_size=2048,
                key_usage="digitalSignature,keyEncipherment",
                extended_key_usage="clientAuth",
                san_required=False,
                description="Default profile for VCF and KMIP client certificates.",
            )
        )
        db.add(
            CaCertificate(
                common_name="core.atlaso.internal",
                profile_id=server_profile.id,
                subject_alt_names="core.atlaso.internal\natlaso.internal",
                ip_addresses="192.168.50.1",
                description="Sample appliance console certificate request.",
                enabled=True,
            )
        )

    if db.execute(select(KmsSettings)).first() is None:
        db.add(
            KmsSettings(
                enabled=False,
                backend="atlaso-kmip",
                listen_interface="eth2" if include_examples else "",
                listen_address="192.168.50.1" if include_examples else "",
                port=5696,
                hostname="kms.atlaso.internal",
                server_certificate="kms.atlaso.internal",
                ca_certificate_path="/etc/atlaso/ca/root.crt",
                database_path="/var/lib/atlaso/kmip/store.db",
                config_path="/etc/atlaso/kmip/server.json",
                require_client_cert=True,
                allow_register=False,
                allow_destroy=False,
            )
        )

    if db.execute(select(VcfBackupSettings)).first() is None:
        db.add(
            VcfBackupSettings(
                enabled=False,
                listen_interface="eth2" if include_examples else "",
                listen_address="192.168.50.1" if include_examples else "",
                port=22,
                sftp_user_id=vcf_backup_user.id if vcf_backup_user else None,
                storage_path="/mnt/atlaso-vcf-backups",
                chroot_enabled=True,
                allow_password_auth=True,
                allow_public_key_auth=True,
                max_sessions=4,
            )
        )
    if db.execute(select(VcfPrivateRegistrySettings)).first() is None:
        db.add(VcfPrivateRegistrySettings())
    if db.execute(select(VcfOfflineDepotSettings)).first() is None:
        db.add(VcfOfflineDepotSettings())
    if db.execute(select(VcfDepotDownloadProfile)).first() is None:
        db.add_all(
            [
                VcfDepotDownloadProfile(
                    name="Binaries",
                    profile_type="binaries",
                    sku="VCF",
                    vcf_version="9.1.0",
                    binary_type="INSTALL",
                    automated_install=True,
                    enabled=False,
                    status="planned",
                ),
                VcfDepotDownloadProfile(
                    name="Metadata",
                    profile_type="metadata",
                    sku="VCF",
                    vcf_version="9.1.0",
                    binary_type="INSTALL",
                    automated_install=True,
                    enabled=False,
                    status="planned",
                ),
                VcfDepotDownloadProfile(
                    name="Esx",
                    profile_type="esx",
                    sku="VCF",
                    vcf_version="9.1.0",
                    binary_type="INSTALL",
                    automated_install=True,
                    enabled=False,
                    status="planned",
                ),
            ]
        )

    seed_update_sources(db)
    if not commit:
        db.flush()
        return
    db.commit()
    if ntp_defaults_restored:
        record_audit(
            db,
            actor="system",
            action="restore_ntp_nts_defaults",
            resource_type="ntpd",
            resource_id=str(ntp_settings.id),
            detail="Reconciled canonical NTS defaults.",
        )
    if any(reconciled_network_roles.values()):
        record_audit(
            db,
            actor="system",
            action="reconcile_network_roles",
            resource_type="network",
            resource_id="roles",
            detail=(
                f"Mapped {reconciled_network_roles['physical_interfaces']} physical interface and "
                f"{reconciled_network_roles['vlan_interfaces']} VLAN interface retired roles to access."
            ),
        )


def seed_update_sources(db: Session) -> None:
    """Handle seed update sources.

    Args:
        db: Active database session.
    """
    photon_source = db.execute(select(UpdateSource).where(UpdateSource.kind == "photon")).scalars().first()
    if photon_source is None:
        photon_source = UpdateSource(
            kind="photon",
            name="System Photon repositories",
            url="",
            enabled=True,
            priority=10,
            settings_json='{"managed": false, "source": "system"}',
        )
        db.add(photon_source)
    powershell_source = db.execute(select(UpdateSource).where(UpdateSource.kind == "powershell")).scalars().first()
    if powershell_source is None:
        powershell_source = UpdateSource(
            kind="powershell",
            name="PSGallery",
            url="https://www.powershellgallery.com/api/v2",
            enabled=True,
            priority=50,
            settings_json='{"trusted": false}',
        )
        db.add(powershell_source)
    atlaso_source = db.execute(select(UpdateSource).where(UpdateSource.kind == "atlaso")).scalars().first()
    if atlaso_source is None:
        atlaso_source = UpdateSource(
            kind="atlaso",
            name="GitHub Releases",
            url="https://mdaneri.github.io/Atlaso/updates",
            enabled=True,
            priority=10,
            settings_json='{"channel": "stable"}',
        )
        db.add(atlaso_source)
    db.flush()
    if db.execute(select(ManagedPackage).where(ManagedPackage.ecosystem == "powershell")).scalars().first() is None:
        db.add(
            ManagedPackage(
                ecosystem="powershell",
                name="VCF.PowerCLI",
                source_id=powershell_source.id,
                policy="pinned",
                target_version="9.1.0.25380678",
                enabled=True,
            )
        )


def _domain_from_fqdn(fqdn: str) -> str:
    """Return domain from fqdn.

    Args:
        fqdn: Fqdn consumed by domain from FQDN.
    """
    normalized = normalize_fqdn(fqdn)
    parts = normalized.split(".", 1)
    return parts[1] if len(parts) == 2 else ""


def _settings_lines(value: str) -> str:
    """Return settings lines.

    Args:
        value: Candidate value consumed by settings lines.
    """
    parts = [part.strip() for part in value.replace(",", "\n").replace(";", "\n").splitlines() if part.strip()]
    return "\n".join(parts)


def _management_ips(db: Session) -> list[str]:
    """Return every desired address that exposes the management browser plane.

    Args:
        db: Active database session.
    """
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    addresses: list[str] = []
    for interface in interfaces:
        role = normalize_interface_role(interface.role)
        exposes_management = role == "management" or (
            role == "access"
            and normalize_interface_mode(interface.mode) == "access"
            and interface.admin_state == "up"
            and interface.access_management_ui_enabled
        )
        if interface.oper_state == "missing" or not exposes_management:
            continue
        ipv4_cidr = interface.host_ip_cidr if normalize_ipv4_method(interface.ipv4_method) == "dhcp" else interface.ip_cidr
        ipv6_cidr = (interface.ipv6_cidr or interface.host_ipv6_cidr) if interface.ipv6_enabled else None
        for candidate_cidr in (ipv4_cidr, ipv6_cidr):
            if not candidate_cidr:
                continue
            try:
                parsed = ip_interface(candidate_cidr).ip
            except ValueError:
                continue
            if parsed.is_link_local:
                continue
            address = str(parsed)
            if address not in addresses:
                addresses.append(address)
    vlans = db.execute(
        select(VlanInterface)
        .where(VlanInterface.enabled.is_(True))
        .order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)
    ).scalars().all()
    for vlan in vlans:
        if normalize_interface_role(vlan.role) != "access" or not vlan.access_management_ui_enabled:
            continue
        for candidate_cidr in (vlan.ip_cidr, vlan.ipv6_cidr):
            if not candidate_cidr:
                continue
            try:
                parsed = ip_interface(candidate_cidr).ip
            except ValueError:
                continue
            if parsed.is_link_local:
                continue
            address = str(parsed)
            if address not in addresses:
                addresses.append(address)
    return addresses


def _ensure_appliance_dns_record(db: Session, appliance_settings: ApplianceSettings) -> None:
    """Ensure appliance dns record.

    Args:
        db: Active database session.
        appliance_settings: Appliance settings supplied by the caller.
    """
    fqdn = normalize_fqdn(appliance_settings.fqdn)
    addresses = _management_ips(db)
    if not fqdn or not addresses:
        return
    existing_records = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == fqdn,
            DnsRecord.record_type.in_(["A", "AAAA"]),
        )
    ).scalars().all()
    existing_by_key = {(record.record_type, record.address): record for record in existing_records}
    desired_keys: set[tuple[str, str]] = set()
    for address in addresses:
        record_type = "AAAA" if ":" in address else "A"
        if validate_dns_record(fqdn, record_type, address):
            continue
        key = (record_type, address)
        desired_keys.add(key)
        existing = existing_by_key.get(key)
        if existing is None:
            db.add(
                DnsRecord(
                    hostname=fqdn,
                    record_type=record_type,
                    address=address,
                    description=APPLIANCE_DNS_RECORD_DESCRIPTION,
                    enabled=True,
                )
            )
        elif APPLIANCE_DNS_RECORD_DESCRIPTION in (existing.description or ""):
            existing.enabled = True
            existing.description = APPLIANCE_DNS_RECORD_DESCRIPTION
            db.add(existing)
    for record in existing_records:
        if (
            APPLIANCE_DNS_RECORD_DESCRIPTION in (record.description or "")
            and (record.record_type, record.address) not in desired_keys
        ):
            db.delete(record)
