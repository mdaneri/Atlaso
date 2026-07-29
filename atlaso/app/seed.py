from ipaddress import ip_interface

from sqlalchemy import select, text
from sqlalchemy.orm import Session

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
    KmsClient,
    KmsKey,
    KmsSettings,
    LdapSettings,
    NatRule,
    NtpSettings,
    ManagedPackage,
    PhysicalInterface,
    Route,
    ServiceState,
    Setting,
    User,
    UpdateSource,
    VcfBackupSettings,
    VcfDepotDownloadProfile,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
    WanPolicy,
)
from atlaso.app.services.appliance_settings import APPLIANCE_DNS_RECORD_DESCRIPTION, normalize_fqdn
from atlaso.app.services.local_users import DEFAULT_LOCAL_USER_SHELL, POWERSHELL_LOCAL_USER_SHELL, stage_user_os_password
from atlaso.app.services.ldap import LDAP_DEFAULT_HOSTNAME, LDAP_STAGED_CONFIG_PATH
from atlaso.app.services.dnsmasq import ensure_dns_authoritative_defaults, join_domains, split_domains, validate_dns_record
from atlaso.app.services.networking import normalize_interface_mode, normalize_ipv4_method
from atlaso.app.services.ntp import NTP_DEFAULT_HOSTNAME, NTP_STAGED_CONFIG_PATH, default_ntp_upstream_fields
from atlaso.app.services.service_registry import RETIRED_SERVICE_IDS, SERVICE_STATE_DEFAULTS
from atlaso.app.services.vcf_backups import VCF_BACKUP_DEFAULT_USERNAME
from atlaso.app.services.vcf_offline_depot import VCF_DEPOT_DEFAULT_USERNAME
from atlaso.app.security import ensure_appliance_instance_id


VCF_BACKUP_USERNAME = VCF_BACKUP_DEFAULT_USERNAME
VCF_DEPOT_USERNAME = VCF_DEPOT_DEFAULT_USERNAME
SEED_EXAMPLES_SETTING_KEY = "seed.include_examples"


def seed_initial_data(db: Session, *, include_examples: bool = True, appliance_mode: bool = False) -> None:
    ensure_appliance_instance_id(db)
    if include_examples:
        seed_examples_setting = db.execute(select(Setting).where(Setting.key == SEED_EXAMPLES_SETTING_KEY)).scalar_one_or_none()
        if seed_examples_setting is not None and seed_examples_setting.value.strip().lower() in {"0", "false", "no"}:
            include_examples = False
    settings = get_settings()
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

    if include_examples and db.execute(select(KmsClient)).first() is None:
        client = KmsClient(
            name="vcf-management",
            certificate_subject="CN=vcf-management.atlaso.internal,O=Atlaso",
            role="service",
            allowed_operations="locate,get,create,activate,get-attributes,get-attribute-list,query,discover-versions",
            description="Sample VCF management KMIP client.",
            enabled=True,
        )
        db.add(client)
        db.flush()
        db.add(
            KmsKey(
                name="vcf-sddc-manager-aes",
                algorithm="AES",
                length=256,
                usage="encrypt,decrypt",
                state="active",
                owner_client_id=client.id,
                exportable=False,
                description="Sample AES key desired state for VCF lab encryption.",
                enabled=True,
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
    db.commit()


def seed_update_sources(db: Session) -> None:
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
    normalized = normalize_fqdn(fqdn)
    parts = normalized.split(".", 1)
    return parts[1] if len(parts) == 2 else ""


def _settings_lines(value: str) -> str:
    parts = [part.strip() for part in value.replace(",", "\n").replace(";", "\n").splitlines() if part.strip()]
    return "\n".join(parts)


def _management_ip(db: Session) -> str:
    interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    candidates = [interface for interface in interfaces if interface.role == "management"] + [
        interface for interface in interfaces if interface.name == "eth0"
    ]
    seen: set[str] = set()
    for interface in candidates:
        if interface.name in seen:
            continue
        seen.add(interface.name)
        candidate_cidr = interface.host_ip_cidr if normalize_ipv4_method(interface.ipv4_method) == "dhcp" else interface.ip_cidr
        if not candidate_cidr:
            continue
        try:
            return str(ip_interface(candidate_cidr).ip)
        except ValueError:
            continue
    return ""


def _ensure_appliance_dns_record(db: Session, appliance_settings: ApplianceSettings) -> None:
    fqdn = normalize_fqdn(appliance_settings.fqdn)
    address = _management_ip(db)
    if not fqdn or not address:
        return
    record_type = "AAAA" if ":" in address else "A"
    if validate_dns_record(fqdn, record_type, address):
        return
    existing = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == fqdn,
            DnsRecord.record_type == record_type,
        )
    ).scalar_one_or_none()
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
        existing.address = address
        existing.enabled = True
        existing.description = APPLIANCE_DNS_RECORD_DESCRIPTION
        db.add(existing)
