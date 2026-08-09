"""Test firewall behavior."""

from atlaso.app.models import (
    DhcpScope,
    DhcpSettings,
    DnsSettings,
    CaSettings,
    FirewallRule,
    FirewallSettings,
    KmsSettings,
    LdapSettings,
    NtpSettings,
    OidcProviderSettings,
    PhysicalInterface,
    VcfBackupSettings,
    VcfOfflineDepotSettings,
    VcfPrivateRegistrySettings,
    VlanInterface,
)
from atlaso.app.services.firewall import (
    ca_portal_firewall_interfaces,
    dhcp_firewall_rules,
    managed_routing_firewall_rules,
    managed_service_firewall_rules,
    render_nftables_config,
    validate_firewall_state,
)


def test_dhcp_firewall_rules_follow_scope_interface_and_replace_legacy_rule():
    """Verify that dhcp firewall rules follow scope interface and replace legacy rule."""
    settings = FirewallSettings(enabled=True, default_input_policy="drop", default_forward_policy="drop", default_output_policy="accept")
    legacy_rule = FirewallRule(
        name="sitea-dns-dhcp",
        direction="input",
        action="accept",
        protocol="udp",
        source="192.168.50.0/24",
        destination="any",
        destination_port="53,67",
        interface_name="eth1",
        priority=20,
        enabled=True,
        description="Allow SiteA clients to reach Atlaso DNS and DHCP.",
    )
    scopes = [
        DhcpScope(
            name="SiteA",
            interface_name="eth2.50",
            site_address="192.168.50.1",
            prefix_length=24,
            enabled=True,
        )
    ]
    generated_rules = dhcp_firewall_rules(DhcpSettings(enabled=True), scopes)

    config = render_nftables_config(settings, [legacy_rule], generated_rules, replace_atlaso_dhcp_rules=True)

    assert 'iifname "eth2.50" udp dport 67 accept comment "sitea-dns-dhcp"' in config
    assert 'iifname "eth1" ip saddr 192.168.50.0/24 udp dport { 53, 67 } accept comment "sitea-dns-dhcp"' not in config


def test_dhcp_firewall_rules_use_dhcpv6_port_for_ipv6_zones():
    """Verify that dhcp firewall rules use dhcpv6 port for ipv6 zones."""
    settings = FirewallSettings(enabled=True, default_input_policy="drop", default_forward_policy="drop", default_output_policy="accept")
    scopes = [
        DhcpScope(
            name="IPv6Lab",
            address_family="ipv6",
            interface_name="eth2",
            site_address="fd00:50::1",
            prefix_length=64,
            enabled=True,
        )
    ]

    generated_rules = dhcp_firewall_rules(DhcpSettings(enabled=True), scopes)
    config = render_nftables_config(settings, [], generated_rules, replace_atlaso_dhcp_rules=True)

    assert generated_rules[0].name == "ipv6lab-dns-dhcpv6"
    assert generated_rules[0].destination_port == "547"
    assert 'iifname "eth2" udp dport 547 accept comment "ipv6lab-dns-dhcpv6"' in config


def test_disabled_dhcp_removes_atlaso_managed_dns_dhcp_rule():
    """Verify that disabled dhcp removes atlaso managed dns dhcp rule."""
    settings = FirewallSettings(enabled=True, default_input_policy="drop", default_forward_policy="drop", default_output_policy="accept")
    legacy_rule = FirewallRule(
        name="sitea-dns-dhcp",
        direction="input",
        action="accept",
        protocol="udp",
        source="192.168.50.0/24",
        destination="any",
        destination_port="53,67",
        interface_name="eth1",
        priority=20,
        enabled=True,
        description="Allow SiteA clients to reach Atlaso DNS and DHCP.",
    )
    generated_rules = dhcp_firewall_rules(DhcpSettings(enabled=False), [])

    config = render_nftables_config(settings, [legacy_rule], generated_rules, replace_atlaso_dhcp_rules=True)

    assert "sitea-dns-dhcp" not in config
    assert 'iifname "eth1"' not in config


def test_default_management_firewall_source_cidr_can_follow_image_network():
    """Verify that default management firewall source cidr can follow image network."""
    settings = FirewallSettings(enabled=True, default_input_policy="drop")

    config = render_nftables_config(settings, [], management_source_cidr="192.168.167.0/24")

    assert 'ip saddr 192.168.167.0/24 tcp dport { 22, 80, 443 } accept comment "Atlaso management access"' in config
    assert "192.168.49.0/24" not in config


def test_ca_portal_firewall_interfaces_include_non_management_addresses_only():
    """Verify that ca portal firewall interfaces include non management addresses only."""
    interfaces = [
        PhysicalInterface(name="eth0", role="management", ip_cidr="192.168.167.10/24", mac_address="00:50:56:00:00:10"),
        PhysicalInterface(name="eth1", role="access", ip_cidr="192.168.65.1/24", mac_address="00:50:56:00:00:11"),
        PhysicalInterface(name="eth2", role="services", ip_cidr="192.168.87.32/24", mac_address="00:50:56:00:00:12"),
    ]
    vlans = [
        VlanInterface(name="eth3.10", parent_interface="eth3", vlan_id=10, role="access", ip_cidr="172.20.1.1/24", enabled=True),
        VlanInterface(name="eth3.20", parent_interface="eth3", vlan_id=20, role="management", ip_cidr="172.20.2.1/24", enabled=True),
    ]

    targets = ca_portal_firewall_interfaces(
        interfaces,
        vlans,
        {
            "eth0": ["192.168.167.0/24"],
            "eth1": ["192.168.65.0/24"],
            "eth2": ["192.168.87.0/24"],
            "eth3.10": ["172.20.1.0/24"],
            "eth3.20": ["172.20.2.0/24"],
        },
    )

    assert targets == ["eth1", "eth2", "eth3.10"]


def test_ca_portal_firewall_interfaces_exclude_trunk_parents():
    """Verify that ca portal firewall interfaces exclude trunk parents."""
    interfaces = [
        PhysicalInterface(name="eth1", role="access", mode="trunk", ip_cidr="192.168.65.1/24", mac_address="00:50:56:00:00:11"),
        PhysicalInterface(name="eth2", role="access", mode="access", ip_cidr="192.168.87.32/24", mac_address="00:50:56:00:00:12"),
    ]
    vlans = [
        VlanInterface(name="eth1.50", parent_interface="eth1", vlan_id=50, role="access", ip_cidr="192.168.50.1/24", enabled=True),
    ]

    targets = ca_portal_firewall_interfaces(
        interfaces,
        vlans,
        {
            "eth1": ["192.168.65.0/24"],
            "eth2": ["192.168.87.0/24"],
            "eth1.50": ["192.168.50.0/24"],
        },
    )

    assert targets == ["eth2", "eth1.50"]


def test_managed_routing_firewall_rules_isolate_management_and_allow_route_role_pairs():
    """Verify that managed routing firewall rules isolate management and allow route role pairs."""
    settings = FirewallSettings(enabled=True, default_input_policy="drop", default_forward_policy="drop", default_output_policy="accept")
    interfaces = [
        PhysicalInterface(name="eth0", role="management", mode="access", ip_cidr="192.168.49.1/24", mac_address="00:50:56:00:00:10"),
        PhysicalInterface(name="eth1", role="route", mode="access", ip_cidr="172.20.1.1/24", mac_address="00:50:56:00:00:11"),
        PhysicalInterface(name="eth2", role="route", mode="access", ip_cidr="172.20.2.1/24", mac_address="00:50:56:00:00:12"),
        PhysicalInterface(name="eth3", role="access", mode="access", ip_cidr="172.20.3.1/24", mac_address="00:50:56:00:00:13"),
    ]

    rules = managed_routing_firewall_rules(interfaces, [])
    config = render_nftables_config(settings, [], rules, replace_atlaso_service_rules=True)

    assert 'iifname "eth1" ip saddr 172.20.1.0/24 ip daddr 192.168.49.0/24 drop comment "isolate-eth1-to-eth0"' in config
    assert 'iifname "eth0" ip saddr 192.168.49.0/24 ip daddr 172.20.1.0/24 drop comment "isolate-eth0-to-eth1"' in config
    assert 'iifname "eth1" ip saddr 172.20.1.0/24 ip daddr 172.20.2.0/24 accept comment "route-eth1-to-eth2"' in config
    assert 'iifname "eth3" ip saddr 172.20.3.0/24 ip daddr 172.20.1.0/24 accept' not in config


def test_managed_service_firewall_rules_include_all_enabled_service_listeners():
    """Verify that managed service firewall rules include all enabled service listeners."""
    rules = managed_service_firewall_rules(
        dns_settings=DnsSettings(enabled=True, listen_interface="eth2.50"),
        dhcp_settings=DhcpSettings(enabled=True),
        dhcp_scopes=[
            DhcpScope(
                name="SiteA",
                interface_name="eth2.50",
                site_address="192.168.50.1",
                prefix_length=24,
                enabled=True,
            )
        ],
        ca_settings=CaSettings(enabled=True, listen_interface="eth2.50"),
        kms_settings=KmsSettings(enabled=True, listen_interface="eth2.50\neth3.60", port=5696),
        ldap_settings=LdapSettings(
            enabled=True,
            listen_interface="eth0\neth2.50",
            ldaps_enabled=True,
            port=1636,
            ldap_enabled=True,
            ldap_port=1389,
        ),
        ntp_settings=NtpSettings(enabled=True, listen_interface="eth2.50\neth3.60", port=123, nts_server_enabled=True),
        oidc_settings=OidcProviderSettings(
            enabled=True,
            listen_interface="eth2.50",
            port=8443,
        ),
        vcf_backup_settings=VcfBackupSettings(enabled=True, listen_interface="eth2.50\neth3.60", port=22),
        vcf_depot_settings=VcfOfflineDepotSettings(enabled=True, listen_interface="eth2.50\neth3.60", port=8443),
        vcf_registry_settings=VcfPrivateRegistrySettings(enabled=True, listen_interface="eth2.50\neth3.60", port=9443),
        esxi_pxe_boot={"enabled": True, "listen_interface": "eth2.50\neth3.60", "http_port": 8080},
        interface_networks={"eth0": "192.168.49.0/24", "eth2.50": "192.168.50.0/24", "eth3.60": "192.168.60.0/24"},
    )

    by_name = {rule.name: rule for rule in rules}

    assert by_name["mgmt-console"].interface_name == "eth0"
    assert by_name["eth2-50-dns-tcp"].destination_port == "53"
    assert by_name["eth2-50-dns-udp"].destination_port == "53"
    assert by_name["sitea-dns-dhcp"].interface_name == "eth2.50"
    assert by_name["sitea-dns-dhcp"].source == "any"
    assert by_name["sitea-dns-dhcp"].destination_port == "67"
    assert by_name["mgmt-console"].source == "any"
    assert by_name["ca-portal-eth2.50"].destination_port == "80,443"
    assert by_name["vcf-backups-sftp-eth2.50"].source == "any"
    assert by_name["kms-kmip-eth2.50"].destination_port == "5696"
    assert by_name["kms-kmip-eth3.60"].interface_name == "eth3.60"
    assert by_name["ldap-ldaps-eth0"].destination_port == "1636"
    assert by_name["ldap-ldaps-eth2.50"].protocol == "tcp"
    assert by_name["ldap-plaintext-eth0"].destination_port == "1389"
    assert by_name["ldap-plaintext-eth2.50"].protocol == "tcp"
    assert by_name["ntpd-eth2.50"].protocol == "udp"
    assert by_name["ntpd-eth2.50"].destination_port == "123"
    assert by_name["ntpd-eth3.60"].interface_name == "eth3.60"
    assert by_name["ntpd-nts-eth2.50"].protocol == "tcp"
    assert by_name["ntpd-nts-eth2.50"].destination_port == "4460"
    assert by_name["oidc-eth2.50"].destination_port == "8443"
    assert by_name["vcf-backups-sftp-eth2.50"].destination_port == "22"
    assert by_name["vcf-backups-sftp-eth3.60"].interface_name == "eth3.60"
    assert by_name["public-services-eth2.50"].destination_port == "80"
    assert by_name["public-services-eth3.60"].destination_port == "80"
    assert by_name["vcf-offline-depot-eth2.50"].destination_port == "8443"
    assert by_name["vcf-offline-depot-eth3.60"].interface_name == "eth3.60"
    assert by_name["vcf-private-registry-eth2.50"].destination_port == "9443"
    assert by_name["vcf-private-registry-eth3.60"].interface_name == "eth3.60"
    assert by_name["esxi-pxe-tftp-eth2.50"].protocol == "udp"
    assert by_name["esxi-pxe-tftp-eth2.50"].destination_port == "69"
    assert by_name["esxi-pxe-http-eth2.50"].protocol == "tcp"
    assert by_name["esxi-pxe-http-eth2.50"].destination_port == "8080"


def test_managed_service_firewall_rules_skip_ca_portal_when_ca_disabled():
    """Verify that managed service firewall rules skip ca portal when ca disabled."""
    rules = managed_service_firewall_rules(
        dns_settings=DnsSettings(enabled=False),
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_scopes=[],
        ca_settings=CaSettings(enabled=False, listen_interface="eth2"),
        ca_portal_interfaces=["eth2", "eth3.50"],
        kms_settings=KmsSettings(enabled=False),
        ntp_settings=NtpSettings(enabled=False),
        vcf_backup_settings=VcfBackupSettings(enabled=False),
        vcf_depot_settings=VcfOfflineDepotSettings(enabled=False),
        vcf_registry_settings=VcfPrivateRegistrySettings(enabled=False),
        interface_networks={"eth0": "192.168.49.0/24", "eth2": "192.168.87.0/24", "eth3.50": "192.168.50.0/24"},
    )

    assert {rule.name for rule in rules} == {"mgmt-console"}


def test_managed_service_firewall_rules_add_https_for_extra_terminal_interfaces():
    """Verify that managed service firewall rules add https for extra terminal interfaces."""
    rules = managed_service_firewall_rules(
        dns_settings=DnsSettings(enabled=False),
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_scopes=[],
        ca_settings=CaSettings(enabled=False),
        kms_settings=KmsSettings(enabled=False),
        ntp_settings=NtpSettings(enabled=False),
        vcf_backup_settings=VcfBackupSettings(enabled=False),
        vcf_depot_settings=VcfOfflineDepotSettings(enabled=False),
        vcf_registry_settings=VcfPrivateRegistrySettings(enabled=False),
        interface_networks={"eth0": "192.168.49.0/24", "eth2": "192.168.87.0/24", "eth3.50": "192.168.50.0/24"},
        web_terminal_interfaces=["eth0", "eth2", "eth3.50"],
    )

    by_name = {rule.name: rule for rule in rules}
    assert "web-terminal-eth0" not in by_name
    assert by_name["web-terminal-eth2"].interface_name == "eth2"
    assert by_name["web-terminal-eth2"].protocol == "tcp"
    assert by_name["web-terminal-eth2"].destination_port == "443"
    assert by_name["web-terminal-eth2"].source == "any"
    assert by_name["web-terminal-eth3.50"].interface_name == "eth3.50"


def test_managed_service_firewall_rules_use_assigned_source_group():
    """Verify that managed service firewall rules use assigned source group."""
    rules = managed_service_firewall_rules(
        dns_settings=DnsSettings(enabled=False),
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_scopes=[],
        ca_settings=CaSettings(enabled=False),
        kms_settings=KmsSettings(enabled=False),
        ntp_settings=NtpSettings(enabled=False),
        vcf_backup_settings=VcfBackupSettings(enabled=True, listen_interface="eth2.50", port=22),
        vcf_depot_settings=VcfOfflineDepotSettings(enabled=False),
        vcf_registry_settings=VcfPrivateRegistrySettings(enabled=False),
        interface_networks={"eth0": "192.168.49.0/24", "eth2.50": "192.168.50.0/24"},
        source_groups=[
            {"id": "any", "name": "Any", "entries": ["any"]},
            {"id": "custom:site-a", "name": "Site A clients", "entries": ["10.10.0.0/16"]},
            {"id": "custom:managed-clients", "name": "Managed clients", "entries": ["group:custom:site-a", "10.20.0.0/16"]},
        ],
        source_group_assignments={"vcf-backups-sftp": "custom:managed-clients"},
    )
    settings = FirewallSettings(enabled=True, default_input_policy="drop")
    config = render_nftables_config(settings, [], rules, replace_atlaso_service_rules=True)

    assert 'iifname "eth2.50" ip saddr { 10.10.0.0/16, 10.20.0.0/16 } tcp dport 22 accept comment "vcf-backups-sftp-eth2.50"' in config


def test_custom_firewall_rules_resolve_source_and_destination_groups():
    """Verify that custom firewall rules resolve source and destination groups."""
    settings = FirewallSettings(enabled=True, default_input_policy="drop")
    rule = FirewallRule(
        name="custom-grouped",
        direction="input",
        action="accept",
        protocol="tcp",
        source="group:custom:clients",
        destination="group:custom:targets",
        destination_port="443",
        interface_name="eth2.50",
        priority=100,
        enabled=True,
    )
    groups = [
        {"id": "any", "name": "Any", "entries": ["any"]},
        {"id": "custom:clients", "name": "Clients", "entries": ["10.10.0.0/16"]},
        {"id": "custom:targets", "name": "Targets", "entries": ["172.20.0.10/32", "172.20.0.20/32"]},
    ]

    config = render_nftables_config(settings, [rule], source_groups=groups)

    assert 'iifname "eth2.50" ip saddr 10.10.0.0/16 ip daddr { 172.20.0.10/32, 172.20.0.20/32 } tcp dport 443 accept comment "custom-grouped"' in config


def test_firewall_rules_split_mixed_family_source_groups():
    """Verify that firewall rules split mixed family source groups."""
    settings = FirewallSettings(enabled=True, default_input_policy="drop", default_forward_policy="drop", default_output_policy="accept")
    rule = FirewallRule(
        name="dual-stack-service",
        direction="input",
        action="accept",
        protocol="tcp",
        source="group:custom:dual",
        destination="any",
        destination_port="443",
        interface_name="eth2.50",
        priority=100,
        enabled=True,
    )
    groups = [
        {"id": "any", "name": "Any", "entries": ["any"]},
        {"id": "custom:dual", "name": "Dual stack clients", "entries": ["10.10.0.0/16", "2001:db8:10::/64"]},
    ]

    assert validate_firewall_state(settings, [rule], source_groups=groups) == []
    config = render_nftables_config(settings, [rule], source_groups=groups)

    assert 'iifname "eth2.50" ip saddr 10.10.0.0/16 tcp dport 443 accept comment "dual-stack-service"' in config
    assert 'iifname "eth2.50" ip6 saddr 2001:db8:10::/64 tcp dport 443 accept comment "dual-stack-service"' in config
    assert "ip saddr { 10.10.0.0/16, 2001:db8:10::/64 }" not in config
