"""Test dns dhcp behavior."""

import re
from ipaddress import ip_address

from atlaso.app.models import (
    DhcpOption,
    DhcpReservation,
    DhcpScope,
    DhcpSettings,
    DnsRecord,
    DnsSettings,
    NtpSettings,
    PhysicalInterface,
    VlanInterface,
)
from atlaso.app.services.dnsmasq import (
    DHCP_DENY_RESERVATION_DESCRIPTION_PREFIX,
    DNSMASQ_DNSSEC_TRUST_ANCHORS_PATH,
    DNSMASQ_LEASE_FILE_PATH,
    compact_dhcp_range_expression,
    dhcp_bind_target_families,
    dhcp_bind_target_names,
    dhcp_dns_upstream_required,
    dns_domain_warnings,
    dns_reverse_records,
    dump_dns_record_data,
    join_conditional_forwarders,
    parse_dhcp_range_expression,
    parse_dnsmasq_leases,
    parse_hosts_records,
    parse_zone_records,
    render_dnsmasq_config,
    render_zone_file,
    split_conditional_forwarders,
    validate_authoritative_dns_record,
    validate_dhcp_bind_targets,
    validate_dhcp_settings,
    validate_dns_listen_targets,
    validate_dns_record,
    validate_dns_settings,
)
from atlaso.app.services.ntp import (
    NTP_DEFAULT_UPSTREAM_SERVERS,
    dump_ntp_upstream_sources,
    ntp_upstream_sources,
    parse_ntp_source,
    render_ntp_config,
    validate_ntp_state,
)


def create_token(client, scopes):
    """Create token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Normalized authorization scopes granted or required by the operation.


    Returns:
        The created token.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "dns dhcp test token", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_dnsmasq_renderer_binds_dhcp_to_sitea_interface_only():
    """Verify that dnsmasq renderer binds dhcp to sitea interface only."""
    dns_settings = DnsSettings(
        enabled=True,
        listen_interface="eth1\neth2",
        listen_address="192.168.50.1\n192.168.60.1",
        domain="atlaso.internal\ncorp.lab",
        upstream_servers="1.1.1.1\n9.9.9.9",
    )
    dhcp_settings = DhcpSettings(
        enabled=True,
        interface_name="eth1",
        site_address="192.168.50.1",
        prefix_length=24,
        dns_server="192.168.50.1",
    )
    config = render_dnsmasq_config(
        dns_settings=dns_settings,
        dns_records=[
            DnsRecord(hostname="app.atlaso.internal", record_type="A", address="192.168.50.10"),
            DnsRecord(hostname="ipv6.atlaso.internal", record_type="AAAA", address="2001:db8::10"),
            DnsRecord(hostname="www.atlaso.internal", record_type="CNAME", address="app.atlaso.internal"),
        ],
        dhcp_settings=dhcp_settings,
        dhcp_scopes=[
            DhcpScope(
                name="SiteA",
                interface_name="eth1",
                site_address="192.168.50.1",
                prefix_length=24,
                range_expression="192.168.50.100-200",
                dns_server="192.168.50.1",
            )
        ],
        dhcp_reservations=[
            DhcpReservation(hostname="client1", mac_address="02:15:5d:00:20:20", ip_address="192.168.50.120"),
            DhcpReservation(
                hostname="deny-client.atlaso.internal",
                mac_address="02:15:5d:00:20:99",
                ip_address="192.168.50.199",
                enabled=False,
                description=f"{DHCP_DENY_RESERVATION_DESCRIPTION_PREFIX}02:15:5d:00:20:99.",
            ),
        ],
        dhcp_options=[DhcpOption(option_code="ntp-server", value="192.168.50.1")],
        conditional_forwarders="sddc.internal=192.168.10.10\ncorp.example=192.168.20.10#5353",
    )

    assert "interface=eth1" in config
    assert "interface=eth2" in config
    assert "interface=lo" in config
    assert "interface=eth0" not in config
    assert "listen-address=127.0.0.1" in config
    assert "listen-address=192.168.50.1" in config
    assert "listen-address=192.168.60.1" in config
    assert "domain=atlaso.internal" in config
    assert "domain=corp.lab" in config
    assert "local=/atlaso.internal/" in config
    assert "local=/corp.lab/" in config
    assert "dhcp-range=set:sitea,192.168.50.100,192.168.50.200,12h" in config
    assert "dhcp-option=tag:sitea,option:router,192.168.50.1" in config
    assert "dhcp-option=option:ntp-server,192.168.50.1" in config
    assert "host-record=app.atlaso.internal,192.168.50.10" in config
    assert "host-record=ipv6.atlaso.internal,2001:db8::10" in config
    assert "cname=www.atlaso.internal,app.atlaso.internal" in config
    assert "server=/sddc.internal/192.168.10.10" in config
    assert "server=/corp.example/192.168.20.10#5353" in config
    assert "ptr-record=" not in config
    assert f"dhcp-leasefile={DNSMASQ_LEASE_FILE_PATH}" in config
    assert "dhcp-host=02:15:5d:00:20:20,client1,192.168.50.120" in config
    assert "dhcp-host=02:15:5d:00:20:99,ignore" in config


def test_dnsmasq_renderer_excludes_records_owned_by_disabled_domains():
    """Verify that dnsmasq renderer excludes records owned by disabled domains."""
    config = render_dnsmasq_config(
        dns_settings=DnsSettings(
            enabled=True,
            domain="atlaso.internal",
            disabled_domains="disabled.internal",
        ),
        dns_records=[
            DnsRecord(hostname="active.atlaso.internal", record_type="A", address="192.168.50.10"),
            DnsRecord(hostname="disabled.internal", record_type="A", address="192.168.50.20"),
            DnsRecord(hostname="child.disabled.internal", record_type="A", address="192.168.50.21"),
        ],
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_reservations=[],
    )

    assert "host-record=active.atlaso.internal,192.168.50.10" in config
    assert "disabled.internal" not in config


def test_dnsmasq_renderer_emits_shared_authoritative_zones_and_generated_glue():
    """Verify that dnsmasq renderer emits shared authoritative zones and generated glue."""
    settings = DnsSettings(
        enabled=True,
        listen_interface="eth1\neth2",
        listen_address="192.168.50.1\n2001:db8::53",
        domain="atlaso.internal\nsitea.internal",
        authoritative=True,
        authoritative_server="ns1.atlaso.internal",
        authoritative_contact="hostmaster.atlaso.internal",
        authoritative_ttl=3600,
        authoritative_serial=2026072201,
        authoritative_refresh=1200,
        authoritative_retry=180,
        authoritative_expire=1209600,
    )

    config = render_dnsmasq_config(
        dns_settings=settings,
        dns_records=[DnsRecord(hostname="app.sitea.internal", record_type="A", address="192.168.50.20")],
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_reservations=[],
    )

    assert "auth-zone=atlaso.internal" in config
    assert "auth-zone=sitea.internal" in config
    assert "local=/atlaso.internal/" not in config
    assert "auth-server=ns1.atlaso.internal,eth1,eth2" in config
    assert "auth-soa=2026072201,hostmaster.atlaso.internal,1200,180,1209600" in config
    assert "auth-ttl=3600" in config
    assert "host-record=ns1.atlaso.internal,192.168.50.1" in config
    assert "host-record=ns1.atlaso.internal,2001:db8::53" in config
    assert "host-record=app.sitea.internal,192.168.50.20" in config


def test_authoritative_validation_rejects_bad_identity_timers_and_conflicting_glue():
    """Verify that authoritative validation rejects bad identity timers and conflicting glue."""
    settings = DnsSettings(
        enabled=True,
        listen_interface="eth1",
        listen_address="192.168.50.1",
        domain="atlaso.internal",
        authoritative=True,
        authoritative_server="ns1.outside.example",
        authoritative_contact="bad contact",
        authoritative_ttl=0,
        authoritative_serial=0,
        authoritative_refresh=1200,
        authoritative_retry=180,
        authoritative_expire=100,
    )
    errors = validate_dns_settings(settings, [])

    assert any("must belong to one of the managed domains" in error for error in errors)
    assert any("administrator must be a valid" in error for error in errors)
    assert any("TTL must be between" in error for error in errors)
    assert any("expire must be greater" in error for error in errors)
    assert any("serial must be between" in error for error in errors)

    settings.authoritative_server = "ns1.atlaso.internal"
    assert validate_authoritative_dns_record(settings, "ns1.atlaso.internal", "A", "192.168.50.99")
    assert validate_authoritative_dns_record(settings, "ns1.atlaso.internal", "CNAME", "other.atlaso.internal")
    assert validate_authoritative_dns_record(settings, "ns1.atlaso.internal", "A", "192.168.50.1") == []


def test_authoritative_zone_file_round_trip_ignores_matching_structural_records():
    """Verify that authoritative zone file round trip ignores matching structural records."""
    settings = DnsSettings(
        listen_address="192.168.50.1\n2001:db8::53",
        domain="atlaso.internal",
        authoritative=True,
        authoritative_server="ns1.atlaso.internal",
        authoritative_contact="hostmaster.atlaso.internal",
        authoritative_ttl=3600,
        authoritative_serial=2026072201,
        authoritative_refresh=1200,
        authoritative_retry=180,
        authoritative_expire=1209600,
    )
    zone_text = render_zone_file(
        "atlaso.internal",
        [{"hostname": "app.atlaso.internal", "host_label": "app", "record_type": "A", "address": "192.168.50.20", "enabled": True}],
        settings,
    )
    records, errors = parse_zone_records(zone_text, "atlaso.internal", settings)

    assert errors == []
    assert len(records) == 1
    assert records[0]["hostname"] == "app.atlaso.internal"
    assert "IN SOA" in zone_text
    assert "IN NS" in zone_text
    assert "ns1" in zone_text

    conflicting = zone_text.replace("hostmaster.atlaso.internal.", "admin.atlaso.internal.")
    _, errors = parse_zone_records(conflicting, "atlaso.internal", settings)
    assert any("SOA metadata must match" in error for error in errors)

    second_zone = render_zone_file("sitea.internal", [], settings)
    assert re.search(r"ns1\.atlaso\.internal\.\s+IN A\s+192\.168\.50\.1", second_zone)
    assert "@                        IN A" not in second_zone
    second_records, second_errors = parse_zone_records(second_zone, "sitea.internal", settings)
    assert second_errors == []
    assert second_records == []


def test_dnsmasq_renderer_uses_dhcp_upstreams_when_desired_upstreams_empty():
    """Verify that dnsmasq renderer uses dhcp upstreams when desired upstreams empty."""
    config = render_dnsmasq_config(
        dns_settings=DnsSettings(
            enabled=True,
            listen_interface="eth1",
            listen_address="192.168.87.200",
            domain="atlaso.internal",
            upstream_servers="",
        ),
        dns_records=[],
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_reservations=[],
        fallback_upstream_servers=["127.0.0.1", "::1", "fe80::53", "192.168.167.2", "192.168.167.2"],
        require_dhcp_upstream=True,
    )

    assert "server=192.168.167.2" in config
    assert config.count("server=192.168.167.2") == 1
    assert "server=127.0.0.1" not in config
    assert "server=::1" not in config
    assert "server=fe80::53" not in config
    assert "# atlaso-dhcp-upstream-required" in config


def test_dnsmasq_validation_fails_closed_when_required_dhcp_upstream_is_unavailable():
    """Verify that dnsmasq validation fails closed when required dhcp upstream is unavailable."""
    settings = DnsSettings(enabled=True, upstream_servers="")

    errors = validate_dns_settings(
        settings,
        [],
        fallback_upstream_servers=["127.0.0.1", "fe80::53", "malformed"],
        require_dhcp_upstream=True,
    )

    assert any("systemd-networkd lease did not provide one" in error for error in errors)
    assert dhcp_dns_upstream_required(settings, {"ipv4_method": "dhcp"}) is True


def test_dnsmasq_renderer_filters_unusable_configured_upstreams():
    """Verify that dnsmasq renderer filters unusable configured upstreams."""
    settings = DnsSettings(
        enabled=True,
        listen_interface="eth1",
        listen_address="192.168.87.200",
        domain="atlaso.internal",
        upstream_servers="127.0.0.1\n::1\nfe80::53\n192.168.167.2",
    )
    config = render_dnsmasq_config(
        dns_settings=settings,
        dns_records=[],
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_reservations=[],
    )
    errors = validate_dns_settings(settings, [])

    assert "server=192.168.167.2" in config
    assert "server=127.0.0.1" not in config
    assert "server=fe80::53" not in config
    assert "upstream server fe80::53 must not be a link-local address." in errors


def test_ntp_renderer_supports_nts_sources_server_and_hardening():
    """Verify that ntp renderer supports nts sources server and hardening."""
    settings = NtpSettings(
        enabled=True,
        hostname="ntp.atlaso.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=123,
        allow_clients="any",
        nts_ke_port=4460,
        config_path="/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf",
        upstream_sources_json=dump_ntp_upstream_sources(
            [
                {"source": "time.cloudflare.com", "enabled": True, "use_nts": True, "description": "secure"},
                {"source": "time.google.com", "enabled": True, "use_nts": False, "description": ""},
                {"source": "disabled.example.com", "enabled": False, "use_nts": True, "description": ""},
            ]
        ),
        nts_server_enabled=True,
        nts_server_cert_path="/etc/atlaso/certs/ntp.pem",
        nts_server_key_path="/etc/atlaso/certs/ntp.key",
        minsources=2,
    )

    config = render_ntp_config(settings)

    assert "driftfile /var/lib/ntp/ntp.drift" in config
    assert "interface ignore wildcard" in config
    assert "restrict source kod limited nomodify noquery" in config
    assert "interface listen 192.168.50.1" in config
    assert "restrict default kod limited nomodify noquery" in config
    assert "server time.cloudflare.com iburst nts" in config
    assert "server time.google.com iburst" in config
    assert "disabled.example.com" not in config
    assert "nts enable" in config
    assert "nts cert /etc/atlaso/certs/ntp.pem" in config
    assert "nts key /etc/atlaso/certs/ntp.key" in config
    assert "nts cookie /var/lib/ntp/nts-keys" in config
    assert "tos minsane 2" in config


def test_ntp_default_server_fallback_uses_nts_sources():
    """Verify that ntp default server fallback uses nts sources."""
    settings = NtpSettings(
        hostname="ntp.atlaso.internal",
        upstream_servers=NTP_DEFAULT_UPSTREAM_SERVERS,
        upstream_sources_json="",
    )

    sources = ntp_upstream_sources(settings)
    config = render_ntp_config(settings)

    assert [source["source"] for source in sources] == [
        "time.cloudflare.com",
        "nts.netnod.se",
        "ptbtime1.ptb.de",
        "0.pool.ntp.org",
        "1.pool.ntp.org",
        "2.pool.ntp.org",
        "3.pool.ntp.org",
        "time.google.com",
        "time.nist.gov",
        "time.facebook.com",
    ]
    assert [source["use_nts"] for source in sources[:3]] == [True, True, True]
    assert sources[2]["enabled"] is False
    assert all(source["enabled"] is False and source["use_nts"] is False for source in sources[3:])
    assert "server time.cloudflare.com iburst nts" in config
    assert "server nts.netnod.se iburst nts" in config
    assert "server ptbtime1.ptb.de" not in config
    assert "server 0.pool.ntp.org" not in config
    assert "server time.google.com" not in config


def test_ntp_custom_server_fallback_remains_plain_ntp():
    """Verify that ntp custom server fallback remains plain ntp."""
    settings = NtpSettings(upstream_servers="time.google.com", upstream_sources_json="")

    sources = ntp_upstream_sources(settings)

    assert sources == [
        {
            "id": "source-1",
            "source": "time.google.com",
            "enabled": True,
            "use_nts": False,
            "description": "",
        }
    ]


def test_ntp_rejects_nts_source_ip_and_renders_disabled_state_without_servers():
    """Verify that ntp rejects nts source ip and renders disabled state without servers."""
    invalid = NtpSettings(
        enabled=True,
        hostname="ntp.atlaso.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=123,
        allow_clients="any",
        nts_server_enabled=False,
        nts_ke_port=4460,
        config_path="/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf",
        upstream_sources_json=dump_ntp_upstream_sources(
            [{"source": "192.0.2.10", "enabled": True, "use_nts": True, "description": "invalid NTS identity"}]
        ),
    )
    assert "certificate-valid DNS hostname" in "\n".join(validate_ntp_state(invalid, {"eth2"}))

    disabled = NtpSettings(enabled=False, hostname="ntp.atlaso.internal", listen_interface="", listen_address="", upstream_servers="", upstream_sources_json="", allow_clients="any")
    config = render_ntp_config(disabled)
    assert "# Atlaso NTP enabled: false" in config
    assert "server " not in config


def test_ntp_sources_accept_addresses_fqdns_and_optional_ports():
    """Verify that ntp sources accept addresses fqdns and optional ports."""
    settings = NtpSettings(
        enabled=True,
        hostname="ntp.atlaso.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=123,
        allow_clients="any",
        nts_ke_port=4460,
        config_path="/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf",
        upstream_sources_json=dump_ntp_upstream_sources(
            [
                {"source": "time.example.com:7443", "enabled": True, "use_nts": True, "description": "custom NTS-KE"},
                {"source": "192.0.2.10:123", "enabled": True, "use_nts": False, "description": "IPv4"},
                {"source": "2001:db8::10", "enabled": True, "use_nts": False, "description": "IPv6"},
                {"source": "[2001:db8::20]:123", "enabled": True, "use_nts": False, "description": "IPv6 port"},
            ]
        ),
    )

    assert validate_ntp_state(settings, {"eth2"}) == []
    config = render_ntp_config(settings)
    assert "server time.example.com:7443 iburst nts" in config
    assert "server 192.0.2.10:123 iburst" in config
    assert "server [2001:db8::10] iburst" in config
    assert "server [2001:db8::20]:123 iburst" in config
    assert parse_ntp_source("time.example.com:7443") == ("time.example.com", 7443, False)


def test_ntp_sources_reject_invalid_identity_port_and_nts_ip():
    """Verify that ntp sources reject invalid identity port and nts ip."""
    settings = NtpSettings(
        enabled=True,
        hostname="ntp.atlaso.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=123,
        allow_clients="any",
        nts_ke_port=4460,
        config_path="/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf",
        upstream_sources_json=dump_ntp_upstream_sources(
            [
                {"source": "not-a-fqdn", "enabled": True, "use_nts": False, "description": ""},
                {"source": "time.example.com:70000", "enabled": True, "use_nts": False, "description": ""},
                {"source": "192.0.2.10:4460", "enabled": True, "use_nts": True, "description": ""},
            ]
        ),
    )

    errors = "\n".join(validate_ntp_state(settings, {"eth2"}))
    assert "NTP upstream server not-a-fqdn" in errors
    assert "NTP upstream server time.example.com:70000" in errors
    assert "NTS upstream 192.0.2.10:4460 must use a certificate-valid DNS hostname" in errors


def test_dnsmasq_renderer_supports_dnssec_rebind_logging_and_extended_records():
    """Verify that dnsmasq renderer supports dnssec rebind logging and extended records."""
    dns_settings = DnsSettings(
        enabled=True,
        listen_interface="eth1",
        listen_address="192.168.50.1",
        domain="atlaso.internal",
        upstream_servers="1.1.1.1",
        dnssec_enabled=True,
        rebind_protection_enabled=True,
        rebind_domain_exemptions="corp.example\nsddc.internal",
        query_logging_mode="queries-extra",
    )
    records = [
        DnsRecord(hostname="txt.atlaso.internal", record_type="TXT", address="hello world"),
        DnsRecord(hostname="_ldap._tcp.atlaso.internal", record_type="SRV", address="ldap.atlaso.internal 389 10 20", record_data_json=dump_dns_record_data("SRV", "ldap.atlaso.internal 389 10 20")),
        DnsRecord(hostname="atlaso.internal", record_type="MX", address="mail.atlaso.internal 10", record_data_json=dump_dns_record_data("MX", "mail.atlaso.internal 10")),
        DnsRecord(hostname="atlaso.internal", record_type="CAA", address='0 issue "lab-ca"', record_data_json=dump_dns_record_data("CAA", '0 issue "lab-ca"')),
        DnsRecord(hostname="10.50.168.192.in-addr.arpa", record_type="PTR", address="host.atlaso.internal"),
    ]

    config = render_dnsmasq_config(
        dns_settings=dns_settings,
        dns_records=records,
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_reservations=[],
    )

    assert "log-queries=extra" in config
    assert "dnssec" in config
    assert f"conf-file={DNSMASQ_DNSSEC_TRUST_ANCHORS_PATH}" in config
    assert "stop-dns-rebind" in config
    assert "rebind-domain-ok=/corp.example/" in config
    assert "rebind-domain-ok=/sddc.internal/" in config
    assert 'txt-record=txt.atlaso.internal,"hello world"' in config
    assert "srv-host=_ldap._tcp.atlaso.internal,ldap.atlaso.internal,389,10,20" in config
    assert "mx-host=atlaso.internal,mail.atlaso.internal,10" in config
    assert 'caa-record=atlaso.internal,0,issue,"lab-ca"' in config
    assert "ptr-record=10.50.168.192.in-addr.arpa,host.atlaso.internal" in config
    assert "server=::1" not in config


def test_zone_file_round_trips_mx_srv_standard_rdata_order():
    """Verify that zone file round trips mx srv standard rdata order."""
    records = [
        {
            "host_label": "@",
            "record_type": "MX",
            "address": "mail.atlaso.internal 10",
            "record_data": {"target": "mail.atlaso.internal", "preference": "10"},
            "enabled": True,
        },
        {
            "host_label": "_ldap._tcp",
            "record_type": "SRV",
            "address": "ldap.atlaso.internal 389 10 20",
            "record_data": {"target": "ldap.atlaso.internal", "port": "389", "priority": "10", "weight": "20"},
            "enabled": True,
        },
    ]

    zone = render_zone_file("atlaso.internal", records)

    assert "@                        IN MX    10 mail.atlaso.internal" in zone
    assert "_ldap._tcp               IN SRV   10 20 389 ldap.atlaso.internal" in zone

    parsed_records, errors = parse_zone_records(
        "\n".join(
            [
                "$ORIGIN atlaso.internal.",
                "@ IN MX 10 mail.atlaso.internal.",
                "_ldap._tcp IN SRV 10 20 389 ldap.atlaso.internal.",
            ]
        ),
        "atlaso.internal",
    )

    assert errors == []
    assert {
        "hostname": "atlaso.internal",
        "record_type": "MX",
        "address": "mail.atlaso.internal. 10",
        "record_data_json": dump_dns_record_data("MX", "mail.atlaso.internal. 10"),
        "description": "Imported from zone editor",
        "enabled": True,
    } in parsed_records
    assert {
        "hostname": "_ldap._tcp.atlaso.internal",
        "record_type": "SRV",
        "address": "ldap.atlaso.internal. 389 10 20",
        "record_data_json": dump_dns_record_data("SRV", "ldap.atlaso.internal. 389 10 20"),
        "description": "Imported from zone editor",
        "enabled": True,
    } in parsed_records


def test_dnsmasq_renderer_keeps_configured_upstreams_over_dhcp_fallback():
    """Verify that dnsmasq renderer keeps configured upstreams over dhcp fallback."""
    config = render_dnsmasq_config(
        dns_settings=DnsSettings(
            enabled=True,
            listen_interface="eth1",
            listen_address="192.168.87.200",
            domain="atlaso.internal",
            upstream_servers="1.1.1.1",
        ),
        dns_records=[],
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_reservations=[],
        fallback_upstream_servers=["192.168.167.2"],
    )

    assert "server=1.1.1.1" in config
    assert "server=192.168.167.2" not in config
    assert "# atlaso-dhcp-upstream-required" not in config


def test_dnsmasq_renderer_supports_ipv6_dhcp_zones():
    """Verify that dnsmasq renderer supports ipv6 dhcp zones."""
    scope = DhcpScope(
        name="IPv6Lab",
        address_family="ipv6",
        interface_name="eth2",
        site_address="fd00:50::1",
        prefix_length=64,
        range_expression="fd00:50::100-fd00:50::1ff, fd00:50::30",
        lease_time="12h",
        domain_name="atlaso.internal",
        dns_server="fd00:50::1",
        ntp_server="fd00:50::1",
        enabled=True,
    )
    reservations = [DhcpReservation(hostname="v6client", mac_address="02:15:5d:00:20:21", ip_address="fd00:50::120")]

    errors = validate_dhcp_settings(DhcpSettings(enabled=True), reservations, [scope])
    config = render_dnsmasq_config(
        dns_settings=DnsSettings(domain="atlaso.internal"),
        dns_records=[],
        dhcp_settings=DhcpSettings(enabled=True),
        dhcp_scopes=[scope],
        dhcp_reservations=reservations,
    )

    assert errors == []
    assert "enable-ra" in config
    assert "interface=eth2" in config
    assert "dhcp-range=set:ipv6lab,fd00:50::100,fd00:50::1ff,64,12h" in config
    assert "dhcp-range=set:ipv6lab,fd00:50::30,fd00:50::30,64,12h" in config
    assert "dhcp-option=tag:ipv6lab,option6:dns-server,[fd00:50::1]" in config
    assert "dhcp-option=tag:ipv6lab,option6:domain-search,atlaso.internal" in config
    assert "dhcp-option=tag:ipv6lab,option6:ntp-server,[fd00:50::1]" in config
    assert "dhcp-option=tag:ipv6lab,option:router" not in config
    assert "dhcp-host=02:15:5d:00:20:21,v6client,[fd00:50::120]" in config


def test_dhcp_range_expression_supports_ipv4_prefix_suffix_syntax():
    """Verify that dhcp range expression supports ipv4 prefix suffix syntax."""
    scope_24 = DhcpScope(
        name="Site24",
        site_address="192.168.87.1",
        prefix_length=24,
        range_expression="192.168.87.100-200, 192.168.87.222, 192.168.87.226-228",
    )
    scope_16 = DhcpScope(
        name="Site16",
        site_address="192.168.87.1",
        prefix_length=16,
        range_expression="192.168.87.100-87.200, 192.168.87.222, 192.168.87.226-87.228",
    )

    assert parse_dhcp_range_expression(scope_24) == (
        [],
        [
            (ip_address("192.168.87.100"), ip_address("192.168.87.200")),
            (ip_address("192.168.87.222"), ip_address("192.168.87.222")),
            (ip_address("192.168.87.226"), ip_address("192.168.87.228")),
        ],
    )
    assert parse_dhcp_range_expression(scope_16) == (
        [],
        [
            (ip_address("192.168.87.100"), ip_address("192.168.87.200")),
            (ip_address("192.168.87.222"), ip_address("192.168.87.222")),
            (ip_address("192.168.87.226"), ip_address("192.168.87.228")),
        ],
    )
    assert compact_dhcp_range_expression(scope_24) == (
        "192.168.87.100-192.168.87.200, 192.168.87.222, 192.168.87.226-192.168.87.228"
    )


def test_dhcp_range_expression_supports_full_ipv4_ranges_and_single_addresses():
    """Verify that dhcp range expression supports full ipv4 ranges and single addresses."""
    scope = DhcpScope(
        name="SiteFull",
        site_address="192.168.87.1",
        prefix_length=24,
        range_expression="192.168.87.100-192.168.87.200, 192.168.87.30",
    )

    assert parse_dhcp_range_expression(scope) == (
        [],
        [
            (ip_address("192.168.87.100"), ip_address("192.168.87.200")),
            (ip_address("192.168.87.30"), ip_address("192.168.87.30")),
        ],
    )
    assert compact_dhcp_range_expression(scope) == "192.168.87.100-192.168.87.200, 192.168.87.30"


def test_dhcp_range_expression_supports_full_ipv6_ranges_and_single_addresses():
    """Verify that dhcp range expression supports full ipv6 ranges and single addresses."""
    scope = DhcpScope(
        name="IPv6Full",
        address_family="ipv6",
        site_address="fd00:50::1",
        prefix_length=64,
        range_expression="fd00:50::100-fd00:50::200, fd00:50::30",
    )

    assert parse_dhcp_range_expression(scope) == (
        [],
        [
            (ip_address("fd00:50::100"), ip_address("fd00:50::200")),
            (ip_address("fd00:50::30"), ip_address("fd00:50::30")),
        ],
    )
    assert compact_dhcp_range_expression(scope) == "fd00:50::100-fd00:50::200, fd00:50::30"


def test_dns_conditional_forwarders_accept_multiple_servers_per_domain():
    """Verify that dns conditional forwarders accept multiple servers per domain."""
    forwarders = split_conditional_forwarders("sddc.internal=192.168.10.10,192.168.10.11")

    assert forwarders == [
        {"domain": "sddc.internal", "server": "192.168.10.10"},
        {"domain": "sddc.internal", "server": "192.168.10.11"},
    ]
    assert join_conditional_forwarders(forwarders) == "sddc.internal=192.168.10.10,192.168.10.11"

    config = render_dnsmasq_config(
        dns_settings=DnsSettings(domain="atlaso.internal"),
        dns_records=[],
        dhcp_settings=DhcpSettings(enabled=False),
        dhcp_reservations=[],
        conditional_forwarders="sddc.internal=192.168.10.10,192.168.10.11",
    )

    assert "server=/sddc.internal/192.168.10.10" in config
    assert "server=/sddc.internal/192.168.10.11" in config
    assert "server=/sddc.internal/192.168.10.10,192.168.10.11" not in config


def test_dnsmasq_renderer_only_marks_dhcp_authoritative_when_dhcp_enabled():
    """Verify that dnsmasq renderer only marks dhcp authoritative when dhcp enabled."""
    dns_settings = DnsSettings(domain="atlaso.internal", authoritative=True)
    dhcp_settings = DhcpSettings(enabled=False, authoritative=True)

    config = render_dnsmasq_config(
        dns_settings=dns_settings,
        dns_records=[],
        dhcp_settings=dhcp_settings,
        dhcp_reservations=[],
    )

    assert "dhcp-authoritative" not in config
    assert "dhcp-range=" not in config


def test_dnsmasq_renderer_adds_esxi_pxe_boot_options():
    """Verify that dnsmasq renderer adds esxi pxe boot options."""
    pxe_scope = DhcpScope(
        id=50,
        name="PXE",
        interface_name="eth1",
        site_address="192.168.50.1",
        prefix_length=24,
        range_expression="192.168.50.100-200",
        lease_time="12h",
        domain_name="atlaso.internal",
        dns_server="192.168.50.1",
        ntp_server="192.168.50.1",
    )
    config = render_dnsmasq_config(
        dns_settings=DnsSettings(domain="atlaso.internal", listen_interface="eth1"),
        dns_records=[],
        dhcp_settings=DhcpSettings(
            enabled=True,
            interface_name="eth1",
            site_address="192.168.50.1",
            prefix_length=24,
            dns_server="192.168.50.1",
        ),
        dhcp_scopes=[pxe_scope],
        dhcp_reservations=[],
        esxi_pxe_boot={
            "enabled": True,
            "dhcp_scope_id": pxe_scope.id,
            "hostname": "esxi-pxe.atlaso.internal",
            "listen_address": "192.168.50.1",
            "tftp_root": "/var/lib/atlaso/pxe/tftp",
            "bios_bootfile": "undionly.kpxe",
            "uefi_bootfile": "snponly.efi",
            "bios_second_stage_bootfile": "pxelinux.0",
            "uefi_second_stage_bootfile": "mboot.efi",
            "native_uefi_http_enabled": True,
            "effective_native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/snponly.efi",
            "host_bootfiles": [
                {
                    "mac_address": "00:50:56:aa:bb:cc",
                    "tag": "esxi-005056aabbcc",
                    "uefi_second_stage_bootfile": "01-00-50-56-aa-bb-cc/mboot.efi",
                    "native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/01-00-50-56-aa-bb-cc/mboot.efi",
                }
            ],
        },
    )

    assert "enable-tftp=eth1" in config
    assert "tftp-root=/var/lib/atlaso/pxe/tftp" in config
    assert "dhcp-userclass=set:ipxe,iPXE" in config
    assert "dhcp-match=set:ipxe,175" in config
    assert "dhcp-match=set:efi-x86_64,option:client-arch,7" in config
    assert "dhcp-match=set:efi-x86_64,option:client-arch,9" in config
    assert "dhcp-vendorclass=set:uefi-http,HTTPClient" in config
    assert "dhcp-match=set:uefi-http-x64,option:client-arch,16" in config
    assert "dhcp-boot=tag:pxe,tag:uefi-http,tag:uefi-http-x64,http://192.168.50.1:8080/pxe/esxi/snponly.efi" in config
    assert "dhcp-option=tag:pxe,66,esxi-pxe.atlaso.internal" in config
    assert (
        "dhcp-boot=tag:pxe,tag:ipxe,"
        "http://192.168.50.1:8080/pxe/boot.ipxe?mac=${net0/mac}"
        "&firmware=${platform}"
    ) in config
    assert "dhcp-boot=tag:pxe,tag:!ipxe,tag:efi-x86_64,snponly.efi,esxi-pxe.atlaso.internal,192.168.50.1" in config
    assert "dhcp-boot=tag:pxe,tag:!ipxe,tag:!efi-x86_64,undionly.kpxe,esxi-pxe.atlaso.internal,192.168.50.1" in config
    assert "dhcp-mac=set:esxi-005056aabbcc,00:50:56:aa:bb:cc" in config
    assert "mboot.efi" not in "\n".join(
        line for line in config.splitlines() if line.startswith("dhcp-boot=")
    )


def test_dnsmasq_lease_parser_tracks_active_and_expired_leases():
    """Verify that dnsmasq lease parser tracks active and expired leases."""
    leases = parse_dnsmasq_leases(
        "1893456000 02:15:5d:00:20:30 192.168.50.130 api-client.atlaso.internal 01:02:15:5d:00:20:30\n"
        "1 02:15:5d:00:20:31 192.168.50.131 old.atlaso.internal *"
    )

    assert leases[0]["status"] == "active"
    assert leases[0]["hostname"] == "api-client.atlaso.internal"
    assert leases[1]["status"] == "expired"
    assert leases[1]["client_id"] == ""


def test_disabled_dhcp_allows_blank_reset_defaults():
    """Verify that disabled dhcp allows blank reset defaults."""
    errors = validate_dhcp_settings(
        DhcpSettings(
            enabled=False,
            interface_name="",
            site_address="",
            dns_server="",
        ),
        [],
        [],
        [],
    )

    assert errors == []


def test_dnsmasq_renderer_supports_multiple_dhcp_ip_zones():
    """Verify that dnsmasq renderer supports multiple dhcp ip zones."""
    dns_settings = DnsSettings(listen_interface="eth1", domain="atlaso.internal")
    dhcp_settings = DhcpSettings(enabled=True, authoritative=True)
    config = render_dnsmasq_config(
        dns_settings=dns_settings,
        dns_records=[],
        dhcp_settings=dhcp_settings,
        dhcp_reservations=[],
        dhcp_scopes=[
            DhcpScope(
                id=10,
                name="SiteA",
                interface_name="eth1",
                site_address="192.168.50.1",
                prefix_length=24,
                range_expression="192.168.50.100-200, 192.168.50.222",
                lease_time="12h",
                domain_name="atlaso.internal",
                dns_server="192.168.50.1",
            ),
            DhcpScope(
                id=11,
                name="SiteB",
                interface_name="eth2",
                site_address="192.168.60.1",
                prefix_length=24,
                range_expression="192.168.60.100-200",
                lease_time="8h",
                domain_name="siteb.internal",
                dns_server="192.168.60.1",
                ntp_server="192.168.60.1",
            ),
        ],
        dhcp_options=[DhcpOption(scope_id=11, option_code="ntp-server", value="192.168.60.1")],
    )

    assert "interface=eth1" in config
    assert "interface=eth2" in config
    assert "dhcp-range=set:sitea,192.168.50.100,192.168.50.200,12h" in config
    assert "dhcp-range=set:sitea,192.168.50.222,192.168.50.222,12h" in config
    assert "dhcp-range=set:siteb,192.168.60.100,192.168.60.200,8h" in config
    assert "dhcp-option=tag:siteb,option:domain-name,siteb.internal" in config
    assert "dhcp-option=tag:siteb,option:ntp-server,192.168.60.1" in config


def test_dns_reverse_records_include_ipv4_and_ipv6_only():
    """Verify that dns reverse records include ipv4 and ipv6 only."""
    records = dns_reverse_records(
        [
            DnsRecord(hostname="app.atlaso.internal", record_type="A", address="192.168.50.10"),
            DnsRecord(hostname="ipv6.atlaso.internal", record_type="AAAA", address="2001:db8::10"),
            DnsRecord(hostname="alias.atlaso.internal", record_type="CNAME", address="app.atlaso.internal"),
        ]
    )

    ptr_names = {record["ptr_name"] for record in records}
    assert "10.50.168.192.in-addr.arpa" in ptr_names
    assert "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" in ptr_names
    assert all(record["target"] != "alias.atlaso.internal" for record in records)


def test_dns_dhcp_validation_reports_bad_addresses():
    """Verify that dns dhcp validation reports bad addresses."""
    dns_settings = DnsSettings(
        listen_interface="eth1",
        listen_address="bad-ip",
        domain="atlaso.internal",
        upstream_servers="not-an-ip",
    )
    dhcp_settings = DhcpSettings(
        enabled=True,
        interface_name="eth1",
        site_address="192.168.50.1",
        prefix_length=24,
        dns_server="192.168.60.1",
    )
    dhcp_scope = DhcpScope(
        name="BadRange",
        interface_name="eth1",
        site_address="192.168.50.1",
        prefix_length=24,
        range_expression="192.168.51.10-192.168.50.20",
        dns_server="192.168.60.1",
    )

    errors = validate_dns_settings(dns_settings, [], "sddc.internal=not-an-ip\nbad=192.168.1.10#70000") + validate_dhcp_settings(dhcp_settings, [], [dhcp_scope])

    assert any("DNS listen address" in error for error in errors)
    assert any("upstream server" in error for error in errors)
    assert any("conditional forwarder sddc.internal server" in error for error in errors)
    assert any("conditional forwarder bad server port" in error for error in errors)
    assert any("range 192.168.51.10-192.168.50.20 must stay inside" in error for error in errors)
    assert any("DNS server" in error for error in errors)


def test_dns_listen_target_validation_rejects_trunks_and_unknown_targets():
    """Verify that dns listen target validation rejects trunks and unknown targets."""
    settings = DnsSettings(enabled=True, listen_interface="eth1\neth2\nmissing", domain="atlaso.internal")

    errors = validate_dns_listen_targets(settings, {"eth1"})

    assert "DNS listen interface eth1" not in "\n".join(errors)
    assert any("DNS listen interface eth2 is not a valid bind target" in error for error in errors)
    assert any("DNS listen interface missing is not a valid bind target" in error for error in errors)


def test_dhcp_bind_target_validation_accepts_access_physical_and_vlans():
    """Verify that dhcp bind target validation accepts access physical and vlans."""
    physical = [
        PhysicalInterface(name="eth0", mode="access", ip_cidr="192.168.49.1/24", mac_address="00:00:00:00:00:01"),
        PhysicalInterface(name="eth1", mode="trunk", ip_cidr="192.168.60.1/24", mac_address="00:00:00:00:00:02"),
        PhysicalInterface(name="eth2", mode="access", ip_cidr="192.168.50.1/24", ipv6_cidr="fd00:50::1/64", mac_address="00:00:00:00:00:03"),
        PhysicalInterface(name="eth3", mode="access", ip_cidr="", mac_address="00:00:00:00:00:04"),
    ]
    vlans = [
        VlanInterface(name="eth1.20", parent_interface="eth1", vlan_id=20, ip_cidr="192.168.20.1/24", enabled=True),
        VlanInterface(name="eth1.30", parent_interface="eth1", vlan_id=30, ip_cidr="", enabled=True),
        VlanInterface(name="eth1.40", parent_interface="eth1", vlan_id=40, ip_cidr="192.168.40.1/24", enabled=False),
    ]

    targets = dhcp_bind_target_names(physical, vlans)
    target_families = dhcp_bind_target_families(physical, vlans)

    assert targets == {"eth0", "eth2", "eth1.20"}
    assert target_families["eth2"] == {"ipv4", "ipv6"}
    assert validate_dhcp_bind_targets(
        DhcpSettings(enabled=True),
        [
            DhcpScope(name="SiteA", interface_name="eth2"),
            DhcpScope(name="IPv6Lab", address_family="ipv6", interface_name="eth2", site_address="fd00:50::1", prefix_length=64, range_expression="fd00:50::100-fd00:50::1ff", dns_server="fd00:50::1"),
            DhcpScope(name="SiteB", interface_name="eth1.20"),
        ],
        target_families,
    ) == []
    assert any(
        "does not have a matching IPv6 CIDR" in error
        for error in validate_dhcp_bind_targets(
            DhcpSettings(enabled=True),
            [DhcpScope(name="BadIPv6", address_family="ipv6", interface_name="eth1.20")],
            target_families,
        )
    )


def test_dhcp_bind_target_validation_rejects_trunks_missing_ip_and_unknown_targets():
    """Verify that dhcp bind target validation rejects trunks missing ip and unknown targets."""
    errors = validate_dhcp_bind_targets(
        DhcpSettings(enabled=True),
        [
            DhcpScope(name="Trunk", interface_name="eth1"),
            DhcpScope(name="MissingIp", interface_name="eth3"),
            DhcpScope(name="Unknown", interface_name="missing"),
        ],
        {"eth2"},
    )

    assert any("DHCP IP zone Trunk interface eth1 is not a valid bind target" in error for error in errors)
    assert any("DHCP IP zone MissingIp interface eth3 is not a valid bind target" in error for error in errors)
    assert any("DHCP IP zone Unknown interface missing is not a valid bind target" in error for error in errors)


def test_dns_domain_warnings_flag_local_domains_for_vcf():
    """Verify that dns domain warnings flag local domains for vcf."""
    assert dns_domain_warnings(["atlaso.internal"]) == []

    warnings = dns_domain_warnings(["atlaso.local", "vcf.internal"])

    assert len(warnings) == 1
    assert "atlaso.local" in warnings[0]
    assert "VCF" in warnings[0]
    assert "RFC 6762" in warnings[0]
    assert "RFC 6761" in warnings[0]
    assert "ICANN/IANA" in warnings[0]
    assert ".internal" in warnings[0]


def test_dns_record_validation_distinguishes_ipv4_and_ipv6():
    """Verify that dns record validation distinguishes ipv4 and ipv6."""
    assert validate_dns_record("app.atlaso.internal", "A", "192.168.50.10") == []
    assert validate_dns_record("ipv6.atlaso.internal", "AAAA", "2001:db8::10") == []
    assert validate_dns_record("www.atlaso.internal", "CNAME", "app.atlaso.internal") == []

    a_errors = validate_dns_record("bad-a.atlaso.internal", "A", "2001:db8::20")
    aaaa_errors = validate_dns_record("bad-aaaa.atlaso.internal", "AAAA", "192.168.50.20")
    cname_errors = validate_dns_record("bad-cname.atlaso.internal", "CNAME", "192.168.50.30")

    assert any("must use an IPv4 address" in error for error in a_errors)
    assert any("must use an IPv6 address" in error for error in aaaa_errors)
    assert any("must point to a hostname" in error for error in cname_errors)


def test_hosts_file_parser_supports_aliases_comments_and_ipv6():
    """Verify that hosts file parser supports aliases comments and ipv6."""
    records, errors = parse_hosts_records(
        """
        # comment
        192.168.50.10 app.atlaso.internal app
        2001:db8::10 ipv6.atlaso.internal
        bad-ip broken.atlaso.internal
        """
    )

    assert any("Line 5 address" in error for error in errors)
    assert {"hostname": "app.atlaso.internal", "record_type": "A", "address": "192.168.50.10", "description": "Imported from hosts editor", "enabled": True} in records
    assert {"hostname": "app", "record_type": "A", "address": "192.168.50.10", "description": "Imported from hosts editor", "enabled": True} in records
    assert {"hostname": "ipv6.atlaso.internal", "record_type": "AAAA", "address": "2001:db8::10", "description": "Imported from hosts editor", "enabled": True} in records


def test_dns_api_requires_scope_and_returns_config_preview(client):
    """Verify that dns api requires scope and returns config preview.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token = create_token(client, ["read:dashboard"])
    denied = client.get("/api/v1/dns/status", headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 403

    dns_token = create_token(client, ["read:dns", "write:dns"])
    status = client.get("/api/v1/dns/status", headers={"Authorization": f"Bearer {dns_token}"})
    assert status.status_code == 200
    assert status.json()["domain"] == "atlaso.internal"

    created = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "api.atlaso.internal", "record_type": "A", "address": "192.168.50.30"},
    )
    assert created.status_code == 201, created.text
    same_owner_different_value = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "API.atlaso.internal", "record_type": "a", "address": "192.168.50.31"},
    )
    assert same_owner_different_value.status_code == 201, same_owner_different_value.text
    duplicate = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "API.atlaso.internal", "record_type": "a", "address": "192.168.50.30"},
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"]

    wrong_family = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "wrong-family.atlaso.internal", "record_type": "A", "address": "2001:db8::30"},
    )
    assert wrong_family.status_code == 422
    assert "IPv4" in wrong_family.json()["detail"]

    cname = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "alias.atlaso.internal", "record_type": "CNAME", "address": "api.atlaso.internal"},
    )
    assert cname.status_code == 201, cname.text
    assert cname.json()["record_type"] == "CNAME"

    forwarder_settings = client.patch(
        "/api/v1/dns/settings",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"conditional_forwarders": [{"domain": "sddc.internal", "server": "192.168.10.10"}]},
    )
    assert forwarder_settings.status_code == 200
    assert forwarder_settings.json()["conditional_forwarders"] == [
        {"domain": "sddc.internal", "server": "192.168.10.10"}
    ]

    validation = client.post("/api/v1/dns/validate", headers={"Authorization": f"Bearer {dns_token}"})
    assert validation.status_code == 200
    assert validation.json()["valid"] is True
    assert validation.json()["warnings"] == []
    assert "api.atlaso.internal" in validation.json()["config_preview"]
    assert "cname=alias.atlaso.internal,api.atlaso.internal" in validation.json()["config_preview"]
    assert "server=/sddc.internal/192.168.10.10" in validation.json()["config_preview"]

    settings = client.patch(
        "/api/v1/dns/settings",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"domain": "vcf.local"},
    )
    assert settings.status_code == 200
    local_validation = client.post("/api/v1/dns/validate", headers={"Authorization": f"Bearer {dns_token}"})
    assert local_validation.status_code == 200
    assert "vcf.local" in local_validation.json()["warnings"][0]
    assert "RFC 6762" in local_validation.json()["warnings"][0]
    assert "ICANN/IANA" in local_validation.json()["warnings"][0]
    assert ".internal" in local_validation.json()["warnings"][0]

    updated = client.patch(
        f"/api/v1/dns/records/{created.json()['id']}",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "hostname": "api-renamed.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.32",
            "description": "updated through API",
            "enabled": False,
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["hostname"] == "api-renamed.atlaso.internal"
    assert updated.json()["address"] == "192.168.50.32"
    assert updated.json()["enabled"] is False


def test_dns_api_exposes_read_only_authoritative_settings_and_advances_serial(client):
    """Verify that dns api exposes read only authoritative settings and advances serial.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dns_token = create_token(client, ["read:dns", "write:dns"])
    headers = {"Authorization": f"Bearer {dns_token}"}
    initial = client.get("/api/v1/dns/settings", headers=headers)
    assert initial.status_code == 200
    initial_body = initial.json()
    initial_serial = initial_body["authoritative_serial"]

    assert initial_body["authoritative_server"] == "ns1.atlaso.internal"
    assert initial_body["authoritative_contact"] == "hostmaster.atlaso.internal"
    assert initial_body["authoritative_ttl"] == 3600
    assert initial_body["authoritative_refresh"] == 1200
    assert initial_body["authoritative_retry"] == 180
    assert initial_body["authoritative_expire"] == 1209600

    created = client.post(
        "/api/v1/dns/records",
        headers=headers,
        json={"hostname": "serial.atlaso.internal", "record_type": "A", "address": "192.168.50.88"},
    )
    assert created.status_code == 201, created.text
    after_create = client.get("/api/v1/dns/settings", headers=headers).json()["authoritative_serial"]
    assert after_create > initial_serial

    updated = client.patch(
        f"/api/v1/dns/records/{created.json()['id']}",
        headers=headers,
        json={"hostname": "serial.atlaso.internal", "record_type": "A", "address": "192.168.50.89"},
    )
    assert updated.status_code == 200, updated.text
    after_update = client.get("/api/v1/dns/settings", headers=headers).json()["authoritative_serial"]
    assert after_update > after_create

    schema = client.get("/openapi.json").json()["components"]["schemas"]
    assert "authoritative_serial" in schema["DnsSettingsResponse"]["properties"]
    assert "authoritative_serial" not in schema["DnsSettingsUpdate"]["properties"]


def test_dns_api_update_rejects_duplicate_record(client):
    """Verify that dns api update rejects duplicate record.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dns_token = create_token(client, ["read:dns", "write:dns"])
    first = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "first.atlaso.internal", "record_type": "A", "address": "192.168.50.50"},
    )
    second = client.post(
        "/api/v1/dns/records",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "second.atlaso.internal", "record_type": "A", "address": "192.168.50.51"},
    )
    assert first.status_code == 201
    assert second.status_code == 201

    duplicate = client.patch(
        f"/api/v1/dns/records/{second.json()['id']}",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "FIRST.atlaso.internal", "record_type": "a", "address": "192.168.50.50"},
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"]

    allowed = client.patch(
        f"/api/v1/dns/records/{second.json()['id']}",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={"hostname": "FIRST.atlaso.internal", "record_type": "a", "address": "192.168.50.52"},
    )
    assert allowed.status_code == 200, allowed.text


def test_dns_hosts_import_replaces_existing_records(client):
    """Verify that dns hosts import replaces existing records.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dns_token = create_token(client, ["read:dns", "write:dns"])
    response = client.post(
        "/api/v1/dns/records/import",
        headers={"Authorization": f"Bearer {dns_token}"},
        json={
            "replace_existing": True,
            "hosts_text": "192.168.50.70 imported.atlaso.internal imported-alias\n",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["imported_count"] == 2
    hostnames = {record["hostname"] for record in body["records"]}
    assert hostnames == {"imported-alias", "imported.atlaso.internal"}

    validation = client.post("/api/v1/dns/validate", headers={"Authorization": f"Bearer {dns_token}"})
    assert "imported.atlaso.internal" in validation.json()["config_preview"]
    assert "core.atlaso.internal" not in validation.json()["config_preview"]


def test_dhcp_api_scope_and_reservations(client):
    """Verify that dhcp api scope and reservations.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    dhcp_token = create_token(client, ["read:dhcp", "write:dhcp", "read:dns"])
    status = client.get("/api/v1/dhcp/status", headers={"Authorization": f"Bearer {dhcp_token}"})
    assert status.status_code == 200
    assert status.json()["interface_name"] == "eth2"

    reservation = client.post(
        "/api/v1/dhcp/reservations",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "hostname": "api-client",
            "mac_address": "02:15:5d:00:20:30",
            "ip_address": "192.168.50.130",
        },
    )
    assert reservation.status_code == 201, reservation.text
    assert reservation.json()["hostname"] == "api-client.atlaso.internal"
    dns_records = client.get("/api/v1/dns/records", headers={"Authorization": f"Bearer {dhcp_token}"})
    assert any(record["hostname"] == "api-client.atlaso.internal" for record in dns_records.json())

    scopes = client.get("/api/v1/dhcp/scopes", headers={"Authorization": f"Bearer {dhcp_token}"})
    assert scopes.status_code == 200
    assert scopes.json()[0]["name"] == "SiteA"
    assert scopes.json()[0]["range_expression"] == "192.168.50.100-192.168.50.200"
    family_change = client.patch(
        f"/api/v1/dhcp/scopes/{scopes.json()[0]['id']}",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "name": "SiteA",
            "address_family": "ipv6",
            "interface_name": "eth2",
            "site_address": "fd00:50::1",
            "prefix_length": 64,
            "range_expression": "fd00:50::100-fd00:50::200",
            "lease_time": "12h",
            "domain_name": "atlaso.internal",
            "dns_server": "fd00:50::1",
            "ntp_server": "fd00:50::1",
            "enabled": True,
        },
    )
    assert family_change.status_code == 409
    assert family_change.json()["detail"] == "DHCP IP zone family cannot be changed after it is created"

    created_scope = client.post(
        "/api/v1/dhcp/scopes",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "name": "SiteB",
            "interface_name": "eth2",
            "site_address": "192.168.60.1",
            "prefix_length": 24,
            "range_expression": "192.168.60.100-192.168.60.200",
            "lease_time": "8h",
            "domain_name": "siteb.internal",
            "dns_server": "192.168.60.1",
            "ntp_server": "192.168.60.1",
            "enabled": True,
        },
    )
    assert created_scope.status_code == 201, created_scope.text
    created_option = client.post(
        "/api/v1/dhcp/options",
        headers={"Authorization": f"Bearer {dhcp_token}"},
        json={
            "scope_id": created_scope.json()["id"],
            "option_code": "ntp-server",
            "value": "192.168.60.1",
            "enabled": True,
        },
    )
    assert created_option.status_code == 201, created_option.text
    assert created_option.json()["scope_id"] == created_scope.json()["id"]
    options = client.get("/api/v1/dhcp/options", headers={"Authorization": f"Bearer {dhcp_token}"})
    assert any(option["option_code"] == "ntp-server" for option in options.json())
    leases = client.get("/api/v1/dhcp/leases", headers={"Authorization": f"Bearer {dhcp_token}"})
    assert leases.status_code == 200
    assert leases.json()[0]["hostname"] == "api-client.atlaso.internal"
    scopes = client.get("/api/v1/dhcp/scopes", headers={"Authorization": f"Bearer {dhcp_token}"})
    assert {scope["name"] for scope in scopes.json()} == {"SiteA", "SiteB"}


def test_dhcp_api_leases_reflect_helper_output(client, monkeypatch):
    """Verify that dhcp api leases reflect helper output.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult

    def fake_read_dhcp_leases(self):
        """Return fake read dhcp leases."""
        return AdapterResult(
            command=["sudo", "-n", "/opt/atlaso/bin/atlaso-helper", "dnsmasq", "leases", "--real"],
            dry_run=False,
            stdout="1893456000 02:15:5d:00:20:40 192.168.50.140 live-client.atlaso.internal *\n",
        )

    monkeypatch.setattr("atlaso.app.api.v1.SystemAdapter.read_dhcp_leases", fake_read_dhcp_leases)
    dhcp_token = create_token(client, ["read:dhcp"])

    leases = client.get("/api/v1/dhcp/leases", headers={"Authorization": f"Bearer {dhcp_token}"})

    assert leases.status_code == 200
    assert leases.json() == [
        {
            "expires_at": "2030-01-01T00:00:00Z",
            "mac_address": "02:15:5d:00:20:40",
            "ip_address": "192.168.50.140",
            "hostname": "live-client.atlaso.internal",
            "client_id": "",
            "status": "active",
        }
    ]
