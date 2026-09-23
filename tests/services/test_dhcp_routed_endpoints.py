"""DHCP service options accept routed endpoints without weakening subnet rules."""

import pytest

from atlaso.app.models import DhcpScope, DhcpSettings, DnsSettings
from atlaso.app.services.dnsmasq import render_dnsmasq_config, validate_dhcp_scope


@pytest.mark.parametrize("family,gateway,prefix,lease,endpoint", [
    ("ipv4", "192.168.4.254", 24, "192.168.4.100-150", "192.168.1.250"),
    ("ipv4", "192.168.4.254", 24, "192.168.4.100-150", "192.168.4.250"),
    ("ipv6", "2001:db8:4::1", 64, "2001:db8:4::100-2001:db8:4::150", "2001:db8:1::250"),
    ("ipv6", "2001:db8:4::1", 64, "2001:db8:4::100-2001:db8:4::150", "64:ff9b::808:808"),
    ("ipv6", "2001:db8:4::1", 64, "2001:db8:4::100-2001:db8:4::150", "64:ff9b:1::808:808"),
])
def test_scope_routed_service_endpoints_are_rendered(family, gateway, prefix, lease, endpoint):
    """DNS/NTP endpoints need no local ownership or subnet membership.

    Args:
        family: Address family under test.
        gateway: Scope site address under test.
        prefix: Scope prefix length under test.
        lease: Scope lease range under test.
        endpoint: Routed DNS and NTP endpoint under test.
    """
    scope = DhcpScope(name="Routed", interface_name="eth1", address_family=family,
                      site_address=gateway, prefix_length=prefix, range_expression=lease,
                      dns_server=endpoint, ntp_server=endpoint)
    errors, network = validate_dhcp_scope(scope)
    assert errors == []
    assert network is not None
    config = render_dnsmasq_config(dns_settings=DnsSettings(enabled=False), dns_records=[],
                                  dhcp_settings=DhcpSettings(enabled=True), dhcp_reservations=[],
                                  dhcp_scopes=[scope])
    assert endpoint in config
    assert "dns-server" in config
    assert "ntp-server" in config or "sntp-server" in config
    scope.range_expression = "192.168.9.100-150" if family == "ipv4" else "2001:db8:9::100-2001:db8:9::150"
    assert validate_dhcp_scope(scope)[0]


@pytest.mark.parametrize("endpoint", ["bad", "::1", "2001:db8::1", "127.0.0.1", "0.0.0.0", "0.0.0.1",
                                       "224.0.0.1", "255.255.255.255", "169.254.1.2", "192.168.4.255"])
@pytest.mark.parametrize("field", ["dns_server", "ntp_server"])
def test_scope_rejects_invalid_service_endpoint(field, endpoint):
    """Service endpoint validation retains family and usable-address boundaries.

    Args:
        field: DHCP service endpoint field under test.
        endpoint: Invalid endpoint value under test.
    """
    scope = DhcpScope(name="Routed", interface_name="eth1", address_family="ipv4",
                      site_address="192.168.4.254", prefix_length=24, range_expression="192.168.4.100-150",
                      dns_server="192.168.1.250", ntp_server="192.168.1.250")
    setattr(scope, field, endpoint)
    assert validate_dhcp_scope(scope)[0]


@pytest.mark.parametrize("field", ["dns_server", "ntp_server"])
@pytest.mark.parametrize("endpoint", ["2001:4860:1::", "::ffff:8.8.8.8", "::8.8.8.8", "::192.0.2.1", "100::1"])
def test_ipv6_scope_rejects_unusable_service_endpoint(field, endpoint):
    """Reject subnet-router anycast and IPv4-mapped DHCPv6 endpoints.

    Args:
        field: DHCP service endpoint field under test.
        endpoint: Unusable IPv6 service endpoint under test.
    """
    scope = DhcpScope(
        name="IPv6 routed",
        interface_name="eth1",
        address_family="ipv6",
        site_address="2001:4860:1::1",
        prefix_length=64,
        range_expression="2001:4860:1::100-2001:4860:1::150",
        dns_server="2001:4860:1::53",
        ntp_server="2001:4860:1::123",
    )
    setattr(scope, field, endpoint)

    errors, _network = validate_dhcp_scope(scope)

    assert any(f"{field.split('_')[0].upper()} server must be a usable unicast IPv6" in error for error in errors)
