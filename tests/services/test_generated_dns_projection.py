"""Tests for address-derived dnsmasq config projection."""

from atlaso.app.services.generated_dns_projection import (
    defer_dns_record_publication,
    project_generated_dns,
    project_listener_addresses,
)

REGISTRY_DESCRIPTION = "Created from VCF private registry endpoint."
OPERATOR_DESCRIPTION = "Operator-owned record"


def test_listener_projection_preserves_pending_settings_and_authority_advances() -> None:
    """Move applied listeners and generated targets without copying pending settings."""
    previous = "listen-address=192.0.2.10\nserver=192.0.2.53\n# atlaso-authoritative-config: auth-soa=42,admin,3600,600,86400\n# atlaso-authoritative-config: auth-zone=example.internal,192.0.2.10/32\n# atlaso-authoritative-config: host-record=registry.example.internal,192.0.2.10\n"
    desired = "listen-address=198.51.100.10\nserver=198.51.100.53\n# atlaso-authoritative-config: host-record=registry.example.internal,198.51.100.10\n"
    old = [_record("registry.example.internal", "A", "192.0.2.10")]
    new = [_record("registry.example.internal", "A", "198.51.100.10")]
    projected = project_generated_dns(previous, desired, old, new)
    projected = project_listener_addresses(projected, {"192.0.2.10": "198.51.100.10"})
    assert "listen-address=198.51.100.10\n" in projected
    assert "server=192.0.2.53\n" in projected
    assert "auth-soa=43,admin,3600,600,86400" in projected
    assert "auth-zone=example.internal,192.0.2.10/32,198.51.100.10/32" in projected
    assert project_generated_dns(projected, desired, new, new) == projected


def test_authority_listener_move_preserves_explicit_reverse_record() -> None:
    """A manual PTR remains owned by the operator even when it names the DNS server."""
    original = "listen-address=192.0.2.10\n# atlaso-authoritative-config: auth-server=ns.example.internal,eth1\n# atlaso-authoritative-config: host-record=ns.example.internal,192.0.2.10\nptr-record=10.2.0.192.in-addr.arpa,ns.example.internal\n"
    moved = project_listener_addresses(original, {"192.0.2.10": "192.0.2.20"},
                                       protected_ptr_owners={"10.2.0.192.in-addr.arpa"})
    assert "host-record=ns.example.internal,192.0.2.20" in moved
    assert "ptr-record=10.2.0.192.in-addr.arpa,ns.example.internal" in moved
    assert "ptr-record=20.2.0.192.in-addr.arpa" not in moved


def test_projection_replaces_only_exactly_owned_service_records() -> None:
    """Replace stale owned A, AAAA, and CNAME rows while retaining manual rows."""
    previous = """# Atlaso authoritative serial: 10
host-record=registry-eth9.atlaso.internal,192.0.2.70
host-record=registry-eth9.atlaso.internal,2001:db8::70
cname=registry.atlaso.internal,registry-eth9.atlaso.internal
cname=registry-old.atlaso.internal,registry-eth9.atlaso.internal
host-record=registry-eth9.atlaso.internal,192.0.2.99
host-record=registry-other.atlaso.internal,192.0.2.101
dhcp-range=192.0.2.100,192.0.2.200,12h
"""
    desired = """# Atlaso authoritative serial: 11
host-record=registry-eth9.atlaso.internal,192.0.2.80
host-record=registry-eth9.atlaso.internal,2001:db8::80
cname=registry.atlaso.internal,registry-eth9.atlaso.internal
"""
    previous_records = [
        _record("registry-eth9.atlaso.internal", "A", "192.0.2.70"),
        _record("registry-eth9.atlaso.internal", "AAAA", "2001:db8::70"),
        _record("registry.atlaso.internal", "CNAME", "registry-eth9.atlaso.internal"),
        _record("registry-old.atlaso.internal", "CNAME", "registry-eth9.atlaso.internal"),
    ]
    desired_records = [
        _record("registry-eth9.atlaso.internal", "A", "192.0.2.80"),
        _record("registry-eth9.atlaso.internal", "AAAA", "2001:db8::80"),
        _record("registry.atlaso.internal", "CNAME", "registry-eth9.atlaso.internal"),
    ]

    projected = project_generated_dns(previous, desired, previous_records, desired_records)

    assert "host-record=registry-eth9.atlaso.internal,192.0.2.70" not in projected
    assert "host-record=registry-eth9.atlaso.internal,2001:db8::70" not in projected
    assert "cname=registry-old.atlaso.internal,registry-eth9.atlaso.internal" not in projected
    assert "host-record=registry-eth9.atlaso.internal,192.0.2.80" in projected
    assert "host-record=registry-eth9.atlaso.internal,2001:db8::80" in projected
    assert projected.count("cname=registry.atlaso.internal,registry-eth9.atlaso.internal") == 1
    assert "host-record=registry-eth9.atlaso.internal,192.0.2.99" in projected
    assert "host-record=registry-other.atlaso.internal,192.0.2.101" in projected
    assert "dhcp-range=192.0.2.100,192.0.2.200,12h" in projected
    assert "# Atlaso authoritative serial: 10" in projected


def test_projection_matches_authoritative_wrappers_and_generated_ptr_only() -> None:
    """Remove wrapped owned records and generated PTRs without touching explicit PTRs."""
    previous = """# atlaso-authoritative-config: host-record=nfs-vlan30.example.internal,192.0.2.30
# atlaso-authoritative-config: ptr-record=30.2.0.192.in-addr.arpa,nfs-vlan30.example.internal
# atlaso-authoritative-config: host-record=nfs-vlan30.example.internal,192.0.2.31
ptr-record=31.2.0.192.in-addr.arpa,nfs-vlan30.example.internal
ptr-record=31.2.0.192.in-addr.arpa,operator.example.internal
auth-zone=example.internal,192.0.2.0/24
"""
    desired = """# atlaso-authoritative-config: host-record=nfs-vlan30.example.internal,192.0.2.40
# atlaso-authoritative-config: ptr-record=40.2.0.192.in-addr.arpa,nfs-vlan30.example.internal
"""
    previous_records = [
        _record(
            "nfs-vlan30.example.internal",
            "A",
            "192.0.2.30",
            description="Created from ESX Storage endpoint.",
            generated_ptr="true",
        ),
        _record(
            "nfs-vlan30.example.internal",
            "A",
            "192.0.2.31",
            description="Created from ESX Storage endpoint.",
            generated_ptr="false",
        ),
    ]
    desired_records = [
        _record(
            "nfs-vlan30.example.internal",
            "A",
            "192.0.2.40",
            description="Created from ESX Storage endpoint.",
            generated_ptr="true",
        )
    ]

    projected = project_generated_dns(previous, desired, previous_records, desired_records)

    assert "host-record=nfs-vlan30.example.internal,192.0.2.30" not in projected
    assert "ptr-record=30.2.0.192.in-addr.arpa,nfs-vlan30.example.internal" not in projected
    assert "host-record=nfs-vlan30.example.internal,192.0.2.31" not in projected
    assert "ptr-record=31.2.0.192.in-addr.arpa,nfs-vlan30.example.internal" in projected
    assert "# atlaso-authoritative-config: host-record=nfs-vlan30.example.internal,192.0.2.40" in projected
    assert "# atlaso-authoritative-config: ptr-record=40.2.0.192.in-addr.arpa,nfs-vlan30.example.internal" in projected
    assert "ptr-record=31.2.0.192.in-addr.arpa,operator.example.internal" in projected
    assert "auth-zone=example.internal,192.0.2.0/24" in projected


def test_projection_ignores_rows_without_exact_owned_provenance() -> None:
    """A matching service-name pattern alone cannot authorize record removal."""
    previous = """host-record=ca-eth4.example.internal,192.0.2.44
host-record=ca-eth4.example.internal,192.0.2.45
"""
    desired = ""
    previous_records = [
        _record(
            "ca-eth4.example.internal",
            "A",
            "192.0.2.44",
            description=OPERATOR_DESCRIPTION,
        )
    ]

    projected = project_generated_dns(previous, desired, previous_records, [])

    assert projected == previous


def test_defer_publication_keeps_previous_records_with_candidate_settings() -> None:
    """Candidate non-record settings advance while all prior record lines remain."""
    previous = """# Atlaso authoritative serial: 10
interface=eth1
host-record=ca-eth1.example.internal,192.0.2.10
cname=ca.example.internal,ca-eth1.example.internal
txt-record=operator.example.internal,old-value
ptr-record=10.2.0.192.in-addr.arpa,ca-eth1.example.internal
mx-host=example.internal,mail-old.example.internal,10
caa-record=example.internal,0 issue old.example.internal
"""
    desired = """# Atlaso authoritative serial: 11
interface=eth2
listen-address=192.0.2.20
host-record=ca-eth2.example.internal,192.0.2.20
cname=ca.example.internal,ca-eth2.example.internal
txt-record=operator.example.internal,new-value
srv-host=_ldap._tcp.example.internal,ldap.example.internal,389
mx-host=example.internal,mail-new.example.internal,10
caa-record=example.internal,0 issue new.example.internal
auth-zone=example.internal,192.0.2.0/24
"""

    projected = defer_dns_record_publication(previous, desired)

    assert "# Atlaso authoritative serial: 11" in projected
    assert "interface=eth2" in projected
    assert "listen-address=192.0.2.20" in projected
    assert "auth-zone=example.internal,192.0.2.0/24" in projected
    assert "host-record=ca-eth1.example.internal,192.0.2.10" in projected
    assert "cname=ca.example.internal,ca-eth1.example.internal" in projected
    assert "txt-record=operator.example.internal,old-value" in projected
    assert "ptr-record=10.2.0.192.in-addr.arpa,ca-eth1.example.internal" in projected
    assert "mx-host=example.internal,mail-old.example.internal,10" in projected
    assert "caa-record=example.internal,0 issue old.example.internal" in projected
    assert "ca-eth2.example.internal" not in projected
    assert "new-value" not in projected
    assert "srv-host=_ldap._tcp.example.internal,ldap.example.internal,389" not in projected
    assert "mail-new.example.internal" not in projected
    assert "issue new.example.internal" not in projected


def test_defer_publication_removes_candidate_records_when_no_prior_records_exist() -> None:
    """A first activation does not publish candidate DNS records before readiness."""
    desired = """interface=eth2
host-record=ca-eth2.example.internal,192.0.2.20
cname=ca.example.internal,ca-eth2.example.internal
"""

    projected = defer_dns_record_publication("", desired)

    assert projected == "interface=eth2\n"


def test_dns_comparison_ignores_generated_serial_but_preserves_soa_policy() -> None:
    """An address publication serial does not mask unrelated SOA edits."""
    from atlaso.app.services.generated_dns_projection import dns_comparison_preview

    original = "# Atlaso authoritative serial: 10\n# atlaso-authoritative-config: auth-soa=10,admin.example.internal,3600,600,86400\n"
    moved = original.replace("serial: 10", "serial: 11").replace("auth-soa=10,", "auth-soa=11,")
    assert dns_comparison_preview(original) == dns_comparison_preview(moved)
    assert dns_comparison_preview(original) != dns_comparison_preview(moved.replace(",3600,", ",7200,"))


def _record(
    hostname: str,
    record_type: str,
    address: str,
    *,
    description: str = REGISTRY_DESCRIPTION,
    generated_ptr: str = "false",
) -> dict[str, str]:
    """Build a record mapping for projection tests.

    Args:
        hostname: Record owner name.
        record_type: DNS record type.
        address: Record value.
        description: Provenance marker.
        generated_ptr: Whether the renderer may manage the derived PTR.
    """
    return {
        "hostname": hostname,
        "record_type": record_type,
        "address": address,
        "description": description,
        "generated_ptr": generated_ptr,
    }
