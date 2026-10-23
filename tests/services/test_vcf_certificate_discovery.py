from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from atlaso.app.services.vcf_certificate_discovery import (
    healthy_services,
    names_from_certificate,
    standalone_vcenter,
    supported_version,
)


def _certificate(dns: list[str], ips: list[str]) -> x509.Certificate:
    """Provide certificate.

    Args:
        dns: DNS SANs used in the certificate fixture.
        ips: IP SANs used in the certificate fixture.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vc.example.test")])
    sans: list[x509.GeneralName] = [x509.DNSName(value) for value in dns]
    sans.extend(x509.IPAddress(ip_address(value)) for value in ips)
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )


@pytest.mark.parametrize(
    ("product", "info"),
    [
        (
            "srm",
            {"product_name": "Protection and recovery appliance", "version": "8.0.3"},
        ),
        ("srm", {"product": "SiteRecoveryManager", "version": "9.0"}),
        (
            "srm",
            {
                "product_name": "Protection and recovery appliance",
                "appliance_version": "9.1.1.0100 build 25753785",
            },
        ),
        (
            "vcenter",
            {"product": "VMware vCenter Server Appliance", "version": "8.0.2.00100"},
        ),
        ("vcenter", {"product": "vCenter Server", "version": "9.0.0"}),
    ],
)
def test_supported_version_accepts_native_product_8_and_9(product, info):
    """Verify supported version accepts native product 8 and 9.

    Args:
        product: Detected appliance product identifier.
        info: Public native discovery metadata.
    """
    assert supported_version(product, info)


@pytest.mark.parametrize(
    ("product", "info"),
    [
        (
            "srm",
            {"product_name": "Protection and recovery appliance", "version": "7.0.3"},
        ),
        (
            "srm",
            {"product_name": "Protection and recovery appliance", "version": "unknown"},
        ),
        ("srm", {"product_name": "Other", "version": "9.0"}),
        ("vcenter", {"product": "vCenter Server", "version": "10.invalid"}),
    ],
)
def test_supported_version_rejects_old_invalid_or_wrong_identity(product, info):
    """Verify supported version rejects old invalid or wrong identity.

    Args:
        product: Detected appliance product identifier.
        info: Public native discovery metadata.
    """
    assert not supported_version(product, info)


def test_names_preserve_sans_and_require_native_identity():
    cert = _certificate(["vc.example.test", "alias.example.test"], ["192.0.2.10"])
    assert names_from_certificate(cert, "vcenter", "vc.example.test").dns_names == (
        "alias.example.test",
        "vc.example.test",
    )
    assert (
        "missing.example.test"
        in names_from_certificate(cert, "vcenter", "missing.example.test").dns_names
    )
    ip_pnid = names_from_certificate(cert, "vcenter", "192.0.2.20")
    assert "192.0.2.20" in ip_pnid.ip_addresses and ip_pnid.dns_names


def test_srm_replaces_localhost_with_native_hostname_and_preserves_other_sans():
    cert = _certificate(["localhost", "keep.example.test"], ["127.0.0.1", "192.0.2.10"])
    names = names_from_certificate(cert, "srm", "srm.example.test")
    assert names.common_name == "srm.example.test"
    assert names.dns_names == ("keep.example.test", "srm.example.test")
    assert names.ip_addresses == ("192.0.2.10",)


def test_native_health_shapes_and_srm_service_baseline():
    assert healthy_services("vcenter", "green")
    assert healthy_services("vcenter", {"value": "green"})
    assert not healthy_services("vcenter", {"value": "yellow"})
    services = {
        "list": [
            {
                "id": "srm",
                "name": "srm",
                "service_status": "RUNNING",
                "startup_type": "AUTOMATIC",
                "is_running": True,
            },
            {
                "id": "vpostgres",
                "name": "vpostgres",
                "service_status": "stopped",
                "startup_type": "MANUAL",
                "is_running": False,
            },
        ],
        "_meta": {"total": 2, "offset": 0, "limit": 100, "links": {"next": None}},
    }
    assert healthy_services("srm", services)
    assert healthy_services("srm", services, {"srm"})
    assert not healthy_services("srm", services, {"srm", "vpostgres"})
    broken = {
        "list": [
            {
                "id": "srm",
                "name": "srm",
                "startup_type": "AUTOMATIC",
                "is_running": False,
            }
        ],
        "_meta": {"total": 1, "offset": 0, "limit": 100, "links": {"next": "next"}},
    }
    assert not healthy_services("srm", broken)


@pytest.mark.parametrize("state", ["NOTCONFIGURED", "notConfigured", "NOT_CONFIGURED"])
def test_vcenter_topology_accepts_only_explicit_unconfigured_single_registration(state):
    """Verify vcenter topology accepts only explicit unconfigured single registration.

    Args:
        state: Public operation checkpoint and reviewed inputs.
    """
    assert standalone_vcenter(
        {"config_state": state},
        [{"node_id": "n1", "service_id": "s1", "endpoints": ["https://vc"]}],
    )
    assert not standalone_vcenter(
        {"config_state": state},
        [
            {"node_id": "one", "service_id": "s1", "endpoints": ["a"]},
            {"node_id": "two", "service_id": "s2", "endpoints": ["b"]},
        ],
    )


@pytest.mark.parametrize(
    "info",
    [
        {"config_state": "CONFIGURED"},
        {"config_state": "INVALID"},
        {},
        {"config_state": "future-state"},
    ],
)
def test_vcenter_topology_rejects_ha_and_unknown_states(info):
    """Verify vcenter topology rejects ha and unknown states.

    Args:
        info: Public native discovery metadata.
    """
    assert not standalone_vcenter(
        info, [{"node_id": "n1", "service_id": "s1", "endpoints": ["https://vc"]}]
    )
    assert not standalone_vcenter(info, None)


def test_vcenter_topology_rejects_empty_or_incomplete_registration():
    assert not standalone_vcenter({"config_state": "NOTCONFIGURED"}, [{}])
    assert not standalone_vcenter(
        {"config_state": "NOTCONFIGURED"}, [{"node_id": "n1", "service_id": "s1"}]
    )


@pytest.mark.parametrize("version", ["9.0.0.0", "9.1.1.0100", "9.1"])
def test_sddc_supported_version_requires_native_manager_role(version):
    """Verify sddc supported version requires native manager role.

    Args:
        version: Native product version used by this compatibility case.
    """
    assert supported_version(
        "sddc",
        {
            "role": "SddcManager",
            "version": version,
            "identity": "sddc.example.test",
            "domain_id": "domain-1",
            "resource_id": "resource-1",
        },
    )


@pytest.mark.parametrize(
    "info",
    [
        {"role": "VcfInstaller", "version": "9.0.0.0"},
        {"role": "SddcManager", "version": "8.0.0.0"},
        {"role": "SddcManager", "version": "10.0.0.0"},
        {"role": "SddcManager", "version": "unknown"},
        {"version": "9.0.0.0"},
    ],
)
def test_sddc_supported_version_rejects_wrong_role_or_version(info):
    """Verify sddc supported version rejects wrong role or version.

    Args:
        info: Public native discovery metadata.
    """
    assert not supported_version("sddc", info)


def test_sddc_names_preserve_current_sans_and_require_native_fqdn():
    cert = _certificate(
        ["old.example.test", "localhost"], ["192.0.2.10", "127.0.0.1"]
    )
    names = names_from_certificate(cert, "sddc", "sddc.example.test")
    assert names.common_name == "sddc.example.test"
    assert names.dns_names == ("old.example.test", "sddc.example.test")
    assert names.ip_addresses == ("192.0.2.10",)
    with pytest.raises(ValueError):
        names_from_certificate(cert, "sddc", "192.0.2.20")
    with pytest.raises(ValueError):
        names_from_certificate(cert, "sddc", "localhost")


def test_sddc_health_requires_complete_healthy_service_list_and_baseline():
    healthy = {
        "list": [
            {"id": "sddc-manager", "status": "UP"},
            {"id": "lcm", "status": "running"},
        ]
    }
    assert healthy_services("sddc", healthy)
    assert healthy_services("sddc", healthy, {"sddc-manager"})
    assert not healthy_services("sddc", healthy, {"missing-service"})
    assert not healthy_services("sddc", {"list": []})
    assert not healthy_services(
        "sddc", {"list": [{"id": "sddc-manager", "status": "UNKNOWN"}]}
    )
    assert not healthy_services(
        "sddc",
        {"list": [{"id": "sddc-manager", "status": "UP"}, {"id": "sddc-manager", "status": "UP"}]},
    )
    assert not healthy_services("sddc", {"list": [{"id": "sddc-manager"}]})
