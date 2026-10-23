from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlaso.app.services.vcf_certificate_material import (
    CertificateMaterialError,
    ProductProfile,
    public_chain_pem,
    validate_csr,
    validate_issued_certificate,
    validate_product_csr,
    validate_profile,
)


def _material(bits: int = 2048):
    """Provide material.

    Args:
        bits: RSA key size used by the certificate fixture.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcf.example.test")])
    now = datetime.now(timezone.utc)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("vcf.example.test"),
                    x509.IPAddress(ip_address("192.0.2.2")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root.subject)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, True, True, False, False, False, None, None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return csr, leaf, root


def test_csr_and_issued_leaf_validate():
    csr, leaf, root = _material()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    assert validate_csr(csr_pem, {"vcf.example.test"}, {"192.0.2.2"}) == csr
    assert (
        validate_issued_certificate(
            csr_pem,
            leaf.public_bytes(serialization.Encoding.PEM),
            "srm",
            {"vcf.example.test"},
            {"192.0.2.2"},
            root,
        )
        == leaf
    )


@pytest.mark.parametrize(
    "dns,ips", [({"other.test"}, {"192.0.2.2"}), ({"vcf.example.test"}, {"192.0.2.3"})]
)
def test_csr_rejects_san_mismatch(dns, ips):
    """Verify csr rejects san mismatch.

    Args:
        dns: DNS SANs used in the certificate fixture.
        ips: IP SANs used in the certificate fixture.
    """
    csr, _, _ = _material()
    with pytest.raises(CertificateMaterialError):
        validate_csr(csr.public_bytes(serialization.Encoding.PEM), dns, ips)


def test_pem_parsers_reject_trailing_data_and_duplicate_sans():
    csr, leaf, root = _material()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(CertificateMaterialError):
        validate_csr(csr_pem + b"unexpected", {"vcf.example.test"}, {"192.0.2.2"})
    with pytest.raises(CertificateMaterialError):
        validate_issued_certificate(
            csr_pem,
            leaf.public_bytes(serialization.Encoding.PEM) + b"junk",
            "srm",
            {"vcf.example.test"},
            {"192.0.2.2"},
            root,
        )
    with pytest.raises(CertificateMaterialError):
        public_chain_pem(
            root.public_bytes(serialization.Encoding.PEM) + b"trailing", root
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    duplicate_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(csr.subject)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("vcf.example.test"), x509.DNSName("vcf.example.test")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(CertificateMaterialError):
        validate_csr(
            duplicate_csr.public_bytes(serialization.Encoding.PEM),
            {"vcf.example.test"},
            set(),
        )


def test_rejects_weak_rsa_and_disabled_or_weakened_profile():
    csr, _, _ = _material(1024)
    with pytest.raises(CertificateMaterialError):
        validate_csr(
            csr.public_bytes(serialization.Encoding.PEM),
            {"vcf.example.test"},
            {"192.0.2.2"},
        )
    with pytest.raises(CertificateMaterialError):
        validate_profile(ProductProfile("srm", False, frozenset(), frozenset()), "srm")
    with pytest.raises(CertificateMaterialError):
        validate_profile(
            ProductProfile(
                "srm", True, frozenset({"digitalSignature"}), frozenset({"serverAuth"})
            ),
            "srm",
        )


def test_chain_requires_expected_ca_root():
    _, _, root = _material()
    pem = root.public_bytes(serialization.Encoding.PEM)
    assert public_chain_pem(pem, root) == pem
    with pytest.raises(CertificateMaterialError):
        public_chain_pem(pem + pem, root)
    with pytest.raises(CertificateMaterialError):
        public_chain_pem(b"garbage", root)


def test_rejects_spki_mismatch_wrong_issuer_and_non_ca_issuer():
    csr, leaf, root = _material()
    other_csr, _, _ = _material()
    with pytest.raises(CertificateMaterialError):
        validate_issued_certificate(
            other_csr.public_bytes(serialization.Encoding.PEM),
            leaf.public_bytes(serialization.Encoding.PEM),
            "srm",
            {"vcf.example.test"},
            {"192.0.2.2"},
            root,
        )
    _, _, wrong_root = _material()
    with pytest.raises(CertificateMaterialError):
        validate_issued_certificate(
            csr.public_bytes(serialization.Encoding.PEM),
            leaf.public_bytes(serialization.Encoding.PEM),
            "srm",
            {"vcf.example.test"},
            {"192.0.2.2"},
            wrong_root,
        )
    non_ca = (
        x509.CertificateBuilder()
        .subject_name(root.subject)
        .issuer_name(root.issuer)
        .public_key(root.public_key())
        .serial_number(3)
        .not_valid_before(root.not_valid_before_utc)
        .not_valid_after(root.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            hashes.SHA256(),
        )
    )
    with pytest.raises(CertificateMaterialError):
        validate_issued_certificate(
            csr.public_bytes(serialization.Encoding.PEM),
            leaf.public_bytes(serialization.Encoding.PEM),
            "srm",
            {"vcf.example.test"},
            {"192.0.2.2"},
            non_ca,
        )


def test_profile_and_leaf_require_exact_product_usages():
    with pytest.raises(CertificateMaterialError):
        validate_profile(
            ProductProfile(
                "vc",
                True,
                frozenset({"digitalSignature", "keyEncipherment"}),
                frozenset({"serverAuth", "clientAuth"}),
            ),
            "vcenter",
        )
    csr, leaf, root = _material()
    with pytest.raises(CertificateMaterialError):
        validate_issued_certificate(
            csr.public_bytes(serialization.Encoding.PEM),
            leaf.public_bytes(serialization.Encoding.PEM),
            "vcenter",
            {"vcf.example.test"},
            {"192.0.2.2"},
            root,
        )


def test_chain_rejects_expired_trust_root():
    _, _, root = _material()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired = (
        x509.CertificateBuilder()
        .subject_name(root.subject)
        .issuer_name(root.subject)
        .public_key(key.public_key())
        .serial_number(4)
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=3))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(CertificateMaterialError):
        public_chain_pem(expired.public_bytes(serialization.Encoding.PEM), expired)


def _csr_with_sans(dns=(), ips=()):
    """Provide csr with sans.

    Args:
        dns: DNS SANs used in the certificate fixture.
        ips: IP SANs used in the certificate fixture.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vc.example.test")])
    names = [x509.DNSName(value) for value in dns] + [
        x509.IPAddress(ip_address(value)) for value in ips
    ]
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def test_vcenter_native_ip_pnid_csr_exception_is_exact():
    pem = _csr_with_sans(ips=["192.0.2.10"])
    validate_product_csr(pem, "vcenter", {"192.0.2.10"}, {"192.0.2.10"})
    with pytest.raises(CertificateMaterialError):
        validate_product_csr(
            pem, "vcenter", {"vc.example.test", "192.0.2.10"}, {"192.0.2.10"}
        )
    with pytest.raises(CertificateMaterialError):
        validate_product_csr(
            _csr_with_sans(dns=["vc.example.test"], ips=["192.0.2.10"]),
            "vcenter",
            {"192.0.2.10"},
            {"192.0.2.10"},
        )
    with pytest.raises(CertificateMaterialError):
        validate_product_csr(
            _csr_with_sans(ips=["192.0.2.10", "192.0.2.11"]),
            "vcenter",
            {"192.0.2.10"},
            {"192.0.2.10"},
        )


def test_srm_does_not_apply_vcenter_ip_pnid_exception():
    pem = _csr_with_sans(ips=["192.0.2.10"])
    with pytest.raises(CertificateMaterialError):
        validate_product_csr(pem, "srm", {"192.0.2.10"}, {"192.0.2.10"})


def test_sddc_profile_requires_exact_product_usages_and_supported_rsa_size():
    profile = ProductProfile(
        "sddc-manager",
        True,
        frozenset({"digitalSignature", "keyEncipherment"}),
        frozenset({"serverAuth", "clientAuth"}),
    )
    validate_profile(profile, "sddc")
    validate_profile(
        ProductProfile(
            "sddc-manager",
            True,
            profile.key_usages,
            profile.extended_key_usages,
            key_size=4096,
        ),
        "sddc",
    )
    with pytest.raises(CertificateMaterialError):
        validate_profile(
            ProductProfile(
                "sddc-manager",
                True,
                profile.key_usages,
                frozenset({"serverAuth"}),
            ),
            "sddc",
        )
    with pytest.raises(CertificateMaterialError):
        validate_profile(
            ProductProfile(
                "sddc-manager",
                True,
                profile.key_usages,
                profile.extended_key_usages,
                key_size=1024,
            ),
            "sddc",
        )


def test_sddc_csr_requires_exact_reviewed_dns_and_ip_sans():
    pem = _csr_with_sans(dns=["sddc.example.test"], ips=["192.0.2.30"])
    validate_product_csr(pem, "sddc", {"sddc.example.test"}, {"192.0.2.30"})
    with pytest.raises(CertificateMaterialError):
        validate_product_csr(pem, "sddc", {"other.example.test"}, {"192.0.2.30"})
    with pytest.raises(CertificateMaterialError):
        validate_product_csr(
            _csr_with_sans(ips=["192.0.2.30"]), "sddc", set(), {"192.0.2.30"}
        )
