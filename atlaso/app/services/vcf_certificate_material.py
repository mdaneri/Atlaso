"""Pure validation for VCF appliance certificate material."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


class CertificateMaterialError(ValueError):
    """Certificate material does not meet the VCF replacement contract."""


@dataclass(frozen=True)
class ProductProfile:
    """Public CA profile constraints used for product-specific validation.

    Attributes:
        name: Profile name.
        enabled: Whether the profile can issue certificates.
        key_usages: Configured X.509 key usage names.
        extended_key_usages: Configured X.509 extended usage names.
        profile_type: CA profile type (must be ``server``).
        key_type: Configured subject key type (must be ``RSA``).
        key_size: Minimum configured RSA key size.
        san_required: Whether subject alternative names are required.
    """

    name: str
    enabled: bool
    key_usages: frozenset[str]
    extended_key_usages: frozenset[str]
    profile_type: str = "server"
    key_type: str = "RSA"
    key_size: int = 2048
    san_required: bool = True


@dataclass(frozen=True)
class CertificateMetadata:
    """Safe public certificate fields for a review screen."""

    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    fingerprint_sha256: str
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]


_PROFILE_REQUIREMENTS = {
    "srm": (
        frozenset({"digitalSignature", "keyEncipherment", "dataEncipherment"}),
        frozenset({"serverAuth", "clientAuth"}),
    ),
    "vcenter": (
        frozenset({"digitalSignature", "keyEncipherment"}),
        frozenset({"serverAuth"}),
    ),
}
_EKUS = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
}


def validate_profile(profile: ProductProfile, product: str) -> None:
    """Reject disabled or weakened profiles without modifying shared CA configuration."""
    required = _PROFILE_REQUIREMENTS.get(product.lower())
    if required is None:
        raise CertificateMaterialError("Unsupported VCF certificate product.")
    if not profile.enabled:
        raise CertificateMaterialError("The selected CA profile is disabled.")
    if (
        profile.profile_type != "server"
        or profile.key_type.upper() != "RSA"
        or profile.key_size < 2048
        or not profile.san_required
    ):
        raise CertificateMaterialError(
            "The selected CA profile has incompatible certificate constraints."
        )
    if profile.key_usages != required[0] or profile.extended_key_usages != required[1]:
        raise CertificateMaterialError(
            "The selected CA profile lacks required product key usages."
        )
    if (product == "srm" and profile.key_size != 2048) or profile.key_size not in {
        2048,
        3072,
        4096,
    }:
        raise CertificateMaterialError(
            "The native CSR key size does not support this profile. Use RSA 2048 for SRM."
        )


def _load_csr(pem: bytes) -> x509.CertificateSigningRequest:
    if len(pem) > 65536:
        raise CertificateMaterialError("CSR exceeds the 64 KiB limit.")
    if pem.count(b"-----BEGIN CERTIFICATE REQUEST-----") != 1 or b"PRIVATE KEY" in pem:
        raise CertificateMaterialError(
            "CSR input must contain exactly one public CSR and no private material."
        )
    try:
        csr = x509.load_pem_x509_csr(pem)
    except ValueError as exc:
        raise CertificateMaterialError("CSR is not valid PEM.") from exc
    canonical = csr.public_bytes(serialization.Encoding.PEM)
    if pem.strip().replace(b"\r\n", b"\n") != canonical.strip():
        raise CertificateMaterialError("CSR input contains trailing or non-PEM data.")
    if not csr.is_signature_valid:
        raise CertificateMaterialError("CSR signature is invalid.")
    csr_hash = csr.signature_hash_algorithm
    if csr_hash is not None and csr_hash.name.lower() in {"md5", "sha1"}:
        raise CertificateMaterialError("CSR uses an unsafe signature hash algorithm.")
    key = csr.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise CertificateMaterialError("RSA keys must be at least 2048 bits.")
    return csr


def validate_csr(
    pem: bytes, expected_dns: set[str], expected_ips: set[str]
) -> x509.CertificateSigningRequest:
    """Validate CSR signature, strength, and exact requested SAN sets."""
    csr = _load_csr(pem)
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise CertificateMaterialError(
            "CSR must contain the expected subject alternative names."
        ) from exc
    if any(not isinstance(name, (x509.DNSName, x509.IPAddress)) for name in san):
        raise CertificateMaterialError(
            "CSR contains unsupported subject alternative name types."
        )
    dns_values = san.get_values_for_type(x509.DNSName)
    ip_values = san.get_values_for_type(x509.IPAddress)
    dns = set(dns_values)
    ips = {str(value) for value in ip_values}
    if len(dns) != len(dns_values) or len(ips) != len(ip_values):
        raise CertificateMaterialError(
            "CSR contains duplicate subject alternative names."
        )
    if dns != expected_dns or ips != {str(ip_address(value)) for value in expected_ips}:
        raise CertificateMaterialError(
            "CSR subject alternative names do not match the reviewed target names."
        )
    return csr


def validate_product_csr(
    pem: bytes, product: str, expected_dns: set[str], expected_ips: set[str]
) -> x509.CertificateSigningRequest:
    """Account for native vCenter encoding numeric SAN requests as IPAddress.

    vCenter's IP PNID must also appear as a DNS SAN on the installed leaf, while
    its native CSR API encodes that numeric request only as an IP SAN. No other
    SAN differences are permitted between the native CSR and reviewed names.
    """
    csr_dns = expected_dns - expected_ips if product == "vcenter" else expected_dns
    return validate_csr(pem, csr_dns, expected_ips)


def _verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    try:
        params = cert.signature_algorithm_parameters
        algorithm = cert.signature_hash_algorithm
        if algorithm is not None and algorithm.name.lower() in {"md5", "sha1"}:
            raise CertificateMaterialError(
                "Certificate uses an unsafe signature hash algorithm."
            )
        if (
            isinstance(key, rsa.RSAPublicKey)
            and isinstance(params, (padding.PKCS1v15, padding.PSS))
            and algorithm is not None
        ):
            key.verify(cert.signature, cert.tbs_certificate_bytes, params, algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if not isinstance(params, ec.ECDSA):
                raise CertificateMaterialError(
                    "Unsupported certificate signature algorithm."
                )
            key.verify(cert.signature, cert.tbs_certificate_bytes, params)
        else:
            raise CertificateMaterialError(
                "Unsupported certificate signature algorithm."
            )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise CertificateMaterialError(
            "Certificate chain signature is invalid."
        ) from exc


def _ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _reject_unknown_critical_extensions(cert: x509.Certificate) -> None:
    known = {
        x509.BasicConstraints,
        x509.KeyUsage,
        x509.SubjectAlternativeName,
        x509.ExtendedKeyUsage,
        x509.SubjectKeyIdentifier,
        x509.AuthorityKeyIdentifier,
    }
    for extension in cert.extensions:
        if extension.critical and not isinstance(extension.value, tuple(known)):
            raise CertificateMaterialError(
                "Certificate contains an unsupported critical extension."
            )


def validate_issued_certificate(
    csr_pem: bytes,
    leaf_pem: bytes,
    product: str,
    expected_dns: set[str],
    expected_ips: set[str],
    issuer: x509.Certificate,
) -> x509.Certificate:
    """Validate issued leaf key, SANs, validity, usages, and issuer signature."""
    csr = validate_product_csr(csr_pem, product, expected_dns, expected_ips)
    if (
        leaf_pem.count(b"-----BEGIN CERTIFICATE-----") != 1
        or b"PRIVATE KEY" in leaf_pem
    ):
        raise CertificateMaterialError(
            "Issued certificate input must contain exactly one public certificate."
        )
    try:
        leaf = x509.load_pem_x509_certificate(leaf_pem)
    except ValueError as exc:
        raise CertificateMaterialError("Issued certificate is not valid PEM.") from exc
    if (
        leaf_pem.strip().replace(b"\r\n", b"\n")
        != leaf.public_bytes(serialization.Encoding.PEM).strip()
    ):
        raise CertificateMaterialError(
            "Issued certificate input contains trailing or non-PEM data."
        )
    _reject_unknown_critical_extensions(leaf)
    try:
        constraints = leaf.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise CertificateMaterialError(
            "Issued certificate must contain basic constraints."
        ) from exc
    if (
        constraints.ca
        or leaf.subject != csr.subject
        or leaf.issuer != issuer.subject
        or leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        != csr.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ):
        raise CertificateMaterialError(
            "Issued certificate key or CA constraints do not match the CSR."
        )
    now = datetime.now(timezone.utc)
    if (
        not _ca(issuer)
        or not issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc
        or not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc
        or leaf.not_valid_before_utc < issuer.not_valid_before_utc
        or leaf.not_valid_after_utc > issuer.not_valid_after_utc
    ):
        raise CertificateMaterialError(
            "Issued certificate validity is outside current issuer validity."
        )
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateMaterialError(
            "Issued certificate is missing required SAN or usage extensions."
        ) from exc
    if any(not isinstance(name, (x509.DNSName, x509.IPAddress)) for name in san):
        raise CertificateMaterialError(
            "Issued certificate contains unsupported subject alternative name types."
        )
    dns_values = san.get_values_for_type(x509.DNSName)
    ip_values = san.get_values_for_type(x509.IPAddress)
    if (
        len(set(dns_values)) != len(dns_values)
        or len({str(v) for v in ip_values}) != len(ip_values)
        or set(dns_values) != expected_dns
        or {str(v) for v in ip_values} != {str(ip_address(v)) for v in expected_ips}
    ):
        raise CertificateMaterialError(
            "Issued certificate SANs do not match the reviewed target names."
        )
    required_ku, required_eku = _PROFILE_REQUIREMENTS[product.lower()]
    actual_ku = {
        name
        for name, enabled in (
            ("digitalSignature", ku.digital_signature),
            ("keyEncipherment", ku.key_encipherment),
            ("dataEncipherment", ku.data_encipherment),
        )
        if enabled
    }
    if (
        required_ku != actual_ku
        or {_EKUS[name] for name in required_eku} != set(eku)
        or ku.key_cert_sign
        or ku.crl_sign
        or ku.content_commitment
        or ku.key_agreement
    ):
        raise CertificateMaterialError(
            "Issued certificate lacks required product usages."
        )
    _verify_signature(leaf, issuer)
    return leaf


def public_chain_pem(chain_pem: bytes, root: x509.Certificate) -> bytes:
    """Validate a CA-only issuer-ordered chain terminating at the expected root."""
    if (
        len(chain_pem) > 262144
        or chain_pem.count(b"-----BEGIN CERTIFICATE-----") > 8
        or b"PRIVATE KEY" in chain_pem
    ):
        raise CertificateMaterialError(
            "Certificate chain must not contain private material."
        )
    try:
        certs = x509.load_pem_x509_certificates(chain_pem)
    except ValueError as exc:
        raise CertificateMaterialError("Certificate chain is malformed.") from exc
    canonical_chain = b"".join(
        cert.public_bytes(serialization.Encoding.PEM) for cert in certs
    )
    if chain_pem.strip().replace(b"\r\n", b"\n") != canonical_chain.strip():
        raise CertificateMaterialError(
            "Certificate chain contains trailing or non-PEM data."
        )
    if not certs or len({c.fingerprint(hashes.SHA256()) for c in certs}) != len(certs):
        raise CertificateMaterialError(
            "Certificate chain is empty or contains duplicates."
        )
    if certs[-1].fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
        raise CertificateMaterialError(
            "Certificate chain does not terminate at the expected root."
        )
    for index, cert in enumerate(certs):
        _reject_unknown_critical_extensions(cert)
        if (
            not cert.not_valid_before_utc
            <= datetime.now(timezone.utc)
            <= cert.not_valid_after_utc
        ):
            raise CertificateMaterialError(
                "Certificate chain contains an expired or not-yet-valid certificate."
            )
        if not _ca(cert):
            raise CertificateMaterialError(
                "Certificate chain contains a non-CA certificate."
            )
        issuer = certs[index + 1] if index + 1 < len(certs) else cert
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if not usage.key_cert_sign:
                raise CertificateMaterialError(
                    "CA certificate cannot sign certificates."
                )
        except x509.ExtensionNotFound:
            pass
        if cert.issuer != issuer.subject:
            raise CertificateMaterialError("Certificate chain issuer order is invalid.")
        _verify_signature(cert, issuer)
        try:
            path_length = cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value.path_length
        except x509.ExtensionNotFound:
            path_length = None
        subordinate_ca_count = max(0, index)
        if path_length is not None and subordinate_ca_count > path_length:
            raise CertificateMaterialError(
                "Certificate chain exceeds a CA path length constraint."
            )
    if root.issuer != root.subject:
        raise CertificateMaterialError("Expected trust root is not self-issued.")
    return b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs)


def certificate_metadata(cert: x509.Certificate) -> CertificateMetadata:
    """Return safe, public certificate fields for review screens."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        dns: tuple[str, ...] = ()
        ips: tuple[str, ...] = ()
    else:
        dns = tuple(sorted(san.get_values_for_type(x509.DNSName)))
        ips = tuple(
            sorted(str(value) for value in san.get_values_for_type(x509.IPAddress))
        )
    fingerprint = (
        sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    )
    return CertificateMetadata(
        cert.subject.rfc4514_string(),
        cert.issuer.rfc4514_string(),
        format(cert.serial_number, "X"),
        cert.not_valid_before_utc.isoformat(),
        cert.not_valid_after_utc.isoformat(),
        fingerprint,
        dns,
        ips,
    )
