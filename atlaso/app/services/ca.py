"""Implement ca service behavior."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import PurePosixPath

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.models import CaCertificate, CaProfile, CaSettings, utcnow
from atlaso.app.secrets import decrypt_secret, encrypt_secret, secret_key_status

CA_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/ca/atlaso-ca.json"
CA_DEFAULT_PORTAL_HOSTNAME = "ca.atlaso.internal"
CA_MANAGED_PATH_BASE = PurePosixPath("/etc/atlaso")
CA_SERVER_PROFILE_NAME = "VCF service TLS"
CA_CLIENT_PROFILE_NAME = "VCF KMIP client"
CA_STATUS_VALUES = {"planned", "csr-staged", "issued", "revoked"}
SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class ManagedCertificateSpec:
    """Represent managed certificate spec.

    Attributes:
        owner: Owner maintained by this managedcertificatespec.
        common_name: Common name maintained by this managedcertificatespec.
        dns_names: Dns names maintained by this managedcertificatespec.
        ip_addresses: Ip addresses maintained by this managedcertificatespec.
        profile_name: Profile name maintained by this managedcertificatespec.
        description: Operator-facing purpose or context for the resource.
        cert_path: Filesystem path used for cert.
        key_path: Filesystem path used for key.
        chain_path: Filesystem path used for chain.
    """
    owner: str
    common_name: str
    dns_names: list[str]
    ip_addresses: list[str]
    profile_name: str
    description: str
    cert_path: str
    key_path: str
    chain_path: str


def split_multiline(value: str | None) -> list[str]:
    """Return split multiline.

    Args:
        value: Comma- or newline-delimited text to normalize into unique entries.
    """
    if not value:
        return []
    items: list[str] = []
    for line in value.replace(",", "\n").splitlines():
        item = line.strip().strip(",")
        if item and item not in items:
            items.append(item)
    return items


def managed_certificate_for_owner(db: Session, owner: str) -> CaCertificate | None:
    """Return the newest managed certificate row for an owner.

    Older appliances can contain duplicate owner rows. Treat the newest row as
    canonical so read-only status and preview paths remain available while the
    managed-certificate reconciliation converges the desired state.

    Args:
        db: Active database session used to query certificate records.
        owner: Stable managed-owner identifier assigned to the certificate.
    """
    return db.execute(
        select(CaCertificate)
        .where(CaCertificate.managed_owner == owner)
        .order_by(CaCertificate.id.desc())
    ).scalars().first()


def join_multiline(values: list[str]) -> str:
    """Return join multiline.

    Args:
        values: Entries to normalize and serialize as newline-delimited text.
    """
    return "\n".join(split_multiline("\n".join(values)))


def ca_service_state(settings: CaSettings) -> dict[str, object]:
    """Return ca service state.

    Args:
        settings: Saved CA settings whose desired enablement and root material determine service
            health.
    """
    desired_enabled = bool(settings.enabled)
    has_material = bool(settings.root_certificate_pem and settings.root_private_key_encrypted)
    running = desired_enabled and has_material
    if running:
        health = "healthy"
        label = "live"
        pill = "good"
    elif desired_enabled:
        health = "degraded"
        label = "enabled"
        pill = "warn"
    else:
        health = "disabled"
        label = "disabled"
        pill = "muted"
    return {
        "running": running,
        "enabled": desired_enabled,
        "health": health,
        "label": label,
        "pill": pill,
    }


def safe_certificate_name(value: str) -> str:
    """Return safe certificate name.

    Args:
        value: Operator-provided certificate name to make safe for filesystem use.
    """
    safe = SAFE_NAME_PATTERN.sub("-", value.strip()).strip("-")
    return safe or "certificate"


def _hash_algorithm(name: str) -> hashes.HashAlgorithm:
    """Return hash algorithm.

    Args:
        name: Configured digest name; unsupported values fall back to SHA-256.
    """
    return {"sha384": hashes.SHA384(), "sha512": hashes.SHA512()}.get(name.lower(), hashes.SHA256())


def _private_key(algorithm: str, key_size: int):
    """Return private key.

    Args:
        algorithm: Key algorithm name, currently RSA or ECDSA.
        key_size: Requested RSA key size or ECDSA curve size in bits.
    """
    if algorithm.upper() == "ECDSA":
        curve = ec.SECP521R1() if key_size >= 521 else ec.SECP384R1() if key_size >= 384 else ec.SECP256R1()
        return ec.generate_private_key(curve)
    return rsa.generate_private_key(public_exponent=65537, key_size=max(key_size, 2048))


def _subject(
    *,
    common_name: str,
    organization: str,
    organizational_unit: str = "",
    country: str = "",
    state: str = "",
    locality: str = "",
) -> x509.Name:
    """Return subject.

    Args:
        common_name: Certificate subject common name.
        organization: X.509 subject organization, defaulting to Atlaso when empty.
        organizational_unit: Optional X.509 subject organizational unit.
        country: Optional two-letter X.509 subject country code.
        state: Optional X.509 subject state or province.
        locality: Optional X.509 subject locality or city.
    """
    parts = [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or "Atlaso"),
    ]
    if organizational_unit:
        parts.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    if country:
        parts.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()))
    if state:
        parts.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        parts.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    return x509.Name(parts)


def _pem_private_key(private_key) -> str:
    """Return pem private key.

    Args:
        private_key: Cryptography private-key object to serialize as unencrypted PKCS#8 PEM.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _pem_public_cert(certificate: x509.Certificate) -> str:
    """Return pem public cert.

    Args:
        certificate: Parsed X.509 certificate to serialize as PEM.
    """
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _fingerprint(certificate: x509.Certificate) -> str:
    """Return fingerprint.

    Args:
        certificate: Parsed X.509 certificate whose SHA-256 fingerprint is required.
    """
    return certificate.fingerprint(hashes.SHA256()).hex()


def _load_root(settings: CaSettings) -> tuple[x509.Certificate, object]:
    """Return root.

    Args:
        settings: Saved CA settings containing the root certificate and encrypted private key.


    Raises:
        ValueError: If an input value is invalid.
    """
    if not settings.root_certificate_pem or not settings.root_private_key_encrypted:
        raise ValueError("Atlaso root CA material is not available.")
    certificate = x509.load_pem_x509_certificate(settings.root_certificate_pem.encode("utf-8"))
    private_key_pem = decrypt_secret(settings.root_private_key_encrypted)
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    return certificate, private_key


def generate_crl_pem(settings: CaSettings, certificates: list[CaCertificate]) -> str:
    """Build crl pem.

    Args:
        settings: Saved CA settings containing the root signing material.
        certificates: Issued certificate records from which revoked serial numbers are collected.


    Returns:
        The generate crl pem result.
    """
    revoked_certificates = [
        certificate
        for certificate in certificates
        if certificate.status == "revoked" and certificate.serial_number and certificate.revoked_at
    ]
    if not revoked_certificates or not settings.root_certificate_pem or not settings.root_private_key_encrypted:
        return ""
    root_certificate, root_private_key = _load_root(settings)
    now = utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_certificate.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )
    for certificate in revoked_certificates:
        revoked_at = ensure_aware(certificate.revoked_at)
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(str(certificate.serial_number), 16))
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(private_key=root_private_key, algorithm=_hash_algorithm(settings.digest_algorithm)).public_bytes(serialization.Encoding.PEM).decode("utf-8")


def ensure_default_ca_profiles(db: Session) -> bool:
    """Ensure default ca profiles.

    Args:
        db: Active database session in which missing built-in profiles are created.

    Returns:
        The ensure default ca profiles result.
    """
    changed = False
    existing = {profile.name for profile in db.execute(select(CaProfile)).scalars().all()}
    if CA_SERVER_PROFILE_NAME not in existing:
        db.add(
            CaProfile(
                name=CA_SERVER_PROFILE_NAME,
                certificate_type="server",
                validity_days=825,
                key_algorithm="RSA",
                key_size=2048,
                key_usage="digitalSignature,keyEncipherment",
                extended_key_usage="serverAuth",
                san_required=True,
                description="Default profile for VCF lab services and appliance HTTPS endpoints.",
            )
        )
        changed = True
    if CA_CLIENT_PROFILE_NAME not in existing:
        db.add(
            CaProfile(
                name=CA_CLIENT_PROFILE_NAME,
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
        changed = True
    if changed:
        db.flush()
    return changed


def ensure_root_ca_material(settings: CaSettings) -> bool:
    """Ensure root ca material.

    Args:
        settings: Saved CA settings to populate with generated root certificate material.


    Returns:
        The ensure root ca material result.
    """
    if settings.root_certificate_pem and settings.root_private_key_encrypted:
        return False

    private_key = _private_key(settings.key_algorithm, settings.key_size)
    subject = _subject(
        common_name=settings.root_common_name or "Atlaso Internal Root CA",
        organization=settings.organization or "Atlaso",
        organizational_unit=settings.organizational_unit,
        country=settings.country,
        state=settings.state,
        locality=settings.locality,
    )
    now = utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=max(settings.root_valid_days, 365)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, _hash_algorithm(settings.digest_algorithm))
    )
    settings.root_certificate_pem = _pem_public_cert(certificate)
    settings.root_private_key_encrypted = encrypt_secret(_pem_private_key(private_key))
    settings.root_serial_number = format(certificate.serial_number, "x")
    settings.root_fingerprint = _fingerprint(certificate)
    settings.root_issued_at = certificate.not_valid_before_utc
    settings.root_expires_at = certificate.not_valid_after_utc
    settings.updated_at = utcnow()
    return True


def import_root_ca_material(
    settings: CaSettings,
    certificate_pem: str,
    private_key_pem: str,
    *,
    expected_common_name: str = "",
) -> None:
    """Validate and import externally supplied root CA material.

    Args:
        settings: Saved CA settings to populate with encrypted root material.
        certificate_pem: One canonical self-signed CA certificate PEM.
        private_key_pem: Matching unencrypted private-key PEM held in memory.
        expected_common_name: Optional exact root common name required by the caller.

    Raises:
        ValueError: If the material is malformed, unsafe, expired, or mismatched.
    """
    normalized_certificate_pem = certificate_pem.strip()
    normalized_private_key_pem = private_key_pem.strip()
    if (
        normalized_certificate_pem.count("-----BEGIN CERTIFICATE-----") != 1
        or "PRIVATE KEY" in normalized_certificate_pem
        or len(normalized_certificate_pem) > 32768
        or len(normalized_private_key_pem) > 16384
    ):
        raise ValueError("Development root CA material is not one bounded certificate and private key.")
    try:
        certificate = x509.load_pem_x509_certificate(
            normalized_certificate_pem.encode("utf-8")
        )
        private_key = serialization.load_pem_private_key(
            normalized_private_key_pem.encode("utf-8"),
            password=None,
        )
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except (TypeError, UnsupportedAlgorithm, ValueError, x509.ExtensionNotFound) as exc:
        raise ValueError("Development root CA material is not usable.") from exc

    canonical_certificate_pem = _pem_public_cert(certificate).strip()
    if canonical_certificate_pem != normalized_certificate_pem:
        raise ValueError("Development root CA certificate PEM is not canonical.")
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = common_names[0].value if len(common_names) == 1 else ""
    if expected_common_name and common_name != expected_common_name:
        raise ValueError("Development root CA common name does not match the required trust anchor.")
    if (
        not constraints.ca
        or not key_usage.key_cert_sign
        or not key_usage.crl_sign
        or certificate.subject != certificate.issuer
    ):
        raise ValueError("Development root certificate is not a self-signed CA certificate.")
    now = datetime.now(timezone.utc)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
        raise ValueError("Development root CA certificate is not currently valid.")

    public_key = certificate.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        else:
            raise ValueError("Development root CA key algorithm is unsupported.")
    except (InvalidSignature, TypeError, UnsupportedAlgorithm, ValueError) as exc:
        raise ValueError("Development root CA certificate signature is invalid.") from exc

    certificate_public = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public != private_public:
        raise ValueError("Development root CA certificate and private key do not match.")

    settings.root_common_name = common_name
    organizations = certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    settings.organization = organizations[0].value if organizations else ""
    settings.key_algorithm = "RSA" if isinstance(private_key, rsa.RSAPrivateKey) else "EC"
    settings.key_size = private_key.key_size
    settings.digest_algorithm = certificate.signature_hash_algorithm.name
    settings.root_certificate_pem = canonical_certificate_pem + "\n"
    settings.root_private_key_encrypted = encrypt_secret(
        _pem_private_key(private_key)
    )
    settings.root_serial_number = format(certificate.serial_number, "x")
    settings.root_fingerprint = _fingerprint(certificate)
    settings.root_issued_at = certificate.not_valid_before_utc
    settings.root_expires_at = certificate.not_valid_after_utc
    settings.updated_at = utcnow()


def _certificate_profile(profiles: list[CaProfile], certificate: CaCertificate) -> CaProfile | None:
    """Return certificate profile.

    Args:
        profiles: Available CA profiles indexed by the certificate's profile identifier.
        certificate: Certificate record whose issuing profile is required.
    """
    return next((profile for profile in profiles if profile.id == certificate.profile_id), None)


def _extended_key_usage(value: str) -> x509.ExtendedKeyUsage | None:
    """Return extended key usage.

    Args:
        value: Comma- or newline-delimited extended-key-usage names from a CA profile.
    """
    usages = []
    for item in split_multiline(value):
        normalized = item.strip()
        if normalized == "serverAuth":
            usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
        elif normalized == "clientAuth":
            usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    return x509.ExtendedKeyUsage(usages) if usages else None


def _key_usage(value: str) -> x509.KeyUsage:
    """Return key usage.

    Args:
        value: Comma- or newline-delimited key-usage names from a CA profile.
    """
    usages = {item.strip() for item in split_multiline(value)}
    return x509.KeyUsage(
        digital_signature="digitalSignature" in usages,
        content_commitment="contentCommitment" in usages,
        key_encipherment="keyEncipherment" in usages,
        data_encipherment="dataEncipherment" in usages,
        key_agreement="keyAgreement" in usages,
        key_cert_sign="keyCertSign" in usages,
        crl_sign="cRLSign" in usages,
        encipher_only=None,
        decipher_only=None,
    )


def certificate_needs_issue(certificate: CaCertificate) -> bool:
    """Return certificate needs issue.

    Args:
        certificate: Certificate record inspected for missing or stale issued material.
    """
    if certificate.status != "issued":
        return True
    if not certificate.certificate_pem:
        return True
    if not certificate.csr_text and not certificate.private_key_encrypted:
        return True
    expires_at = certificate.expires_at
    return bool(expires_at and ensure_aware(expires_at) <= utcnow() + timedelta(days=30))


def ensure_aware(value: datetime) -> datetime:
    """Ensure aware.

    Args:
        value: Datetime to normalize, treating a naive value as UTC.


    Returns:
        The ensure aware result.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def issue_certificate(settings: CaSettings, profiles: list[CaProfile], certificate: CaCertificate) -> bool:
    """Return issue certificate.

    Args:
        settings: Saved CA settings containing the root signing material.
        profiles: Available CA profiles used to select issuance constraints.
        certificate: Desired certificate record to issue and update in place.
    """
    if not certificate.enabled or certificate.status == "revoked" or not certificate_needs_issue(certificate):
        return False
    profile = _certificate_profile(profiles, certificate)
    if profile is None:
        return False
    root_certificate, root_private_key = _load_root(settings)
    now = utcnow()
    dns_names = split_multiline(certificate.subject_alt_names)
    ip_names = split_multiline(certificate.ip_addresses)
    san_values: list[x509.GeneralName] = [x509.DNSName(item) for item in dns_names]
    san_values.extend(x509.IPAddress(ip_address(item)) for item in ip_names)

    private_key = None
    if certificate.csr_text:
        csr = x509.load_pem_x509_csr(certificate.csr_text.encode("utf-8"))
        public_key = csr.public_key()
        subject = csr.subject
    else:
        private_key = _private_key(profile.key_algorithm, profile.key_size)
        public_key = private_key.public_key()
        subject = _subject(
            common_name=certificate.common_name,
            organization=settings.organization or "Atlaso",
            organizational_unit=settings.organizational_unit,
            country=settings.country,
            state=settings.state,
            locality=settings.locality,
        )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(min(root_certificate.not_valid_after_utc, now + timedelta(days=max(profile.validity_days, 1))))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(profile.key_usage), critical=True)
    )
    if san_values:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_values), critical=False)
    eku = _extended_key_usage(profile.extended_key_usage)
    if eku is not None:
        builder = builder.add_extension(eku, critical=False)
    issued = builder.sign(root_private_key, _hash_algorithm(settings.digest_algorithm))

    certificate.certificate_pem = _pem_public_cert(issued)
    certificate.chain_pem = f"{certificate.certificate_pem}{settings.root_certificate_pem}"
    certificate.issuer_common_name = settings.root_common_name
    certificate.serial_number = format(issued.serial_number, "x")
    certificate.fingerprint = _fingerprint(issued)
    certificate.issued_at = issued.not_valid_before_utc
    certificate.expires_at = issued.not_valid_after_utc
    certificate.status = "issued"
    if private_key is not None:
        certificate.private_key_encrypted = encrypt_secret(_pem_private_key(private_key))
    return True


def ensure_managed_certificate_rows(
    db: Session,
    *,
    settings: CaSettings,
    profiles: list[CaProfile],
    specs: list[ManagedCertificateSpec],
) -> bool:
    """Ensure managed certificate rows.

    Args:
        db: Active database session used to reconcile managed certificate records.
        settings: Saved CA settings controlling whether managed certificates are enabled.
        profiles: Available CA profiles used to resolve each desired specification.
        specs: Desired managed-certificate specifications keyed by stable owner identity.

    Returns:
        The ensure managed certificate rows result.
    """
    if not settings.enabled:
        return False
    changed = False
    profile_by_name = {profile.name: profile for profile in profiles}
    existing_by_owner = {
        certificate.managed_owner: certificate
        for certificate in db.execute(select(CaCertificate).where(CaCertificate.managed_owner != "")).scalars().all()
    }
    for spec in specs:
        profile = profile_by_name.get(spec.profile_name)
        if profile is None:
            continue
        certificate = existing_by_owner.get(spec.owner)
        if certificate is None:
            certificate = CaCertificate(common_name=spec.common_name, managed_owner=spec.owner, enabled=True)
            db.add(certificate)
            changed = True
        desired_dns = join_multiline(spec.dns_names)
        desired_ips = join_multiline(spec.ip_addresses)
        updates = {
            "common_name": spec.common_name,
            "profile_id": profile.id,
            "subject_alt_names": desired_dns,
            "ip_addresses": desired_ips,
            "description": spec.description,
            "cert_path": spec.cert_path,
            "key_path": spec.key_path,
            "chain_path": spec.chain_path,
            "enabled": True,
        }
        stale = False
        for key, value in updates.items():
            if getattr(certificate, key) != value:
                setattr(certificate, key, value)
                stale = True
        if stale:
            certificate.status = "planned"
            changed = True
    if changed:
        db.flush()
    return changed


def ensure_ca_issued_state(
    db: Session,
    *,
    settings: CaSettings,
    profiles: list[CaProfile],
    certificates: list[CaCertificate],
) -> bool:
    """Ensure ca issued state.

    Args:
        db: Active database session used to persist issuance changes.
        settings: Saved CA settings containing root signing material and lifecycle policy.
        profiles: Available CA profiles used to issue desired certificates.
        certificates: Certificate records to inspect and issue when required.

    Returns:
        The ensure ca issued state result.
    """
    changed = ensure_root_ca_material(settings)
    if settings.enabled:
        for certificate in certificates:
            changed = issue_certificate(settings, profiles, certificate) or changed
    if changed:
        db.flush()
    return changed


def ca_profile_to_dict(profile: CaProfile) -> dict:
    """Return ca profile to dict.

    Args:
        profile: CA profile to serialize for API or UI consumption.
    """
    return {
        "id": profile.id,
        "name": profile.name,
        "certificate_type": profile.certificate_type,
        "validity_days": profile.validity_days,
        "key_algorithm": profile.key_algorithm,
        "key_size": profile.key_size,
        "key_usage": profile.key_usage,
        "extended_key_usage": profile.extended_key_usage,
        "san_required": profile.san_required,
        "enabled": profile.enabled,
        "description": profile.description or "",
    }


def ca_certificate_can_edit(certificate: CaCertificate) -> bool:
    """Return ca certificate can edit.

    Args:
        certificate: Certificate record whose managed and issuance state controls editability.
    """
    return not certificate.managed_owner and certificate.status == "planned" and not certificate.certificate_pem


def ca_certificate_can_delete(certificate: CaCertificate) -> bool:
    """Return ca certificate can delete.

    Args:
        certificate: Certificate record whose managed status controls deletion.
    """
    return not certificate.managed_owner


def validate_ca_certificate_request(
    *,
    profile: CaProfile | None,
    common_name: str,
    subject_alt_names: str,
    ip_addresses: str,
) -> list[str]:
    """Validate ca certificate request.

    Args:
        profile: CA profile whose subject and SAN constraints must be enforced.
        common_name: Requested certificate subject common name.
        subject_alt_names: Requested DNS subject-alternative names.
        ip_addresses: Requested IP-address subject-alternative names.


    Returns:
        The validate ca certificate request result.
    """
    errors: list[str] = []
    normalized_common_name = common_name.strip()
    if not normalized_common_name:
        errors.append("Certificate common name is required.")
    if profile is None or not profile.enabled:
        errors.append("Select an enabled CA profile.")

    dns_names = split_multiline(subject_alt_names)
    ip_names = split_multiline(ip_addresses)
    if profile is not None and profile.enabled and profile.san_required and not dns_names and not ip_names:
        errors.append(f"Certificate {normalized_common_name or 'request'} requires at least one DNS name or IP SAN.")
    for item in ip_names:
        try:
            ip_address(item)
        except ValueError:
            errors.append(f"Certificate {normalized_common_name or 'request'} has invalid IP SAN {item}.")
    return errors


def ca_certificate_to_dict(certificate: CaCertificate) -> dict:
    """Return ca certificate to dict.

    Args:
        certificate: Certificate record to serialize for API or UI consumption.
    """
    can_export_certificate = certificate.status == "issued" and bool(certificate.certificate_pem)
    return {
        "id": certificate.id,
        "common_name": certificate.common_name,
        "profile_id": certificate.profile_id or "",
        "profile_name": certificate.profile.name if certificate.profile else "Unassigned",
        "subject_alt_names": certificate.subject_alt_names,
        "ip_addresses": certificate.ip_addresses,
        "status": certificate.status,
        "serial_number": certificate.serial_number or "",
        "fingerprint": certificate.fingerprint or "",
        "managed_owner": certificate.managed_owner or "manual",
        "cert_path": certificate.cert_path or "",
        "enabled": certificate.enabled,
        "description": certificate.description or "",
        "has_certificate": bool(certificate.certificate_pem),
        "has_private_key": bool(certificate.private_key_encrypted),
        "can_edit": ca_certificate_can_edit(certificate),
        "can_delete": ca_certificate_can_delete(certificate),
        "can_export_certificate": can_export_certificate,
        "can_export_chain": can_export_certificate,
        "can_export_private_key": can_export_certificate and bool(certificate.private_key_encrypted),
        "revoked_at": certificate.revoked_at.isoformat() if certificate.revoked_at else "",
        "revoked_by": certificate.revoked_by or "",
        "revocation_reason": certificate.revocation_reason or "",
    }


def render_ca_config(
    *,
    settings: CaSettings,
    profiles: list[CaProfile],
    certificates: list[CaCertificate],
) -> str:
    """Render ca config.

    Args:
        settings: Saved CA settings to expose to the constrained appliance helper.
        profiles: CA profiles included in the staged desired-state configuration.
        certificates: Certificate records included in the staged desired-state configuration.


    Returns:
        The rendered ca config.
    """
    payload = {
        "managed_by": "Atlaso",
        "enabled": settings.enabled,
        "portal_hostname": settings.portal_hostname,
        "storage_path": settings.storage_path,
        "publication": {
            "portal_hostname": settings.portal_hostname,
            "listen_interfaces": settings.listen_interface,
            "listen_addresses": settings.listen_address,
        },
        "root": {
            "common_name": settings.root_common_name,
            "organization": settings.organization,
            "key": f"{settings.key_algorithm}:{settings.key_size}",
            "digest": settings.digest_algorithm,
            "serial_number": settings.root_serial_number,
            "fingerprint": settings.root_fingerprint,
            "issued_at": settings.root_issued_at.isoformat() if settings.root_issued_at else "",
            "expires_at": settings.root_expires_at.isoformat() if settings.root_expires_at else "",
            "certificate_pem": "[public certificate available]" if settings.root_certificate_pem else "",
            "private_key": "[encrypted in Atlaso database]" if settings.root_private_key_encrypted else "",
        },
        "profiles": [ca_profile_to_dict(profile) for profile in profiles if profile.enabled],
        "certificates": [
            {
                "common_name": certificate.common_name,
                "managed_owner": certificate.managed_owner or "manual",
                "status": certificate.status,
                "serial_number": certificate.serial_number or "",
                "fingerprint": certificate.fingerprint or "",
                "cert_path": certificate.cert_path or "",
                "key_path": certificate.key_path or "",
                "chain_path": certificate.chain_path or "",
                "private_key": "[encrypted in Atlaso database]" if certificate.private_key_encrypted else "",
            }
            for certificate in certificates
            if certificate.enabled
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_ca_apply_payload(settings: CaSettings, certificates: list[CaCertificate], *, include_private_keys: bool) -> str:
    """Render ca apply payload.

    Args:
        settings: Saved CA settings represented in the reviewed apply payload.
        certificates: Certificate records represented in the reviewed apply payload.
        include_private_keys: Whether the constrained helper payload may contain private-key
            material required for deployment.


    Returns:
        The rendered ca apply payload.
    """
    root_cert_path = str(PurePosixPath(settings.storage_path) / "root-ca.pem")
    legacy_root_path = str(PurePosixPath(settings.storage_path) / "root.crt")
    bundle_path = str(PurePosixPath(settings.storage_path) / "ca-bundle.pem")
    crl_path = str(PurePosixPath(settings.storage_path) / "atlaso-ca.crl")
    crl_pem = generate_crl_pem(settings, certificates) if settings.publish_crl else ""
    payload = {
        "enabled": settings.enabled,
        "portal_hostname": settings.portal_hostname,
        "storage_path": settings.storage_path,
        "publication": {
            "portal_hostname": settings.portal_hostname,
            "listen_interfaces": settings.listen_interface,
            "listen_addresses": settings.listen_address,
        },
        "root": {
            "common_name": settings.root_common_name,
            "certificate_pem": settings.root_certificate_pem,
            "private_key_pem": decrypt_secret(settings.root_private_key_encrypted) if include_private_keys and settings.root_private_key_encrypted else "[redacted]",
            "root_cert_path": root_cert_path,
            "legacy_root_cert_path": legacy_root_path,
            "ca_bundle_path": bundle_path,
            "crl_path": crl_path,
            "crl_pem": crl_pem if include_private_keys else ("[public CRL available]" if crl_pem else ""),
            "fingerprint": settings.root_fingerprint,
            "expires_at": settings.root_expires_at.isoformat() if settings.root_expires_at else "",
        },
        "certificates": [],
    }
    for certificate in certificates:
        if not certificate.enabled or certificate.status == "revoked":
            continue
        private_key_pem = ""
        if certificate.private_key_encrypted:
            private_key_pem = decrypt_secret(certificate.private_key_encrypted) if include_private_keys else "[redacted]"
        payload["certificates"].append(
            {
                "common_name": certificate.common_name,
                "managed_owner": certificate.managed_owner or "",
                "certificate_pem": certificate.certificate_pem,
                "chain_pem": certificate.chain_pem or f"{certificate.certificate_pem}{settings.root_certificate_pem}",
                "private_key_pem": private_key_pem,
                "cert_path": certificate.cert_path,
                "key_path": certificate.key_path,
                "chain_path": certificate.chain_path,
                "fingerprint": certificate.fingerprint,
                "expires_at": certificate.expires_at.isoformat() if certificate.expires_at else "",
            }
        )
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def validate_ca_private_key_material(
    settings: CaSettings,
    certificates: list[CaCertificate],
) -> list[str]:
    """Validate encrypted private keys consumed by the CA apply payload.

    Args:
        settings: Saved CA settings containing optional encrypted root material.
        certificates: Certificate records that may contain deployable encrypted keys.

    Returns:
        Public-safe validation errors for encrypted keys that cannot be decrypted and imported.
    """
    def certificate_signature_is_valid(
        certificate: x509.Certificate,
        issuer: x509.Certificate,
    ) -> bool:
        """Return whether one supported certificate signature verifies.

        Args:
            certificate: Certificate whose signature is verified.
            issuer: Certificate containing the expected issuer public key.
        """
        public_key = issuer.public_key()
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    ec.ECDSA(certificate.signature_hash_algorithm),
                )
            else:
                return False
        except (InvalidSignature, TypeError, UnsupportedAlgorithm, ValueError):
            return False
        return True

    errors: list[str] = []
    root_certificate: x509.Certificate | None = None
    if bool((settings.root_certificate_pem or "").strip()) != bool(
        (settings.root_private_key_encrypted or "").strip()
    ):
        errors.append(
            "CA root certificate and encrypted private key must be restored together."
        )
    if settings.root_certificate_pem:
        try:
            root_pem = settings.root_certificate_pem.strip()
            if (
                root_pem.count("-----BEGIN CERTIFICATE-----") != 1
                or "PRIVATE KEY" in root_pem
            ):
                raise ValueError
            root_certificate = x509.load_pem_x509_certificate(
                root_pem.encode("utf-8")
            )
            constraints = root_certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            canonical_pem = root_certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode("utf-8").strip()
            if (
                not constraints.ca
                or root_certificate.issuer != root_certificate.subject
                or not certificate_signature_is_valid(root_certificate, root_certificate)
                or root_pem != canonical_pem
            ):
                raise ValueError
            now = datetime.now(timezone.utc)
            if root_certificate.not_valid_before_utc > now:
                errors.append("CA root certificate is not yet valid.")
                root_certificate = None
            elif root_certificate.not_valid_after_utc <= now:
                errors.append("CA root certificate has expired.")
                root_certificate = None
        except (
            TypeError,
            UnsupportedAlgorithm,
            ValueError,
            x509.ExtensionNotFound,
        ):
            errors.append("CA root certificate is not a valid self-signed certificate.")
            root_certificate = None

    parsed_certificates: dict[int, x509.Certificate] = {}
    now = datetime.now(timezone.utc)
    for certificate in certificates:
        if not certificate.enabled:
            continue
        label = f"Certificate {certificate.common_name}"
        if not certificate.certificate_pem:
            continue
        try:
            parsed_certificate = x509.load_pem_x509_certificate(
                certificate.certificate_pem.encode("utf-8")
            )
            parsed_certificates[id(certificate)] = parsed_certificate
        except (TypeError, ValueError):
            errors.append(f"{label} certificate is not usable on this appliance.")
            continue
        if certificate.status == "issued" and (
            parsed_certificate.not_valid_before_utc > now
            or parsed_certificate.not_valid_after_utc <= now
        ):
            errors.append(f"{label} is not currently valid.")
        if certificate.status in {"issued", "revoked"} and (
            root_certificate is None
            or parsed_certificate.issuer != root_certificate.subject
            or not certificate_signature_is_valid(parsed_certificate, root_certificate)
        ):
            errors.append(f"{label} is not issued by the restored CA root.")
        if (
            certificate.status in {"issued", "revoked"}
            and certificate.chain_pem
            and root_certificate is not None
        ):
            try:
                chain = x509.load_pem_x509_certificates(
                    certificate.chain_pem.encode("utf-8")
                )
                expected_chain = [parsed_certificate, root_certificate]
                if len(chain) != len(expected_chain) or any(
                    actual.fingerprint(hashes.SHA256())
                    != expected.fingerprint(hashes.SHA256())
                    for actual, expected in zip(chain, expected_chain, strict=True)
                ):
                    raise ValueError
            except (TypeError, ValueError):
                errors.append(f"{label} chain does not match the restored CA root.")

    candidates: list[tuple[str, str, x509.Certificate | None]] = []
    if settings.root_private_key_encrypted:
        candidates.append(
            (
                "CA root",
                settings.root_private_key_encrypted,
                root_certificate,
            )
        )
    candidates.extend(
        (
            f"Certificate {certificate.common_name}",
            certificate.private_key_encrypted,
            parsed_certificates.get(id(certificate)),
        )
        for certificate in certificates
        if certificate.enabled
        and certificate.status != "revoked"
        and certificate.private_key_encrypted
    )
    for label, encrypted_key, certificate in candidates:
        try:
            private_key_pem = decrypt_secret(encrypted_key)
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=None,
            )
        except (TypeError, UnsupportedAlgorithm, ValueError):
            errors.append(f"{label} encrypted private key is not usable on this appliance.")
            continue
        if certificate is None:
            continue
        private_public_key = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        certificate_public_key = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if private_public_key != certificate_public_key:
            errors.append(f"{label} encrypted private key does not match its certificate.")
    return errors


def validate_ca_state(
    *,
    settings: CaSettings,
    profiles: list[CaProfile],
    certificates: list[CaCertificate],
) -> list[str]:
    """Validate ca state.

    Args:
        settings: Saved CA settings to validate before staging or apply.
        profiles: CA profiles whose names, algorithms, and validity constraints are validated.
        certificates: Certificate records whose profile references and requested names are
            validated.


    Returns:
        The validate ca state result.
    """
    errors: list[str] = []

    def managed_path_error(value: str, label: str, *, required: bool = False) -> str:
        """Return a bounded error when a CA apply path escapes its managed directory.

        Args:
            value: Candidate managed filesystem path.
            label: Public-safe field label used in validation feedback.
            required: Require a nonempty path when true.
        """
        raw_value = value.strip()
        if not raw_value:
            return f"{label} is required." if required else ""
        path = PurePosixPath(raw_value)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or not path.is_relative_to(CA_MANAGED_PATH_BASE)
        ):
            return f"{label} must stay under {CA_MANAGED_PATH_BASE}."
        return ""

    storage_path_error = managed_path_error(
        settings.storage_path,
        "CA storage path",
        required=True,
    )
    if storage_path_error:
        errors.append(storage_path_error)
    if settings.enabled and not secret_key_status(get_settings()).dedicated and get_settings().environment not in {"development", "test"}:
        errors.append("ATLASO_SECRETS_KEY is required before enabling the CA outside development.")
    if not settings.portal_hostname.strip() or "." not in settings.portal_hostname.strip():
        errors.append("CA portal hostname must be a fully qualified DNS name.")
    elif not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", settings.portal_hostname.strip().lower()):
        errors.append("CA portal hostname must be a valid DNS name.")
    if not settings.root_common_name.strip():
        errors.append("CA root common name is required.")
    if settings.country and len(settings.country.strip()) != 2:
        errors.append("CA country must be a two-letter ISO code.")
    if settings.key_algorithm not in {"RSA", "ECDSA"}:
        errors.append("CA key algorithm must be RSA or ECDSA.")
    if settings.key_algorithm == "RSA" and settings.key_size < 2048:
        errors.append("CA RSA key size must be at least 2048 bits.")
    if settings.root_valid_days < 365:
        errors.append("CA root validity should be at least 365 days.")
    if settings.enabled and not settings.root_certificate_pem:
        errors.append("CA root certificate material is not available.")

    enabled_profiles = {profile.id: profile for profile in profiles if profile.enabled}
    for profile in profiles:
        if not profile.name.strip():
            errors.append("CA profile name is required.")
        if profile.certificate_type not in {"server", "client", "user", "intermediate"}:
            errors.append(f"CA profile {profile.name or profile.id} has an unsupported type.")
        if profile.validity_days < 1:
            errors.append(f"CA profile {profile.name or profile.id} validity must be at least one day.")
        if profile.key_algorithm == "RSA" and profile.key_size < 2048:
            errors.append(f"CA profile {profile.name or profile.id} RSA key size must be at least 2048 bits.")

    for certificate in certificates:
        if not certificate.enabled:
            continue
        for value, label in (
            (certificate.cert_path, f"Certificate {certificate.common_name or certificate.id} certificate path"),
            (certificate.key_path, f"Certificate {certificate.common_name or certificate.id} private-key path"),
            (certificate.chain_path, f"Certificate {certificate.common_name or certificate.id} chain path"),
        ):
            path_error = managed_path_error(value, label)
            if path_error:
                errors.append(path_error)
        if certificate.status not in CA_STATUS_VALUES:
            errors.append(f"Certificate {certificate.common_name or certificate.id} has unsupported status {certificate.status}.")
        if not certificate.common_name.strip():
            errors.append("Certificate common name is required.")
        if certificate.profile_id and certificate.profile_id not in enabled_profiles:
            errors.append(f"Certificate {certificate.common_name or certificate.id} uses a disabled or missing CA profile.")
        profile = enabled_profiles.get(certificate.profile_id)
        dns_names = split_multiline(certificate.subject_alt_names)
        ip_addresses = split_multiline(certificate.ip_addresses)
        if profile and profile.san_required and not dns_names and not ip_addresses:
            errors.append(f"Certificate {certificate.common_name} requires at least one DNS name or IP SAN.")
        for item in ip_addresses:
            try:
                ip_address(item)
            except ValueError:
                errors.append(f"Certificate {certificate.common_name} has invalid IP SAN {item}.")
        if settings.enabled and certificate.status == "issued" and not certificate.certificate_pem:
            errors.append(f"Certificate {certificate.common_name} is marked issued but has no certificate PEM.")
        if settings.enabled and certificate.status == "revoked" and not certificate.serial_number:
            errors.append(f"Revoked certificate {certificate.common_name} has no serial number for CRL publication.")
        if settings.enabled and certificate.status == "revoked" and not certificate.revoked_at:
            errors.append(f"Revoked certificate {certificate.common_name} has no revocation timestamp.")
        if settings.enabled and certificate.status != "revoked" and certificate.managed_owner and not certificate.private_key_encrypted:
            errors.append(f"Managed certificate {certificate.common_name} has no encrypted private key.")
    return errors
