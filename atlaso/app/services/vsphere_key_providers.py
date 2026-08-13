"""Implement the vSphere Key Provider control-plane contract."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.models import (
    CaSettings,
    KmsSettings,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
    utcnow,
)
from atlaso.app.services.appliance_settings import HOSTNAME_PATTERN
from atlaso.app.services.ca import safe_certificate_name
from atlaso.app.services.dnsmasq import split_addresses
from atlaso.app.services.kms import (
    KMS_DEFAULT_DATABASE_PATH,
    KMS_DEFAULT_KEK_PATH,
    KMS_SERVER_CERT_BASE,
)

MAX_PUBLIC_CERTIFICATE_BYTES = 65_536
PRIVATE_KEY_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
)


def normalize_service_hostname(value: str) -> str:
    """Return a canonical fully qualified DNS name for the shared listener.

    Args:
        value: Candidate public listener hostname.

    Returns:
        Canonical lowercase fully qualified DNS name.

    Raises:
        ValueError: If the value is not a fully qualified DNS name.
    """
    hostname = value.strip().casefold().rstrip(".")
    if not HOSTNAME_PATTERN.fullmatch(hostname):
        raise ValueError("vSphere Key Provider hostname must be a valid fully qualified DNS name.")
    return hostname


def normalize_vcenter_hostname(value: str) -> str:
    """Return a canonical optional vCenter IP address or fully qualified DNS name.

    Args:
        value: Candidate trusted-vCenter network identifier.

    Returns:
        Canonical IP address or lowercase fully qualified DNS name, or an empty string.

    Raises:
        ValueError: If the value is neither an IP address nor a fully qualified DNS name.
    """
    hostname = value.strip().casefold().rstrip(".")
    if not hostname:
        return ""
    try:
        return str(ip_address(hostname))
    except ValueError:
        if HOSTNAME_PATTERN.fullmatch(hostname):
            return hostname
    raise ValueError("Trusted vCenter hostname must be an IP address or valid fully qualified DNS name.")


def _aware(value: datetime) -> datetime:
    """Return a timezone-aware UTC timestamp.

    Args:
        value: Timestamp to normalize.

    Returns:
        The normalized timestamp.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_public_certificate(certificate_pem: str, *, require_current: bool = True) -> dict[str, object]:
    """Validate and normalize one public vCenter client certificate.

    Args:
        certificate_pem: PEM-encoded public certificate supplied by an administrator.
        require_current: Whether the certificate must be valid at the current time.

    Returns:
        Parsed public certificate metadata and canonical PEM.

    Raises:
        ValueError: If the input is unsafe, malformed, expired, or not suitable for client authentication.
    """
    encoded = certificate_pem.encode("utf-8")
    if not encoded or len(encoded) > MAX_PUBLIC_CERTIFICATE_BYTES:
        raise ValueError("The vCenter public certificate must contain 1 to 65536 UTF-8 bytes.")
    if any(marker in certificate_pem for marker in PRIVATE_KEY_MARKERS):
        raise ValueError("Private keys are forbidden; upload only the vCenter public client certificate.")
    if len(re.findall(r"-----BEGIN CERTIFICATE-----", certificate_pem)) != 1:
        raise ValueError("Upload exactly one PEM-encoded vCenter public client certificate.")
    try:
        certificate = x509.load_pem_x509_certificate(encoded)
    except ValueError as exc:
        raise ValueError("The vCenter public certificate is not valid PEM X.509 data.") from exc

    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        if constraints.ca:
            raise ValueError("A CA certificate cannot be assigned as a vCenter client identity.")
    except x509.ExtensionNotFound:
        pass
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
            raise ValueError("The vCenter certificate extended key usage does not permit client authentication.")
    except x509.ExtensionNotFound:
        pass
    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not key_usage.digital_signature:
            raise ValueError("The vCenter certificate key usage does not permit digital signatures.")
    except x509.ExtensionNotFound:
        pass

    not_before = _aware(certificate.not_valid_before_utc)
    not_after = _aware(certificate.not_valid_after_utc)
    now = utcnow()
    if require_current and not_before > now:
        raise ValueError("The vCenter public certificate is not valid yet.")
    if require_current and not_after <= now:
        raise ValueError("The vCenter public certificate has expired.")
    canonical = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return {
        "certificate_pem": canonical,
        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "x"),
        "not_valid_before": not_before,
        "not_valid_after": not_after,
    }


def certificate_status(certificate: VsphereTrustedVcenterCertificate) -> str:
    """Return the current status of a trusted public certificate.

    Args:
        certificate: Persisted certificate to classify.

    Returns:
        A stable status label.
    """
    now = utcnow()
    if certificate.not_valid_before and _aware(certificate.not_valid_before) > now:
        return "not-yet-valid"
    if certificate.not_valid_after and _aware(certificate.not_valid_after) <= now:
        return "expired"
    return "valid"


def provider_rows(db: Session) -> list[VsphereKeyProvider]:
    """Return all providers with their trust graph loaded.

    Args:
        db: Active database session.

    Returns:
        Ordered provider records.
    """
    return list(
        db.execute(
            select(VsphereKeyProvider)
            .options(
                selectinload(VsphereKeyProvider.trusted_vcenters).selectinload(
                    VsphereTrustedVcenter.certificates
                )
            )
            .order_by(VsphereKeyProvider.name)
            .execution_options(populate_existing=True)
        ).scalars()
    )


def provider_to_dict(provider: VsphereKeyProvider) -> dict[str, object]:
    """Return one provider without operational key identifiers.

    Args:
        provider: Provider to serialize.

    Returns:
        Public provider metadata.
    """
    certificates = [
        certificate
        for trusted in provider.trusted_vcenters
        for certificate in trusted.certificates
    ]
    return {
        "id": provider.id,
        "name": provider.name,
        "description": provider.description,
        "enabled": provider.enabled,
        "trusted_vcenter_count": len(provider.trusted_vcenters),
        "certificate_count": len(certificates),
        "usable_certificate_count": sum(
            len(usable_certificates(trusted))
            for trusted in provider.trusted_vcenters
            if trusted.enabled
        ),
        "created_at": provider.created_at.isoformat(),
        "updated_at": provider.updated_at.isoformat(),
    }


def provider_requires_appliance_apply(provider: VsphereKeyProvider) -> bool:
    """Return whether the provider changed after its last successful apply.

    Args:
        provider: Provider whose desired and applied timestamps are compared.

    Returns:
        Whether global Appliance Apply is still required.
    """
    return provider.applied_at is None or _aware(provider.updated_at) > _aware(provider.applied_at)


def mark_provider_desired_changed(provider: VsphereKeyProvider) -> None:
    """Mark a provider trust-graph mutation as pending global Appliance Apply.

    Args:
        provider: Provider whose desired trust graph changed.
    """
    provider.updated_at = utcnow()


def trusted_vcenter_to_dict(trusted: VsphereTrustedVcenter) -> dict[str, object]:
    """Return one provider-scoped trusted vCenter.

    Args:
        trusted: Trusted vCenter to serialize.

    Returns:
        Public trusted-vCenter metadata.
    """
    expiry_values = [
        _aware(certificate.not_valid_after)
        for certificate in trusted.certificates
        if certificate.not_valid_after is not None
    ]
    return {
        "id": trusted.id,
        "provider_id": trusted.provider_id,
        "provider_name": trusted.provider.name if trusted.provider else "",
        "name": trusted.name,
        "hostname": trusted.hostname,
        "description": trusted.description,
        "enabled": trusted.enabled,
        "certificate_count": len(trusted.certificates),
        "usable_certificate_count": len(usable_certificates(trusted)),
        "earliest_expiry": min(expiry_values).isoformat() if expiry_values else None,
        "created_at": trusted.created_at.isoformat(),
        "updated_at": trusted.updated_at.isoformat(),
    }


def certificate_to_dict(certificate: VsphereTrustedVcenterCertificate) -> dict[str, object]:
    """Return public certificate metadata with no private material.

    Args:
        certificate: Certificate to serialize.

    Returns:
        Public certificate metadata.
    """
    trusted = certificate.trusted_vcenter
    provider = trusted.provider if trusted else None
    return {
        "id": certificate.id,
        "provider_id": provider.id if provider else "",
        "provider_name": provider.name if provider else "",
        "trusted_vcenter_id": trusted.id if trusted else "",
        "trusted_vcenter_name": trusted.name if trusted else "",
        "fingerprint_sha256": certificate.fingerprint_sha256,
        "certificate_pem": certificate.certificate_pem,
        "subject": certificate.subject,
        "issuer": certificate.issuer,
        "serial_number": certificate.serial_number,
        "not_valid_before": certificate.not_valid_before.isoformat() if certificate.not_valid_before else None,
        "not_valid_after": certificate.not_valid_after.isoformat() if certificate.not_valid_after else None,
        "source": certificate.source,
        "status": certificate_status(certificate),
        "created_at": certificate.created_at.isoformat(),
    }


def usable_certificates(trusted_vcenter: VsphereTrustedVcenter) -> list[VsphereTrustedVcenterCertificate]:
    """Return exact certificate identities usable in rendered desired state.

    Args:
        trusted_vcenter: Trusted vCenter whose certificates are evaluated.

    Returns:
        Usable certificate records.
    """
    return [
        certificate
        for certificate in trusted_vcenter.certificates
        if certificate_status(certificate) == "valid"
    ]


def validate_provider_state(providers: list[VsphereKeyProvider]) -> list[str]:
    """Validate the provider and certificate assignment graph.

    Args:
        providers: Providers to validate.

    Returns:
        Secret-free validation messages.
    """
    errors: list[str] = []
    fingerprints: dict[str, str] = {}
    if not any(provider.enabled for provider in providers):
        errors.append("At least one enabled provider with a current public client certificate is required.")
    for provider in providers:
        enabled_vcenters = [item for item in provider.trusted_vcenters if item.enabled]
        if provider.enabled and not enabled_vcenters:
            errors.append(f"Provider {provider.name} requires an enabled trusted vCenter.")
        usable_count = 0
        for trusted in enabled_vcenters:
            usable = usable_certificates(trusted)
            if not usable:
                errors.append(f"Trusted vCenter {trusted.name} requires a current public client certificate.")
            usable_count += len(usable)
            for certificate in usable:
                previous = fingerprints.get(certificate.fingerprint_sha256)
                if previous and previous != provider.id:
                    errors.append("A vCenter certificate fingerprint cannot be assigned across providers.")
                fingerprints[certificate.fingerprint_sha256] = provider.id
        if provider.enabled and usable_count == 0:
            errors.append(f"Provider {provider.name} has no usable exact certificate fingerprint.")
    return list(dict.fromkeys(errors))


def render_provider_config(settings: KmsSettings, providers: list[VsphereKeyProvider]) -> str:
    """Render the bounded daemon configuration for all enabled providers.

    Args:
        settings: Appliance-wide listener settings.
        providers: Provider trust graph to render.

    Returns:
        Deterministic JSON desired state.
    """
    certificate_name = safe_certificate_name(settings.server_certificate or settings.hostname)
    listen_addresses = split_addresses(settings.listen_address)
    rendered_listen_addresses = listen_addresses if settings.enabled and listen_addresses else ["127.0.0.1"]
    rendered_providers = []
    for provider in providers:
        if not provider.enabled:
            continue
        fingerprints = sorted(
            {
                certificate.fingerprint_sha256
                for trusted in provider.trusted_vcenters
                if trusted.enabled
                for certificate in usable_certificates(trusted)
            }
        )
        rendered_providers.append(
            {
                "id": str(UUID(provider.id)),
                "name": provider.name,
                "client_fingerprints": fingerprints,
                "client_certificate_paths": [],
            }
        )
    document = {
        "schema_version": 1,
        "enabled": bool(settings.enabled),
        "listen": {"addresses": rendered_listen_addresses, "port": settings.port},
        "tls": {
            "certificate_path": f"{KMS_SERVER_CERT_BASE}/{certificate_name}.crt",
            "private_key_path": f"{KMS_SERVER_CERT_BASE}/{certificate_name}.key",
            "ca_path": "/etc/atlaso/kmip/client-trust.pem",
        },
        "store": {
            "database_path": KMS_DEFAULT_DATABASE_PATH,
            "kek_path": KMS_DEFAULT_KEK_PATH,
        },
        "limits": {
            "max_request_bytes": 1_048_576,
            "max_connections": 32,
            "idle_timeout_seconds": 30,
            "max_requests_per_connection": 128,
        },
        "providers": rendered_providers,
        "interop_trace_path": "",
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def render_client_trust_bundle(db: Session, providers: list[VsphereKeyProvider]) -> str:
    """Render public trust anchors used only for the KMIP client handshake.

    Args:
        db: Active database session.
        providers: Provider trust graph to render.

    Returns:
        A deterministic PEM bundle containing no private keys.
    """
    pem_by_digest: dict[str, str] = {}
    ca_settings = db.execute(select(CaSettings)).scalar_one_or_none()
    if ca_settings and ca_settings.root_certificate_pem:
        pem = ca_settings.root_certificate_pem.strip() + "\n"
        pem_by_digest[hashlib.sha256(pem.encode("utf-8")).hexdigest()] = pem
    for provider in providers:
        if not provider.enabled:
            continue
        for trusted in provider.trusted_vcenters:
            if not trusted.enabled:
                continue
            for certificate in usable_certificates(trusted):
                if certificate.certificate_pem:
                    pem = certificate.certificate_pem.strip() + "\n"
                    pem_by_digest[hashlib.sha256(pem.encode("utf-8")).hexdigest()] = pem
    return "".join(pem_by_digest[key] for key in sorted(pem_by_digest))


def runtime_status_snapshot(adapter: SystemAdapter | None = None) -> dict[str, object]:
    """Return bounded helper health and lifecycle-count evidence.

    Args:
        adapter: Optional system adapter used by tests or the live appliance.

    Returns:
        Validated redacted evidence, defaulting to not-reported.
    """
    result = (adapter or SystemAdapter()).kms_status()
    unavailable: dict[str, object] = {
        "status": "not-reported",
        "runtime_state": "not-reported",
        "store_status": "not-reported",
        "providers": {},
    }
    if result.returncode != 0:
        return unavailable
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return unavailable
    if not isinstance(payload, dict) or payload.get("status") not in {"available", "not-reported"}:
        return unavailable
    provider_values = payload.get("providers")
    if not isinstance(provider_values, dict):
        return unavailable
    providers: dict[str, dict[str, int]] = {}
    for provider_id, counts in provider_values.items():
        try:
            normalized_id = str(UUID(str(provider_id)))
        except ValueError:
            return unavailable
        if not isinstance(counts, dict):
            return unavailable
        values = {
            "pre_active": counts.get("pre_active"),
            "active": counts.get("active"),
            "total": counts.get("total"),
        }
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values.values()):
            return unavailable
        if values["pre_active"] + values["active"] != values["total"]:
            return unavailable
        providers[normalized_id] = values
    return {
        "status": payload["status"],
        "runtime_state": str(payload.get("runtime_state") or "not-reported"),
        "store_status": str(payload.get("store_status") or "not-reported"),
        "providers": providers,
    }


def authenticated_provider_counts(
    snapshot: dict[str, object],
    provider_id: str,
) -> dict[str, int] | None:
    """Return verified counts, including an authenticated zero for an absent namespace.

    Args:
        snapshot: Validated helper status payload.
        provider_id: Immutable provider UUID to inspect.

    Returns:
        Redacted counts when the complete store was authenticated, otherwise ``None``.
    """
    if snapshot.get("status") != "available":
        return None
    providers = snapshot.get("providers")
    if not isinstance(providers, dict):
        return None
    counts = providers.get(provider_id)
    if isinstance(counts, dict):
        return counts
    if snapshot.get("store_status") in {"authenticated", "healthy", "empty"}:
        return {"pre_active": 0, "active": 0, "total": 0}
    return None
