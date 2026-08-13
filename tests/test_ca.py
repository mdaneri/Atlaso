"""Test ca behavior."""

import pytest

from atlaso.app.config import Settings
from atlaso.app.models import CaCertificate, CaProfile, CaSettings, utcnow
from atlaso.app.secrets import decrypt_secret, encrypt_secret
from atlaso.app.services.ca import (
    ca_certificate_to_dict,
    ensure_root_ca_material,
    issue_certificate,
    render_ca_apply_payload,
    validate_ca_private_key_material,
)


def test_encrypted_secret_round_trip_and_wrong_key_failure():
    """Verify that encrypted secret round trip and wrong key failure."""
    first = Settings(secret_key="test-secret-key-with-enough-length", secrets_key="first-ca-secrets-key")
    second = Settings(secret_key="test-secret-key-with-enough-length", secrets_key="second-ca-secrets-key")

    encrypted = encrypt_secret("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n", first)

    assert encrypted.startswith("fernet:v1:")
    assert "BEGIN PRIVATE KEY" not in encrypted
    assert decrypt_secret(encrypted, first).startswith("-----BEGIN PRIVATE KEY-----")
    with pytest.raises(ValueError):
        decrypt_secret(encrypted, second)


def test_ca_apply_payload_includes_crl_for_revoked_certificates():
    """Verify that ca apply payload includes crl for revoked certificates."""
    import json

    settings = CaSettings(
        enabled=True,
        publish_crl=True,
        root_common_name="Atlaso Test Root CA",
        organization="Atlaso",
        key_algorithm="RSA",
        key_size=2048,
        digest_algorithm="sha256",
        root_valid_days=3650,
        storage_path="/etc/atlaso/ca",
    )
    assert ensure_root_ca_material(settings) is True
    certificate = CaCertificate(
        common_name="revoked.atlaso.internal",
        status="revoked",
        serial_number="2a",
        revoked_at=utcnow(),
        revoked_by="admin",
        revocation_reason="rotation",
        enabled=True,
    )

    payload = json.loads(render_ca_apply_payload(settings, [certificate], include_private_keys=True))

    assert payload["root"]["crl_path"].endswith("/atlaso-ca.crl")
    assert "BEGIN X509 CRL" in payload["root"]["crl_pem"]
    assert payload["certificates"] == []


def test_existing_root_ca_material_is_not_rotated_by_identity_edits():
    """Verify that existing root ca material is not rotated by identity edits."""
    settings = CaSettings(
        enabled=True,
        root_common_name="Original Atlaso Root",
        organization="Atlaso",
        key_algorithm="RSA",
        key_size=2048,
        digest_algorithm="sha256",
        root_valid_days=3650,
        storage_path="/etc/atlaso/ca",
    )
    assert ensure_root_ca_material(settings) is True
    original_certificate = settings.root_certificate_pem
    original_private_key = settings.root_private_key_encrypted
    original_fingerprint = settings.root_fingerprint

    settings.root_common_name = "Renamed Atlaso Root"
    settings.organization = "Updated Atlaso"

    assert ensure_root_ca_material(settings) is False
    assert settings.root_certificate_pem == original_certificate
    assert settings.root_private_key_encrypted == original_private_key
    assert settings.root_fingerprint == original_fingerprint


def test_ca_private_key_validation_rejects_mismatched_certificate():
    """Verify CA private-key validation requires the matching public certificate."""
    first = CaSettings(
        enabled=True,
        root_common_name="First Atlaso Root",
        organization="Atlaso",
        key_algorithm="RSA",
        key_size=2048,
        digest_algorithm="sha256",
        root_valid_days=3650,
        storage_path="/etc/atlaso/ca",
    )
    second = CaSettings(
        enabled=True,
        root_common_name="Second Atlaso Root",
        organization="Atlaso",
        key_algorithm="RSA",
        key_size=2048,
        digest_algorithm="sha256",
        root_valid_days=3650,
        storage_path="/etc/atlaso/ca",
    )
    assert ensure_root_ca_material(first) is True
    assert ensure_root_ca_material(second) is True
    first.root_private_key_encrypted = second.root_private_key_encrypted

    assert validate_ca_private_key_material(first, []) == [
        "CA root encrypted private key does not match its certificate."
    ]


def test_ca_private_key_validation_rejects_leaf_from_another_root():
    """Verify issued leaf certificates chain to the restored root."""
    restored_root = CaSettings(
        enabled=True,
        root_common_name="Restored Atlaso Root",
        organization="Atlaso",
        key_algorithm="RSA",
        key_size=2048,
        digest_algorithm="sha256",
        root_valid_days=3650,
        storage_path="/etc/atlaso/ca",
    )
    unrelated_root = CaSettings(
        enabled=True,
        root_common_name="Unrelated Atlaso Root",
        organization="Atlaso",
        key_algorithm="RSA",
        key_size=2048,
        digest_algorithm="sha256",
        root_valid_days=3650,
        storage_path="/etc/atlaso/ca",
    )
    assert ensure_root_ca_material(restored_root) is True
    assert ensure_root_ca_material(unrelated_root) is True
    profile = CaProfile(
        id=1,
        name="Service TLS",
        certificate_type="server",
        validity_days=30,
        key_algorithm="RSA",
        key_size=2048,
        key_usage="digitalSignature,keyEncipherment",
        extended_key_usage="serverAuth",
        enabled=True,
    )
    certificate = CaCertificate(
        common_name="service.example.test",
        profile_id=profile.id,
        status="planned",
        enabled=True,
    )
    assert issue_certificate(unrelated_root, [profile], certificate) is True

    errors = validate_ca_private_key_material(restored_root, [certificate])

    assert "Certificate service.example.test is not issued by the restored CA root." in errors
    assert "Certificate service.example.test chain does not match the restored CA root." in errors


@pytest.mark.parametrize(
    ("is_ca", "expired", "not_yet_valid", "expected_error"),
    [
        (False, False, False, "CA root certificate is not a valid self-signed certificate."),
        (True, True, False, "CA root certificate has expired."),
        (True, False, True, "CA root certificate is not yet valid."),
    ],
)
def test_ca_private_key_validation_requires_current_ca_root(is_ca, expired, not_yet_valid, expected_error):
    """Verify restored root material is a current certificate-authority certificate."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Archive root")])
    now = datetime.now(timezone.utc)
    not_valid_before = now + timedelta(days=1) if not_yet_valid else now - timedelta(days=30)
    not_valid_after = now - timedelta(days=1) if expired else now + timedelta(days=30)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    settings = CaSettings(
        enabled=True,
        root_certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        root_private_key_encrypted=encrypt_secret(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")
        ),
    )

    assert expected_error in validate_ca_private_key_material(settings, [])


def test_ca_certificate_row_capabilities_follow_lifecycle_and_ownership():
    """Verify that ca certificate row capabilities follow lifecycle and ownership."""
    planned = ca_certificate_to_dict(CaCertificate(common_name="planned.example.test", status="planned"))
    csr_issued = ca_certificate_to_dict(
        CaCertificate(
            common_name="csr.example.test",
            status="issued",
            csr_text="-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----\n",
            certificate_pem="-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
        )
    )
    managed = ca_certificate_to_dict(
        CaCertificate(
            common_name="managed.example.test",
            status="issued",
            managed_owner="service:https",
            certificate_pem="-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
            private_key_encrypted="fernet:v1:key",
        )
    )

    assert planned["can_edit"] is True
    assert planned["can_delete"] is True
    assert planned["can_export_certificate"] is False
    assert csr_issued["can_edit"] is False
    assert csr_issued["can_export_certificate"] is True
    assert csr_issued["can_export_chain"] is True
    assert csr_issued["can_export_private_key"] is False
    assert managed["can_edit"] is False
    assert managed["can_delete"] is False
    assert managed["can_export_private_key"] is True


def test_managed_ca_specs_include_portal_https_certificate(client):
    """Verify that managed ca specs include portal https certificate.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NtpSettings
    from atlaso.app.ui import get_ca_settings_row, managed_ca_certificate_specs

    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        settings.portal_hostname = "ca.atlaso.internal"
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.87.32"
        ntp = db.execute(select(NtpSettings)).scalar_one_or_none()
        if ntp is None:
            ntp = NtpSettings()
            db.add(ntp)
        ntp.nts_server_enabled = True
        ntp.hostname = "ntp.atlaso.internal"
        ntp.listen_address = "192.168.87.33"
        db.commit()

        specs = {spec.owner: spec for spec in managed_ca_certificate_specs(db)}

    ca_portal = specs["ca_portal:https"]
    assert ca_portal.common_name == "ca.atlaso.internal"
    assert ca_portal.dns_names == ["ca.atlaso.internal"]
    assert ca_portal.ip_addresses == ["192.168.87.32"]
    assert ca_portal.cert_path == "/etc/atlaso/ca-portal/certs/ca.atlaso.internal.crt"
    assert ca_portal.key_path == "/etc/atlaso/ca-portal/certs/ca.atlaso.internal.key"
    assert ca_portal.chain_path == "/etc/atlaso/ca-portal/certs/ca.atlaso.internal-chain.pem"
    ntp_nts = specs["ntp:nts"]
    assert ntp_nts.common_name == "ntp.atlaso.internal"
    assert ntp_nts.dns_names == ["ntp.atlaso.internal"]
    assert ntp_nts.ip_addresses == ["192.168.87.33"]
    assert ntp_nts.cert_path == "/etc/atlaso/ntp/certs/ntp.atlaso.internal.crt"
    assert ntp_nts.key_path == "/etc/atlaso/ntp/certs/ntp.atlaso.internal.key"
