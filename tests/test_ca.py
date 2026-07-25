import pytest

from atlaso.app.config import Settings
from atlaso.app.models import CaCertificate, CaSettings, utcnow
from atlaso.app.secrets import decrypt_secret, encrypt_secret
from atlaso.app.services.ca import ca_certificate_to_dict, ensure_root_ca_material, render_ca_apply_payload


def test_encrypted_secret_round_trip_and_wrong_key_failure():
    first = Settings(secret_key="test-secret-key-with-enough-length", secrets_key="first-ca-secrets-key")
    second = Settings(secret_key="test-secret-key-with-enough-length", secrets_key="second-ca-secrets-key")

    encrypted = encrypt_secret("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n", first)

    assert encrypted.startswith("fernet:v1:")
    assert "BEGIN PRIVATE KEY" not in encrypted
    assert decrypt_secret(encrypted, first).startswith("-----BEGIN PRIVATE KEY-----")
    with pytest.raises(ValueError):
        decrypt_secret(encrypted, second)


def test_ca_apply_payload_includes_crl_for_revoked_certificates():
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


def test_ca_certificate_row_capabilities_follow_lifecycle_and_ownership():
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
