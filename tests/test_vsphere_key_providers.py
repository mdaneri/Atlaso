"""Test vSphere Key Provider management behavior."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    KmsSettings,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
)
from atlaso.app.services import kmip_recovery
from atlaso.app.services.settings_archive import (
    export_settings_archive,
    restore_settings_archive,
)
from atlaso.app.services.vsphere_key_providers import (
    certificate_status,
    parse_public_certificate,
    render_client_trust_bundle,
    render_provider_config,
)


def _public_client_certificate(
    common_name: str = "vcsa.atlaso.internal",
    *,
    expired: bool = False,
) -> tuple[str, str]:
    """Return one current public client certificate and its private key.

    Args:
        common_name: Subject common name encoded into the test certificate.
        expired: Whether to issue a certificate whose validity already ended.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30) if expired else now - timedelta(minutes=1))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


def _token(client, scopes: list[str]) -> str:
    """Return a bearer token with the requested scopes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Authorization scopes granted to the token.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": f"vSphere provider test {uuid4()}", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def _login(client) -> str:
    """Authenticate the browser client and return the active CSRF token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.

    Returns:
        CSRF token rendered after successful authentication.
    """
    login_page = client.get("/login")
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = client.get("/vsphere-key-providers")
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]





def test_settings_archive_round_trips_only_public_provider_desired_state(client, monkeypatch) -> None:
    """Verify settings archives preserve the provider graph without operational-key state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to reject unexpected helper invocation.
    """
    public_pem, _private_pem = _public_client_certificate("vcsa-archive.atlaso.internal", expired=True)
    parsed = parse_public_certificate(public_pem, require_current=False)
    provider_id = str(uuid4())
    vcenter_id = str(uuid4())
    certificate_id = str(uuid4())
    with SessionLocal() as db:
        provider = VsphereKeyProvider(id=provider_id, name="Archive provider", enabled=True)
        vcenter = VsphereTrustedVcenter(
            id=vcenter_id,
            provider_id=provider_id,
            name="Archive vCenter",
            hostname="vcsa-archive.atlaso.internal",
            enabled=True,
        )
        certificate = VsphereTrustedVcenterCertificate(
            id=certificate_id,
            trusted_vcenter_id=vcenter_id,
            source="uploaded_public",
            **parsed,
        )
        provider.trusted_vcenters.append(vcenter)
        vcenter.certificates.append(certificate)
        db.add(provider)
        db.commit()

        archive = export_settings_archive(db, actor="test")
        assert "kms_clients" not in archive["data"]
        assert "kms_keys" not in archive["data"]
        assert archive["data"]["vsphere_key_providers"][0]["id"] == provider_id
        assert archive["data"]["vsphere_trusted_vcenter_certificates"][0]["certificate_pem"] == public_pem

        restore_settings_archive(db, archive)
        restored = db.get(VsphereKeyProvider, provider_id)
        assert restored is not None
        assert restored.trusted_vcenters[0].id == vcenter_id
        assert restored.trusted_vcenters[0].certificates[0].id == certificate_id
        assert restored.trusted_vcenters[0].certificates[0].certificate_pem == public_pem
        assert certificate_status(restored.trusted_vcenters[0].certificates[0]) == "expired"

        # A whole-appliance restore populates the import target even without operational keys.
        monkeypatch.setattr(
            kmip_recovery,
            "_request",
            lambda *_args: pytest.fail("settings-restored target reached recovery helper"),
        )
        with pytest.raises(kmip_recovery.RecoveryError, match="empty provider/trust target"):
            kmip_recovery.import_archive(db, b"synthetic-bundle", "synthetic-passphrase")


def test_kmip_recovery_on_clean_target_preserves_public_graph_for_review(client, monkeypatch) -> None:
    """Keep empty-target import independent of a full settings restore.

    Args:
        client: HTTP test client providing an isolated clean appliance database.
        monkeypatch: Pytest fixture replacing the privileged operational import.
    """
    public_pem, _private_pem = _public_client_certificate("vcsa-recovery.example.test")
    parsed = parse_public_certificate(public_pem)
    provider_id, vcenter_id, certificate_id = (str(uuid4()) for _ in range(3))
    trust = {
        "providers": [{"id": provider_id, "name": "Recovered provider", "description": "", "enabled": True}],
        "vcenters": [{
            "id": vcenter_id, "provider_id": provider_id, "name": "Recovered vCenter",
            "hostname": "vcsa-recovery.example.test", "description": "", "enabled": True,
        }],
        "certificates": [{
            "id": certificate_id, "trusted_vcenter_id": vcenter_id,
            "certificate_pem": public_pem, "fingerprint_sha256": parsed["fingerprint_sha256"],
        }],
    }
    calls = []

    def import_offline(action, payload):
        """Return synthetic public evidence after the offline helper succeeds.

        Args:
            action: Fixed helper action requested by the coordinator.
            payload: Request-bound synthetic import input.
        """
        calls.append(action)
        assert set(payload) == {"passphrase", "archive"}
        return {"trust": trust}

    monkeypatch.setattr(kmip_recovery, "_request", import_offline)
    with SessionLocal() as db:
        assert not any(kmip_recovery.public_trust(db).values())
        kmip_recovery.import_archive(db, b"synthetic-bundle", "synthetic-passphrase")
        db.commit()
        restored = kmip_recovery.public_trust(db)
        assert calls == ["recovery-import"]
        assert restored["providers"] == [{**trust["providers"][0], "enabled": False}]
        assert restored["vcenters"] == [{**trust["vcenters"][0], "enabled": False}]
        assert restored["certificates"] == trust["certificates"]
        assert db.get(VsphereKeyProvider, provider_id).applied_at is None
        assert db.scalar(select(KmsSettings)).enabled is False




def test_rendered_trust_uses_exact_enabled_fingerprints_and_public_pem_only(client) -> None:
    """Verify rendered daemon state includes exact public trust and no legacy key metadata.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    public_pem, private_pem = _public_client_certificate("vcsa-render.atlaso.internal")
    parsed = parse_public_certificate(public_pem)
    with SessionLocal() as db:
        settings = db.execute(select(KmsSettings)).scalar_one()
        settings.enabled = True
        settings.listen_address = "192.0.2.10,2001:db8::10"
        provider = VsphereKeyProvider(id=str(uuid4()), name="Rendered provider", enabled=True)
        vcenter = VsphereTrustedVcenter(
            id=str(uuid4()),
            provider=provider,
            name="Rendered vCenter",
            hostname="vcsa-render.atlaso.internal",
            enabled=True,
        )
        certificate = VsphereTrustedVcenterCertificate(
            id=str(uuid4()),
            trusted_vcenter=vcenter,
            source="uploaded_public",
            **parsed,
        )
        db.add(provider)
        db.add(certificate)
        db.commit()

        rendered = json.loads(render_provider_config(settings, [provider]))
        assert rendered["listen"] == {
            "addresses": ["192.0.2.10", "2001:db8::10"],
            "port": settings.port,
        }
        assert rendered["providers"] == [
            {
                "id": provider.id,
                "name": provider.name,
                "client_fingerprints": [parsed["fingerprint_sha256"]],
                "client_certificate_paths": [],
            }
        ]
        trust_bundle = render_client_trust_bundle(db, [provider])
        assert public_pem in trust_bundle
        assert private_pem not in trust_bundle
        assert "PRIVATE KEY" not in trust_bundle
        assert "legacy-metadata-only" not in json.dumps(rendered)
        rotated = json.loads(render_provider_config(settings, [provider], server_fingerprint="a" * 64))
        assert rotated["tls"]["certificate_path"].endswith(f"-{'a' * 64}.crt")
        assert rotated["tls"]["private_key_path"].endswith(f"-{'a' * 64}.key")


def test_public_certificate_validation_rejects_expiry_and_private_key_blocks() -> None:
    """Verify public trust intake rejects expired and private-key inputs."""
    expired_pem, private_pem = _public_client_certificate(expired=True)
    try:
        parse_public_certificate(expired_pem)
    except ValueError as exc:
        assert "expired" in str(exc)
    else:
        raise AssertionError("Expired vCenter certificate was accepted.")
    try:
        parse_public_certificate(private_pem)
    except ValueError as exc:
        assert "Private keys are forbidden" in str(exc)
    else:
        raise AssertionError("Private key material was accepted as a public certificate.")


def test_certificate_fingerprint_is_globally_unique_in_persistence(client) -> None:
    """Verify the database enforces one global exact-fingerprint assignment.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    with SessionLocal() as db:
        assert VsphereTrustedVcenterCertificate.__table__.c.fingerprint_sha256.unique is True
        assert db.execute(select(VsphereKeyProvider)).scalars().all() == []
