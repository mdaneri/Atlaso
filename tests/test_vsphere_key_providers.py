"""Test vSphere Key Provider management behavior."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    KmsSettings,
    PhysicalInterface,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
)
from atlaso.app.services.vsphere_key_providers import (
    certificate_status,
    parse_public_certificate,
    provider_rows,
    render_client_trust_bundle,
    render_provider_config,
)
from atlaso.app.services.settings_archive import export_settings_archive, restore_settings_archive


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


def test_provider_api_enforces_scopes_public_certificates_and_global_fingerprint_uniqueness(client) -> None:
    """Verify API authorization and the public-certificate trust model.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    read_token = _token(client, ["read:kms"])
    write_token = _token(client, ["read:kms", "write:kms"])
    read_headers = {"Authorization": f"Bearer {read_token}"}
    write_headers = {"Authorization": f"Bearer {write_token}"}

    assert client.get("/api/v1/vsphere-key-providers", headers=read_headers).status_code == 200
    assert client.post(
        "/api/v1/vsphere-key-providers",
        headers=read_headers,
        json={"name": "Rejected", "enabled": False},
    ).status_code == 403

    first_provider = client.post(
        "/api/v1/vsphere-key-providers",
        headers=write_headers,
        json={"name": "Provider A", "description": "First namespace", "enabled": False},
    )
    assert first_provider.status_code == 201, first_provider.text
    provider_a = first_provider.json()["id"]
    first_vcenter = client.post(
        f"/api/v1/vsphere-key-providers/{provider_a}/trusted-vcenters",
        headers=write_headers,
        json={"name": "vCenter A", "hostname": "vcsa-a.atlaso.internal", "enabled": False},
    )
    assert first_vcenter.status_code == 201, first_vcenter.text
    vcenter_a = first_vcenter.json()["id"]

    public_pem, private_pem = _public_client_certificate()
    private_response = client.post(
        f"/api/v1/vsphere-key-providers/{provider_a}/trusted-vcenters/{vcenter_a}/certificates",
        headers=write_headers,
        json={"certificate_pem": private_pem},
    )
    assert private_response.status_code == 400
    assert "Private keys are forbidden" in private_response.text

    certificate = client.post(
        f"/api/v1/vsphere-key-providers/{provider_a}/trusted-vcenters/{vcenter_a}/certificates",
        headers=write_headers,
        json={"certificate_pem": public_pem},
    )
    assert certificate.status_code == 201, certificate.text
    assert certificate.json()["certificate_pem"] == public_pem
    assert "PRIVATE KEY" not in certificate.text

    second_provider = client.post(
        "/api/v1/vsphere-key-providers",
        headers=write_headers,
        json={"name": "Provider B", "enabled": False},
    ).json()["id"]
    second_vcenter = client.post(
        f"/api/v1/vsphere-key-providers/{second_provider}/trusted-vcenters",
        headers=write_headers,
        json={"name": "vCenter B", "enabled": False},
    ).json()["id"]
    duplicate = client.post(
        f"/api/v1/vsphere-key-providers/{second_provider}/trusted-vcenters/{second_vcenter}/certificates",
        headers=write_headers,
        json={"certificate_pem": public_pem},
    )
    assert duplicate.status_code == 409
    assert "already assigned" in duplicate.text


def test_provider_readiness_tracks_every_trust_graph_mutation(client) -> None:
    """Verify vCenter and certificate mutations make the provider desired state pending.

    Args:
        client: HTTP test client used to exercise the public provider API.
    """
    token = _token(client, ["read:kms", "write:kms"])
    headers = {"Authorization": f"Bearer {token}"}
    provider_id = client.post(
        "/api/v1/vsphere-key-providers",
        headers=headers,
        json={"name": "Readiness provider", "enabled": False},
    ).json()["id"]

    def mark_applied() -> None:
        with SessionLocal() as db:
            provider = db.get(VsphereKeyProvider, provider_id)
            applied_at = datetime.now(timezone.utc)
            provider.updated_at = applied_at
            provider.applied_at = applied_at
            db.commit()

    def requires_apply() -> bool:
        response = client.get(
            f"/api/v1/vsphere-key-providers/{provider_id}/readiness",
            headers=headers,
        )
        assert response.status_code == 200
        return response.json()["requires_appliance_apply"]

    mark_applied()
    assert requires_apply() is False
    vcenter = client.post(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters",
        headers=headers,
        json={"name": "Tracked vCenter", "hostname": "vcsa-tracked.atlaso.internal", "enabled": False},
    )
    assert vcenter.status_code == 201
    vcenter_id = vcenter.json()["id"]
    assert requires_apply() is True

    mark_applied()
    updated = client.patch(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
        headers=headers,
        json={"description": "updated desired trust"},
    )
    assert updated.status_code == 200
    assert requires_apply() is True

    mark_applied()
    public_pem, _private_pem = _public_client_certificate("vcsa-tracked.atlaso.internal")
    certificate = client.post(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates",
        headers=headers,
        json={"certificate_pem": public_pem},
    )
    assert certificate.status_code == 201
    certificate_id = certificate.json()["id"]
    assert requires_apply() is True

    mark_applied()
    retired = client.delete(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates/{certificate_id}",
        headers=headers,
    )
    assert retired.status_code == 204
    assert requires_apply() is True

    mark_applied()
    detached = client.delete(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
        headers=headers,
    )
    assert detached.status_code == 204
    assert requires_apply() is True


def test_provider_api_rejects_invalid_listener_and_vcenter_network_identifiers(client) -> None:
    """Verify listener and trusted-vCenter network identifiers are canonical and bounded.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token = _token(client, ["read:kms", "write:kms"])
    headers = {"Authorization": f"Bearer {token}"}
    with SessionLocal() as db:
        db.add(
            PhysicalInterface(
                name="eth42",
                mac_address="02:00:00:00:00:42",
                ip_cidr="192.0.2.10/24",
                role="access",
                mode="access",
                oper_state="up",
            )
        )
        db.commit()

    derived_address = client.patch(
        "/api/v1/vsphere-key-providers/settings",
        headers=headers,
        json={
            "enabled": False,
            "listen_interfaces": ["eth42"],
            "listen_addresses": ["not-an-ip"],
            "port": 5696,
            "hostname": "kms.atlaso.internal",
        },
    )
    assert derived_address.status_code == 200
    assert derived_address.json()["listen_addresses"] == ["192.0.2.10"]

    invalid_interface = client.patch(
        "/api/v1/vsphere-key-providers/settings",
        headers=headers,
        json={
            "enabled": False,
            "listen_interfaces": ["eth999"],
            "listen_addresses": ["192.0.2.10"],
            "port": 5696,
            "hostname": "kms.atlaso.internal",
        },
    )
    assert invalid_interface.status_code == 422
    assert "available addressed access or VLAN interfaces" in invalid_interface.text

    invalid_hostname = client.patch(
        "/api/v1/vsphere-key-providers/settings",
        headers=headers,
        json={
            "enabled": False,
            "listen_interfaces": ["eth42"],
            "listen_addresses": ["192.0.2.10"],
            "port": 5696,
            "hostname": "not-qualified",
        },
    )
    assert invalid_hostname.status_code == 422
    assert "fully qualified DNS name" in invalid_hostname.text

    provider_id = client.post(
        "/api/v1/vsphere-key-providers",
        headers=headers,
        json={"name": "Validated provider", "enabled": False},
    ).json()["id"]
    invalid_vcenter = client.post(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters",
        headers=headers,
        json={"name": "Invalid vCenter", "hostname": "https://vcsa.example.test", "enabled": False},
    )
    assert invalid_vcenter.status_code == 422
    assert "IP address or valid fully qualified DNS name" in invalid_vcenter.text

    canonical_vcenter = client.post(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters",
        headers=headers,
        json={"name": "Canonical vCenter", "hostname": "VCSA.EXAMPLE.TEST.", "enabled": False},
    )
    assert canonical_vcenter.status_code == 201
    assert canonical_vcenter.json()["hostname"] == "vcsa.example.test"


def test_settings_archive_round_trips_only_public_provider_desired_state(client) -> None:
    """Verify settings archives preserve the provider graph without operational-key state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
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


def test_browser_retirement_preserves_the_last_usable_certificate(client) -> None:
    """Verify browser retirement distinguishes expired records from the last usable trust record.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    current_pem, _current_key = _public_client_certificate("vcsa-current.atlaso.internal")
    expired_pem, _expired_key = _public_client_certificate("vcsa-expired.atlaso.internal", expired=True)
    provider_id = str(uuid4())
    vcenter_id = str(uuid4())
    current_id = str(uuid4())
    expired_id = str(uuid4())
    with SessionLocal() as db:
        provider = VsphereKeyProvider(id=provider_id, name="Retirement provider", enabled=True)
        vcenter = VsphereTrustedVcenter(
            id=vcenter_id,
            provider_id=provider_id,
            name="Retirement vCenter",
            enabled=True,
        )
        provider.trusted_vcenters.append(vcenter)
        vcenter.certificates.extend(
            [
                VsphereTrustedVcenterCertificate(
                    id=current_id,
                    trusted_vcenter_id=vcenter_id,
                    source="uploaded_public",
                    **parse_public_certificate(current_pem),
                ),
                VsphereTrustedVcenterCertificate(
                    id=expired_id,
                    trusted_vcenter_id=vcenter_id,
                    source="uploaded_public",
                    **parse_public_certificate(expired_pem, require_current=False),
                ),
            ]
        )
        db.add(provider)
        db.commit()

    csrf = _login(client)
    headers = {"X-Atlaso-Grid": "1", "Accept": "application/json"}
    expired_retirement = client.post(
        f"/vsphere-key-providers/trusted-vcenters/{vcenter_id}/certificates/{expired_id}/delete",
        data={"csrf": csrf},
        headers=headers,
    )
    assert expired_retirement.status_code == 204

    last_usable_retirement = client.post(
        f"/vsphere-key-providers/trusted-vcenters/{vcenter_id}/certificates/{current_id}/delete",
        data={"csrf": csrf},
        headers=headers,
    )
    assert last_usable_retirement.status_code == 409
    assert last_usable_retirement.json()["detail"] == (
        "Disable the trusted vCenter before retiring its last usable certificate."
    )


def test_lifecycle_counts_report_null_when_unavailable_and_verified_counts_when_available(client, monkeypatch) -> None:
    """Verify unavailable evidence is never represented as zero.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace runtime helper behavior.
    """
    token = _token(client, ["read:kms", "write:kms"])
    headers = {"Authorization": f"Bearer {token}"}
    provider_id = client.post(
        "/api/v1/vsphere-key-providers",
        headers=headers,
        json={"name": "Counted provider", "enabled": False},
    ).json()["id"]

    monkeypatch.setattr(
        "atlaso.app.services.vsphere_key_providers.SystemAdapter.kms_status",
        lambda _self: AdapterResult(command=[], dry_run=False, returncode=2, stderr="secret-bearing raw error"),
    )
    unavailable = client.get(
        f"/api/v1/vsphere-key-providers/{provider_id}/lifecycle-counts",
        headers=headers,
    )
    assert unavailable.status_code == 200
    assert unavailable.json()["status"] == "not-reported"
    assert unavailable.json()["total"] is None
    assert "secret-bearing raw error" not in unavailable.text

    zero_payload = {
        "status": "available",
        "runtime_state": "running",
        "store_status": "authenticated",
        "providers": {},
    }
    monkeypatch.setattr(
        "atlaso.app.services.vsphere_key_providers.SystemAdapter.kms_status",
        lambda _self: AdapterResult(command=[], dry_run=False, stdout=json.dumps(zero_payload)),
    )
    authenticated_zero = client.get(
        f"/api/v1/vsphere-key-providers/{provider_id}/lifecycle-counts",
        headers=headers,
    )
    assert authenticated_zero.status_code == 200
    assert authenticated_zero.json()["status"] == "available"
    assert authenticated_zero.json()["pre_active"] == 0
    assert authenticated_zero.json()["active"] == 0
    assert authenticated_zero.json()["total"] == 0

    payload = {
        "status": "available",
        "runtime_state": "running",
        "store_status": "authenticated",
        "providers": {provider_id: {"pre_active": 2, "active": 3, "total": 5}},
    }
    monkeypatch.setattr(
        "atlaso.app.services.vsphere_key_providers.SystemAdapter.kms_status",
        lambda _self: AdapterResult(command=[], dry_run=False, stdout=json.dumps(payload)),
    )
    available = client.get(
        f"/api/v1/vsphere-key-providers/{provider_id}/lifecycle-counts",
        headers=headers,
    )
    assert available.status_code == 200
    assert available.json()["status"] == "available"
    assert available.json()["pre_active"] == 2
    assert available.json()["active"] == 3
    assert available.json()["total"] == 5

    monkeypatch.setattr(
        "atlaso.app.services.vsphere_key_providers.SystemAdapter.kms_status",
        lambda _self: AdapterResult(command=[], dry_run=False, stdout=json.dumps(zero_payload)),
    )
    deleted = client.delete(
        f"/api/v1/vsphere-key-providers/{provider_id}",
        headers=headers,
    )
    assert deleted.status_code == 204


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
