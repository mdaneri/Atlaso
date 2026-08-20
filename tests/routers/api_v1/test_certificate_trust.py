"""Test vSphere Key Provider API v1 transports."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    PhysicalInterface,
    VsphereKeyProvider,
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
        .not_valid_before(
            now - timedelta(days=30) if expired else now - timedelta(minutes=1)
        )
        .not_valid_after(
            now - timedelta(days=1) if expired else now + timedelta(days=30)
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
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


def test_provider_api_enforces_scopes_public_certificates_and_global_fingerprint_uniqueness(
    client,
) -> None:
    """Verify API authorization and the public-certificate trust model.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    read_token = _token(client, ["read:kms"])
    write_token = _token(client, ["read:kms", "write:kms"])
    read_headers = {"Authorization": f"Bearer {read_token}"}
    write_headers = {"Authorization": f"Bearer {write_token}"}

    assert (
        client.get("/api/v1/vsphere-key-providers", headers=read_headers).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/vsphere-key-providers",
            headers=read_headers,
            json={"name": "Rejected", "enabled": False},
        ).status_code
        == 403
    )

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
        json={
            "name": "vCenter A",
            "hostname": "vcsa-a.atlaso.internal",
            "enabled": False,
        },
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
        json={
            "name": "Tracked vCenter",
            "hostname": "vcsa-tracked.atlaso.internal",
            "enabled": False,
        },
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
    public_pem, _private_pem = _public_client_certificate(
        "vcsa-tracked.atlaso.internal"
    )
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


def test_provider_api_rejects_invalid_listener_and_vcenter_network_identifiers(
    client,
) -> None:
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
        json={
            "name": "Invalid vCenter",
            "hostname": "https://vcsa.example.test",
            "enabled": False,
        },
    )
    assert invalid_vcenter.status_code == 422
    assert "IP address or valid fully qualified DNS name" in invalid_vcenter.text

    canonical_vcenter = client.post(
        f"/api/v1/vsphere-key-providers/{provider_id}/trusted-vcenters",
        headers=headers,
        json={
            "name": "Canonical vCenter",
            "hostname": "VCSA.EXAMPLE.TEST.",
            "enabled": False,
        },
    )
    assert canonical_vcenter.status_code == 201
    assert canonical_vcenter.json()["hostname"] == "vcsa.example.test"


def test_lifecycle_counts_report_null_when_unavailable_and_verified_counts_when_available(
    client, monkeypatch
) -> None:
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
        lambda _self: AdapterResult(
            command=[], dry_run=False, returncode=2, stderr="secret-bearing raw error"
        ),
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
        lambda _self: AdapterResult(
            command=[], dry_run=False, stdout=json.dumps(zero_payload)
        ),
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
        lambda _self: AdapterResult(
            command=[], dry_run=False, stdout=json.dumps(payload)
        ),
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
        lambda _self: AdapterResult(
            command=[], dry_run=False, stdout=json.dumps(zero_payload)
        ),
    )
    pending_delete = client.delete(
        f"/api/v1/vsphere-key-providers/{provider_id}",
        headers=headers,
    )
    assert pending_delete.status_code == 409
    assert (
        pending_delete.json()["detail"]
        == "Apply the disabled and detached provider state before deletion."
    )

    with SessionLocal() as db:
        provider = db.get(VsphereKeyProvider, provider_id)
        assert provider is not None
        provider.applied_at = provider.updated_at
        db.commit()

    deleted = client.delete(
        f"/api/v1/vsphere-key-providers/{provider_id}",
        headers=headers,
    )
    assert deleted.status_code == 204
