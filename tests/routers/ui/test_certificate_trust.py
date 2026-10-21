"""Test Certificate Authority and vSphere Key Provider UI transports."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    Vault,
    VaultEntry,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
)
from atlaso.app.secrets import encrypt_secret
from atlaso.app.services.vsphere_enrollment import (
    DiscoveredClient,
    DiscoveredInventory,
    certificate_fingerprint,
)
from atlaso.app.services.vsphere_key_providers import (
    parse_public_certificate,
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


def test_browser_retirement_preserves_the_last_usable_certificate(client) -> None:
    """Verify browser retirement distinguishes expired records from the last usable trust record.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    current_pem, _current_key = _public_client_certificate(
        "vcsa-current.atlaso.internal"
    )
    expired_pem, _expired_key = _public_client_certificate(
        "vcsa-expired.atlaso.internal", expired=True
    )
    provider_id = str(uuid4())
    vcenter_id = str(uuid4())
    current_id = str(uuid4())
    expired_id = str(uuid4())
    with SessionLocal() as db:
        provider = VsphereKeyProvider(
            id=provider_id, name="Retirement provider", enabled=True
        )
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


def test_browser_provider_deletion_requires_applied_disablement(
    client, monkeypatch
) -> None:
    """Verify the browser cannot delete a provider before runtime trust removal is applied.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace runtime helper behavior.
    """
    provider_id = str(uuid4())
    with SessionLocal() as db:
        db.add(
            VsphereKeyProvider(id=provider_id, name="Browser removal", enabled=False)
        )
        db.commit()

    zero_payload = {
        "status": "available",
        "runtime_state": "running",
        "store_status": "authenticated",
        "providers": {provider_id: {"pre_active": 0, "active": 0, "total": 0}},
    }
    monkeypatch.setattr(
        "atlaso.app.services.vsphere_key_providers.SystemAdapter.kms_status",
        lambda _self: AdapterResult(
            command=[], dry_run=False, stdout=json.dumps(zero_payload)
        ),
    )
    csrf = _login(client)
    url = f"/ui/management/vsphere-key-providers/providers/{provider_id}/delete"
    pending = client.post(
        url,
        data={"csrf": csrf},
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert pending.status_code == 409
    assert (
        pending.json()["detail"]
        == "Apply the disabled and detached provider state before deletion."
    )

    with SessionLocal() as db:
        provider = db.get(VsphereKeyProvider, provider_id)
        assert provider is not None
        provider.applied_at = provider.updated_at
        db.commit()

    deleted = client.post(
        url,
        data={"csrf": csrf},
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert deleted.status_code == 204


def test_certificate_authority_downloads_public_pems(client):
    """Verify that certificate authority downloads public pems.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    _login(client)
    root = client.get("/certificate-authority/downloads/root-ca.pem")
    assert root.status_code == 200
    assert (
        root.headers["content-disposition"]
        == 'attachment; filename="atlaso-root-ca.pem"'
    )
    assert "BEGIN CERTIFICATE" in root.text
    assert "BEGIN PRIVATE KEY" not in root.text

    bundle = client.get("/certificate-authority/downloads/ca-bundle.pem")
    assert bundle.status_code == 200
    assert (
        bundle.headers["content-disposition"]
        == 'attachment; filename="atlaso-ca-bundle.pem"'
    )
    assert "BEGIN CERTIFICATE" in bundle.text


def test_public_ca_root_page_is_unauthenticated(client):
    """Verify that public ca root page is unauthenticated.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaSettings, PhysicalInterface

    with SessionLocal() as db:
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.management_https_enabled = True
        settings = db.execute(select(CaSettings)).scalar_one()
        settings.enabled = True
        settings.root_certificate_pem = (
            "-----BEGIN CERTIFICATE-----\npublic-root\n-----END CERTIFICATE-----\n"
        )
        settings.root_fingerprint = "abc123"
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.87.32\nfd00:87::32"
        db.add(settings)
        eth0 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        eth0.role = "management"
        eth0.ip_cidr = "192.168.167.10/24"
        eth2 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        eth2.role = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        eth2.ipv6_enabled = True
        eth2.ipv6_cidr = "fd00:87::32/64"
        db.commit()

    public_headers = {"host": "ca.atlaso.internal"}
    page = client.get("/ui/public/ca", headers=public_headers)
    assert page.status_code == 200
    assert "Atlaso Certificate Authority" in page.text
    assert "Photon appliance" in page.text
    assert 'class="brand" href="/ui/public"' in page.text
    assert "Atlaso Internal Root CA" in page.text
    assert "abc123" in page.text
    assert "ca-fingerprint-block" in page.text
    assert 'data-copy-value="abc123"' in page.text
    assert "Copy fingerprint" in page.text
    assert "ca.atlaso.internal" in page.text
    assert "/ca/downloads/root-ca.pem" in page.text
    assert 'href="/ui/public/ca/requests"' in page.text
    assert page.text.count('href="/ui/public/ca/requests"') == 1
    assert "public-link-panel" in page.text
    assert "Open request portal" not in page.text
    assert 'href="/ui/public/ca/login"' in page.text
    assert "Trust Material" not in page.text
    assert "Appliance Information" not in page.text
    assert "https://github.com/mdaneri/Atlaso" in page.text
    public_footer = page.text.split('<footer class="public-info-footnote"', 1)[1].split(
        "</footer>", 1
    )[0]
    documentation_link = (
        'href="https://mdaneri.github.io/Atlaso/docs/" target="_blank" rel="noopener" '
        'title="Atlaso documentation"'
    )
    assert documentation_link in public_footer
    assert ">Documentation<" in public_footer
    assert public_footer.index(
        "https://github.com/mdaneri/Atlaso"
    ) < public_footer.index(documentation_link)
    assert public_footer.index(documentation_link) < public_footer.index(">Swagger<")
    assert 'href="https://192.168.167.10/ui/management"' in page.text
    assert ">Management<" in page.text
    assert 'href="https://192.168.167.10/api/docs"' in page.text
    assert ">Swagger<" in page.text
    assert 'href="https://www.python.org/"' in page.text
    assert "Python " in page.text
    assert "/certificate-authority" not in page.text
    assert "/appliance-apply" not in page.text

    login_page = client.get("/ui/public/ca/login", headers=public_headers)
    assert login_page.status_code == 200
    assert "Sign in to user portal" in login_page.text
    assert "Use your Atlaso user account to continue." in login_page.text
    assert (
        'action="/ui/public/ca/login" method="post" target="_self"' in login_page.text
    )
    assert 'name="next" value="/ui/public/ca"' in login_page.text
    assert "data-history-back" in login_page.text
    assert ">Cancel<" in login_page.text
    assert 'class="public-portal-shell"' in login_page.text
    assert "https://github.com/mdaneri/Atlaso" in login_page.text
    assert 'href="https://192.168.167.10/api/docs"' in login_page.text
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    login_response = client.post(
        "/ui/public/ca/login",
        headers=public_headers,
        data={
            "username": "admin",
            "password": "atlaso-admin",
            "csrf": csrf,
            "next": "/ca",
        },
        follow_redirects=False,
    )
    assert login_response.status_code == 303
    assert login_response.headers["location"] == "/ui/public/ca"

    signed_in_page = client.get("/ui/public/ca", headers=public_headers)
    assert signed_in_page.status_code == 200
    assert "Sign out" in signed_in_page.text
    assert 'name="next" value="/ui/public/ca"' in signed_in_page.text
    csrf = signed_in_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    logout_response = client.post(
        "/ui/public/ca/requests/logout",
        headers=public_headers,
        data={"csrf": csrf, "next": "/ui/public/ca"},
        follow_redirects=False,
    )
    assert logout_response.status_code == 303
    assert logout_response.headers["location"] == "/ui/public/ca"

    ca_host_home = client.get("/", headers={"host": "ca.atlaso.internal"})
    assert ca_host_home.status_code == 200
    assert "Atlaso Public Services" in ca_host_home.text
    assert "Certificate Authority" in ca_host_home.text
    assert 'class="public-portal-shell"' in ca_host_home.text
    assert 'class="app-shell"' not in ca_host_home.text
    assert 'class="sidebar"' not in ca_host_home.text
    assert "/certificate-authority" not in ca_host_home.text

    ca_ip_home = client.get("/", headers={"host": "192.168.87.32"})
    assert ca_ip_home.status_code == 200
    assert "Atlaso Public Services" in ca_ip_home.text
    assert "Certificate Authority" in ca_ip_home.text
    assert "/ca/downloads/root-ca.pem" not in ca_ip_home.text
    assert "Appliance Information" not in ca_ip_home.text
    assert 'href="/ui/public/ca/login"' in ca_ip_home.text
    assert ">Login<" in ca_ip_home.text
    assert "https://github.com/mdaneri/Atlaso" in ca_ip_home.text
    assert 'href="https://192.168.167.10/ui/management"' in ca_ip_home.text
    assert ">Management<" in ca_ip_home.text
    assert 'href="https://192.168.167.10/api/docs"' in ca_ip_home.text
    assert ">Swagger<" in ca_ip_home.text
    assert 'href="https://www.python.org/"' in ca_ip_home.text
    assert 'href="/ui/public/ca/requests"' not in ca_ip_home.text
    assert "Request certificate" not in ca_ip_home.text
    assert ca_ip_home.text.index(
        "https://github.com/mdaneri/Atlaso"
    ) > ca_ip_home.text.index('href="/ui/public/ca/login"')
    assert ca_ip_home.text.index(
        "https://github.com/mdaneri/Atlaso"
    ) > ca_ip_home.text.index("Public Services")
    assert 'class="public-portal-shell"' in ca_ip_home.text
    assert 'class="app-shell"' not in ca_ip_home.text
    assert 'class="sidebar"' not in ca_ip_home.text
    assert "/certificate-authority" not in ca_ip_home.text

    ca_ipv6_home = client.get("/", headers={"host": "[fd00:87::32]"})
    assert ca_ipv6_home.status_code == 200
    assert "Atlaso Public Services" in ca_ipv6_home.text
    assert "Certificate Authority" in ca_ipv6_home.text
    assert "/certificate-authority" not in ca_ipv6_home.text

    management_ip_home = client.get(
        "/", headers={"host": "192.168.167.10"}, follow_redirects=False
    )
    assert management_ip_home.status_code == 303
    assert management_ip_home.headers["location"] == "/ui/management"

    root = client.get("/ca/downloads/root-ca.pem")
    assert root.status_code == 200
    assert "public-root" in root.text
    assert "PRIVATE KEY" not in root.text


def test_vcenter_enrollment_requires_confirmed_https_before_vault_use(
    client, monkeypatch
) -> None:
    """A changed HTTPS identity cannot trigger Vault secret decryption.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing public probing and secret access.
    """
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    with SessionLocal() as db:
        vault = Vault(name=f"vcenter-{uuid4()}", created_by="admin")
        db.add(vault)
        db.flush()
        entry = VaultEntry(
            vault_id=vault.id,
            key="vcenter-admin",
            secret_type="vcf_password",
            uris_json='["https://vcsa.example.test"]',
            username="administrator",
            encrypted_value=encrypt_secret("test-secret"),
            created_by="admin",
        )
        db.add(entry)
        db.commit()
        vault_id, entry_id = vault.id, entry.id
    monkeypatch.setattr(
        transport, "vcenter_https_leaf", lambda _host, **_kwargs: b"changed-leaf"
    )
    monkeypatch.setattr(
        transport,
        "decrypt_secret",
        lambda _secret: (_ for _ in ()).throw(AssertionError("Vault decrypted")),
    )

    response = client.post(
        "/vsphere-key-providers/enrollment/inspect",
        data={
            "hostname": "vcsa.example.test",
            "cluster_id": "Atlaso-KMIP",
            "vault_id": vault_id,
            "entry_id": entry_id,
            "uri_index": 0,
            "confirmed_https_fingerprint": "00" * 32,
            "csrf": csrf,
        },
    )
    assert response.status_code == 422
    assert "Confirm the current vCenter HTTPS fingerprint" in response.text


def test_vcenter_enrollment_approval_binds_only_inspected_client_to_provider(
    client, monkeypatch
) -> None:
    """Approval stores an exact certificate in one provider's desired state.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing vCenter discovery.
    """
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    public_pem, _ = _public_client_certificate("vcsa-enrolled.example.test")
    parsed = parse_public_certificate(public_pem)
    with SessionLocal() as db:
        provider = VsphereKeyProvider(
            id=str(uuid4()), name=f"Enrollment {uuid4()}", enabled=True
        )
        db.add(provider)
        vault = Vault(name=f"enrollment-vault-{uuid4()}", created_by="admin")
        db.add(vault)
        db.flush()
        entry = VaultEntry(
            vault_id=vault.id,
            key="vcenter-admin",
            secret_type="vcf_password",
            uris_json='["https://vcsa.example.test"]',
            username="administrator",
            encrypted_value=encrypt_secret("test-secret"),
            created_by="admin",
        )
        db.add(entry)
        db.commit()
        provider_id = provider.id
        vault_id, entry_id = vault.id, entry.id
        from atlaso.app.ui import kms_context

        health = kms_context(db, include_runtime_counts=False)["vsphere_status_rows"]
        assert (
            next(row for row in health if row["provider_id"] == provider_id)[
                "readiness"
            ]
            == "enrollment required"
        )

    discovered = DiscoveredClient(
        certificate_pem=public_pem,
        fingerprint_sha256=str(parsed["fingerprint_sha256"]),
        subject=str(parsed["subject"]),
        not_valid_after=str(parsed["not_valid_after"]),
        cluster_id="Atlaso-KMIP",
        vcenter_host="vcsa.example.test",
    )
    monkeypatch.setattr(
        transport, "vcenter_https_leaf", lambda _host, **_kwargs: b"confirmed-leaf"
    )
    monkeypatch.setattr(
        transport, "discover_vcenter_client", lambda **_kwargs: discovered
    )
    data = {
        "provider_id": provider_id,
        "name": "New vCenter",
        "hostname": "vcsa.example.test",
        "cluster_id": "Atlaso-KMIP",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "uri_index": 0,
        "confirmed_https_fingerprint": certificate_fingerprint(b"confirmed-leaf"),
        "expected_client_fingerprint": "00" * 32,
        "csrf": csrf,
    }
    changed = client.post("/vsphere-key-providers/enrollment/approve", data=data)
    assert changed.status_code == 422
    with SessionLocal() as db:
        assert (
            db.query(VsphereTrustedVcenter).filter_by(provider_id=provider_id).count()
            == 0
        )

    data["expected_client_fingerprint"] = str(parsed["fingerprint_sha256"])
    approved = client.post("/vsphere-key-providers/enrollment/approve", data=data)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "saved_pending_appliance_apply"
    assert approved.json()["trusted_vcenter"]["name"] == "New vCenter"
    assert approved.json()["trusted_vcenter"]["hostname"] == "vcsa.example.test"
    assert approved.json()["provider"]["id"] == provider_id
    assert approved.json()["provider"]["name"].startswith("Enrollment ")
    assert len(approved.json()["certificates"]) == 1
    assert (
        approved.json()["certificates"][0]["fingerprint_sha256"]
        == parsed["fingerprint_sha256"]
    )
    with SessionLocal() as db:
        trusted = (
            db.query(VsphereTrustedVcenter).filter_by(provider_id=provider_id).one()
        )
        assert trusted.hostname == "vcsa.example.test"
        assert (
            trusted.certificates[0].fingerprint_sha256 == parsed["fingerprint_sha256"]
        )
        assert trusted.certificates[0].source == "vcenter_api_discovered"
        health = kms_context(db, include_runtime_counts=False)["vsphere_status_rows"]
        assert (
            next(row for row in health if row["provider_id"] == provider_id)[
                "readiness"
            ]
            == "ready"
        )

    data["vcenter_id"] = approved.json()["trusted_vcenter_id"]
    data["name"] = "Refreshed vCenter"
    refreshed = client.post("/vsphere-key-providers/enrollment/approve", data=data)
    assert refreshed.status_code == 200, refreshed.text
    with SessionLocal() as db:
        trusted = db.get(VsphereTrustedVcenter, data["vcenter_id"])
        assert trusted.name == "Refreshed vCenter"
        assert len(trusted.certificates) == 1
        original_certificate_id = trusted.certificates[0].id
        desired_updated_at = db.get(VsphereKeyProvider, provider_id).updated_at
    unchanged = client.post("/vsphere-key-providers/enrollment/approve", data=data)
    assert unchanged.status_code == 200, unchanged.text
    with SessionLocal() as db:
        trusted = db.get(VsphereTrustedVcenter, data["vcenter_id"])
        assert len(trusted.certificates) == 1
        assert trusted.certificates[0].id == original_certificate_id
        assert (
            db.get(VsphereKeyProvider, provider_id).updated_at == desired_updated_at
        )
        other = VsphereTrustedVcenter(
            id=str(uuid4()),
            provider_id=provider_id,
            name="Other vCenter",
            hostname="vcsa.example.test",
            enabled=True,
        )
        db.add(other)
        db.commit()
        other_id = other.id
    assigned_elsewhere = client.post(
        "/vsphere-key-providers/enrollment/approve",
        data={**data, "vcenter_id": other_id, "name": "Other rename"},
    )
    assert assigned_elsewhere.status_code == 422
    with SessionLocal() as db:
        other = db.get(VsphereTrustedVcenter, other_id)
        assert other.name == "Other vCenter"
        assert other.certificates == []

    replacement_pem, _ = _public_client_certificate("vcsa-rotation.example.test")
    replacement = parse_public_certificate(replacement_pem)
    replacement_discovery = DiscoveredClient(
        certificate_pem=replacement_pem,
        fingerprint_sha256=str(replacement["fingerprint_sha256"]),
        subject=str(replacement["subject"]),
        not_valid_after=str(replacement["not_valid_after"]),
        cluster_id="Atlaso-KMIP",
        vcenter_host="vcsa.example.test",
    )
    monkeypatch.setattr(
        transport, "discover_vcenter_client", lambda **_kwargs: replacement_discovery
    )
    data["vcenter_id"] = approved.json()["trusted_vcenter_id"]
    data["name"] = "Renamed vCenter"
    data["expected_client_fingerprint"] = str(replacement["fingerprint_sha256"])
    with SessionLocal() as db:
        trusted = db.get(VsphereTrustedVcenter, data["vcenter_id"])
        trusted.hostname = "different.example.test"
        db.commit()
    mismatched = client.post("/vsphere-key-providers/enrollment/approve", data=data)
    assert mismatched.status_code == 422
    with SessionLocal() as db:
        trusted = db.get(VsphereTrustedVcenter, data["vcenter_id"])
        assert len(trusted.certificates) == 1
        trusted.hostname = ""
        db.commit()
    rotated = client.post("/vsphere-key-providers/enrollment/approve", data=data)
    assert rotated.status_code == 200, rotated.text
    with SessionLocal() as db:
        trusted = db.get(VsphereTrustedVcenter, data["vcenter_id"])
        assert trusted is not None
        assert trusted.name == "Renamed vCenter"
        assert trusted.hostname == "vcsa.example.test"
        assert {item.fingerprint_sha256 for item in trusted.certificates} == {
            parsed["fingerprint_sha256"],
            replacement["fingerprint_sha256"],
        }


def test_manual_vcenter_create_returns_current_provider_and_certificate_rows(client):
    """Return refreshed named rows after creating a vCenter without a certificate.

    Args:
        client: Authenticated HTTP test client used to exercise the UI transport.
    """
    provider_id = str(uuid4())
    with SessionLocal() as db:
        provider = VsphereKeyProvider(
            id=provider_id, name="Manual provider response", enabled=True
        )
        db.add(provider)
        db.commit()

    csrf = _login(client)
    response = client.post(
        "/vsphere-key-providers/trusted-vcenters",
        data={
            "provider_id": provider_id,
            "name": "Manual vCenter response",
            "hostname": "vcsa-manual.example.test",
            "description": "Manual setup",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["trusted_vcenter"]["name"] == "Manual vCenter response"
    assert payload["trusted_vcenter"]["hostname"] == "vcsa-manual.example.test"
    assert payload["provider"]["id"] == provider_id
    assert payload["provider"]["name"] == "Manual provider response"
    assert payload["certificates"] == []


def test_enrollment_saved_endpoint_binding_and_choices(client, monkeypatch) -> None:
    """Reject substituted endpoints before secret use and preserve URI ports.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing network and secret access.
    """
    import re
    from urllib.parse import urlsplit

    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    with SessionLocal() as db:
        provider = VsphereKeyProvider(
            id=str(uuid4()), name=f"Binding {uuid4()}", enabled=True
        )
        db.add(provider)
        vault = Vault(name=f"binding-{uuid4()}", created_by="admin")
        db.add(vault)
        db.flush()
        entry = VaultEntry(
            vault_id=vault.id,
            key="bound-vcenter",
            secret_type="vcf_password",
            username="administrator",
            encrypted_value=encrypt_secret("test-secret"),
            uris_json=json.dumps(
                [
                    "ssh://vcsa.example.test",
                    "https://vcsa.example.test:8443/ui",
                    "https://other.example.test",
                ]
            ),
            created_by="admin",
        )
        empty = VaultEntry(
            vault_id=vault.id,
            key="no-endpoint",
            secret_type="vcf_password",
            username="administrator",
            encrypted_value=encrypt_secret("test-secret"),
            created_by="admin",
        )
        db.add_all([entry, empty])
        db.commit()
        vault_id, entry_id, empty_id = vault.id, entry.id, empty.id
        provider_id = provider.id
    page = client.get("/vsphere-key-providers")
    assert page.status_code == 200
    assert f'value="{vault_id}|{entry_id}|1"' in page.text
    assert f'value="{vault_id}|{entry_id}|2"' in page.text
    assert f'value="{vault_id}|{entry_id}|0"' not in page.text
    assert f'value="{vault_id}|{empty_id}|' not in page.text
    label = re.search(
        rf'value="{vault_id}\|{entry_id}\|1">[^<]* (https://[^ ]+) ', page.text
    )
    assert label is not None
    endpoint = urlsplit(label.group(1))
    assert endpoint.hostname == "vcsa.example.test"
    assert endpoint.port == 8443
    data = {
        "provider_id": provider_id,
        "name": "Bound vCenter",
        "expected_client_fingerprint": "00" * 32,
        "hostname": "vcsa.example.test",
        "cluster_id": "Atlaso-KMIP",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "uri_index": 1,
        "confirmed_https_fingerprint": certificate_fingerprint(b"leaf"),
        "csrf": csrf,
    }
    monkeypatch.setattr(
        transport,
        "decrypt_secret",
        lambda _secret: (_ for _ in ()).throw(AssertionError("Vault decrypted")),
    )
    monkeypatch.setattr(
        transport,
        "vcenter_https_leaf",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network used")),
    )
    for changes in (
        {"hostname": "attacker.example.test"},
        {"uri_index": 0},
        {"uri_index": -1},
        {"uri_index": 99},
        {"uri_index": 2},
        {"entry_id": empty_id},
        {"vault_id": vault_id + 10000},
    ):
        for route in ("probe", "inspect", "approve"):
            response = client.post(
                f"/vsphere-key-providers/enrollment/{route}", data={**data, **changes}
            )
            assert response.status_code == 422, response.text
    seen = []

    def probe(host, *, port):
        """Capture the saved endpoint used by the public probe.

        Args:
            host: Resolved saved endpoint hostname.
            port: Resolved saved endpoint port.
        """
        seen.append((host, port))
        return b"leaf"

    monkeypatch.setattr(transport, "vcenter_https_leaf", probe)
    response = client.post("/vsphere-key-providers/enrollment/probe", data=data)
    assert response.status_code == 200
    assert seen == [("vcsa.example.test", 8443)]
    monkeypatch.setattr(transport, "decrypt_secret", lambda _secret: "test-secret")

    def discover(**kwargs):
        """Capture the saved endpoint used by authenticated discovery.

        Args:
            **kwargs: Discovery arguments containing the resolved endpoint.
        """
        assert kwargs["host"] == "vcsa.example.test"
        assert kwargs["port"] == 8443
        raise transport.EnrollmentError("endpoint captured")

    monkeypatch.setattr(transport, "discover_vcenter_client", discover)
    response = client.post("/vsphere-key-providers/enrollment/inspect", data=data)
    assert response.status_code == 422
    assert "endpoint captured" in response.text


def test_enrollment_endpoint_rejection_preserves_http_error_and_trust_state(client, monkeypatch) -> None:
    """Expose sanitized endpoint guidance through inspect and approval without saving trust.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing network and credential operations.
    """
    from atlaso.app.routers.ui import certificate_trust as transport
    from atlaso.app.services.vsphere_enrollment import _check_cluster_endpoint

    csrf = _login(client)
    leaf = b"endpoint-regression-leaf"
    monkeypatch.setattr(transport, "vcenter_https_leaf", lambda *_args, **_kwargs: leaf)

    def reject(**kwargs):
        """Run the real endpoint guard using the listener settings passed by the route.

        Args:
            **kwargs: Request-local discovery arguments.
        """
        _check_cluster_endpoint(
            [{"address": kwargs["password"], "port": 61337}], kwargs["atlaso_host"], kwargs["atlaso_port"]
        )

    monkeypatch.setattr(transport, "discover_vcenter_client", reject)
    with SessionLocal() as db:
        provider = VsphereKeyProvider(id=str(uuid4()), name="Endpoint regression", enabled=True)
        db.add(provider)
        vault = Vault(name="Endpoint regression", created_by="admin")
        db.add(vault)
        db.flush()
        entry = VaultEntry(
            vault_id=vault.id, key="endpoint-regression", secret_type="vcf_password",
            uris_json='["https://vcsa.example.test"]', username="saved-user",
            encrypted_value=encrypt_secret("request-only-secret.example.test"), created_by="admin",
        )
        db.add(entry)
        db.commit()
        provider_id = provider.id
        vault_id, entry_id = vault.id, entry.id
        before = [row.id for row in db.query(VsphereTrustedVcenter).all()]
        certificates = [row.id for row in db.query(VsphereTrustedVcenterCertificate).all()]
    data = {
        "csrf": csrf, "credential_source": "manual", "hostname": "vcsa.example.test",
        "username": "request-only-user", "password": "request-only-secret.example.test",
        "cluster_id": "Default", "confirmed_https_fingerprint": certificate_fingerprint(leaf),
        "provider_id": provider_id, "name": "Lab vCenter", "expected_client_fingerprint": "00" * 32,
    }
    for credential in ({}, {"credential_source": "vault", "vault_id": vault_id, "entry_id": entry_id,
                            "uri_index": 0, "username": "", "password": ""}):
        for route in ("inspect", "approve"):
            response = client.post(f"/vsphere-key-providers/enrollment/{route}", data={**data, **credential})
            assert response.status_code == 422
            message = response.json()["detail"]
            assert "Expected configured Atlaso endpoint:" in message
            assert "member 1" not in message
            assert "address differs" not in message
            assert "port differs" not in message
            assert "61337" not in message
            assert "then retry" in message
            assert "request-only" not in message
    with SessionLocal() as db:
        assert [row.id for row in db.query(VsphereTrustedVcenter).all()] == before
        assert [row.id for row in db.query(VsphereTrustedVcenterCertificate).all()] == certificates


def test_vcenter_enrollment_manual_credentials_are_request_local(client, monkeypatch) -> None:
    """Enroll with manual credentials without reading or storing a Vault secret.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing public probing, discovery, and secret access.
    """
    from atlaso.app.models import AuditEvent
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    username = "temporary-vcenter-operator"
    password = "manual-secret-that-must-not-persist"
    host = "vcsa-manual.example.test"
    cluster_id = "Atlaso-KMIP"
    https_leaf = b"manual-vcenter-https-leaf"
    fingerprint = certificate_fingerprint(https_leaf)
    public_pem, _ = _public_client_certificate(host)
    parsed = parse_public_certificate(public_pem)
    discovered = DiscoveredClient(
        certificate_pem=public_pem,
        fingerprint_sha256=str(parsed["fingerprint_sha256"]),
        subject=str(parsed["subject"]),
        not_valid_after=str(parsed["not_valid_after"]),
        cluster_id=cluster_id,
        vcenter_host=host,
    )
    probes = []
    calls = []

    def probe(observed_host, *, port):
        """Capture the unauthenticated HTTPS certificate probe.

        Args:
            observed_host: Endpoint selected for the certificate probe.
            port: HTTPS port used by the probe.
        """
        probes.append((observed_host, port))
        return https_leaf

    def discover(**kwargs):
        """Capture request-local credentials passed to authenticated discovery.

        Args:
            **kwargs: Discovery arguments captured for request-isolation assertions.
        """
        calls.append(kwargs)
        return discovered

    monkeypatch.setattr(transport, "vcenter_https_leaf", probe)
    monkeypatch.setattr(transport, "discover_vcenter_client", discover)
    monkeypatch.setattr(
        transport,
        "decrypt_secret",
        lambda _secret: (_ for _ in ()).throw(AssertionError("Vault decrypted")),
    )

    with SessionLocal() as db:
        provider = VsphereKeyProvider(
            id=str(uuid4()), name=f"Manual enrollment {uuid4()}", enabled=True
        )
        db.add(provider)
        db.commit()
        provider_id = provider.id
        vault_count_before = db.query(Vault).count()
        entry_count_before = db.query(VaultEntry).count()

    common = {
        "credential_source": "manual",
        "hostname": host,
        "cluster_id": cluster_id,
        "username": username,
        "password": password,
        "csrf": csrf,
    }
    probed = client.post(
        "/vsphere-key-providers/enrollment/probe", data=common
    )
    assert probed.status_code == 200, probed.text
    assert probed.json() == {"https_fingerprint": fingerprint}
    assert probes == [(host, 443)]
    assert calls == []

    inspected = client.post(
        "/vsphere-key-providers/enrollment/inspect",
        data={
            **common,
            "confirmed_https_fingerprint": fingerprint.replace(":", ""),
        },
    )
    assert inspected.status_code == 200, inspected.text
    assert inspected.json()["client_fingerprint"] == parsed["fingerprint_sha256"]
    assert calls[-1]["username"] == username
    assert calls[-1]["password"] == password
    assert calls[-1]["port"] == 443

    approved = client.post(
        "/vsphere-key-providers/enrollment/approve",
        data={
            **common,
            "provider_id": provider_id,
            "name": "Manual vCenter",
            "confirmed_https_fingerprint": fingerprint,
            "expected_client_fingerprint": parsed["fingerprint_sha256"],
        },
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "saved_pending_appliance_apply"
    assert probes == [(host, 443), (host, 443), (host, 443)]
    assert len(calls) == 2

    for response in (probed, inspected, approved):
        assert username not in response.text
        assert password not in response.text
    page = client.get("/vsphere-key-providers")
    assert page.status_code == 200
    assert username not in page.text
    assert password not in page.text
    with SessionLocal() as db:
        assert db.query(Vault).count() == vault_count_before
        assert db.query(VaultEntry).count() == entry_count_before
        trusted = (
            db.query(VsphereTrustedVcenter)
            .filter_by(provider_id=provider_id)
            .one()
        )
        assert trusted.name == "Manual vCenter"
        assert len(trusted.certificates) == 1
        assert username not in repr(trusted.__dict__)
        assert password not in repr(trusted.__dict__)
        audit = db.query(AuditEvent).all()
        enrollment_audit = [
            event
            for event in audit
            if event.action == "discover_vsphere_client_certificate"
        ]
        assert len(enrollment_audit) == 2
        assert all("credential_source=manual" in event.detail for event in enrollment_audit)
        assert all(username not in (event.detail or "") for event in audit)
        assert all(password not in (event.detail or "") for event in audit)


def test_vcenter_enrollment_manual_invalid_source_or_host_stops_before_probe(
    client, monkeypatch
) -> None:
    """Reject unsupported credential sources and non-host manual targets early.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing the public HTTPS probe.
    """
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    monkeypatch.setattr(
        transport,
        "vcenter_https_leaf",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("HTTPS probe should not run")
        ),
    )
    base = {
        "credential_source": "manual",
        "hostname": "vcsa.example.test",
        "csrf": csrf,
    }
    for changes in (
        {"credential_source": "other"},
        {"hostname": "https://vcsa.example.test/path"},
        {"hostname": "user@vcsa.example.test"},
        {"hostname": ""},
    ):
        response = client.post(
            "/vsphere-key-providers/enrollment/probe", data={**base, **changes}
        )
        assert response.status_code == 422, response.text


def test_vcenter_enrollment_manual_fingerprint_must_be_confirmed_before_discovery(
    client, monkeypatch
) -> None:
    """Missing or changed server pins prevent both discovery and Vault decryption.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing HTTPS probing and credential consumers.
    """
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    with SessionLocal() as db:
        vault = Vault(name=f"pin-check-{uuid4()}", created_by="admin")
        db.add(vault)
        db.flush()
        entry = VaultEntry(
            vault_id=vault.id,
            key="vcenter-admin",
            secret_type="vcf_password",
            uris_json='["https://vcsa.example.test"]',
            username="administrator",
            encrypted_value=encrypt_secret("not-used"),
            created_by="admin",
        )
        db.add(entry)
        db.commit()
        vault_id, entry_id = vault.id, entry.id

    monkeypatch.setattr(
        transport, "vcenter_https_leaf", lambda _host, **_kwargs: b"observed-leaf"
    )
    calls = []
    monkeypatch.setattr(
        transport,
        "discover_vcenter_client",
        lambda **kwargs: calls.append(kwargs),
    )
    monkeypatch.setattr(
        transport,
        "decrypt_secret",
        lambda _secret: (_ for _ in ()).throw(AssertionError("Vault decrypted")),
    )
    for data in (
        {
            "credential_source": "manual",
            "hostname": "vcsa.example.test",
            "cluster_id": "Atlaso-KMIP",
            "username": "manual-user",
            "password": "manual-password",
            "confirmed_https_fingerprint": "",
            "csrf": csrf,
        },
        {
            "credential_source": "manual",
            "hostname": "vcsa.example.test",
            "cluster_id": "Atlaso-KMIP",
            "username": "manual-user",
            "password": "manual-password",
            "confirmed_https_fingerprint": "00" * 32,
            "csrf": csrf,
        },
        {
            "hostname": "vcsa.example.test",
            "cluster_id": "Atlaso-KMIP",
            "vault_id": vault_id,
            "entry_id": entry_id,
            "uri_index": 0,
            "confirmed_https_fingerprint": "00" * 32,
            "csrf": csrf,
        },
    ):
        response = client.post(
            "/vsphere-key-providers/enrollment/inspect", data=data
        )
        assert response.status_code == 422, response.text
    assert calls == []


def test_vcenter_enrollment_manual_approval_rejects_client_rotation_without_changes(
    client, monkeypatch
) -> None:
    """A rotated client certificate cannot change the reviewed provider record.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Fixture replacing the HTTPS probe and vCenter discovery.
    """
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    old_pem, _ = _public_client_certificate("vcsa.example.test")
    old_parsed = parse_public_certificate(old_pem)
    replacement_pem, _ = _public_client_certificate("vcsa.example.test")
    replacement = parse_public_certificate(replacement_pem)
    cluster_id = "Atlaso-KMIP"
    host = "vcsa.example.test"
    confirmed = certificate_fingerprint(b"confirmed-leaf")
    changed = DiscoveredClient(
        certificate_pem=replacement_pem,
        fingerprint_sha256=str(replacement["fingerprint_sha256"]),
        subject=str(replacement["subject"]),
        not_valid_after=str(replacement["not_valid_after"]),
        cluster_id=cluster_id,
        vcenter_host=host,
    )
    monkeypatch.setattr(
        transport, "vcenter_https_leaf", lambda _host, **_kwargs: b"confirmed-leaf"
    )
    monkeypatch.setattr(transport, "discover_vcenter_client", lambda **_kwargs: changed)
    monkeypatch.setattr(
        transport,
        "decrypt_secret",
        lambda _secret: (_ for _ in ()).throw(AssertionError("Vault decrypted")),
    )
    with SessionLocal() as db:
        provider = VsphereKeyProvider(
            id=str(uuid4()), name=f"Rotation {uuid4()}", enabled=True
        )
        trusted = VsphereTrustedVcenter(
            id=str(uuid4()),
            provider_id=provider.id,
            name="Reviewed vCenter",
            hostname=host,
            enabled=True,
        )
        trusted.certificates.append(
            VsphereTrustedVcenterCertificate(
                id=str(uuid4()),
                source="uploaded_public",
                **old_parsed,
            )
        )
        provider.trusted_vcenters.append(trusted)
        db.add(provider)
        db.commit()
        provider_id, vcenter_id = provider.id, trusted.id
        provider_updated_at = provider.updated_at
        certificate_id = trusted.certificates[0].id

    response = client.post(
        "/vsphere-key-providers/enrollment/approve",
        data={
            "credential_source": "manual",
            "provider_id": provider_id,
            "vcenter_id": vcenter_id,
            "name": "Must not be applied",
            "hostname": host,
            "cluster_id": cluster_id,
            "username": "manual-user",
            "password": "manual-password",
            "confirmed_https_fingerprint": confirmed,
            "expected_client_fingerprint": old_parsed["fingerprint_sha256"],
            "csrf": csrf,
        },
    )
    assert response.status_code == 422
    assert "changed since inspection" in response.text
    with SessionLocal() as db:
        provider = db.get(VsphereKeyProvider, provider_id)
        trusted = db.get(VsphereTrustedVcenter, vcenter_id)
        assert provider.updated_at.replace(tzinfo=timezone.utc) == provider_updated_at
        assert trusted.name == "Reviewed vCenter"
        assert len(trusted.certificates) == 1
        assert trusted.certificates[0].id == certificate_id
        assert (
            trusted.certificates[0].fingerprint_sha256
            == old_parsed["fingerprint_sha256"]
        )


def test_vcenter_enrollment_manual_routes_keep_admin_and_csrf_guards(
    client, monkeypatch
) -> None:
    """Require an admin session and valid CSRF token on each manual route.

    Args:
        client: Isolated HTTP test client.
        monkeypatch: Fixture replacing the public HTTPS probe.
    """
    from atlaso.app.routers.ui import certificate_trust as transport
    from atlaso.app.security import Identity

    csrf = _login(client)
    monkeypatch.setattr(
        transport,
        "vcenter_https_leaf",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("request reached network")
        ),
    )
    common = {
        "credential_source": "manual",
        "hostname": "vcsa.example.test",
        "cluster_id": "Atlaso-KMIP",
        "username": "manual-user",
        "password": "manual-password",
        "confirmed_https_fingerprint": "00" * 32,
        "provider_id": str(uuid4()),
        "name": "Guard test",
        "expected_client_fingerprint": "00" * 32,
        "csrf": csrf,
    }
    for route in ("probe", "inspect", "approve"):
        unauthorized = client.post(
            f"/vsphere-key-providers/enrollment/{route}",
            data={**common, "csrf": "invalid"},
        )
        assert unauthorized.status_code == 403

    client.app.dependency_overrides[transport.require_session_identity] = lambda: Identity(
        "viewer", "viewer", set()
    )
    try:
        for route in ("probe", "inspect", "approve"):
            forbidden = client.post(
                f"/vsphere-key-providers/enrollment/{route}", data=common
            )
            assert forbidden.status_code == 403
    finally:
        client.app.dependency_overrides.pop(transport.require_session_identity, None)


def test_inventory_requires_tls_before_credentials_and_changes_no_trust(client, monkeypatch):
    """Inventory keeps TLS gating, credential locality, and saved trust unchanged.

    Args:
        client: Isolated HTTP test client.
        monkeypatch: Fixture replacing external credential and network calls.
    """
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    calls = []
    leaf = b"inventory-public-leaf"
    monkeypatch.setattr(transport, "vcenter_https_leaf", lambda *_args, **_kwargs: leaf)

    def discover(**kwargs):
        """Capture only synthetic request-local test credentials.

        Args:
            **kwargs: Pinned inventory connection arguments.
        """
        calls.append(kwargs)
        return DiscoveredInventory(name="VMware vCenter Server", cluster_ids=("a", "b"))

    monkeypatch.setattr(transport, "discover_vcenter_inventory", discover)
    monkeypatch.setattr(transport, "decrypt_secret", lambda _: pytest.fail("Unexpected Vault access"))
    with SessionLocal() as db:
        before = (db.query(VsphereKeyProvider).count(), db.query(VsphereTrustedVcenter).count(), db.query(VsphereTrustedVcenterCertificate).count())
    data = dict(csrf=csrf, hostname="vc.example.test", credential_source="manual", username="temporary-user", password="temporary-password")
    bad = client.post("/vsphere-key-providers/enrollment/inventory", data={**data, "confirmed_https_fingerprint": "00" * 32})
    assert bad.status_code == 422
    assert not calls
    response = client.post("/vsphere-key-providers/enrollment/inventory", data={**data, "confirmed_https_fingerprint": certificate_fingerprint(leaf)})
    assert response.status_code == 200, response.text
    assert response.json() == {"name": "VMware vCenter Server", "cluster_ids": ["a", "b"]}
    assert response.headers["cache-control"] == "no-store"
    assert calls[0]["port"] == 443
    assert calls[0]["username"] == "temporary-user"
    assert "temporary-password" not in response.text
    with SessionLocal() as db:
        assert before == (db.query(VsphereKeyProvider).count(), db.query(VsphereTrustedVcenter).count(), db.query(VsphereTrustedVcenterCertificate).count())


def test_inventory_keeps_admin_and_csrf_guards(client, monkeypatch):
    """Reject unauthorised discovery before external calls.

    Args:
        client: Isolated HTTP test client.
        monkeypatch: Fixture rejecting unexpected network calls.
    """
    from atlaso.app.routers.ui import certificate_trust as transport

    csrf = _login(client)
    monkeypatch.setattr(transport, "vcenter_https_leaf", lambda *_args, **_kwargs: pytest.fail("Unexpected probe"))
    response = client.post("/vsphere-key-providers/enrollment/inventory", data={"csrf": "invalid", "hostname": "vc.example.test", "confirmed_https_fingerprint": "00" * 32})
    assert response.status_code == 403
    from atlaso.app.security import Identity, require_session_identity

    client.app.dependency_overrides[require_session_identity] = lambda: Identity(username="reader", role="viewer", scopes=set())
    try:
        response = client.post("/vsphere-key-providers/enrollment/inventory", data={"csrf": csrf, "hostname": "vc.example.test", "confirmed_https_fingerprint": "00" * 32})
        assert response.status_code == 403
    finally:
        client.app.dependency_overrides.pop(require_session_identity, None)
