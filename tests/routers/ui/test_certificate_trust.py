"""Test Certificate Authority and vSphere Key Provider UI transports."""

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
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
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
