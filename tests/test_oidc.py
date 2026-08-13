"""Test oidc behavior."""

import base64
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select, text


def _admin_headers(client) -> dict[str, str]:
    """Return admin headers.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "oidc administration", "scopes": ["admin:all"]},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['raw_token']}"}


def _set_applied_management_https(db, fqdn: str = "atlaso.example.test") -> None:
    """Update applied management https.

    Args:
        db: Active database session.
        fqdn: Fully qualified domain name to validate or use.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from atlaso.app.models import ApplianceSettings, CaCertificate, Setting
    from atlaso.app.secrets import encrypt_secret

    appliance = db.execute(select(ApplianceSettings)).scalar_one()
    appliance.fqdn = fqdn
    appliance.management_https_enabled = True
    payload = {
        "appliance_settings": {
            "config_preview": json.dumps(
                {
                    "fqdn": fqdn,
                    "management_https_enabled": True,
                    "management_https_cert_path": "/etc/atlaso/https/appliance.crt",
                    "management_https_key_path": "/etc/atlaso/https/appliance.key",
                }
            )
        }
    }
    row = db.execute(
        select(Setting).where(Setting.key == "appliance_apply.baselines.v1")
    ).scalar_one_or_none()
    if row is None:
        row = Setting(key="appliance_apply.baselines.v1", value=json.dumps(payload))
        db.add(row)
    else:
        row.value = json.dumps(payload)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
    now = datetime.now(timezone.utc)
    certificate_pem = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]), critical=False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    certificate = db.execute(
        select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")
    ).scalar_one_or_none()
    if certificate is None:
        certificate = CaCertificate(
            common_name=fqdn,
            managed_owner="appliance:https",
        )
        db.add(certificate)
    certificate.private_key_encrypted = encrypt_secret(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
    )
    certificate.status = "issued"
    certificate.enabled = True
    certificate.certificate_pem = certificate_pem
    parsed_certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    certificate.fingerprint = parsed_certificate.fingerprint(hashes.SHA256()).hex()
    certificate.subject_alt_names = fqdn
    payload["ca"] = {
        "config_preview": json.dumps(
            {
                "certificates": [
                    {
                        "managed_owner": "appliance:https",
                        "fingerprint": certificate.fingerprint,
                    }
                ]
            }
        )
    }
    row.value = json.dumps(payload)
    db.flush()


def _set_oidc_service_ready(
    db,
    hostname: str = "oidc.atlaso.internal",
    *,
    certificate_hostname: str | None = None,
) -> None:
    """Update oidc service ready.

    Args:
        db: Active database session.
        hostname: DNS hostname of the target resource.
        certificate_hostname: Certificate hostname supplied by the caller.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from atlaso.app.models import CaCertificate, CaSettings, DnsRecord
    from atlaso.app.secrets import decrypt_secret, encrypt_secret
    from atlaso.app.services import oidc
    from atlaso.app.services.ca import ensure_root_ca_material

    provider = oidc.ensure_provider_settings(db)
    provider.hostname = hostname
    provider.listen_interface = "eth2"
    provider.listen_address = "192.168.50.1"
    provider.port = 443
    provider.issuer_url = f"https://{hostname}/identity"
    certificate_name = certificate_hostname or hostname
    ca_settings = db.execute(select(CaSettings)).scalar_one()
    ca_settings.enabled = True
    ensure_root_ca_material(ca_settings)
    root_certificate = x509.load_pem_x509_certificate(
        ca_settings.root_certificate_pem.encode("ascii")
    )
    root_private_key = serialization.load_pem_private_key(
        decrypt_secret(ca_settings.root_private_key_encrypted).encode("ascii"),
        password=None,
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, certificate_name)]
    )
    now = datetime.now(timezone.utc)
    certificate_pem = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(certificate_name),
                    x509.IPAddress(ip_address("192.168.50.1")),
                ]
            ),
            critical=False,
        )
        .sign(root_private_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    certificate = db.execute(
        select(CaCertificate).where(CaCertificate.managed_owner == "oidc:https")
    ).scalar_one_or_none()
    if certificate is None:
        certificate = CaCertificate(
            common_name=certificate_name,
            managed_owner="oidc:https",
        )
        db.add(certificate)
    certificate.private_key_encrypted = encrypt_secret(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
    )
    certificate.common_name = certificate_name
    certificate.subject_alt_names = certificate_name
    certificate.ip_addresses = "192.168.50.1"
    certificate.status = "issued"
    certificate.enabled = True
    certificate.certificate_pem = certificate_pem
    dns_record = db.execute(
        select(DnsRecord).where(
            DnsRecord.hostname == hostname,
            DnsRecord.record_type == "CNAME",
        )
    ).scalar_one_or_none()
    if dns_record is None:
        dns_record = DnsRecord(
            hostname=hostname,
            record_type="CNAME",
            address="oidc-eth2.atlaso.internal",
            description=oidc.OIDC_DNS_RECORD_DESCRIPTION,
            enabled=True,
        )
        db.add(dns_record)
    else:
        dns_record.description = oidc.OIDC_DNS_RECORD_DESCRIPTION
        dns_record.enabled = True
    db.flush()


def _configure_protocol_client(
    *,
    organization_id: int | None = None,
    redirect_uri: str = "https://rp.example.test/callback?case=A%2Fb",
    post_logout_redirect_uri: str = "https://rp.example.test/logout",
) -> tuple[str, str]:
    """Update protocol client.

    Args:
        organization_id: Stable identifier of the associated organization resource.
        redirect_uri: Redirect uri supplied to the test scenario.
        post_logout_redirect_uri: Post logout redirect uri supplied to the test scenario.


    Returns:
        The configure protocol client result.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import oidc

    with SessionLocal() as db:
        _set_oidc_service_ready(db)
        provider = oidc.ensure_provider_settings(db)
        provider.enabled = True
        if oidc.active_signing_key(db) is None:
            oidc.generate_signing_key(db, rotate=False)
        client_row, secret = oidc.create_client(
            db,
            name=f"Protocol client {organization_id or 'local'}",
            organization_id=organization_id,
            redirect_uris=[redirect_uri],
            post_logout_redirect_uris=[post_logout_redirect_uri],
            allowed_scopes=["openid", "profile", "email", "groups"],
            allow_loopback_redirects=False,
            access_token_lifetime_seconds=300,
            id_token_lifetime_seconds=300,
            authorization_code_lifetime_seconds=60,
            enabled=True,
        )
        client_id = client_row.client_id
        db.commit()
    return client_id, secret


def _authorization_parameters(client_id: str, verifier: str, **overrides: str) -> dict[str, str]:
    """Return authorization parameters.

    Args:
        client_id: Stable identifier of the associated client resource.
        verifier: Verifier supplied to the test scenario.
        **overrides: Additional keyword arguments accepted by the callable.
    """
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    params = {
        "response_type": "code",
        "response_mode": "query",
        "client_id": client_id,
        "redirect_uri": "https://rp.example.test/callback?case=A%2Fb",
        "scope": "openid profile",
        "state": "state-original",
        "nonce": "nonce-original",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "login_hint": "admin",
    }
    params.update(overrides)
    return params


def _start_login(client, params: dict[str, str]) -> tuple[str, str, str]:
    """Return start login.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        params: Params supplied to the test scenario.
    """
    response = client.get("https://testserver/identity/authorize", params=params)
    assert response.status_code == 200, response.text
    transaction = re.search(r'name="transaction" value="([^"]+)"', response.text)
    csrf = re.search(r'name="csrf" value="([^"]+)"', response.text)
    assert transaction and csrf
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    return transaction.group(1), csrf.group(1), cookie


def _finish_local_login(client, transaction: str, csrf: str):
    """Return finish local login.

    Args:
        client: Client used to invoke the external or application interface.
        transaction: Transaction supplied by the caller.
        csrf: Validated CSRF token authorizing the request.
    """
    return client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": transaction,
            "csrf": csrf,
            "source": "local",
            "username": "admin",
            "password": "atlaso-admin",
        },
        follow_redirects=False,
    )


def _exchange_code(
    client, *, client_id: str, secret: str, code: str, verifier: str,
    redirect_uri: str = "https://rp.example.test/callback?case=A%2Fb",
):
    """Return exchange code.

    Args:
        client: Client used to invoke the external or application interface.
        client_id: Identifier of the client.
        secret: Secret supplied by the caller.
        code: Code supplied by the caller.
        verifier: Verifier supplied by the caller.
        redirect_uri: Redirect uri supplied by the caller.
    """
    credentials = base64.b64encode(f"{client_id}:{secret}".encode("utf-8")).decode("ascii")
    return client.post(
        "https://testserver/identity/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        headers={"Authorization": f"Basic {credentials}"},
    )


def _jwt_claims(token: str) -> dict[str, object]:
    """Return jwt claims.

    Args:
        token: Credential or token value consumed by the operation.
    """
    segment = token.split(".")[1]
    padded = segment + ("=" * (-len(segment) % 4))
    return json.loads(base64.urlsafe_b64decode(padded))


def test_oidc_public_documents_require_complete_protocol_readiness(client):
    """Verify that oidc public documents require complete protocol readiness.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    assert client.get("/identity/.well-known/openid-configuration").status_code == 404
    assert client.get("/identity/jwks").status_code == 404

    headers = _admin_headers(client)
    provider = client.get("/api/v1/oidc/provider", headers=headers)
    assert provider.status_code == 200
    payload = provider.json()
    payload["enabled"] = True
    enable = client.put("/api/v1/oidc/provider", headers=headers, json=payload)
    assert enable.status_code == 409
    assert "access or routed listen interface" in enable.text

    from atlaso.app.database import SessionLocal
    from atlaso.app.services import oidc

    with SessionLocal() as db:
        _set_oidc_service_ready(db)
        oidc.ensure_provider_settings(db)
        oidc.generate_signing_key(db, rotate=False)
        db.commit()

    payload = client.get("/api/v1/oidc/provider", headers=headers).json()
    payload["enabled"] = True
    enabled = client.put("/api/v1/oidc/provider", headers=headers, json=payload)
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["enabled"] is True
    assert (
        client.get("https://testserver/identity/.well-known/openid-configuration").status_code
        == 200
    )
    assert client.get("https://testserver/identity/jwks").status_code == 200


def test_oidc_forwarded_https_rejects_management_listener(client):
    """Verify that oidc forwarded https rejects management listener.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from starlette.requests import Request

    from atlaso.app.database import SessionLocal
    from atlaso.app.oidc import _identity_https
    from atlaso.app.services import oidc

    with SessionLocal() as db:
        _set_oidc_service_ready(db)
        provider = oidc.ensure_provider_settings(db)
        provider.enabled = True
        oidc.generate_signing_key(db, rotate=False)
        db.commit()
        base_scope = {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/identity/.well-known/openid-configuration",
            "raw_path": b"/identity/.well-known/openid-configuration",
            "query_string": b"",
            "server": ("127.0.0.1", 8000),
            "client": ("127.0.0.1", 12345),
            "root_path": "",
            "http_version": "1.1",
        }
        management = Request(
            {
                **base_scope,
                "headers": [
                    (b"x-forwarded-proto", b"https"),
                    (b"x-atlaso-listener-address", b"192.168.49.1"),
                ],
            }
        )
        service = Request(
            {
                **base_scope,
                "headers": [
                    (b"x-forwarded-proto", b"https"),
                    (b"x-atlaso-listener-address", b"192.168.50.1"),
                ],
            }
        )
        assert _identity_https(management, db) is False
        assert _identity_https(service, db) is True


def test_oidc_readiness_requires_oidc_service_certificate(client):
    """Verify that oidc readiness requires oidc service certificate.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate
    from atlaso.app.services import oidc

    with SessionLocal() as db:
        _set_oidc_service_ready(db)
        provider = oidc.ensure_provider_settings(db)
        certificate = db.execute(
            select(CaCertificate).where(
                CaCertificate.managed_owner == "oidc:https"
            )
        ).scalar_one()
        certificate.status = "planned"
        errors = oidc.provider_validation_errors(db, provider, require_active_key=False)
        assert errors == [
            "OIDC requires an applied managed certificate for its service hostname and listener addresses."
        ]


def test_oidc_readiness_rejects_missing_listener(client):
    """Verify that oidc readiness rejects missing listener.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import oidc

    with SessionLocal() as db:
        _set_oidc_service_ready(db)
        provider = oidc.ensure_provider_settings(db)
        provider.listen_interface = ""
        provider.listen_address = ""
        errors = oidc.provider_validation_errors(db, provider, require_active_key=False)
        assert "OIDC requires at least one access or routed listen interface." in errors
        assert "OIDC listen interfaces must have at least one configured IP address." in errors


def test_oidc_confidential_client_secret_is_argon2_and_shown_only_once(client):
    """Verify that oidc confidential client secret is argon2 and shown only once.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    headers = _admin_headers(client)
    created = client.post(
        "/api/v1/oidc/clients",
        headers=headers,
        json={
            "name": "VCF 9.1",
            "description": "VCF identity broker",
            "redirect_uris": ["https://vcf.example.test/identity/callback?case=A%2Fb"],
            "post_logout_redirect_uris": [],
            "allowed_scopes": ["openid", "profile", "email", "groups"],
            "allow_loopback_redirects": False,
            "access_token_lifetime_seconds": 300,
            "id_token_lifetime_seconds": 300,
            "authorization_code_lifetime_seconds": 60,
            "enabled": True,
        },
    )
    assert created.status_code == 201, created.text
    plaintext = created.json()["client_secret"]
    assert plaintext
    listed = client.get("/api/v1/oidc/clients", headers=headers)
    assert listed.status_code == 200
    assert plaintext not in listed.text
    assert listed.json()[0]["description"] == "VCF identity broker"
    assert listed.json()[0]["redirect_uris"] == [
        "https://vcf.example.test/identity/callback?case=A%2Fb"
    ]

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcClient
    from atlaso.app.services.oidc import verify_client_secret

    with SessionLocal() as db:
        row = db.execute(select(OidcClient)).scalar_one()
        assert row.client_secret_hash.startswith("$argon2")
        assert verify_client_secret(row.client_secret_hash, plaintext)
        old_hash = row.client_secret_hash

    rotated = client.post(
        f"/api/v1/oidc/clients/{listed.json()[0]['id']}/secret/rotate",
        headers=headers,
    )
    assert rotated.status_code == 200
    replacement = rotated.json()["client_secret"]
    assert replacement != plaintext
    with SessionLocal() as db:
        row = db.execute(select(OidcClient)).scalar_one()
        assert row.client_secret_hash != old_hash
        assert not verify_client_secret(row.client_secret_hash, plaintext)
        assert verify_client_secret(row.client_secret_hash, replacement)


def test_oidc_client_update_preserves_generated_identity_and_export_is_redacted(client):
    """Verify that oidc client update preserves generated identity and export is redacted.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    headers = _admin_headers(client)
    created = client.post(
        "/api/v1/oidc/clients",
        headers=headers,
        json={
            "name": "Lifecycle client",
            "description": "Original relying party",
            "redirect_uris": ["https://rp.example.test/callback"],
            "allowed_scopes": ["openid", "profile"],
        },
    )
    assert created.status_code == 201, created.text
    created_payload = created.json()
    row = created_payload["client"]
    original_secret = created_payload["client_secret"]

    updated = client.put(
        f"/api/v1/oidc/clients/{row['id']}",
        headers=headers,
        json={
            "name": "Lifecycle client updated",
            "description": "Updated relying party",
            "redirect_uris": ["https://rp.example.test/callback-2"],
            "post_logout_redirect_uris": ["https://rp.example.test/signed-out"],
            "allowed_scopes": ["openid", "email"],
            "enabled": False,
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["client_id"] == row["client_id"]
    assert updated.json()["description"] == "Updated relying party"
    assert updated.json()["redirect_uris"] == ["https://rp.example.test/callback-2"]
    assert "client_secret_hash" not in updated.text
    assert original_secret not in updated.text

    exported = client.get(
        f"/api/v1/oidc/clients/{row['id']}/integration-export",
        headers=headers,
    )
    assert exported.status_code == 200, exported.text
    assert exported.json()["client_id"] == row["client_id"]
    assert exported.json()["redirect_uris"] == ["https://rp.example.test/callback-2"]
    assert exported.json()["organization"] == "explicit-source-selection"
    assert original_secret not in exported.text
    assert "client_secret" not in exported.json()
    assert "private" not in exported.text.lower()


def test_oidc_operational_redaction_covers_authenticated_urls_and_protocol_values():
    """Verify that oidc operational redaction covers authenticated urls and protocol values."""
    from atlaso.app.operational_logging import redact_operational_text

    original = (
        "callback=https://operator:credential@example.test/callback"
        "?code=opaque-code&client_secret=opaque-secret"
        "&id_token_hint=header.payload.signature "
        "source=https://operator@example.test/private"
    )
    redacted = redact_operational_text(original)
    assert "credential" not in redacted
    assert "opaque-code" not in redacted
    assert "opaque-secret" not in redacted
    assert "header.payload.signature" not in redacted
    assert "operator@" not in redacted


def test_retired_signing_key_cannot_be_deleted_before_overlap(client):
    """Verify that retired signing key cannot be deleted before overlap.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcSigningKey

    headers = _admin_headers(client)
    created = client.post("/api/v1/oidc/signing-keys", headers=headers)
    assert created.status_code == 201, created.text
    rotated = client.post("/api/v1/oidc/signing-keys/rotate", headers=headers)
    assert rotated.status_code == 200, rotated.text

    with SessionLocal() as db:
        retired = db.execute(
            select(OidcSigningKey).where(OidcSigningKey.status == "retired")
        ).scalar_one()
        retired_id = retired.id

    blocked = client.delete(f"/api/v1/oidc/signing-keys/{retired_id}", headers=headers)
    assert blocked.status_code == 409
    assert "overlap window" in blocked.json()["detail"]

    with SessionLocal() as db:
        retired = db.get(OidcSigningKey, retired_id)
        retired.publish_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    deleted = client.delete(f"/api/v1/oidc/signing-keys/{retired_id}", headers=headers)
    assert deleted.status_code == 204


def test_oidc_redirect_validation_rejects_wildcards_fragments_and_nonliteral_loopback():
    """Verify that oidc redirect validation rejects wildcards fragments and nonliteral loopback.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    from atlaso.app.services.oidc import OidcConfigurationError, validate_redirect_uri

    invalid = [
        ("https://vcf.example.test/*", False),
        ("https://vcf.example.test/callback#fragment", False),
        ("http://localhost:8080/callback", True),
        ("http://127.0.0.1/callback", True),
    ]
    for uri, allow_loopback in invalid:
        try:
            validate_redirect_uri(uri, allow_loopback=allow_loopback)
        except OidcConfigurationError:
            pass
        else:
            raise AssertionError(f"{uri} should be rejected")
    assert (
        validate_redirect_uri("http://127.0.0.1:49152/callback", allow_loopback=True)
        == "http://127.0.0.1:49152/callback"
    )


def test_oidc_rsa_key_is_encrypted_and_rotation_keeps_public_overlap(client, monkeypatch):
    """Verify that oidc rsa key is encrypted and rotation keeps public overlap.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, OidcSigningKey
    from atlaso.app.secrets import decrypt_secret
    from atlaso.app.services import oidc

    with SessionLocal() as db:
        appliance = db.execute(select(ApplianceSettings)).scalar_one()
        appliance.fqdn = "atlaso.example.test"
        appliance.management_https_enabled = True
        _set_oidc_service_ready(db, "atlaso.example.test")
        provider = oidc.ensure_provider_settings(db)
        provider.issuer_url = "https://atlaso.example.test/identity"
        provider.clock_skew_seconds = 120
        provider.signing_key_overlap_seconds = 300
        first, _ = oidc.generate_signing_key(db, rotate=False)
        private_pem = decrypt_secret(first.private_key_encrypted)
        assert private_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert private_pem not in first.private_key_encrypted
        second, previous = oidc.generate_signing_key(db, rotate=True)
        assert second.kid != first.kid
        assert previous is first
        assert previous.publish_until >= previous.retired_at + timedelta(seconds=420)
        provider.enabled = True
        db.commit()

    with SessionLocal() as db:
        document = oidc.discovery_document(db)
        jwks = oidc.jwks_document(db)
        assert document["issuer"] == "https://atlaso.example.test/identity"
        assert {key["kid"] for key in jwks["keys"]} == {
            row.kid for row in db.execute(select(OidcSigningKey)).scalars()
        }
        assert all("d" not in key for key in jwks["keys"])


def test_oidc_cryptographic_validation_rejects_mismatched_public_jwk(client):
    """Verify persisted OIDC public JWK values are public-only and match the private key.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from joserfc.jwk import RSAKey

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate
    from atlaso.app.secrets import decrypt_secret
    from atlaso.app.services import oidc

    with SessionLocal() as db:
        _set_oidc_service_ready(db)
        provider = oidc.ensure_provider_settings(db)
        signing_key, _ = oidc.generate_signing_key(db, rotate=False)
        unrelated = RSAKey.generate_key(
            key_size=2048,
            parameters={"alg": oidc.OIDC_SIGNING_ALGORITHM, "use": "sig"},
            private=True,
            auto_kid=True,
        )
        mismatched_public_jwk = unrelated.as_dict(private=False)
        mismatched_public_jwk["kid"] = signing_key.kid
        mismatched_public_jwk["alg"] = oidc.OIDC_SIGNING_ALGORITHM
        signing_key.public_jwk_json = json.dumps(mismatched_public_jwk)
        certificate = db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner == "oidc:https")
        ).scalar_one()

        assert oidc.provider_cryptographic_validation_errors(
            provider,
            certificate,
            signing_key,
        ) == ["The active OIDC signing key is not protocol-ready."]

        signing_key.public_jwk_json = "[]"

        assert oidc.provider_cryptographic_validation_errors(
            provider,
            certificate,
            signing_key,
        ) == ["The active OIDC signing key is not protocol-ready."]

        private_jwk = RSAKey.import_key(
            decrypt_secret(signing_key.private_key_encrypted)
        ).as_dict(private=True)
        private_jwk.update(
            {
                "alg": oidc.OIDC_SIGNING_ALGORITHM,
                "kid": signing_key.kid,
                "use": "sig",
            }
        )
        signing_key.public_jwk_json = json.dumps(private_jwk)

        assert oidc.provider_cryptographic_validation_errors(
            provider,
            certificate,
            signing_key,
        ) == ["The active OIDC signing key is not protocol-ready."]


def test_oidc_subject_is_stable_across_metadata_changes_and_new_after_recreation(client):
    """Verify that oidc subject is stable across metadata changes and new after recreation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcSubject, User
    from atlaso.app.services.identity_credentials import (
        VerifiedIdentity,
        ensure_oidc_subject,
    )

    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "admin")).scalar_one()
        identity = VerifiedIdentity("local", user.id, user.username, "Admin", "", None, "Local")
        first = ensure_oidc_subject(db, identity)
        first_uuid = first.subject_uuid
        user.external_display_name = "Renamed Administrator"
        user.external_email = "renamed@example.test"
        db.flush()
        assert ensure_oidc_subject(db, identity).subject_uuid == first_uuid
        db.delete(user)
        db.commit()
        assert db.execute(select(OidcSubject)).scalar_one_or_none() is None
        db.expunge_all()
        recreated = User(username="admin", auth_provider="local", enabled=True)
        db.add(recreated)
        db.flush()
        replacement = ensure_oidc_subject(
            db,
            VerifiedIdentity("local", recreated.id, recreated.username, "Admin", "", None, "Local"),
        )
        assert replacement.subject_uuid != first_uuid


def test_sqlite_foreign_keys_are_enabled(client):
    """Verify that sqlite foreign keys are enabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        assert db.execute(text("PRAGMA foreign_keys")).scalar_one() == 1


def test_managed_ldap_credential_service_checks_persisted_scope_before_helper(client, monkeypatch):
    """Verify that managed ldap credential service checks persisted scope before helper.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapOrganization, LdapSettings, LdapUser
    from atlaso.app.services import identity_credentials

    calls: list[tuple[str, str]] = []

    class AuthenticationAdapter:
        """Represent authentication adapter."""
        def authenticate_ldap_user(self, user_dn: str, password: str) -> AdapterResult:
            """Return authenticate ldap user.

            Args:
                user_dn: User dn supplied by the caller.
                password: Password supplied for the immediate authenticated operation.
            """
            calls.append((user_dn, password))
            return AdapterResult(
                command=["atlaso-helper", "ldap", "authenticate", user_dn],
                dry_run=False,
                returncode=0 if password == "Directory-Password!" else 1,
            )

    monkeypatch.setattr(identity_credentials, "SystemAdapter", AuthenticationAdapter)
    with SessionLocal() as db:
        settings = db.execute(select(LdapSettings)).scalar_one()
        settings.enabled = True
        organization = LdapOrganization(
            name="Research",
            slug="research",
            suffix_dn="dc=research,dc=example,dc=test",
            enabled=True,
        )
        db.add(organization)
        db.flush()
        user = LdapUser(
            organization_id=organization.id,
            uid="duplicate",
            display_name="Directory User",
            enabled=True,
        )
        db.add(user)
        db.commit()
        verified = identity_credentials.verify_credentials(
            db,
            source="managed_ldap",
            organization_id=organization.id,
            username="duplicate",
            password="Directory-Password!",
        )
        assert verified is not None
        assert verified.organization_id == organization.id
        assert calls == [
            (
                "uid=duplicate,ou=users,dc=research,dc=example,dc=test",
                "Directory-Password!",
            )
        ]
        user.enabled = False
        db.commit()
        assert (
            identity_credentials.verify_credentials(
                db,
                source="managed_ldap",
                organization_id=organization.id,
                username="duplicate",
                password="Directory-Password!",
            )
            is None
        )
        assert len(calls) == 1


def test_oidc_backup_restore_preserves_subject_client_mapping_and_encrypted_key(client):
    """Verify that oidc backup restore preserves subject client mapping and encrypted key.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        OidcClient,
        OidcGroupMapping,
        OidcSigningKey,
        OidcSubject,
        User,
    )
    from atlaso.app.services.identity_credentials import (
        VerifiedIdentity,
        ensure_oidc_subject,
    )
    from atlaso.app.services.oidc import (
        create_client,
        create_group_mapping,
        generate_signing_key,
    )
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        factory_reset_desired_state,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        subject = ensure_oidc_subject(
            db,
            VerifiedIdentity("local", admin.id, admin.username, "Admin", "", None, "Local"),
        )
        subject_uuid = subject.subject_uuid
        client_row, _secret = create_client(
            db,
            name="Backup client",
            organization_id=None,
            redirect_uris=["https://backup.example.test/callback"],
            post_logout_redirect_uris=[],
            allowed_scopes=["openid", "profile"],
            allow_loopback_redirects=False,
            access_token_lifetime_seconds=300,
            id_token_lifetime_seconds=300,
            authorization_code_lifetime_seconds=60,
            enabled=True,
        )
        key, _ = generate_signing_key(db, rotate=False)
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="admin",
            ldap_group_id=None,
            oidc_client_id=client_row.id,
            external_group_name="Backup Administrators",
        )
        encrypted_private_key = key.private_key_encrypted
        db.commit()
        archive = export_settings_archive(db, actor="admin")
        serialized = json.dumps(archive)
        assert encrypted_private_key in serialized
        assert "BEGIN PRIVATE KEY" not in serialized
        assert _secret not in serialized
        factory_reset_desired_state(db)
        assert db.execute(select(OidcClient)).scalar_one_or_none() is None
        assert db.execute(select(OidcGroupMapping)).scalar_one_or_none() is None
        restore_settings_archive(db, archive)
        assert db.execute(select(OidcSubject)).scalar_one().subject_uuid == subject_uuid
        assert db.execute(select(OidcClient)).scalar_one().client_id == client_row.client_id
        assert (
            db.execute(select(OidcSigningKey)).scalar_one().private_key_encrypted
            == encrypted_private_key
        )
        restored_mapping = db.execute(select(OidcGroupMapping)).scalar_one()
        assert restored_mapping.external_group_name == "Backup Administrators"
        assert restored_mapping.oidc_client_id == db.execute(select(OidcClient.id)).scalar_one()


def test_oidc_backup_restore_validates_the_final_effective_mapping_set(client):
    """Verify that oidc backup restore validates the final effective mapping set.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcClient, OidcGroupMapping
    from atlaso.app.services.oidc import create_group_mapping, update_group_mapping
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        factory_reset_desired_state,
        restore_settings_archive,
    )

    client_id, _secret = _configure_protocol_client()
    with SessionLocal() as db:
        client_row = db.execute(
            select(OidcClient).where(OidcClient.client_id == client_id)
        ).scalar_one()
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="admin",
            ldap_group_id=None,
            oidc_client_id=None,
            external_group_name="Default Admin",
        )
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="viewer",
            ldap_group_id=None,
            oidc_client_id=None,
            external_group_name="Default Viewer",
        )
        admin_override = create_group_mapping(
            db,
            source_type="local_role",
            local_role="admin",
            ldap_group_id=None,
            oidc_client_id=client_row.id,
            external_group_name="Temporary Admin",
        )
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="viewer",
            ldap_group_id=None,
            oidc_client_id=client_row.id,
            external_group_name="Client Viewer",
        )
        update_group_mapping(
            db,
            row=admin_override,
            oidc_client_id=client_row.id,
            external_group_name="Default Viewer",
        )
        db.commit()

        archive = export_settings_archive(db, actor="admin")
        factory_reset_desired_state(db)
        counts = restore_settings_archive(db, archive)

        assert counts["oidc_group_mappings"] == 4
        restored = db.execute(
            select(OidcGroupMapping).order_by(OidcGroupMapping.id)
        ).scalars().all()
        assert [row.external_group_name for row in restored] == [
            "Default Admin",
            "Default Viewer",
            "Default Viewer",
            "Client Viewer",
        ]


def test_openid_connect_page_exposes_authorization_code_oidc_ui(client):
    """Verify that openid connect page exposes authorization code oidc ui.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login = client.get("/login")
    csrf = login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    authentication_page = client.get("/authentication")
    assert authentication_page.status_code == 200
    assert 'href="/ui/management/openid-connect"' in authentication_page.text
    assert 'id="oidc-provider"' not in authentication_page.text

    page = client.get("/openid-connect")
    assert page.status_code == 200
    assert "OpenID Connect Provider" in page.text
    assert "<h1>OpenID Connect</h1>" in page.text
    assert 'aria-label="OpenID Connect administration"' in page.text
    assert page.text.count('class="tab-button') >= 5
    assert 'id="oidc-group-mappings-table"' in page.text
    assert 'data-fallback-id="oidc-group-mappings-fallback"' in page.text
    assert 'class="split-workspace service-settings-workspace oidc-service-workspace"' in page.text
    assert 'class="panel wide-panel oidc-administration-panel"' in page.text
    assert 'class="tab-buttons tool-tabs oidc-page-tabs"' in page.text
    assert 'class="tab-panel active" id="oidc-provider"' in page.text
    assert '<aside class="side-stack service-settings-column">' in page.text
    assert page.text.index('class="tab-panels oidc-page-panels"') < page.text.index(
        '<aside class="side-stack service-settings-column">'
    )
    assert "<h2>Issuer DNS</h2>" in page.text
    assert "the only supported issuer host" in page.text
    assert "<span>Listener interfaces</span>" in page.text
    assert 'name="hostname"' in page.text
    assert "oidc.atlaso.internal" in page.text
    assert 'data-tag-name="listen_interfaces"' in page.text
    assert "<span>HTTPS port</span>" in page.text
    assert 'name="port"' in page.text
    assert page.text.count("data-copy-value=") >= 7
    assert 'class="scope-choice-grid"' in page.text
    assert page.text.count('class="scope-choice"') == 4
    assert '<span class="scope-choice-badge">required</span>' in page.text
    assert 'data-atlaso-wizard-nav="state"' in page.text
    assert 'data-atlaso-wizard-step="state"' in page.text
    assert "<h2>Validation</h2>" in page.text
    assert "data-oidc-provider-validation" in page.text
    assert "data-oidc-provider-validation-status" in page.text
    assert "Public services nginx config" in page.text
    assert "/var/lib/atlaso/apply/public-services/atlaso-public-services.conf" in page.text
    assert "data-oidc-config-preview" in page.text
    assert "OIDC HTTPS front door." in page.text
    assert "Exact post-logout URIs (optional)" in page.text
    assert "<noscript>" in page.text
    assert "server-rendered client, signing-key, mapping, and subject tables remain readable" in page.text
    assert 'id="oidc-clients-table"' in page.text
    oidc_client_wizard = page.text.split('id="oidc-client-dialog"', 1)[1].split("</dialog>", 1)[0]
    oidc_identity = oidc_client_wizard.split('data-atlaso-wizard-step="identity"', 1)[1].split(
        "</section>", 1
    )[0]
    assert '<textarea name="description" rows="3" maxlength="1000">' in oidc_identity
    assert 'id="oidc-keys-table"' in page.text
    assert 'id="oidc-subjects-table"' in page.text
    assert page.text.count("data-atlaso-wizard") >= 2
    assert page.text.count("vcf-sddc-wizard-rail") >= 2
    assert "vcf-sddc-wizard-shell" not in page.text
    assert "Atlaso never guesses" in page.text
    assert "+ Add client here" in page.text
    assert "Register client" not in page.text
    assert 'name="enabled"' in page.text
    assert 'data-autosave-status-id="oidc-provider-autosave-status"' in page.text
    assert page.text.count('class="help-icon"') >= 10
    assert "Rotate signing key" in page.text or "Generate first signing key" in page.text
    javascript = client.get("/static/app.js").text
    assert "Client changes are unavailable because the interactive grid could not initialize." in javascript
    assert "Signing-key changes are unavailable because the interactive grid could not initialize." in javascript
    assert javascript.count('launcher.setAttribute("aria-disabled", "true")') >= 2
    assert "At least one exact redirect URI is required." in javascript
    assert "is not a valid absolute URI." in javascript


def test_authentication_ui_deletes_bound_client_before_ldap_organization(client):
    """Verify that authentication ui deletes bound client before ldap organization.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapOrganization, OidcClient
    from atlaso.app.services.oidc import create_client

    with SessionLocal() as db:
        organization = LdapOrganization(
            name="Bound organization",
            slug="bound-organization",
            suffix_dn="dc=bound-organization,dc=example,dc=test",
            enabled=True,
        )
        db.add(organization)
        db.flush()
        client_row, _secret = create_client(
            db,
            name="Bound VCF client",
            organization_id=organization.id,
            redirect_uris=["https://vcf.example.test/identity/callback"],
            post_logout_redirect_uris=[],
            allowed_scopes=["openid", "profile", "email", "groups"],
            allow_loopback_redirects=False,
            access_token_lifetime_seconds=300,
            id_token_lifetime_seconds=300,
            authorization_code_lifetime_seconds=60,
            enabled=True,
        )
        organization_id = organization.id
        client_record_id = client_row.id
        db.commit()

    login = client.get("/login")
    csrf = login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    page = client.get("/openid-connect")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert '"name": "Bound VCF client"' in page.text
    assert 'data-fallback-id="oidc-clients-fallback"' in page.text

    deleted = client.post(
        f"/authentication/oidc/clients/{client_record_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/ui/management/openid-connect#oidc-clients"
    organization_deleted = client.post(
        f"/ldap/organizations/{organization_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert organization_deleted.status_code == 303

    with SessionLocal() as db:
        assert db.get(OidcClient, client_record_id) is None
        assert db.get(LdapOrganization, organization_id) is None


def test_unbound_clients_require_validated_source_and_bound_clients_hide_selector(
    client, monkeypatch
):
    """Verify that unbound clients require validated source and bound clients hide selector.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapOrganization, LdapSettings, LdapUser
    from atlaso.app.services import identity_credentials

    class AuthenticationAdapter:
        """Represent authentication adapter."""
        def authenticate_ldap_user(self, user_dn: str, password: str) -> AdapterResult:
            """Return authenticate ldap user.

            Args:
                user_dn: User dn supplied by the caller.
                password: Password supplied for the immediate authenticated operation.
            """
            return AdapterResult(
                command=["atlaso-helper", "ldap", "authenticate", user_dn],
                dry_run=False,
                returncode=0 if password == "Directory-Password!" else 1,
            )

    monkeypatch.setattr(identity_credentials, "SystemAdapter", AuthenticationAdapter)
    with SessionLocal() as db:
        settings = db.execute(select(LdapSettings)).scalar_one()
        settings.enabled = True
        enabled = LdapOrganization(
            name="Research",
            slug="research",
            suffix_dn="dc=research,dc=example,dc=test",
            enabled=True,
        )
        disabled = LdapOrganization(
            name="Disabled directory",
            slug="disabled-directory",
            suffix_dn="dc=disabled,dc=example,dc=test",
            enabled=False,
        )
        db.add_all([enabled, disabled])
        db.flush()
        db.add_all(
            [
                LdapUser(
                    organization_id=enabled.id,
                    uid="admin",
                    display_name="Directory Admin",
                    enabled=True,
                ),
                LdapUser(
                    organization_id=disabled.id,
                    uid="admin",
                    display_name="Disabled Admin",
                    enabled=True,
                ),
            ]
        )
        enabled_id = enabled.id
        disabled_id = disabled.id
        db.commit()

    client_id, _secret = _configure_protocol_client()
    params = _authorization_parameters(client_id, "a" * 64)
    page = client.get("https://testserver/identity/authorize", params=params)
    assert page.status_code == 200
    assert '<select name="source" required>' in page.text
    assert '<option value="local">Local</option>' in page.text
    assert f'value="managed_ldap:{enabled_id}"' in page.text
    assert f'value="managed_ldap:{disabled_id}"' not in page.text
    transaction = re.search(r'name="transaction" value="([^"]+)"', page.text).group(1)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)

    invalid = client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": transaction,
            "csrf": csrf,
            "source": f"managed_ldap:{disabled_id}",
            "username": "admin",
            "password": "atlaso-admin",
        },
        follow_redirects=False,
    )
    assert invalid.status_code == 400
    assert "Select Local or an available organization." in invalid.text
    local = client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": transaction,
            "csrf": csrf,
            "source": "local",
            "username": "admin",
            "password": "atlaso-admin",
        },
        follow_redirects=False,
    )
    assert local.status_code == 303

    bound_client_id, _bound_secret = _configure_protocol_client(
        organization_id=enabled_id
    )
    bound_page = client.get(
        "https://testserver/identity/authorize",
        params=_authorization_parameters(bound_client_id, "b" * 64),
    )
    assert bound_page.status_code == 200
    assert 'name="source"' not in bound_page.text
    assert "Research" in bound_page.text
    bound_transaction = re.search(
        r'name="transaction" value="([^"]+)"', bound_page.text
    ).group(1)
    bound_csrf = re.search(r'name="csrf" value="([^"]+)"', bound_page.text).group(1)
    injected = client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": bound_transaction,
            "csrf": bound_csrf,
            "source": f"managed_ldap:{enabled_id}",
            "username": "admin",
            "password": "Directory-Password!",
        },
        follow_redirects=False,
    )
    assert injected.status_code == 400
    accepted = client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": bound_transaction,
            "csrf": bound_csrf,
            "username": "admin",
            "password": "Directory-Password!",
        },
        follow_redirects=False,
    )
    assert accepted.status_code == 303


def test_local_role_mappings_override_defaults_reject_collisions_and_filter_scopes(client):
    """Verify that local role mappings override defaults reject collisions and filter scopes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcClient

    client_id, secret = _configure_protocol_client()
    headers = _admin_headers(client)
    with SessionLocal() as db:
        client_record_id = db.execute(
            select(OidcClient.id).where(OidcClient.client_id == client_id)
        ).scalar_one()

    default_admin = client.post(
        "/api/v1/oidc/group-mappings",
        headers=headers,
        json={
            "source_type": "local_role",
            "local_role": "admin",
            "external_group_name": "Atlaso Administrators",
        },
    )
    assert default_admin.status_code == 201, default_admin.text
    default_viewer = client.post(
        "/api/v1/oidc/group-mappings",
        headers=headers,
        json={
            "source_type": "local_role",
            "local_role": "viewer",
            "external_group_name": "Atlaso Viewers",
        },
    )
    assert default_viewer.status_code == 201, default_viewer.text
    collision = client.post(
        "/api/v1/oidc/group-mappings",
        headers=headers,
        json={
            "source_type": "local_role",
            "local_role": "admin",
            "oidc_client_id": client_record_id,
            "external_group_name": "ATLASO VIEWERS",
        },
    )
    assert collision.status_code == 422
    assert "unique case-insensitively" in collision.text
    override = client.post(
        "/api/v1/oidc/group-mappings",
        headers=headers,
        json={
            "source_type": "local_role",
            "local_role": "admin",
            "oidc_client_id": client_record_id,
            "external_group_name": "VCF Administrators",
        },
    )
    assert override.status_code == 201, override.text
    listed = client.get("/api/v1/oidc/group-mappings", headers=headers)
    assert listed.status_code == 200
    assert {row["external_group_name"] for row in listed.json()} == {
        "Atlaso Administrators",
        "Atlaso Viewers",
        "VCF Administrators",
    }

    verifier = "c" * 64
    transaction, csrf, _cookie = _start_login(
        client,
        _authorization_parameters(
            client_id,
            verifier,
            scope="openid profile email groups",
        ),
    )
    login = _finish_local_login(client, transaction, csrf)
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]
    all_tokens = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=code,
        verifier=verifier,
    ).json()
    all_claims = _jwt_claims(all_tokens["id_token"])
    assert all_claims["preferred_username"] == "admin"
    assert all_claims["name"] == "admin"
    assert all_claims["organization"] == "Local"
    assert all_claims["email"] == ""
    assert all_claims["email_verified"] is False
    assert all_claims["groups"] == ["VCF Administrators"]
    assert "Atlaso Administrators" not in all_tokens["id_token"]
    access_claims = _jwt_claims(all_tokens["access_token"])
    assert "organization_id" not in access_claims
    assert "source" not in access_claims

    openid_verifier = "d" * 64
    openid_transaction, openid_csrf, _cookie = _start_login(
        client,
        _authorization_parameters(client_id, openid_verifier, scope="openid"),
    )
    openid_login = _finish_local_login(client, openid_transaction, openid_csrf)
    openid_code = parse_qs(urlsplit(openid_login.headers["location"]).query)["code"][0]
    openid_tokens = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=openid_code,
        verifier=openid_verifier,
    ).json()
    openid_claims = _jwt_claims(openid_tokens["id_token"])
    for claim_name in (
        "preferred_username",
        "name",
        "organization",
        "email",
        "email_verified",
        "groups",
    ):
        assert claim_name not in openid_claims
    openid_userinfo = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {openid_tokens['access_token']}"},
    )
    assert openid_userinfo.status_code == 200
    assert openid_userinfo.json() == {"sub": openid_claims["sub"]}


def test_group_mapping_delete_rejects_a_revealed_effective_name_collision(client):
    """Verify that group mapping delete rejects a revealed effective name collision.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcClient, OidcGroupMapping
    from atlaso.app.services.oidc import create_group_mapping, update_group_mapping

    client_id, _secret = _configure_protocol_client()
    headers = _admin_headers(client)
    with SessionLocal() as db:
        client_row = db.execute(
            select(OidcClient).where(OidcClient.client_id == client_id)
        ).scalar_one()
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="admin",
            ldap_group_id=None,
            oidc_client_id=None,
            external_group_name="Default Admin",
        )
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="viewer",
            ldap_group_id=None,
            oidc_client_id=None,
            external_group_name="Default Viewer",
        )
        admin_override = create_group_mapping(
            db,
            source_type="local_role",
            local_role="admin",
            ldap_group_id=None,
            oidc_client_id=client_row.id,
            external_group_name="Temporary Admin",
        )
        viewer_override = create_group_mapping(
            db,
            source_type="local_role",
            local_role="viewer",
            ldap_group_id=None,
            oidc_client_id=client_row.id,
            external_group_name="Client Viewer",
        )
        update_group_mapping(
            db,
            row=admin_override,
            oidc_client_id=client_row.id,
            external_group_name="Default Viewer",
        )
        viewer_override_id = viewer_override.id
        db.commit()

    api_delete = client.delete(
        f"/api/v1/oidc/group-mappings/{viewer_override_id}",
        headers=headers,
    )
    assert api_delete.status_code == 422
    assert "not valid in its effective context" in api_delete.json()["detail"]
    with SessionLocal() as db:
        assert db.get(OidcGroupMapping, viewer_override_id) is not None

    login_page = client.get("/login")
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    authentication_page = client.get("/authentication")
    csrf = authentication_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    ui_delete = client.post(
        f"/authentication/oidc/group-mappings/{viewer_override_id}/delete",
        data={"csrf": csrf},
        headers={"X-Atlaso-Grid": "1"},
        follow_redirects=False,
    )
    assert ui_delete.status_code == 422
    assert "duplicate effective external group names" in ui_delete.json()["detail"]
    with SessionLocal() as db:
        assert db.get(OidcGroupMapping, viewer_override_id) is not None


def test_ldap_nested_cycle_mappings_emit_only_external_names_and_revalidate_source(
    client, monkeypatch
):
    """Verify that ldap nested cycle mappings emit only external names and revalidate source.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        LdapGroup,
        LdapGroupMembership,
        LdapOrganization,
        LdapSettings,
        LdapUser,
    )
    from atlaso.app.services import identity_credentials
    from atlaso.app.services.oidc import create_group_mapping

    class AuthenticationAdapter:
        """Represent authentication adapter."""
        def authenticate_ldap_user(self, user_dn: str, password: str) -> AdapterResult:
            """Return authenticate ldap user.

            Args:
                user_dn: User dn supplied by the caller.
                password: Password supplied for the immediate authenticated operation.
            """
            return AdapterResult(
                command=["atlaso-helper", "ldap", "authenticate", user_dn],
                dry_run=False,
                returncode=0 if password == "Directory-Password!" else 1,
            )

    monkeypatch.setattr(identity_credentials, "SystemAdapter", AuthenticationAdapter)
    with SessionLocal() as db:
        settings = db.execute(select(LdapSettings)).scalar_one()
        settings.enabled = True
        organization = LdapOrganization(
            name="Engineering",
            slug="engineering",
            suffix_dn="dc=engineering,dc=example,dc=test",
            enabled=True,
        )
        db.add(organization)
        db.flush()
        user = LdapUser(
            organization_id=organization.id,
            uid="engineer",
            display_name="Engineering User",
            email="engineer@example.test",
            enabled=True,
        )
        direct = LdapGroup(
            organization_id=organization.id,
            name="cn=raw-direct-secret",
            enabled=True,
        )
        parent = LdapGroup(
            organization_id=organization.id,
            name="cn=raw-parent-secret",
            enabled=True,
        )
        unmapped = LdapGroup(
            organization_id=organization.id,
            name="cn=raw-unmapped-secret",
            enabled=True,
        )
        disabled = LdapGroup(
            organization_id=organization.id,
            name="cn=raw-disabled-secret",
            enabled=False,
        )
        db.add_all([user, direct, parent, unmapped, disabled])
        db.flush()
        db.add_all(
            [
                LdapGroupMembership(group_id=direct.id, member_user_id=user.id),
                LdapGroupMembership(group_id=parent.id, member_group_id=direct.id),
                LdapGroupMembership(group_id=direct.id, member_group_id=parent.id),
                LdapGroupMembership(group_id=unmapped.id, member_user_id=user.id),
                LdapGroupMembership(group_id=disabled.id, member_user_id=user.id),
            ]
        )
        create_group_mapping(
            db,
            source_type="ldap_group",
            local_role="",
            ldap_group_id=direct.id,
            oidc_client_id=None,
            external_group_name="Engineering Direct",
        )
        create_group_mapping(
            db,
            source_type="ldap_group",
            local_role="",
            ldap_group_id=parent.id,
            oidc_client_id=None,
            external_group_name="Engineering Nested",
        )
        create_group_mapping(
            db,
            source_type="ldap_group",
            local_role="",
            ldap_group_id=disabled.id,
            oidc_client_id=None,
            external_group_name="Must Not Emit",
        )
        organization_id = organization.id
        db.commit()

    client_id, secret = _configure_protocol_client(organization_id=organization_id)
    verifier = "e" * 64
    transaction, csrf, _cookie = _start_login(
        client,
        _authorization_parameters(
            client_id,
            verifier,
            login_hint="engineer",
            scope="openid profile email groups",
        ),
    )
    login = client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": transaction,
            "csrf": csrf,
            "username": "engineer",
            "password": "Directory-Password!",
        },
        follow_redirects=False,
    )
    assert login.status_code == 303
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]
    token_response = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=code,
        verifier=verifier,
    )
    assert token_response.status_code == 200, token_response.text
    tokens = token_response.json()
    claims = _jwt_claims(tokens["id_token"])
    assert claims["groups"] == ["Engineering Direct", "Engineering Nested"]
    assert claims["organization"] == "Engineering"
    assert claims["email"] == "engineer@example.test"
    for private_value in (
        "raw-direct-secret",
        "raw-parent-secret",
        "raw-unmapped-secret",
        "raw-disabled-secret",
        "dc=engineering",
    ):
        assert private_value not in tokens["id_token"]
        assert private_value not in tokens["access_token"]
    userinfo = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert userinfo.status_code == 200
    assert userinfo.json()["groups"] == ["Engineering Direct", "Engineering Nested"]

    with SessionLocal() as db:
        settings = db.execute(select(LdapSettings)).scalar_one()
        settings.enabled = False
        db.commit()
    disabled_source = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert disabled_source.status_code == 401


def test_authorization_code_local_flow_rotates_session_and_rejects_replay(client):
    """Verify that authorization code local flow rotates session and rejects replay.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        OidcAuthorizationCode,
        OidcAuthorizationTransaction,
        OidcSigningKey,
    )

    client_id, secret = _configure_protocol_client()
    verifier = "v" * 64
    transaction, csrf, first_cookie = _start_login(
        client, _authorization_parameters(client_id, verifier)
    )
    login = _finish_local_login(client, transaction, csrf)
    assert login.status_code == 303, login.text
    assert login.headers["location"].startswith(
        "https://rp.example.test/callback?case=A%2Fb&"
    )
    assert login.headers["set-cookie"] != first_cookie
    callback = parse_qs(urlsplit(login.headers["location"]).query)
    assert callback["state"] == ["state-original"]
    code = callback["code"][0]

    with SessionLocal() as db:
        persisted = db.execute(select(OidcAuthorizationCode)).scalar_one()
        assert code not in persisted.code_hash
        assert persisted.nonce == "nonce-original"
        assert persisted.state == "state-original"
        assert persisted.redirect_uri == "https://rp.example.test/callback?case=A%2Fb"
        assert persisted.browser_session_id
        assert db.execute(select(OidcAuthorizationTransaction)).scalar_one_or_none() is None

    token_response = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=code,
        verifier=verifier,
    )
    assert token_response.status_code == 200, token_response.text
    tokens = token_response.json()
    assert tokens["expires_in"] == 300
    with SessionLocal() as db:
        key = db.execute(select(OidcSigningKey).where(OidcSigningKey.status == "active")).scalar_one()
        public = RSAKey.import_key(json.loads(key.public_jwk_json))
        id_token = jwt.decode(tokens["id_token"], public, algorithms=["RS256"])
        access_token = jwt.decode(tokens["access_token"], public, algorithms=["RS256"])
    assert id_token.header == {"alg": "RS256", "kid": key.kid, "typ": "JWT"}
    assert access_token.header == {"alg": "RS256", "kid": key.kid, "typ": "at+jwt"}
    assert id_token.claims["aud"] == client_id
    assert id_token.claims["nonce"] == "nonce-original"
    assert id_token.claims["exp"] - id_token.claims["iat"] == 300
    assert access_token.claims["exp"] - access_token.claims["iat"] == 300

    userinfo = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert userinfo.status_code == 200
    assert userinfo.json() == {
        "sub": id_token.claims["sub"],
        "preferred_username": "admin",
        "name": "admin",
        "organization": "Local",
    }
    replay = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=code,
        verifier=verifier,
    )
    assert replay.status_code == 400
    assert replay.json() == {"error": "invalid_grant"}


def test_client_policy_edit_invalidates_pending_authorization(client):
    """Verify that client policy edit invalidates pending authorization.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcAuthorizationTransaction, OidcClient

    client_id, _secret = _configure_protocol_client()
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, "e" * 64)
    )
    with SessionLocal() as db:
        record_id = db.execute(
            select(OidcClient.id).where(OidcClient.client_id == client_id)
        ).scalar_one()

    updated = client.put(
        f"/api/v1/oidc/clients/{record_id}",
        headers=_admin_headers(client),
        json={
            "name": "Edited while authorization is pending",
            "redirect_uris": ["https://rp.example.test/new-callback"],
            "allowed_scopes": ["openid"],
        },
    )
    assert updated.status_code == 200, updated.text

    login = _finish_local_login(client, transaction, csrf)
    assert login.status_code == 400
    assert login.json() == {"error": "invalid_request"}
    assert "location" not in login.headers
    with SessionLocal() as db:
        assert db.execute(select(OidcAuthorizationTransaction)).scalar_one_or_none() is None


def test_authorization_rejects_substitution_downgrade_and_inexact_redirect(client):
    """Verify that authorization rejects substitution downgrade and inexact redirect.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    client_id, _secret = _configure_protocol_client()
    verifier = "p" * 64
    params = _authorization_parameters(client_id, verifier)
    for changes, expected in [
        ({"state": ""}, "invalid_request"),
        ({"nonce": ""}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"response_mode": "fragment"}, "unsupported_response_mode"),
        ({"prompt": "consent"}, "invalid_request"),
        ({"max_age": "-1"}, "invalid_request"),
    ]:
        response = client.get(
            "https://testserver/identity/authorize",
            params=params | changes,
            follow_redirects=False,
        )
        assert response.status_code == 303
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["error"] == [expected]

    inexact = client.get(
        "https://testserver/identity/authorize",
        params=params | {"redirect_uri": "https://rp.example.test/callback?case=A%2fb"},
        follow_redirects=False,
    )
    assert inexact.status_code == 400
    assert inexact.json() == {"error": "invalid_request"}


def test_token_endpoint_requires_basic_exact_redirect_and_pkce(client):
    """Verify that token endpoint requires basic exact redirect and pkce.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    client_id, secret = _configure_protocol_client()
    verifier = "k" * 64
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, verifier)
    )
    login = _finish_local_login(client, transaction, csrf)
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]

    body_secret = client.post(
        "https://testserver/identity/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": secret,
            "code": code,
            "redirect_uri": "https://rp.example.test/callback?case=A%2Fb",
            "code_verifier": verifier,
        },
    )
    assert body_secret.status_code == 401
    wrong_redirect = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=code,
        verifier=verifier,
        redirect_uri="https://rp.example.test/callback?case=A%2Fb/",
    )
    assert wrong_redirect.status_code == 400
    wrong_pkce = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=code,
        verifier="x" * 64,
    )
    assert wrong_pkce.status_code == 400
    valid = _exchange_code(
        client,
        client_id=client_id,
        secret=secret,
        code=code,
        verifier=verifier,
    )
    assert valid.status_code == 200


def test_prompt_none_max_age_and_login_hint_is_prefill_only(client):
    """Verify that prompt none max age and login hint is prefill only.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.oidc import OIDC_SESSION_COOKIE, _session_serializer

    client_id, _secret = _configure_protocol_client()
    verifier = "m" * 64
    transaction, csrf, _cookie = _start_login(
        client,
        _authorization_parameters(
            client_id, verifier, login_hint='admin"><script>alert(1)</script>'
        ),
    )
    page = client.get(
        "https://testserver/identity/authorize",
        params=_authorization_parameters(client_id, verifier, login_hint="<admin>"),
    )
    assert "&lt;admin&gt;" in page.text
    assert "<admin>" not in page.text
    login = _finish_local_login(client, transaction, csrf)
    assert login.status_code == 303

    silent = client.get(
        "https://testserver/identity/authorize",
        params=_authorization_parameters(
            client_id,
            "n" * 64,
            prompt="none",
            max_age="300",
            state="silent-state",
            nonce="silent-nonce",
        ),
        follow_redirects=False,
    )
    assert silent.status_code == 303
    silent_query = parse_qs(urlsplit(silent.headers["location"]).query)
    assert silent_query["state"] == ["silent-state"]
    assert "code" in silent_query

    session = _session_serializer().loads(client.cookies[OIDC_SESSION_COOKIE])
    session["auth_time"] = 1
    client.cookies.set(
        OIDC_SESSION_COOKIE,
        _session_serializer().dumps(session),
        domain="testserver.local",
        path="/identity",
    )
    expired = client.get(
        "https://testserver/identity/authorize",
        params=_authorization_parameters(
            client_id, "q" * 64, prompt="none", max_age="10"
        ),
        follow_redirects=False,
    )
    assert expired.status_code == 303
    assert parse_qs(urlsplit(expired.headers["location"]).query)["error"] == [
        "login_required"
    ]


def test_userinfo_revalidates_client_subject_and_local_identity_state(client):
    """Verify that userinfo revalidates client subject and local identity state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcClient, User

    client_id, secret = _configure_protocol_client()
    verifier = "r" * 64
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, verifier)
    )
    login = _finish_local_login(client, transaction, csrf)
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]
    tokens = _exchange_code(
        client, client_id=client_id, secret=secret, code=code, verifier=verifier
    ).json()

    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "admin")).scalar_one()
        user.enabled = False
        db.commit()
    disabled_user = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert disabled_user.status_code == 401

    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "admin")).scalar_one()
        user.enabled = True
        oidc_client = db.execute(
            select(OidcClient).where(OidcClient.client_id == client_id)
        ).scalar_one()
        oidc_client.enabled = False
        db.commit()
    disabled_client = client.post(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert disabled_client.status_code == 401


def test_userinfo_rejects_algorithm_and_kid_confusion(client):
    """Verify that userinfo rejects algorithm and kid confusion.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    client_id, secret = _configure_protocol_client()
    verifier = "s" * 64
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, verifier)
    )
    login = _finish_local_login(client, transaction, csrf)
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]
    token = _exchange_code(
        client, client_id=client_id, secret=secret, code=code, verifier=verifier
    ).json()["access_token"]
    segments = token.split(".")
    for header in [
        {"alg": "HS256", "kid": "wrong", "typ": "at+jwt"},
        {"alg": "RS256", "kid": "wrong", "typ": "at+jwt"},
        {"alg": "RS256", "typ": "at+jwt"},
    ]:
        segments[0] = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        response = client.get(
            "https://testserver/identity/userinfo",
            headers={"Authorization": f"Bearer {'.'.join(segments)}"},
        )
        assert response.status_code == 401


def test_userinfo_rejects_forged_signature(client):
    """Return an authentication error instead of leaking a JOSE decode failure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    client_id, secret = _configure_protocol_client()
    verifier = "u" * 64
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, verifier)
    )
    login = _finish_local_login(client, transaction, csrf)
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]
    token = _exchange_code(
        client, client_id=client_id, secret=secret, code=code, verifier=verifier
    ).json()["access_token"]
    segments = token.split(".")
    segments[2] = ("A" if segments[2][0] != "A" else "B") + segments[2][1:]

    response = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {'.'.join(segments)}"},
    )

    assert response.status_code == 401


def test_logout_requires_valid_hint_and_exact_registered_redirect(client):
    """Verify that logout requires valid hint and exact registered redirect.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.oidc import OIDC_SESSION_COOKIE

    operator_login = client.get("/login")
    operator_csrf = operator_login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "atlaso-admin",
            "csrf": operator_csrf,
        },
        follow_redirects=False,
    )
    assert signed_in.status_code == 303

    client_id, secret = _configure_protocol_client()
    verifier = "t" * 64
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, verifier)
    )
    login = _finish_local_login(client, transaction, csrf)
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]
    tokens = _exchange_code(
        client, client_id=client_id, secret=secret, code=code, verifier=verifier
    ).json()
    invalid = client.get(
        "https://testserver/identity/logout",
        params={
            "id_token_hint": tokens["id_token"],
            "post_logout_redirect_uri": "https://rp.example.test/logout/",
            "state": "logout-state",
        },
        follow_redirects=False,
    )
    assert invalid.status_code == 400
    assert OIDC_SESSION_COOKIE not in client.cookies
    assert client.get("/dashboard").status_code == 200

    valid = client.get(
        "https://testserver/identity/logout",
        params={
            "id_token_hint": tokens["id_token"],
            "post_logout_redirect_uri": "https://rp.example.test/logout",
            "state": "logout-state",
        },
        follow_redirects=False,
    )
    assert valid.status_code == 303
    assert valid.headers["location"] == "https://rp.example.test/logout?state=logout-state"
    assert client.get("/dashboard").status_code == 200


def test_fixed_organization_managed_ldap_flow_never_creates_operator_session(client, monkeypatch):
    """Verify that fixed organization managed ldap flow never creates operator session.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapOrganization, LdapSettings, LdapUser
    from atlaso.app.services import identity_credentials

    class AuthenticationAdapter:
        """Represent authentication adapter."""
        def authenticate_ldap_user(self, user_dn: str, password: str) -> AdapterResult:
            """Return authenticate ldap user.

            Args:
                user_dn: User dn supplied by the caller.
                password: Password supplied for the immediate authenticated operation.
            """
            return AdapterResult(
                command=["atlaso-helper", "ldap", "authenticate", user_dn],
                dry_run=False,
                returncode=0 if password == "Directory-Password!" else 1,
            )

    monkeypatch.setattr(identity_credentials, "SystemAdapter", AuthenticationAdapter)
    with SessionLocal() as db:
        settings = db.execute(select(LdapSettings)).scalar_one()
        settings.enabled = True
        organization = LdapOrganization(
            name="Research",
            slug="research",
            suffix_dn="dc=research,dc=example,dc=test",
            enabled=True,
        )
        db.add(organization)
        db.flush()
        db.add(
            LdapUser(
                organization_id=organization.id,
                uid="scientist",
                display_name="Scientist",
                enabled=True,
            )
        )
        organization_id = organization.id
        db.commit()
    client_id, secret = _configure_protocol_client(organization_id=organization_id)
    verifier = "u" * 64
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, verifier, login_hint="scientist")
    )
    login = client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": transaction,
            "csrf": csrf,
            "username": "scientist",
            "password": "Directory-Password!",
        },
        follow_redirects=False,
    )
    assert login.status_code == 303
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]
    token_response = _exchange_code(
        client, client_id=client_id, secret=secret, code=code, verifier=verifier
    )
    assert token_response.status_code == 200
    access_token = token_response.json()["access_token"]
    userinfo = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert userinfo.status_code == 200
    with SessionLocal() as db:
        organization = db.get(LdapOrganization, organization_id)
        organization.enabled = False
        db.commit()
    disabled_organization = client.get(
        "https://testserver/identity/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert disabled_organization.status_code == 401
    dashboard = client.get("/ui/management/dashboard", follow_redirects=False)
    assert dashboard.status_code == 303
    assert dashboard.headers["location"].startswith("/ui/management/login")


def test_concurrent_code_redemption_has_at_most_one_success(client):
    """Verify that concurrent code redemption has at most one success.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    client_id, secret = _configure_protocol_client()
    verifier = "w" * 64
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, verifier)
    )
    login = _finish_local_login(client, transaction, csrf)
    code = parse_qs(urlsplit(login.headers["location"]).query)["code"][0]

    def redeem() -> int:
        """Return redeem."""
        return _exchange_code(
            client, client_id=client_id, secret=secret, code=code, verifier=verifier
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _index: redeem(), range(2)))
    assert sorted(statuses) == [200, 400]


def test_oidc_login_throttle_is_bounded_and_never_persists_password(client):
    """Verify that oidc login throttle is bounded and never persists password.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.oidc import _OIDC_LOGIN_BUCKETS, OIDC_LOGIN_BUCKET_LIMIT

    client_id, _secret = _configure_protocol_client()
    transaction, csrf, _cookie = _start_login(
        client, _authorization_parameters(client_id, "y" * 64)
    )
    password = "Never-Persist-This-Password!"
    statuses = []
    for _attempt in range(7):
        response = client.post(
            "https://testserver/identity/authorize",
            data={
                "transaction": transaction,
                "csrf": csrf,
                "source": "local",
                "username": "admin",
                "password": password,
            },
            follow_redirects=False,
        )
        statuses.append(response.status_code)
        assert password not in response.text
    assert statuses[-1] == 429
    assert len(_OIDC_LOGIN_BUCKETS) <= OIDC_LOGIN_BUCKET_LIMIT
    with SessionLocal() as db:
        for table in (
            "oidc_authorization_transactions",
            "oidc_authorization_codes",
            "audit_events",
            "jobs",
        ):
            values = db.execute(text(f"SELECT * FROM {table}")).all()
            assert password not in repr(values)


def test_oidc_login_throttle_survives_browser_session_renewal(client):
    """Verify that oidc login throttle survives browser session renewal.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.oidc import OIDC_SESSION_COOKIE

    client_id, _secret = _configure_protocol_client()
    params = _authorization_parameters(client_id, "q" * 64)
    transaction, csrf, _cookie = _start_login(client, params)
    for _attempt in range(5):
        response = client.post(
            "https://testserver/identity/authorize",
            data={
                "transaction": transaction,
                "csrf": csrf,
                "source": "local",
                "username": "renewal-test-user",
                "password": "Invalid-Password!",
            },
            follow_redirects=False,
        )
        assert response.status_code == 401

    client.cookies.delete(OIDC_SESSION_COOKIE)
    renewed_transaction, renewed_csrf, renewed_cookie = _start_login(client, params)
    assert renewed_cookie != _cookie
    limited = client.post(
        "https://testserver/identity/authorize",
        data={
            "transaction": renewed_transaction,
            "csrf": renewed_csrf,
            "source": "local",
            "username": "renewal-test-user",
            "password": "Invalid-Password!",
        },
        follow_redirects=False,
    )
    assert limited.status_code == 429


def test_begin_authorization_purges_expired_transactions_and_codes(client):
    """Verify that begin authorization purges expired transactions and codes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        OidcAuthorizationCode,
        OidcAuthorizationTransaction,
        utcnow,
    )

    client_id, _secret = _configure_protocol_client()
    params = _authorization_parameters(client_id, "r" * 64)
    expired_transaction, _csrf, _cookie = _start_login(client, params)
    with SessionLocal() as db:
        row = db.execute(
            select(OidcAuthorizationTransaction).where(
                OidcAuthorizationTransaction.transaction_id == expired_transaction
            )
        ).scalar_one()
        row.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

    live_transaction, live_csrf, _cookie = _start_login(client, params)
    with SessionLocal() as db:
        transaction_ids = set(
            db.execute(select(OidcAuthorizationTransaction.transaction_id)).scalars()
        )
        assert transaction_ids == {live_transaction}

    login = _finish_local_login(client, live_transaction, live_csrf)
    assert login.status_code == 303
    with SessionLocal() as db:
        code = db.execute(select(OidcAuthorizationCode)).scalar_one()
        code.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

    newest_transaction, _csrf, _cookie = _start_login(client, params)
    with SessionLocal() as db:
        assert db.execute(select(OidcAuthorizationCode)).scalar_one_or_none() is None
        assert (
            db.execute(select(OidcAuthorizationTransaction.transaction_id)).scalar_one()
            == newest_transaction
        )
