from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from atlaso.app.models import CaSettings
from atlaso.app.services import vcf_trust


def root_ca() -> tuple[CaSettings, vcf_trust.RootCaInfo]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Atlaso Test Root")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    settings = CaSettings(enabled=True, root_certificate_pem=pem)
    return settings, vcf_trust.root_ca_info(settings)


def test_root_ca_info_validates_and_fingerprints_public_root():
    _settings, info = root_ca()

    assert info.subject == "CN=Atlaso Test Root"
    assert len(info.fingerprint.split(":")) == 32
    assert "PRIVATE KEY" not in info.pem


def test_root_ca_info_rejects_disabled_ca():
    settings, _info = root_ca()
    settings.enabled = False

    with pytest.raises(vcf_trust.VcfTrustError, match="must be enabled"):
        vcf_trust.root_ca_info(settings)


def test_execute_vcf_trust_is_idempotent_without_restart(monkeypatch):
    _settings, ca = root_ca()

    class FakeApi:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def appliance_info(self):
            return {"role": "VcfInstaller", "version": "9.0.1.0"}

        def trusted_certificates(self):
            return [{"certificate": ca.pem}]

    monkeypatch.setattr(vcf_trust, "VcfApiClient", FakeApi)

    result = vcf_trust.execute_vcf_trust(
        address="vcf.example.test",
        port=443,
        expected_tls_fingerprint="AA:BB",
        credentials=vcf_trust.VcfTrustCredentials("admin", "api-secret"),
        ca=ca,
    )

    assert result["outcome"] == "no-op"


def test_execute_vcf_trust_imports_and_verifies_sddc_manager_without_ssh(monkeypatch):
    _settings, ca = root_ca()
    certificates: list[dict[str, str]] = []

    class FakeApi:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def appliance_info(self):
            return {"role": "SddcManager", "version": "9.0.1.0"}

        def trusted_certificates(self):
            return certificates

        def add_trusted_certificate(self, pem):
            certificates.append({"certificate": pem})

    monkeypatch.setattr(vcf_trust, "VcfApiClient", FakeApi)

    result = vcf_trust.execute_vcf_trust(
        address="vcf.example.test",
        port=443,
        expected_tls_fingerprint="AA:BB",
        credentials=vcf_trust.VcfTrustCredentials("admin", "api-secret"),
        ca=ca,
    )

    assert result == {
        "role": "SddcManager",
        "version": "9.0.1.0",
        "outcome": "installed",
        "restart": "not-required",
        "verified": True,
    }


def test_execute_vcf_trust_installer_import_does_not_restart(monkeypatch):
    _settings, ca = root_ca()
    certificates: list[dict[str, str]] = []

    class FakeApi:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def appliance_info(self):
            return {"role": "VcfInstaller", "version": "9.1.0.0"}

        def trusted_certificates(self):
            return certificates

        def add_trusted_certificate(self, pem):
            certificates.append({"certificate": pem})

    monkeypatch.setattr(vcf_trust, "VcfApiClient", FakeApi)

    result = vcf_trust.execute_vcf_trust(
        address="installer.example.test",
        port=443,
        expected_tls_fingerprint="AA:BB",
        credentials=vcf_trust.VcfTrustCredentials("admin", "secret"),
        ca=ca,
    )

    assert result["restart"] == "not-required"


def test_sanitized_result_contains_no_credentials():
    _settings, ca = root_ca()
    result = vcf_trust.sanitized_result(address="10.0.0.5", port=443, ca=ca, state="queued")

    assert "password" not in result.lower()
    assert "private" not in result.lower()
    assert ca.fingerprint in result


def test_vcf_api_client_uses_vcf9_token_info_and_trust_endpoints():
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/v1/tokens":
            return httpx.Response(201, json={"accessToken": "temporary-token"})
        assert request.headers["Authorization"] == "Bearer temporary-token"
        if request.url.path == "/v1/system/appliance-info":
            return httpx.Response(200, json={"role": "SddcManager", "version": "9.1.0.0"})
        if request.method == "GET":
            return httpx.Response(200, json={"elements": [], "pageMetadata": {"totalPages": 1}})
        return httpx.Response(200, json={"elements": []})

    api = vcf_trust.VcfApiClient("vcf.example.test", "admin", "secret")
    api.client.close()
    api.client = httpx.Client(base_url="https://vcf.example.test", transport=httpx.MockTransport(handler))
    with api:
        assert api.appliance_info()["role"] == "SddcManager"
        assert api.trusted_certificates() == []
        api.add_trusted_certificate("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")

    assert seen == [
        ("POST", "/v1/tokens"),
        ("GET", "/v1/system/appliance-info"),
        ("GET", "/v1/sddc-manager/trusted-certificates"),
        ("POST", "/v1/sddc-manager/trusted-certificates"),
    ]


def test_vcf_api_client_brackets_ipv6_literal():
    api = vcf_trust.VcfApiClient("2001:db8::10", "admin", "secret")
    try:
        assert api.base_url == "https://[2001:db8::10]"
    finally:
        api.client.close()


def test_vcf_api_client_rejects_changed_tls_fingerprint(monkeypatch):
    monkeypatch.setattr(vcf_trust, "tls_sha256_fingerprint", lambda _address, _port: "AA:BB")

    with pytest.raises(vcf_trust.VcfTrustError, match="TLS certificate changed"):
        vcf_trust.VcfApiClient("vcf.example.test", "admin", "secret", expected_fingerprint="CC:DD")
