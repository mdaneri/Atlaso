"""Exercise the read-only vCenter client-certificate discovery boundary."""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlaso.app.services import vsphere_enrollment as enrollment


def _client_certificate() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcsa.example.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


class _FakeVcenter:
    def __init__(
        self, certificate: str, *, endpoint: str = "kms.atlaso.example.test"
    ) -> None:
        """Initialize public identity and cluster responses for the fake vCenter.

        Args:
            certificate: Public certificate returned by the fake vCenter.
            endpoint: KMIP hostname registered in the fake cluster.
        """
        self.certificate = certificate
        self.endpoint = endpoint
        self.headers: dict[str, str] = {}
        self.calls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        """Close the fake session without suppressing exceptions.

        Args:
            *_args: Context-manager exception details ignored by the fake session.
        """
        pass

    def get(self, path: str) -> httpx.Response:
        """Return the fake managed-object service metadata.

        Args:
            path: Request or snapshot path being exercised.
        """
        self.calls.append(path)
        return httpx.Response(
            200,
            json={
                "sessionManager": {"type": "SessionManager", "value": "SessionManager"},
                "cryptoManager": {
                    "type": "CryptoManagerKmip",
                    "value": "CryptoManager",
                },
            },
        )

    def post(self, path: str, *, json=None) -> httpx.Response:
        """Emulate login, cluster discovery, certificate retrieval, and logout.

        Args:
            path: Request or snapshot path being exercised.
            json: Request payload inspected by the fake vCenter.
        """
        self.calls.append(path)
        if path.endswith("/Login"):
            assert json == {"userName": "admin", "password": "test-secret"}
            return httpx.Response(
                200, json={}, headers={"vmware-api-session-id": "opaque-session"}
            )
        if path.endswith("/ListKmsClusters"):
            assert self.headers["vmware-api-session-id"] == "opaque-session"
            return httpx.Response(
                200,
                json=[
                    {
                        "clusterId": {"id": "Atlaso-KMIP"},
                        "servers": [{"address": self.endpoint, "port": 5696}],
                    }
                ],
            )
        if path.endswith("/RetrieveClientCert"):
            assert json == {
                "cluster": {"_typeName": "KeyProviderId", "id": "Atlaso-KMIP"}
            }
            return httpx.Response(200, json=self.certificate)
        if path.endswith("/Logout"):
            return httpx.Response(204)
        raise AssertionError(path)


def test_discovery_reads_only_registered_atlaso_cluster_and_logs_out(
    monkeypatch,
) -> None:
    """Verify discovery checks the registered Atlaso endpoint and logs out.

    Args:
        monkeypatch: Fixture replacing vCenter network calls.
    """
    pem = _client_certificate()
    fake = _FakeVcenter(pem)
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"test-https-leaf"
    )
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    def client_factory(**kwargs):
        """Check the saved port reaches the pinned HTTP client.

        Args:
            **kwargs: HTTP client configuration.
        """
        assert kwargs["base_url"] == "https://vcsa.example.test:8443"
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return fake

    monkeypatch.setattr(enrollment.httpx, "Client", client_factory)

    result = enrollment.discover_vcenter_client(
        host="vcsa.example.test",
        port=8443,
        cluster_id="Atlaso-KMIP",
        username="admin",
        password="test-secret",
        confirmed_https_fingerprint=enrollment.certificate_fingerprint(
            b"test-https-leaf"
        ),
        atlaso_host="kms.atlaso.example.test",
        atlaso_port=5696,
    )

    assert result.certificate_pem == pem
    assert (
        result.fingerprint_sha256
        == x509.load_pem_x509_certificate(pem.encode())
        .fingerprint(hashes.SHA256())
        .hex()
    )
    assert any(path.endswith("/Logout") for path in fake.calls)


def test_discovery_rejects_wrong_atlaso_endpoint_before_client_certificate(
    monkeypatch,
) -> None:
    """Reject a cluster targeting another endpoint before reading its certificate.

    Args:
        monkeypatch: Fixture replacing vCenter network calls.
    """
    fake = _FakeVcenter(_client_certificate(), endpoint="other.example.test")
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"test-https-leaf"
    )
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    monkeypatch.setattr(enrollment.httpx, "Client", lambda **_kwargs: fake)

    with pytest.raises(enrollment.EnrollmentError, match="does not point only"):
        enrollment.discover_vcenter_client(
            host="vcsa.example.test",
            cluster_id="Atlaso-KMIP",
            username="admin",
            password="test-secret",
            confirmed_https_fingerprint=enrollment.certificate_fingerprint(
                b"test-https-leaf"
            ),
            atlaso_host="kms.atlaso.example.test",
            atlaso_port=5696,
        )
    assert not any(path.endswith("/RetrieveClientCert") for path in fake.calls)


def test_discovery_rejects_changed_https_identity_before_authentication(
    monkeypatch,
) -> None:
    """Reject a changed HTTPS identity before sending credentials.

    Args:
        monkeypatch: Fixture replacing vCenter network calls.
    """
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"unexpected-leaf"
    )
    monkeypatch.setattr(
        enrollment.httpx,
        "Client",
        lambda **_kwargs: pytest.fail("HTTP authentication was attempted"),
    )
    with pytest.raises(enrollment.EnrollmentError, match="fingerprint differs"):
        enrollment.discover_vcenter_client(
            host="vcsa.example.test",
            cluster_id="Atlaso-KMIP",
            username="admin",
            password="test-secret",
            confirmed_https_fingerprint="00" * 32,
            atlaso_host="kms.atlaso.example.test",
            atlaso_port=5696,
        )


def test_pinned_https_context_uses_only_the_observed_leaf() -> None:
    """The vCenter request must not fall back to the host's system CAs."""
    pem = _client_certificate()
    leaf = x509.load_pem_x509_certificate(pem.encode()).public_bytes(
        serialization.Encoding.DER
    )
    context = enrollment._pinned_context(leaf)
    assert context.verify_mode.name == "CERT_REQUIRED"
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.cert_store_stats()["x509"] == 1


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("https://VCSA.example.test/ui", ("vcsa.example.test", 443)),
        ("https://vcsa.example.test:8443", ("vcsa.example.test", 8443)),
        ("https://[2001:db8::1]:9443/ui", ("2001:db8::1", 9443)),
    ],
)
def test_saved_https_endpoint(uri, expected) -> None:
    """Resolve the saved HTTPS authority without changing its port.

    Args:
        uri: Saved HTTPS URI to resolve.
        expected: Expected normalized hostname and port.
    """
    assert enrollment.vcenter_https_endpoint(uri) == expected


@pytest.mark.parametrize(
    "uri",
    [
        "ssh://vcsa.example.test",
        "http://vcsa.example.test",
        "https://user:secret@vcsa.example.test",
        "https://vcsa.example.test:0",
        "https://vcsa.example.test:99999",
        "https://vcsa.example.test:bad",
        "https:///missing",
    ],
)
def test_invalid_saved_https_endpoint(uri) -> None:
    """Reject unsupported or credential-bearing saved endpoints.

    Args:
        uri: Invalid saved URI to reject.
    """
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.vcenter_https_endpoint(uri)
