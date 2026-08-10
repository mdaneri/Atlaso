"""Test tls policy behavior."""

from __future__ import annotations

import ssl

from atlaso.app.kmip import server as kmip_server
from atlaso.app.services import ldap, vcf_sddc_deployment


def test_kms_context_requires_tls_1_2_or_newer(monkeypatch, tmp_path):
    """Verify that kms context requires tls 1 2 or newer.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    certificate_path = tmp_path / "server.crt"
    private_key_path = tmp_path / "server.key"
    ca_path = tmp_path / "ca.crt"
    for path in (certificate_path, private_key_path, ca_path):
        path.write_text("test fixture", encoding="utf-8")

    class FakeContext:
        """Represent fake context.

        Attributes:
            protocol: Protocol captured or supplied by this test helper.
            minimum_version: Minimum version captured or supplied by this test helper.
            verify_mode: Verify mode captured or supplied by this test helper.
            verify_flags: X.509 verification flags captured by this test helper.
        """
        def __init__(self, protocol):
            """Initialize the fake context.

            Args:
                protocol: Protocol supplied to the test scenario.
            """
            self.protocol = protocol
            self.minimum_version = None
            self.verify_mode = None
            self.verify_flags = 0

        def load_cert_chain(self, _certificate_path, _private_key_path):
            """Return cert chain.

            Args:
                _certificate_path: Filesystem path used for certificate.
                _private_key_path: Filesystem path used for private key.
            """
            return None

        def load_verify_locations(self, *, cafile):
            """Return verify locations.

            Args:
                cafile: Cafile supplied to the test scenario.
            """
            return None

    monkeypatch.setattr(kmip_server.ssl, "SSLContext", FakeContext)
    config = kmip_server.ServiceConfig(
        enabled=True,
        host="127.0.0.1",
        port=5696,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        ca_path=ca_path,
        database_path=tmp_path / "store.db",
        kek_path=tmp_path / "kek.json",
        limits=kmip_server.ServiceLimits(),
        providers=(),
    )
    context = kmip_server.tls_context(config)

    assert context.protocol == ssl.PROTOCOL_TLS_SERVER
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


def test_vcf_automation_fingerprint_context_requires_tls_1_2_without_ca_verification():
    """Verify that vcf automation fingerprint context requires tls 1 2 without ca verification."""
    context = ldap._fingerprint_tls_context()

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_vsphere_fingerprint_context_requires_tls_1_2_without_ca_verification():
    """Verify that vsphere fingerprint context requires tls 1 2 without ca verification."""
    context = vcf_sddc_deployment._fingerprint_tls_context()

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE
