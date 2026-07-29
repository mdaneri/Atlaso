from __future__ import annotations

import ssl

from atlaso.app.services import ldap, pykmip_compat_server, vcf_sddc_deployment


def test_kms_compatibility_context_requires_tls_1_2_or_newer():
    context = pykmip_compat_server._compat_ssl_context(
        server_side=True,
        cert_reqs=ssl.CERT_NONE,
        ca_certs=None,
        certfile=None,
        keyfile=None,
        ciphers=None,
    )

    assert context.protocol == ssl.PROTOCOL_TLS_SERVER
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_vcf_automation_fingerprint_context_requires_tls_1_2_without_ca_verification():
    context = ldap._fingerprint_tls_context()

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_vsphere_fingerprint_context_requires_tls_1_2_without_ca_verification():
    context = vcf_sddc_deployment._fingerprint_tls_context()

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE
