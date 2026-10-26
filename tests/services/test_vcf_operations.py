"""Contract and safety tests for the VCF Operations renewal client."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from atlaso.app.services.vcf_certificate_remote import (
    Credentials,
    RemoteError,
    Target,
)
from atlaso.app.services.vcf_operations import OperationsClient


@pytest.fixture
def client() -> OperationsClient:
    item = OperationsClient(Target("vcf-ops.test", 443, "a" * 64))
    item._token = "test-ops-token"
    return item


def test_login_uses_pinned_transport_and_ops_token(monkeypatch):
    transport_request = Mock(return_value=(200, {"token": "short-lived-token"}))
    monkeypatch.setattr(
        "atlaso.app.services.vcf_operations.PinnedHTTPS.request", transport_request
    )
    item = OperationsClient(Target("vcf-ops.test", 443, "a" * 64))

    item.login(Credentials("operator", "example-password"))

    assert item._token == "short-lived-token"
    assert transport_request.call_args.args == (
        "POST",
        "/suite-api/api/auth/token/acquire",
    )
    assert transport_request.call_args.kwargs["body"] == {
        "username": "operator",
        "password": "example-password",
    }
    assert transport_request.call_args.kwargs["session_header"] is None


def test_login_sends_no_credentials_when_endpoint_pin_mismatches():
    item = OperationsClient(Target("vcf-ops.test", 443, "a" * 64))
    connection = Mock()
    connection.sock.getpeercert.return_value = b"unconfirmed-certificate"

    with (
        patch(
            "atlaso.app.services.vcf_certificate_remote.ssl._create_unverified_context"
        ),
        patch(
            "atlaso.app.services.vcf_certificate_remote._PinnedConnection",
            return_value=connection,
        ),
        pytest.raises(RemoteError, match="fingerprint"),
    ):
        item.login(Credentials("operator", "example-password"))

    connection.request.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [None, {}, {"token": ""}, {"token": "bad\r\nheader"}, {"token": "x" * 4097}],
)
def test_login_rejects_invalid_tokens(payload):
    item = OperationsClient(Target("vcf-ops.test", 443, "a" * 64))
    item.transport.request = Mock(return_value=(200, payload))

    with pytest.raises(RemoteError, match="invalid token"):
        item.login(Credentials("operator", "example-password"))

    assert item._token is None


def test_context_exit_releases_and_erases_token(client):
    client.transport.request = Mock(return_value=(200, None))
    client._token = "secret-session-token"

    client.__exit__(None, None, None)

    assert client._token is None
    assert "secret-session-token" not in repr(client)
    assert client.transport.request.call_args.args == (
        "POST",
        "/suite-api/api/auth/token/release",
    )
    assert client.transport.request.call_args.kwargs["session_header"] == (
        "Authorization",
        "OpsToken secret-session-token",
    )


def test_requests_require_login():
    item = OperationsClient(Target("vcf-ops.test", 443, "a" * 64))

    with pytest.raises(RemoteError, match="Authenticate"):
        item.version()


def test_version_requires_exact_locked_contract(client):
    client.transport.request = Mock(
        return_value=(
            200,
            {
                "major": 9,
                "minor": 1,
                "minorMinor": 1,
                "patch": 0,
                "releaseName": "VCF Operations 9.1.1.0",
                "buildNumber": 12345678,
                "untrusted": "discarded",
            },
        )
    )

    assert client.version() == {
        "major": 9,
        "minor": 1,
        "minorMinor": 1,
        "patch": 0,
        "releaseName": "VCF Operations 9.1.1.0",
        "buildNumber": 12345678,
    }
    assert client.transport.request.call_args.args == (
        "GET",
        "/suite-api/api/versions/current",
    )


@pytest.mark.parametrize(
    "version",
    [
        {"major": 9, "minor": 1, "minorMinor": 0, "patch": 0},
        {"major": 9, "minor": 1, "minorMinor": 1, "patch": 1},
        {"major": 10, "minor": 1, "minorMinor": 1, "patch": 0},
    ],
)
def test_version_rejects_other_build_families(client, version):
    client.transport.request = Mock(return_value=(200, version))

    with pytest.raises(RemoteError, match="9.1.1.0"):
        client.version()


def _certificate(certificate_id: str = "vc-machine-ssl") -> dict[str, object]:
    return {
        "certificateResourceKey": certificate_id,
        "appliance": "VCENTER",
        "applianceFqdn": "vcenter.test",
        "category": "TLS_CERT",
        "type": "MACHINE_SSL_CERT",
        "certificateMetadata": {
            "certificatePurpose": "MACHINE_SSL_CERT",
            "certificateChainRole": "LEAF",
            "privateField": "ignored",
        },
        "subjectAlternativeNames": {"dns": ["vcenter.test"], "ip": ["192.0.2.5"]},
        "autoRenewState": "DISABLED",
        "expiryDate": 1900000000000,
        "privateKey": "discard me",
    }


def _page(rows, page: int, total: int) -> dict[str, object]:
    return {
        "pageInfo": {"page": page, "pageSize": 100, "totalCount": total},
        "vcfCertificateModels": rows,
    }


def test_inventory_paginates_and_returns_only_public_allowlisted_fields(client):
    rows = [_certificate(f"vc-machine-ssl-{index}") for index in range(100)]
    client.transport.request = Mock(
        side_effect=[
            (200, _page(rows, 0, 101)),
            (200, _page([_certificate("vc-machine-ssl-final")], 1, 101)),
        ]
    )

    inventory = client.inventory()

    assert len(inventory) == 101
    assert inventory[0]["certificateMetadata"] == {
        "certificatePurpose": "MACHINE_SSL_CERT",
        "certificateChainRole": "LEAF",
    }
    assert "privateKey" not in inventory[0]
    assert client.transport.request.call_count == 2
    assert "page=1" in client.transport.request.call_args.args[1]


@pytest.mark.parametrize(
    "payload",
    [
        {"vcfCertificateModels": []},
        _page([_certificate("invalid/id")], 0, 1),
        _page([_certificate("duplicate"), _certificate("duplicate")], 0, 2),
        _page([_certificate()], 1, 1),
    ],
)
def test_inventory_rejects_missing_or_ambiguous_data(client, payload):
    client.transport.request = Mock(return_value=(200, payload))

    with pytest.raises(RemoteError):
        client.inventory()


def _csr(certificate_id: str = "vc-machine-ssl", csr_id: str = "request-1"):
    return {
        "id": csr_id,
        "certificateId": certificate_id,
        "applianceHostname": "vcenter.test",
        "applianceType": "VCENTER",
        "certificateType": "MACHINE_SSL_CERT",
        "commonName": "vcenter.test",
        "csr": "-----BEGIN CERTIFICATE REQUEST-----\npublic-csr\n-----END CERTIFICATE REQUEST-----",
        "privateData": "ignored",
    }


def test_csr_listing_is_scoped_to_exact_certificate(client):
    client.transport.request = Mock(
        return_value=(
            200,
            {
                "pageInfo": {"page": 0, "pageSize": 100, "totalCount": 1},
                "certificateSignatureInfo": [_csr()],
            },
        )
    )

    rows = client.csrs("vc-machine-ssl")

    assert rows == [{key: value for key, value in _csr().items() if key != "privateData"}]
    assert "certificateId=vc-machine-ssl" in client.transport.request.call_args.args[1]


def test_csr_listing_rejects_cross_certificate_or_ambiguous_rows(client):
    for records in ([_csr("different")], [_csr(), _csr(csr_id="request-1")]):
        client.transport.request = Mock(
            return_value=(
                200,
                {
                    "pageInfo": {"page": 0, "pageSize": 100, "totalCount": len(records)},
                    "certificateSignatureInfo": records,
                },
            )
        )
        with pytest.raises(RemoteError):
            client.csrs("vc-machine-ssl")


def test_generate_csr_uses_target_owned_request_and_validates_async_id(client):
    client.transport.request = Mock(return_value=(202, {"requestId": "workflow-1"}))
    spec = {
        "commonName": "vcenter.test",
        "keyAlgorithm": "RSA",
        "keySize": "KEY_2048",
        "subjectAltNames": {"dns": ["vcenter.test"], "ip": ["192.0.2.5"]},
    }

    assert client.generate_csr("vc-machine-ssl", spec) == "workflow-1"
    assert client.transport.request.call_args.args == (
        "POST",
        "/suite-api/api/fleet-management/certificate-management/csrs",
    )
    assert client.transport.request.call_args.kwargs["body"] == {
        "certificateId": "vc-machine-ssl",
        "generateCsrSpec": spec,
    }
    client.transport.request.return_value = (202, {"requestId": "bad/id"})
    with pytest.raises(RemoteError, match="workflow request identity"):
        client.generate_csr("vc-machine-ssl", spec)


def test_generate_csr_rejects_unsupported_spec_fields(client):
    with pytest.raises(RemoteError, match="unsupported fields"):
        client.generate_csr("vc-machine-ssl", {"commonName": "vcenter.test", "key": "private"})


def _chain_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcenter.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_replace_submits_exact_external_chain_and_request_id(client):
    chain = _chain_pem()
    client.transport.request = Mock(return_value=(202, {"requestId": "replace-1"}))

    assert client.replace("vc-machine-ssl", chain) == "replace-1"
    method, path = client.transport.request.call_args.args
    assert method == "PUT"
    assert path == "/suite-api/api/fleet-management/certificate-management/certificates/vc-machine-ssl"
    assert client.transport.request.call_args.kwargs["body"] == {
        "caType": "EXTERNAL_CA",
        "certificateChain": chain,
    }


def test_replace_rejects_malformed_chain_before_remote_write(client):
    client.transport.request = Mock()

    with pytest.raises(RemoteError, match="public PEM"):
        client.replace("vc-machine-ssl", "not a certificate")

    client.transport.request.assert_not_called()


@pytest.mark.parametrize(
    "remote_state,expected",
    [
        ("COMPLETED", "COMPLETED"),
        ("IN_PROGRESS", "IN_PROGRESS"),
        ("CREATED", "IN_PROGRESS"),
        ("FAILED", "FAILED"),
        ("CANCELLED", "FAILED"),
    ],
)
def test_workflow_returns_canonical_state_without_remote_error_text(
    client, remote_state, expected
):
    client.transport.request = Mock(
        return_value=(
            200,
            {
                "requestId": "workflow-1",
                "state": remote_state,
                "category": "VCF_CERTIFICATE_MANAGEMENT",
                "requestType": "CERTIFICATE_REPLACE",
                "errorCause": [{"message": "secret-like remote detail"}],
            },
        )
    )

    assert client.workflow("workflow-1") == {
        "requestId": "workflow-1",
        "state": expected,
        "category": "VCF_CERTIFICATE_MANAGEMENT",
        "requestType": "CERTIFICATE_REPLACE",
    }


def test_workflow_rejects_mismatched_id_and_unknown_state(client):
    client.transport.request = Mock(
        return_value=(200, {"requestId": "other", "state": "COMPLETED"})
    )
    with pytest.raises(RemoteError, match="ambiguous"):
        client.workflow("workflow-1")
    client.transport.request.return_value = (
        200,
        {"requestId": "workflow-1", "state": "MAYBE"},
    )
    with pytest.raises(RemoteError, match="unsupported workflow state"):
        client.workflow("workflow-1")


def test_health_is_explicitly_unknown_without_resource_identity_mapping(client):
    with pytest.raises(RemoteError, match="health is unknown"):
        client.component_health(_certificate())
