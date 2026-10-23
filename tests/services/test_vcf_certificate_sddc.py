import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from atlaso.app.services.vcf_certificate_remote import Credentials, RemoteError, Target
from atlaso.app.services.vcf_certificate_sddc import SddcAdapter


@pytest.fixture
def adapter():
    item = SddcAdapter(Target("10.0.0.5", 443, "a" * 64))
    item._access_token = "token"
    return item


def test_login_posts_json_and_uses_bearer_only(monkeypatch):
    """Verify login posts json and uses bearer only.

    Args:
        monkeypatch: Pytest patch fixture isolating native and background behavior.
    """
    item = SddcAdapter(Target("10.0.0.5", 443, "a" * 64))
    item.transport.request = Mock(return_value=(200, {"accessToken": "opaque-token"}))
    assert item.login(Credentials("admin", "secret")) == "opaque-token"
    assert item.transport.request.call_args.args == ("POST", "/v1/tokens")
    assert item.transport.request.call_args.kwargs["body"] == {
        "username": "admin",
        "password": "secret",
    }
    assert "credentials" not in item.transport.request.call_args.kwargs
    item._request("GET", "/v1/users")
    assert item.transport.request.call_args.kwargs["session_header"] == (
        "Authorization",
        "Bearer opaque-token",
    )


def test_discovery_requires_sddc_role9_active_domain_and_bound_resource(
    adapter, monkeypatch
):
    """Verify discovery requires sddc role9 active domain and bound resource.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
        monkeypatch: Pytest patch fixture isolating native and background behavior.
    """
    adapter.transport.server_time = __import__("time").time()
    adapter._request = Mock(
        side_effect=[
            {
                "role": "SddcManager",
                "version": "9.0.1",
                "ipAddresses": [
                    {
                        "ipAddress": "10.0.0.5",
                        "type": "MANAGEMENT",
                        "ipAddressVersion": "IPv4",
                    }
                ],
            },
            {
                "elements": [
                    {
                        "id": "manager-1",
                        "fqdn": "sddc.test",
                        "version": "9.0.1",
                        "ipAddress": "10.0.0.5",
                        "domain": {"id": "domain-1", "type": "MANAGEMENT"},
                    }
                ],
                "pageMetadata": {"pageNumber": 0, "totalPages": 1, "totalElements": 1},
            },
            {"id": "domain-1", "type": "MANAGEMENT", "status": "ACTIVE"},
        ]
    )
    monkeypatch.setattr(
        "atlaso.app.services.vcf_certificate_sddc.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.5", 443))],
    )
    assert adapter.product_info()["identity"] == "sddc.test"
    assert adapter._binding["resource_id"] == "manager-1"


@pytest.mark.parametrize(
    "info",
    [
        {"role": "VCF_INSTALLER", "version": "9.0"},
        {"role": "SddcManager", "version": "8.0"},
        {"role": "SddcManager", "version": "9.0"},
    ],
)
def test_discovery_rejects_wrong_role_version_or_incomplete_data(adapter, info):
    """Verify discovery rejects wrong role version or incomplete data.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
        info: Public native discovery metadata.
    """
    adapter._request = Mock(return_value=info)
    with pytest.raises(RemoteError):
        adapter.product_info()


def _public_material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sddc.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .sign(key, hashes.SHA256())
    )
    return (
        cert,
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        csr.public_bytes(serialization.Encoding.PEM).decode(),
    )


def test_current_certificate_selects_only_bound_installed_leaf(adapter):
    """Verify current certificate selects only bound installed leaf.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    cert, pem, _ = _public_material()
    from dataclasses import replace

    adapter.target = replace(
        adapter.target, fingerprint=cert.fingerprint(hashes.SHA256()).hex()
    )
    adapter.configure_binding(
        {"domain_id": "domain-1", "resource_id": "manager-1", "identity": "sddc.test"}
    )
    adapter._csr_rows = Mock(return_value=[])
    adapter._pages = Mock(
        return_value=[
            {"resourceType": "VCENTER", "issuedTo": "sddc.test", "isInstalled": True},
            {
                "resourceType": "SDDC_MANAGER",
                "issuedTo": "other.test",
                "isInstalled": True,
            },
            {
                "resourceType": "SDDC_MANAGER",
                "issuedTo": "sddc.test",
                "isInstalled": True,
                "pemEncoded": pem,
            },
        ]
    )
    assert adapter.current_certificate()["pemEncoded"] == pem
    assert adapter._pages.call_args.args == (
        "/v1/domains/domain-1/resource-certificates",
    )


def test_csr_validation_install_payloads_are_bound_to_one_resource(adapter):
    """Verify csr validation install payloads are bound to one resource.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    adapter._csr_rows = Mock(return_value=[])
    adapter._request = Mock(return_value={"id": "task-1"})
    adapter.current_certificate = Mock(return_value={})
    assert (
        adapter.start_csr(
            {
                "csrGenerationSpec": {"keySize": 2048},
                "resources": [
                    {
                        "resourceId": "r1",
                        "fqdn": "sddc.test",
                        "type": "SDDC_MANAGER",
                        "sans": ["sddc.test"],
                    }
                ],
            }
        )
        == "task-1"
    )
    request = adapter._request.call_args
    assert request.args[1] == "/v1/domains/d1/csrs"
    assert request.kwargs["expected_status"] == 202
    adapter._request.return_value = {"validationId": "validation-1"}
    assert adapter.start_validation("LEAF", ["ROOT"]) == "validation-1"
    assert adapter._request.call_args.args[2] == [
        {
            "resourceId": "r1",
            "resourceFqdn": "sddc.test",
            "resourceCertificate": "LEAF",
            "caCertificate": "ROOT",
            "certificateChain": "LEAF\nROOT",
        }
    ]
    adapter._request.return_value = {"id": "task-2"}
    assert adapter.start_install("LEAF", ["ROOT"]) == "task-2"
    assert adapter._request.call_args.args[1] == "/v1/domains/d1/resource-certificates"


@pytest.mark.parametrize("status", ["PENDING", "IN_PROGRESS", "QUEUED"])
def test_active_native_certificate_task_blocks_preparation(adapter, status):
    """Verify active native certificate task blocks preparation.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
        status: Native status value used by the test case.
    """
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    adapter._pages = Mock(
        return_value=[
            {
                "resourceType": "SDDC_MANAGER",
                "issuedTo": "sddc.test",
                "isInstalled": True,
                "operationStatus": status,
            }
        ]
    )
    adapter._csr_rows = Mock()
    with pytest.raises(RemoteError, match="task is active"):
        adapter.current_certificate()
    adapter._csr_rows.assert_not_called()


def test_validation_must_match_bound_resource_and_success(adapter):
    """Verify validation must match bound resource and success.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    adapter._request = Mock(
        return_value={
            "validationId": "v1",
            "completed": True,
            "validations": [
                {
                    "resourceId": "r2",
                    "resourceFqdn": "sddc.test",
                    "validationStatus": "SUCCESSFUL",
                }
            ],
        }
    )
    with pytest.raises(RemoteError):
        adapter.wait_validation("v1", time.monotonic() + 10)
    adapter._request.return_value = {
        "validationId": "v1",
        "completed": True,
        "validations": [
            {
                "resourceId": "r1",
                "resourceFqdn": "sddc.test",
                "validationStatus": "SUCCESSFUL",
            }
        ],
    }
    assert adapter.wait_validation("v1", time.monotonic() + 10)


def test_task_states_fail_closed(adapter):
    """Verify task states fail closed.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter._request = Mock(
        side_effect=[
            {"id": "task-1", "status": "IN_PROGRESS"},
            {"id": "task-1", "status": "SUCCESSFUL"},
        ]
    )
    assert not adapter.task_complete("task-1")
    assert adapter.task_complete("task-1")
    adapter._request.side_effect = None
    adapter._request.return_value = {"status": "UNKNOWN"}
    with pytest.raises(RemoteError):
        adapter.task_complete("task-1")


def test_bad_task_ids_and_unknown_domain_refuse(adapter):
    """Verify bad task ids and unknown domain refuse.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter._request = Mock(return_value={"id": "https://evil.test"})
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    with pytest.raises(RemoteError):
        adapter.start_install("LEAF", ["ROOT"])
    adapter._request = Mock(return_value={"status": "UNKNOWN"})
    with pytest.raises(RemoteError):
        adapter.configure_binding(
            {"domain_id": "https://evil.test", "resource_id": "r1", "identity": "x"}
        )


def test_permissions_use_documented_name_domain_and_role_fields(adapter):
    """Verify permissions use documented name domain and role fields.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter._pages = Mock(
        side_effect=[
            [
                {
                    "name": "administrator",
                    "domain": "vsphere.local",
                    "type": "USER",
                    "role": {"id": "admin-role"},
                    "apiKey": "excluded",
                }
            ],
            [{"id": "admin-role", "name": "ADMIN"}],
        ]
    )
    assert adapter.vcenter_permissions(
        Credentials("administrator@vsphere.local", "unused")
    )


@pytest.mark.parametrize(
    "role,version",
    [
        ("VcfInstaller", "9.0"),
        ("SddcManager", "8.0"),
        ("SddcManager", "10.0"),
        ("SDDC_MANAGER", "9.0"),
    ],
)
def test_native_appliance_role_is_distinct_from_resource_type(adapter, role, version):
    """Verify native appliance role is distinct from resource type.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
        role: Native appliance or administrator role used by the test case.
        version: Native product version used by this compatibility case.
    """
    adapter.transport.server_time = time.time()
    adapter._request = Mock(return_value={"role": role, "version": version})
    with pytest.raises(RemoteError):
        adapter.product_info()


@pytest.mark.parametrize(
    "elements,meta",
    [
        ([], {"pageNumber": 0, "totalPages": 1, "totalElements": 1}),
        ([{"id": "one"}], {"pageNumber": 0, "totalPages": 1, "totalElements": 2}),
        ([{"id": "one"}], {"pageNumber": 1, "totalPages": 1, "totalElements": 1}),
    ],
)
def test_inventory_refuses_truncation_or_wrong_page(adapter, elements, meta):
    """Verify inventory refuses truncation or wrong page.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
        elements: Native inventory elements used by the pagination fixture.
        meta: Native pagination metadata supplied by the test case.
    """
    adapter._request = Mock(return_value={"elements": elements, "pageMetadata": meta})
    with pytest.raises(RemoteError):
        adapter._pages("/v1/users")


def test_empty_csr_inventory_is_valid_and_nested_resource_is_required(adapter):
    """Verify empty csr inventory is valid and nested resource is required.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    adapter._request = Mock(
        return_value={
            "elements": [],
            "pageMetadata": {"pageNumber": 0, "totalPages": 0, "totalElements": 0},
        }
    )
    assert adapter._csr_rows() == []
    adapter._request = Mock(
        side_effect=[
            {"id": "t1", "status": "SUCCESSFUL"},
            {
                "elements": [
                    {
                        "resource": {
                            "resourceId": "r1",
                            "fqdn": "sddc.test",
                            "type": "SDDC_MANAGER",
                        },
                        "csrEncodedContent": "PUBLIC CSR",
                    }
                ],
                "pageMetadata": {"pageNumber": 0, "totalPages": 1, "totalElements": 1},
            },
        ]
    )
    assert adapter.wait_csr("t1", time.monotonic() + 10) == "PUBLIC CSR"
    assert all(call.args[0] == "GET" for call in adapter._request.call_args_list)
    assert adapter._request.call_args.args[1].startswith("/v1/domains/d1/csrs?")


def test_csr_never_dispatches_additional_managed_resources(adapter):
    """Verify csr never dispatches additional managed resources.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    adapter._request = Mock()
    with pytest.raises(RemoteError):
        adapter.start_csr(
            {
                "resources": [
                    {"resourceId": "r1", "fqdn": "sddc.test", "type": "SDDC_MANAGER"},
                    {"resourceId": "vc", "type": "VCENTER"},
                ]
            }
        )
    adapter._request.assert_not_called()


def test_unresolved_native_csr_cannot_be_regenerated(adapter):
    """Verify unresolved native csr cannot be regenerated.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    _, pem, csr = _public_material()
    _, _, other = _public_material()
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    adapter._csr_rows = Mock(return_value=[{"csrEncodedContent": other}])
    adapter.current_certificate = Mock(return_value={"pemEncoded": pem})
    adapter._request = Mock(return_value={"id": "t1"})
    spec = {
        "resources": [{"resourceId": "r1", "fqdn": "sddc.test", "type": "SDDC_MANAGER"}]
    }
    with pytest.raises(RemoteError, match="unresolved CSR"):
        adapter.start_csr(spec)
    adapter._request.assert_not_called()
    adapter._csr_rows.return_value = [{"csrEncodedContent": csr}]
    assert adapter.start_csr(spec) == "t1"


def test_validation_polls_documented_validation_status_without_repeating_put(
    adapter, monkeypatch
):
    """Verify validation polls documented validation status without repeating put.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
        monkeypatch: Pytest patch fixture isolating native and background behavior.
    """
    adapter.configure_binding(
        {"domain_id": "d1", "resource_id": "r1", "identity": "sddc.test"}
    )
    adapter._request = Mock(
        side_effect=[
            {"validationId": "v1", "completed": False, "validations": []},
            {
                "validationId": "v1",
                "completed": True,
                "validations": [
                    {
                        "resourceId": "r1",
                        "resourceFqdn": "sddc.test",
                        "validationStatus": "SUCCESSFUL",
                    }
                ],
            },
        ]
    )
    monkeypatch.setattr(
        "atlaso.app.services.vcf_certificate_sddc.time.sleep", lambda _: None
    )
    assert adapter.wait_validation("v1", time.monotonic() + 10)
    assert all(call.args[0] == "GET" for call in adapter._request.call_args_list)


def test_operation_polling_obeys_deadline(adapter):
    """Verify operation polling obeys deadline.

    Args:
        adapter: SDDC adapter fixture with bounded synthetic native responses.
    """
    adapter._request = Mock()
    with pytest.raises(RemoteError, match="timed out"):
        adapter.wait_csr("t1", time.monotonic() - 1)
    adapter._request.assert_not_called()
