"""Test VCF credential discovery without contacting an appliance."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import nullcontext
from typing import Any

import httpx
import pytest

from atlaso.app.services import vcf_vault_import as service
from atlaso.app.services.vaults import normalize_vault_key
from atlaso.app.services.vcf_depot_target import VcfDepotTargetError


@pytest.fixture
def fake_api_factory() -> Iterator[
    Callable[[Callable[[httpx.Request], tuple[int, Any]]], tuple[Any, list[httpx.Request]]]
]:
    """Build a request-recording API client backed only by httpx.MockTransport."""
    clients: list[httpx.Client] = []

    def create(handler: Callable[[httpx.Request], tuple[int, Any]]) -> tuple[Any, list[httpx.Request]]:
        """Create one API stub and expose its recorded requests.

        Args:
            handler: Fake response factory for each intercepted HTTP request.
        """
        requests: list[httpx.Request] = []

        def transport(request: httpx.Request) -> httpx.Response:
            """Record and answer one fake HTTP request.

            Args:
                request: Request intercepted by the in-memory transport.
            """
            requests.append(request)
            status, payload = handler(request)
            return httpx.Response(status, json=payload, request=request)

        client = httpx.Client(base_url="https://vcf.invalid", transport=httpx.MockTransport(transport))
        clients.append(client)
        return type("FakeApi", (), {"client": client})(), requests

    yield create
    for client in clients:
        client.close()


@pytest.mark.parametrize(
    "payload, expected_ids",
    [
        ([{"id": "one"}], ["one"]),
        ({"elements": [{"id": "one"}]}, ["one"]),
        ({"credentials": [{"id": "one"}]}, ["one"]),
        ([], []),
        ({"elements": []}, []),
        ({"credentials": []}, []),
    ],
)
def test_credential_rows_accepts_documented_inventory_shapes(fake_api_factory, payload, expected_ids):
    """Accept list and object inventory envelopes, including empty inventories.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        payload: Fake inventory response envelope.
        expected_ids: Expected identifiers extracted from that envelope.
    """
    api, _requests = fake_api_factory(lambda _request: (200, payload))

    assert [row.get("id") for row in service._credential_rows(api)] == expected_ids


def test_credential_rows_traverses_documented_pages(fake_api_factory):
    """Follow pageNumber metadata and use the returned page size after page zero.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    rows = {
        0: {
            "elements": [{"id": "first"}],
            "pageMetadata": {"pageNumber": 0, "pageSize": 1, "totalPages": 2, "totalElements": 2},
        },
        1: {
            "elements": [{"id": "second"}],
            "pageMetadata": {"pageNumber": 1, "pageSize": 1, "totalPages": 2, "totalElements": 2},
        },
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return the fake page requested by pageNumber.

        Args:
            request: Intercepted HTTP request, including its query parameters.
        """
        assert request.url.path == "/v1/credentials"
        page = int(request.url.params["pageNumber"])
        return 200, rows[page]

    api, requests = fake_api_factory(handler)

    assert [row["id"] for row in service._credential_rows(api)] == ["first", "second"]
    assert [request.url.params["pageNumber"] for request in requests] == ["0", "1"]
    assert [request.url.params["pageSize"] for request in requests] == ["0", "1"]


@pytest.mark.parametrize(
    "responses, message",
    [
        (
            [
                {
                    "elements": [{"id": "first"}],
                    "pageMetadata": {"pageNumber": 0, "pageSize": 1, "totalPages": 2, "totalElements": 2},
                },
                {
                    "elements": [{"id": "first"}],
                    "pageMetadata": {"pageNumber": 1, "pageSize": 1, "totalPages": 2, "totalElements": 2},
                },
            ],
            "repeated",
        ),
        (
            [
                {
                    "elements": [{"id": "first"}],
                    "pageMetadata": {"pageNumber": 0, "pageSize": 1, "totalPages": 2, "totalElements": 2},
                },
                {
                    "elements": [],
                    "pageMetadata": {"pageNumber": 1, "pageSize": 1, "totalPages": 2, "totalElements": 2},
                },
            ],
            "incomplete",
        ),
        (
            [
                {
                    "elements": [{"id": "first"}],
                    "pageMetadata": {"pageNumber": 0, "pageSize": 1, "totalPages": 1, "totalElements": 2},
                }
            ],
            "incomplete",
        ),
    ],
)
def test_credential_rows_rejects_repeated_or_incomplete_pages(fake_api_factory, responses, message):
    """Do not present a repeated or truncated inventory as complete.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        responses: Ordered fake page responses.
        message: Safe error text expected for the invalid inventory.
    """
    index = 0

    def handler(_request: httpx.Request) -> tuple[int, Any]:
        """Return the next fake page.

        Args:
            _request: Intercepted request, unused by this ordered response fixture.
        """
        nonlocal index
        payload = responses[index]
        index += 1
        return 200, payload

    api, _requests = fake_api_factory(handler)

    with pytest.raises(VcfDepotTargetError, match=message):
        service._credential_rows(api)


def test_masked_password_retrieval_uses_encoded_id_and_returns_no_secret_in_preview(fake_api_factory):
    """Fetch a masked listed credential by encoded ID and expose only its safe preview.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    listed = {
        "elements": [
            {
                "id": "credential/with space",
                "password": "********",
                "username": "svc-vsphere",
                "credentialType": "API",
                "resource": {"resourceType": "VCENTER", "resourceName": "vc01.lab.example"},
            }
        ]
    }
    detail = {
        "id": "credential/with space",
        "password": "fixture-only-secret",
        "username": "svc-vsphere",
        "credentialType": "API",
        "resource": {"resourceType": "VCENTER", "resourceName": "vc01.lab.example"},
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fixture inventory or matching credential detail.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/credentials":
            return 200, listed
        assert request.url.raw_path == b"/v1/credentials/credential%2Fwith%20space"
        return 200, detail

    api, requests = fake_api_factory(handler)
    candidates = service._sddc_manager_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].value == "fixture-only-secret"
    assert candidates[0].uris == ("https://vc01.lab.example",)
    assert "fixture-only-secret" not in repr(candidates[0].sanitized())
    assert requests[1].url.raw_path == b"/v1/credentials/credential%2Fwith%20space"


def test_denied_detail_is_reported_with_fixed_reason_without_vendor_message(fake_api_factory):
    """Summarize inaccessible credentials without reflecting response diagnostics.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    listed = {"elements": [{"id": "masked-id", "password": "••••", "username": "svc"}]}
    vendor_message = "fixture vendor detail diagnostic"

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Deny detail retrieval with a non-sensitive vendor-message fixture.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/credentials":
            return 200, listed
        return 403, {"message": vendor_message}

    api, _requests = fake_api_factory(handler)
    candidates = service._sddc_manager_candidates(api)
    safe_summary = repr(candidates.summary())

    assert not candidates
    assert candidates.summary()["skipped"] == {"Credential retrieval unavailable or permission-limited": 1}
    assert vendor_message not in safe_summary


@pytest.mark.parametrize(
    "detail",
    [
        {"id": "different-id", "password": "fixture-only-secret", "username": "svc"},
        {"id": "same-id", "password": "fixture-only-secret", "username": "different-user"},
    ],
)
def test_mismatched_detail_is_skipped(fake_api_factory, detail):
    """Never pair a listed account/resource with a detail record of another identity.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        detail: Mismatched fake detail response.
    """
    listed = {
        "elements": [
            {
                "id": "same-id",
                "password": "********",
                "username": "svc",
                "credentialType": "SSH",
                "resource": {"resourceType": "ESXI", "resourceName": "esx01.lab.example"},
            }
        ]
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return the listed credential or its mismatched detail.

        Args:
            request: Intercepted HTTP request to answer.
        """
        return (200, listed) if request.url.path == "/v1/credentials" else (200, detail)

    api, _requests = fake_api_factory(handler)
    candidates = service._sddc_manager_candidates(api)

    assert not candidates
    assert candidates.summary()["skipped"] == {"Credential detail identity unavailable or changed": 1}


@pytest.mark.parametrize(
    "credential_type, resource, expected",
    [
        (
            "SSH",
            {"resourceType": "ESXI", "resourceName": "esx01.lab.example", "resourceIp": "2001:db8::10"},
            ("ssh://esx01.lab.example", "ssh://[2001:db8::10]"),
        ),
        (
            "API",
            {"resourceType": "VCENTER", "resourceName": "vc01.lab.example", "resourceIp": "192.0.2.20"},
            ("https://vc01.lab.example", "https://192.0.2.20"),
        ),
        (
            "API",
            {"resourceType": "VCENTER", "resourceName": "vc01.lab.example."},
            ("https://vc01.lab.example",),
        ),
        (
            "API",
            {"resourceType": "VCENTER", "resourceName": "vc01.lab.example.."},
            (),
        ),
    ],
)
def test_resource_metadata_maps_supported_ssh_and_https_endpoints(credential_type, resource, expected):
    """Map resource names and verified IP metadata to the credential protocol.

    Args:
        credential_type: Supported credential protocol from the fake response.
        resource: Sanitized source resource metadata.
        expected: Expected protocol URIs in discovery order.
    """
    assert service._resource_uris(resource, credential_type) == expected


def test_opaque_credential_id_does_not_become_an_endpoint():
    """An opaque ID may label an entry, but cannot establish a network destination."""
    assert service._resource_uris({}, "API") == ()
    assert service._resource_uris({"resourceName": "credential-123"}, "API") == ()
    assert service._resource_uris({"resourceType": "VCENTER", "resourceName": "vc01"}, "API") == ()


@pytest.mark.parametrize(
    "resource",
    [
        {"resourceType": "VCENTER", "resourceName": "https://user:pass@vc01.lab.example"},
        {"resourceType": "VCENTER", "resourceName": "user:pass@vc01.lab.example"},
        {"resourceType": "VCENTER", "resourceIp": "vc01.lab.example/path"},
        {"resourceType": "VCENTER", "resourceIp": "vc01.lab.example?token=fixture"},
    ],
)
def test_credential_bearing_or_malformed_endpoints_are_rejected(resource):
    """Do not turn URLs, userinfo, paths, or query strings into vault destinations.

    Args:
        resource: Malformed fake resource endpoint metadata.
    """
    assert service._resource_uris(resource, "API") == ()


def test_unsupported_credential_type_is_counted_and_not_imported(fake_api_factory):
    """Expose a safe skip reason for credentials Atlaso cannot model.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    payload = {
        "elements": [
            {
                "id": "unsupported-id",
                "password": "fixture-only-secret",
                "credentialType": "DATABASE",
                "username": "db-user",
                "resource": {"resourceType": "DATABASE", "resourceName": "db01.lab.example"},
            }
        ]
    }
    api, _requests = fake_api_factory(lambda _request: (200, payload))
    candidates = service._sddc_manager_candidates(api)

    assert not candidates
    assert candidates.summary()["skipped"] == {"Unsupported credential type": 1}


def test_installer_import_uses_local_endpoints_and_skips_masked_latest_spec(fake_api_factory):
    """Use each nested component's own endpoint and label installer scope as latest-only.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {
        "hosts": [{"hostname": "esx01.lab.example", "rootPassword": "fixture-root-secret"}],
        "components": [
            {
                "hostname": "vc01.lab.example",
                "credentials": {"username": "svc-vsphere", "password": "********"},
            }
        ],
        "secretContainer": {"password": {"value": "fixture-container-value"}},
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return the latest SDDC identity or its sanitized specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        assert request.url.path == "/v1/sddcs/fixture-sddc/spec"
        return 200, spec

    api, requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert [candidate.uris for candidate in candidates] == [("ssh://esx01.lab.example",)]
    assert candidates[0].username == "root"
    assert candidates.summary()["scope"].startswith("Passwords in the latest VCF Installer SDDC specification only")
    assert candidates.summary()["skipped"] == {
        "Password missing, masked, or unsupported in the latest specification": 1,
        "Unsupported password container in the latest specification": 1,
    }
    assert len(requests) == 2
    assert all("fixture-container-value" not in repr(candidate.sanitized()) for candidate in candidates)


def test_installer_does_not_guess_protocol_for_unidentified_password_purpose(fake_api_factory):
    """Keep unknown passwords importable without associating an unrelated web endpoint.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {
        "unknownService": {"hostname": "unknown.lab.example", "password": "fixture-unknown-secret"},
        "vcenterSpec": {"hostname": "vc01.lab.example", "username": "admin", "password": "fixture-web-secret"},
    }
    api, _requests = fake_api_factory(lambda request: (200, {"id": "fixture-sddc"})
                                    if request.url.path == "/v1/sddcs/latest" else (200, spec))
    candidates = service._vcf_installer_candidates(api)
    assert [(candidate.username, candidate.uris) for candidate in candidates] == [
        ("", ()), ("admin", ("https://vc01.lab.example",)),
    ]


def test_installer_maps_vcenter_and_nsxt_passwords_to_their_local_endpoints(fake_api_factory):
    """Associate supported vCenter and NSX-T accounts with their documented endpoints.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {
        "vcenterSpec": {
            "vcenterHostname": "vc01.lab.example",
            "rootVcenterPassword": "fixture-vcenter-root",
            "adminUserSsoUsername": "  administrator@vsphere.local  ",
            "adminUserSsoPassword": "fixture-vcenter-sso",
        },
        "nsxtSpec": {
            "vipFqdn": "nsx-vip.lab.example",
            "rootNsxtManagerPassword": "fixture-nsxt-root",
            "nsxtAdminPassword": "fixture-nsxt-admin",
            "nsxtAuditPassword": "fixture-nsxt-audit",
            "nsxtManagers": [
                {"hostname": "nsxt01.lab.example"},
                {"hostname": "nsxt02.lab.example"},
            ],
        },
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its installer specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert [(candidate.username, candidate.uris) for candidate in candidates] == [
        ("root", ("ssh://vc01.lab.example",)),
        ("administrator@vsphere.local", ("https://vc01.lab.example",)),
        ("root", ("ssh://nsxt01.lab.example",)),
        ("root", ("ssh://nsxt02.lab.example",)),
        ("admin", ("https://nsx-vip.lab.example",)),
        ("audit", ("https://nsx-vip.lab.example",)),
    ]


@pytest.mark.parametrize(
    "hostname, expected_uri",
    [
        ("esx-1", "ssh://esx-1"),
        ("esx-1.", "ssh://esx-1"),
        ("esx-1..", ""),
        ("esx-1.lab.example", "ssh://esx-1.lab.example"),
        ("esx-1.lab.example.", "ssh://esx-1.lab.example"),
        ("esx-1.lab.example..", ""),
    ],
)
def test_installer_host_specs_accept_only_one_trailing_dns_root_dot(fake_api_factory, hostname, expected_uri):
    """Accept valid short/FQDN host fields and one root dot, but reject multiple trailing dots.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        hostname: Sanitized explicit hostSpecs hostname.
        expected_uri: Expected endpoint URI, or an empty string when invalid.
    """
    spec = {
        "hostSpecs": [
            {"hostname": hostname, "credentials": {"username": "root", "password": "fixture-esxi-root"}}
        ]
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].username == "root"
    assert candidates[0].uris == ((expected_uri,) if expected_uri else ())


@pytest.mark.parametrize(
    "spec, hostname, username",
    [
        (
            {
                "hostSpecs": [
                    {"hostname": ".".join(("a" * 63, "b" * 63, "c" * 63, "example")),
                     "credentials": {"username": "root", "password": "fixture-long-esxi-root"}}
                ]
            },
            ".".join(("a" * 63, "b" * 63, "c" * 63, "example")),
            "root",
        ),
        (
            {
                "vcfOperationsSpec": {
                    "nodes": [
                        {"hostname": ".".join(("d" * 63, "e" * 63, "f" * 63, "example")),
                         "rootUserPassword": "fixture-long-operations-root"}
                    ]
                }
            },
            ".".join(("d" * 63, "e" * 63, "f" * 63, "example")),
            "root",
        ),
    ],
)
def test_long_host_credentials_keep_raw_identity_and_bounded_valid_key(fake_api_factory, spec, hostname, username):
    """Bound generated vault keys while retaining the full long host in identity and URI.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        spec: Fake installer specification containing a long explicit host credential.
        hostname: Long DNS hostname expected in candidate identity and endpoint URI.
        username: Expected username associated with the candidate.
    """
    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidate = next(item for item in service._vcf_installer_candidates(api) if item.username == username)

    assert hostname in candidate.candidate_id
    assert candidate.uris == (f"ssh://{hostname}",)
    assert len(candidate.key) <= 180
    assert normalize_vault_key(candidate.key) == candidate.key


def test_installer_nsxt_managers_accept_explicit_short_hostnames(fake_api_factory):
    """Use each short explicit NSX manager hostname for its root SSH URI.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {
        "nsxtSpec": {
            "vipFqdn": "nsx-vip.lab.example",
            "rootNsxtManagerPassword": "fixture-nsxt-root",
            "nsxtManagers": [{"hostname": "nsx-1"}],
        }
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert [(candidate.username, candidate.uris) for candidate in candidates] == [
        ("root", ("ssh://nsx-1",)),
    ]


@pytest.mark.parametrize(
    "hostname",
    [
        "https://user:password@esx-1",
        "user:password@esx-1",
        "esx-1/path",
        "esx-1?token=fixture",
        "esx-%31",
        "-esx",
        "esx_1",
        "esx..1",
    ],
)
def test_installer_short_hostname_allowance_still_rejects_malformed_values(fake_api_factory, hostname):
    """Reject URL syntax and invalid DNS labels even on explicit installer fields.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        hostname: Malformed explicit hostname from the fake specification.
    """
    spec = {
        "hostSpecs": [
            {"hostname": hostname, "credentials": {"username": "root", "password": "fixture-esxi-root"}}
        ]
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].uris == ()


@pytest.mark.parametrize(
    "sso_domain, expected_username",
    [
        ("", "administrator"),
        ("vsphere.local", "administrator@vsphere.local"),
    ],
)
def test_vcenter_sso_password_uses_documented_default_username(
    fake_api_factory, sso_domain, expected_username
):
    """Use the documented administrator fallback, adding only a supplied SSO domain.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        sso_domain: Optional valid SSO domain from the fake specification.
        expected_username: Documented fallback username for that domain.
    """
    vcenter = {
        "vcenterHostname": "vc01.lab.example",
        "rootVcenterPassword": "fixture-vcenter-root",
        "adminUserSsoPassword": "fixture-vcenter-sso",
    }
    if sso_domain:
        vcenter["ssoDomain"] = sso_domain
    spec = {"vcenterSpec": vcenter}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert [(candidate.username, candidate.uris) for candidate in candidates] == [
        ("root", ("ssh://vc01.lab.example",)),
        (expected_username, ("https://vc01.lab.example",)),
    ]


def test_installer_nsxt_root_without_manager_hosts_does_not_use_vip(fake_api_factory):
    """Keep a root credential unassociated when only a cluster VIP is known.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {"nsxtSpec": {"vipFqdn": "nsx-vip.lab.example",
                         "rootNsxtManagerPassword": "fixture-root-secret"}}
    api, _requests = fake_api_factory(lambda request: (200, {"id": "fixture-sddc"})
                                    if request.url.path == "/v1/sddcs/latest" else (200, spec))
    candidates = service._vcf_installer_candidates(api)
    assert [(candidate.username, candidate.uris) for candidate in candidates] == [("root", ())]


def test_installer_maps_sddc_manager_ssh_password_to_vcf_account(fake_api_factory):
    """Map SDDC Manager root and vcf SSH passwords to its appliance hostname.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {
        "sddcManagerSpec": {
            "hostname": "sddcm01.lab.example",
            "rootPassword": "fixture-sddc-root",
            "sshPassword": "fixture-sddc-vcf",
            "localUserPassword": "fixture-sddc-local-admin",
        }
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its installer specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert [(candidate.username, candidate.uris) for candidate in candidates] == [
        ("root", ("ssh://sddcm01.lab.example",)),
        ("vcf", ("ssh://sddcm01.lab.example",)),
        ("admin@local", ("https://sddcm01.lab.example",)),
    ]


def test_unrelated_ssh_password_does_not_assume_vcf_account_or_uri(fake_api_factory):
    """Keep unrelated sshPassword fields unassociated until their purpose is known.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {"unrelatedSpec": {"hostname": "unknown01.lab.example", "sshPassword": "fixture-unknown-ssh"}}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its installer specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].username == ""
    assert candidates[0].uris == ()


def test_unrelated_local_user_password_does_not_assume_admin_account_or_uri(fake_api_factory):
    """Keep unrelated localUserPassword fields unassociated without a source contract.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {"unrelatedSpec": {"hostname": "unknown01.lab.example", "localUserPassword": "fixture-unknown-local"}}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].username == ""
    assert candidates[0].uris == ()


def test_nsxt_manager_candidate_identity_and_key_survive_reordering_and_removal(fake_api_factory):
    """Keep each NSX manager's imported identity stable across inventory changes.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    host_a = "nsx-a.lab.example"
    host_b = "nsx.a.lab.example"

    def discover(hostnames: list[str]) -> dict[str, tuple[str, str]]:
        """Return SSH endpoint to candidate identity/key mappings for one spec.

        Args:
            hostnames: Ordered NSX manager hostnames in the fake specification.
        """
        spec = {
            "nsxtSpec": {
                "vipFqdn": "nsx-vip.lab.example",
                "rootNsxtManagerPassword": "fixture-nsxt-root",
                "nsxtManagers": [{"hostname": hostname} for hostname in hostnames],
            }
        }

        def handler(request: httpx.Request) -> tuple[int, Any]:
            """Return a fake latest SDDC record or its specification.

            Args:
                request: Intercepted HTTP request to answer.
            """
            if request.url.path == "/v1/sddcs/latest":
                return 200, {"id": "fixture-sddc"}
            return 200, spec

        api, _requests = fake_api_factory(handler)
        candidates = service._vcf_installer_candidates(api)
        return {
            candidate.uris[0]: (candidate.candidate_id, candidate.key)
            for candidate in candidates
            if candidate.uris and candidate.uris[0].startswith("ssh://")
        }

    original = discover([host_a, host_b])
    reordered = discover([host_b, host_a])
    remaining = discover([host_b])

    assert set(original) == {f"ssh://{host_a}", f"ssh://{host_b}"}
    assert original == reordered
    assert remaining == {f"ssh://{host_b}": original[f"ssh://{host_b}"]}
    assert original[f"ssh://{host_a}"][0] != original[f"ssh://{host_b}"][0]
    assert original[f"ssh://{host_a}"][1] != original[f"ssh://{host_b}"][1]


def test_long_nsxt_manager_hostname_keeps_valid_bounded_key_and_exact_identity(fake_api_factory):
    """Keep a long valid NSX hostname in candidate identity while bounding the vault key.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    hostname = ".".join(("a" * 63, "b" * 63, "c" * 63, "example"))
    spec = {
        "nsxtSpec": {
            "rootNsxtManagerPassword": "fixture-nsxt-root",
            "nsxtManagers": [{"hostname": hostname}],
        }
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)
    candidate = next(candidate for candidate in candidates if candidate.username == "root")

    assert candidate.candidate_id.endswith(hostname + ".rootNsxtManagerPassword")
    assert candidate.uris == (f"ssh://{hostname}",)
    assert len(candidate.key) <= 180
    assert normalize_vault_key(candidate.key) == candidate.key


def test_vsp_system_password_expands_to_distinct_ssh_and_admin_https_entries(fake_api_factory):
    """Map the shared VSP password to its system-user SSH and local-admin HTTPS accounts.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    hostname = "platform.vsp.lab.example"
    spec = {"vspClusterSpec": {"platformFqdn": hostname, "systemUserPassword": "fixture-vsp-password"}}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert {(candidate.username, candidate.uris) for candidate in candidates} == {
        ("vmware-system-user", (f"ssh://{hostname}",)),
        ("admin@vsp.local", (f"https://{hostname}",)),
    }
    assert len({candidate.candidate_id for candidate in candidates}) == 2
    assert len({candidate.key for candidate in candidates}) == 2


@pytest.mark.parametrize(
    "operations, expected_uri",
    [
        (
            {"adminUserPassword": "fixture-ops-admin", "loadBalancerFqdn": "ops-lb.lab.example",
             "nodes": [{"hostname": "ops-master.lab.example", "type": "master"}]},
            "https://ops-lb.lab.example",
        ),
        (
            {"adminUserPassword": "fixture-ops-admin", "nodes": [
                {"hostname": "ops-master.lab.example", "type": "master"},
                {"hostname": "ops-replica.lab.example", "type": "replica"},
            ]},
            "https://ops-master.lab.example",
        ),
        (
            {"adminUserPassword": "fixture-ops-admin", "nodes": [{"hostname": "ops-single.lab.example"}]},
            "https://ops-single.lab.example",
        ),
        (
            {"adminUserPassword": "fixture-ops-admin", "nodes": [
                {"hostname": "ops01.lab.example", "type": "replica"},
                {"hostname": "ops02.lab.example", "type": "replica"},
            ]},
            "",
        ),
    ],
)
def test_vcf_operations_admin_endpoint_uses_load_balancer_or_unambiguous_node(
    fake_api_factory, operations, expected_uri
):
    """Prefer the Operations load balancer, then an explicit master or sole node.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        operations: VCF Operations portion of the fake installer specification.
        expected_uri: Expected HTTPS endpoint, or empty when node selection is ambiguous.
    """
    spec = {"vcfOperationsSpec": operations}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].username == "admin"
    assert candidates[0].uris == ((expected_uri,) if expected_uri else ())


def test_vcf_automation_admin_password_uses_component_hostname(fake_api_factory):
    """Map the VCF Automation admin password to HTTPS at its explicit hostname.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    hostname = "automation.lab.example"
    spec = {"vcfAutomationSpec": {"hostname": hostname, "adminUserPassword": "fixture-automation-admin"}}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert [(candidate.username, candidate.uris) for candidate in candidates] == [
        ("admin", (f"https://{hostname}",)),
    ]


@pytest.mark.parametrize(
    "spec",
    [
        {"vspClusterSpec": {"systemUserPassword": "fixture-vsp-password"}},
        {"vspClusterSpec": {"platformFqdn": "https://bad.example", "systemUserPassword": "fixture-vsp-password"}},
        {"vcfOperationsSpec": {"adminUserPassword": "fixture-ops-admin", "loadBalancerFqdn": "ops/path"}},
        {"vcfAutomationSpec": {"adminUserPassword": "fixture-automation-admin", "hostname": "auto?token=x"}},
    ],
)
def test_management_credentials_keep_empty_uris_when_endpoints_are_missing_or_invalid(fake_api_factory, spec):
    """Keep management credential URIs empty when authoritative endpoints are unusable.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
        spec: Fake installer specification with missing or malformed endpoint metadata.
    """
    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert candidates
    assert all(candidate.uris == () for candidate in candidates)


def test_unknown_management_admin_password_does_not_gain_an_endpoint_or_username(fake_api_factory):
    """Do not infer account or protocol for an undocumented management password field.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {"unknownComponentSpec": {"hostname": "unknown.lab.example", "adminUserPassword": "fixture-unknown-admin"}}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].username == ""
    assert candidates[0].uris == ()


def test_vcf_operations_root_passwords_use_each_node_hostname_for_ssh(fake_api_factory):
    """Import Operations and collector root passwords against their own SSH hosts.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {
        "vcfOperationsSpec": {
            "nodes": [
                {"hostname": "ops01.lab.example", "rootUserPassword": "fixture-ops-root-1"},
                {"hostname": "ops02.lab.example", "rootUserPassword": "fixture-ops-root-2"},
            ]
        },
        "vcfOperationsCollectorSpec": {
            "hostname": "collector01.lab.example",
            "rootUserPassword": "fixture-collector-root",
        },
    }

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert [(candidate.username, candidate.uris) for candidate in candidates] == [
        ("root", ("ssh://ops01.lab.example",)),
        ("root", ("ssh://ops02.lab.example",)),
        ("root", ("ssh://collector01.lab.example",)),
    ]


def test_unknown_root_user_password_does_not_infer_root_account_or_endpoint(fake_api_factory):
    """Leave an unknown rootUserPassword unassociated without a documented component mapping.

    Args:
        fake_api_factory: Fixture that creates an in-memory HTTP API client.
    """
    spec = {"unknownComponentSpec": {"hostname": "unknown01.lab.example", "rootUserPassword": "fixture-unknown-root"}}

    def handler(request: httpx.Request) -> tuple[int, Any]:
        """Return a fake latest SDDC record or its specification.

        Args:
            request: Intercepted HTTP request to answer.
        """
        if request.url.path == "/v1/sddcs/latest":
            return 200, {"id": "fixture-sddc"}
        return 200, spec

    api, _requests = fake_api_factory(handler)
    candidates = service._vcf_installer_candidates(api)

    assert len(candidates) == 1
    assert candidates[0].username == ""
    assert candidates[0].uris == ()


def test_final_candidate_keys_reserve_natural_suffixes_and_survive_reordering(monkeypatch):
    """Allocate collision keys without stealing natural keys or depending on row order.

    Args:
        monkeypatch: Pytest fixture used to replace the source API and discovery result.
    """
    from types import SimpleNamespace

    first_identity = service.VcfPasswordCandidate(
        "identity-2", "vcf.cluster.admin", "First account", "vcf_password",
        "admin", "cluster", "fixture-password-a",
    )
    candidates = [
        first_identity,
        service.VcfPasswordCandidate(
            "credential-b", "vcf.cluster.admin", "Second account", "vcf_password",
            "admin", "cluster", "fixture-password-b",
        ),
        service.VcfPasswordCandidate(
            "credential-c", "vcf.cluster.admin_2", "Natural numeric suffix account", "vcf_password",
            "admin_2", "cluster", "fixture-password-c",
        ),
    ]
    api = SimpleNamespace(appliance_info=lambda: {"role": "SddcManager"})
    monkeypatch.setattr(service, "VcfDepotApiClient", lambda *_args, **_kwargs: nullcontext(api))
    current_candidates = list(candidates)
    monkeypatch.setattr(service, "_sddc_manager_candidates", lambda _api: list(current_candidates))

    def discover() -> dict[str, service.VcfPasswordCandidate]:
        """Run discovery and index candidates by stable source identity."""
        result = service.discover_vcf_passwords(
            source_type="sddc_manager",
            address="sddc-manager.example.internal",
            port=443,
            username="admin",
            password="fixture-source-password",
            expected_fingerprint="AA:BB",
        )
        return {candidate.candidate_id: candidate for candidate in result}

    original_keys = {candidate.candidate_id: candidate.key for candidate in candidates}
    first = discover()
    assert len({candidate.key for candidate in first.values()}) == len(candidates)
    for candidate_id, candidate in first.items():
        natural_key = original_keys[candidate_id]
        expected_key = f"vcf.imported.id_{candidate.identity_id.removeprefix('vcf-')}"
        assert candidate.natural_key == natural_key
        assert candidate.key == expected_key
    assert {candidate.candidate_id: candidate.value for candidate in first.values()} == {
        candidate.candidate_id: candidate.value for candidate in candidates
    }
    assert all(len(candidate.key) <= 180 and normalize_vault_key(candidate.key) == candidate.key
               for candidate in first.values())

    current_candidates.reverse()
    reordered = discover()
    assert {candidate_id: candidate.key for candidate_id, candidate in reordered.items()} == {
        candidate_id: candidate.key for candidate_id, candidate in first.items()
    }

    current_candidates[:] = [candidates[0]]
    alone = discover()
    assert alone["identity-2"].key == first["identity-2"].key

    added = service.VcfPasswordCandidate(
        "credential-d", "vcf.cluster.admin", "Added account", "vcf_password",
        "admin", "cluster", "fixture-password-d",
    )
    current_candidates[:] = [candidates[1], candidates[2], added]
    after_remove_and_add = discover()
    assert after_remove_and_add["credential-b"].key == first["credential-b"].key
    assert after_remove_and_add["credential-c"].key == first["credential-c"].key
    assert after_remove_and_add["credential-d"].key != first["credential-b"].key
    assert len({candidate.key for candidate in after_remove_and_add.values()}) == 3


def test_duplicate_candidate_suffix_cannot_take_another_original_key(monkeypatch):
    """Reserve a natural key that matches the first candidate's identity suffix.

    Args:
        monkeypatch: Pytest fixture used to replace the source API and discovery result.
    """
    from types import SimpleNamespace

    first = service.VcfPasswordCandidate(
        "identity-2", "vcf.cluster.admin", "First duplicate", "vcf_password",
        "admin", "cluster", "fixture-password-a",
    )
    reserved_key = f"vcf.imported.id_{first.identity_id.removeprefix('vcf-')}"
    candidates = [
        first,
        service.VcfPasswordCandidate(
            "second-duplicate", "vcf.cluster.admin", "Second duplicate", "vcf_password",
            "admin", "cluster", "fixture-password-b",
        ),
        service.VcfPasswordCandidate(
            "natural-identity-key", reserved_key, "Natural identity suffix key", "vcf_password",
            "admin", "cluster", "fixture-password-c",
        ),
    ]
    api = SimpleNamespace(appliance_info=lambda: {"role": "SddcManager"})
    monkeypatch.setattr(service, "VcfDepotApiClient", lambda *_args, **_kwargs: nullcontext(api))
    monkeypatch.setattr(service, "_sddc_manager_candidates", lambda _api: list(candidates))

    discovered = service.discover_vcf_passwords(
        source_type="sddc_manager",
        address="sddc-manager.example.internal",
        port=443,
        username="admin",
        password="fixture-source-password",
        expected_fingerprint="AA:BB",
    )
    by_id = {candidate.candidate_id: candidate for candidate in discovered}

    assert len({candidate.key for candidate in discovered}) == len(candidates)
    assert by_id["natural-identity-key"].natural_key == reserved_key
    assert by_id["natural-identity-key"].key != reserved_key
    assert by_id[first.candidate_id].key == reserved_key
    assert by_id["natural-identity-key"].key == (
        f"vcf.imported.id_{by_id['natural-identity-key'].identity_id.removeprefix('vcf-')}"
    )
    assert not any(candidate.key.endswith("_2") for candidate in discovered)
    assert all(len(candidate.key) <= 180 and normalize_vault_key(candidate.key) == candidate.key
               for candidate in discovered)


def test_duplicate_long_original_keys_get_bounded_valid_identity_suffixes(monkeypatch):
    """Keep two candidates with a 180-character natural key unique and importable.

    Args:
        monkeypatch: Pytest fixture used to replace the source API and discovery result.
    """
    from types import SimpleNamespace

    long_key = "vcf." + "a" * 176
    candidates = [
        service.VcfPasswordCandidate(
            "long-key-a", long_key, "Long key A", "vcf_password", "admin", "resource",
            "fixture-long-password-a",
        ),
        service.VcfPasswordCandidate(
            "long-key-b", long_key, "Long key B", "vcf_password", "admin", "resource",
            "fixture-long-password-b",
        ),
    ]
    api = SimpleNamespace(appliance_info=lambda: {"role": "SddcManager"})
    monkeypatch.setattr(service, "VcfDepotApiClient", lambda *_args, **_kwargs: nullcontext(api))
    monkeypatch.setattr(service, "_sddc_manager_candidates", lambda _api: list(candidates))

    discovered = service.discover_vcf_passwords(
        source_type="sddc_manager",
        address="sddc-manager.example.internal",
        port=443,
        username="admin",
        password="fixture-source-password",
        expected_fingerprint="AA:BB",
    )

    assert len({candidate.key for candidate in discovered}) == 2
    assert all(candidate.natural_key == long_key for candidate in discovered)
    assert all(candidate.key == f"vcf.imported.id_{candidate.identity_id.removeprefix('vcf-')}"
               for candidate in discovered)
    assert all(len(candidate.key) <= 180 and normalize_vault_key(candidate.key) == candidate.key
               for candidate in discovered)
    assert {candidate.candidate_id: candidate.value for candidate in discovered} == {
        "long-key-a": "fixture-long-password-a",
        "long-key-b": "fixture-long-password-b",
    }


def test_unique_overlong_original_key_is_bounded_and_valid(monkeypatch):
    """Bound an overlong natural key even when no other candidate shares it.

    Args:
        monkeypatch: Pytest fixture used to replace the source API and discovery result.
    """
    from types import SimpleNamespace

    original_key = "vcf." + "b" * 177
    candidate = service.VcfPasswordCandidate(
        "unique-overlong", original_key, "Unique overlong key", "vcf_password",
        "admin", "resource", "fixture-unique-long-password",
    )
    api = SimpleNamespace(appliance_info=lambda: {"role": "SddcManager"})
    monkeypatch.setattr(service, "VcfDepotApiClient", lambda *_args, **_kwargs: nullcontext(api))
    monkeypatch.setattr(service, "_sddc_manager_candidates", lambda _api: [candidate])

    discovered = service.discover_vcf_passwords(
        source_type="sddc_manager",
        address="sddc-manager.example.internal",
        port=443,
        username="admin",
        password="fixture-source-password",
        expected_fingerprint="AA:BB",
    )

    assert len(discovered) == 1
    assert discovered[0].candidate_id == candidate.candidate_id
    assert discovered[0].natural_key == original_key
    assert discovered[0].key == f"vcf.imported.id_{candidate.identity_id.removeprefix('vcf-')}"
    assert discovered[0].key != original_key
    assert len(discovered[0].key) <= 180
    assert normalize_vault_key(discovered[0].key) == discovered[0].key
    assert discovered[0].value == candidate.value


def test_duplicate_selection_identity_fails_closed_during_key_allocation(monkeypatch):
    """Reject duplicate browser selection identities rather than ambiguously importing.

    Args:
        monkeypatch: Pytest fixture used to replace the source API and discovery result.
    """
    from types import SimpleNamespace

    candidates = [
        service.VcfPasswordCandidate(
            "duplicate-id", "vcf.first.admin", "First", "vcf_password", "admin", "first", "fixture-a",
        ),
        service.VcfPasswordCandidate(
            "duplicate-id", "vcf.second.admin", "Second", "vcf_password", "admin", "second", "fixture-b",
        ),
    ]
    api = SimpleNamespace(appliance_info=lambda: {"role": "SddcManager"})
    monkeypatch.setattr(service, "VcfDepotApiClient", lambda *_args, **_kwargs: nullcontext(api))
    monkeypatch.setattr(service, "_sddc_manager_candidates", lambda _api: list(candidates))

    with pytest.raises(VcfDepotTargetError, match="duplicate credential identities"):
        service.discover_vcf_passwords(
            source_type="sddc_manager",
            address="sddc-manager.example.internal",
            port=443,
            username="admin",
            password="fixture-source-password",
            expected_fingerprint="AA:BB",
        )


@pytest.mark.parametrize(
    "field, changed_value",
    [
        ("key", "vcf.changed.key"),
        ("description", "Updated reviewed description"),
        ("secret_type", "esx_password"),
        ("username", "updated-user"),
        ("resource_name", "updated-resource.example.internal"),
        ("uris", ("https://updated.example.internal",)),
    ],
)
def test_selection_identity_binds_reviewed_metadata_but_canonical_identity_is_stable(field, changed_value):
    """Invalidate a reviewed selection token on metadata drift without changing source identity.

    Args:
        field: Candidate metadata field changed after inspection.
        changed_value: Updated value for the selected metadata field.
    """
    from dataclasses import replace

    candidate = service.VcfPasswordCandidate(
        "stable-source-credential",
        "vcf.imported.id_source",
        "Original description",
        "vcf_password",
        "admin",
        "manager.example.internal",
        "fixture-password-original",
        ("https://manager.example.internal",),
    )
    changed = replace(candidate, **{field: changed_value})

    assert changed.selection_id != candidate.selection_id
    assert changed.identity_id == candidate.identity_id
    assert f"vcf.imported.id_{changed.identity_id.removeprefix('vcf-')}" == (
        f"vcf.imported.id_{candidate.identity_id.removeprefix('vcf-')}"
    )


def test_password_only_refresh_keeps_selection_and_canonical_identity_tokens():
    """Allow a password refresh when the source candidate's reviewed metadata is unchanged."""
    from dataclasses import replace

    candidate = service.VcfPasswordCandidate(
        "stable-source-credential",
        "vcf.imported.id_source",
        "Reviewed description",
        "vcf_password",
        "admin",
        "manager.example.internal",
        "fixture-password-old",
        ("https://manager.example.internal",),
    )
    refreshed = replace(candidate, value="fixture-password-current")

    assert refreshed.selection_id == candidate.selection_id
    assert refreshed.identity_id == candidate.identity_id
    assert refreshed.value == "fixture-password-current"


def test_candidate_preview_and_repr_do_not_include_password():
    """Mask even a password accidentally repeated in source metadata."""
    candidate = service.VcfPasswordCandidate("id", "vcf.fixture", "fixture-secret", "vcf_password",
                                             "admin", "fixture.lab.example", "fixture-secret")
    assert "fixture-secret" not in repr(candidate)
    assert "fixture-secret" not in repr(candidate.sanitized())
