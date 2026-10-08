"""Test VCF credential discovery without contacting an appliance."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

from atlaso.app.services import vcf_vault_import as service
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
            "adminUserSsoUsername": "administrator@vsphere.local",
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


def test_candidate_preview_and_repr_do_not_include_password():
    """Mask even a password accidentally repeated in source metadata."""
    candidate = service.VcfPasswordCandidate("id", "vcf.fixture", "fixture-secret", "vcf_password",
                                             "admin", "fixture.lab.example", "fixture-secret")
    assert "fixture-secret" not in repr(candidate)
    assert "fixture-secret" not in repr(candidate.sanitized())
