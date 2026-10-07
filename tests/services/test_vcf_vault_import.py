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
        requests: list[httpx.Request] = []

        def transport(request: httpx.Request) -> httpx.Response:
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
    """Accept list and object inventory envelopes, including empty inventories."""
    api, _requests = fake_api_factory(lambda _request: (200, payload))

    assert [row.get("id") for row in service._credential_rows(api)] == expected_ids


def test_credential_rows_traverses_documented_pages(fake_api_factory):
    """Follow pageNumber metadata and use the returned page size after page zero."""
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
    """Do not present a repeated or truncated inventory as complete."""
    index = 0

    def handler(_request: httpx.Request) -> tuple[int, Any]:
        nonlocal index
        payload = responses[index]
        index += 1
        return 200, payload

    api, _requests = fake_api_factory(handler)

    with pytest.raises(VcfDepotTargetError, match=message):
        service._credential_rows(api)


def test_masked_password_retrieval_uses_encoded_id_and_returns_no_secret_in_preview(fake_api_factory):
    """Fetch a masked listed credential by encoded ID and expose only its safe preview."""
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
    """Summarize inaccessible credentials without reflecting response diagnostics."""
    listed = {"elements": [{"id": "masked-id", "password": "••••", "username": "svc"}]}
    vendor_message = "fixture vendor detail diagnostic"

    def handler(request: httpx.Request) -> tuple[int, Any]:
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
    """Never pair a listed account/resource with a detail record of another identity."""
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
    """Map resource names and verified IP metadata to the credential protocol."""
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
    """Do not turn URLs, userinfo, paths, or query strings into vault destinations."""
    assert service._resource_uris(resource, "API") == ()


def test_unsupported_credential_type_is_counted_and_not_imported(fake_api_factory):
    """Expose a safe skip reason for credentials Atlaso cannot model."""
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
    """Use each nested component's own endpoint and label installer scope as latest-only."""
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
    """Keep unknown passwords importable without associating an unrelated web endpoint."""
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


def test_candidate_preview_and_repr_do_not_include_password():
    """Mask even a password accidentally repeated in source metadata."""
    candidate = service.VcfPasswordCandidate("id", "vcf.fixture", "fixture-secret", "vcf_password",
                                             "admin", "fixture.lab.example", "fixture-secret")
    assert "fixture-secret" not in repr(candidate)
    assert "fixture-secret" not in repr(candidate.sanitized())
