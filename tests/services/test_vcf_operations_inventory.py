"""Safety and contract tests for Operations-managed inventory discovery."""

from __future__ import annotations

import json

import pytest

from atlaso.app.services.vcf_operations_inventory import (
    InventoryError,
    discover_inventory,
)

MANAGER_ID = "d9e6cb38-4aad-4d70-863a-0d09b5536059"
MANAGER_UUID = "7fb33718-c559-4442-86e4-1e08f8fca7a3"
DOMAIN_RESOURCE_ID = "cceb9fce-49c5-40a1-9a33-7f05544c0979"
DOMAIN_ID = "ba3761c1-72c4-4090-8549-0997b32c63fe"


def _identifiers(**values: str) -> list[dict[str, object]]:
    """Build Operations resourceIdentifiers in their wire representation.

    Args:
        **values: Identifier names and their synthetic string values.
    """
    return [
        {"identifierType": {"name": name}, "value": value}
        for name, value in values.items()
    ]


def _manager(
    resource_id: str = MANAGER_ID,
    manager_uuid: str = MANAGER_UUID,
    hostname: str = "sddcm.lab.internal",
) -> dict[str, object]:
    """Build the captured VCF Adapter manager resource shape.

    Args:
        resource_id: Synthetic Operations resource UUID.
        manager_uuid: Native SDDC Manager UUID identifier.
        hostname: Operations-reported manager endpoint value.
    """
    return {
        "identifier": resource_id,
        "credentialInstanceId": "secret-credential-reference",
        "resourceKey": {
            "name": "max-dev-pa-01",
            "adapterKindKey": "VcfAdapter",
            "resourceKindKey": "VcfAdapterInstance",
            "resourceIdentifiers": _identifiers(
                SDDCManager_Hostname=hostname,
                SDDCManager_uuid=manager_uuid,
            ),
        },
    }


def _domain(
    resource_id: str = DOMAIN_RESOURCE_ID,
    domain_id: str = DOMAIN_ID,
    vc_url: str = "vc01.lab.internal",
) -> dict[str, object]:
    """Build the captured VCFDomain child resource shape.

    Args:
        resource_id: Synthetic Operations resource UUID.
        domain_id: Native VCF domain UUID identifier.
        vc_url: Operations-reported vCenter address.
    """
    return {
        "identifier": resource_id,
        "credentialInstanceId": "another-secret-reference",
        "resourceKey": {
            "name": "max-dev-pa-mgt-01",
            "adapterKindKey": "VcfAdapter",
            "resourceKindKey": "VCFDomain",
            "resourceIdentifiers": _identifiers(
                NsxUrl="nsx-vip.lab.internal",
                SDDCManager_Hostname="sddcm.lab.internal",
                Type="MANAGEMENT",
                VcfDomainId=domain_id,
                VcUrl=vc_url,
            ),
        },
    }


def _page(rows: list[object], page: int, total: int) -> dict[str, object]:
    """Build one captured Operations page envelope.

    Args:
        rows: Resource rows in the page.
        page: Zero-based current page.
        total: Declared count across all pages.
    """
    return {
        "resourceList": rows,
        "pageInfo": {"page": page, "pageSize": 100, "totalCount": total},
    }


def _fixture_pages() -> dict[str, object]:
    """Return synthetic query and relationship pages based on the captured proof."""
    irrelevant = {
        "identifier": "d77621b4-ac83-4cd9-85a3-22f82cfb45ee",
        "resourceKey": {
            "name": "sddcm.lab.internal",
            "adapterKindKey": "VMWARE_INFRA_HEALTH",
            "resourceKindKey": "VCF_DEPLOYMENT",
            "resourceIdentifiers": [],
        },
    }
    return {
        "POST /suite-api/api/resources/query?page=0&pageSize=100": _page(
            [_manager()], 0, 1
        ),
        f"GET /suite-api/api/resources/{MANAGER_ID}/relationships?relationshipType=CHILD&page=0&pageSize=100": _page(
            [_domain(), irrelevant], 0, 2
        ),
    }


class RequestRecorder:
    """Return synthetic Operations pages while recording bounded requests."""

    def __init__(self, responses: dict[str, object]) -> None:
        """Initialize the recorder with route-keyed response payloads.

        Args:
            responses: Responses keyed by method and exact path.
        """
        self.responses = responses
        self.calls: list[tuple[str, str, object]] = []

    def __call__(self, method: str, path: str, body: object) -> object:
        """Record one request and return its synthetic response.

        Args:
            method: HTTP method requested by the inventory client.
            path: Exact Operations path and query string.
            body: JSON body passed by the inventory client.
        """
        self.calls.append((method, path, body))
        return self.responses[f"{method} {path}"]


def test_discovery_projects_manager_and_connected_vcenter_without_secrets():
    request = RequestRecorder(_fixture_pages())

    result = discover_inventory(request)

    assert result["managers"] == [
        {
            "resource_id": MANAGER_ID,
            "manager_uuid": MANAGER_UUID,
            "name": "max-dev-pa-01",
            "address": "sddcm.lab.internal",
            "port": 443,
            "domains": [
                {
                    "resource_id": DOMAIN_RESOURCE_ID,
                    "domain_id": DOMAIN_ID,
                    "name": "max-dev-pa-mgt-01",
                    "type": "MANAGEMENT",
                    "vcenter_address": "vc01.lab.internal",
                    "vcenter_port": 443,
                }
            ],
        }
    ]
    vcenter = result["vcenters"][0]
    assert vcenter["address"] == "vc01.lab.internal"
    assert vcenter["port"] == 443
    assert vcenter["manager_resource_ids"] == [MANAGER_ID]
    assert vcenter["domain_ids"] == [DOMAIN_ID]
    assert len(vcenter["id"]) == len("vcenter-") + 64
    assert request.calls == [
        (
            "POST",
            "/suite-api/api/resources/query?page=0&pageSize=100",
            {"adapterKind": ["VcfAdapter"], "resourceKind": ["VcfAdapterInstance"]},
        ),
        (
            "GET",
            f"/suite-api/api/resources/{MANAGER_ID}/relationships?relationshipType=CHILD&page=0&pageSize=100",
            None,
        ),
    ]
    serialized = json.dumps(result)
    assert "credentialInstanceId" not in serialized
    assert "secret-credential-reference" not in serialized
    assert "another-secret-reference" not in serialized
    assert "nsx-vip" not in serialized


def test_discovery_collects_multiple_pages_and_rejects_changed_total():
    second_id = "016d962c-904f-4b8a-810b-0ac158237c20"
    first_rows = [
        _manager(
            f"00000000-0000-0000-0000-{index:012d}",
            f"10000000-0000-0000-0000-{index:012d}",
            f"sddcm-{index}.lab.internal",
        )
        for index in range(100)
    ]
    second_row = _manager(second_id, "cbb27c39-4c4a-47f0-a801-a972cc33e83c")
    responses: dict[str, object] = {
        "POST /suite-api/api/resources/query?page=0&pageSize=100": _page(
            first_rows, 0, 101
        ),
        "POST /suite-api/api/resources/query?page=1&pageSize=100": _page(
            [second_row], 1, 101
        ),
    }
    for row in [*first_rows, second_row]:
        row_id = row["identifier"]
        responses[
            f"GET /suite-api/api/resources/{row_id}/relationships?relationshipType=CHILD&page=0&pageSize=100"
        ] = _page([], 0, 0)
    request = RequestRecorder(responses)

    result = discover_inventory(request)

    assert len(result["managers"]) == 101
    assert len(request.calls) == 103

    responses["POST /suite-api/api/resources/query?page=1&pageSize=100"] = _page(
        [second_row], 1, 102
    )
    with pytest.raises(InventoryError, match="changed during pagination"):
        discover_inventory(RequestRecorder(responses))


@pytest.mark.parametrize(
    "response, message",
    [
        (_page([_manager(), _manager()], 0, 2), "duplicate manager"),
        (_page([_manager("not-a-uuid")], 0, 1), "invalid manager resource"),
        (_page([_manager(), _manager("016d962c-904f-4b8a-810b-0ac158237c20")], 0, 2), "ambiguous manager"),
        (
            _page(
                [
                    {
                        **_manager(),
                        "resourceKey": {
                            **_manager()["resourceKey"],
                            "resourceIdentifiers": [
                                *_identifiers(SDDCManager_Hostname="sddcm.lab.internal"),
                                *_identifiers(SDDCManager_Hostname="other.lab.internal"),
                                *_identifiers(SDDCManager_uuid=MANAGER_UUID),
                            ],
                        },
                    }
                ],
                0,
                1,
            ),
            "duplicate or malformed identifiers",
        ),
    ],
)
def test_discovery_rejects_duplicate_or_malformed_manager_records(response, message):
    """Bind the selected Operations test context.

    Args:
        response: Malformed or duplicated Operations inventory.
        message: Expected sanitized refusal.
    """
    request = RequestRecorder(_fixture_pages())
    request.responses["POST /suite-api/api/resources/query?page=0&pageSize=100"] = response

    with pytest.raises(InventoryError, match=message):
        discover_inventory(request)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://vc01.lab.internal",
        "https://user:password@vc01.lab.internal/sdk",
        "https://vc01.lab.internal/sdk?token=secret",
        "https://vc01.lab.internal/other",
        "vc01.lab.internal:70000",
        "bad host",
        "256.256.256.256",
        "https://vc01.lab.internal/#fragment",
        "https://[not-ip]/sdk",
    ],
)
def test_discovery_rejects_unsafe_vcenter_endpoints(endpoint):
    """Bind the selected Operations test context.

    Args:
        endpoint: Unsafe native vCenter endpoint.
    """
    request = RequestRecorder(_fixture_pages())
    path = f"GET /suite-api/api/resources/{MANAGER_ID}/relationships?relationshipType=CHILD&page=0&pageSize=100"
    request.responses[path] = _page([_domain(vc_url=endpoint)], 0, 1)

    with pytest.raises(InventoryError, match="invalid vCenter endpoint"):
        discover_inventory(request)


def test_discovery_normalizes_safe_https_vcenter_url():
    request = RequestRecorder(_fixture_pages())
    path = f"GET /suite-api/api/resources/{MANAGER_ID}/relationships?relationshipType=CHILD&page=0&pageSize=100"
    request.responses[path] = _page([_domain(vc_url="https://VC01.lab.internal:8443/sdk")], 0, 1)

    result = discover_inventory(request)

    assert result["vcenters"][0]["address"] == "vc01.lab.internal"
    assert result["vcenters"][0]["port"] == 8443


def test_discovery_deduplicates_vcenters_and_aggregates_domain_ownership():
    request = RequestRecorder(_fixture_pages())
    path = f"GET /suite-api/api/resources/{MANAGER_ID}/relationships?relationshipType=CHILD&page=0&pageSize=100"
    second_domain_id = "2a8838de-5906-4855-985e-c46f361dc4d0"
    second_domain_resource = "79b68d0f-ea74-4786-8e61-61f565a83e19"
    request.responses[path] = _page(
        [
            _domain(),
            _domain(
                resource_id=second_domain_resource,
                domain_id=second_domain_id,
                vc_url="https://VC01.lab.internal:443/sdk",
            ),
        ],
        0,
        2,
    )

    result = discover_inventory(request)

    assert len(result["vcenters"]) == 1
    assert result["vcenters"][0]["domain_ids"] == sorted(
        [DOMAIN_ID, second_domain_id]
    )
    assert sorted(
        domain["resource_id"] for domain in result["managers"][0]["domains"]
    ) == sorted([DOMAIN_RESOURCE_ID, second_domain_resource])


def test_discovery_rejects_duplicate_domain_identities():
    request = RequestRecorder(_fixture_pages())
    path = f"GET /suite-api/api/resources/{MANAGER_ID}/relationships?relationshipType=CHILD&page=0&pageSize=100"
    request.responses[path] = _page(
        [
            _domain(),
            _domain(
                resource_id="79b68d0f-ea74-4786-8e61-61f565a83e19",
                vc_url="vc02.lab.internal",
            ),
        ],
        0,
        2,
    )

    with pytest.raises(InventoryError, match="duplicate domain identities"):
        discover_inventory(request)


@pytest.mark.parametrize(
    "page",
    [
        {"resourceList": [], "pageInfo": {"page": True, "pageSize": 100, "totalCount": 0}},
        {"resourceList": [], "pageInfo": {"page": 0, "pageSize": 99, "totalCount": 0}},
        {"resourceList": [], "pageInfo": {"page": 0, "pageSize": 100, "totalCount": -1}},
        {"resourceList": [_manager()], "pageInfo": {"page": 0, "pageSize": 100, "totalCount": 2}},
        {"resourceList": [], "pageInfo": {"page": 1, "pageSize": 100, "totalCount": 0}},
    ],
)
def test_discovery_rejects_malformed_or_incomplete_pages(page):
    """Bind the selected Operations test context.

    Args:
        page: Malformed or incomplete native pagination envelope.
    """
    request = RequestRecorder(_fixture_pages())
    request.responses["POST /suite-api/api/resources/query?page=0&pageSize=100"] = page

    with pytest.raises(InventoryError):
        discover_inventory(request)
