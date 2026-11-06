"""Read-only VCF Operations inventory discovery for backup planning."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

_PAGE_SIZE = 100
_MAX_PAGES = 50
_MAX_RECORDS = _PAGE_SIZE * _MAX_PAGES
_MANAGER_QUERY = "/suite-api/api/resources/query?page=0&pageSize=100"
_MANAGER_QUERY_BODY = {
    "adapterKind": ["VcfAdapter"],
    "resourceKind": ["VcfAdapterInstance"],
}
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class InventoryError(ValueError):
    """Sanitized error for an invalid or incomplete Operations inventory."""


Request = Callable[[str, str, Any], Any]


def discover_inventory(request: Request) -> dict[str, Any]:
    """Discover Operations-managed SDDC Managers and their vCenter domains.

    The supplied callback must use the already authenticated, fingerprint-pinned
    Operations session. This function makes read-only requests and does not
    accept or return appliance credentials.

    Args:
        request: Callable accepting an HTTP method, API path, and JSON body.

    Returns:
        Allowlisted manager and vCenter inventory records suitable for UI
        selection. Secret-bearing Operations fields are not projected.

    Raises:
        InventoryError: If any response is malformed, ambiguous, unsafe, or
            incomplete.
    """
    if not callable(request):
        raise InventoryError("Operations inventory request is unavailable")

    manager_rows = _collect_pages(
        request,
        lambda page: (
            _MANAGER_QUERY
            if page == 0
            else f"/suite-api/api/resources/query?page={page}&pageSize={_PAGE_SIZE}"
        ),
        _MANAGER_QUERY_BODY,
    )
    managers: list[dict[str, Any]] = []
    seen_resource_ids: set[str] = set()
    seen_manager_uuids: set[str] = set()
    seen_manager_endpoints: dict[tuple[str, int], str] = {}

    for row in manager_rows:
        if not isinstance(row, Mapping):
            raise InventoryError("Operations returned a malformed manager record")
        key = row.get("resourceKey")
        if not isinstance(key, Mapping):
            raise InventoryError("Operations returned a malformed manager record")
        if key.get("adapterKindKey") != "VcfAdapter" or key.get(
            "resourceKindKey"
        ) != "VcfAdapterInstance":
            raise InventoryError("Operations returned an unexpected manager record")
        resource_id = _uuid(row.get("identifier"), "manager resource identifier")
        if resource_id in seen_resource_ids:
            raise InventoryError("Operations returned duplicate manager records")
        seen_resource_ids.add(resource_id)
        identifiers = _identifiers(key.get("resourceIdentifiers"))
        manager_uuid = _uuid(
            identifiers.get("SDDCManager_uuid"), "manager UUID"
        )
        if manager_uuid in seen_manager_uuids:
            raise InventoryError("Operations returned ambiguous manager identities")
        seen_manager_uuids.add(manager_uuid)
        address, port = _host_port(
            identifiers.get("SDDCManager_Hostname"), "manager endpoint"
        )
        prior_uuid = seen_manager_endpoints.get((address, port))
        if prior_uuid is not None and prior_uuid != manager_uuid:
            raise InventoryError("Operations returned conflicting manager aliases")
        seen_manager_endpoints[(address, port)] = manager_uuid
        name = _display_name(key.get("name"), "manager name")
        domains = _discover_domains(request, resource_id)
        managers.append(
            {
                "resource_id": resource_id,
                "manager_uuid": manager_uuid,
                "name": name,
                "address": address,
                "port": port,
                "domains": domains,
            }
        )

    managers.sort(key=lambda item: (item["manager_uuid"], item["resource_id"]))
    vcenters = _project_vcenters(managers)
    return {"managers": managers, "vcenters": vcenters}


def _discover_domains(request: Request, manager_id: str) -> list[dict[str, Any]]:
    """Read and validate VCF domain children for one Operations resource.

    Args:
        request: Authenticated Operations request callback.
        manager_id: Canonical UUID of the discovered manager resource.

    Returns:
        Stable, allowlisted VCF domain records.
    """
    rows = _collect_pages(
        request,
        lambda page: (
            f"/suite-api/api/resources/{manager_id}/relationships"
            f"?relationshipType=CHILD&page={page}&pageSize={_PAGE_SIZE}"
        ),
        None,
    )
    domains: list[dict[str, Any]] = []
    resource_ids: set[str] = set()
    domain_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise InventoryError("Operations returned a malformed relationship")
        key = row.get("resourceKey")
        if not isinstance(key, Mapping):
            raise InventoryError("Operations returned a malformed relationship")
        if key.get("adapterKindKey") != "VcfAdapter" or key.get(
            "resourceKindKey"
        ) != "VCFDomain":
            continue
        resource_id = _uuid(row.get("identifier"), "domain resource identifier")
        if resource_id in resource_ids:
            raise InventoryError("Operations returned duplicate domain records")
        resource_ids.add(resource_id)
        identifiers = _identifiers(key.get("resourceIdentifiers"))
        domain_id = _uuid(identifiers.get("VcfDomainId"), "domain identifier")
        if domain_id in domain_ids:
            raise InventoryError("Operations returned duplicate domain identities")
        domain_ids.add(domain_id)
        address, port = _host_port(identifiers.get("VcUrl"), "vCenter endpoint")
        domain_type = _display_name(identifiers.get("Type"), "domain type")
        domains.append(
            {
                "resource_id": resource_id,
                "domain_id": domain_id,
                "name": _display_name(key.get("name"), "domain name"),
                "type": domain_type,
                "vcenter_address": address,
                "vcenter_port": port,
            }
        )
    domains.sort(key=lambda item: (item["domain_id"], item["resource_id"]))
    return domains


def _collect_pages(
    request: Request,
    path_for_page: Callable[[int], str],
    body: Any,
) -> list[Any]:
    """Collect a bounded, internally consistent Operations resource page set.

    Args:
        request: Authenticated Operations request callback.
        path_for_page: Path builder for a zero-based page number.
        body: JSON body sent with every page request, if required.

    Returns:
        Resource rows in Operations page order.
    """
    rows: list[Any] = []
    expected_total: int | None = None
    for page in range(_MAX_PAGES):
        try:
            response = request(
                "POST" if body is not None else "GET", path_for_page(page), body
            )
        except Exception:  # noqa: BLE001 - suppress transport details that may contain secrets.
            raise InventoryError("Operations inventory request failed") from None
        payload = _unwrap(response)
        if not isinstance(payload, Mapping):
            raise InventoryError("Operations returned an invalid inventory page")
        page_info = payload.get("pageInfo")
        page_rows = payload.get("resourceList")
        if not isinstance(page_info, Mapping) or not isinstance(page_rows, list):
            raise InventoryError("Operations returned incomplete inventory pagination")
        current, page_size, total = (
            page_info.get("page"),
            page_info.get("pageSize"),
            page_info.get("totalCount"),
        )
        if (
            type(current) is not int
            or current != page
            or type(page_size) is not int
            or page_size != _PAGE_SIZE
            or type(total) is not int
            or not 0 <= total <= _MAX_RECORDS
        ):
            raise InventoryError("Operations returned inconsistent inventory pagination")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise InventoryError("Operations inventory changed during pagination")
        expected_rows = min(_PAGE_SIZE, max(total - page * _PAGE_SIZE, 0))
        if len(page_rows) != expected_rows:
            raise InventoryError("Operations returned an incomplete inventory page")
        rows.extend(page_rows)
        if len(rows) == total:
            return rows
    raise InventoryError("Operations inventory exceeds the page limit")


def _unwrap(response: Any) -> Any:
    """Accept callback payloads and the existing status/payload response shape.

    Args:
        response: Result returned by the injected request callback.

    Returns:
        Decoded API payload.
    """
    if (
        isinstance(response, tuple)
        and len(response) == 2
        and type(response[0]) is int
    ):
        status, payload = response
        if not 200 <= status < 300:
            raise InventoryError("Operations inventory request failed")
        return payload
    return response


def _identifiers(value: Any) -> dict[str, str]:
    """Validate and index a resource's named identifier list.

    Args:
        value: Operations resourceIdentifiers response field.

    Returns:
        Mapping from unique identifier names to their string values.
    """
    if not isinstance(value, list):
        raise InventoryError("Operations returned malformed resource identifiers")
    result: dict[str, str] = {}
    for item in value:
        if not isinstance(item, Mapping):
            raise InventoryError("Operations returned malformed resource identifiers")
        identifier_type = item.get("identifierType")
        if not isinstance(identifier_type, Mapping):
            raise InventoryError("Operations returned malformed resource identifiers")
        name, content = identifier_type.get("name"), item.get("value")
        if (
            not isinstance(name, str)
            or not name
            or name in result
            or not isinstance(content, str)
        ):
            raise InventoryError("Operations returned duplicate or malformed identifiers")
        result[name] = content
    return result


def _uuid(value: Any, label: str) -> str:
    """Validate and canonicalize an Operations UUID field.

    Args:
        value: Candidate UUID value.
        label: Public field label used in a sanitized error.

    Returns:
        Lowercase canonical UUID.
    """
    if not isinstance(value, str):
        raise InventoryError(f"Operations returned an invalid {label}")
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        raise InventoryError(f"Operations returned an invalid {label}") from None


def _display_name(value: Any, label: str) -> str:
    """Validate a bounded, printable inventory label.

    Args:
        value: Candidate public display value.
        label: Public field label used in a sanitized error.

    Returns:
        A trimmed display value.
    """
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise InventoryError(f"Operations returned an invalid {label}")
    return value.strip()


def _host_port(value: Any, label: str) -> tuple[str, int]:
    """Parse a bare appliance address or a narrowly allowed HTTPS URL.

    Args:
        value: Operations hostname, optional host:port, or HTTPS URL.
        label: Public endpoint label used in a sanitized error.

    Returns:
        Normalized host and TCP port.
    """
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
        or "\\" in value
    ):
        raise InventoryError(f"Operations returned an invalid {label}")
    if value.lower().startswith("https://"):
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme.lower() != "https"
                or parsed.username is not None
                or parsed.password is not None
                or "?" in value
                or "#" in value
                or parsed.path not in ("", "/sdk")
            ):
                raise ValueError
            host = parsed.hostname
            port = parsed.port or 443
        except ValueError:
            raise InventoryError(f"Operations returned an invalid {label}") from None
        if host is None:
            raise InventoryError(f"Operations returned an invalid {label}")
        normalized = _normalize_host(host, label)
        if not 1 <= port <= 65535:
            raise InventoryError(f"Operations returned an invalid {label}")
        return normalized, port
    if "://" in value or any(char in value for char in "/@?#%"):
        raise InventoryError(f"Operations returned an invalid {label}")
    try:
        parsed = urlsplit(f"//{value}")
        if parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
            raise ValueError
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError:
        raise InventoryError(f"Operations returned an invalid {label}") from None
    if host is None:
        raise InventoryError(f"Operations returned an invalid {label}")
    normalized = _normalize_host(host, label)
    if not 1 <= port <= 65535:
        raise InventoryError(f"Operations returned an invalid {label}")
    return normalized, port


def _normalize_host(host: str, label: str) -> str:
    """Normalize a DNS name or IP address while rejecting ambiguous syntax.

    Args:
        host: Host component from a constrained endpoint value.
        label: Public endpoint label used in a sanitized error.

    Returns:
        Lowercase IDNA DNS name or canonical IP address.
    """
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", host):
        raise InventoryError(f"Operations returned an invalid {label}")
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise InventoryError(f"Operations returned an invalid {label}") from None
    labels = ascii_host.split(".")
    if (
        not ascii_host
        or len(ascii_host) > 253
        or not all(_DNS_LABEL.fullmatch(part) for part in labels)
    ):
        raise InventoryError(f"Operations returned an invalid {label}")
    return ascii_host


def _project_vcenters(managers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate vCenters while retaining all manager/domain relationships.

    Args:
        managers: Validated manager records with their discovered domains.

    Returns:
        Stable vCenter records with public ownership metadata.
    """
    collected: dict[tuple[str, int], dict[str, Any]] = {}
    for manager in managers:
        for domain in manager["domains"]:
            endpoint = (domain["vcenter_address"], domain["vcenter_port"])
            item = collected.setdefault(
                endpoint,
                {
                    "address": endpoint[0],
                    "port": endpoint[1],
                    "name": endpoint[0],
                    "manager_resource_ids": set(),
                    "domain_ids": set(),
                },
            )
            item["manager_resource_ids"].add(manager["resource_id"])
            item["domain_ids"].add(domain["domain_id"])
    result: list[dict[str, Any]] = []
    for endpoint, item in collected.items():
        digest = hashlib.sha256(f"{endpoint[0]}:{endpoint[1]}".encode()).hexdigest()
        result.append(
            {
                "id": f"vcenter-{digest}",
                "address": item["address"],
                "port": item["port"],
                "name": item["name"],
                "manager_resource_ids": sorted(item["manager_resource_ids"]),
                "domain_ids": sorted(item["domain_ids"]),
            }
        )
    result.sort(key=lambda item: (item["address"], item["port"], item["id"]))
    return result
