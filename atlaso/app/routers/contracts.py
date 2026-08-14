"""Characterize Atlaso route and OpenAPI contracts deterministically."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any, cast

from fastapi import APIRouter, FastAPI
from starlette.routing import compile_path

from atlaso.app.routers.registry import RouteIdentity

_WEBSOCKET_METHOD = "WEBSOCKET"
_OPAQUE_METHOD = "*"

type RouteContractRecord = dict[str, object]


class RouterContractError(ValueError):
    """Report route or OpenAPI characterization drift."""


def _routing_plane(path: str) -> str:
    """Return the stable external routing plane for a path.

    Args:
        path: Fully prefixed application route path.

    Returns:
        Stable routing plane name.
    """
    if path == "/api/v1" or path.startswith("/api/v1/"):
        return "api_v1"
    if path == "/ui/management" or path.startswith("/ui/management/"):
        return "ui_management"
    if path == "/ui/public" or path.startswith("/ui/public/"):
        return "ui_public"
    return "protocol"


def _effective_route_sources(app: FastAPI) -> tuple[object, ...]:
    """Return every effective application route in registration order.

    Args:
        app: FastAPI application whose external routes are characterized.

    Returns:
        Direct routes and effective included-router contexts.
    """
    sources: list[object] = []
    for route in app.routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if callable(contexts):
            sources.extend(cast(Sequence[object], contexts()))
        else:
            sources.append(route)
    return tuple(sources)


def _route_record(source: object, *, order: int) -> RouteContractRecord:
    """Return one stable route contract record.

    Args:
        source: Direct route or effective included-router context.
        order: Zero-based effective application route order.

    Returns:
        JSON-serializable stable route metadata.

    Raises:
        RouterContractError: If the route lacks a stable absolute path.
    """
    original = getattr(source, "original_route", source)
    path = getattr(source, "path", "") or getattr(original, "path", "")
    if not isinstance(path, str) or not path.startswith("/"):
        raise RouterContractError(f"route at order {order} has no stable absolute path")

    methods = getattr(source, "methods", None) or getattr(original, "methods", None)
    if methods:
        route_methods = sorted(str(method).upper() for method in methods)
        kind = "http"
    elif type(original).__name__.endswith("WebSocketRoute"):
        route_methods = [_WEBSOCKET_METHOD]
        kind = "websocket"
    else:
        route_methods = [_OPAQUE_METHOD]
        kind = "mount"

    name = getattr(source, "name", "") or getattr(original, "name", "")
    operation_id = getattr(source, "operation_id", None) or getattr(original, "operation_id", None)
    include_in_schema = getattr(source, "include_in_schema", None)
    if include_in_schema is None:
        include_in_schema = getattr(original, "include_in_schema", None)
    return {
        "include_in_schema": include_in_schema,
        "kind": kind,
        "methods": route_methods,
        "name": name,
        "operation_id": operation_id,
        "order": order,
        "path": path,
        "plane": _routing_plane(path),
    }


def _record_identities(record: Mapping[str, object]) -> tuple[RouteIdentity, ...]:
    """Return route-method identities encoded by one record.

    Args:
        record: Route contract record to inspect.

    Returns:
        One identity for every method in the record.

    Raises:
        RouterContractError: If the record is malformed.
    """
    plane = record.get("plane")
    path = record.get("path")
    methods = record.get("methods")
    if not isinstance(plane, str) or not isinstance(path, str) or not isinstance(methods, list):
        raise RouterContractError(f"malformed route contract record: {record!r}")
    if not all(isinstance(method, str) for method in methods):
        raise RouterContractError(f"malformed route methods for {plane} {path}: {methods!r}")
    return tuple(RouteIdentity(plane=plane, path=path, method=method) for method in methods)


def _validate_unique_routes(records: Sequence[Mapping[str, object]]) -> None:
    """Reject duplicate route-method identities.

    Args:
        records: Route contract records to validate.

    Raises:
        RouterContractError: If one plane/path/method identity occurs twice.
    """
    identities: dict[RouteIdentity, int] = {}
    for index, record in enumerate(records):
        for identity in _record_identities(record):
            previous = identities.get(identity)
            if previous is not None:
                raise RouterContractError(
                    "duplicate route registration "
                    f"({identity.plane!r}, {identity.path!r}, {identity.method!r}) "
                    f"at orders {previous} and {index}"
                )
            identities[identity] = index


def _validate_catch_all_order(records: Sequence[Mapping[str, object]]) -> None:
    """Reject catch-all routes that shadow later fixed handlers.

    Args:
        records: Route contract records in effective application order.

    Raises:
        RouterContractError: If a parameterized route shadows a later fixed route with another handler.
    """
    for index, record in enumerate(records):
        path = record.get("path")
        plane = record.get("plane")
        name = record.get("name")
        methods = record.get("methods")
        if not isinstance(path, str) or "{" not in path or not isinstance(methods, list):
            continue
        path_regex, _, _ = compile_path(path)
        for later in records[index + 1 :]:
            later_path = later.get("path")
            later_methods = later.get("methods")
            if (
                later.get("plane") != plane
                or later.get("name") == name
                or not isinstance(later_path, str)
                or "{" in later_path
                or not isinstance(later_methods, list)
                or not set(methods).intersection(later_methods)
                or path_regex.fullmatch(later_path) is None
            ):
                continue
            raise RouterContractError(
                f"parameterized route {path!r} at order {index} must follow fixed route {later_path!r}"
            )


def build_route_inventory(app: FastAPI) -> list[RouteContractRecord]:
    """Return and validate the complete effective application route inventory.

    Args:
        app: FastAPI application whose routes are characterized.

    Returns:
        Stable route records in effective registration order.

    Raises:
        RouterContractError: If duplicate or shadowing registrations exist.
    """
    inventory = [
        _route_record(source, order=order)
        for order, source in enumerate(_effective_route_sources(app))
    ]
    _validate_unique_routes(inventory)
    _validate_catch_all_order(inventory)
    return inventory


def validate_route_inventory(
    actual: Sequence[Mapping[str, object]],
    expected: Sequence[Mapping[str, object]],
) -> None:
    """Require exact route inventory membership and order.

    Args:
        actual: Newly generated route contract records.
        expected: Checked-in route contract baseline.

    Raises:
        RouterContractError: If a route is duplicated, omitted, added, or reordered.
    """
    _validate_unique_routes(actual)
    _validate_catch_all_order(actual)
    if len(actual) != len(expected):
        raise RouterContractError(
            f"route inventory length changed: expected {len(expected)}, found {len(actual)}"
        )
    for index, (actual_record, expected_record) in enumerate(zip(actual, expected, strict=True)):
        if actual_record != expected_record:
            raise RouterContractError(
                f"route inventory changed at order {index}: expected {dict(expected_record)!r}, "
                f"found {dict(actual_record)!r}"
            )


def normalize_openapi_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Return an OpenAPI schema without generated application-version metadata.

    Args:
        schema: Generated OpenAPI document to normalize.

    Returns:
        A deep copy that omits only ``info.version``.

    Raises:
        RouterContractError: If the generated schema lacks an object-valued info section.
    """
    normalized = deepcopy(dict(schema))
    info = normalized.get("info")
    if not isinstance(info, dict):
        raise RouterContractError("OpenAPI schema has no object-valued info section")
    info.pop("version", None)
    return normalized


def normalized_openapi(app: FastAPI) -> dict[str, Any]:
    """Return the normalized generated OpenAPI document for an application.

    Args:
        app: FastAPI application whose OpenAPI contract is characterized.

    Returns:
        Generated OpenAPI with only application-version metadata removed.
    """
    return normalize_openapi_schema(app.openapi())


def included_router_count(app: FastAPI, router: APIRouter) -> int:
    """Return how many times one facade router is included directly.

    Args:
        app: FastAPI application whose top-level includes are inspected.
        router: Facade router object expected exactly once.

    Returns:
        Number of direct includes for the exact router object.
    """
    return sum(getattr(route, "original_router", None) is router for route in app.routes)
