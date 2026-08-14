"""Characterize Atlaso route and OpenAPI contracts deterministically."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

from fastapi import APIRouter, FastAPI

from atlaso.app.routers.registry import (
    RouteIdentity,
    RouterRegistryError,
    compatible_route_shadows,
    included_facade_routers,
    route_paths_overlap,
)

_WEBSOCKET_METHOD = "WEBSOCKET"
_OPAQUE_METHOD = "*"

type RouteContractRecord = dict[str, object]


class RouterContractError(ValueError):
    """Report route or OpenAPI characterization drift."""


@dataclass(frozen=True)
class _EffectiveRoute:
    """Retain stable metadata and explicit compatibility declarations."""

    record: RouteContractRecord
    allowed_shadows: frozenset[tuple[str, str]]


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


def _effective_route(source: object, *, order: int) -> _EffectiveRoute:
    """Return one stable route record with compatibility declarations.

    Args:
        source: Direct route or effective included-router context.
        order: Zero-based effective application route order.

    Returns:
        Stable metadata and exact compatibility declarations.

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
    return _EffectiveRoute(
        record={
            "include_in_schema": include_in_schema,
            "kind": kind,
            "methods": route_methods,
            "name": name,
            "operation_id": operation_id,
            "order": order,
            "path": path,
            "plane": _routing_plane(path),
        },
        allowed_shadows=compatible_route_shadows(source),
    )


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


def _overlapping_methods(first: Sequence[object], second: Sequence[object]) -> frozenset[str]:
    """Return concrete methods matched by both route records."""
    first_methods = {method for method in first if isinstance(method, str)}
    second_methods = {method for method in second if isinstance(method, str)}
    if _OPAQUE_METHOD in first_methods:
        return frozenset(second_methods)
    if _OPAQUE_METHOD in second_methods:
        return frozenset(first_methods)
    return frozenset(first_methods.intersection(second_methods))


def _validate_catch_all_order(routes: Sequence[_EffectiveRoute]) -> None:
    """Reject catch-all routes that shadow later fixed handlers.

    Args:
        routes: Effective routes with exact compatibility declarations.

    Raises:
        RouterContractError: If a parameterized route shadows a later route with another handler.
    """
    declared: set[tuple[int, str, str]] = set()
    for index, route in enumerate(routes):
        route_methods = route.record.get("methods")
        if not isinstance(route_methods, list):
            continue
        declared.update(
            (index, later_path, method)
            for later_path, method in route.allowed_shadows
            if method in route_methods
        )
    used: set[tuple[int, str, str]] = set()
    for index, route in enumerate(routes):
        record = route.record
        path = record.get("path")
        plane = record.get("plane")
        methods = record.get("methods")
        kind = record.get("kind")
        if not isinstance(path, str) or not isinstance(methods, list):
            continue
        is_mount = kind == "mount"
        if not is_mount and "{" not in path:
            continue
        for later_route in routes[index + 1 :]:
            later = later_route.record
            later_path = later.get("path")
            later_methods = later.get("methods")
            if (
                later.get("plane") != plane
                or not isinstance(later_path, str)
                or not isinstance(later_methods, list)
            ):
                continue
            overlapping_methods = _overlapping_methods(methods, later_methods or ())
            allowed_methods = {
                method
                for method in overlapping_methods
                if (later_path, method) in route.allowed_shadows
            }
            try:
                paths_overlap = route_paths_overlap(path, later_path, is_mount=is_mount)
            except RouterRegistryError as exc:
                raise RouterContractError(str(exc)) from exc
            if not overlapping_methods or not paths_overlap:
                continue
            if allowed_methods == overlapping_methods:
                used.update((index, later_path, method) for method in allowed_methods)
                continue
            raise RouterContractError(
                f"parameterized route {path!r} at order {index} must follow route {later_path!r}"
            )
    unused = declared - used
    if unused:
        index, later_path, method = sorted(unused)[0]
        path = routes[index].record.get("path")
        raise RouterContractError(
            "unused compatible route shadow declaration "
            f"{method} {path!r} -> {later_path!r} at order {index}"
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
    routes = [
        _effective_route(source, order=order)
        for order, source in enumerate(_effective_route_sources(app))
    ]
    inventory = [route.record for route in routes]
    _validate_unique_routes(inventory)
    _validate_catch_all_order(routes)
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
    return sum(included is router for included in included_facade_routers(app))
