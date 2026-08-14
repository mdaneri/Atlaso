"""Characterize Atlaso route and OpenAPI contracts deterministically."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from inspect import Parameter, signature
from typing import Any, cast

from fastapi import APIRouter, FastAPI
from starlette.routing import compile_path

from atlaso.app.routers.registry import RouteIdentity

_WEBSOCKET_METHOD = "WEBSOCKET"
_OPAQUE_METHOD = "*"

type RouteContractRecord = dict[str, object]


class RouterContractError(ValueError):
    """Report route or OpenAPI characterization drift."""


@dataclass(frozen=True)
class _EffectiveRoute:
    """Retain stable metadata and runtime semantics for order validation."""

    record: RouteContractRecord
    endpoint: object | None
    configuration: tuple[object, ...]


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


def _dependency_signature(dependant: object) -> tuple[object, ...]:
    """Return a recursive dependency signature for route comparison."""
    children = getattr(dependant, "dependencies", ())
    return (
        getattr(dependant, "call", None),
        getattr(dependant, "name", None),
        getattr(dependant, "use_cache", None),
        tuple(getattr(dependant, "oauth_scopes", ()) or ()),
        tuple(_dependency_signature(child) for child in children),
    )


def _route_configuration(source: object, original: object) -> tuple[object, ...]:
    """Return dispatch- and response-relevant route configuration."""
    attributes = (
        "status_code",
        "response_class",
        "response_model",
        "response_model_include",
        "response_model_exclude",
        "response_model_by_alias",
        "response_model_exclude_unset",
        "response_model_exclude_defaults",
        "response_model_exclude_none",
        "responses",
        "deprecated",
        "include_in_schema",
        "callbacks",
    )
    values = tuple(getattr(source, name, getattr(original, name, None)) for name in attributes)
    dependant = getattr(source, "dependant", None) or getattr(original, "dependant", None)
    return (*values, _dependency_signature(dependant))


def _effective_route(source: object, *, order: int) -> _EffectiveRoute:
    """Return one stable route record with runtime semantics.

    Args:
        source: Direct route or effective included-router context.
        order: Zero-based effective application route order.

    Returns:
        Stable metadata and runtime semantics.

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
        endpoint=getattr(source, "endpoint", None) or getattr(original, "endpoint", None),
        configuration=_route_configuration(source, original),
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


def _methods_overlap(first: Sequence[object], second: Sequence[object]) -> bool:
    """Return whether two route method sets can match the same request.

    Args:
        first: Earlier route methods.
        second: Later route methods.

    Returns:
        Whether the methods intersect or either route uses the mount wildcard.
    """
    return _OPAQUE_METHOD in first or _OPAQUE_METHOD in second or bool(set(first).intersection(second))


def _representative_route_path(path: str) -> str | None:
    """Return one concrete path that exercises each standard path convertor."""
    _, path_format, convertors = compile_path(path)
    samples = {
        "FloatConvertor": "1.5",
        "IntegerConvertor": "1",
        "PathConvertor": "value/path",
        "StringConvertor": "value",
        "UUIDConvertor": "00000000-0000-0000-0000-000000000000",
    }
    values: dict[str, str] = {}
    for name, convertor in convertors.items():
        value = samples.get(type(convertor).__name__)
        if value is None:
            return None
        values[name] = value
    return path_format.format(**values)


def _matches_later_route(path: str, candidate: str, *, is_mount: bool) -> bool:
    """Return whether an earlier fallback route matches a later route.

    Args:
        path: Earlier parameterized or mount path.
        candidate: Later fixed or parameterized route path.
        is_mount: Whether the earlier route owns an entire mounted subtree.

    Returns:
        Whether the earlier route would intercept the later fixed path.
    """
    if is_mount:
        concrete_candidate = _representative_route_path(candidate)
        if concrete_candidate is None:
            concrete_candidate = candidate
        return concrete_candidate.startswith(f"{path.rstrip('/')}/")
    concrete_candidate = _representative_route_path(candidate)
    if concrete_candidate is None:
        return False
    path_regex, _, _ = compile_path(path)
    return path_regex.fullmatch(concrete_candidate) is not None


def _is_equivalent_default_alias(
    route: _EffectiveRoute,
    later: _EffectiveRoute,
    *,
    path: str,
    later_path: str,
    is_mount: bool,
) -> bool:
    """Return whether a fixed alias is semantically identical to its fallback."""
    if (
        is_mount
        or "{" in later_path
        or route.endpoint is None
        or route.endpoint is not later.endpoint
        or route.configuration != later.configuration
    ):
        return False
    path_regex, _, convertors = compile_path(path)
    match = path_regex.fullmatch(later_path)
    if match is None:
        return False
    try:
        parameters = signature(cast(Callable[..., object], route.endpoint)).parameters
    except (TypeError, ValueError):
        return False
    for name, raw_value in match.groupdict().items():
        parameter = parameters.get(name)
        if parameter is None or parameter.default is Parameter.empty:
            return False
        try:
            value = convertors[name].convert(raw_value)
        except (KeyError, ValueError):
            return False
        if value != parameter.default:
            return False
    return True


def _validate_catch_all_order(routes: Sequence[_EffectiveRoute]) -> None:
    """Reject catch-all routes that shadow later fixed handlers.

    Args:
        routes: Effective routes in application order with runtime semantics.

    Raises:
        RouterContractError: If a parameterized route shadows a later route with another handler.
    """
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
                or not _methods_overlap(methods, later_methods)
                or not _matches_later_route(path, later_path, is_mount=is_mount)
                or _is_equivalent_default_alias(
                    route,
                    later_route,
                    path=path,
                    later_path=later_path,
                    is_mount=is_mount,
                )
            ):
                continue
            raise RouterContractError(
                f"parameterized route {path!r} at order {index} must follow route {later_path!r}"
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
    return sum(getattr(route, "original_router", None) is router for route in app.routes)
