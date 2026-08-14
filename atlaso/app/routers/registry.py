"""Register domain routers without depending on application facades."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from fastapi import APIRouter
from starlette.routing import compile_path

_REGISTRY_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_WEBSOCKET_METHOD = "WEBSOCKET"
_OPAQUE_METHOD = "*"


class RouterRegistryError(ValueError):
    """Report a deterministic router registration contract violation."""


@dataclass(frozen=True)
class RouterContribution:
    """Associate one router object with its external routing plane.

    Attributes:
        plane: Stable routing plane used in duplicate and ordering checks.
        router: FastAPI router contributed by one domain.
    """

    plane: str
    router: APIRouter


@dataclass(frozen=True)
class RouteIdentity:
    """Identify one externally matchable route method.

    Attributes:
        plane: Stable UI or API routing plane.
        path: Fully prefixed route path.
        method: Uppercase HTTP method or the WebSocket marker.
    """

    plane: str
    path: str
    method: str


@dataclass(frozen=True)
class DomainRouterRegistration:
    """Record one domain's ordered router contributions.

    Attributes:
        domain: Stable domain registration name.
        contributions: Routers in their declared application order.
    """

    domain: str
    contributions: tuple[RouterContribution, ...]


@dataclass(frozen=True)
class _RouteDescriptor:
    """Retain the fields needed for registry validation."""

    identity: RouteIdentity
    endpoint: object | None
    is_mount: bool


def _validated_name(value: str, *, kind: str) -> str:
    """Return a validated registry name.

    Args:
        value: Candidate domain or plane name.
        kind: Human-readable name kind used in diagnostics.

    Returns:
        The unchanged validated name.

    Raises:
        RouterRegistryError: If the value is not a stable snake-case name.
    """
    if not _REGISTRY_NAME_PATTERN.fullmatch(value):
        raise RouterRegistryError(f"{kind} must use lower snake case: {value!r}")
    return value


def _route_sources(router: APIRouter) -> tuple[object, ...]:
    """Return effective route contexts from one router in declared order.

    Args:
        router: Router whose directly declared or included routes are inspected.

    Returns:
        Effective route contexts suitable for stable identity inspection.
    """
    sources: list[object] = []
    for route in router.routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if callable(contexts):
            sources.extend(cast(Sequence[object], contexts()))
        else:
            sources.append(route)
    return tuple(sources)


def _route_descriptors(contribution: RouterContribution) -> tuple[_RouteDescriptor, ...]:
    """Return externally matchable identities for one contribution.

    Args:
        contribution: Plane and router being registered.

    Returns:
        Route descriptors in their effective registration order.

    Raises:
        RouterRegistryError: If a route cannot expose a stable path.
    """
    descriptors: list[_RouteDescriptor] = []
    for source in _route_sources(contribution.router):
        original = getattr(source, "original_route", source)
        path = getattr(source, "path", "") or getattr(original, "path", "")
        if not isinstance(path, str) or not path.startswith("/"):
            raise RouterRegistryError(
                f"router in plane {contribution.plane!r} contains a route without a stable absolute path"
            )
        methods = getattr(source, "methods", None) or getattr(original, "methods", None)
        if methods:
            route_methods = tuple(sorted(str(method).upper() for method in methods))
        elif type(original).__name__.endswith("WebSocketRoute"):
            route_methods = (_WEBSOCKET_METHOD,)
        else:
            route_methods = (_OPAQUE_METHOD,)
        endpoint = getattr(source, "endpoint", None) or getattr(original, "endpoint", None)
        descriptors.extend(
            _RouteDescriptor(
                identity=RouteIdentity(plane=contribution.plane, path=path, method=method),
                endpoint=endpoint,
                is_mount=not methods and not type(original).__name__.endswith("WebSocketRoute"),
            )
            for method in route_methods
        )
    return tuple(descriptors)


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


def _validate_catch_all_order(descriptors: Sequence[_RouteDescriptor]) -> None:
    """Reject a parameterized route that shadows a later fixed peer.

    Args:
        descriptors: Route identities in effective registration order.

    Raises:
        RouterRegistryError: If an earlier parameterized route matches a later fixed route handled elsewhere.
    """
    for index, descriptor in enumerate(descriptors):
        identity = descriptor.identity
        if not descriptor.is_mount and "{" not in identity.path:
            continue
        for later in descriptors[index + 1 :]:
            later_identity = later.identity
            if (
                later_identity.plane != identity.plane
                or (
                    later_identity.method != identity.method
                    and identity.method != _OPAQUE_METHOD
                    and later_identity.method != _OPAQUE_METHOD
                )
                or (descriptor.endpoint is not None and descriptor.endpoint is later.endpoint)
                or not _matches_later_route(
                    identity.path,
                    later_identity.path,
                    is_mount=descriptor.is_mount,
                )
            ):
                continue
            raise RouterRegistryError(
                "parameterized route "
                f"{identity.method} {identity.path!r} in plane {identity.plane!r} "
                f"must follow route {later_identity.path!r}"
            )


class DomainRouterRegistry:
    """Keep domain router registration deterministic and collision-free.

    Attributes:
        name: Stable registry name used in diagnostics.
    """

    def __init__(self, name: str) -> None:
        """Create an empty domain router registry.

        Args:
            name: Stable lower-snake-case registry name.
        """
        self.name = _validated_name(name, kind="registry name")
        self._registrations: list[DomainRouterRegistration] = []

    @property
    def registrations(self) -> tuple[DomainRouterRegistration, ...]:
        """Return immutable registrations in application order."""
        return tuple(self._registrations)

    @property
    def domains(self) -> tuple[str, ...]:
        """Return registered domain names in application order."""
        return tuple(registration.domain for registration in self._registrations)

    def routers_for_plane(self, plane: str) -> tuple[APIRouter, ...]:
        """Return registered routers for one plane in application order.

        Args:
            plane: Stable plane name to select.

        Returns:
            Routers contributed to the requested plane.
        """
        return tuple(
            contribution.router
            for registration in self._registrations
            for contribution in registration.contributions
            if contribution.plane == plane
        )

    def route_identities(self) -> tuple[RouteIdentity, ...]:
        """Return every registered route-method identity in application order."""
        return tuple(
            descriptor.identity
            for registration in self._registrations
            for contribution in registration.contributions
            for descriptor in _route_descriptors(contribution)
        )

    def register(self, domain: str, contributions: Sequence[RouterContribution]) -> None:
        """Register one domain's router contributions atomically.

        Args:
            domain: Stable lower-snake-case domain name.
            contributions: Non-empty ordered plane/router contributions.

        Raises:
            RouterRegistryError: If names, routers, route identities, or effective ordering conflict.
        """
        domain = _validated_name(domain, kind="domain name")
        candidate_contributions = tuple(contributions)
        if not candidate_contributions:
            raise RouterRegistryError(f"domain {domain!r} must contribute at least one router")
        if domain in self.domains:
            raise RouterRegistryError(f"domain {domain!r} is already registered in {self.name!r}")

        for contribution in candidate_contributions:
            plane = _validated_name(contribution.plane, kind="plane name")
            if not isinstance(contribution.router, APIRouter):
                raise RouterRegistryError(f"domain {domain!r} contribution {plane!r} is not an APIRouter")

        candidate = [
            *self._registrations,
            DomainRouterRegistration(domain=domain, contributions=candidate_contributions),
        ]
        routers: dict[int, tuple[str, str]] = {}
        descriptors: list[_RouteDescriptor] = []
        identities: dict[RouteIdentity, str] = {}
        for registration in candidate:
            for contribution in registration.contributions:
                router_key = id(contribution.router)
                if router_key in routers:
                    previous_domain, previous_plane = routers[router_key]
                    raise RouterRegistryError(
                        f"router object for {registration.domain!r}/{contribution.plane!r} is already registered "
                        f"as {previous_domain!r}/{previous_plane!r}"
                    )
                routers[router_key] = (registration.domain, contribution.plane)
                for descriptor in _route_descriptors(contribution):
                    previous_identity_domain = identities.get(descriptor.identity)
                    if previous_identity_domain is not None:
                        identity = descriptor.identity
                        raise RouterRegistryError(
                            "duplicate route registration "
                            f"({identity.plane!r}, {identity.path!r}, {identity.method!r}) "
                            f"in domains {previous_identity_domain!r} and {registration.domain!r}"
                        )
                    identities[descriptor.identity] = registration.domain
                    descriptors.append(descriptor)
        _validate_catch_all_order(descriptors)
        self._registrations.append(candidate[-1])

    def validate_domains(self, expected: Sequence[str]) -> None:
        """Require the complete expected domain set and order.

        Args:
            expected: Exact ordered domain names required by the facade.

        Raises:
            RouterRegistryError: If a domain is omitted, unexpected, or reordered.
        """
        expected_domains = tuple(expected)
        if self.domains != expected_domains:
            raise RouterRegistryError(
                f"{self.name!r} domain order mismatch: expected {expected_domains!r}, registered {self.domains!r}"
            )


def route_identity_counts(identities: Sequence[RouteIdentity]) -> Mapping[RouteIdentity, int]:
    """Return occurrence counts for route identities.

    Args:
        identities: Route identities to count.

    Returns:
        Identity occurrence counts.
    """
    counts: dict[RouteIdentity, int] = {}
    for identity in identities:
        counts[identity] = counts.get(identity, 0) + 1
    return counts
