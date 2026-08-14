"""Register domain routers without depending on application facades."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from typing import Any, cast

from fastapi import APIRouter, FastAPI
from starlette.routing import compile_path

_REGISTRY_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_WEBSOCKET_METHOD = "WEBSOCKET"
_OPAQUE_METHOD = "*"
_ALLOWED_SHADOWS_ATTRIBUTE = "_atlaso_allowed_route_shadows"
_FACADE_INCLUSIONS_ATTRIBUTE = "_atlaso_facade_router_inclusions"
_ROUTE_PARAMETER_PATTERN = re.compile(
    r"\{([a-zA-Z_][a-zA-Z0-9_]*)(?::[a-zA-Z_][a-zA-Z0-9_]*)?\}"
)


class RouterRegistryError(ValueError):
    """Report a deterministic router registration contract violation."""


def include_facade_router(
    app: FastAPI,
    router: APIRouter,
    **options: Any,
) -> None:
    """Include and record one application-facing facade router.

    Args:
        app: FastAPI application receiving the facade.
        router: Exact facade router object being included.
        **options: Options forwarded to ``FastAPI.include_router``.
    """
    route_count = len(app.routes)
    app.include_router(router, **options)
    _propagate_compatible_route_shadows(router, app.routes[route_count:])
    included = getattr(app.state, _FACADE_INCLUSIONS_ATTRIBUTE, ())
    setattr(app.state, _FACADE_INCLUSIONS_ATTRIBUTE, (*included, router))


def included_facade_routers(app: FastAPI) -> tuple[APIRouter, ...]:
    """Return explicitly tracked facade includes in application order.

    Args:
        app: FastAPI application whose facade inclusions are inspected.

    Returns:
        Facade router objects in inclusion order.
    """
    return cast(
        tuple[APIRouter, ...],
        getattr(app.state, _FACADE_INCLUSIONS_ATTRIBUTE, ()),
    )


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
    allowed_shadows: frozenset[tuple[str, str]]
    is_mount: bool


@dataclass(frozen=True)
class _CharacterClass:
    """Represent one transition in a standard route convertor language."""

    kind: str
    literal: str | None = None


@dataclass(frozen=True)
class _PathAutomaton:
    """Represent a finite automaton for one standard Starlette route path."""

    transitions: tuple[tuple[tuple[_CharacterClass, int], ...], ...]
    epsilons: tuple[tuple[int, ...], ...]
    accepting_state: int


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


def allow_compatible_route_shadow(
    router: APIRouter,
    *,
    earlier_path: str,
    later_path: str,
    methods: Sequence[str],
) -> None:
    """Declare one exact legacy alias whose external order must be preserved.

    Args:
        router: Router containing both legacy route records.
        earlier_path: Earlier catch-all path that intercepts the alias.
        later_path: Later compatibility alias path.
        methods: Exact HTTP methods intentionally shadowed.

    Raises:
        RouterRegistryError: If either route is missing, ambiguous, or handled by another endpoint.
    """
    normalized_methods = tuple(sorted({method.upper() for method in methods}))
    if not normalized_methods:
        raise RouterRegistryError("compatible route shadow must declare at least one method")
    sources = _route_sources(router)
    for method in normalized_methods:
        earlier = [
            source
            for source in sources
            if (getattr(source, "path", "") or getattr(getattr(source, "original_route", source), "path", ""))
            == earlier_path
            and method
            in {
                str(candidate).upper()
                for candidate in (
                    getattr(source, "methods", None)
                    or getattr(getattr(source, "original_route", source), "methods", None)
                    or ()
                )
            }
        ]
        later = [
            source
            for source in sources
            if (getattr(source, "path", "") or getattr(getattr(source, "original_route", source), "path", ""))
            == later_path
            and method
            in {
                str(candidate).upper()
                for candidate in (
                    getattr(source, "methods", None)
                    or getattr(getattr(source, "original_route", source), "methods", None)
                    or ()
                )
            }
        ]
        if len(earlier) != 1 or len(later) != 1:
            raise RouterRegistryError(
                "compatible route shadow declaration must resolve exactly one earlier and later route: "
                f"{method} {earlier_path!r} -> {later_path!r}"
            )
        earlier_original = getattr(earlier[0], "original_route", earlier[0])
        later_original = getattr(later[0], "original_route", later[0])
        earlier_endpoint = getattr(earlier[0], "endpoint", None) or getattr(earlier_original, "endpoint", None)
        later_endpoint = getattr(later[0], "endpoint", None) or getattr(later_original, "endpoint", None)
        if earlier_endpoint is None or earlier_endpoint is not later_endpoint:
            raise RouterRegistryError(
                "compatible route shadow declaration requires the same endpoint: "
                f"{method} {earlier_path!r} -> {later_path!r}"
            )
        declared = set(getattr(earlier_original, _ALLOWED_SHADOWS_ATTRIBUTE, ()))
        declared.add((later_path, method))
        setattr(earlier_original, _ALLOWED_SHADOWS_ATTRIBUTE, frozenset(declared))


def compatible_route_shadows(source: object) -> frozenset[tuple[str, str]]:
    """Return exact compatibility shadows declared on a route source.

    Args:
        source: Effective route source whose declarations are read.

    Returns:
        Declared later-path and method pairs.
    """
    original = getattr(source, "original_route", source)
    return frozenset(
        {
            *getattr(source, _ALLOWED_SHADOWS_ATTRIBUTE, ()),
            *getattr(original, _ALLOWED_SHADOWS_ATTRIBUTE, ()),
        }
    )


def _propagate_compatible_route_shadows(
    router: APIRouter,
    included_routes: Sequence[object],
) -> None:
    """Copy explicit shadow declarations onto FastAPI's included route copies.

    Args:
        router: Facade router containing the source declarations.
        included_routes: FastAPI route copies produced by the facade include.
    """
    targets: list[object] = []
    for route in included_routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if callable(contexts):
            targets.extend(cast(Sequence[object], contexts()))
        else:
            targets.append(route)

    for source in _route_sources(router):
        allowed_shadows = compatible_route_shadows(source)
        if not allowed_shadows:
            continue
        source_original = getattr(source, "original_route", source)
        source_path = getattr(source, "path", "") or getattr(source_original, "path", "")
        source_endpoint = getattr(source, "endpoint", None) or getattr(
            source_original,
            "endpoint",
            None,
        )
        shadow_methods = {method for _, method in allowed_shadows}
        matching_targets = []
        for target in targets:
            target_original = getattr(target, "original_route", target)
            target_path = getattr(target, "path", "") or getattr(target_original, "path", "")
            target_endpoint = getattr(target, "endpoint", None) or getattr(
                target_original,
                "endpoint",
                None,
            )
            target_methods = {
                str(method).upper()
                for method in (
                    getattr(target, "methods", None)
                    or getattr(target_original, "methods", None)
                    or ()
                )
            }
            if (
                target_path == source_path
                and target_endpoint is source_endpoint
                and shadow_methods.intersection(target_methods)
            ):
                matching_targets.append(target)
        if not matching_targets:
            raise RouterRegistryError(
                f"included facade route {source_path!r} lost its compatibility-shadow declaration"
            )
        for target in matching_targets:
            declared = set(compatible_route_shadows(target))
            declared.update(allowed_shadows)
            setattr(target, _ALLOWED_SHADOWS_ATTRIBUTE, frozenset(declared))


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
        methods = getattr(source, "methods", None) or getattr(original, "methods", None)
        is_websocket = type(original).__name__.endswith("WebSocketRoute")
        path = getattr(source, "path", "") or getattr(original, "path", "")
        if path == "" and not methods and not is_websocket:
            path = "/"
        if not isinstance(path, str) or not path.startswith("/"):
            raise RouterRegistryError(
                f"router in plane {contribution.plane!r} contains a route without a stable absolute path"
            )
        if methods:
            route_methods = tuple(sorted(str(method).upper() for method in methods))
        elif is_websocket:
            route_methods = (_WEBSOCKET_METHOD,)
        else:
            route_methods = (_OPAQUE_METHOD,)
        allowed_shadows = compatible_route_shadows(source)
        descriptors.extend(
            _RouteDescriptor(
                identity=RouteIdentity(plane=contribution.plane, path=path, method=method),
                allowed_shadows=allowed_shadows,
                is_mount=not methods and not is_websocket,
            )
            for method in route_methods
        )
    return tuple(descriptors)


def _character_class_accepts(character_class: _CharacterClass, character: str) -> bool:
    """Return whether one transition accepts a concrete character.

    Args:
        character_class: Transition class being tested.
        character: Concrete character to test.

    Returns:
        Whether the transition accepts the character.
    """
    if character_class.literal is not None:
        return character == character_class.literal
    if character_class.kind == "any":
        return True
    if character_class.kind == "non_slash":
        return character != "/"
    if character_class.kind == "digit":
        return character in "0123456789"
    if character_class.kind == "hex":
        return character in "0123456789abcdefABCDEF"
    return False


def _character_classes_overlap(first: _CharacterClass, second: _CharacterClass) -> bool:
    """Return whether two standard route transition classes intersect.

    Args:
        first: First transition class.
        second: Second transition class.

    Returns:
        Whether both classes accept a common character.
    """
    candidates = tuple(
        dict.fromkeys(
            (
                *(value for value in (first.literal, second.literal) if value is not None),
                "0",
                "a",
                "A",
                "/",
            )
        )
    )
    return any(
        _character_class_accepts(first, candidate)
        and _character_class_accepts(second, candidate)
        for candidate in candidates
    )


@cache
def _path_automaton(path: str, *, is_mount: bool = False) -> _PathAutomaton:
    """Build an exact automaton for standard Starlette route convertors.

    Args:
        path: Starlette route path to model.
        is_mount: Whether the path owns a mounted subtree.

    Returns:
        Exact automaton for the supported route language.

    Raises:
        RouterRegistryError: If the path uses an unsupported convertor.
    """
    _, _, convertors = compile_path(path)
    transitions: list[list[tuple[_CharacterClass, int]]] = [[]]
    epsilons: list[list[int]] = [[]]

    def new_state() -> int:
        transitions.append([])
        epsilons.append([])
        return len(transitions) - 1

    def add_literal(start: int, literal: str) -> int:
        """Append literal transitions.

        Args:
            start: State from which the literal begins.
            literal: Exact characters to append.

        Returns:
            State reached after the literal.
        """
        current = start
        for character in literal:
            following = new_state()
            transitions[current].append((_CharacterClass("literal", character), following))
            current = following
        return current

    def add_one_or_more(start: int, character_class: _CharacterClass) -> int:
        """Append a one-or-more transition loop.

        Args:
            start: State from which the loop begins.
            character_class: Character class accepted by the loop.

        Returns:
            Accepting state after at least one character.
        """
        end = new_state()
        transitions[start].append((character_class, end))
        transitions[end].append((character_class, end))
        return end

    current = 0
    position = 0
    for parameter in _ROUTE_PARAMETER_PATTERN.finditer(path):
        current = add_literal(current, path[position : parameter.start()])
        convertor = convertors.get(parameter.group(1))
        convertor_type = type(convertor).__name__
        if convertor_type == "StringConvertor":
            current = add_one_or_more(current, _CharacterClass("non_slash"))
        elif convertor_type == "PathConvertor":
            end = new_state()
            transitions[current].append((_CharacterClass("any"), current))
            epsilons[current].append(end)
            current = end
        elif convertor_type == "IntegerConvertor":
            current = add_one_or_more(current, _CharacterClass("digit"))
        elif convertor_type == "FloatConvertor":
            integer = add_one_or_more(current, _CharacterClass("digit"))
            end = new_state()
            epsilons[integer].append(end)
            decimal = new_state()
            transitions[integer].append((_CharacterClass("literal", "."), decimal))
            fraction = add_one_or_more(decimal, _CharacterClass("digit"))
            epsilons[fraction].append(end)
            current = end
        elif convertor_type == "UUIDConvertor":
            for group_index, group_length in enumerate((8, 4, 4, 4, 12)):
                if group_index:
                    after_hyphen = new_state()
                    transitions[current].append(
                        (_CharacterClass("literal", "-"), after_hyphen)
                    )
                    epsilons[current].append(after_hyphen)
                    current = after_hyphen
                for _ in range(group_length):
                    following = new_state()
                    transitions[current].append((_CharacterClass("hex"), following))
                    current = following
        else:
            raise RouterRegistryError(
                f"route {path!r} uses unsupported convertor {convertor_type!r}"
            )
        position = parameter.end()
    current = add_literal(current, path[position:])

    if is_mount:
        accepting_state = new_state()
        if path == "/":
            epsilons[current].append(accepting_state)
            transitions[current].append((_CharacterClass("any"), current))
        else:
            subtree = new_state()
            transitions[current].append((_CharacterClass("literal", "/"), subtree))
            transitions[subtree].append((_CharacterClass("any"), subtree))
            epsilons[subtree].append(accepting_state)
    else:
        accepting_state = current

    return _PathAutomaton(
        transitions=tuple(tuple(items) for items in transitions),
        epsilons=tuple(tuple(items) for items in epsilons),
        accepting_state=accepting_state,
    )


def _epsilon_closure(automaton: _PathAutomaton, state: int) -> frozenset[int]:
    """Return every state reachable without consuming a character.

    Args:
        automaton: Automaton whose epsilon transitions are traversed.
        state: Starting state.

    Returns:
        Starting and epsilon-reachable states.
    """
    closure = {state}
    pending = [state]
    while pending:
        current = pending.pop()
        for following in automaton.epsilons[current]:
            if following not in closure:
                closure.add(following)
                pending.append(following)
    return frozenset(closure)


def _path_automata_overlap(first: _PathAutomaton, second: _PathAutomaton) -> bool:
    """Return whether two route-language automata accept a common path.

    Args:
        first: Earlier route-language automaton.
        second: Later route-language automaton.

    Returns:
        Whether the automata accept a common path.
    """
    first_closures = tuple(_epsilon_closure(first, state) for state in range(len(first.transitions)))
    second_closures = tuple(_epsilon_closure(second, state) for state in range(len(second.transitions)))
    pending = deque(
        (first_state, second_state)
        for first_state in first_closures[0]
        for second_state in second_closures[0]
    )
    visited = set(pending)
    while pending:
        first_state, second_state = pending.popleft()
        if (
            first_state == first.accepting_state
            and second_state == second.accepting_state
        ):
            return True
        for first_class, first_following in first.transitions[first_state]:
            for second_class, second_following in second.transitions[second_state]:
                if not _character_classes_overlap(first_class, second_class):
                    continue
                for first_reachable in first_closures[first_following]:
                    for second_reachable in second_closures[second_following]:
                        pair = (first_reachable, second_reachable)
                        if pair not in visited:
                            visited.add(pair)
                            pending.append(pair)
    return False


def route_paths_overlap(
    path: str,
    candidate: str,
    *,
    is_mount: bool,
    candidate_is_mount: bool = False,
) -> bool:
    """Return whether an earlier fallback route matches a later route.

    Args:
        path: Earlier parameterized or mount path.
        candidate: Later fixed or parameterized route path.
        is_mount: Whether the earlier route owns an entire mounted subtree.
        candidate_is_mount: Whether the later route owns an entire mounted subtree.

    Returns:
        Whether the earlier route would intercept the later fixed path.
    """
    earlier = _path_automaton(path, is_mount=is_mount)
    later = _path_automaton(candidate, is_mount=candidate_is_mount)
    return _path_automata_overlap(earlier, later)


def _validate_catch_all_order(descriptors: Sequence[_RouteDescriptor]) -> None:
    """Reject a parameterized route that shadows a later fixed peer.

    Args:
        descriptors: Route identities in effective registration order.

    Raises:
        RouterRegistryError: If an earlier parameterized route matches a later fixed route handled elsewhere.
    """
    declared = {
        (descriptor.identity, later_path, method)
        for descriptor in descriptors
        for later_path, method in descriptor.allowed_shadows
        if method == descriptor.identity.method
    }
    used: set[tuple[RouteIdentity, str, str]] = set()
    for index, descriptor in enumerate(descriptors):
        identity = descriptor.identity
        if not descriptor.is_mount and "{" not in identity.path:
            continue
        for later in descriptors[index + 1 :]:
            later_identity = later.identity
            allowed = (later_identity.path, later_identity.method) in descriptor.allowed_shadows
            if (
                (
                    later_identity.method != identity.method
                    and identity.method != _OPAQUE_METHOD
                    and later_identity.method != _OPAQUE_METHOD
                )
                or not route_paths_overlap(
                    identity.path,
                    later_identity.path,
                    is_mount=descriptor.is_mount,
                    candidate_is_mount=later.is_mount,
                )
            ):
                continue
            if allowed:
                used.add((identity, later_identity.path, later_identity.method))
                continue
            raise RouterRegistryError(
                "parameterized route "
                f"{identity.method} {identity.path!r} in plane {identity.plane!r} "
                f"must follow route {later_identity.path!r}"
            )
    unused = declared - used
    if unused:
        identity, later_path, method = sorted(
            unused,
            key=lambda item: (item[0].plane, item[0].path, item[0].method, item[1], item[2]),
        )[0]
        raise RouterRegistryError(
            "unused compatible route shadow declaration "
            f"{method} {identity.path!r} -> {later_path!r} in plane {identity.plane!r}"
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
        runtime_identities: dict[tuple[str, str], tuple[str, str]] = {}
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
                    runtime_identity = (
                        descriptor.identity.path,
                        descriptor.identity.method,
                    )
                    previous_runtime = runtime_identities.get(runtime_identity)
                    if previous_runtime is not None:
                        previous_domain, previous_plane = previous_runtime
                        raise RouterRegistryError(
                            "duplicate runtime route registration "
                            f"({descriptor.identity.path!r}, {descriptor.identity.method!r}) "
                            f"in {previous_domain!r}/{previous_plane!r} and "
                            f"{registration.domain!r}/{descriptor.identity.plane!r}"
                        )
                    identities[descriptor.identity] = registration.domain
                    runtime_identities[runtime_identity] = (
                        registration.domain,
                        descriptor.identity.plane,
                    )
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
