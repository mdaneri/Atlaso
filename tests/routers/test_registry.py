"""Test deterministic domain-router registry behavior."""

import pytest
from fastapi import APIRouter

from atlaso.app import ui
from atlaso.app.api import v1
from atlaso.app.routers.registry import (
    DomainRouterRegistry,
    RouteIdentity,
    RouterContribution,
    RouterRegistryError,
)


def _router(path: str, *, method: str = "GET", endpoint_name: str = "route") -> APIRouter:
    """Return a router with one uniquely handled route.

    Args:
        path: Absolute test route path.
        method: HTTP method registered for the path.
        endpoint_name: Stable route name used in assertions.

    Returns:
        Router containing the requested route.
    """
    router = APIRouter()

    async def endpoint() -> dict[str, str]:
        """Return a bounded synthetic response."""
        return {"route": endpoint_name}

    router.add_api_route(path, endpoint, methods=[method], name=endpoint_name)
    return router


def test_facades_register_current_router_bundles_once():
    """Keep the current monolithic facades as the sole initial domains."""
    assert ui.UI_ROUTER_REGISTRY.domains == ("facade",)
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("management") == (ui.router,)
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("public") == (ui.public_router,)
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("front_door") == (ui.front_door_router,)
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("protocol") == (ui.protocol_router,)
    assert v1.API_V1_ROUTER_REGISTRY.domains == ("facade",)
    assert v1.API_V1_ROUTER_REGISTRY.routers_for_plane("api_v1") == (v1.router,)


def test_registry_rejects_duplicate_domain_names():
    """Reject a domain name reused by a later contribution."""
    registry = DomainRouterRegistry("test")
    registry.register("core", (RouterContribution("api_v1", _router("/api/v1/core")),))

    with pytest.raises(RouterRegistryError, match="already registered"):
        registry.register("core", (RouterContribution("api_v1", _router("/api/v1/other")),))


def test_registry_rejects_duplicate_router_objects():
    """Reject one router object assigned to multiple domains or planes."""
    registry = DomainRouterRegistry("test")
    router = _router("/api/v1/core")
    registry.register("core", (RouterContribution("api_v1", router),))

    with pytest.raises(RouterRegistryError, match="router object"):
        registry.register("networking", (RouterContribution("api_v1", router),))


def test_registry_rejects_duplicate_route_identities():
    """Reject equal plane, path, and method registrations from different routers."""
    registry = DomainRouterRegistry("test")
    registry.register("core", (RouterContribution("api_v1", _router("/api/v1/core")),))

    with pytest.raises(RouterRegistryError, match="duplicate route registration"):
        registry.register("duplicate", (RouterContribution("api_v1", _router("/api/v1/core")),))


def test_registry_keeps_plane_and_method_in_route_identity():
    """Allow equal paths when the external plane or method differs."""
    registry = DomainRouterRegistry("test")
    registry.register("management", (RouterContribution("management", _router("/shared")),))
    registry.register("public", (RouterContribution("public", _router("/shared")),))
    registry.register("write", (RouterContribution("management", _router("/shared", method="POST")),))

    assert registry.route_identities() == (
        RouteIdentity("management", "/shared", "GET"),
        RouteIdentity("public", "/shared", "GET"),
        RouteIdentity("management", "/shared", "POST"),
    )


def test_registry_detects_domain_omission_and_order_changes():
    """Require exact expected domain membership and registration order."""
    registry = DomainRouterRegistry("test")
    registry.register("core", (RouterContribution("api_v1", _router("/api/v1/core")),))
    registry.register("networking", (RouterContribution("api_v1", _router("/api/v1/networking")),))
    registry.validate_domains(("core", "networking"))

    with pytest.raises(RouterRegistryError, match="domain order mismatch"):
        registry.validate_domains(("core",))
    with pytest.raises(RouterRegistryError, match="domain order mismatch"):
        registry.validate_domains(("networking", "core"))


def test_registry_rejects_catch_all_before_fixed_peer():
    """Reject a parameterized handler that shadows a later fixed handler."""
    registry = DomainRouterRegistry("test")
    catch_all = _router("/resources/{item:path}", endpoint_name="catch_all")
    fixed = _router("/resources/status", endpoint_name="fixed")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "bad_order",
            (
                RouterContribution("management", catch_all),
                RouterContribution("management", fixed),
            ),
        )


def test_registry_accepts_fixed_route_before_catch_all():
    """Accept fixed peers before their parameterized fallback."""
    registry = DomainRouterRegistry("test")
    registry.register(
        "ordered",
        (
            RouterContribution("management", _router("/resources/status", endpoint_name="fixed")),
            RouterContribution("management", _router("/resources/{item:path}", endpoint_name="catch_all")),
        ),
    )

    assert registry.domains == ("ordered",)


def test_registry_rejects_same_endpoint_shadowing():
    """Reject shadowing even when route records reference the same callable."""
    router = APIRouter()

    def shared(item: str = "default") -> dict[str, str]:
        return {"item": item}

    router.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    router.add_api_route("/resources/status", shared, methods=["GET"])
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "same_endpoint",
            (RouterContribution("management", router),),
        )


def test_registry_accepts_semantically_equivalent_default_alias():
    """Allow a fixed alias only when fallback binding and configuration match."""
    router = APIRouter()

    def shared(item: str = "") -> dict[str, str]:
        return {"item": item}

    router.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    router.add_api_route("/resources/", shared, methods=["GET"])
    registry = DomainRouterRegistry("test")
    registry.register("equivalent_alias", (RouterContribution("management", router),))

    assert registry.domains == ("equivalent_alias",)


def test_registry_rejects_same_endpoint_configuration_drift():
    """Reject aliases whose response configuration changes route semantics."""
    router = APIRouter()

    def shared(item: str = "") -> dict[str, str]:
        return {"item": item}

    router.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    router.add_api_route("/resources/", shared, methods=["GET"], status_code=202)
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "configuration_drift",
            (RouterContribution("management", router),),
        )


def test_registry_rejects_broad_parameter_before_narrow_parameter():
    """Reject a broad path convertor that shadows a narrower peer."""
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "bad_parameter_order",
            (
                RouterContribution(
                    "management",
                    _router("/resources/{value:path}", endpoint_name="broad"),
                ),
                RouterContribution(
                    "management",
                    _router("/resources/{resource_id:int}", endpoint_name="narrow"),
                ),
            ),
        )
