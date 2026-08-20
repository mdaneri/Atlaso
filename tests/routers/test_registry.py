"""Test deterministic domain-router registry behavior."""

import pytest
from fastapi import APIRouter, FastAPI
from starlette.convertors import Convertor, register_url_convertor

from atlaso.app import ui
from atlaso.app.api import v1
from atlaso.app.routers.registry import (
    DomainRouterRegistry,
    RouteIdentity,
    RouterContribution,
    RouterRegistryError,
    allow_compatible_route_shadow,
)


class _SlugConvertor(Convertor[str]):
    """Provide one test-only custom route convertor."""

    regex = "[a-z-]+"

    def convert(self, value: str) -> str:
        """Return the converted route value.

        Args:
            value: Matched route text.
        """
        return value

    def to_string(self, value: str) -> str:
        """Return the serialized route value.

        Args:
            value: Converted route value.
        """
        return value


register_url_convertor("atlaso_slug", _SlugConvertor())


def _router(
    path: str, *, method: str = "GET", endpoint_name: str = "route"
) -> APIRouter:
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


def test_facades_register_extracted_domains_in_exact_order():
    """Keep every extracted router in its established facade sequence."""
    assert ui.UI_ROUTER_REGISTRY.domains == (
        "facade_before_vaults",
        "vaults",
        "facade_between_vaults_dashboard_monitor",
        "dashboard_monitor",
        "facade_between_dashboard_monitor_automation",
        "automation",
        "facade_between_automation_routes_wan",
        "appliance_apply",
        "routes_wan",
        "firewall",
        "physical_vlans",
        "dns_dhcp",
        "facade_between_dns_dhcp_managed_ldap",
        "managed_ldap",
        "facade_between_managed_ldap_vcf_workflows",
        "vcf_workflows",
        "facade_between_vcf_workflows_identity",
        "identity",
        "facade_between_identity_operations",
        "operations",
        "facade_between_identity_network_boot",
        "network_boot",
        "settings_backup",
        "facade_after_settings_backup",
    )
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("management") == (
        ui._management_before_vaults_router,
        ui.vaults_router,
        ui._management_between_vaults_dashboard_monitor_router,
        ui.dashboard_monitor_router,
        ui._management_before_automation_router,
        ui.automation_router,
        ui._management_before_routes_wan_router,
        ui.appliance_apply_router,
        ui.routes_wan_router,
        ui.firewall_router,
        ui.physical_vlans_router,
        ui.dns_dhcp_router,
        ui._management_between_dns_dhcp_managed_ldap_router,
        ui.managed_ldap_router,
        ui._management_between_managed_ldap_vcf_workflows_router,
        ui.vcf_workflows_router,
        ui._management_between_vcf_workflows_identity_router,
        ui.identity_router,
        ui._management_between_identity_operations_router,
        ui.operations_router,
        ui._management_between_identity_network_boot_router,
        ui.network_boot_router,
        ui.settings_backup_router,
        ui._management_after_settings_backup_router,
    )
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("public") == (ui.public_router,)
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("front_door") == (
        ui.front_door_router,
    )
    assert ui.UI_ROUTER_REGISTRY.routers_for_plane("protocol") == (ui.protocol_router,)
    assert v1.API_V1_ROUTER_REGISTRY.domains == (
        "facade_before_identity",
        "identity",
        "dashboard_monitor",
        "physical_vlans",
        "routes_wan",
        "facade_between_routes_wan_dns_dhcp",
        "dns_dhcp",
        "firewall",
        "facade_between_firewall_operations",
        "operations",
        "settings",
        "vcf_workflows_backups",
        "facade_between_vcf_backups_offline_depot",
        "vcf_workflows_offline_depot",
        "facade_between_offline_depot_private_registry",
        "vcf_workflows_private_registry",
        "facade_between_vcf_private_registry_network_boot",
        "network_boot",
        "managed_ldap",
        "facade_after_managed_ldap",
    )
    assert v1.API_V1_ROUTER_REGISTRY.routers_for_plane("api_v1") == (
        v1._api_before_identity_router,
        v1.identity_router,
        v1.dashboard_monitor_router,
        v1.physical_vlans_router,
        v1.routes_wan_router,
        v1._api_between_routes_wan_dns_dhcp_router,
        v1.dns_dhcp_router,
        v1.firewall_router,
        v1._api_between_firewall_operations_router,
        v1.operations_router,
        v1.settings_router,
        v1.vcf_workflows_backups_router,
        v1._api_between_vcf_backups_offline_depot_router,
        v1.vcf_workflows_offline_depot_router,
        v1._api_between_offline_depot_private_registry_router,
        v1.vcf_workflows_private_registry_router,
        v1._api_between_vcf_private_registry_network_boot_router,
        v1.network_boot_router,
        v1.managed_ldap_router,
        v1._api_after_managed_ldap_router,
    )
    assert {
        route.endpoint.__module__ for route in ui.appliance_apply_router.routes
    } == {"atlaso.app.routers.ui.appliance_apply"}
    assert {
        route.endpoint.__module__ for route in ui.dashboard_monitor_router.routes
    } == {"atlaso.app.routers.ui.dashboard_monitor"}
    assert {route.endpoint.__module__ for route in ui.vaults_router.routes} == {
        "atlaso.app.routers.ui.vaults"
    }
    assert {route.endpoint.__module__ for route in ui.routes_wan_router.routes} == {
        "atlaso.app.routers.ui.routes_wan"
    }
    assert {route.endpoint.__module__ for route in ui.firewall_router.routes} == {
        "atlaso.app.routers.ui.firewall"
    }
    assert {route.endpoint.__module__ for route in ui.physical_vlans_router.routes} == {
        "atlaso.app.routers.ui.physical_vlans"
    }
    assert {route.endpoint.__module__ for route in ui.dns_dhcp_router.routes} == {
        "atlaso.app.routers.ui.dns_dhcp"
    }
    assert {route.endpoint.__module__ for route in ui.identity_router.routes} == {
        "atlaso.app.routers.ui.identity"
    }
    assert {route.endpoint.__module__ for route in ui.managed_ldap_router.routes} == {
        "atlaso.app.routers.ui.managed_ldap"
    }
    assert {route.endpoint.__module__ for route in ui.network_boot_router.routes} == {
        "atlaso.app.routers.ui.network_boot"
    }
    assert {route.endpoint.__module__ for route in ui.vcf_workflows_router.routes} == {
        "atlaso.app.routers.ui.vcf_workflows"
    }
    assert {route.endpoint.__module__ for route in ui.automation_router.routes} == {
        "atlaso.app.routers.ui.automation"
    }
    assert {route.endpoint.__module__ for route in ui.operations_router.routes} == {
        "atlaso.app.routers.ui.operations"
    }
    assert {
        route.endpoint.__module__ for route in ui.settings_backup_router.routes
    } == {"atlaso.app.routers.ui.settings_backup"}
    assert {route.endpoint.__module__ for route in v1.routes_wan_router.routes} == {
        "atlaso.app.routers.api_v1.routes_wan"
    }
    assert {
        route.endpoint.__module__ for route in v1.dashboard_monitor_router.routes
    } == {"atlaso.app.routers.api_v1.dashboard_monitor"}
    assert {route.endpoint.__module__ for route in v1.firewall_router.routes} == {
        "atlaso.app.routers.api_v1.firewall"
    }
    assert {route.endpoint.__module__ for route in v1.physical_vlans_router.routes} == {
        "atlaso.app.routers.api_v1.physical_vlans"
    }
    assert {route.endpoint.__module__ for route in v1.dns_dhcp_router.routes} == {
        "atlaso.app.routers.api_v1.dns_dhcp"
    }
    assert {route.endpoint.__module__ for route in v1.identity_router.routes} == {
        "atlaso.app.routers.api_v1.identity"
    }
    assert {route.endpoint.__module__ for route in v1.managed_ldap_router.routes} == {
        "atlaso.app.routers.api_v1.managed_ldap"
    }
    assert {route.endpoint.__module__ for route in v1.network_boot_router.routes} == {
        "atlaso.app.routers.api_v1.network_boot"
    }
    assert {route.endpoint.__module__ for route in v1.operations_router.routes} == {
        "atlaso.app.routers.api_v1.operations"
    }
    assert {route.endpoint.__module__ for route in v1.settings_router.routes} == {
        "atlaso.app.routers.api_v1.settings"
    }
    assert {
        route.endpoint.__module__
        for router in (
            v1.vcf_workflows_backups_router,
            v1.vcf_workflows_offline_depot_router,
            v1.vcf_workflows_private_registry_router,
        )
        for route in router.routes
    } == {"atlaso.app.routers.api_v1.vcf_workflows"}


def test_registry_rejects_duplicate_domain_names():
    """Reject a domain name reused by a later contribution."""
    registry = DomainRouterRegistry("test")
    registry.register("core", (RouterContribution("api_v1", _router("/api/v1/core")),))

    with pytest.raises(RouterRegistryError, match="already registered"):
        registry.register(
            "core", (RouterContribution("api_v1", _router("/api/v1/other")),)
        )


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
        registry.register(
            "duplicate", (RouterContribution("api_v1", _router("/api/v1/core")),)
        )


def test_registry_keeps_plane_metadata_and_rejects_runtime_duplicates():
    """Reject equal runtime identities even when plane metadata differs."""
    registry = DomainRouterRegistry("test")
    registry.register(
        "management", (RouterContribution("management", _router("/shared")),)
    )

    with pytest.raises(
        RouterRegistryError, match="duplicate runtime route registration"
    ):
        registry.register("public", (RouterContribution("public", _router("/shared")),))

    registry.register(
        "write", (RouterContribution("public", _router("/shared", method="POST")),)
    )

    assert registry.route_identities() == (
        RouteIdentity("management", "/shared", "GET"),
        RouteIdentity("public", "/shared", "POST"),
    )


def test_registry_detects_domain_omission_and_order_changes():
    """Require exact expected domain membership and registration order."""
    registry = DomainRouterRegistry("test")
    registry.register("core", (RouterContribution("api_v1", _router("/api/v1/core")),))
    registry.register(
        "networking", (RouterContribution("api_v1", _router("/api/v1/networking")),)
    )
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


def test_registry_rejects_cross_plane_catch_all_before_fixed_route():
    """Treat planes as classifications within one Starlette route list."""
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "cross_plane_order",
            (
                RouterContribution(
                    "protocol",
                    _router("/ui/{rest:path}", endpoint_name="protocol"),
                ),
                RouterContribution(
                    "management",
                    _router(
                        "/ui/management/status",
                        endpoint_name="management",
                    ),
                ),
            ),
        )


def test_registry_accepts_fixed_route_at_mount_prefix():
    """Require a subtree separator before a mount shadows a fixed peer."""
    registry = DomainRouterRegistry("test")
    mounted = APIRouter()
    mounted.mount(
        "/assets",
        FastAPI(openapi_url=None, docs_url=None, redoc_url=None),
        name="assets",
    )

    registry.register(
        "mount_prefix",
        (
            RouterContribution("management", mounted),
            RouterContribution(
                "management",
                _router("/assets", endpoint_name="fixed"),
            ),
        ),
    )

    assert registry.domains == ("mount_prefix",)


def test_registry_normalizes_root_mount_and_rejects_later_fixed_route():
    """Model Starlette's empty internal root-mount path as `/`."""
    registry = DomainRouterRegistry("test")
    mounted = APIRouter()
    mounted.mount(
        "/",
        FastAPI(openapi_url=None, docs_url=None, redoc_url=None),
        name="root",
    )

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "root_mount",
            (
                RouterContribution("protocol", mounted),
                RouterContribution(
                    "protocol",
                    _router("/health", endpoint_name="fixed"),
                ),
            ),
        )

    registry.register("root_mount", (RouterContribution("protocol", mounted),))
    assert registry.route_identities() == (
        RouteIdentity(plane="protocol", path="/", method="*"),
    )


def test_registry_models_later_mount_as_subtree_language():
    """Compare parameterized routes with the later mount's subtree semantics."""
    registry = DomainRouterRegistry("test")
    nested_mount = APIRouter()
    nested_mount.mount(
        "/assets/site",
        FastAPI(openapi_url=None, docs_url=None, redoc_url=None),
        name="site",
    )

    registry.register(
        "nested_mount",
        (
            RouterContribution(
                "protocol",
                _router("/assets/{name:str}", endpoint_name="asset"),
            ),
            RouterContribution("protocol", nested_mount),
        ),
    )

    root_registry = DomainRouterRegistry("root_test")
    root_mount = APIRouter()
    root_mount.mount(
        "/",
        FastAPI(openapi_url=None, docs_url=None, redoc_url=None),
        name="root",
    )
    with pytest.raises(RouterRegistryError, match="must follow route"):
        root_registry.register(
            "root_mount",
            (
                RouterContribution(
                    "protocol",
                    _router("/{name:str}", endpoint_name="named"),
                ),
                RouterContribution("protocol", root_mount),
            ),
        )


def test_registry_accepts_fixed_route_before_catch_all():
    """Accept fixed peers before their parameterized fallback."""
    registry = DomainRouterRegistry("test")
    registry.register(
        "ordered",
        (
            RouterContribution(
                "management", _router("/resources/status", endpoint_name="fixed")
            ),
            RouterContribution(
                "management",
                _router("/resources/{item:path}", endpoint_name="catch_all"),
            ),
        ),
    )

    assert registry.domains == ("ordered",)


def test_registry_rejects_same_endpoint_shadowing():
    """Reject shadowing even when route records reference the same callable."""
    router = APIRouter()

    def shared(item: str = "default") -> dict[str, str]:
        """Return the synthetic shared response.

        Args:
            item: Captured or default item value.
        """
        return {"item": item}

    router.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    router.add_api_route("/resources/status", shared, methods=["GET"])
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "same_endpoint",
            (RouterContribution("management", router),),
        )


def test_registry_accepts_explicit_compatible_route_shadow():
    """Allow only an exact declared legacy route shadow."""
    router = APIRouter()

    def shared(item: str = "") -> dict[str, str]:
        """Return the synthetic shared response.

        Args:
            item: Captured or default item value.
        """
        return {"item": item}

    router.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    router.add_api_route("/resources/", shared, methods=["GET"])
    allow_compatible_route_shadow(
        router,
        earlier_path="/resources/{item:path}",
        later_path="/resources/",
        methods=("GET",),
    )
    registry = DomainRouterRegistry("test")
    registry.register("equivalent_alias", (RouterContribution("management", router),))

    assert registry.domains == ("equivalent_alias",)


def test_registry_rejects_undeclared_default_binding_shadow():
    """Do not infer alias compatibility from a shared callable and default."""
    router = APIRouter()

    def shared(item: str = "") -> dict[str, str]:
        """Return the synthetic shared response.

        Args:
            item: Captured or default item value.
        """
        return {"item": item}

    router.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    router.add_api_route("/resources/", shared, methods=["GET"])
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "binding_drift",
            (RouterContribution("management", router),),
        )


def test_compatible_route_shadow_rejects_missing_target():
    """Fail when an explicit compatibility declaration becomes stale."""
    router = APIRouter()

    def shared(item: str = "") -> dict[str, str]:
        """Return the synthetic shared response.

        Args:
            item: Captured or default item value.
        """
        return {"item": item}

    router.add_api_route("/resources/{item:path}", shared, methods=["GET"])

    with pytest.raises(RouterRegistryError, match="resolve exactly one"):
        allow_compatible_route_shadow(
            router,
            earlier_path="/resources/{item:path}",
            later_path="/resources/",
            methods=("GET",),
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


@pytest.mark.parametrize(
    ("earlier_path", "later_path"),
    (
        ("/values/{value:int}", "/values/{value:float}"),
        ("/values/{value:int}", "/values/{value:uuid}"),
        ("/values/{value:uuid}", "/values/{value:path}"),
    ),
)
def test_registry_rejects_partial_convertor_overlap(
    earlier_path: str,
    later_path: str,
):
    """Reject partially shadowed peers across standard convertor subsets.

    Args:
        earlier_path: Earlier parameterized route path.
        later_path: Later parameterized route path.
    """
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "overlapping_convertors",
            (
                RouterContribution(
                    "management",
                    _router(earlier_path, endpoint_name="earlier"),
                ),
                RouterContribution(
                    "management",
                    _router(later_path, endpoint_name="later"),
                ),
            ),
        )


def test_registry_rejects_overlap_requiring_peer_literal_witness():
    """Use literals from both patterns when checking partial shadowing."""
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "literal_witness_overlap",
            (
                RouterContribution(
                    "management",
                    _router("/items/{first:str}/edit", endpoint_name="earlier"),
                ),
                RouterContribution(
                    "management",
                    _router("/items/fixed/{second:str}", endpoint_name="later"),
                ),
            ),
        )


def test_registry_rejects_overlap_across_adjacent_route_literals():
    """Compute exact intersections across converter and literal boundaries."""
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="must follow route"):
        registry.register(
            "adjacent_literal_overlap",
            (
                RouterContribution(
                    "management",
                    _router("/{value:int}b1a", endpoint_name="earlier"),
                ),
                RouterContribution(
                    "management",
                    _router("/1{peer:str}a", endpoint_name="later"),
                ),
            ),
        )


def test_registry_fails_closed_for_custom_route_convertor_overlap():
    """Never treat an unsupported registered convertor as disjoint."""
    registry = DomainRouterRegistry("test")

    with pytest.raises(RouterRegistryError, match="unsupported convertor"):
        registry.register(
            "custom_convertor_overlap",
            (
                RouterContribution(
                    "management",
                    _router("/items/{value:path}", endpoint_name="broad"),
                ),
                RouterContribution(
                    "management",
                    _router(
                        "/items/{value:atlaso_slug}",
                        endpoint_name="custom",
                    ),
                ),
            ),
        )
