"""Test checked-in application route and normalized OpenAPI contracts."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi import APIRouter, FastAPI
from starlette.convertors import Convertor, register_url_convertor

from atlaso.app import main, ui
from atlaso.app.api import v1
from atlaso.app.routers.contracts import (
    RouterContractError,
    build_route_inventory,
    included_router_count,
    normalize_openapi_schema,
    normalized_openapi,
    validate_route_inventory,
)
from atlaso.app.routers.registry import (
    allow_compatible_route_shadow,
    include_facade_router,
)

ROOT = Path(__file__).resolve().parents[2]
ROUTE_BASELINE = ROOT / "tests" / "contracts" / "route_inventory.json"
OPENAPI_BASELINE = ROOT / "tests" / "contracts" / "openapi_v1.json"


class _SlugConvertor(Convertor[str]):
    """Provide one test-only custom route convertor."""

    regex = "[a-z-]+"

    def convert(self, value: str) -> str:
        return value

    def to_string(self, value: str) -> str:
        return value


register_url_convertor("atlaso_slug", _SlugConvertor())


def _load_json(path: Path) -> object:
    """Return one checked-in JSON contract document.

    Args:
        path: Contract baseline path.

    Returns:
        Parsed JSON value.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def test_application_route_inventory_matches_checked_in_contract():
    """Fail on any omitted, added, duplicated, or reordered application route."""
    expected = _load_json(ROUTE_BASELINE)
    assert isinstance(expected, list)

    validate_route_inventory(build_route_inventory(main.app), expected)


def test_route_inventory_covers_every_external_plane():
    """Characterize API v1, management UI, public UI, and protocol routes."""
    inventory = build_route_inventory(main.app)

    assert {record["plane"] for record in inventory} == {
        "api_v1",
        "protocol",
        "ui_management",
        "ui_public",
    }
    assert len(inventory) >= 500


def test_route_inventory_validator_detects_omission_and_order_drift():
    """Report both missing routes and stable-order changes deterministically."""
    inventory = build_route_inventory(main.app)

    with pytest.raises(RouterContractError, match="length changed"):
        validate_route_inventory(inventory[:-1], inventory)

    reordered = deepcopy(inventory)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(RouterContractError, match="changed at order 0"):
        validate_route_inventory(reordered, inventory)


def test_route_inventory_rejects_same_named_shadow_handlers():
    """Compare endpoint identity when route names are intentionally reused."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    @app.get("/resources/{item:path}", name="shared")
    def catch_all() -> dict[str, str]:
        """Return the synthetic catch-all response."""
        return {"handler": "catch-all"}

    @app.get("/resources/status", name="shared")
    def fixed() -> dict[str, str]:
        """Return the synthetic fixed response."""
        return {"handler": "fixed"}

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_rejects_cross_plane_catch_all_before_fixed_route():
    """Treat planes as classifications within one Starlette route list."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    @app.get("/ui/{rest:path}")
    def protocol(rest: str) -> dict[str, str]:
        return {"rest": rest}

    @app.get("/ui/management/status")
    def management() -> dict[str, str]:
        return {"status": "ok"}

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_rejects_mount_before_fixed_subtree_route():
    """Treat a mounted subtree as a catch-all for later fixed routes."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    mounted = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.mount("/assets", mounted, name="assets")

    @app.get("/assets/health")
    def fixed() -> dict[str, str]:
        """Return the synthetic fixed response beneath the mount."""
        return {"status": "ok"}

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_accepts_fixed_route_at_mount_prefix():
    """Require a subtree separator before a mount shadows a fixed peer."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    mounted = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.mount("/assets", mounted, name="assets")

    @app.get("/assets")
    def fixed() -> dict[str, str]:
        return {"status": "ok"}

    assert [record["path"] for record in build_route_inventory(app)] == [
        "/assets",
        "/assets",
    ]


def test_route_inventory_normalizes_root_mount_and_rejects_later_fixed_route():
    """Model Starlette's empty internal root-mount path as `/`."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    mounted = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.mount("/", mounted, name="root")

    inventory = build_route_inventory(app)
    assert [(record["path"], record["kind"]) for record in inventory] == [
        ("/", "mount"),
    ]

    @app.get("/health")
    def fixed() -> dict[str, str]:
        return {"status": "ok"}

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_models_later_mount_as_subtree_language():
    """Compare parameterized routes with the later mount's subtree semantics."""
    nested = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    @nested.get("/assets/{name:str}")
    def asset(name: str) -> dict[str, str]:
        return {"name": name}

    nested.mount(
        "/assets/site",
        FastAPI(openapi_url=None, docs_url=None, redoc_url=None),
        name="site",
    )
    assert [record["path"] for record in build_route_inventory(nested)] == [
        "/assets/{name:str}",
        "/assets/site",
    ]

    root = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    @root.get("/{name:str}")
    def named(name: str) -> dict[str, str]:
        return {"name": name}

    root.mount(
        "/",
        FastAPI(openapi_url=None, docs_url=None, redoc_url=None),
        name="root",
    )
    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(root)


def test_route_inventory_rejects_same_endpoint_shadowing():
    """Reject shadowing even when route records reference the same callable."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    def shared(item: str = "default") -> dict[str, str]:
        return {"item": item}

    app.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    app.add_api_route("/resources/status", shared, methods=["GET"])

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_accepts_explicit_compatible_route_shadow():
    """Allow only an exact declared legacy route shadow."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    def shared(item: str = "") -> dict[str, str]:
        return {"item": item}

    app.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    app.add_api_route("/resources/", shared, methods=["GET"])
    allow_compatible_route_shadow(
        app.router,
        earlier_path="/resources/{item:path}",
        later_path="/resources/",
        methods=("GET",),
    )

    inventory = build_route_inventory(app)

    assert [record["path"] for record in inventory] == [
        "/resources/{item:path}",
        "/resources/",
    ]


def test_route_inventory_rejects_undeclared_default_binding_shadow():
    """Do not infer alias compatibility from a shared callable and default."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    def shared(item: str = "") -> dict[str, str]:
        return {"item": item}

    app.add_api_route("/resources/{item:path}", shared, methods=["GET"])
    app.add_api_route("/resources/", shared, methods=["GET"])

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_rejects_broad_parameter_before_narrow_parameter():
    """Reject a broad path convertor that shadows a narrower peer."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    @app.get("/resources/{value:path}")
    def broad() -> dict[str, str]:
        """Return the synthetic broad response."""
        return {"handler": "broad"}

    @app.get("/resources/{resource_id:int}")
    def narrow() -> dict[str, str]:
        """Return the synthetic narrow response."""
        return {"handler": "narrow"}

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


@pytest.mark.parametrize(
    ("earlier_path", "later_path"),
    (
        ("/values/{value:int}", "/values/{value:float}"),
        ("/values/{value:int}", "/values/{value:uuid}"),
        ("/values/{value:uuid}", "/values/{value:path}"),
    ),
)
def test_route_inventory_rejects_partial_convertor_overlap(
    earlier_path: str,
    later_path: str,
):
    """Reject partially shadowed peers across standard convertor subsets."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    def earlier(value: object) -> dict[str, str]:
        return {"handler": f"earlier:{value}"}

    def later(value: object) -> dict[str, str]:
        return {"handler": f"later:{value}"}

    app.add_api_route(earlier_path, earlier, methods=["GET"])
    app.add_api_route(later_path, later, methods=["GET"])

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_rejects_overlap_requiring_peer_literal_witness():
    """Use literals from both patterns when checking partial shadowing."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    def earlier(first: str) -> dict[str, str]:
        return {"handler": f"earlier:{first}"}

    def later(second: str) -> dict[str, str]:
        return {"handler": f"later:{second}"}

    app.add_api_route("/items/{first:str}/edit", earlier, methods=["GET"])
    app.add_api_route("/items/fixed/{second:str}", later, methods=["GET"])

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_rejects_overlap_across_adjacent_route_literals():
    """Compute exact intersections across converter and literal boundaries."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    def earlier(value: int) -> dict[str, int]:
        return {"value": value}

    def later(peer: str) -> dict[str, str]:
        return {"peer": peer}

    app.add_api_route("/{value:int}b1a", earlier, methods=["GET"])
    app.add_api_route("/1{peer:str}a", later, methods=["GET"])

    with pytest.raises(RouterContractError, match="must follow route"):
        build_route_inventory(app)


def test_route_inventory_fails_closed_for_custom_route_convertor_overlap():
    """Never treat an unsupported registered convertor as disjoint."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    def broad(value: str) -> dict[str, str]:
        return {"value": value}

    def custom(value: str) -> dict[str, str]:
        return {"value": value}

    app.add_api_route("/items/{value:path}", broad, methods=["GET"])
    app.add_api_route(
        "/items/{value:atlaso_slug}",
        custom,
        methods=["GET"],
    )

    with pytest.raises(RouterContractError, match="unsupported convertor"):
        build_route_inventory(app)


def test_facade_routers_are_included_exactly_once():
    """Keep every stable UI and API facade router included exactly once."""
    for router in (
        v1.router,
        ui.front_door_router,
        ui.protocol_router,
        ui.public_router,
        ui.router,
    ):
        assert included_router_count(main.app, router) == 1


def test_facade_inclusion_count_uses_version_independent_tracking():
    """Avoid FastAPI-version-specific copied-route provenance attributes."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    router = APIRouter()
    router.add_api_route("/tracked", lambda: None, methods=["GET"])

    include_facade_router(app, router)

    assert included_router_count(app, router) == 1


def test_facade_include_propagates_compatible_route_shadow_without_provenance():
    """Retain declarations when copied routes do not expose original_route."""
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    router = APIRouter()

    def shared(resource: str = "") -> dict[str, str]:
        return {"resource": resource}

    router.add_api_route("/resources/{resource:path}", shared, methods=["GET"])
    router.add_api_route("/resources/{resource:path}", shared, methods=["HEAD"])
    router.add_api_route("/resources/", shared, methods=["GET"])
    router.add_api_route("/resources/", shared, methods=["HEAD"])
    allow_compatible_route_shadow(
        router,
        earlier_path="/resources/{resource:path}",
        later_path="/resources/",
        methods=("GET", "HEAD"),
    )

    include_facade_router(app, router)
    for route in app.routes:
        route.__dict__.pop("original_route", None)

    assert [
        (record["path"], record["methods"])
        for record in build_route_inventory(app)
    ] == [
        ("/resources/{resource:path}", ["GET"]),
        ("/resources/{resource:path}", ["HEAD"]),
        ("/resources/", ["GET"]),
        ("/resources/", ["HEAD"]),
    ]


def test_normalized_openapi_matches_checked_in_contract():
    """Fail on any normalized OpenAPI contract change."""
    expected = _load_json(OPENAPI_BASELINE)

    assert normalized_openapi(main.app) == expected


def test_openapi_normalization_ignores_only_application_version():
    """Ignore generated version metadata while retaining every other field."""
    schema = main.app.openapi()
    changed_version = deepcopy(schema)
    changed_version["info"]["version"] = "999.999.999"
    assert normalize_openapi_schema(changed_version) == normalize_openapi_schema(schema)

    changed_title = deepcopy(schema)
    changed_title["info"]["title"] = "Changed API title"
    assert normalize_openapi_schema(changed_title) != normalize_openapi_schema(schema)
