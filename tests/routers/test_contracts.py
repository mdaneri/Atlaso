"""Test checked-in application route and normalized OpenAPI contracts."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi import FastAPI

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
from atlaso.app.routers.registry import allow_compatible_route_shadow

ROOT = Path(__file__).resolve().parents[2]
ROUTE_BASELINE = ROOT / "tests" / "contracts" / "route_inventory.json"
OPENAPI_BASELINE = ROOT / "tests" / "contracts" / "openapi_v1.json"


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
