"""Enforce the declared Atlaso browser-route ownership boundaries."""

from __future__ import annotations

from sqlalchemy import select
from starlette.requests import Request

from atlaso.app import main, ui, web_terminal
from atlaso.app.database import SessionLocal
from atlaso.app.models import ApplianceSettings, CaSettings, PhysicalInterface
from atlaso.app.ui_routes import (
    MANAGEMENT_UI_ROOT,
    PUBLIC_UI_ROOT,
    legacy_browser_target,
    safe_management_return_path,
    safe_public_return_path,
)


PROTOCOL_ROUTE_INVENTORY = {
    "/PROD",
    "/PROD/",
    "/PROD/auth-check",
    "/PROD/auth-failure",
    "/PROD/login",
    "/PROD/logout",
    "/PROD/{depot_path:path}",
    "/ca/downloads/ca-bundle.pem",
    "/ca/downloads/root-ca.pem",
    "/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem",
    "/certificate-authority/certificates/{certificate_id}/downloads/chain.pem",
    "/certificate-authority/certificates/{certificate_id}/downloads/private-key.pem",
    "/certificate-authority/downloads/ca-bundle.pem",
    "/certificate-authority/downloads/root-ca.pem",
    "/pxe/esxi/boot.ipxe",
    "/pxe/esxi/ks/{mac_key}/{kickstart_revision}/{capability_file}",
}


def _route_paths(router) -> set[str]:
    """Return the paths owned by a router.

    Args:
        router: FastAPI router whose routes are inventoried.
    """
    return {route.path for route in router.routes}


def test_browser_route_inventory_has_explicit_plane_owners():
    """Fail when an app-owned human route escapes its declared namespace."""
    management_paths = _route_paths(ui.router) | _route_paths(web_terminal.management_router)
    public_paths = _route_paths(ui.public_router) | _route_paths(web_terminal.public_router)

    assert management_paths
    assert public_paths
    assert all(path == MANAGEMENT_UI_ROOT or path.startswith(f"{MANAGEMENT_UI_ROOT}/") for path in management_paths)
    assert all(path == PUBLIC_UI_ROOT or path.startswith(f"{PUBLIC_UI_ROOT}/") for path in public_paths)
    assert _route_paths(ui.front_door_router) == {"/", "/favicon.ico", "/manifest.webmanifest", "/service-worker.js"}
    assert _route_paths(ui.protocol_router) == PROTOCOL_ROUTE_INVENTORY
    assert _route_paths(web_terminal.protocol_router) == {
        "/terminal/remote-launches",
        "/terminal/tickets",
        "/terminal/ws",
    }


def test_return_targets_are_same_plane_and_same_host():
    """Fail closed for external, protocol, or cross-plane return targets."""
    assert safe_management_return_path("/dashboard?tab=one#status") == "/ui/management/dashboard?tab=one#status"
    assert safe_management_return_path("/ui/public/ca") == MANAGEMENT_UI_ROOT
    assert safe_management_return_path("https://example.test/dashboard") == MANAGEMENT_UI_ROOT
    assert safe_public_return_path("/terminal", default="/terminal") == "/ui/public/terminal"
    assert safe_public_return_path("/ui/management/dashboard", default="/terminal") == "/ui/public/terminal"
    assert safe_public_return_path("//example.test/terminal", default="/terminal") == "/ui/public/terminal"
    assert legacy_browser_target("/ca/requests") == ("management", "/ui/management/ca/requests")
    assert legacy_browser_target("/terminal/tickets") is None


def test_legacy_safe_redirect_and_unsafe_bridge(client):
    """Redirect safe bookmarks while never replay-redirecting a mutation.

    Args:
        client: Test application client.
    """
    safe = client.get("/dashboard?sample=1", follow_redirects=False)
    assert safe.status_code == 307
    assert safe.headers["location"] == "/ui/management/dashboard?sample=1"

    unsafe = client.post("/settings", data={}, follow_redirects=False)
    assert unsafe.status_code not in {307, 308}
    assert unsafe.headers["location"].startswith("/ui/management/login?")


def test_public_listener_cannot_cross_into_management_plane(client):
    """Keep management existence and login behavior unavailable publicly.

    Args:
        client: Test application client.
    """
    with SessionLocal() as db:
        appliance = db.execute(select(ApplianceSettings)).scalar_one()
        appliance.management_https_enabled = True
        ca = db.execute(select(CaSettings)).scalar_one()
        ca.enabled = True
        ca.listen_interface = "eth2"
        ca.listen_address = "192.168.87.32"
        management = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        management.role = "management"
        management.ip_cidr = "192.168.167.10/24"
        public = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        public.role = "access"
        public.mode = "access"
        public.ip_cidr = "192.168.87.32/24"
        db.commit()

    public_root = client.get("/", headers={"host": "192.168.87.32"}, follow_redirects=False)
    assert public_root.status_code == 303
    assert public_root.headers["location"] == PUBLIC_UI_ROOT
    assert client.get(PUBLIC_UI_ROOT, headers={"host": "192.168.87.32"}).status_code == 200
    crossed = client.get(f"{MANAGEMENT_UI_ROOT}/login", headers={"host": "192.168.87.32"})
    assert crossed.status_code == 404
    assert "Sign in" not in crossed.text

    management_root = client.get("/", headers={"host": "192.168.167.10"}, follow_redirects=False)
    assert management_root.status_code == 303
    assert management_root.headers["location"] == MANAGEMENT_UI_ROOT
    assert client.get(PUBLIC_UI_ROOT, headers={"host": "192.168.167.10"}).status_code == 404


def test_front_door_uses_observed_management_dhcp_address(client):
    """Recognize the live DHCP lease even though desired-state CIDR is empty.

    Args:
        client: Test application client.
    """
    with SessionLocal() as db:
        management = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        management.role = "management"
        management.ipv4_method = "dhcp"
        management.ip_cidr = None
        management.host_ip_cidr = "192.0.2.25/24"
        db.commit()

    response = client.get("/", headers={"host": "192.0.2.25"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == MANAGEMENT_UI_ROOT


def test_protocol_and_static_requests_skip_ui_listener_lookup(client, monkeypatch):
    """Keep stable machine routes outside browser listener-state inspection.

    Args:
        client: Test application client.
        monkeypatch: Pytest monkeypatch helper.
    """
    def reject_session_lookup():
        """Fail if browser middleware opens a database session."""
        raise AssertionError("browser namespace middleware queried protocol listener state")

    monkeypatch.setattr(main, "SessionLocal", reject_session_lookup)

    assert client.get("/openapi.json").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_listener_address_header_is_trusted_only_from_loopback_proxy():
    """Classify aliases by nginx listener identity without trusting remote spoofing."""
    headers = [(b"host", b"alias.example.test"), (b"x-atlaso-listener-address", b"192.0.2.25")]
    proxied = Request(
        {
            "type": "http",
            "headers": headers,
            "client": ("192.0.2.99", 49152),
            "server": ("127.0.0.1", 8000),
        }
    )
    direct = Request(
        {
            "type": "http",
            "headers": headers,
            "client": ("192.0.2.99", 49152),
            "server": ("192.0.2.25", 8000),
        }
    )

    assert ui.request_host_name(proxied) == "192.0.2.25"
    assert ui.request_host_name(direct) == "alias.example.test"
