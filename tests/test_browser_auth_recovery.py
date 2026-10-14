"""Keep browser recovery distinct from fetch, API, and authorization failures."""

from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

from atlaso.app import ui
from atlaso.app.browser_requests import is_browser_navigation
from atlaso.app.database import SessionLocal
from atlaso.app.models import BrowserSession, utcnow
from atlaso.app.problem import install_problem_handlers
from tests.routers.ui.helpers import login

DOCUMENT = {"Accept": "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
FORWARDED = {"Accept": "text/html", "Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty",
             "X-Atlaso-Browser-Navigation": "1"}


@pytest.mark.parametrize("headers, expected", [
    (DOCUMENT, True), (FORWARDED, True), ({"Accept": "text/html"}, True),
    ({"Accept": "text/html", "Sec-Fetch-Mode": "same-origin"}, False),
    ({"Accept": "text/html", "Sec-Fetch-Mode": "cors"}, False),
    ({**DOCUMENT, "Authorization": "Bearer test-fixture"}, False),
    ({**DOCUMENT, "X-Requested-With": "XMLHttpRequest"}, False),
    ({**FORWARDED, "Accept": "application/problem+json"}, False),
])
def test_navigation_classification(headers, expected):
    """Only document intent receives browser recovery, including forwarded intent."""
    request = Request({"type": "http", "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]})
    assert is_browser_navigation(request) is expected


@pytest.mark.parametrize("headers", [DOCUMENT, FORWARDED])
def test_dashboard_navigation_and_reload_recover_after_expiry(client, headers):
    """Expired server state redirects the reproduced dashboard path with its notice."""
    login(client)
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalar_one()
        session.last_interactive_at = utcnow() - timedelta(days=2)
        db.commit()
    response = client.get("/ui/management/dashboard?tab=one&filter=two", headers=headers, follow_redirects=False)
    assert response.status_code == 303
    target = parse_qs(urlsplit(response.headers["location"]).query)
    assert target == {"next": ["/ui/management/dashboard?tab=one&filter=two"]}
    page = client.get(response.headers["location"], headers=headers)
    assert page.status_code == 200
    assert "Session expired due to inactivity" in page.text
    assert "Session expired due to inactivity" not in client.get("/ui/management/login").text


def test_forwarded_navigation_refreshes_activity_but_fetch_does_not(client):
    """The same classification owns activity and expired-document recovery."""
    login(client)
    before = utcnow() - timedelta(minutes=2)
    with SessionLocal() as db:
        db.execute(select(BrowserSession)).scalar_one().last_interactive_at = before
        db.commit()
    client.get("/ui/management/dashboard", headers={"Accept": "text/html", "Sec-Fetch-Mode": "same-origin"})
    with SessionLocal() as db:
        assert db.execute(select(BrowserSession)).scalar_one().last_interactive_at.replace(tzinfo=before.tzinfo) == before
    client.get("/ui/management/dashboard", headers=FORWARDED)
    with SessionLocal() as db:
        assert db.execute(select(BrowserSession)).scalar_one().last_interactive_at.replace(tzinfo=before.tzinfo) > before


@pytest.mark.parametrize("headers", [DOCUMENT, FORWARDED])
@pytest.mark.parametrize("next_path", ["/ui/management/dashboard?a=1&b=2", "//example.test", "/ui/public/ca", "/ui/management/login"])
def test_stale_management_login_rejects_submission_and_opens_fresh_form(client, monkeypatch, headers, next_path):
    """A stale CSRF submission never reaches authentication and preserves a safe next."""
    def forbidden_authentication(*args):
        pytest.fail("CSRF-invalid submission reached authentication")

    monkeypatch.setattr(ui, "authenticate_user", forbidden_authentication)
    response = client.post("/ui/management/login", data={
        "username": "fixture", "password": "fixture", "csrf": "stale-fixture", "next": next_path,
    }, headers=headers, follow_redirects=False)
    assert response.status_code == 303
    expected = next_path if next_path.startswith("/ui/management/dashboard") else "/ui/management"
    assert parse_qs(urlsplit(response.headers["location"]).query) == {"next": [expected]}
    page = client.get(response.headers["location"], headers=headers)
    assert page.status_code == 200
    assert "Sign-in form expired. Please sign in again." in page.text
    assert 'name="csrf" value="' in page.text
    assert "Sign-in form expired" not in client.get("/ui/management/login").text


@pytest.mark.parametrize("headers", [
    {"Accept": "application/json", "Sec-Fetch-Mode": "cors"},
    {"Accept": "text/html", "Sec-Fetch-Mode": "same-origin"},
    {**DOCUMENT, "Authorization": "Bearer test-fixture"},
])
def test_fetch_login_csrf_error_remains_structured(client, headers):
    """Background consumers retain truthful 403 JSON without login redirects."""
    response = client.post("/ui/management/login", data={
        "username": "fixture", "password": "fixture", "csrf": "stale-fixture",
    }, headers=headers, follow_redirects=False)
    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid CSRF token"
    assert "location" not in response.headers


@pytest.mark.parametrize("path, status, detail, expected", [
    ("/ui/public/login", 403, "Invalid CSRF token", "/ui/public/login"),
    ("/ui/public/ca/login", 403, "Invalid CSRF token", "/ui/public/ca/login"),
    ("/ui/public/ca/requests/login", 403, "Invalid CSRF token", "/ui/public/ca/requests/login"),
    ("/PROD/login", 403, "Invalid CSRF token", "/PROD/login"),
    ("/ui/public/terminal", 401, "Authentication required", "/ui/public/login"),
    ("/api/v1/dashboard", 401, "Authentication required", None),
    ("/terminal/tickets", 401, "Authentication required", None),
    ("/certificate-authority/downloads/root-ca.pem", 401, "Authentication required", "/ui/management/login"),
    ("/ui/management/dashboard", 403, "Missing required scope: read:dashboard", None),
    ("/ui/management/settings", 403, "Invalid CSRF token", None),
    ("/ui/management/dashboard", 401, "Invalid token", None),
])
def test_error_recovery_preserves_plane_and_error_meaning(path, status, detail, expected):
    """Only known login CSRF failures and unauthenticated documents recover."""
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-fixture-secret-with-enough-length")
    install_problem_handlers(app)

    @app.api_route(path, methods=["GET", "POST"])
    def rejected():
        raise HTTPException(status_code=status, detail=detail)

    with TestClient(app) as client:
        response = client.post(path, headers=DOCUMENT, follow_redirects=False)
        if expected:
            assert response.status_code == 303
            assert urlsplit(response.headers["location"]).path == expected
        else:
            assert response.status_code == status
            assert response.json()["detail"] == detail


def test_fresh_login_after_recovery_succeeds(client):
    """Fresh CSRF and credentials are required after the rejected stale submission."""
    response = client.post("/ui/management/login", headers=DOCUMENT, data={
        "username": "admin", "password": "atlaso-admin", "csrf": "stale-fixture",
    }, follow_redirects=False)
    assert response.status_code == 303
    page = client.get(response.headers["location"])
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/ui/management/login", headers=DOCUMENT, data={
        "username": "admin", "password": "atlaso-admin", "csrf": csrf,
        "next": "/ui/management/dashboard",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/management/dashboard"
    assert client.get(response.headers["location"]).status_code == 200
