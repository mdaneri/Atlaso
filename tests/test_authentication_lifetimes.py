"""Verify configurable browser-session and API-token lifetime policies."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    ApiToken,
    ApplianceSettings,
    AuditEvent,
    BrowserSession,
)
from atlaso.app.security import ensure_aware
from atlaso.app.services.settings_archive import (
    export_settings_archive,
    restore_settings_archive,
)
from tests.routers.ui.helpers import login


def _current_browser_session() -> BrowserSession:
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalars().one()
        db.expunge(session)
        return session


def _set_lifetimes(*, idle_minutes: int = 30, token_days: int = 90) -> None:
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalars().one()
        settings.browser_session_idle_timeout_minutes = idle_minutes
        settings.api_token_max_lifetime_days = token_days
        db.commit()


def _create_token(client, *, name: str, expires_at: str | None = None):
    payload = {"name": name, "scopes": ["read:dashboard"]}
    if expires_at is not None:
        payload["expires_at"] = expires_at
    return client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json=payload,
    )


def test_browser_session_expires_at_exact_idle_boundary_and_audits_notice(
    client, monkeypatch
):
    """The server expires before the handler and discloses no session identifier."""
    login(client)
    baseline = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
    _set_lifetimes(idle_minutes=5)
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalars().one()
        session.last_interactive_at = baseline
        db.commit()

    monkeypatch.setattr("atlaso.app.security.utcnow", lambda: baseline + timedelta(minutes=5))
    expired = client.get(
        "/ui/management/settings",
        headers={"Accept": "text/html", "Sec-Fetch-Mode": "navigate"},
        follow_redirects=False,
    )
    assert expired.status_code == 303
    assert expired.headers["location"].startswith("/ui/management/login?")

    login_page = client.get("/ui/management/login")
    assert "Session expired due to inactivity" in login_page.text
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalars().one()
        event = db.execute(
            select(AuditEvent).where(AuditEvent.action == "browser_session_expired")
        ).scalar_one()
        assert ensure_aware(session.expired_at) == baseline + timedelta(minutes=5)
        assert session.expiry_reason == "inactivity"
        assert event.actor == "admin"
        assert event.resource_id is None
        assert event.detail == "session_class=browser; reason=inactivity"
        assert session.id not in (event.detail or "")


def test_background_fetch_does_not_refresh_but_navigation_and_heartbeat_do(
    client, monkeypatch
):
    """Only deliberate navigation or the CSRF-protected activity endpoint extends activity."""
    login(client)
    baseline = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalars().one()
        session.last_interactive_at = baseline
        db.commit()

    monkeypatch.setattr("atlaso.app.security.utcnow", lambda: baseline + timedelta(minutes=1))
    background = client.get(
        "/ui/management/settings",
        headers={"Accept": "application/json", "Sec-Fetch-Mode": "cors"},
    )
    assert background.status_code == 200
    assert ensure_aware(_current_browser_session().last_interactive_at) == baseline

    navigation = client.get(
        "/ui/management/settings",
        headers={"Accept": "text/html", "Sec-Fetch-Mode": "navigate"},
    )
    assert navigation.status_code == 200
    assert ensure_aware(_current_browser_session().last_interactive_at) == baseline + timedelta(minutes=1)

    csrf = navigation.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr("atlaso.app.security.utcnow", lambda: baseline + timedelta(minutes=2))
    heartbeat = client.post(
        "/ui/management/session/activity",
        headers={"X-CSRF-Token": csrf, "Accept": "application/json"},
    )
    assert heartbeat.status_code == 204
    assert ensure_aware(_current_browser_session().last_interactive_at) == baseline + timedelta(minutes=2)


def test_lowering_policy_expires_existing_session_and_expiration_is_terminal(
    client, monkeypatch
):
    """Policy changes apply on the next request and cannot resurrect expired state."""
    login(client)
    baseline = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalars().one()
        session.last_interactive_at = baseline
        db.commit()
    monkeypatch.setattr("atlaso.app.security.utcnow", lambda: baseline + timedelta(minutes=10))
    _set_lifetimes(idle_minutes=5)

    response = client.get(
        "/ui/management/settings",
        headers={"Accept": "application/json", "Sec-Fetch-Mode": "cors"},
        follow_redirects=False,
    )
    assert response.status_code == 401
    _set_lifetimes(idle_minutes=30)
    response = client.get(
        "/ui/management/settings",
        headers={"Accept": "text/html", "Sec-Fetch-Mode": "navigate"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _current_browser_session().expired_at is not None


def test_logout_terminally_invalidates_server_browser_session(client):
    """Explicit logout closes the server record as well as clearing signed cookie state."""
    login(client)
    page = client.get("/ui/management/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ui/management/logout",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    closed = _current_browser_session()
    assert closed.expired_at is not None
    assert closed.expiry_reason == "logout"


def test_authentication_lifetime_settings_save_validate_and_archive(client):
    """The immediate settings UI enforces bounds and archive restore preserves policy."""
    login(client)
    page = client.get("/ui/management/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    saved = client.post(
        "/ui/management/settings/authentication-lifetimes",
        data={
            "browser_session_idle_timeout_minutes": "45",
            "api_token_max_lifetime_days": "120",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert saved.status_code == 200
    assert saved.json()["browser_session_idle_timeout_minutes"] == 45
    assert saved.json()["api_token_max_lifetime_days"] == 120

    rejected = client.post(
        "/ui/management/settings/authentication-lifetimes",
        data={
            "browser_session_idle_timeout_minutes": "4",
            "api_token_max_lifetime_days": "366",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert rejected.status_code == 422
    assert "between 5 and 1440" in rejected.json()["detail"]

    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
        assert "browser_sessions" not in archive["data"]
        invalid_archive = deepcopy(archive)
        invalid_archive["data"]["appliance_settings"][0][
            "browser_session_idle_timeout_minutes"
        ] = 4
        with pytest.raises(
            ValueError,
            match="Authentication lifetimes are invalid.*between 5 and 1440",
        ):
            restore_settings_archive(db, invalid_archive)
        settings = db.execute(select(ApplianceSettings)).scalars().one()
        settings.browser_session_idle_timeout_minutes = 30
        settings.api_token_max_lifetime_days = 90
        db.commit()
        restore_settings_archive(db, archive)
        restored = db.execute(select(ApplianceSettings)).scalars().one()
        assert restored.browser_session_idle_timeout_minutes == 45
        assert restored.api_token_max_lifetime_days == 120
        assert len(db.execute(select(BrowserSession)).scalars().all()) == 1


def test_api_token_default_and_explicit_expirations_obey_current_policy(client):
    """Omitted expiration uses policy while invalid explicit timestamps get stable 422 details."""
    _set_lifetimes(token_days=30)
    before = datetime.now(timezone.utc)
    created = _create_token(client, name="policy default")
    after = datetime.now(timezone.utc)
    assert created.status_code == 200, created.text
    expires_at = ensure_aware(datetime.fromisoformat(created.json()["token"]["expires_at"]))
    assert before + timedelta(days=30) <= expires_at <= after + timedelta(days=30)

    naive = _create_token(client, name="naive", expires_at="2026-09-01T12:00:00")
    assert naive.status_code == 422
    assert naive.json()["detail"] == "expires_at must include a timezone"

    past = _create_token(client, name="past", expires_at="2020-01-01T00:00:00Z")
    assert past.status_code == 422
    assert past.json()["detail"] == "expires_at must be in the future"

    too_late = _create_token(
        client,
        name="too late",
        expires_at=(datetime.now(timezone.utc) + timedelta(days=31)).isoformat(),
    )
    assert too_late.status_code == 422
    assert too_late.json()["detail"] == (
        "expires_at must not exceed the configured maximum lifetime of 30 days"
    )

    malformed = _create_token(client, name="malformed", expires_at="not-a-date")
    assert malformed.status_code == 422
    assert malformed.json()["error_code"] == "VALIDATION_ERROR"


def test_api_token_explicit_expiry_accepts_exact_policy_boundary(client, monkeypatch):
    """An explicit timezone-aware expiration is inclusive at the exact maximum."""
    fixed_now = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
    _set_lifetimes(token_days=30)
    monkeypatch.setattr("atlaso.app.token_service.utcnow", lambda: fixed_now)
    response = _create_token(
        client,
        name="exact boundary",
        expires_at=(fixed_now + timedelta(days=30)).isoformat(),
    )
    assert response.status_code == 200, response.text
    assert ensure_aware(
        datetime.fromisoformat(response.json()["token"]["expires_at"])
    ) == fixed_now + timedelta(days=30)


def test_existing_api_token_expiration_is_immutable_when_policy_changes(client):
    """Changing the issuance ceiling does not rewrite previously issued credentials."""
    _set_lifetimes(token_days=30)
    explicit = datetime.now(timezone.utc) + timedelta(days=10)
    created = _create_token(client, name="immutable", expires_at=explicit.isoformat())
    assert created.status_code == 200, created.text
    token_id = created.json()["token"]["id"]
    original = ensure_aware(datetime.fromisoformat(created.json()["token"]["expires_at"]))

    _set_lifetimes(token_days=1)
    with SessionLocal() as db:
        persisted = db.get(ApiToken, token_id)
        assert persisted is not None
        assert ensure_aware(persisted.expires_at) == original


@pytest.mark.parametrize(
    ("idle_minutes", "token_days"),
    [(5, 1), (1440, 365)],
)
def test_authentication_lifetime_ui_accepts_documented_boundaries(
    client, idle_minutes, token_days
):
    """Both configured ranges include their documented minimum and maximum."""
    login(client)
    page = client.get("/ui/management/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ui/management/settings/authentication-lifetimes",
        data={
            "browser_session_idle_timeout_minutes": str(idle_minutes),
            "api_token_max_lifetime_days": str(token_days),
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert response.status_code == 200, response.text
