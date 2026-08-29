"""Verify configurable browser-session and API-token lifetime policies."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from atlaso.app import web_terminal
from atlaso.app.config import Settings
from atlaso.app.database import (
    SessionLocal,
    _reconcile_authentication_lifetime_columns,
)
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


def test_authentication_lifetime_schema_reconciliation_is_portable_and_idempotent(
    monkeypatch,
):
    """Existing PostgreSQL-style schemas receive only missing policy columns.

    Args:
        monkeypatch: Pytest fixture used to replace SQLAlchemy inspection.
    """
    existing_columns = [
        {"name": "id"},
        {"name": "browser_session_idle_timeout_minutes"},
    ]

    class Inspector:
        """Return the existing appliance-settings schema."""

        @staticmethod
        def get_columns(table_name):
            """Return existing columns for the requested table.

            Args:
                table_name: Database table being inspected.
            """
            assert table_name == "appliance_settings"
            return existing_columns

    class Connection:
        """Capture portable ALTER TABLE statements."""

        def __init__(self):
            """Initialize captured statements."""
            self.statements = []
            self.parameters = []
            self.dialect = SimpleNamespace(name="postgresql")

        def execute(self, statement, parameters=None):
            """Capture a reconciliation statement.

            Args:
                statement: SQLAlchemy statement emitted by reconciliation.
                parameters: Optional bound values emitted with the statement.
            """
            self.statements.append(str(statement))
            self.parameters.append(parameters)

    monkeypatch.setattr("atlaso.app.database.inspect", lambda _connection: Inspector())
    monkeypatch.setattr(
        "atlaso.app.database.get_settings",
        lambda: SimpleNamespace(api_token_ttl_days=7),
    )
    monkeypatch.setenv("ATLASO_API_TOKEN_TTL_DAYS", "7")
    assert Settings(_env_file=None).api_token_ttl_days == 7
    connection = Connection()

    _reconcile_authentication_lifetime_columns(connection)

    assert connection.statements == [
        "ALTER TABLE appliance_settings ADD COLUMN IF NOT EXISTS "
        "api_token_max_lifetime_days INTEGER NOT NULL DEFAULT 90",
        "UPDATE appliance_settings SET api_token_max_lifetime_days = :legacy_token_days",
    ]
    assert connection.parameters == [None, {"legacy_token_days": 7}]

    existing_columns.append({"name": "api_token_max_lifetime_days"})
    reconciled_connection = Connection()
    _reconcile_authentication_lifetime_columns(reconciled_connection)
    assert reconciled_connection.statements == []


def _current_browser_session() -> BrowserSession:
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalars().one()
        db.expunge(session)
        return session


def _set_lifetimes(*, idle_minutes: int = 30, token_days: int = 90) -> None:
    """Persist authentication-lifetime policy values for a test.

    Args:
        idle_minutes: Browser inactivity timeout in minutes.
        token_days: Maximum API-token lifetime in days.
    """
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalars().one()
        settings.browser_session_idle_timeout_minutes = idle_minutes
        settings.api_token_max_lifetime_days = token_days
        db.commit()


def _create_token(client, *, name: str, expires_at: str | None = None):
    """Issue an API token through the tested transport.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        name: Operator-visible token name.
        expires_at: Optional explicit expiration timestamp.
    """
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
    """The server expires before the handler and discloses no session identifier.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace time for the test.
    """
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
    """Only deliberate navigation or the activity endpoint extends activity.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace time for the test.
    """
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
    """Policy changes apply on the next request and cannot resurrect expired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace time for the test.
    """
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
    """Explicit logout closes the server record as well as signed cookie state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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


def test_terminal_protocol_revalidation_expires_inactive_browser_session(client):
    """Terminal protocol checks enforce the persisted browser inactivity deadline.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    _set_lifetimes(idle_minutes=5)
    with SessionLocal() as db:
        session = db.execute(select(BrowserSession)).scalars().one()
        session.last_interactive_at = datetime.now(timezone.utc) - timedelta(minutes=6)
        session_id = session.id
        user_id = session.user_id
        db.commit()

    assert web_terminal._browser_session_is_active(session_id, user_id) is False
    expired = _current_browser_session()
    assert expired.expired_at is not None
    assert expired.expiry_reason == "inactivity"


def test_authentication_lifetime_settings_save_validate_and_archive(client):
    """The settings UI enforces bounds and archive restore preserves policy.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Omitted expiration uses policy while invalid timestamps get stable details.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """An explicit timezone-aware expiration is inclusive at the exact maximum.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace time for the test.
    """
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
    """Changing the issuance ceiling does not rewrite existing credentials.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Both configured ranges include their documented boundaries.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        idle_minutes: Browser inactivity boundary under test.
        token_days: API-token lifetime boundary under test.
    """
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
