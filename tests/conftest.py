"""Test conftest behavior."""

import os
from collections.abc import Generator

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    """Return client."""
    db_path = tmp_path / "atlaso-test.db"
    monkeypatch.setenv("ATLASO_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ATLASO_SECRET_KEY", "test-secret-key-with-enough-length")
    monkeypatch.setenv("ATLASO_BOOTSTRAP_ADMIN_PASSWORD", "atlaso-admin")
    monkeypatch.setenv("ATLASO_MONITOR_ENABLED", "false")

    from atlaso.app.config import get_settings

    get_settings.cache_clear()

    import atlaso.app.database as database

    database.engine.dispose()
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal.configure(bind=database.engine)

    from atlaso.app.main import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client

    get_settings.cache_clear()
    os.environ.pop("ATLASO_DATABASE_URL", None)
